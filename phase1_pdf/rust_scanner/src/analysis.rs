// =============================================================================
// PHANTOM-X :: Phase 1 -- PDF scanner (Rust), analysis half
// =============================================================================
// analysis.rs -- The feature inventory: what actions, what JavaScript, what
// embedded files, what external references a PDF contains.
//
// The inventory is deliberately about WHAT IS PRESENT, not about whether it
// is malicious. A PDF that opens a web page is not automatically an attack;
// the severity comes from what the action does and whether it needs user
// interaction. The lab needs the observation, not the verdict.
// =============================================================================

use crate::parser::{decode_stream, Decoded};
use crate::scanner::{Document, Object};
use std::collections::{BTreeMap, BTreeSet};

/// One action found in the document.
#[derive(Debug, Clone)]
pub struct Action {
    pub action_type: String,
    pub location: String,
    pub requires_interaction: bool,
    pub parameters: BTreeMap<String, String>,
}

/// One JavaScript entry.
#[derive(Debug, Clone)]
pub struct Script {
    pub location: String,
    pub length: usize,
    pub sha256: String,
    pub preview: String,
}

/// One embedded file.
#[derive(Debug, Clone)]
pub struct EmbeddedFile {
    pub name: String,
    pub location: String,
    pub size: usize,
    pub sha256: String,
    pub content_type: String,
    pub identified_as: String,
    pub is_pe: bool,
    pub entropy: f64,
}

/// One external reference.
#[derive(Debug, Clone)]
pub struct ExternalRef {
    pub kind: String,
    pub target: String,
    pub location: String,
}

/// One annotation.
#[derive(Debug, Clone)]
pub struct Annotation {
    pub subtype: String,
    pub location: String,
    pub contents: String,
    pub has_action: bool,
}

/// A form field.
#[derive(Debug, Clone)]
pub struct FormField {
    pub name: String,
    pub field_type: String,
    pub location: String,
    pub has_action: bool,
}

/// The complete inventory.
#[derive(Debug, Default)]
pub struct Inventory {
    pub actions: Vec<Action>,
    pub scripts: Vec<Script>,
    pub embedded_files: Vec<EmbeddedFile>,
    pub external_refs: Vec<ExternalRef>,
    pub annotations: Vec<Annotation>,
    pub form_fields: Vec<FormField>,
    pub page_count: usize,
    pub streams_seen: usize,
    pub streams_decoded: usize,
    pub object_count: usize,
    pub strings_of_interest: Vec<(String, String)>,
    /// Object numbers that have already been recorded as actions.
    ///
    /// One action dictionary can be reachable by more than one path. In
    /// the combined test document the JavaScript action is referenced
    /// both from the catalog's /Names tree and from the page's /AA
    /// dictionary. It is one action, so it is counted once -- but it is
    /// still one behaviour, and an inventory that reported it twice would
    /// misstate how much is happening in the document.
    pub action_objs: BTreeSet<u32>,
}

/// Walk the document and build the inventory.
pub fn analyze(doc: &Document) -> Inventory {
    let mut inv = Inventory {
        object_count: doc.objects.len(),
        ..Default::default()
    };

    // -- pages ---------------------------------------------------------------
    let pages = doc
        .objects
        .iter()
        .filter(|(_, o)| {
            o.as_dict()
                .and_then(|d| d.get("Type"))
                .and_then(|t| t.as_name())
                == Some("Page")
        })
        .count();
    inv.page_count = pages.max(1);

    // -- name trees ----------------------------------------------------------
    let mut visited: BTreeSet<u32> = BTreeSet::new();
    for (num, obj) in &doc.objects {
        let dict = match obj.as_dict() {
            Some(d) => d,
            None => continue,
        };

        // Catalog-level /OpenAction
        if let Some(oa) = dict.get("OpenAction") {
            collect_action(doc, oa, "catalog/OpenAction", true, &mut inv, &mut visited);
        }
        // Page-level /AA (additional actions)
        if let Some(aa) = dict.get("AA") {
            collect_additional_actions(doc, aa, &format!("obj {}/AA", num), &mut inv, &mut visited);
        }
        // Annotations
        if let Some(annots) = dict.get("Annots").and_then(|v| v.resolve(doc)) {
            if let Some(arr) = annots.as_array() {
                for (i, a) in arr.iter().enumerate() {
                    let a = match a.resolve(doc) {
                        Some(x) => x,
                        None => continue,
                    };
                    let ad = match a.as_dict() {
                        Some(d) => d,
                        None => continue,
                    };
                    let subtype = ad
                        .get("Subtype")
                        .and_then(|v| v.resolve(doc))
                        .and_then(|v| v.as_name())
                        .unwrap_or("?")
                        .to_string();
                    let contents = ad
                        .get("Contents")
                        .and_then(|v| v.resolve(doc))
                        .and_then(|v| match v {
                            Object::Str(s) => Some(String::from_utf8_lossy(s).into_owned()),
                            _ => None,
                        })
                        .unwrap_or_default();
                    let has_action = ad.contains_key("A") || ad.contains_key("AA");
                    inv.annotations.push(Annotation {
                        subtype,
                        location: format!("obj {}/Annots[{}]", num, i),
                        contents,
                        has_action,
                    });
                    if let Some(a) = ad.get("A") {
                        collect_action(
                            doc,
                            a,
                            &format!("obj {}/Annots[{}]/A", num, i),
                            true,
                            &mut inv,
                            &mut visited,
                        );
                    }
                }
            }
        }
        // Form fields
        if dict.contains_key("FT") {
            let name = dict
                .get("T")
                .and_then(|v| v.resolve(doc))
                .and_then(|v| match v {
                    Object::Str(s) => Some(String::from_utf8_lossy(s).into_owned()),
                    _ => None,
                })
                .unwrap_or_default();
            let ft = dict
                .get("FT")
                .and_then(|v| v.resolve(doc))
                .and_then(|v| v.as_name())
                .unwrap_or("?")
                .to_string();
            let has_action = dict.contains_key("A") || dict.contains_key("AA");
            inv.form_fields.push(FormField {
                name,
                field_type: ft,
                location: format!("obj {}", num),
                has_action,
            });
            if let Some(a) = dict.get("A") {
                collect_action(doc, a, &format!("obj {}/A", num), true, &mut inv, &mut visited);
            }
        }
    }

    // -- embedded files ------------------------------------------------------
    collect_embedded_files(doc, &mut inv);

    // -- JavaScript name trees ----------------------------------------------
    //
    // A document can carry JavaScript in two different places: as an
    // action (an /OpenAction or an /AA entry with /S /JavaScript), or as
    // a named entry in the catalog's /Names /JavaScript name tree. The
    // second form is the one a reader executes at document open, and it
    // is easy to miss because it is not an action at all.
    collect_js_name_tree(doc, &mut inv);

    // -- streams -------------------------------------------------------------
    for obj in doc.objects.values() {
        if let Object::Stream { dict, raw } = obj {
            inv.streams_seen += 1;
            let d = decode_stream(doc, dict, raw);
            if !d.skipped.is_empty() && d.data.is_empty() {
                continue;
            }
            inv.streams_decoded += 1;
            // Look for JavaScript inside streams.
            if let Some(st) = dict.get("Type").and_then(|v| v.as_name()) {
                if st == "JavaScript" {
                    let text = String::from_utf8_lossy(&d.data).into_owned();
                    inv.scripts.push(Script {
                        location: "stream(Type=JavaScript)".into(),
                        length: d.data.len(),
                        sha256: crate::sha256::hex(&d.data),
                        preview: text.chars().take(2048).collect(),
                    });
                }
            }
        }
    }

    inv
}

/// Walk a PDF name tree and collect the JavaScript entries in it.
///
/// The tree is a linked list of /Kids or a single /Names array of
/// (name, value) pairs. Each value is either a JavaScript action
/// dictionary (with /S /JavaScript and /JS) or a stream.
fn collect_js_name_tree(doc: &Document, inv: &mut Inventory) {
    // Find the catalog.
    let catalog = doc
        .objects
        .iter()
        .find(|(_, o)| {
            o.as_dict()
                .and_then(|d| d.get("Type"))
                .and_then(|t| t.as_name())
                == Some("Catalog")
        })
        .map(|(n, _)| *n);
    let cat = match catalog {
        Some(n) => &doc.objects[&n],
        None => return,
    };
    let cat_dict = match cat.as_dict() {
        Some(d) => d,
        None => return,
    };

    let names = match cat_dict.get("Names").and_then(|v| v.resolve(doc)) {
        Some(Object::Dict(d)) => d,
        _ => return,
    };
    let js_tree = match names.get("JavaScript").and_then(|v| v.resolve(doc)) {
        Some(Object::Dict(d)) => d,
        _ => return,
    };

    let mut visited: BTreeSet<u32> = BTreeSet::new();
    let mut pairs: Vec<(String, &Object, Option<u32>)> = Vec::new();
    // The tree node was already resolved to its dictionary, so the walk
    // starts from the dictionary rather than from an Object.
    walk_name_tree_dict(doc, js_tree, &mut pairs, &mut visited);

    for (name, value, name_obj_num) in pairs {
        match value {
            Object::Dict(d) => {
                // A JavaScript action dictionary.
                //
                // It can be reached twice: once through the name tree walk
                // and once through the ordinary action walk, because a
                // JavaScript action in a document's /Names tree is also a
                // valid action dictionary. The action_objs set decides
                // which one gets there first; either way it is counted
                // exactly once.
                let already = match name_obj_num {
                    Some(n) => !inv.action_objs.insert(n),
                    None => false,
                };
                if let Some(js) = d.get("JS") {
                    let (loc, bytes) = match js.resolve(doc) {
                        Some(Object::Str(b)) => (format!("JS name tree '{}'", name), b.clone()),
                        Some(Object::Stream { dict, raw }) => {
                            let dec = decode_stream(doc, dict, raw);
                            (format!("JS name tree '{}'", name), dec.data)
                        }
                        _ => (format!("JS name tree '{}'", name), Vec::new()),
                    };
                    if !already {
                        push_script(inv, loc, bytes);
                    }
                }
                // The dictionary itself may be an action.
                if d.get("S").and_then(|v| v.as_name()) == Some("JavaScript") && !already {
                    inv.actions.push(Action {
                        action_type: "JavaScript".into(),
                        location: format!("JS name tree '{}'", name),
                        requires_interaction: false,
                        parameters: BTreeMap::new(),
                    });
                }
            }
            Object::Stream { dict, raw } => {
                let dec = decode_stream(doc, dict, raw);
                push_script(inv, format!("JS name tree '{}'", name), dec.data);
            }
            _ => {}
        }
    }
}

/// Recursively collect (name, value) pairs from a PDF name tree node.
fn walk_name_tree_dict<'a>(
    doc: &'a Document,
    d: &'a BTreeMap<String, Object>,
    out: &mut Vec<(String, &'a Object, Option<u32>)>,
    visited: &mut BTreeSet<u32>,
) {
    // A leaf: an array of alternating name and value.
    if let Some(arr) = d.get("Names").and_then(|v| v.resolve(doc)).and_then(|v| v.as_array()) {
        let mut i = 0;
        while i + 1 < arr.len() {
            let name = match arr[i].resolve(doc) {
                Some(Object::Str(b)) => String::from_utf8_lossy(b).into_owned(),
                Some(Object::Name(n)) => n.clone(),
                _ => String::new(),
            };
            if let Some(val) = arr[i + 1].resolve(doc) {
                // Keep the object number so the same action can be
                // recognised when it is reached by another path.
                let num = match &arr[i + 1] {
                    Object::Ref(r) => Some(r.num),
                    _ => None,
                };
                out.push((name, val, num));
            }
            i += 2;
        }
    }

    // An interior node: children.
    if let Some(kids) = d.get("Kids").and_then(|v| v.resolve(doc)).and_then(|v| v.as_array()) {
        for kid in kids {
            if let Object::Ref(r) = kid {
                if !visited.insert(r.num) {
                    continue;
                }
            }
            if let Some(Object::Dict(kd)) = kid.resolve(doc) {
                walk_name_tree_dict(doc, kd, out, visited);
            }
        }
    }
}

/// Record a JavaScript entry.
fn push_script(inv: &mut Inventory, location: String, bytes: Vec<u8>) {
    let text = String::from_utf8_lossy(&bytes).into_owned();
    inv.scripts.push(Script {
        location,
        length: bytes.len(),
        sha256: crate::sha256::hex(&bytes),
        preview: text.chars().take(2048).collect(),
    });
}

/// Walk /AA (additional actions) dictionaries.
fn collect_additional_actions(
    doc: &Document,
    aa: &Object,
    location: &str,
    inv: &mut Inventory,
    visited: &mut BTreeSet<u32>,
) {
    let d = match aa.resolve(doc) {
        Some(Object::Dict(d)) => d,
        _ => return,
    };
    for (trigger, action) in d {
        let loc = format!("{}/{}", location, trigger);
        // Some triggers (WC, WS, DS, WP) fire without user interaction.
        let interactive = !matches!(
            trigger.as_str(),
            "WC" | "WS" | "DS" | "WP" | "DP"
        );
        collect_action(doc, action, &loc, interactive, inv, visited);
    }
}

/// Record one action, resolving it through /Next chains and /S dispatch.
fn collect_action(
    doc: &Document,
    action: &Object,
    location: &str,
    requires_interaction: bool,
    inv: &mut Inventory,
    visited: &mut BTreeSet<u32>,
) {
    // Guard against a reference cycle in /Next.
    if let Object::Ref(r) = action {
        if !visited.insert(r.num) {
            return;
        }
    }

    // Deduplicate by the object the action resolves to. The same action
    // dictionary can be reached from several places (a /Names tree and a
    // page's /AA, for instance). It is one action, so it is recorded
    // once.
    let target_num = match action {
        Object::Ref(r) => Some(r.num),
        _ => None,
    };
    if let Some(n) = target_num {
        if !inv.action_objs.insert(n) {
            return;
        }
    }

    let obj = match action.resolve(doc) {
        Some(o) => o,
        None => return,
    };
    let d = match obj.as_dict() {
        Some(d) => d,
        None => return,
    };

    let action_type = d
        .get("S")
        .and_then(|v| v.resolve(doc))
        .and_then(|v| v.as_name())
        .unwrap_or("")
        .to_string();

    let mut params: BTreeMap<String, String> = BTreeMap::new();
    for key in ["URI", "F", "Win", "Mac", "Unix", "NewWindow", "IsMap"] {
        if let Some(v) = d.get(key) {
            let s = match v.resolve(doc) {
                Some(Object::Str(b)) => Some(String::from_utf8_lossy(b).into_owned()),
                Some(Object::Name(n)) => Some(format!("/{}", n)),
                Some(Object::Int(i)) => Some(i.to_string()),
                _ => None,
            };
            if let Some(s) = s {
                params.insert(key.to_string(), s);
            }
        }
    }

    // An action whose type is unknown but which has a /Next is still an
    // action; record it with its actual type rather than dropping it.
    inv.actions.push(Action {
        action_type: if action_type.is_empty() {
            "untyped".into()
        } else {
            action_type
        },
        location: location.to_string(),
        requires_interaction,
        parameters: params,
    });

    // A JavaScript action carries its code in /JS.
    if let Some(js) = d.get("JS") {
        let (loc, bytes) = match js.resolve(doc) {
            Some(Object::Str(b)) => (location.to_string(), b.clone()),
            Some(Object::Stream { dict, raw }) => {
                let d = decode_stream(doc, dict, raw);
                (format!("{}/JS", location), d.data)
            }
            _ => (location.to_string(), Vec::new()),
        };
        let text = String::from_utf8_lossy(&bytes).into_owned();
        inv.scripts.push(Script {
            location: loc,
            length: bytes.len(),
            sha256: crate::sha256::hex(&bytes),
            preview: text.chars().take(2048).collect(),
        });
    }

    // External references from URI / GoToR / Launch / GoToE actions.
    if let Some(uri) = d.get("URI").and_then(|v| v.resolve(doc)) {
        if let Object::Str(b) = uri {
            let target = String::from_utf8_lossy(b).into_owned();
            if is_external(&target) {
                inv.external_refs.push(ExternalRef {
                    kind: "URI".into(),
                    target,
                    location: location.to_string(),
                });
            }
        }
    }
    for (key, kind) in [("F", "file"), ("Win", "file"), ("Mac", "file"), ("Unix", "file")] {
        if let Some(v) = d.get(key).and_then(|v| v.resolve(doc)) {
            let target = match v {
                Object::Str(b) => String::from_utf8_lossy(b).into_owned(),
                Object::Name(n) => format!("/{}", n),
                _ => continue,
            };
            inv.external_refs.push(ExternalRef {
                kind: kind.to_string(),
                target,
                location: location.to_string(),
            });
        }
    }

    // Follow the /Next chain.
    if let Some(next) = d.get("Next") {
        match next.resolve(doc) {
            Some(Object::Array(arr)) => {
                for (i, n) in arr.iter().enumerate() {
                    collect_action(
                        doc,
                        n,
                        &format!("{}/Next[{}]", location, i),
                        requires_interaction,
                        inv,
                        visited,
                    );
                }
            }
            Some(_) => {
                collect_action(
                    doc,
                    next,
                    &format!("{}/Next", location),
                    requires_interaction,
                    inv,
                    visited,
                );
            }
            None => {}
        }
    }
}

fn is_external(target: &str) -> bool {
    let t = target.to_ascii_lowercase();
    t.starts_with("http:") || t.starts_with("https:") || t.starts_with("ftp:")
        || t.starts_with("file:") || t.starts_with("mailto:")
}

/// Find embedded files: /EmbeddedFiles name trees and /FileAttachment
/// annotations.
fn collect_embedded_files(doc: &Document, inv: &mut Inventory) {
    // Walk every /Filespec dictionary in the document.
    for (num, obj) in &doc.objects {
        let dict = match obj.as_dict() {
            Some(d) => d,
            None => continue,
        };
        let is_filespec = dict
            .get("Type")
            .and_then(|v| v.resolve(doc))
            .and_then(|v| v.as_name())
            == Some("Filespec");
        let has_ef = dict.contains_key("EF");
        if !is_filespec && !has_ef {
            continue;
        }

        let name = dict
            .get("UF")
            .or_else(|| dict.get("F"))
            .and_then(|v| v.resolve(doc))
            .and_then(|v| match v {
                Object::Str(b) => Some(String::from_utf8_lossy(b).into_owned()),
                _ => None,
            })
            .unwrap_or_else(|| format!("obj{}", num));

        // The EF dictionary holds the actual stream.
        let ef = match dict.get("EF").and_then(|v| v.resolve(doc)) {
            Some(Object::Dict(d)) => d,
            _ => continue,
        };
        let stream_ref = ef
            .get("F")
            .or_else(|| ef.get("UF"))
            .and_then(|v| v.resolve(doc));
        let stream = match stream_ref {
            Some(Object::Stream { dict, raw }) => (dict.clone(), raw.clone()),
            _ => continue,
        };

        let decoded = decode_stream(doc, &stream.0, &stream.1);
        let data = decoded.data;

        let content_type = stream
            .0
            .get("Subtype")
            .and_then(|v| v.as_name())
            .unwrap_or("")
            .to_string();

        let is_pe = is_real_pe(&data);
        inv.embedded_files.push(EmbeddedFile {
            name,
            location: format!("obj {}/EF/F", num),
            size: data.len(),
            sha256: crate::sha256::hex(&data),
            content_type,
            identified_as: identify_bytes(&data),
            is_pe,
            entropy: shannon_entropy(&data),
        });
    }
}

/// True only if the data is a genuine PE image.
///
/// A DOS header starts with "MZ", but so does anything that wants to look
/// like one. The 'PE\0\0' signature at the offset given by the DWORD at
/// 0x3C is what makes it real.
pub fn is_real_pe(data: &[u8]) -> bool {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return false;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 4 <= data.len() {
        &data[e_lfanew..e_lfanew + 4] == b"PE\0\0"
    } else {
        false
    }
}

/// Shannon entropy in bits per byte.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / total;
            h -= p * p.log2();
        }
    }
    h
}

/// True if the data is overwhelmingly printable text.
pub fn is_texty(data: &[u8], threshold: f64) -> bool {
    if data.is_empty() {
        return false;
    }
    let sample = &data[..data.len().min(8192)];
    let printable = sample
        .iter()
        .filter(|&&b| (0x20..0x7F).contains(&b) || b == 0x09 || b == 0x0A || b == 0x0D || b == 0)
        .count();
    (printable as f64 / sample.len() as f64) >= threshold
}

/// Describe embedded content by what it is, not by what it claims.
pub fn identify_bytes(data: &[u8]) -> String {
    let starts = |m: &[u8]| data.starts_with(m);
    if starts(b"MZ") {
        if is_real_pe(data) {
            return "PE/DOS executable".into();
        }
        if is_texty(data, 0.90) {
            return "MZ-prefixed plain text (NOT a PE image)".into();
        }
        return "MZ-prefixed binary (no PE signature -- malformed or truncated)".into();
    }
    if starts(b"\x7fELF") {
        return "ELF executable".into();
    }
    if starts(b"PK\x03\x04") {
        return "ZIP archive".into();
    }
    if starts(b"\xd0\xcf\x11\xe0") {
        return "OLE2 compound document".into();
    }
    if starts(b"#!") {
        return "script (shebang)".into();
    }
    if starts(b"%PDF-") {
        return "PDF document".into();
    }
    if starts(b"MSCF") {
        return "CAB archive".into();
    }
    if starts(b"Rar!") {
        return "RAR archive".into();
    }
    if starts(b"\x1f\x8b") {
        return "gzip stream".into();
    }
    if starts(b"BM") {
        return "BMP image".into();
    }
    if starts(b"\x89PNG") {
        return "PNG image".into();
    }
    if starts(b"\xff\xd8\xff") {
        return "JPEG image".into();
    }
    if starts(b"GIF8") {
        return "GIF image".into();
    }
    if data.len() >= 2 && &data[..2] == b"PK" {
        return "ZIP-like archive".into();
    }
    if is_texty(data, 0.90) {
        return "plain text".into();
    }
    "unrecognised".into()
}
