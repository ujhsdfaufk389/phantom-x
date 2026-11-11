// =============================================================================
// PHANTOM-X :: Phase 1 -- PDF scanner (Rust), parser half
// =============================================================================
// parser.rs -- Object table construction, stream decoding and the feature
// inventory that the scanner reports.
//
// This half is written against the PDF specification (ISO 32000-1) rather
// than against the Python inspector, so that cross-validation compares two
// independent readings of the format.
// =============================================================================

use crate::scanner::{
    hex_val, Document, Lexer, ObjRef, Object, PdfError, Result, Token,
};

/// Re-exported so that callers can name the document type through the
/// parser module.
pub use crate::scanner::Document as ParsedDocument;
use std::collections::{BTreeMap, BTreeSet};

/// Parse a PDF file into a Document.
pub fn parse(data: &[u8]) -> Result<Document> {
    let mut doc = Document {
        objects: BTreeMap::new(),
        version: String::new(),
        encrypted: false,
        xref_type: String::new(),
        trailer_root: None,
        offsets: BTreeMap::new(),
    };

    // -- version -------------------------------------------------------------
    if data.len() >= 8 && &data[..5] == b"%PDF-" {
        let end = (5 + 3).min(data.len());
        doc.version = String::from_utf8_lossy(&data[5..end]).trim().to_string();
    }

    // -- xref style ----------------------------------------------------------
    doc.xref_type = detect_xref_type(data);

    // -- brute-force scan for "N G obj" --------------------------------------
    //
    // A full xref table walk is brittle in the face of damaged files, and
    // the point of this scanner is to report what is in a PDF that may well
    // be malformed. A linear scan finds the objects regardless of whether
    // the xref table is correct, which is the more useful behaviour for an
    // inspection tool. Where a document uses an object stream (a PDF 1.5
    // compressed xref), the objects inside it are expanded separately.
    let mut lexer = Lexer::new(data);
    let mut num: Option<u32> = None;
    let mut gen: Option<u16> = None;
    let mut pending_start = 0usize;

    loop {
        let start = lexer.pos();
        let tok = lexer.next_token()?;
        match tok {
            Token::Eof => break,
            Token::Int(v) if v >= 0 => {
                // Could be "N G obj" or a value inside an object body.
                if num.is_some() && gen.is_none() {
                    gen = Some(v as u16);
                } else if num.is_none() {
                    num = Some(v as u32);
                }
                pending_start = start;
            }
            Token::Keyword(k) if k == "obj" => {
                if let (Some(n), Some(g)) = (num.take(), gen.take()) {
                    doc.offsets.insert(n, pending_start as u64);
                    let obj = parse_object(&mut lexer, data)?;
                    doc.objects.insert(n, obj);
                }
            }
            Token::Keyword(k) if k == "endobj" => {
                num = None;
                gen = None;
            }
            _ => {
                // Any other token ends the "N G" pair.
                if !matches!(tok, Token::Int(_)) {
                    num = None;
                    gen = None;
                }
            }
        }
    }

    // -- trailer -------------------------------------------------------------
    let mut lexer = Lexer::new(data);
    loop {
        let tok = lexer.next_token()?;
        match tok {
            Token::Eof => break,
            Token::Keyword(ref k) if k == "trailer" => {
                let d = parse_dict_body(&mut lexer, data)?;
                if let Object::Dict(td) = &d {
                    if let Some(Object::Ref(r)) = td.get("Root") {
                        doc.trailer_root = Some(*r);
                    }
                    if td.contains_key("Encrypt") {
                        doc.encrypted = true;
                    }
                }
                break;
            }
            _ => {}
        }
    }

    // If the trailer had no /Root, fall back to a Catalog object.
    if doc.trailer_root.is_none() {
        for (n, obj) in &doc.objects {
            if let Some(d) = obj.as_dict() {
                if d.get("Type").and_then(|t| t.as_name()) == Some("Catalog") {
                    doc.trailer_root = Some(ObjRef::new(*n, 0));
                    break;
                }
            }
        }
    }

    // -- object streams ------------------------------------------------------
    expand_object_streams(&mut doc, data)?;

    Ok(doc)
}

fn detect_xref_type(data: &[u8]) -> String {
    if find_bytes(data, b"/XRef").is_some() {
        "cross-reference stream".into()
    } else if find_bytes(data, b"xref").is_some() {
        "classic table".into()
    } else {
        "none (scanned)".into()
    }
}

/// Find the first occurrence of a needle.
fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

// ---------------------------------------------------------------------------
// object parsing
// ---------------------------------------------------------------------------

/// Parse one object body, assuming the "N G obj" header was consumed.
fn parse_object(lexer: &mut Lexer, data: &[u8]) -> Result<Object> {
    let obj = parse_value(lexer, data, 0)?;

    // A stream may follow a dictionary.
    if let Object::Dict(dict) = &obj {
        let save = lexer.pos();
        if let Ok(Token::Keyword(k)) = lexer.next_token() {
            if k == "stream" {
                let raw = read_stream_data(lexer, data, dict)?;
                return Ok(Object::Stream { dict: dict.clone(), raw });
            }
        }
        lexer.seek(save);
    }
    Ok(obj)
}

/// Recursive value parser.
fn parse_value(lexer: &mut Lexer, data: &[u8], depth: usize) -> Result<Object> {
    if depth > 64 {
        return Err(PdfError("object nesting too deep".into()));
    }
    let tok = lexer.next_token()?;
    match tok {
        Token::ArrayOpen => {
            let mut items = Vec::new();
            loop {
                let save = lexer.pos();
                let t = lexer.next_token()?;
                if t == Token::ArrayClose {
                    break;
                }
                lexer.seek(save);
                match parse_value(lexer, data, depth + 1) {
                    Ok(v) => items.push(v),
                    Err(_) => {
                        // Skip an unreadable element rather than abandoning
                        // the whole array.
                        if lexer.pos() == save {
                            lexer.next_token()?;
                        }
                    }
                }
            }
            Ok(Object::Array(items))
        }
        Token::DictOpen => parse_dict_body(lexer, data),
        Token::Str(s) => Ok(Object::Str(s)),
        Token::HexStr(s) => Ok(Object::Str(s)),
        Token::Name(n) => Ok(Object::Name(n)),
        Token::Int(v) => {
            // Might be "N G R" (a reference).
            let save = lexer.pos();
            if v >= 0 {
                if let Ok(Token::Int(g)) = lexer.next_token() {
                    if g >= 0 {
                        let save2 = lexer.pos();
                        if let Ok(Token::Keyword(k)) = lexer.next_token() {
                            if k == "R" {
                                return Ok(Object::Ref(ObjRef::new(v as u32, g as u16)));
                            }
                        }
                        lexer.seek(save2);
                    }
                }
                lexer.seek(save);
            }
            Ok(Object::Int(v))
        }
        Token::Real(v) => Ok(Object::Real(v)),
        Token::Keyword(k) => match k.as_str() {
            "true" => Ok(Object::Bool(true)),
            "false" => Ok(Object::Bool(false)),
            "null" => Ok(Object::Null),
            _ => Ok(Object::Null),
        },
        Token::Obj(_) | Token::Gen(_) | Token::Eof => Ok(Object::Null),
        Token::ArrayClose | Token::DictClose | Token::BraceOpen | Token::BraceClose => {
            Ok(Object::Null)
        }
    }
}

/// Parse a dictionary body, assuming "<<" was consumed.
fn parse_dict_body(lexer: &mut Lexer, data: &[u8]) -> Result<Object> {
    let mut dict = BTreeMap::new();
    loop {
        let tok = lexer.next_token()?;
        match tok {
            Token::DictClose => break,
            Token::Eof => break,
            Token::Name(key) => {
                // The value may be a reference, so parse with lookahead.
                let value = parse_value(lexer, data, 1)?;
                dict.insert(key, value);
            }
            _ => {}
        }
    }
    Ok(Object::Dict(dict))
}

/// Read the raw bytes of a stream, given its dictionary.
fn read_stream_data(
    lexer: &mut Lexer,
    data: &[u8],
    dict: &BTreeMap<String, Object>,
) -> Result<Vec<u8>> {
    // After the "stream" keyword comes an EOL, then the bytes.
    let mut p = lexer.pos();
    if p < data.len() && data[p] == b'\r' {
        p += 1;
    }
    if p < data.len() && data[p] == b'\n' {
        p += 1;
    }
    lexer.seek(p);

    // Length comes from the dictionary, but it is often wrong in the wild.
    // Prefer /Length when it resolves to an integer; otherwise scan for
    // the "endstream" keyword.
    let mut declared: Option<usize> = None;
    if let Some(v) = dict.get("Length") {
        if let Object::Int(i) = v {
            if *i >= 0 {
                declared = Some(*i as usize);
            }
        }
    }

    if let Some(len) = declared {
        let end = (p + len).min(data.len());
        if end <= data.len() {
            // Sanity check: "endstream" should follow shortly after.
            let tail = &data[end..(end + 20).min(data.len())];
            if find_bytes(tail, b"endstream").is_some() {
                lexer.seek(end);
                return Ok(data[p..end].to_vec());
            }
        }
    }

    // Fall back to scanning for "endstream".
    let marker = find_bytes(&data[p..], b"endstream").ok_or_else(|| {
        PdfError("stream has no endstream marker".into())
    })?;
    let mut end = p + marker;
    // Trim the EOL that precedes "endstream".
    if end > p && data[end - 1] == b'\n' {
        end -= 1;
    }
    if end > p && data[end - 1] == b'\r' {
        end -= 1;
    }
    lexer.seek(end);
    Ok(data[p..end].to_vec())
}

// ---------------------------------------------------------------------------
// stream decoding
// ---------------------------------------------------------------------------

/// A decoded stream.
pub struct Decoded {
    pub data: Vec<u8>,
    /// Filters that could not be applied, in order.
    pub skipped: Vec<String>,
}

/// Decode a stream's data through its filter chain.
///
/// The first filter's output is the input to the second, and so on. A
/// filter that cannot be applied is recorded and the data passes through
/// unchanged, because a partial decode is more useful to an inspector than
/// no decode at all.
pub fn decode_stream(
    doc: &Document,
    dict: &BTreeMap<String, Object>,
    raw: &[u8],
) -> Decoded {
    let mut filters: Vec<String> = Vec::new();
    let mut parms: Vec<Option<BTreeMap<String, Object>>> = Vec::new();

    match dict.get("Filter") {
        Some(Object::Name(n)) => {
            filters.push(n.clone());
            parms.push(resolve_parms(doc, dict, "DecodeParms"));
        }
        Some(Object::Array(a)) => {
            for item in a {
                match item.resolve(doc) {
                    Some(Object::Name(n)) => {
                        filters.push(n.clone());
                        parms.push(None);
                    }
                    _ => {
                        filters.push(String::new());
                        parms.push(None);
                    }
                }
            }
            // A single /DecodeParms applies to a single filter; a parallel
            // array applies positionally.
            if let Some(p) = resolve_parms(doc, dict, "DecodeParms") {
                if parms.len() == 1 {
                    parms[0] = Some(p);
                }
            }
        }
        _ => {}
    }

    let mut data = raw.to_vec();
    let mut skipped = Vec::new();

    for (i, filter) in filters.iter().enumerate() {
        let parm = parms.get(i).cloned().flatten();
        match filter.as_str() {
            "FlateDecode" | "Fl" => match flate_decode(&data) {
                Some(out) => data = out,
                None => {
                    skipped.push(format!("{}@{}", filter, i));
                    break;
                }
            },
            "ASCIIHexDecode" | "AHx" => {
                data = ascii_hex_decode(&data);
            }
            "ASCII85Decode" | "A85" => {
                data = ascii85_decode(&data);
            }
            "RunLengthDecode" | "RL" => {
                data = runlength_decode(&data);
            }
            "LZWDecode" | "LZW" => {
                match lzw_decode(&data, early_change(&parm)) {
                    Some(out) => data = out,
                    None => {
                        skipped.push(format!("{}@{}", filter, i));
                        break;
                    }
                }
            }
            "DCTDecode" | "JPXDecode" | "CCITTFaxDecode" | "JBIG2Decode" => {
                // Image codecs: the raw bytes are the payload.
                skipped.push(format!("{}@{} (image codec)", filter, i));
                break;
            }
            "" => {}
            other => {
                skipped.push(format!("{}@{}", other, i));
                break;
            }
        }
    }

    Decoded { data, skipped }
}

fn resolve_parms(
    doc: &Document,
    dict: &BTreeMap<String, Object>,
    key: &str,
) -> Option<BTreeMap<String, Object>> {
    match dict.get(key) {
        Some(v) => match v.resolve(doc) {
            Some(Object::Dict(d)) => Some(d.clone()),
            _ => None,
        },
        None => None,
    }
}

fn early_change(parm: &Option<BTreeMap<String, Object>>) -> u8 {
    if let Some(p) = parm {
        if let Some(Object::Int(i)) = p.get("EarlyChange") {
            return if *i == 0 { 0 } else { 1 };
        }
    }
    1
}

/// Inflate a zlib or raw-deflate stream.
///
/// PDF's FlateDecode is zlib unless the /Predictor-style repair is
/// needed. If the zlib header is absent the data is raw deflate, so both
/// are attempted.
pub fn flate_decode(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 2 {
        return None;
    }
    // zlib header: CMF/FLG where CM = 8 and (CMF<<8|FLG) % 31 == 0.
    let cmf = data[0];
    let flg = data[1];
    let zlib = (cmf & 0x0f) == 8 && ((cmf as u16) << 8 | flg as u16) % 31 == 0;

    if zlib {
        if let Some(out) = inflate_raw(&data[2..]) {
            return Some(out);
        }
    }
    inflate_raw(data).or_else(|| {
        // Some writers emit a leading garbage byte.
        inflate_raw(&data[1..])
    })
}

/// A minimal, self-contained DEFLATE decompressor.
///
/// The lab must build with no crates, so the inflate implementation is
/// written out here rather than pulled from a dependency.
pub fn inflate_raw(data: &[u8]) -> Option<Vec<u8>> {
    let mut br = BitReader::new(data);
    let mut out: Vec<u8> = Vec::new();

    loop {
        let bfinal = br.bits(1)?;
        let btype = br.bits(2)?;
        match btype {
            0 => {
                // stored
                br.align();
                let len = br.u16()? as usize;
                let nlen = br.u16()? as usize;
                if len != (!nlen & 0xffff) {
                    return None;
                }
                for _ in 0..len {
                    out.push(br.byte()?);
                }
            }
            1 => {
                // fixed huffman
                let (lit, dist) = fixed_tables();
                if !inflate_block(&mut br, &mut out, &lit, &dist)? {
                    return None;
                }
            }
            2 => {
                // dynamic huffman
                let hlit = br.bits(5)? as usize + 257;
                let hdist = br.bits(5)? as usize + 1;
                let hclen = br.bits(4)? as usize + 4;
                const ORDER: [usize; 19] = [
                    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                ];
                let mut code_lengths = [0u8; 19];
                for i in 0..hclen {
                    code_lengths[ORDER[i]] = br.bits(3)? as u8;
                }
                let cl_tree = build_tree(&code_lengths)?;
                let mut lengths = vec![0u8; hlit + hdist];
                let mut i = 0;
                while i < hlit + hdist {
                    let sym = decode_symbol(&mut br, &cl_tree)?;
                    match sym {
                        0..=15 => {
                            lengths[i] = sym as u8;
                            i += 1;
                        }
                        16 => {
                            if i == 0 {
                                return None;
                            }
                            let prev = lengths[i - 1];
                            let rep = 3 + br.bits(2)? as usize;
                            for _ in 0..rep {
                                if i >= lengths.len() {
                                    return None;
                                }
                                lengths[i] = prev;
                                i += 1;
                            }
                        }
                        17 => {
                            let rep = 3 + br.bits(3)? as usize;
                            i += rep;
                            if i > lengths.len() {
                                return None;
                            }
                        }
                        18 => {
                            let rep = 11 + br.bits(7)? as usize;
                            i += rep;
                            if i > lengths.len() {
                                return None;
                            }
                        }
                        _ => return None,
                    }
                }
                let lit = build_tree(&lengths[..hlit])?;
                let dist = build_tree(&lengths[hlit..])?;
                if !inflate_block(&mut br, &mut out, &lit, &dist)? {
                    return None;
                }
            }
            _ => return None,
        }
        if bfinal == 1 {
            break;
        }
    }
    Some(out)
}

/// A canonical Huffman decoding table.
struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

fn build_tree(lengths: &[u8]) -> Option<Huffman> {
    let mut counts = [0u16; 16];
    for &l in lengths {
        counts[l as usize] += 1;
    }
    counts[0] = 0;
    let mut offs = [0u16; 16];
    for i in 1..15 {
        offs[i + 1] = offs[i] + counts[i];
    }
    let mut symbols = vec![0u16; lengths.len()];
    for (sym, &l) in lengths.iter().enumerate() {
        if l != 0 {
            symbols[offs[l as usize] as usize] = sym as u16;
            offs[l as usize] += 1;
        }
    }
    Some(Huffman { counts, symbols })
}

fn fixed_tables() -> (Huffman, Huffman) {
    let mut lit = vec![0u8; 288];
    for (i, l) in lit.iter_mut().enumerate() {
        *l = if i < 144 {
            8
        } else if i < 256 {
            9
        } else if i < 280 {
            7
        } else {
            8
        };
    }
    let dist = vec![5u8; 30];
    (
        build_tree(&lit).unwrap(),
        build_tree(&dist).unwrap(),
    )
}

fn decode_symbol(br: &mut BitReader, h: &Huffman) -> Option<u16> {
    let mut code: i32 = 0;
    let mut first: i32 = 0;
    let mut index: i32 = 0;
    for len in 1..16 {
        code |= br.bits(1)? as i32;
        let count = h.counts[len] as i32;
        if code - first < count {
            return h.symbols.get((index + (code - first)) as usize).copied();
        }
        index += count;
        first = (first + count) << 1;
        code <<= 1;
    }
    None
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
    131, 163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// Returns false when the block is the end-of-block marker.
fn inflate_block(
    br: &mut BitReader,
    out: &mut Vec<u8>,
    lit: &Huffman,
    dist: &Huffman,
) -> Option<bool> {
    loop {
        let sym = decode_symbol(br, lit)?;
        match sym {
            0..=255 => out.push(sym as u8),
            256 => return Some(true),
            257..=285 => {
                let idx = sym as usize - 257;
                let len = LEN_BASE[idx] as usize + br.bits(LEN_EXTRA[idx] as u32)? as usize;
                let dsym = decode_symbol(br, dist)? as usize;
                if dsym >= DIST_BASE.len() {
                    return None;
                }
                let d = DIST_BASE[dsym] as usize + br.bits(DIST_EXTRA[dsym] as u32)? as usize;
                if d == 0 || d > out.len() {
                    return None;
                }
                let start = out.len() - d;
                for i in 0..len {
                    let b = out[start + i];
                    out.push(b);
                }
            }
            _ => return None,
        }
    }
}

/// A bit reader over a byte slice, least-significant-bit first.
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bit: u32,
    acc: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader { data, pos: 0, bit: 0, acc: 0 }
    }

    fn bits(&mut self, n: u32) -> Option<u32> {
        while self.bit < n {
            let b = *self.data.get(self.pos)? as u32;
            self.pos += 1;
            self.acc |= b << self.bit;
            self.bit += 8;
        }
        let v = self.acc & ((1u32 << n) - 1).max(if n == 32 { u32::MAX } else { 0 });
        self.acc >>= n;
        self.bit -= n;
        Some(v)
    }

    fn align(&mut self) {
        let drop = self.bit % 8;
        self.acc >>= drop;
        self.bit -= drop;
    }

    fn byte(&mut self) -> Option<u8> {
        if self.bit >= 8 {
            let v = (self.acc & 0xff) as u8;
            self.acc >>= 8;
            self.bit -= 8;
            Some(v)
        } else {
            let b = *self.data.get(self.pos)?;
            self.pos += 1;
            Some(b)
        }
    }

    fn u16(&mut self) -> Option<u16> {
        let a = self.byte()? as u16;
        let b = self.byte()? as u16;
        Some(a | (b << 8))
    }
}

// ---------------------------------------------------------------------------
// the other standard filters
// ---------------------------------------------------------------------------

pub fn ascii_hex_decode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut hi: Option<u8> = None;
    for &c in data {
        if c == b'>' {
            break;
        }
        if let Some(v) = hex_val(c) {
            match hi {
                None => hi = Some(v),
                Some(h) => {
                    out.push(h * 16 + v);
                    hi = None;
                }
            }
        }
    }
    if let Some(h) = hi {
        out.push(h * 16);
    }
    out
}

pub fn ascii85_decode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut group = [0u8; 5];
    let mut n = 0usize;
    let mut i = 0usize;
    // Skip the optional <~ prefix.
    if data.len() >= 2 && data[0] == b'<' && data[1] == b'~' {
        i = 2;
    }
    while i < data.len() {
        let c = data[i];
        i += 1;
        if c == b'~' {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'z' && n == 0 {
            out.extend_from_slice(&[0, 0, 0, 0]);
            continue;
        }
        if !(b'!'..=b'u').contains(&c) {
            continue;
        }
        group[n] = c - b'!';
        n += 1;
        if n == 5 {
            let mut v: u32 = 0;
            for g in &group {
                v = v.wrapping_mul(85).wrapping_add(*g as u32);
            }
            out.push((v >> 24) as u8);
            out.push((v >> 16) as u8);
            out.push((v >> 8) as u8);
            out.push(v as u8);
            n = 0;
        }
    }
    if n > 0 {
        let mut v: u32 = 0;
        for i in 0..5 {
            let g = if i < n { group[i] } else { 84 };
            v = v.wrapping_mul(85).wrapping_add(g as u32);
        }
        for i in 0..n - 1 {
            out.push((v >> (24 - 8 * i)) as u8);
        }
    }
    out
}

pub fn runlength_decode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        let l = data[i];
        i += 1;
        if l == 128 {
            break;
        }
        if l < 128 {
            let n = l as usize + 1;
            let end = (i + n).min(data.len());
            out.extend_from_slice(&data[i..end]);
            i = end;
        } else {
            if i >= data.len() {
                break;
            }
            let b = data[i];
            i += 1;
            let n = 257 - l as usize;
            for _ in 0..n {
                out.push(b);
            }
        }
    }
    out
}

/// LZW decode, as used by PDF.
pub fn lzw_decode(data: &[u8], early: u8) -> Option<Vec<u8>> {
    const CLEAR: u16 = 256;
    const EOD: u16 = 257;
    let mut out: Vec<u8> = Vec::new();
    let mut dict: Vec<Vec<u8>> = Vec::new();
    let reset = |dict: &mut Vec<Vec<u8>>| {
        dict.clear();
        for i in 0..256 {
            dict.push(vec![i as u8]);
        }
        dict.push(Vec::new()); // 256 clear
        dict.push(Vec::new()); // 257 eod
    };
    reset(&mut dict);
    let mut code_width = 9u32;
    let mut prev: Option<u16> = None;
    let mut bitpos = 0usize;
    let total_bits = data.len() * 8;

    while bitpos + code_width as usize <= total_bits {
        let mut code: u16 = 0;
        for i in 0..code_width as usize {
            let b = (data[(bitpos + i) / 8] >> ((bitpos + i) % 8)) & 1;
            code |= (b as u16) << i;
        }
        bitpos += code_width as usize;

        if code == CLEAR {
            reset(&mut dict);
            code_width = 9;
            prev = None;
            continue;
        }
        if code == EOD {
            break;
        }
        let entry: Vec<u8> = if (code as usize) < dict.len() {
            dict[code as usize].clone()
        } else if let Some(p) = prev {
            let mut e = dict[p as usize].clone();
            e.push(dict[p as usize][0]);
            e
        } else {
            return None;
        };
        out.extend_from_slice(&entry);
        if let Some(p) = prev {
            let mut ne = dict[p as usize].clone();
            ne.push(entry[0]);
            dict.push(ne);
        }
        prev = Some(code);

        let size = dict.len();
        if size + (if early != 0 { 1 } else { 0 }) >= (1 << code_width) && code_width < 12 {
            code_width += 1;
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// object streams (PDF 1.5 compressed xref)
// ---------------------------------------------------------------------------

/// Expand the objects held inside /Type /ObjStm streams.
fn expand_object_streams(doc: &mut Document, data: &[u8]) -> Result<()> {
    let candidates: Vec<u32> = doc
        .objects
        .iter()
        .filter(|(_, obj)| {
            obj.as_dict()
                .and_then(|d| d.get("Type"))
                .and_then(|t| t.as_name())
                == Some("ObjStm")
        })
        .map(|(n, _)| *n)
        .collect();

    for num in candidates {
        let (dict, raw) = match &doc.objects[&num] {
            Object::Stream { dict, raw } => (dict.clone(), raw.clone()),
            _ => continue,
        };
        let decoded = decode_stream(doc, &dict, &raw);
        let n = match dict.get("N").and_then(|v| v.resolve(doc)) {
            Some(Object::Int(i)) => *i as usize,
            _ => continue,
        };
        let first = match dict.get("First").and_then(|v| v.resolve(doc)) {
            Some(Object::Int(i)) => *i as usize,
            _ => continue,
        };

        // The header is "objnum offset" pairs.
        let header = &decoded.data[..first.min(decoded.data.len())];
        let text = String::from_utf8_lossy(header);
        let mut pairs: Vec<(u32, usize)> = Vec::new();
        for line in text.split_whitespace() {
            if pairs.len() >= n {
                break;
            }
            if let Ok(o) = line.parse::<u32>() {
                pairs.push((o, 0));
            } else if let Ok(off) = line.parse::<usize>() {
                if let Some(last) = pairs.last_mut() {
                    last.1 = off;
                }
            }
        }

        for (obj_num, off) in pairs {
            if obj_num == 0 {
                continue;
            }
            let start = first + off;
            if start >= decoded.data.len() {
                continue;
            }
            let mut lexer = Lexer::new(&decoded.data[start..]);
            if let Ok(obj) = parse_value(&mut lexer, &decoded.data[start..], 0) {
                doc.objects.entry(obj_num).or_insert(obj);
            }
        }
    }
    Ok(())
}

/// Collect the set of object numbers that a document references but does
/// not define. A dangling reference is a real defect in a PDF and worth
/// reporting.
pub fn dangling_refs(doc: &Document) -> BTreeSet<u32> {
    let mut refs = BTreeSet::new();
    for obj in doc.objects.values() {
        collect_refs(obj, &mut refs);
    }
    let defined: BTreeSet<u32> = doc.objects.keys().copied().collect();
    refs.difference(&defined).copied().collect()
}

fn collect_refs(obj: &Object, out: &mut BTreeSet<u32>) {
    match obj {
        Object::Ref(r) => {
            out.insert(r.num);
        }
        Object::Array(a) => {
            for v in a {
                collect_refs(v, out);
            }
        }
        Object::Dict(d) => {
            for v in d.values() {
                collect_refs(v, out);
            }
        }
        Object::Stream { dict, .. } => {
            for v in dict.values() {
                collect_refs(v, out);
            }
        }
        _ => {}
    }
}
