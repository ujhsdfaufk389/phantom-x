// =============================================================================
// PHANTOM-X :: Phase 1 -- px_pdfscan (Rust)
// =============================================================================
// px_pdfscan -- Read-only PDF structure and action scanner.
//
// This is the independent Rust implementation of the Phase 1 inspection,
// written to cross-validate the Python inspector (pdf_inspector.py). The
// two are compared by validate_cross_impl.py.
//
// READ-ONLY. The scanner never writes to a PDF and never executes anything
// it finds. Embedded files are reported, not launched.
//
// USAGE
//     px_pdfscan <file.pdf> [...]              human-readable report
//     px_pdfscan --json <file.pdf> [...]       JSON report
//     px_pdfscan --quiet <file.pdf> [...]       one line per file
//
// BUILD
//     cargo build --release
//     # a fully static binary for the lab VM:
//     rustup target add x86_64-pc-windows-msvc
// =============================================================================

mod analysis;
mod parser;
mod scanner;
mod sha256;

use analysis::{analyze, Inventory};
use std::fmt::Write as _;

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut json = false;
    let mut quiet = false;
    let mut files: Vec<String> = Vec::new();

    for a in &args {
        match a.as_str() {
            "--json" => json = true,
            "--quiet" => quiet = true,
            "--help" | "-h" => {
                print_usage();
                return std::process::ExitCode::SUCCESS;
            }
            other => files.push(other.to_string()),
        }
    }

    if files.is_empty() {
        print_usage();
        return std::process::ExitCode::from(2);
    }

    let mut failed = false;
    let mut reports: Vec<(String, String, Inventory, Vec<String>)> = Vec::new();

    for path in &files {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[!] cannot read {}: {}", path, e);
                failed = true;
                continue;
            }
        };

        let doc = match parser::parse(&data) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[!] {}: {}", path, e);
                failed = true;
                continue;
            }
        };

        let inv = analyze(&doc);
        let dangling: Vec<String> = parser::dangling_refs(&doc)
            .iter()
            .map(|n| n.to_string())
            .collect();

        if quiet {
            println!(
                "{}\t{}\tactions={}\tjs={}\tembedded={}\texternal={}",
                path,
                sha256::hex(&data),
                inv.actions.len(),
                inv.scripts.len(),
                inv.embedded_files.len(),
                inv.external_refs.len()
            );
        } else if json {
            reports.push((path.clone(), sha256::hex(&data), inv, dangling));
        } else {
            print_report(path, &data, &doc, &inv, &dangling);
        }
    }

    if json {
        println!("{}", build_json(&reports));
    }

    if failed {
        std::process::ExitCode::from(1)
    } else {
        std::process::ExitCode::SUCCESS
    }
}

fn print_usage() {
    eprintln!(
        "px_pdfscan -- PHANTOM-X read-only PDF structure and action scanner\n\n\
         USAGE:\n    \
         px_pdfscan <file.pdf> [...]          human-readable report\n    \
         px_pdfscan --json <file.pdf> [...]   JSON report\n    \
         px_pdfscan --quiet <file.pdf> [...]   one line per file\n"
    );
}

fn print_report(
    path: &str,
    data: &[u8],
    doc: &scanner::Document,
    inv: &Inventory,
    dangling: &[String],
) {
    println!("{}", "=".repeat(78));
    println!("PHANTOM-X :: PDF SCAN (Rust) -- {}", path);
    println!("{}", "=".repeat(78));
    println!("size          : {} bytes", data.len());
    println!("sha256        : {}", sha256::hex(data));
    println!("pdf version   : {}   encrypted: {}", doc.version, doc.encrypted);
    println!(
        "objects       : {}   xref: {}   streams decoded: {}/{}",
        inv.object_count, doc.xref_type, inv.streams_decoded, inv.streams_seen
    );
    println!(
        "pages         : {}   annotations: {}   form fields: {}",
        inv.page_count,
        inv.annotations.len(),
        inv.form_fields.len()
    );

    if !dangling.is_empty() {
        println!();
        println!("{}", format!("-- DANGLING REFERENCES {}", "-".repeat(53)));
        for d in dangling {
            println!("  object {} is referenced but not defined", d);
        }
    }

    if !inv.actions.is_empty() {
        println!();
        println!("{}", format!("-- ACTIONS {}", "-".repeat(66)));
        for a in &inv.actions {
            println!(
                "  {:<12} @ {:<40} interaction: {}",
                a.action_type, a.location, a.requires_interaction
            );
            for (k, v) in &a.parameters {
                println!("        {}: {}", k, v);
            }
        }
    }

    if !inv.scripts.is_empty() {
        println!();
        println!("{}", format!("-- JAVASCRIPT {}", "-".repeat(64)));
        for s in &inv.scripts {
            println!(
                "  @ {}  len={}  sha256={}",
                s.location,
                s.length,
                &s.sha256[..16.min(s.sha256.len())]
            );
            for line in s.preview.lines().take(20) {
                println!("      | {}", line);
            }
        }
    }

    if !inv.embedded_files.is_empty() {
        println!();
        println!("{}", format!("-- EMBEDDED FILES {}", "-".repeat(61)));
        for e in &inv.embedded_files {
            println!(
                "  {}  {} bytes  @ {}",
                e.name, e.size, e.location
            );
            println!("      identified : {}", e.identified_as);
            println!("      sha256     : {}", e.sha256);
            println!("      entropy    : {:.3}", e.entropy);
            if e.is_pe {
                println!("      !! this is a PE image -- a Windows executable");
            }
        }
    }

    if !inv.external_refs.is_empty() {
        println!();
        println!("{}", format!("-- EXTERNAL REFERENCES {}", "-".repeat(56)));
        for r in &inv.external_refs {
            println!("  [{}] {}  @ {}", r.kind, r.target, r.location);
        }
    }

    if !inv.annotations.is_empty() {
        println!();
        println!("{}", format!("-- ANNOTATIONS {}", "-".repeat(63)));
        for a in &inv.annotations {
            println!(
                "  {:<18} @ {:<32} action: {}",
                a.subtype, a.location, a.has_action
            );
        }
    }

    println!();
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn build_json(reports: &[(String, String, Inventory, Vec<String>)]) -> String {
    let mut out = String::from("[\n");
    for (i, (path, sha, inv, dangling)) in reports.iter().enumerate() {
        let _ = write!(out, "  {{\n");
        let _ = write!(out, "    \"file\": \"{}\",\n", json_escape(path));
        let _ = write!(out, "    \"sha256\": \"{}\",\n", sha);
        let _ = write!(out, "    \"object_count\": {},\n", inv.object_count);
        let _ = write!(out, "    \"page_count\": {},\n", inv.page_count);
        let _ = write!(out, "    \"streams_seen\": {},\n", inv.streams_seen);
        let _ = write!(out, "    \"streams_decoded\": {},\n", inv.streams_decoded);

        let _ = write!(out, "    \"actions\": [");
        for (j, a) in inv.actions.iter().enumerate() {
            if j > 0 {
                let _ = write!(out, ",");
            }
            let _ = write!(out, "\n      {{\"type\": \"{}\", \"location\": \"{}\", \"requires_interaction\": {}}}",
                json_escape(&a.action_type),
                json_escape(&a.location),
                a.requires_interaction);
        }
        let _ = write!(out, "\n    ],\n");

        let _ = write!(out, "    \"javascript\": [");
        for (j, s) in inv.scripts.iter().enumerate() {
            if j > 0 {
                let _ = write!(out, ",");
            }
            let _ = write!(out, "\n      {{\"location\": \"{}\", \"length\": {}, \"sha256\": \"{}\"}}",
                json_escape(&s.location), s.length, s.sha256);
        }
        let _ = write!(out, "\n    ],\n");

        let _ = write!(out, "    \"embedded_files\": [");
        for (j, e) in inv.embedded_files.iter().enumerate() {
            if j > 0 {
                let _ = write!(out, ",");
            }
            let _ = write!(out, "\n      {{\"name\": \"{}\", \"size\": {}, \"sha256\": \"{}\", \"identified_as\": \"{}\", \"is_pe\": {}, \"entropy\": {:.4}}}",
                json_escape(&e.name), e.size, e.sha256,
                json_escape(&e.identified_as), e.is_pe, e.entropy);
        }
        let _ = write!(out, "\n    ],\n");

        let _ = write!(out, "    \"external_references\": [");
        for (j, r) in inv.external_refs.iter().enumerate() {
            if j > 0 {
                let _ = write!(out, ",");
            }
            let _ = write!(out, "\n      {{\"kind\": \"{}\", \"target\": \"{}\", \"location\": \"{}\"}}",
                json_escape(&r.kind), json_escape(&r.target), json_escape(&r.location));
        }
        let _ = write!(out, "\n    ],\n");

        let _ = write!(out, "    \"dangling_refs\": [");
        for (j, d) in dangling.iter().enumerate() {
            if j > 0 {
                let _ = write!(out, ",");
            }
            let _ = write!(out, "\"{}\"", d);
        }
        let _ = write!(out, "]\n  }}");
        if i + 1 < reports.len() {
            let _ = write!(out, ",");
        }
        let _ = write!(out, "\n");
    }
    out.push(']');
    out
}
