// =============================================================================
// PHANTOM-X :: Phase 7 -- px_detect
// =============================================================================
// px_detect -- emit the defensive detection rules for the PHANTOM-X chain.
//
// This is the defender-side deliverable of the lab. The chain exists to
// produce a signal; these rules are what turn that signal into an alert.
//
// WHY A BINARY INSTEAD OF A YAML FILE
//     The rules are generated so that the behaviour each one keys on can be
//     stated next to the rule itself, in the same source file, with the
//     observation that justifies it. A reviewer can read one file and know
//     exactly why every rule exists.
//
// USAGE
//     px_detect --emit sigma     write the Sigma rules to stdout
//     px_detect --emit json      write them as a JSON array
//     px_detect --list           list rule ids and titles
//     px_detect --explain <id>   print the reasoning for one rule
// =============================================================================

mod catalog;
mod detections;
mod rules_extra;

use detections::Rule;
use std::process::ExitCode;

const USAGE: &str = "\
px_detect -- PHANTOM-X defensive detection rules

USAGE:
    px_detect --emit sigma       write the Sigma rules to stdout
    px_detect --emit json        write a JSON array of rule metadata
    px_detect --emit catalog     write the technique catalogue as JSON
    px_detect --list             list rule ids and titles
    px_detect --catalog          print the technique catalogue as a table
    px_detect --catalog-summary  count what the lab measures and what it does not
    px_detect --explain <id>     print the reasoning behind one rule
    px_detect --help             this text
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print!("{}", USAGE);
        return ExitCode::from(2);
    }

    match args[1].as_str() {
        "--help" | "-h" => {
            print!("{}", USAGE);
            ExitCode::SUCCESS
        }
        "--emit" => {
            let format = args.get(2).map(|s| s.as_str()).unwrap_or("sigma");
            match format {
                "sigma" => {
                    for r in detections::rules() {
                        print!("{}", r.to_sigma());
                        println!("---");
                    }
                    ExitCode::SUCCESS
                }
                "catalog" => {
                    // The technique catalogue. It is the other half of
                    // the coverage story: the rules say what can be
                    // detected, the catalogue says what the lab does
                    // and, more usefully, what it does not.
                    print!("{}", catalog::catalog_json());
                    ExitCode::SUCCESS
                }
                "json" => {
                    // The machine-readable form, consumed by the rule
                    // evaluator in phase8_evaluation. It is a direct
                    // translation of the same definition the Sigma text
                    // is rendered from, so the two cannot disagree.
                    println!("[");
                    let rules = detections::rules();
                    for (i, r) in rules.iter().enumerate() {
                        print!("{}", r.to_json());
                        if i + 1 < rules.len() {
                            println!(",");
                        } else {
                            println!();
                        }
                    }
                    println!("]");
                    ExitCode::SUCCESS
                }
                other => {
                    eprintln!("unknown format: {}\n", other);
                    ExitCode::from(2)
                }
            }
        }
        "--list" => {
            for r in detections::rules() {
                println!("{:<8} {:<10} {}", r.id, r.level, r.title);
            }
            ExitCode::SUCCESS
        }
        "--catalog" => {
            print!("{}", catalog::catalog_table());
            ExitCode::SUCCESS
        }
        "--catalog-summary" => {
            let entries = catalog::catalog();
            let mut measured = 0;
            let mut ruled = 0;
            let mut not_exercised = 0;
            let mut campaigns = 0;
            for t in &entries {
                match t.status() {
                    "measured" => measured += 1,
                    "ruled" => ruled += 1,
                    _ => not_exercised += 1,
                }
                if t.kind == "campaign" {
                    campaigns += 1;
                }
            }
            println!("PHANTOM-X :: THE CATALOGUE");
            println!();
            println!("  techniques in scope : {}", entries.len());
            println!("  measured            : {}", measured);
            println!("  ruled only          : {}", ruled);
            println!("  not exercised       : {}", not_exercised);
            println!("  of which campaigns  : {}", campaigns);
            println!();
            println!("  A rule that has never fired is a hypothesis. The 'ruled only'");
            println!("  line is where the lab is honest about that.");
            ExitCode::SUCCESS
        }
        "--explain" => {
            let want = match args.get(2) {
                Some(s) => s.to_lowercase(),
                None => {
                    eprintln!("--explain needs a rule id\n");
                    return ExitCode::from(2);
                }
            };
            match detections::rules().iter().find(|r| r.id.to_lowercase() == want) {
                Some(r) => {
                    print_rule(r);
                    ExitCode::SUCCESS
                }
                None => {
                    eprintln!("no such rule: {}\n", want);
                    ExitCode::from(1)
                }
            }
        }
        other => {
            eprintln!("unknown argument: {}\n\n{}", other, USAGE);
            ExitCode::from(2)
        }
    }
}

fn print_rule(r: &Rule) {
    println!("id          : {}", r.id);
    println!("title       : {}", r.title);
    println!("status      : {}", r.status);
    println!("level       : {}", r.level);
    println!("tags        : {}", r.techniques.join(", "));
    println!("catches     : {}", r.catches);
    println!("logsource   :");
    for (k, v) in &r.logsource {
        println!("  {}: {}", k, v);
    }
    println!("\nwhy this rule exists:\n{}", r.description);
    println!("\nkeyed on:");
    for f in r.fields {
        println!("  - {}", f);
    }
}
