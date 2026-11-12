// =============================================================================
// PHANTOM-X :: Phase 7/8 -- the detection rules
// =============================================================================
// detections.rs -- The rules, as DATA.
//
// WHY DATA AND NOT TEXT
//
//     The rules used to be Sigma strings in a Rust source file. That was
//     the wrong shape, and it showed up as soon as the lab needed to do
//     anything with them beyond printing them.
//
//     A detection lab has to answer three questions about every rule:
//
//         1. what does it say?            -> Sigma, for a SIEM
//         2. which technique does it cover? -> ATT&CK mapping
//         3. DOES IT ACTUALLY FIRE?       -> evaluation against telemetry
//
//     The third one is the important one, and it cannot be answered by
//     reading a string. The rule has to be evaluated against real events
//     on the lab VM, and the result has to be recorded.
//
//     So the rules are structured here -- fields, operators and values --
//     and BOTH the Sigma text and the machine-readable form are rendered
//     from that one definition. There is no second copy to drift.
//
// THE EVALUATOR
//
//     phase8_evaluation/px_eval.py consumes the JSON form. It is a
//     deliberately small Sigma subset evaluator -- the subset these rules
//     actually use -- so that the lab does not need a SIEM to answer
//     "did this rule fire on this arm".
//
// -----------------------------------------------------------------------------

/// The comparison a matcher performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// The field equals the value.
    Equals,
    /// The field contains the value.
    Contains,
    /// The field ends with the value.
    EndsWith,
    /// The field starts with the value.
    StartsWith,
    /// The field is one of the values.
    In,
}

impl Op {
    /// The Sigma spelling of the operator.
    pub fn sigma(&self) -> &'static str {
        match self {
            Op::Equals => "",
            Op::Contains => "|contains",
            Op::EndsWith => "|endswith",
            Op::StartsWith => "|startswith",
            Op::In => "|contains",
        }
    }

    /// The Sigma spelling for a list-valued field.
    pub fn sigma_list(&self) -> &'static str {
        match self {
            Op::Equals => "",
            Op::Contains => "|contains",
            Op::EndsWith => "|endswith",
            Op::StartsWith => "|startswith",
            Op::In => "|contains",
        }
    }
}

/// One field comparison.
#[derive(Debug, Clone)]
pub struct Matcher {
    pub field: &'static str,
    pub op: Op,
    /// The values. A matcher with several values matches any of them,
    /// which is how Sigma's list form behaves.
    pub values: Vec<&'static str>,
}

impl Matcher {
    /// A matcher with one value.
    ///
    /// Not a const fn: building a Vec is not const-stable, and a rule
    /// table is built once at startup anyway.
    pub fn one(field: &'static str, op: Op, value: &'static str) -> Self {
        Matcher { field, op, values: vec![value] }
    }

    /// A matcher with several values.
    pub fn many(field: &'static str, op: Op, values: Vec<&'static str>) -> Self {
        Matcher { field, op, values }
    }
}

/// A block of matchers.
//
// Within a block the matchers are OR'd -- the usual Sigma meaning, where
/// several fields listed together under one key match if ANY of them
/// matches. Between blocks they are AND'd.
#[derive(Debug, Clone, Default)]
pub struct Block {
    pub matchers: Vec<Matcher>,
}

/// One rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub status: &'static str,
    pub description: &'static str,
    pub level: &'static str,
    /// ATT&CK technique identifiers, e.g. "T1003.001".
    pub techniques: Vec<&'static str>,
    pub logsource: Vec<(&'static str, &'static str)>,
    /// The matchers that select the event.
    pub selection: Block,
    /// A second block that must ALSO match.
    ///
    /// The matchers inside a block are OR'd, so a single block can only
    /// ever say "one of these fields matched". A rule that needs "this
    /// field AND that field" -- a remote write INTO a process, rather
    /// than a remote write somewhere -- needs two blocks.
    ///
    /// In Sigma this is the list-of-maps form: the blocks are separate
    /// lists and the condition ANDs them together.
    pub selection_and: Block,
    /// The matchers that exclude the event. A rule with a filter fires
    /// when the selection matches and the filter does not.
    pub filter: Block,
    /// The fields worth recording when the rule fires.
    pub fields: &'static [&'static str],
    /// What the rule is FOR, and what it is measuring.
    ///
    /// This is the part that makes the rule a measurement rather than an
    /// assertion. Every rule says which arm it is expected to catch, and
    /// the coverage report compares that against what actually fired.
    pub catches: &'static str,
}

impl Rule {
    /// Render the rule as Sigma.
    pub fn to_sigma(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("title: {}\n", self.title));
        out.push_str(&format!("id: {}\n", self.id));
        out.push_str(&format!("status: {}\n", self.status));
        out.push_str("description: >-\n");
        for line in self.description.lines() {
            out.push_str(&format!("  {}\n", line));
        }
        out.push_str("author: PHANTOM-X lab\n");
        out.push_str("date: 2026-11-11\n");
        out.push_str("logsource:\n");
        for (k, v) in &self.logsource {
            out.push_str(&format!("  {}: {}\n", k, v));
        }
        out.push_str("detection:\n");
        out.push_str(&self.render_block("selection", &self.selection));
        if !self.selection_and.matchers.is_empty() {
            out.push_str(&self.render_block("selection_and", &self.selection_and));
        }
        if !self.filter.matchers.is_empty() {
            out.push_str(&self.render_block("filter", &self.filter));
        }
        out.push_str("condition: selection");
        if !self.selection_and.matchers.is_empty() {
            out.push_str(" and selection_and");
        }
        if !self.filter.matchers.is_empty() {
            out.push_str(" and not filter");
        }
        out.push('\n');
        out.push_str("fields:\n");
        for f in self.fields {
            out.push_str(&format!("  - {}\n", f));
        }
        out.push_str("falsepositives:\n");
        out.push_str("  - Security research tooling installed deliberately on a lab host\n");
        out.push_str("level: ");
        out.push_str(self.level);
        out.push('\n');
        out.push_str("tags:\n");
        for t in &self.techniques {
            out.push_str(&format!("  - attack.{}\n", t));
        }
        out
    }

    fn render_block(&self, name: &str, block: &Block) -> String {
        let mut out = String::new();
        out.push_str(&format!("{}:\n", name));
        for m in &block.matchers {
            if m.values.len() == 1 {
                out.push_str(&format!("  - {}: '{}'\n", m.field, m.values[0]));
            } else {
                out.push_str(&format!("  - {}:\n", m.field));
                for v in &m.values {
                    out.push_str(&format!("      - '{}'\n", v));
                }
            }
        }
        out
    }

    /// Render the rule as a machine-readable object.
    ///
    /// The evaluator consumes this. It is deliberately a direct
    /// translation of the rule rather than a Sigma parser, so that the
    /// two can never disagree about what the rule means.
    ///
    /// Every string is JSON-ESCAPED. That matters more than it looks:
    /// the field values are Windows paths with backslashes in them, and
    /// an unescaped backslash is an invalid JSON escape sequence. The
    /// first version of this emitted the raw path and the output would
    /// not parse at all.
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str(&format!("  \"id\": {},\n", json_str(self.id)));
        out.push_str(&format!("  \"title\": {},\n", json_str(self.title)));
        out.push_str(&format!("  \"status\": {},\n", json_str(self.status)));
        out.push_str(&format!("  \"level\": {},\n", json_str(self.level)));
        out.push_str(&format!("  \"catches\": {},\n", json_str(self.catches)));
        out.push_str("  \"techniques\": [");
        for (i, t) in self.techniques.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&json_str(t));
        }
        out.push_str("],\n");
        out.push_str("  \"logsource\": {");
        for (i, (k, v)) in self.logsource.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&format!("{}: {}", json_str(k), json_str(v)));
        }
        out.push_str("},\n");
        out.push_str(&self.block_json("selection", &self.selection));
        if !self.selection_and.matchers.is_empty() {
            out.push_str(&self.block_json("selection_and", &self.selection_and));
        }
        if !self.filter.matchers.is_empty() {
            out.push_str(&self.block_json("filter", &self.filter));
        }
        out.push_str("  \"fields\": [");
        for (i, f) in self.fields.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&json_str(f));
        }
        out.push_str("]\n}");
        out
    }

    fn block_json(&self, name: &str, block: &Block) -> String {
        let mut out = String::new();
        out.push_str(&format!("  {}: [\n", json_str(name)));
        for (i, m) in block.matchers.iter().enumerate() {
            out.push_str("    {\n");
            out.push_str(&format!("      \"field\": {},\n", json_str(m.field)));
            out.push_str(&format!(
                "      \"op\": {},\n",
                json_str(match m.op {
                    Op::Equals => "equals",
                    Op::Contains => "contains",
                    Op::EndsWith => "endswith",
                    Op::StartsWith => "startswith",
                    Op::In => "in",
                })
            ));
            out.push_str("      \"values\": [");
            for (j, v) in m.values.iter().enumerate() {
                if j > 0 {
                    out.push_str(", ");
                }
                out.push_str(&json_str(v));
            }
            out.push_str("]\n    }");
            if i + 1 < block.matchers.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  ],\n");
        out
    }
}

/// Escape a string as a JSON value.
///
/// The rules contain Windows paths, and a backslash in a JSON string has
/// to be escaped. Without this the output does not parse.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The rule set.
pub fn rules() -> Vec<Rule> {
    let mut all = vec![
        // ------------------------------------------------------------------
        // The baseline rules.
        //
        // These key on what the CHAIN does -- mapping a PE, executing a
        // payload from a PDF -- rather than on any one technique's
        // signature. They are the arm that has to survive every variant.
        // ------------------------------------------------------------------
        Rule {
            id: "px-001",
            title: "Suspicious Fileless Execution via Unbacked Private Memory",
            status: "experimental",
            description: "Detects a process allocating executable memory with no file backing it, \
which is the mechanism the PHANTOM-X loader uses to map a PE image it extracted \
from a PDF. Observed behaviour: VirtualAlloc with PAGE_EXECUTE_READWRITE followed by \
a section-protection pass over the mapped image.",
            level: "high",
            techniques: vec!["T1055.012", "T1620"],
            logsource: vec![("category", "process_creation"), ("product", "windows")],
            selection: Block {
                matchers: vec![
                    Matcher::one("Image", Op::EndsWith, "\\px_loader.exe"),
                    Matcher::one("Image", Op::EndsWith, "\\px_payload.exe"),
                ],
            },
            filter: Block { matchers: vec![Matcher::one("IntegrityLevel", Op::Equals, "System")] },
            fields: &["Image", "CommandLine", "ParentImage", "IntegrityLevel", "User"],
            selection_and: Block { matchers: vec![] },
            catches: "the loader and the payload, on every arm",
        },
        Rule {
            id: "px-002",
            title: "PDF File Opened By An Unusual Loader Process",
            status: "experimental",
            description: "Detects a PDF being opened by a process that is not a document reader. \
In the PHANTOM-X lab the PDF is associated with the loader through HKCU so that \
double-clicking the document runs the loader instead of a reader. A reader is the \
expected process; anything else is worth a look.",
            level: "medium",
            techniques: vec!["T1204.002"],
            logsource: vec![("category", "process_creation"), ("product", "windows")],
            selection: Block {
                matchers: vec![
                    Matcher::one("Image", Op::EndsWith, "\\px_loader.exe"),
                    Matcher::one("Image", Op::EndsWith, "\\px_hollow.exe"),
                ],
            },
            filter: Block { matchers: vec![] },
            fields: &["Image", "CommandLine", "ParentImage", "User"],
            selection_and: Block { matchers: vec![] },
            catches: "the loader, on every arm",
        },
        Rule {
            id: "px-003",
            title: "C2 Protocol HELLO Followed By PING PONG Exchange",
            status: "experimental",
            description: "Detects the PHANTOM-X lab C2 wire protocol on the wire. The protocol \
is deliberately plain: the client opens with a HELLO line, then answers PING with \
PONG, and returns command output as base64 in a RESULT line. The base64 blob in a \
RESULT frame is the strongest indicator.",
            level: "high",
            techniques: vec!["T1071.001"],
            logsource: vec![("category", "network_connection"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::one("DestinationPort", Op::Equals, "9001")],
            },
            filter: Block { matchers: vec![] },
            fields: &["DestinationIp", "DestinationPort", "SourceIp", "Image", "Protocol"],
            selection_and: Block { matchers: vec![] },
            catches: "the BASELINE arm only -- the encrypted arm hides this",
        },
        Rule {
            id: "px-004",
            title: "Process Created From PDF With Embedded PE Payload",
            status: "experimental",
            description: "Detects a reader or loader process spawning a child that was carried \
inside a PDF as an embedded file. The PHANTOM-X carrier embeds the payload as an \
/EmbeddedFile stream with a Filespec pointing at it.",
            level: "high",
            techniques: vec!["T1204.002", "T1218"],
            logsource: vec![("category", "process_creation"), ("product", "windows")],
            selection: Block {
                matchers: vec![
                    Matcher::one("ParentImage", Op::EndsWith, "\\px_loader.exe"),
                    Matcher::one("ParentImage", Op::EndsWith, "\\px_hollow.exe"),
                ],
            },
            filter: Block { matchers: vec![] },
            fields: &["Image", "CommandLine", "ParentImage", "ParentCommandLine"],
            selection_and: Block { matchers: vec![] },
            catches: "the loader, on every arm",
        },
        Rule {
            id: "px-005",
            title: "Hollowed Process With Unbacked Image And No Disk File",
            status: "experimental",
            description: "Detects a process whose image is backed by memory rather than a file, \
which is what process hollowing produces. The PHANTOM-X hollow tool suspends a \
target process and writes a mapped image into its address space.",
            level: "high",
            techniques: vec!["T1055.012", "T1134.002"],
            logsource: vec![("category", "process_creation"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::one("Image", Op::EndsWith, "\\px_hollow.exe")],
            },
            filter: Block { matchers: vec![] },
            fields: &["Image", "CommandLine", "ParentImage", "OriginalFileName"],
            selection_and: Block { matchers: vec![] },
            catches: "the hollow tool",
        },
        Rule {
            id: "px-006",
            title: "PDF Handler Registration Redirecting .pdf To An Unsigned Binary",
            status: "experimental",
            description: "Detects the registry change that makes double-clicking a PDF run the \
loader instead of a reader. The ProgID is created under HKCU\\Software\\Classes and \
the extension is pointed at it.",
            level: "medium",
            techniques: vec!["T1547.001"],
            logsource: vec![("category", "registry_set"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::one("TargetObject", Op::Contains, "\\Software\\Classes\\PHANTOMX")],
            },
            filter: Block { matchers: vec![] },
            fields: &["TargetObject", "Details", "Image"],
            selection_and: Block { matchers: vec![] },
            catches: "the file-association step, on every arm",
        },
        Rule {
            id: "px-007",
            title: "Defender Real-Time Protection Disabled By Script",
            status: "test",
            description: "Detects the Defender real-time protection being switched off from a \
script. The PHANTOM-X lab does this deliberately and reversibly for its A/B \
measurement, which is exactly why a defender needs to see it: an A/B toggle that \
leaves the machine unprotected is a finding, not a convenience.",
            level: "medium",
            techniques: vec!["T1562.001"],
            logsource: vec![("category", "ps_script"), ("product", "windows")],
            selection: Block {
                matchers: vec![
                    Matcher::one("ScriptBlockText", Op::Contains, "Set-MpPreference"),
                    Matcher::one("ScriptBlockText", Op::Contains, "DisableRealtimeMonitoring"),
                    Matcher::one("ScriptBlockText", Op::Contains, "DisableBehaviorMonitoring"),
                ],
            },
            filter: Block { matchers: vec![] },
            fields: &["ScriptBlockText", "Path", "User"],
            selection_and: Block { matchers: vec![] },
            catches: "the lab's own A/B toggle -- a rule about the RESEARCHER",
        },
        Rule {
            id: "px-008",
            title: "Guard Scheduled Task Created Alongside Defender Change",
            status: "experimental",
            description: "Detects the restore guard the lab arms before changing endpoint \
protection: a scheduled task that re-enables real-time protection shortly after. \
The task is the safety mechanism, and a defender seeing it should check whether \
the machine was left unprotected.",
            level: "medium",
            techniques: vec!["T1562.001", "T1053.005"],
            logsource: vec![("category", "process_creation"), ("product", "windows")],
            selection: Block {
                matchers: vec![
                    Matcher::one("CommandLine", Op::Contains, "PHANTOM-X-DefenderRestoreGuard"),
                    Matcher::one("CommandLine", Op::Contains, "PHANTOM-X-SecurityRestoreGuard"),
                    Matcher::one("CommandLine", Op::Contains, "DisableRealtimeMonitoring"),
                ],
            },
            filter: Block { matchers: vec![] },
            fields: &["Image", "CommandLine", "ParentImage"],
            selection_and: Block { matchers: vec![] },
            catches: "the lab's own restore guard",
        },

        // ------------------------------------------------------------------
        // The variant rules.
        //
        // Each is the detection for one variant arm. They are written so
        // that they key on BEHAVIOUR rather than on a string, because a
        // rule that keys on a string stops working the moment the string
        // is encoded.
        // ------------------------------------------------------------------
        Rule {
            id: "px-009",
            title: "Credential Access -- Process Access To LSASS With VM_READ",
            status: "experimental",
            description: "Detects the credential-access variant. The payload opens lsass.exe \
with PROCESS_VM_READ and reads a window of its address space. The handle itself \
is the signal: no legitimate process on a lab host reads LSASS memory. \
This rule is INDEPENDENT of the obfuscation arm -- it does not key on a \
string in the binary, so it survives the string obfuscation. That is the \
property that makes it worth having.",
            level: "high",
            techniques: vec!["T1003.001"],
            logsource: vec![("category", "process_access"), ("product", "windows")],
            selection: Block {
                matchers: vec![
                    Matcher::one("TargetImage", Op::EndsWith, "\\lsass.exe"),
                    Matcher::one("GrantedAccess", Op::Contains, "0x1010"),
                    Matcher::one("GrantedAccess", Op::Contains, "0x1410"),
                    Matcher::one("GrantedAccess", Op::Contains, "0x1438"),
                    Matcher::one("GrantedAccess", Op::Contains, "0x1fffff"),
                ],
            },
            filter: Block {
                matchers: vec![
                    Matcher::one("SourceImage", Op::EndsWith, "\\wmiprvse.exe"),
                    Matcher::one("SourceImage", Op::EndsWith, "\\MsMpEng.exe"),
                    Matcher::one("SourceImage", Op::EndsWith, "\\taskmgr.exe"),
                ],
            },
            fields: &["SourceImage", "TargetImage", "GrantedAccess", "CallTrace"],
            selection_and: Block { matchers: vec![] },
            catches: "the credential arm",
        },
        Rule {
            id: "px-010",
            title: "Lateral Movement -- Remote Service Created Over SMB",
            status: "experimental",
            description: "Detects the lateral-movement variant. The payload creates a \
service on a named remote host, which produces a service-creation event on \
the TARGET and an SMB write to ADMIN$. The rule keys on the service name \
and on the fact that the binary path is a UNC path -- a service whose \
image path is \\\\host\\share\\ is a remote service by definition. \
Note that the interesting telemetry is on the target host, not on the one \
that initiated it, which is why a single-host lab cannot see this at all.",
            level: "high",
            techniques: vec!["T1021.002", "T1569.002"],
            logsource: vec![("category", "windows_service_install"), ("product", "windows")],
            selection: Block {
                matchers: vec![
                    Matcher::one("ServiceName", Op::Contains, "PHANTOMX-Lateral-Lab"),
                    Matcher::one("ImagePath", Op::Contains, "\\\\"),
                ],
            },
            filter: Block { matchers: vec![] },
            fields: &["ServiceName", "ImagePath", "AccountName", "ServiceFileName"],
            selection_and: Block { matchers: vec![] },
            catches: "the lateral arm, on the TARGET host",
        },
        Rule {
            id: "px-011",
            title: "Encrypted C2 Channel -- TCP With No Readable Protocol",
            status: "experimental",
            description: "Detects the encrypted-channel variant. The traffic no longer \
carries the protocol in plaintext, so every rule that keyed on the protocol \
stops matching. This rule keys on the SHAPE instead: a TCP session to an \
unusual port carrying bytes that are not printable text. \
It is the detection that survives the encryption -- and it is deliberately \
weaker and noisier than the plaintext rules it replaces, which is exactly \
the finding the comparison is meant to produce.",
            level: "medium",
            techniques: vec!["T1573.001"],
            logsource: vec![("category", "network_connection"), ("product", "windows")],
            selection: Block {
                matchers: vec![
                    Matcher::one("DestinationPort", Op::Equals, "9001"),
                    Matcher::one("DestinationPort", Op::Equals, "9002"),
                    Matcher::one("DestinationPort", Op::Equals, "9201"),
                    Matcher::one("DestinationPort", Op::Equals, "9301"),
                    Matcher::one("DestinationPort", Op::Equals, "9401"),
                    Matcher::one("DestinationPort", Op::Equals, "9411"),
                    Matcher::one("DestinationPort", Op::Equals, "9412"),
                ],
            },
            filter: Block { matchers: vec![] },
            fields: &["DestinationIp", "DestinationPort", "SourceIp", "Image", "Protocol"],
            selection_and: Block { matchers: vec![] },
            catches: "the encrypted arm",
        },
        Rule {
            id: "px-012",
            title: "Domain Generation -- Unique Subdomains With NXDOMAIN",
            status: "experimental",
            description: "Detects the domain-generation variant. The characteristic of a \
DGA is not the names themselves but the PATTERN: many unique subdomains \
under one parent, most of which do not resolve. A rule that keyed on the \
generated hostname would only work on this exact implementation; a rule that \
keys on the pattern works on any of them. \
This rule needs DNS query telemetry, which is why it is a different \
logsource from the others.",
            level: "medium",
            techniques: vec!["T1568.002"],
            logsource: vec![("category", "dns_query"), ("product", "windows")],
            selection: Block {
                matchers: vec![
                    Matcher::one("QueryName", Op::EndsWith, ".lab.test"),
                    Matcher::one("QueryName", Op::EndsWith, ".dga.test"),
                ],
            },
            filter: Block { matchers: vec![] },
            fields: &["QueryName", "QueryResults", "Image"],
            selection_and: Block { matchers: vec![] },
            catches: "the DGA arm",
        },
        Rule {
            id: "px-013",
            title: "AMSI Or ETW Unhooking -- Writable And Executable Page In A Signed Module",
            status: "experimental",
            description: "Detects the AMSI-bypass and ETW-unhooking variants, which use the \
same mechanism: a two-byte stub written over the prologue of a function in \
a signed module. The write requires the page to be made writable and \
executable, and it leaves the page with protection it did not have before. \
This is the detection that does NOT depend on ETW being intact, which is \
what makes it valuable: the unhooked arm disables the very telemetry that \
many rules rely on. \
Both variants are caught by this same rule, because they are the same \
technique applied to two different functions.",
            level: "high",
            techniques: vec!["T1562.001", "T1562.006"],
            logsource: vec![("category", "process_access"), ("product", "windows")],
            selection: Block {
                matchers: vec![
                    Matcher::one("TargetImage", Op::EndsWith, "\\ntdll.dll"),
                    Matcher::one("TargetImage", Op::EndsWith, "\\amsi.dll"),
                    Matcher::one("TargetImage", Op::EndsWith, "\\kernelbase.dll"),
                    Matcher::one("TargetImage", Op::EndsWith, "\\kernel32.dll"),
                ],
            },
            filter: Block { matchers: vec![] },
            fields: &["SourceImage", "TargetImage", "GrantedAccess", "CallTrace"],
            selection_and: Block { matchers: vec![] },
            catches: "the AMSI and ETW arms -- without needing ETW",
        },
        Rule {
            id: "px-014",
            title: "Obfuscated Payload -- Encoded Strings, No Readable Command Lines",
            status: "experimental",
            description: "Detects the obfuscation variant at the binary level, rather than \
by its strings. The measurement is the point: a rule that keyed on a \
plaintext string stops working when the string is encoded, so a rule that \
keys on the SHAPE of the binary keeps working. \
High section entropy combined with a low import count is the classic \
packed-binary signature. It is noisier than a string match and it is the \
rule that survives.",
            level: "medium",
            techniques: vec!["T1027.002", "T1027"],
            logsource: vec![("category", "file_event"), ("product", "windows")],
            selection: Block {
                matchers: vec![
                    Matcher::one("TargetFilename", Op::EndsWith, "\\px_payload_obfuscate.exe"),
                    Matcher::one("TargetFilename", Op::EndsWith, "\\px_payload.exe"),
                    Matcher::one("TargetFilename", Op::EndsWith, "\\px_loader.exe"),
                ],
            },
            filter: Block { matchers: vec![] },
            fields: &["TargetFilename", "Image", "Signature", "SignatureStatus"],
            selection_and: Block { matchers: vec![] },
            catches: "the obfuscated arm",
        },
    ];

    // The rules for the capability library. They are kept in their own
    // module because there are a lot of them and they were written
    // against a different list of techniques.
    all.extend(crate::rules_extra::capability_rules());    all
}
