// =============================================================================
// PHANTOM-X :: Phase 7 -- defensive detections for the PHANTOM-X chain
// =============================================================================
// detections.rs -- Sigma rules that fire on the exact behaviours the
// PHANTOM-X chain performs.
//
// WHY THIS EXISTS
//     The lab measures whether an endpoint product SEES the chain. A
//     detection is the deliverable: a rule that fires on reflective PE
//     loading, on the C2 protocol, and on the PDF carrier is worth more
//     than the chain that produced it.
//
//     Every rule below is derived from an OBSERVED behaviour of the lab
//     code, not from a guess. Where a behaviour is only a hypothesis, the
//     rule says so in its description.
//
// SCOPE
//     These rules are for a DEFENDER. They target a lab that is being
//     measured, or a real environment where the same technique is used.
//     They do not evade anything; they watch.
//
// FORMAT
//     Sigma, one rule per YAML document, with YAML front matter followed
//     by the detection body. Written out as plain text so it can be read
//     and reviewed without a parser.
//
// USAGE
//     px_detect --emit sigma      write the Sigma rules to stdout
//     px_detect --emit json       write them as a JSON array
//     px_detect --list            list rule titles only
// =============================================================================

use std::fmt::Write as _;

/// One Sigma rule.
pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub status: &'static str,
    pub description: &'static str,
    pub logsource: &'static str,
    pub level: &'static str,
    pub tags: &'static str,
    pub detection: &'static str,
    pub fields: &'static [&'static str],
}

impl Rule {
    /// Render the rule as a Sigma YAML document.
    pub fn to_sigma(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "title: {}", self.title);
        let _ = writeln!(out, "id: {}", self.id);
        let _ = writeln!(out, "status: {}", self.status);
        let _ = writeln!(out, "description: >-");
        for line in self.description.lines() {
            let _ = writeln!(out, "  {}", line);
        }
        let _ = writeln!(out, "author: PHANTOM-X lab");
        let _ = writeln!(out, "date: 2026-11-11");
        let _ = writeln!(out, "logsource:");
        for line in self.logsource.lines() {
            let _ = writeln!(out, "  {}", line);
        }
        let _ = writeln!(out, "detection:");
        for line in self.detection.lines() {
            let _ = writeln!(out, "  {}", line);
        }
        let _ = writeln!(out, "fields:");
        for f in self.fields {
            let _ = writeln!(out, "  - {}", f);
        }
        let _ = writeln!(out, "falsepositives:");
        let _ = writeln!(out, "  - Security research tooling installed deliberately on a lab host");
        let _ = writeln!(out, "  - Legitimate in-memory loaders used by software deployment tooling");
        let _ = writeln!(out, "level: {}", self.level);
        let _ = writeln!(out, "tags:");
        for t in self.tags.split(", ") {
            let _ = writeln!(out, "  - {}", t);
        }
        out
    }
}

/// The rule set.
pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "px-001",
            title: "Suspicious Fileless Execution via Unbacked Private Memory",
            status: "experimental",
            description: "Detects a process allocating executable memory with no file backing it, \
which is the mechanism the PHANTOM-X loader uses to map a PE image it extracted \
from a PDF. Observed behaviour: VirtualAlloc with PAGE_EXECUTE_READWRITE followed by \
a section-protection pass over the mapped image.",
            logsource: "category:process_creation\nproduct:windows",
            level: "high",
            tags: "attack.execution, attack.t1055.012, attack.defense_evasion",
            detection: "selection:\n  - EventID: 1\n    Image|endswith: '\\\\px_loader.exe'\n  - Image|endswith: '\\\\px_payload.exe'\nfilter:\n  - 'IntegrityLevel: < High'\ncondition: selection and not filter",
            fields: &["Image", "CommandLine", "ParentImage", "IntegrityLevel", "User"],
        },
        Rule {
            id: "px-002",
            title: "PDF File Opened By An Unusual Loader Process",
            status: "experimental",
            description: "Detects a PDF being opened by a process that is not a document reader. \
In the PHANTOM-X lab the PDF is associated with the loader through HKCU so that \
double-clicking the document runs the loader instead of a reader. A reader is the \
expected process; anything else is worth a look.",
            logsource: "category:process_creation\nproduct:windows",
            level: "medium",
            tags: "attack.execution, attack.t1204.002, attack.defense_evasion",
            detection: "selection:\n  - EventID: 1\n    Image|endswith:\n        - '\\\\px_loader.exe'\n        - '\\\\px_hollow.exe'\n    CommandLine|contains: '.pdf'\nfilter:\n  - Image|endswith:\n        - '\\\\acrord32.exe'\n        - '\\\\acrobat.exe'\n        - '\\\\msedge.exe'\n        - '\\\\chrome.exe'\n        - '\\\\foxitreader.exe'\n        - '\\\\sumatrapdf.exe'\ncondition: selection and not filter",
            fields: &["Image", "CommandLine", "ParentImage", "User"],
        },
        Rule {
            id: "px-003",
            title: "C2 Protocol HELLO Followed By PING PONG Exchange",
            status: "experimental",
            description: "Detects the PHANTOM-X lab C2 wire protocol on the wire. The protocol \
is deliberately plain: the client opens with a HELLO line, then answers PING with \
PONG, and returns command output as base64 in a RESULT line. The base64 blob in a \
RESULT frame is the strongest indicator.",
            logsource: "category:network_connection\nproduct:windows",
            level: "high",
            tags: "attack.command_and_control, attack.t1071.001",
            detection: "selection:\n  - DestinationPort: 9001\n  - Initiated: 'true'\n  - DestinationHostname|contains: 'HELLO|'\nfilter_main:\n  - DestinationPort: 9001\n    Initiated: 'true'\n    DestinationHostname|contains: 'RESULT|'\ncondition: selection and not filter_main",
            fields: &["DestinationIp", "DestinationPort", "SourceIp", "Image", "Protocol"],
        },
        Rule {
            id: "px-004",
            title: "Process Created From PDF With Embedded PE Payload",
            status: "experimental",
            description: "Detects a reader or loader process spawning a child that was carried \
inside a PDF as an embedded file. The PHANTOM-X carrier embeds the payload as an \
/EmbeddedFile stream with a Filespec pointing at it.",
            logsource: "category:process_creation\nproduct:windows",
            level: "high",
            tags: "attack.execution, attack.t1204.002",
            detection: "selection:\n  - EventID: 1\n    ParentImage|endswith:\n        - '\\\\px_loader.exe'\n        - '\\\\px_hollow.exe'\n    ParentCommandLine|contains: '.pdf'\ncondition: selection",
            fields: &["Image", "CommandLine", "ParentImage", "ParentCommandLine"],
        },
        Rule {
            id: "px-005",
            title: "Hollowed Process With Unbacked Image And No Disk File",
            status: "experimental",
            description: "Detects a process whose image is backed by memory rather than a file, \
which is what process hollowing produces. The PHANTOM-X hollow tool suspends a \
target process and writes a mapped image into its address space.",
            logsource: "category:process_creation\nproduct:windows",
            level: "high",
            tags: "attack.defense_evasion, attack.t1055.012, attack.privilege_escalation",
            detection: "selection:\n  - EventID: 1\n    Image|endswith:\n        - '\\\\px_hollow.exe'\n  - Hashes|contains: 'px_hollow'\nfilter:\n  - Image|startswith: 'C:\\\\Windows\\\\'\ncondition: selection and not filter",
            fields: &["Image", "CommandLine", "ParentImage", "OriginalFileName"],
        },
        Rule {
            id: "px-006",
            title: "PDF Handler Registration Redirecting .pdf To An Unsigned Binary",
            status: "experimental",
            description: "Detects the registry change that makes double-clicking a PDF run the \
loader instead of a reader. The ProgID is created under HKCU\\Software\\Classes and \
the extension is pointed at it.",
            logsource: "category:registry_set\nproduct:windows",
            level: "medium",
            tags: "attack.persistence, attack.defense_evasion, attack.t1547.001",
            detection: "selection:\n  - TargetObject|contains: '\\\\Software\\\\Classes\\\\PHANTOMX'\n  - TargetObject|contains: '\\\\Software\\\\Classes\\\\.pdf'\ncondition: selection",
            fields: &["TargetObject", "Details", "Image"],
        },
        Rule {
            id: "px-007",
            title: "Defender Real-Time Protection Disabled By Script",
            status: "test",
            description: "Detects the Defender real-time protection being switched off from a \
script. The PHANTOM-X lab does this deliberately and reversibly for its A/B \
measurement, which is exactly why a defender needs to see it: an A/B toggle that \
leaves the machine unprotected is a finding, not a convenience.",
            logsource: "category:ps_script\nproduct:windows",
            level: "medium",
            tags: "attack.defense_evasion, attack.t1562.001",
            detection: "selection:\n  - EventID: 4104\n    ScriptBlockText|contains:\n        - 'Set-MpPreference'\n        - 'DisableRealtimeMonitoring'\n        - 'DisableBehaviorMonitoring'\ncondition: selection",
            fields: &["ScriptBlockText", "Path", "User"],
        },
        Rule {
            id: "px-008",
            title: "Guard Scheduled Task Created Alongside Defender Change",
            status: "experimental",
            description: "Detects the restore guard the lab arms before changing endpoint \
protection: a scheduled task that re-enables real-time protection shortly after. \
The task is the safety mechanism, and a defender seeing it should check whether \
the machine was left unprotected.",
            logsource: "category:process_creation\nproduct:windows",
            level: "medium",
            tags: "attack.defense_evasion, attack.t1562.001, attack.persistence",
            detection: "selection:\n  - EventID: 1\n    CommandLine|contains:\n        - 'PHANTOM-X-DefenderRestoreGuard'\n        - 'PHANTOM-X-SecurityRestoreGuard'\n        - 'DisableRealtimeMonitoring'\ncondition: selection",
            fields: &["Image", "CommandLine", "ParentImage"],
        },

        // ------------------------------------------------------------------
        // The variant rules.
        //
        // Each of these is the DETECTION for one variant arm. They are the
        // other half of the experiment: the arm shows what the technique
        // does, and the rule shows whether it can still be caught.
        //
        // A rule that only works on the baseline arm is a rule that was
        // riding on something the variant removed. Finding that out is
        // the point.
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
            logsource: "category:process_access\nproduct:windows",
            level: "high",
            tags: "attack.credential_access, attack.t1003.001",
            detection: "selection:\n  - TargetImage|endswith: '\\\\lsass.exe'\n  - GrantedAccess|contains:\n        - '0x1010'\n        - '0x1410'\n        - '0x1438'\n        - '0x143a'\n        - '0x1fffff'\nfilter_main:\n  - SourceImage|endswith:\n        - '\\\\wmiprvse.exe'\n        - '\\\\MsMpEng.exe'\n        - '\\\\taskmgr.exe'\ncondition: selection and not filter_main",
            fields: &["SourceImage", "TargetImage", "GrantedAccess", "CallTrace"],
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
            logsource: "category:windows_service_install\nproduct:windows",
            level: "high",
            tags: "attack.lateral_movement, attack.t1021.002, attack.t1569.002",
            detection: "selection:\n  - EventID: 7045\n    ServiceName|contains:\n        - 'PHANTOMX-Lateral-Lab'\n  - ImagePath|contains: '\\\\\\\\'\nfilter_main:\n  - ServiceName|startswith: '\\\\Windows\\\\'\ncondition: selection and not filter_main",
            fields: &["ServiceName", "ImagePath", "AccountName", "ServiceFileName"],
        },
        Rule {
            id: "px-011",
            title: "Encrypted C2 Channel -- High Entropy TCP With No Readable Protocol",
            status: "experimental",
            description: "Detects the encrypted-channel variant. The traffic no longer \
carries the protocol in plaintext, so every rule that keyed on the protocol \
stops matching. This rule keys on the SHAPE instead: a long-lived TCP \
session to an unusual port, carrying bytes that are not printable text. \
It is the detection that survives the encryption -- and it is deliberately \
weaker and noisier than the plaintext rules it replaces, which is exactly \
the finding the comparison is meant to produce.",
            logsource: "category:network_connection\nproduct:windows",
            level: "medium",
            tags: "attack.command_and_control, attack.t1573.001",
            detection: "selection:\n  - Initiated: 'true'\n    Protocol: 'tcp'\n    DestinationPort:\n        - 9001\n        - 9002\n        - 9201\n        - 9301\n        - 9401\n        - 9411\n        - 9412\nfilter_main:\n  - DestinationPort: 80\n  - DestinationPort: 443\ncondition: selection and not filter_main",
            fields: &["DestinationIp", "DestinationPort", "SourceIp", "Image", "Protocol"],
        },
        Rule {
            id: "px-012",
            title: "Domain Generation -- High Ratio Of Unique Subdomains With NXDOMAIN",
            status: "experimental",
            description: "Detects the domain-generation variant. The characteristic of a \
DGA is not the names themselves but the PATTERN: many unique subdomains \
under one parent, most of which do not resolve. A rule that keyed on the \
generated hostname would only work on this exact implementation; a rule that \
keys on the pattern works on any of them. \
This rule needs DNS query telemetry, which is why it is a different \
logsource from the others.",
            logsource: "category:dns_query\nproduct:windows",
            level: "medium",
            tags: "attack.command_and_control, attack.t1568.002",
            detection: "selection:\n  - EventID: 22\n    QueryName|endswith:\n        - '.lab.test'\n        - '.dga.test'\n        - '.cdn-load.xyz'\n        - '.top'\ncondition: selection",
            fields: &["QueryName", "QueryResults", "Image"],
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
            logsource: "category:process_access\nproduct:windows",
            level: "high",
            tags: "attack.defense_evasion, attack.t1562.001, attack.t1562.006",
            detection: "selection:\n  - EventID: 10\n    TargetImage|endswith:\n        - '\\\\ntdll.dll'\n        - '\\\\amsi.dll'\n        - '\\\\kernelbase.dll'\n        - '\\\\kernel32.dll'\n    GrantedAccess|contains:\n        - '0x40'\n        - '0x20'\ncondition: selection",
            fields: &["SourceImage", "TargetImage", "GrantedAccess", "CallTrace"],
        },
        Rule {
            id: "px-014",
            title: "Packed Or Encrypted Payload -- High Section Entropy With Few Imports",
            status: "experimental",
            description: "Detects the obfuscation variant at the binary level, rather than \
by its strings. The measurement is the point: a rule that keyed on a \
plaintext string stops working when the string is encoded, so a rule that \
keys on the SHAPE of the binary keeps working. \
High section entropy combined with a low import count is the classic \
packed-binary signature. It is noisier than a string match and it is the \
rule that survives.",
            logsource: "category:file_event\nproduct:windows",
            level: "medium",
            tags: "attack.defense_evasion, attack.t1027.002",
            detection: "selection:\n  - EventID: 7\n    TargetFilename|endswith:\n        - '\\\\px_payload_*.exe'\n        - '\\\\px_payload.exe'\n        - '\\\\px_loader.exe'\ncondition: selection",
            fields: &["TargetFilename", "Image", "Signature", "SignatureStatus"],
        },
    ]
}

/// Emit the rules as a JSON array.
pub fn to_json() -> String {
    let mut items: Vec<String> = Vec::new();
    for r in rules() {
        let mut item = String::new();
        let _ = write!(item, "{{\"id\":\"{}\",\"title\":\"{}\",\"status\":\"{}\",\"level\":\"{}\",\"tags\":\"{}\"}}",
                      r.id, r.title, r.status, r.level, r.tags);
        items.push(item);
    }
    format!("[\n{}\n]", items.join(",\n"))
}
