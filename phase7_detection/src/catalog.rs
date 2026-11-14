// =============================================================================
// PHANTOM-X :: the technique catalogue
// =============================================================================
// catalog.rs -- Every technique the lab knows about, and what it does about
// each one.
//
// WHY A CATALOGUE AND NOT A RULE LIST
//
//     The rule list says what the lab can DETECT. The catalogue says what
//     the lab can DO, and, more importantly, what it does not do.
//
//     A detection lab that only lists its successes is a marketing
//     document. The interesting number is the denominator: of the
//     techniques in scope, how many are measured, how many have a rule,
//     and how many are simply not exercised at all.
//
//     Three statuses, and they are not equally good:
//
//       measured       the lab exercises the technique, so the telemetry
//                      it produces is real and the rule can be tested
//                      against it
//       ruled          a rule exists for the technique, but the lab does
//                      not exercise it -- the rule is UNVALIDATED, and
//                      that is a different thing from a working rule
//       not_exercised  neither. The lab says nothing about it.
//
//     The distinction between "ruled" and "not_exercised" is the honest
//     part of this file. A rule that has never fired is a hypothesis.
//
// WHY THE CAMPAIGN TECHNIQUES ARE IN HERE
//
//     Some techniques on the list -- ransomware, wiper, cryptojacking,
//     botnet -- are not techniques at all in the sense the rest of the
//     catalogue uses. They are CAMPAIGNS: a ransomware run is a hundred
//     techniques executed in an order, and no single capability in a
//     single binary is "ransomware". They are listed, and marked as
//     campaigns, so that the gap is visible rather than hidden.
//
// -----------------------------------------------------------------------------

/// One technique in the catalogue.
#[derive(Debug, Clone)]
pub struct Technique {
    /// The ATT&CK identifier, e.g. "T1055".
    pub id: &'static str,
    /// The ATT&CK tactic.
    pub tactic: &'static str,
    /// The ATT&CK technique name.
    pub name: &'static str,
    /// The capability in the library that exercises it, or "" if none.
    ///
    /// The name is the one the C2 uses: "cap inject 1234 dll".
    pub capability: &'static str,
    /// The arm that exercises it, or "" if none.
    ///
    /// An arm is a whole build: the encrypted channel, the obfuscation,
    /// the credential arm. A capability is one entry in the library, and
    /// it exists inside an arm.
    pub arm: &'static str,
    /// The telemetry that carries the signal.
    pub telemetry: &'static str,
    /// The rules that cover it, or "" if none.
    pub rules: &'static str,
    /// Whether the technique is a single behaviour or a whole campaign.
    pub kind: &'static str,
}

impl Technique {
    /// The status of the technique in this lab.
    ///
    /// "measured" wins over "ruled": a technique the lab exercises is
    /// more than one it merely has a rule for.
    pub fn status(&self) -> &'static str {
        if !self.capability.is_empty() || !self.arm.is_empty() {
            "measured"
        } else if !self.rules.is_empty() {
            "ruled"
        } else {
            "not_exercised"
        }
    }

    /// Render the entry as JSON.
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("  {\n");
        out.push_str(&format!("    \"id\": {},\n", json_str(self.id)));
        out.push_str(&format!("    \"tactic\": {},\n", json_str(self.tactic)));
        out.push_str(&format!("    \"name\": {},\n", json_str(self.name)));
        out.push_str(&format!("    \"kind\": {},\n", json_str(self.kind)));
        out.push_str(&format!("    \"capability\": {},\n", json_str(self.capability)));
        out.push_str(&format!("    \"arm\": {},\n", json_str(self.arm)));
        out.push_str(&format!("    \"telemetry\": {},\n", json_str(self.telemetry)));
        out.push_str(&format!("    \"rules\": {},\n", json_str(self.rules)));
        out.push_str(&format!("    \"status\": {}\n", json_str(self.status())));
        out.push_str("  }");
        out
    }
}

/// Escape a string as a JSON value.
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
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The whole catalogue.
pub fn catalog() -> Vec<Technique> {
    vec![
        // -- execution ------------------------------------------------------
        Technique {
            id: "T1059",
            tactic: "execution",
            name: "Command and Scripting Interpreter",
            capability: "script",
            arm: "",
            telemetry: "process_creation (wscript.exe, cscript.exe, mshta.exe)",
            rules: "px-033, px-047",
            kind: "technique",
        },
        Technique {
            id: "T1059.001",
            tactic: "execution",
            name: "PowerShell",
            capability: "ps",
            arm: "",
            telemetry: "process_creation (CommandLine)",
            rules: "px-035",
            kind: "technique",
        },
        Technique {
            id: "T1059.005",
            tactic: "execution",
            name: "Visual Basic",
            capability: "script",
            arm: "",
            telemetry: "process_creation (script host and its child)",
            rules: "px-033, px-047",
            kind: "technique",
        },
        Technique {
            id: "T1059.007",
            tactic: "execution",
            name: "JavaScript / JScript",
            capability: "script",
            arm: "",
            telemetry: "process_creation (script host and its child)",
            rules: "px-033",
            kind: "technique",
        },
        Technique {
            id: "T1106",
            tactic: "execution",
            name: "Native API",
            capability: "",
            arm: "",
            telemetry: "process_access (call trace)",
            rules: "px-016",
            kind: "technique",
        },
        Technique {
            id: "T1204",
            tactic: "execution",
            name: "User Execution",
            capability: "",
            arm: "",
            telemetry: "process_creation (parent and child)",
            rules: "px-047",
            kind: "technique",
        },
        Technique {
            id: "T1204.002",
            tactic: "execution",
            name: "User Execution: Malicious File",
            capability: "",
            arm: "the PDF carrier",
            telemetry: "process_creation, file_event",
            rules: "px-002, px-004, px-047, px-048",
            kind: "technique",
        },
        Technique {
            id: "T1203",
            tactic: "execution",
            name: "Exploitation for Client Execution",
            capability: "",
            arm: "",
            telemetry: "process_creation (a browser or document app spawning a child)",
            rules: "",
            kind: "technique",
        },
        Technique {
            id: "T1218",
            tactic: "defense-evasion",
            name: "System Binary Proxy Execution",
            capability: "lolbin",
            arm: "",
            telemetry: "process_creation (Image and CommandLine)",
            rules: "px-004, px-034",
            kind: "technique",
        },
        Technique {
            id: "T1218.015",
            tactic: "defense-evasion",
            name: "System Binary Proxy Execution: COM",
            capability: "",
            arm: "",
            telemetry: "file_event (a document with an OLE object)",
            rules: "px-048",
            kind: "technique",
        },

        // -- persistence ----------------------------------------------------
        Technique {
            id: "T1547.001",
            tactic: "persistence",
            name: "Boot or Logon Autostart Execution: Registry Run Keys",
            capability: "persist",
            arm: "",
            telemetry: "registry_set",
            rules: "px-006, px-021",
            kind: "technique",
        },
        Technique {
            id: "T1546.003",
            tactic: "persistence",
            name: "Event Triggered Execution: WMI Event Subscription",
            capability: "persist",
            arm: "",
            telemetry: "wmi",
            rules: "px-022",
            kind: "technique",
        },
        Technique {
            id: "T1053.005",
            tactic: "persistence",
            name: "Scheduled Task/Job: Scheduled Task",
            capability: "schtask",
            arm: "",
            telemetry: "process_creation (schtasks.exe)",
            rules: "px-008, px-023",
            kind: "technique",
        },
        Technique {
            id: "T1543.003",
            tactic: "persistence",
            name: "Create or Modify System Process: Windows Service",
            capability: "service",
            arm: "",
            telemetry: "windows_service_install",
            rules: "px-024",
            kind: "technique",
        },
        Technique {
            id: "T1543",
            tactic: "persistence",
            name: "Create or Modify System Process",
            capability: "service",
            arm: "",
            telemetry: "windows_service_install",
            rules: "px-024",
            kind: "technique",
        },
        Technique {
            id: "T1546.015",
            tactic: "persistence",
            name: "Event Triggered Execution: Component Object Model Hijacking",
            capability: "com",
            arm: "",
            telemetry: "registry_set (a CLSID under InprocServer32)",
            rules: "px-051",
            kind: "technique",
        },
        Technique {
            id: "T1574.002",
            tactic: "persistence",
            name: "Hijack Execution Flow: DLL Side-Loading",
            capability: "",
            arm: "",
            telemetry: "process_creation (a signed program loading an unsigned DLL)",
            rules: "",
            kind: "technique",
        },
        Technique {
            id: "T1505.003",
            tactic: "persistence",
            name: "Server Software Component: Web Shell",
            capability: "",
            arm: "",
            telemetry: "file_event (a script written into a web root)",
            rules: "",
            kind: "technique",
        },

        // -- defence evasion ------------------------------------------------
        Technique {
            id: "T1055",
            tactic: "defense-evasion",
            name: "Process Injection",
            capability: "inject",
            arm: "",
            telemetry: "process_access (open with thread rights, then a remote write)",
            rules: "px-015, px-016",
            kind: "technique",
        },
        Technique {
            id: "T1055.012",
            tactic: "defense-evasion",
            name: "Process Injection: Process Hollowing",
            capability: "",
            arm: "px_hollow.exe",
            telemetry: "process_creation (an image with no file backing it)",
            rules: "px-001, px-005",
            kind: "technique",
        },
        Technique {
            id: "T1620",
            tactic: "defense-evasion",
            name: "Reflective Code Loading",
            capability: "",
            arm: "the loader",
            telemetry: "process_access (executable memory with no file backing it)",
            rules: "px-001",
            kind: "technique",
        },
        Technique {
            id: "T1027",
            tactic: "defense-evasion",
            name: "Obfuscated Files or Information",
            capability: "",
            arm: "the obfuscated arm",
            telemetry: "file_event (section entropy, import count)",
            rules: "px-014, px-035",
            kind: "technique",
        },
        Technique {
            id: "T1027.002",
            tactic: "defense-evasion",
            name: "Obfuscated Files or Information: Software Packing",
            capability: "",
            arm: "the obfuscated arm",
            telemetry: "file_event (section entropy)",
            rules: "px-014",
            kind: "technique",
        },
        Technique {
            id: "T1027.003",
            tactic: "defense-evasion",
            name: "Obfuscated Files or Information: Steganography",
            capability: "steg",
            arm: "",
            telemetry: "file_event (data after the image end marker)",
            rules: "px-038",
            kind: "technique",
        },
        Technique {
            id: "T1140",
            tactic: "defense-evasion",
            name: "Deobfuscate/Decode Files or Information",
            capability: "ps",
            arm: "",
            telemetry: "process_creation (a decoder named in the command line)",
            rules: "px-035",
            kind: "technique",
        },
        Technique {
            id: "T1036",
            tactic: "defense-evasion",
            name: "Masquerading",
            capability: "spoof",
            arm: "",
            telemetry: "file_event and process_creation (name against image)",
            rules: "px-018, px-019",
            kind: "technique",
        },
        Technique {
            id: "T1036.005",
            tactic: "defense-evasion",
            name: "Masquerading: Match Legitimate Name or Location",
            capability: "spoof",
            arm: "",
            telemetry: "file_event (the image renamed on disk)",
            rules: "px-018, px-019",
            kind: "technique",
        },
        Technique {
            id: "T1564.010",
            tactic: "defense-evasion",
            name: "Hide Artifacts: Argument Spoofing",
            capability: "spoof",
            arm: "",
            telemetry: "process_creation (command line against image)",
            rules: "px-019",
            kind: "technique",
        },
        Technique {
            id: "T1134",
            tactic: "defense-evasion",
            name: "Access Token Manipulation",
            capability: "token",
            arm: "",
            telemetry: "process_access (TOKEN_DUPLICATE)",
            rules: "px-017",
            kind: "technique",
        },
        Technique {
            id: "T1134.001",
            tactic: "defense-evasion",
            name: "Access Token Manipulation: Token Impersonation/Theft",
            capability: "token",
            arm: "",
            telemetry: "process_access (TOKEN_DUPLICATE and TOKEN_ASSIGN_PRIMARY)",
            rules: "px-017",
            kind: "technique",
        },
        Technique {
            id: "T1134.002",
            tactic: "defense-evasion",
            name: "Access Token Manipulation: Create Process with Token",
            capability: "",
            arm: "px_hollow.exe",
            telemetry: "process_creation (a child with an inherited token)",
            rules: "px-005",
            kind: "technique",
        },
        Technique {
            id: "T1134.004",
            tactic: "defense-evasion",
            name: "Access Token Manipulation: Parent PID Spoofing",
            capability: "spoof",
            arm: "",
            telemetry: "process_creation (a parent that did not spawn it)",
            rules: "px-020",
            kind: "technique",
        },
        Technique {
            id: "T1070",
            tactic: "defense-evasion",
            name: "Indicator Removal",
            capability: "antifor",
            arm: "",
            telemetry: "file_event, event_audit",
            rules: "px-025, px-026, px-027",
            kind: "technique",
        },
        Technique {
            id: "T1070.001",
            tactic: "defense-evasion",
            name: "Indicator Removal: Clear Windows Event Logs",
            capability: "antifor",
            arm: "",
            telemetry: "event_audit (event 1102 and 104)",
            rules: "px-025",
            kind: "technique",
        },
        Technique {
            id: "T1070.004",
            tactic: "defense-evasion",
            name: "Indicator Removal: File Deletion",
            capability: "antifor",
            arm: "",
            telemetry: "file_event (a running image deleted or renamed)",
            rules: "px-026",
            kind: "technique",
        },
        Technique {
            id: "T1070.006",
            tactic: "defense-evasion",
            name: "Indicator Removal: Timestomp",
            capability: "antifor",
            arm: "",
            telemetry: "file_event (a write time far from the event)",
            rules: "px-027",
            kind: "technique",
        },
        Technique {
            id: "T1562.001",
            tactic: "defense-evasion",
            name: "Impair Defenses: Disable or Modify Tools",
            capability: "",
            arm: "the AMSI arm and the lab's own A/B toggle",
            telemetry: "process_access (a patched module), ps_script",
            rules: "px-007, px-013, px-045",
            kind: "technique",
        },
        Technique {
            id: "T1562.006",
            tactic: "defense-evasion",
            name: "Impair Defenses: Indicator Blocking",
            capability: "",
            arm: "the ETW arm",
            telemetry: "process_access (a patched provider function)",
            rules: "px-013, px-046",
            kind: "technique",
        },
        Technique {
            id: "T1112",
            tactic: "defense-evasion",
            name: "Modify Registry",
            capability: "persist",
            arm: "",
            telemetry: "registry_set",
            rules: "px-021",
            kind: "technique",
        },
        Technique {
            id: "T1497",
            tactic: "defense-evasion",
            name: "Virtualization/Sandbox Evasion",
            capability: "antivm",
            arm: "",
            telemetry: "process_access (the inspection calls)",
            rules: "px-039",
            kind: "technique",
        },
        Technique {
            id: "T1497.001",
            tactic: "defense-evasion",
            name: "Virtualization/Sandbox Evasion: System Checks",
            capability: "antivm",
            arm: "",
            telemetry: "process_access (IsDebuggerPresent, firmware reads)",
            rules: "px-039",
            kind: "technique",
        },
        Technique {
            id: "T1497.003",
            tactic: "defense-evasion",
            name: "Virtualization/Sandbox Evasion: Time Based Evasion",
            capability: "delay",
            arm: "",
            telemetry: "process_creation (a gap between start and first action)",
            rules: "px-040",
            kind: "technique",
        },
        Technique {
            id: "T1622",
            tactic: "defense-evasion",
            name: "Debugger Evasion",
            capability: "antivm",
            arm: "",
            telemetry: "process_access (NtQueryInformationProcess)",
            rules: "px-039",
            kind: "technique",
        },
        Technique {
            id: "T1014",
            tactic: "defense-evasion",
            name: "Rootkit",
            capability: "",
            arm: "",
            telemetry: "process_creation (a process that is not in the process list)",
            rules: "",
            kind: "technique",
        },

        // -- discovery ------------------------------------------------------
        Technique {
            id: "T1082",
            tactic: "discovery",
            name: "System Information Discovery",
            capability: "avstatus",
            arm: "",
            telemetry: "process_creation (systeminfo, GetNativeSystemInfo)",
            rules: "px-031",
            kind: "technique",
        },
        Technique {
            id: "T1057",
            tactic: "discovery",
            name: "Process Discovery",
            capability: "recon",
            arm: "",
            telemetry: "process_creation (tasklist, the process snapshot)",
            rules: "px-031",
            kind: "technique",
        },
        Technique {
            id: "T1087",
            tactic: "discovery",
            name: "Account Discovery",
            capability: "recon",
            arm: "",
            telemetry: "process_creation (net user, net group)",
            rules: "px-031",
            kind: "technique",
        },
        Technique {
            id: "T1046",
            tactic: "discovery",
            name: "Network Service Discovery",
            capability: "recon",
            arm: "",
            telemetry: "network_connection (many ports, one host)",
            rules: "px-032",
            kind: "technique",
        },
        Technique {
            id: "T1047",
            tactic: "discovery",
            name: "Windows Management Instrumentation",
            capability: "recon",
            arm: "",
            telemetry: "process_creation (wmic process, wmic service)",
            rules: "px-031",
            kind: "technique",
        },
        Technique {
            id: "T1482",
            tactic: "discovery",
            name: "Domain Trust Discovery",
            capability: "delay",
            arm: "",
            telemetry: "process_creation (a domain lookup before the work)",
            rules: "px-041",
            kind: "technique",
        },
        Technique {
            id: "T1589",
            tactic: "reconnaissance",
            name: "Gather Victim Identity Information",
            capability: "",
            arm: "",
            telemetry: "file_event (an address book or a mail store being read)",
            rules: "",
            kind: "technique",
        },
        Technique {
            id: "T1114.003",
            tactic: "collection",
            name: "Email Collection: Email Forwarding Rule",
            capability: "",
            arm: "",
            telemetry: "registry_set (a transport rule under HKCU)",
            rules: "",
            kind: "technique",
        },

        // -- collection -----------------------------------------------------
        Technique {
            id: "T1005",
            tactic: "collection",
            name: "Data from Local System",
            capability: "browser",
            arm: "",
            telemetry: "file_event (a bulk read of user documents)",
            rules: "px-054",
            kind: "technique",
        },
        Technique {
            id: "T1115",
            tactic: "collection",
            name: "Clipboard Data",
            capability: "clip",
            arm: "",
            telemetry: "process_access (OpenClipboard, GetClipboardData)",
            rules: "px-028",
            kind: "technique",
        },
        Technique {
            id: "T1113",
            tactic: "collection",
            name: "Screen Capture",
            capability: "",
            arm: "the file-transfer arm",
            telemetry: "file_event (a bitmap written to a temporary directory)",
            rules: "px-029",
            kind: "technique",
        },
        Technique {
            id: "T1125",
            tactic: "collection",
            name: "Video Capture",
            capability: "",
            arm: "",
            telemetry: "driver_load (a capture device opened)",
            rules: "px-030",
            kind: "technique",
        },
        Technique {
            id: "T1056.001",
            tactic: "credential-access",
            name: "Input Capture: Keylogging",
            capability: "keylog",
            arm: "",
            telemetry: "process_access (GetAsyncKeyState, SetWindowsHookEx)",
            rules: "px-049",
            kind: "technique",
        },
        Technique {
            id: "T1056",
            tactic: "credential-access",
            name: "Input Capture",
            capability: "keylog",
            arm: "",
            telemetry: "process_access",
            rules: "px-049",
            kind: "technique",
        },

        // -- credential access ----------------------------------------------
        Technique {
            id: "T1003",
            tactic: "credential-access",
            name: "OS Credential Dumping",
            capability: "",
            arm: "the credential arm",
            telemetry: "process_access, file_event",
            rules: "px-009, px-042, px-043",
            kind: "technique",
        },
        Technique {
            id: "T1003.001",
            tactic: "credential-access",
            name: "OS Credential Dumping: LSASS Memory",
            capability: "",
            arm: "the credential arm",
            telemetry: "process_access (VM_READ on lsass.exe)",
            rules: "px-009, px-043",
            kind: "technique",
        },
        Technique {
            id: "T1003.002",
            tactic: "credential-access",
            name: "OS Credential Dumping: Security Account Manager",
            capability: "",
            arm: "the credential arm",
            telemetry: "file_event (the SAM hive being read)",
            rules: "px-042",
            kind: "technique",
        },
        Technique {
            id: "T1555.003",
            tactic: "credential-access",
            name: "Credentials from Password Stores: Credentials from Web Browsers",
            capability: "browser",
            arm: "",
            telemetry: "file_event (Login Data and the DPAPI master key)",
            rules: "px-054",
            kind: "technique",
        },
        Technique {
            id: "T1558.003",
            tactic: "credential-access",
            name: "Steal or Forge Kerberos Tickets: Kerberoasting",
            capability: "",
            arm: "",
            telemetry: "network_connection (a service ticket requested for a service account)",
            rules: "",
            kind: "technique",
        },

        // -- lateral movement ------------------------------------------------
        Technique {
            id: "T1021",
            tactic: "lateral-movement",
            name: "Remote Services",
            capability: "",
            arm: "",
            telemetry: "windows_service_install, network_connection",
            rules: "px-050",
            kind: "technique",
        },
        Technique {
            id: "T1021.001",
            tactic: "lateral-movement",
            name: "Remote Services: Remote Desktop Protocol",
            capability: "",
            arm: "",
            telemetry: "logon events (type 10 with a remote desktop source)",
            rules: "",
            kind: "technique",
        },
        Technique {
            id: "T1021.002",
            tactic: "lateral-movement",
            name: "Remote Services: SMB/Windows Admin Shares",
            capability: "",
            arm: "the lateral arm",
            telemetry: "windows_service_install (a service with a UNC image path)",
            rules: "px-010, px-050",
            kind: "technique",
        },
        Technique {
            id: "T1569.002",
            tactic: "execution",
            name: "System Services: Service Execution",
            capability: "",
            arm: "the lateral arm",
            telemetry: "windows_service_install",
            rules: "px-010, px-050",
            kind: "technique",
        },
        Technique {
            id: "T1570",
            tactic: "lateral-movement",
            name: "Lateral Tool Transfer",
            capability: "",
            arm: "",
            telemetry: "file_event (a tool copied to a remote share)",
            rules: "",
            kind: "technique",
        },
        Technique {
            id: "T1550.002",
            tactic: "lateral-movement",
            name: "Use Alternate Authentication Material: Pass the Hash",
            capability: "",
            arm: "",
            telemetry: "logon events (type 3 with a null session)",
            rules: "",
            kind: "technique",
        },
        Technique {
            id: "T1550.003",
            tactic: "lateral-movement",
            name: "Use Alternate Authentication Material: Pass the Ticket",
            capability: "",
            arm: "",
            telemetry: "logon events (a service ticket used without a key)",
            rules: "",
            kind: "technique",
        },

        // -- command and control ---------------------------------------------
        Technique {
            id: "T1071.001",
            tactic: "command-and-control",
            name: "Application Layer Protocol: Web Protocols",
            capability: "",
            arm: "the plain channel",
            telemetry: "network_connection (the protocol in the clear)",
            rules: "px-003",
            kind: "technique",
        },
        Technique {
            id: "T1573.001",
            tactic: "command-and-control",
            name: "Encrypted Channel: Symmetric Cryptography",
            capability: "",
            arm: "the encrypted arm",
            telemetry: "network_connection (the shape of the traffic)",
            rules: "px-011",
            kind: "technique",
        },
        Technique {
            id: "T1572",
            tactic: "command-and-control",
            name: "Protocol Tunneling",
            capability: "dnstun",
            arm: "",
            telemetry: "dns_query (a long label)",
            rules: "px-036",
            kind: "technique",
        },
        Technique {
            id: "T1568.002",
            tactic: "command-and-control",
            name: "Dynamic Resolution: Domain Generation Algorithms",
            capability: "",
            arm: "the DGA arm",
            telemetry: "dns_query (many unique subdomains)",
            rules: "px-012",
            kind: "technique",
        },
        Technique {
            id: "T1105",
            tactic: "command-and-control",
            name: "Ingress Tool Transfer",
            capability: "",
            arm: "the file-transfer arm",
            telemetry: "network_connection (the framed transfer)",
            rules: "px-037",
            kind: "technique",
        },
        Technique {
            id: "T1090",
            tactic: "command-and-control",
            name: "Proxy",
            capability: "proxy",
            arm: "",
            telemetry: "registry_set (the WinINet proxy) and network_connection",
            rules: "px-053",
            kind: "technique",
        },
        Technique {
            id: "T1090.003",
            tactic: "command-and-control",
            name: "Proxy: Multi-hop Proxy",
            capability: "",
            arm: "",
            telemetry: "network_connection (a chain of intermediaries)",
            rules: "",
            kind: "technique",
        },
        Technique {
            id: "T1102",
            tactic: "command-and-control",
            name: "Web Service",
            capability: "",
            arm: "",
            telemetry: "network_connection (a cloud provider's host as the endpoint)",
            rules: "",
            kind: "technique",
        },
        Technique {
            id: "T1210",
            tactic: "exploitation",
            name: "Exploitation of Remote Services",
            capability: "",
            arm: "",
            telemetry: "process_creation on the target",
            rules: "",
            kind: "technique",
        },

        // -- exfiltration ----------------------------------------------------
        Technique {
            id: "T1041",
            tactic: "exfiltration",
            name: "Exfiltration Over C2 Channel",
            capability: "",
            arm: "the file-transfer arm",
            telemetry: "network_connection (framed chunks leaving)",
            rules: "px-037",
            kind: "technique",
        },
        Technique {
            id: "T1560.001",
            tactic: "exfiltration",
            name: "Archive Collected Data: Archive via Utility",
            capability: "stage",
            arm: "",
            telemetry: "file_event (an archive appearing next to its sources)",
            rules: "px-044",
            kind: "technique",
        },
        Technique {
            id: "T1074.001",
            tactic: "collection",
            name: "Data Staged: Local Data Staging",
            capability: "stage",
            arm: "",
            telemetry: "file_event",
            rules: "px-044",
            kind: "technique",
        },

        // -- impact (campaigns) ----------------------------------------------
        Technique {
            id: "T1486",
            tactic: "impact",
            name: "Data Encrypted for Impact",
            capability: "",
            arm: "",
            telemetry: "file_event (mass rename) and process_creation (shadow copy deletion)",
            rules: "",
            kind: "campaign",
        },
        Technique {
            id: "T1485",
            tactic: "impact",
            name: "Data Destruction",
            capability: "",
            arm: "",
            telemetry: "file_event (mass delete) and process_creation (wipe tooling)",
            rules: "",
            kind: "campaign",
        },
        Technique {
            id: "T1496",
            tactic: "impact",
            name: "Resource Hijacking",
            capability: "",
            arm: "",
            telemetry: "network_connection (a mining pool) and process_creation",
            rules: "",
            kind: "campaign",
        },
        Technique {
            id: "T1565.002",
            tactic: "impact",
            name: "Data Manipulation: Transmitted Data Manipulation",
            capability: "clip",
            arm: "",
            telemetry: "process_access (the clipboard replaced)",
            rules: "px-028",
            kind: "technique",
        },

        // -- initial access and resource development ------------------------
        Technique {
            id: "T1566",
            tactic: "initial-access",
            name: "Phishing",
            capability: "",
            arm: "",
            telemetry: "file_event (a document from a mail store) and process_creation",
            rules: "px-047, px-048",
            kind: "technique",
        },
        Technique {
            id: "T1189",
            tactic: "initial-access",
            name: "Drive-by Compromise",
            capability: "",
            arm: "",
            telemetry: "network_connection (a download from a compromised site)",
            rules: "",
            kind: "technique",
        },
        Technique {
            id: "T1195",
            tactic: "initial-access",
            name: "Supply Chain Compromise",
            capability: "",
            arm: "",
            telemetry: "file_event (an unsigned component in a signed package)",
            rules: "",
            kind: "technique",
        },
        Technique {
            id: "T1583",
            tactic: "resource-development",
            name: "Acquire Infrastructure",
            capability: "",
            arm: "",
            telemetry: "dns_query and registration records",
            rules: "",
            kind: "campaign",
        },
        Technique {
            id: "T1078.004",
            tactic: "defense-evasion",
            name: "Valid Accounts: Cloud Accounts",
            capability: "",
            arm: "",
            telemetry: "cloud sign-in logs",
            rules: "",
            kind: "technique",
        },

        // -- privilege escalation --------------------------------------------
        Technique {
            id: "T1068",
            tactic: "privilege-escalation",
            name: "Exploitation for Privilege Escalation",
            capability: "",
            arm: "",
            telemetry: "process_creation (a SYSTEM process from a user process)",
            rules: "",
            kind: "technique",
        },
        Technique {
            id: "T1548.002",
            tactic: "privilege-escalation",
            name: "Abuse Elevation Control Mechanism: Bypass User Account Control",
            capability: "elev",
            arm: "",
            telemetry: "registry_set (the auto-elevate key) and process_creation",
            rules: "px-052",
            kind: "technique",
        },
    ]
}

/// The catalogue as a JSON array.
pub fn catalog_json() -> String {
    let entries = catalog();
    let mut out = String::new();
    out.push_str("[\n");
    for (i, t) in entries.iter().enumerate() {
        out.push_str(&t.to_json());
        if i + 1 < entries.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("]\n");
    out
}

/// The catalogue as a plain table, for the console.
pub fn catalog_table() -> String {
    let mut out = String::new();
    out.push_str(&format!("{:<12} {:<18} {:<26} {:<12} {}\n",
                         "TECHNIQUE", "TACTIC", "NAME", "STATUS", "RULES"));
    out.push_str(&format!("{:<12} {:<18} {:<26} {:<12} {}\n",
                         "-".repeat(12), "-".repeat(18), "-".repeat(26),
                         "-".repeat(12), "-".repeat(20)));
    for t in catalog() {
        out.push_str(&format!("{:<12} {:<18} {:<26} {:<12} {}\n",
                             t.id, t.tactic, t.name, t.status(), t.rules));
    }
    out
}
