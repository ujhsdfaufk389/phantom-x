// =============================================================================
// PHANTOM-X :: Phase 7 -- the rules for the capability library
// =============================================================================
// rules_extra.rs -- The rules that detect the techniques the capability
// library exercises.
//
// WHY A SEPARATE FILE
//
//     detections.rs holds the rules for the chain itself: the PDF carrier,
//     the loader, the hollow tool, and the seven original variant arms.
//     Those rules were written before the capability library existed.
//
//     The rules here were written from the other direction. For each
//     technique in the library the question was asked in advance: if this
//     behaviour happened on a real host, what would the endpoint see?
//     The answer became the rule. Then the capability was written to
//     produce exactly that telemetry.
//
//     That order matters. A rule written after the fact tends to key on
//     whatever the code happened to do; a rule written first tends to key
//     on the behaviour that matters.
//
// THE RULE OF THUMB FOR EVERY RULE HERE
//
//     Key on the BEHAVIOUR, never on a string in the binary.
//
//     A rule that keys on "px_payload.exe" stops working the moment the
//     string is encoded, which is what the obfuscation arm does. A rule
//     that keys on "a remote thread was created in a process that has no
//     remote thread business" keeps working. Every rule below is written
//     to survive the obfuscation arm, because a rule that does not is
//     worth very little in a lab whose whole point is to find that out.
//
// THE TWO BLOCKS
//
//     A selection block ORs its matchers. A rule that needs "this field
//     AND that field" therefore uses two blocks: "selection" and
//     "selection_and". Most of the rules below need only one, because
//     the most characteristic field is enough on its own -- which is the
//     better rule, since every extra condition is another chance for the
//     rule to miss.
//
// -----------------------------------------------------------------------------

use crate::detections::{Block, Matcher, Op, Rule};

/// The rules for the capability library.
pub fn capability_rules() -> Vec<Rule> {
    vec![
        // ------------------------------------------------------------------
        // Process injection -- T1055
        // ------------------------------------------------------------------
        Rule {
            id: "px-015",
            title: "Process Opened With All Access And Thread Rights",
            status: "experimental",
            description: "Detects the classic DLL-injection shape: a process opens another \
process with everything it could ask for and then creates a thread in it. \
The access mask is the signal. 0x1F0FFF is PROCESS_ALL_ACCESS with \
PROCESS_CREATE_THREAD added, and no legitimate program on a lab host \
opens another process with that combination. \
This rule does not depend on the injected DLL's name, so it survives the \
string obfuscation arm.",
            level: "high",
            techniques: vec!["T1055"],
            logsource: vec![("category", "process_access"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("GrantedAccess", Op::In,
                    vec!["0x1F0FFF", "0x1FFFFF", "0x1FFEFF", "0x1FFFFF"])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block {
                matchers: vec![
                    Matcher::one("SourceImage", Op::EndsWith, "\\MsMpEng.exe"),
                    Matcher::one("SourceImage", Op::EndsWith, "\\wmiprvse.exe"),
                ],
            },
            fields: &["SourceImage", "TargetImage", "GrantedAccess", "CallTrace"],
            catches: "the injection capability -- both the DLL and the APC method",
        },
        Rule {
            id: "px-016",
            title: "Memory Written In Another Process",
            status: "experimental",
            description: "Detects the write half of process injection, which is the half that \
happens before any thread exists. A write into another process's address \
space is the technique; the thread is only how the write becomes code. \
This rule therefore also fires for the APC variant, where the payload is \
queued rather than started with a remote thread.",
            level: "high",
            techniques: vec!["T1055", "T1106"],
            logsource: vec![("category", "process_access"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("CallTrace", Op::Contains,
                    vec!["WriteProcessMemory", "NtWriteVirtualMemory",
                         "VirtualAllocEx", "NtMapViewOfSection"])],
            },
            selection_and: Block {
                matchers: vec![Matcher::many("GrantedAccess", Op::Contains,
                    vec!["0x1F0FFF", "0x1FFEFF", "0x1FFFFF", "0x1410", "0x1010"])],
            },
            filter: Block {
                matchers: vec![
                    Matcher::one("SourceImage", Op::EndsWith, "\\MsMpEng.exe"),
                ],
            },
            fields: &["SourceImage", "TargetImage", "GrantedAccess", "CallTrace"],
            catches: "the injection capability -- before any thread is created",
        },

        // ------------------------------------------------------------------
        // Token theft -- T1134.001
        // ------------------------------------------------------------------
        Rule {
            id: "px-017",
            title: "Token Of Another Process Duplicated Or Used",
            status: "experimental",
            description: "Detects the duplication of a token that belongs to another process, \
which is how a payload turns a privileged process's identity into its \
own. The observation is the token call itself: no program that is not \
an impersonation library opens another process's token and duplicates \
it.",
            level: "high",
            techniques: vec!["T1134.001", "T1134"],
            logsource: vec![("category", "process_access"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("CallTrace", Op::Contains,
                    vec!["OpenProcessToken", "DuplicateTokenEx",
                         "ImpersonateLoggedOnUser", "CreateProcessWithTokenW",
                         "SetThreadToken", "CreateProcessAsUser"])],
            },
            selection_and: Block {
                matchers: vec![Matcher::one("GrantedAccess", Op::Equals, "0x1000")],
            },
            filter: Block {
                matchers: vec![
                    Matcher::one("SourceImage", Op::EndsWith, "\\services.exe"),
                    Matcher::one("SourceImage", Op::EndsWith, "\\lsass.exe"),
                ],
            },
            fields: &["SourceImage", "TargetImage", "GrantedAccess", "CallTrace"],
            catches: "the token capability",
        },

        // ------------------------------------------------------------------
        // Masquerading and spoofing -- T1036.005, T1134.004, T1564.010
        // ------------------------------------------------------------------
        Rule {
            id: "px-018",
            title: "Running Image Renamed To A Known System Binary Name",
            status: "experimental",
            description: "Detects a running process whose image file has been renamed to the \
name of a legitimate program, which is the simplest form of masquerading \
there is. The two halves disagree: the process list shows the new name, \
the file record shows the original. A defender can catch it by comparing \
the two, which is what this rule asks the collector to do.",
            level: "medium",
            techniques: vec!["T1036.005", "T1036"],
            logsource: vec![("category", "file_event"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("TargetFilename", Op::EndsWith,
                    vec!["\\svchost.exe", "\\lsass.exe", "\\explorer.exe",
                         "\\services.exe", "\\dllhost.exe"])],
            },
            selection_and: Block {
                matchers: vec![Matcher::many("EventType", Op::Contains,
                    vec!["Rename", "Create"])],
            },
            filter: Block {
                matchers: vec![
                    Matcher::one("TargetFilename", Op::StartsWith, "C:\\Windows\\"),
                ],
            },
            fields: &["TargetFilename", "Image", "EventType", "User"],
            catches: "the masquerading capability",
        },
        Rule {
            id: "px-019",
            title: "Process Command Line Does Not Match The Image On Disk",
            status: "experimental",
            description: "Detects a process whose command line has been rewritten after it \
started, which is how the command-line spoofing capability hides what it \
is doing. The rule compares the command line against the image path: the \
command line names one program and the image on disk is another. \
That mismatch is the whole signal; there is no string to key on.",
            level: "medium",
            techniques: vec!["T1564.010", "T1036.005"],
            logsource: vec![("category", "process_creation"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("CommandLine", Op::Contains,
                    vec!["svchost.exe", "lsass.exe", "explorer.exe"])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block {
                matchers: vec![
                    Matcher::one("Image", Op::EndsWith, "\\svchost.exe"),
                    Matcher::one("Image", Op::EndsWith, "\\lsass.exe"),
                    Matcher::one("Image", Op::EndsWith, "\\explorer.exe"),
                ],
            },
            fields: &["Image", "CommandLine", "ParentImage", "OriginalFileName"],
            catches: "the command-line spoofing capability",
        },
        Rule {
            id: "px-020",
            title: "Parent Process Changed After The Process Started",
            status: "experimental",
            description: "Detects a process whose recorded parent is not the process that \
actually created it. The parent pid is reported from the process's own \
basic information, so a payload that rewrites it changes what every \
process-creation event says about the tree. \
The rule keys on the parent not existing any more, or on the parent \
being something that could not have spawned it. Either way the tree is \
inconsistent, and an inconsistent tree is the finding.",
            level: "medium",
            techniques: vec!["T1134.004"],
            logsource: vec![("category", "process_creation"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("ParentImage", Op::In,
                    vec!["-", "", "Non-existent", "Unknown"])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block { matchers: vec![] },
            fields: &["Image", "CommandLine", "ParentImage", "ParentProcessId", "ProcessId"],
            catches: "the parent-process spoofing capability",
        },

        // ------------------------------------------------------------------
        // Persistence -- T1547.001, T1546.003, T1053.005, T1543.003
        // ------------------------------------------------------------------
        Rule {
            id: "px-021",
            title: "Registry Run Key Written",
            status: "experimental",
            description: "Detects a Run key being written. The Run key is the oldest \
persistence mechanism on Windows and the easiest to look for, which makes \
it the natural baseline for a persistence rule. \
The rule keys on the KEY, not on the value: the value is chosen by the \
attacker, the key is chosen by the mechanism.",
            level: "medium",
            techniques: vec!["T1547.001", "T1112"],
            logsource: vec![("category", "registry_set"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("TargetObject", Op::Contains,
                    vec!["\\CurrentVersion\\Run",
                         "\\CurrentVersion\\RunOnce",
                         "\\CurrentVersion\\Explorer\\Run"])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block {
                matchers: vec![
                    Matcher::one("Image", Op::EndsWith, "\\explorer.exe"),
                ],
            },
            fields: &["TargetObject", "Details", "Image", "User"],
            catches: "the persistence capability -- the Run key method",
        },
        Rule {
            id: "px-022",
            title: "WMI Event Subscription Created",
            status: "experimental",
            description: "Detects the fileless persistence mechanism: a WMI event filter, a \
consumer and the binding between them. This is persistence with no file \
to find, which is why it needs its own rule -- the file-based rules will \
never see it. \
Three objects have to exist for it to work, and the third one is the \
interesting one: a filter and a consumer on their own do nothing.",
            level: "high",
            techniques: vec!["T1546.003"],
            logsource: vec![("category", "wmi"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("Operation", Op::Contains,
                    vec!["__EventFilter", "__EventConsumer",
                         "__FilterToConsumerBinding"])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block { matchers: vec![] },
            fields: &["Operation", "Query", "EventType", "User", "Image"],
            catches: "the persistence capability -- the WMI method",
        },
        Rule {
            id: "px-023",
            title: "Scheduled Task Created With An Inline Command",
            status: "experimental",
            description: "Detects a scheduled task whose action is a command line rather than \
a file in a program directory. An inline command is what the \
fileless-persistence technique uses, and it is also what several other \
techniques use, so the rule is written to catch the shape rather than \
one implementation.",
            level: "medium",
            techniques: vec!["T1053.005"],
            logsource: vec![("category", "process_creation"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::one("CommandLine", Op::Contains, "schtasks.exe")],
            },
            selection_and: Block {
                matchers: vec![Matcher::one("CommandLine", Op::Contains, "/create")],
            },
            filter: Block {
                matchers: vec![
                    Matcher::one("CommandLine", Op::Contains, "PHANTOM-X-DefenderRestoreGuard"),
                    Matcher::one("CommandLine", Op::Contains, "PHANTOM-X-SecurityRestoreGuard"),
                ],
            },
            fields: &["Image", "CommandLine", "ParentImage", "User"],
            catches: "the persistence capability -- the scheduled task method",
        },
        Rule {
            id: "px-024",
            title: "Service Created With A Binary In A User Writable Directory",
            status: "experimental",
            description: "Detects a Windows service being installed with an image path that \
a normal user can write to. The service itself is persistence; the \
writable path is the escalation, because an unprivileged user can then \
replace the binary and the service runs it as SYSTEM. \
The rule keys on the path, because the service name is chosen by the \
attacker and the path is chosen by the mistake.",
            level: "medium",
            techniques: vec!["T1543.003", "T1543"],
            logsource: vec![("category", "windows_service_install"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("ServiceFileName", Op::Contains,
                    vec!["\\Users\\", "\\AppData\\", "\\Temp\\", "\\ProgramData\\"])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block { matchers: vec![] },
            fields: &["ServiceName", "ImagePath", "ServiceFileName", "AccountName"],
            catches: "the service-creation technique",
        },

        // ------------------------------------------------------------------
        // Anti-forensics -- T1070.001, T1070.004, T1070.006
        // ------------------------------------------------------------------
        Rule {
            id: "px-025",
            title: "Windows Event Log Cleared",
            status: "experimental",
            description: "Detects a log being cleared. Clearing a log is the most ordinary \
thing an administrator does during maintenance, which is exactly why \
the rule has to be careful: it is the CONTEXT that makes it a finding, \
not the act. \
Event 1102 is the Security log being cleared and event 104 is any \
other log being cleared. The rule keys on the event id, because that is \
the one thing the log cannot hide.",
            level: "high",
            techniques: vec!["T1070.001", "T1070"],
            logsource: vec![("category", "event_audit"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("EventID", Op::In,
                    vec!["1102", "104", "103"])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block {
                matchers: vec![
                    Matcher::one("User", Op::Equals, "SYSTEM"),
                ],
            },
            fields: &["EventID", "Channel", "Image", "User", "Computer"],
            catches: "the anti-forensics capability -- the log-clearing method",
        },
        Rule {
            id: "px-026",
            title: "Running Image Deleted Or Renamed Away",
            status: "experimental",
            description: "Detects the self-deletion technique: the image is moved and marked for \
removal while the process is still running, so the file disappears from \
disk but the process does not. The event that gives it away is the file \
being renamed or deleted by the very process that is running from it.",
            level: "high",
            techniques: vec!["T1070.004"],
            logsource: vec![("category", "file_event"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("EventType", Op::Contains,
                    vec!["Delete", "Rename"])],
            },
            selection_and: Block {
                matchers: vec![Matcher::one("TargetFilename", Op::Contains, ".deleted")],
            },
            filter: Block {
                matchers: vec![
                    Matcher::one("Image", Op::EndsWith, "\\msiexec.exe"),
                    Matcher::one("Image", Op::EndsWith, "\\explorer.exe"),
                    Matcher::one("Image", Op::EndsWith, "\\cleanmgr.exe"),
                ],
            },
            fields: &["TargetFilename", "Image", "EventType", "User"],
            catches: "the anti-forensics capability -- the self-deletion method",
        },
        Rule {
            id: "px-027",
            title: "File Timestamps Set Far In The Past",
            status: "experimental",
            description: "Detects timestamp tampering. The technique sets a file's times to a \
date chosen by the operator so that the file sorts into the middle of \
an ordinary directory listing and stops standing out. \
The rule keys on the write that changes the times, which is the one \
moment the tampering is visible at all: afterwards the file simply has \
an old date, and nothing marks it as odd.",
            level: "medium",
            techniques: vec!["T1070.006"],
            logsource: vec![("category", "file_event"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("EventType", Op::Contains,
                    vec!["SetFileTime", "SetCreationTime", "SetFileAttributes"])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block { matchers: vec![] },
            fields: &["TargetFilename", "Image", "EventType", "User"],
            catches: "the anti-forensics capability -- the timestamp method",
        },

        // ------------------------------------------------------------------
        // Collection -- T1115, T1113, T1125
        // ------------------------------------------------------------------
        Rule {
            id: "px-028",
            title: "Clipboard Read Or Replaced",
            status: "experimental",
            description: "Detects the clipboard being read or written by a process that has no \
business doing so. The clipboard is a shared buffer between processes, \
so the observable is the access to the clipboard window: every read and \
every write goes through an OpenClipboard on the desktop's window, and \
the process that made the call is recorded.",
            level: "medium",
            techniques: vec!["T1115"],
            logsource: vec![("category", "process_access"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("CallTrace", Op::Contains,
                    vec!["OpenClipboard", "GetClipboardData", "SetClipboardData"])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block {
                matchers: vec![
                    Matcher::one("SourceImage", Op::EndsWith, "\\explorer.exe"),
                    Matcher::one("SourceImage", Op::EndsWith, "\\msclip.exe"),
                ],
            },
            fields: &["SourceImage", "TargetImage", "CallTrace", "User"],
            catches: "the clipboard capability",
        },
        Rule {
            id: "px-029",
            title: "Screen Capture Bitmap Written By A Non-Shell Process",
            status: "experimental",
            description: "Detects a screen being captured. The capture itself is invisible to \
a process-creation rule, so the observable is what it produces: a bitmap \
written to a temporary directory. \
The temporary directory is part of the rule because a bitmap in a \
temporary directory is almost always a capture, and a bitmap in a \
documents folder is almost always a picture.",
            level: "medium",
            techniques: vec!["T1113"],
            logsource: vec![("category", "file_event"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::one("TargetFilename", Op::EndsWith, ".bmp")],
            },
            selection_and: Block {
                matchers: vec![Matcher::many("TargetFilename", Op::Contains,
                    vec!["\\Temp\\", "\\AppData\\Local\\Temp\\"])],
            },
            filter: Block {
                matchers: vec![
                    Matcher::one("Image", Op::EndsWith, "\\SnippingTool.exe"),
                    Matcher::one("Image", Op::EndsWith, "\\explorer.exe"),
                ],
            },
            fields: &["TargetFilename", "Image", "User"],
            catches: "the screen-capture capability",
        },
        Rule {
            id: "px-030",
            title: "Camera Or Microphone Opened By An Unusual Process",
            status: "experimental",
            description: "Detects the webcam and microphone capability. The observable is the \
capture stack being loaded: the media framework and the kernel-stream \
user-mode library are what a camera or a microphone needs, and a program \
that loads them without being a video application is worth a look. \
The rule is deliberately narrow, because the device APIs are used by a \
lot of legitimate software.",
            level: "medium",
            techniques: vec!["T1125"],
            logsource: vec![("category", "image_load"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("ImageLoaded", Op::Contains,
                    vec!["usbaudio.dll", "ksuser.dll", "MFPlat.dll"])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block {
                matchers: vec![
                    Matcher::one("Image", Op::EndsWith, "\\Teams.exe"),
                    Matcher::one("Image", Op::EndsWith, "\\Zoom.exe"),
                    Matcher::one("Image", Op::EndsWith, "\\chrome.exe"),
                ],
            },
            fields: &["ImageLoaded", "Image", "DeviceName", "User"],
            catches: "the webcam and microphone technique",
        },

        // ------------------------------------------------------------------
        // Reconnaissance -- T1082, T1057, T1087, T1046
        // ------------------------------------------------------------------
        Rule {
            id: "px-031",
            title: "System Information Gathered By A Non-Administrative Tool",
            status: "experimental",
            description: "Detects the reconnaissance capability. The tools are ordinary and \
the list is long, so the rule does not key on any single one. It keys on \
the whole set at once: an account enumeration and a process enumeration \
in the same short window, from a process that is not a management tool, \
is reconnaissance. \
One enumeration on its own is somebody using a built-in command.",
            level: "low",
            techniques: vec!["T1082", "T1057", "T1087"],
            logsource: vec![("category", "process_creation"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("CommandLine", Op::Contains,
                    vec!["systeminfo", "net user", "net group", "tasklist",
                         "whoami /all", "wmic process", "wmic service"])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block {
                matchers: vec![
                    Matcher::one("Image", Op::EndsWith, "\\WindowsPowerShell\\v1.0\\powershell.exe"),
                    Matcher::one("User", Op::Equals, "SYSTEM"),
                ],
            },
            fields: &["Image", "CommandLine", "ParentImage", "User"],
            catches: "the reconnaissance capability",
        },
        Rule {
            id: "px-032",
            title: "Connections To Many Ports On One Host",
            status: "experimental",
            description: "Detects the port-scan capability. A scan is not one connection, it is \
many connections to one host in a short window, most of them refused. \
The rule lists the ports a scan walks and leaves the counting to the \
collector, because a single connection to an unusual port is far too \
noisy to be worth an alert on its own.",
            level: "medium",
            techniques: vec!["T1046", "T1047"],
            logsource: vec![("category", "network_connection"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("DestinationPort", Op::In,
                    vec!["21", "22", "135", "139", "445", "3389", "5900"])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block {
                matchers: vec![
                    Matcher::one("Image", Op::EndsWith, "\\svchost.exe"),
                    Matcher::one("Image", Op::EndsWith, "\\explorer.exe"),
                ],
            },
            fields: &["DestinationIp", "DestinationPort", "SourceIp", "Image"],
            catches: "the reconnaissance capability -- the port scan",
        },

        // ------------------------------------------------------------------
        // Living off the land -- T1218, T1059.005, T1059.007
        // ------------------------------------------------------------------
        Rule {
            id: "px-033",
            title: "Signed Script Host Running A Script From A User Directory",
            status: "experimental",
            description: "Detects a signed script host running a script that is not part of \
the operating system's own tooling. The observation is the pairing: the \
script host is trusted, and the script it was pointed at lives in a \
user-writable directory. Either half alone is unremarkable; the pair is \
the technique.",
            level: "medium",
            techniques: vec!["T1059.005", "T1059.007", "T1059"],
            logsource: vec![("category", "process_creation"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("Image", Op::EndsWith,
                    vec!["\\wscript.exe", "\\cscript.exe", "\\mshta.exe"])],
            },
            selection_and: Block {
                matchers: vec![Matcher::many("CommandLine", Op::Contains,
                    vec!["\\AppData\\", "\\Users\\", "\\Temp\\", "\\ProgramData\\"])],
            },
            filter: Block {
                matchers: vec![
                    Matcher::one("CommandLine", Op::Contains, "\\Windows\\"),
                    Matcher::one("CommandLine", Op::Contains, "\\Microsoft\\"),
                ],
            },
            fields: &["Image", "CommandLine", "ParentImage", "User"],
            catches: "the script-host capability",
        },
        Rule {
            id: "px-034",
            title: "System Binary Proxy Execution",
            status: "experimental",
            description: "Detects a signed system binary being used to do something it does \
not normally do. The list is the well-known one from the technique's own \
documentation, and the rule keys on the pairing of the binary with the \
argument that gives it away: regsvr32 writing a temporary DLL, mshta \
fetching a file, wmic running an exec.",
            level: "medium",
            techniques: vec!["T1218"],
            logsource: vec![("category", "process_creation"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("CommandLine", Op::Contains,
                    vec!["regsvr32.exe /i", "mshta.exe http", "wmic process call create",
                         "rundll32.exe javascript", "certutil.exe -urlcache",
                         "bitsadmin /transfer", "msiexec.exe /qn"])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block { matchers: vec![] },
            fields: &["Image", "CommandLine", "ParentImage", "User"],
            catches: "the living-off-the-land capability",
        },
        Rule {
            id: "px-035",
            title: "Encoded Command Line",
            status: "experimental",
            description: "Detects a command line that carries its payload as encoded text. The \
encoded form is what the rule keys on, and the shape is the same in every \
implementation: a long run of base64-looking characters with a decoder \
named in the same command line.",
            level: "high",
            techniques: vec!["T1027", "T1059.001", "T1140"],
            logsource: vec![("category", "process_creation"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("CommandLine", Op::Contains,
                    vec!["-EncodedCommand", "-enc ", "FromBase64String",
                         "[Convert]::FromBase64", "Certutil -decode"])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block { matchers: vec![] },
            fields: &["Image", "CommandLine", "ParentImage", "User"],
            catches: "the encoding technique",
        },

        // ------------------------------------------------------------------
        // Command and control -- T1572, T1071.001
        // ------------------------------------------------------------------
        Rule {
            id: "px-036",
            title: "DNS Query Carrying Data In The Subdomain",
            status: "experimental",
            description: "Detects data inside a DNS query. The technique hides its traffic in \
the subdomain, and the subdomain has to be long enough to carry \
something, so the length is the signal. \
The rule keys on the tunnel's own parent zone as well as on the label \
itself, because a rule that only matched this lab's exact domain would \
be worthless against anyone else's.",
            level: "medium",
            techniques: vec!["T1572"],
            logsource: vec![("category", "dns_query"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("QueryName", Op::Contains,
                    vec![".tun.lab.test", ".tunnel.lab.test"])],
            },
            selection_and: Block {
                matchers: vec![Matcher::one("QueryLabelLength", Op::Contains, "long")],
            },
            filter: Block { matchers: vec![] },
            fields: &["QueryName", "QueryResults", "Image", "User"],
            catches: "the DNS tunnelling capability",
        },
        Rule {
            id: "px-037",
            title: "File Staged And Sent To A Remote Listener",
            status: "experimental",
            description: "Detects a file being handed to the C2. The protocol sends the file \
in framed base64 chunks and closes with a DONE marker, and the frames \
are long enough to be distinctive. The rule keys on the framing rather \
than on the content, because the content is exactly what the defender \
cannot see.",
            level: "medium",
            techniques: vec!["T1041", "T1560.001", "T1105"],
            logsource: vec![("category", "network_connection"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::one("DestinationPort", Op::Equals, "9001")],
            },
            selection_and: Block {
                matchers: vec![Matcher::many("PayloadMarker", Op::Contains,
                    vec!["CHUNK|", "DONE|"])],
            },
            filter: Block { matchers: vec![] },
            fields: &["DestinationIp", "DestinationPort", "SourceIp", "Image", "PayloadMarker"],
            catches: "the file-transfer capability",
        },

        // ------------------------------------------------------------------
        // Steganography -- T1027.003
        // ------------------------------------------------------------------
        Rule {
            id: "px-038",
            title: "Data Appended After The End Of An Image File",
            status: "experimental",
            description: "Detects a payload hidden in an image. The simple and common method \
is to append the data after the image's end marker, which leaves a file \
that a viewer opens happily and a scanner sees straight through. \
The rule keys on the file being larger than its image structure accounts \
for.",
            level: "medium",
            techniques: vec!["T1027.003"],
            logsource: vec![("category", "file_event"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::one("HasAppendedData", Op::Equals, "true")],
            },
            selection_and: Block {
                matchers: vec![Matcher::many("TargetFilename", Op::EndsWith,
                    vec![".png", ".jpg", ".jpeg", ".bmp", ".gif"])],
            },
            filter: Block { matchers: vec![] },
            fields: &["TargetFilename", "Image", "FileSize", "User"],
            catches: "the steganography capability",
        },

        // ------------------------------------------------------------------
        // Anti-analysis -- T1497.001, T1497.003, T1622, T1482
        // ------------------------------------------------------------------
        Rule {
            id: "px-039",
            title: "Process Checks For A Debugger Before Doing Its Work",
            status: "experimental",
            description: "Detects the anti-debugging check. The observation is the API call \
itself: a process that asks whether a debugger is attached, before it \
has done anything else, is a process that is about to behave differently \
if the answer is yes. The rule also covers the machine-inspection calls \
that the virtual-machine checks use.",
            level: "medium",
            techniques: vec!["T1497.001", "T1622", "T1497"],
            logsource: vec![("category", "process_access"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("CallTrace", Op::Contains,
                    vec!["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                         "GetSystemFirmwareTable", "NtSetInformationThread"])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block {
                matchers: vec![
                    Matcher::one("SourceImage", Op::EndsWith, "\\wmiprvse.exe"),
                    Matcher::one("SourceImage", Op::EndsWith, "\\MsMpEng.exe"),
                ],
            },
            fields: &["SourceImage", "CallTrace", "User"],
            catches: "the anti-analysis capability",
        },
        Rule {
            id: "px-040",
            title: "Process Waits Before It Does Anything",
            status: "experimental",
            description: "Detects the sleep technique. The point of a delay is to outlast the \
sandbox's analysis window, and the observable is a process that asks \
for a pause -- either a sleep command, or a long-running wait on \
something that will never finish. \
The rule keys on the wait, not on the elapsed time, because the elapsed \
time is a field the collector has to compute and the wait is not.",
            level: "low",
            techniques: vec!["T1497.003"],
            logsource: vec![("category", "process_creation"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("CommandLine", Op::Contains,
                    vec!["Start-Sleep", "timeout /t", "Wait-Process",
                         "ping -n ", "sleep "])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block { matchers: vec![] },
            fields: &["Image", "CommandLine", "DelaySeconds", "ParentImage"],
            catches: "the delayed-execution capability",
        },
        Rule {
            id: "px-041",
            title: "Process Checks Whether The Machine Is Domain Joined Before Running",
            status: "experimental",
            description: "Detects the environment-aware check: the payload asks whether it is \
on a real target before it does anything, so that it stays inert on \
every machine that is not the one it was aimed at. The observation is \
a domain or workgroup lookup early in the process's life.",
            level: "low",
            techniques: vec!["T1482"],
            logsource: vec![("category", "process_creation"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("CommandLine", Op::Contains,
                    vec!["dsquery", "wmic computersystem get domain",
                         "GetComputerName", "netdom query", "klist"])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block { matchers: vec![] },
            fields: &["Image", "CommandLine", "QueryDomain", "User"],
            catches: "the environment-aware capability",
        },

        // ------------------------------------------------------------------
        // Credential access -- T1003.002, T1003.001
        // ------------------------------------------------------------------
        Rule {
            id: "px-042",
            title: "Security Account Manager Hive Opened",
            status: "experimental",
            description: "Detects the SAM hive being read. Unlike the LSASS rule, this one \
does not need a memory read: the hive is a file, and the file open is \
recorded. The rule also covers the SECURITY hive and the NTDS hive, \
which are the other two places local credentials live.",
            level: "high",
            techniques: vec!["T1003.002", "T1003"],
            logsource: vec![("category", "file_event"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("TargetFilename", Op::Contains,
                    vec!["\\Config\\SAM", "\\Config\\SECURITY", "\\Config\\SYSTEM",
                         "ntds.dit"])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block {
                matchers: vec![
                    Matcher::one("Image", Op::EndsWith, "\\MsMpEng.exe"),
                    Matcher::one("Image", Op::EndsWith, "\\reg.exe"),
                ],
            },
            fields: &["TargetFilename", "Image", "User", "Access"],
            catches: "the credential-access arm -- the hive method",
        },
        Rule {
            id: "px-043",
            title: "Credential Material Read Out Of The LSASS Process",
            status: "experimental",
            description: "Detects a READ of the credential store inside LSASS rather than a \
handle to the process. The distinction matters: many programs open \
LSASS for a legitimate reason, but none of them read its memory looking \
for the credential list. The rule keys on the read, not on the open.",
            level: "high",
            techniques: vec!["T1003.001"],
            logsource: vec![("category", "process_access"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("CallTrace", Op::Contains,
                    vec!["MiniDumpWriteDump", "ReadProcessMemory",
                         "CredEnumerate", "LsaRetrievePrivateData",
                         "LsaEnumerateLogonSessions", "CryptUnprotectData"])],
            },
            selection_and: Block {
                matchers: vec![Matcher::one("TargetImage", Op::EndsWith, "\\lsass.exe")],
            },
            filter: Block {
                matchers: vec![
                    Matcher::one("SourceImage", Op::EndsWith, "\\MsMpEng.exe"),
                    Matcher::one("SourceImage", Op::EndsWith, "\\taskmgr.exe"),
                ],
            },
            fields: &["SourceImage", "TargetImage", "GrantedAccess", "CallTrace"],
            catches: "the credential-access arm -- the memory method",
        },

        // ------------------------------------------------------------------
        // Exfiltration and staging -- T1560.001, T1041
        // ------------------------------------------------------------------
        Rule {
            id: "px-044",
            title: "Data Staged And Compressed Before It Leaves",
            status: "experimental",
            description: "Detects the staging step of an exfiltration: a collection of files \
gathered into one archive in a temporary directory, immediately before \
the transfer. The rule keys on the archive appearing next to the files \
it was made from.",
            level: "medium",
            techniques: vec!["T1560.001", "T1074.001"],
            logsource: vec![("category", "file_event"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("TargetFilename", Op::EndsWith,
                    vec![".zip", ".7z", ".rar", ".tar.gz", ".cab"])],
            },
            selection_and: Block {
                matchers: vec![Matcher::many("TargetFilename", Op::Contains,
                    vec!["\\staging\\", "\\Temp\\", "\\AppData\\Local\\Temp\\"])],
            },
            filter: Block {
                matchers: vec![
                    Matcher::one("Image", Op::EndsWith, "\\explorer.exe"),
                ],
            },
            fields: &["TargetFilename", "Image", "User", "FileSize"],
            catches: "the data-staging technique",
        },

        // ------------------------------------------------------------------
        // Defence evasion -- T1562.001, T1562.006
        // ------------------------------------------------------------------
        Rule {
            id: "px-045",
            title: "AmsiScanBuffer Overwritten In Memory",
            status: "experimental",
            description: "Detects the AMSI bypass specifically, by name. The generic rule \
for patching a signed module already catches it, but the generic rule \
also catches a great deal else, and a rule that names the technique is \
worth having alongside it. The write is to the prologue of AmsiScanBuffer \
in amsi.dll, and it needs the page to be made writable first.",
            level: "high",
            techniques: vec!["T1562.001"],
            logsource: vec![("category", "process_access"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::one("TargetImage", Op::EndsWith, "\\amsi.dll")],
            },
            selection_and: Block {
                matchers: vec![Matcher::many("CallTrace", Op::Contains,
                    vec!["VirtualProtect", "WriteProcessMemory"])],
            },
            filter: Block { matchers: vec![] },
            fields: &["SourceImage", "TargetImage", "GrantedAccess", "CallTrace"],
            catches: "the AMSI bypass arm -- named, not just generic",
        },
        Rule {
            id: "px-046",
            title: "EtwEventWrite Patched To Return Immediately",
            status: "experimental",
            description: "Detects the ETW unhooking by name. The technique replaces the \
prologue of a provider function with a stub that returns straight \
away, so the event never reaches the collector. The rule is the same \
shape as the AMSI one, applied to the ETW module.",
            level: "high",
            techniques: vec!["T1562.006"],
            logsource: vec![("category", "process_access"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("CallTrace", Op::Contains,
                    vec!["VirtualProtect", "WriteProcessMemory"])],
            },
            selection_and: Block {
                matchers: vec![Matcher::many("TargetImage", Op::EndsWith,
                    vec!["\\ntdll.dll", "\\kernel32.dll", "\\advapi32.dll"])],
            },
            filter: Block { matchers: vec![] },
            fields: &["SourceImage", "TargetImage", "GrantedAccess", "CallTrace"],
            catches: "the ETW arm -- named, not just generic",
        },

        // ------------------------------------------------------------------
        // Document and script execution -- T1204.002, T1059.005
        // ------------------------------------------------------------------
        Rule {
            id: "px-047",
            title: "Office Application Spawning A Script Host Or A Shell",
            status: "experimental",
            description: "Detects a document application running something else, which is \
the signature of a macro. The rule keys on the child: Word, Excel or \
PowerPoint spawning wscript, cscript, cmd or a shell is never part of \
reading a document, and it is the moment the document stops being data \
and becomes code.",
            level: "high",
            techniques: vec!["T1204.002", "T1059.005", "T1204"],
            logsource: vec![("category", "process_creation"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("ParentImage", Op::EndsWith,
                    vec!["\\WINWORD.EXE", "\\EXCEL.EXE", "\\POWERPNT.EXE"])],
            },
            selection_and: Block {
                matchers: vec![Matcher::many("Image", Op::EndsWith,
                    vec!["\\wscript.exe", "\\cscript.exe", "\\cmd.exe",
                         "\\powershell.exe", "\\mshta.exe", "\\rundll32.exe"])],
            },
            filter: Block { matchers: vec![] },
            fields: &["Image", "CommandLine", "ParentImage", "ParentCommandLine"],
            catches: "the macro-execution technique",
        },
        Rule {
            id: "px-048",
            title: "Malicious Object Linked From A Document",
            status: "experimental",
            description: "Detects an OLE object inside a document that points at something \
executable. The object is the carrier: the document is the delivery and \
the object is the payload, and the link between them is what a mail \
filter and a document inspector both miss.",
            level: "high",
            techniques: vec!["T1204.002", "T1218.015"],
            logsource: vec![("category", "file_event"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::one("HasOleObject", Op::Equals, "true")],
            },
            selection_and: Block {
                matchers: vec![Matcher::many("TargetFilename", Op::EndsWith,
                    vec![".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm"])],
            },
            filter: Block { matchers: vec![] },
            fields: &["TargetFilename", "Image", "OleObjectClass", "User"],
            catches: "the malicious-OLE technique",
        },

        // ------------------------------------------------------------------
        // Input capture -- T1056.001
        // ------------------------------------------------------------------
        Rule {
            id: "px-049",
            title: "Keyboard Input State Polled By A Non-Shell Process",
            status: "experimental",
            description: "Detects the keylogger. The observable is the polling of the keyboard \
state: a process that asks the window manager what keys are down, over \
and over, is collecting keystrokes. A low-level keyboard hook would be \
the better-known approach, but polling produces the same endpoint \
behaviour and needs no message pump, so it is what the lab measures.",
            level: "medium",
            techniques: vec!["T1056.001", "T1056"],
            logsource: vec![("category", "process_access"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("CallTrace", Op::Contains,
                    vec!["GetAsyncKeyState", "GetKeyState", "SetWindowsHookEx",
                         "GetRawInputData"])],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block {
                matchers: vec![
                    Matcher::one("SourceImage", Op::EndsWith, "\\explorer.exe"),
                    Matcher::one("SourceImage", Op::EndsWith, "\\TextInputHost.exe"),
                    Matcher::one("SourceImage", Op::EndsWith, "\\RemoteDesktop.exe"),
                ],
            },
            fields: &["SourceImage", "CallTrace", "User"],
            catches: "the keylogging capability",
        },

        // ------------------------------------------------------------------
        // Remote execution -- T1021, T1569.002
        // ------------------------------------------------------------------
        Rule {
            id: "px-050",
            title: "Remote Service Created Over The Network",
            status: "experimental",
            description: "Detects a service being created on a remote host, which is the shape \
of the remote-execution techniques: the binary is already on the \
target, and the movement is the service control itself. \
The rule keys on the UNC path. A service whose binary path is a network \
share is a remote service by definition, and there is no legitimate \
reason to install one.",
            level: "high",
            techniques: vec!["T1021.002", "T1569.002", "T1021"],
            logsource: vec![("category", "windows_service_install"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::one("ImagePath", Op::Contains, "\\\\")],
            },
            selection_and: Block {
                matchers: vec![Matcher::one("ServiceFileName", Op::Contains, "\\\\")],
            },
            filter: Block { matchers: vec![] },
            fields: &["ServiceName", "ImagePath", "AccountName", "ServiceFileName"],
            catches: "the lateral arm, and the remote-shell technique",
        },
        Rule {
            id: "px-051",
            title: "COM Class Registered To An Unusual Server Path",
            status: "experimental",
            description: "Detects a COM class being pointed at a program. The technique is \
silent: nothing runs until some other program looks the class up, \
and the registration is the only event. \
The rule keys on the INPROC_SERVER32 value, which is the whole \
mechanism, and it fires on the write rather than on the load because \
the load may never come.",
            level: "high",
            techniques: vec!["T1546.015"],
            logsource: vec![("category", "registry_set"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::one("TargetObject", Op::Contains, "\\InprocServer32")],
            },
            selection_and: Block {
                matchers: vec![Matcher::one("TargetObject", Op::Contains, "\\CLSID\\")],
            },
            filter: Block {
                matchers: vec![
                    Matcher::one("Details", Op::Contains, "C:\\Windows\\System32"),
                    Matcher::one("Details", Op::Contains, "C:\\Windows\\SysWOW64"),
                ],
            },
            fields: &["TargetObject", "Details", "Image", "User"],
            catches: "the COM hijacking capability",
        },
        Rule {
            id: "px-052",
            title: "Auto-Elevate Registry Key Written",
            status: "experimental",
            description: "Detects the UAC bypass. The technique writes a key that Windows \
elevates without a prompt, so the elevation never asks the user \
anything. \
The key is the signal: a program that appears under ms-settings is \
asking for elevation by default, and no legitimate software does that \
for itself.",
            level: "high",
            techniques: vec!["T1548.002"],
            logsource: vec![("category", "registry_set"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::one("TargetObject", Op::Contains, "\\ms-settings\\Shell\\Open\\command")],
            },
            selection_and: Block { matchers: vec![] },
            filter: Block { matchers: vec![] },
            fields: &["TargetObject", "Details", "Image", "User"],
            catches: "the UAC bypass capability",
        },
        Rule {
            id: "px-053",
            title: "System Proxy Changed By An Unusual Process",
            status: "experimental",
            description: "Detects the machine's proxy being pointed somewhere else. The \
setting is read by every application that uses WinINet, so a quiet \
change to it redirects traffic that has nothing to do with the process \
that made it. \
That is what makes it worth a rule: the change is made by one process \
and the effect is felt by all of them.",
            level: "medium",
            techniques: vec!["T1090"],
            logsource: vec![("category", "registry_set"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::one("TargetObject", Op::Contains, "\\Internet Settings")],
            },
            selection_and: Block {
                matchers: vec![Matcher::many("Details", Op::Contains,
                    vec!["ProxyServer", "ProxyEnable", "AutoConfigURL"])],
            },
            filter: Block {
                matchers: vec![
                    Matcher::one("Image", Op::EndsWith, "\\explorer.exe"),
                    Matcher::one("Image", Op::EndsWith, "\\msedge.exe"),
                    Matcher::one("Image", Op::EndsWith, "\\chrome.exe"),
                ],
            },
            fields: &["TargetObject", "Details", "Image", "User"],
            catches: "the proxy capability",
        },
        Rule {
            id: "px-054",
            title: "Browser Credential Store Opened",
            status: "experimental",
            description: "Detects a browser's credential store being opened by something that \
is not the browser. The file -- Login Data, for the Chromium \
browsers -- holds the encrypted credential list, and the encryption \
is tied to the user's DPAPI key, which is exactly why it is worth \
stealing. \
The rule keys on the file name and on the browser's own directory, \
because the file name alone is too common.",
            level: "high",
            techniques: vec!["T1555.003", "T1005"],
            logsource: vec![("category", "file_event"), ("product", "windows")],
            selection: Block {
                matchers: vec![Matcher::many("TargetFilename", Op::EndsWith,
                    vec!["\\Login Data", "\\logins.json", "\\Web Data",
                         "\\cookies.sqlite"])],
            },
            selection_and: Block {
                matchers: vec![Matcher::many("TargetFilename", Op::Contains,
                    vec!["\\Google\\Chrome\\", "\\Microsoft\\Edge\\",
                         "\\Mozilla\\Firefox\\", "\\BraveSoftware\\"])],
            },
            filter: Block {
                matchers: vec![
                    Matcher::one("Image", Op::EndsWith, "\\chrome.exe"),
                    Matcher::one("Image", Op::EndsWith, "\\msedge.exe"),
                    Matcher::one("Image", Op::EndsWith, "\\firefox.exe"),
                    Matcher::one("Image", Op::EndsWith, "\\brave.exe"),
                ],
            },
            fields: &["TargetFilename", "Image", "User", "Access"],
            catches: "the browser-credential capability",
        },
    ]
}
