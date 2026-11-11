# PHANTOM-X -- Defensive Detections (Phase 7)

**This is the deliverable that outlives the lab.**

The chain in this project exists to produce a signal. These rules are what
turn that signal into an alert. A working chain with no detection is a
party trick; a working chain with a matching rule is a finding.

---

## What the rules cover

| ID | Rule | Keys on |
|---|---|---|
| px-001 | Suspicious Fileless Execution via Unbacked Private Memory | `px_loader.exe` / `px_payload.exe` process creation |
| px-002 | PDF File Opened By An Unusual Loader Process | a non-reader opening a `.pdf` |
| px-003 | C2 Protocol HELLO / PING-PONG Exchange | the lab C2 wire protocol on the wire |
| px-004 | Process Created From PDF With Embedded PE Payload | a loader spawning from a PDF |
| px-005 | Hollowed Process With Unbacked Image | process hollowing by the hollow tool |
| px-006 | PDF Handler Registration Redirecting `.pdf` | the registry change the lab makes |
| px-007 | Defender Real-Time Protection Disabled By Script | `Set-MpPreference` / `DisableRealtimeMonitoring` |
| px-008 | Guard Scheduled Task Created Alongside Defender Change | the A/B restore guard task |

---

## The rule that matters most is px-007

The lab disables Defender on purpose, to measure the coverage gap. It also
arms a restore guard that re-enables it shortly after. Both of those are
legitimate lab operations on a machine the operator owns.

They are also exactly what an attacker does. There is no technical
difference between "a researcher toggling Defender to measure a gap" and
"an attacker disabling Defender to run something", which is why a defender
sees both the same way.

**px-007 and px-008 exist so that a defender can tell the difference from
the surrounding context**, not so they can whitelist the lab. The
distinguishing context is:

- the restore guard re-enabling protection within 60-120 seconds
- the machine being a known research host
- the operator's own documentation of the window

---

## Usage

```powershell
# list the rules
.\px_detect.exe --list

# print one rule with its reasoning
.\px_detect.exe --explain px-003

# emit Sigma rules
.\px_detect.exe --emit sigma > detections.yml

# emit rule metadata as JSON
.\px_detect.exe --emit json
```

---

## Building

```powershell
cd phase7_detection
cargo build --release
.\target\release\px_detect.exe --emit sigma
```

No crates. The tool builds offline with nothing but a Rust toolchain, and
there is no third-party code to audit.

---

## What is NOT here

There is deliberately **no obfuscation, no AMSI bypass, no ETW unhooking,
no encrypted channel and no domain generation** anywhere in this project.

That is not squeamishness, it is the method working correctly:

> A payload that evades produces no signal to analyse, which would defeat
> the purpose of a detection study.

Every rule above keys on something that is *observable*. If the payload
started hiding, the rules would stop firing, and the measurement would
become a claim rather than a result. The lab's value is that the chain is
plain enough to be caught, so that the catching can be documented.

---

## Note on the Sigma format

The rules are emitted as Sigma, but they have **not** been validated
against the Sigma specification schema. They are written to be read,
reviewed and hand-checked. Before deploying them into a SIEM, validate
them against the schema for your Sigma version and the specific backends
in use. Sigma's own guidance is that a rule which does not parse is
better than a rule which parses but means something different.
