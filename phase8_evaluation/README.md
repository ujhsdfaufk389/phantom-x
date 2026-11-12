# PHANTOM-X -- Phase 8 :: Evaluation

**This is the phase that closes the loop.**

Until now the lab had variant arms and detection rules, and nothing that
connected them. That meant it could not say the thing it exists to say:

> which of my rules still work once the payload is obfuscated, once ETW
> is unhooked, once the channel is encrypted?

Without that, the lab was a collection of samples with some rules next to
them. With it, the lab is a measurement.

---

## The loop

```
   arm built  ->  run on the VM  ->  telemetry collected  ->  rules evaluated
        ^                                                              |
        |                                                              v
        +------------------  which rules survived?  <------------  the finding
```

The finding is about the RULE. A rule that fires on the baseline and is
silent on the obfuscated arm was riding on a plaintext string, and it is
worth knowing that before someone uses it.

---

## The tools

### `px_eval.py` -- the rule evaluator

Evaluates the rules against a set of events and reports which fired.

```
python3 px_eval.py --rules rules.json --events events.json
```

```
  ID        LVL     FIRES  TITLE
  --------- ------- ------ ----------------------------------------
  px-001    high      YES  Suspicious Fileless Execution via Unback
  px-002    medium    YES  PDF File Opened By An Unusual Loader Pro
  px-003    high      YES  C2 Protocol HELLO Followed By PING PONG
  ...
  50 rules, 6 fired, 44 silent
```

It is a small evaluator for the subset of Sigma these rules use, not a
general Sigma implementation. That is deliberate: the lab does not have a
SIEM, and needing one to answer "did this rule fire" would make the
measurement depend on infrastructure the lab does not have.

The semantics follow the Sigma specification rather than the intuition,
because a rule that means something different from its Sigma text is worse
than no rule -- it looks like it works.

### `collect_events.ps1` -- the telemetry collector

Runs on the VM and exports the Windows events the rules key on: Sysmon,
Defender, Task Scheduler, DNS client, PowerShell, and the service log.

It collects a **window** rather than the whole log, so a run can be
attributed to a run. And it clears nothing -- the point is to leave the
evidence in place so the operator can look at it afterwards with the same
eyes as anyone else.

### `coverage.py` -- the coverage matrix

The matrix is the lab's output:

```
  TECHNIQUE     TACTIC             STATUS          RULES
  T1003.001     credential-access  measured        px-009, px-043
  T1027.003     defense-evasion    measured        px-038
  T1548.002     privilege-escalation not exercised
  ...

  THE DENOMINATOR
    techniques in scope   : 93
    measured              : 65
    ruled but not measured: 6
    not exercised at all  : 22
    of which campaigns    : 4

  RULES THAT FIRED ON THE BASELINE AND ARE SILENT ON THE VARIANT
  (these were riding on something the variant removed)

    px-002  PDF File Opened By An Unusual Loader Process
          catches: the loader, on every arm
```

The matrix is driven by the **catalogue**, not by a list kept in the Python
tool, so the denominator is the same everywhere:

```bash
phase7_detection/target/release/px_detect.exe --emit catalog > catalog.json

python3 phase8_evaluation/coverage.py \
    --rules rules.json --catalog catalog.json \
    --baseline events_baseline_arm.json \
    --variant events_obfuscate_arm.json
```

Three kinds of gap, and they need different answers:

| Gap | What it means | Fix |
|---|---|---|
| a technique with no rule | nothing would catch it | write a rule |
| a rule that never fires | it might be broken, or the technique might not be exercised | find out which |
| a technique not exercised | the lab says nothing about it | build a capability, or say so |

The second kind is the interesting one. A rule that looks right and never
fires gives false confidence -- and the catalogue's `ruled` status is
exactly that, made visible.

### `make_synthetic_events.py` -- the test fixtures

The evaluator needs events with known answers, so that "does this rule
fire" can be tested rather than assumed. The fixtures are a table, one
line per case, with the expected rule named next to it.

---

## The rules are structured, not text

The rules used to be Sigma strings in a Rust file. That was the wrong
shape, and it showed up as soon as the lab needed to do anything with
them beyond printing them.

A detection lab has to answer three questions about every rule:

1. what does it say? -- **Sigma**, for a SIEM
2. which technique does it cover? -- **ATT&CK mapping**
3. does it actually fire? -- **evaluation against telemetry**

The third cannot be answered by reading a string. So the rules are
structured -- fields, operators and values -- and **both** the Sigma text
and the machine-readable form are rendered from that one definition.
There is no second copy to drift.

Every rule also carries:

- the **ATT&CK technique** it covers
- the **arm it is expected to catch**, in its own words

The second one is what makes a rule a measurement rather than an
assertion. The coverage report compares the expectation against what
actually fired.

---

## Running a comparison

On the VM:

```powershell
cd C:\pxvm\phase8_evaluation
.\collect_events.ps1 -Label baseline_arm
```

Run the baseline arm, then the variant arm, then collect again.

On the host:

```bash
phase7_detection/target/release/px_detect.exe --emit json > rules.json

python3 phase8_evaluation/coverage.py \
    --rules rules.json \
    --catalog catalog.json \
    --baseline events_baseline_arm.json \
    --variant events_obfuscate_arm.json
```

---

## What the rules are for

The baseline rules (px-001 to px-008) key on what the CHAIN does rather
than on any one technique's signature. They are the arm that has to
survive every variant, because they key on behaviour that the variants
do not change.

The variant rules (px-009 to px-014) are the detections for the specific
arms. Each is written to key on **behaviour** rather than on a string,
because a rule that keys on a string stops working the moment the string
is encoded.

The capability rules (px-015 onwards) are the detections for the technique
library, and they were written in the opposite order: for each technique
the question was asked **first** -- *if this happened on a real host, what
would the endpoint see?* -- and the answer became the rule. Then the
capability was written to produce exactly that telemetry.

That order matters. A rule written after the fact tends to key on whatever
the code happened to do; a rule written first tends to key on the behaviour
that matters.

**px-013 is the important one.** It catches the AMSI and ETW unhooking
arms by the writable-and-executable page they leave behind in a signed
module -- and it does that **without needing ETW**, which the unhooked
arm disables. A detection that needs the mechanism it is detecting is
not a detection.

---

## Testing the evaluator

```bash
python3 phase8_evaluation/test_evaluator.py
```

996 assertions pinning the semantics: the selection must match, the
selection_and block must match, the filter must not, matchers inside a
block are OR'd, the comparison is case-insensitive, an absent field never
matches, and a backslash in a Windows path survives the JSON round trip.

Three of those checks are about the rules rather than the evaluator, and
they are the ones that keep a rule from being a noise generator:

- **every synthetic arm fires its own rules** -- one arm per technique, so
  that a telemetry delta can be attributed to the technique that produced
  it
- **and only its own rules** -- a rule that fires on every event of every
  arm is not a detection, it is a line of noise in the report
- **every rule the catalogue names exists, and every technique a rule
  claims is in the catalogue** -- a catalogue entry that names a rule
  which does not exist would make the coverage matrix claim a technique
  is covered when nothing detects it

That last one is not hypothetical. The first version of the JSON emitter
did not escape backslashes, so every path in every rule was an invalid
JSON escape and the output did not parse at all -- which would have
looked like "no rules fired" rather than "the tool is broken".
