# PHANTOM-X — Phase 1, Experiment 1
## PDF Attack Surface: Structural Analysis and Document-Action Inventory

**Status:** Part A (Linux) complete with real results. Part B (Windows VM) pending your run.

---

## 1. Objective

Determine what a PDF file can *ask* a reader to do, as distinct from what a reader will *actually* do.

This experiment answers only the first question. The second requires the Windows 11 VM.

**In scope**
- Inventory of document features that cross a trust boundary: embedded files, JavaScript, launch actions, URI/external references, form actions, active-content annotations.
- A read-only analyzer that reports structure with evidence and hashes.
- A controlled set of test documents that exercise each feature class without exploiting anything.
- An independent cross-check that the analyzer is not merely agreeing with itself.

**Explicitly out of scope for this experiment**
- Any claim that opening a PDF causes code execution. That is false as a general statement and this experiment is designed to show *why* it is false: the document asks, the reader disposes.
- Parser vulnerability discovery. This is an inventory tool, not a fuzzer.
- Any change to Defender, the reader, or the VM.

---

## 2. Non-claims (read this before interpreting any output)

These are the specific misreadings this tool is built to prevent.

| Claim | Status |
|---|---|
| "The PDF contains a `/Launch` action, so code will execute." | **Unsupported.** Structure is present. Execution depends on reader policy, sandbox, and user confirmation. |
| "The PDF contains an embedded `.exe`, so it is malware." | **Unsupported.** It means the document *carries* a file. Extraction, inspection and execution are three separate events. |
| "Memory was allocated, so code ran." | **Unsupported** (Phase 2). Allocation is not execution. |
| "Defender did not alert, so the payload is clean." | **Unsupported.** Absence of an alert is evidence about Defender's coverage, not about the file. |
| "The risk score is a verdict." | **Unsupported.** It counts *features present*. It is a triage aid, not a classifier. |

---

## 3. What is delivered

```
phase1_pdf/
  pdf_inspector.py          read-only structural analyzer (stdlib only)
  make_test_pdfs.py         generator for the controlled test documents
  validate_against_pypdf.py cross-validation harness (independent implementation)
  samples/                  11 generated test PDFs + manifest.json
  quarantine/               embedded files extracted from samples (safe to inspect)
  reports/                  JSON reports produced by the runs below
phase4_defender/
  collect_defender.ps1      Defender posture + Windows event collector (read-only)
  sysmon_config.xml         Sysmon telemetry configuration
  validate_sysmon_config.py offline validator for the above
  sysmon_v4_90_schema.xsd   official schema manifest used for validation
```

---

## 4. Dependencies

| Component | Needs | Notes |
|---|---|---|
| `pdf_inspector.py` | Python 3.9+ | **No third-party packages.** Deliberately self-contained so parsing behaviour is auditable and not confused with a library under test. |
| `make_test_pdfs.py` | Python 3.9+ | None. |
| `validate_against_pypdf.py` | `pip install pypdf` | Test-time only. |
| `collect_defender.ps1` | Windows PowerShell 5.1+ | Elevated. Defender module present by default on Win11. |
| `validate_sysmon_config.py` | Python 3.9+ | None; ships the schema locally. |

Linux-side optional cross-checks (already used): `qpdf`, `poppler-utils`, `pypdf`.

---

## 5. Part A — Linux / attacker workstation

### 5.1 Commands

```bash
cd /home/syco/phantom-x/phase1_pdf

# 1. Generate the controlled test documents
python3 make_test_pdfs.py

# 2. Confirm every sample is a structurally valid PDF using an INDEPENDENT parser
cd samples
for f in px*.pdf; do qpdf --check "$f"; done        # expect: 0 errors, 0 warnings
for f in px*.pdf; do pdfinfo "$f" | head -3; done   # expect: 1 page each
cd ..

# 3. Run the analyzer
python3 pdf_inspector.py samples/ \
    --extract-dir ./quarantine \
    --json reports/phase1_exp1_linux_baseline.json

# 4. Cross-validate against an independent implementation
python3 validate_against_pypdf.py --json reports/phase1_exp1_crossvalidation.json

# 5. Optional: diff a sample against the clean baseline
python3 pdf_inspector.py samples/px11_combined.pdf --baseline samples/px01_clean_baseline.pdf
```

### 5.2 Actual results (observed, not predicted)

**Sample generation** — 11 documents produced. All pass `qpdf --check` with **0 errors and 0 warnings**; all parse in `poppler` and `pypdf`; all report 1 page.

**Cross-validation** — `RESULT: PASS`. The analyzer agrees with `pypdf` on JavaScript, embedded-file and action counts for **all 11 samples**, on a payload-identity basis (see §5.4).

**Inventory**

| Sample | Score | Band | JS | Embedded | Actions | External refs |
|---|---|---|---|---|---|---|
| px01_clean_baseline.pdf | 0 | none | 0 | 0 | 0 | 0 |
| px02_embedded_text.pdf | 24 | medium | 0 | 1 | 0 | 0 |
| px03_embedded_exe_canary.pdf | 18 | low | 0 | 1 | 0 | 0 |
| px04_javascript.pdf | 18 | low | 1 | 0 | 1 | 0 |
| px05_launch_action.pdf | 20 | medium | 0 | 0 | 1 | 1 |
| px06_uri_action.pdf | 12 | low | 0 | 0 | 1 | 1 |
| px07_openaction_js.pdf | 36 | medium | 1 | 0 | 1 | 0 |
| px08_gotor_remote.pdf | 8 | low | 0 | 0 | 1 | 1 |
| px09_form_with_action.pdf | 56 | high | 1 | 0 | 1 | 0 |
| px10_embedded_pdf.pdf | 6 | low | 0 | 1 | 0 | 0 |
| px11_combined.pdf | 100 | critical | 1 | 1 | 4 | 3 |

**Extracted content (from `quarantine/`)**

| File | Size | SHA-256 (first 16) | Identified as |
|---|---|---|---|
| px_benign_attachment.txt | 182 B | `8e2de920a73b1889` | plain text |
| px_detection_canary.bin | 507 B | `bd9f1897e62c8fa2` | MZ-prefixed plain text (**not** a PE image) |
| px_inner_document.pdf | 872 B | — | PDF document |
| px_combined_attachment.txt | 45 B | — | plain text |

The canary begins with the two ASCII bytes `MZ` but carries **no** `PE\0\0` signature at the offset given by its DOS header, and is >99% printable text. The analyzer reports it as *MZ-prefixed plain text (NOT a PE image)* rather than as an executable — verified against a genuine 3.2 MB PE (`Sysmon64.exe`) which is correctly identified as `PE/DOS executable`.

**Three defects were found and fixed during this experiment** (each was caught by a cross-check, not by the tool agreeing with itself):
1. `/Contents` indirect references were off by one in the generator — caught by `qpdf --check`, which reported *"page object N 0: object is supposed to be a stream or an array of streams but is neither"*.
2. Action object numbers resolved to `None` after dereferencing, causing double-counted actions and lost JavaScript records — caught by the cross-validation harness.
3. The `/S` action-type key (`/JavaScript`) was being classified as a filesystem path — caught by inspecting the external-reference list.

### 5.3 Baseline differential

`px01_clean_baseline.pdf` scores **0** and contains no actions, no embedded files, no external references. It exists so that every other sample can be diffed against a known-clean document. Use `--baseline`.

### 5.4 A note on counting basis

The analyzer counts **payloads** (one embedded stream, one script, one action object). A naive traversal counts **references** (one script reachable from two triggers counts twice). Both views are legitimate; they must be normalised before comparison or the comparison is meaningless. `px11_combined.pdf` is the case that exposes this: it reaches one JavaScript action from three places (`/OpenAction`, page `/AA /O`, and the `/Names /JavaScript` tree). The analyzer reports 1 script and records all three trigger locations under `also_referenced_at`. The harness in §5.1 step 4 normalises to the same basis; an earlier version did not, and reported false failures. Both the analyzer and the harness now record reference counts as well as payload counts.

---

## 6. Part B — Windows 11 research VM

### 6.1 Preconditions — verify, do not assume

```
[ ] Windows 11 VM, isolated host-only network
[ ] Microsoft Defender Real-Time Protection ENABLED
[ ] PDF reader installed (record the exact product and version)
[ ] Sysmon installed and running
[ ] Windows Event Logging enabled
```

Capture the Defender posture **first**, so that "Defender was enabled during the test" is a recorded fact rather than an assumption:

```powershell
# Elevated PowerShell on the VM
cd C:\phantom-x
.\collect_defender.ps1 -Label baseline
```

The collector is **read-only**. It calls `Get-MpComputerStatus`, `Get-MpPreference`, `Get-MpThreatDetection` and `Get-WinEvent`. It never calls `Set-MpPreference`, `Add-MpPreference`, `Remove-MpPreference`, or any remediation verb.

**Stop condition:** if `RealTimeProtectionEnabled` or `AntivirusEnabled` is not `True` in `baseline_defender_status.json`, the lab precondition is not met. Fix that before proceeding; do not proceed and annotate.

### 6.2 Install Sysmon telemetry

```powershell
# Copy phase4_defender\sysmon_config.xml to the VM first.
# Validate on the VM (or offline, it is the same file):
.\Sysmon64.exe -c sysmon_config.xml
# Expect exactly: "Sysmon 15.x Configuration successfully updated"
```

The config is validated offline against the official Sysmon 4.90 schema manifest:

```bash
python3 validate_sysmon_config.py sysmon_config.xml
# RESULT: VALID -- 0 errors, 0 warnings
```

That validation caught **30 real errors** in the first draft of the config (30 × invalid `condition="endswith"` — the legal spelling is `"end with"` — plus two duplicate-rule-block conflicts). Those would have failed on the VM.

### 6.3 The measurement procedure

For **each** sample, one at a time:

```powershell
# 1. Note the wall clock
Get-Date -Format o

# 2. Pre-event snapshot
.\collect_defender.ps1 -Label "before_$sample"

# 3. Open the sample in the reader. Do nothing else.
#    Record for each sample:
#      - did the reader prompt?
#      - did a script dialog appear?
#      - did anything open automatically?
#      - did a network request leave the host? (watch the collector output)

# 4. Post-event snapshot
.\collect_defender.ps1 -Label "after_$sample"
```

Then close the reader and collect again:

```powershell
.\collect_defender.ps1 -Label "after_close_$sample"
```

**Controls**
- Run `px01_clean_baseline.pdf` first, before anything else. It establishes what the host looks like with nothing happening.
- Between samples, close the reader completely and wait ~15 seconds so that transient child processes are gone from the snapshot.
- Record the reader product and version once. Reader policy is the single largest variable in this experiment.
- If the VM has internet egress, temporarily deny it for the reader process during this experiment so that "the reader tried to reach the network" is distinguishable from "the reader reached the network". If egress is already blocked, say so.

### 6.4 Expected Windows events

This is a **hypothesis list**, not a promise. Record what actually appears; where reality differs, reality wins.

| Sample | Expected observable |
|---|---|
| px01 baseline | Nothing beyond the reader's own launch |
| px02 embedded text | Reader extracts attachment to its temp dir → Sysmon ID 11 `FileCreate` (`.txt`/`.tmp`); Defender may log a scan of the extracted file |
| px03 canary | Same as px02, but Defender's handling of an attachment whose *content* starts with `MZ` and contains `powershell`/`cmd.exe` strings is the interesting result — this is the actual detection question |
| px04 javascript | Reader prompts about scripting, or silently refuses. If scripting is enabled: a JS-engine activity, possibly no new process at all |
| px05 launch action | Reader prompts to open `px_harmless_target.txt`. If the file does not exist, an error. No `notepad.exe` should spawn unless the reader launches the default handler |
| px06 uri action | Reader prompts / opens a browser. **NetworkConnect (ID 3) and/or DnsQuery (ID 22) to example.com** — this is the clearest network-visible sample |
| px07 openaction js | Scripting prompt on open, before the document renders |
| px08 gotor | Reader attempts to open `px_external_target.pdf`; file missing → error, no network |
| px09 form action | Field-level JS fires on interaction (focus/format), not on open |
| px10 nested pdf | Reader offers to open the embedded PDF |
| px11 combined | All of the above in sequence |

**Defender event IDs to watch** (Microsoft-Windows-Windows Defender/Operational):

| ID | Meaning |
|---|---|
| 1116 | Threat detected — read the `Source` field; `AMSI` means AMSI engaged |
| 1117 | Action taken (quarantine/removal) |
| 1118 / 1119 | Action failed / restoration |
| 5001 | Real-time protection disabled — **would invalidate the experiment** |
| 5007 | Configuration changed |
| 5010 / 5012 / 5013 | Scanning or antivirus disabled — **would invalidate the experiment** |
| 1121 | Protection disabled |

**Sysmon event IDs**: 1 (process creation, with `ParentImage`), 3 (network connect), 7 (image load), 11 (file create), 15 (file create stream hash), 22 (DNS query), 25 (process tampering).

### 6.5 The three questions this experiment must answer

1. **Which features does the reader act on at all?** Compare `px04`–`px08` behaviour against the structural inventory in Part A. A feature present in the file but inert in the reader is a *defender-relevant fact*: it means the reader is the control, not the file.
2. **Which require user interaction?** Record, per sample, whether anything happened with no input from you. `/Launch`, `/URI`, `/GoToR` are normally click-gated; `/OpenAction` and `/AA` are normally automatic. Whether the reader's sandbox permits automatic action is the point of measurement.
3. **What is visible to the defender?** For each sample, note whether Defender or Sysmon produced *any* record. A feature that is neither executed nor detected is invisible — that is the finding with the biggest defensive consequences.

---

## 7. Interpreting failures

| Symptom | Likely cause | Action |
|---|---|---|
| `qpdf --check` reports "object is supposed to be a stream" | Generator `/Contents` reference is off by one | Regenerate; `make_test_pdfs.py` uses explicit object numbers, not arithmetic |
| Inspector reports `risk score: 0` for a sample that should have features | Sample not regenerated, or inspector run on the wrong path | Confirm file hashes against `samples/manifest.json` |
| Cross-validation reports `FAIL` with mismatched counts | Counting basis differs, or a real defect | Compare `reference_counts` vs `mine_reference_counts` in the JSON; the harness reports both |
| `collect_defender.ps1` says `Get-MpComputerStatus failed` | Defender module not loaded | Open an *elevated* PowerShell (not VS Code's integrated terminal) and retry |
| `RealTimeProtectionEnabled` is `False` | Lab precondition broken | Restore it before continuing. Do not proceed and annotate. |
| Sysmon shows no events | Config not applied, or reader never ran | `.\Sysmon64.exe -c` to dump effective config; confirm the reader actually started |
| Sysmon rejects the config | Schema/condition mismatch | Run `python3 validate_sysmon_config.py`; check `.\Sysmon64.exe -s` for the accepted schema |
| `WARNING: field name not found in the schema manifest` | Field name typo | The manifest lists the legal field names per event |
| Nothing happens at all when opening a PDF | Reader policy blocked everything | That is a *result*, not a failure — record it. The point of the experiment is what the reader refuses to do. |

---

## 8. JSON report schema

`reports/phase1_exp1_linux_baseline.json` (per-file) / batch envelope:

```
schema              "phantom-x.phase1.pdf-inspection/1.0"
analysis_mode       "static-structure"
file                path, size_bytes, sha256, md5, pdf_version, encrypted,
                    page_count, object_count, xref_type, streams_seen/decoded
risk                score, band, severity_counts, interpretation
summary             actions, javascript_entries, embedded_files,
                    external_references, annotations, form_fields,
                    strings_of_interest
actions[]           location, objnum, action_type, severity,
                    requires_interaction, parameters, also_referenced_at
javascript[]        location, name_path, objnum, script_length,
                    script_sha256, script_preview, also_referenced_at
embedded_files[]    location, filename, declared_size, decoded_size,
                    encoded_size, size_matches_declared, filters, subtype,
                    sha256, md5, magic, identified_type, entropy,
                    is_ascii_text, extracted_to
external_references[]location, action_type, parameter, value, kind
annotations[]       location, subtype, flags, contents, has_action
form_fields[]       location, name, type, flags, actions
findings[]          id, category, severity, title, location, detail,
                    evidence, iocs
parser_warnings[]   structural problems encountered while parsing
```

Finding IDs are stable: `PX1-000` identity, `PX1-010/011/012` open action and document events, `PX1-013/014` forms, `PX1-020/021` name trees, `PX1-030` page events, `PX1-040/041/042` annotations, `PX1-050` form actions, `PX1-060/061` embedded files and size anomalies, `PX1-070` JavaScript, `PX1-080` external references.

---

## 9. What to send back

1. `reports/` from the VM — the `before_*` / `after_*` / `after_close_*` JSON files.
2. A short table: `sample | reader prompt? (Y/N) | what happened without input | Defender alert? (Y/N, event ID) | Sysmon event IDs | network traffic?`
3. The reader product and exact version.
4. Your Defender version (`Get-MpComputerStatus | Select AMProductVersion`).
5. Anything that surprised you — especially where the reader did **more** than expected.

With those, the next experiment (Phase 1 Experiment 2: reader sandbox and configuration behaviour) can be scoped to what actually happens on your system rather than to a generic assumption.

---

## 10. Phase 1 checklist status

| # | Item | Status |
|---|---|---|
| 1 | PDF embedded files | **Done** (Part A) — pending Part B reader behaviour |
| 2 | PDF JavaScript capabilities | **Done** (Part A) — pending Part B |
| 3 | PDF launch actions | **Done** (Part A) — pending Part B |
| 4 | PDF reader sandbox restrictions | Pending Part B |
| 5 | External resource handling | **Done** (Part A) — pending Part B |
| 6 | PDF reader process creation | Pending Part B (Sysmon ID 1) |
| 7 | Document-triggered network requests | **Done** (Part A) — pending Part B (Sysmon ID 3/22) |
| 8 | Reader security configuration | Pending Part B |
| 9 | PDF parser vulnerabilities | Out of scope for inventory — separate experiment, separate authorisation |
| 10 | Windows Defender inspection | Pending Part B (`collect_defender.ps1` ready) |
