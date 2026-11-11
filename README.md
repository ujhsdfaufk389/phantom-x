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

---

## Layout

```
phantom-x/
├── docs/
│   ├── phase1_experiment1.md        PDF attack surface — Phase 1 procedure + results
│   └── phase3_phase5_chain.md       the working chain: build, deploy, measure
├── phase1_pdf/
│   ├── pdf_inspector.py             read-only PDF structure & action analyzer
│   ├── make_test_pdfs.py            11 controlled test documents
│   ├── make_attack_pdf.py           builds the carrier PDF
│   ├── validate_against_pypdf.py    cross-validation vs. an independent parser
│   ├── samples/                     generated PDFs + manifest.json
│   └── reports/                     JSON reports
├── phase2_memory/
│   └── win_mem_lab.py               VirtualAlloc/Protect/Query/Free,
│                                    ReadProcessMemory, in-memory execution proof
├── phase3_fileless/
│   └── loader/
│       ├── px_loader.c/.exe         PDF extractor + reflective PE mapper
│       ├── px_payload.c/.exe        freestanding C2 client
│       └── build_lab.sh/.ps1        rebuild everything
├── phase4_defender/
│   ├── collect_defender.ps1         read-only Defender + event collector
│   ├── lab_ab_toggle.ps1            Defender A/B with guaranteed restore
│   ├── sysmon_config.xml            Sysmon telemetry configuration
│   ├── validate_sysmon_config.py    offline schema validation
│   └── sysmon_v4_90_schema.xsd      official schema manifest
├── phase5_network/
│   ├── c2_server.py                 lab C2 with sessions, latency, JSONL audit
│   ├── test_c2_integration.py       payload-level integration test
│   └── test_chain_integration.py    FULL chain integration test
└── phase6_reports/                  structured JSON reports
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

On the Windows VM:

```powershell
.\collect_defender.ps1 -Label before_chain   # prove Defender was ON
.\px_loader.exe .\px_attack_chain.pdf .\loader.log
.\collect_defender.ps1 -Label after_chain
.\lab_ab_toggle.ps1 -Action off               # guarded A/B, auto-restores
```

---

## Status

| Phase | Status |
|---|---|
| 1 — PDF attack surface | Experiment 1 complete (Linux side); VM reader run pending |
| 2 — Windows memory research | `win_mem_lab.py` built; VM run pending |
| 3 — Fileless techniques | **Reflective loading working.** Remaining catalogue pending |
| 4 — Defender evaluation | Collector + Sysmon config built and validated; A/B toggle built; VM run pending |
| 5 — Network research | **C2 rig working and tested.** VM run pending |
| 6 — Reporting infrastructure | JSON schema established |

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
