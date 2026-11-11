#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: Phase 1 -- cross-validation of the Rust scanner
================================================================================
validate_cross_impl.py -- Checks the Rust PDF scanner against the Python
reference inspector.

    The lab's ground rule #6 is "cross-validate before trusting: every
    analyzer is checked against an independent implementation." This script
    is that check for the PDF scanner. The Rust scanner (px_pdfscan) was
    written from the PDF specification rather than from the Python source,
    so the two are genuinely independent readings of the format.

    A disagreement is a bug in one of them. This script reports every
    disagreement rather than the first one, because the interesting case is
    usually a systematic difference that affects many files.

    WHAT IS COMPARED
        * the set of action types found in each document
        * the number of JavaScript entries
        * the number of embedded files
        * the number of external references
        * the SHA-256 of each embedded file's contents
        * whether each embedded file is a genuine PE image

    The embedded-file hashes are the strongest check: they compare the
    actual bytes both implementations extracted, so a difference there is a
    real difference in the data, not a difference in how it is described.

USAGE
    python3 validate_cross_impl.py \
        --rust ../rust_scanner/target/release/px_pdfscan.exe \
        --samples samples/

    python3 validate_cross_impl.py --rust <path> --samples samples/ \
        --json cross_validation.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from pdf_inspector import analyse_path  # noqa: E402


def run_rust(binary: str, path: str) -> dict:
    """Run the Rust scanner on one file and return its parsed JSON."""
    proc = subprocess.run(
        [binary, "--json", path],
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"rust scanner failed on {path}: {proc.stderr.strip()}")
    data = json.loads(proc.stdout)
    if isinstance(data, list):
        if not data:
            raise RuntimeError(f"rust scanner returned no report for {path}")
        return data[0]
    return data


def python_report(path: str) -> dict:
    """Run the Python reference inspector on one file."""
    return analyse_path(path, None)


def collect_actions(report: dict) -> list:
    """Normalise the action list from either implementation."""
    out = []
    for a in report.get("actions", []):
        t = a.get("action_type") or a.get("type") or "untyped"
        out.append(str(t))
    return sorted(out)


def collect_embedded(report: dict) -> list:
    """Normalise the embedded file list: (name, sha256, is_pe).

    The two implementations use different field names for the same facts:
    the Python reference calls it 'filename' and reports the type as
    'identified_type', the Rust scanner calls them 'name' and
    'identified_as'. This function reads whichever is present, so the
    comparison is about the FACTS and not about the schema.
    """
    out = []
    for e in report.get("embedded_files", []):
        name = e.get("name") or e.get("filename") or ""
        sha = e.get("sha256", "")
        # 'is_pe' in the Rust report; in the Python report the type is
        # described in words.
        if "is_pe" in e:
            is_pe = bool(e["is_pe"])
        else:
            is_pe = "PE/DOS executable" in str(e.get("identified_type", ""))
        size = e.get("size") or e.get("decoded_size") or 0
        out.append({
            "name": name,
            "sha256": sha,
            "is_pe": is_pe,
            "size": size,
        })
    return sorted(out, key=lambda x: (x["name"], x["sha256"]))


def compare(py: dict, rs: dict) -> list:
    """Return the list of disagreements between the two reports."""
    diffs = []

    py_actions = collect_actions(py)
    rs_actions = collect_actions(rs)
    if py_actions != rs_actions:
        diffs.append({
            "field": "actions",
            "python": py_actions,
            "rust": rs_actions,
        })

    py_js = len(py.get("javascript", []))
    rs_js = len(rs.get("javascript", []))
    if py_js != rs_js:
        diffs.append({
            "field": "javascript_count",
            "python": py_js,
            "rust": rs_js,
        })

    py_ext = len(py.get("external_refs", py.get("external_references", [])))
    rs_ext = len(rs.get("external_references", []))
    if py_ext != rs_ext:
        diffs.append({
            "field": "external_reference_count",
            "python": py_ext,
            "rust": rs_ext,
        })

    py_emb = collect_embedded(py)
    rs_emb = collect_embedded(rs)
    if py_emb != rs_emb:
        diffs.append({
            "field": "embedded_files",
            "python": py_emb,
            "rust": rs_emb,
        })

    return diffs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Cross-validate the Rust PDF scanner against the Python "
                    "reference inspector.")
    ap.add_argument("--rust", required=True,
                    help="path to the px_pdfscan binary")
    ap.add_argument("--samples", default=os.path.join(HERE, "samples"),
                    help="directory of PDFs to test")
    ap.add_argument("--json", default=None,
                    help="write the full result as JSON")
    args = ap.parse_args(argv)

    rust_bin = os.path.abspath(args.rust)
    if not os.path.isfile(rust_bin):
        print(f"error: rust scanner not found: {rust_bin}", file=sys.stderr)
        print("  build it:  cd rust_scanner && cargo build --release",
              file=sys.stderr)
        return 2

    if not os.path.isdir(args.samples):
        print(f"error: samples directory not found: {args.samples}",
              file=sys.stderr)
        return 2

    pdfs = sorted(
        os.path.join(args.samples, f)
        for f in os.listdir(args.samples)
        if f.lower().endswith(".pdf")
    )
    if not pdfs:
        print(f"error: no PDFs in {args.samples}", file=sys.stderr)
        return 2

    results = []
    all_ok = True

    print("=" * 72)
    print("PHANTOM-X :: PDF SCANNER CROSS-VALIDATION")
    print("=" * 72)
    print(f"reference (python) : pdf_inspector.py")
    print(f"cross-check (rust)  : {rust_bin}")
    print(f"documents           : {len(pdfs)}")
    print()

    for path in pdfs:
        name = os.path.basename(path)
        try:
            py = python_report(path)
            rs = run_rust(rust_bin, path)
        except Exception as exc:  # noqa: BLE001
            print(f"  [ERROR] {name}: {exc}")
            results.append({"file": name, "status": "error",
                            "error": str(exc), "differences": []})
            all_ok = False
            continue

        diffs = compare(py, rs)
        if diffs:
            all_ok = False
            print(f"  [DIFF ] {name}")
            for d in diffs:
                print(f"           field: {d['field']}")
                print(f"             python: {d['python']}")
                print(f"             rust  : {d['rust']}")
        else:
            n_act = len(collect_actions(py))
            n_emb = len(collect_embedded(py))
            n_js = len(py.get("javascript", []))
            print(f"  [MATCH] {name:<38} actions={n_act} js={n_js} embedded={n_emb}")

        results.append({
            "file": name,
            "status": "match" if not diffs else "difference",
            "python_sha256": hashlib.sha256(open(path, "rb").read()).hexdigest(),
            "python_actions": collect_actions(py),
            "rust_actions": collect_actions(rs),
            "python_embedded": collect_embedded(py),
            "rust_embedded": collect_embedded(rs),
            "differences": diffs,
        })

    print()
    print("-" * 72)
    print(f"RESULT: {'PASS' if all_ok else 'FAIL'}")
    print("-" * 72)

    out = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "reference": "pdf_inspector.py",
        "cross_check": rust_bin,
        "document_count": len(pdfs),
        "result": "pass" if all_ok else "fail",
        "documents": results,
    }
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        print(f"[+] JSON written: {os.path.abspath(args.json)}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
