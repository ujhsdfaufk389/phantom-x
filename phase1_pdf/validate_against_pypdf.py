#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: Phase 1 / Experiment 1 (verification harness)
================================================================================
validate_against_pypdf.py -- Cross-check pdf_inspector.py against an independent
PDF implementation (pypdf) to prove the inspector is not merely reporting its
own opinion.

WHY
    A static analyser that only agrees with itself proves nothing. This
    harness enumerates the same three feature classes (JavaScript, embedded
    files, actions) from pypdf's object graph and compares against the
    inspector.

COUNTING BASIS -- IMPORTANT
    The inspector counts PAYLOADS: one embedded stream, one script, one
    action object. A naive traversal counts every REFERENCE to those
    payloads, so a single script reached from two triggers counts twice.
    Both views are legitimate, but they must be normalised to the same basis
    before comparison or the result is meaningless. This harness deduplicates
    by PDF object identity, which is exactly the basis the inspector uses.

DEPENDENCIES
    pip install pypdf        (test-time only -- the inspector itself needs none)

USAGE
    python3 validate_against_pypdf.py
    python3 validate_against_pypdf.py --samples-dir samples --json report.json

EXIT
    0 = all samples agree
    1 = at least one disagreement (details printed)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import warnings
from datetime import datetime, timezone

warnings.filterwarnings("ignore")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import pypdf
    from pypdf.generic import IndirectObject
except ImportError:
    print("error: pypdf not installed.  pip install pypdf", file=sys.stderr)
    raise SystemExit(2)

from pdf_inspector import analyse_path  # noqa: E402


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _deref(v):
    try:
        return v.get_object()
    except AttributeError:
        return v


def _obj_id(v):
    """Stable identity of a PDF object, matching the inspector's basis."""
    if isinstance(v, IndirectObject):
        return ("ind", v.idnum)
    return ("dir", id(v))


def _pairs(arr):
    """Iterate a PDF name-tree /Names array as (key, value) pairs.

    The spec defines /Names as a FLAT array of alternating key and value
    objects -- NOT an array of two-element arrays. `for k, v in arr` would
    therefore iterate the keys as items, not the pairs.
    """
    if not arr:
        return []
    return [(arr[i], arr[i + 1]) for i in range(0, len(arr) - 1, 2)]


def _ef_subtypes(fs) -> list:
    if not isinstance(fs, dict):
        return []
    ef = _deref(fs.get("/EF"))
    if not isinstance(ef, dict):
        return []
    subs = []
    for k in ef:
        st = _deref(ef[k])
        if isinstance(st, dict):
            subs.append(str(st.get("/Subtype", "")))
    return subs


# --------------------------------------------------------------------------- #
# reference-level collection from pypdf
# --------------------------------------------------------------------------- #

def collect_pypdf(path: str) -> dict:
    """Enumerate JS / embedded files / actions from pypdf's view of the file.

    Records are REFERENCE-level: each entry says "something points here".
    Object identity is captured so the caller can collapse to payload level.
    """
    reader = pypdf.PdfReader(path)
    out = {"javascript": [], "embedded_files": [], "actions": [], "errors": []}

    def try_(label, fn):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            out["errors"].append(f"{label}: {type(exc).__name__}: {exc}")
            return None

    def note_action(where, raw_act):
        actd = _deref(raw_act)
        s = str(actd.get("/S", "")) if isinstance(actd, dict) else ""
        out["actions"].append({"where": where, "s": s, "_id": _obj_id(raw_act)})
        if s == "/JavaScript":
            out["javascript"].append({"where": where,
                                      "js": str(_deref(actd.get("/JS"))),
                                      "_id": _obj_id(raw_act)})

    def note_filespec(where, raw_fs):
        fs = _deref(raw_fs)
        if isinstance(fs, dict):
            out["embedded_files"].append({
                "where": where,
                "name": str(fs.get("/F", "")),
                "subtype": _ef_subtypes(fs),
                "_id": _obj_id(raw_fs),
            })

    root = try_("root", lambda: _deref(reader.trailer["/Root"])) or {}

    # -- annotations ---------------------------------------------------------
    pages = try_("pages", lambda: reader.pages) or []
    for i, page in enumerate(pages):
        annots = try_(f"page{i}/Annots", lambda pg=page: pg.get("/Annots")) or []
        for j, a in enumerate(annots):
            ao = try_(f"page{i}/Annots[{j}]", lambda x=a: _deref(x))
            if not isinstance(ao, dict):
                continue
            act = try_(f"page{i}/Annots[{j}]/A", lambda x=ao: x.get("/A"))
            if act is not None:
                note_action(f"page[{i}]/Annots[{j}]/A", act)
            if str(ao.get("/Subtype", "")) == "/FileAttachment":
                fs = try_(f"page{i}/Annots[{j}]/FS", lambda x=ao: x.get("/FS"))
                if fs is not None:
                    note_filespec(f"page[{i}]/Annots[{j}]", fs)

    # -- document level ------------------------------------------------------
    oa = try_("OpenAction", lambda: root.get("/OpenAction"))
    if oa is not None:
        oad = _deref(oa)
        if isinstance(oad, dict):
            note_action("catalog/OpenAction", oa)
        elif isinstance(oad, list):
            out["actions"].append({"where": "catalog/OpenAction", "s": "[dest]",
                                   "_id": ("dest", id(oa))})

    names = try_("Names", lambda: root.get("/Names"))
    if isinstance(_deref(names), dict):
        nd = _deref(names)

        jt = _deref(nd.get("/JavaScript"))
        if isinstance(jt, dict):
            for k, v in _pairs(jt.get("/Names") or []):
                note_action(f"Names/JavaScript/{k}", v)

        ef = _deref(nd.get("/EmbeddedFiles"))
        if isinstance(ef, dict):
            for k, v in _pairs(ef.get("/Names") or []):
                note_filespec(f"Names/EmbeddedFiles/{k}", v)

    acro = _deref(root.get("/AcroForm"))
    if isinstance(acro, dict):
        for i, f in enumerate(acro.get("/Fields") or []):
            fd = _deref(f)
            if not isinstance(fd, dict):
                continue
            aa = _deref(fd.get("/AA"))
            if isinstance(aa, dict):
                for ev, act in aa.items():
                    note_action(f"AcroForm/Fields[{i}]/AA/{ev}", act)

    for i, page in enumerate(pages):
        pd = _deref(page)
        aa = _deref(pd.get("/AA")) if isinstance(pd, dict) else None
        if isinstance(aa, dict):
            for ev, act in aa.items():
                note_action(f"page[{i}]/AA/{ev}", act)

    return out


def normalise(theirs: dict) -> dict:
    """Collapse reference-level records to payload level by object identity."""
    def collapse(records):
        seen = {}
        for r in records:
            k = r["_id"]
            if k not in seen:
                seen[k] = r
        return seen

    js = collapse(theirs["javascript"])
    ef = collapse(theirs["embedded_files"])
    ac = collapse(theirs["actions"])
    return {
        "javascript": js,
        "embedded_files": ef,
        "actions": ac,
        "refs": {
            "javascript": len(theirs["javascript"]),
            "embedded_files": len(theirs["embedded_files"]),
            "actions": len(theirs["actions"]),
        },
    }


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Cross-validate pdf_inspector against pypdf.")
    ap.add_argument("--samples-dir", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "samples"))
    ap.add_argument("--json", default=None, help="write machine-readable result")
    args = ap.parse_args(argv)

    files = sorted(os.path.join(args.samples_dir, f)
                   for f in os.listdir(args.samples_dir) if f.lower().endswith(".pdf"))
    if not files:
        print(f"error: no PDFs in {args.samples_dir}", file=sys.stderr)
        return 2

    hdr = (f"{'sample':<32} {'JS (payload)':>18} {'EMBED (payload)':>19} "
           f"{'ACTIONS (payload)':>21}")
    print(hdr)
    print("-" * len(hdr))
    print(f"{'':<32} {'mine / pypdf':>18} {'mine / pypdf':>19} {'mine / pypdf':>21}")

    disagreements = []
    rows = []
    for path in files:
        mine = analyse_path(path, None)
        theirs = normalise(collect_pypdf(path))

        m_js, m_ef, m_act = len(mine["javascript"]), len(mine["embedded_files"]), len(mine["actions"])
        p_js = len(theirs["javascript"])
        p_ef = len(theirs["embedded_files"])
        p_act = len(theirs["actions"])

        row = {
            "file": os.path.basename(path),
            "mine": {"javascript": m_js, "embedded_files": m_ef, "actions": m_act},
            "pypdf": {"javascript": p_js, "embedded_files": p_ef, "actions": p_act},
            "reference_counts": theirs["refs"],
            "mine_reference_counts": {
                "javascript": sum(1 + len(j.get("also_referenced_at", []))
                                  for j in mine["javascript"]),
                "embedded_files": sum(1 + len(e.get("also_referenced_at", []))
                                      for e in mine["embedded_files"]),
                "actions": sum(1 + len(a.get("also_referenced_at", []))
                               for a in mine["actions"]),
            },
        }
        rows.append(row)

        flag = ""
        for field, m, p in (("javascript", m_js, p_js),
                            ("embedded_files", m_ef, p_ef),
                            ("actions", m_act, p_act)):
            if m != p:
                flag += f"  !! {field}: mine={m} pypdf={p}"
                disagreements.append({"file": os.path.basename(path), "field": field,
                                      "mine": m, "pypdf": p})
        print(f"{os.path.basename(path):<32} {m_js:>8} / {p_js:<7} "
              f"{m_ef:>8} / {p_ef:<8} {m_act:>9} / {p_act:<8}{flag}")

    print("-" * len(hdr))
    if disagreements:
        print("RESULT: FAIL -- see mismatches above")
    else:
        print("RESULT: PASS -- inspector agrees with independent implementation")
    print()
    print("Scope of this check: feature COUNTS on a payload basis.")
    print("It does NOT validate the severity model, the risk score, or the")
    print("behaviour of a PDF reader. Those are separate questions.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"schema": "phantom-x.phase1.crossvalidation/1.0",
                       "generated_utc": datetime.now(timezone.utc).isoformat(),
                       "reference_implementation": f"pypdf {pypdf.__version__}",
                       "counting_basis": "payload identity (PDF object identity)",
                       "rows": rows,
                       "disagreements": disagreements,
                       "result": "pass" if not disagreements else "fail"},
                      fh, indent=2)
        print(f"\n[+] JSON written: {os.path.abspath(args.json)}")

    return 0 if not disagreements else 1


if __name__ == "__main__":
    sys.exit(main())
