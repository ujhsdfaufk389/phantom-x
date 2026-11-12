#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: Phase 8 -- the coverage matrix
===============================================================================
coverage.py -- Compares what the rules CLAIM to cover against what they
ACTUALLY cover, and shows the gaps.

WHY THIS EXISTS
    A lab that only shows its successes teaches nothing. The interesting
    output is the holes: the techniques the lab does not exercise, the
    rules that never fire, and the capabilities that have no rule at all.

    Two kinds of gap, and they need different answers:

      A technique with no rule       -- nothing would catch it
      A rule that never fires        -- it might be broken, or the
                                       technique might not be exercised

    The second kind is the interesting one, because a rule that looks
    right and never fires is a rule that gives false confidence.

THE CATALOGUE IS THE DENOMINATOR
    The rule list says what can be DETECTED. The technique catalogue says
    what the lab can DO -- and, more usefully, what it does not do.

    Three statuses:

      measured       the lab exercises the technique, so the telemetry is
                     real and the rule can be tested against it
      ruled          a rule exists, but the lab does not exercise it --
                     the rule is UNVALIDATED, which is a different thing
                     from a working rule
      not_exercised  neither

    The difference between "ruled" and "not_exercised" is the honest
    part of the report. A rule that has never fired is a hypothesis.

USAGE
    coverage.py --rules rules.json --catalog catalog.json \
                 --events baseline.json --variant variant.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from px_eval import evaluate, load_json  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Show what the detection rules cover, and where the gaps are")
    ap.add_argument("--rules", required=True)
    ap.add_argument("--catalog", default=None,
                    help="the catalogue JSON, from px_detect --emit catalog")
    ap.add_argument("--baseline", default=None,
                    help="the events JSON from the baseline arm")
    ap.add_argument("--variant", default=None,
                    help="the events JSON from the variant arm")
    ap.add_argument("--json", default=None)
    args = ap.parse_args(argv)

    rules = load_json(args.rules)

    catalog = []
    if args.catalog and os.path.isfile(args.catalog):
        catalog = load_json(args.catalog)

    baseline_report = None
    variant_report = None

    if args.baseline and os.path.isfile(args.baseline):
        baseline_report = evaluate(rules, load_json(args.baseline))
    if args.variant and os.path.isfile(args.variant):
        variant_report = evaluate(rules, load_json(args.variant))

    # Which techniques have at least one rule.
    covered = set()
    for r in rules:
        for t in r.get("techniques", []):
            covered.add(t.strip())

    print("=" * 74)
    print("PHANTOM-X :: COVERAGE MATRIX")
    print("=" * 74)
    print()

    gaps = []
    unexercised = []

    if catalog:
        # -- the catalogue matrix -----------------------------------------
        print("  TECHNIQUE     TACTIC             STATUS          RULES")
        print(f"  {'-'*13} {'-'*18} {'-'*15} {'-'*18}")
        for t in sorted(catalog, key=lambda e: (e["status"], e["id"])):
            status = t.get("status", "?")
            if status == "not_exercised":
                unexercised.append(t)
            elif not t.get("rules"):
                # The technique is in scope and something measures it,
                # but nothing would catch it. That is the worst kind of
                # gap, so it is called out separately.
                gaps.append(t["id"])
            mark = {"measured": "measured", "ruled": "ruled ONLY",
                    "not_exercised": "NOT EXERCISED"}.get(status, status)
            print(f"  {t['id']:<13} {t['tactic'][:18]:<18} {mark:<15} "
                  f"{t.get('rules', '') or '** NONE **'}")
        print()

        measured = [t for t in catalog if t.get("status") == "measured"]
        ruled_only = [t for t in catalog if t.get("status") == "ruled"]
        not_ex = [t for t in catalog if t.get("status") == "not_exercised"]
        campaigns = [t for t in catalog if t.get("kind") == "campaign"]

        print("  THE DENOMINATOR")
        print(f"    techniques in scope   : {len(catalog)}")
        print(f"    measured              : {len(measured)}")
        print(f"    ruled but not measured: {len(ruled_only)}")
        print(f"    not exercised at all  : {len(not_ex)}")
        print(f"    of which campaigns    : {len(campaigns)}")
        print()

        if ruled_only:
            print("  RULED BUT NOT MEASURED (a rule nobody has watched fire)")
            for t in ruled_only:
                print(f"    {t['id']:<12} {t['name'][:38]:<40} {t.get('rules', '')}")
            print()

        if not_ex:
            print("  NOT EXERCISED (the lab says nothing about these)")
            for t in not_ex:
                kind = " (campaign)" if t.get("kind") == "campaign" else ""
                print(f"    {t['id']:<12} {t['name'][:38]:<40}{kind}")
            print()

    # -- the technique matrix, from the rules alone ------------------------
    print("  TECHNIQUES WITH NO RULE (a detection gap)")
    if catalog:
        if gaps:
            for m in gaps:
                print(f"    {m}")
        else:
            print("    (none -- every exercised technique has at least one rule)")
    else:
        print("    (no catalogue supplied; run px_detect --emit catalog)")
    print()

    # -- the rule behaviour ---------------------------------------------
    if baseline_report:
        print("  BASELINE ARM")
        print(f"    {'ID':<9} {'FIRES':<7} TITLE")
        print(f"    {'-'*9} {'-'*7} {'-'*40}")
        for r in baseline_report["results"]:
            mark = "  YES" if r["fired"] else "   no"
            print(f"    {r['id']:<9} {mark:<7} {r['title'][:40]}")
        print()

    if variant_report:
        print("  VARIANT ARM")
        print(f"    {'ID':<9} {'FIRES':<7} TITLE")
        print(f"    {'-'*9} {'-'*7} {'-'*40}")
        for r in variant_report["results"]:
            mark = "  YES" if r["fired"] else "   no"
            print(f"    {r['id']:<9} {mark:<7} {r['title'][:40]}")
        print()

    # -- the difference --------------------------------------------------
    lost = []
    if baseline_report and variant_report:
        base = {r["id"]: r["fired"] for r in baseline_report["results"]}
        var = {r["id"]: r["fired"] for r in variant_report["results"]}
        print("  RULES THAT FIRED ON THE BASELINE AND ARE SILENT ON THE VARIANT")
        print("  (these were riding on something the variant removed)")
        print()
        for rid, count in sorted(base.items()):
            if count > 0 and var.get(rid, 0) == 0:
                title = next(r["title"] for r in baseline_report["results"]
                             if r["id"] == rid)
                catches = next(r["catches"] for r in baseline_report["results"]
                               if r["id"] == rid)
                lost.append({"id": rid, "title": title, "catches": catches})
                print(f"    {rid}  {title[:44]}")
                print(f"          catches: {catches}")
        print()
        if not lost:
            print("    (none -- every rule that fired on the baseline still fires)")
            print()
        # The reverse is worth knowing too: a rule that only fires on the
        # variant is catching something the baseline did not do.
        gained = []
        for rid, count in sorted(var.items()):
            if count > 0 and base.get(rid, 0) == 0:
                title = next(r["title"] for r in variant_report["results"]
                             if r["id"] == rid)
                gained.append({"id": rid, "title": title})
        if gained:
            print("  RULES THAT ONLY FIRE ON THE VARIANT")
            print("  (these catch the technique the variant adds)")
            print()
            for g in gained:
                print(f"    {g['id']}  {g['title'][:44]}")
            print()

    if args.json:
        out = {
            "rules": len(rules),
            "techniques_covered": sorted(covered),
            "techniques_without_rules": gaps,
            "catalogue": catalog,
            "baseline": baseline_report,
            "variant": variant_report,
            "rules_lost_on_variant": lost,
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        print(f"  matrix -> {os.path.abspath(args.json)}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
