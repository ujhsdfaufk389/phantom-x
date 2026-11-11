#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: Phase 8 -- the coverage matrix
================================================================================
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

USAGE
    coverage.py --rules rules.json --events baseline.json --variant variant.json

    The two event files are compared: a rule that fires on the baseline
    and is silent on the variant was riding on something the variant
    removed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from px_eval import evaluate, load_json  # noqa: E402

# The ATT&CK techniques the lab's arms actually exercise, and what each
# one is for. This is the SIDE of the matrix: what the lab can do.
#
# A technique here with no rule is a hole in the DETECTION coverage.
# A technique here with no arm is a hole in the lab's own coverage.
ARMS = {
    "T1055.012": ("process hollowing", "px_hollow.exe"),
    "T1003.001": ("credential access (LSASS)", "the credential arm"),
    "T1569.002": ("service execution", "the lateral arm"),
    "T1021.002": ("SMB/Windows admin shares", "the lateral arm"),
    "T1573.001": ("symmetric cryptography", "the encrypted arm"),
    "T1568.002": ("domain generation", "the DGA arm"),
    "T1562.001": ("impair defenses (AMSI)", "the AMSI arm"),
    "T1562.006": ("impair ETW", "the ETW arm"),
    "T1027.002": ("software packing", "the obfuscated arm"),
    "T1027": ("obfuscated files", "the obfuscated arm"),
    "T1204.002": ("user execution (malicious file)", "the PDF carrier"),
    "T1071.001": ("application layer protocol", "the plain channel"),
    "T1547.001": ("registry run keys", "the file-association step"),
    "T1053.005": ("scheduled task", "the lab's restore guard"),
    "T1620": ("reflective code loading", "the loader"),
    "T1218": ("system binary proxy execution", "cmd.exe"),
    "T1134.002": ("create process with token", "the hollow tool"),
    "T1562.001 ": ("impair defenses", "the lab's own A/B toggle"),
}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Show what the detection rules cover, and where the gaps are")
    ap.add_argument("--rules", required=True)
    ap.add_argument("--baseline", default=None,
                    help="the events JSON from the baseline arm")
    ap.add_argument("--variant", default=None,
                    help="the events JSON from the variant arm")
    ap.add_argument("--json", default=None)
    args = ap.parse_args(argv)

    rules = load_json(args.rules)

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

    # -- the technique matrix -------------------------------------------
    print("  TECHNIQUE        ARM                        RULES")
    print(f"  {'-'*16} {'-'*26} {'-'*10}")
    gaps = []
    for tech, (desc, arm) in sorted(ARMS.items()):
        tech = tech.strip()
        rule_ids = sorted(r["id"] for r in rules
                          if tech in [t.strip() for t in r.get("techniques", [])])
        if rule_ids:
            rulestr = ",".join(rule_ids)
        else:
            rulestr = "** NONE **"
            gaps.append(tech)
        print(f"  {tech:<16} {desc[:26]:<26} {rulestr}")
    print()

    if gaps:
        print("  TECHNIQUES WITH NO RULE (a detection gap):")
        for g in gaps:
            print(f"    {g}  {ARMS.get(g, ('?',))[0]}")
        print()
    else:
        print("  every technique the lab exercises has at least one rule.")
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
