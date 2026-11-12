#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: Phase 8 -- the rule evaluator
================================================================================
px_eval.py -- Answers the question the whole lab exists to answer:

    "which of my rules fire against this arm?"

WHY THIS EXISTS
    The lab builds variant arms and writes detection rules. Until now
    nothing connected the two, so the lab could not say whether a rule
    still worked once the payload was obfuscated, once ETW was unhooked,
    or once the channel was encrypted.

    That gap is the difference between a collection of malware samples
    and a detection study. A rule that fires on the baseline and stops
    firing on the obfuscated arm was riding on a plaintext string. That
    is a finding about the RULE, and it is the finding the operator
    actually needs.

    Without a SIEM, the answer would need one, and the lab does not have
    one. So this is a small evaluator for the subset of Sigma that these
    rules use. It is deliberately not a general Sigma implementation: it
    does exactly what the rules need, and it is small enough to read.

THE SEMANTICS
    A rule fires on an event when:

        the SELECTION matches, AND the SELECTION_AND matches, AND the
        FILTER does not match

    Within a selection block the matchers are OR'd -- the usual Sigma
    meaning, where several fields under one key match if ANY of them
    matches. Between blocks they are AND'd.

    WHY THERE ARE TWO SELECTION BLOCKS
        A single block ORs its matchers, so it can only ever say that one
        of its fields matched. A rule that needs a remote write INTO a
        process, rather than a remote write somewhere, needs two blocks,
        and the second one is selection_and. Without it the rule would
        fire on every event that had a CallTrace at all, which is not a
        rule so much as a noise generator.

    This mirrors the Sigma specification rather than the intuition, which
    matters: a rule that means something different from its Sigma text is
    worse than no rule at all, because it looks like it works.

WHAT IT EVALUATES AGAINST
    Events in JSON, one object per event, with the field names the rules
    use. Two sources:

      * a live export from the VM (collect_events.ps1)
      * a saved export from an earlier run, so a comparison is repeatable

USAGE
    px_eval.py --rules rules.json --events events.json
    px_eval.py --rules rules.json --events events.json --json report.json
    px_eval.py --rules rules.json --events events.json --quiet
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict


def load_json(path: str):
    """Load a JSON file, tolerating the encodings Windows produces.

    PowerShell's `>` redirection writes UTF-16, and `Out-File -Encoding
    utf8` writes a BOM. Both are normal things to happen to a file on
    Windows, and the evaluator should not care: a tool that only reads
    files written one particular way is a tool that fails on the second
    machine.
    """
    raw = open(path, "rb").read()

    # A UTF-16 file starts with a byte-order mark.
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    else:
        # utf-8-sig strips the BOM if there is one and behaves like utf-8
        # if there is not.
        text = raw.decode("utf-8-sig")

    return json.loads(text)


def match_one(event: dict, matcher: dict) -> bool:
    """Does one matcher match one event?

    The comparison is case-insensitive, which is what Sigma does for
    string fields. It matters: an image path on Windows can be spelled
    with any case, and a rule that only matched one spelling would miss
    the event half the time.
    """
    field = matcher.get("field", "")
    op = matcher.get("op", "equals")
    values = matcher.get("values", [])

    raw = event.get(field)
    if raw is None:
        # The field is absent from the event. It cannot match.
        return False

    actual = str(raw)
    lowered = actual.lower()

    for value in values:
        want = str(value).lower()
        if op == "equals":
            if lowered == want:
                return True
        elif op == "contains":
            if want in lowered:
                return True
        elif op == "endswith":
            if lowered.endswith(want):
                return True
        elif op == "startswith":
            if lowered.startswith(want):
                return True
        elif op == "in":
            if lowered in [str(v).lower() for v in values]:
                return True
    return False


def match_block(event: dict, block: list) -> bool:
    """Does a block match?

    The matchers inside a block are OR'd, which is the Sigma meaning for
    a list of fields under one key.
    """
    if not block:
        # An empty block cannot match anything. A rule with an empty
        # filter therefore excludes nothing, which is right.
        return False
    for matcher in block:
        if match_one(event, matcher):
            return True
    return False


def rule_fires(rule: dict, event: dict) -> bool:
    """Does a rule fire on an event?

    A rule fires when the SELECTION matches, the SELECTION_AND block
    also matches, and the FILTER does not match.

    The selection_and block is the second half of the AND. A single
    selection block ORs its matchers, so it can only ever say "one of
    these fields matched". A rule that needs "a remote write INTO a
    process, rather than a remote write somewhere" needs two blocks,
    and that is what selection_and is for.
    """
    selection = rule.get("selection", [])
    selection_and = rule.get("selection_and", [])
    filt = rule.get("filter", [])

    if not match_block(event, selection):
        return False
    if selection_and and not match_block(event, selection_and):
        return False
    if filt and match_block(event, filt):
        return False
    return True


def evaluate(rules: list, events: list) -> dict:
    """Evaluate every rule against every event."""
    hits = defaultdict(list)
    for rule in rules:
        rid = rule.get("id", "?")
        for idx, event in enumerate(events):
            if rule_fires(rule, event):
                hits[rid].append({
                    "event_index": idx,
                    "event_id": event.get("EventID") or event.get("event_id"),
                    "provider": event.get("Provider") or event.get("provider"),
                    "image": event.get("Image") or event.get("TargetImage")
                             or event.get("ImagePath") or event.get("QueryName"),
                    "time": event.get("TimeCreated") or event.get("utc"),
                })

    by_id = {r.get("id", "?"): r for r in rules}
    results = []
    for rule in rules:
        rid = rule.get("id", "?")
        fired = hits.get(rid, [])
        results.append({
            "id": rid,
            "title": rule.get("title", ""),
            "level": rule.get("level", ""),
            "techniques": rule.get("techniques", []),
            "catches": rule.get("catches", ""),
            "fired": len(fired),
            "hits": fired[:20],
        })
    return {
        "rule_count": len(rules),
        "event_count": len(events),
        "rules_fired": sum(1 for r in results if r["fired"] > 0),
        "rules_silent": sum(1 for r in results if r["fired"] == 0),
        "results": results,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Evaluate the lab's detection rules against telemetry")
    ap.add_argument("--rules", required=True,
                    help="the rules JSON, from px_detect --emit json")
    ap.add_argument("--events", required=True,
                    help="the events JSON")
    ap.add_argument("--json", default=None,
                    help="write the report as JSON")
    ap.add_argument("--quiet", action="store_true",
                    help="only print the summary")
    args = ap.parse_args(argv)

    for path in (args.rules, args.events):
        if not os.path.isfile(path):
            print(f"error: not found: {path}", file=sys.stderr)
            return 2

    rules = load_json(args.rules)
    events = load_json(args.events)

    report = evaluate(rules, events)

    if not args.quiet:
        print("=" * 72)
        print("PHANTOM-X :: RULE EVALUATION")
        print("=" * 72)
        print(f"  rules  : {report['rule_count']}")
        print(f"  events : {report['event_count']}")
        print()
        print(f"  {'ID':<9} {'LVL':<7} {'FIRES':<6} TITLE")
        print(f"  {'-'*9} {'-'*7} {'-'*6} {'-'*40}")
        for r in report["results"]:
            mark = "  YES" if r["fired"] else "   no"
            print(f"  {r['id']:<9} {r['level']:<7} {mark:<6} {r['title'][:40]}")
        print()

    print(f"  {report['rules_fired']}/{report['rule_count']} rules fired, "
          f"{report['rules_silent']} silent")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"  report -> {os.path.abspath(args.json)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
