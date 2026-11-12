#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: Phase 8 -- the evaluator's own tests
================================================================================
test_evaluator.py -- Checks that the evaluator means what it says.

WHY THIS IS NEEDED
    The evaluator is what makes the lab's output trustworthy. If it has
    the wrong semantics, then "this rule did not fire" means nothing --
    it might just mean the evaluator is broken, and the report would look
    like a successful measurement of a rule that is actually fine.

    So the semantics are pinned here:

      - a rule fires when the selection matches
      - a rule does NOT fire when the filter matches
      - matchers inside a block are OR'd
      - the comparison is case-insensitive
      - an absent field never matches
      - a backslash in a path is handled correctly

    The last one is not hypothetical: the first version of the JSON
    emitter did not escape backslashes, so every path in every rule was
    an invalid JSON escape and the output did not parse at all.

RUN
    python3 test_evaluator.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from px_eval import evaluate, match_block, match_one, rule_fires  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, got, want) -> None:
    global PASS, FAIL
    if got == want:
        PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL {name}: got {got!r}, want {want!r}")


def matcher(field, op, *values):
    return {"field": field, "op": op, "values": list(values)}


def test_matching():
    ev = {"Image": "C:\\pxvm\\px_loader.exe", "EventID": 1}

    check("endswith", match_one(ev, matcher("Image", "endswith", "\\px_loader.exe")), True)
    check("endswith no match", match_one(ev, matcher("Image", "endswith", "\\px_payload.exe")), False)
    check("contains", match_one(ev, matcher("Image", "contains", "pxvm")), True)
    check("equals", match_one(ev, matcher("EventID", "equals", "1")), True)
    check("equals numeric type", match_one(ev, matcher("EventID", "equals", 1)), True)
    check("startswith", match_one(ev, matcher("Image", "startswith", "C:\\pxvm")), True)

    # Case insensitivity: a Windows path can be spelled any way.
    check("case insensitive", match_one(ev, matcher("Image", "endswith", "\\PX_LOADER.EXE")), True)

    # An absent field never matches. A rule that fired on missing data
    # would fire on everything.
    check("absent field", match_one(ev, matcher("NotThere", "equals", "x")), False)

    # A field present but empty does not match a non-empty value.
    check("empty field", match_one({"Image": ""}, matcher("Image", "contains", "px")), False)


def test_blocks():
    ev = {"Image": "C:\\pxvm\\px_loader.exe"}

    # OR within a block.
    block = [matcher("Image", "endswith", "\\px_loader.exe"),
             matcher("Image", "endswith", "\\px_payload.exe")]
    check("block or match", match_block(ev, block), True)
    check("block or no match", match_block(ev, [matcher("Image", "endswith", "\\x.exe")]), False)
    check("empty block", match_block(ev, []), False)


def test_rule_semantics():
    rule = {
        "id": "test",
        "selection": [matcher("Image", "endswith", "\\px_loader.exe")],
        "filter": [matcher("Image", "endswith", "\\acrobat.exe")],
    }
    check("fires", rule_fires(rule, {"Image": "C:\\px\\px_loader.exe"}), True)
    check("filtered out", rule_fires(rule, {"Image": "C:\\a\\acrobat.exe"}), False)
    check("no match", rule_fires(rule, {"Image": "C:\\a\\notepad.exe"}), False)

    # A rule with no filter: nothing excludes it.
    nofilter = {"id": "t", "selection": [matcher("Image", "endswith", "x")]}
    check("no filter", rule_fires(nofilter, {"Image": "x"}), True)

    # The AND block. A rule with one is narrower, and the narrowing is
    # the whole reason the block exists: without it the rule would fire
    # on every event with a CallTrace.
    andrule = {
        "id": "t",
        "selection": [matcher("CallTrace", "contains", "WriteProcessMemory")],
        "selection_and": [matcher("TargetImage", "endswith", "\\lsass.exe")],
    }
    check("and block matches",
          rule_fires(andrule, {"CallTrace": "WriteProcessMemory",
                               "TargetImage": "C:\\W\\lsass.exe"}), True)
    check("and block blocks",
          rule_fires(andrule, {"CallTrace": "WriteProcessMemory",
                               "TargetImage": "C:\\W\\notepad.exe"}), False)
    check("and block needs the selection too",
          rule_fires(andrule, {"TargetImage": "C:\\W\\lsass.exe"}), False)


def test_backslash_paths():
    """A path with backslashes must survive the JSON round trip.

    This is the bug that broke the first version: the emitter wrote the
    raw path, and a backslash in a JSON string is an invalid escape.
    """
    with tempfile.TemporaryDirectory() as td:
        # Build a rules file with a Windows path in it.
        rules = [{
            "id": "px-test",
            "selection": [matcher("Image", "endswith", "\\px_loader.exe")],
        }]
        rpath = os.path.join(td, "rules.json")
        with open(rpath, "w", encoding="utf-8") as fh:
            json.dump(rules, fh)

        from px_eval import load_json
        loaded = load_json(rpath)
        check("backslash survived", loaded[0]["selection"][0]["values"][0],
              "\\px_loader.exe")

        # And it still matches.
        ev = {"Image": "C:\\pxvm\\px_loader.exe"}
        check("backslash rule fires", rule_fires(loaded[0], ev), True)


def test_evaluate_counts():
    rules = [
        {"id": "r1", "title": "one", "level": "high",
         "selection": [matcher("Image", "endswith", "\\a.exe")]},
        {"id": "r2", "title": "two", "level": "low",
         "selection": [matcher("Image", "endswith", "\\b.exe")]},
    ]
    events = [{"Image": "C:\\x\\a.exe"}, {"Image": "C:\\x\\a.exe"}]
    rep = evaluate(rules, events)
    check("rules_fired", rep["rules_fired"], 1)
    check("rules_silent", rep["rules_silent"], 1)
    check("hit count", rep["results"][0]["fired"], 2)
    check("event_count", rep["event_count"], 2)


def test_real_rules_parse():
    """The REAL rules must load and evaluate.

    A test that only used made-up rules would not catch a rule whose
    field names are wrong, which is exactly the kind of thing that makes
    a rule quietly never fire.
    """
    exe = os.path.join(HERE, "..", "phase7_detection", "target", "release",
                       "px_detect.exe")
    if not os.path.isfile(exe):
        exe = os.path.join(HERE, "..", "phase7_detection", "target", "release",
                           "px_detect")
    if not os.path.isfile(exe):
        print("  SKIP the real rules test: px_detect is not built")
        return

    with tempfile.TemporaryDirectory() as td:
        rpath = os.path.join(td, "rules.json")
        with open(rpath, "wb") as fh:
            subprocess.run([exe, "--emit", "json"], stdout=fh, check=True)

        from px_eval import load_json
        rules = load_json(rpath)
        check("rule count", len(rules) >= 14, True)

        # Every rule must have the shape the evaluator needs.
        for r in rules:
            check(f"{r['id']} has a selection", len(r.get("selection", [])) > 0, True)
            for m in r.get("selection", []):
                check(f"{r['id']} matcher has a field", bool(m.get("field")), True)
                check(f"{r['id']} matcher has values", len(m.get("values", [])) > 0, True)
                check(f"{r['id']} matcher op is known",
                      m.get("op") in ("equals", "contains", "endswith",
                                      "startswith", "in"), True)

        # A known event must fire the rule that claims it.
        ev = {"Image": "C:\\pxvm\\px_payload.exe"}
        fired = [r["id"] for r in rules if rule_fires(r, ev)]
        check("px-001 fires on the payload", "px-001" in fired, True)

        # And a reader must NOT fire the loader rules.
        ev2 = {"Image": "C:\\Program Files\\Adobe\\Acrobat\\Acrobat.exe"}
        fired2 = [r["id"] for r in rules if rule_fires(r, ev2)]
        check("a reader does not fire px-001", "px-001" in fired2, False)


def test_synthetic_arms():
    """Every synthetic arm must fire its own rules, and only its own.

    This is the check that keeps a rule from being a noise generator.

    A rule that fires on every event of every arm is not a detection; it
    is a line of noise in the report. And a rule that fires on nothing
    is a rule that will never be found in production. Both failures are
    silent, so they are checked here rather than being noticed later.
    """
    exe = os.path.join(HERE, "..", "phase7_detection", "target", "release",
                       "px_detect.exe")
    if not os.path.isfile(exe):
        exe = os.path.join(HERE, "..", "phase7_detection", "target", "release",
                           "px_detect")
    if not os.path.isfile(exe):
        print("  SKIP the synthetic arms test: px_detect is not built")
        return

    sys.path.insert(0, HERE)
    from make_synthetic_events import ARMS

    with tempfile.TemporaryDirectory() as td:
        rpath = os.path.join(td, "rules.json")
        with open(rpath, "wb") as fh:
            subprocess.run([exe, "--emit", "json"], stdout=fh, check=True)

        from px_eval import load_json
        rules = load_json(rpath)

        # The rules that are allowed to fire on more than one arm: the
        # ones that describe the chain itself, which every arm inherits.
        shared = {"px-001", "px-003", "px-004", "px-006", "px-009",
                  "px-010", "px-011", "px-012", "px-013", "px-014"}

        for arm, (events, expected) in ARMS.items():
            fired = {r["id"] for r in rules
                     for ev in events if rule_fires(r, ev)}
            for rid in expected:
                check(f"{arm}: {rid} fires", rid in fired, True)

            # Nothing else that belongs to another arm may fire here.
            others = set()
            for other_arm, (_, other_expected) in ARMS.items():
                if other_arm == arm:
                    continue
                others |= set(other_expected)
            for rid in sorted(fired - set(expected) - shared - others):
                check(f"{arm}: {rid} does not fire", rid in fired, False)


def test_catalog():
    """The catalogue must be well formed, and its rules must exist.

    A catalogue entry that names a rule which does not exist is a lie:
    it would make the coverage matrix claim a technique is covered when
    nothing detects it.
    """
    exe = os.path.join(HERE, "..", "phase7_detection", "target", "release",
                       "px_detect.exe")
    if not os.path.isfile(exe):
        exe = os.path.join(HERE, "..", "phase7_detection", "target", "release",
                           "px_detect")
    if not os.path.isfile(exe):
        print("  SKIP the catalogue test: px_detect is not built")
        return

    with tempfile.TemporaryDirectory() as td:
        cpath = os.path.join(td, "catalog.json")
        rpath = os.path.join(td, "rules.json")
        with open(cpath, "wb") as fh:
            subprocess.run([exe, "--emit", "catalog"], stdout=fh, check=True)
        with open(rpath, "wb") as fh:
            subprocess.run([exe, "--emit", "json"], stdout=fh, check=True)

        from px_eval import load_json
        catalog = load_json(cpath)
        rules = load_json(rpath)
        rule_ids = {r["id"] for r in rules}

        check("catalogue is not empty", len(catalog) > 50, True)
        check("catalogue covers the lab's techniques",
              len({t["id"] for t in catalog}) == len(catalog), True)

        for t in catalog:
            check(f"{t['id']} has a tactic", bool(t.get("tactic")), True)
            check(f"{t['id']} has a name", bool(t.get("name")), True)
            check(f"{t['id']} has a status",
                  t.get("status") in ("measured", "ruled", "not_exercised"), True)
            check(f"{t['id']} has a kind",
                  t.get("kind") in ("technique", "campaign"), True)
            check(f"{t['id']} has telemetry", bool(t.get("telemetry")), True)

            for rid in [x.strip() for x in t.get("rules", "").split(",") if x.strip()]:
                check(f"{t['id']} names a rule that exists ({rid})",
                      rid in rule_ids, True)

        # Every technique the rules cover must also be in the catalogue.
        # A rule for a technique that the catalogue does not mention is
        # a rule the coverage matrix will never account for.
        in_catalog = {t["id"] for t in catalog}
        for r in rules:
            for tech in r.get("techniques", []):
                check(f"{r['id']} technique {tech} is in the catalogue",
                      tech.strip() in in_catalog, True)


def main() -> int:
    print("=" * 60)
    print("PHANTOM-X :: EVALUATOR TESTS")
    print("=" * 60)
    for fn in (test_matching, test_blocks, test_rule_semantics,
               test_backslash_paths, test_evaluate_counts,
               test_real_rules_parse, test_synthetic_arms, test_catalog):
        print(f"  {fn.__name__}")
        fn()
    print()
    print(f"  {PASS} passed, {FAIL} failed")
    print(f"  RESULT: {'PASS' if FAIL == 0 else 'FAIL'}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
