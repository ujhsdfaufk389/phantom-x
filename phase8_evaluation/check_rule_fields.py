"""Which rule fields can the lab's own telemetry actually produce?

A rule that keys on a field nothing produces can never fire. That is
not a rule, it is a decoration -- and the coverage report would show it
as covered.

The collector (phase8_evaluation/collect_events.ps1) copies the Sysmon
EventData fields verbatim, plus EventID/Provider/LogName/TimeCreated/
Level/Message for everything else. So the question is: which fields do
Sysmon, Defender, the WMI-Activity log, the service log and the DNS
client log actually carry?
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "phase8_evaluation"))
from px_eval import load_json  # noqa: E402

# What the platform actually produces.
#
# Sysmon 1 (process create), 2 (file create time), 3 (network connect),
# 7 (image load), 8 (create remote thread), 10 (process access),
# 11 (file create), 13 (registry set), 22 (dns query), 23/25 (delete).
#
# Plus Defender, PowerShell 4104, WMI-Activity, the service log (7045)
# and the task scheduler log.
REAL = {
    # Sysmon 1
    "Image", "CommandLine", "CurrentDirectory", "User", "LogonGuid",
    "LogonId", "TerminalSessionId", "IntegrityLevel", "Hashes",
    "ParentProcessGuid", "ParentProcessId", "ParentImage",
    "ParentCommandLine", "ParentUser", "Protocol", "ParentProtocol",
    "ProcessId", "ProcessGuid", "ProcessStartTime", "UtcTime",
    # Sysmon 2 / 11 / 23 / 25
    "TargetFilename", "CreationUtcTime", "IsExecutableDeleted",
    # Sysmon 3
    "Initiated", "SourceIsIpv6", "SourceIp", "SourceHostname", "SourcePort",
    "DestinationIsIpv6", "DestinationIp", "DestinationHostname",
    "DestinationPort",
    # Sysmon 7
    "ImageLoaded", "FileVersion", "Description", "Product", "Company",
    "OriginalFileName", "Signed", "Signature", "SignatureStatus",
    # Sysmon 8 / 10
    "SourceImage", "TargetImage", "TargetId", "StartModule", "StartFunction",
    "GrantedAccess", "CallTrace", "SourceUser", "TargetUser",
    # Sysmon 13
    "EventType", "TargetObject", "Details",
    # Sysmon 22
    "QueryName", "QueryStatus", "QueryResults",
    # Defender
    "ThreatID", "ThreatName", "ActionSuccess", "ThreatDetails",
    "AdditionalDetails", "Resources",
    # PowerShell 4104
    "ScriptBlockText", "Path", "MessageNumber", "MessageTotal",
    "HostApplication",
    # WMI-Activity
    "Operation", "Query", "UserID", "ProcessID", "Namespace",
    # service log 7045
    "ServiceName", "ImagePath", "ServiceFileName", "ServiceType",
    "ServiceStartType", "AccountName", "ServiceAccount",
    # task scheduler
    "TaskName", "TaskContent", "TaskContentXML",
    # the collector's own envelope
    "EventID", "Provider", "LogName", "TimeCreated", "Level", "Message",
}

# The EventType values Sysmon can produce.
#
# Sysmon 13 (registry set) carries EventType and it is always
# "SetValue". The file events carry no EventType at all. So a rule that
# asks for EventType "Delete" is asking for something that does not
# exist, and it would never fire however long the lab ran.
EVENTTYPE_VALUES = {"setvalue"}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Check that every rule keys on fields the platform produces")
    ap.add_argument("--rules", default=None,
                    help="the rules JSON (default: read from px_detect)")
    ap.add_argument("--catalog", default=None,
                    help="the catalogue JSON (default: read from px_detect)")
    args = ap.parse_args()

    rules_path = args.rules
    catalog_path = args.catalog
    tmp = None
    if not rules_path or not catalog_path:
        tmp = tempfile.mkdtemp(prefix="px_fieldcheck_")
        exe = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "phase7_detection", "target", "release",
                           "px_detect.exe")
        if not os.path.isfile(exe):
            exe = exe[:-4]
        if not os.path.isfile(exe):
            print("px_detect is not built; run build_all.ps1", file=sys.stderr)
            return 2
        rules_path = rules_path or os.path.join(tmp, "rules.json")
        catalog_path = catalog_path or os.path.join(tmp, "catalog.json")
        for path, fmt in ((rules_path, "json"), (catalog_path, "catalog")):
            with open(path, "wb") as fh:
                subprocess.run([exe, "--emit", fmt], stdout=fh, check=True)

    rules = load_json(rules_path)
    cat = load_json(catalog_path)

    print("=" * 74)
    print("RULES THAT KEY ON A FIELD THE PLATFORM DOES NOT PRODUCE")
    print("=" * 74)
    print()
    print("  These rules CANNOT fire against the lab's own telemetry. They")
    print("  are not wrong; they are unmeasurable with the collector that")
    print("  exists. A rule that needs a field nothing emits is a")
    print("  decoration, and the coverage matrix would count it as covered.")
    print()

    broken = []
    declared = []
    for r in rules:
        matchers = (r.get("selection", []) + r.get("selection_and", [])
                    + r.get("filter", []))
        fields = {m["field"] for m in matchers}
        missing = sorted(f for f in fields if f not in REAL)
        if not missing:
            continue
        if r.get("requires"):
            # The rule says what it needs. That is accounted for, not
            # broken -- but it is not measurable either, so it is still
            # reported.
            declared.append((r["id"], r["title"], r["requires"]))
        else:
            broken.append((r["id"], r["title"], missing, r.get("catches", "")))

    print("  UNDECLARED -- a defect. The rule needs a field nothing")
    print("  produces and does not say so:")
    print()
    for rid, title, missing, catches in broken:
        print(f"  {rid}  {title[:46]}")
        print(f"        needs : {', '.join(missing)}")
        print(f"        catches: {catches[:60]}")
    if not broken:
        print("    (none)")
    print()

    print("  DECLARED -- the rule says what it needs. Not measurable with")
    print("  the collector that exists, but not pretending:")
    print()
    for rid, title, req in declared:
        print(f"  {rid}  {title[:46]}")
        print(f"        needs : {req}")
    if not declared:
        print("    (none)")
    print()
    print(f"  {len(rules) - len(broken) - len(declared)} of {len(rules)} rules "
          f"are measurable today,")
    print(f"  {len(declared)} need a data source the lab does not have, and "
          f"{len(broken)} are defects.")
    print()

    # The EventType values.
    #
    # Sysmon 13 (registry set) carries EventType, and its value is
    # ALWAYS "SetValue". The file events (2, 11, 23, 25) carry no
    # EventType at all. So a rule that says EventType contains "Delete"
    # or "Rename" is not just unlikely -- it is impossible against
    # Sysmon, and it would never fire however long the lab ran.
    print("=" * 74)
    print("RULES THAT KEY ON AN EventType VALUE SYSMON NEVER PRODUCES")
    print("=" * 74)
    print()
    impossible = []
    for r in rules:
        matchers = (r.get("selection", []) + r.get("selection_and", []))
        for m in matchers:
            if m["field"] != "EventType":
                continue
            for v in m["values"]:
                if str(v).lower() not in EVENTTYPE_VALUES:
                    impossible.append((r["id"], r["title"], v))
                    break
    for rid, title, v in impossible:
        print(f"  {rid}  {title[:46]}")
        print(f"        wants EventType '{v}', which Sysmon never emits")
    print()
    if impossible:
        print(f"  {len(impossible)} rules ask for an EventType that does not")
        print("  exist.")
    else:
        print("  none.")
    print()

    total = len(broken) + len(impossible)
    print("=" * 74)
    print(f"DEFECTS: {total}. DECLARED BUT UNMEASURABLE: {len(declared)}.")
    print("=" * 74)
    print()
    print("  The catalogue's status column:")
    print()
    for t in cat:
        if t["status"] == "measured":
            continue
        print(f"    {t['id']:<12} {t['status']:<14} {t['name'][:44]}")
    print()

    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
