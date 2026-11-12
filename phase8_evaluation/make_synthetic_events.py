#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: Phase 8 -- synthetic telemetry for the rule evaluator
================================================================================
make_synthetic_events.py -- Builds the event sets the evaluator is tested
against.

    WHY THIS EXISTS
        The evaluator's whole value is answering "does this rule fire".
        To test THAT, the test needs events with known answers: an event
        that a rule should match, and one that it should not.

        Writing those by hand in the test would be a wall of JSON that
        nobody can read. Writing them as a table here means the intent of
        each case is one line, and the expected rule is named next to it.

    THE CASES
        Each case is a set of events and the rules that must fire on
        them. The evaluator is checked against the expectation, so a
        change to a rule that breaks the evaluator's semantics is caught
        here rather than in a report that says "0 rules fired" and looks
        like a successful measurement.

    THIS IS NOT TELEMETRY
        The events here are synthetic. They exist to test the evaluator,
        not to measure anything. Real telemetry comes from
        collect_events.ps1 on the VM.
"""

from __future__ import annotations

import argparse
import json
import os
import sys


def base_event(**kw):
    """An event with the fields every rule looks at."""
    e = {
        "EventID": 1,
        "Provider": "Microsoft-Windows-Sysmon",
        "LogName": "Microsoft-Windows-Sysmon/Operational",
        "TimeCreated": "2026-11-12T10:00:00.0000000Z",
        "Level": "Information",
        "Image": "",
        "CommandLine": "",
    }
    e.update(kw)
    return e


# Each arm's event set, and the rules that must fire on it.
ARMS = {
    "baseline": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_loader.exe",
                       CommandLine="C:\\pxvm\\px_loader.exe C:\\pxvm\\px_attack_chain.pdf"),
            base_event(EventID=1, Image="C:\\Windows\\System32\\cmd.exe",
                       CommandLine="cmd.exe /c whoami",
                       ParentImage="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=3, Image="C:\\pxvm\\px_payload.exe",
                       DestinationPort="9001", DestinationIp="10.0.0.5",
                       Protocol="tcp", Initiated="true"),
            base_event(EventID=13, Image="C:\\Windows\\System32\\reg.exe",
                       TargetObject="HKEY_CURRENT_USER\\Software\\Classes\\PHANTOMX.PdfHandler"),
            base_event(EventID=1, Image="C:\\Windows\\System32\\cmd.exe",
                       CommandLine="cmd.exe /c echo PHANTOM",
                       ParentImage="C:\\pxvm\\px_loader.exe"),
            # A reader opening a PDF. This MUST NOT match the loader
            # rules -- it is the negative case, and a rule that fires on
            # every PDF is a rule nobody would keep.
            base_event(EventID=1, Image="C:\\Program Files\\Adobe\\Acrobat\\Acrobat.exe",
                       CommandLine="Acrobat.exe C:\\docs\\report.pdf"),
        ],
        ["px-001", "px-002", "px-003", "px-004", "px-006"],
    ),
    "obfuscate": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload_obfuscate.exe",
                       CommandLine="C:\\pxvm\\px_payload_obfuscate.exe"),
            base_event(EventID=7, Image="C:\\Windows\\System32\\cmd.exe",
                       TargetFilename="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=3, Image="C:\\pxvm\\px_payload.exe",
                       DestinationPort="9001", DestinationIp="10.0.0.5",
                       Protocol="tcp", Initiated="true"),
        ],
        ["px-003", "px-014"],
    ),
    "encrypt": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            # The encrypted channel: still the same port, but the traffic
            # no longer carries the protocol.
            base_event(EventID=3, Image="C:\\pxvm\\px_payload.exe",
                       DestinationPort="9001", DestinationIp="10.0.0.5",
                       Protocol="tcp", Initiated="true"),
        ],
        ["px-001", "px-011"],
    ),
    "cred": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=10, SourceImage="C:\\pxvm\\px_payload.exe",
                       TargetImage="C:\\Windows\\System32\\lsass.exe",
                       GrantedAccess="0x1410",
                       CallTrace="C:\\pxvm\\px_payload.exe+0x1234"),
        ],
        ["px-001", "px-009"],
    ),
    "amsi_etw": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=10, SourceImage="C:\\pxvm\\px_payload.exe",
                       TargetImage="C:\\Windows\\System32\\ntdll.dll",
                       GrantedAccess="0x40",
                       CallTrace="C:\\pxvm\\px_payload.exe+0x1234"),
            base_event(EventID=10, SourceImage="C:\\pxvm\\px_payload.exe",
                       TargetImage="C:\\Windows\\System32\\amsi.dll",
                       GrantedAccess="0x40",
                       CallTrace="C:\\pxvm\\px_payload.exe+0x1234"),
        ],
        ["px-001", "px-013"],
    ),
    "dga": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=22, Image="C:\\pxvm\\px_payload.exe",
                       QueryName="pxlab-20768-5a17c0de.lab.test",
                       QueryResults="0"),
        ],
        ["px-001", "px-012"],
    ),
    "lateral": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=7045, Provider="Service Control Manager",
                       ServiceName="PHANTOMX-Lateral-Lab",
                       ImagePath="\\\\LAB-PC\\ADMIN$\\px_payload.exe",
                       AccountName="SYSTEM"),
        ],
        ["px-001", "px-010"],
    ),

    # ------------------------------------------------------------------
    # The capability library.
    #
    # One arm per technique, because the whole point of the library is
    # that each technique produces its own telemetry delta. An arm that
    # mixed two techniques would produce a delta that could not be
    # attributed to either.
    # ------------------------------------------------------------------
    "cap_inject": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=10, SourceImage="C:\\pxvm\\px_payload.exe",
                       TargetImage="C:\\Windows\\System32\\svchost.exe",
                       GrantedAccess="0x1F0FFF",
                       CallTrace="C:\\pxvm\\px_payload.exe+0x1a20|WriteProcessMemory"),
        ],
        ["px-001", "px-015", "px-016"],
    ),
    "cap_token": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=10, SourceImage="C:\\pxvm\\px_payload.exe",
                       TargetImage="C:\\Windows\\System32\\lsass.exe",
                       GrantedAccess="0x1000",
                       CallTrace="C:\\pxvm\\px_payload.exe+0x2b10|OpenProcessToken"),
        ],
        ["px-001", "px-017"],
    ),
    "cap_keylog": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=10, SourceImage="C:\\pxvm\\px_payload.exe",
                       TargetImage="C:\\Windows\\System32\\user32.dll",
                       GrantedAccess="0x1000",
                       CallTrace="C:\\pxvm\\px_payload.exe+0x3c40|GetAsyncKeyState"),
        ],
        ["px-001", "px-049"],
    ),
    "cap_clip": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=10, SourceImage="C:\\pxvm\\px_payload.exe",
                       TargetImage="C:\\Windows\\System32\\user32.dll",
                       GrantedAccess="0x1000",
                       CallTrace="C:\\pxvm\\px_payload.exe+0x4d50|GetClipboardData"),
        ],
        ["px-001", "px-028"],
    ),
    "cap_persist": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=13, Image="C:\\pxvm\\px_payload.exe",
                       TargetObject="HKEY_CURRENT_USER\\Software\\Microsoft\\"
                                    "Windows\\CurrentVersion\\Run",
                       Details="PXLab"),
            base_event(EventID=19, Provider="Microsoft-Windows-WMI-Activity",
                       Operation="__EventFilter",
                       Query="SELECT * FROM __InstanceModificationEvent"),
        ],
        ["px-001", "px-021", "px-022"],
    ),
    "cap_antifor": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=104, Provider="Microsoft-Windows-Sysmon",
                       Channel="Application", User="lab"),
            base_event(EventID=11, Image="C:\\pxvm\\px_payload.exe",
                       TargetFilename="C:\\pxvm\\px_payload.exe.deleted",
                       EventType="Rename"),
            base_event(EventID=2, Image="C:\\pxvm\\px_payload.exe",
                       TargetFilename="C:\\pxvm\\px_payload.exe",
                       EventType="SetFileTime"),
        ],
        ["px-001", "px-025", "px-026", "px-027"],
    ),
    "cap_recon": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=1, Image="C:\\Windows\\System32\\cmd.exe",
                       CommandLine="cmd.exe /c net user",
                       ParentImage="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=3, Image="C:\\pxvm\\px_payload.exe",
                       DestinationPort="445", DestinationIp="10.0.0.9",
                       Protocol="tcp", Initiated="true"),
        ],
        ["px-001", "px-031", "px-032"],
    ),
    "cap_lolbin": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=1, Image="C:\\Windows\\System32\\wmic.exe",
                       CommandLine="wmic process call create \"cmd /c echo x\"",
                       ParentImage="C:\\pxvm\\px_payload.exe"),
        ],
        ["px-001", "px-034"],
    ),
    "cap_script": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=1, Image="C:\\Windows\\System32\\wscript.exe",
                       CommandLine="wscript.exe //nologo C:\\Users\\lab\\AppData\\"
                                   "Local\\Temp\\px_lab_script.js",
                       ParentImage="C:\\pxvm\\px_payload.exe"),
        ],
        ["px-001", "px-033"],
    ),
    "cap_dnstun": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=22, Image="C:\\pxvm\\px_payload.exe",
                       QueryName="t.p.h.a.n.t.o.m.x.tun.lab.test",
                       QueryLabelLength="long",
                       QueryResults="0"),
        ],
        ["px-001", "px-036"],
    ),
    "cap_steg": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=2, Image="C:\\pxvm\\px_payload.exe",
                       TargetFilename="C:\\Users\\lab\\AppData\\Local\\Temp\\"
                                    "px_lab_steg.png",
                       HasAppendedData="true", FileSize="4096"),
        ],
        ["px-001", "px-038"],
    ),
    "cap_spoof": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=11, Image="C:\\pxvm\\px_payload.exe",
                       TargetFilename="C:\\pxvm\\svchost.exe",
                       EventType="Rename"),
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="svchost.exe -k netsvcs"),
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe",
                       ParentImage="-", ParentProcessId="9999"),
        ],
        ["px-001", "px-018", "px-019", "px-020"],
    ),
    "cap_delay": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=1, Image="C:\\Windows\\System32\\cmd.exe",
                       CommandLine="cmd.exe /c timeout /t 300",
                       ParentImage="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=1, Image="C:\\Windows\\System32\\cmd.exe",
                       CommandLine="cmd.exe /c dsquery computer -name LAB-PC",
                       ParentImage="C:\\pxvm\\px_payload.exe"),
        ],
        ["px-001", "px-040", "px-041"],
    ),
    "cap_antivm": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=10, SourceImage="C:\\pxvm\\px_payload.exe",
                       TargetImage="C:\\Windows\\System32\\kernel32.dll",
                       GrantedAccess="0x1000",
                       CallTrace="C:\\pxvm\\px_payload.exe+0x5e60|IsDebuggerPresent"),
        ],
        ["px-001", "px-039"],
    ),
    "cap_xfer": (
        [
            base_event(EventID=1, Image="C:\\pxvm\\px_payload.exe",
                       CommandLine="C:\\pxvm\\px_payload.exe"),
            base_event(EventID=3, Image="C:\\pxvm\\px_payload.exe",
                       DestinationPort="9001", DestinationIp="10.0.0.5",
                       Protocol="tcp", Initiated="true",
                       PayloadMarker="CHUNK|7|0|5|QUJDREU="),
            base_event(EventID=2, Image="C:\\pxvm\\px_payload.exe",
                       TargetFilename="C:\\Users\\lab\\AppData\\Local\\Temp\\"
                                    "px_lab_shot.bmp"),
        ],
        ["px-001", "px-029", "px-037"],
    ),
}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Emit the synthetic event sets the evaluator is tested against")
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--arm", default=None,
                    help="emit only this arm")
    args = ap.parse_args(argv)

    os.makedirs(args.outdir, exist_ok=True)

    manifest = {}
    for name, (events, expected) in ARMS.items():
        if args.arm and name != args.arm:
            continue
        path = os.path.join(args.outdir, f"events_{name}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(events, fh, indent=2)
        manifest[name] = {"events": path, "expected_rules": expected}
        print(f"  {name:<12} {len(events)} events, expected: {', '.join(expected)}")

    manpath = os.path.join(args.outdir, "synthetic_manifest.json")
    with open(manpath, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    print(f"  manifest -> {manpath}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
