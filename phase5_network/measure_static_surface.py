#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: the static surface of each arm
===============================================================================
measure_static_surface.py -- What a defender can read from the binary BEFORE
the program does anything at all.

WHY THIS EXISTS
    A detection that fires at execution -- which is what caught this
    payload, as Trojan:Win32/Wacatac -- is not reading the binary. It is
    watching what the process does.

    But there is a second layer, and it is the layer a defender reads
    FIRST: the import table and the strings. An import table that says
    "RegCreateKeyExA" is not a list of API calls, it is a description of
    the behaviour, and it is available before a single instruction of
    the payload has run.

    So the question "what reduces the detection rate" has two parts, and
    this measures the first one:

        1. which arm has the smaller static surface      <- this script
        2. which arm gets fewer verdicts                 <- a submission

    Measure (1), submit, correlate. That is the lab's method, and it
    produces a table rather than an opinion.

USAGE
    python3 measure_static_surface.py
    python3 measure_static_surface.py --variants ..\\dist\\variants
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# The strings the obfuscation arm is supposed to remove. This is the
# same list the build verifies against, so the two cannot drift.
SENSITIVE = [
    "HELLO|", "RESULT|", "EXEC|", "PING", "PONG", "EXIT", "CRED|",
    "LATERAL|", "CAPS|", "ws2_32.dll", "kernel32.dll", "ntdll.dll",
    "amsi.dll", "AmsiScanBuffer", "EtwEventWrite", "schtasks.exe",
    "lsass.exe", "PX_C2_HOST", "cmd /c ",
]

# The API names that describe a behaviour rather than a facility.
# An import table that names one of these is telling the defender what
# the program will do.
BEHAVIOURAL = [
    "RegCreateKeyExA", "RegSetValueExA", "RegOpenKeyExA", "RegDeleteKeyA",
    "CreateServiceA", "OpenSCManagerA", "OpenProcessToken",
    "DuplicateTokenEx", "AdjustTokenPrivileges", "SetWindowsHookEx",
    "WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread",
    "WinExec", "ShellExecute",
]


def dumpbin(path):
    """The import table, as raw text."""
    try:
        r = subprocess.run(["dumpbin", "/imports", path],
                           capture_output=True, text=True, timeout=120)
        return (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return ""
    except Exception:  # noqa: BLE001
        return ""


def measure(path):
    """One arm's static surface."""
    with open(path, "rb") as fh:
        blob = fh.read()

    imports = dumpbin(path)

    dlls = sorted({m.group(1).lower() for m in
                   re.finditer(r"^\s+([A-Za-z0-9_]+\.dll)\s*$", imports,
                               re.M | re.I)})

    behavioural = sorted({n for n in BEHAVIOURAL
                          if re.search(r"\b" + re.escape(n) + r"\b", imports)})

    # The strings, in the raw image. An XOR-encoded string table does
    # not contain them.
    try:
        text = blob.decode("latin-1")
    except Exception:  # noqa: BLE001
        text = ""
    visible = [s for s in SENSITIVE if s in text]

    return {
        "size": len(blob),
        "dlls": dlls,
        "behavioural": behavioural,
        "visible": visible,
    }


def main():
    ap = argparse.ArgumentParser(
        description="Measure what a defender can read from each arm's binary")
    ap.add_argument("--variants", default=os.path.join(ROOT, "dist", "variants"))
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    if not os.path.isdir(args.variants):
        print(f"error: no variant builds in {args.variants}", file=sys.stderr)
        print("  build them:  cd phase3_fileless\\loader && "
              ".\\build_variants.ps1", file=sys.stderr)
        return 2

    arms = sorted(f for f in os.listdir(args.variants)
                  if f.startswith("px_payload_") and f.endswith(".exe"))

    print("=" * 78)
    print("PHANTOM-X :: THE STATIC SURFACE OF EACH ARM")
    print("=" * 78)
    print()
    print("  What a defender can read from the binary before it runs:")
    print()
    print(f"  {'ARM':<12} {'SIZE':>7}  {'DLLs':<28} {'BEHAVIOURAL':<12} {'STRINGS'}")
    print(f"  {'-'*12} {'-'*7}  {'-'*28} {'-'*12} {'-'*8}")

    rows = []
    for name in arms:
        path = os.path.join(args.variants, name)
        arm = name[len("px_payload_"):-len(".exe")]
        m = measure(path)
        rows.append((arm, m))
        print(f"  {arm:<12} {m['size']:>7}  "
              f"{','.join(d.split('.')[0] for d in m['dlls']):<28} "
              f"{len(m['behavioural']):<12} {len(m['visible'])}")

    print()
    print("  BEHAVIOURAL is the count of imported API names that describe a")
    print("  BEHAVIOUR rather than a facility -- RegCreateKeyExA says 'this")
    print("  writes to the registry'; WriteProcessMemory says 'this writes")
    print("  into another process'. A static scanner reads the import table")
    print("  before the program does anything, so every one of those names")
    print("  is a statement about what is coming.")
    print()
    print("  STRINGS is the count of sensitive literals still readable in")
    print("  the binary. The obfuscation arm's job is to make it zero.")
    print()
    print("  Submit each arm and correlate. The arm with the smaller")
    print("  surface is not automatically the quieter one -- the vendors")
    print("  that flagged this one were watching the BEHAVIOUR -- but the")
    print("  table says which reduction is worth measuring next.")
    print()

    if args.json:
        import json
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({arm: m for arm, m in rows}, fh, indent=2)
        print(f"  -> {os.path.abspath(args.json)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
