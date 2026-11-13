"""What did the endpoint think of each arm, during the suite run?

The suite drives every arm for real: it starts the payload, runs
commands through it, transfers a file, captures the screen, and runs
the capability library. That is a lot more behaviour than "start the
binary and let it retry", and the endpoint's verdict depends on what
the process actually does.

So this script runs the suite and then asks Defender, for each arm,
what it detected SINCE the suite started. The history is not the
answer -- an arm flagged last week still shows a verdict today -- so
the clock matters.

USAGE
    python measure_suite_detections.py
"""

import os
import subprocess
import sys
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VARIANTS = os.path.join(ROOT, "dist", "variants")


def detections_since(path, since):
    try:
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command",
             "$p = '%s'; $s = '%s';"
             " Get-MpThreatDetection | Where-Object {"
             " $_.Resources -match [regex]::Escape($p) -and"
             " $_.InitialDetectionTime -gt $s } | ForEach-Object {"
             " $t = Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue;"
             " Write-Output $t.ThreatName }"
             % (path, since.strftime("%Y-%m-%d %H:%M:%S"))],
            capture_output=True, text=True, timeout=120)
        return sorted({ln.strip() for ln in (r.stdout or "").splitlines()
                       if ln.strip()})
    except Exception:  # noqa: BLE001
        return []


def main():
    started = datetime.now()
    print("=" * 74)
    print("PHANTOM-X :: THE ENDPOINT'S VERDICT, DURING A REAL SUITE RUN")
    print("=" * 74)
    print(f"  started : {started.strftime('%H:%M:%S')}")
    print()

    r = subprocess.run([sys.executable,
                        os.path.join(ROOT, "run_all_tests.py")],
                       cwd=ROOT, capture_output=True, text=True, timeout=3600)
    tail = [ln for ln in (r.stdout or "").splitlines()
            if "variant arms" in ln or "PASS" in ln or "FAIL" in ln]
    for ln in tail[-16:]:
        print("  " + ln)
    print()

    print("-" * 74)
    print("  WHAT DEFENDER SAID, ARM BY ARM, SINCE THE RUN STARTED")
    print("-" * 74)
    flagged = 0
    for name in sorted(os.listdir(VARIANTS)):
        if not name.endswith(".exe"):
            continue
        path = os.path.join(VARIANTS, name)
        threats = detections_since(path, started)
        if threats:
            flagged += 1
            print(f"  {name:<28} {', '.join(threats)}")
        else:
            print(f"  {name:<28} (nothing)")

    print()
    print(f"  {flagged} of the arms were flagged during the run.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
