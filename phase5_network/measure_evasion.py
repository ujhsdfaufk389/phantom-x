"""Does the stealth arm survive the endpoint?

THE EXPERIMENT
    The endpoint's verdict on this payload arrives at EXECUTION. The
    question is what it is reading. The candidates are:

        a) the binary's static shape    -- strings, imports, layout
        b) the ARTEFACTS                -- the marker file and the log
                                          file written next to the image
        c) the BEHAVIOUR                -- the socket, the commands

    The stealth arm changes (b) and blurs (c)'s opening move, and
    leaves (a) and the techniques alone. So running it is the
    measurement: if the verdict changes, the artefact was the trigger.

    Each arm is run N times. The endpoint is a probabilistic detector,
    so one run proves nothing; the count is the answer.
"""

import os
import subprocess
import sys
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VARIANTS = os.path.join(ROOT, "dist", "variants")
SERVER = os.path.join(HERE, "px_c2.exe")


def detections_for(path, since=None):
    """The threat names Defender has recorded against this file.

    Only detections AFTER the run started, when a start time is given.

    The distinction matters: Defender keeps the history, so an arm that
    was flagged last week still shows a verdict today. Counting those
    would make every arm look guilty and the experiment would prove
    nothing. The question is what the endpoint thinks of the binary NOW.
    """
    try:
        since_clause = ""
        if since is not None:
            since_clause = (" -and $_.InitialDetectionTime -gt '%s'"
                            % since.strftime("%Y-%m-%d %H:%M:%S"))
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command",
             "$p = '%s';"
             " Get-MpThreatDetection | Where-Object { $_.Resources -match"
             " [regex]::Escape($p)" + since_clause + " } | ForEach-Object {"
             " $t = Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue;"
             " Write-Output $t.ThreatName }" % path],
            capture_output=True, text=True, timeout=120)
        return sorted({ln.strip() for ln in (r.stdout or "").splitlines()
                       if ln.strip()})
    except Exception:  # noqa: BLE001
        return []


def run_arm(arm, port):
    """Run one arm once. Returns 'ok', 'blocked', or 'gone'."""
    exe = os.path.join(VARIANTS, f"px_payload_{arm}.exe")
    if not os.path.isfile(exe):
        return "gone"
    env = dict(os.environ)
    env["PX_C2_HOST"] = "127.0.0.1"
    env["PX_C2_PORT"] = str(port)
    try:
        p = subprocess.Popen([exe], env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
    except OSError as exc:
        # "the file contains a virus or potentially unwanted software"
        if "virus" in str(exc).lower() or "did not complete" in str(exc).lower():
            return "blocked"
        return "gone"

    time.sleep(3.0)
    try:
        p.terminate()
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
    return "ok"


def main():
    arms = sys.argv[1:] or ["baseline", "caps", "all", "stealth"]
    rounds = int(os.environ.get("ROUNDS", "5"))

    print("=" * 74)
    print("PHANTOM-X :: DOES THE STEALTH ARM SURVIVE THE ENDPOINT?")
    print("=" * 74)
    print(f"  rounds per arm : {rounds}")
    print()

    port = 9500
    for arm in arms:
        exe = os.path.join(VARIANTS, f"px_payload_{arm}.exe")
        outcomes = []
        # The clock starts now, so only detections from THIS experiment
        # count. Defender's history is evidence about the past, not
        # about the binary in front of us now.
        started = datetime.now()
        for _ in range(rounds):
            port += 1
            outcomes.append(run_arm(arm, port))
            time.sleep(0.5)

        ok = outcomes.count("ok")
        blocked = outcomes.count("blocked")
        gone = outcomes.count("gone")
        threats = detections_for(exe, started)

        print(f"  {arm:<12} ran {ok}/{rounds}   blocked {blocked}   "
              f"missing {gone}")
        if threats:
            print(f"               Defender, since the run started: "
                  f"{', '.join(threats)}")
        else:
            print("               Defender, since the run started: "
                  "nothing")
        print()

    print("  A 'blocked' is the endpoint refusing to execute the binary.")
    print("  A 'missing' is the endpoint having quarantined it.")
    print("  Neither is a lab failure; both are the answer.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
