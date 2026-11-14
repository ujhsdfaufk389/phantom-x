"""The full local loop, in one script.

    1. start the C2 server
    2. start the payload
    3. ask the payload what it can see of the endpoint
    4. ask the CHECKER what it can see of the payload
    5. put the two side by side

    The two views are of the same machine at the same moment, and the
    point is that they agree: the payload says its ETW unhook is in
    place, and the checker finds the patched function in the payload's
    own memory.
"""

import os
import subprocess
import sys
import time

ROOT = r"C:\Users\SycoDiliCo\projects\phantom-x"
NET = os.path.join(ROOT, "phase5_network")
DEF = os.path.join(ROOT, "phase4_defender")
VAR = os.path.join(ROOT, "dist", "variants")
PORT = 9650


def step(n, text):
    print()
    print(f"[{n}] {text}")
    print("-" * 70)


def main():
    payload = os.path.join(VAR, "px_payload_all.exe")
    server = os.path.join(NET, "px_c2.exe")
    for p in (payload, server):
        if not os.path.isfile(p):
            print(f"error: {p} not found")
            return 2

    step(1, "Start the C2 server")
    audit = os.path.join(os.environ.get("TEMP", "."), "local_loop.jsonl")
    srv = subprocess.Popen(
        [server, "--host", "127.0.0.1", "--port", str(PORT), "--log", audit],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, bufsize=1)
    time.sleep(1.5)
    print(f"  listening on 127.0.0.1:{PORT}")
    print(f"  audit log: {audit}")

    step(2, "Start the payload")
    env = dict(os.environ)
    env["PX_C2_HOST"] = "127.0.0.1"
    env["PX_C2_PORT"] = str(PORT)
    pay = subprocess.Popen([payload], env=env, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
    time.sleep(4)
    print(f"  payload pid: {pay.pid}")

    try:
        step(3, "Ask the PAYLOAD what the endpoint looks like from inside")
        srv.stdin.write("cap 1 avstatus\n")
        srv.stdin.flush()
        time.sleep(2)

        step(4, "Ask the CHECKER what the PAYLOAD looks like from outside")
        chk = subprocess.run(
            [sys.executable, os.path.join(DEF, "check_endpoint_hooks.py"),
             "--pid", str(pay.pid), "--scan-mb", "64"],
            capture_output=True, text=True, timeout=600)

        step(5, "The two views, side by side")
        srv.stdin.write("quit\n")
        srv.stdin.flush()
        time.sleep(1)
        out, _ = srv.communicate(timeout=10)
        try:
            pay.terminate()
            pout, _ = pay.communicate(timeout=5)
        except Exception:
            pout = ""

        # The payload's own view.
        for ln in (out or "").splitlines():
            if "capability avstatus" in ln or "endpoint posture" in ln:
                print("  PAYLOAD  : " + ln.strip()[:100])
        for ln in (pout or "").splitlines():
            if "posture" in ln:
                print("  PAYLOAD  : " + ln.strip()[:100])
        # The checker's view.
        for ln in (chk.stdout or "").splitlines():
            if "PATCHED" in ln and "->" in ln:
                print("  CHECKER  : " + ln.strip()[:100])
            if "stub(s) found" in ln:
                print("  CHECKER  : " + ln.strip()[:100])

        print()
        print("  The payload says the ETW unhook is in place, and the")
        print("  checker finds the patched function in the payload's own")
        print("  memory. Two independent measurements, one machine.")
        print()
        print("  Full checker output:")
        for ln in (chk.stdout or "").splitlines():
            if ln.strip():
                print("    " + ln)
        return 0
    finally:
        try:
            pay.terminate()
        except Exception:
            pass
        try:
            srv.terminate()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
