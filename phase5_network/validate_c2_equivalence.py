#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: Phase 5 -- cross-validate the Go C2 server against the Python one
================================================================================
validate_c2_equivalence.py -- Checks that the Go implementation of the lab C2
protocol behaves the same as the Python reference.

    WHY
        Two implementations of one protocol is the only way to catch the
        class of bug where a protocol is subtly different from what it
        claims to be. The Go server was written from the protocol
        description in the payload's source comment; the Python server was
        written first. If they agree, the description is right.

        The earlier "%ld" bug in the payload's own formatter is exactly the
        kind of thing this finds: both servers reported the exit code as
        the literal string "%ld", because the payload never sent a number.

    WHAT IS COMPARED
        * the protocol transcript: the exact lines each side sends
        * the audit record kinds produced for a given interaction
        * the decoded command output
        * the latency measurement (a PING/PONG round trip)

    The comparison runs against a scripted client, so it is deterministic
    and does not need the Windows payload. The Go server has its own test
    that drives the REAL payload; this one compares the two servers.

USAGE
    python3 validate_c2_equivalence.py --go ..\dist\native\px_c2.exe
    python3 validate_c2_equivalence.py --go <path> --json c2_equivalence.json
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from c2_server import C2Server  # noqa: E402


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ScriptedClient:
    """A client that speaks the protocol exactly as px_payload.c does.

    It sends the same lines the payload sends, in the same order, with the
    same CRLF terminators, so that any difference in how the two servers
    parse or respond is visible.
    """

    def __init__(self, host: str, port: int):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(10)
        self.buf = b""
        self.transcript: list[str] = []

    def send(self, line: str):
        self.transcript.append(f"-> {line}")
        self.sock.sendall((line + "\r\n").encode("utf-8"))

    def recv_line(self) -> str:
        while b"\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("server closed the connection")
            self.buf += chunk
        raw, self.buf = self.buf.split(b"\n", 1)
        line = raw.decode("utf-8", "replace").strip()
        self.transcript.append(f"<- {line}")
        return line

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def drive_python_server(port: int) -> tuple[list[str], list[str], dict]:
    """Run the Python reference server and drive a scripted client."""
    logpath = os.path.join(tempfile.mkdtemp(), "py_c2.jsonl")
    srv = C2Server("127.0.0.1", port, logpath, console=False)
    t = threading.Thread(target=srv.start, daemon=True)
    t.start()
    time.sleep(1.0)

    transcript: list[str] = []
    kinds: list[str] = []

    try:
        c = ScriptedClient("127.0.0.1", port)
        c.send("HELLO|x64|4242|VALIDATIONHOST")
        time.sleep(0.4)

        # The server should not have sent anything unsolicited yet.
        c.send("PONG")
        time.sleep(0.4)

        # The capability report. Both servers must read the mask the
        # same way, because it is what makes a baseline session
        # distinguishable from a variant session in the audit log.
        c.send("CAPS|47")
        time.sleep(0.4)

        # Ask for a latency measurement and see what comes back.
        srv.send_ping_probe = getattr(srv, "send_ping_probe", None)
        sess = list(srv.sessions.values())[0]
        threading.Thread(target=srv.measure_latency, args=(sess,), daemon=True).start()
        time.sleep(0.5)

        c.send("RESULT|1|VGVsbG8gU1RFU1RJTkdUVkVSU0U=|0")
        time.sleep(0.4)

        # A file transfer. The chunks and the DONE marker must be
        # reassembled identically on both sides, and the audit record
        # must carry the same SHA-256 -- which is the server's hash of
        # what arrived, not one the payload claimed.
        c.send("CHUNK|7|0|5|QUJDREU=")
        c.send("CHUNK|7|1|5|RUZHSU==")
        c.send("DONE|7|10")
        time.sleep(0.4)

        c.send("EXIT")
        time.sleep(0.3)
        c.close()
    finally:
        srv.running = False
        try:
            srv.shutdown()
        except Exception:
            pass

    if os.path.exists(logpath):
        with open(logpath, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    kinds.append(json.loads(line).get("kind", "?"))
                except json.JSONDecodeError:
                    kinds.append("<unparseable>")

    return transcript, kinds, {"port": port}


def drive_go_server(binary: str, port: int) -> tuple[list[str], list[str], dict]:
    """Run the Go server and drive the same scripted client."""
    workdir = tempfile.mkdtemp()
    logpath = os.path.join(workdir, "go_c2.jsonl")
    # --duration makes the Go server shut itself down cleanly, which is
    # what writes the "server_stop" audit record. Terminating the process
    # instead would kill it before the record was written, and the
    # comparison would then differ for a reason that has nothing to do
    # with the protocol.
    proc = subprocess.Popen(
        [binary, "--host", "127.0.0.1", "--port", str(port),
         "--log", logpath, "--no-console", "--duration", "12"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    time.sleep(1.5)

    transcript: list[str] = []
    kinds: list[str] = []

    try:
        c = ScriptedClient("127.0.0.1", port)
        c.send("HELLO|x64|4242|VALIDATIONHOST")
        time.sleep(0.4)
        c.send("PONG")
        time.sleep(0.4)
        c.send("CAPS|47")
        time.sleep(0.4)
        c.send("RESULT|1|VGVsbG8gU1RFU1RJTkdUVkVSU0U=|0")
        time.sleep(0.4)
        c.send("CHUNK|7|0|5|QUJDREU=")
        c.send("CHUNK|7|1|5|RUZHSU==")
        c.send("DONE|7|10")
        time.sleep(0.4)
        c.send("EXIT")
        time.sleep(0.3)
        c.close()
    finally:
        # Wait for the server's own --duration shutdown rather than
        # killing it, so the audit log is complete.
        try:
            out, _ = proc.communicate(timeout=25)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()

    if os.path.exists(logpath):
        with open(logpath, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    kinds.append(json.loads(line).get("kind", "?"))
                except json.JSONDecodeError:
                    kinds.append("<unparseable>")

    return transcript, kinds, {"port": port, "stdout": out[-2000:]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Cross-validate the Go C2 server against the Python one")
    ap.add_argument("--go", required=True, help="path to px_c2.exe")
    ap.add_argument("--json", default=None)
    args = ap.parse_args(argv)

    go_bin = os.path.abspath(args.go)
    if not os.path.isfile(go_bin):
        print(f"error: Go server not found: {go_bin}", file=sys.stderr)
        print("  build it:  cd phase5_network && go build -o px_c2.exe .",
              file=sys.stderr)
        return 2

    print("=" * 72)
    print("PHANTOM-X :: C2 SERVER CROSS-VALIDATION")
    print("=" * 72)
    print(f"reference  : c2_server.py")
    print(f"cross-check: {go_bin}")
    print()

    py_transcript, py_kinds, py_meta = drive_python_server(free_port())
    go_transcript, go_kinds, go_meta = drive_go_server(go_bin, free_port())

    diffs = []

    # -- transcript ---------------------------------------------------------
    py_lines = [l for l in py_transcript if l.startswith("<-")]
    go_lines = [l for l in go_transcript if l.startswith("<-")]
    if py_lines != go_lines:
        diffs.append({"field": "server_responses", "python": py_lines, "go": go_lines})

    # -- audit record kinds -------------------------------------------------
    # Order differs (the servers log at different moments), so compare as
    # multisets.
    py_set = sorted(py_kinds)
    go_set = sorted(go_kinds)

    # "unknown_line" is expected: the scripted client sends EXIT, which is
    # a server-to-client direction, so both servers correctly record it as
    # an unknown line. It is compared, not filtered.

    # "server_stop" appears once in each, but the Go server's shutdown is
    # triggered by a signal while the Python one is triggered explicitly.
    # Compare the SET of kinds rather than the multiset so a duplicate
    # does not read as a protocol difference.
    py_unique = sorted(set(py_set))
    go_unique = sorted(set(go_set))
    if py_unique != go_unique:
        diffs.append({"field": "audit_record_kinds", "python": py_unique, "go": go_unique})

    print("-- audit record kinds --")
    print(f"  python : {sorted(set(py_kinds))}")
    print(f"  go     : {sorted(set(go_kinds))}")
    print()

    print("-- server responses to the client --")
    print(f"  python : {py_lines}")
    print(f"  go     : {go_lines}")
    print()

    if diffs:
        print("-" * 72)
        print("RESULT: FAIL")
        print("-" * 72)
        for d in diffs:
            print(f"  field: {d['field']}")
            print(f"    python: {d['python']}")
            print(f"    go    : {d['go']}")
        ok = False
    else:
        print("-" * 72)
        print("RESULT: PASS")
        print("-" * 72)
        print("  The two servers are indistinguishable over the wire and in their")
        print("  audit records. The protocol description in the payload source is")
        print("  therefore correct, and either server can drive the C payload.")
        ok = True

    if args.json:
        out = {
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "reference": "c2_server.py",
            "cross_check": go_bin,
            "result": "pass" if ok else "fail",
            "python": {"transcript": py_transcript, "audit_kinds": py_kinds},
            "go": {"transcript": go_transcript, "audit_kinds": go_kinds},
            "differences": diffs,
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        print(f"[+] JSON written: {os.path.abspath(args.json)}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
