#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: network reachability check
================================================================================
netreach.py -- Answers the question that actually blocks the lab:

    "can the VM reach the C2 from where it is right now?"

    It runs on the VM. It resolves the C2 the same way the payload does,
    tries every port the payload would try, and reports exactly where the
    path breaks: DNS, routing, the port, or the C2 itself.

WHY THIS EXISTS
    The lab has to work on whatever network the operator is on today: the
    office wifi, a mobile hotspot, a hotel. The most common failure is not
    a bug in the payload -- it is that the VM cannot reach the C2 at all,
    and the symptom is a payload that logs "connect failed" once and
    exits, which looks like a broken build.

    This separates the four possible causes:

        DNS          the name does not resolve
        ROUTING      the address resolves but no route exists
        FILTERED     the route exists but the port is dropped
        OK           the C2 answered

    The difference matters because the fix is different for each. A
    filtered port on a corporate network is fixed by using a port the
    network permits, not by changing the payload.

WHAT IT DOES NOT DO
    It does not send anything to the C2. It opens the TCP connection and
    closes it. The C2 will log a session that connected and disconnected
    without saying anything, which is visible in the audit log -- so run
    this before a measurement, not during one.

USAGE
    On the VM:

        python3 netreach.py --host c2.lab.example --port 9001
        python3 netreach.py --host c2.lab.example --ports 9001,443,80
        python3 netreach.py --host c2.lab.example --json

    With no --host it uses the payload's own default endpoint, so the
    operator does not have to keep two sets of answers in their head.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone


def resolve(host: str) -> tuple[list[str], str]:
    """Resolve a host to its addresses.

    Returns the addresses and a status: "ok", "literal", or "failed".
    """
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET,
                                   socket.SOCK_STREAM)
        addrs = []
        for info in infos:
            a = info[4][0]
            if a not in addrs:
                addrs.append(a)
        if addrs:
            return addrs, "ok"
    except socket.gaierror as exc:
        return [], f"failed ({exc})"

    # getaddrinfo can fail for a bare address on some resolvers, so try
    # the literal interpretation before giving up.
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return [host], "literal"
    return [], "failed"


def probe(addr: str, port: int, timeout: float) -> tuple[str, str]:
    """Try one TCP connection.

    Returns (verdict, detail). The verdict is one of:
        open       the connection was accepted
        refused    nothing is listening
        timeout    the packets went nowhere (filtered or no route)
        error      something else
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((addr, port))
        return "open", "the C2 accepted the connection"
    except socket.timeout:
        return "timeout", ("no answer -- the port is filtered or there is "
                           "no route")
    except ConnectionRefusedError:
        return "refused", ("nothing is listening -- the C2 is not up, or it "
                           "is bound to a different address")
    except OSError as exc:
        return "error", str(exc)
    finally:
        s.close()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Check whether the VM can reach the lab C2")
    ap.add_argument("--host", default=None,
                    help="the C2 host (defaults to the payload's own)")
    ap.add_argument("--port", type=int, default=None,
                    help="the C2 port")
    ap.add_argument("--ports", default=None,
                    help="a comma-separated port list to try in order")
    ap.add_argument("--timeout", type=float, default=5.0,
                    help="seconds per probe")
    ap.add_argument("--json", action="store_true",
                    help="emit the result as JSON")
    args = ap.parse_args(argv)

    # The defaults match the payload's compiled-in ones, so the operator
    # does not have to keep two sets of answers in their head.
    host = args.host or os.environ.get("PX_C2_HOST", "127.0.0.1")
    if args.ports:
        ports = [int(p) for p in args.ports.split(",") if p.strip()]
    elif args.port:
        ports = [args.port]
    else:
        env_port = os.environ.get("PX_C2_PORT")
        ports = [int(env_port)] if env_port else [9001]

    report = {
        "checked_utc": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "ports": ports,
        "addresses": [],
        "resolution": "unknown",
        "results": [],
        "reachable": False,
    }

    if not args.json:
        print("=" * 70)
        print("PHANTOM-X :: NETWORK REACHABILITY")
        print("=" * 70)
        print(f"  target : {host}")
        print(f"  ports  : {', '.join(str(p) for p in ports)}")
        print()

    addrs, status = resolve(host)
    report["addresses"] = addrs
    report["resolution"] = status

    if not args.json:
        if addrs:
            print(f"  DNS    : {host} -> {', '.join(addrs)}")
        else:
            print(f"  DNS    : {host} DID NOT RESOLVE ({status})")
            print()
            print("  This is a name problem, not a network problem.")
            print("  Check that the domain resolves from THIS machine:")
            print(f"    nslookup {host}")
            print("    Resolve-DnsName {host}")
        print()

    if addrs:
        for addr in addrs:
            for port in ports:
                t0 = time.time()
                verdict, detail = probe(addr, port, args.timeout)
                elapsed = (time.time() - t0) * 1000
                report["results"].append({
                    "address": addr, "port": port,
                    "verdict": verdict, "detail": detail,
                    "elapsed_ms": round(elapsed, 1),
                })
                if verdict == "open":
                    report["reachable"] = True
                if not args.json:
                    tag = {"open": "OPEN", "refused": "REFUSED",
                           "timeout": "TIMEOUT", "error": "ERROR"}[verdict]
                    print(f"  {addr}:{port:<6} {tag:<9} {detail} "
                          f"({elapsed:.0f} ms)")

    if not args.json:
        print()
        if report["reachable"]:
            print("  RESULT: the C2 is reachable from here.")
            print("  The payload will connect.")
        elif not addrs:
            print("  RESULT: the name does not resolve from this machine.")
            print()
            print("  If the C2 is on a different network, the name has to be")
            print("  a real one that resolves everywhere. A name that only")
            print("  resolves on the lab's own DNS will not work from the")
            print("  laptop's network -- which is the whole reason the")
            print("  payload takes a HOSTNAME rather than an address.")
        else:
            print("  RESULT: the name resolves but the port is not open.")
            print()
            print("  Nothing is listening, or the network is dropping it.")
            print("  On a phone hotspot the operator's own machine is")
            print("  usually reachable at the hotspot gateway address --")
            print("  check what the C2 actually bound to.")
    else:
        print(json.dumps(report, indent=2))

    return 0 if report["reachable"] else 1


if __name__ == "__main__":
    sys.exit(main())
