#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: Phase 5 -- the lab DNS helper for the domain generation variant
================================================================================
dga_dns.py -- A tiny authoritative DNS server for the lab segment.

WHAT IT IS FOR
    The domain generation variant produces a hostname that changes daily.
    The question the variant answers is: which of the C2 detections depend
    on a single fixed address?

    To answer it, the lab needs the generated names to actually RESOLVE,
    inside the isolated segment, without a real DNS server and without
    touching the internet.

    So this is a DNS server that answers the lab's generated names with
    the lab C2's address, and refuses everything else.

    A name that is not in the expected shape gets NXDOMAIN. That matters:
    the interesting detection signal of a DGA is the pattern of unique
    subdomains being queried, most of which resolve to nothing. A helper
    that answered everything would hide exactly the behaviour the lab is
    trying to measure.

THE ALGORITHM
    It must match px_dga.c exactly:

        seed      = days since the Unix epoch (UTC)
        hostname  = "<prefix>-<seed>-<nonce>.<tld>"

    The nonce is a compile-time constant in the payload, so the helper
    reproduces the same names without being configured with it.

WHAT IT SERVES
    Nothing outside the lab segment. It binds to the lab interface and
    answers only the lab's own names.

USAGE
    python3 dga_dns.py --host 192.168.77.1 --port 53 \
        --c2 192.168.77.1 --prefix pxlab --tld .lab.test

    Then point the VM's DNS at the lab gateway and run the DGA variant.

    The helper also has a --verify mode, which prints the name it would
    answer for today and for a given date, without binding a socket. That
    is how you check the payload and the helper agree.
"""

from __future__ import annotations

import argparse
import datetime
import os
import socket
import struct
import sys
import time

# The nonce. This MUST match PX_DGA_NONCE in px_dga.c.
DEFAULT_NONCE = 0x5A17C0DE


def days_since_epoch(dt: datetime.datetime) -> int:
    """Days since the Unix epoch for a UTC date.

    This is the same arithmetic as px_dga.c, so the two agree without
    either of them needing a time library the other lacks.
    """
    return (dt - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)).days


def dga_name(day: int, prefix: str, tld: str, nonce: int = DEFAULT_NONCE) -> str:
    """The hostname the payload generates for a given day."""
    return f"{prefix}-{day}-{nonce:08x}{tld}"


def expected_names(days_back: int, days_forward: int, prefix: str,
                   tld: str, nonce: int = DEFAULT_NONCE) -> list[str]:
    """The names a payload would generate around today."""
    today = days_since_epoch(datetime.datetime.now(datetime.timezone.utc))
    out = []
    for delta in range(-days_back, days_forward + 1):
        out.append(dga_name(today + delta, prefix, tld, nonce))
    return out


# ---------------------------------------------------------------------------
# DNS message handling
# ---------------------------------------------------------------------------

def parse_question(data: bytes) -> tuple[str, int]:
    """Extract the QNAME and QTYPE from a DNS query.

    Returns the name in presentation form (dotted, no trailing dot) and
    the query type.
    """
    if len(data) < 12:
        return "", 0
    labels = []
    i = 12
    while i < len(data):
        length = data[i]
        if length == 0:
            i += 1
            break
        if length & 0xC0:  # compression pointer: not used in a question
            break
        i += 1
        labels.append(data[i:i + length].decode("ascii", "replace"))
        i += length
    qtype = 0
    if i + 1 < len(data):
        qtype = struct.unpack("!H", data[i:i + 2])[0]
    return ".".join(labels), qtype


def build_response(query: bytes, qname: str, qtype: int, rcode: int,
                   address: str | None) -> bytes:
    """Build a DNS response.

    The question section is echoed verbatim, which is what a real server
    does and what makes the reply parseable by a normal resolver.
    """
    # Find the end of the question section.
    i = 12
    while i < len(query):
        length = query[i]
        if length == 0:
            i += 1
            break
        i += 1 + length
    question = query[12:i]
    if len(question) < 4:
        question = query[12:]

    flags = 0x8180 | (rcode & 0x0F)  # QR + AA + RD + RA

    header = struct.pack("!HHHHHH", 0, flags, 1 if rcode == 0 else 0,
                          0, 0, 0)
    if rcode != 0 or address is None:
        return header + question

    # The answer: a single A record pointing at the lab C2.
    qname_bytes = b""
    for label in qname.split("."):
        qname_bytes += bytes([len(label)]) + label.encode("ascii")
    qname_bytes += b"\x00"

    answer = b""
    answer += qname_bytes
    answer += struct.pack("!HHIH", qtype, 1, 60, 4)
    answer += socket.inet_aton(address)
    return header + question + answer


class LabDNS:
    """The lab's authoritative DNS server."""

    def __init__(self, host: str, port: int, c2: str, prefix: str, tld: str,
                 nonce: int = DEFAULT_NONCE):
        self.host = host
        self.port = port
        self.c2 = c2
        self.prefix = prefix
        self.tld = tld
        self.nonce = nonce
        self.sock: socket.socket | None = None
        self.queries = 0
        self.answered = 0
        self.nxdomain = 0

    def is_lab_name(self, qname: str) -> bool:
        """True if the name has the shape the DGA produces.

        The check is on the SHAPE, not on an exact match to today's
        seed, because a payload that has been running for a day or two
        will query yesterday's and tomorrow's names too -- and the
        interesting signal is precisely that it queries many names.
        """
        name = qname.lower()
        if not name.endswith(self.tld.lower()):
            return False
        label = name[: -len(self.tld)]
        parts = label.split("-")
        if len(parts) != 3:
            return False
        prefix, day, nonce = parts
        if prefix != self.prefix.lower():
            return False
        try:
            int(day)
            int(nonce, 16)
        except ValueError:
            return False
        return True

    def serve(self, duration: int = 0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.settimeout(1.0)
        print(f"[+] lab DNS on {self.host}:{self.port}")
        print(f"    c2    : {self.c2}")
        print(f"    shape : {self.prefix}-<day>-<nonce>{self.tld}")
        print(f"    today : {dga_name(days_since_epoch(datetime.datetime.now(datetime.timezone.utc)), self.prefix, self.tld, self.nonce)}")
        print()

        deadline = time.time() + duration if duration else None
        try:
            while deadline is None or time.time() < deadline:
                try:
                    data, addr = self.sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break

                self.queries += 1
                qname, qtype = parse_question(data)
                if self.is_lab_name(qname):
                    self.answered += 1
                    reply = build_response(data, qname, qtype, 0, self.c2)
                    print(f"    ANSWER {qname} -> {self.c2}")
                else:
                    self.nxdomain += 1
                    reply = build_response(data, qname, qtype, 3, None)
                    print(f"    NXDOMAIN {qname}")
                try:
                    self.sock.sendto(reply, addr)
                except OSError:
                    pass
        finally:
            if self.sock:
                self.sock.close()
            print(f"\n[+] stopped. queries={self.queries} "
                  f"answered={self.answered} nxdomain={self.nxdomain}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Lab DNS helper for the PHANTOM-X domain generation variant")
    ap.add_argument("--host", default="0.0.0.0", help="bind address")
    ap.add_argument("--port", type=int, default=53, help="bind port")
    ap.add_argument("--c2", default="127.0.0.1",
                    help="the address the lab C2 is reachable at")
    ap.add_argument("--prefix", default="pxlab", help="the DGA label prefix")
    ap.add_argument("--tld", default=".lab.test", help="the DGA top-level domain")
    ap.add_argument("--nonce", type=lambda s: int(s, 0),
                    default=DEFAULT_NONCE,
                    help="the DGA nonce (must match the payload)")
    ap.add_argument("--duration", type=int, default=0,
                    help="stop after N seconds (0 = run forever)")
    ap.add_argument("--verify", action="store_true",
                    help="print the names the payload would use and exit")
    args = ap.parse_args(argv)

    if args.verify:
        today = datetime.datetime.now(datetime.timezone.utc)
        print("the payload would generate:")
        for name in expected_names(2, 2, args.prefix, args.tld, args.nonce):
            print(f"    {name}")
        print()
        print(f"today's seed : {days_since_epoch(today)}")
        return 0

    srv = LabDNS(args.host, args.port, args.c2, args.prefix, args.tld,
                 args.nonce)
    srv.serve(args.duration)
    return 0


if __name__ == "__main__":
    sys.exit(main())
