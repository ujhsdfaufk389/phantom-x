#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: Phase 1 / Experiment 1
================================================================================
pdf_inspector.py -- PDF structural parser and document-action risk analyzer.

PURPOSE
    Static, read-only analysis of PDF container structure. Identifies document
    features that are relevant to the Phase 1 attack-surface questions:
    embedded files, JavaScript, launch actions, external references, form
    actions, and active-content annotations. Reports what a reader *could* be
    asked to do, and what a defender *should* be able to see.

DESIGN CONSTRAINTS
    * Read-only. This tool never executes, renders, or transmits anything.
    * Dependency-free (Python 3.9+ stdlib only). A self-contained parser is
      used deliberately so that parsing behaviour is auditable and cannot be
      confused with the behaviour of a third-party library under test.
    * No exploitation. No fuzzing of the reader. No shellcode. This tool only
      reports on structure.

SCOPE / LIMITATIONS (stated explicitly so results are not over-read)
    * Static analysis only. A finding means "the document contains the
      structure". It does NOT mean "the reader will execute it". Reader policy,
      sandboxing, and user confirmation are decisive and are Phase 1
      Experiment 2+ subjects, not this tool's subject.
    * Encrypted documents are detected and reported, but the encrypted body is
      not decrypted (no key is known or solicited).
    * This tool will not detect a vulnerability in a parser. It inventories
      features. Parser vulnerability research is a separate, separately-scoped
      activity.

USAGE
    python3 pdf_inspector.py <file.pdf> [...]                 # console report
    python3 pdf_inspector.py <file.pdf> --json report.json    # + JSON report
    python3 pdf_inspector.py <file.pdf> --extract-dir ./quarantine
    python3 pdf_inspector.py <dir/                           # recursive
    python3 pdf_inspector.py <file.pdf> --baseline clean.pdf   # diff mode

EXIT CODES
    0 = analysis completed (regardless of risk score)
    2 = usage / IO error
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import math
import os
import re
import sys
import zlib
from collections import Counter, defaultdict
from datetime import datetime, timezone

# =============================================================================
# SECTION 0 -- Primitive PDF object types
# =============================================================================

WHITESPACE = b"\x00\t\n\x0c\r "
DELIMITERS = b"()<>[]{}/%"


class Name(str):
    """A PDF name object, e.g. /Type. Distinguished from a string literal."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "/" + str.__str__(self)


class Ref:
    """An indirect reference, e.g. '12 0 R'."""

    __slots__ = ("num", "gen")

    def __init__(self, num: int, gen: int = 0):
        self.num = int(num)
        self.gen = int(gen)

    def __repr__(self) -> str:
        return f"{self.num} {self.gen} R"

    def __eq__(self, other) -> bool:
        return isinstance(other, Ref) and (self.num, self.gen) == (other.num, other.gen)

    def __hash__(self) -> int:
        return hash((self.num, self.gen))


class Stream:
    """A stream object: a dictionary plus raw (still encoded) bytes."""

    __slots__ = ("dict", "raw", "_decoded")

    def __init__(self, d: dict, raw: bytes):
        self.dict = d
        self.raw = raw
        self._decoded = None

    def __repr__(self) -> str:
        return f"<Stream {len(self.raw)} bytes /Type={self.dict.get('Type')}>"


class PDFError(Exception):
    pass


# =============================================================================
# SECTION 1 -- Lexer / recursive-descent object parser
# =============================================================================

_ESCAPES = {
    ord("n"): 0x0A, ord("r"): 0x0D, ord("t"): 0x09, ord("b"): 0x08,
    ord("f"): 0x0C, ord("("): 0x28, ord(")"): 0x29, ord("\\"): 0x5C,
}


class Parser:
    """Minimal PDF object parser over a bytes buffer."""

    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    # -- low level -----------------------------------------------------------
    def skip_ws(self) -> None:
        data, n = self.data, len(self.data)
        while self.pos < n:
            c = data[self.pos]
            if c in WHITESPACE:
                self.pos += 1
            elif c == 0x25:  # '%' comment
                while self.pos < n and data[self.pos] not in b"\r\n":
                    self.pos += 1
            else:
                break

    def eof(self) -> bool:
        self.skip_ws()
        return self.pos >= len(self.data)

    # -- object dispatch -----------------------------------------------------
    def parse_object(self):
        self.skip_ws()
        data, n = self.data, len(self.data)
        if self.pos >= n:
            raise PDFError("unexpected EOF")
        c = data[self.pos]

        if c == 0x2F:  # '/'
            return self.parse_name()
        if c == 0x28:  # '('
            return self.parse_literal_string()
        if c == 0x3C:  # '<'
            if data[self.pos:self.pos + 2] == b"<<":
                return self.parse_dict()
            return self.parse_hex_string()
        if c == 0x5B:  # '['
            return self.parse_array()
        if c in b"+-.0123456789":
            return self.parse_number_or_ref()
        if data[self.pos:self.pos + 4] == b"true":
            self.pos += 4
            return True
        if data[self.pos:self.pos + 5] == b"false":
            self.pos += 5
            return False
        if data[self.pos:self.pos + 4] == b"null":
            self.pos += 4
            return None
        raise PDFError(f"unparseable token at offset {self.pos} (byte {c:#04x})")

    # -- individual types ----------------------------------------------------
    def parse_name(self) -> Name:
        self.pos += 1
        out = bytearray()
        data, n = self.data, len(self.data)
        while self.pos < n:
            c = data[self.pos]
            if c in WHITESPACE or c in DELIMITERS:
                break
            if c == 0x23 and self.pos + 2 < n:  # '#' hex escape
                try:
                    out.append(int(data[self.pos + 1:self.pos + 3], 16))
                    self.pos += 3
                    continue
                except ValueError:
                    pass
            out.append(c)
            self.pos += 1
        return Name(out.decode("latin-1"))

    def parse_literal_string(self) -> bytes:
        self.pos += 1
        out = bytearray()
        depth = 1
        data, n = self.data, len(self.data)
        while self.pos < n:
            c = data[self.pos]
            if c == 0x5C:  # backslash
                self.pos += 1
                if self.pos >= n:
                    break
                e = data[self.pos]
                if e in _ESCAPES:
                    out.append(_ESCAPES[e])
                    self.pos += 1
                elif e in b"\r\n":
                    if e == 0x0D and data[self.pos + 1:self.pos + 2] == b"\n":
                        self.pos += 1
                    self.pos += 1
                elif 0x30 <= e <= 0x37:  # octal
                    digits = ""
                    for _ in range(3):
                        if self.pos < n and 0x30 <= data[self.pos] <= 0x37:
                            digits += chr(data[self.pos])
                            self.pos += 1
                        else:
                            break
                    out.append(int(digits, 8) & 0xFF)
                else:
                    out.append(e)
                    self.pos += 1
            elif c == 0x28:
                depth += 1
                out.append(c)
                self.pos += 1
            elif c == 0x29:
                depth -= 1
                self.pos += 1
                if depth == 0:
                    break
                out.append(c)
            else:
                out.append(c)
                self.pos += 1
        return bytes(out)

    def parse_hex_string(self) -> bytes:
        self.pos += 1
        end = self.data.find(b">", self.pos)
        if end == -1:
            end = len(self.data)
        hx = re.sub(rb"\s", b"", self.data[self.pos:end])
        self.pos = end + 1
        if len(hx) % 2:
            hx += b"0"
        try:
            return bytes.fromhex(hx.decode("ascii"))
        except ValueError:
            return b""

    def parse_number_or_ref(self):
        data, n = self.data, len(self.data)
        start = self.pos
        while self.pos < n and data[self.pos] in b"+-.0123456789":
            self.pos += 1
        tok = data[start:self.pos]
        # Lookahead for '<int> <int> R'
        save = self.pos
        try:
            v = float(tok) if any(ch in tok for ch in b".eE") else int(tok)
        except ValueError:
            raise PDFError(f"bad number {tok!r}")
        if isinstance(v, int):
            p2 = Parser(self.data, self.pos)
            p2.skip_ws()
            s2 = p2.pos
            while p2.pos < n and data[p2.pos] in b"0123456789":
                p2.pos += 1
            if p2.pos > s2:
                gen = int(data[s2:p2.pos])
                p3 = Parser(self.data, p2.pos)
                p3.skip_ws()
                if self.data[p3.pos:p3.pos + 1] == b"R" and (
                    p3.pos + 1 >= n or self.data[p3.pos + 1] in WHITESPACE or
                    self.data[p3.pos + 1] in DELIMITERS
                ):
                    self.pos = p3.pos + 1
                    return Ref(v, gen)
        self.pos = save
        return v

    def parse_array(self) -> list:
        self.pos += 1
        arr = []
        while True:
            self.skip_ws()
            if self.pos >= len(self.data):
                break
            if self.data[self.pos] == 0x5D:  # ']'
                self.pos += 1
                break
            if self.data[self.pos:self.pos + 6] == b"endobj":
                break
            try:
                arr.append(self.parse_object())
            except PDFError:
                break
        return arr

    def parse_dict(self) -> dict:
        self.pos += 2
        d: dict = {}
        while True:
            self.skip_ws()
            if self.pos >= len(self.data):
                break
            if self.data[self.pos:self.pos + 2] == b">>":
                self.pos += 2
                break
            if self.data[self.pos:self.pos + 6] == b"endobj":
                break
            if self.data[self.pos] != 0x2F:
                # Junk key: skip a token to stay in sync
                try:
                    self.parse_object()
                except PDFError:
                    self.pos += 1
                continue
            key = self.parse_name()
            try:
                val = self.parse_object()
            except PDFError:
                val = None
            d[str(key)] = val
        return d

    # -- streams -------------------------------------------------------------
    def maybe_stream(self, d: dict):
        """If the dict is followed by a 'stream' keyword, extract it."""
        save = self.pos
        self.skip_ws()
        if self.data[self.pos:self.pos + 6] != b"stream":
            self.pos = save
            return None
        self.pos += 6
        if self.data[self.pos:self.pos + 2] == b"\r\n":
            self.pos += 2
        elif self.data[self.pos:self.pos + 1] in (b"\n", b"\r"):
            self.pos += 1

        length = d.get("Length")
        raw = None
        if isinstance(length, int) and length >= 0 and self.pos + length <= len(self.data):
            raw = self.data[self.pos:self.pos + length]
            tail = self.data[self.pos + length:self.pos + length + 32]
            if b"endstream" not in tail:
                raw = None  # Length is wrong -> fall through to search
            else:
                self.pos += length
        if raw is None:
            end = self.data.find(b"endstream", self.pos)
            if end == -1:
                self.pos = save
                return None
            raw = self.data[self.pos:end]
            if raw.endswith(b"\r\n"):
                raw = raw[:-2]
            elif raw.endswith(b"\n") or raw.endswith(b"\r"):
                raw = raw[:-1]
        e = self.data.find(b"endstream", self.pos)
        if e != -1:
            self.pos = e + 9
        return Stream(d, raw)


# =============================================================================
# SECTION 2 -- Stream filters
# =============================================================================

def _ascii85_decode(data: bytes) -> bytes:
    data = re.sub(rb"\s", b"", data)
    if data.startswith(b"<~"):
        data = data[2:]
    idx = data.find(b"~>")
    if idx != -1:
        data = data[:idx]
    out = bytearray()
    group = []
    for ch in data:
        if ch == 0x7A and not group:  # 'z'
            out.extend(b"\x00\x00\x00\x00")
            continue
        if 0x21 <= ch <= 0x75:
            group.append(ch - 0x21)
            if len(group) == 5:
                v = 0
                for g in group:
                    v = v * 85 + g
                out.extend(v.to_bytes(4, "big"))
                group = []
    if group:
        n = len(group)
        group += [84] * (5 - n)
        v = 0
        for g in group:
            v = v * 85 + g
        out.extend(v.to_bytes(4, "big")[: n - 1])
    return bytes(out)


def _asciihex_decode(data: bytes) -> bytes:
    idx = data.find(b">")
    if idx != -1:
        data = data[:idx]
    hx = re.sub(rb"\s", b"", data)
    if len(hx) % 2:
        hx += b"0"
    try:
        return bytes.fromhex(hx.decode("ascii"))
    except ValueError:
        return b""


def _runlength_decode(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        l = data[i]
        i += 1
        if l == 128:
            break
        if l < 128:
            out.extend(data[i:i + l + 1])
            i += l + 1
        else:
            if i < len(data):
                out.extend(bytes([data[i]]) * (257 - l))
                i += 1
    return bytes(out)


def _lzw_decode(data: bytes, early: int = 1) -> bytes:
    out = bytearray()
    table = [bytes([i]) for i in range(256)] + [b"", b""]
    bitpos = 0
    codewidth = 9
    prev = None
    total_bits = len(data) * 8
    while bitpos + codewidth <= total_bits:
        byte_i = bitpos >> 3
        chunk = data[byte_i:byte_i + 3]
        if len(chunk) < 3:
            chunk = chunk + b"\x00" * (3 - len(chunk))
        val = int.from_bytes(chunk, "big")
        code = (val >> (24 - (bitpos & 7) - codewidth)) & ((1 << codewidth) - 1)
        bitpos += codewidth
        if code == 256:
            table = [bytes([i]) for i in range(256)] + [b"", b""]
            codewidth = 9
            prev = None
            continue
        if code == 257:
            break
        if prev is None:
            entry = table[code]
        elif code < len(table):
            entry = table[code]
            table.append(prev + entry[:1])
        else:
            entry = prev + prev[:1]
            table.append(entry)
        out.extend(entry)
        prev = entry
        if len(table) + early >= (1 << codewidth) and codewidth < 12:
            codewidth += 1
    return bytes(out)


def _apply_png_predictor(data: bytes, colors: int, bpc: int, columns: int) -> bytes:
    bpp = max(1, (colors * bpc + 7) // 8)
    rowlen = (columns * colors * bpc + 7) // 8
    out = bytearray()
    prev = bytearray(rowlen)
    i = 0
    while i < len(data):
        ft = data[i]
        i += 1
        row = bytearray(data[i:i + rowlen])
        i += rowlen
        if len(row) < rowlen:
            row.extend(b"\x00" * (rowlen - len(row)))
        if ft == 1:
            for j in range(bpp, rowlen):
                row[j] = (row[j] + row[j - bpp]) & 0xFF
        elif ft == 2:
            for j in range(rowlen):
                row[j] = (row[j] + prev[j]) & 0xFF
        elif ft == 3:
            for j in range(rowlen):
                left = row[j - bpp] if j >= bpp else 0
                row[j] = (row[j] + ((left + prev[j]) >> 1)) & 0xFF
        elif ft == 4:
            for j in range(rowlen):
                a = row[j - bpp] if j >= bpp else 0
                b = prev[j]
                c = prev[j - bpp] if j >= bpp else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                row[j] = (row[j] + pr) & 0xFF
        out.extend(row)
        prev = row
    return bytes(out)


def decode_stream(stream: Stream, resolve_len=None) -> bytes:
    """Decode a stream through its filter chain. Returns raw bytes on failure."""
    d = stream.dict
    filters = d.get("Filter")
    if filters is None:
        return stream.raw
    if isinstance(filters, (Name, str)):
        filters = [filters]
    if not isinstance(filters, list):
        return stream.raw

    parms = d.get("DecodeParms") or d.get("DP")
    if not isinstance(parms, list):
        parms = [parms] * len(filters)

    data = stream.raw
    for idx, f in enumerate(filters):
        f = str(f)
        p = parms[idx] if idx < len(parms) else None
        if not isinstance(p, dict):
            p = {}
        try:
            if f in ("FlateDecode", "Fl"):
                try:
                    data = zlib.decompress(data)
                except zlib.error:
                    d2 = zlib.decompressobj()
                    try:
                        data = d2.decompress(data)
                    except zlib.error:
                        try:
                            data = zlib.decompressobj(-15).decompress(data[2:])
                        except zlib.error:
                            return data
                pred = int(p.get("Predictor", 1) or 1)
                if pred >= 10:
                    data = _apply_png_predictor(
                        data,
                        int(p.get("Colors", 1) or 1),
                        int(p.get("BitsPerComponent", 8) or 8),
                        int(p.get("Columns", 1) or 1),
                    )
            elif f in ("LZWDecode", "LZW"):
                early = 1
                if isinstance(p, dict):
                    early = int(p.get("EarlyChange", 1) or 0)
                data = _lzw_decode(data, early)
                pred = int(p.get("Predictor", 1) or 1)
                if pred >= 10:
                    data = _apply_png_predictor(
                        data, int(p.get("Colors", 1) or 1),
                        int(p.get("BitsPerComponent", 8) or 8),
                        int(p.get("Columns", 1) or 1))
            elif f in ("ASCIIHexDecode", "AHx"):
                data = _asciihex_decode(data)
            elif f in ("ASCII85Decode", "A85"):
                data = _ascii85_decode(data)
            elif f in ("RunLengthDecode", "RL"):
                data = _runlength_decode(data)
            elif f in ("DCTDecode", "JPXDecode", "CCITTFaxDecode", "JBIG2Decode"):
                return data  # image codecs -- leave encoded
            else:
                return data  # unknown filter (e.g. Crypt) -- leave encoded
        except Exception:
            return data
    return data


# =============================================================================
# SECTION 3 -- Document model
# =============================================================================

OBJ_RE = re.compile(rb"(?<![0-9])(\d{1,10})\s+(\d{1,5})\s+obj\b")


class PDFDocument:
    """Loads a PDF and exposes a resolved-enough object graph for analysis."""

    def __init__(self, path: str, password: str = ""):
        self.path = path
        self.password = password
        with open(path, "rb") as fh:
            self.data = fh.read()
        self.objects: dict[int, tuple] = {}   # num -> (offset, value, gen)
        self.trailer: dict = {}
        self.catalog: dict = {}
        self.xref_type = "unknown"
        self.warnings: list[str] = []

    # -- loading -------------------------------------------------------------
    def load(self) -> "PDFDocument":
        self._scan_objects()
        self._parse_xref()
        self._expand_object_streams()
        self._locate_catalog()
        return self

    def _scan_objects(self) -> None:
        """Brute-force object scan. Robust against damaged/odd xref tables.

        For incremental updates the highest file offset wins, which matches
        the PDF spec's rule that later revisions supersede earlier ones.
        """
        search_from = 0
        for m in OBJ_RE.finditer(self.data):
            if m.start() < search_from:
                continue
            num = int(m.group(1))
            gen = int(m.group(2))
            offset = m.start()
            p = Parser(self.data, m.end())
            try:
                val = p.parse_object()
            except PDFError:
                continue
            if isinstance(val, dict):
                st = p.maybe_stream(val)
                if st is not None:
                    val = st
            end = self.data.find(b"endobj", p.pos)
            if end == -1 or end - m.end() > 2_000_000:
                continue
            # Reject if another object header appears before this endobj.
            nxt = OBJ_RE.search(self.data, m.end(), end)
            if nxt is not None:
                continue
            search_from = end + 6
            prev = self.objects.get(num)
            if prev is None or prev[0] <= offset:
                self.objects[num] = (offset, val, gen)

    def _parse_xref(self) -> None:
        """Parse the xref chain for trailer metadata (Root/Encrypt/ID)."""
        idx = self.data.rfind(b"startxref")
        if idx == -1:
            self.warnings.append("no startxref found; using brute-force object scan only")
            self.xref_type = "bruteforce"
            return
        m = re.match(rb"startxref\s+(\d+)", self.data[idx:])
        if not m:
            self.warnings.append("malformed startxref")
            self.xref_type = "bruteforce"
            return
        offset = int(m.group(1))
        seen = set()
        self.xref_type = "chain"
        while offset is not None and offset not in seen and 0 <= offset < len(self.data):
            seen.add(offset)
            offset = self._parse_xref_section(offset)

    def _parse_xref_section(self, offset: int):
        p = Parser(self.data, offset)
        p.skip_ws()
        if self.data[p.pos:p.pos + 4] == b"xref":
            self.xref_type = "table" if self.xref_type == "chain" else self.xref_type
            p.pos += 4
            # skip any subsection headers until 'trailer'
            while True:
                p.skip_ws()
                if self.data[p.pos:p.pos + 7] == b"trailer":
                    p.pos += 7
                    try:
                        tr = p.parse_object()
                    except PDFError:
                        tr = {}
                    if isinstance(tr, dict):
                        for k, v in tr.items():
                            self.trailer.setdefault(k, v)
                        prev = tr.get("Prev")
                        return int(prev) if isinstance(prev, (int, float)) else None
                    return None
                if not re.match(rb"\d+", self.data[p.pos:p.pos + 12]):
                    return None
                # subsection: 'start count' then entries
                sm = re.match(rb"(\d+)\s+(\d+)", self.data[p.pos:])
                if not sm:
                    return None
                p.pos += sm.end()
                for _ in range(int(sm.group(2))):
                    p.skip_ws()
                    em = re.match(rb"(\d{1,10})\s+(\d{1,5})\s+([nf])", self.data[p.pos:])
                    if not em:
                        break
                    p.pos += em.end()
        else:
            # Could be an XRef stream: object 'N G obj'
            om = OBJ_RE.match(self.data, p.pos)
            if not om:
                return None
            num = int(om.group(1))
            self.xref_type = "stream" if self.xref_type == "chain" else self.xref_type
            pp = Parser(self.data, om.end())
            try:
                val = pp.parse_object()
            except PDFError:
                return None
            st = pp.maybe_stream(val) if isinstance(val, dict) else None
            if st is None:
                return None
            self._parse_xref_stream(st)
            prev = st.dict.get("Prev")
            return int(prev) if isinstance(prev, (int, float)) else None
        return None

    def _parse_xref_stream(self, st: Stream) -> None:
        d = st.dict
        for k in ("Root", "Encrypt", "Info", "ID"):
            if k in d:
                self.trailer.setdefault(k, d[k])
        w = d.get("W")
        if not isinstance(w, list) or not all(isinstance(x, int) for x in w):
            return
        size = d.get("Size", 0)
        index = d.get("Index")
        if not isinstance(index, list) or len(index) % 2:
            index = [0, int(size or 0)]
        data = decode_stream(st)
        widths = [int(x) for x in w]
        entry_len = sum(widths)
        if entry_len <= 0:
            return
        pos = 0
        for i in range(0, len(index), 2):
            start = int(index[i])
            count = int(index[i + 1])
            for j in range(count):
                if pos + entry_len > len(data):
                    return
                fields = []
                for width in widths:
                    if width == 0:
                        fields.append(None)
                    else:
                        fields.append(int.from_bytes(data[pos:pos + width], "big"))
                        pos += width
                objnum = start + j
                if objnum in self.objects:
                    continue
                ftype = fields[0] if fields[0] is not None else 1
                f2 = fields[1] if len(fields) > 1 else None
                f3 = fields[2] if len(fields) > 2 else None
                if ftype == 1 and f2 is not None and f3 is not None:
                    off = f2
                    if 0 <= off < len(self.data):
                        om = OBJ_RE.match(self.data, off)
                        if om:
                            pp = Parser(self.data, om.end())
                            try:
                                val = pp.parse_object()
                            except PDFError:
                                continue
                            if isinstance(val, dict):
                                s2 = pp.maybe_stream(val)
                                if s2 is not None:
                                    val = s2
                            self.objects.setdefault(objnum, (off, val, 0))
                elif ftype == 2 and f2 is not None:
                    # object stream: (objstm_num, index)
                    pass

    def _expand_object_streams(self) -> None:
        """Unpack compressed object streams (/Type /ObjStm)."""
        for num in list(self.objects.keys()):
            entry = self.objects[num]
            val = entry[1]
            if not isinstance(val, Stream):
                continue
            d = val.dict
            if str(d.get("Type", "")) != "ObjStm":
                continue
            try:
                n = int(d.get("N", 0) or 0)
                first = int(d.get("First", 0) or 0)
            except (TypeError, ValueError):
                continue
            data = decode_stream(val)
            header = data[:first]
            pairs = []
            for m in re.finditer(rb"(\d+)\s+(\d+)", header):
                pairs.append((int(m.group(1)), int(m.group(2))))
            if len(pairs) > n:
                pairs = pairs[:n]
            for objnum, off in pairs:
                if objnum in self.objects:
                    continue  # a direct definition supersedes the packed one
                start = first + off
                if start >= len(data):
                    continue
                pp = Parser(data, start)
                try:
                    ov = pp.parse_object()
                except PDFError:
                    continue
                self.objects[objnum] = (entry[0], ov, 0)

    def _locate_catalog(self) -> None:
        root = self.trailer.get("Root")
        if isinstance(root, Ref):
            cat = self.resolve(root)
            if isinstance(cat, dict):
                self.catalog = cat
                return
        # Fallback: scan for /Type /Catalog
        for num, (_, val, _) in self.objects.items():
            if isinstance(val, dict) and str(val.get("Type", "")) == "Catalog":
                self.catalog = val
                self.warnings.append(f"catalog located by scan (object {num})")
                return
        self.warnings.append("catalog not found")

    # -- access --------------------------------------------------------------
    def resolve(self, obj, depth: int = 0):
        if isinstance(obj, Ref) and depth < 32:
            entry = self.objects.get(obj.num)
            if entry is None:
                return None
            return self.resolve(entry[1], depth + 1)
        return obj

    def get(self, d: dict, key: str, depth: int = 0):
        if not isinstance(d, dict):
            return None
        v = self.resolve(d.get(key), depth)
        return v

    def dget(self, d: dict, key: str, depth: int = 0):
        """Resolve and require a dict."""
        v = self.get(d, key, depth)
        return v if isinstance(v, dict) else None

    def stream_of(self, obj):
        v = self.resolve(obj)
        return v if isinstance(v, Stream) else None

    @property
    def is_encrypted(self) -> bool:
        return "Encrypt" in self.trailer

    @property
    def pdf_version(self) -> str:
        m = re.match(rb"%PDF-(\d+\.\d+)", self.data[:16])
        return m.group(1).decode() if m else "unknown"

    def page_count(self) -> int:
        pages = self.dget(self.catalog, "Pages")
        if not pages:
            return 0
        count = pages.get("Count")
        if isinstance(count, int):
            return count
        kids = pages.get("Kids")
        if isinstance(kids, list):
            return len(kids)
        return 0

    def iter_pages(self):
        """Yield page dictionaries (bounded recursion)."""
        pages = self.dget(self.catalog, "Pages")
        if not pages:
            return
        stack = [(pages, 0)]
        seen = set()
        while stack:
            node, depth = stack.pop()
            if not isinstance(node, dict) or depth > 32:
                continue
            key = id(node)
            if key in seen:
                continue
            seen.add(key)
            t = str(node.get("Type", ""))
            if t == "Page" or ("Kids" not in node and "Contents" in node):
                yield node
            else:
                kids = node.get("Kids")
                if isinstance(kids, list):
                    for k in reversed(kids):
                        r = self.resolve(k)
                        if isinstance(r, dict):
                            stack.append((r, depth + 1))


# =============================================================================
# SECTION 4 -- Analysis engine
# =============================================================================

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Action subtypes and what they imply for the reader.
ACTION_SEMANTICS = {
    "Launch": {
        "title": "Launch action",
        "note": "Instructs the reader to launch an external application or file.",
        "severity": "high",
        "interactive": True,
    },
    "URI": {
        "title": "URI action",
        "note": "Instructs the reader to open a network resource (browser/handler).",
        "severity": "medium",
        "interactive": True,
    },
    "JavaScript": {
        "title": "JavaScript action",
        "note": "Executes script in the reader's scripting engine.",
        "severity": "high",
        "interactive": False,
    },
    "GoToR": {
        "title": "Remote GoTo action",
        "note": "Opens a different PDF file; may reference a local or remote path.",
        "severity": "medium",
        "interactive": True,
    },
    "GoToE": {
        "title": "Embedded GoTo action",
        "note": "Navigates to a target inside an embedded file specification.",
        "severity": "medium",
        "interactive": True,
    },
    "SubmitForm": {
        "title": "Submit form action",
        "note": "Sends form data to a URL.",
        "severity": "high",
        "interactive": True,
    },
    "ImportData": {
        "title": "Import data action",
        "note": "Imports FDF data into the document form.",
        "severity": "medium",
        "interactive": True,
    },
    "Movie": {
        "title": "Movie action",
        "note": "Plays an embedded or referenced movie.",
        "severity": "medium",
        "interactive": True,
    },
    "Sound": {
        "title": "Sound action",
        "note": "Plays an embedded or referenced sound.",
        "severity": "low",
        "interactive": True,
    },
    "Rendition": {
        "title": "Rendition action",
        "note": "Plays a multimedia rendition.",
        "severity": "medium",
        "interactive": True,
    },
    "GoTo3DView": {
        "title": "3D view action",
        "note": "Activates an embedded 3D view.",
        "severity": "medium",
        "interactive": True,
    },
    "Hide": {
        "title": "Hide action",
        "note": "Toggles visibility of annotations.",
        "severity": "low",
        "interactive": False,
    },
    "Named": {
        "title": "Named action",
        "note": "Invokes a reader-defined named action.",
        "severity": "low",
        "interactive": False,
    },
    "ResetForm": {
        "title": "Reset form action",
        "note": "Resets form fields.",
        "severity": "info",
        "interactive": False,
    },
}

# File types that indicate a genuine execution-chain payload.
PAYLOAD_SIGNATURES = [
    (b"MZ", "PE/DOS executable"),
    (b"\x7fELF", "ELF executable"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"\xd0\xcf\x11\xe0", "OLE2 compound document"),
    (b"#!", "script (shebang)"),
    (b"%PDF-", "PDF document"),
    (b"MSCF", "CAB archive"),
    (b"Rar!", "RAR archive"),
    (b"\x1f\x8b", "gzip stream"),
    (b"BM", "BMP image"),
    (b"\x89PNG", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
]

# Text markers of interest inside decoded content. Purely observational.
SUSPICIOUS_TEXT_MARKERS = [
    (rb"powershell", "PowerShell reference"),
    (rb"cmd\.exe", "cmd.exe reference"),
    (rb"wscript\.exe", "WScript reference"),
    (rb"cscript\.exe", "CScript reference"),
    (rb"rundll32", "rundll32 reference"),
    (rb"regsvr32", "regsvr32 reference"),
    (rb"mshta", "mshta reference"),
    (rb"certutil", "certutil reference"),
    (rb"bitsadmin", "bitsadmin reference"),
    (rb"Invoke-Expression", "PowerShell Invoke-Expression"),
    (rb"DownloadString", "PowerShell DownloadString"),
    (rb"FromBase64String", "PowerShell FromBase64String"),
    (rb"http://", "cleartext HTTP URL"),
    (rb"https://", "HTTPS URL"),
    (rb"ActiveXObject", "ActiveX instantiation"),
    (rb"WScript\.Shell", "WScript.Shell instantiation"),
    (rb"\.exe", "executable extension reference"),
]


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def is_real_pe(data: bytes) -> bool:
    """True only if `data` is a genuine PE image.

    The DOS header starts with 'MZ', but so does any file that merely wants
    to look like one. A real PE carries the 'PE\\0\\0' signature at the
    offset stored in the DWORD at 0x3C. Checking that signature is the
    difference between identifying an executable and being fooled by a
    two-byte prefix.
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    if 0 <= e_lfanew <= len(data) - 4:
        return data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"
    return False


def is_texty(data: bytes, threshold: float = 0.90) -> bool:
    """True if the payload is overwhelmingly printable text."""
    if not data:
        return False
    sample = data[:8192]
    printable = sum(1 for b in sample
                    if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D, 0x00))
    return (printable / len(sample)) >= threshold


def identify_bytes(data: bytes) -> str:
    """Describe embedded content by content, not by claim.

    A payload that merely STARTS with 'MZ' is not necessarily a PE image.
    Calling an inert text file a "PE/DOS executable" would mislead a
    defender, so the PE signature is verified and text-ness is measured.
    """
    if data.startswith(b"MZ"):
        if is_real_pe(data):
            return "PE/DOS executable"
        if is_texty(data):
            return "MZ-prefixed plain text (NOT a PE image)"
        return "MZ-prefixed binary (no PE signature -- malformed or truncated)"
    if data.startswith(b"\x7fELF"):
        return "ELF executable"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP archive"
    if data.startswith(b"\xd0\xcf\x11\xe0"):
        return "OLE2 compound document"
    if data.startswith(b"#!"):
        return "script (shebang)"
    if data.startswith(b"%PDF-"):
        return "PDF document"
    if data.startswith(b"MSCF"):
        return "CAB archive"
    if data.startswith(b"Rar!"):
        return "RAR archive"
    if data.startswith(b"\x1f\x8b"):
        return "gzip stream"
    if data.startswith(b"BM"):
        return "BMP image"
    if data.startswith(b"\x89PNG"):
        return "PNG image"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG image"
    if data.startswith(b"GIF8"):
        return "GIF image"
    if len(data) >= 2 and data[:2] == b"PK":
        return "ZIP-like archive"
    if is_texty(data):
        return "plain text"
    return "unrecognised"


class Analyzer:
    """Runs the Phase 1 feature inventory over a PDFDocument."""

    def __init__(self, doc: PDFDocument, extract_dir: str | None = None):
        self.doc = doc
        self.extract_dir = extract_dir
        self.findings: list[dict] = []
        self.embedded_files: list[dict] = []
        self.actions: list[dict] = []
        self.javascript: list[dict] = []
        self.external_refs: list[dict] = []
        self.annotations: list[dict] = []
        self.form_fields: list[dict] = []
        self.strings_of_interest: list[dict] = []
        self.name_trees: dict = {}
        self.streams_seen = 0
        self.decoded_streams = 0
        self._seen_obj = set()
        self._registered_streams: set[int] = set()
        self._recorded_js_objnums: set[int] = set()

    # -- helpers -------------------------------------------------------------
    def add_finding(self, fid, category, severity, title, location, detail,
                    evidence=None, iocs=None):
        self.findings.append({
            "id": fid,
            "category": category,
            "severity": severity,
            "title": title,
            "location": location,
            "detail": detail,
            "evidence": evidence if evidence is not None else {},
            "iocs": iocs or {},
        })

    def _objnum(self, obj):
        return obj.num if isinstance(obj, Ref) else None

    def _dict_objnum(self, val):
        """Find the object number of a dictionary by identity.

        Needed because callers often hand us an already-dereferenced dict,
        which loses the 'N G R' reference and would otherwise dedupe
        incorrectly.
        """
        for num, (_, v, _) in self.doc.objects.items():
            if v is val:
                return num
        return None

    def _loc(self, obj, prefix="obj"):
        n = self._objnum(obj)
        return f"{prefix} {n}" if n is not None else prefix

    # -- main entry ----------------------------------------------------------
    def analyze(self) -> dict:
        d = self.doc
        sha256 = hashlib.sha256(d.data).hexdigest()
        md5 = hashlib.md5(d.data).hexdigest()

        self.add_finding(
            "PX1-000", "metadata", "info", "Document identity",
            "file",
            "Hashes and container metadata for the analysed file.",
            {"path": os.path.abspath(d.path),
             "size_bytes": len(d.data),
             "sha256": sha256, "md5": md5,
             "pdf_version": d.pdf_version,
             "encrypted": d.is_encrypted,
             "page_count": d.page_count(),
             "object_count": len(d.objects),
             "xref_type": d.xref_type},
            {"sha256": sha256, "md5": md5})

        if d.is_encrypted:
            self.add_finding(
                "PX1-001", "encryption", "medium", "Encrypted document",
                "trailer",
                "Document declares /Encrypt. Body structures may be opaque to "
                "static analysis; a reader with a valid credential will see "
                "different content than this tool.",
                {"encrypt_ref": repr(d.trailer.get('Encrypt'))})

        self._analyze_catalog()
        self._analyze_name_trees()
        self._analyze_pages()
        self._analyze_forms()
        self._scan_all_objects_for_actions()
        self._scan_content_streams()
        self._scan_streams_for_embedded_files()
        self._inventory_name_trees()
        self._collect_external_refs()

        return self._build_report(sha256, md5)

    # -- catalog level -------------------------------------------------------
    def _analyze_catalog(self) -> None:
        cat = self.doc.catalog
        if not cat:
            return

        oa = cat.get("OpenAction")
        if oa is not None:
            resolved = self.doc.resolve(oa)
            if isinstance(resolved, dict):
                sub = str(resolved.get("S", ""))
                sem = ACTION_SEMANTICS.get(sub, {})
                self.add_finding(
                    "PX1-010", "open-action", sem.get("severity", "medium"),
                    f"Catalog /OpenAction ({sub or 'untyped'})",
                    "catalog/OpenAction",
                    sem.get("note", "Document defines an automatic action on open."),
                    {"action_type": sub,
                     "action_dict": self._describe_dict(resolved)},
                    iocs=self._action_iocs(resolved))
                self._record_action(resolved, "catalog/OpenAction")
            elif isinstance(resolved, list):
                self.add_finding(
                    "PX1-011", "open-action", "medium",
                    "Catalog /OpenAction (destination array)",
                    "catalog/OpenAction",
                    "Open action points at a destination; no execution implied.",
                    {"dest": repr(resolved)})

        aa = self.doc.dget(cat, "AA")
        if isinstance(aa, dict) and aa:
            for ev, act in aa.items():
                self._record_action(act, f"catalog/AA/{ev}")
                self.add_finding(
                    "PX1-012", "document-event", "medium",
                    f"Catalog additional action: {ev}",
                    f"catalog/AA/{ev}",
                    "Document-level event handler is defined.",
                    {"event": ev, "action": self._describe_dict(self.doc.resolve(act))},
                    iocs=self._action_iocs(self.doc.resolve(act)))

        if "AcroForm" in cat:
            self.add_finding(
                "PX1-013", "form", "low", "Interactive form present",
                "catalog/AcroForm",
                "Document contains an AcroForm. Form fields may carry "
                "per-field actions that a reader honours.",
                {"acroform": self._describe_dict(self.doc.dget(cat, 'AcroForm'))})

        xfa = self.doc.dget(cat, "AcroForm")
        if xfa and "XFA" in xfa:
            self.add_finding(
                "PX1-014", "form", "medium", "XFA form architecture present",
                "catalog/AcroForm/XFA",
                "XFA is an alternative form model executed by some readers; "
                "it is a common route for document-level script logic.",
                {"xfa": self._describe_dict(self.doc.resolve(xfa.get('XFA')))})

        for key, label in (("RichMediaContent", "RichMedia content"),
                           ("Movie", "Movie annotation tree"),
                           ("Sound", "Sound annotation tree")):
            if key in cat:
                self.add_finding(
                    "PX1-015", "active-content", "medium", label,
                    f"catalog/{key}",
                    "Active-content collection present in the document catalog.",
                    {key: self._describe_dict(self.doc.resolve(cat.get(key)))})

    # -- name trees ----------------------------------------------------------
    def _analyze_name_trees(self) -> None:
        names = self.doc.dget(self.doc.catalog, "Names")
        if not names:
            return
        for key in ("EmbeddedFiles", "JavaScript", "Renditions"):
            node = self.doc.dget(names, key)
            if not node:
                continue
            self._walk_name_tree(node, [], f"catalog/Names/{key}")

    def _walk_name_tree(self, node: dict, path: list[str], loc: str) -> None:
        kids = node.get("Kids")
        if isinstance(kids, list):
            for i, k in enumerate(kids):
                self._walk_name_tree(self.doc.dget(k) or {}, path, f"{loc}/Kids[{i}]")
            return
        names_arr = node.get("Names")
        if isinstance(names_arr, list):
            for i in range(0, len(names_arr) - 1, 2):
                nm = names_arr[i]
                val = self.doc.resolve(names_arr[i + 1])
                key = nm.decode("latin-1", "replace") if isinstance(nm, bytes) else str(nm)
                full = path + [key]
                self._name_tree_item(full, val, f"{loc}/Names[{i}]")

    def _name_tree_item(self, path: list[str], val, loc: str) -> None:
        if isinstance(val, Stream):
            d = val.dict
            if str(d.get("Type", "")) == "Filespec":
                fs = self.doc.dget(d, "EF") or {}
                embedded = None
                for k in ("F", "UF", "DOS", "Mac", "Unix"):
                    if k in fs:
                        embedded = fs[k]
                        break
                st = self.doc.stream_of(embedded)
                if st is not None:
                    self._register_embedded(path, st, d, loc)
            else:
                self.add_finding(
                    "PX1-020", "name-tree", "info", f"Name tree entry: {'/'.join(path)}",
                    loc, "Stream entry in a name tree.", {"type": str(d.get('Type'))})
        elif isinstance(val, dict):
            sub = str(val.get("S", ""))
            if sub == "JavaScript":
                self._record_js(path, val, loc)
            elif sub in ACTION_SEMANTICS:
                self._record_action(val, loc)
            else:
                self.add_finding(
                    "PX1-021", "name-tree", "info",
                    f"Name tree entry: {'/'.join(path)}",
                    loc, "Dictionary entry in a name tree.",
                    {"dict": self._describe_dict(val)})

    def _inventory_name_trees(self) -> None:
        for entry in self.actions:
            pass
        self.name_trees = {
            "actions": len(self.actions),
            "javascript_entries": len(self.javascript),
            "embedded_files": len(self.embedded_files),
        }

    # -- pages ---------------------------------------------------------------
    def _analyze_pages(self) -> None:
        for i, page in enumerate(self.doc.iter_pages()):
            aa = self.doc.dget(page, "AA")
            if isinstance(aa, dict) and aa:
                for ev, act in aa.items():
                    self._record_action(act, f"page[{i}]/AA/{ev}")
                    self.add_finding(
                        "PX1-030", "document-event", "medium",
                        f"Page additional action: {ev}",
                        f"page[{i}]/AA/{ev}",
                        "Page-level event handler is defined.",
                        {"event": ev,
                         "action": self._describe_dict(self.doc.resolve(act))},
                        iocs=self._action_iocs(self.doc.resolve(act)))
            annots = page.get("Annots")
            if isinstance(annots, list):
                for j, a in enumerate(annots):
                    self._analyze_annotation(self.doc.resolve(a), f"page[{i}]/Annots[{j}]")

    def _analyze_annotation(self, annot, loc: str) -> None:
        if not isinstance(annot, dict):
            return
        st = str(annot.get("Subtype", ""))
        act = self.doc.resolve(annot.get("A"))
        rec = {"location": loc, "subtype": st,
               "flags": annot.get("Flags"),
               "contents": self._as_text(annot.get("Contents")),
               "name": self._as_text(annot.get("Name")),
               "has_action": act is not None}
        self.annotations.append(rec)
        if st == "FileAttachment":
            fs = self.doc.dget(annot, "FS")
            ef = self.doc.dget(fs, "EF") if fs else None
            if ef:
                embedded = None
                for k in ("F", "UF", "DOS", "Mac", "Unix"):
                    if k in ef:
                        embedded = ef[k]
                        break
                st_obj = self.doc.stream_of(embedded)
                if st_obj is not None:
                    self._register_embedded(
                        [self._as_text(fs.get("F") or fs.get("UF") or "attachment")],
                        st_obj, fs or {}, loc + "/FileAttachment")
            self.add_finding(
                "PX1-040", "embedded-file", "high",
                "File attachment annotation",
                loc,
                "An embedded file is attached to this page. A reader may "
                "extract and/or open it.",
                {"annotation": rec,
                 "filespec": self._describe_dict(fs) if fs else None},
                iocs=self._filespec_iocs(fs))
        if act is not None:
            self._record_action(act, f"{loc}/A")
            sem = ACTION_SEMANTICS.get(str(self.doc.resolve(act).get("S", "") if isinstance(self.doc.resolve(act), dict) else ""), {})
            self.add_finding(
                "PX1-041", "annotation-action", sem.get("severity", "medium"),
                f"Annotation action ({sem.get('title', 'action')})",
                f"{loc}/A",
                sem.get("note", "Annotation carries an action dictionary."),
                {"action": self._describe_dict(act) if isinstance(act, dict) else repr(act)},
                iocs=self._action_iocs(act))
        if st in ("Movie", "Sound", "Screen", "RichMedia", "3D"):
            self.add_finding(
                "PX1-042", "active-content", "medium",
                f"Active-content annotation: /{st}",
                loc,
                "Annotation type that can invoke external or embedded media "
                "handlers.",
                {"annotation": rec})

    # -- forms ---------------------------------------------------------------
    def _analyze_forms(self) -> None:
        acro = self.doc.dget(self.doc.catalog, "AcroForm")
        if not acro:
            return
        fields = acro.get("Fields")
        if not isinstance(fields, list):
            return
        for i, f in enumerate(fields):
            fd = self.doc.resolve(f)
            if not isinstance(fd, dict):
                continue
            name = self._as_text(fd.get("T"))
            rec = {"location": f"AcroForm/Fields[{i}]", "name": name,
                   "type": str(fd.get("FT", "")),
                   "flags": fd.get("Ff"),
                   "actions": []}
            aa = self.doc.dget(fd, "AA")
            if isinstance(aa, dict):
                for ev, act in aa.items():
                    resolved = self.doc.resolve(act)
                    rec["actions"].append({"event": ev,
                                           "action": self._describe_dict(resolved)})
                    self._record_action(act, f"AcroForm/Fields[{i}]/AA/{ev}")
                    self.add_finding(
                        "PX1-050", "form-action", "high",
                        f"Form field action: {ev}",
                        f"AcroForm/Fields[{i}]/AA/{ev}",
                        "A form field defines an event handler. Validate / "
                        "Calculate / format handlers can run script.",
                        {"field": name, "event": ev,
                         "action": self._describe_dict(resolved)},
                        iocs=self._action_iocs(resolved))
            self.form_fields.append(rec)

    # -- global action scan --------------------------------------------------
    def _scan_all_objects_for_actions(self) -> None:
        for num, (off, val, gen) in sorted(self.doc.objects.items()):
            if not isinstance(val, dict):
                continue
            sub = val.get("S")
            is_action = isinstance(sub, (Name, str)) and str(sub) in ACTION_SEMANTICS
            if is_action:
                self._record_action(val, f"obj {num}", objnum=num)
            # A dictionary carrying /JS may be a JavaScript action even when
            # /S is missing or non-standard. Track JS separately from
            # actions so it is not lost when the action was already seen.
            if ("JS" in val or "JavaScript" in val):
                self._record_js([f"obj {num}"], val, f"obj {num}", objnum=num)

    # -- content streams -----------------------------------------------------
    def _scan_content_streams(self) -> None:
        for num, (off, val, gen) in sorted(self.doc.objects.items()):
            if not isinstance(val, Stream):
                continue
            self.streams_seen += 1
            d = val.dict
            stype = str(d.get("Type", ""))
            filters = d.get("Filter")
            fl = []
            if isinstance(filters, (Name, str)):
                fl = [str(filters)]
            elif isinstance(filters, list):
                fl = [str(x) for x in filters]
            if stype not in ("ObjStm", "XRef", "Metadata", "Image", "EmbeddedFile"):
                data = decode_stream(val)
                if data != val.raw or not fl:
                    self.decoded_streams += 1
                self._scan_text(data, f"obj {num}")

    def _scan_text(self, data: bytes, loc: str) -> None:
        if not data or len(data) > 8_000_000:
            return
        for pat, label in SUSPICIOUS_TEXT_MARKERS:
            for m in re.finditer(pat, data, re.IGNORECASE):
                start = max(0, m.start() - 24)
                end = min(len(data), m.end() + 24)
                snippet = data[start:end]
                self.strings_of_interest.append({
                    "location": loc,
                    "marker": label,
                    "offset": m.start(),
                    "snippet": snippet.decode("latin-1", "replace"),
                })

    # -- embedded files ------------------------------------------------------
    def _scan_streams_for_embedded_files(self) -> None:
        for num, (off, val, gen) in sorted(self.doc.objects.items()):
            if not isinstance(val, Stream):
                continue
            if str(val.dict.get("Type", "")) != "EmbeddedFile":
                continue
            parent = self._find_filespec_for(num)
            self._register_embedded(
                [parent.get("filename") if parent else f"embeddedfile_obj_{num}"],
                val, parent.get("fs") if parent else {}, f"obj {num}")

    def _find_filespec_for(self, stream_num: int):
        for num, (off, val, gen) in self.doc.objects.items():
            if not isinstance(val, dict):
                continue
            ef = val.get("EF")
            if not isinstance(ef, dict):
                continue
            for k, v in ef.items():
                if isinstance(v, Ref) and v.num == stream_num:
                    return {"filename": self._as_text(val.get("UF") or val.get("F") or f"obj{num}"),
                            "fs": val, "filespec_obj": num}
        return None

    def _register_embedded(self, path: list[str], stream: Stream, filespec: dict, loc: str) -> None:
        # A single embedded stream may be reachable through several routes
        # (name tree entry AND a FileAttachment annotation). Deduplicate on the
        # stream's object number so one payload is one entry, but keep the
        # richest location label.
        onum = self._stream_objnum(stream)
        if onum is not None:
            if onum in self._registered_streams:
                existing = next((e for e in self.embedded_files
                                 if e.get("embedded_object_num") == onum), None)
                if existing is not None:
                    existing["also_referenced_at"].append(loc)
                return
            self._registered_streams.add(onum)

        d = stream.dict
        size = d.get("Size")
        params = d.get("Params")
        params = self.doc.resolve(params) if params is not None else None
        subtype = str(d.get("Subtype", "")) if "Subtype" in d else ""

        try:
            decoded = decode_stream(stream)
        except Exception:
            decoded = b""
        raw_size = len(stream.raw)

        # /Params /Size is the declared *decoded* length per the spec.
        declared = None
        if isinstance(params, dict) and isinstance(params.get("Size"), int):
            declared = int(params["Size"])
        if declared is None and isinstance(size, int):
            declared = int(size)

        rec = {
            "location": loc,
            "also_referenced_at": [],
            "embedded_object_num": onum,
            "name_path": path,
            "filename": path[-1] if path else "unknown",
            "embedded_object": self._objnum(self.doc.resolve(d)),
            "declared_size": declared,
            "encoded_size": raw_size,
            "decoded_size": len(decoded),
            "size_matches_declared": (declared == len(decoded)) if declared is not None else None,
            "filters": [str(x) for x in (d.get("Filter") if isinstance(d.get("Filter"), list)
                                         else ([d.get("Filter")] if d.get("Filter") else []))],
            "subtype": subtype,
            "checksum": d.get("CheckSum"),
            "filespec": self._describe_dict(filespec) if filespec else None,
            "params": self._describe_dict(params) if isinstance(params, dict) else None,
            "sha256": hashlib.sha256(decoded).hexdigest(),
            "md5": hashlib.md5(decoded).hexdigest(),
            "magic": decoded[:8].hex(),
            "identified_type": identify_bytes(decoded),
            "entropy": round(shannon_entropy(decoded), 3),
            "is_ascii_text": bool(decoded) and all(
                0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) for b in decoded[:2048]),
        }

        if self.extract_dir:
            os.makedirs(self.extract_dir, exist_ok=True)
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", rec["filename"]) or f"embedded_{len(self.embedded_files)}"
            out_path = os.path.join(self.extract_dir, safe)
            with open(out_path, "wb") as fh:
                fh.write(decoded)
            rec["extracted_to"] = out_path

        self.embedded_files.append(rec)

        sev = "medium"
        note = ("Document carries an embedded file. Extraction and opening "
                "are separate events; a reader may not offer to open it "
                "without user action.")
        if rec["identified_type"] in ("PE/DOS executable", "ELF executable"):
            sev = "high"
            note = ("Embedded content identifies as an executable image. This "
                    "is the classic 'open the attachment' step of a PDF "
                    "delivery chain; whether the reader executes or merely "
                    "stages it depends on reader policy and user action.")
        elif rec["entropy"] >= 7.2 and rec["decoded_size"] > 512:
            sev = "medium"
            note = ("Embedded content has high entropy, consistent with "
                    "compressed or packed data. May be a container hiding "
                    "further content.")

        self.add_finding(
            "PX1-060", "embedded-file", sev, "Embedded file present",
            loc, note, rec,
            iocs={"sha256": rec["sha256"], "filename": rec["filename"],
                  "identified_type": rec["identified_type"]})

        if rec["size_matches_declared"] is False:
            self.add_finding(
                "PX1-061", "anomaly", "medium",
                "Embedded size mismatch",
                loc,
                "The declared /Params /Size does not match the actual "
                "decoded length. A mismatch means a reader that trusts the "
                "declared size and a scanner that measures the real size "
                "will disagree about the file's extent.",
                {"declared": rec["declared_size"], "actual": rec["decoded_size"]})

    def _stream_objnum(self, stream: Stream):
        for num, (_, val, _) in self.doc.objects.items():
            if val is stream:
                return num
        return None

    # -- javascript ----------------------------------------------------------
    def _record_js(self, path: list[str], action: dict, loc: str, objnum=None) -> None:
        if objnum is None:
            objnum = self._dict_objnum(action)
        if objnum is not None:
            existing = next((j for j in self.javascript if j.get("objnum") == objnum), None)
            if existing is not None:
                if loc not in existing["also_referenced_at"]:
                    existing["also_referenced_at"].append(loc)
                return
            self._recorded_js_objnums.add(objnum)
        js = action.get("JS")
        resolved = self.doc.resolve(js)
        text = ""
        if isinstance(resolved, bytes):
            text = resolved.decode("latin-1", "replace")
        elif isinstance(resolved, list):
            text = "\n".join(
                (self.doc.resolve(x).decode("latin-1", "replace")
                 if isinstance(self.doc.resolve(x), bytes) else "")
                for x in resolved)
        elif isinstance(resolved, str):
            text = str(resolved)

        rec = {
            "location": loc,
            "also_referenced_at": [],
            "name_path": path,
            "objnum": objnum,
            "script_length": len(text),
            "script_sha256": hashlib.sha256(text.encode("latin-1", "replace")).hexdigest(),
            "script_preview": text[:2000],
        }
        self.javascript.append(rec)
        self.add_finding(
            "PX1-070", "javascript", "high", "JavaScript in document",
            loc,
            "Document contains JavaScript for a reader scripting engine. "
            "Execution depends on the reader's scripting policy, sandbox and "
            "any user prompt.",
            rec)
        self._scan_text(text.encode("latin-1", "replace"), loc)

    def _record_action(self, act, loc: str, objnum=None) -> None:
        resolved = self.doc.resolve(act)
        if not isinstance(resolved, dict):
            return
        sub = str(resolved.get("S", ""))
        sem = ACTION_SEMANTICS.get(sub, {"title": "Unknown action",
                                          "note": "Unrecognised action type.",
                                          "severity": "medium"})
        if objnum is None:
            objnum = self._objnum(act)
            if objnum is None:
                objnum = self._dict_objnum(resolved)
        if objnum is not None:
            existing = next((a for a in self.actions if a.get("objnum") == objnum), None)
            if existing is not None:
                if loc not in existing["also_referenced_at"]:
                    existing["also_referenced_at"].append(loc)
                return
        rec = {
            "location": loc,
            "also_referenced_at": [],
            "objnum": objnum,
            "action_type": sub,
            "severity": sem.get("severity"),
            "requires_interaction": sem.get("interactive", True),
            "parameters": self._describe_dict(resolved),
        }
        self.actions.append(rec)

    # -- external references -------------------------------------------------
    URL_RE = re.compile(r"^(https?|ftp|ftps|file|smb|mailto)://", re.IGNORECASE)
    UNC_RE = re.compile(r"^\\\\[^\\]+\\")
    DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")

    # Only these action keys carry a *target*. Keys like /S hold a PDF name
    # (/JavaScript), which must never be mistaken for a filesystem path.
    REF_KEYS = {"URI", "F", "UF", "Win", "Mac", "Unix", "DOS", "File", "Doc"}

    def _classify_ref(self, value):
        """Classify a reference target as url / unc / drive-path / relative-file."""
        if not isinstance(value, str) or not value:
            return None
        v = value.strip()
        if not v:
            return None
        if self.URL_RE.match(v):
            return "url"
        if self.UNC_RE.match(v):
            return "unc"
        if self.DRIVE_RE.match(v):
            return "drive-path"
        # A leading '/' denotes a PDF name, not a path.
        if v.startswith("/"):
            return None
        if any(ch in v for ch in "/\\") or "." in v:
            return "relative-file"
        return None

    def _collect_external_refs(self) -> None:
        for a in self.actions:
            params = a.get("parameters", {})
            if not isinstance(params, dict):
                continue
            for key, val in params.items():
                candidates = []
                if isinstance(val, dict):
                    candidates = [(f"{key}.{k2}", v2) for k2, v2 in val.items()
                                  if k2 in self.REF_KEYS]
                elif key in self.REF_KEYS:
                    candidates = [(key, val)]
                for pname, pval in candidates:
                    kind = self._classify_ref(pval)
                    if kind is None:
                        continue
                    self.external_refs.append({
                        "location": a["location"],
                        "action_type": a["action_type"],
                        "parameter": pname,
                        "value": pval,
                        "kind": kind,
                    })
        # De-duplicate
        seen = set()
        uniq = []
        for r in self.external_refs:
            k = (r["location"], r["parameter"], r["value"])
            if k in seen:
                continue
            seen.add(k)
            uniq.append(r)
        self.external_refs = uniq
        for r in uniq:
            sev = {"url": "medium", "unc": "medium",
                   "drive-path": "medium", "relative-file": "low"}[r["kind"]]
            self.add_finding(
                "PX1-080", "external-reference", sev,
                f"External reference in {r['action_type'] or 'action'} "
                f"({r['kind']})",
                r["location"],
                "Action points at a resource outside the document. A reader "
                "may resolve, fetch, or launch it -- subject to reader policy.",
                r, iocs={"url": r["value"], "kind": r["kind"]})

    # -- helpers for describing values --------------------------------------
    def _describe_dict(self, d) -> dict:
        if not isinstance(d, dict):
            return {"value": repr(d)}
        out = {}
        for k, v in d.items():
            out[k] = self._describe_value(v)
        return out

    def _describe_value(self, v):
        if isinstance(v, Ref):
            return f"Ref({v.num} {v.gen} R)"
        if isinstance(v, Stream):
            return f"Stream({len(v.raw)} bytes, {self._describe_dict(v.dict)})"
        if isinstance(v, bytes):
            if len(v) <= 256:
                return v.decode("latin-1", "replace")
            return f"<bytes len={len(v)} sha256={hashlib.sha256(v).hexdigest()[:16]}>"
        if isinstance(v, list):
            return [self._describe_value(x) for x in v]
        if isinstance(v, dict):
            return self._describe_dict(v)
        if isinstance(v, Name):
            return "/" + str.__str__(v)
        return v

    def _as_text(self, v) -> str:
        v = self.doc.resolve(v)
        if isinstance(v, bytes):
            if v.startswith(b"\xfe\xff"):
                try:
                    return v[2:].decode("utf-16-be", "replace")
                except Exception:
                    return v.decode("latin-1", "replace")
            return v.decode("latin-1", "replace")
        if v is None:
            return ""
        return str(v)

    def _action_iocs(self, act) -> dict:
        act = self.doc.resolve(act)
        if not isinstance(act, dict):
            return {}
        out = {}
        for key in ("URI", "F", "Win", "Mac", "Unix", "NewWindow"):
            v = self.doc.resolve(act.get(key))
            if isinstance(v, (str, bytes)):
                out[key] = self._as_text(v)
        return out

    def _filespec_iocs(self, fs) -> dict:
        if not isinstance(fs, dict):
            return {}
        out = {}
        for key in ("F", "UF", "DOS", "Mac", "Unix"):
            v = fs.get(key)
            if v is not None:
                out[key] = self._as_text(v)
        return out

    # -- report --------------------------------------------------------------
    def _build_report(self, sha256: str, md5: str) -> dict:
        sev_counts = Counter(f["severity"] for f in self.findings)
        score = 0
        score += sev_counts.get("critical", 0) * 40
        score += sev_counts.get("high", 0) * 18
        score += sev_counts.get("medium", 0) * 6
        score += sev_counts.get("low", 0) * 2
        score = min(100, score)
        band = ("none" if score == 0 else
                "low" if score < 20 else
                "medium" if score < 50 else
                "high" if score < 80 else "critical")

        return {
            "schema": "phantom-x.phase1.pdf-inspection/1.0",
            "tool": "pdf_inspector.py",
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "analysis_mode": "static-structure",
            "file": {
                "path": os.path.abspath(self.doc.path),
                "size_bytes": len(self.doc.data),
                "sha256": sha256,
                "md5": md5,
                "pdf_version": self.doc.pdf_version,
                "encrypted": self.doc.is_encrypted,
                "page_count": self.doc.page_count(),
                "object_count": len(self.doc.objects),
                "xref_type": self.doc.xref_type,
                "streams_seen": self.streams_seen,
                "streams_decoded": self.decoded_streams,
            },
            "risk": {
                "score": score,
                "band": band,
                "severity_counts": dict(sev_counts),
                "interpretation": (
                    "Score reflects the PRESENCE of risky document features. "
                    "It is not an execution verdict and not a malware verdict."
                ),
            },
            "summary": {
                "actions": len(self.actions),
                "javascript_entries": len(self.javascript),
                "embedded_files": len(self.embedded_files),
                "external_references": len(self.external_refs),
                "annotations": len(self.annotations),
                "form_fields": len(self.form_fields),
                "strings_of_interest": len(self.strings_of_interest),
            },
            "actions": self.actions,
            "javascript": self.javascript,
            "embedded_files": self.embedded_files,
            "external_references": self.external_refs,
            "annotations": self.annotations,
            "form_fields": self.form_fields,
            "strings_of_interest": self.strings_of_interest,
            "findings": sorted(self.findings, key=lambda f: -SEV_ORDER.get(f["severity"], 0)),
            "parser_warnings": self.doc.warnings,
        }


# =============================================================================
# SECTION 5 -- Console rendering
# =============================================================================

SEV_ICON = {"info": "INFO", "low": "LOW ", "medium": "MED ", "high": "HIGH", "critical": "CRIT"}


def render_console(rep: dict, verbose: bool = False) -> str:
    L = []
    f = rep["file"]
    L.append("=" * 78)
    L.append("PHANTOM-X :: PDF STRUCTURE & ACTION INSPECTION")
    L.append("=" * 78)
    L.append(f"file          : {f['path']}")
    L.append(f"size          : {f['size_bytes']} bytes")
    L.append(f"sha256        : {f['sha256']}")
    L.append(f"pdf version   : {f['pdf_version']}   encrypted: {f['encrypted']}")
    L.append(f"pages         : {f['page_count']}   objects: {f['object_count']}   "
             f"xref: {f['xref_type']}   streams: {f['streams_decoded']}/{f['streams_seen']} decoded")
    r = rep["risk"]
    L.append(f"risk score    : {r['score']}/100  ({r['band']})")
    L.append("")

    s = rep["summary"]
    L.append("-- SUMMARY " + "-" * 66)
    L.append(f"  actions={s['actions']}  javascript={s['javascript_entries']}  "
             f"embedded_files={s['embedded_files']}  external_refs={s['external_references']}")
    L.append(f"  annotations={s['annotations']}  form_fields={s['form_fields']}  "
             f"strings_of_interest={s['strings_of_interest']}")
    L.append("")

    if rep["actions"]:
        L.append("-- ACTIONS " + "-" * 66)
        for a in rep["actions"]:
            L.append(f"  [{SEV_ICON.get(a['severity'], a['severity'])}] {a['action_type'] or 'untyped':<12} "
                     f"@ {a['location']}  (interaction: {a['requires_interaction']})")
            if verbose:
                for k, v in a["parameters"].items():
                    L.append(f"        {k}: {v}")
        L.append("")

    if rep["javascript"]:
        L.append("-- JAVASCRIPT " + "-" * 64)
        for j in rep["javascript"]:
            L.append(f"  @ {j['location']}  len={j['script_length']}  sha256={j['script_sha256'][:16]}")
            for line in j["script_preview"].splitlines()[:20]:
                L.append(f"      | {line}")
        L.append("")

    if rep["embedded_files"]:
        L.append("-- EMBEDDED FILES " + "-" * 61)
        for e in rep["embedded_files"]:
            L.append(f"  filename    : {e['filename']}")
            L.append(f"    location  : {e['location']}")
            L.append(f"    type      : {e['identified_type']}   subtype={e['subtype'] or '-'}")
            L.append(f"    size      : declared={e['declared_size']} decoded={e['decoded_size']} "
                     f"encoded={e['encoded_size']}")
            L.append(f"    filters   : {e['filters'] or '-'}")
            L.append(f"    entropy   : {e['entropy']}   ascii_text={e['is_ascii_text']}")
            L.append(f"    sha256    : {e['sha256']}")
            if e.get("extracted_to"):
                L.append(f"    extracted : {e['extracted_to']}")
            L.append("")

    if rep["external_references"]:
        L.append("-- EXTERNAL REFERENCES " + "-" * 57)
        for r2 in rep["external_references"]:
            L.append(f"  {r2['parameter']} = {r2['value']}   ({r2['action_type']} @ {r2['location']})")
        L.append("")

    if rep["annotations"]:
        L.append("-- ANNOTATIONS " + "-" * 62)
        for a in rep["annotations"]:
            L.append(f"  /{a['subtype']:<16} @ {a['location']}  action={a['has_action']}  "
                     f"flags={a['flags']}")
        L.append("")

    if rep["form_fields"]:
        L.append("-- FORM FIELDS " + "-" * 63)
        for fl in rep["form_fields"]:
            L.append(f"  name={fl['name']!r} type={fl['type'] or '-'} @ {fl['location']} "
                     f"actions={len(fl['actions'])}")
        L.append("")

    if rep["strings_of_interest"] and verbose:
        L.append("-- STRINGS OF INTEREST " + "-" * 56)
        for s2 in rep["strings_of_interest"][:100]:
            L.append(f"  {s2['marker']:<26} @ {s2['location']} off={s2['offset']}")
            L.append(f"      {s2['snippet']!r}")
        L.append("")

    L.append("-- FINDINGS " + "-" * 65)
    for fi in rep["findings"]:
        L.append(f"  [{SEV_ICON.get(fi['severity'], fi['severity'])}] {fi['id']} {fi['title']}")
        L.append(f"        {fi['detail']}")
        L.append(f"        location: {fi['location']}")
        if fi["iocs"]:
            L.append(f"        iocs    : {fi['iocs']}")
    L.append("")

    if rep["parser_warnings"]:
        L.append("-- PARSER WARNINGS " + "-" * 60)
        for w in rep["parser_warnings"]:
            L.append(f"  ! {w}")
        L.append("")

    L.append("NOTE: Findings describe document STRUCTURE only. Execution by a")
    L.append("      PDF reader depends on reader policy, sandboxing, and user")
    L.append("      confirmation. No execution was attempted by this tool.")
    L.append("=" * 78)
    return "\n".join(L)


# =============================================================================
# SECTION 6 -- CLI
# =============================================================================

def analyse_path(path: str, extract_dir: str | None) -> dict:
    doc = PDFDocument(path).load()
    return Analyzer(doc, extract_dir).analyze()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="PHANTOM-X Phase 1: PDF structure and document-action inspector (read-only).")
    ap.add_argument("targets", nargs="+", help="PDF file(s) or directory(ies)")
    ap.add_argument("--json", metavar="PATH", help="write JSON report to PATH")
    ap.add_argument("--extract-dir", metavar="DIR",
                    help="directory to extract embedded files into (quarantine)")
    ap.add_argument("--baseline", metavar="PDF",
                    help="baseline PDF; print a delta against it")
    ap.add_argument("--verbose", "-v", action="store_true", help="verbose console output")
    ap.add_argument("--quiet", "-q", action="store_true", help="suppress console report")
    args = ap.parse_args(argv)

    files: list[str] = []
    for t in args.targets:
        if os.path.isdir(t):
            for root, _, names in os.walk(t):
                for nm in sorted(names):
                    if nm.lower().endswith(".pdf"):
                        files.append(os.path.join(root, nm))
        else:
            files.append(t)

    if not files:
        print("error: no PDF files found", file=sys.stderr)
        return 2

    reports = []
    for p in files:
        try:
            rep = analyse_path(p, args.extract_dir)
        except Exception as exc:  # noqa: BLE001 - report, don't crash the sweep
            print(f"error: {p}: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        reports.append(rep)
        if not args.quiet:
            print(render_console(rep, args.verbose))

    if args.baseline:
        try:
            base = analyse_path(args.baseline, None)
        except Exception as exc:  # noqa: BLE001
            print(f"error: baseline: {exc}", file=sys.stderr)
            return 2
        for rep in reports:
            print("=" * 78)
            print(f"DELTA vs baseline {args.baseline}")
            print("=" * 78)
            b_ids = {x["id"] for x in base["findings"]}
            b_cats = Counter(x["category"] for x in base["findings"])
            for fi in rep["findings"]:
                if fi["id"] not in b_ids:
                    print(f"  + NEW  [{SEV_ICON.get(fi['severity'], fi['severity'])}] "
                          f"{fi['id']} {fi['title']}  @ {fi['location']}")
            r_cats = Counter(x["category"] for x in rep["findings"])
            for cat in set(r_cats) | set(b_cats):
                delta = r_cats.get(cat, 0) - b_cats.get(cat, 0)
                if delta:
                    print(f"  ~ category '{cat}': {delta:+d}")
            print()

    if args.json:
        payload = reports[0] if len(reports) == 1 else {
            "schema": "phantom-x.phase1.pdf-inspection-batch/1.0",
            "tool": "pdf_inspector.py",
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "count": len(reports),
            "reports": reports,
        }
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        print(f"[+] JSON report written: {os.path.abspath(args.json)}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
