#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: build-time string obfuscator
================================================================================
gen_strings.py -- Encodes the sensitive string table so that the plaintext
does not appear in the compiled binary.

    WHY
        A defender looking at a sample greps for strings. A YARA rule
        matches a literal, a Sigma rule matches a command line, an AV
        heuristic counts on "cmd.exe" appearing next to "/c". Encoding the
        strings removes that signal.

        The point of the lab is to MEASURE that: build the baseline, build
        the variant, and compare what the endpoint sees. The obfuscation
        is the experimental arm. Removing it would remove the experiment.

    HOW
        Each string is XORed with a per-string key that is derived from
        its own name, so the same plaintext in two places does not produce
        the same ciphertext. The key is stored alongside the bytes.

        The encoding is deliberately reversible and simple. It is not a
        cryptographic protection and it is not meant to be: it exists to
        remove a literal from the binary, and the detection that catches
        the obfuscated variant has to work regardless of how the encoding
        is done.

    USAGE
        python3 gen_strings.py --def px_strings.def --out px_strings.h

    Then build the payload with -DPX_OBFUSCATE=1 to include the decoder.
    Without that define the string table is not compiled in at all and the
    payload carries the plain literals, which is the baseline arm.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys

ENTRY_RE = re.compile(r'X\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)')

# The C escape sequences that matter here. The order matters: \\ has to be
# handled before the others, or a literal backslash gets eaten by the
# pass that handles \n.
C_ESCAPES = {
    'n': '\n',
    'r': '\r',
    't': '\t',
    '0': '\0',
    '\\': '\\',
    '"': '"',
}


def unescape_c(literal: str) -> str:
    """Turn a C string literal's contents into the bytes it represents."""
    out = []
    i = 0
    while i < len(literal):
        c = literal[i]
        if c == '\\' and i + 1 < len(literal):
            nxt = literal[i + 1]
            if nxt in C_ESCAPES:
                out.append(C_ESCAPES[nxt])
                i += 2
                continue
        out.append(c)
        i += 1
    return ''.join(out)


def parse_def(path: str) -> list[tuple[str, str]]:
    """Read the X(NAME, "text") entries out of the .def file.

    Comments are stripped first. The .def file documents its own format,
    and the documentation contains an example of the X() syntax, which
    would otherwise be parsed as a real entry and shift every index.
    """
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    out = []
    for name, raw in ENTRY_RE.findall(text):
        # Un-escape the C string literal into the ACTUAL bytes it
        # represents. A C literal "\\n" is a newline; storing the two
        # characters backslash and n would put a literal "\n" in the
        # decoded string, which then prints as "\n" instead of a line
        # break. That is not a cosmetic difference: it changes every
        # length in the payload.
        value = unescape_c(raw)
        out.append((name, value))
    if not out:
        raise SystemExit(f"no entries found in {path}")
    return out


def derive_key(name: str, plaintext: str) -> int:
    """Derive a per-string key from the name and the plaintext.

    Using the name as well as the plaintext means two strings with the
    same content but different names encode differently, so a frequency
    analysis of the ciphertext does not reveal repeats.
    """
    h = hashlib.sha256(name.encode("utf-8") + b"\x00" +
                       plaintext.encode("utf-8")).digest()
    return h[0] | 1  # never zero: a zero key would leave the string clear


def c_escape(data: bytes) -> str:
    """Render bytes as a C array initialiser body."""
    return ", ".join(str(b) for b in data)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Generate the encoded string table for the payload")
    ap.add_argument("--def", dest="def_path", default="px_strings.def")
    ap.add_argument("--out", default="px_strings.h")
    args = ap.parse_args(argv)

    entries = parse_def(args.def_path)

    lines = []
    lines.append("/* ================================================================== */")
    lines.append("/* PHANTOM-X :: GENERATED FILE -- do not edit by hand.              */")
    lines.append("/* ================================================================== */")
    lines.append("/*")
    lines.append(" * Produced by tools/gen_strings.py from px_strings.def.")
    lines.append(" * Regenerate with:")
    lines.append(" *     python3 gen_strings.py --def px_strings.def --out px_strings.h")
    lines.append(" *")
    lines.append(" * Each entry is: length, key, encoded bytes. The decoder in")
    lines.append(" * px_obfuscate.c XORs the bytes with the key at runtime.")
    lines.append(" */")
    lines.append("")
    lines.append("#ifndef PX_STRINGS_H")
    lines.append("#define PX_STRINGS_H")
    lines.append("")
    lines.append("typedef struct px_encoded_string {")
    lines.append("    unsigned char len;")
    lines.append("    unsigned char key;")
    # Sized to the longest string in the table, with a little headroom.
    # A fixed size keeps the table a plain C array with no allocator.
    maxlen = max((len(p.encode("latin-1", "replace")) for _n, p in entries),
                  default=0)
    bufsize = max(96, maxlen + 8)
    lines.append(f"    unsigned char bytes[{bufsize}];")
    lines.append("} px_encoded_string;")
    lines.append("")
    lines.append("/* The IDs. These are generated so that the table index and")
    lines.append(" * the name can never drift apart: adding an entry to the")
    lines.append(" * .def renumbers the table, and the enum follows it. */")
    lines.append("typedef enum px_string_id {")
    for idx, (name, _plaintext) in enumerate(entries):
        # The names in the .def already carry an S_ prefix, so the
        # enumerator is PX_SID_ + name without adding another one.
        lines.append(f"    PX_SID_{name} = {idx},")
    lines.append("    PX_SID_COUNT")
    lines.append("} px_string_id;")
    lines.append("")
    lines.append("static const px_encoded_string px_string_table[] = {")
    for idx, (name, plaintext) in enumerate(entries):
        key = derive_key(name, plaintext)
        enc = bytes(b ^ key for b in plaintext.encode("latin-1", "replace"))
        # The comment carries the NAME, not the plaintext. The name is not
        # a secret and it is what makes the table readable, but the
        # plaintext must not survive into the output or the whole point
        # is lost.
        lines.append(f"    /* [{idx:02d}] */ {{ {len(enc)}, 0x{key:02X}, "
                     f"{{ {c_escape(enc)} }} }},")
    lines.append("};")
    lines.append("")
    lines.append(f"#define PX_STRING_COUNT {len(entries)}")
    lines.append("")
    lines.append("#endif /* PX_STRINGS_H */")

    out = "\n".join(lines) + "\n"
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(out)

    print(f"[+] {len(entries)} strings encoded -> {args.out}")
    print(f"    {os.path.getsize(args.out)} bytes")

    # A self-check: the plaintext must not survive into the ENCODED
    # TABLE. The generated identifiers necessarily contain the string
    # NAMES (PX_SID_S_PROTO_PING contains "PING"), and the names are not
    # the secret -- but a name that happens to be the whole plaintext
    # would defeat the purpose, because a defender grepping for "PING"
    # would still hit it.
    #
    # So the check is against the table region only, and it additionally
    # flags any name that IS its own plaintext.
    leaked = []
    with open(args.out, "r", encoding="utf-8") as fh:
        generated = fh.read()
    table_start = generated.index("px_string_table[] = {")
    table_end = generated.index("};", table_start)
    table = generated[table_start:table_end]
    for name, plaintext in entries:
        # The check is on the ENCODED BYTES, not on the source text. A
        # string containing a newline must not appear in the table as
        # either the raw text or the raw bytes.
        raw = plaintext.encode("latin-1", "replace")
        if len(raw) >= 4:
            if raw.decode("latin-1", "replace") in table:
                leaked.append(f"{name} (in table)")
            if repr(raw)[2:-1] in table:
                leaked.append(f"{name} (in table, escaped)")
        # A name that contains the plaintext is a leak even in the
        # identifier region.
        if len(plaintext) >= 4 and plaintext in name:
            leaked.append(f"{name} (in identifier)")
    if leaked:
        print(f"[!] plaintext still present: {', '.join(leaked)}",
              file=sys.stderr)
        return 1
    print("    verified: no plaintext literal survives in the output")
    return 0


if __name__ == "__main__":
    sys.exit(main())
