#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: Phase 1 / Experiment 1 (companion)
================================================================================
make_test_pdfs.py -- Generates harmless PDF test samples that exercise document
features a reader may act on, WITHOUT exploiting the reader.

WHY THIS EXISTS
    Phase 1 asks which document features exist, which ones a reader will
    honour, and which require user interaction. To answer that empirically you
    need controlled inputs. These samples provide them.

SAFETY PROPERTIES (deliberate, please keep them)
    * Every embedded payload is inert. The "executable canary" is a text file
      whose FIRST TWO BYTES are the ASCII characters 'M' and 'Z' followed by a
      non-executable comment body. It is NOT a PE image and cannot run. It
      exists solely to answer the question "does the endpoint's file/AV
      pipeline inspect the CONTENT of embedded attachments, and does it match
      on embedded payload strings?"
    * All JavaScript is limited to app.alert() -- no network, no filesystem,
      no process access, no persistence. Scripts that try to do real work are
      a Phase 2+ concern and are deliberately absent here.
    * Launch actions point at a harmless local text file name, never at an
      executable, never at a remote URL.
    * URI actions point at example.com, a reserved IANA documentation domain.
    * No sample is designed to crash, hang, or fuzz a parser.

USAGE
    python3 make_test_pdfs.py                       # write to ./samples
    python3 make_test_pdfs.py --outdir /tmp/px      # custom output dir
"""

from __future__ import annotations

import argparse
import os
import sys
import zlib
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pdf_inspector import Name, Ref  # noqa: E402  (shared serialisation types)


# =============================================================================
# Minimal PDF serialiser
# =============================================================================

def ser(v) -> bytes:
    if isinstance(v, Ref):
        return f"{v.num} {v.gen} R".encode("latin-1")
    if isinstance(v, bool):
        return b"true" if v else b"false"
    if isinstance(v, Name):
        out = bytearray(b"/")
        for ch in str.__str__(v).encode("latin-1"):
            if 0x21 <= ch <= 0x7E and ch not in b"()<>[]{}/%#":
                out.append(ch)
            else:
                out += b"#%02X" % ch
        return bytes(out)
    if isinstance(v, int):
        return str(v).encode("latin-1")
    if isinstance(v, float):
        s = f"{v:.6f}".rstrip("0").rstrip(".")
        return (s if s else "0").encode("latin-1")
    if isinstance(v, bytes):
        return b"<" + v.hex().encode("ascii") + b">"
    if isinstance(v, str):
        return b"(" + escape_literal(v) + b")"
    if isinstance(v, list):
        return b"[" + b" ".join(ser(x) for x in v) + b"]"
    if isinstance(v, dict):
        parts = bytearray(b"<<")
        for k, val in v.items():
            parts += ser(Name(k)) + b" " + ser(val)
        parts += b">>"
        return bytes(parts)
    raise TypeError(f"cannot serialise {type(v)!r}")


def escape_literal(s: str) -> bytes:
    out = bytearray()
    for ch in s.encode("latin-1", "replace"):
        if ch in b"()\\":
            out += b"\\" + bytes([ch])
        elif ch == 0x0D:
            out += b"\\r"
        elif ch == 0x0A:
            out += b"\\n"
        else:
            out.append(ch)
    return bytes(out)


def stream_obj(dic: dict, data: bytes, compress: bool = True) -> bytes:
    d = dict(dic)
    if compress:
        data = zlib.compress(data, 9)
        d["Filter"] = Name("FlateDecode")
    d["Length"] = len(data)
    return ser(d) + b"\nstream\n" + data + b"\nendstream"


class PDFWriter:
    """Accumulates PDF objects and serialises a valid (cross-reference) file."""

    def __init__(self):
        self.objects: list[bytes | None] = []

    def reserve(self) -> int:
        self.objects.append(None)
        return len(self.objects)

    def put(self, num: int, content: bytes) -> int:
        self.objects[num - 1] = content
        return num

    def add(self, content: bytes) -> int:
        return self.put(self.reserve(), content)

    def add_dict(self, d: dict) -> int:
        return self.add(ser(d))

    def add_stream(self, d: dict, data: bytes, compress: bool = True) -> int:
        return self.add(stream_obj(d, data, compress))

    def build(self, root_num: int, info_num: int | None = None) -> bytes:
        out = bytearray()
        out += b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
        offsets = [0] * (len(self.objects) + 1)
        for i, content in enumerate(self.objects, start=1):
            if content is None:
                content = b"null"
            offsets[i] = len(out)
            out += f"{i} 0 obj\n".encode("latin-1")
            out += content
            out += b"\nendobj\n"
        xref_off = len(out)
        size = len(self.objects) + 1
        out += f"xref\n0 {size}\n".encode("latin-1")
        out += b"0000000000 65535 f \n"
        for i in range(1, size):
            out += f"{offsets[i]:010d} 00000 n \n".encode("latin-1")
        trailer = {"Size": size, "Root": Ref(root_num)}
        if info_num:
            trailer["Info"] = Ref(info_num)
        out += b"trailer\n" + ser(trailer) + b"\n"
        out += f"startxref\n{xref_off}\n%%EOF\n".encode("latin-1")
        return bytes(out)


# =============================================================================
# Shared building blocks
# =============================================================================

PAGE_TEXT = b"""BT
/F1 12 Tf
72 720 Td
(PHANTOM-X Phase 1 test document) Tj
0 -18 Td
(Static structural analysis sample - no exploit payload.) Tj
ET
"""


class PageRef:
    """Object numbers for a generated page. Explicit beats arithmetic."""

    __slots__ = ("font", "content", "pages", "page")

    def __init__(self, font, content, pages, page):
        self.font = font
        self.content = content
        self.pages = pages
        self.page = page


def simple_page(w: PDFWriter, text: bytes = PAGE_TEXT) -> PageRef:
    """Create font + content stream + pages node + page dict."""
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
    w.put(pages, ser({
        "Type": Name("Pages"), "Kids": [Ref(page)], "Count": 1,
    }))
    return PageRef(font, content, pages, page)


def page_dict(pr: PageRef, extra: dict | None = None) -> dict:
    """Rebuild a page dictionary with optional additions."""
    d = {
        "Type": Name("Page"),
        "Parent": Ref(pr.pages),
        "MediaBox": [0, 0, 612, 792],
        "Resources": {"Font": {"F1": Ref(pr.font)}},
        "Contents": Ref(pr.content),
    }
    if extra:
        d.update(extra)
    return d


def make_doc(title: str, extra_catalog: dict | None = None,
             page_extra: dict | None = None, annots: list | None = None) -> bytes:
    """Build a one-page document with optional catalog/page additions."""
    w = PDFWriter()
    pr = simple_page(w)
    if page_extra or annots:
        extra = dict(page_extra or {})
        if annots:
            extra["Annots"] = annots
        w.put(pr.page, ser(page_dict(pr, extra)))
    catalog = {"Type": Name("Catalog"), "Pages": Ref(pr.pages)}
    if extra_catalog:
        catalog.update(extra_catalog)
    cat_num = w.add_dict(catalog)
    info_num = w.add_dict({
        "Title": title,
        "Producer": "PHANTOM-X make_test_pdfs.py",
        "Creator": "PHANTOM-X",
        "CreationDate": "D:20260101000000Z",
    })
    return w.build(cat_num, info_num)


# =============================================================================
# Sample builders
# =============================================================================

def s01_clean_baseline() -> bytes:
    """Control sample: no active content at all."""
    return make_doc("PHANTOM-X S01 clean baseline")


def s02_embedded_text() -> bytes:
    """Embedded benign text file, referenced via name tree AND annotation."""
    w = PDFWriter()
    payload = (b"PHANTOM-X embedded attachment.\n"
               b"This is an inert UTF-8 text file used to test whether an\n"
               b"endpoint's document pipeline extracts and inspects embedded\n"
               b"attachments. It contains no code.\n")
    ef_num = w.add_stream({
        "Type": Name("EmbeddedFile"),
        "Subtype": Name("text#2Fplain"),
        "Params": {"Size": len(payload)},
    }, payload)
    fs_num = w.add_dict({
        "Type": Name("Filespec"),
        "F": "px_benign_attachment.txt",
        "UF": "px_benign_attachment.txt",
        "EF": {"F": Ref(ef_num)},
        "Desc": "PHANTOM-X benign embedded text attachment",
    })
    tree_num = w.add_dict({
        "Names": ["px_benign_attachment.txt", Ref(fs_num)],
    })
    pr = simple_page(w)
    annot = w.add_dict({
        "Type": Name("Annot"),
        "Subtype": Name("FileAttachment"),
        "Rect": [72, 500, 200, 540],
        "Contents": "PHANTOM-X benign attachment",
        "FS": Ref(fs_num),
    })
    w.put(pr.page, ser(page_dict(pr, {"Annots": [Ref(annot)]})))
    cat = w.add_dict({
        "Type": Name("Catalog"), "Pages": Ref(pr.pages),
        "Names": {"EmbeddedFiles": Ref(tree_num)},
    })
    return w.build(cat)


def s03_embedded_exe_canary() -> bytes:
    """Inert 'executable-looking' attachment used as a DETECTION CANARY.

    The payload begins with the ASCII bytes 'MZ' and contains inert strings
    commonly used by script-based detection heuristics. It is a plain text
    file and cannot execute. Purpose: determine whether the endpoint
    inspects embedded attachment CONTENT (vs only the PDF container), and
    whether string-level heuristics fire on it.
    """
    w = PDFWriter()
    payload = (b"MZ\x90\x00\x03"                     # ASCII marker only; not a PE header
               b"\nPHANTOM-X DETECTION CANARY -- INERT TEXT PAYLOAD\n"
               b"This file is deliberately NOT a PE image. The leading 'MZ'\n"
               b"bytes are plain ASCII markers used to probe whether the\n"
               b"endpoint's engine inspects embedded attachment content and\n"
               b"matches on embedded payload strings.\n"
               b"Marker strings for observation only:\n"
               b"  powershell  cmd.exe  wscript.exe  rundll32  certutil\n"
               b"  Invoke-Expression  DownloadString  FromBase64String\n"
               b"  ActiveXObject  WScript.Shell  http://  https://\n"
               b"No code is present. No command will execute.\n")
    ef_num = w.add_stream({
        "Type": Name("EmbeddedFile"),
        "Subtype": Name("application#2Foctet-stream"),
        "Params": {"Size": len(payload)},
    }, payload)
    fs_num = w.add_dict({
        "Type": Name("Filespec"),
        "F": "px_detection_canary.bin",
        "UF": "px_detection_canary.bin",
        "EF": {"F": Ref(ef_num)},
        "Desc": "PHANTOM-X inert detection canary (not an executable)",
    })
    tree_num = w.add_dict({"Names": ["px_detection_canary.bin", Ref(fs_num)]})
    pr = simple_page(w)
    w.put(pr.page, ser(page_dict(pr)))
    cat = w.add_dict({
        "Type": Name("Catalog"), "Pages": Ref(pr.pages),
        "Names": {"EmbeddedFiles": Ref(tree_num)},
    })
    return w.build(cat)


def s04_javascript() -> bytes:
    """JavaScript in the document-level /Names /JavaScript tree.

    The script is limited to app.alert() -- it displays text and stops.
    It performs no network, filesystem, or process activity.
    """
    w = PDFWriter()
    js = (b"// PHANTOM-X benign JavaScript probe\n"
          b"// Scope: app.alert only. No network, no filesystem, no exec.\n"
          b"var msg = 'PHANTOM-X JS probe: document script executed.';\n"
          b"try { app.alert(msg); } catch (e) { /* reader refused scripting */ }\n"
          b"try { this.getField('probe_field').value = 'js-ran'; } catch (e2) {}\n")
    js_action = w.add_dict({
        "S": Name("JavaScript"),
        "JS": js,
    })
    tree_num = w.add_dict({"Names": ["px_js_probe", Ref(js_action)]})
    pr = simple_page(w)
    w.put(pr.page, ser(page_dict(pr)))
    cat = w.add_dict({
        "Type": Name("Catalog"), "Pages": Ref(pr.pages),
        "Names": {"JavaScript": Ref(tree_num)},
    })
    return w.build(cat)


def s05_launch_action() -> bytes:
    """A /Launch action naming a harmless local text file."""
    w = PDFWriter()
    launch = w.add_dict({
        "S": Name("Launch"),
        "F": "px_harmless_target.txt",
        "NewWindow": True,
    })
    pr = simple_page(w)
    annot = w.add_dict({
        "Type": Name("Annot"),
        "Subtype": Name("Link"),
        "Rect": [72, 600, 300, 630],
        "Contents": "PHANTOM-X launch action probe",
        "A": Ref(launch),
    })
    w.put(pr.page, ser(page_dict(pr, {"Annots": [Ref(annot)]})))
    cat = w.add_dict({"Type": Name("Catalog"), "Pages": Ref(pr.pages)})
    return w.build(cat)


def s06_uri_action() -> bytes:
    """A /URI action pointing at a reserved documentation domain."""
    w = PDFWriter()
    uri = w.add_dict({
        "S": Name("URI"),
        "URI": "https://example.com/phantom-x-canary",
    })
    pr = simple_page(w)
    annot = w.add_dict({
        "Type": Name("Annot"),
        "Subtype": Name("Link"),
        "Rect": [72, 600, 320, 630],
        "Contents": "PHANTOM-X URI action probe",
        "A": Ref(uri),
    })
    w.put(pr.page, ser(page_dict(pr, {"Annots": [Ref(annot)]})))
    cat = w.add_dict({"Type": Name("Catalog"), "Pages": Ref(pr.pages)})
    return w.build(cat)


def s07_openaction_js() -> bytes:
    """Catalog /OpenAction that is itself a JavaScript action."""
    w = PDFWriter()
    js = (b"// PHANTOM-X benign OpenAction JavaScript probe\n"
          b"try { app.alert('PHANTOM-X: OpenAction JS executed.'); } catch (e) {}\n")
    js_action = w.add_dict({
        "S": Name("JavaScript"),
        "JS": js,
    })
    pr = simple_page(w)
    w.put(pr.page, ser(page_dict(pr)))
    cat = w.add_dict({
        "Type": Name("Catalog"), "Pages": Ref(pr.pages),
        "OpenAction": Ref(js_action),
    })
    return w.build(cat)


def s08_gotor_remote() -> bytes:
    """A /GoToR action referencing an external PDF path."""
    w = PDFWriter()
    goto_r = w.add_dict({
        "S": Name("GoToR"),
        "F": "px_external_target.pdf",
        "D": [0, Name("Fit")],
        "NewWindow": True,
    })
    pr = simple_page(w)
    annot = w.add_dict({
        "Type": Name("Annot"),
        "Subtype": Name("Link"),
        "Rect": [72, 600, 320, 630],
        "Contents": "PHANTOM-X GoToR probe",
        "A": Ref(goto_r),
    })
    w.put(pr.page, ser(page_dict(pr, {"Annots": [Ref(annot)]})))
    cat = w.add_dict({"Type": Name("Catalog"), "Pages": Ref(pr.pages)})
    return w.build(cat)


def s09_form_with_action() -> bytes:
    """AcroForm with a text field that carries a format/validate action."""
    w = PDFWriter()
    js = (b"// PHANTOM-X benign form-field action probe\n"
          b"try { app.alert('PHANTOM-X: field JS action executed.'); } catch (e) {}\n")
    js_action = w.add_dict({
        "S": Name("JavaScript"),
        "JS": js,
    })
    pr = simple_page(w)
    field = w.add_dict({
        "Type": Name("Annot"),
        "Subtype": Name("Widget"),
        "FT": Name("Tx"),
        "T": "probe_field",
        "Rect": [72, 640, 300, 665],
        "V": "",
        "F": 4,
        "AA": {"F": Ref(js_action), "Fo": Ref(js_action)},
    })
    w.put(pr.page, ser(page_dict(pr, {"Annots": [Ref(field)]})))
    cat = w.add_dict({
        "Type": Name("Catalog"), "Pages": Ref(pr.pages),
        "AcroForm": {"Fields": [Ref(field)], "DA": ("/Helv 0 Tf 0 g")},
    })
    return w.build(cat)


def s10_embedded_pdf() -> bytes:
    """A nested PDF embedded as a file attachment."""
    w = PDFWriter()
    inner = make_doc("PHANTOM-X inner document")
    ef_num = w.add_stream({
        "Type": Name("EmbeddedFile"),
        "Subtype": Name("application#2Fpdf"),
        "Params": {"Size": len(inner)},
    }, inner)
    fs_num = w.add_dict({
        "Type": Name("Filespec"),
        "F": "px_inner_document.pdf",
        "UF": "px_inner_document.pdf",
        "EF": {"F": Ref(ef_num)},
        "Desc": "PHANTOM-X nested PDF attachment",
    })
    tree_num = w.add_dict({"Names": ["px_inner_document.pdf", Ref(fs_num)]})
    pr = simple_page(w)
    w.put(pr.page, ser(page_dict(pr)))
    cat = w.add_dict({
        "Type": Name("Catalog"), "Pages": Ref(pr.pages),
        "Names": {"EmbeddedFiles": Ref(tree_num)},
    })
    return w.build(cat)


def s11_combined() -> bytes:
    """Single document combining every feature class under test."""
    w = PDFWriter()

    text_payload = b"PHANTOM-X combined sample benign attachment.\n"
    ef_num = w.add_stream({
        "Type": Name("EmbeddedFile"),
        "Subtype": Name("text#2Fplain"),
        "Params": {"Size": len(text_payload)},
    }, text_payload)
    fs_num = w.add_dict({
        "Type": Name("Filespec"),
        "F": "px_combined_attachment.txt",
        "UF": "px_combined_attachment.txt",
        "EF": {"F": Ref(ef_num)},
    })
    ef_tree = w.add_dict({"Names": ["px_combined_attachment.txt", Ref(fs_num)]})

    js = b"try { app.alert('PHANTOM-X combined probe'); } catch (e) {}\n"
    js_action = w.add_dict({"S": Name("JavaScript"), "JS": js})
    js_tree = w.add_dict({"Names": ["px_combined_js", Ref(js_action)]})

    launch = w.add_dict({"S": Name("Launch"), "F": "px_harmless_target.txt"})
    uri = w.add_dict({"S": Name("URI"), "URI": "https://example.com/phantom-x-combined"})
    goto_r = w.add_dict({"S": Name("GoToR"), "F": "px_external_target.pdf", "NewWindow": True})

    pr = simple_page(w)
    a1 = w.add_dict({"Type": Name("Annot"), "Subtype": Name("FileAttachment"),
                     "Rect": [72, 500, 200, 540], "FS": Ref(fs_num),
                     "Contents": "combined attachment"})
    a2 = w.add_dict({"Type": Name("Annot"), "Subtype": Name("Link"),
                     "Rect": [72, 560, 300, 590], "A": Ref(launch),
                     "Contents": "combined launch"})
    a3 = w.add_dict({"Type": Name("Annot"), "Subtype": Name("Link"),
                     "Rect": [72, 620, 320, 650], "A": Ref(uri),
                     "Contents": "combined uri"})
    a4 = w.add_dict({"Type": Name("Annot"), "Subtype": Name("Link"),
                     "Rect": [72, 680, 340, 710], "A": Ref(goto_r),
                     "Contents": "combined gotoR"})
    w.put(pr.page, ser(page_dict(pr, {
        "Annots": [Ref(a1), Ref(a2), Ref(a3), Ref(a4)],
        "AA": {"O": Ref(js_action)},
    })))
    cat = w.add_dict({
        "Type": Name("Catalog"), "Pages": Ref(pr.pages),
        "Names": {"EmbeddedFiles": Ref(ef_tree), "JavaScript": Ref(js_tree)},
        "OpenAction": Ref(js_action),
        "AcroForm": {"Fields": [], "DA": ("/Helv 0 Tf 0 g")},
    })
    return w.build(cat)


SAMPLES = [
    ("px01_clean_baseline.pdf", s01_clean_baseline,
     "Control: no active content. Use as the differential baseline."),
    ("px02_embedded_text.pdf", s02_embedded_text,
     "Inert text attachment via name tree + FileAttachment annotation."),
    ("px03_embedded_exe_canary.pdf", s03_embedded_exe_canary,
     "Inert 'MZ'-prefixed text canary. Probes attachment-content inspection."),
    ("px04_javascript.pdf", s04_javascript,
     "Document-level JavaScript (app.alert only)."),
    ("px05_launch_action.pdf", s05_launch_action,
     "Launch action naming a harmless local text file."),
    ("px06_uri_action.pdf", s06_uri_action,
     "URI action to example.com."),
    ("px07_openaction_js.pdf", s07_openaction_js,
     "Catalog OpenAction executing JavaScript."),
    ("px08_gotor_remote.pdf", s08_gotor_remote,
     "GoToR action referencing an external PDF path."),
    ("px09_form_with_action.pdf", s09_form_with_action,
     "AcroForm field with JS event handlers."),
    ("px10_embedded_pdf.pdf", s10_embedded_pdf,
     "Nested PDF embedded as an attachment."),
    ("px11_combined.pdf", s11_combined,
     "All feature classes combined in one document."),
]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Generate PHANTOM-X harmless PDF test samples.")
    ap.add_argument("--outdir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples"))
    args = ap.parse_args(argv)
    os.makedirs(args.outdir, exist_ok=True)

    manifest = {
        "schema": "phantom-x.phase1.sample-manifest/1.0",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "safety": {
            "all_payloads_inert": True,
            "javascript_scope": "app.alert only",
            "launch_targets": "harmless local .txt names only",
            "uri_targets": "example.com (reserved documentation domain)",
            "exploit_content": "none",
        },
        "samples": [],
    }

    for fname, fn, desc in SAMPLES:
        data = fn()
        path = os.path.join(args.outdir, fname)
        with open(path, "wb") as fh:
            fh.write(data)
        import hashlib
        manifest["samples"].append({
            "file": fname,
            "description": desc,
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "features": sorted(set(
                [k for k in ("embedded_file", "javascript", "launch", "uri", "gotor",
                             "openaction", "form", "nested_pdf", "attachment_annotation")
                 if _has_feature(fname, k)])),
        })
        print(f"[+] {fname:<36} {len(data):>7} bytes  {desc}")

    mpath = os.path.join(args.outdir, "manifest.json")
    import json
    with open(mpath, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    print(f"\n[+] manifest: {mpath}")
    return 0


def _has_feature(fname: str, feature: str) -> bool:
    m = {
        "px01_clean_baseline.pdf": set(),
        "px02_embedded_text.pdf": {"embedded_file", "attachment_annotation"},
        "px03_embedded_exe_canary.pdf": {"embedded_file"},
        "px04_javascript.pdf": {"javascript"},
        "px05_launch_action.pdf": {"launch"},
        "px06_uri_action.pdf": {"uri"},
        "px07_openaction_js.pdf": {"javascript", "openaction"},
        "px08_gotor_remote.pdf": {"gotor"},
        "px09_form_with_action.pdf": {"javascript", "form"},
        "px10_embedded_pdf.pdf": {"embedded_file", "nested_pdf"},
        "px11_combined.pdf": {"embedded_file", "javascript", "launch", "uri", "gotor",
                              "openaction", "form", "attachment_annotation"},
    }
    return feature in m.get(fname, set())


if __name__ == "__main__":
    sys.exit(main())
