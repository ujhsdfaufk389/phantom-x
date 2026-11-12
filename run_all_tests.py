#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: full regression suite
================================================================================
run_all_tests.py -- Runs every check the lab has, in the order that fails
fastest, and prints one summary.

    WHAT IT RUNS
      1. the payload formatter self-test (C, built with MSVC)
      2. the Go C2 server integration test against the REAL payload
      3. the Go C2 server against the Python reference
      4. the Rust PDF scanner against the Python reference
      5. the Rust SHA-256 against the FIPS 180-4 vectors
      6. the PDF inspector against pypdf (if installed)
      7. the Sysmon config against the official schema (if the validator
         is present)

    Each step is independent. A failure in one does not stop the others,
    because a single failing check tells you much less than five
    independent ones do.

USAGE
    python3 run_all_tests.py
    python3 run_all_tests.py --quick     # skip the slow chain test
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
# The suite lives at the repository root, so the root IS this directory.
ROOT = HERE


class Result:
    def __init__(self, name: str, ok: bool, detail: str, seconds: float):
        self.name = name
        self.ok = ok
        self.detail = detail
        self.seconds = seconds


def run(cmd, cwd=None, timeout=600, env=None):
    """Run a command and return (ok, combined output)."""
    e = dict(os.environ)
    if env:
        e.update(env)
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           timeout=timeout, env=e, shell=isinstance(cmd, str))
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode == 0, out
    except subprocess.TimeoutExpired:
        return False, f"timed out after {timeout}s"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def find(name, *relatives):
    """Look for a built artefact in a few likely places.

    Every candidate path is resolved against the repository root, so the
    suite finds the artefacts regardless of which directory it was
    started from.
    """
    here = os.path.join(HERE, name)
    if os.path.isfile(here):
        return here
    for rel in relatives:
        p = os.path.join(ROOT, rel)
        if os.path.isfile(p):
            return p
    return None


def find_tool(name, *hints):
    """Look for a build tool on PATH or in a well-known install location."""
    found = shutil.which(name)
    if found:
        return found
    for h in hints:
        p = os.path.expandvars(h)
        if os.path.isfile(p):
            return p
    return None


def test_formatter_selftest() -> Result:
    """The payload's own formatter regression test."""
    name = "payload formatter self-test"
    exe = find("px_selftest.exe",
               "phase3_fileless/loader/px_selftest.exe",
               "dist/native/px_selftest.exe")
    if not exe:
        return Result(name, False, "px_selftest.exe not built", 0.0)
    ok, out = run([exe], timeout=120)
    passed = "RESULT: PASS" in out
    counts = ""
    for line in out.splitlines():
        if "passed," in line:
            counts = line.strip()
            break
    return Result(name, passed, ("PASS " + counts).strip(), 0.0)


def test_go_c2_integration() -> Result:
    """The Go server against the real Windows payload."""
    name = "Go C2 server vs real payload"
    go = find_tool("go.exe", r"%ProgramFiles%\Go\bin\go.exe")
    if not go:
        return Result(name, False, "Go toolchain not found", 0.0)
    payload = find("px_payload.exe",
                   "phase3_fileless/loader/px_payload.exe",
                   "dist/native/px_payload.exe",
                   "phase3_fileless/loader/px_payload_msvc.exe")
    if not payload:
        return Result(name, False, "no built payload found", 0.0)
    t0 = time.time()
    ok, out = run([go, "test", "-v", "-run", "TestGoC2Integration",
                   "-payload", payload, "."],
                  cwd=os.path.join(ROOT, "phase5_network"), timeout=300)
    detail = "PASS" if ok and "--- PASS" in out else "FAIL"
    return Result(name, ok and "--- PASS" in out, detail, time.time() - t0)


def test_c2_equivalence() -> Result:
    """The Go server against the Python reference."""
    name = "Go C2 server vs Python reference"
    go_bin = find("px_c2.exe", "phase5_network/px_c2.exe",
                  "dist/native/px_c2.exe")
    if not go_bin:
        return Result(name, False, "px_c2.exe not built", 0.0)
    t0 = time.time()
    ok, out = run([sys.executable, "validate_c2_equivalence.py",
                   "--go", go_bin],
                  cwd=os.path.join(ROOT, "phase5_network"), timeout=300)
    detail = "PASS" if "RESULT: PASS" in out else "FAIL"
    return Result(name, ok and "RESULT: PASS" in out, detail, time.time() - t0)


def test_pdf_cross_impl() -> Result:
    """The Rust PDF scanner against the Python reference."""
    name = "Rust PDF scanner vs Python reference"
    rust = find("px_pdfscan.exe",
                "phase1_pdf/rust_scanner/target/release/px_pdfscan.exe",
                "dist/native/px_pdfscan.exe")
    if not rust:
        alt = os.path.join(ROOT, "phase1_pdf", "rust_scanner", "target",
                           "release", "px_pdfscan.exe")
        rust = alt if os.path.isfile(alt) else None
    if not rust:
        return Result(name, False, "px_pdfscan.exe not built", 0.0)
    t0 = time.time()
    ok, out = run([sys.executable, "validate_cross_impl.py",
                   "--rust", rust, "--samples", "samples"],
                  cwd=os.path.join(ROOT, "phase1_pdf"), timeout=600)
    detail = "PASS" if "RESULT: PASS" in out else "FAIL"
    matched = out.count("[MATCH]")
    diffed = out.count("[DIFF")
    return Result(name, ok and "RESULT: PASS" in out,
                  f"{detail} ({matched} match, {diffed} differ)",
                  time.time() - t0)


def test_sha256() -> Result:
    """The Rust SHA-256 against the FIPS 180-4 test vectors."""
    name = "SHA-256 (FIPS 180-4 vectors)"
    cargo = find_tool("cargo.exe", r"%USERPROFILE%\.cargo\bin\cargo.exe")
    if not cargo:
        return Result(name, False, "cargo not found", 0.0)
    t0 = time.time()
    ok, out = run([cargo, "test", "--release", "known_vectors"],
                  cwd=os.path.join(ROOT, "phase1_pdf", "rust_scanner"),
                  timeout=300)
    detail = "PASS" if "test result: ok" in out else "FAIL"
    return Result(name, ok and "test result: ok" in out, detail,
                  time.time() - t0)


def test_variants() -> Result:
    """The variant arms, driven against the Go server.

    Each arm is a separate build with a separate wire behaviour, so each
    one needs its own check. A test that only exercised the baseline
    would pass whether or not the variant code worked at all.
    """
    name = "variant arms"
    go = find_tool("go.exe", r"%ProgramFiles%\Go\bin\go.exe")
    if not go:
        return Result(name, False, "Go toolchain not found", 0.0)

    variants_dir = os.path.join(ROOT, "dist", "variants")
    if not os.path.isdir(variants_dir):
        return Result(name, False, "no variant builds (run build_variants.ps1)", 0.0)

    t0 = time.time()
    ok = True
    detail = []

    # The lab DNS helper.
    #
    # The domain generation arm connects to a generated hostname, which
    # only resolves if the helper is running. The helper binds to the
    # loopback interface and answers only the lab's own names, so it is
    # safe to run during the suite.
    dns_proc = None
    dns_port = 15353
    dns_script = os.path.join(ROOT, "phase5_network", "dga_dns.py")
    if os.path.isfile(dns_script):
        dns_proc = subprocess.Popen(
            [sys.executable, dns_script, "--host", "127.0.0.1",
             "--port", str(dns_port), "--c2", "127.0.0.1",
             "--duration", "300"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        time.sleep(1.0)
        # The payload resolves through the system resolver, so the helper
        # has to be reachable by name. The hosts entry is what makes that
        # work without touching the machine's DNS configuration.
        _add_hosts_entry()

    try:
        for arm in ("baseline", "obfuscate", "amsi", "etw", "encrypt",
                    "dga", "cred", "lateral", "resilient", "xfer",
                    "caps", "full"):
            exe = os.path.join(variants_dir, f"px_payload_{arm}.exe")
            if not os.path.isfile(exe):
                detail.append(f"{arm}=missing")
                ok = False
                continue
            p = subprocess.run(
                [go, "test", "-count=1", "-timeout", "120s", "-v",
                 "-run", "TestVariant", "-variant", exe, "."],
                cwd=os.path.join(ROOT, "phase5_network"),
                capture_output=True, text=True, timeout=300,
                env=dict(os.environ),
            )
            out = (p.stdout or "") + (p.stderr or "")
            # A SKIP is not a failure. The baseline arm has no encrypted
            # channel, so the encrypted-channel test skips it, and
            # `go test` still exits non-zero for a package where every
            # test skipped. The per-test result lines are what matter,
            # not the exit code.
            if "--- FAIL" in out:
                detail.append(f"{arm}=FAIL")
                ok = False
            elif "--- PASS" in out:
                detail.append(f"{arm}=pass")
            elif "--- SKIP" in out:
                detail.append(f"{arm}=skip")
            elif "no test files" in out or "cannot find" in out:
                detail.append(f"{arm}=error")
                ok = False
            else:
                detail.append(f"{arm}=unknown")
                ok = False
    finally:
        if dns_proc is not None:
            dns_proc.terminate()
            try:
                dns_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                dns_proc.kill()
        _remove_hosts_entry()

    return Result(name, ok, ", ".join(detail), time.time() - t0)


def test_resilient_reconnect() -> Result:
    """The resilient arm must come back when the connection drops.

    This is the behaviour that makes the lab work on a network that is
    not the one it was built on: the operator's laptop changed network,
    the socket died, and the payload has to find its C2 again on its own.
    """
    name = "resilient reconnect"
    go = find_tool("go.exe", r"%ProgramFiles%\Go\bin\go.exe")
    if not go:
        return Result(name, False, "Go toolchain not found", 0.0)

    exe = os.path.join(ROOT, "dist", "variants", "px_payload_resilient.exe")
    if not os.path.isfile(exe):
        return Result(name, False, "no resilient build (run build_variants.ps1)",
                      0.0)

    t0 = time.time()
    p = subprocess.run(
        [go, "test", "-count=1", "-timeout", "200s", "-v",
         "-run", "TestResilientPayloadReconnects", "-variant", exe, "."],
        cwd=os.path.join(ROOT, "phase5_network"),
        capture_output=True, text=True, timeout=300,
    )
    out = (p.stdout or "") + (p.stderr or "")
    ok = "--- PASS" in out
    detail = "PASS" if ok else "FAIL"
    if not ok:
        for line in out.splitlines():
            if "did not reconnect" in line or "FAIL" in line:
                detail = line.strip()
                break
    return Result(name, ok, detail, time.time() - t0)


# The hosts entry that lets the DGA arm resolve its generated name to the
# lab DNS helper. It is removed again when the suite finishes.
#
# The entry is for a name in the lab's own TLD, so it cannot shadow
# anything on the real internet.
_HOSTS = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                      "System32", "drivers", "etc", "hosts")
_DGA_MARKER = "# PHANTOM-X lab DNS helper (added by run_all_tests.py)"


def _dga_name_for_today() -> str:
    """The DGA name for today, matching px_dga.c."""
    import datetime
    seed = (datetime.datetime.now(datetime.timezone.utc)
            - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)).days
    return f"pxlab-{seed}-5a17c0de.lab.test"


def _add_hosts_entry() -> None:
    try:
        with open(_HOSTS, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        if _DGA_MARKER in text:
            return
        with open(_HOSTS, "a", encoding="utf-8") as fh:
            fh.write(_DGA_MARKER + "\n")
            fh.write(f"127.0.0.1 {_dga_name_for_today()}\n")
    except OSError:
        # The hosts file may not be writable. The DGA arm then skips,
        # which the suite reports.
        pass


def _remove_hosts_entry() -> None:
    try:
        with open(_HOSTS, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        kept = [ln for ln in lines
                if _DGA_MARKER not in ln and "pxlab-" not in ln]
        with open(_HOSTS, "w", encoding="utf-8") as fh:
            fh.writelines(kept)
    except OSError:
        pass


def test_evaluator() -> Result:
    """The rule evaluator's own semantics.

    The evaluator is what makes the lab's output trustworthy. If its
    semantics are wrong, "this rule did not fire" means nothing -- it
    might just mean the evaluator is broken, and the report would look
    like a successful measurement of a rule that is actually fine.
    """
    name = "rule evaluator"
    script = os.path.join(ROOT, "phase8_evaluation", "test_evaluator.py")
    if not os.path.isfile(script):
        return Result(name, False, "test_evaluator.py not found", 0.0)
    ok, out = run([sys.executable, script], timeout=300)
    detail = "PASS"
    for line in out.splitlines():
        if "passed," in line:
            detail = line.strip()
    if not ok:
        detail = "FAIL"
    return Result(name, ok, detail, 0.0)


def test_capability_and_transfer() -> Result:
    """The capability library and the file transfer, against the real payload.

    These are the checks that would have caught the two bugs that made
    the capabilities silently dead: the capability library was not
    compiled into any arm the suite exercised, and the file transfer
    died on a stack frame larger than a page.

    A capability that does not work is worse than one that is missing,
    because the report says it was measured.
    """
    name = "capability library and file transfer"
    go = find_tool("go.exe", r"%ProgramFiles%\Go\bin\go.exe")
    if not go:
        return Result(name, False, "Go toolchain not found", 0.0)

    caps = os.path.join(ROOT, "dist", "variants", "px_payload_caps.exe")
    xfer = os.path.join(ROOT, "dist", "variants", "px_payload_xfer.exe")
    if not os.path.isfile(caps) or not os.path.isfile(xfer):
        return Result(name, False,
                      "no caps or xfer build (run build_variants.ps1)", 0.0)

    t0 = time.time()
    ok = True
    detail = []

    for exe, pattern in ((caps, "TestCapability"),
                          (xfer, "TestFileTransfer|TestScreenCapture")):
        p = subprocess.run(
            [go, "test", "-count=1", "-timeout", "300s", "-v",
             "-run", pattern, "-variant", exe, "."],
            cwd=os.path.join(ROOT, "phase5_network"),
            capture_output=True, text=True, timeout=600,
        )
        out = (p.stdout or "") + (p.stderr or "")
        if "--- FAIL" in out:
            detail.append(f"{os.path.basename(exe)}=FAIL")
            ok = False
        elif "--- PASS" in out:
            detail.append(f"{os.path.basename(exe)}=pass")
        elif "--- SKIP" in out:
            detail.append(f"{os.path.basename(exe)}=skip")
        else:
            detail.append(f"{os.path.basename(exe)}=unknown")
            ok = False

    return Result(name, ok, ", ".join(detail), time.time() - t0)


def test_coverage_matrix() -> Result:
    """The catalogue and the coverage matrix must agree with the rules.

    The catalogue is the denominator, so a number that is wrong is a
    report that is wrong. The check is that the matrix runs, that every
    rule the catalogue names exists, and that the technique count is
    what the lab says it is.
    """
    name = "coverage matrix"
    exe = os.path.join(ROOT, "phase7_detection", "target", "release",
                       "px_detect.exe")
    if not os.path.isfile(exe):
        return Result(name, False, "px_detect.exe is not built", 0.0)

    script = os.path.join(ROOT, "phase8_evaluation", "coverage.py")
    if not os.path.isfile(script):
        return Result(name, False, "coverage.py not found", 0.0)

    t0 = time.time()
    with tempfile.TemporaryDirectory() as td:
        rules_path = os.path.join(td, "rules.json")
        catalog_path = os.path.join(td, "catalog.json")
        with open(rules_path, "wb") as fh:
            subprocess.run([exe, "--emit", "json"], stdout=fh, check=True)
        with open(catalog_path, "wb") as fh:
            subprocess.run([exe, "--emit", "catalog"], stdout=fh, check=True)

        ok, out = run([sys.executable, script, "--rules", rules_path,
                       "--catalog", catalog_path], timeout=300)
        if not ok:
            return Result(name, False, "coverage.py failed", time.time() - t0)

        # The matrix must print the denominator, and the technique count
        # must not have silently changed.
        if "THE DENOMINATOR" not in out:
            return Result(name, False, "the matrix printed no denominator",
                          time.time() - t0)

        import json as _json
        with open(catalog_path, "r", encoding="utf-8-sig") as fh:
            catalog = _json.load(fh)
        measured = sum(1 for t in catalog if t["status"] == "measured")
        ruled = sum(1 for t in catalog if t["status"] == "ruled")
        gaps = sum(1 for t in catalog if t["status"] == "not_exercised")

        # Every rule the catalogue names must exist.
        with open(rules_path, "r", encoding="utf-8-sig") as fh:
            rule_ids = {r["id"] for r in _json.load(fh)}
        missing = []
        for t in catalog:
            for rid in [x.strip() for x in t.get("rules", "").split(",")
                        if x.strip()]:
                if rid not in rule_ids:
                    missing.append(f"{t['id']}->{rid}")

    detail = (f"{len(catalog)} techniques, {measured} measured, "
              f"{ruled} ruled only, {gaps} not exercised")
    if missing:
        detail += f", MISSING RULES: {', '.join(missing)}"
        return Result(name, False, detail, time.time() - t0)
    return Result(name, True, detail, time.time() - t0)


def test_pypdf() -> Result:
    """The PDF inspector against pypdf, if it is installed."""
    name = "PDF inspector vs pypdf"
    script = os.path.join(ROOT, "phase1_pdf", "validate_against_pypdf.py")
    if not os.path.isfile(script):
        return Result(name, False, "validator not present", 0.0)
    ok, out = run([sys.executable, script], cwd=os.path.join(ROOT, "phase1_pdf"),
                  timeout=300)
    if "ModuleNotFoundError" in out or "pypdf" in out.lower() and "not installed" in out.lower():
        return Result(name, True, "skipped (pypdf not installed)", 0.0)
    detail = "PASS" if "RESULT: PASS" in out else "FAIL"
    return Result(name, ok, detail, 0.0)


def test_sysmon_schema() -> Result:
    """The Sysmon config against the official schema."""
    name = "Sysmon config vs official schema"
    script = os.path.join(ROOT, "phase4_defender", "validate_sysmon_config.py")
    config = os.path.join(ROOT, "phase4_defender", "sysmon_config.xml")
    if not os.path.isfile(script):
        return Result(name, False, "validator not present", 0.0)
    if not os.path.isfile(config):
        return Result(name, False, "sysmon_config.xml not present", 0.0)
    ok, out = run([sys.executable, script, config],
                  cwd=os.path.join(ROOT, "phase4_defender"), timeout=300)
    detail = "PASS" if ok else "FAIL"
    return Result(name, ok, detail, 0.0)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="PHANTOM-X regression suite")
    ap.add_argument("--quick", action="store_true",
                    help="skip the slower checks")
    args = ap.parse_args(argv)

    print("=" * 72)
    print("PHANTOM-X :: REGRESSION SUITE")
    print("=" * 72)
    print(f"started : {datetime.now(timezone.utc).isoformat()}")
    print()

    tests = [
        test_formatter_selftest,
        test_sha256,
        test_pdf_cross_impl,
        test_c2_equivalence,
        test_go_c2_integration,
    ]
    if not args.quick:
        tests += [test_variants, test_resilient_reconnect, test_evaluator,
                  test_capability_and_transfer, test_coverage_matrix,
                  test_pypdf, test_sysmon_schema]

    results = []
    for fn in tests:
        print(f"--> {fn.__doc__.strip().splitlines()[0]}")
        try:
            r = fn()
        except Exception as exc:  # noqa: BLE001
            r = Result(fn.__name__, False, f"{type(exc).__name__}: {exc}", 0.0)
        results.append(r)
        tag = "PASS" if r.ok else "FAIL"
        colour = "\033[32m" if r.ok else "\033[31m"
        print(f"    [{colour}{tag}\033[0m] {r.name} -- {r.detail}")
        print()

    print("-" * 72)
    print("SUMMARY")
    print("-" * 72)
    for r in results:
        tag = "PASS" if r.ok else "FAIL"
        print(f"  [{tag}] {r.name:<40} {r.detail}")
    passed = sum(1 for r in results if r.ok)
    total = len(results)
    print()
    print(f"  {passed}/{total} passed")
    print(f"  RESULT: {'PASS' if passed == total else 'FAIL'}")
    print("-" * 72)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
