#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHANTOM-X :: Phase 4 support -- Sysmon configuration validator
================================================================================
validate_sysmon_config.py -- Validate a Sysmon XML configuration against the
official Sysmon schema manifest BEFORE deploying it to the research VM.

WHY
    Sysmon rejects a bad configuration with runtime errors that are easy to
    misread ("Failed to convert EventFiltering nodes"), and some mistakes are
    silent -- a rule that never matches logs nothing and looks like a quiet
    system. Validating offline turns guesswork into a fact.

    The manifest is the authoritative list of event types, their field names,
    and the legal condition operators. It is what `sysmon.exe -s` prints.

SCHEMA SOURCE
    xsd_schema/v4_90_schema.xsd from the public 'whit3rabbit/sysmon-archive'
    repository, which mirrors the schema embedded in the official Sysmon
    binaries. A copy is kept next to this script as
    'sysmon_v4_90_schema.xsd'.

    NOTE: the archived copy shipped with one malformed XML comment
    ('<!- -' instead of '<!--'). It is patched on first use; the patch is
    reported so the change is not silent.

USAGE
    python3 validate_sysmon_config.py sysmon_config.xml
    python3 validate_sysmon_config.py sysmon_config.xml --schema path/to.xsd

EXIT
    0 = configuration is valid
    1 = configuration has errors
    2 = could not run the validator
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import xml.etree.ElementTree as ET

XS = "{http://www.w3.org/2001/XMLSchema}"
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SCHEMA = os.path.join(HERE, "sysmon_v4_90_schema.xsd")

# The condition operators Sysmon accepts on filter fields.
# Derived from the schema manifest's ConditionType enumeration; this list is
# the fallback when the schema cannot be parsed.
FALLBACK_CONDITIONS = {
    "is", "is not", "contains", "contains any", "is any", "contains all",
    "excludes", "excludes any", "excludes all", "begin with", "not begin with",
    "end with", "not end with", "less than", "more than", "image", "any",
}


def conditions_from_schema(root) -> set[str]:
    """Extract the legal condition operators from the schema manifest."""
    found: set[str] = set()
    for st in root.iter(f"{XS}simpleType"):
        if st.get("name") == "ConditionType":
            found = {e.get("value") for e in st.iter(f"{XS}enumeration")
                     if e.get("value")}
    return found or set(FALLBACK_CONDITIONS)

# Global (non-event-filter) elements that may appear directly under <Sysmon>.
VALID_GLOBALS = {
    "HashAlgorithms", "ArchiveDirectory", "CaptureClipboard", "DnsLookup",
    "CheckRevocation", "FieldSizes", "RuleGroup", "EventFiltering",
    "ProcessAccessConfig", "PipeMonitoringConfig", "SysmonDrvConfig",
    "ArchiveDirectory",
}


def load_schema(path: str):
    """Load the manifest, patching the known upstream comment typo if needed."""
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    patched = 0
    if "<!- -" in raw:
        raw = raw.replace("<!- -", "<!--")
        patched = 1
    root = ET.fromstring(raw)
    return root, patched


def extract_manifest(root) -> dict:
    """Extract {event_type: set(field_names)} from the schema manifest."""
    events: dict[str, set[str]] = {}

    # The manifest models each event as a complexType whose elements are the
    # event's fields. Walk every complexType and record its child element
    # names, then map them to the event they belong to.
    type_to_name = {}
    for el in root.iter(f"{XS}element"):
        nm = el.get("name")
        if not nm:
            continue
        t = el.get("type")
        if t:
            type_to_name.setdefault(t, nm)

    for ct in root.iter(f"{XS}complexType"):
        ctname = ct.get("name", "")
        fields = set()
        for child in ct.iter(f"{XS}element"):
            cn = child.get("name")
            if cn:
                fields.add(cn)
        if not fields:
            continue
        # Heuristic mapping: manifest types are named after their event.
        for ev, t in type_to_name.items():
            if t == ctname or ctname.startswith(t) or t.startswith(ctname):
                events.setdefault(ev, set()).update(fields)
                break

    # Direct fallback: any element whose type contains a set of
    # capitalised field names is an event type.
    for el in root.iter(f"{XS}element"):
        nm = el.get("name")
        if not nm or nm in events:
            continue
        t = el.get("type")
        if not t:
            continue
        for ct in root.iter(f"{XS}complexType"):
            if ct.get("name") == t:
                fields = {c.get("name") for c in ct.iter(f"{XS}element") if c.get("name")}
                if fields and nm[0].isupper():
                    events.setdefault(nm, set()).update(fields)
    return events


def validate(config_path: str, schema_path: str) -> tuple[list, list, dict]:
    errors: list[str] = []
    warnings: list[str] = []
    info: dict = {}

    root, patched = load_schema(schema_path)
    if patched:
        warnings.append("upstream XSD had a malformed XML comment ('<!- -'); patched on load")
    events = extract_manifest(root)
    valid_conditions = conditions_from_schema(root)
    info["schema_event_types"] = len(events)
    info["valid_conditions"] = sorted(valid_conditions)

    try:
        cfg = ET.parse(config_path).getroot()
    except ET.ParseError as exc:
        errors.append(f"config is not well-formed XML: {exc}")
        return errors, warnings, info

    if cfg.tag != "Sysmon":
        errors.append(f"root element must be <Sysmon>, found <{cfg.tag}>")

    sv = cfg.get("schemaversion")
    info["schemaversion"] = sv
    if not sv:
        errors.append("root <Sysmon> is missing the schemaversion attribute")
    elif sv not in ("4.90", "4.91"):
        warnings.append(f"schemaversion {sv} is not one of the commonly deployed "
                        f"versions (4.90, 4.91)")

    ef = None
    for child in cfg:
        if child.tag == "EventFiltering":
            ef = child
        elif child.tag not in VALID_GLOBALS:
            warnings.append(f"unrecognised global element <{child.tag}>")

    if ef is None:
        errors.append("no <EventFiltering> block found")
        return errors, warnings, info

    seen_events: dict[str, list[str]] = {}
    rule_count = 0
    field_count = 0

    for rule in ef:
        ev = rule.tag
        rule_count += 1
        onmatch = rule.get("onmatch")
        default = rule.get("default")

        if onmatch is None and default is None:
            errors.append(f"<{ev}> has neither onmatch nor default "
                          f"(Sysmon requires onmatch)")
        if onmatch is not None and default is not None:
            errors.append(f"<{ev}> specifies both onmatch and default; "
                          f"Sysmon accepts only one")
        if onmatch is not None and onmatch not in ("include", "exclude"):
            errors.append(f"<{ev}> has invalid onmatch='{onmatch}' "
                          f"(must be 'include' or 'exclude')")

        seen_events.setdefault(ev, []).append(onmatch or "default")

        if ev not in events and events:
            warnings.append(f"event type <{ev}> is not listed in the schema manifest")

        ev_fields = events.get(ev, set())
        for cond in rule:
            fname = cond.tag
            field_count += 1
            ccond = cond.get("condition")
            if ccond is None:
                errors.append(f"<{ev}>/<{fname}> is missing the 'condition' attribute")
            elif ccond not in valid_conditions:
                errors.append(f"<{ev}>/<{fname}> has invalid condition "
                              f"'{ccond}'; valid: {sorted(valid_conditions)}")
            if ev_fields and fname not in ev_fields:
                warnings.append(f"<{ev}>/<{fname}>: field name not found in the "
                                f"schema manifest for this event")

    # Sysmon merges rule blocks that share an event type. An include block and
    # an exclude block for the SAME event is the classic way to end up with a
    # rule that silently never matches.
    for ev, modes in seen_events.items():
        if len(modes) > 1 and len(set(modes)) > 1:
            errors.append(f"<{ev}> has multiple rule blocks with conflicting "
                          f"onmatch values {sorted(set(modes))}; Sysmon merges "
                          f"same-event blocks and the result is unpredictable")

    info["rule_blocks"] = rule_count
    info["field_conditions"] = field_count
    info["event_types_used"] = sorted(seen_events.keys())
    return errors, warnings, info


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Validate a Sysmon XML configuration.")
    ap.add_argument("config")
    ap.add_argument("--schema", default=DEFAULT_SCHEMA)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    if not os.path.exists(args.schema):
        print(f"error: schema not found: {args.schema}", file=sys.stderr)
        return 2

    errors, warnings, info = validate(args.config, args.schema)

    if not args.quiet:
        print("=" * 70)
        print("SYSMON CONFIG VALIDATION")
        print("=" * 70)
        print(f"config          : {os.path.abspath(args.config)}")
        print(f"schema          : {os.path.abspath(args.schema)}")
        print(f"schemaversion   : {info.get('schemaversion')}")
        print(f"rule blocks     : {info.get('rule_blocks')}")
        print(f"field conditions: {info.get('field_conditions')}")
        print(f"event types     : {', '.join(info.get('event_types_used', []))}")
        print()

    for w in warnings:
        print(f"[WARN] {w}")
    for e in errors:
        print(f"[FAIL] {e}")

    if errors:
        print(f"\nRESULT: INVALID -- {len(errors)} error(s), {len(warnings)} warning(s)")
        return 1
    print(f"\nRESULT: VALID -- 0 errors, {len(warnings)} warning(s)")
    print("Deployment will still be confirmed on the VM by:")
    print("    sysmon64.exe -c sysmon_config.xml")
    print("Sysmon prints 'Configuration successfully updated' only on success.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
