#!/usr/bin/env python3
from __future__ import annotations

"""Validate tuning report reference document against source code.

Run as: python tests/validate_tuning_report_reference.py
Exit code 0 = all checks pass, non-zero = drift detected.

Checks:
1. Code → Doc: Every WARNING in tuning_report_printer.cpp has a troubleshooting rule
2. Doc → Code: Every troubleshooting rule WARNING has a corresponding code WARNING
3. Config knob coverage: every knob in doc body is in Config Knob Quick Reference
4. Schema accuracy: every Quick Reference knob exists in xlio_config_schema.json
5. Config namespace coverage: schema top-level keys match the extraction filter
6. Scenario field names: field names in scenario snippets exist in the source

Known limitations:
- sw_rx_packets_dropped and sw_rx_bytes_dropped share identical WARNING text
  ("non-zero drops"), producing 20 unique phrases from 21 WARNINGs. Both are
  covered under the same "Software RX drops" troubleshooting rule, so
  individual WARNING-level coverage is guaranteed by the doc structure but
  not by this validator's phrase matching.
- Profile settings table values are not validated against profile definitions.
  Profile changes require manual review of the table in the analysis guide.
"""

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PRINTER_CPP = REPO_ROOT / "src/core/tuning_report_printer.cpp"
SCHEMA_JSON = REPO_ROOT / "src/core/config/descriptor_providers/xlio_config_schema.json"
REFERENCE_MD = REPO_ROOT / "docs/xlio_tuning_report_reference.md"


def load_schema_top_level_keys(schema_path: Path) -> set[str]:
    """Extract top-level config namespace keys from the JSON schema.

    These are the valid prefixes for config knob dotted paths (e.g., 'core',
    'performance', 'network'). Dynamically derived so new namespaces are
    automatically included.
    """
    schema = json.loads(schema_path.read_text())
    return set(schema.get("properties", {}).keys())


def extract_warning_phrases_from_code(cpp_path: Path) -> set[str]:
    """Extract distinctive English phrases from WARNING messages in C++ source.

    WARNING messages contain printf format specifiers (%.0f%%, PRIu64) that
    don't appear in the documentation. This extracts the constant English
    text (runs of 2+ words) which serves as a matchable signature.

    Known dedup: sw_rx_packets_dropped and sw_rx_bytes_dropped both produce
    "non-zero drops", yielding 20 unique phrases from 21 WARNING conditions.
    """
    content = cpp_path.read_text()
    phrases = set()
    for line in content.splitlines():
        if "# WARNING:" not in line:
            continue
        match = re.search(r"# WARNING:\s*(.*)", line)
        if not match:
            continue
        raw = match.group(1)
        for m in re.finditer(r"[a-zA-Z][a-zA-Z\s\->()/]+[a-zA-Z)]", raw):
            phrase = m.group().strip()
            words = phrase.split()
            if len(words) >= 2:
                phrases.add(" ".join(words).lower())
    return phrases


def extract_warning_phrases_from_doc(md_path: Path) -> set[str]:
    """Extract WARNING phrases from the doc's **WARNING:** lines.

    These are the signatures the doc claims to cover. Used for the reverse
    check (doc → code) to detect orphaned troubleshooting rules.
    """
    content = md_path.read_text()
    phrases = set()
    for match in re.finditer(r"# WARNING:\s*([^`\n]+)", content):
        raw = match.group(1).strip().rstrip("`")
        for m in re.finditer(r"[a-zA-Z][a-zA-Z\s\->()/]+[a-zA-Z)]", raw):
            phrase = m.group().strip()
            words = phrase.split()
            if len(words) >= 2:
                phrases.add(" ".join(words).lower())
    return phrases


def strip_fenced_code_blocks(text: str) -> str:
    """Remove fenced code blocks (``` ... ```) from markdown text.

    This prevents headings inside code blocks (e.g., ## Runtime Stats in
    scenario snippets) from being treated as section boundaries.
    """
    return re.sub(r"```[^\n]*\n.*?\n```", "", text, flags=re.DOTALL)


def get_troubleshooting_section(md_path: Path) -> str:
    """Extract the Troubleshooting Rules section text (lowercased).

    Code blocks are stripped first to avoid false section boundaries from
    headings inside fenced code blocks.
    """
    content = strip_fenced_code_blocks(md_path.read_text())
    match = re.search(
        r"## Troubleshooting Rules\n(.*?)(?=\n## [A-Z]|\Z)",
        content, re.DOTALL,
    )
    return match.group(1).lower() if match else ""


def extract_config_knobs_from_doc(md_path: Path, valid_prefixes: set[str]) -> set[str]:
    """Extract config knob dotted paths from the full document.

    Only matches paths starting with schema-derived top-level namespaces
    to avoid false positives like 'auto', 'lwip', 'true', etc.
    """
    content = md_path.read_text()
    prefix_tuple = tuple(p + "." for p in valid_prefixes)
    pattern = r"`([a-z][a-z0-9_.]+\.[a-z][a-z0-9_.]+)`"
    return {
        m
        for m in re.findall(pattern, content)
        if any(m.startswith(p) for p in prefix_tuple)
    }


def extract_config_knobs_from_quick_ref(md_path: Path) -> set[str]:
    """Extract config knob paths from Config Knob Quick Reference tables.

    Only extracts from the first column of markdown tables (knob name column).
    """
    content = md_path.read_text()
    match = re.search(
        r"## Config Knob Quick Reference\n(.*?)(?=\n## |\Z)",
        content, re.DOTALL,
    )
    if not match:
        return set()
    section = match.group(1)
    knobs = set()
    for line in section.splitlines():
        m = re.match(r"\| `([a-z][a-z0-9_.]+\.[a-z][a-z0-9_.]+)` \|", line)
        if m:
            knobs.add(m.group(1))
    return knobs


def extract_field_names_from_scenarios(md_path: Path) -> set[str]:
    """Extract report field names used in scenario snippet code blocks.

    Matches field names in the format '  field_name: value' inside fenced
    code blocks within the Scenario Snippets section.
    """
    content = md_path.read_text()
    match = re.search(
        r"## Scenario Snippets\n(.*?)(?=\n## [A-Z]|\Z)",
        content, re.DOTALL,
    )
    if not match:
        return set()
    section = match.group(1)
    fields = set()
    in_code_block = False
    for line in section.splitlines():
        if line.startswith("```"):
            in_code_block = not in_code_block
            continue
        if in_code_block:
            m = re.match(r"\s+([a-z][a-z0-9_]+):\s", line)
            if m:
                field = m.group(1)
                if field not in ("default", "key", "value"):
                    fields.add(field)
    return fields


def extract_field_names_from_code(cpp_path: Path) -> set[str]:
    """Extract report field names from fprintf calls in the printer source.

    Matches patterns like fprintf(f, "  field_name: ..." which are the
    field output lines in the report.
    """
    content = cpp_path.read_text()
    fields = set()
    for m in re.finditer(r'fprintf\(f,\s*"  ([a-z][a-z0-9_]+):', content):
        fields.add(m.group(1))
    return fields


def resolve_schema_path(schema: dict, dotted_path: str):
    """Walk nested JSON schema 'properties' to resolve a dotted config path.

    Returns the leaf schema node if found, or None if the path doesn't exist.
    """
    parts = dotted_path.split(".")
    node = schema
    for part in parts:
        props = node.get("properties", {})
        if part not in props:
            return None
        node = props[part]
    return node


def extract_schema_default(node: dict):
    """Extract the default value from a schema node.

    Handles 'oneOf' schemas (where default may be in the first variant)
    and direct 'default' fields.
    """
    if "default" in node:
        return node["default"]
    if "oneOf" in node:
        for variant in node["oneOf"]:
            if "default" in variant:
                return variant["default"]
    return None


def main():
    errors = []
    schema = json.loads(SCHEMA_JSON.read_text())
    schema_top_keys = load_schema_top_level_keys(SCHEMA_JSON)

    # Check 1: Code → Doc — every code WARNING phrase must appear
    # somewhere in the Troubleshooting Rules section of the doc
    code_phrases = extract_warning_phrases_from_code(PRINTER_CPP)
    rules_text = get_troubleshooting_section(REFERENCE_MD)
    for phrase in sorted(code_phrases):
        if phrase not in rules_text:
            errors.append(f"WARNING phrase from code not in troubleshooting rules: '{phrase}'")

    # Check 2: Doc → Code — every doc WARNING phrase must correspond to
    # at least one code WARNING phrase (catches orphaned rules).
    # Uses substring matching because doc placeholders (<N>, <pct>) and
    # C string literal splits cause exact-match failures.
    doc_warning_phrases = extract_warning_phrases_from_doc(REFERENCE_MD)
    for doc_phrase in sorted(doc_warning_phrases):
        if not any(cp in doc_phrase or doc_phrase in cp for cp in code_phrases):
            errors.append(f"Orphaned troubleshooting rule — WARNING not in code: '{doc_phrase}'")

    # Check 3: Config knob coverage — every config knob referenced in the
    # doc body must appear in the Config Knob Quick Reference section
    doc_knobs = extract_config_knobs_from_doc(REFERENCE_MD, schema_top_keys)
    ref_knobs = extract_config_knobs_from_quick_ref(REFERENCE_MD)
    for knob in sorted(doc_knobs):
        if knob not in ref_knobs:
            errors.append(f"Config knob in doc but not in Quick Reference: {knob}")

    # Check 4: Schema accuracy — every Quick Reference knob must exist
    # in the JSON schema with a reachable default value
    for knob in sorted(ref_knobs):
        node = resolve_schema_path(schema, knob)
        if node is None:
            errors.append(f"Config knob not found in schema: {knob}")
        else:
            default = extract_schema_default(node)
            if default is None:
                errors.append(f"Config knob has no default in schema: {knob}")

    # Check 5: Config namespace coverage — verify the schema hasn't gained
    # new top-level keys that the knob extractor would silently skip
    doc_prefixes = {k.split(".")[0] for k in doc_knobs | ref_knobs}
    for key in sorted(schema_top_keys):
        if key not in doc_prefixes:
            errors.append(
                f"Schema top-level namespace '{key}' has no config knobs in doc "
                f"(new namespace? update doc if it contains tuning-relevant knobs)"
            )

    # Check 6: Scenario field names — verify field names used in scenario
    # snippets exist in the printer source
    scenario_fields = extract_field_names_from_scenarios(REFERENCE_MD)
    code_fields = extract_field_names_from_code(PRINTER_CPP)
    # Some scenario fields use dynamic names (buffer_pool_*, hugepages_*)
    # or section headers — filter to static field names only
    for field in sorted(scenario_fields):
        if field in code_fields:
            continue
        # Allow dynamic field patterns
        if any(
            re.match(pat, field)
            for pat in [
                r"buffer_pool_\w+",
                r"hugepages_\w+",
                r"nic_device",
                r"ring_total_\w+",
            ]
        ):
            continue
        errors.append(f"Scenario field name not found in printer source: '{field}'")

    if errors:
        print(f"FAIL: {len(errors)} validation errors:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("PASS: Tuning report reference document is in sync with code.")
        sys.exit(0)


if __name__ == "__main__":
    main()
