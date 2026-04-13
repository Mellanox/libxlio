#!/usr/bin/env python3
from __future__ import annotations

"""Validate tuning report documentation against source code.

Run as: python tests/validate_tuning_report_docs.py
Exit code 0 = all checks pass, non-zero = drift detected.

Validates both documents:
  - docs/llm/xlio_tuning_report_guide.md  (LLM guide)
  - docs/xlio_tuning_report_reference.md  (human reference)

Guide checks:
1. Code → Doc: every WARNING in tuning_report_printer.cpp has a troubleshooting rule
2. Doc → Code: every troubleshooting rule WARNING has a corresponding code WARNING
3. Config knob coverage: every knob in doc body is in Config Knob Quick Reference
4. Schema accuracy: every Quick Reference knob exists in xlio_config_schema.json
5. Config namespace coverage: schema top-level keys match the extraction filter
   (namespaces in IGNORED_SCHEMA_NAMESPACES are skipped)
6. Scenario field names: field names in scenario snippets exist in the source

Reference checks:
7. WARNING coverage: every code WARNING phrase appears in the WARNING Reference
8. Field coverage: every report field name appears in the Field Reference
9. Config knob accuracy: Troubleshooting Quick Reference knobs exist in schema

Known limitations:
- sw_rx_packets_dropped and sw_rx_bytes_dropped share identical WARNING text
  ("non-zero drops"), producing 20 unique phrases from 21 WARNINGs. Both are
  covered under the same troubleshooting rule / table row.
- Profile settings table values are not validated against profile definitions.
"""

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PRINTER_CPP = REPO_ROOT / "src/core/tuning_report_printer.cpp"
SCHEMA_JSON = REPO_ROOT / "src/core/config/descriptor_providers/xlio_config_schema.json"
GUIDE_MD = REPO_ROOT / "docs/llm/xlio_tuning_report_guide.md"
REFERENCE_MD = REPO_ROOT / "docs/xlio_tuning_report_reference.md"

# Schema namespaces that are intentionally excluded from the tuning guide.
# Add entries here for namespaces that have no user-facing tuning relevance.
IGNORED_SCHEMA_NAMESPACES: set[str] = set()

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

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


def extract_field_names_from_code(cpp_path: Path) -> set[str]:
    """Extract report field names from fprintf calls in the printer source."""
    content = cpp_path.read_text()
    fields = set()
    for m in re.finditer(r'fprintf\(f,\s*"([a-z][a-z0-9_]+):', content):
        fields.add(m.group(1))
    return fields


def resolve_schema_path(schema: dict, dotted_path: str):
    """Walk nested JSON schema 'properties' to resolve a dotted config path."""
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


def load_schema_top_level_keys(schema_path: Path) -> set[str]:
    """Extract top-level config namespace keys from the JSON schema."""
    schema = json.loads(schema_path.read_text())
    return set(schema.get("properties", {}).keys())


# ---------------------------------------------------------------------------
# Guide-specific helpers
# ---------------------------------------------------------------------------

def extract_warning_phrases_from_doc(md_path: Path) -> set[str]:
    """Extract WARNING phrases from the doc's **WARNING:** lines.

    Used for the reverse check (doc → code) to detect orphaned rules.
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
    """Remove fenced code blocks (``` ... ```) from markdown text."""
    return re.sub(r"```[^\n]*\n.*?\n```", "", text, flags=re.DOTALL)


def get_troubleshooting_section(md_path: Path) -> str:
    """Extract the Troubleshooting Rules section text (lowercased)."""
    content = strip_fenced_code_blocks(md_path.read_text())
    match = re.search(
        r"## Troubleshooting Rules\n(.*?)(?=\n## [A-Z]|\Z)",
        content, re.DOTALL,
    )
    return match.group(1).lower() if match else ""


def extract_config_knobs_from_doc(md_path: Path, valid_prefixes: set[str]) -> set[str]:
    """Extract config knob dotted paths from the full document."""
    content = md_path.read_text()
    prefix_tuple = tuple(p + "." for p in valid_prefixes)
    pattern = r"`([a-z][a-z0-9_.]+\.[a-z][a-z0-9_.]+)`"
    return {
        m
        for m in re.findall(pattern, content)
        if any(m.startswith(p) for p in prefix_tuple)
    }


def extract_config_knobs_from_quick_ref(md_path: Path) -> set[str]:
    """Extract config knob paths from Config Knob Quick Reference tables."""
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

    Uses line-by-line parsing instead of a section regex because the
    scenario code blocks contain ``## Section`` headers that confuse
    regex-based section boundary detection.
    """
    lines = md_path.read_text().splitlines()
    in_section = False
    in_code_block = False
    fields: set[str] = set()
    for line in lines:
        if line.startswith("```"):
            in_code_block = not in_code_block
            continue
        if not in_code_block:
            if line.startswith("## Scenario Snippets"):
                in_section = True
                continue
            if in_section and re.match(r"## [A-Z]", line):
                break
        if in_section and in_code_block:
            m = re.match(r"\s+([a-z][a-z0-9_]+):\s", line)
            if m:
                field = m.group(1)
                if field not in ("default", "key", "value"):
                    fields.add(field)
    return fields


# ---------------------------------------------------------------------------
# Reference-specific helpers
# ---------------------------------------------------------------------------

def extract_warning_section_from_reference(md_path: Path) -> str:
    """Extract the WARNING Reference section text (lowercased)."""
    content = md_path.read_text()
    match = re.search(
        r"## WARNING Reference\n(.*?)(?=\n## [A-Z]|\Z)",
        content, re.DOTALL,
    )
    return match.group(1).lower() if match else ""


def extract_field_names_from_reference(md_path: Path) -> set[str]:
    """Extract field names from the Field Reference section tables."""
    content = md_path.read_text()
    match = re.search(
        r"## Field Reference\n(.*?)(?=\n## WARNING Reference|\Z)",
        content, re.DOTALL,
    )
    if not match:
        return set()
    section = match.group(1)
    fields = set()
    for m in re.finditer(r"\| `([a-z][a-z0-9_]+(?:<[^>]+>)?[a-z0-9_]*)` \|", section):
        fields.add(m.group(1))
    return fields


def extract_config_knobs_from_troubleshooting_qr(md_path: Path) -> set[str]:
    """Extract config knob paths from the Troubleshooting Quick Reference."""
    content = md_path.read_text()
    match = re.search(
        r"## Troubleshooting Quick Reference\n(.*?)(?=\n## |\Z)",
        content, re.DOTALL,
    )
    if not match:
        return set()
    section = match.group(1)
    return set(re.findall(r"`([a-z][a-z0-9_.]+\.[a-z][a-z0-9_.]+)`", section))


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_guide(
    code_phrases: set[str],
    code_fields: set[str],
    schema: dict,
    schema_top_keys: set[str],
) -> list[str]:
    """Validate the LLM guide against source code."""
    errors = []

    # 1. Code → Doc WARNING coverage
    rules_text = get_troubleshooting_section(GUIDE_MD)
    for phrase in sorted(code_phrases):
        if phrase not in rules_text:
            errors.append(f"[guide] WARNING phrase from code not in troubleshooting rules: '{phrase}'")

    # 2. Doc → Code WARNING coverage (orphaned rules)
    doc_warning_phrases = extract_warning_phrases_from_doc(GUIDE_MD)
    for doc_phrase in sorted(doc_warning_phrases):
        if not any(cp in doc_phrase or doc_phrase in cp for cp in code_phrases):
            errors.append(f"[guide] Orphaned troubleshooting rule — WARNING not in code: '{doc_phrase}'")

    # 3. Config knob body → Quick Reference coverage
    doc_knobs = extract_config_knobs_from_doc(GUIDE_MD, schema_top_keys)
    ref_knobs = extract_config_knobs_from_quick_ref(GUIDE_MD)
    for knob in sorted(doc_knobs):
        if knob not in ref_knobs:
            errors.append(f"[guide] Config knob in doc but not in Quick Reference: {knob}")

    # 4. Schema accuracy for Quick Reference knobs
    for knob in sorted(ref_knobs):
        node = resolve_schema_path(schema, knob)
        if node is None:
            errors.append(f"[guide] Config knob not found in schema: {knob}")
        else:
            default = extract_schema_default(node)
            if default is None:
                errors.append(f"[guide] Config knob has no default in schema: {knob}")

    # 5. Config namespace coverage
    doc_prefixes = {k.split(".")[0] for k in doc_knobs | ref_knobs}
    for key in sorted(schema_top_keys):
        if key in doc_prefixes or key in IGNORED_SCHEMA_NAMESPACES:
            continue
        errors.append(
            f"[guide] Schema namespace '{key}' has no config knobs in doc "
            f"(new namespace? update doc if it contains tuning-relevant knobs, "
            f"or add to IGNORED_SCHEMA_NAMESPACES in this script)"
        )

    # 6. Scenario field names
    scenario_fields = extract_field_names_from_scenarios(GUIDE_MD)
    for field in sorted(scenario_fields):
        if field in code_fields:
            continue
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
        errors.append(f"[guide] Scenario field name not found in printer source: '{field}'")

    return errors


def validate_reference(
    code_phrases: set[str],
    code_fields: set[str],
    schema: dict,
) -> list[str]:
    """Validate the human reference against source code."""
    errors = []

    # 7. WARNING coverage
    warning_section = extract_warning_section_from_reference(REFERENCE_MD)
    if not warning_section:
        errors.append("[reference] WARNING Reference section not found")
    else:
        for phrase in sorted(code_phrases):
            if phrase not in warning_section:
                errors.append(f"[reference] WARNING phrase from code not in reference: '{phrase}'")

    # 8. Field coverage
    ref_fields = extract_field_names_from_reference(REFERENCE_MD)
    dynamic_patterns = [
        r"buffer_pool_\w+_(size|alloc_failures)",
        r"hugepages_\w+_(total|free)",
    ]
    for field in sorted(code_fields):
        if field in ref_fields:
            continue
        if any(re.match(pat, field) for pat in dynamic_patterns):
            if any("<" in rf and field.split("_")[0] in rf for rf in ref_fields):
                continue
        errors.append(f"[reference] Report field not in Field Reference: '{field}'")

    # 9. Config knob accuracy
    ref_knobs = extract_config_knobs_from_troubleshooting_qr(REFERENCE_MD)
    for knob in sorted(ref_knobs):
        node = resolve_schema_path(schema, knob)
        if node is None:
            errors.append(f"[reference] Config knob not found in schema: {knob}")

    return errors


def main():
    schema = json.loads(SCHEMA_JSON.read_text())
    schema_top_keys = load_schema_top_level_keys(SCHEMA_JSON)
    code_phrases = extract_warning_phrases_from_code(PRINTER_CPP)
    code_fields = extract_field_names_from_code(PRINTER_CPP)

    errors = []
    errors.extend(validate_guide(code_phrases, code_fields, schema, schema_top_keys))
    errors.extend(validate_reference(code_phrases, code_fields, schema))

    if errors:
        print(f"FAIL: {len(errors)} validation errors:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("PASS: Both tuning report documents are in sync with code.")
        sys.exit(0)


if __name__ == "__main__":
    main()
