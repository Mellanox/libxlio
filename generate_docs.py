#!/usr/bin/env python3
"""Generate XLIO configuration reference from JSON schema.

Pipeline:
  1. Parse ``xlio_config_schema.json`` into a flat list of Property objects
  2. Format each property as Markdown with type/constraint metadata
  3. Write the full reference to ``docs/xlio_config_reference.md``
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent

_SCHEMA_PATH = _REPO_ROOT / "src/core/config/descriptor_providers/xlio_config_schema.json"
_CONFIG_REF_PATH = _REPO_ROOT / "docs/xlio_config_reference.md"

_SIZE_SUFFIXES = ((1024**3, "GB"), (1024**2, "MB"), (1024, "KB"))


_MISSING: Any = object()
"""Sentinel for distinguishing 'no default in schema' from explicit null."""

# The schema must not use $ref, allOf, anyOf, or exclusive range keywords.
# Array-typed parameters (e.g. "rules") are treated as leaf values — their
# "items" sub-schema is not traversed.  Only "properties" and "oneOf" are
# supported.
_UNSUPPORTED_KEYWORDS = frozenset(
    {"allOf", "anyOf", "$ref", "exclusiveMinimum", "exclusiveMaximum"}
)

# JSON Schema primitive types accepted by this generator.  Any other value
# (e.g. a typo like "integr") is rejected early rather than silently
# propagated into the output.
_VALID_SCHEMA_TYPES = frozenset(
    {"string", "integer", "number", "boolean", "array", "object", "null"}
)

# Matches an env-var name that is either bare or wrapped in paired
# Markdown bold (**…**).  Uses alternation so the bold markers must
# either both be present or both be absent.
_ENV_VAR_RE = re.compile(
    r"Maps to (?:\*\*([A-Z0-9_]+)\*\*|([A-Z0-9_]+)) environment variable"
)

# Matches the full "Maps to … environment variable." sentence (with optional
# trailing period and whitespace) so it can be stripped from the description
# when the env-var is rendered as a separate metadata line.
_STRIP_ENV_SENTENCE_RE = re.compile(
    r"Maps to (?:\*\*[A-Z0-9_]+\*\*|[A-Z0-9_]+) environment variable\.?\s*"
)

_BACKTICK_TOKEN_RE = re.compile(r"`([^`]+)`")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class GenerationError(Exception):
    """Raised when document generation encounters an unrecoverable problem."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class TypeVariant:
    """One type option (there may be several when ``oneOf`` is used)."""

    type: str
    enum: list[Any] | None = None
    minimum: int | float | None = None
    maximum: int | float | None = None
    pattern: str | None = None


@dataclass
class TypeInfo:
    """Aggregated type and constraint metadata for a parameter."""

    variants: list[TypeVariant] = field(default_factory=list)
    is_memory_size: bool = False
    is_power_of_2: bool = False


@dataclass
class Property:
    """A single leaf configuration parameter."""

    path: str
    description: str
    env_var: str | None
    default: Any
    type_info: TypeInfo

    @property
    def section(self) -> str:
        """Top-level group name (first dotted-path component)."""
        return self.path.split(".")[0]


@dataclass
class _XRefIndex:
    """Lookup structures for cross-reference linking."""

    full_paths: frozenset[str]
    leaf_to_path: dict[str, str | None]
    path_to_slug: dict[str, str]


# ---------------------------------------------------------------------------
# Schema parsing
# ---------------------------------------------------------------------------


def _parse_schema(path: Path) -> list[Property]:
    """Read the JSON schema and return a sorted list of leaf properties."""
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GenerationError(f"Invalid JSON in {path}: {exc}") from exc

    seen: set[str] = set()
    properties: list[Property] = []
    for section_name, section_data in schema.get("properties", {}).items():
        if not isinstance(section_data, dict):
            continue
        properties.extend(_walk(section_data, section_name, seen))

    properties.sort(key=lambda p: p.path)
    return properties


def _walk(node: dict, prefix: str, seen: set[str]) -> Iterator[Property]:
    """Yield leaf Property objects from a schema node, recursing into groups.

    *seen* is updated in-place to track visited dotted paths.
    """
    for name, data in node.get("properties", {}).items():
        # Guard: the schema has "additionalProperties": false placed
        # *inside* a "properties" dict (e.g. performance.rings.tx) rather
        # than as a sibling keyword.  Skip these non-dict entries.
        if not isinstance(data, dict):
            continue
        dotted = f"{prefix}.{name}"
        if dotted in seen:
            continue
        seen.add(dotted)

        for kw in _UNSUPPORTED_KEYWORDS:
            if kw in data:
                raise GenerationError(
                    f"Unsupported JSON Schema keyword '{kw}' in "
                    f"property '{dotted}'. Only 'properties' and "
                    f"'oneOf' are supported."
                )

        # Nodes with child "properties" (and no oneOf) are intermediate
        # groups — recurse.  Checking for the "properties" key instead of
        # 'type == "object"' avoids silently treating a group node as a
        # leaf when the schema omits the explicit type annotation.
        child_props = data.get("properties")
        has_children = isinstance(child_props, dict) and child_props
        has_one_of = "oneOf" in data
        if has_children and has_one_of:
            log.warning(
                "Property '%s' has both 'properties' and 'oneOf'; "
                "treating as leaf (child properties ignored).",
                dotted,
            )
        if has_children and not has_one_of:
            yield from _walk(data, dotted, seen)
        else:
            yield _build_property(dotted, data)


def _build_property(path: str, data: dict) -> Property:
    """Construct a Property from a JSON-schema leaf node."""
    description = data.get("description", "")
    return Property(
        path=path,
        description=description,
        env_var=_extract_env_var(description),
        default=_resolve_default(data, path),
        type_info=_extract_type_info(data, path),
    )


def _extract_env_var(description: str) -> str | None:
    """Return the ``XLIO_*`` env-var name from *description*, or ``None``.

    Handles env-var names containing digits (e.g. ``XLIO_TCP_3T_RULES``)
    and descriptions where the name is already Markdown-bolded with ``**``.
    """
    match = _ENV_VAR_RE.search(description)
    return (match.group(1) or match.group(2)) if match else None


def _resolve_default(data: dict, path: str) -> Any:
    """Return the default value, searching ``oneOf`` options when needed.

    Returns the ``_MISSING`` sentinel (not ``None``) when no default is
    declared, so that an explicit ``"default": null`` in the schema is
    distinguishable from a missing default.

    Raises :class:`GenerationError` if the resolved default is ``None``
    (explicit null), which is not currently supported.

    When multiple ``oneOf`` branches each declare a default, the first one
    is used.  This is normal for multi-type parameters (e.g. integer bytes
    and string with suffix representing the same value).
    """
    if "default" in data:
        found = data["default"]
    else:
        found = next(
            (opt["default"] for opt in data.get("oneOf", []) if "default" in opt),
            _MISSING,
        )

    if found is None:
        raise GenerationError(
            f"Parameter '{path}' has an explicit null default. "
            "Null defaults are not currently supported — use a meaningful "
            "value or omit the default entirely."
        )
    return found


def _extract_type_info(data: dict, path: str) -> TypeInfo:
    """Build a TypeInfo from the raw schema node."""

    def _variant(node: dict[str, Any]) -> TypeVariant:
        raw_type = node.get("type")
        if raw_type is None:
            raise GenerationError(
                f"Parameter '{path}': schema node has no 'type' field."
            )
        if raw_type not in _VALID_SCHEMA_TYPES:
            raise GenerationError(
                f"Parameter '{path}': unrecognised JSON Schema type "
                f"'{raw_type}'. Expected one of: "
                f"{', '.join(sorted(_VALID_SCHEMA_TYPES))}."
            )
        return TypeVariant(
            type=raw_type,
            enum=node.get("enum"),
            minimum=node.get("minimum"),
            maximum=node.get("maximum"),
            pattern=node.get("pattern"),
        )

    if "oneOf" in data:
        if not data["oneOf"]:
            raise GenerationError(
                f"Parameter '{path}': 'oneOf' must not be empty."
            )
        variants = [_variant(opt) for opt in data["oneOf"]]
    else:
        variants = [_variant(data)]
    return TypeInfo(
        variants=variants,
        is_memory_size=data.get("x-memory-size", False),
        is_power_of_2=data.get("x-power-of-2-or-zero", False),
    )


# ---------------------------------------------------------------------------
# Cross-reference linking
# ---------------------------------------------------------------------------


def _build_xref_index(properties: list[Property]) -> _XRefIndex:
    """Build a lookup index for cross-reference linking.

    Full dotted paths are always linkable.  Leaf names (the last
    component) are linkable only when unambiguous (one parameter has
    that leaf name).  Ambiguous leaves are stored as ``None``.
    """
    full_paths = frozenset(p.path for p in properties)

    leaf_groups: dict[str, list[str]] = {}
    for p in properties:
        leaf = p.path.rsplit(".", 1)[-1]
        leaf_groups.setdefault(leaf, []).append(p.path)

    leaf_to_path = {
        leaf: paths[0] if len(paths) == 1 else None
        for leaf, paths in leaf_groups.items()
    }

    path_to_slug = {p.path: _gfm_heading_slug(p.path) for p in properties}

    return _XRefIndex(
        full_paths=full_paths,
        leaf_to_path=leaf_to_path,
        path_to_slug=path_to_slug,
    )


def _gfm_heading_slug(text: str) -> str:
    """Compute GitHub-Flavored Markdown heading anchor from *text*.

    Mirrors GitHub's algorithm: lowercase, keep word-characters / spaces /
    hyphens, replace spaces with hyphens.
    """
    slug = text.lower()
    slug = re.sub(r"[^\w\s-]", "", slug)
    return slug.strip().replace(" ", "-")


def _linkify_xrefs(text: str, xref: _XRefIndex, self_path: str) -> str:
    """Replace backticked parameter names with Markdown internal links.

    Only acts on backticked tokens that match a known parameter path
    (full dotted path or unambiguous leaf name).  Self-references are
    left as plain backticked text.
    """

    def _replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in xref.full_paths:
            target = name
        elif xref.leaf_to_path.get(name) is not None:
            target = xref.leaf_to_path[name]
        else:
            return match.group(0)

        if target == self_path:
            return match.group(0)

        slug = xref.path_to_slug[target]
        return f"[`{name}`](#{slug})"

    return _BACKTICK_TOKEN_RE.sub(_replace, text)


# ---------------------------------------------------------------------------
# Markdown formatting
# ---------------------------------------------------------------------------


def _format_reference_body(properties: list[Property], xref: _XRefIndex) -> str:
    """Return the Markdown body (section headers + parameter entries)."""
    parts: list[str] = []
    current_section: str | None = None

    for prop in properties:
        if prop.section != current_section:
            if current_section is not None:
                parts.append("---\n\n")
            parts.append(f"## {prop.section.upper()}\n\n")
            current_section = prop.section
        parts.append(_format_property(prop, xref))

    return "".join(parts)


def _format_property(prop: Property, xref: _XRefIndex) -> str:
    """Return one parameter rendered as a Markdown block with trailing newlines."""
    parts: list[str] = [f"### `{prop.path}`\n\n"]

    type_line = _format_type_line(prop.type_info)
    if prop.env_var:
        parts.append(type_line.rstrip("\n") + "\n>\n")
        parts.append(f"> **Maps to:** `{prop.env_var}`\n\n")
    else:
        parts.append(type_line)

    desc = prop.description
    if prop.env_var:
        desc = _STRIP_ENV_SENTENCE_RE.sub("", desc).strip()

    if desc:
        desc = _linkify_xrefs(desc, xref, prop.path)
        parts.append(f"{desc}\n\n")

    if prop.default is not _MISSING:
        default_str = _format_default_with_enum(prop.default, prop.type_info)
        parts.append(f"**Default:** `{default_str}`\n\n")

    return "".join(parts)


def _format_type_line(info: TypeInfo) -> str:
    """Return a Markdown blockquote line summarizing type and constraints."""
    # Special-case formatters expect exactly one integer and one string
    # variant (the two forms every dual-type schema parameter uses).
    # Fall through to the general formatter when neither matches.
    if info.is_memory_size and len(info.variants) == 2:
        line = _format_memory_size_type(info)
        if line:
            return line

    if len(info.variants) == 2:
        line = _format_paired_enum_type(info.variants)
        if line:
            return line

    return _format_general_type(info)


def _format_memory_size_type(info: TypeInfo) -> str | None:
    """Format a memory-size type (integer bytes | string with suffix).

    Returns ``None`` if the variants don't match the expected pattern.
    """
    int_v = _find_variant(info.variants, "integer")
    str_v = _find_variant(info.variants, "string")
    if not int_v or not str_v:
        return None

    range_parts: list[str] = []
    if int_v.minimum is not None:
        range_parts.append(f"min: {_humanize_bytes(int_v.minimum)}")
    if int_v.maximum is not None:
        range_parts.append(f"max: {_humanize_bytes(int_v.maximum)}")
    extra = f", {', '.join(range_parts)}" if range_parts else ""
    line = (
        f"> **Type:** integer (bytes{extra}) "
        f"or string with size suffix (B, KB, MB, GB)"
    )
    if info.is_power_of_2:
        line += " \u2014 must be a power of 2, or 0"
    return line + "\n\n"


def _format_paired_enum_type(variants: list[TypeVariant]) -> str | None:
    """Format paired integer/string enums (e.g. 0/"lwip", 1/"cubic").

    Returns ``None`` if the variants don't match the expected pattern.
    """
    int_v = _find_variant(variants, "integer", needs_enum=True)
    str_v = _find_variant(variants, "string", needs_enum=True)
    if not int_v or not str_v or len(int_v.enum) != len(str_v.enum):
        return None

    # Assumes integer and string enums are listed in corresponding
    # positional order (e.g. [0, 1, 2] pairs with ["lwip", "os", "cubic"]).
    pairs = [f'{i}/"{s}"' for i, s in zip(int_v.enum, str_v.enum)]
    return (
        f"> **Type:** integer or string\n>\n"
        f"> **Values:** {', '.join(pairs)}\n\n"
    )


def _format_general_type(info: TypeInfo) -> str:
    """Format type line for the general case (one or more variants)."""
    type_parts: list[str] = []
    for v in info.variants:
        constraints: list[str] = []

        if v.enum is not None:
            vals = ", ".join(
                f'"{x}"' if isinstance(x, str) else str(x) for x in v.enum
            )
            constraints.append(f"one of: {vals}")
        else:
            if v.minimum is not None and v.maximum is not None:
                constraints.append(f"range: {v.minimum} to {v.maximum}")
            elif v.minimum is not None:
                constraints.append(f"min: {v.minimum}")
            elif v.maximum is not None:
                constraints.append(f"max: {v.maximum}")

        if v.pattern is not None:
            constraints.append(f"pattern: `{v.pattern}`")

        if constraints:
            type_parts.append(f"{v.type} ({', '.join(constraints)})")
        else:
            type_parts.append(v.type)

    line = f"> **Type:** {' | '.join(type_parts)}"
    if info.is_power_of_2:
        line += " \u2014 must be a power of 2, or 0"
    return line + "\n\n"


def _find_variant(
    variants: list[TypeVariant],
    type_name: str,
    *,
    needs_enum: bool = False,
) -> TypeVariant | None:
    """Return the first variant matching *type_name* (optionally with an enum)."""
    for v in variants:
        if v.type == type_name and (not needs_enum or v.enum is not None):
            return v
    return None


def _format_default_with_enum(value: Any, type_info: TypeInfo) -> str:
    """Format a default, enriching paired integer/string enums with both forms.

    For parameters with paired integer and string enums (e.g. 0/"lwip",
    3/"system"), shows both: ``"system" (3)`` instead of bare ``3``.
    """
    fallback = _format_default(value, is_memory_size=type_info.is_memory_size)

    # bool is a subclass of int in Python; exclude it explicitly.
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and len(type_info.variants) == 2
    ):
        int_v = _find_variant(type_info.variants, "integer", needs_enum=True)
        str_v = _find_variant(type_info.variants, "string", needs_enum=True)
        if (
            int_v
            and str_v
            and len(int_v.enum) == len(str_v.enum)
            and value in int_v.enum
        ):
            idx = int_v.enum.index(value)
            return f'"{str_v.enum[idx]}" ({value})'

    return fallback


def _humanize_bytes(value: int) -> str:
    """Format an integer as a human-readable size (e.g. 262144 -> '256KB').

    Returns the plain decimal string when the value is not an exact
    multiple of a standard binary unit.
    """
    for divisor, suffix in _SIZE_SUFFIXES:
        if value >= divisor and value % divisor == 0:
            return f"{value // divisor}{suffix}"
    return str(value)


def _format_default(value: Any, *, is_memory_size: bool = False) -> str:
    """Human-readable string for a default value."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        # Only apply human-readable size suffixes (KB, MB, GB) to
        # parameters explicitly marked as memory sizes in the schema, so
        # that a count or duration that happens to equal 1048576 is not
        # misleadingly displayed as "1MB".
        if is_memory_size:
            return _humanize_bytes(value)
        return str(value)
    if isinstance(value, float):
        return f"{value:g}"
    if isinstance(value, str):
        return value if value else '""'
    return json.dumps(value)


# ---------------------------------------------------------------------------
# File writers
# ---------------------------------------------------------------------------


def _build_reference_text(body: str, param_count: int) -> str:
    """Return the complete configuration reference Markdown content."""
    header = (
        "# XLIO Configuration Reference\n\n"
        f"This file documents all {param_count} XLIO runtime configuration "
        "parameters with their types, defaults, environment variables, "
        "and constraints.\n\n"
        "> **Auto-generated** from the JSON schema by `generate_docs.py`. "
        "Do not edit manually.\n\n"
    )
    return header + body


def _write_config_reference(path: Path, body: str, param_count: int) -> None:
    """Write the standalone configuration reference Markdown file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_build_reference_text(body, param_count), encoding="utf-8")


# ---------------------------------------------------------------------------
# Check mode
# ---------------------------------------------------------------------------


def _check_stale(path: Path, body: str, param_count: int) -> None:
    """Raise :class:`GenerationError` if the config reference is stale or missing."""
    expected = _build_reference_text(body, param_count)

    if not path.exists():
        raise GenerationError(
            f"Missing {path}. Re-run generate_docs.py to generate."
        )
    if path.read_text(encoding="utf-8") != expected:
        raise GenerationError(
            f"Stale {path}. Re-run generate_docs.py to update."
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Parse schema and generate configuration reference file."""
    parser = argparse.ArgumentParser(
        description="Generate XLIO configuration reference from JSON schema.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit with code 1 if output files would change (useful for CI).",
    )
    parser.add_argument(
        "-s",
        "--schema",
        type=Path,
        default=_SCHEMA_PATH,
        help=f"Input schema path (default: {_SCHEMA_PATH.relative_to(_REPO_ROOT)}).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=_CONFIG_REF_PATH,
        help=f"Output path for the config reference (default: {_CONFIG_REF_PATH.relative_to(_REPO_ROOT)}).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        format="%(levelname)s: %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    if not args.schema.exists():
        raise GenerationError(f"Schema file not found: {args.schema}")

    properties = _parse_schema(args.schema)
    if not properties:
        raise GenerationError(
            f"Schema at {args.schema} produced zero parameters. "
            "Check that the file has a top-level 'properties' object."
        )

    param_count = len(properties)
    xref_index = _build_xref_index(properties)
    body = _format_reference_body(properties, xref_index)

    if args.check:
        _check_stale(args.output, body, param_count)
        log.info("All output files are up to date.")
        return

    _write_config_reference(args.output, body, param_count)
    log.info("Written %s (%d parameters)", args.output, param_count)


def _cli() -> None:
    """CLI entry point with error handling."""
    try:
        main()
    except (GenerationError, OSError) as exc:
        sys.exit(f"Error: {exc}")
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        log.debug("Schema structure error", exc_info=True)
        sys.exit(
            f"Error: unexpected schema structure: {exc}\n"
            "  (re-run with --verbose for full traceback)"
        )


if __name__ == "__main__":
    _cli()
