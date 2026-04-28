"""WISEPROOF-V1 line-oriented format per spec §31.3.

Canonical rules (STRICT):
  - UTF-8
  - First line exactly "WISEPROOF-V1\n"
  - Exactly one blank line "\n" after the header
  - Body lines: key=value\n
  - No leading/trailing whitespace on any line
  - No empty lines inside the body
  - Keys sorted by pure lexical full-key order (Q18)
  - Values raw UTF-8; MUST NOT contain "\n" or "="
  - File ends with "\n" after the last body line

Any violation -> INVALID_PROOF.
"""

from __future__ import annotations

from typing import Iterable

from . import WISE_PROOF_HEADER


class FormatError(Exception):
    pass


def _validate_key(key: str) -> None:
    if key == "":
        raise FormatError("empty key")
    for ch in key:
        if ch == "\n" or ch == "=" or ch.isspace():
            raise FormatError(f"invalid character in key: {key!r}")


def _validate_value(value: str) -> None:
    if "\n" in value:
        raise FormatError("value contains newline")
    if "=" in value:
        raise FormatError("value contains '='")
    if value != value.strip():
        raise FormatError("value has leading or trailing whitespace")


def encode(items: dict[str, str]) -> bytes:
    """Render a dict of key=value to canonical WISEPROOF-V1 bytes."""
    for k, v in items.items():
        _validate_key(k)
        _validate_value(v)
    sorted_keys = sorted(items.keys())
    lines = [WISE_PROOF_HEADER, ""]
    for k in sorted_keys:
        lines.append(f"{k}={items[k]}")
    text = "\n".join(lines) + "\n"
    return text.encode("utf-8")


def encode_subset(items: dict[str, str], keys: Iterable[str]) -> bytes:
    """Render a strict subset of items in canonical form (for id digests)."""
    keep = {k: items[k] for k in keys if k in items}
    return encode(keep)


def decode(raw: bytes) -> dict[str, str]:
    """Parse canonical WISEPROOF-V1 bytes back to a dict.

    Raises FormatError on any deviation from the canonical formatting rules.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise FormatError(f"not valid UTF-8: {e}") from e

    if not text.endswith("\n"):
        raise FormatError("file does not end with newline")
    if "\r" in text:
        raise FormatError("CR characters not permitted")

    # Split keeping no trailing empty element from the final \n.
    lines = text[:-1].split("\n")

    if len(lines) < 2:
        raise FormatError("file too short")
    if lines[0] != WISE_PROOF_HEADER:
        raise FormatError(f"expected header {WISE_PROOF_HEADER!r}")
    if lines[1] != "":
        raise FormatError("missing blank line after header")

    body = lines[2:]
    if not body:
        raise FormatError("empty body")
    items: dict[str, str] = {}
    seen_keys: list[str] = []
    for ln in body:
        if ln == "":
            raise FormatError("empty line inside body")
        if ln != ln.strip():
            raise FormatError("line has leading/trailing whitespace")
        if "=" not in ln:
            raise FormatError(f"line missing '=': {ln!r}")
        key, _, value = ln.partition("=")
        _validate_key(key)
        _validate_value(value)
        if key in items:
            raise FormatError(f"duplicate key: {key}")
        items[key] = value
        seen_keys.append(key)

    if seen_keys != sorted(seen_keys):
        raise FormatError("keys not in lexical order")

    return items
