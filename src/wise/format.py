"""WISEPROOF-V1 line-oriented format per spec §31.3 (v0.1.1 hardened).

Canonical rules (STRICT):
  - UTF-8
  - MUST NOT begin with UTF-8 BOM (EF BB BF)              [C7]
  - First line exactly "WISEPROOF-V1\n"
  - Exactly one blank line "\n" after the header
  - Body lines: key=value\n
  - No leading/trailing ASCII whitespace on any line       [C3]
    (whitespace = U+0020 SPACE or U+0009 TAB only — no Unicode strip)
  - Values MUST NOT contain any control character          [C2]
    (U+0000–U+001F or U+007F)
  - No empty lines inside the body
  - Keys sorted by UTF-8 byte order on the encoded key     [C5]
  - Values raw UTF-8; MUST NOT contain "\n" or "="
  - File ends with "\n" after the last body line

Any violation -> INVALID_PROOF.
"""

from __future__ import annotations

from typing import Iterable

from . import WISE_PROOF_HEADER

UTF8_BOM = b"\xef\xbb\xbf"

# C2: explicit control-character set — U+0000..U+001F plus U+007F.
_CONTROL_ORDS = set(range(0x00, 0x20)) | {0x7F}

# C3: ASCII whitespace = SPACE (0x20) and TAB (0x09) only.
_ASCII_WS = (" ", "\t")


class FormatError(Exception):
    pass


def _validate_key(key: str) -> None:
    if key == "":
        raise FormatError("empty key")
    for ch in key:
        if ch == "\n" or ch == "=":
            raise FormatError(f"invalid character in key: {key!r}")
        # Keys may not contain ANY whitespace or control char.
        if ord(ch) <= 0x20 or ord(ch) == 0x7F:
            raise FormatError(f"invalid character in key: {key!r}")


def _validate_value(value: str) -> None:
    if "\n" in value:
        raise FormatError("value contains newline")
    if "=" in value:
        raise FormatError("value contains '='")
    # C2: reject any control character.
    for ch in value:
        if ord(ch) in _CONTROL_ORDS:
            raise FormatError(
                f"value contains control character U+{ord(ch):04X}"
            )
    # C3: explicit ASCII whitespace check (do NOT use .strip()).
    if value.startswith(_ASCII_WS) or value.endswith(_ASCII_WS):
        raise FormatError("value has leading/trailing ASCII whitespace")


def _byte_sort_key(k: str) -> bytes:
    """C5: sort keys by their UTF-8 byte sequence, not codepoint."""
    return k.encode("utf-8")


def encode(items: dict[str, str]) -> bytes:
    """Render a dict of key=value to canonical WISEPROOF-V1 bytes."""
    for k, v in items.items():
        _validate_key(k)
        _validate_value(v)
    sorted_keys = sorted(items.keys(), key=_byte_sort_key)
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
    # C7: reject UTF-8 BOM up front — same bytes must mean the same thing
    # to every conformant implementation.
    if raw.startswith(UTF8_BOM):
        raise FormatError("UTF-8 BOM not permitted")

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
        # C3: explicit ASCII-whitespace boundary check on every line.
        if ln.startswith(_ASCII_WS) or ln.endswith(_ASCII_WS):
            raise FormatError("line has leading/trailing ASCII whitespace")
        if "=" not in ln:
            raise FormatError(f"line missing '=': {ln!r}")
        key, _, value = ln.partition("=")
        _validate_key(key)
        _validate_value(value)
        if key in items:
            raise FormatError(f"duplicate key: {key}")
        items[key] = value
        seen_keys.append(key)

    # C5: keys must already be in UTF-8 byte order on the wire.
    if seen_keys != sorted(seen_keys, key=_byte_sort_key):
        raise FormatError("keys not in UTF-8 byte order")

    return items
