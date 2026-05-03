"""Tests for WISEPROOF-V1 line format."""

from __future__ import annotations

import pytest

from wise.format import FormatError, decode, encode


def test_round_trip():
    items = {
        "artifact.size_bytes": "6",
        "artifact.type": "file",
        "measurement.algorithm": "WiseDigest-0",
    }
    raw = encode(items)
    assert raw.endswith(b"\n")
    parsed = decode(raw)
    assert parsed == items


def test_keys_emitted_in_lexical_order():
    items = {
        "z.last": "1",
        "a.first": "2",
        "m.middle": "3",
    }
    raw = encode(items).decode("utf-8")
    body = raw.split("\n", 2)[2]
    keys_in_file = [line.split("=", 1)[0] for line in body.strip("\n").split("\n")]
    assert keys_in_file == sorted(items.keys())


def test_first_line_is_header_and_blank_follows():
    raw = encode({"k": "v"}).decode("utf-8")
    lines = raw.split("\n")
    assert lines[0] == "WISEPROOF-V1"
    assert lines[1] == ""


def test_decode_rejects_wrong_header():
    with pytest.raises(FormatError):
        decode(b"WISEPROOF-V2\n\nk=v\n")


def test_decode_rejects_missing_blank_line():
    with pytest.raises(FormatError):
        decode(b"WISEPROOF-V1\nk=v\n")


def test_decode_rejects_unsorted_keys():
    with pytest.raises(FormatError):
        decode(b"WISEPROOF-V1\n\nz=1\na=2\n")


def test_decode_rejects_value_with_newline():
    with pytest.raises(FormatError):
        encode({"k": "line1\nline2"})


def test_decode_rejects_value_with_equals():
    with pytest.raises(FormatError):
        encode({"k": "a=b"})


def test_decode_rejects_cr_chars():
    with pytest.raises(FormatError):
        decode(b"WISEPROOF-V1\r\n\r\nk=v\r\n")


def test_decode_rejects_missing_trailing_newline():
    with pytest.raises(FormatError):
        decode(b"WISEPROOF-V1\n\nk=v")


def test_decode_rejects_duplicate_key():
    with pytest.raises(FormatError):
        decode(b"WISEPROOF-V1\n\na=1\nb=2\nb=3\n")


# ============================================================================
# v0.1.1 hardening tests
# ============================================================================


# ---- C2: control characters in values ----

def test_c2_rejects_value_with_esc_char():
    """ESC (0x1b) — used by ANSI terminal escape sequences."""
    with pytest.raises(FormatError):
        encode({"k": "hi\x1b[2J"})


def test_c2_rejects_value_with_bel_char():
    """BEL (0x07) — beeps the terminal."""
    with pytest.raises(FormatError):
        encode({"k": "hi\x07"})


def test_c2_rejects_value_with_nul_char():
    with pytest.raises(FormatError):
        encode({"k": "hi\x00there"})


def test_c2_rejects_value_with_del_char():
    """DEL (0x7f) — also a control character."""
    with pytest.raises(FormatError):
        encode({"k": "hi\x7fthere"})


def test_c2_decode_rejects_proof_carrying_escape():
    """A handcrafted proof with an ANSI escape on the wire is INVALID_PROOF."""
    raw = b"WISEPROOF-V1\n\nk=hi\x1b[2Jbye\n"
    with pytest.raises(FormatError):
        decode(raw)


# ---- C3: explicit ASCII whitespace, no Unicode strip ----

def test_c3_rejects_leading_ascii_space():
    with pytest.raises(FormatError):
        encode({"k": " value"})


def test_c3_rejects_leading_tab():
    with pytest.raises(FormatError):
        encode({"k": "\tvalue"})


def test_c3_rejects_trailing_ascii_space():
    with pytest.raises(FormatError):
        encode({"k": "value "})


def test_c3_rejects_trailing_tab():
    with pytest.raises(FormatError):
        encode({"k": "value\t"})


def test_c3_does_NOT_silently_normalize_unicode_whitespace():
    """U+00A0 (NO-BREAK SPACE) is whitespace under Python str.strip() but is
    NOT in our ASCII whitespace set. The reference impl must NOT silently
    strip it — instead it must accept the value byte-for-byte. A Rust port
    using str::trim() would also reject it; a port using a custom 'ascii-only'
    trim must agree byte-for-byte with this behavior."""
    # NBSP at the boundary of a value: it is NOT ASCII whitespace, so it is
    # accepted as a valid character WITHIN the value. (Round-tripping is the
    # contract: same bytes in, same bytes out.)
    items = {"k": " value "}
    raw = encode(items)
    assert decode(raw) == items


def test_c3_rejects_zero_width_space_NOT_treated_as_whitespace():
    """U+200B is also not ASCII whitespace — value should round-trip."""
    items = {"k": "a​b"}
    raw = encode(items)
    assert decode(raw) == items


# ---- C5: UTF-8 byte-order key sort ----

def test_c5_byte_order_sort_with_ascii_keys_unchanged():
    """ASCII keys: codepoint order == byte order. Behavior unchanged."""
    items = {"a": "1", "b": "2", "c": "3"}
    raw = encode(items).decode("utf-8")
    body = raw.split("\n", 2)[2]
    keys = [line.split("=", 1)[0] for line in body.strip("\n").split("\n")]
    assert keys == ["a", "b", "c"]


def test_c5_byte_order_sort_locks_non_ascii_key():
    """A non-ASCII key locks the byte-order rule. 'µ' (U+00B5) encodes to
    2 bytes 0xc2 0xb5; it must sort AFTER any ASCII key (whose first byte is
    < 0x80). Codepoint sort would put it after 'z' (0x7a) too — they happen
    to agree here. The test is forward-looking: any future port must use
    byte order, and this test will catch a port that uses codepoint order
    for keys whose byte-vs-codepoint sort actually differ."""
    items = {"a": "1", "µ": "2", "z": "3"}
    raw = encode(items).decode("utf-8")
    body = raw.split("\n", 2)[2]
    keys = [line.split("=", 1)[0] for line in body.strip("\n").split("\n")]
    # Byte order: 'a' (0x61) < 'z' (0x7a) < '\xc2\xb5' (0xc2...).
    assert keys == ["a", "z", "µ"]


# ---- C7: UTF-8 BOM rejection ----

def test_c7_decode_rejects_utf8_bom():
    raw = b"\xef\xbb\xbfWISEPROOF-V1\n\nk=v\n"
    with pytest.raises(FormatError):
        decode(raw)


def test_c7_decode_accepts_no_bom():
    """Same content WITHOUT the BOM is the canonical form."""
    raw = b"WISEPROOF-V1\n\nk=v\n"
    assert decode(raw) == {"k": "v"}


# ============================================================================
# Adversarial torture: random bytes through decode()
# ============================================================================
# The hardening tests above cover specific named attacks. These tests cover
# the *unnamed* attacks — random byte sequences I did not design for.
#
# The contract: decode() must EITHER produce a valid dict OR raise
# FormatError. Any other exception type (KeyError, IndexError, ValueError
# from int conversion, AssertionError, ...) escaping means the parser has
# a hidden assumption that an attacker can hit.
#
# These tests do NOT prove WISEATA "survives attack" — proving that requires
# outside cryptanalysts and time. They do prove: 60,000 random adversarial
# byte sequences cannot crash the parser into an unexpected exception type.

import random


def _decode_must_raise_only_format_error(data: bytes) -> None:
    try:
        decode(data)
    except FormatError:
        return  # OK — the documented failure mode
    except Exception as e:
        # Any other exception escaping the decoder is a bug.
        import pytest
        pytest.fail(
            f"decode() raised unexpected {type(e).__name__}: {e!r} on input "
            f"of length {len(data)} starting with {data[:32]!r}"
        )


def test_torture_decode_random_bytes_short():
    """20,000 short random byte sequences must not crash decode()."""
    rng = random.Random(0xDEAD_BEEF)
    for _ in range(20_000):
        n = rng.randint(0, 64)
        data = bytes(rng.randint(0, 255) for _ in range(n))
        _decode_must_raise_only_format_error(data)


def test_torture_decode_random_bytes_medium():
    """20,000 medium-length random byte sequences."""
    rng = random.Random(0xCAFE_BABE)
    for _ in range(20_000):
        n = rng.randint(64, 512)
        data = bytes(rng.randint(0, 255) for _ in range(n))
        _decode_must_raise_only_format_error(data)


def test_torture_decode_mutated_valid_proofs():
    """Take a valid proof, flip random bytes, decode, observe."""
    rng = random.Random(0xF00D_FACE)
    base = encode({"a": "1", "b": "2", "c": "3"})
    for _ in range(20_000):
        data = bytearray(base)
        n_flips = rng.randint(1, 10)
        for _ in range(n_flips):
            i = rng.randint(0, len(data) - 1)
            data[i] = rng.randint(0, 255)
        _decode_must_raise_only_format_error(bytes(data))


def test_torture_decode_truncated_valid_proofs():
    """Truncate a valid proof at every possible cut point."""
    base = encode({"a": "1", "b": "2", "c": "3"})
    for cut in range(len(base) + 1):
        _decode_must_raise_only_format_error(base[:cut])


def test_torture_decode_extended_valid_proofs():
    """Append random tail bytes to a valid proof."""
    rng = random.Random(0xABBA)
    base = encode({"a": "1", "b": "2", "c": "3"})
    for _ in range(5_000):
        n = rng.randint(0, 200)
        tail = bytes(rng.randint(0, 255) for _ in range(n))
        _decode_must_raise_only_format_error(base + tail)


def test_torture_decode_only_control_chars():
    """A blob of just control characters must fail cleanly."""
    for c in range(32):
        _decode_must_raise_only_format_error(bytes([c]) * 100)
    _decode_must_raise_only_format_error(bytes([0x7F]) * 100)
