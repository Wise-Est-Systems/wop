"""Tests for WISE-DIGEST-0 and SHA-256 hashers."""

from __future__ import annotations

import hashlib

from spas.digest import WiseDigest0, digest_bytes, new_hasher


def test_wisedigest0_output_is_64_hex():
    h = digest_bytes(b"truth\n", "WISE-DIGEST-0")
    assert len(h) == 64
    int(h, 16)
    assert h == h.lower()


def test_wisedigest0_deterministic():
    a = digest_bytes(b"truth\n", "WISE-DIGEST-0")
    b = digest_bytes(b"truth\n", "WISE-DIGEST-0")
    assert a == b


def test_wisedigest0_streaming_equals_one_shot():
    one_shot = digest_bytes(b"truth\nmore\nbytes\n", "WISE-DIGEST-0")
    h = WiseDigest0()
    h.update(b"truth\n")
    h.update(b"more\n")
    h.update(b"bytes\n")
    assert h.hexdigest() == one_shot


def test_wisedigest0_empty_input_is_constant():
    a = digest_bytes(b"", "WISE-DIGEST-0")
    b = digest_bytes(b"", "WISE-DIGEST-0")
    assert a == b
    assert len(a) == 64


def test_wisedigest0_change_breaks_digest():
    a = digest_bytes(b"truth\n", "WISE-DIGEST-0")
    b = digest_bytes(b"truth\r\n", "WISE-DIGEST-0")
    assert a != b
    c = digest_bytes(b"truth", "WISE-DIGEST-0")
    assert a != c


def test_wisedigest0_length_absorption_separates_inputs():
    # Without length absorption, an attacker could pad to collide.
    # With it, "a" and "aa" must differ even if internal state aligned.
    assert digest_bytes(b"a", "WISE-DIGEST-0") != digest_bytes(b"aa", "WISE-DIGEST-0")
    assert digest_bytes(b"\x00", "WISE-DIGEST-0") != digest_bytes(b"\x00\x00", "WISE-DIGEST-0")


def test_sha256_matches_hashlib():
    h = new_hasher("SHA-256")
    h.update(b"truth\n")
    assert h.hexdigest() == hashlib.sha256(b"truth\n").hexdigest()
