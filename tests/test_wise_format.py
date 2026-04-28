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
