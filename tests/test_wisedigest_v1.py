"""WiseDigest-1 functional tests + locked reference vectors."""

from __future__ import annotations

import pytest

from wise.digest_v1 import ALGORITHM_NAME, WiseDigest1, digest_bytes, digest_stream


def test_algorithm_name():
    assert ALGORITHM_NAME == "WiseDigest-1"


def test_output_is_64_lowercase_hex():
    h = digest_bytes(b"truth\n")
    assert len(h) == 64
    int(h, 16)
    assert h == h.lower()


def test_deterministic():
    a = digest_bytes(b"truth\n")
    b = digest_bytes(b"truth\n")
    assert a == b


def test_streaming_equals_one_shot():
    one_shot = digest_bytes(b"truth\nmore\nbytes\n")
    h = WiseDigest1()
    h.update(b"truth\n")
    h.update(b"more\n")
    h.update(b"bytes\n")
    assert h.hexdigest() == one_shot


def test_streaming_arbitrary_partition():
    msg = b"the quick brown fox jumps over the lazy dog" * 7
    one_shot = digest_bytes(msg)
    for split in (1, 7, 31, 32, 33, 100, len(msg) - 1):
        h = WiseDigest1()
        h.update(msg[:split])
        h.update(msg[split:])
        assert h.hexdigest() == one_shot


def test_digest_stream_helper():
    chunks = [b"alpha", b"", b"beta", b"gamma"]
    one_shot = digest_bytes(b"".join(chunks))
    assert digest_stream(chunks) == one_shot


def test_update_after_finalize_raises():
    h = WiseDigest1()
    h.update(b"x")
    _ = h.hexdigest()
    with pytest.raises(RuntimeError):
        h.update(b"more")


def test_hexdigest_idempotent():
    h = WiseDigest1()
    h.update(b"truth\n")
    a = h.hexdigest()
    b = h.hexdigest()
    assert a == b


# -------- Locked reference vectors. --------
# These are normative for WiseDigest-1.0. Changing them requires a new
# algorithm version and a Lab notebook entry.

_LOCKED_VECTORS: list[tuple[str, bytes, str]] = [
    (
        "empty",
        b"",
        "83fdedf78ebe416c64f140f8480e55f5f302e1b79258f37833fd9288b2211e48",
    ),
    (
        "single_a",
        b"a",
        "3a129072a4d8aa950011cc22b957433f40be87302720c20ad4e2b3533c426022",
    ),
    (
        "double_a",
        b"aa",
        "97ea05405e692b56fc2dd1304fd574850901898c89483809f11aa6dc5fb76383",
    ),
    (
        "a_then_nul",
        b"a\x00",
        "f245c18066316a26517b92ceb490d51c8175a85cfa3a5ab521f597cd02d316f3",
    ),
    (
        "abc",
        b"abc",
        "7e2582aa328fd6d3b4b855680eeaa2587cced6d39be87570c662dbf60aace937",
    ),
    (
        "rate_minus_one",
        b"x" * 31,
        "a817a471e6e3738c6bb20ea289e1dd2d723398778d9c3982f735ab20e2950b35",
    ),
    (
        "rate_exact",
        b"x" * 32,
        "65f8fc3b53eccbcd4265ae88fb6d6fb46c8c4a4e1af3274443781d0f301964c6",
    ),
    (
        "rate_plus_one",
        b"x" * 33,
        "79851b32a1a1de2fe886772c77b0d78bc17b67ff6c0a5b4a773416115b84d8c2",
    ),
    (
        "rate_double",
        b"x" * 64,
        "5c02c4318e3ccf508c4c0aa3a739053d1bfe34dfcf73ecccb9383f321dbe7d6e",
    ),
    (
        "truth_newline",
        b"truth\n",
        "1cb228f3c35b471a9430ef4cd5802275bdb7302c24289d9d7186da7a0f6c8834",
    ),
    (
        "kilobyte_x",
        b"x" * 1024,
        "aaeafa051e12cb556fec4ca1fef92925a99913712f594ecc7f88d0b44e5fb712",
    ),
]


@pytest.mark.parametrize("label,data,expected", _LOCKED_VECTORS, ids=[v[0] for v in _LOCKED_VECTORS])
def test_locked_vector(label: str, data: bytes, expected: str):
    assert digest_bytes(data) == expected, f"vector {label!r} drifted"


def test_block_boundary_distinguishability():
    # Inputs of length 31/32/33 cross the rate boundary; all must be distinct.
    a = digest_bytes(b"x" * 31)
    b = digest_bytes(b"x" * 32)
    c = digest_bytes(b"x" * 33)
    assert len({a, b, c}) == 3


def test_length_distinguishability():
    # "a", "aa", "a\0" must all differ — length absorption guarantees this.
    a = digest_bytes(b"a")
    b = digest_bytes(b"aa")
    c = digest_bytes(b"a\x00")
    assert len({a, b, c}) == 3


def test_empty_input_well_defined():
    # No exception, 64 hex chars, stable.
    e1 = digest_bytes(b"")
    e2 = digest_bytes(b"")
    assert e1 == e2
    assert len(e1) == 64
