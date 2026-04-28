"""WiseDigest-3 functional tests + locked vectors + 793-bit invariant."""

from __future__ import annotations

import random

import pytest

from wise.digest_v3 import (
    ALGORITHM_NAME,
    LANES,
    LIVE_BITS,
    MASK61,
    WiseDigest3,
    digest_bytes,
    digest_stream,
)


def test_algorithm_name():
    assert ALGORITHM_NAME == "WiseDigest-3"


def test_live_bits_is_793():
    assert LIVE_BITS == 793
    assert LANES == 13
    assert MASK61 == (1 << 61) - 1
    assert LANES * 61 == 793


def test_output_is_64_lowercase_hex():
    h = digest_bytes(b"truth\n")
    assert len(h) == 64
    int(h, 16)
    assert h == h.lower()


def test_deterministic():
    assert digest_bytes(b"truth\n") == digest_bytes(b"truth\n")


def test_streaming_equals_one_shot():
    one_shot = digest_bytes(b"truth\nmore\nbytes\n")
    h = WiseDigest3()
    h.update(b"truth\n")
    h.update(b"more\n")
    h.update(b"bytes\n")
    assert h.hexdigest() == one_shot


def test_streaming_arbitrary_partition():
    msg = b"the quick brown fox jumps over the lazy dog" * 7
    one_shot = digest_bytes(msg)
    for split in (1, 7, 31, 32, 33, 100, len(msg) - 1):
        h = WiseDigest3()
        h.update(msg[:split])
        h.update(msg[split:])
        assert h.hexdigest() == one_shot, f"split at {split} disagrees"


def test_digest_stream_helper():
    chunks = [b"alpha", b"", b"beta", b"gamma"]
    assert digest_stream(chunks) == digest_bytes(b"".join(chunks))


def test_update_after_finalize_raises():
    h = WiseDigest3()
    h.update(b"x")
    _ = h.hexdigest()
    with pytest.raises(RuntimeError):
        h.update(b"more")


def test_hexdigest_idempotent():
    h = WiseDigest3()
    h.update(b"truth\n")
    assert h.hexdigest() == h.hexdigest()


# ============================================================================
# 793-bit invariant
# ============================================================================

def test_state_lanes_within_61_bits_after_init():
    h = WiseDigest3()
    for s in h._state:
        assert 0 <= s <= MASK61, f"init state lane outside 61-bit envelope: {s:#x}"


def test_state_lanes_within_61_bits_during_streaming():
    h = WiseDigest3()
    rng = random.Random(0)
    for _ in range(20):
        chunk = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 50)))
        h.update(chunk)
        for s in h._state:
            assert 0 <= s <= MASK61, f"streaming state lane outside envelope: {s:#x}"


def test_state_lanes_within_61_bits_after_finalize():
    h = WiseDigest3()
    h.update(b"truth\n")
    _ = h.digest()
    for s in h._state:
        assert 0 <= s <= MASK61, f"post-finalize lane outside envelope: {s:#x}"


def test_all_lanes_take_more_than_one_value():
    """All 13 lanes must vary across diverse inputs (no constant lanes)."""
    rng = random.Random(0xABC)
    seen_per_lane: list[set[int]] = [set() for _ in range(LANES)]
    for _ in range(80):
        msg = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 200)))
        h = WiseDigest3()
        h.update(msg)
        h._finalize()
        for k in range(LANES):
            seen_per_lane[k].add(h._state[k])
    for k, s in enumerate(seen_per_lane):
        assert len(s) > 1, f"lane {k} took only one value across 80 inputs"


def test_dead_top_3_bits_are_always_zero_after_finalize():
    """The top 3 bits above 61 must be zero in every lane after finalize."""
    rng = random.Random(0xDEAD)
    for _ in range(30):
        msg = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 100)))
        h = WiseDigest3()
        h.update(msg)
        h._finalize()
        for k, s in enumerate(h._state):
            top3 = s >> 61
            assert top3 == 0, f"lane {k} carries dead bits: top3 = {top3:#b}"


# ============================================================================
# Locked reference vectors
# ============================================================================

_LOCKED_VECTORS: list[tuple[str, bytes, str]] = [
    ("empty", b"", "94f8a850b58985834a7e72864c0db6757d9864c5d5ab4ff31188b6323c43e999"),
    ("single_a", b"a", "339b6fd3cf5564a43b6aeaf4fb5541c7d81971da6a13f5b5cbac9f69f2d9e716"),
    ("ab", b"ab", "dd6bf5baf04fd981bd1c8c5e5c2502ae9f89e2a651eda341b253c6f12bf4eb46"),
    ("abc", b"abc", "7316f497541bb373d07a30be6fe0af0a25722b5c4adc98236fb27e0575ecec23"),
    ("a_then_nul", b"a\x00", "ba9e8aeff70b5d4b9e0e498fc6fd89feccb0a600b97de5e2896703d63deb7d80"),
    ("double_a", b"aa", "a03cbdbf5c6b5b90b1f8c9b660146a25aeeaa6030a0af8ca843e53aae2d0a2e6"),
    ("rate_minus_one", b"x" * 31, "b3fad47a344d3aa014e6099959f6b3907bc25dc4d3bdaee8c94bc6ca4cd44f08"),
    ("rate_exact", b"x" * 32, "4bc92233a1bb9a2748eccb8352e9b762c8e2e737832702dc9a8f4fbb45cf7c57"),
    ("rate_plus_one", b"x" * 33, "83617500dfb4735370474a67b321ff844a6394ef3ec2d660aa21e994aa8597a3"),
    ("rate_double", b"x" * 64, "ffb348a0242010a62a02defaa06fddef3901e2c07c7ecd454cd774961b3aab45"),
    ("truth_newline", b"truth\n", "f3163db0ed191994acd9a309a6dc7eee6d08560b670b31f182c8ade17ccb89c8"),
    ("kilobyte_x", b"x" * 1024, "d85c906e3e19cdd7c2536fa7fa06b29f0ab450f63957d2d9524f6af051d782ee"),
    ("zero_byte", b"\x00", "79ff08e1dfab4ccc95c7275da0c00752be91c69872b54dcf0fd939e8cbbe24ec"),
    ("ones_block", b"\xff" * 32, "9462c1a98d3ce53e97a67860e0b280b737fe6b77346c4f54792bf55f17aaaa9a"),
]


@pytest.mark.parametrize(
    "label,data,expected", _LOCKED_VECTORS, ids=[v[0] for v in _LOCKED_VECTORS]
)
def test_locked_vector(label: str, data: bytes, expected: str):
    assert digest_bytes(data) == expected, f"vector {label!r} drifted"


def test_short_inputs_distinct():
    digests = {digest_bytes(bytes([b])) for b in range(256)}
    assert len(digests) == 256


def test_length_distinguishability():
    a = digest_bytes(b"a")
    aa = digest_bytes(b"aa")
    a_nul = digest_bytes(b"a\x00")
    nul_a = digest_bytes(b"\x00a")
    assert len({a, aa, a_nul, nul_a}) == 4


def test_block_boundary_distinguishability():
    digests = {digest_bytes(b"x" * n) for n in (31, 32, 33, 63, 64, 65)}
    assert len(digests) == 6
