"""WiseDigest-3 attack suite.

Passing does not prove security. Failing points at concrete weaknesses.
Heavy tests are kept small enough for pure-Python execution; bigger runs
belong in research/WiseDigest-Lab.md and require a faster implementation.
"""

from __future__ import annotations

import random
import struct
from collections import Counter

import pytest

from wise.digest import digest_bytes as digest_v0
from wise.digest_v1 import digest_bytes as digest_v1
from wise.digest_v2 import digest_bytes as digest_v2
from wise.digest_v3 import MASK61, WiseDigest3, digest_bytes as digest_v3


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def _D(data: bytes) -> bytes:
    return WiseDigest3().update(data).digest()


# -----------------------------------------------------------------------------
# Required: empty + one-byte + repeated bytes + long repeats
# -----------------------------------------------------------------------------

def test_empty_stable():
    assert digest_v3(b"") == digest_v3(b"")


def test_one_byte_inputs_distinct():
    assert len({digest_v3(bytes([b])) for b in range(256)}) == 256


def test_repeated_byte_lengths_distinct():
    digests = {digest_v3(b"\x41" * n) for n in range(0, 200)}
    assert len(digests) == 200


def test_long_repeated_pattern_inputs_distinct():
    digests = {digest_v3(bytes([b]) * 1024) for b in range(256)}
    assert len(digests) == 256


# -----------------------------------------------------------------------------
# Required: similar prefixes / suffixes
# -----------------------------------------------------------------------------

def test_similar_prefix_inputs_diverge():
    base = b"the quick brown fox jumps over the lazy dog"
    rng = random.Random(0xAA1)
    distances: list[int] = []
    for _ in range(80):
        i = rng.randint(0, len(base) - 1)
        flipped = bytearray(base)
        flipped[i] ^= 1 << rng.randint(0, 7)
        distances.append(_hamming(_D(base), _D(bytes(flipped))))
    mean = sum(distances) / len(distances)
    assert 110.0 <= mean <= 146.0, f"similar-prefix mean {mean:.2f} biased"


def test_similar_suffix_inputs_diverge():
    base = b"the quick brown fox jumps over the lazy dog"
    rng = random.Random(0xAA2)
    distances: list[int] = []
    for _ in range(80):
        s1 = bytes(rng.randint(0, 255) for _ in range(8))
        s2 = bytearray(s1)
        i = rng.randint(0, len(s2) - 1)
        s2[i] ^= 1 << rng.randint(0, 7)
        distances.append(_hamming(_D(base + s1), _D(base + bytes(s2))))
    mean = sum(distances) / len(distances)
    assert 110.0 <= mean <= 146.0, f"similar-suffix mean {mean:.2f} biased"


# -----------------------------------------------------------------------------
# Required: single-bit + per-byte avalanche
# -----------------------------------------------------------------------------

def test_single_bit_avalanche():
    rng = random.Random(0xB1)
    n_messages = 16
    msg_len = 48
    distances: list[int] = []
    for _ in range(n_messages):
        msg = bytes(rng.randint(0, 255) for _ in range(msg_len))
        base = _D(msg)
        for bit_pos in range(msg_len * 8):
            mut = bytearray(msg)
            mut[bit_pos // 8] ^= 1 << (bit_pos % 8)
            distances.append(_hamming(base, _D(bytes(mut))))
    mean = sum(distances) / len(distances)
    assert 118.0 <= mean <= 138.0, f"single-bit avalanche mean {mean:.2f} biased"
    assert min(distances) >= 32, f"saw bit flip with only {min(distances)} output bits flipped"
    assert max(distances) <= 224, f"saw bit flip with {max(distances)} output bits flipped"


def test_per_byte_avalanche():
    rng = random.Random(0xB2)
    base = bytes(rng.randint(0, 255) for _ in range(64))
    base_d = _D(base)
    distances: list[int] = []
    for byte_pos in range(len(base)):
        for delta in range(1, 8):
            mut = bytearray(base)
            mut[byte_pos] ^= delta
            distances.append(_hamming(base_d, _D(bytes(mut))))
    mean = sum(distances) / len(distances)
    assert 118.0 <= mean <= 138.0, f"per-byte avalanche mean {mean:.2f} biased"


# -----------------------------------------------------------------------------
# Required: random differential + birthday smoke + structured XOR + rotation
# -----------------------------------------------------------------------------

def test_random_pair_differential():
    rng = random.Random(0xC1)
    distances: list[int] = []
    for _ in range(300):
        a = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 200)))
        b = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 200)))
        if a == b:
            continue
        distances.append(_hamming(_D(a), _D(b)))
    mean = sum(distances) / len(distances)
    assert 118.0 <= mean <= 138.0, f"random differential mean {mean:.2f} biased"


def test_birthday_collision_smoke_16bit():
    rng = random.Random(0xC2)
    N = 6144
    seen: dict[bytes, int] = {}
    collisions = 0
    for _ in range(N):
        msg = struct.pack(">Q", rng.getrandbits(64)) + struct.pack(">Q", rng.getrandbits(64))
        prefix = _D(msg)[:2]
        if prefix in seen:
            collisions += seen[prefix]
            seen[prefix] += 1
        else:
            seen[prefix] = 1
    expected = N * (N - 1) / 2 / (1 << 16)
    assert 0.4 * expected <= collisions <= 2.5 * expected, (
        f"16-bit birthday {collisions} far from expected {expected:.0f}"
    )


def test_full_output_no_collisions_in_small_search():
    rng = random.Random(0xC3)
    seen: set[bytes] = set()
    for _ in range(4096):
        msg = struct.pack(">Q", rng.getrandbits(64))
        d = _D(msg)
        assert d not in seen
        seen.add(d)


def test_structured_xor_pair():
    rng = random.Random(0xC4)
    masks = [
        b"\x01" + b"\x00" * 31,
        b"\x80" + b"\x00" * 31,
        b"\x00" * 16 + b"\xff" + b"\x00" * 15,
        b"\xff" * 8 + b"\x00" * 24,
        bytes(range(32)),
    ]
    distances: list[int] = []
    for mask in masks:
        for _ in range(30):
            a = bytes(rng.randint(0, 255) for _ in range(32))
            b = bytes(x ^ y for x, y in zip(a, mask))
            distances.append(_hamming(_D(a), _D(b)))
    mean = sum(distances) / len(distances)
    assert 118.0 <= mean <= 138.0, f"structured-XOR mean {mean:.2f} biased"


def test_rotated_input_diverges():
    rng = random.Random(0xC5)
    distances: list[int] = []
    for _ in range(50):
        n = rng.randint(8, 80)
        msg = bytes(rng.randint(0, 255) for _ in range(n))
        rot = msg[1:] + msg[:1]
        if rot == msg:
            continue
        distances.append(_hamming(_D(msg), _D(rot)))
    mean = sum(distances) / len(distances)
    assert 118.0 <= mean <= 138.0, f"rotated-input mean {mean:.2f} biased"


# -----------------------------------------------------------------------------
# Required: length-extension smoke + streaming + determinism
# -----------------------------------------------------------------------------

def test_length_extension_smoke():
    secret = b"the-secret-prefix-12345"
    extension = b"|attacker-suffix"
    real = _D(secret + extension)
    naive = WiseDigest3()
    naive.update(extension)
    assert naive.digest() != real
    assert _D(_D(secret) + extension) != real


def test_streaming_equals_one_shot_under_random_partition():
    rng = random.Random(0xE1)
    msg = bytes(rng.randint(0, 255) for _ in range(500))
    one_shot = digest_v3(msg)
    for _ in range(10):
        h = WiseDigest3()
        cursor = 0
        while cursor < len(msg):
            chunk = rng.randint(1, max(1, len(msg) - cursor))
            h.update(msg[cursor : cursor + chunk])
            cursor += chunk
        assert h.hexdigest() == one_shot


def test_deterministic_across_repeated_runs():
    rng = random.Random(0xE2)
    for _ in range(40):
        n = rng.randint(0, 200)
        msg = bytes(rng.randint(0, 255) for _ in range(n))
        a = digest_v3(msg)
        b = digest_v3(msg)
        c = WiseDigest3().update(msg).hexdigest()
        assert a == b == c


# -----------------------------------------------------------------------------
# Required: domain separation across all four candidates
# -----------------------------------------------------------------------------

def test_four_way_domain_separation():
    rng = random.Random(0xD1)
    crosscolls = 0
    for _ in range(250):
        msg = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 80)))
        d0 = digest_v0(msg, "WiseDigest-0")
        d1 = digest_v1(msg)
        d2 = digest_v2(msg)
        d3 = digest_v3(msg)
        digests = {d0, d1, d2, d3}
        if len(digests) < 4:
            crosscolls += 1
    assert crosscolls == 0


# -----------------------------------------------------------------------------
# 793-bit invariant under attack-shaped inputs
# -----------------------------------------------------------------------------

def test_invariant_holds_on_adversarial_inputs():
    """Specific patterns that might push state out of the 61-bit envelope."""
    inputs = [
        b"",
        b"\x00",
        b"\xff",
        b"\xff" * 1024,
        b"\x00" * 1024,
        b"\xff\x00" * 64,
        bytes(range(256)) * 4,
    ]
    for msg in inputs:
        h = WiseDigest3()
        h.update(msg)
        _ = h.digest()
        for k, s in enumerate(h._state):
            assert 0 <= s <= MASK61, (
                f"input {msg[:20]!r} ({len(msg)}B) pushed lane {k} out of 61 bits: {s:#x}"
            )


# -----------------------------------------------------------------------------
# Output byte distribution sanity
# -----------------------------------------------------------------------------

def test_output_byte_distribution_near_uniform():
    rng = random.Random(0xF1)
    counts: Counter = Counter()
    for _ in range(1200):
        msg = struct.pack(">Q", rng.getrandbits(64)) + bytes(rng.randint(0, 255) for _ in range(8))
        counts.update(_D(msg))
    total = sum(counts.values())
    expected_per = total / 256
    low = expected_per * 0.6
    high = expected_per * 1.4
    for v in range(256):
        c = counts.get(v, 0)
        assert low <= c <= high, (
            f"byte 0x{v:02x} count {c} outside [{low:.0f},{high:.0f}] (expected ~{expected_per:.0f})"
        )
