"""WiseDigest-2 attack suite.

Passing these tests does not prove security. Failing them points at concrete
weaknesses. Heavy tests are kept small enough for pure-Python execution; bigger
runs belong in research/WiseDigest-Lab.md and require a faster implementation.
"""

from __future__ import annotations

import random
import struct
from collections import Counter

import pytest

from wise.digest import digest_bytes as digest_v0
from wise.digest_v1 import digest_bytes as digest_v1
from wise.digest_v2 import WiseDigest2, digest_bytes as digest_v2


_OUTPUT_BYTES = 32


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def _D(data: bytes) -> bytes:
    return WiseDigest2().update(data).digest()


# -----------------------------------------------------------------------------
# Required: empty + one-byte + repeated bytes + long repeats
# -----------------------------------------------------------------------------

def test_empty_stable():
    assert digest_v2(b"") == digest_v2(b"")


def test_all_one_byte_inputs_distinct():
    digests = {digest_v2(bytes([b])) for b in range(256)}
    assert len(digests) == 256


def test_repeated_byte_inputs_distinct_lengths():
    digests = {digest_v2(b"\x41" * n) for n in range(0, 200)}
    assert len(digests) == 200, "two different-length repeats collided"


def test_long_repeated_pattern_inputs_distinct():
    """Long inputs of single repeated bytes must produce distinct digests."""
    digests = {digest_v2(bytes([b]) * 1024) for b in range(256)}
    assert len(digests) == 256, "two long-repeat inputs with different bytes collided"


# -----------------------------------------------------------------------------
# Required: similar prefixes + similar suffixes
# -----------------------------------------------------------------------------

def test_similar_prefix_inputs_diverge():
    base = b"the quick brown fox jumps over the lazy dog"
    rng = random.Random(0xAA1)
    distances = []
    for _ in range(100):
        i = rng.randint(0, len(base) - 1)
        flipped = bytearray(base)
        flipped[i] ^= 1 << rng.randint(0, 7)
        distances.append(_hamming(_D(base), _D(bytes(flipped))))
    mean = sum(distances) / len(distances)
    assert 110.0 <= mean <= 146.0, f"similar-prefix mean {mean:.2f} biased (target 128)"


def test_similar_suffix_inputs_diverge():
    base = b"the quick brown fox jumps over the lazy dog"
    rng = random.Random(0xAA2)
    distances = []
    for _ in range(100):
        suffix1 = bytes(rng.randint(0, 255) for _ in range(8))
        suffix2 = bytearray(suffix1)
        i = rng.randint(0, len(suffix2) - 1)
        suffix2[i] ^= 1 << rng.randint(0, 7)
        distances.append(_hamming(_D(base + suffix1), _D(base + bytes(suffix2))))
    mean = sum(distances) / len(distances)
    assert 110.0 <= mean <= 146.0, f"similar-suffix mean {mean:.2f} biased"


# -----------------------------------------------------------------------------
# Required: single-bit avalanche + per-byte avalanche
# -----------------------------------------------------------------------------

def test_single_bit_avalanche():
    rng = random.Random(0xB1)
    n_messages = 20
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
    # Wider window than v1 — this is an unanalyzed candidate.
    assert 118.0 <= mean <= 138.0, f"single-bit avalanche mean {mean:.2f} biased"
    assert min(distances) >= 32, f"saw bit flip with only {min(distances)} output bits flipped"
    assert max(distances) <= 224, f"saw bit flip with {max(distances)} output bits flipped"


def test_per_byte_avalanche():
    """Replacing one whole byte should also flip ~50% of output bits."""
    rng = random.Random(0xB2)
    base = bytes(rng.randint(0, 255) for _ in range(64))
    base_d = _D(base)
    distances: list[int] = []
    for byte_pos in range(len(base)):
        for delta in range(1, 8):  # XOR with deltas 1..7
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
    distances = []
    for _ in range(400):
        a = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 200)))
        b = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 200)))
        if a == b:
            continue
        distances.append(_hamming(_D(a), _D(b)))
    mean = sum(distances) / len(distances)
    assert 118.0 <= mean <= 138.0, f"random differential mean {mean:.2f} biased"


def test_birthday_collision_smoke_16bit():
    rng = random.Random(0xC2)
    N = 8192
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
    # Wider window than v1 — accept 0.4x to 2.5x of birthday expectation.
    assert 0.4 * expected <= collisions <= 2.5 * expected, (
        f"16-bit birthday collisions {collisions} far from expectation {expected:.0f}"
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
    """Pairs differing only by a fixed XOR mask must produce uncorrelated digests."""
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
        for _ in range(40):
            a = bytes(rng.randint(0, 255) for _ in range(32))
            b = bytes(x ^ y for x, y in zip(a, mask))
            distances.append(_hamming(_D(a), _D(b)))
    mean = sum(distances) / len(distances)
    assert 118.0 <= mean <= 138.0, f"structured-XOR mean {mean:.2f} biased"


def test_rotated_input_diverges():
    """A message and its left-byte-rotation must produce uncorrelated digests."""
    rng = random.Random(0xC5)
    distances: list[int] = []
    for _ in range(60):
        n = rng.randint(8, 80)
        msg = bytes(rng.randint(0, 255) for _ in range(n))
        rot = msg[1:] + msg[:1]
        if rot == msg:
            continue
        distances.append(_hamming(_D(msg), _D(rot)))
    mean = sum(distances) / len(distances)
    assert 118.0 <= mean <= 138.0, f"rotated-input mean {mean:.2f} biased"


# -----------------------------------------------------------------------------
# Required: length extension smoke
# -----------------------------------------------------------------------------

def test_length_extension_smoke():
    """Naive concat extension attack must fail."""
    secret = b"the-secret-prefix-12345"
    extension = b"|attacker-suffix"
    real = _D(secret + extension)
    naive_extend = WiseDigest2()
    naive_extend.update(extension)
    assert naive_extend.digest() != real
    # Also: hashing the digest of the secret alongside the extension must not match.
    assert _D(_D(secret) + extension) != real


# -----------------------------------------------------------------------------
# Required: domain separation across all three candidates
# -----------------------------------------------------------------------------

def test_three_way_domain_separation():
    rng = random.Random(0xD1)
    crosscolls = 0
    for _ in range(300):
        msg = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 80)))
        d0 = digest_v0(msg, "WiseDigest-0")
        d1 = digest_v1(msg)
        d2 = digest_v2(msg)
        if d0 == d1 or d0 == d2 or d1 == d2:
            crosscolls += 1
    assert crosscolls == 0


# -----------------------------------------------------------------------------
# Required: streaming equals one-shot + deterministic across repeated runs
# -----------------------------------------------------------------------------

def test_streaming_equals_one_shot_under_random_partition():
    rng = random.Random(0xE1)
    msg = bytes(rng.randint(0, 255) for _ in range(500))
    one_shot = digest_v2(msg)
    for _ in range(10):
        h = WiseDigest2()
        cursor = 0
        while cursor < len(msg):
            chunk = rng.randint(1, max(1, len(msg) - cursor))
            h.update(msg[cursor : cursor + chunk])
            cursor += chunk
        assert h.hexdigest() == one_shot


def test_deterministic_across_repeated_runs():
    rng = random.Random(0xE2)
    for _ in range(50):
        n = rng.randint(0, 200)
        msg = bytes(rng.randint(0, 255) for _ in range(n))
        a = digest_v2(msg)
        b = digest_v2(msg)
        c = WiseDigest2().update(msg).hexdigest()
        assert a == b == c


# -----------------------------------------------------------------------------
# Output distribution sanity
# -----------------------------------------------------------------------------

def test_output_byte_distribution_near_uniform():
    rng = random.Random(0xF1)
    counts: Counter = Counter()
    for _ in range(1500):
        msg = struct.pack(">Q", rng.getrandbits(64)) + bytes(rng.randint(0, 255) for _ in range(8))
        counts.update(_D(msg))
    total = sum(counts.values())
    expected_per = total / 256
    low = expected_per * 0.65
    high = expected_per * 1.35
    for v in range(256):
        c = counts.get(v, 0)
        assert low <= c <= high, (
            f"byte 0x{v:02x} count {c} outside window [{low:.0f},{high:.0f}] (expected ~{expected_per:.0f})"
        )
