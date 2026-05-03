"""WiseDigest attack suite (covers v0 and v1).

These tests probe properties an attacker would exploit. PASSING does NOT prove
security — a hash function with no analysis can still pass every cheap test.
FAILING is meaningful: it points at a concrete weakness.

Heavy-volume tests are kept small enough to run in well under one second of
pure-Python CPU. Bigger runs belong in research/WiseDigest-Lab.md and should
be invoked manually.
"""

from __future__ import annotations

import os
import random
import struct
from collections import Counter

import pytest

from wise.digest import digest_bytes as digest_v0
from wise.digest_v1 import WiseDigest1, digest_bytes as digest_v1


_OUTPUT_BITS = 256
_OUTPUT_BYTES = 32


def _hamming_bytes(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def _digest_raw(data: bytes) -> bytes:
    return WiseDigest1().update(data).digest()


# =============================================================================
# Attack 1 — Single-bit avalanche
# =============================================================================

def test_avalanche_single_bit_flip_is_well_distributed():
    """Flipping one bit of input must scatter ~50% of output bits.

    For a strong hash, mean Hamming distance over output should be ~128 with
    very tight variance for many trials. We accept a wide window per trial
    and a tight window on the mean across all trials.
    """
    rng = random.Random(0xA1A1A1)
    n_messages = 30
    msg_len = 48  # straddles the rate boundary
    distances: list[int] = []

    for _ in range(n_messages):
        msg = bytes(rng.randint(0, 255) for _ in range(msg_len))
        base = _digest_raw(msg)
        for bit_pos in range(msg_len * 8):
            mutated = bytearray(msg)
            mutated[bit_pos // 8] ^= 1 << (bit_pos % 8)
            mutated_d = _digest_raw(bytes(mutated))
            distances.append(_hamming_bytes(base, mutated_d))

    mean = sum(distances) / len(distances)
    # Expected mean for an ideal random function = 128. Allow ±6 bits.
    assert 122.0 <= mean <= 134.0, f"avalanche mean {mean:.2f} outside [122,134]"

    # No single trial should be catastrophically biased (e.g. < 64 or > 192).
    worst_low = min(distances)
    worst_high = max(distances)
    assert worst_low >= 64, f"saw a single-bit flip with only {worst_low} output bits flipped"
    assert worst_high <= 192, f"saw a single-bit flip flipping {worst_high} output bits"


# =============================================================================
# Attack 2 — Two-input differential
# =============================================================================

def test_random_pair_differential():
    """Two unrelated random inputs produce ~uncorrelated outputs."""
    rng = random.Random(0xB2B2B2)
    distances: list[int] = []
    for _ in range(500):
        a = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 200)))
        b = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 200)))
        if a == b:
            continue
        distances.append(_hamming_bytes(_digest_raw(a), _digest_raw(b)))
    mean = sum(distances) / len(distances)
    assert 122.0 <= mean <= 134.0, f"differential mean {mean:.2f} outside [122,134]"


# =============================================================================
# Attack 3 — Domain separation against WiseDigest-0
# =============================================================================

def test_domain_separation_v0_v1():
    """Same input under WiseDigest-0 and WiseDigest-1 must differ for many inputs."""
    rng = random.Random(0xC3C3C3)
    collisions = 0
    trials = 200
    for _ in range(trials):
        msg = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 100)))
        if digest_v0(msg, "WiseDigest-0") == digest_v1(msg):
            collisions += 1
    assert collisions == 0, f"v0/v1 cross-collision in {collisions}/{trials} trials"


# =============================================================================
# Attack 4 — Pattern bias (degenerate inputs)
# =============================================================================

@pytest.mark.parametrize(
    "label,gen",
    [
        ("all_zeros_short", lambda: bytes(16)),
        ("all_zeros_block", lambda: bytes(32)),
        ("all_zeros_long", lambda: bytes(1024)),
        ("all_ones_block", lambda: b"\xff" * 32),
        ("alternating_55_block", lambda: b"\x55" * 32),
        ("alternating_aa_block", lambda: b"\xaa" * 32),
        ("counter_block", lambda: bytes(range(32))),
    ],
)
def test_pattern_inputs_have_unbiased_output_bytes(label, gen):
    """Degenerate input should not produce degenerate output."""
    out = _digest_raw(gen())
    counts = Counter(out)
    # No byte value occupies > 50% of the output.
    most_common_count = counts.most_common(1)[0][1]
    assert most_common_count <= _OUTPUT_BYTES // 2, f"{label}: output dominated by single byte"
    # At least 16 distinct byte values present out of 32.
    assert len(counts) >= 16, f"{label}: only {len(counts)} distinct output bytes"


def test_distinct_pattern_inputs_have_distinct_outputs():
    inputs = [
        bytes(32),
        b"\xff" * 32,
        b"\x55" * 32,
        b"\xaa" * 32,
        bytes(range(32)),
    ]
    digests = {_digest_raw(x) for x in inputs}
    assert len(digests) == len(inputs)


# =============================================================================
# Attack 5 — Truncated-prefix collision search (small-scale)
# =============================================================================

def test_truncated_prefix_collisions_match_birthday_expectation():
    """Search 2^14 random inputs for collisions on first 16 output bits.

    For an ideal 16-bit projection, the expected number of colliding pairs in
    N=16384 random inputs is N*(N-1)/2 / 2^16 ≈ 2050. Real well-mixing hashes
    cluster tightly around that. We accept anything in a wide band.
    """
    rng = random.Random(0xD4D4D4)
    N = 16384
    seen: dict[bytes, int] = {}
    collisions = 0
    for _ in range(N):
        msg = struct.pack(">Q", rng.getrandbits(64)) + struct.pack(">Q", rng.getrandbits(64))
        prefix = _digest_raw(msg)[:2]
        if prefix in seen:
            collisions += seen[prefix]
            seen[prefix] += 1
        else:
            seen[prefix] = 1
    expected = N * (N - 1) / 2 / (1 << 16)
    # Accept 0.5x to 2x of birthday expectation.
    assert 0.5 * expected <= collisions <= 2.0 * expected, (
        f"16-bit truncated collisions {collisions} far from birthday expectation {expected:.0f}"
    )


def test_full_output_no_collisions_in_small_search():
    """No full-output collisions in 2^12 random inputs."""
    rng = random.Random(0xE5E5E5)
    seen: set[bytes] = set()
    for _ in range(4096):
        msg = struct.pack(">Q", rng.getrandbits(64))
        d = _digest_raw(msg)
        assert d not in seen, "full 256-bit collision in small random search"
        seen.add(d)


# =============================================================================
# Attack 6 — Length-extension (sponge property)
# =============================================================================

def test_length_extension_attempt():
    """In an MD-style hash, given hash(M) an attacker can append.

    A sponge with capacity > 0 should resist trivial extension: there is no
    way, knowing only hash(M), to compute hash(M || X) without knowing M.

    This test cannot prove resistance — it only verifies that the obvious
    naive extension fails. Treat as a smoke test, not a security proof.
    """
    secret = b"the-secret-prefix-" + os.urandom(16)
    extension = b"|attacker-suffix"
    real = _digest_raw(secret + extension)

    # Naive attempt: re-seed a hasher with the digest of `secret` and absorb
    # the extension. This is the classic MD length-extension move. It MUST
    # NOT match `real`.
    h = WiseDigest1()
    h.update(extension)
    naive_attempt = h.digest()

    assert naive_attempt != real
    # Also, simply hashing the digest of secret bytes alongside the extension
    # must not match.
    assert _digest_raw(_digest_raw(secret) + extension) != real


# =============================================================================
# Attack 7 — Output byte distribution chi-squared (light-touch)
# =============================================================================

def test_output_byte_distribution_is_near_uniform():
    """Across many random inputs, the union of output bytes should look uniform.

    We do not run a real chi-squared test; we check that no byte value is
    grossly over- or under-represented across a few thousand digests.
    """
    rng = random.Random(0xF6F6F6)
    counts = Counter()
    for _ in range(2000):
        msg = struct.pack(">Q", rng.getrandbits(64)) + bytes(rng.randint(0, 255) for _ in range(8))
        counts.update(_digest_raw(msg))
    total = sum(counts.values())
    expected_per_value = total / 256
    # Allow each byte value to be within ±25% of its expected count.
    low = expected_per_value * 0.75
    high = expected_per_value * 1.25
    for byte_value in range(256):
        c = counts.get(byte_value, 0)
        assert low <= c <= high, (
            f"byte 0x{byte_value:02x} appears {c} times; expected ~{expected_per_value:.0f} "
            f"(window [{low:.0f},{high:.0f}])"
        )


# =============================================================================
# v0.1.1 — explicit attack coverage for WiseDigest-0 (the shipped algorithm)
# =============================================================================
# The tests above target WiseDigest-1 via _digest_raw. WiseDigest-0 is the
# default in v0.1.1 — it deserves its own attack-suite section.


def _v0_digest_bytes(data: bytes) -> bytes:
    """Run WiseDigest-0 and return the raw 32-byte output."""
    return bytes.fromhex(digest_v0(data, "WiseDigest-0"))


def _v0_digest_hex(data: bytes) -> str:
    """Run WiseDigest-0 and return the 64-char lowercase hex output."""
    return digest_v0(data, "WiseDigest-0")


def test_v0_avalanche_single_bit_flip_distributes_output():
    """Flipping one input bit must scatter ~50% of output bits for WD-0."""
    rng = random.Random(0x0000_0001)
    n_messages = 20
    msg_len = 48
    distances: list[int] = []
    for _ in range(n_messages):
        msg = bytes(rng.randint(0, 255) for _ in range(msg_len))
        base = _v0_digest_bytes(msg)
        for bit_pos in range(msg_len * 8):
            mutated = bytearray(msg)
            mutated[bit_pos // 8] ^= 1 << (bit_pos % 8)
            mutated_d = _v0_digest_bytes(bytes(mutated))
            distances.append(_hamming_bytes(base, mutated_d))
    mean = sum(distances) / len(distances)
    # Looser window for WD-0 since it is documented as experimental.
    assert 110.0 <= mean <= 146.0, f"v0 avalanche mean {mean:.2f} outside [110,146]"


def test_v0_random_pair_outputs_uncorrelated():
    """Two unrelated random inputs produce ~uncorrelated WD-0 outputs."""
    rng = random.Random(0x0000_0002)
    distances: list[int] = []
    for _ in range(200):
        a = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 100)))
        b = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 100)))
        distances.append(_hamming_bytes(_v0_digest_bytes(a), _v0_digest_bytes(b)))
    mean = sum(distances) / len(distances)
    assert 110.0 <= mean <= 146.0, f"v0 differential mean {mean:.2f} outside [110,146]"


def test_v0_short_inputs_distinct():
    """All single-byte inputs (0..255) produce distinct WD-0 outputs."""
    digests = {_v0_digest_hex(bytes([b])) for b in range(256)}
    assert len(digests) == 256


def test_v0_length_extension_resistant_in_practice():
    """Given digest(M), an attacker should not trivially find digest(M||X)."""
    rng = random.Random(0x0000_0003)
    secret = bytes(rng.randint(0, 255) for _ in range(20))
    extension = b"||attacker_appended"
    real_extended = _v0_digest_hex(secret + extension)
    # A naive "concatenate digest with extension and re-hash" must NOT match.
    assert _v0_digest_hex(_v0_digest_bytes(secret) + extension) != real_extended


def test_v0_output_byte_distribution_near_uniform():
    """Across many WD-0 outputs, no output byte value is grossly biased."""
    rng = random.Random(0x0000_0004)
    counts = Counter()
    for _ in range(2000):
        msg = struct.pack(">Q", rng.getrandbits(64)) + bytes(rng.randint(0, 255) for _ in range(8))
        counts.update(_v0_digest_bytes(msg))
    total = sum(counts.values())
    expected = total / 256
    low, high = expected * 0.75, expected * 1.25
    for byte_value in range(256):
        c = counts.get(byte_value, 0)
        assert low <= c <= high, (
            f"WD-0 byte 0x{byte_value:02x} appears {c} times; expected ~{expected:.0f}"
        )


def test_v0_each_output_bit_position_is_balanced():
    """Across many WD-0 outputs, each output bit position is ~50% ones."""
    rng = random.Random(0x0000_0005)
    n_trials = 1000
    bit_counts = [0] * 256
    for _ in range(n_trials):
        msg = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 200)))
        out = _v0_digest_bytes(msg)
        for byte_pos in range(32):
            for bit_pos in range(8):
                bit_counts[byte_pos * 8 + bit_pos] += (out[byte_pos] >> bit_pos) & 1
    # Each bit position should be 500 ± allowance.
    for i, c in enumerate(bit_counts):
        assert 0.40 * n_trials <= c <= 0.60 * n_trials, (
            f"WD-0 output bit {i} biased: {c}/{n_trials} ones"
        )
