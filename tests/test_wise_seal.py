"""Tests for the WISESEAL-V1 container."""

from __future__ import annotations

import os

import pytest

from wise.proof import build_file_proof_items, render
from wise.seal import SealError, pack, unpack


FIXED_TIME = "2026-04-27T00:00:00Z"


def test_pack_unpack_round_trip(tmp_path):
    artifact = b"truth\n"
    items = build_file_proof_items(
        os.path.join(tmp_path, "demo.txt") if False else _stash(tmp_path, artifact),
        created_at=FIXED_TIME,
    )
    proof_bytes = render(items)
    sealed = pack(artifact, proof_bytes)
    a, p = unpack(sealed)
    assert a == artifact
    assert p == proof_bytes


def test_unpack_rejects_truncated():
    with pytest.raises(SealError):
        unpack(b"WISESEAL-V1\n[ARTIFACT]\n\x00\x00\x00\x05truth")  # missing PROOF section


def test_unpack_rejects_bad_header():
    with pytest.raises(SealError):
        unpack(b"NOPE-V1\n[ARTIFACT]\n\x00\x00\x00\x00\n[PROOF]\n\x00\x00\x00\x00\n[END]\n")


def _stash(tmp_path, data):
    p = os.path.join(tmp_path, "demo.txt")
    with open(p, "wb") as fh:
        fh.write(data)
    return p


# ============================================================================
# v0.1.1 hardening tests
# ============================================================================


def test_h3_pack_rejects_oversize_proof_section():
    """Embedded proof bytes are capped at 1 MiB; refuse to pack a runaway."""
    artifact = b"truth\n"
    huge_proof = b"WISEPROOF-V1\n\nk=v\n" + b"x" * (2 * 1024 * 1024)
    with pytest.raises(SealError):
        pack(artifact, huge_proof)


def test_h3_unpack_rejects_oversize_proof_section_in_header():
    """A handcrafted seal whose proof-length field claims > 1 MiB should be
    rejected at the length-field check, before any allocation."""
    # Build a seal byte sequence where the proof-length field declares 4 MiB.
    artifact = b"x"
    seal = (
        b"WISESEAL-V1\n"
        b"[ARTIFACT]\n"
        + (1).to_bytes(4, "big")
        + artifact
        + b"\n[PROOF]\n"
        + (4 * 1024 * 1024).to_bytes(4, "big")  # claim 4 MiB proof
        + b""  # but provide no bytes
        + b"\n[END]\n"
    )
    with pytest.raises(SealError):
        unpack(seal)


def test_c6_unpack_uses_subtraction_check_for_truncation():
    """Subtraction-form length check (`m > len(data) - pos`) must reject a
    seal whose declared proof length would, on a 32-bit add, wrap around."""
    # Construct a seal where the declared proof length is much larger than
    # remaining bytes. Even with normal sizes the check rejects, which is
    # what conformant ports must do too.
    artifact = b"truth\n"
    seal = (
        b"WISESEAL-V1\n"
        b"[ARTIFACT]\n"
        + len(artifact).to_bytes(4, "big")
        + artifact
        + b"\n[PROOF]\n"
        + (1024).to_bytes(4, "big")  # declare 1 KiB proof
        + b"only-a-few-bytes"  # provide far fewer
        + b"\n[END]\n"
    )
    with pytest.raises(SealError):
        unpack(seal)


# ============================================================================
# Adversarial torture: random bytes through unpack()
# ============================================================================
# Same contract as for decode(): unpack() must EITHER return (artifact, proof)
# OR raise SealError. Any other exception escaping is a bug an attacker can hit.

import random


def _unpack_must_raise_only_seal_error(data: bytes) -> None:
    try:
        unpack(data)
    except SealError:
        return
    except Exception as e:
        pytest.fail(
            f"unpack() raised unexpected {type(e).__name__}: {e!r} on input "
            f"of length {len(data)} starting with {data[:32]!r}"
        )


def test_torture_unpack_random_bytes_short():
    rng = random.Random(0x5EA1_DEAD)
    for _ in range(20_000):
        n = rng.randint(0, 100)
        data = bytes(rng.randint(0, 255) for _ in range(n))
        _unpack_must_raise_only_seal_error(data)


def test_torture_unpack_random_bytes_medium():
    rng = random.Random(0x5EA1_BEEF)
    for _ in range(10_000):
        n = rng.randint(100, 4096)
        data = bytes(rng.randint(0, 255) for _ in range(n))
        _unpack_must_raise_only_seal_error(data)


def test_torture_unpack_mutated_valid_seal(tmp_path):
    """Build a valid seal, flip random bytes, observe."""
    artifact = b"truth\n"
    items = build_file_proof_items(_stash(tmp_path, artifact), created_at=FIXED_TIME)
    base = pack(artifact, render(items))
    rng = random.Random(0xC0FFEE)
    for _ in range(10_000):
        data = bytearray(base)
        n_flips = rng.randint(1, 8)
        for _ in range(n_flips):
            i = rng.randint(0, len(data) - 1)
            data[i] = rng.randint(0, 255)
        try:
            a, p = unpack(bytes(data))
            # If unpack succeeded, the round-trip must produce sensible bytes.
            # (We don't assert they verify — only that the parser didn't crash.)
            assert isinstance(a, bytes) and isinstance(p, bytes)
        except SealError:
            pass
        except Exception as e:
            pytest.fail(f"unpack() crashed on mutated seal: {type(e).__name__}: {e!r}")


def test_torture_unpack_pathological_length_fields():
    """Length fields claiming MAX_UINT32, MAX_UINT32-1, etc."""
    artifact = b"x"
    rng = random.Random(0xDEADC0DE)
    pathological_lengths = [
        0x00000000, 0x00000001, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE,
        0xFFFFFFFF,
    ]
    for art_len in pathological_lengths:
        for proof_len in pathological_lengths:
            seal = (
                b"WISESEAL-V1\n"
                b"[ARTIFACT]\n"
                + art_len.to_bytes(4, "big")
                + b"x"  # absurdly short payload
                + b"\n[PROOF]\n"
                + proof_len.to_bytes(4, "big")
                + b"x"
                + b"\n[END]\n"
            )
            _unpack_must_raise_only_seal_error(seal)
