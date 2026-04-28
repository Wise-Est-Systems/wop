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
