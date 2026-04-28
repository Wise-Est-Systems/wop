"""Tests for proof construction and identity model (proof_id / seal_id)."""

from __future__ import annotations

import os

import pytest

from spas.canonical import canonicalize
from spas.proof import (
    build_file_proof,
    build_text_proof,
    compute_proof_id,
    compute_seal_id,
)


FIXED_TIME = "2026-04-27T00:00:00Z"


def _write(tmp_path, name, data):
    p = os.path.join(tmp_path, name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def test_text_proof_has_required_top_level_fields(tmp_path):
    proof = build_text_proof("truth\n", created_at_utc=FIXED_TIME)
    for k in (
        "spas_version",
        "proof_format",
        "artifact",
        "measurement",
        "origin",
        "proof_id",
        "seal_id",
        "status_rule",
    ):
        assert k in proof


def test_proof_id_excludes_time_creator_unaffected_by_rename(tmp_path):
    """Same artifact, same algorithm, different time → same proof_id."""
    p1 = build_text_proof("truth\n", created_at_utc="2026-01-01T00:00:00Z")
    p2 = build_text_proof("truth\n", created_at_utc="2099-12-31T23:59:59Z")
    assert p1["proof_id"] == p2["proof_id"]
    assert p1["seal_id"] != p2["seal_id"]


def test_proof_id_changes_with_creator(tmp_path):
    p1 = build_text_proof("truth\n", created_at_utc=FIXED_TIME, creator_label="A")
    p2 = build_text_proof("truth\n", created_at_utc=FIXED_TIME, creator_label="B")
    assert p1["proof_id"] != p2["proof_id"]


def test_proof_id_unaffected_by_artifact_name(tmp_path):
    """artifact.name is metadata-only (§30.12) — must not affect proof_id."""
    file_a = _write(tmp_path, "a.txt", b"truth\n")
    file_b = _write(tmp_path, "b.txt", b"truth\n")
    pa = build_file_proof(file_a, created_at_utc=FIXED_TIME)
    pb = build_file_proof(file_b, created_at_utc=FIXED_TIME)
    assert pa["artifact"]["name"] != pb["artifact"]["name"]
    assert pa["proof_id"] == pb["proof_id"]


def test_proof_id_changes_when_bytes_change(tmp_path):
    f1 = _write(tmp_path, "x1.txt", b"truth\n")
    f2 = _write(tmp_path, "x2.txt", b"changed\n")
    p1 = build_file_proof(f1, created_at_utc=FIXED_TIME)
    p2 = build_file_proof(f2, created_at_utc=FIXED_TIME)
    assert p1["proof_id"] != p2["proof_id"]


def test_recomputed_ids_match_stored(tmp_path):
    proof = build_text_proof("truth\n", created_at_utc=FIXED_TIME)
    assert compute_proof_id(proof) == proof["proof_id"]
    assert compute_seal_id(proof) == proof["seal_id"]


def test_canonical_json_is_bit_for_bit_deterministic(tmp_path):
    """The serialized proof file must be byte-identical across runs."""
    f = _write(tmp_path, "demo.txt", b"truth\n")
    p1 = build_file_proof(f, created_at_utc=FIXED_TIME)
    p2 = build_file_proof(f, created_at_utc=FIXED_TIME)
    assert canonicalize(p1) == canonicalize(p2)


def test_supports_sha256_algorithm(tmp_path):
    proof = build_text_proof("truth\n", algorithm="SHA-256", created_at_utc=FIXED_TIME)
    assert proof["measurement"]["algorithm"] == "SHA-256"
    assert len(proof["measurement"]["digest"]) == 64


def test_unsupported_algorithm_rejected():
    with pytest.raises(ValueError):
        build_text_proof("x", algorithm="MD5")
