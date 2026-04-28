"""End-to-end tests for verify_file / verify_text covering all status codes."""

from __future__ import annotations

import copy
import json
import os

from spas.canonical import canonicalize
from spas.errors import (
    INVALID_PROOF,
    TAMPERED,
    UNREADABLE_ARTIFACT,
    UNSUPPORTED_ALGORITHM,
    UNSUPPORTED_VERSION,
    VERIFIED,
)
from spas.proof import build_file_proof, build_text_proof
from spas.verify import load_proof, verify_file, verify_text


FIXED_TIME = "2026-04-27T00:00:00Z"


def _write_bytes(tmp_path, name, data):
    p = os.path.join(tmp_path, name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def _write_proof_json(tmp_path, name, proof):
    p = os.path.join(tmp_path, name)
    with open(p, "wb") as f:
        f.write(canonicalize(proof))
    return p


def test_verified_round_trip_file(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    proof = build_file_proof(f, created_at_utc=FIXED_TIME)
    assert verify_file(f, proof).status == VERIFIED


def test_verified_round_trip_text(tmp_path):
    proof = build_text_proof("truth\n", created_at_utc=FIXED_TIME)
    assert verify_text("truth\n", proof).status == VERIFIED


def test_tampered_byte_mutation(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    proof = build_file_proof(f, created_at_utc=FIXED_TIME)
    with open(f, "wb") as fh:
        fh.write(b"changed\n")
    r = verify_file(f, proof)
    assert r.status == TAMPERED


def test_tampered_text_mutation(tmp_path):
    proof = build_text_proof("truth\n", created_at_utc=FIXED_TIME)
    r = verify_text("truth\r\n", proof)
    assert r.status == TAMPERED


def test_tampered_truncation(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    proof = build_file_proof(f, created_at_utc=FIXED_TIME)
    with open(f, "wb") as fh:
        fh.write(b"trut")  # shorter
    r = verify_file(f, proof)
    assert r.status == TAMPERED


def test_replay_against_different_artifact_is_tampered(tmp_path):
    f1 = _write_bytes(tmp_path, "a.txt", b"truth\n")
    f2 = _write_bytes(tmp_path, "b.txt", b"different bytes\n")
    proof = build_file_proof(f1, created_at_utc=FIXED_TIME)
    r = verify_file(f2, proof)
    assert r.status == TAMPERED


def test_invalid_proof_when_proof_body_mutated(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    proof = build_file_proof(f, created_at_utc=FIXED_TIME)
    proof["origin"]["creator_label"] = "Attacker"  # but proof_id was computed with the old label
    r = verify_file(f, proof)
    assert r.status == INVALID_PROOF


def test_invalid_proof_when_required_field_missing(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    proof = build_file_proof(f, created_at_utc=FIXED_TIME)
    del proof["status_rule"]
    r = verify_file(f, proof)
    assert r.status == INVALID_PROOF


def test_unsupported_version(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    proof = build_file_proof(f, created_at_utc=FIXED_TIME)
    proof["spas_version"] = "9.9.9"
    r = verify_file(f, proof)
    assert r.status == UNSUPPORTED_VERSION


def test_unsupported_algorithm_field(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    proof = build_file_proof(f, created_at_utc=FIXED_TIME)
    proof["measurement"]["algorithm"] = "MD5"
    r = verify_file(f, proof)
    assert r.status == UNSUPPORTED_ALGORITHM


def test_unreadable_artifact(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    proof = build_file_proof(f, created_at_utc=FIXED_TIME)
    missing = os.path.join(tmp_path, "nope.txt")
    r = verify_file(missing, proof)
    assert r.status == UNREADABLE_ARTIFACT


def test_size_check_short_circuits_before_digest(tmp_path):
    """§30.9 — size mismatch returns TAMPERED with size_bytes recorded but no digest read."""
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    proof = build_file_proof(f, created_at_utc=FIXED_TIME)
    with open(f, "wb") as fh:
        fh.write(b"truth\n\n")  # one byte longer
    r = verify_file(f, proof)
    assert r.status == TAMPERED
    assert r.expected_size == 6
    assert r.observed_size == 7
    assert r.observed_digest is None  # digest not computed because size short-circuited


def test_load_proof_unreadable_returns_invalid(tmp_path):
    bad = os.path.join(tmp_path, "bad.spas.json")
    with open(bad, "wb") as fh:
        fh.write(b"{not valid json")
    proof, err = load_proof(bad)
    assert proof is None
    assert err is not None
    assert err.status == INVALID_PROOF


def test_proof_file_is_bit_for_bit_reproducible(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    p1 = build_file_proof(f, created_at_utc=FIXED_TIME)
    p2 = build_file_proof(f, created_at_utc=FIXED_TIME)
    out1 = _write_proof_json(tmp_path, "1.spas.json", p1)
    out2 = _write_proof_json(tmp_path, "2.spas.json", p2)
    with open(out1, "rb") as f1, open(out2, "rb") as f2:
        assert f1.read() == f2.read()
