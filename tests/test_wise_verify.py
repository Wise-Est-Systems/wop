"""End-to-end verify tests for WISE covering every status."""

from __future__ import annotations

import os

from wise.errors import (
    INVALID_PROOF,
    TAMPERED,
    UNREADABLE_ARTIFACT,
    UNSUPPORTED_ALGORITHM,
    VERIFIED,
)
from wise.format import encode
from wise.proof import build_file_proof_items, build_text_proof_items, render
from wise.verify import load_proof, verify_file, verify_text


FIXED_TIME = "2026-04-27T00:00:00Z"


def _write_bytes(tmp_path, name, data):
    p = os.path.join(tmp_path, name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def _write_proof(tmp_path, name, items):
    p = os.path.join(tmp_path, name)
    with open(p, "wb") as f:
        f.write(render(items))
    return p


def test_verified_file_round_trip(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    proof_path = _write_proof(tmp_path, "demo.txt.wiseproof", items)
    parsed, err = load_proof(proof_path)
    assert err is None
    assert verify_file(f, parsed).status == VERIFIED


def test_verified_text_round_trip():
    items = build_text_proof_items("truth\n", created_at=FIXED_TIME)
    assert verify_text("truth\n", items).status == VERIFIED


def test_tampered_byte_change(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    with open(f, "wb") as fh:
        fh.write(b"changed\n")
    assert verify_file(f, items).status == TAMPERED


def test_tampered_text_crlf(tmp_path):
    items = build_text_proof_items("truth\n", created_at=FIXED_TIME)
    assert verify_text("truth\r\n", items).status == TAMPERED


def test_size_mismatch_short_circuits_to_tampered(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    with open(f, "wb") as fh:
        fh.write(b"truth\n\n")  # one byte longer
    r = verify_file(f, items)
    assert r.status == TAMPERED
    assert r.expected_size == 6
    assert r.observed_size == 7
    assert r.observed_digest is None  # short-circuit, no digest computed


def test_replay_against_other_artifact_is_tampered(tmp_path):
    f1 = _write_bytes(tmp_path, "a.txt", b"truth\n")
    f2 = _write_bytes(tmp_path, "b.txt", b"differs\n")
    items = build_file_proof_items(f1, created_at=FIXED_TIME)
    assert verify_file(f2, items).status == TAMPERED


def test_invalid_proof_when_body_mutated(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    items["origin.creator"] = "Attacker"
    assert verify_file(f, items).status == INVALID_PROOF


def test_invalid_proof_when_required_key_missing(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    del items["artifact.size_bytes"]
    assert verify_file(f, items).status == INVALID_PROOF


def test_unsupported_algorithm_field(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    items["measurement.algorithm"] = "MD5"
    assert verify_file(f, items).status == UNSUPPORTED_ALGORITHM


def test_unreadable_artifact(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    missing = os.path.join(tmp_path, "no.txt")
    assert verify_file(missing, items).status == UNREADABLE_ARTIFACT


def test_load_proof_rejects_bad_file(tmp_path):
    bad = os.path.join(tmp_path, "bad.wiseproof")
    with open(bad, "wb") as fh:
        fh.write(b"not a wiseproof\n")
    parsed, err = load_proof(bad)
    assert parsed is None
    assert err is not None
    assert err.status == INVALID_PROOF


def test_format_violation_in_proof_file_is_invalid_proof(tmp_path):
    """A handcrafted proof violating sort order parses as INVALID_PROOF."""
    bad = os.path.join(tmp_path, "bad.wiseproof")
    with open(bad, "wb") as fh:
        fh.write(b"WISEPROOF-V1\n\nz=1\na=2\n")  # keys out of order
    parsed, err = load_proof(bad)
    assert parsed is None and err is not None
    assert err.status == INVALID_PROOF
