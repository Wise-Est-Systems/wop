"""Identity-model and determinism tests for WISE proofs."""

from __future__ import annotations

import os

import pytest

from wise.proof import (
    build_file_proof_items,
    build_text_proof_items,
    compute_wise_id,
    compute_wise_seal,
    render,
)


FIXED_TIME = "2026-04-27T00:00:00Z"


def _write(tmp_path, name, data):
    p = os.path.join(tmp_path, name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def test_required_keys_present(tmp_path):
    items = build_text_proof_items("truth\n", created_at=FIXED_TIME)
    for k in (
        "artifact.encoding",
        "artifact.name",
        "artifact.size_bytes",
        "artifact.type",
        "measurement.algorithm",
        "measurement.digest",
        "origin.created_at",
        "origin.creator",
        "origin.mode",
        "wise_id",
        "wise_seal",
    ):
        assert k in items


def test_wise_id_excludes_time(tmp_path):
    a = build_text_proof_items("truth\n", created_at="2026-01-01T00:00:00Z")
    b = build_text_proof_items("truth\n", created_at="2099-12-31T23:59:59Z")
    assert a["wise_id"] == b["wise_id"]
    assert a["wise_seal"] != b["wise_seal"]


def test_wise_id_excludes_artifact_name(tmp_path):
    f1 = _write(tmp_path, "alpha.txt", b"truth\n")
    f2 = _write(tmp_path, "beta.txt", b"truth\n")
    p1 = build_file_proof_items(f1, created_at=FIXED_TIME)
    p2 = build_file_proof_items(f2, created_at=FIXED_TIME)
    assert p1["artifact.name"] != p2["artifact.name"]
    assert p1["wise_id"] == p2["wise_id"]


def test_wise_id_changes_when_creator_changes():
    a = build_text_proof_items("truth\n", created_at=FIXED_TIME, creator="A")
    b = build_text_proof_items("truth\n", created_at=FIXED_TIME, creator="B")
    assert a["wise_id"] != b["wise_id"]


def test_wise_id_changes_when_bytes_change(tmp_path):
    f1 = _write(tmp_path, "a.txt", b"truth\n")
    f2 = _write(tmp_path, "b.txt", b"changed\n")
    p1 = build_file_proof_items(f1, created_at=FIXED_TIME)
    p2 = build_file_proof_items(f2, created_at=FIXED_TIME)
    assert p1["wise_id"] != p2["wise_id"]


def test_recomputed_ids_match_stored():
    items = build_text_proof_items("truth\n", created_at=FIXED_TIME)
    algo = items["measurement.algorithm"]
    assert compute_wise_id(items, algo) == items["wise_id"]
    assert compute_wise_seal(items, algo) == items["wise_seal"]


def test_proof_file_is_byte_for_byte_reproducible(tmp_path):
    f = _write(tmp_path, "demo.txt", b"truth\n")
    p1 = build_file_proof_items(f, created_at=FIXED_TIME)
    p2 = build_file_proof_items(f, created_at=FIXED_TIME)
    assert render(p1) == render(p2)


def test_sha256_supported():
    items = build_text_proof_items("truth\n", algorithm="SHA-256", created_at=FIXED_TIME)
    assert items["measurement.algorithm"] == "SHA-256"
    assert len(items["measurement.digest"]) == 64


def test_unsupported_algorithm_rejected():
    with pytest.raises(ValueError):
        build_text_proof_items("x", algorithm="MD5")


# ============================================================================
# v0.1.1 hardening tests
# ============================================================================


def test_v0_1_1_attestation_field_is_set_to_self_declared():
    items = build_text_proof_items("hi\n", created_at=FIXED_TIME)
    assert items["origin.attestation"] == "self_declared"


def test_v0_1_1_attestation_excluded_from_wise_id(tmp_path):
    """wise_id must be stable across attestation states. A future v0.4
    signed proof of the same artifact must have the same wise_id as a
    v0.1.1 self_declared proof."""
    items = build_text_proof_items("hi\n", created_at=FIXED_TIME)
    id_with = compute_wise_id(items, items["measurement.algorithm"])

    # Simulate: same artifact + creator + algo but no attestation field.
    # We compute wise_id with a copy that omits attestation; the result
    # must equal what build_text_proof_items produced.
    items_no_att = {k: v for k, v in items.items() if k != "origin.attestation"}
    # Don't recompute wise_id from a body missing the field — instead,
    # confirm that compute_wise_id ignores attestation by construction.
    id_without = compute_wise_id(items_no_att, items["measurement.algorithm"])
    assert id_with == id_without == items["wise_id"]


def test_v0_1_1_attestation_included_in_wise_seal(tmp_path):
    """wise_seal MUST commit to the attestation value. Replacing it should
    break wise_seal re-derivation."""
    items = build_text_proof_items("hi\n", created_at=FIXED_TIME)
    # We cannot legally set attestation to a non-allowed value here without
    # also having to update wise_seal — just confirm the seal contains it.
    seal_with = compute_wise_seal(items, items["measurement.algorithm"])
    items_no_att = {k: v for k, v in items.items() if k != "origin.attestation"}
    seal_without = compute_wise_seal(items_no_att, items["measurement.algorithm"])
    assert seal_with != seal_without


def test_v0_1_1_creator_homoglyph_rejected_at_build_time(tmp_path):
    """build_*_proof_items() rejects non-ASCII creator immediately."""
    p = _write(tmp_path, "demo.txt", b"truth\n")
    with pytest.raises(ValueError):
        build_file_proof_items(p, creator="Аnthropic", created_at=FIXED_TIME)


def test_v0_1_1_creator_empty_rejected_at_build_time():
    with pytest.raises(ValueError):
        build_text_proof_items("x\n", creator="", created_at=FIXED_TIME)


def test_v0_1_1_creator_ascii_punctuation_accepted():
    """Printable ASCII includes punctuation: dots, parens, hyphens, etc."""
    items = build_text_proof_items(
        "x\n", creator="Wise.Est Systems (2026) - test", created_at=FIXED_TIME
    )
    assert items["origin.creator"] == "Wise.Est Systems (2026) - test"
