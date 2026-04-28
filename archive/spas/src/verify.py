"""Verification per SPAS §30.10 (replaces §8 ordering).

Order:
  1. Parse proof JSON                         -> INVALID_PROOF
  2. Required fields per §30.17               -> INVALID_PROOF
  3. spas_version + proof_format              -> UNSUPPORTED_VERSION
  4. measurement.algorithm support            -> UNSUPPORTED_ALGORITHM
  5. origin.mode                              -> INVALID_PROOF
  6. proof_id                                 -> INVALID_PROOF
  7. seal_id                                  -> INVALID_PROOF
  8. size                                     -> TAMPERED  (short-circuit)
  9. open artifact                            -> UNREADABLE_ARTIFACT
 10. artifact digest                          -> TAMPERED
 11. VERIFIED
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from . import (
    ALLOWED_ARTIFACT_TYPES,
    ALLOWED_ORIGIN_MODES,
    PROOF_FORMAT,
    SPAS_VERSION,
    STATUS_RULE,
    SUPPORTED_ALGORITHMS,
)
from .errors import (
    INVALID_PROOF,
    TAMPERED,
    UNREADABLE_ARTIFACT,
    UNSUPPORTED_ALGORITHM,
    UNSUPPORTED_VERSION,
    VERIFIED,
)
from .proof import compute_proof_id, compute_seal_id, digest_file, digest_text


@dataclass
class VerifyResult:
    status: str
    detail: str = ""
    expected_digest: str | None = None
    observed_digest: str | None = None
    expected_size: int | None = None
    observed_size: int | None = None
    proof_id: str | None = None
    seal_id: str | None = None


_REQUIRED_TOP = (
    "spas_version",
    "proof_format",
    "artifact",
    "measurement",
    "origin",
    "proof_id",
    "seal_id",
    "status_rule",
)
_REQUIRED_ARTIFACT = ("type", "name", "size_bytes")
_REQUIRED_MEASUREMENT = ("algorithm", "digest")
_REQUIRED_ORIGIN = ("mode", "created_at_utc", "creator_label")


def load_proof(path: str) -> tuple[dict[str, Any] | None, VerifyResult | None]:
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        return None, VerifyResult(INVALID_PROOF, f"cannot read proof: {e}")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        return None, VerifyResult(INVALID_PROOF, f"proof JSON unreadable: {e}")
    if not isinstance(obj, dict):
        return None, VerifyResult(INVALID_PROOF, "proof root must be a JSON object")
    return obj, None


def _check_required_fields(proof: dict[str, Any]) -> VerifyResult | None:
    for k in _REQUIRED_TOP:
        if k not in proof:
            return VerifyResult(INVALID_PROOF, f"missing required field: {k}")
    art = proof["artifact"]
    if not isinstance(art, dict):
        return VerifyResult(INVALID_PROOF, "artifact must be an object")
    for k in _REQUIRED_ARTIFACT:
        if k not in art:
            return VerifyResult(INVALID_PROOF, f"missing required field: artifact.{k}")
    if art["type"] not in ALLOWED_ARTIFACT_TYPES:
        return VerifyResult(INVALID_PROOF, f"unknown artifact.type: {art['type']!r}")
    if art["type"] == "text" and art.get("encoding") != "utf-8":
        return VerifyResult(INVALID_PROOF, "text artifact requires encoding=utf-8")
    if not isinstance(art["size_bytes"], int) or art["size_bytes"] < 0:
        return VerifyResult(INVALID_PROOF, "artifact.size_bytes must be non-negative integer")

    mes = proof["measurement"]
    if not isinstance(mes, dict):
        return VerifyResult(INVALID_PROOF, "measurement must be an object")
    for k in _REQUIRED_MEASUREMENT:
        if k not in mes:
            return VerifyResult(INVALID_PROOF, f"missing required field: measurement.{k}")

    org = proof["origin"]
    if not isinstance(org, dict):
        return VerifyResult(INVALID_PROOF, "origin must be an object")
    for k in _REQUIRED_ORIGIN:
        if k not in org:
            return VerifyResult(INVALID_PROOF, f"missing required field: origin.{k}")

    if proof["status_rule"] != STATUS_RULE:
        return VerifyResult(INVALID_PROOF, f"status_rule must be {STATUS_RULE!r}")
    return None


def _check_versions(proof: dict[str, Any]) -> VerifyResult | None:
    if proof["spas_version"] != SPAS_VERSION:
        return VerifyResult(
            UNSUPPORTED_VERSION,
            f"spas_version {proof['spas_version']!r} not supported (need {SPAS_VERSION!r})",
        )
    if proof["proof_format"] != PROOF_FORMAT:
        return VerifyResult(
            UNSUPPORTED_VERSION,
            f"proof_format {proof['proof_format']!r} not supported (need {PROOF_FORMAT!r})",
        )
    return None


def _check_algorithm(proof: dict[str, Any]) -> VerifyResult | None:
    algo = proof["measurement"]["algorithm"]
    if algo not in SUPPORTED_ALGORITHMS:
        return VerifyResult(UNSUPPORTED_ALGORITHM, f"algorithm {algo!r} not supported")
    return None


def _check_origin_mode(proof: dict[str, Any]) -> VerifyResult | None:
    mode = proof["origin"]["mode"]
    if mode not in ALLOWED_ORIGIN_MODES:
        return VerifyResult(INVALID_PROOF, f"origin.mode {mode!r} not allowed")
    return None


def _check_ids(proof: dict[str, Any]) -> VerifyResult | None:
    expected_pid = proof["proof_id"]
    actual_pid = compute_proof_id(proof)
    if actual_pid != expected_pid:
        return VerifyResult(
            INVALID_PROOF,
            "proof_id mismatch — proof body has been altered",
            expected_digest=expected_pid,
            observed_digest=actual_pid,
        )
    expected_sid = proof["seal_id"]
    actual_sid = compute_seal_id(proof)
    if actual_sid != expected_sid:
        return VerifyResult(
            INVALID_PROOF,
            "seal_id mismatch — proof body has been altered",
            expected_digest=expected_sid,
            observed_digest=actual_sid,
        )
    return None


def verify_file(artifact_path: str, proof: dict[str, Any]) -> VerifyResult:
    if (r := _check_required_fields(proof)) is not None:
        return r
    if (r := _check_versions(proof)) is not None:
        return r
    if (r := _check_algorithm(proof)) is not None:
        return r
    if (r := _check_origin_mode(proof)) is not None:
        return r
    if proof["artifact"]["type"] != "file":
        return VerifyResult(INVALID_PROOF, "proof is not a file artifact proof")
    if (r := _check_ids(proof)) is not None:
        return r

    expected_size = proof["artifact"]["size_bytes"]
    try:
        actual_size = os.path.getsize(artifact_path)
    except OSError as e:
        return VerifyResult(UNREADABLE_ARTIFACT, f"cannot stat artifact: {e}")
    if actual_size != expected_size:
        return VerifyResult(
            TAMPERED,
            "size mismatch",
            expected_size=expected_size,
            observed_size=actual_size,
        )

    algo = proof["measurement"]["algorithm"]
    expected_digest = proof["measurement"]["digest"]
    try:
        actual_digest, _ = digest_file(artifact_path, algo)
    except OSError as e:
        return VerifyResult(UNREADABLE_ARTIFACT, f"cannot read artifact: {e}")
    if actual_digest != expected_digest:
        return VerifyResult(
            TAMPERED,
            "digest mismatch",
            expected_digest=expected_digest,
            observed_digest=actual_digest,
        )

    return VerifyResult(
        VERIFIED,
        "",
        expected_digest=expected_digest,
        observed_digest=actual_digest,
        expected_size=expected_size,
        observed_size=actual_size,
        proof_id=proof["proof_id"],
        seal_id=proof["seal_id"],
    )


def verify_text(text: str, proof: dict[str, Any]) -> VerifyResult:
    if (r := _check_required_fields(proof)) is not None:
        return r
    if (r := _check_versions(proof)) is not None:
        return r
    if (r := _check_algorithm(proof)) is not None:
        return r
    if (r := _check_origin_mode(proof)) is not None:
        return r
    if proof["artifact"]["type"] != "text":
        return VerifyResult(INVALID_PROOF, "proof is not a text artifact proof")
    if (r := _check_ids(proof)) is not None:
        return r

    expected_size = proof["artifact"]["size_bytes"]
    raw = text.encode("utf-8")
    actual_size = len(raw)
    if actual_size != expected_size:
        return VerifyResult(
            TAMPERED,
            "size mismatch",
            expected_size=expected_size,
            observed_size=actual_size,
        )

    algo = proof["measurement"]["algorithm"]
    expected_digest = proof["measurement"]["digest"]
    actual_digest, _ = digest_text(text, algo)
    if actual_digest != expected_digest:
        return VerifyResult(
            TAMPERED,
            "digest mismatch",
            expected_digest=expected_digest,
            observed_digest=actual_digest,
        )

    return VerifyResult(
        VERIFIED,
        "",
        expected_digest=expected_digest,
        observed_digest=actual_digest,
        expected_size=expected_size,
        observed_size=actual_size,
        proof_id=proof["proof_id"],
        seal_id=proof["seal_id"],
    )
