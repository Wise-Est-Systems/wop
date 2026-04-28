"""Verification per §31.9."""

from __future__ import annotations

import os
from dataclasses import dataclass

from . import (
    ALLOWED_ARTIFACT_TYPES,
    ALLOWED_ORIGIN_MODES,
    SUPPORTED_ALGORITHMS,
)
from .errors import (
    INVALID_PROOF,
    TAMPERED,
    UNREADABLE_ARTIFACT,
    UNSUPPORTED_ALGORITHM,
    VERIFIED,
)
from .format import FormatError, decode
from .proof import compute_wise_id, compute_wise_seal, digest_file, digest_text


@dataclass
class VerifyResult:
    status: str
    detail: str = ""
    expected_digest: str | None = None
    observed_digest: str | None = None
    expected_size: int | None = None
    observed_size: int | None = None
    wise_id: str | None = None
    wise_seal: str | None = None


_REQUIRED_COMMON = (
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
)


def load_proof(path: str) -> tuple[dict[str, str] | None, VerifyResult | None]:
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        return None, VerifyResult(INVALID_PROOF, f"cannot read proof: {e}")
    try:
        items = decode(raw)
    except FormatError as e:
        return None, VerifyResult(INVALID_PROOF, f"proof format error: {e}")
    return items, None


def _check_required(items: dict[str, str]) -> VerifyResult | None:
    for k in _REQUIRED_COMMON:
        if k not in items:
            return VerifyResult(INVALID_PROOF, f"missing required key: {k}")
    if items["artifact.type"] not in ALLOWED_ARTIFACT_TYPES:
        return VerifyResult(INVALID_PROOF, f"unknown artifact.type: {items['artifact.type']!r}")
    if items["artifact.type"] == "text":
        if items.get("artifact.encoding") != "utf-8":
            return VerifyResult(INVALID_PROOF, "text artifact requires artifact.encoding=utf-8")
    try:
        size = int(items["artifact.size_bytes"])
    except ValueError:
        return VerifyResult(INVALID_PROOF, "artifact.size_bytes is not an integer")
    if size < 0:
        return VerifyResult(INVALID_PROOF, "artifact.size_bytes is negative")
    return None


def _check_algorithm(items: dict[str, str]) -> VerifyResult | None:
    algo = items["measurement.algorithm"]
    if algo not in SUPPORTED_ALGORITHMS:
        return VerifyResult(UNSUPPORTED_ALGORITHM, f"algorithm {algo!r} not supported")
    return None


def _check_origin_mode(items: dict[str, str]) -> VerifyResult | None:
    mode = items["origin.mode"]
    if mode not in ALLOWED_ORIGIN_MODES:
        return VerifyResult(INVALID_PROOF, f"origin.mode {mode!r} not allowed")
    return None


def _check_ids(items: dict[str, str]) -> VerifyResult | None:
    algo = items["measurement.algorithm"]
    expected_id = items["wise_id"]
    actual_id = compute_wise_id(items, algo)
    if actual_id != expected_id:
        return VerifyResult(
            INVALID_PROOF,
            "wise_id mismatch — proof body has been altered",
            expected_digest=expected_id,
            observed_digest=actual_id,
        )
    expected_seal = items["wise_seal"]
    actual_seal = compute_wise_seal(items, algo)
    if actual_seal != expected_seal:
        return VerifyResult(
            INVALID_PROOF,
            "wise_seal mismatch — proof body has been altered",
            expected_digest=expected_seal,
            observed_digest=actual_seal,
        )
    return None


def _common_preamble(items: dict[str, str]) -> VerifyResult | None:
    if (r := _check_required(items)) is not None:
        return r
    if (r := _check_algorithm(items)) is not None:
        return r
    if (r := _check_origin_mode(items)) is not None:
        return r
    if (r := _check_ids(items)) is not None:
        return r
    return None


def verify_file(artifact_path: str, items: dict[str, str]) -> VerifyResult:
    if (r := _common_preamble(items)) is not None:
        return r
    if items["artifact.type"] != "file":
        return VerifyResult(INVALID_PROOF, "proof is not for a file artifact")

    expected_size = int(items["artifact.size_bytes"])
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

    algo = items["measurement.algorithm"]
    expected_digest = items["measurement.digest"]
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
        wise_id=items["wise_id"],
        wise_seal=items["wise_seal"],
    )


def verify_text(text: str, items: dict[str, str]) -> VerifyResult:
    if (r := _common_preamble(items)) is not None:
        return r
    if items["artifact.type"] != "text":
        return VerifyResult(INVALID_PROOF, "proof is not for a text artifact")

    expected_size = int(items["artifact.size_bytes"])
    raw = text.encode("utf-8")
    if len(raw) != expected_size:
        return VerifyResult(
            TAMPERED,
            "size mismatch",
            expected_size=expected_size,
            observed_size=len(raw),
        )

    algo = items["measurement.algorithm"]
    expected_digest = items["measurement.digest"]
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
        observed_size=len(raw),
        wise_id=items["wise_id"],
        wise_seal=items["wise_seal"],
    )
