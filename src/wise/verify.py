"""Verification per §31.9 (v0.1.1 hardened).

Hardening applied:
    C1  constant-time digest comparison (hmac.compare_digest)
    C4  strict ASCII-digit parsing for integer fields
    H2  strict ISO-8601 UTC validation for origin.created_at
    H3  hard cap on .wiseproof file size before reading
    H4  reject unknown top-level keys
    H1/H5  enforce origin.attestation field and printable-ASCII creator
"""

from __future__ import annotations

import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime

from . import (
    ALLOWED_ARTIFACT_TYPES,
    ALLOWED_ATTESTATION,
    ALLOWED_KEYS_FILE,
    ALLOWED_KEYS_TEXT,
    ALLOWED_ORIGIN_MODES,
    MAX_PROOF_BYTES,
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
    "origin.attestation",  # v0.1.1
    "origin.created_at",
    "origin.creator",
    "origin.mode",
    "wise_id",
    "wise_seal",
)


# C4: strict integer = ASCII digits, no signs, no leading zeros except the
# single digit "0".
_STRICT_UINT = re.compile(r"^(?:0|[1-9][0-9]*)$")

# H2: ISO 8601 UTC, "YYYY-MM-DDTHH:MM:SSZ", no fractional seconds, no offset.
_ISO8601_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

# H1/H5: origin.creator must be printable ASCII (U+0020..U+007E) and contain
# no '=' or newline characters.
_PRINTABLE_ASCII_MIN = 0x20
_PRINTABLE_ASCII_MAX = 0x7E


def _parse_strict_uint(s: str) -> int | None:
    """Return non-negative int iff s is a strict ASCII-digit integer; else None."""
    if not _STRICT_UINT.match(s):
        return None
    return int(s)


def _is_iso8601_utc(s: str) -> bool:
    """True iff s matches ^YYYY-MM-DDTHH:MM:SSZ$ AND is a real calendar moment."""
    if not _ISO8601_UTC.match(s):
        return False
    try:
        datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
        return True
    except ValueError:
        return False


def _is_printable_ascii(s: str) -> bool:
    if s == "":
        return False
    for ch in s:
        cp = ord(ch)
        if cp < _PRINTABLE_ASCII_MIN or cp > _PRINTABLE_ASCII_MAX:
            return False
        if ch == "=" or ch == "\n":
            return False
    return True


def load_proof(path: str) -> tuple[dict[str, str] | None, VerifyResult | None]:
    # H3: cap proof file size before reading. A real .wiseproof is well
    # under 2 KB; refuse to load anything above MAX_PROOF_BYTES.
    try:
        size = os.path.getsize(path)
    except OSError as e:
        return None, VerifyResult(INVALID_PROOF, f"cannot stat proof: {e}")
    if size > MAX_PROOF_BYTES:
        return None, VerifyResult(
            INVALID_PROOF,
            f"proof file exceeds {MAX_PROOF_BYTES} byte cap (got {size})",
        )
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_PROOF_BYTES + 1)
    except OSError as e:
        return None, VerifyResult(INVALID_PROOF, f"cannot read proof: {e}")
    if len(raw) > MAX_PROOF_BYTES:
        return None, VerifyResult(
            INVALID_PROOF,
            f"proof file exceeds {MAX_PROOF_BYTES} byte cap",
        )
    try:
        items = decode(raw)
    except FormatError as e:
        return None, VerifyResult(INVALID_PROOF, f"proof format error: {e}")
    return items, None


def _check_required_and_keys(items: dict[str, str]) -> VerifyResult | None:
    # All required common keys must be present.
    for k in _REQUIRED_COMMON:
        if k not in items:
            return VerifyResult(INVALID_PROOF, f"missing required key: {k}")

    # H4: every key must be in the closed allow-set for this artifact type.
    artifact_type = items["artifact.type"]
    if artifact_type not in ALLOWED_ARTIFACT_TYPES:
        return VerifyResult(
            INVALID_PROOF, f"unknown artifact.type: {artifact_type!r}"
        )
    allowed = ALLOWED_KEYS_FILE if artifact_type == "file" else ALLOWED_KEYS_TEXT
    for k in items.keys():
        if k not in allowed:
            return VerifyResult(INVALID_PROOF, f"unknown key not allowed: {k}")

    if artifact_type == "text":
        if items.get("artifact.encoding") != "utf-8":
            return VerifyResult(
                INVALID_PROOF, "text artifact requires artifact.encoding=utf-8"
            )
    elif artifact_type == "file":
        if "artifact.encoding" in items:
            return VerifyResult(
                INVALID_PROOF, "file artifact must not carry artifact.encoding"
            )

    # C4: strict integer check.
    size = _parse_strict_uint(items["artifact.size_bytes"])
    if size is None:
        return VerifyResult(
            INVALID_PROOF,
            "artifact.size_bytes is not a strict ASCII-digit integer",
        )

    # H2: strict ISO 8601 UTC check.
    if not _is_iso8601_utc(items["origin.created_at"]):
        return VerifyResult(
            INVALID_PROOF,
            "origin.created_at is not a valid ISO 8601 UTC timestamp",
        )

    # H1/H5: origin.attestation must be from the closed allow-set.
    att = items["origin.attestation"]
    if att not in ALLOWED_ATTESTATION:
        return VerifyResult(
            INVALID_PROOF,
            f"origin.attestation {att!r} not in {ALLOWED_ATTESTATION}",
        )

    # H1: origin.creator must be printable ASCII (no homoglyphs).
    if not _is_printable_ascii(items["origin.creator"]):
        return VerifyResult(
            INVALID_PROOF,
            "origin.creator must be printable ASCII",
        )

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
    # C1: constant-time comparison.
    if not hmac.compare_digest(actual_id, expected_id):
        return VerifyResult(
            INVALID_PROOF,
            "wise_id mismatch — proof body has been altered",
            expected_digest=expected_id,
            observed_digest=actual_id,
        )
    expected_seal = items["wise_seal"]
    actual_seal = compute_wise_seal(items, algo)
    if not hmac.compare_digest(actual_seal, expected_seal):
        return VerifyResult(
            INVALID_PROOF,
            "wise_seal mismatch — proof body has been altered",
            expected_digest=expected_seal,
            observed_digest=actual_seal,
        )
    return None


def _common_preamble(items: dict[str, str]) -> VerifyResult | None:
    if (r := _check_required_and_keys(items)) is not None:
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

    expected_size = _parse_strict_uint(items["artifact.size_bytes"])
    assert expected_size is not None  # validated in preamble
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
    # C1: constant-time comparison.
    if not hmac.compare_digest(actual_digest, expected_digest):
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

    expected_size = _parse_strict_uint(items["artifact.size_bytes"])
    assert expected_size is not None
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
    # C1: constant-time comparison.
    if not hmac.compare_digest(actual_digest, expected_digest):
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
