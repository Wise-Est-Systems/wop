"""Build SPAS proof objects per §30.

Identity model (§30.5 + §30.12):
    proof_id = digest(canonical(P without proof_id, seal_id,
                                origin.created_at_utc, artifact.name))
    seal_id  = digest(canonical(P without proof_id, seal_id))

artifact.name is excluded from the proof_id digest because §30.12 declares
it metadata only. It is still recorded in the proof JSON for human readers.
"""

from __future__ import annotations

import copy
import os
from datetime import datetime, timezone
from typing import Any

from . import (
    DEFAULT_CREATOR,
    PROOF_FORMAT,
    SPAS_VERSION,
    STATUS_RULE,
    SUPPORTED_ALGORITHMS,
)
from .canonical import canonicalize
from .digest import new_hasher

_FILE_CHUNK = 64 * 1024


def now_utc_iso() -> str:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def _ensure_algo(algorithm: str) -> None:
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"unsupported algorithm: {algorithm}")


def digest_file(path: str, algorithm: str) -> tuple[str, int]:
    _ensure_algo(algorithm)
    h = new_hasher(algorithm)
    size = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_FILE_CHUNK)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def digest_text(text: str, algorithm: str) -> tuple[str, int]:
    _ensure_algo(algorithm)
    raw = text.encode("utf-8")
    h = new_hasher(algorithm)
    h.update(raw)
    return h.hexdigest(), len(raw)


def _strip_for_proof_id(proof: dict[str, Any]) -> dict[str, Any]:
    p = copy.deepcopy(proof)
    p.pop("proof_id", None)
    p.pop("seal_id", None)
    if "origin" in p and isinstance(p["origin"], dict):
        p["origin"].pop("created_at_utc", None)
    if "artifact" in p and isinstance(p["artifact"], dict):
        p["artifact"].pop("name", None)
    return p


def _strip_for_seal_id(proof: dict[str, Any]) -> dict[str, Any]:
    p = copy.deepcopy(proof)
    p.pop("proof_id", None)
    p.pop("seal_id", None)
    return p


def _id_algorithm(measurement_algorithm: str) -> str:
    # Identity ids use the same algorithm as the artifact measurement.
    return measurement_algorithm


def _digest_obj(obj: dict[str, Any], algorithm: str) -> str:
    h = new_hasher(algorithm)
    h.update(canonicalize(obj))
    return h.hexdigest()


def compute_proof_id(proof: dict[str, Any]) -> str:
    algo = proof["measurement"]["algorithm"]
    return _digest_obj(_strip_for_proof_id(proof), _id_algorithm(algo))


def compute_seal_id(proof: dict[str, Any]) -> str:
    algo = proof["measurement"]["algorithm"]
    return _digest_obj(_strip_for_seal_id(proof), _id_algorithm(algo))


def _base_proof(
    *,
    artifact: dict[str, Any],
    measurement: dict[str, Any],
    creator_label: str,
    created_at_utc: str | None,
    origin_mode: str = "local",
) -> dict[str, Any]:
    return {
        "spas_version": SPAS_VERSION,
        "proof_format": PROOF_FORMAT,
        "artifact": artifact,
        "measurement": measurement,
        "origin": {
            "mode": origin_mode,
            "created_at_utc": created_at_utc or now_utc_iso(),
            "creator_label": creator_label,
        },
        "status_rule": STATUS_RULE,
    }


def finalize(proof: dict[str, Any]) -> dict[str, Any]:
    proof["proof_id"] = compute_proof_id(proof)
    proof["seal_id"] = compute_seal_id(proof)
    return proof


def build_file_proof(
    path: str,
    *,
    algorithm: str = "WISE-DIGEST-0",
    creator_label: str = DEFAULT_CREATOR,
    created_at_utc: str | None = None,
    origin_mode: str = "local",
) -> dict[str, Any]:
    _ensure_algo(algorithm)
    digest_hex, size = digest_file(path, algorithm)
    artifact = {
        "type": "file",
        "name": os.path.basename(path),
        "size_bytes": size,
    }
    measurement = {"algorithm": algorithm, "digest": digest_hex}
    proof = _base_proof(
        artifact=artifact,
        measurement=measurement,
        creator_label=creator_label,
        created_at_utc=created_at_utc,
        origin_mode=origin_mode,
    )
    return finalize(proof)


def build_text_proof(
    text: str,
    *,
    algorithm: str = "WISE-DIGEST-0",
    creator_label: str = DEFAULT_CREATOR,
    created_at_utc: str | None = None,
    origin_mode: str = "local",
) -> dict[str, Any]:
    _ensure_algo(algorithm)
    digest_hex, size = digest_text(text, algorithm)
    artifact = {
        "type": "text",
        "name": "",
        "encoding": "utf-8",
        "size_bytes": size,
    }
    measurement = {"algorithm": algorithm, "digest": digest_hex}
    proof = _base_proof(
        artifact=artifact,
        measurement=measurement,
        creator_label=creator_label,
        created_at_utc=created_at_utc,
        origin_mode=origin_mode,
    )
    return finalize(proof)
