"""Build WISE proof objects and compute wise_id / wise_seal per §31.4.

Identity model (LOCKED — Q5 / Q12 / Q17):
    wise_id   = digest(canonical body excluding wise_id, wise_seal,
                                            origin.created_at, artifact.name)
    wise_seal = digest(canonical body excluding wise_seal only)

The canonical body is the WISEPROOF-V1 line format (§31.3) restricted to
the included keys.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Iterable

from . import (
    DEFAULT_CREATOR,
    SUPPORTED_ALGORITHMS,
)
from .digest import new_hasher
from .format import encode, encode_subset

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


_WISE_ID_EXCLUDE = {"wise_id", "wise_seal", "origin.created_at", "artifact.name"}
_WISE_SEAL_EXCLUDE = {"wise_seal"}


def _digest_subset(items: dict[str, str], exclude: set[str], algorithm: str) -> str:
    keep_keys: Iterable[str] = (k for k in items.keys() if k not in exclude)
    body = encode_subset(items, keep_keys)
    h = new_hasher(algorithm)
    h.update(body)
    return h.hexdigest()


def compute_wise_id(items: dict[str, str], algorithm: str) -> str:
    return _digest_subset(items, _WISE_ID_EXCLUDE, algorithm)


def compute_wise_seal(items: dict[str, str], algorithm: str) -> str:
    return _digest_subset(items, _WISE_SEAL_EXCLUDE, algorithm)


def _base_items(
    *,
    artifact_type: str,
    artifact_name: str,
    artifact_size: int,
    artifact_encoding: str | None,
    algorithm: str,
    digest_hex: str,
    creator: str,
    created_at: str,
    origin_mode: str,
) -> dict[str, str]:
    items: dict[str, str] = {
        "artifact.name": artifact_name,
        "artifact.size_bytes": str(artifact_size),
        "artifact.type": artifact_type,
        "measurement.algorithm": algorithm,
        "measurement.digest": digest_hex,
        "origin.created_at": created_at,
        "origin.creator": creator,
        "origin.mode": origin_mode,
    }
    if artifact_encoding is not None:
        items["artifact.encoding"] = artifact_encoding
    return items


def finalize_items(items: dict[str, str], algorithm: str) -> dict[str, str]:
    items["wise_id"] = compute_wise_id(items, algorithm)
    items["wise_seal"] = compute_wise_seal(items, algorithm)
    return items


def build_file_proof_items(
    path: str,
    *,
    algorithm: str = "WiseDigest-0",
    creator: str = DEFAULT_CREATOR,
    created_at: str | None = None,
    origin_mode: str = "local",
) -> dict[str, str]:
    _ensure_algo(algorithm)
    digest_hex, size = digest_file(path, algorithm)
    items = _base_items(
        artifact_type="file",
        artifact_name=os.path.basename(path),
        artifact_size=size,
        artifact_encoding=None,
        algorithm=algorithm,
        digest_hex=digest_hex,
        creator=creator,
        created_at=created_at or now_utc_iso(),
        origin_mode=origin_mode,
    )
    return finalize_items(items, algorithm)


def build_text_proof_items(
    text: str,
    *,
    algorithm: str = "WiseDigest-0",
    creator: str = DEFAULT_CREATOR,
    created_at: str | None = None,
    origin_mode: str = "local",
) -> dict[str, str]:
    _ensure_algo(algorithm)
    digest_hex, size = digest_text(text, algorithm)
    items = _base_items(
        artifact_type="text",
        artifact_name="",
        artifact_size=size,
        artifact_encoding="utf-8",
        algorithm=algorithm,
        digest_hex=digest_hex,
        creator=creator,
        created_at=created_at or now_utc_iso(),
        origin_mode=origin_mode,
    )
    return finalize_items(items, algorithm)


def render(items: dict[str, str]) -> bytes:
    return encode(items)
