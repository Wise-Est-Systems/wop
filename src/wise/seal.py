"""WISESEAL-V1 container per §31.7.

Layout:
  "WISESEAL-V1\n"
  "[ARTIFACT]\n"
  4 bytes big-endian uint32 = N (artifact length)
  N bytes raw artifact
  "\n[PROOF]\n"
  4 bytes big-endian uint32 = M (proof length)
  M bytes raw proof
  "\n[END]\n"

No compression. Both artifact and proof are byte-preserved.

v0.1.1 hardening:
    H3 — embedded proof section is capped at MAX_SEAL_PROOF_SECTION_BYTES.
"""

from __future__ import annotations

import struct

from . import MAX_SEAL_PROOF_SECTION_BYTES, WISE_SEAL_HEADER
from .format import FormatError


_HEADER = (WISE_SEAL_HEADER + "\n").encode("utf-8")
_ART_TAG = b"[ARTIFACT]\n"
_PROOF_TAG = b"\n[PROOF]\n"
_END_TAG = b"\n[END]\n"


class SealError(Exception):
    pass


def pack(artifact_bytes: bytes, proof_bytes: bytes) -> bytes:
    if len(artifact_bytes) > 0xFFFFFFFF:
        raise SealError("artifact exceeds 4 GiB cap for WISESEAL-V1")
    if len(proof_bytes) > 0xFFFFFFFF:
        raise SealError("proof exceeds 4 GiB cap for WISESEAL-V1")
    # H3: an honest proof is far below 1 MiB; refuse to pack a runaway proof.
    if len(proof_bytes) > MAX_SEAL_PROOF_SECTION_BYTES:
        raise SealError(
            f"proof section exceeds {MAX_SEAL_PROOF_SECTION_BYTES} byte cap"
        )
    parts = [
        _HEADER,
        _ART_TAG,
        struct.pack(">I", len(artifact_bytes)),
        artifact_bytes,
        _PROOF_TAG,
        struct.pack(">I", len(proof_bytes)),
        proof_bytes,
        _END_TAG,
    ]
    return b"".join(parts)


def unpack(data: bytes) -> tuple[bytes, bytes]:
    pos = 0
    if not data.startswith(_HEADER):
        raise SealError(f"missing header {WISE_SEAL_HEADER!r}")
    pos += len(_HEADER)
    if data[pos : pos + len(_ART_TAG)] != _ART_TAG:
        raise SealError("missing [ARTIFACT] tag")
    pos += len(_ART_TAG)
    if pos + 4 > len(data):
        raise SealError("truncated before artifact length")
    (n,) = struct.unpack(">I", data[pos : pos + 4])
    pos += 4
    # C6 (defense in depth): subtraction-based check so a 32-bit port can
    # never have pos+n wrap around to a small value.
    if n > len(data) - pos:
        raise SealError("truncated artifact")
    artifact = data[pos : pos + n]
    pos += n
    if data[pos : pos + len(_PROOF_TAG)] != _PROOF_TAG:
        raise SealError("missing [PROOF] tag")
    pos += len(_PROOF_TAG)
    if pos + 4 > len(data):
        raise SealError("truncated before proof length")
    (m,) = struct.unpack(">I", data[pos : pos + 4])
    # H3: refuse to allocate / read more than the proof-section cap.
    if m > MAX_SEAL_PROOF_SECTION_BYTES:
        raise SealError(
            f"proof section exceeds {MAX_SEAL_PROOF_SECTION_BYTES} byte cap"
        )
    pos += 4
    # C6 (defense in depth): use subtraction so pos+m can never overflow on
    # a 32-bit target. In Python ints are arbitrary-precision so either form
    # is fine; spec-§4 mandates this form for ports.
    if m > len(data) - pos:
        raise SealError("truncated proof")
    proof = data[pos : pos + m]
    pos += m
    if data[pos : pos + len(_END_TAG)] != _END_TAG:
        raise SealError("missing [END] tag")
    pos += len(_END_TAG)
    if pos != len(data):
        raise SealError("trailing bytes after [END]")
    return artifact, proof
