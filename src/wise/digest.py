"""Digest layer for WISE.

WiseDigest-0 — native, deterministic, experimental.
Mathematics defined in spec §7 + §30.1 + §30.2 + §30.3 + §30.4.

SHA-256 — production fallback via hashlib.

Both expose .update(bytes) and .hexdigest().
"""

from __future__ import annotations

import hashlib
from typing import Iterable

_MASK32 = 0xFFFFFFFF
_GOLDEN = 0x9E3779B9
_FINAL_CONST = 0xA5A5A5A5

_INITIAL_STATE = (
    0x57495345,  # "WISE"
    0x4F524947,  # "ORIG"
    0x494E3030,  # "IN00"
    0x53504153,  # "SPAS"
    0x54525545,  # "TRUE"
    0x4641494C,  # "FAIL"
    0x50524F46,  # "PROF"
    0x30303100,  # "001\0"
)


def _rotl32(x: int, n: int) -> int:
    n &= 31
    if n == 0:
        return x & _MASK32
    return ((x << n) & _MASK32) | ((x & _MASK32) >> (32 - n))


class WiseDigest0:
    name = "WiseDigest-0"

    def __init__(self) -> None:
        self._state = list(_INITIAL_STATE)
        self._index = 0
        self._byte_count = 0
        self._finalized = False

    def update(self, data: bytes) -> None:
        if self._finalized:
            raise RuntimeError("WiseDigest0: update() after finalize()")
        s = self._state
        i = self._index
        for b in data:
            j = i & 7
            sj = (s[j] ^ b) & _MASK32
            sj = _rotl32(sj, (b % 31) + 1)
            sj = (sj + _GOLDEN + i) & _MASK32
            s[j] = sj
            j1 = (j + 1) & 7
            s[j1] = (s[j1] ^ sj) & _MASK32
            j3 = (j + 3) & 7
            s[j3] = (_rotl32(s[j3], 7) ^ sj) & _MASK32
            i += 1
        self._index = i
        self._byte_count += len(data)

    def _absorb_length(self) -> None:
        bit_length = (self._byte_count * 8) & 0xFFFFFFFFFFFFFFFF
        length_bytes = bit_length.to_bytes(8, "big", signed=False)
        s = self._state
        i = self._index
        for b in length_bytes:
            j = i & 7
            sj = (s[j] ^ b) & _MASK32
            sj = _rotl32(sj, (b % 31) + 1)
            sj = (sj + _GOLDEN + i) & _MASK32
            s[j] = sj
            j1 = (j + 1) & 7
            s[j1] = (s[j1] ^ sj) & _MASK32
            j3 = (j + 3) & 7
            s[j3] = (_rotl32(s[j3], 7) ^ sj) & _MASK32
            i += 1
        self._index = i

    def _finalize_rounds(self) -> None:
        s = self._state
        for _ in range(16):
            for j in range(8):
                s[j] = (s[j] ^ s[(j + 1) & 7]) & _MASK32
                s[j] = _rotl32(s[j], 11)
                s[j] = (s[j] + s[(j + 5) & 7] + _FINAL_CONST) & _MASK32

    def hexdigest(self) -> str:
        if not self._finalized:
            self._absorb_length()
            self._finalize_rounds()
            self._finalized = True
        return "".join(f"{w:08x}" for w in self._state)


class _Sha256Hasher:
    name = "SHA-256"

    def __init__(self) -> None:
        self._h = hashlib.sha256()

    def update(self, data: bytes) -> None:
        self._h.update(data)

    def hexdigest(self) -> str:
        return self._h.hexdigest()


def new_hasher(algorithm: str):
    if algorithm == "WiseDigest-0":
        return WiseDigest0()
    if algorithm == "SHA-256":
        return _Sha256Hasher()
    raise ValueError(f"unsupported algorithm: {algorithm}")


def digest_bytes(data: bytes, algorithm: str) -> str:
    h = new_hasher(algorithm)
    h.update(data)
    return h.hexdigest()


def digest_stream(chunks: Iterable[bytes], algorithm: str) -> str:
    h = new_hasher(algorithm)
    for chunk in chunks:
        h.update(chunk)
    return h.hexdigest()
