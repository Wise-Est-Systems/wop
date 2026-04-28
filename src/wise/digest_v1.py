"""WiseDigest-1 — research-track candidate digest.

NOT promoted to the wise CLI. Selectable only via direct import.
NOT a security claim. See research/WiseDigest-1.md for the full spec
and research/WiseDigest-Lab.md for measured properties.
"""

from __future__ import annotations

import struct
from typing import Iterable

ALGORITHM_NAME = "WiseDigest-1"

_MASK64 = 0xFFFFFFFFFFFFFFFF
_ROUNDS = 12
_RATE_BYTES = 32
_RATE_LANES = 4
_STATE_LANES = 8
_OUTPUT_LANES = 4
_OUTPUT_BYTES = 32

# BLAKE2b IV: fractional parts of sqrt of first 8 primes (2,3,5,7,11,13,17,19).
_IV = (
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
)

# Domain separator: ASCII "WiseDigest-1" (12 bytes) padded to 16 with NUL,
# split into two big-endian uint64 lanes XOR'd into state[0] and state[1].
#   "WiseDige" = 0x57 69 73 65 44 69 67 65
#   "st-1\0\0\0\0" = 0x73 74 2D 31 00 00 00 00
_DOMAIN_LANE_0 = 0x5769736544696765
_DOMAIN_LANE_1 = 0x73742D3100000000


def _rotr64(x: int, n: int) -> int:
    n &= 63
    if n == 0:
        return x & _MASK64
    return (((x & _MASK64) >> n) | ((x << (64 - n)) & _MASK64)) & _MASK64


def _g(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & _MASK64
    s[d] = _rotr64(s[d] ^ s[a], 32)
    s[c] = (s[c] + s[d]) & _MASK64
    s[b] = _rotr64(s[b] ^ s[c], 24)
    s[a] = (s[a] + s[b]) & _MASK64
    s[d] = _rotr64(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _MASK64
    s[b] = _rotr64(s[b] ^ s[c], 63)


def _permute(state: list[int]) -> None:
    for _ in range(_ROUNDS):
        _g(state, 0, 2, 4, 6)
        _g(state, 1, 3, 5, 7)
        _g(state, 0, 3, 4, 7)
        _g(state, 1, 2, 5, 6)


class WiseDigest1:
    name = ALGORITHM_NAME

    def __init__(self) -> None:
        self._state: list[int] = list(_IV)
        self._state[0] ^= _DOMAIN_LANE_0
        self._state[1] ^= _DOMAIN_LANE_1
        self._buffer = bytearray()
        self._byte_count = 0
        self._finalized = False

    def update(self, data: bytes) -> "WiseDigest1":
        if self._finalized:
            raise RuntimeError("WiseDigest1: update() after hexdigest()")
        self._buffer.extend(data)
        self._byte_count += len(data)
        while len(self._buffer) >= _RATE_BYTES:
            block = bytes(self._buffer[:_RATE_BYTES])
            del self._buffer[:_RATE_BYTES]
            self._absorb_block(block)
        return self

    def _absorb_block(self, block: bytes) -> None:
        for i in range(_RATE_LANES):
            (lane,) = struct.unpack(">Q", block[i * 8 : (i + 1) * 8])
            self._state[i] ^= lane
        _permute(self._state)

    def _finalize(self) -> None:
        if self._finalized:
            return
        bit_length = (self._byte_count * 8) & _MASK64
        suffix = struct.pack(">Q", bit_length)
        tail = bytes(self._buffer) + suffix
        pad = (_RATE_BYTES - (len(tail) % _RATE_BYTES)) % _RATE_BYTES
        tail = tail + (b"\x00" * pad)
        for i in range(0, len(tail), _RATE_BYTES):
            self._absorb_block(tail[i : i + _RATE_BYTES])
        self._buffer.clear()
        self._finalized = True

    def digest(self) -> bytes:
        self._finalize()
        return b"".join(struct.pack(">Q", self._state[i]) for i in range(_OUTPUT_LANES))

    def hexdigest(self) -> str:
        return self.digest().hex()


def digest_bytes(data: bytes) -> str:
    h = WiseDigest1()
    h.update(data)
    return h.hexdigest()


def digest_stream(chunks: Iterable[bytes]) -> str:
    h = WiseDigest1()
    for chunk in chunks:
        h.update(chunk)
    return h.hexdigest()
