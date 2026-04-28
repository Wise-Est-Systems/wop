"""WiseDigest-2 — research-track candidate, original construction.

NOT promoted to the wise CLI. Selectable only via direct import.
NOT a security claim.

Construction: positional accumulator with state-driven head walk and
multi-tap cross-lane mixing. See research/WiseDigest-2.md for the full
spec and research/WiseDigest-Lab.md for measured properties.

Originality rule: no SHA, BLAKE, ChaCha, Keccak, Merkle-Damgård, or sponge
core is borrowed. Only universal primitives (integer add, XOR, rotation)
and Wise-native ASCII-derived constants are used.
"""

from __future__ import annotations

import struct
from typing import Iterable

ALGORITHM_NAME = "WiseDigest-2"

_MASK64 = 0xFFFFFFFFFFFFFFFF
_LANES = 12
_OUTPUT_LANES = 4
_OUTPUT_BYTES = 32
_FINALIZE_ROUNDS = 24


def _phrase(p: bytes) -> int:
    assert len(p) == 8, f"phrase {p!r} must be 8 bytes"
    return int.from_bytes(p, "big")


# 12 Wise-native phrases (see WiseDigest-2.md §3.1).
_INITIAL_STATE: tuple[int, ...] = (
    _phrase(b"WISEDIG2"),
    _phrase(b"ORIGINAL"),
    _phrase(b"OWNTRACK"),
    _phrase(b"PROVEUNI"),
    _phrase(b"BYTETRUE"),
    _phrase(b"NOMIXING"),
    _phrase(b"REPRODUC"),
    _phrase(b"REJECTAL"),
    _phrase(b"DOMAINTG"),
    _phrase(b"ALIVEWIN"),
    _phrase(b"FAIL2DIE"),
    _phrase(b"LENABSRB"),
)

# Domain separator: ASCII "WiseDigest-2" + NUL pad to 16 bytes,
# split into two big-endian uint64 lanes.
_DOMAIN_BYTES = b"WiseDigest-2" + b"\x00" * 4
_DOMAIN_LANE_0 = int.from_bytes(_DOMAIN_BYTES[:8], "big")
_DOMAIN_LANE_1 = int.from_bytes(_DOMAIN_BYTES[8:], "big")

# Mixing constants (see WiseDigest-2.md §3.2).
_MIX_A = _phrase(b"WISEMIX1")
_MIX_B = _phrase(b"WISEMIX2")
_MIX_C = _phrase(b"WISEMIX3")
_MIX_D = _phrase(b"WISEMIX4")
_MIX_E = _phrase(b"WISEMIX5")


def _rotl64(x: int, n: int) -> int:
    n &= 63
    if n == 0:
        return x & _MASK64
    return (((x << n) & _MASK64) | ((x & _MASK64) >> (64 - n))) & _MASK64


def _absorb_byte(state: list[int], head_box: list[int], b: int, i: int) -> None:
    h = head_box[0]

    # (1) Mix the byte into the lane the head currently points at.
    state[h] = (state[h] ^ ((b * _MIX_A) & _MASK64) ^ ((i * _MIX_B) & _MASK64)) & _MASK64
    state[h] = (state[h] + (_MIX_C * (b + 1)) & _MASK64) & _MASK64

    # (2) State-driven rotation. NOT directly chosen by the input byte.
    rot = (((state[h] >> 58) | 1) & 0x3F)  # in [1, 63]
    state[h] = _rotl64(state[h], rot)

    # (3) Multi-tap cross-lane mixing.
    tap1 = (h + 1) % _LANES
    tap2 = (h + 5) % _LANES
    tap3 = (h + 7) % _LANES
    state[tap1] = (state[tap1] ^ state[h]) & _MASK64
    state[tap2] = (state[tap2] + state[h]) & _MASK64
    state[tap3] = (_rotl64(state[tap3], 11) ^ state[h]) & _MASK64

    # (4) State-driven stride.
    stride = (state[(h + 11) % _LANES] % 11) + 1  # in [1, 11]
    head_box[0] = (h + stride) % _LANES


def _finalize_round(state: list[int]) -> None:
    snapshot = list(state)
    for k in range(_LANES):
        a = snapshot[k]
        b = snapshot[(k + 5) % _LANES]
        c = snapshot[(k + 7) % _LANES]
        d = snapshot[(k + 11) % _LANES]
        x = _rotl64(a, 13) ^ _rotl64(b, 31) ^ ((c + _MIX_D) & _MASK64)
        state[k] = (x + _rotl64(d, 41) + _MIX_E) & _MASK64


class WiseDigest2:
    name = ALGORITHM_NAME

    def __init__(self) -> None:
        self._state: list[int] = list(_INITIAL_STATE)
        self._state[0] ^= _DOMAIN_LANE_0
        self._state[1] ^= _DOMAIN_LANE_1
        self._head_box = [0]
        self._byte_count = 0
        self._finalized = False

    def update(self, data: bytes) -> "WiseDigest2":
        if self._finalized:
            raise RuntimeError("WiseDigest2: update() after hexdigest()")
        i = self._byte_count
        for b in data:
            _absorb_byte(self._state, self._head_box, b, i)
            i += 1
        self._byte_count = i
        return self

    def _finalize(self) -> None:
        if self._finalized:
            return
        bit_length = (self._byte_count * 8) & _MASK64
        length_bytes = struct.pack(">Q", bit_length)
        i = self._byte_count
        for b in length_bytes:
            _absorb_byte(self._state, self._head_box, b, i)
            i += 1
        for _ in range(_FINALIZE_ROUNDS):
            _finalize_round(self._state)
        self._finalized = True

    def digest(self) -> bytes:
        self._finalize()
        out = [
            self._state[0] ^ self._state[4] ^ self._state[8],
            self._state[1] ^ self._state[5] ^ self._state[9],
            self._state[2] ^ self._state[6] ^ self._state[10],
            self._state[3] ^ self._state[7] ^ self._state[11],
        ]
        return b"".join(struct.pack(">Q", w & _MASK64) for w in out)

    def hexdigest(self) -> str:
        return self.digest().hex()


def digest_bytes(data: bytes) -> str:
    h = WiseDigest2()
    h.update(data)
    return h.hexdigest()


def digest_stream(chunks: Iterable[bytes]) -> str:
    h = WiseDigest2()
    for chunk in chunks:
        h.update(chunk)
    return h.hexdigest()
