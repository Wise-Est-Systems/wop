"""WiseDigest-3 — research-track candidate, 793-bit live state.

State = 13 lanes × 61 bits = 793 bits exactly. Top 3 bits of each lane's
storage cell are dead and are explicitly masked to zero after every
operation; a finalize-time assertion verifies the invariant.

NOT promoted to the wise CLI. NOT a security claim.

See research/WiseDigest-3.md for the full normative spec and
research/WiseDigest-Lab.md for measured properties.
"""

from __future__ import annotations

import struct
from typing import Iterable

ALGORITHM_NAME = "WiseDigest-3"

LIVE_BITS = 793
LANES = 13
LANE_BITS = 61
assert LANES * LANE_BITS == LIVE_BITS, "13 * 61 != 793"

MASK61 = (1 << 61) - 1
MASK64 = (1 << 64) - 1

OUTPUT_BITS = 256
OUTPUT_LANES = 4
OUTPUT_BYTES = 32

FINALIZE_ROUNDS = 25


def _phrase61(p: bytes) -> int:
    assert len(p) == 8, f"phrase {p!r} must be exactly 8 bytes"
    return int.from_bytes(p, "big") & MASK61


def _phrase64(p: bytes) -> int:
    assert len(p) == 8, f"phrase {p!r} must be exactly 8 bytes"
    return int.from_bytes(p, "big")


# 13 Wise-native phrases for the initial state, masked to 61 bits.
_INITIAL_STATE: tuple[int, ...] = (
    _phrase61(b"WISEDIG3"),
    _phrase61(b"STATE793"),
    _phrase61(b"THIRTEEN"),
    _phrase61(b"SIXTYONE"),
    _phrase61(b"ORIGINAL"),
    _phrase61(b"OWNTRACK"),
    _phrase61(b"BYTETRUE"),
    _phrase61(b"NOFOLDFL"),
    _phrase61(b"DOMTAG3X"),
    _phrase61(b"REPRODUC"),
    _phrase61(b"ALIVE793"),
    _phrase61(b"LENABSRB"),
    _phrase61(b"FAIL2DIE"),
)

# Domain separator: ASCII "WiseDigest-3" + NUL pad to 16 bytes,
# split into two 64-bit halves and masked to 61 bits each.
_DOM_BYTES = b"WiseDigest-3" + b"\x00" * 4
_DOMAIN_LANE_0 = int.from_bytes(_DOM_BYTES[:8], "big") & MASK61
_DOMAIN_LANE_1 = int.from_bytes(_DOM_BYTES[8:], "big") & MASK61

# Mixing constants (61-bit world).
_MIX_A = _phrase61(b"WMIX793A")
_MIX_B = _phrase61(b"WMIX793B")
_MIX_C = _phrase61(b"WMIX793C")
_MIX_D = _phrase61(b"WMIX793D")
_MIX_E = _phrase61(b"WMIX793E")

# Output-extraction salts (64-bit world, used only at extraction).
_OUT_SALT: tuple[int, ...] = (
    _phrase64(b"OUTMIX01"),
    _phrase64(b"OUTMIX02"),
    _phrase64(b"OUTMIX03"),
    _phrase64(b"OUTMIX04"),
)


def _rotl61(x: int, n: int) -> int:
    n %= 61
    if n == 0:
        return x & MASK61
    return (((x << n) & MASK61) | ((x & MASK61) >> (61 - n))) & MASK61


def _rotl64(x: int, n: int) -> int:
    n &= 63
    if n == 0:
        return x & MASK64
    return (((x << n) & MASK64) | ((x & MASK64) >> (64 - n))) & MASK64


def _absorb_byte(state: list[int], head_box: list[int], b: int, i: int) -> None:
    h = head_box[0]

    # (1) Mix the byte into state[h]. All 61-bit masked.
    state[h] = (state[h] ^ ((b * _MIX_A) & MASK61) ^ ((i * _MIX_B) & MASK61)) & MASK61
    state[h] = (state[h] + ((_MIX_C * (b + 1)) & MASK61)) & MASK61

    # (2) State-driven uniform rotation in [1, 60].
    rot = ((state[h] * 60) >> 61) + 1
    state[h] = _rotl61(state[h], rot)

    # (3) Multi-tap cross-lane mixing.
    tap1 = (h + 1) % LANES
    tap2 = (h + 5) % LANES
    tap3 = (h + 7) % LANES
    state[tap1] = (state[tap1] ^ state[h]) & MASK61
    state[tap2] = (state[tap2] + state[h]) & MASK61
    state[tap3] = (_rotl61(state[tap3], 11) ^ state[h]) & MASK61

    # (4) State-driven uniform stride in [1, 12].
    # 13 is prime ⇒ every stride is coprime to 13 ⇒ head visits all lanes.
    stride = ((state[(h + 11) % LANES] * 12) >> 61) + 1
    head_box[0] = (h + stride) % LANES


def _finalize_round(state: list[int]) -> None:
    snap = list(state)
    for k in range(LANES):
        a = snap[k]
        b = snap[(k + 5) % LANES]
        c = snap[(k + 7) % LANES]
        d = snap[(k + 11) % LANES]
        x = (_rotl61(a, 13) ^ _rotl61(b, 31) ^ ((c + _MIX_D) & MASK61)) & MASK61
        state[k] = (x + _rotl61(d, 41) + _MIX_E) & MASK61


def _extract_output(state: list[int]) -> bytes:
    m = state[12]
    rot = ((m * 63) >> 61) + 1  # in [1, 63]
    out_words: list[int] = []
    for k in range(4):
        a = state[2 * k]
        b = state[2 * k + 1]
        c = state[k + 8]
        # Two non-linear multiplications. OR-with-1 removes the zero trap.
        u = ((a | 1) * (b | 1)) & MASK64
        v = ((c | 1) * (m | 1)) & MASK64
        word = u ^ v
        word = (word ^ _rotl64(word, rot)) & MASK64
        word = (word + _OUT_SALT[k]) & MASK64
        out_words.append(word)
    return b"".join(struct.pack(">Q", w) for w in out_words)


def _check_invariant(state: list[int]) -> None:
    """Every lane must be within the 61-bit live envelope."""
    for k, s in enumerate(state):
        if not (0 <= s <= MASK61):
            raise AssertionError(f"WiseDigest-3 invariant violated: state[{k}] = {s:#x}")


class WiseDigest3:
    name = ALGORITHM_NAME

    def __init__(self) -> None:
        self._state: list[int] = list(_INITIAL_STATE)
        self._state[0] = (self._state[0] ^ _DOMAIN_LANE_0) & MASK61
        self._state[1] = (self._state[1] ^ _DOMAIN_LANE_1) & MASK61
        self._head_box = [0]
        self._byte_count = 0
        self._finalized = False

    def update(self, data: bytes) -> "WiseDigest3":
        if self._finalized:
            raise RuntimeError("WiseDigest3: update() after hexdigest()")
        i = self._byte_count
        for b in data:
            _absorb_byte(self._state, self._head_box, b, i)
            i += 1
        self._byte_count = i
        return self

    def _finalize(self) -> None:
        if self._finalized:
            return
        bit_length = (self._byte_count * 8) & MASK64
        length_bytes = struct.pack(">Q", bit_length)
        i = self._byte_count
        for b in length_bytes:
            _absorb_byte(self._state, self._head_box, b, i)
            i += 1
        for _ in range(FINALIZE_ROUNDS):
            _finalize_round(self._state)
        _check_invariant(self._state)
        self._finalized = True

    def digest(self) -> bytes:
        self._finalize()
        return _extract_output(self._state)

    def hexdigest(self) -> str:
        return self.digest().hex()


def digest_bytes(data: bytes) -> str:
    return WiseDigest3().update(data).hexdigest()


def digest_stream(chunks: Iterable[bytes]) -> str:
    h = WiseDigest3()
    for c in chunks:
        h.update(c)
    return h.hexdigest()
