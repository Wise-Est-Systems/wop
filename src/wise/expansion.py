"""WiseExpansion — structured expansion-based measurement of an artifact.

NOT a hash. NOT compression. NOT a Merkle tree.

Produces a deterministic, multi-layer fingerprint of input bytes. The final
`wisemark` field is a 256-bit digest of the canonical body (excluding the
wisemark line itself), provided as the integrity proof for the expansion
document and the compatibility hook for a future WiseMeasure verifier.

See research/WiseExpansion.md for the normative specification.
"""

from __future__ import annotations

import math
import struct
from collections import Counter

from .digest import digest_bytes as _digest_bytes

EXPANSION_HEADER = "WISEEXP-V1"
EXPANSION_VERSION = "v1"
DEFAULT_BLOCK_SIZE = 1024
DEFAULT_ALGORITHM = "WiseDigest-0"

_SUPPORTED_ALGORITHMS = ("WiseDigest-0", "SHA-256")
_MASK64 = 0xFFFFFFFFFFFFFFFF


def _digest(data: bytes, algorithm: str) -> str:
    return _digest_bytes(data, algorithm)


def _hist_canonical(counts: Counter) -> bytes:
    return b"".join(struct.pack(">Q", counts.get(v, 0)) for v in range(256))


def _bigram_canonical(bigrams: Counter) -> bytes:
    parts = []
    for ab in sorted(bigrams.keys()):
        a, b = ab
        parts.append(bytes([a, b]) + struct.pack(">Q", bigrams[ab]))
    return b"".join(parts)


def _runs(data: bytes) -> list[tuple[int, int]]:
    if not data:
        return []
    runs: list[tuple[int, int]] = []
    cur = data[0]
    cnt = 1
    for b in data[1:]:
        if b == cur:
            cnt += 1
        else:
            runs.append((cur, cnt))
            cur = b
            cnt = 1
    runs.append((cur, cnt))
    return runs


def _runs_canonical(runs: list[tuple[int, int]]) -> bytes:
    return b"".join(bytes([v]) + struct.pack(">Q", L) for (v, L) in runs)


def _block_digests(data: bytes, block_size: int, algorithm: str) -> list[str]:
    digests: list[str] = []
    for i in range(0, len(data), block_size):
        digests.append(_digest_bytes(data[i : i + block_size], algorithm))
    return digests


def _blocks_canonical(digests: list[str]) -> bytes:
    parts = [struct.pack(">Q", len(digests))]
    for d in digests:
        parts.append(bytes.fromhex(d))
    return b"".join(parts)


def _offset_mod16_canonical(data: bytes) -> bytes:
    parts = []
    for k in range(16):
        bs = data[k::16]
        s = sum(bs) & _MASK64
        x = 0
        for b in bs:
            x ^= b
        parts.append(struct.pack(">Q", s) + bytes([x]))
    return b"".join(parts)


def _shannon_milli(counts: Counter, total: int) -> int:
    if total <= 0:
        return 0
    h = 0.0
    for c in counts.values():
        if c > 0:
            p = c / total
            h -= p * math.log2(p)
    return round(h * 1000)


def _chi_squared_milli(counts: Counter, total: int) -> int:
    if total <= 0:
        return 0
    expected = total / 256.0
    chi = 0.0
    for v in range(256):
        c = counts.get(v, 0)
        chi += (c - expected) * (c - expected) / expected
    return round(chi * 1000)


def _bigram_entropy_milli(bigrams: Counter, total: int) -> int:
    if total <= 0:
        return 0
    h = 0.0
    for c in bigrams.values():
        if c > 0:
            p = c / total
            h -= p * math.log2(p)
    return round(h * 1000)


def _validate_kv(key: str, value: str) -> None:
    if "=" in key or "\n" in key:
        raise ValueError(f"invalid key: {key!r}")
    if "\n" in value or "=" in value:
        raise ValueError(f"invalid value (contains \\n or =): {value!r}")


def _render_canonical(items: dict[str, str], exclude: frozenset[str] = frozenset()) -> bytes:
    keys = sorted(k for k in items.keys() if k not in exclude)
    lines = [EXPANSION_HEADER, ""]
    for k in keys:
        v = items[k]
        _validate_kv(k, v)
        lines.append(f"{k}={v}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def expand(
    data: bytes,
    *,
    algorithm: str = DEFAULT_ALGORITHM,
    block_size: int = DEFAULT_BLOCK_SIZE,
) -> dict[str, str]:
    """Compute a WiseExpansion of the given bytes.

    Returns a dict[key, value] of all WISEEXP-V1 fields including `wisemark`.
    The dict is suitable as input to `render()`.
    """
    if algorithm not in _SUPPORTED_ALGORITHMS:
        raise ValueError(f"unsupported algorithm: {algorithm!r}")
    if block_size < 1:
        raise ValueError(f"block_size must be >= 1, got {block_size}")

    n = len(data)
    items: dict[str, str] = {}

    # ---------------- Layer 1: byte layer
    items["expansion.version"] = EXPANSION_VERSION
    items["artifact.algorithm"] = algorithm
    items["artifact.block_size"] = str(block_size)
    items["artifact.size_bytes"] = str(n)
    items["artifact.byte_digest"] = _digest(data, algorithm)

    # ---------------- Layer 2: positional patterns
    items["positional.first16"] = data[:16].hex()
    items["positional.last16"] = data[-16:].hex() if n >= 32 else ""
    if n >= 48:
        mid_start = n // 2 - 8
        items["positional.midpoint16"] = data[mid_start : mid_start + 16].hex()
    else:
        items["positional.midpoint16"] = ""
    items["positional.offset_mod16_digest"] = _digest(_offset_mod16_canonical(data), algorithm)

    # ---------------- Layer 3: frequency
    counts: Counter = Counter(data)
    items["frequency.distinct_bytes"] = str(len(counts))
    if n == 0:
        items["frequency.most_common_byte"] = ""
        items["frequency.most_common_count"] = "0"
    else:
        # Highest count; ties broken by lowest byte value (deterministic).
        mcv, mcc = max(counts.items(), key=lambda kv: (kv[1], -kv[0]))
        items["frequency.most_common_byte"] = f"0x{mcv:02x}"
        items["frequency.most_common_count"] = str(mcc)
    items["frequency.shannon_milli"] = str(_shannon_milli(counts, n))
    items["frequency.chi_squared_milli"] = str(_chi_squared_milli(counts, n))
    items["frequency.histogram_digest"] = _digest(_hist_canonical(counts), algorithm)

    # ---------------- Layer 4: transition relationships
    bigrams: Counter = Counter()
    for i in range(n - 1):
        bigrams[(data[i], data[i + 1])] += 1
    items["transition.distinct_bigrams"] = str(len(bigrams))
    if n < 2:
        items["transition.most_common_bigram"] = ""
        items["transition.most_common_count"] = "0"
        items["transition.bigram_entropy_milli"] = "0"
    else:
        mcb, mcc = max(
            bigrams.items(),
            key=lambda kv: (kv[1], -(kv[0][0] * 256 + kv[0][1])),
        )
        items["transition.most_common_bigram"] = f"0x{mcb[0]:02x}{mcb[1]:02x}"
        items["transition.most_common_count"] = str(mcc)
        items["transition.bigram_entropy_milli"] = str(_bigram_entropy_milli(bigrams, n - 1))
    items["transition.matrix_digest"] = _digest(_bigram_canonical(bigrams), algorithm)

    # ---------------- Layer 5: derived structural
    runs = _runs(data)
    items["structural.run_count"] = str(len(runs))
    if not runs:
        items["structural.longest_run"] = "0"
        items["structural.longest_run_byte"] = ""
    else:
        lr_byte, lr_len = max(runs, key=lambda r: (r[1], -r[0]))
        items["structural.longest_run"] = str(lr_len)
        items["structural.longest_run_byte"] = f"0x{lr_byte:02x}"
    items["structural.run_length_digest"] = _digest(_runs_canonical(runs), algorithm)
    block_digests = _block_digests(data, block_size, algorithm)
    items["structural.block_count"] = str(len(block_digests))
    items["structural.blocks_digest"] = _digest(_blocks_canonical(block_digests), algorithm)

    # ---------------- Layer 6: WiseMark
    body_without_mark = _render_canonical(items, exclude=frozenset({"wisemark"}))
    items["wisemark"] = _digest(body_without_mark, algorithm)

    return items


def render(items: dict[str, str]) -> bytes:
    """Render an expansion dict as canonical WISEEXP-V1 bytes."""
    return _render_canonical(items)


def verify_wisemark(items: dict[str, str]) -> bool:
    """Recompute the wisemark from `items` and compare to the stored value.

    Returns True iff the stored wisemark matches what we re-derive from the
    rest of the fields. Does NOT verify the artifact bytes — that requires
    re-running expand() on the artifact and comparing.
    """
    stored = items.get("wisemark")
    if stored is None:
        return False
    algorithm = items.get("artifact.algorithm")
    if algorithm not in _SUPPORTED_ALGORITHMS:
        return False
    body = _render_canonical(items, exclude=frozenset({"wisemark"}))
    return _digest(body, algorithm) == stored
