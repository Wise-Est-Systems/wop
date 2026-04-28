# WiseDigest-2 — Specification (RESEARCH TRACK, ORIGINALITY-FIRST)

**Status:** experimental, original-construction candidate. **NOT a security claim.**

WiseDigest-0 and WiseDigest-1 are frozen. WiseDigest-2 is a third candidate built under a stricter rule: no hash core borrowed from another design.

What WiseDigest-2 does **not** use:

- No SHA family compression function or message schedule.
- No BLAKE / ChaCha `G` quarter-round.
- No Keccak/SHA-3-style sponge `theta/rho/pi/chi/iota`.
- No Merkle-Damgård length-padded compression-function chain.
- No tree hash (no internal Merkle structure).
- No constants borrowed from existing crypto designs (no SHA-256 IV, no BLAKE2b IV, no `0x9E3779B9` Knuth golden ratio, no fractional parts of irrationals).

What WiseDigest-2 **does** use: integer addition, XOR, bitwise rotation. These are universal primitives, not algorithm cores.

The construction is novel: a **positional accumulator with state-driven head walk and multi-tap cross-lane mixing**.

---

## 1. Output

```
256 bits, 64 lowercase hexadecimal characters.
```

## 2. State

```
12 lanes of 64-bit unsigned integers     (768-bit internal state)
no rate / capacity split — the construction is not a sponge
```

The state is strictly larger than the output (768 > 256), satisfying the design rule.

## 3. Wise-native constants

All constants are derived directly from 8-byte ASCII phrases packed big-endian into 64-bit unsigned integers. Each phrase is exactly 8 bytes; phrases were chosen for thematic coherence with Wise.Est Systems and contain no reference to any external cryptographic design.

### 3.1 Initial state (12 phrases)

```
state[0]  = "WISEDIG2"
state[1]  = "ORIGINAL"
state[2]  = "OWNTRACK"
state[3]  = "PROVEUNI"
state[4]  = "BYTETRUE"
state[5]  = "NOMIXING"
state[6]  = "REPRODUC"
state[7]  = "REJECTAL"
state[8]  = "DOMAINTG"
state[9]  = "ALIVEWIN"
state[10] = "FAIL2DIE"
state[11] = "LENABSRB"
```

### 3.2 Mixing constants

```
MIX_A = "WISEMIX1"
MIX_B = "WISEMIX2"
MIX_C = "WISEMIX3"
MIX_D = "WISEMIX4"
MIX_E = "WISEMIX5"
```

Each is 8 ASCII bytes, big-endian uint64. Concrete hex values are listed in the locked test vectors and reproduced in the reference implementation comments.

### 3.3 Domain separator

```
ASCII "WiseDigest-2"  (12 bytes)  + NUL pad to 16 bytes
split into lane_0 (first 8 bytes) and lane_1 (next 8 bytes), big-endian
state[0] ^= domain_lane_0
state[1] ^= domain_lane_1
```

A future `WiseDigest-N` would XOR a different string. Both the initial-state phrases and the domain-tag XOR jointly separate this candidate from any sibling candidate.

## 4. Head and stride

The construction maintains a per-instance pointer `head ∈ {0..11}` that walks the state as input bytes arrive. The head moves with a **state-derived stride** — not a stride directly chosen by the input byte.

```
head        starts at 0
byte_count  starts at 0
finalized   starts at false
```

## 5. Per-byte absorption

For each input byte `b` at absolute position `i` (0-indexed across the entire stream including any later length suffix):

```
h = head

# (1) Mix the byte into the lane the head currently points at.
state[h] = state[h] XOR (b * MIX_A) XOR (i * MIX_B)
state[h] = (state[h] + MIX_C * (b + 1)) mod 2^64

# (2) State-driven rotation (NOT directly chosen by the input byte).
rot = ((state[h] >> 58) | 1) AND 0x3F        # rot in [1, 63], odd
state[h] = ROTL64(state[h], rot)

# (3) Multi-tap cross-lane mixing (three non-adjacent neighbors).
tap1 = (h + 1)  mod 12
tap2 = (h + 5)  mod 12
tap3 = (h + 7)  mod 12
state[tap1] = state[tap1] XOR state[h]
state[tap2] = (state[tap2] + state[h]) mod 2^64
state[tap3] = ROTL64(state[tap3], 11) XOR state[h]

# (4) State-driven stride. Head advances by an amount derived from a
# distant lane, NOT from the input byte.
stride = (state[(h + 11) mod 12] mod 11) + 1     # stride in [1, 11]
head   = (h + stride) mod 12
```

All arithmetic is unsigned 64-bit modular. `ROTL64(x, n)` rotates `x` left by `n` bits.

The choice of taps `(+1, +5, +7)` and stride source `(+11)` means each byte touches four distinct lanes and influences the head movement via a fifth.

The choice to derive both the rotation amount and the stride from state — rather than from the input byte directly — is intentional: an attacker who picks input bytes does not directly choose the schedule.

## 6. Length absorption

After all input bytes have been absorbed, append eight bytes representing the bit-length of the input as a big-endian uint64, and feed them through the **same per-byte absorption path** used for input. Their position indices continue from `byte_count`.

```
bit_length  = (byte_count * 8) mod 2^64
length_bytes = big_endian_8(bit_length)
for k in 0..7:
    absorb_byte(b = length_bytes[k], i = byte_count + k)
```

Inputs ≥ 2^61 bytes wrap their bit-length modulo 2^64. This is out of scope for v0.1.

## 7. Finalization

After length absorption, run **24 input-free finalization rounds**. Each round mixes every lane with three non-adjacent lanes:

```
for round in 0..24:
    new = copy(state)
    for k in 0..12:
        a = state[k]
        b = state[(k + 5)  mod 12]
        c = state[(k + 7)  mod 12]
        d = state[(k + 11) mod 12]
        x = ROTL64(a, 13) XOR ROTL64(b, 31) XOR ((c + MIX_D) mod 2^64)
        new[k] = (x + ROTL64(d, 41) + MIX_E) mod 2^64
    state = new
```

The round operates on a snapshot (`copy(state)`) so that lane updates do not interfere within a single round. Rounds are deterministic and contain no input.

## 8. Output extraction

Fold the 12-lane state to 4 lanes via per-row XOR:

```
out[0] = state[0] XOR state[4] XOR state[8]
out[1] = state[1] XOR state[5] XOR state[9]
out[2] = state[2] XOR state[6] XOR state[10]
out[3] = state[3] XOR state[7] XOR state[11]

digest = big_endian_8(out[0]) || big_endian_8(out[1])
       || big_endian_8(out[2]) || big_endian_8(out[3])
```

That is 32 bytes. Encode as 64 lowercase hex characters.

The output fold is linear (XOR). This is a known weakness pattern called out in §10.

## 9. Streaming behavior

`update(data)` streams bytes through per-byte absorption immediately; no buffering of partial blocks is required because the construction is not block-based. Calling `hexdigest()` triggers length-absorption + finalization once and is idempotent thereafter. `update()` after `hexdigest()` raises.

Streaming output MUST equal one-shot output for any partition of the same input.

## 10. Known weaknesses (stated honestly)

These are real weaknesses, not protocol fluff. Nobody — including the author — should assume the absence of an attack the author hasn't run.

1. **Linear output fold.** The 12 → 4 XOR fold means any state-level differential trail of length zero on the modulo-3 row groups maps directly into the output. A real design would replace this with a non-linear projection.
2. **Data-dependent rotation.** Deriving the rotation amount from `state[h] >> 58` is a known cryptanalytic weakness category (RC5/RC6 style). It buys nonlinearity but introduces structure that academic cryptanalysis has historically broken in similar designs.
3. **Per-byte absorption is slow** (~5 μs per byte in pure Python). This caps the scale at which the author can run their own attack tests. A Rust port is required before any larger-scale attack analysis is meaningful.
4. **No round-reduced cryptanalysis.** 24 finalization rounds is a guess. The right count is unknown.
5. **No structured-input adversarial search.** Random pairs, single-bit flips, and small birthday searches all behave as expected; structured (chosen) attacks have not been attempted by the author.
6. **No third-party implementation.** Spec ambiguities will not surface until a second author writes a conformant implementation.
7. **Constants are non-mathematical.** ASCII phrases are auditable ("nothing up our sleeve" — we wrote them in plaintext) but lack the mathematical justification of constants like sqrt(2)'s fractional bits. They could embed weak structure we did not anticipate.
8. **The state-driven stride can produce short cycles.** When `stride` mod 12 falls in `{2, 3, 4, 6}`, only a strict subset of lanes is visited until the stride changes. For adversarial inputs that pin stride to a small subgroup, lane visit patterns degrade.
9. **The taps `(+1, +5, +7)` are author-chosen.** No analysis was performed to confirm they maximize diffusion vs. alternative tap sets.
10. **The mixing constants (`MIX_A` … `MIX_E`) are derived from short ASCII phrases.** Their bit patterns are biased toward printable ASCII (high nibble in `0x4` … `0x7`). This is a structural bias an attacker can exploit if it correlates with the construction's algebra.

WiseDigest-2 is **research-track only**. SHA-256 is the recommendation in `SECURITY.md` for production threat models. WiseDigest-0 remains the live native default in the `wise` CLI; WiseDigest-2 is reachable only via direct import.

## 11. Test vectors

Locked vectors live in `tests/test_wisedigest_v2.py`. They will not change within a `WiseDigest-2.x` line; any change requires a new algorithm version (e.g., `WiseDigest-2.1`) and a `WiseDigest-Lab.md` entry.
