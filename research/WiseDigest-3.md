# WiseDigest-3 — Specification (RESEARCH TRACK, 793-BIT LIVE STATE)

**Status:** experimental, original-construction candidate. **NOT a security claim.**

WiseDigest-3 is the third originality-first candidate. The defining choice is a **793-bit live internal state**, deliberately off the 256/512/768/1024 framing. The breakdown is `13 × 61 = 793`. Both numbers carry the constraint:

- **13** is prime, so any non-zero lane stride is coprime to the lane count and visits every lane.
- **61** is prime and not a power of two; arithmetic happens modulo `2^61` and every lane MUST be masked to 61 bits after every operation.

The internal state is exactly 793 live bits — not a marketing number. Storage uses 64-bit Python ints, but the top three bits of each lane are explicitly masked to zero after every arithmetic step and a digest-time invariant check verifies it.

What WiseDigest-3 does **not** use:

- No SHA, BLAKE, ChaCha, Keccak, Merkle-Damgård, or sponge core.
- No mathematical IV constants (sqrt of primes, etc.).
- No simple linear XOR fold for output extraction.

What WiseDigest-3 **does** use: integer addition modulo `2^61`, XOR, 61-bit rotation, integer multiplication modulo `2^64` (output extraction only), and Wise-native ASCII-derived constants.

---

## 1. State layout

```
LIVE_BITS  = 793
LANES      = 13
LANE_BITS  = 61
MASK61     = 0x1FFFFFFFFFFFFFFF       (= 2^61 - 1)

state: array of 13 unsigned 61-bit integers
       each lane stored in a Python int, but invariant 0 <= state[k] <= MASK61
       MUST be re-established after every operation
```

`13 * 61 == 793` is asserted at module load time.

The top 3 bits of each 64-bit storage cell are **dead bits**. They are masked to zero after every assignment. A `_invariant_check()` is run at finalize-time to confirm; tests assert this.

## 2. Wise-native constants

All constants are 8-byte ASCII phrases packed big-endian into 64-bit integers, then masked to 61 bits where used in 61-bit arithmetic. Output-extraction salts retain the full 64 bits.

### 2.1 Initial state (13 phrases, masked to 61 bits)

```
state[0]  = "WISEDIG3"      // algorithm tag
state[1]  = "STATE793"
state[2]  = "THIRTEEN"
state[3]  = "SIXTYONE"
state[4]  = "ORIGINAL"
state[5]  = "OWNTRACK"
state[6]  = "BYTETRUE"
state[7]  = "NOFOLDFL"
state[8]  = "DOMTAG3X"
state[9]  = "REPRODUC"
state[10] = "ALIVE793"
state[11] = "LENABSRB"
state[12] = "FAIL2DIE"
```

### 2.2 Mixing constants (61-bit)

```
MIX_A = "WMIX793A"
MIX_B = "WMIX793B"
MIX_C = "WMIX793C"
MIX_D = "WMIX793D"
MIX_E = "WMIX793E"
```

### 2.3 Output-extraction salts (64-bit, used only at extraction)

```
OUT_SALT[0] = "OUTMIX01"
OUT_SALT[1] = "OUTMIX02"
OUT_SALT[2] = "OUTMIX03"
OUT_SALT[3] = "OUTMIX04"
```

### 2.4 Domain separator

```
ASCII "WiseDigest-3"  (12 bytes)  + NUL pad to 16 bytes
split into two big-endian uint64 halves, each masked to 61 bits
state[0] ^= domain_lane_0 & MASK61
state[1] ^= domain_lane_1 & MASK61
```

## 3. Byte absorption

Maintain an integer `head ∈ {0..12}` initialized to 0, and a `byte_count` initialized to 0.

For each input byte `b ∈ [0, 255]` at absolute position `i`:

```
h = head

# (1) Mix the byte into state[h]. All operations masked to 61 bits.
state[h] = state[h] XOR ((b * MIX_A) & MASK61) XOR ((i * MIX_B) & MASK61)
state[h] = (state[h] + (MIX_C * (b + 1)) & MASK61) & MASK61

# (2) State-driven rotation amount, uniformly distributed in [1, 60].
#     Multiplication by 60 followed by right-shift by 61 produces a
#     uniform integer in [0, 60) using all 61 bits of state[h].
rot = ((state[h] * 60) >> 61) + 1            // in [1, 60]
state[h] = ROTL61(state[h], rot)

# (3) Multi-tap cross-lane mixing.
tap1 = (h + 1)  mod 13
tap2 = (h + 5)  mod 13
tap3 = (h + 7)  mod 13
state[tap1] = (state[tap1] XOR state[h])             & MASK61
state[tap2] = (state[tap2] + state[h])               & MASK61
state[tap3] = (ROTL61(state[tap3], 11) XOR state[h]) & MASK61

# (4) State-driven head stride, uniform in [1, 12].
#     13 is prime → every stride in [1, 12] is coprime to 13, so the head
#     visits all 13 lanes regardless of which stride is drawn.
stride = ((state[(h + 11) mod 13] * 12) >> 61) + 1   // in [1, 12]
head   = (h + stride) mod 13
```

`ROTL61(x, n)` rotates the low 61 bits of `x` left by `n`:

```
ROTL61(x, n):
    n = n mod 61
    return ( ((x << n) AND MASK61) OR ((x AND MASK61) >> (61 - n)) ) AND MASK61
```

## 4. Length absorption

After all input bytes are absorbed, append eight bytes representing the input bit-length as a big-endian uint64, and feed them through the **same per-byte absorption path** with `i` continuing from `byte_count`.

```
bit_length     = (byte_count * 8)  mod 2^64
length_bytes   = big_endian_8(bit_length)
for k in 0..7:
    absorb_byte(b = length_bytes[k], i = byte_count + k)
```

## 5. Finalization

After length absorption, run **25 input-free finalization rounds**:

```
for round in 0..25:
    snap = copy(state)
    for k in 0..13:
        a = snap[k]
        b = snap[(k + 5)  mod 13]
        c = snap[(k + 7)  mod 13]
        d = snap[(k + 11) mod 13]
        x         = (ROTL61(a, 13) XOR ROTL61(b, 31) XOR ((c + MIX_D) & MASK61)) & MASK61
        state[k]  = (x + ROTL61(d, 41) + MIX_E) & MASK61
```

The snapshot ensures lane updates within a round are independent. Round count differs from WiseDigest-2's 24 to mark distinction; both counts are heuristic.

## 6. Output extraction (NON-LINEAR)

The user requirement explicitly forbade simple linear XOR folding. Output extraction uses **two integer multiplications per output word, plus state-driven self-rotation**, both of which are non-linear over GF(2).

```
m   = state[12]
rot = (m * 63) >> 61    // uniform in [0, 63), used as rotation amount
rot = rot + 1            // in [1, 63]

for k in 0..3:
    a = state[2k]
    b = state[2k + 1]
    c = state[k + 8]

    // (i) Two non-linear products. OR-with-1 forces every operand to
    //     be odd, removing the zero-trap fixed point at a=0 or b=0.
    u    = ((a | 1) * (b | 1)) & MASK64
    v    = ((c | 1) * (m | 1)) & MASK64

    // (ii) XOR-combine then state-driven self-rotation diffuses
    //      structure. Self-rotation amount comes from lane 12.
    word = u XOR v
    word = (word XOR ROTL64(word, rot)) & MASK64

    // (iii) Per-word salt to break cross-word symmetry.
    word = (word + OUT_SALT[k]) & MASK64

    out[k] = word

digest = big_endian_8(out[0]) || big_endian_8(out[1])
       || big_endian_8(out[2]) || big_endian_8(out[3])
```

That is 32 bytes. Encode as 64 lowercase hex characters.

`ROTL64(x, n)` is full 64-bit rotation; output extraction leaves the 61-bit world. Every one of the 13 lanes participates: lanes 0..7 feed pairs `(a, b)` for `k=0..3`, lanes 8..11 feed `c`, lane 12 feeds `m` and the rotation amount.

## 7. Streaming

`update(data)` streams bytes immediately through per-byte absorption. No buffering of partial blocks. `hexdigest()` triggers length-absorption + finalization once and is idempotent. `update()` after `hexdigest()` raises.

Streaming output MUST equal one-shot output for any partition of the same input.

## 8. Comparison to WiseDigest-2

| Property | WiseDigest-2 | WiseDigest-3 |
|---|---|---|
| State size | 768 bits (12 × 64) | **793 bits (13 × 61)** |
| Lane width | 64 bits | 61 bits — top 3 bits dead, masked |
| Lane count | 12 (composite) | **13 (prime)** |
| Stride coprime to lane count | only when stride ∈ {1,5,7,11} | **always** |
| Output extraction | linear XOR fold | **nonlinear: two multiplications + state-driven rotation** |
| Finalization rounds | 24 | 25 |
| Mask discipline | `& 0xFFFFFFFFFFFFFFFF` (full word) | `& MASK61` after every op + assertion at digest |
| Live-bit invariant | implicit | **explicit, asserted at digest** |
| Schedule entropy source | bits 58..63 of state lane | uniform via `(state * N) >> 61` |

## 9. Known weaknesses (stated honestly)

1. **Multiplicative output extraction has weak operand patterns.** When `a|1, b|1, c|1, m|1` happen to be small, the products `u = (a|1)·(b|1)` and `v = (c|1)·(m|1)` carry low entropy. The OR-with-1 trick removes the worst case (operand = 0) but does not eliminate small-operand bias.
2. **Data-dependent rotations are still present**, both during absorption and at output extraction. RC5/RC6-class structure with all the cryptanalytic precedent that implies.
3. **No round-reduced study.** 25 rounds is a heuristic increment over WiseDigest-2's 24.
4. **No per-bit avalanche matrix.** Aggregate diffusion can be healthy while specific input-bit → output-bit cells are biased.
5. **Mixing constants from 8-byte ASCII phrases** carry printable-byte bias (high nibble in `0x4`–`0x7`) and the additional bias of being masked to 61 bits.
6. **The 61-bit lane width is unprecedented in mainstream cryptanalysis.** This may be a strength (no known attacks) or a weakness (no understanding of subtle interactions); we cannot say.
7. **Pure-Python ceiling** (~6 μs/byte estimated) caps attack scale at ~10⁵ hashes.
8. **Dead-bit leak risk.** If any operation forgets to mask, three bits per lane outside the 793-bit live envelope could carry ghost state. The implementation masks defensively; the digest-time assertion catches drift.

## 10. Test vectors

Locked vectors live in `tests/test_wisedigest_v3.py`. They will not change within a `WiseDigest-3.x` line; any change requires a new algorithm version and a `WiseDigest-Lab.md` entry.
