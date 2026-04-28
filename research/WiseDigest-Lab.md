# WiseDigest Lab Notebook

This is a running record of analysis done on WiseDigest candidates. It is the working document where measurements, attacks, and decisions live. The spec lives in `WiseDigest-1.md`; this file is the journal.

Format: each entry is dated, names the candidate version, lists the experiments run and their numerical results, and ends with weaknesses found and the next improvement to attempt.

---

## 2026-04-27 — WiseDigest-1.0, first pass

### Setup

- Reference implementation: `src/wise/digest_v1.py`, pure Python.
- Functional tests: `tests/test_wisedigest_v1.py` (locked vectors + streaming).
- Attack suite: `tests/test_wisedigest_attack_suite.py`.
- Host: macOS arm64, Python 3.14.3.

### Design summary (from `WiseDigest-1.md`)

| Parameter | Value |
|---|---|
| State | 8 × 64-bit lanes (512 bits) |
| Rate | 4 lanes (256 bits, 32 bytes) |
| Capacity | 4 lanes (256 bits) |
| Output | 256 bits |
| Rounds | 12 |
| Mixing primitive | BLAKE2b G function (verbatim) |
| IV | BLAKE2b IV (sqrt of first 8 primes) |
| Domain separator | `"WiseDigest-1"` XOR'd into `state[0..1]` |
| Padding | message ‖ BE64(bit_length) ‖ zero-pad to rate boundary |

### Functional results

11 locked test vectors pass. Streaming-vs-one-shot equivalence verified across 7 partition points on a 301-byte message. Empty input is well-defined and stable.

```
WiseDigest-1("")     = 83fdedf78ebe416c64f140f8480e55f5f302e1b79258f37833fd9288b2211e48
WiseDigest-1("abc")  = 7e2582aa328fd6d3b4b855680eeaa2587cced6d39be87570c662dbf60aace937
WiseDigest-1("a")    = 3a129072a4d8aa950011cc22b957433f40be87302720c20ad4e2b3533c426022
WiseDigest-1("aa")   = 97ea05405e692b56fc2dd1304fd574850901898c89483809f11aa6dc5fb76383
WiseDigest-1("a\0")  = f245c18066316a26517b92ceb490d51c8175a85cfa3a5ab521f597cd02d316f3
```

### Attack measurements

All numbers below are from a deterministic-seeded run and can be reproduced by re-running `tests/test_wisedigest_attack_suite.py` plus the capture script in `research/scripts/` (TODO).

#### Avalanche — single-bit flip

11 520 trials (30 random 48-byte messages × 384 bit positions each).

| Statistic | Observed | Ideal |
|---|---|---|
| Mean Hamming distance | **127.96 bits** | 128.00 |
| Standard deviation | 7.97 | ≈8.00 (binomial, n=256, p=0.5) |
| Minimum (worst single bit-flip) | 92 | — |
| Maximum (most-flipped) | 159 | — |

The mean is within 0.04 bits of ideal. The stdev matches the binomial expectation for an unbiased ideal random function within rounding. No single-bit-flip produced fewer than 92 output-bit changes (`> 64` lower bound passes).

**Verdict:** No avalanche weakness detected at this scale. Cannot rule out localized weaknesses without longer trails / per-bit position breakdown.

#### Differential — random pairs

500 trials of two unrelated random messages (1–200 bytes each).

| Statistic | Observed | Ideal |
|---|---|---|
| Mean Hamming distance | **128.09 bits** | 128.00 |
| Standard deviation | 8.29 | ≈8.00 |
| Min / Max | 106 / 150 | — |

**Verdict:** No two-input differential bias detected at this scale.

#### Truncated-prefix collision search (birthday smoke test)

N = 16 384 random 16-byte messages, projected to first 16 output bits.

| | Observed | Birthday expected (N(N−1)/2 / 2¹⁶) |
|---|---|---|
| Collisions | **2 071** | 2 047.9 |
| Ratio | **1.011×** | 1.000× |

**Verdict:** Within 1.1% of birthday expectation. No exploitable bias surfaced at 16 bits. This is a smoke test, not a real collision search.

#### Full 256-bit collision search

N = 4 096 random messages — zero collisions observed (as expected).

#### Output byte distribution

Across 2 000 digests (64 000 output bytes total), per-byte-value occurrences vs. uniform expectation of 250:

| Statistic | Observed |
|---|---|
| Max absolute deviation from 250 | **46** |
| Max relative deviation | **18.4%** |

Within the ±25% acceptance window the test enforces. The 18% peak is consistent with sampling noise at this N (a uniform distribution over 256 values with 64 000 samples has stdev ≈ 15.6 per value — 46 ≈ 3σ, occurs in some byte value with high probability across 256 trials).

**Verdict:** Distribution is near-uniform within sampling-noise bounds.

#### Length-extension smoke test

Naive concatenation attacks fail. The sponge capacity is non-zero, so this is expected by construction; we only confirmed the obvious naive attempt does not succeed.

**Verdict:** Sponge capacity provides structural length-extension resistance. Real cryptanalytic length-extension would need to recover capacity bits, which we have not attempted.

#### Domain separation

200 random inputs hashed under both WiseDigest-0 and WiseDigest-1 — zero cross-collisions.

**Verdict:** Domain separation works at this scale. Cannot rule out structured attacks that intentionally search for cross-collisions.

### Weaknesses found

1. **No round-reduced cryptanalysis.** Nothing in this notebook tells us whether 12 rounds is enough. Could be far too many or just barely enough.
2. **No per-bit-position avalanche breakdown.** Aggregate mean is healthy; we have not checked whether some specific bit positions in the input have weak diffusion to specific output bits.
3. **No structured-input differential search.** Random pairs look fine; chosen pairs (related-key, related-message) are untested.
4. **Pure-Python ceiling.** At ~2 ms per hash for short inputs, large-scale attacks are off the table until a Rust port lands. ~10⁵ hashes is comfortable; 10⁹ is not.
5. **No third-party implementation.** Spec ambiguity will not surface until a second author implements it. Locked vectors guard against drift but cannot prove the spec is unambiguous.
6. **Capacity equals output.** Generic sponge collision bound is 128 bits, which we cannot match in concrete analysis without round analysis.
7. **Constants are inherited verbatim from BLAKE2b** but the surrounding construction is novel. The mixing function carries BLAKE2b's reputation; the schedule does not.

### Next improvements (in order)

1. **Per-bit avalanche matrix.** For each input bit position × output bit position, measure flip probability across ~10⁵ random messages. Look for cells far from 0.5.
2. **Round-reduction study.** Run the same suite at ROUNDS = 4, 6, 8, 10, 12. The point at which avalanche stabilizes is the *minimum* safe count, not the recommended count (typically 2–3× the stabilization point).
3. **Rotational and structured-message tests.** Inputs that differ only by a bit rotation, or by a XOR with a sparse mask, often reveal weaknesses random-pair tests miss.
4. **Rust port.** Required for every attack above to run at meaningful scale.
5. **External cryptanalysis.** Once the Rust port exists and the spec is stable, post a proposal-and-attack-bounty thread on a relevant venue.

### Decision

**WiseDigest-1.0 is NOT promoted to the `wise` CLI.** It will sit on the research track, behind `from wise.digest_v1 import digest_bytes`, until the items in "Next improvements" produce evidence that warrants promotion. SHA-256 remains the recommended algorithm for any threat model that requires collision resistance.

---

## 2026-04-27 — WiseDigest-2.0, first pass (originality-first track)

### Setup

- Reference implementation: `src/wise/digest_v2.py`, pure Python.
- Functional tests: `tests/test_wisedigest_v2.py` (locked vectors + streaming).
- Attack suite: `tests/test_wisedigest_v2_attack_suite.py`.
- Host: macOS arm64, Python 3.14.3.
- Originality rule: no SHA, BLAKE/ChaCha G, Keccak, sponge, Merkle-Damgård, or external IV.

### Design summary (from `WiseDigest-2.md`)

Positional accumulator with state-driven head walk + multi-tap cross-lane mixing.

| Parameter | Value |
|---|---|
| State | 12 × 64-bit lanes (768 bits, > output) |
| Output | 256 bits via XOR fold of 12 → 4 lanes |
| Mixing | per-byte: lane mutate + state-driven rotation + 3 cross-lane taps + state-driven head stride |
| Initial state | 12 Wise-native 8-byte ASCII phrases |
| Domain tag | `"WiseDigest-2"` XOR'd into `state[0..1]` |
| Mixing constants | 5 Wise-native phrases (`WISEMIX1`..`WISEMIX5`) |
| Length absorption | append BE64 bit-length, run through same per-byte path |
| Finalization | 24 input-free rounds with 4-lane mixing per lane |

### Functional results

14 locked vectors pass. Streaming-vs-one-shot equivalence verified across 7 fixed split points and 10 random partitions.

```
WiseDigest-2("")     = d71b0a2b351e225730cf339b97dba675175c947930fc455cac218d98b9482e92
WiseDigest-2("abc")  = 5dc7284b3b965577a328b90c3da7d53d5cbc4f42893856b50c17a5aaf9bf8063
```

### Attack measurements

| Test | Observed | Ideal/Expected | Verdict |
|---|---|---|---|
| Single-bit avalanche (n=7,680) | mean **128.05**, stdev 7.91, min 98, max 155 | 128, ≈8 | within ideal |
| Per-byte avalanche (n=448) | mean **128.08**, stdev 8.12 | 128 | within ideal |
| Random-pair differential (n=400) | mean **128.11**, stdev 7.36 | 128 | within ideal |
| Structured-XOR pair (n=200, 5 masks) | mean **128.07**, stdev 7.69 | 128 | within ideal |
| Rotated-input pair (n=60) | mean **128.52**, stdev 7.08 | 128 | within ideal |
| 16-bit birthday (N=8,192) | **498** collisions | 511.9 | ratio 0.973× |
| 256-bit collisions (N=4,096) | **0** | 0 | as expected |
| 3-way domain separation v0/v1/v2 (n=300) | **0** cross-collisions | 0 | as expected |
| Output byte distribution (1,500 digests) | within ±35% of uniform | — | passes |

### Weaknesses found / suspected

1. **Linear output fold.** `out[i] = state[i] ^ state[i+4] ^ state[i+8]` means state-level differential trails projecting cleanly onto output rows are visible.
2. **Data-dependent rotation** in the per-byte step is a known cryptanalytic weakness category (RC5/RC6 lineage).
3. **Mixing constants from short ASCII phrases** carry printable-ASCII bit bias (high nibble in `0x4`–`0x7`).
4. **24 finalization rounds** is a guess.
5. **Pure-Python ceiling** (~5 μs/byte) prevents anything beyond ~10⁵-scale attacks.
6. **No round-reduced or per-bit-position analysis** has been performed.
7. **State-driven stride can fall in `{2,3,4,6}`** which is non-coprime to 12, producing short lane visit cycles when stride is forced.

### Comparison to WiseDigest-1

| Property | v1 (BLAKE-derived sponge) | v2 (original positional accumulator) |
|---|---|---|
| Borrowed cores | BLAKE2b G + IV | none |
| Construction | sponge | positional head walk |
| Constants | math (sqrt of primes) | Wise-native ASCII phrases |
| Avalanche mean | 127.96 | 128.05 |
| Birthday-16bit ratio | 1.011× | 0.973× |
| Output fold | direct rate emit | linear XOR fold (weakness) |
| Round count | 12 (BLAKE2b's count) | 24 (heuristic) |
| Pure-Python speed | ~2 μs/byte | ~5 μs/byte |

Both candidates pass the same battery of cheap statistical tests. v1 inherits BLAKE2b's analytical heritage in its mixing core; v2 inherits nothing.

### Decision

**WiseDigest-2.0 is NOT promoted** to the `wise` CLI. It stays research-only behind `from wise.digest_v2 import digest_bytes`. SHA-256 remains the recommendation for production threat models. WiseDigest-0 stays the live default.

The originality rule was met. The statistical tests passed. Neither fact constitutes a security claim.

### Next attack phase

In order:

1. **Per-(input-bit, output-bit) avalanche matrix** at n ≥ 10⁵ to surface localized weaknesses the aggregate mean hides.
2. **Round-reduced study at FINALIZE_ROUNDS ∈ {6, 9, 12, 15, 18, 21, 24}.** Identify minimum count for full diffusion; production count should be 2–3× that.
3. **Algebraic / linear approximation search** targeting the linear output fold — this is the most likely place a real attack lands.
4. **Forced-schedule attacks**: craft inputs that pin the state-driven rotation amount to a small set, then run differential search under that fixed schedule.
5. **Rust port** to lift the n ≥ 10⁵ ceiling on every test above.
6. **Promotion gate**: WiseDigest-2 will not be considered for CLI promotion until it survives at least items 1, 2, and 3, and a Rust port exists with vector-conformance proven.

---

## 2026-04-27 — WiseDigest-3.0, first pass (793-bit live state)

### Setup

- Reference implementation: `src/wise/digest_v3.py`, pure Python.
- Functional tests: `tests/test_wisedigest_v3.py` (29 tests + 14 locked vectors).
- Attack suite: `tests/test_wisedigest_v3_attack_suite.py` (21 tests).
- Host: macOS arm64, Python 3.14.3.
- Constraint: state = exactly 793 live bits (`13 × 61`). Top 3 bits of each lane's storage cell are dead and explicitly masked.

### Design summary (from `WiseDigest-3.md`)

| Parameter | Value |
|---|---|
| Live state | **793 bits** (13 lanes × 61 bits, prime × prime) |
| Lane mask | `MASK61 = 0x1FFFFFFFFFFFFFFF` re-applied after every op |
| Lane count | 13 (prime) → every state-driven stride visits every lane |
| Schedule entropy | uniform via `(state * N) >> 61` (no biased high-bit slicing) |
| Output | 256 bits via **non-linear** extraction: 2 multiplications + state-driven self-rotation per output word |
| Finalization | 25 input-free rounds |
| Initial state | 13 Wise-native 8-byte ASCII phrases, 61-bit masked |
| Domain tag | `"WiseDigest-3"` XOR'd into `state[0..1]` |

### 793-bit invariant — verified

For 80 random inputs and 7 adversarial inputs (empty, all-0x00, all-0xFF, alternating, byte-counter, etc.), every one of the 13 lanes always satisfied `0 <= s <= MASK61` after init, after every streaming step, and after finalize. The top 3 bits of every lane were 0 in every observed state.

Lane variation: across 80 random inputs, every lane took 79 distinct values (the maximum possible, given a tiny chance of collision). No constant-lane defect.

### Functional results

14 locked test vectors pass. Streaming-vs-one-shot equivalence verified across 7 fixed split points and 10 random partitions.

```
WiseDigest-3("")     = 94f8a850b58985834a7e72864c0db6757d9864c5d5ab4ff31188b6323c43e999
WiseDigest-3("abc")  = 7316f497541bb373d07a30be6fe0af0a25722b5c4adc98236fb27e0575ecec23
```

### Attack measurements

| Test | Observed | Ideal | Verdict |
|---|---|---|---|
| Single-bit avalanche (n=6,144) | mean **127.94**, stdev 8.04, min 102, max 160 | 128, ≈8 | within ideal |
| Per-byte avalanche (n=448) | mean **127.62**, stdev 7.72 | 128 | within ideal |
| Random-pair differential (n=300) | mean **128.19**, stdev 8.05 | 128 | within ideal |
| Structured-XOR (n=150) | mean **127.01**, stdev 8.80 | 128 | within ideal |
| Rotated-input (n=50) | mean **128.12**, stdev 9.42 | 128 | within ideal |
| 16-bit birthday (N=6,144) | **314** vs expected 288 | birthday | ratio 1.090× |
| 256-bit collisions (N=4,096) | **0** | 0 | as expected |
| 4-way domain sep v0/v1/v2/v3 (n=250) | **0** cross-colls | 0 | as expected |

### Comparison to WiseDigest-2

| Property | v2 | v3 |
|---|---|---|
| Live state | 768 bits (12×64) | **793 bits (13×61)** |
| Lane width | 64 bits | 61 bits + 3 dead masked |
| Lane count | 12 (composite) | **13 (prime)** |
| Stride coprime to lane count | only when stride ∈ {1,5,7,11} | **always** (because 13 prime) |
| Schedule entropy | `state >> 58` (slight bias) | `(state * N) >> 61` (uniform) |
| Output extraction | linear XOR fold | **non-linear: 2 multiplications + state-driven rotation** |
| Avalanche mean | 128.05 | 127.94 |
| Birthday-16bit ratio | 0.973× | 1.090× |
| Round count | 24 | 25 |
| Pure-Python time per byte | ~5 μs | ~6 μs |

v3 fixes three v2 weaknesses: (a) the linear output fold is replaced with multiplications, (b) the stride-cycle subgroup risk is gone (13 prime), (c) schedule entropy is uniform.

v3 introduces new risk surfaces: (a) integer multiplication in output extraction with potential weak-operand cases, (b) data-dependent rotations (still present), (c) 61-bit lane width has no cryptanalytic literature.

### Weaknesses found

1. **Multiplicative output extraction has weak-operand patterns.** When `a|1`, `b|1`, `c|1`, `m|1` happen to all be small, products `u` and `v` carry low entropy. The `|1` trick removes the `=0` worst case but not small-operand bias.
2. **Birthday-16bit ratio drifted higher** (1.090×) compared to v2 (0.973×) and v1 (1.011×). Within the suite's wide acceptance window but worth tracking — may reflect mild structure in the multiplicative output stage at this N.
3. **Data-dependent rotations remain** in absorption and output extraction — RC5/RC6-class concern.
4. **No round-reduced study, no per-bit avalanche matrix.**
5. **61-bit lane width is unprecedented in mainstream cryptanalysis.** No literature to lean on.
6. **Mixing constants from short ASCII** carry printable bias plus a 61-bit truncation bias.
7. **Pure-Python ceiling** (~6 μs/byte) caps attack scale at ~10⁵ hashes.

### Decision

**WiseDigest-3.0 is NOT promoted** to the `wise` CLI. It stays research-only behind `from wise.digest_v3 import digest_bytes`. SHA-256 remains the production recommendation. WiseDigest-0 stays the live default. v1, v2, v3 are parallel research tracks with distinct designs.

### Next attack phase (in order)

1. **Targeted multiplicative-bias search.** Construct inputs that drive multiple state lanes near zero or near small-prime values; measure output entropy under those conditions.
2. **Per-(input-bit, output-bit) avalanche matrix at n ≥ 10⁵.**
3. **Round-reduced study at FINALIZE_ROUNDS ∈ {6, 9, 12, 15, 18, 21, 25}.**
4. **Forced-schedule attack:** craft inputs that pin the state-driven rotation amount into a small set, then run differential search under the fixed schedule.
5. **Rust port.** Required to lift the ~10⁵ scale ceiling.
6. **Promotion gate.** WiseDigest-3 is not eligible for CLI promotion until items 1–4 produce evidence justifying it AND a Rust port produces byte-identical output for every locked vector.

---

## (next entry — date / author / candidate version)

When you do another round of analysis or design changes, append a dated section here. Do not edit prior entries: they are the audit trail.
