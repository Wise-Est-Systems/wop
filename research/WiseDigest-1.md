# WiseDigest-1 — Specification (RESEARCH TRACK)

**Status:** experimental candidate. NOT a security claim.

WiseDigest-0 is frozen at its v0.1.0 definition (`spec/SPAS-v0.1.0-draft.md` §7 + §30). WiseDigest-1 is a new, separately-versioned candidate with a more conservative construction. It is offered for analysis and attack, not yet for production use, and is not selectable from the `wise` CLI.

The intent of this track is honest engineering: build it, attack it, improve it, promote it only when results justify it.

---

## 1. Output

```
256 bits, encoded as 64 lowercase hexadecimal characters.
```

## 2. State

```
8 lanes of 64-bit unsigned integers   (512-bit state)
Rate     = 4 lanes  = 256 bits = 32 bytes per absorbed block
Capacity = 4 lanes  = 256 bits
```

This is a sponge construction with rate = capacity = 256 bits. Squeeze emits the first 4 lanes (32 bytes).

## 3. Initial state (IV)

The initial state is the BLAKE2b IV — the fractional parts of the square roots of the first eight primes (2, 3, 5, 7, 11, 13, 17, 19). These are well-known public-domain "nothing up my sleeve" constants and are reused here precisely because they are not chosen by us.

```
IV[0] = 0x6A09E667F3BCC908     // sqrt(2)
IV[1] = 0xBB67AE8584CAA73B     // sqrt(3)
IV[2] = 0x3C6EF372FE94F82B     // sqrt(5)
IV[3] = 0xA54FF53A5F1D36F1     // sqrt(7)
IV[4] = 0x510E527FADE682D1     // sqrt(11)
IV[5] = 0x9B05688C2B3E6C1F     // sqrt(13)
IV[6] = 0x1F83D9ABFB41BD6B     // sqrt(17)
IV[7] = 0x5BE0CD19137E2179     // sqrt(19)
```

## 4. Domain separation

The initial state is XOR'd with a domain separator derived from the literal ASCII string `"WiseDigest-1"` (12 bytes), padded to 16 bytes with `0x00`, interpreted as two big-endian 64-bit lanes:

```
"WiseDige"          big-endian uint64  →  0x5769736544696765
"st-1\0\0\0\0"      big-endian uint64  →  0x73742D3100000000

state[0] ^= 0x5769736544696765
state[1] ^= 0x73742D3100000000
```

A future `WiseDigest-2` would XOR a different domain string, producing distinct initial states from the same IV.

## 5. Permutation `P`

`P` mixes the 512-bit state in place. It runs **12 rounds**.

### 5.1 Quarter-round `G(a, b, c, d)`

The mixing primitive is the BLAKE2b G function operating on four 64-bit lanes specified by indices `a, b, c, d` of the state. Operations are 64-bit unsigned arithmetic mod `2^64`. `ROTR64(x, n)` is bitwise right-rotation by `n`.

```
state[a] = state[a] + state[b]
state[d] = ROTR64(state[d] XOR state[a], 32)
state[c] = state[c] + state[d]
state[b] = ROTR64(state[b] XOR state[c], 24)
state[a] = state[a] + state[b]
state[d] = ROTR64(state[d] XOR state[a], 16)
state[c] = state[c] + state[d]
state[b] = ROTR64(state[b] XOR state[c], 63)
```

`G` is taken verbatim from BLAKE2b. We borrow it, we do not invent it.

### 5.2 Round

One round = four `G` calls in a fixed schedule that touches every lane exactly twice:

```
column step:    G(0, 2, 4, 6)
                G(1, 3, 5, 7)
diagonal step:  G(0, 3, 4, 7)
                G(1, 2, 5, 6)
```

### 5.3 Round count

```
ROUNDS = 12
```

This count is taken from BLAKE2b. BLAKE2b's 12 rounds were tuned for a 16-lane (1024-bit) state; we operate on 8 lanes (512 bits). Whether 12 is the right count for our smaller state is an open analysis question. See `WiseDigest-Lab.md` for measurements and §10 of this document for known weaknesses.

## 6. Padding and length absorption

Given input message `M` of length `L` bytes, construct `M'`:

```
1. P_len   = big_endian_uint64(L * 8)        // 8 bytes, message bit length mod 2^64
2. tail    = M || P_len
3. pad_len = (RATE_BYTES - (len(tail) mod RATE_BYTES)) mod RATE_BYTES
4. M'      = tail || (0x00 * pad_len)
```

`M'` is always a non-empty byte string whose length is a positive multiple of `RATE_BYTES` (32). The empty input produces `M'` of length 32 (just the length suffix plus 24 zero bytes).

The bit length is encoded modulo `2^64`. Messages longer than `2^64 - 1` bits are out of scope for v1.

## 7. Absorption

Process `M'` as a sequence of 32-byte blocks `B_0, B_1, ..., B_{n-1}`. For each block:

```
for i in 0..3:
    lane[i] = big_endian_uint64(B_k[8i .. 8i+8])
    state[i] = state[i] XOR lane[i]
P(state)                  // run all 12 rounds in place
```

Lanes 4..7 (the capacity) are never directly XOR'd with input. They evolve only through the permutation.

## 8. Squeeze

After all blocks are absorbed, emit:

```
output = big_endian_uint64(state[0]) || ... || big_endian_uint64(state[3])
```

That is 32 bytes. Encode as 64 lowercase hex characters.

WiseDigest-1 is fixed-output (256 bits). No extendable-output mode in v1.

## 9. Streaming

Implementations MUST be streaming-capable. The reference Python implementation buffers any partial trailing block across `update()` calls; final padding is computed and absorbed lazily on first `hexdigest()` call. Streaming output MUST equal one-shot output for any partition of the same input.

## 10. Known weaknesses and open questions

These are stated up front to invite attack rather than hide behind silence.

- **No formal security analysis.** Round-reduced cryptanalysis, differential trail counting, linear analysis, rotational distinguishers — none of these have been performed. Any attacker who runs them may find more than we have.
- **Round count is heuristic.** 12 rounds inherits BLAKE2b's choice without re-justification for our smaller state. The right number for an 8-lane sponge is unknown to us.
- **Capacity equals output.** Generic sponge collision security bound is `c/2 = 128 bits` if the permutation behaves like a random permutation. We do not know that ours does.
- **Pure-Python reference is slow.** Cryptanalysis at scale will require a faster implementation (Rust or C). Until that exists, attack tests are bounded by Python's speed.
- **Domain separation is informal.** XORing a fixed string into the IV is a common technique but not a formally-binding construction in the way that, e.g., Keccak's `02` suffix bytes are.
- **Side channels.** Pure-Python ARX is not constant-time, but constant-time is not in scope for v1.
- **No third-party implementation.** Locked test vectors are produced by our own reference code; if the spec is ambiguous, we will not catch it until a second implementation exists.

## 11. Reference parameters summary

```
state lanes        : 8
lane width         : 64 bits
state size         : 512 bits
rate               : 256 bits  (4 lanes, 32 bytes)
capacity           : 256 bits  (4 lanes, 32 bytes)
output             : 256 bits  (4 lanes, 32 bytes; first 4 lanes after final permute)
rounds             : 12
mixing primitive   : BLAKE2b G function (verbatim)
endianness         : big-endian for all serialization (input absorption, length suffix, output)
padding            : message || BE64(bit_length) || zero-pad to multiple of rate
domain separator   : "WiseDigest-1" XOR'd into state[0..1] before any absorption
```

## 12. Test vectors

Locked test vectors live in `tests/test_wisedigest_v1.py` and are computed by the reference implementation in `src/wise/digest_v1.py`. They will not change within a `WiseDigest-1.x` line. Any change requires a new minor version of the algorithm (e.g., `WiseDigest-1.1`) and an entry in `WiseDigest-Lab.md`.
