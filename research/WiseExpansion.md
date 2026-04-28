# WiseExpansion — Specification (RESEARCH TRACK)

**Status:** prototype. NOT a hash. NOT compression. NOT a Merkle tree.

WiseExpansion is a fourth category of artifact-derived object alongside hashes (lossy compaction with collision-resistance) and compression (lossless reduction). Where a hash answers "are these the same bytes?", a WiseExpansion answers "how are these bytes shaped?" The output is a deterministic, structured, multi-layer fingerprint that **grows in size** with respect to a hash so it can carry inspectable structural properties of the input.

It is reproducible: byte-identical input produces a byte-identical `.wiseexp` file. It is purely deterministic: no normalization, no entropy from the runtime, no time, no creator label.

The terminating field of every WiseExpansion is the **WiseMark** — a 256-bit digest of the canonical body (excluding the WiseMark line itself), provided as the compatibility hook for a future `WiseMeasure` verifier.

---

## 1. What WiseExpansion is for

| Existing category | Question it answers | What it loses |
|---|---|---|
| Hash (`WiseDigest-*`, `SHA-256`) | "are these the exact same bytes?" | all structure |
| Compression (`gzip`, `zstd`) | "can I store this in fewer bytes?" | nothing (lossless) but produces opaque bytes |
| Content-addressable hash (Git, IPFS) | "give me bytes by name" | structure |
| **WiseExpansion** | **"how are these bytes shaped, and is that shape reproducible?"** | **nothing — deterministic, full structure preserved** |

Concrete uses:

- An audit record proving an artifact's distribution, run-length, and bigram structure without exposing the bytes themselves.
- A forensic diff tool: two `.wiseexp` files reveal *which structural property* changed, not just whether bytes changed.
- A pre-filter for verification: if `frequency.most_common_byte` differs, the artifacts cannot be the same — you skip the full digest.
- A reproducibility certificate: a `wisemark` proves the expansion was computed canonically.

---

## 2. Layers

A WiseExpansion contains six layers of information about an input artifact `M` of `N` bytes.

### 2.1 Layer 1 — Byte layer

```
artifact.size_bytes        N
artifact.byte_digest       <hex digest of M under the chosen algorithm>
artifact.algorithm         WiseDigest-0 | SHA-256
```

### 2.2 Layer 2 — Positional patterns

```
positional.first16             hex of M[:16]                 (may be shorter if N<16)
positional.last16              hex of M[-16:]                (empty if N<32)
positional.midpoint16          hex of M[N/2-8 : N/2+8]       (empty if N<48)
positional.offset_mod16_digest digest of canonical 16-class summary
```

The "offset_mod16" canonical summary aggregates, for each `k ∈ {0..15}`, the sum-mod-2^64 and XOR of bytes at positions `i` where `i mod 16 = k`. The digest of these 16 (sum, xor) pairs reveals positional class structure (e.g., regular periodic structure in binary file headers).

### 2.3 Layer 3 — Frequency

```
frequency.distinct_bytes        number of distinct byte values (1..256)
frequency.most_common_byte      "0xNN" of the most common byte (lowest-byte tiebreak)
frequency.most_common_count     occurrences
frequency.shannon_milli         Shannon entropy in milliBits (integer)
frequency.chi_squared_milli     chi-squared deviation from uniform-on-256, in milli (integer)
frequency.histogram_digest      digest of canonical 256-entry BE64 histogram
```

`shannon_milli` is `round(H * 1000)` where `H = -Σ p_v · log2(p_v)`. Float arithmetic uses IEEE 754 doubles; rounding is round-half-even. This is reproducible across runs on the same Python implementation. A cross-language conformance specification will pin exact rational computation in a future version.

### 2.4 Layer 4 — Transition relationships (bigram structure)

```
transition.distinct_bigrams         number of distinct (a, b) bigrams (0 if N<2)
transition.most_common_bigram       "0xAABB" (empty if N<2)
transition.most_common_count        occurrences (0 if N<2)
transition.bigram_entropy_milli     Shannon entropy over bigram distribution (0 if N<2)
transition.matrix_digest            digest of canonical bigram serialization
```

The canonical bigram serialization is the concatenation, for each non-zero `(a, b, count)` in lex order on `(a, b)`, of `[a][b][BE64(count)]`. For `N < 2` this is empty bytes.

### 2.5 Layer 5 — Derived structural layers

```
structural.run_count              number of maximal runs of repeated bytes (0 if N=0)
structural.longest_run            length of longest run (0 if N=0)
structural.longest_run_byte       "0xNN" (empty if N=0)
structural.run_length_digest      digest of canonical run sequence
structural.block_count            ceil(N / block_size) (0 if N=0)
structural.blocks_digest          digest of canonical block-digest manifest
artifact.block_size               block_size used (default 1024)
```

Run canonical encoding: for each run `(value, length)` in order, `[value][BE64(length)]`.
Blocks canonical: `BE64(count) || digest_0 || digest_1 || ...` where each block is `M[i·B : (i+1)·B]` and digests use the chosen algorithm.

### 2.6 Layer 6 — WiseMark

```
wisemark    256-bit digest of the canonical WISEEXP-V1 body with the wisemark line excluded
```

The WiseMark is computed over a canonical text serialization of all the fields above. It is the integrity proof for the expansion document itself, in the same self-referential style as `wise_id` in WISEPROOF-V1. A `WiseMeasure` verifier can re-derive the WiseMark from the document and confirm the expansion has not been altered.

---

## 3. Canonical WISEEXP-V1 file format

```
1. UTF-8 text only.
2. First line exactly "WISEEXP-V1\n".
3. Exactly one blank line "\n".
4. Body lines of the form key=value\n.
5. Keys sorted by pure lexical full-key order (same rule as WISEPROOF-V1, Q18).
6. Values are raw UTF-8 with no escaping; values MUST NOT contain "\n" or "=".
7. File ends with "\n" after the last line.
8. The wisemark line is part of the body and sorts to its lex position (last).
```

Any deviation is a parse failure and treated by a future verifier as `INVALID_EXPANSION`.

---

## 4. Field schema (v1 — exact key list)

```
artifact.algorithm                string
artifact.block_size               int
artifact.byte_digest              hex
artifact.size_bytes               int
expansion.version                 "v1"
frequency.chi_squared_milli       int
frequency.distinct_bytes          int (0..256)
frequency.histogram_digest        hex
frequency.most_common_byte        "0xNN" or ""
frequency.most_common_count       int
frequency.shannon_milli           int
positional.first16                hex (≤32 chars)
positional.last16                 hex (≤32 chars; "" if N<32)
positional.midpoint16             hex (≤32 chars; "" if N<48)
positional.offset_mod16_digest    hex
structural.block_count            int
structural.blocks_digest          hex
structural.longest_run            int
structural.longest_run_byte       "0xNN" or ""
structural.run_count              int
structural.run_length_digest      hex
transition.bigram_entropy_milli   int
transition.distinct_bigrams       int
transition.matrix_digest          hex
transition.most_common_bigram     "0xAABB" or ""
transition.most_common_count      int
wisemark                          hex (256-bit)
```

All hex values are lowercase. All integers are decimal, no leading zeros (except `0` itself). All `0xNN` and `0xAABB` are lowercase hex.

---

## 5. Construction rules (deterministic)

```
1. Parse algorithm and block_size from arguments. block_size MUST be ≥ 1.
2. Compute artifact.byte_digest = digest(M, algorithm).
3. Build frequency.histogram = list of 256 BE64 counts.
4. Walk M to build the bigram counter (N-1 entries; empty if N<2).
5. Walk M to build the run-length list.
6. Split M into blocks of size block_size; digest each; build manifest.
7. Compute aggregate digests: histogram, bigram matrix, runs, blocks, offset_mod16.
8. Compute float-derived fields (shannon_milli, chi_squared_milli, bigram_entropy_milli)
   using IEEE 754 doubles + round-half-even × 1000.
9. Render canonical body sorted by key, EXCLUDING wisemark.
10. wisemark = digest(canonical_body, algorithm).
11. Insert wisemark; render full canonical file.
```

This procedure is purely a function of `(M, algorithm, block_size)`. No system clock, no platform info, no entropy.

---

## 6. Properties

- **Reproducibility.** Byte-identical input + identical parameters → byte-identical `.wiseexp` file. Verified by tests.
- **Layered diff.** A one-byte change in M typically changes `artifact.byte_digest`, `wisemark`, `frequency.histogram_digest`, `transition.matrix_digest`, `structural.run_length_digest`, `structural.blocks_digest`, and `positional.offset_mod16_digest` simultaneously. Aggregate fields like `frequency.distinct_bytes` may stay the same.
- **Self-consistent.** `wisemark` is a digest of all other fields; tampering with any other field invalidates `wisemark`.
- **Algorithm-portable.** Switching `--algorithm` from `WiseDigest-0` to `SHA-256` produces a different but equally valid `.wiseexp` file. Both can be verified by a future `WiseMeasure`.
- **Inspectable without M.** A holder of just the `.wiseexp` file can answer "what's the entropy?", "what's the most common byte?", "how many distinct bigrams?" without ever seeing the artifact.

---

## 7. What is intentionally NOT in v1

- No tree hash. The structural layer uses a flat block manifest digest.
- No N-gram beyond N=2.
- No wavelet / DCT / spectral transforms.
- No language-specific tokenization (UTF-8 normalization is forbidden anyway).
- No floating-point fields exposed directly — only milli-quantized integer scaled values.
- No `WiseMeasure` verifier yet. The compatibility hook is the `wisemark` field.

These are reserved for future versions (`WISEEXP-V2` and beyond) once v1 has been used.

---

## 8. Honest weaknesses

1. **Float-derived integer fields (`shannon_milli`, etc.) are reproducible on CPython but not formally specified at the bit level for cross-language use.** A v2 will pin exact rational arithmetic.
2. **Bigram matrix can be large** for high-entropy inputs — up to 65 536 cells, each 10 bytes serialized. The digest is small but the canonical input to the digest is not.
3. **`positional.first16` / `last16` / `midpoint16` leak raw bytes** of the artifact into the expansion document. For privacy-sensitive use, these would have to be removed or redacted (and that variant would be `WISEEXP-V1-NOLEAK` or similar).
4. **Runtime is O(N) walks plus a Counter over bigrams** — fine for files up to hundreds of MB in pure Python; not engineered for streaming.
5. **The 16 in `offset_mod16_digest` is a chosen constant**. There is no argument that 16 is the right modulus rather than 8 or 32. v1 picks 16 to match the 16-byte slice fields elsewhere; v2 may parameterize it.
