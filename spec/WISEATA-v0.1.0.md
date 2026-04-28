# WISEATA v0.1.0 — Live Specification

**WISEATA** is the deterministic way to process data before it is trusted.

It defines two complementary objects:

1. **A proof** (`.wiseproof`) — a small text record that travels with an artifact so anyone can re-derive its identity offline and confirm the bytes have not changed.
2. **An expansion** (`.wiseexp`) — a structured fingerprint that exposes how the artifact is *shaped*, layer by layer, so two files can be compared structurally rather than just "different / not different."

Both objects are local-first: no servers, no accounts, no platform, no blockchain, no third-party trust.

The single law:

> *An artifact is not accepted as real unless its proof reproduces.*

This document is the normative specification for v0.1.0. The earlier "SPAS" draft (sections 0–30) that this design grew out of is preserved at `spec/archive/SPAS-predecessor-draft.md` for audit only. Where this document and the archive disagree, this document wins.

---

## 1. Status codes

Every verification operation returns exactly one terminal status. There is no "maybe," no confidence score, no AI judgment.

```
VERIFIED              — bytes match the proof
TAMPERED              — bytes diverge (digest or size mismatch)
INVALID_PROOF         — proof is malformed, missing fields, or its body has been altered
UNREADABLE_ARTIFACT   — artifact cannot be read
UNSUPPORTED_ALGORITHM — algorithm not in {WiseDigest-0, SHA-256}
USER_ERROR            — bad CLI invocation
```

Exit codes (CLI):

```
0  VERIFIED or successful create
1  TAMPERED
2  INVALID_PROOF
3  UNREADABLE_ARTIFACT
4  UNSUPPORTED_ALGORITHM
5  USER_ERROR
```

---

## 2. Canonical text formatting (shared by `.wiseproof` and `.wiseexp`)

Both file formats are line-oriented UTF-8 text. The rules are identical:

```
1. UTF-8 only.
2. First line is the format header (e.g. "WISEPROOF-V1\n" or "WISEEXP-V1\n").
3. Exactly one blank line "\n" follows the header.
4. Body lines have the form  key=value\n.
5. No leading or trailing whitespace on any line.
6. No empty lines inside the body.
7. Keys are sorted by pure lexical full-key order (byte order on the dotted key).
8. Values are raw UTF-8 with no escaping; values MUST NOT contain "\n" or "=".
9. The file ends with "\n" after the last body line.
```

Any deviation is `INVALID_PROOF` (for `.wiseproof`) or invalid expansion (for `.wiseexp`).

---

## 3. WISEPROOF-V1 — the proof file

A `.wiseproof` carries integrity and identity information for a single artifact.

### 3.1 Required keys (file artifact)

```
artifact.name            file basename (string)
artifact.size_bytes      non-negative integer
artifact.type            "file"
measurement.algorithm    "WiseDigest-0" | "SHA-256"
measurement.digest       lowercase hex string
origin.created_at        ISO 8601 UTC, "Z" suffix
origin.creator           free-text string (default "Wise.Est Systems")
origin.mode              "local" | "imported"
wise_id                  lowercase hex string (256 bits)
wise_seal                lowercase hex string (256 bits)
```

### 3.2 Required keys (text artifact)

Same as file, plus:

```
artifact.encoding        "utf-8"
```

For text artifacts, `artifact.name` is the empty string `""`.

### 3.3 Identity model — `wise_id` and `wise_seal`

Two identity fields are computed from the canonical body of the proof, restricted to specific key subsets:

```
wise_id   = digest of canonical body EXCLUDING:
              wise_id
              wise_seal
              origin.created_at
              artifact.name

wise_seal = digest of canonical body EXCLUDING:
              wise_seal
            (wise_id, origin.created_at, and artifact.name are INCLUDED)
```

Both digests use the algorithm declared in `measurement.algorithm`.

Consequences:

- Same artifact + same algorithm + same `origin.creator` → **identical `wise_id` on every machine, forever**.
- Different sealing time → identical `wise_id`, different `wise_seal`.
- Tampering with any field that participates in `wise_id` or `wise_seal` invalidates the corresponding identity digest.

`artifact.name` is metadata only. The verifier MUST NOT trust it.

### 3.4 Verification order (the only correct order)

```
1. Read proof bytes                                 → INVALID_PROOF on read failure
2. Parse WISEPROOF-V1 header + canonical format     → INVALID_PROOF
3. Required-keys check                              → INVALID_PROOF
4. measurement.algorithm in {WiseDigest-0, SHA-256} → UNSUPPORTED_ALGORITHM
5. origin.mode in {local, imported}                 → INVALID_PROOF
6. Recompute wise_id; compare                       → INVALID_PROOF
7. Recompute wise_seal; compare                     → INVALID_PROOF
8. Stat artifact size; compare to artifact.size_bytes → TAMPERED  (short-circuit)
9. Open artifact                                    → UNREADABLE_ARTIFACT
10. Recompute artifact digest; compare              → TAMPERED
11. VERIFIED
```

The size check (step 8) short-circuits: if size mismatches, return `TAMPERED` immediately without reading the rest of the artifact.

The proof-id check (steps 6–7) precedes the artifact check (steps 8–10): if the proof itself is corrupt, return `INVALID_PROOF` without ever opening the artifact.

---

## 4. WISESEAL-V1 — the container format

A `.wiseseal` carries an artifact and its proof together byte-for-byte, no compression.

```
header line     "WISESEAL-V1\n"
section tag     "[ARTIFACT]\n"
4 bytes         big-endian uint32 = artifact byte length N
N bytes         raw artifact bytes (no transformation)
section tag     "\n[PROOF]\n"
4 bytes         big-endian uint32 = proof byte length M
M bytes         exact .wiseproof file content
section tag     "\n[END]\n"
```

`wise check` against a `.wiseseal` extracts and verifies in one shot.

---

## 5. WiseDigest-0 — native digest

256-bit deterministic digest. Output is 64 lowercase hex characters.

> **Disclosure.** WiseDigest-0 has not been formally cryptanalyzed. It is included as a native, fully-specified primitive that any implementer can reproduce from this spec. For threat models that require collision resistance against well-funded adversaries, use `--algorithm SHA-256`. See `SECURITY.md`.

### 5.1 Internal state

```
8 unsigned 32-bit words (s0..s7)
```

### 5.2 Initial state

```
s0 = 0x57495345   // "WISE"
s1 = 0x4F524947   // "ORIG"
s2 = 0x494E3030   // "IN00"
s3 = 0x53504153   // "SPAS"
s4 = 0x54525545   // "TRUE"
s5 = 0x4641494C   // "FAIL"
s6 = 0x50524F46   // "PROF"
s7 = 0x30303100   // "001\0"
```

### 5.3 Per-byte absorption

For each byte `b` at index `i` (sequential, starting at 0):

```
j = i mod 8

s[j] = s[j] XOR b
s[j] = ROTL32(s[j], (b mod 31) + 1)
s[j] = (s[j] + 0x9E3779B9 + i) mod 2^32
s[(j+1) mod 8] = s[(j+1) mod 8] XOR s[j]            // s[j] is the just-mutated value
s[(j+3) mod 8] = ROTL32(s[(j+3) mod 8], 7) XOR s[j] // s[j] is the just-mutated value
```

State mutation is sequential within a per-byte round.

### 5.4 Length absorption

After all input bytes, append the input bit-length as 8 bytes big-endian and process them through the same per-byte absorption with `i` continuing sequentially.

### 5.5 Finalization

16 input-free rounds:

```
for round in 0..16:
  for j in 0..7:
    s[j] = s[j] XOR s[(j+1) mod 8]
    s[j] = ROTL32(s[j], 11)
    s[j] = (s[j] + s[(j+5) mod 8] + 0xA5A5A5A5) mod 2^32
```

State mutation is sequential within a finalization round.

### 5.6 Output

```
hex(s0 || s1 || s2 || s3 || s4 || s5 || s6 || s7)
```

64 lowercase hex characters.

---

## 6. SHA-256 — production fallback

Standard NIST FIPS 180-4 SHA-256, accessed via the host platform's standard library. Output is 64 lowercase hex characters. Same proof format and same `wise_id` / `wise_seal` semantics apply.

`SECURITY.md` recommends SHA-256 for any threat model requiring collision resistance.

---

## 7. WISEEXP-V1 — the expansion file

A `.wiseexp` is a structured fingerprint of an artifact. It is **not** a hash and **not** compression. The output is *larger* than the input because it carries six layers of inspectable structure.

A holder of a `.wiseexp` can answer questions like "what's the entropy?", "what's the most common byte?", "how many distinct bigrams?" without ever seeing the artifact.

### 7.1 Required keys

```
expansion.version                 "v1"
artifact.algorithm                "WiseDigest-0" | "SHA-256"
artifact.block_size               int (default 1024)
artifact.byte_digest              hex (full-bytes digest of the artifact)
artifact.size_bytes               non-negative int

positional.first16                hex of bytes [0..16]            (≤32 chars)
positional.last16                 hex of bytes [-16:] or ""       (empty if size < 32)
positional.midpoint16             hex of middle 16 bytes or ""    (empty if size < 48)
positional.offset_mod16_digest    hex (digest of canonical 16-class summary)

frequency.distinct_bytes          int (0..256)
frequency.most_common_byte        "0xNN" or "" (empty if size = 0)
frequency.most_common_count       int
frequency.shannon_milli           int (Shannon entropy in milliBits)
frequency.chi_squared_milli       int (deviation from uniform-on-256, milli-scaled)
frequency.histogram_digest        hex (digest of canonical 256-entry BE64 histogram)

transition.distinct_bigrams       int
transition.most_common_bigram     "0xAABB" or "" (empty if size < 2)
transition.most_common_count      int
transition.bigram_entropy_milli   int
transition.matrix_digest          hex (digest of canonical bigram serialization)

structural.run_count              int (number of maximal runs of repeated bytes)
structural.longest_run            int
structural.longest_run_byte       "0xNN" or ""
structural.run_length_digest      hex
structural.block_count            int (ceil(size / block_size))
structural.blocks_digest          hex (digest of canonical block-digest manifest)

wisemark                          hex (256-bit, digest of canonical body w/o wisemark)
```

### 7.2 The six layers

| Layer | Fields | Question it answers |
|---|---|---|
| **Byte** | `artifact.*` | What's the size? What's the bit-exact identity? |
| **Positional** | `positional.*` | What do the first / last / middle bytes look like? Are there positional patterns? |
| **Frequency** | `frequency.*` | What does the byte distribution look like? Is it text-like, binary-like, random? |
| **Transitions** | `transition.*` | What bigrams are common? Is the data structured or random? |
| **Structural** | `structural.*` | Are there runs? How does it segment into blocks? |
| **WiseMark** | `wisemark` | A self-referential 256-bit digest of all the above (compatibility hook). |

### 7.3 WiseMark — the integrity field

```
wisemark = digest_<algorithm>(canonical body of the .wiseexp file with the
                              wisemark line excluded)
```

Tampering with any other field invalidates `wisemark`. The wisemark is the integrity proof for the expansion document itself, in the same self-referential style as `wise_id` for `.wiseproof`.

### 7.4 Determinism

Byte-identical input + identical parameters (algorithm, block_size) → byte-identical `.wiseexp` file. There is no time, no creator, no system entropy in an expansion.

Float-derived integer fields (`shannon_milli`, `chi_squared_milli`, `bigram_entropy_milli`) are computed using IEEE 754 doubles and round-half-even rounding. They are reproducible across runs on CPython. A future version will pin exact rational arithmetic for cross-language conformance.

---

## 8. CLI surface

### 8.1 `wise` (proofs)

```
wise forge   <file>                       create <file>.wiseproof
wise forge   --text "string" --out p      prove a literal UTF-8 string
wise check   <file>  <proof>              verify a file against a proof
wise check   <proof> --text "string"      verify a string against a proof
wise inspect <proof>                      dump proof contents
wise bind    <file>                       create <file>.wiseseal
wise open    <seal> --out-artifact ... --out-proof ...
wise --version                            print v0.1.0
```

Common flags: `--algorithm {WiseDigest-0,SHA-256}` · `--creator "<name>"` · `--created-at 2026-04-27T00:00:00Z` · `--origin-mode {local,imported}` · `--force` · `--json` · `--quiet`.

### 8.2 `wiseata` (expansions)

```
wiseata expand <file> [--summary]         produce a WiseExpansion
wiseata expand <file> --out p             write canonical .wiseexp to p
wiseata diff   <fileA> <fileB>            compare two artifacts layer by layer
wiseata --version                         print v0.1.0
```

Common flags: `--algorithm {WiseDigest-0,SHA-256}` · `--block-size N` (default 1024).

---

## 9. Versioning

This is `WISEATA v0.1.0`. Locked test vectors in `tests/vectors/` and the locked-vector tests in `tests/test_locked_vectors.py` and `tests/test_wisedigest_*.py` are normative — they will not change within a `0.1.x` release line. Any change that would alter a locked vector requires a new minor version, an entry in `RELEASE_NOTES.md`, and an updated section in `SECURITY.md`.

The roadmap (`ROADMAP.md`) lists planned additions for v0.2 and beyond. Research candidates `WiseDigest-1`, `WiseDigest-2`, `WiseDigest-3` are tracked in `research/` and are NOT part of v0.1.0's normative surface.
