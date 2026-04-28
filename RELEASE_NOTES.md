# Release Notes

## v0.1.0 — 2026-04-27

First public release of WISEATA — the deterministic way to process data before it is trusted.

### What's in it

- **`wise` CLI** — `forge`, `check`, `inspect`, `bind`, `open`. Produces `.wiseproof` text files and `.wiseseal` containers for any artifact (file or text).
- **`wiseata` CLI** — `expand`, `diff`. Produces `.wiseexp` structural fingerprints and compares two artifacts layer by layer.
- **`.wiseproof`** — line-oriented WISEPROOF-V1 text format. Pure lexical full-key sort. UTF-8. Strict canonical formatting; any deviation is `INVALID_PROOF`.
- **`.wiseseal`** — length-prefixed binary WISESEAL-V1 container holding the artifact and its proof byte-for-byte, no compression.
- **`.wiseexp`** — line-oriented WISEEXP-V1 expansion file with six layers of inspectable structure (byte, positional, frequency, transition, structural, WiseMark).
- **`WiseExpansion`** — a fourth artifact-derived category alongside hashes, compression, and content-addressable storage. Output is *larger* than the input and exposes how the bytes are shaped.
- **`WiseDigest-0`** — the native experimental digest (256-bit, length-absorbed, sequential mutation).
- **SHA-256 fallback** — pass `--algorithm SHA-256` for production threat models.
- **Dual identity** in proofs: `wise_id` (stable across machines, time, and filenames) and `wise_seal` (commits to `wise_id` + time).
- **Six terminal statuses** — `VERIFIED`, `TAMPERED`, `INVALID_PROOF`, `UNREADABLE_ARTIFACT`, `UNSUPPORTED_ALGORITHM`, `USER_ERROR` — each with a fixed exit code. No "maybe."
- **`demo.sh`** — under-30-second end-to-end demo: SHA-256 vs WISEATA on two contracts that differ by one word.
- **`--version`** on both CLIs.

### Research tracks (NOT part of normative v0.1.0)

These live in `research/` and `src/wise/digest_v[123].py` for analysis. They are reachable only by direct import. None are wired into the live CLIs.

- **`WiseDigest-1`** — sponge construction over 8 × 64-bit lanes with a borrowed BLAKE2b G mixing primitive. 12 rounds.
- **`WiseDigest-2`** — original positional accumulator with state-driven head walk over 12 × 64-bit lanes. 24 finalization rounds.
- **`WiseDigest-3`** — 793-bit live state (13 × 61-bit lanes, top 3 bits dead and explicitly masked) with non-linear multiplicative output extraction. 25 finalization rounds.
- Each candidate has its own normative spec, locked test vectors, and an attack suite. Promotion gates are documented in `research/WiseDigest-Lab.md`.

### Specification

The live spec is `spec/WISEATA-v0.1.0.md`. The earlier SPAS predecessor draft is preserved under `spec/archive/SPAS-predecessor-draft.md` for audit only.

### Locked vectors (v0.1.0)

`truth\n` file artifact, `WiseDigest-0`, `origin.created_at = 2026-04-27T00:00:00Z`, `origin.creator = Wise.Est Systems`:

```
measurement.digest = 6f9bbc98288bfa8efd7b8ae37c0a0053716bb819688c448d27781a7252fdfd50
wise_id            = 5b0c31df07626993e386434b760539beeb19b9d941c865851a31cd3efa60b091
wise_seal          = 5e9a0ddd0e23a9393302ae6c39e2f31692b597aabad4b89482d1483765dfa564
```

These vectors will not change within the `0.1.x` line.

### Tested on

- macOS arm64, Python 3.14
- 208 tests passing in ~15 s
- CI: `.github/workflows/test.yml` runs `pytest -q` on `ubuntu-latest` and `macos-latest` × Python 3.10, 3.11, 3.12, 3.13

### Known limitations

- **`WiseDigest-0` is experimental.** It has not undergone formal cryptanalytic review. For threat models requiring collision resistance, pass `--algorithm SHA-256`. See `SECURITY.md`.
- **`origin.creator` is a free-text label** until the v0.4 signature/identity layer ships. Anyone can write any value in `origin.creator`.
- **`origin.created_at` is declared, not verified.** WISEATA does not consult a time authority.
- **No directory artifacts** in v0.1.0 (planned for v0.2). Only file and text.
- **WISESEAL-V1 caps both artifact and proof at 4 GiB** each (32-bit length fields). v0.3 lifts this.
- **No streaming `bind` / `check`.** `wise bind` reads the whole artifact into memory.
- **No `WiseMeasure` verifier yet** for `.wiseexp` files. The `wisemark` field is the compatibility hook.
- **WiseExpansion float-derived integer fields** (`shannon_milli`, etc.) are deterministic on CPython but not yet bit-pinned for cross-language conformance.
- **No third-party implementation** of any spec yet. Spec ambiguities will not surface until a second author writes a conformant implementation.
- **No Rust port** yet. v1.0 calls for one with byte-identical conformance to every locked vector.

### Predecessor

The earlier SPAS draft (JSON-based proofs, `.spas.json` files) lives under `archive/spas/` for audit. It is no longer installed and no longer part of the live CLI surface.

### Repo

- `https://github.com/Wise-Est-Systems/wop`
