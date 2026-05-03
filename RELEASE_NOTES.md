# Release Notes

## v0.1.1 — 2026-05-03 — protocol hardening patch

A focused security-hardening release. **No new features. No new digest
candidates. No CLI surface change.** All 208 v0.1.0 tests still pass; 50
new hardening tests added. Total: 258 tests passing on Python 3.10–3.13,
Linux + macOS.

This release responds to an adversarial review (cryptanalyst, parser-exploit,
spec-pedant, supply-chain, integration, side-channel, privacy, and
implementation-differential perspectives). Each change closes a concrete,
named finding.

### Spec changes (live in `spec/WISEATA-v0.1.1.md`)

- **C2** — Values MUST NOT contain any control character (U+0000–U+001F or
  U+007F). Closes ANSI/terminal-escape injection on `wise inspect`.
- **C3** — "Whitespace" in the canonical text rules is defined as **ASCII
  TAB (0x09) or ASCII SPACE (0x20) only.** No Unicode-aware strip.
- **C5** — Keys MUST be sorted in **UTF-8 byte order**, not codepoint order.
- **C7** — A `.wiseproof` MUST NOT begin with the UTF-8 BOM (`EF BB BF`).
  Implementations MUST reject BOM-prefixed input.
- **C6** — Length-field bounds checks in WISESEAL-V1 MUST be performed using
  subtraction (`length > buffer_remaining`), never addition. Mandatory for
  conformant ports on 32-bit targets.
- **H2** — `origin.created_at` MUST match `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`
  AND parse as a real calendar moment.
- **H4** — Unknown top-level keys are not permitted; the closed allow-set
  is normative (see §3.1 / §3.2 of v0.1.1 spec).
- **H1/H5** — `origin.attestation` is a **new required field**. Allowed
  values for v0.1.1: `self_declared`. v0.4 will add `signed`.
  `origin.attestation` is **excluded from `wise_id`** (so artifact identity
  is stable across attestation upgrades) and **included in `wise_seal`**.
- **H1** — `origin.creator` MUST be printable ASCII (U+0020–U+007E),
  excluding `=` and `\n`. Blocks Unicode homoglyph impersonation.

### Implementation changes

- **C1** — All comparisons of recomputed digests against stored proof
  values now use `hmac.compare_digest()`. Closes the "stopwatch" timing
  side-channel: an attacker can no longer leak expected digests one byte
  at a time by measuring verifier latency.
- **C4** — Integer fields (`artifact.size_bytes`) parsed strictly: ASCII
  digits only, no signs, no leading zeros except the single digit `0`.
  Rejects `+5`, `0005`, `５` (FULLWIDTH), `٥` (Arabic-Indic), `-1`.
- **H3** — Hard caps:
  - `.wiseproof` files capped at **1 MiB** at load time. Files exceeding
    the cap are rejected as `INVALID_PROOF` without being read.
  - WISESEAL-V1 embedded proof section also capped at 1 MiB (in both
    `pack` and `unpack`).

### Locked-vector changes

| Field                   | v0.1.0 → v0.1.1 |
|-------------------------|---------|
| `measurement.digest`    | unchanged (it is over artifact bytes, not the body) |
| `wise_id`               | unchanged (`origin.attestation` is excluded from `wise_id`) |
| `wise_seal`             | **changed** (`origin.attestation` is included in `wise_seal`) |

`truth\n` file artifact, `WiseDigest-0`,
`origin.created_at = 2026-04-27T00:00:00Z`,
`origin.creator = Wise.Est Systems`,
`origin.attestation = self_declared`:

```
measurement.digest = 6f9bbc98288bfa8efd7b8ae37c0a0053716bb819688c448d27781a7252fdfd50
wise_id            = 5b0c31df07626993e386434b760539beeb19b9d941c865851a31cd3efa60b091
wise_seal          = c627baaf3cba95f030092ae2b73c9aea26e38b021b0c5327e2c32ad1e9387c57
```

Empty text artifact, same identity inputs:

```
measurement.digest = 2800f3b2e070ed0ce2886ad3a6b5f71cc6182611f9c2e5cfbe57429a0e119d59
wise_id            = df879162047721c0d83d2c53f3a7656b54abdf6085544746bb256fc6e587115e
wise_seal          = 3883f96cf3fffcc4e4542dee8631aab2ef8576e173b6f668734630ea06b9ae45
```

These vectors are normative for the `0.1.1.x` line.

### Compatibility

v0.1.1 is **NOT byte-compatible** with v0.1.0 — the `origin.attestation`
field changes the canonical body, which changes `wise_seal`. v0.1.0 had
zero public adoption; this is the cheapest moment to harden. The earlier
"won't change within 0.1.x" promise from v0.1.0 §9 is reset against this
hardening release; v0.1.1.x is the new locked line.

### Disclosures still in force

- WiseDigest-0 remains EXPERIMENTAL. SHA-256 remains the production
  fallback for adversarial threat models. See `SECURITY.md`.
- `origin.attestation = self_declared` means the `origin.creator` field is
  metadata, not attestation. Until v0.4 ships signatures, anyone can claim
  any creator label.
- WiseExpansion (`.wiseexp`) leaks the first/last/middle 16 bytes of the
  artifact verbatim plus full byte/bigram/run-length structure. **Do not
  generate or share expansions of secret files.**

---

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
