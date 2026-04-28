# SECURITY.md

## What WISEATA is

WISEATA is **structural deterministic processing** of artifacts. It produces:

1. **`.wiseproof`** — a small text proof that travels with an artifact so anyone can re-derive its identity offline and confirm bytes haven't changed.
2. **`.wiseexp`** — a layered structural fingerprint that exposes how the artifact is shaped.

WISEATA is local-first. No servers, no accounts, no platform, no blockchain.

## What WISEATA is NOT

**WISEATA is not a cryptographic security guarantee.** It is structural, deterministic processing. v0.1.0 alone is not appropriate for high-stakes adversarial security. If your threat model includes well-funded adversaries, see "Algorithm choice" below and use `--algorithm SHA-256`.

WISEATA does **not** prove:

- **Truth.** A `.wiseproof` does not say whether an artifact's contents are accurate, ethical, or correct. It says the bytes haven't changed since the proof was forged.
- **Authorship.** `origin.creator` is a free-text label. Anyone can write `origin.creator=Anthropic` in a proof. Until the v0.4 identity/signature layer ships, that field is metadata, not attestation.
- **Origin authenticity.** WISEATA does not verify *who* sealed the artifact.
- **Time.** `origin.created_at` is **declared, not verified**. WISEATA does not consult a time authority. The cryptographic `wise_seal` commits to whatever timestamp the creator chose.
- **Liveness.** A proof from 2026 is still cryptographically valid in 2050; whether the artifact's contents should still be trusted is a policy decision outside the protocol.
- **Confidentiality.** A `.wiseproof` exposes the artifact's size, name, creation time, creator label, algorithm, and digest. A `.wiseseal` carries the artifact in plaintext. A `.wiseexp` exposes byte-distribution statistics, the first/last/middle 16 bytes of the artifact, common bigrams, and run-length structure.

## Algorithm choice — read this before using v0.1.0 in production

WISEATA supports two digest algorithms:

### `WiseDigest-0` (default) — EXPERIMENTAL

`WiseDigest-0` is a 256-bit native digest defined in `spec/WISEATA-v0.1.0.md` §5. **It has not undergone formal cryptanalytic review.** It is included because the WISEATA protocol benefits from a self-contained, fully-specified primitive that any implementer can reproduce from the spec.

Specifically:

- No published collision-resistance analysis.
- No published preimage-resistance analysis.
- No third-party implementations to compare against.
- The construction is small, hand-rolled, and has not been peer-reviewed.

**Do not rely on `WiseDigest-0` for adversarial threat models.**

### `SHA-256` (recommended for production)

`SHA-256` is implemented via the host platform's standard library hash. SHA-256 is a NIST-standardized hash (FIPS 180-4) widely deployed in production systems. Pass `--algorithm SHA-256` at forge time.

The same proof format and the same `wise_id` / `wise_seal` semantics apply with either algorithm.

### Recommendation

> **For any threat model that requires collision resistance against well-funded adversaries, use `--algorithm SHA-256`. Do not use v0.1.0 with `WiseDigest-0` alone for high-stakes security.**

## Research-track digests — also experimental

`WiseDigest-1`, `WiseDigest-2`, and `WiseDigest-3` (in `research/` and `src/wise/digest_v[123].py`) are research candidates. They are NOT wired into the live CLI. They are reachable only by direct import. They have the same disclaimer as `WiseDigest-0`: not formally reviewed. Do not use them in production.

## Attack model — what we expect to detect

| Attack                                      | Status returned   |
|---------------------------------------------|-------------------|
| Single-byte flip in artifact                | `TAMPERED`        |
| Truncation                                  | `TAMPERED`        |
| Extension (extra bytes appended)            | `TAMPERED`        |
| `\n` ↔ `\r\n` newline conversion            | `TAMPERED`        |
| Encoding conversion (UTF-8 ↔ UTF-16, etc.)  | `TAMPERED`        |
| Replacing artifact with a different file    | `TAMPERED`        |
| Editing any field of a `.wiseproof`         | `INVALID_PROOF`   |
| Deleting any required field of a proof      | `INVALID_PROOF`   |
| Reordering keys in a proof                  | `INVALID_PROOF`   |
| Replacing the digest with a re-hashed one   | `INVALID_PROOF` (`wise_id` and `wise_seal` will not reproduce) |
| Mismatched proof and artifact (replay)      | `TAMPERED`        |
| Editing any field of a `.wiseexp`           | `wisemark` mismatch (verified by a future `WiseMeasure`) |

What WISEATA does NOT defend against:

- An attacker who controls **both** the artifact and the proof (they can make a fresh consistent pair anytime — that's why integrity is not authenticity).
- An attacker who replaces the verifier binary on your machine.
- Side-channel attacks on the hash implementation.
- Filesystem-level corruption that flips bytes in both files identically.

## Reporting a vulnerability

If you find a flaw in the protocol, the spec, the reference implementation, or the locked test vectors:

1. Open a GitHub issue at `https://github.com/Wise-Est-Systems/wop/issues` for non-sensitive bugs and protocol questions.
2. For anything that could let an attacker forge a `VERIFIED` outcome on a divergent artifact, **do not open a public issue.** Use a private GitHub Security Advisory (`Security` tab → `Advisories` → `Report a vulnerability`).
3. Include: WISEATA version (`wise --version`), OS / Python version, minimal reproducer (artifact bytes in hex, the `.wiseproof` content, the command run), and your impact assessment.

We will acknowledge within 7 days. Default coordinated disclosure timeline is 90 days from acknowledgment.

## Versioning and breaking changes

Locked test vectors in `tests/test_locked_vectors.py` and `tests/test_wisedigest_*.py` are normative. They will not change within a `0.1.x` release line. Any change that would alter a locked vector requires a new minor version, an entry in `RELEASE_NOTES.md`, and an updated section in this file.
