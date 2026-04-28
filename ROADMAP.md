# ROADMAP

## v0.1 — Local file and text proof  (current)

- `wise forge` / `wise check` / `wise inspect` / `wise bind` / `wise open`
- `.wiseproof` line-oriented text format (WISEPROOF-V1)
- `.wiseseal` length-prefixed container (WISESEAL-V1)
- `WiseDigest-0` (experimental) and `SHA-256` (production)
- Dual identity: `wise_id` (stable) + `wise_seal` (time-committed)
- 68 tests, hex-locked test vectors, full Python 3.10+ reference impl

Status: shipped.

---

## v0.2 — Directory proof

- `wise forge --dir <path>` produces a manifest of `(relative_path, type, size, digest)` entries
- Lexical byte-order ascending entry order
- Forward-slash paths recorded byte-for-byte from the OS (no Unicode normalization, no case folding)
- Symlinks, sockets, FIFOs, device files: fail-fast with `USER_ERROR` (no silent inclusion)
- Empty directories contribute no manifest entries
- Locked test vectors for at least one nested directory and one Unicode-named directory
- New status: directory-mismatch returns `TAMPERED`; missing path returns `TAMPERED` with the missing path named in `--json` output

Spec touch points: §6.3, §22, §30.13–§30.15.

---

## v0.3 — Stronger seal container

- WISESEAL-V2 with:
  - 8-byte length fields (current is 4-byte / 4 GiB cap)
  - Trailing tail digest covering header + artifact length + artifact + proof length + proof, so a truncated `.wiseseal` is detected at the container level before any verification logic runs
  - Optional `[META]` section for forward-compatible non-normative annotations (still excluded from `wise_id` and `wise_seal`)
- `wise check <seal>` (single-arg) flow: open, verify, return one terminal status
- Streaming `bind`/`check` for files larger than memory

WISESEAL-V1 remains supported and continues to verify; v0.3 verifiers accept both.

---

## v0.4 — Identity / signature layer

- New optional fields:
  - `identity.public_key` (raw hex; algorithm-specific)
  - `identity.algorithm` (e.g. `Ed25519`)
  - `identity.signature` over `wise_seal`
- New status: `UNTRUSTED_ORIGIN` (returned only when a verifier is invoked with a trust policy and the signature does not chain to the policy)
- New CLI flags: `--sign <keyfile>` at forge time; `--require-signature` and `--trust <pubkey-or-fingerprint>` at check time
- A signed proof's `wise_id` is unchanged; the signature commits to `wise_seal` and is itself outside both ids
- This is the first version where `origin.creator` becomes a real attestation rather than a label

Spec touch points: §27.1.

---

## v1.0 — Rust implementation

- `wise` reimplemented as a single static binary (`clap` for CLI, `sha2` for SHA-256, hand-implemented WiseDigest-0 verified against the locked vectors)
- Cross-compile targets: macOS (arm64, x86_64), Linux (x86_64, arm64), Windows (x86_64)
- Identical CLI surface, identical exit codes, identical proof bytes — the Python 0.x line and the Rust 1.x line MUST produce byte-identical proofs and digests for every locked test vector
- Conformance test runner: a vector file format that any implementation in any language can be checked against
- Python implementation continues to ship as a reference; Rust becomes the default install target
- The day a Rust forge produces a proof that a Python check verifies (and vice versa), v1.0 is real

---

## Beyond v1.0 (sketches, not commitments)

- Browser verifier (WASM build of the Rust core, no upload)
- AI output sealing helpers (sealing model outputs at inference time)
- Conformance certification mark for third-party implementations
- Lineage layer (`parent_proof_id`) — track artifact derivation chains
- Policy layer — declarative rules for "this verifier accepts only proofs signed by …"

Each beyond-v1 item earns a version when it lands, not before.
