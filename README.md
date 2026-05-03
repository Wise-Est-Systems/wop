# WISEATA

[![CI](https://github.com/Wise-Est-Systems/wop/actions/workflows/test.yml/badge.svg)](https://github.com/Wise-Est-Systems/wop/actions/workflows/test.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue.svg)](pyproject.toml)
[![Spec](https://img.shields.io/badge/spec-WISEATA--v0.1.1-green.svg)](spec/WISEATA-v0.1.1.md)

**WISEATA is the deterministic way to process data before it is trusted.**

Two contracts. One word changed (`thousand` → `MILLION`).

```
SHA-256 says:
  b807ee5d4894...  contract_v1.txt
  665c30ec25f7...  contract_v2.txt
                                    Different. End of report.

WISEATA says:
  byte         2/2 differ   [DIFFERS]
  positional   1/4 differ   [partial]    ← first/last/middle slices identical
  frequency    4/6 differ   [partial]    ← entropy +0.109 bits, +5 distinct bytes
  transition   3/5 differ   [partial]    ← bigram matrix shifted, top bigram unchanged
  structural   3/6 differ   [partial]    ← run-length pattern moved by 2 runs
  wisemark     1/1 differ   [DIFFERS]
                                    A small word edit. Not a rewrite.
```

WISEATA produces two complementary objects from any artifact:

1. A **proof** (`.wiseproof`) — anyone can re-derive the artifact's identity offline and confirm bytes haven't changed.
2. An **expansion** (`.wiseexp`) — a layered structural fingerprint that exposes *how* the artifact is shaped, so two files can be compared meaningfully — not just "different."

Local-first. No accounts. No servers. No platform. No blockchain.

---

## What `.wiseexp` does that nothing else does

Most tools answer one question: *"are these two files different?"* — yes or no.

A WiseExpansion answers *how* they differ, layer by layer:

| Layer | Question it answers |
|---|---|
| **Byte**       | What's the size? What's the bit-exact identity? |
| **Positional** | What do the first / last / middle bytes look like? Are there positional patterns? |
| **Frequency**  | What does the byte distribution look like? Is it text-like, binary-like, random? |
| **Transitions** | Which bigrams are common? Is the data structured or random? |
| **Structural** | Are there runs? How does it segment into blocks? |
| **WiseMark**   | A self-referential 256-bit digest of all the above. |

A `.wiseexp` is **not a hash and not compression** — it is *larger* than the
input. The point is to expose structure cheaply enough to inspect without ever
opening the original artifact. Two files differing by one word produce two
expansions that can be diffed at every layer to show *where* the change
landed (entropy shift, bigram changes, run-length pattern movement) — not
just that bytes diverge.

To my knowledge, this is a primitive without a direct precedent. The closest
neighbors are forensic similarity hashes (ssdeep, sdhash, TLSH) which produce
opaque single-output fingerprints; `.wiseexp` exposes *named, separately
inspectable, deterministically reproducible* layers.

If you can think of prior art for the layered explainable approach, please
open an issue — I want to know.

> **Disclaimer.** `WiseDigest-0`, the native digest used by default, is **experimental** and has **not been formally cryptanalyzed**. For threat models that require collision resistance against well-funded adversaries, pass `--algorithm SHA-256`. See [`SECURITY.md`](SECURITY.md). Do not use v0.1.0 alone for high-stakes adversarial security.

---

## Install (under 1 minute)

Requires Python 3.10+.

```bash
git clone https://github.com/Wise-Est-Systems/wop.git
cd wop
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

Two CLIs land on your `PATH`: `wise` and `wiseata`.

---

## See it work (under 30 seconds)

```bash
bash demo.sh
```

The demo creates two contracts differing in one word, runs SHA-256 against both, then runs `wiseata expand` and `wiseata diff`. You'll see the difference in what they tell you.

---

## Try it on your own files (under 2 minutes)

**Verify a file:**

```bash
printf 'truth\n' > demo.txt

wise forge demo.txt
# → demo.txt.wiseproof

wise check demo.txt demo.txt.wiseproof
# → VERIFIED   (exit 0)

printf 'changed\n' > demo.txt
wise check demo.txt demo.txt.wiseproof
# → TAMPERED   (exit 1)
```

**Compare two files structurally:**

```bash
wiseata expand somefile.pdf --summary
wiseata diff fileA fileB
```

---

## Status codes

```
VERIFIED              0   bytes match the proof
TAMPERED              1   bytes diverge (digest or size mismatch)
INVALID_PROOF         2   proof malformed, missing fields, or body altered
UNREADABLE_ARTIFACT   3   artifact cannot be read
UNSUPPORTED_ALGORITHM 4   algorithm not in {WiseDigest-0, SHA-256}
USER_ERROR            5   bad CLI invocation
```

No "maybe." No confidence score.

---

## What `wise_id` and `wise_seal` are

Every `.wiseproof` carries two identity fields:

| Field       | What it commits to                                                                                       |
|-------------|----------------------------------------------------------------------------------------------------------|
| `wise_id`   | Stable across machines, time, and filenames. Same artifact + same algorithm + same `creator` → same `wise_id`. |
| `wise_seal` | Commits to `wise_id` plus the sealing time. Different sealing time → different `wise_seal`.              |

A proof has its own reproducible name. That's the wedge.

---

## What this is not

WISEATA proves **integrity**, **identity**, and **reproducibility**. It does **not** prove truth, authorship, or origin authenticity. See [`SECURITY.md`](SECURITY.md).

---

## FAQ

**Is this a blockchain?**
No. WISEATA is local-first and stateless. There is no chain, no network, no
consensus, no token, no fees, no online lookup. A proof is a small text file
that verifies offline against the artifact, by anyone, forever.

**How is this different from C2PA?**
C2PA is a media-provenance standard built by a multi-corporation consortium
(Adobe, Microsoft, BBC, Intel, etc.) and targets images and video specifically.
WISEATA is general-purpose (any file or text), local-first only, and currently
solo work. C2PA has industry backing; WISEATA has a spec, an attack suite, and
a public repo. Different scopes. They could coexist — a file could carry both.

**Why a custom hash function?**
WiseDigest-0 is included so the protocol has a *fully self-specified* primitive
any implementer can reproduce from the spec without an external dependency. It
is **experimental and not formally cryptanalyzed.** SHA-256 is the production
fallback for adversarial threat models — pass `--algorithm SHA-256`. See
[`SECURITY.md`](SECURITY.md) for the honest disclosure.

**Why not just SHA-256 plus a JSON file?**
The dual-identity model. `wise_id` is computed over the proof body *excluding*
time and name, so the same artifact produces the same `wise_id` everywhere,
forever. `wise_seal` includes time, so it identifies a specific sealing event.
A plain SHA-256-of-bytes can't answer "is this the same artifact" and "when was
this sealed" in the same proof. See spec §3.3.

**Is `WiseDigest-0` safe to use?**
For non-adversarial integrity (corruption detection, dedup, content
addressing), yes. For adversarial threats (a determined attacker forging a
collision), no — use `--algorithm SHA-256`. The disclosure is in
[`SECURITY.md`](SECURITY.md) and is not optional.

**How is this different from Sigstore?**
Sigstore is for code-supply-chain provenance, requires signatures, and is
backed by a transparency log. WISEATA v0.1.0 is integrity-only — no
signatures, no log, no online component. Identity/signature is on the v0.4
roadmap. The two systems address different layers and could compose.

**Can I write a port in another language?**
Yes — that is one of the explicit asks. The spec is normative, the test
vectors in [`tests/vectors/V1_demo_truth.md`](tests/vectors/V1_demo_truth.md)
are language-neutral byte-level outputs, and the locked vectors in
`tests/test_locked_vectors.py` and `tests/test_wisedigest_*.py` are the
conformance suite. If your implementation produces byte-identical outputs for
every locked vector, it is conformant. Open an issue with the language and
repo URL — we will list it.

**Who built this?**
One person, on nights and weekends. No CS degree, self-taught. The credentials
this work carries are the ones in the code itself: a locked spec, locked test
vectors, an attack suite, honest disclosures, and a public repo.

---

## Contributing

Short version:

```bash
git clone https://github.com/Wise-Est-Systems/wop.git
cd wop && python3 -m venv .venv && source .venv/bin/activate
pip install -e . pytest
pytest -q
```

What is welcome:

- **Spec issues** — anywhere the spec is unclear, ambiguous, or contradicts
  itself, open an issue. Cite the section.
- **Independent implementations** — Rust, Go, JavaScript, Swift, anything. The
  locked test vectors are your conformance target. Byte-identical outputs for
  every vector = conformant. Open an issue with your repo and we will list it.
- **Attacks on WiseDigest-0/1/2/3** — extend
  [`tests/test_wisedigest_attack_suite.py`](tests/test_wisedigest_attack_suite.py)
  or its v2/v3 siblings. A failing attack is a real result; a research-track
  digest that gets broken gets retired. See
  [`research/WiseDigest-Lab.md`](research/WiseDigest-Lab.md) for the journal.
- **Format clarifications** — if writing a port surfaces an ambiguity in
  WISEPROOF-V1, WISESEAL-V1, or WISEEXP-V1, that is a real spec bug. Open an
  issue.

What requires extra care:

- **Changes to the canonical text format, the dual-identity model, or any
  locked test vector** require a new minor version of the spec, an entry in
  [`RELEASE_NOTES.md`](RELEASE_NOTES.md), and an updated section in
  [`SECURITY.md`](SECURITY.md). The 0.1.x line is normative.
- **Security-relevant findings** (forging a `VERIFIED` outcome on a divergent
  artifact) — do **not** open a public issue. Use
  [`Security` → `Advisories` → `Report a vulnerability`](https://github.com/Wise-Est-Systems/wop/security/advisories/new).
  See [`SECURITY.md`](SECURITY.md).

---

## Project layout

```
spec/WISEATA-v0.1.0.md          ← live normative specification (start here)
spec/archive/                    ← predecessor (SPAS) draft, kept for audit
src/wise/                        ← wise CLI (proofs)
src/wiseata/                     ← wiseata CLI (expansions)
research/                        ← experimental WiseDigest-1/2/3 + WiseExpansion notes
demo.sh                          ← one-second WISEATA demo
demo/                            ← sample contracts for the demo
tests/                           ← 208 tests, all passing on Python 3.10–3.13
.github/workflows/test.yml       ← CI: pytest on Linux + macOS, py 3.10–3.13
SECURITY.md                      ← honest threat model + disclosure
ROADMAP.md                       ← v0.1 → v1.0
RELEASE_NOTES.md                 ← v0.1.0
LICENSE                          ← Apache-2.0
```

Run the test suite:

```bash
pip install pytest
pytest -q
```

---

## License

Apache License 2.0. See [`LICENSE`](LICENSE).

— Wise.Est Systems
