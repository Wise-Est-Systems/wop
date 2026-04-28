# WISEATA

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
