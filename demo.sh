#!/usr/bin/env bash
#
# WISEATA — undeniable demo.
#
# A 1-word change in a contract. SHA-256 says "different." That's all.
# WISEATA shows where the change landed, layer by layer.
#
# Run from the repo root:    bash demo.sh
#

set -euo pipefail

cd "$(dirname "$0")"

# Activate the local venv if available and not already active.
if [[ -z "${VIRTUAL_ENV:-}" && -d .venv ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

A="demo/contract_v1.txt"
B="demo/contract_v2.txt"

if [[ ! -f "$A" || ! -f "$B" ]]; then
  echo "demo files missing: $A and/or $B" >&2
  exit 1
fi

# Pick the right SHA-256 binary for the host.
if command -v sha256sum >/dev/null 2>&1; then
  SHA256_CMD=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  SHA256_CMD=(shasum -a 256)
else
  echo "no sha256sum or shasum on PATH" >&2
  exit 1
fi

if ! command -v wiseata >/dev/null 2>&1; then
  echo "wiseata not on PATH. Run:   pip install -e ." >&2
  exit 1
fi

START=$(date +%s)

echo "============================================================"
echo "  WISEATA — Undeniable Demo"
echo "  Two contracts. One word changed. (\"thousand\" -> \"MILLION\")"
echo "============================================================"
echo

echo "--- STANDARD ---"
echo
echo "  sha256:"
"${SHA256_CMD[@]}" "$A" "$B" | awk '{ printf "    %s  %s\n", $1, $2 }'
echo
echo "  Result: SHA-256 prints two different hex strings."
echo "  That is the entire output. SHA-256 cannot tell you WHERE"
echo "  the change is, WHAT KIND of change it is, or whether the"
echo "  documents share any structure at all."
echo

echo "--- WISEATA ---"
echo
echo "  wiseata expand $A --summary"
echo
wiseata expand "$A" --summary
echo
echo "  wiseata expand $B --summary"
echo
wiseata expand "$B" --summary
echo
echo "  wiseata diff $A $B"
echo
# Diff exits 1 when files differ; capture and continue.
wiseata diff "$A" "$B" || true
echo

END=$(date +%s)
ELAPSED=$(( END - START ))

echo "============================================================"
echo "  What just happened"
echo
echo "  SHA-256 emitted: 2 hex strings. They differ. End of report."
echo
echo "  WISEATA emitted: a six-layer fingerprint of each artifact"
echo "  plus a layer-by-layer diff. From the diff alone you can see:"
echo "    - both files have the same number of bytes (or close to it)"
echo "    - both files use roughly the same byte alphabet"
echo "    - the byte_digest, bigram matrix, run-length structure,"
echo "      block manifest, and wisemark all changed"
echo "    - the entropy and most-common-byte stayed the same"
echo
echo "  Pattern of divergence is consistent with a small word edit,"
echo "  not a wholesale replacement. SHA-256 cannot tell you that."
echo
echo "  Elapsed: ${ELAPSED}s"
echo "============================================================"
