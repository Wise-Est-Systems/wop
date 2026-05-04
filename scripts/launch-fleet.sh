#!/usr/bin/env bash
# Launch a cryptanalysis fleet on truly-novel Wise digests.
#
# Strict originality rule: a digest gets fleet cycles only if it borrows
# NO pre-existing cryptographic primitive — no SHA family, no BLAKE,
# no ChaCha, no Keccak, no Merkle-Damgård composition, no IV constants
# from existing designs (sqrt-of-primes, golden ratio, etc.). Universal
# primitives (integer add, XOR, rotation) don't count as borrowed.
#
# By that rule:
#   IN  — WiseDigest-2 (originality-first, 768-bit state)
#   IN  — WiseDigest-3 (originality-first, 793-bit prime-based state)
#   OUT — WiseDigest-0 (uses Knuth's 0x9E3779B9 golden-ratio multiplier)
#   OUT — WiseDigest-1 (uses BLAKE2b IV and G function)
#   OUT — SHA-256 (not Henry's; already 25 years of public cryptanalysis)
#
# 2 truly-novel digests × 8 workers each = 16 workers. Twice the
# cryptanalytic pressure per algorithm vs the previous 4-algo fleet.
#
# Year-per-week math: 16 workers × 720 cycles/hour ÷ 6 attacks per algo
# ≈ 480k cycles/week per (algorithm, attack) pair — roughly 2 yrs/week
# of single-daemon round-robin runtime, concentrated on what is truly Wise.
#
# Usage:
#   bash scripts/launch-fleet.sh start      # spawn the fleet
#   bash scripts/launch-fleet.sh status     # show all workers + per-algo stats
#   bash scripts/launch-fleet.sh stop       # SIGINT all workers; clean checkpoint
#   bash scripts/launch-fleet.sh tail TAG N # peek worker N (TAG=WD0|WD1|WD2|WD3|SHA256)

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
PYTHON="${PYTHON:-$REPO_ROOT/.venv/bin/python}"

# Truly-novel-only fleet: 2 Wise digests × 8 workers each = 16 workers.
#
# WiseDigest-0 and WiseDigest-1 are EXCLUDED from the fleet:
#   WD-0 borrows Knuth's golden-ratio multiplier (0x9E3779B9), used in
#        jhash and FNV variants. Not original.
#   WD-1 borrows BLAKE2b's IV (sqrt of primes) AND the BLAKE2b G mixing
#        function verbatim. Not original.
#
# WiseDigest-2 and WiseDigest-3 are originality-first by design — their
# specs explicitly forbid SHA/BLAKE/ChaCha/Keccak cores and borrowed
# constants. Only addition, XOR, rotation, and Wise-native ASCII
# constants. These are the truly-novel ones; they get the cycles.
ALGOS=(
  "WiseDigest-2:WD2"
  "WiseDigest-3:WD3"
)
WORKERS_PER_ALGO=8

cmd="${1:-help}"

case "$cmd" in
  start)
    total=0
    for entry in "${ALGOS[@]}"; do
      algo="${entry%%:*}"
      tag="${entry##*:}"
      for ((wid=0; wid<WORKERS_PER_ALGO; wid++)); do
        session="wd-${tag}-W$(printf '%02d' "$wid")"
        if tmux has-session -t "$session" 2>/dev/null; then
          echo "  $session already running — skipping"
          continue
        fi
        tmux new-session -d -s "$session" \
          "cd $REPO_ROOT && $PYTHON scripts/cryptanalysis-daemon.py \
            --worker-id $wid --algorithm '$algo' --budget-seconds 5"
        echo "  spawned $session  (algorithm: $algo)"
        total=$((total+1))
      done
    done
    echo
    echo "Fleet up: $total workers, ${#ALGOS[@]} algorithms × $WORKERS_PER_ALGO workers."
    echo "Use 'bash scripts/launch-fleet.sh status' to peek."
    ;;
  status)
    echo "Wise digest cryptanalysis fleet"
    echo "================================"
    tmux list-sessions 2>/dev/null | grep '^wd-' || echo "no workers running"
    echo
    if ls "$REPO_ROOT/research/state-"*.json >/dev/null 2>&1; then
      $PYTHON "$REPO_ROOT/scripts/fleet-summary.py"
    fi
    ;;
  stop)
    echo "Stopping fleet (SIGINT to each worker; clean checkpoint)..."
    while IFS= read -r session; do
      tmux send-keys -t "$session" C-c
      echo "  sent SIGINT to $session"
    done < <(tmux list-sessions 2>/dev/null | grep '^wd-' | cut -d: -f1)
    sleep 2
    while IFS= read -r session; do
      tmux kill-session -t "$session" 2>/dev/null || true
    done < <(tmux list-sessions 2>/dev/null | grep '^wd-' | cut -d: -f1)
    echo "Fleet stopped. State files preserved in research/"
    ;;
  tail)
    tag="${2:-WD0}"
    n="${3:-0}"
    session="wd-${tag}-W$(printf '%02d' "$n")"
    if tmux has-session -t "$session" 2>/dev/null; then
      tmux capture-pane -t "$session" -p | tail -30
    else
      echo "no worker $session running"
    fi
    ;;
  *)
    cat <<EOF
Wise digest cryptanalysis fleet — authentically-Wise only
Usage:
  bash scripts/launch-fleet.sh start             # spawn ${#ALGOS[@]}×${WORKERS_PER_ALGO} workers
  bash scripts/launch-fleet.sh status            # show all workers + per-algo stats
  bash scripts/launch-fleet.sh stop              # checkpoint and stop fleet
  bash scripts/launch-fleet.sh tail TAG N        # peek (TAG=WD0|WD1|WD2|WD3)

Algorithms attacked (truly-novel-to-Henry-only, no borrowed primitives):
  WiseDigest-2   originality-first; 768-bit state, no SHA/BLAKE/ChaCha/Keccak cores,
                 no borrowed constants. Wise-native ASCII only.
  WiseDigest-3   793-bit live state (13×61, both prime); off-grid by construction.
                 Same originality rule, even stricter.

EXCLUDED from the fleet (because they reuse pre-existing primitives):
  WiseDigest-0   borrows Knuth's 0x9E3779B9 (golden-ratio multiplier)
  WiseDigest-1   borrows BLAKE2b's IV and G function
  SHA-256        not Henry's; has 25 years of public cryptanalysis already

Every fleet cycle hardens what's truly novel and truly Henry's.
EOF
    ;;
esac
