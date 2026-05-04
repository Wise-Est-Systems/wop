#!/usr/bin/env bash
# Launch a cryptanalysis fleet on every authentically-Wise digest.
#
# Focus: only what Henry Wayne Wise III made. SHA-256 is the production
# fallback per SECURITY.md but is not part of the fleet — its 25 years
# of academic cryptanalysis are already on the record. The fleet's cycles
# go entirely to hardening the original Wise digest family.
#
# 4 algorithms × 4 workers each = 16 workers, all running 5s cycles in
# parallel tmux sessions. Each algorithm gets its own state/journal files.
# At the end of any time window, fleet-summary.py shows per-algorithm
# stats so you can see where each candidate stands.
#
# Year-per-week math: 16 workers × 720 cycles/hour ÷ ~7 attacks per algo
# ≈ 240k cycles/week per attack class — equivalent to ~1.1 years of
# single-daemon round-robin runtime per (algorithm, attack) pair.
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

# 4 Wise digests × 4 workers each = 16 workers. Authentically-Wise only.
ALGOS=(
  "WiseDigest-0:WD0"
  "WiseDigest-1:WD1"
  "WiseDigest-2:WD2"
  "WiseDigest-3:WD3"
)
WORKERS_PER_ALGO=4

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

Algorithms attacked in parallel (all original to Henry Wayne Wise III):
  WiseDigest-0   shipped baseline; ASCII-encoded constants WISE-ORIG-IN00-SPAS-TRUE-FAIL-PROF-001
  WiseDigest-1   research candidate; sponge construction, 512-bit state
  WiseDigest-2   research candidate; originality-first, 768-bit state, no borrowed cores
  WiseDigest-3   research candidate; 793-bit live state, 13×61-bit lanes, off-grid

SHA-256 is not part of the fleet — it has 25 years of public cryptanalysis
already. Every fleet cycle hardens the Wise digest family directly.
EOF
    ;;
esac
