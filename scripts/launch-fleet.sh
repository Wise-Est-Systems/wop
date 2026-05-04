#!/usr/bin/env bash
# Launch a cryptanalysis fleet on truly-novel Wise digests.
#
# No tmux dependency. Uses `nohup` + `nice -n 19` so workers run in the
# background at lowest priority. On Apple Silicon, low-priority work
# preferentially lands on efficiency cores; performance cores stay free
# for Henry's interactive work.
#
# Worker count auto-detects from `sysctl -n hw.ncpu`, defaulting to
# (cores - 2). Override with `FLEET_TOTAL=N`.
#
# Strict originality rule: a digest gets fleet cycles only if it borrows
# NO pre-existing cryptographic primitive — no SHA family, no BLAKE,
# no ChaCha, no Keccak, no IV constants from existing designs. Universal
# primitives (integer add, XOR, rotation) don't count as borrowed.
#
# By that rule:
#   IN  — WiseDigest-2 (originality-first, 768-bit state)
#   IN  — WiseDigest-3 (originality-first, 793-bit prime-based state)
#   OUT — WiseDigest-0 (uses Knuth's 0x9E3779B9 golden-ratio multiplier)
#   OUT — WiseDigest-1 (uses BLAKE2b IV and G function)
#   OUT — SHA-256 (not Henry's; already 25 years of public cryptanalysis)
#
# Year-per-week math: 8 workers × 720 cycles/hour ÷ 6 attacks per algo
# ≈ 240k cycles/week per (algorithm, attack) pair.

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
PYTHON="${PYTHON:-$REPO_ROOT/.venv/bin/python}"
RUNTIME_DIR="${WD_FLEET_RUNTIME:-/tmp/wd-fleet}"

ALGOS=(
  "WiseDigest-2:WD2"
  "WiseDigest-3:WD3"
)

# Auto-size to the machine.
DETECTED_CORES=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
DEFAULT_TOTAL=$(( DETECTED_CORES > 4 ? DETECTED_CORES - 2 : 2 ))
TOTAL_WORKERS="${FLEET_TOTAL:-$DEFAULT_TOTAL}"
WORKERS_PER_ALGO=$(( TOTAL_WORKERS / ${#ALGOS[@]} ))
[[ "$WORKERS_PER_ALGO" -lt 1 ]] && WORKERS_PER_ALGO=1

mkdir -p "$RUNTIME_DIR"

# All worker names this fleet definition would produce.
all_worker_names() {
  for entry in "${ALGOS[@]}"; do
    local tag="${entry##*:}"
    for ((wid=0; wid<WORKERS_PER_ALGO; wid++)); do
      printf 'wd-%s-W%02d\n' "$tag" "$wid"
    done
  done
}

# Is the worker named $1 currently running? (PID file exists and points to a live process.)
is_running() {
  local name="$1"
  local pid_file="$RUNTIME_DIR/${name}.pid"
  [[ -f "$pid_file" ]] || return 1
  local pid
  pid=$(<"$pid_file")
  [[ -n "$pid" ]] || return 1
  ps -p "$pid" -o pid= >/dev/null 2>&1
}

cmd="${1:-help}"

case "$cmd" in
  start)
    echo "Fleet sizing for this machine:"
    echo "  detected logical cores: $DETECTED_CORES"
    echo "  workers (cores - 2):    $TOTAL_WORKERS  (override with FLEET_TOTAL=N)"
    echo "  per-algorithm:          $WORKERS_PER_ALGO  (across ${#ALGOS[@]} truly-novel digests)"
    echo "  priority:               nice -n 19 (yields to interactive work)"
    echo "  runtime dir:            $RUNTIME_DIR"
    echo
    spawned=0
    for entry in "${ALGOS[@]}"; do
      algo="${entry%%:*}"
      tag="${entry##*:}"
      for ((wid=0; wid<WORKERS_PER_ALGO; wid++)); do
        name="wd-${tag}-W$(printf '%02d' "$wid")"
        pid_file="$RUNTIME_DIR/${name}.pid"
        log_file="$RUNTIME_DIR/${name}.log"
        if is_running "$name"; then
          echo "  $name already running (pid $(<"$pid_file")) — skipping"
          continue
        fi
        # Detached, low-priority, logs to file. Process group setsid lets
        # us send SIGINT cleanly to the worker without touching this shell.
        nohup nice -n 19 "$PYTHON" "$REPO_ROOT/scripts/cryptanalysis-daemon.py" \
          --worker-id "$wid" --algorithm "$algo" --budget-seconds 5 \
          >"$log_file" 2>&1 &
        echo $! > "$pid_file"
        disown 2>/dev/null || true
        echo "  spawned $name  pid=$(<"$pid_file")  algorithm=$algo  log=$log_file"
        spawned=$((spawned+1))
      done
    done
    echo
    echo "Fleet up: $spawned new workers."
    echo "  status:   bash scripts/launch-fleet.sh status"
    echo "  peek:     bash scripts/launch-fleet.sh tail WD2 0"
    echo "  stop:     bash scripts/launch-fleet.sh stop"
    ;;
  status)
    echo "Wise digest cryptanalysis fleet"
    echo "================================"
    running=0
    dead=0
    while IFS= read -r name; do
      if is_running "$name"; then
        printf "  %-18s  pid=%-8s  RUNNING\n" "$name" "$(<"$RUNTIME_DIR/${name}.pid")"
        running=$((running+1))
      else
        printf "  %-18s  pid=%-8s  not running\n" "$name" "$(cat "$RUNTIME_DIR/${name}.pid" 2>/dev/null || echo "-")"
        dead=$((dead+1))
      fi
    done < <(all_worker_names)
    echo
    echo "  $running running, $dead not running"
    echo
    if ls "$REPO_ROOT/research/state-"*.json >/dev/null 2>&1; then
      $PYTHON "$REPO_ROOT/scripts/fleet-summary.py"
    else
      echo "  (no state files yet — workers may not have completed a cycle)"
    fi
    ;;
  stop)
    echo "Stopping fleet (SIGINT — clean checkpoint)..."
    stopped=0
    while IFS= read -r name; do
      pid_file="$RUNTIME_DIR/${name}.pid"
      [[ -f "$pid_file" ]] || continue
      pid=$(<"$pid_file")
      if ps -p "$pid" -o pid= >/dev/null 2>&1; then
        kill -SIGINT "$pid" 2>/dev/null && echo "  SIGINT -> $name (pid $pid)" && stopped=$((stopped+1))
      fi
    done < <(all_worker_names)
    sleep 3
    # Anything still alive after 3s gets a SIGTERM.
    while IFS= read -r name; do
      pid_file="$RUNTIME_DIR/${name}.pid"
      [[ -f "$pid_file" ]] || continue
      pid=$(<"$pid_file")
      if ps -p "$pid" -o pid= >/dev/null 2>&1; then
        kill -SIGTERM "$pid" 2>/dev/null && echo "  SIGTERM -> $name (pid $pid)"
      fi
      rm -f "$pid_file"
    done < <(all_worker_names)
    echo
    echo "Stopped $stopped workers. State preserved in research/. Logs in $RUNTIME_DIR/."
    ;;
  tail)
    tag="${2:-WD2}"
    n="${3:-0}"
    name="wd-${tag}-W$(printf '%02d' "$n")"
    log_file="$RUNTIME_DIR/${name}.log"
    if [[ ! -f "$log_file" ]]; then
      echo "no log for $name (expected at $log_file)"
      exit 1
    fi
    tail -n 30 "$log_file"
    ;;
  logs)
    echo "Recent log lines from every worker:"
    while IFS= read -r name; do
      log_file="$RUNTIME_DIR/${name}.log"
      [[ -f "$log_file" ]] || continue
      echo "--- $name ---"
      tail -n 3 "$log_file"
    done < <(all_worker_names)
    ;;
  *)
    cat <<EOF
Wise digest cryptanalysis fleet — truly-Henry-only, Mac-friendly
Usage:
  bash scripts/launch-fleet.sh start             # spawn ${#ALGOS[@]}×${WORKERS_PER_ALGO} workers via nohup
  bash scripts/launch-fleet.sh status            # show all workers + per-algo stats
  bash scripts/launch-fleet.sh stop              # SIGINT all workers; clean checkpoint
  bash scripts/launch-fleet.sh tail TAG N        # peek (TAG=WD2|WD3)
  bash scripts/launch-fleet.sh logs              # last 3 lines from every worker

Algorithms attacked (truly-novel-to-Henry-only, no borrowed primitives):
  WiseDigest-2   originality-first; 768-bit state, no SHA/BLAKE/ChaCha/Keccak cores,
                 no borrowed constants. Wise-native ASCII only.
  WiseDigest-3   793-bit live state (13×61, both prime); off-grid by construction.
                 Same originality rule, even stricter.

EXCLUDED from the fleet (because they reuse pre-existing primitives):
  WiseDigest-0   borrows Knuth's 0x9E3779B9 (golden-ratio multiplier)
  WiseDigest-1   borrows BLAKE2b's IV and G function
  SHA-256        not Henry's; has 25 years of public cryptanalysis already

Workers run at nice -n 19. On Apple Silicon they preferentially land on
efficiency cores, leaving performance cores for normal Mac use.
EOF
    ;;
esac
