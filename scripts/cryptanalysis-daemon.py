#!/usr/bin/env python3
"""WiseDigest-0 — cryptanalysis worker (formerly "daemon").

Designed to run as a worker in a fleet. Each worker has its own seed
space, optionally specializes in one attack class, and writes to its
own state/journal files (no lock contention with sibling workers).

Year-per-week math: with 16 workers at 5s/cycle, two per attack class,
each attack class accumulates ~240K cycles/week — equivalent to ~1.1
years of single-daemon-at-30s round-robin runtime.

Usage:
    # Single worker, all attacks, default 5s cycles:
    python scripts/cryptanalysis-daemon.py

    # Fleet member: worker 7 specializing in cube attack only, 5s cycles:
    python scripts/cryptanalysis-daemon.py --worker-id 7 --attacks cube --budget-seconds 5

    # Use scripts/launch-fleet.sh to start a 16-worker fleet in tmux.

Per-worker output files:
    research/state-W{ID}.json   — restart-safe state
    research/journal-W{ID}.md   — dated log; anomalies fully logged,
                                  clean cycles sampled at 1/50

Stop conditions:
    SIGINT (Ctrl-C) / SIGTERM   — checkpoint cleanly, exit
    --stop-after N              — run N cycles then stop

Attacks available (--attacks filter, comma-separated, or "all"):
    birthday_partial      birthday partial-collision search
    avalanche_sample      sample-based avalanche bias check
    higher_order_diff     d-th order differential, d=2..5
    random_pair           random-pair output Hamming distance
    linear_search         random single-bit linear approximation search
    cube                  cube/integral attack on small input cubes
    reduced_round         reduced-round collision search

The daemon's job is to produce data, not to make a security claim.
A clean run is evidence; it is not a proof. SHA-256 remains the
production-grade fallback for adversarial threats.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import signal
import statistics
import struct
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

import hashlib  # noqa: E402

from wise.digest import digest_bytes as _wd0_digest, _rotl32, _MASK32, _GOLDEN, _FINAL_CONST, _INITIAL_STATE  # noqa: E402
from wise.digest_v1 import digest_bytes as _wd1_digest  # noqa: E402
from wise.digest_v2 import digest_bytes as _wd2_digest  # noqa: E402
from wise.digest_v3 import digest_bytes as _wd3_digest  # noqa: E402

DEFAULT_BUDGET_SECONDS_PER_CYCLE = 5  # 720 cycles/hour per worker

# All algorithms the fleet attacks. The unified hash() function dispatches.
SUPPORTED_ALGORITHMS = ("WiseDigest-0", "WiseDigest-1", "WiseDigest-2",
                        "WiseDigest-3", "SHA-256")


def hash_bytes(data: bytes, algorithm: str) -> bytes:
    """Unified hash function: dispatch by algorithm name, return raw bytes."""
    if algorithm == "WiseDigest-0":
        return bytes.fromhex(_wd0_digest(data, "WiseDigest-0"))
    if algorithm == "WiseDigest-1":
        return bytes.fromhex(_wd1_digest(data))
    if algorithm == "WiseDigest-2":
        return bytes.fromhex(_wd2_digest(data))
    if algorithm == "WiseDigest-3":
        return bytes.fromhex(_wd3_digest(data))
    if algorithm == "SHA-256":
        return hashlib.sha256(data).digest()
    raise ValueError(f"unknown algorithm: {algorithm}")


# Backwards-compat shim used by attack functions.
_CURRENT_ALGORITHM = {"name": "WiseDigest-0"}  # set by main()


def wd0(d: bytes) -> bytes:
    """Hash with the worker's currently-configured algorithm.
    (Misnomer kept for code minimality; renames would touch every attack.)"""
    return hash_bytes(d, _CURRENT_ALGORITHM["name"])


def hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# =============================================================================
# Reduced-round WD-0 (for margin attacks)
# =============================================================================


def wd0_reduced(data: bytes, finalize_rounds: int) -> bytes:
    """WD-0 with the finalize stage truncated to `finalize_rounds` rounds.

    Full WD-0 has 16 finalize rounds. Reduced versions show whether
    collisions are findable when the cipher's margin is shaved.
    """
    state = list(_INITIAL_STATE)
    i = 0
    for b in data:
        j = i & 7
        sj = (state[j] ^ b) & _MASK32
        sj = _rotl32(sj, (b % 31) + 1)
        sj = (sj + _GOLDEN + i) & _MASK32
        state[j] = sj
        j1 = (j + 1) & 7
        state[j1] = (state[j1] ^ sj) & _MASK32
        j3 = (j + 3) & 7
        state[j3] = (_rotl32(state[j3], 7) ^ sj) & _MASK32
        i += 1

    bit_length = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    for b in bit_length.to_bytes(8, "big"):
        j = i & 7
        sj = (state[j] ^ b) & _MASK32
        sj = _rotl32(sj, (b % 31) + 1)
        sj = (sj + _GOLDEN + i) & _MASK32
        state[j] = sj
        j1 = (j + 1) & 7
        state[j1] = (state[j1] ^ sj) & _MASK32
        j3 = (j + 3) & 7
        state[j3] = (_rotl32(state[j3], 7) ^ sj) & _MASK32
        i += 1

    for _ in range(finalize_rounds):
        for j in range(8):
            state[j] = (state[j] ^ state[(j + 1) & 7]) & _MASK32
            state[j] = _rotl32(state[j], 11)
            state[j] = (state[j] + state[(j + 5) & 7] + _FINAL_CONST) & _MASK32

    return b"".join(w.to_bytes(4, "big") for w in state)


# =============================================================================
# Attacks
# =============================================================================


def attack_birthday_partial(rng: random.Random, budget: float) -> dict:
    prefix_bits = rng.choice([16, 20, 24, 28])
    seen: dict = {}
    n_trials = 0
    n_hits = 0
    deadline = time.time() + budget
    while time.time() < deadline:
        msg = struct.pack(">QQ", rng.getrandbits(64), rng.getrandbits(64))
        d = wd0(msg)
        n_bytes = (prefix_bits + 7) // 8
        key = d[:n_bytes]
        if prefix_bits % 8:
            mask = 0xFF & (0xFF << (8 - (prefix_bits % 8)))
            key = key[:-1] + bytes([key[-1] & mask])
        if key in seen:
            n_hits += 1
        else:
            seen[key] = msg
        n_trials += 1
    expected = n_trials * n_trials / (2 * (1 << prefix_bits))
    return {
        "attack": "birthday_partial",
        "prefix_bits": prefix_bits,
        "n_trials": n_trials,
        "hits_found": n_hits,
        "hits_expected_random": round(expected, 2),
        "ratio": round(n_hits / max(expected, 0.01), 3),
        "anomaly": n_hits > 5 * expected + 10 or n_hits < 0.2 * expected - 10,
    }


def attack_avalanche_sample(rng: random.Random, budget: float) -> dict:
    msg_len = rng.choice([8, 16, 32, 64])
    distances = []
    deadline = time.time() + budget
    while time.time() < deadline:
        msg = bytes(rng.randint(0, 255) for _ in range(msg_len))
        base = wd0(msg)
        for bit in range(msg_len * 8):
            mut = bytearray(msg)
            mut[bit // 8] ^= 1 << (bit % 8)
            distances.append(hamming(base, wd0(bytes(mut))))
    mean = statistics.mean(distances) if distances else 0
    sigma = statistics.stdev(distances) if len(distances) > 1 else 0
    return {
        "attack": "avalanche_sample",
        "msg_len": msg_len,
        "n_measurements": len(distances),
        "mean_hamming": round(mean, 3),
        "stdev": round(sigma, 3),
        "min": min(distances) if distances else 0,
        "max": max(distances) if distances else 0,
        "anomaly": mean < 110 or mean > 146 or (
            distances and (min(distances) < 32 or max(distances) > 224)
        ),
    }


def attack_higher_order_diff(rng: random.Random, budget: float) -> dict:
    d = rng.choice([2, 3, 4, 5])
    msg_len = 16
    bits_set = []
    deadline = time.time() + budget
    while time.time() < deadline:
        base = bytes(rng.randint(0, 255) for _ in range(msg_len))
        deltas = [
            bytes(rng.randint(0, 255) for _ in range(msg_len))
            for _ in range(d + 1)
        ]
        xor_sum = bytes(32)
        for mask in range(1 << (d + 1)):
            m = bytearray(base)
            for k in range(d + 1):
                if (mask >> k) & 1:
                    for i in range(msg_len):
                        m[i] ^= deltas[k][i]
            out = wd0(bytes(m))
            xor_sum = bytes(a ^ b for a, b in zip(xor_sum, out))
        bits_set.append(sum(bin(b).count("1") for b in xor_sum))
    mean = statistics.mean(bits_set) if bits_set else 0
    return {
        "attack": "higher_order_diff",
        "order": d,
        "samples": len(bits_set),
        "mean_bits_set": round(mean, 2),
        "stdev": round(statistics.stdev(bits_set) if len(bits_set) > 1 else 0, 2),
        "anomaly": abs(mean - 128) > 20 if bits_set else False,
    }


def attack_random_pair(rng: random.Random, budget: float) -> dict:
    distances = []
    deadline = time.time() + budget
    while time.time() < deadline:
        a = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 200)))
        b = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 200)))
        distances.append(hamming(wd0(a), wd0(b)))
    mean = statistics.mean(distances) if distances else 0
    return {
        "attack": "random_pair",
        "n_pairs": len(distances),
        "mean_hamming": round(mean, 3),
        "stdev": round(statistics.stdev(distances) if len(distances) > 1 else 0, 3),
        "anomaly": abs(mean - 128) > 6 if distances else False,
    }


def attack_linear_search(rng: random.Random, budget: float) -> dict:
    best_bias = 0.0
    best_pair = None
    n_trials = 0
    deadline = time.time() + budget
    n_messages = 1024
    while time.time() < deadline:
        msg_len = rng.choice([8, 16, 32])
        alpha = (rng.randint(0, msg_len - 1), rng.randint(0, 7))
        beta = (rng.randint(0, 31), rng.randint(0, 7))
        agree = 0
        for _ in range(n_messages):
            m = bytes(rng.randint(0, 255) for _ in range(msg_len))
            d = wd0(m)
            in_bit = (m[alpha[0]] >> alpha[1]) & 1
            out_bit = (d[beta[0]] >> beta[1]) & 1
            if in_bit == out_bit:
                agree += 1
        bias = abs(agree / n_messages - 0.5)
        if bias > best_bias:
            best_bias = bias
            best_pair = (alpha, beta)
        n_trials += 1
    return {
        "attack": "linear_search",
        "n_pairs_tried": n_trials,
        "best_bias_observed": round(best_bias, 4),
        "best_pair": str(best_pair) if best_pair else None,
        "anomaly": best_bias > 0.10,
    }


def attack_cube(rng: random.Random, budget: float) -> dict:
    """Cube/integral attack: pick a small set of input bits to "cube over."

    For each value of the cube-bits (2^k values), hash the resulting message
    and XOR all 2^k outputs together. For a function of algebraic degree < k,
    the XOR-sum is identically zero (the d-th derivative of a degree-d
    polynomial is constant; the (d+1)-th is zero).

    For random function, XOR-sum has ~128 bits set.
    Bias toward zero = degree-collapsing structure = real break.
    """
    cube_size = rng.choice([4, 5, 6, 7, 8])  # 2^4..2^8 hashes per cube
    msg_len = rng.choice([8, 16, 32])
    n_cubes = 0
    bits_set_list = []
    deadline = time.time() + budget
    while time.time() < deadline:
        # Random base message
        base = bytearray(rng.randint(0, 255) for _ in range(msg_len))
        # Pick which input bits form the cube
        cube_bits = sorted(rng.sample(range(msg_len * 8), cube_size))
        # XOR-sum over all 2^cube_size variations
        xor_sum = bytes(32)
        for v in range(1 << cube_size):
            m = bytearray(base)
            for k, bit_pos in enumerate(cube_bits):
                if (v >> k) & 1:
                    m[bit_pos // 8] ^= 1 << (bit_pos % 8)
                else:
                    m[bit_pos // 8] &= ~(1 << (bit_pos % 8)) & 0xFF
                # actually we want to set the bit to (v >> k) & 1, so:
                # clear, then set to v's bit
                pass
            # Build properly: bits_pos = (v >> k) & 1 for each cube bit
            for k, bit_pos in enumerate(cube_bits):
                want = (v >> k) & 1
                cur = (m[bit_pos // 8] >> (bit_pos % 8)) & 1
                if want != cur:
                    m[bit_pos // 8] ^= 1 << (bit_pos % 8)
            out = wd0(bytes(m))
            xor_sum = bytes(a ^ b for a, b in zip(xor_sum, out))
        bits = sum(bin(b).count("1") for b in xor_sum)
        bits_set_list.append(bits)
        n_cubes += 1
    mean = statistics.mean(bits_set_list) if bits_set_list else 0
    sigma = statistics.stdev(bits_set_list) if len(bits_set_list) > 1 else 0
    return {
        "attack": "cube",
        "cube_size": cube_size,
        "msg_len": msg_len,
        "n_cubes": n_cubes,
        "mean_bits_set_in_xor_sum": round(mean, 2),
        "stdev": round(sigma, 2),
        # If cube_size < algebraic_degree, mean ~= 128. If cube_size >= degree,
        # mean -> 0. Anomaly if bits-set drops far below 100 or rises above 156.
        "anomaly": bool(bits_set_list and (mean < 90 or mean > 166)),
    }


def attack_reduced_round(rng: random.Random, budget: float) -> dict:
    """Try to find collisions on REDUCED-round WD-0 (margin attack).

    Full WD-0 has 16 finalize rounds. We hash with R=2,4,8 finalize rounds
    and look for partial-output collisions. If R=2 has easy collisions,
    the design margin is tight and a real cryptanalyst would push for fewer.

    For 256-bit output, even reduced-round birthday is 2^128 - well out of
    reach. We look for 32-bit prefix collisions, which is ~2^16 work for ideal
    and should still be ~2^16 even reduced. Significant deviation = margin issue.
    """
    rounds = rng.choice([2, 4, 8, 12])
    prefix_bits = 32
    seen: dict = {}
    n_trials = 0
    n_hits = 0
    deadline = time.time() + budget
    while time.time() < deadline:
        msg = struct.pack(">QQ", rng.getrandbits(64), rng.getrandbits(64))
        d = wd0_reduced(msg, rounds)
        key = d[:4]  # 32-bit prefix
        if key in seen:
            n_hits += 1
        else:
            seen[key] = msg
        n_trials += 1
    expected = n_trials * n_trials / (2 * (1 << prefix_bits))
    return {
        "attack": "reduced_round",
        "finalize_rounds": rounds,
        "prefix_bits": prefix_bits,
        "n_trials": n_trials,
        "hits_found": n_hits,
        "hits_expected_random": round(expected, 2),
        "ratio": round(n_hits / max(expected, 0.01), 3),
        # Anomaly: significantly more hits than birthday expects
        "anomaly": n_hits > 3 * expected + 5,
    }


# =============================================================================
# Worker plumbing
# =============================================================================


ALL_ATTACKS = {
    "birthday_partial":  attack_birthday_partial,
    "avalanche_sample":  attack_avalanche_sample,
    "higher_order_diff": attack_higher_order_diff,
    "random_pair":       attack_random_pair,
    "linear_search":     attack_linear_search,
    "cube":              attack_cube,
    "reduced_round":     attack_reduced_round,
}


def _algo_tag(algorithm: str) -> str:
    """Short tag for filenames: WD0, WD1, WD2, WD3, SHA256."""
    return {
        "WiseDigest-0": "WD0",
        "WiseDigest-1": "WD1",
        "WiseDigest-2": "WD2",
        "WiseDigest-3": "WD3",
        "SHA-256":      "SHA256",
    }[algorithm]


def _worker_paths(worker_id: int, algorithm: str) -> tuple[Path, Path]:
    tag = _algo_tag(algorithm)
    state = REPO_ROOT / "research" / f"state-{tag}-W{worker_id:02d}.json"
    journal = REPO_ROOT / "research" / f"journal-{tag}-W{worker_id:02d}.md"
    return state, journal


def load_state(state_path: Path) -> dict:
    if state_path.exists():
        return json.loads(state_path.read_text())
    return {
        "started_at": now_iso(),
        "last_run_at": None,
        "total_runtime_seconds": 0.0,
        "cycles_completed": 0,
        "anomalies_logged": 0,
        "by_attack": {},
    }


def save_state(state_path: Path, state: dict) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2) + "\n")


def append_journal(journal_path: Path, line: str, worker_id: int) -> None:
    journal_path.parent.mkdir(parents=True, exist_ok=True)
    if not journal_path.exists():
        journal_path.write_text(
            f"# WiseDigest-0 — Cryptanalysis Worker W{worker_id:02d}\n\n"
            "Append-only journal. Anomalies are flagged with `⚠️`.\n\n---\n\n"
        )
    with open(journal_path, "a") as f:
        f.write(line)


def update_attack_stats(state: dict, name: str, result: dict) -> None:
    s = state["by_attack"].setdefault(
        name,
        {"cycles": 0, "anomalies": 0, "total_samples": 0},
    )
    s["cycles"] += 1
    if result.get("anomaly"):
        s["anomalies"] += 1
    n_samples = (
        result.get("n_trials")
        or result.get("n_measurements")
        or result.get("n_pairs")
        or result.get("samples")
        or result.get("n_pairs_tried")
        or result.get("n_cubes")
        or 0
    )
    s["total_samples"] += n_samples


_should_stop = False


def _handle_signal(signum, frame):
    global _should_stop
    _should_stop = True
    print(f"\n[worker] received signal {signum}, will checkpoint and exit...")


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--worker-id", type=int, default=0)
    p.add_argument("--algorithm", type=str, default="WiseDigest-0",
                   choices=SUPPORTED_ALGORITHMS,
                   help="which hash to attack")
    p.add_argument("--attacks", type=str, default="all",
                   help="comma-separated subset of attack names, or 'all'")
    p.add_argument("--budget-seconds", type=float, default=DEFAULT_BUDGET_SECONDS_PER_CYCLE)
    p.add_argument("--stop-after", type=int, default=None)
    args = p.parse_args(argv)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # Set the worker's algorithm globally so attack functions hash with it.
    _CURRENT_ALGORITHM["name"] = args.algorithm

    if args.attacks == "all":
        attack_names = list(ALL_ATTACKS.keys())
        # reduced_round only applies to WiseDigest-0 (it's a margin attack)
        if args.algorithm != "WiseDigest-0" and "reduced_round" in attack_names:
            attack_names.remove("reduced_round")
    else:
        attack_names = [n.strip() for n in args.attacks.split(",") if n.strip()]
        for n in attack_names:
            if n not in ALL_ATTACKS:
                print(f"unknown attack: {n}. valid: {list(ALL_ATTACKS.keys())}", file=sys.stderr)
                return 2

    state_path, journal_path = _worker_paths(args.worker_id, args.algorithm)
    state = load_state(state_path)
    state["algorithm"] = args.algorithm
    tag = _algo_tag(args.algorithm)
    print(f"[{tag}-W{args.worker_id:02d}] starting; cycles={state['cycles_completed']}, "
          f"anomalies={state['anomalies_logged']}, attacks={attack_names}")

    append_journal(
        journal_path,
        f"## resume @ {now_iso()}\n"
        f"- worker_id: {args.worker_id}\n"
        f"- algorithm: {args.algorithm}\n"
        f"- attacks: {attack_names}\n"
        f"- budget: {args.budget_seconds}s/cycle\n"
        f"- previous cycles: {state['cycles_completed']}\n\n",
        args.worker_id,
    )

    cycles_this_run = 0
    while not _should_stop:
        if args.stop_after and cycles_this_run >= args.stop_after:
            break

        cycle_no = state["cycles_completed"] + 1
        # Seed includes worker id so different workers explore independently.
        seed = (0xC0DE_C0DE * (args.worker_id + 1)) ^ cycle_no
        rng = random.Random(seed)
        name = attack_names[cycle_no % len(attack_names)]
        fn = ALL_ATTACKS[name]

        t0 = time.time()
        try:
            result = fn(rng, args.budget_seconds)
        except Exception as e:
            result = {"attack": name, "error": repr(e), "anomaly": True}
        elapsed = time.time() - t0

        anomaly = result.get("anomaly")
        marker = "⚠️ " if anomaly else "  "
        line = (
            f"### cycle {cycle_no:06d} @ {now_iso()} ({elapsed:.1f}s) — {name}\n"
            f"```json\n{json.dumps(result, indent=2)}\n```\n\n"
        )
        if anomaly:
            line = f"## {marker} ANOMALY — cycle {cycle_no}\n\n" + line
            state["anomalies_logged"] += 1
            append_journal(journal_path, line, args.worker_id)
        else:
            if cycle_no % 50 == 0 or cycle_no <= 3:
                append_journal(journal_path, line, args.worker_id)

        state["cycles_completed"] += 1
        state["last_run_at"] = now_iso()
        state["total_runtime_seconds"] += elapsed
        update_attack_stats(state, name, result)
        save_state(state_path, state)

        cycles_this_run += 1
        if cycle_no % 20 == 0:
            print(
                f"[{tag}-W{args.worker_id:02d}] cycle {cycle_no:06d}  {name:18s}  "
                f"{marker}  runtime={state['total_runtime_seconds']/3600:.1f}h  "
                f"anomalies={state['anomalies_logged']}"
            )

    save_state(state_path, state)
    append_journal(
        journal_path,
        f"## stopped @ {now_iso()}\n"
        f"- total cycles: {state['cycles_completed']}\n"
        f"- total runtime: {state['total_runtime_seconds']/3600:.2f}h\n"
        f"- total anomalies: {state['anomalies_logged']}\n\n---\n\n",
        args.worker_id,
    )
    print(f"[{tag}-W{args.worker_id:02d}] stopped cleanly. cycles={state['cycles_completed']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
