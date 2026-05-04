#!/usr/bin/env python3
"""Aggregate stats across the Wise-digest cryptanalysis fleet.

Reads every research/state-{TAG}-W*.json file. Groups by algorithm tag.
Prints per-algorithm summary and per-(algorithm, attack) breakdown so you
can see at a glance where each candidate stands.

The fleet attacks only authentically-Wise digests (WD-0/1/2/3). SHA-256
is not in the fleet — its public cryptanalysis is a separate concern.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESEARCH = REPO_ROOT / "research"

# Order to display algorithms (matches the family lineage).
ALGO_ORDER = ["WD0", "WD1", "WD2", "WD3"]


def main() -> int:
    states = sorted(RESEARCH.glob("state-*-W*.json"))
    if not states:
        print("no worker state files found in research/")
        print("   start a fleet first: bash scripts/launch-fleet.sh start")
        return 1

    # Group by algorithm tag.
    by_algo: dict = defaultdict(lambda: {
        "workers": 0,
        "cycles": 0,
        "anomalies": 0,
        "runtime": 0.0,
        "by_attack": defaultdict(lambda: {"cycles": 0, "anomalies": 0, "samples": 0}),
    })

    for sp in states:
        # Parse name: state-WD0-W00.json -> tag=WD0, wid=00
        stem = sp.stem  # "state-WD0-W00"
        parts = stem.split("-")
        if len(parts) < 3:
            continue
        tag = parts[1]
        try:
            s = json.loads(sp.read_text())
        except Exception as e:
            print(f"  could not parse {sp.name}: {e}")
            continue
        bucket = by_algo[tag]
        bucket["workers"] += 1
        bucket["cycles"] += s.get("cycles_completed", 0)
        bucket["anomalies"] += s.get("anomalies_logged", 0)
        bucket["runtime"] += s.get("total_runtime_seconds", 0.0)
        for atk_name, atk_stats in s.get("by_attack", {}).items():
            t = bucket["by_attack"][atk_name]
            t["cycles"] += atk_stats.get("cycles", 0)
            t["anomalies"] += atk_stats.get("anomalies", 0)
            t["samples"] += atk_stats.get("total_samples", 0)

    # Print per-algorithm summary.
    print("Wise digest cryptanalysis fleet — summary")
    print("=" * 76)
    print(f"{'algo':6s} {'workers':>8s} {'cycles':>10s} {'anomalies':>10s} "
          f"{'runtime':>10s} {'samples':>16s}")
    print("-" * 76)

    grand_cycles = 0
    grand_anomalies = 0
    grand_samples = 0
    grand_runtime = 0.0
    for tag in ALGO_ORDER + sorted(set(by_algo) - set(ALGO_ORDER)):
        if tag not in by_algo:
            continue
        b = by_algo[tag]
        total_samples = sum(a["samples"] for a in b["by_attack"].values())
        print(f"{tag:6s} {b['workers']:>8d} {b['cycles']:>10,} {b['anomalies']:>10d} "
              f"{b['runtime']/3600:>9.1f}h {total_samples:>16,}")
        grand_cycles += b["cycles"]
        grand_anomalies += b["anomalies"]
        grand_samples += total_samples
        grand_runtime += b["runtime"]
    print("-" * 76)
    print(f"{'TOTAL':6s} {' ':>8} {grand_cycles:>10,} {grand_anomalies:>10d} "
          f"{grand_runtime/3600:>9.1f}h {grand_samples:>16,}")

    # Per-(algorithm, attack) breakdown.
    print()
    print("Per-attack breakdown")
    print("=" * 76)
    all_attacks = set()
    for b in by_algo.values():
        all_attacks.update(b["by_attack"].keys())

    print(f"{'attack':<20s}", end="")
    for tag in ALGO_ORDER:
        if tag in by_algo:
            print(f"{tag:>14s}", end="")
    print()
    print("-" * 76)
    for atk in sorted(all_attacks):
        print(f"{atk:<20s}", end="")
        for tag in ALGO_ORDER:
            if tag not in by_algo:
                continue
            t = by_algo[tag]["by_attack"].get(atk, {"cycles": 0, "anomalies": 0})
            cell = f"{t['cycles']}c/{t['anomalies']}a"
            print(f"{cell:>14s}", end="")
        print()

    print()
    if grand_anomalies:
        print(f"⚠️  {grand_anomalies} anomalies. Inspect:")
        for sp in states:
            jp = sp.parent / sp.name.replace("state-", "journal-").replace(".json", ".md")
            print(f"     grep -A 30 ANOMALY {jp.relative_to(REPO_ROOT)}")
    else:
        print("No anomalies in any worker, any algorithm. The Wise digest family holds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
