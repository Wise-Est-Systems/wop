"""WISEATA CLI — `wiseata expand` and `wiseata diff`."""

from __future__ import annotations

import argparse
import os
import sys

from wise.expansion import (
    DEFAULT_ALGORITHM,
    DEFAULT_BLOCK_SIZE,
    expand,
    render,
)

from . import __version__


SUPPORTED_ALGORITHMS = ("WiseDigest-0", "SHA-256")


def _read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _expand_file(path: str, algorithm: str, block_size: int) -> dict[str, str]:
    return expand(_read_file(path), algorithm=algorithm, block_size=block_size)


# ---------------------------------------------------------------------------
# expand
# ---------------------------------------------------------------------------

def _print_summary(items: dict[str, str], path: str) -> None:
    name = os.path.basename(path)
    print(f"  artifact:                    {name}")
    print(f"  size_bytes:                  {items['artifact.size_bytes']}")
    print(f"  byte_digest:                 {items['artifact.byte_digest'][:16]}…")
    print(f"  distinct_bytes:              {items['frequency.distinct_bytes']}")
    print(f"  most_common_byte:            {items['frequency.most_common_byte']}  "
          f"({items['frequency.most_common_count']} occurrences)")
    sh = int(items["frequency.shannon_milli"])
    print(f"  shannon_entropy:             {sh / 1000:.3f} bits")
    print(f"  distinct_bigrams:            {items['transition.distinct_bigrams']}")
    print(f"  most_common_bigram:          {items['transition.most_common_bigram']}  "
          f"({items['transition.most_common_count']} occurrences)")
    print(f"  run_count:                   {items['structural.run_count']}")
    print(f"  longest_run:                 {items['structural.longest_run']} "
          f"(byte {items['structural.longest_run_byte']})")
    print(f"  block_count:                 {items['structural.block_count']}")
    print(f"  wisemark:                    {items['wisemark']}")


def _cmd_expand(args: argparse.Namespace) -> int:
    if not os.path.isfile(args.path):
        sys.stderr.write(f"USER_ERROR: not a regular file: {args.path}\n")
        return 2
    items = _expand_file(args.path, args.algorithm, args.block_size)
    if args.summary:
        _print_summary(items, args.path)
        return 0
    raw = render(items)
    if args.out:
        if os.path.exists(args.out) and not args.force:
            sys.stderr.write(f"USER_ERROR: output exists: {args.out}. Pass --force.\n")
            return 2
        with open(args.out, "wb") as f:
            f.write(raw)
        sys.stdout.write(f"WISEEXP_CREATED {args.out}\n")
        sys.stdout.write(f"  wisemark {items['wisemark']}\n")
        return 0
    sys.stdout.buffer.write(raw)
    return 0


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------

_LAYER_PREFIXES: tuple[tuple[str, str], ...] = (
    ("artifact.", "byte"),
    ("positional.", "positional"),
    ("frequency.", "frequency"),
    ("transition.", "transition"),
    ("structural.", "structural"),
    ("wisemark", "wisemark"),
)

_DIFF_IGNORE = frozenset({
    "expansion.version",
    "artifact.algorithm",
    "artifact.block_size",
})


def _layer_of(key: str) -> str:
    for prefix, name in _LAYER_PREFIXES:
        if key.startswith(prefix):
            return name
    return "other"


def _short(value: str, width: int = 16) -> str:
    if value == "":
        return "(empty)"
    if len(value) > width and all(c in "0123456789abcdef" for c in value):
        return value[: max(8, width - 1)] + "…"
    if len(value) > width:
        return value[: width - 1] + "…"
    return value


def _cmd_diff(args: argparse.Namespace) -> int:
    for p in (args.file_a, args.file_b):
        if not os.path.isfile(p):
            sys.stderr.write(f"USER_ERROR: not a regular file: {p}\n")
            return 2
    a_items = _expand_file(args.file_a, args.algorithm, args.block_size)
    b_items = _expand_file(args.file_b, args.algorithm, args.block_size)

    a_name = os.path.basename(args.file_a)
    b_name = os.path.basename(args.file_b)

    print(f"  comparing: {a_name}  vs  {b_name}")
    print()

    field_w = 36
    val_w = 18
    header = f"  {'field':{field_w}}  {a_name[:val_w]:{val_w}}  {b_name[:val_w]:{val_w}}  status"
    print(header)
    print("  " + "-" * (len(header) - 2))

    diff_count = 0
    same_count = 0
    layer_diff: dict[str, list[int]] = {}  # name -> [diff, total]

    keys = sorted((set(a_items) | set(b_items)) - _DIFF_IGNORE)
    for k in keys:
        a_v = a_items.get(k, "")
        b_v = b_items.get(k, "")
        layer = _layer_of(k)
        layer_diff.setdefault(layer, [0, 0])
        layer_diff[layer][1] += 1
        if a_v == b_v:
            same_count += 1
            marker = "  "
            status = "(same)"
        else:
            diff_count += 1
            layer_diff[layer][0] += 1
            marker = "* "
            status = "DIFFERS"
        print(f"{marker}{k:{field_w}}  {_short(a_v, val_w):{val_w}}  {_short(b_v, val_w):{val_w}}  {status}")

    # Numerical deltas worth surfacing.
    print()
    print("  Numerical deltas:")
    for k, label in (
        ("artifact.size_bytes", "size_bytes"),
        ("frequency.distinct_bytes", "distinct_bytes"),
        ("frequency.shannon_milli", "shannon_milli"),
        ("frequency.chi_squared_milli", "chi_squared_milli"),
        ("transition.distinct_bigrams", "distinct_bigrams"),
        ("transition.bigram_entropy_milli", "bigram_entropy_milli"),
        ("structural.run_count", "run_count"),
        ("structural.longest_run", "longest_run"),
        ("structural.block_count", "block_count"),
    ):
        try:
            av = int(a_items[k])
            bv = int(b_items[k])
        except (KeyError, ValueError):
            continue
        delta = bv - av
        sign = "+" if delta > 0 else ""
        marker = "  " if delta == 0 else "Δ "
        print(f"  {marker}{label:32} {av:>10}  →  {bv:<10}  ({sign}{delta})")

    # Layer-level summary.
    print()
    print("  Layer summary:")
    layer_order = ["byte", "positional", "frequency", "transition", "structural", "wisemark"]
    for layer in layer_order:
        if layer not in layer_diff:
            continue
        d, t = layer_diff[layer]
        bar = "DIFFERS" if d == t else ("partial" if d > 0 else "same")
        print(f"    {layer:14} {d}/{t} fields differ   [{bar}]")

    print()
    print(f"  Summary: {diff_count} fields differ, {same_count} identical")

    return 0 if diff_count == 0 else 1


# ---------------------------------------------------------------------------
# top-level
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wiseata",
        description="WISEATA — expansion-based artifact measurement",
    )
    p.add_argument("--version", action="version", version=f"wiseata {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("expand", aliases=["expansion"], help="produce a WiseExpansion of an artifact")
    pe.add_argument("path", help="path to the artifact")
    pe.add_argument("--out", default=None, help="write canonical .wiseexp to this path")
    pe.add_argument("--summary", action="store_true", help="human-readable summary instead of full canonical output")
    pe.add_argument("--algorithm", default=DEFAULT_ALGORITHM, choices=SUPPORTED_ALGORITHMS)
    pe.add_argument("--block-size", type=int, default=DEFAULT_BLOCK_SIZE)
    pe.add_argument("--force", action="store_true", help="overwrite existing --out file")

    pd = sub.add_parser("diff", help="compare two artifacts via their expansions")
    pd.add_argument("file_a")
    pd.add_argument("file_b")
    pd.add_argument("--algorithm", default=DEFAULT_ALGORITHM, choices=SUPPORTED_ALGORITHMS)
    pd.add_argument("--block-size", type=int, default=DEFAULT_BLOCK_SIZE)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.cmd in ("expand", "expansion"):
        return _cmd_expand(args)
    if args.cmd == "diff":
        return _cmd_diff(args)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    sys.exit(main())
