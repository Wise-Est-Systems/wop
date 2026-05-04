#!/usr/bin/env python3
"""Seal a release of WOP using WISEATA's own primitives.

Cryptawiselization applied to the protocol's own source: the system that
witnesses every other artifact, witnesses itself.

Walks the repo (using `git ls-files`), computes WiseDigest-0 for every
tracked file, emits a sorted manifest, then seals the manifest with
build_file_proof_items() — the same code path any normal user invokes.

Usage:
    python scripts/seal-release.py <version-tag>
    python scripts/seal-release.py v0.1.1

Produces:
    release-<version>.manifest          — sorted "<digest>  <path>" lines
    release-<version>.manifest.wiseproof — WISEATA proof of the manifest

To verify a release that someone else publishes:
    1. Clone the repo at the released tag.
    2. python scripts/seal-release.py <version> --verify
       (regenerates the manifest, compares to the released one)
    3. wise check release-<version>.manifest release-<version>.manifest.wiseproof

Same code path everyone else uses. No special vendor escape hatch.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from wise.digest import digest_bytes  # noqa: E402
from wise.proof import build_file_proof_items, render  # noqa: E402
from wise.verify import verify_file  # noqa: E402

WITNESSED_NAME = "Henry Wayne Wise III"


def tracked_files() -> list[Path]:
    """Every file tracked by git, sorted, repo-relative."""
    out = subprocess.check_output(
        ["git", "ls-files"], cwd=REPO_ROOT
    ).decode("utf-8")
    paths = sorted(out.splitlines())
    return [REPO_ROOT / p for p in paths if (REPO_ROOT / p).is_file()]


def manifest_lines(paths: list[Path], exclude_names: set[str]) -> list[str]:
    """Sorted '<wisedigest0-hex>  <path>' lines for the given files.

    `exclude_names` lets us omit the manifest itself (and its proof) from
    its own coverage — a manifest can't include itself without an
    infinite-regress problem.
    """
    lines: list[str] = []
    for p in paths:
        rel = p.relative_to(REPO_ROOT).as_posix()
        if rel in exclude_names:
            continue
        with open(p, "rb") as f:
            data = f.read()
        digest = digest_bytes(data, "WiseDigest-0")
        lines.append(f"{digest}  {rel}")
    return lines


def build_manifest(version: str) -> tuple[Path, Path]:
    manifest_name = f"release-{version}.manifest"
    proof_name = f"release-{version}.manifest.wiseproof"
    manifest_path = REPO_ROOT / manifest_name
    proof_path = REPO_ROOT / proof_name

    paths = tracked_files()
    lines = manifest_lines(paths, exclude_names={manifest_name, proof_name})

    body = "\n".join(lines) + "\n"
    manifest_path.write_text(body, encoding="utf-8")

    items = build_file_proof_items(
        str(manifest_path),
        creator=WITNESSED_NAME,
        created_at="2026-05-03T00:00:00Z",
    )
    proof_path.write_bytes(render(items))

    print(f"manifested {len(lines)} files into {manifest_name}")
    print(f"sealed by  {WITNESSED_NAME}")
    print(f"  measurement.digest = {items['measurement.digest']}")
    print(f"  wise_id            = {items['wise_id']}")
    print(f"  wise_seal          = {items['wise_seal']}")
    return manifest_path, proof_path


def verify_manifest(version: str) -> int:
    """Re-derive the manifest and the proof; assert both match the
    released artifacts byte-for-byte. Exit 0 on success, 1 on drift."""
    manifest_path = REPO_ROOT / f"release-{version}.manifest"
    proof_path = REPO_ROOT / f"release-{version}.manifest.wiseproof"
    if not manifest_path.exists() or not proof_path.exists():
        print(f"missing release artifacts for {version}", file=sys.stderr)
        return 2

    # Re-derive the manifest body from current repo state.
    paths = tracked_files()
    fresh_lines = manifest_lines(
        paths,
        exclude_names={manifest_path.name, proof_path.name},
    )
    fresh_body = ("\n".join(fresh_lines) + "\n").encode("utf-8")
    stored_body = manifest_path.read_bytes()

    if fresh_body != stored_body:
        print("MANIFEST DRIFT — current repo does not match released manifest")
        return 1

    # And: the proof matches the manifest.
    from wise.verify import load_proof
    items, err = load_proof(str(proof_path))
    if err is not None:
        print(f"proof failed to load: {err.detail}", file=sys.stderr)
        return 1
    result = verify_file(str(manifest_path), items)
    if result.status != "VERIFIED":
        print(f"proof did not verify: {result.status} {result.detail}")
        return 1

    print(f"release {version} VERIFIED — manifest + proof both intact")
    print(f"  witnessed by {items['origin.creator']}")
    print(f"  wise_id      {items['wise_id']}")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: seal-release.py <version> [--verify]", file=sys.stderr)
        return 2
    version = sys.argv[1]
    if "--verify" in sys.argv[2:]:
        return verify_manifest(version)
    build_manifest(version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
