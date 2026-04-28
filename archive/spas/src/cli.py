"""SPAS CLI per §9 + §23."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from . import DEFAULT_CREATOR, SUPPORTED_ALGORITHMS
from .canonical import canonicalize
from .errors import EXIT_CODES, USER_ERROR, VERIFIED
from .proof import build_file_proof, build_text_proof
from .verify import VerifyResult, load_proof, verify_file, verify_text


def _write_proof(proof: dict[str, Any], out_path: str, force: bool) -> None:
    if os.path.exists(out_path) and not force:
        raise FileExistsError(out_path)
    raw = canonicalize(proof)
    with open(out_path, "wb") as f:
        f.write(raw)


def _emit_create(proof: dict[str, Any], out_path: str, json_mode: bool, quiet: bool) -> None:
    if quiet:
        return
    if json_mode:
        payload = {
            "status": "PROOF_CREATED",
            "out": out_path,
            "proof_id": proof["proof_id"],
            "seal_id": proof["seal_id"],
            "artifact_digest": proof["measurement"]["digest"],
        }
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    else:
        sys.stdout.write(f"PROOF_CREATED {out_path}\n")
        sys.stdout.write(f"proof_id {proof['proof_id']}\n")
        sys.stdout.write(f"seal_id  {proof['seal_id']}\n")


def _emit_verify(result: VerifyResult, json_mode: bool, quiet: bool) -> None:
    if quiet:
        return
    if json_mode:
        payload: dict[str, Any] = {"status": result.status}
        if result.detail:
            payload["detail"] = result.detail
        for key in (
            "expected_digest",
            "observed_digest",
            "expected_size",
            "observed_size",
            "proof_id",
            "seal_id",
        ):
            v = getattr(result, key)
            if v is not None:
                payload[key] = v
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    else:
        sys.stdout.write(result.status + "\n")
        if result.detail and result.status != VERIFIED:
            sys.stdout.write(f"  {result.detail}\n")


def _add_common_create_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--out", required=True, help="output proof path (.spas.json)")
    p.add_argument(
        "--algorithm",
        default="WISE-DIGEST-0",
        choices=SUPPORTED_ALGORITHMS,
        help="digest algorithm (default: WISE-DIGEST-0)",
    )
    p.add_argument(
        "--creator",
        default=DEFAULT_CREATOR,
        help=f"creator label (default: {DEFAULT_CREATOR!r})",
    )
    p.add_argument(
        "--created-at",
        default=None,
        help="override created_at_utc (ISO 8601, UTC, Z suffix)",
    )
    p.add_argument(
        "--origin-mode",
        default="local",
        choices=("local", "imported"),
        help="origin.mode (default: local)",
    )
    p.add_argument("--force", action="store_true", help="overwrite existing proof file")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="spas", description="SPAS — Self-Proving Artifact System")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--quiet", action="store_true", help="suppress stdout (exit codes only)")

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_prove = sub.add_parser("prove", help="create a proof")
    prove_sub = p_prove.add_subparsers(dest="kind", required=True)

    p_prove_file = prove_sub.add_parser("file", help="prove a file artifact")
    p_prove_file.add_argument("path", help="path to the file")
    _add_common_create_flags(p_prove_file)

    p_prove_text = prove_sub.add_parser("text", help="prove a text artifact")
    p_prove_text.add_argument("text", help="exact text string to prove (UTF-8)")
    _add_common_create_flags(p_prove_text)

    p_verify = sub.add_parser("verify", help="verify a proof")
    verify_sub = p_verify.add_subparsers(dest="kind", required=True)

    p_verify_file = verify_sub.add_parser("file", help="verify a file artifact")
    p_verify_file.add_argument("path", help="path to the file")
    p_verify_file.add_argument("--proof", required=True, help="path to the .spas.json proof")

    p_verify_text = verify_sub.add_parser("text", help="verify a text artifact")
    p_verify_text.add_argument("text", help="exact text string to verify (UTF-8)")
    p_verify_text.add_argument("--proof", required=True, help="path to the .spas.json proof")

    p_inspect = sub.add_parser("inspect", help="show proof contents")
    p_inspect.add_argument("proof", help="path to the .spas.json proof")

    return parser


def _cmd_prove_file(args: argparse.Namespace) -> int:
    if not os.path.isfile(args.path):
        sys.stderr.write(f"USER_ERROR: not a regular file: {args.path}\n")
        return EXIT_CODES[USER_ERROR]
    try:
        proof = build_file_proof(
            args.path,
            algorithm=args.algorithm,
            creator_label=args.creator,
            created_at_utc=args.created_at,
            origin_mode=args.origin_mode,
        )
        _write_proof(proof, args.out, args.force)
    except FileExistsError as e:
        sys.stderr.write(f"USER_ERROR: proof file already exists: {e}. Pass --force to overwrite.\n")
        return EXIT_CODES[USER_ERROR]
    except OSError as e:
        sys.stderr.write(f"USER_ERROR: {e}\n")
        return EXIT_CODES[USER_ERROR]
    _emit_create(proof, args.out, args.json, args.quiet)
    return 0


def _cmd_prove_text(args: argparse.Namespace) -> int:
    try:
        proof = build_text_proof(
            args.text,
            algorithm=args.algorithm,
            creator_label=args.creator,
            created_at_utc=args.created_at,
            origin_mode=args.origin_mode,
        )
        _write_proof(proof, args.out, args.force)
    except FileExistsError as e:
        sys.stderr.write(f"USER_ERROR: proof file already exists: {e}. Pass --force to overwrite.\n")
        return EXIT_CODES[USER_ERROR]
    except OSError as e:
        sys.stderr.write(f"USER_ERROR: {e}\n")
        return EXIT_CODES[USER_ERROR]
    _emit_create(proof, args.out, args.json, args.quiet)
    return 0


def _cmd_verify_file(args: argparse.Namespace) -> int:
    proof, err = load_proof(args.proof)
    if err is not None:
        _emit_verify(err, args.json, args.quiet)
        return EXIT_CODES[err.status]
    assert proof is not None
    result = verify_file(args.path, proof)
    _emit_verify(result, args.json, args.quiet)
    return EXIT_CODES[result.status]


def _cmd_verify_text(args: argparse.Namespace) -> int:
    proof, err = load_proof(args.proof)
    if err is not None:
        _emit_verify(err, args.json, args.quiet)
        return EXIT_CODES[err.status]
    assert proof is not None
    result = verify_text(args.text, proof)
    _emit_verify(result, args.json, args.quiet)
    return EXIT_CODES[result.status]


def _cmd_inspect(args: argparse.Namespace) -> int:
    proof, err = load_proof(args.proof)
    if err is not None:
        _emit_verify(err, args.json, args.quiet)
        return EXIT_CODES[err.status]
    assert proof is not None
    if args.json:
        sys.stdout.write(json.dumps(proof, ensure_ascii=False, indent=2) + "\n")
    else:
        for k in (
            "spas_version",
            "proof_format",
            "proof_id",
            "seal_id",
        ):
            sys.stdout.write(f"{k:14} {proof.get(k)}\n")
        art = proof.get("artifact", {})
        sys.stdout.write(f"artifact.type  {art.get('type')}\n")
        sys.stdout.write(f"artifact.name  {art.get('name')!r}\n")
        sys.stdout.write(f"artifact.size  {art.get('size_bytes')}\n")
        mes = proof.get("measurement", {})
        sys.stdout.write(f"algorithm      {mes.get('algorithm')}\n")
        sys.stdout.write(f"digest         {mes.get('digest')}\n")
        org = proof.get("origin", {})
        sys.stdout.write(f"origin.mode    {org.get('mode')}\n")
        sys.stdout.write(f"created_at_utc {org.get('created_at_utc')}\n")
        sys.stdout.write(f"creator_label  {org.get('creator_label')!r}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "prove" and args.kind == "file":
        return _cmd_prove_file(args)
    if args.cmd == "prove" and args.kind == "text":
        return _cmd_prove_text(args)
    if args.cmd == "verify" and args.kind == "file":
        return _cmd_verify_file(args)
    if args.cmd == "verify" and args.kind == "text":
        return _cmd_verify_text(args)
    if args.cmd == "inspect":
        return _cmd_inspect(args)
    parser.error("unknown command")
    return EXIT_CODES[USER_ERROR]


if __name__ == "__main__":
    sys.exit(main())
