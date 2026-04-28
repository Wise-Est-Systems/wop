"""WISE CLI per §31.6."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import DEFAULT_CREATOR, SUPPORTED_ALGORITHMS, __version__
from .errors import EXIT_CODES, USER_ERROR, VERIFIED
from .format import FormatError, decode
from .proof import build_file_proof_items, build_text_proof_items, render
from .seal import SealError, pack, unpack
from .verify import VerifyResult, load_proof, verify_file, verify_text


def _write_bytes(out_path: str, data: bytes, force: bool) -> None:
    if os.path.exists(out_path) and not force:
        raise FileExistsError(out_path)
    with open(out_path, "wb") as f:
        f.write(data)


def _emit_create(items: dict[str, str], out_path: str, json_mode: bool, quiet: bool, kind: str) -> None:
    if quiet:
        return
    if json_mode:
        payload = {
            "status": f"{kind}_CREATED",
            "out": out_path,
            "wise_id": items["wise_id"],
            "wise_seal": items["wise_seal"],
            "artifact_digest": items["measurement.digest"],
        }
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    else:
        sys.stdout.write(f"{kind}_CREATED {out_path}\n")
        sys.stdout.write(f"wise_id   {items['wise_id']}\n")
        sys.stdout.write(f"wise_seal {items['wise_seal']}\n")


def _emit_verify(result: VerifyResult, json_mode: bool, quiet: bool) -> None:
    if quiet:
        return
    if json_mode:
        payload = {"status": result.status}
        if result.detail:
            payload["detail"] = result.detail
        for key in (
            "expected_digest",
            "observed_digest",
            "expected_size",
            "observed_size",
            "wise_id",
            "wise_seal",
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
    p.add_argument("--out", default=None, help="output path (default: <artifact>.wiseproof or .wiseseal)")
    p.add_argument(
        "--algorithm",
        default="WiseDigest-0",
        choices=SUPPORTED_ALGORITHMS,
        help="digest algorithm (default: WiseDigest-0)",
    )
    p.add_argument("--creator", default=DEFAULT_CREATOR, help=f"origin.creator (default: {DEFAULT_CREATOR!r})")
    p.add_argument("--created-at", default=None, help="override origin.created_at (ISO 8601 UTC, Z suffix)")
    p.add_argument("--origin-mode", default="local", choices=("local", "imported"))
    p.add_argument("--force", action="store_true", help="overwrite existing output file")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wise", description="Wise Origin Protocol CLI")
    parser.add_argument("--version", action="version", version=f"wise {__version__}")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--quiet", action="store_true", help="suppress stdout (exit codes only)")

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_forge = sub.add_parser("forge", help="create a .wiseproof for a file or text")
    p_forge.add_argument("path", nargs="?", help="path to a file artifact (omit when using --text)")
    p_forge.add_argument("--text", default=None, help="prove a literal UTF-8 string instead of a file")
    _add_common_create_flags(p_forge)

    p_check = sub.add_parser("check", help="verify a .wiseproof against an artifact")
    p_check.add_argument("artifact", help="path to a file artifact, OR the proof path when using --text")
    p_check.add_argument("proof", nargs="?", help="path to .wiseproof (when verifying a file)")
    p_check.add_argument("--text", default=None, help="verify a literal UTF-8 string against a proof")

    p_inspect = sub.add_parser("inspect", help="show .wiseproof contents")
    p_inspect.add_argument("proof", help="path to .wiseproof")

    p_bind = sub.add_parser("bind", help="produce a .wiseseal container")
    p_bind.add_argument("path", help="path to the file")
    _add_common_create_flags(p_bind)

    p_open = sub.add_parser("open", help="extract artifact + proof from a .wiseseal")
    p_open.add_argument("seal", help="path to .wiseseal")
    p_open.add_argument("--out-artifact", required=True)
    p_open.add_argument("--out-proof", required=True)
    p_open.add_argument("--force", action="store_true")

    return parser


def _cmd_forge_file(args: argparse.Namespace) -> int:
    if not os.path.isfile(args.path):
        sys.stderr.write(f"USER_ERROR: not a regular file: {args.path}\n")
        return EXIT_CODES[USER_ERROR]
    out = args.out or (args.path + ".wiseproof")
    try:
        items = build_file_proof_items(
            args.path,
            algorithm=args.algorithm,
            creator=args.creator,
            created_at=args.created_at,
            origin_mode=args.origin_mode,
        )
        _write_bytes(out, render(items), args.force)
    except FileExistsError as e:
        sys.stderr.write(f"USER_ERROR: file exists: {e}. Pass --force.\n")
        return EXIT_CODES[USER_ERROR]
    except OSError as e:
        sys.stderr.write(f"USER_ERROR: {e}\n")
        return EXIT_CODES[USER_ERROR]
    _emit_create(items, out, args.json, args.quiet, kind="PROOF")
    return 0


def _cmd_forge_text(args: argparse.Namespace) -> int:
    out = args.out or "text.wiseproof"
    try:
        items = build_text_proof_items(
            args.text,
            algorithm=args.algorithm,
            creator=args.creator,
            created_at=args.created_at,
            origin_mode=args.origin_mode,
        )
        _write_bytes(out, render(items), args.force)
    except FileExistsError as e:
        sys.stderr.write(f"USER_ERROR: file exists: {e}. Pass --force.\n")
        return EXIT_CODES[USER_ERROR]
    except OSError as e:
        sys.stderr.write(f"USER_ERROR: {e}\n")
        return EXIT_CODES[USER_ERROR]
    _emit_create(items, out, args.json, args.quiet, kind="PROOF")
    return 0


def _cmd_check_file(args: argparse.Namespace) -> int:
    if not args.artifact or not args.proof:
        sys.stderr.write("USER_ERROR: usage: wise check <artifact> <proof>\n")
        return EXIT_CODES[USER_ERROR]
    items, err = load_proof(args.proof)
    if err is not None:
        _emit_verify(err, args.json, args.quiet)
        return EXIT_CODES[err.status]
    assert items is not None
    result = verify_file(args.artifact, items)
    _emit_verify(result, args.json, args.quiet)
    return EXIT_CODES[result.status]


def _cmd_check_text(args: argparse.Namespace) -> int:
    items, err = load_proof(args.proof)
    if err is not None:
        _emit_verify(err, args.json, args.quiet)
        return EXIT_CODES[err.status]
    assert items is not None
    result = verify_text(args.text, items)
    _emit_verify(result, args.json, args.quiet)
    return EXIT_CODES[result.status]


def _cmd_inspect(args: argparse.Namespace) -> int:
    items, err = load_proof(args.proof)
    if err is not None:
        _emit_verify(err, args.json, args.quiet)
        return EXIT_CODES[err.status]
    assert items is not None
    if args.json:
        sys.stdout.write(json.dumps(items, ensure_ascii=False, indent=2) + "\n")
    else:
        for k in sorted(items.keys()):
            sys.stdout.write(f"{k:24} {items[k]}\n")
    return 0


def _cmd_bind(args: argparse.Namespace) -> int:
    if not os.path.isfile(args.path):
        sys.stderr.write(f"USER_ERROR: not a regular file: {args.path}\n")
        return EXIT_CODES[USER_ERROR]
    out = args.out or (args.path + ".wiseseal")
    try:
        with open(args.path, "rb") as f:
            artifact_bytes = f.read()
        items = build_file_proof_items(
            args.path,
            algorithm=args.algorithm,
            creator=args.creator,
            created_at=args.created_at,
            origin_mode=args.origin_mode,
        )
        proof_bytes = render(items)
        sealed = pack(artifact_bytes, proof_bytes)
        _write_bytes(out, sealed, args.force)
    except FileExistsError as e:
        sys.stderr.write(f"USER_ERROR: file exists: {e}. Pass --force.\n")
        return EXIT_CODES[USER_ERROR]
    except (OSError, SealError) as e:
        sys.stderr.write(f"USER_ERROR: {e}\n")
        return EXIT_CODES[USER_ERROR]
    _emit_create(items, out, args.json, args.quiet, kind="SEAL")
    return 0


def _cmd_open(args: argparse.Namespace) -> int:
    try:
        with open(args.seal, "rb") as f:
            data = f.read()
        artifact_bytes, proof_bytes = unpack(data)
        if os.path.exists(args.out_artifact) and not args.force:
            raise FileExistsError(args.out_artifact)
        if os.path.exists(args.out_proof) and not args.force:
            raise FileExistsError(args.out_proof)
        with open(args.out_artifact, "wb") as f:
            f.write(artifact_bytes)
        with open(args.out_proof, "wb") as f:
            f.write(proof_bytes)
    except FileExistsError as e:
        sys.stderr.write(f"USER_ERROR: file exists: {e}. Pass --force.\n")
        return EXIT_CODES[USER_ERROR]
    except (OSError, SealError) as e:
        sys.stderr.write(f"USER_ERROR: {e}\n")
        return EXIT_CODES[USER_ERROR]
    if not args.quiet:
        sys.stdout.write(f"OPENED {args.seal}\n")
        sys.stdout.write(f"  artifact -> {args.out_artifact}\n")
        sys.stdout.write(f"  proof    -> {args.out_proof}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "forge":
        if args.text is not None:
            if args.path is not None:
                sys.stderr.write("USER_ERROR: pass either <file> or --text, not both\n")
                return EXIT_CODES[USER_ERROR]
            return _cmd_forge_text(args)
        if not args.path:
            sys.stderr.write("USER_ERROR: usage: wise forge <file>  |  wise forge --text <string>\n")
            return EXIT_CODES[USER_ERROR]
        return _cmd_forge_file(args)
    if args.cmd == "check":
        if args.text is not None:
            # In text mode, the first positional is the proof path.
            args.proof = args.artifact
            return _cmd_check_text(args)
        if not args.proof:
            sys.stderr.write("USER_ERROR: usage: wise check <artifact> <proof>  |  wise check <proof> --text <string>\n")
            return EXIT_CODES[USER_ERROR]
        return _cmd_check_file(args)
    if args.cmd == "inspect":
        return _cmd_inspect(args)
    if args.cmd == "bind":
        return _cmd_bind(args)
    if args.cmd == "open":
        return _cmd_open(args)
    parser.error("unknown command")
    return EXIT_CODES[USER_ERROR]


if __name__ == "__main__":
    sys.exit(main())
