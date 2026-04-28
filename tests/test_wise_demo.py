"""The canonical demo from the brief, run via the CLI entry point.

  wise forge demo.txt
  wise check demo.txt demo.txt.wiseproof    -> VERIFIED
  (mutate demo.txt)
  wise check demo.txt demo.txt.wiseproof    -> TAMPERED
"""

from __future__ import annotations

import io
import os
import sys

from wise.cli import main as wise_main


def _run(argv, capsys):
    rc = wise_main(argv)
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def test_demo_verified_then_tampered(tmp_path, capsys):
    artifact = os.path.join(tmp_path, "demo.txt")
    proof = artifact + ".wiseproof"
    with open(artifact, "wb") as f:
        f.write(b"truth\n")

    rc, out, _ = _run(["forge", artifact, "--created-at", "2026-04-27T00:00:00Z"], capsys)
    assert rc == 0
    assert os.path.exists(proof)

    rc, out, _ = _run(["check", artifact, proof], capsys)
    assert rc == 0
    assert out.startswith("VERIFIED")

    with open(artifact, "wb") as f:
        f.write(b"changed\n")

    rc, out, _ = _run(["check", artifact, proof], capsys)
    assert rc == 1
    assert out.startswith("TAMPERED")
