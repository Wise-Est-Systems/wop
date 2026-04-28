"""Locked test vectors — these MUST never change without a major version bump.

If any of these assertions fail, either the spec changed (intentional, requires
a new version line in the spec and updated vectors) or the implementation
drifted (unintentional, fix the implementation).
"""

from __future__ import annotations

import os

from wise.proof import build_file_proof_items, build_text_proof_items


FIXED_TIME = "2026-04-27T00:00:00Z"


def test_v1_truth_file_locked(tmp_path):
    f = os.path.join(tmp_path, "demo.txt")
    with open(f, "wb") as fh:
        fh.write(b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    assert items["measurement.digest"] == (
        "6f9bbc98288bfa8efd7b8ae37c0a0053716bb819688c448d27781a7252fdfd50"
    )
    assert items["wise_id"] == (
        "5b0c31df07626993e386434b760539beeb19b9d941c865851a31cd3efa60b091"
    )
    assert items["wise_seal"] == (
        "5e9a0ddd0e23a9393302ae6c39e2f31692b597aabad4b89482d1483765dfa564"
    )


def test_v1_empty_text_locked():
    items = build_text_proof_items("", created_at=FIXED_TIME)
    assert items["measurement.digest"] == (
        "2800f3b2e070ed0ce2886ad3a6b5f71cc6182611f9c2e5cfbe57429a0e119d59"
    )
    assert items["wise_id"] == (
        "df879162047721c0d83d2c53f3a7656b54abdf6085544746bb256fc6e587115e"
    )
    assert items["wise_seal"] == (
        "edc67a15d60c20283f175dbfb87f2b98e46fd1f622e80cc726882e3d2323b94b"
    )
