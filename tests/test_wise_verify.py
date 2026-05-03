"""End-to-end verify tests for WISE covering every status."""

from __future__ import annotations

import os

from wise.errors import (
    INVALID_PROOF,
    TAMPERED,
    UNREADABLE_ARTIFACT,
    UNSUPPORTED_ALGORITHM,
    VERIFIED,
)
from wise.format import encode
from wise.proof import (
    build_file_proof_items,
    build_text_proof_items,
    compute_wise_id,
    compute_wise_seal,
    render,
)
from wise.verify import load_proof, verify_file, verify_text


FIXED_TIME = "2026-04-27T00:00:00Z"


def _write_bytes(tmp_path, name, data):
    p = os.path.join(tmp_path, name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def _write_proof(tmp_path, name, items):
    p = os.path.join(tmp_path, name)
    with open(p, "wb") as f:
        f.write(render(items))
    return p


def test_verified_file_round_trip(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    proof_path = _write_proof(tmp_path, "demo.txt.wiseproof", items)
    parsed, err = load_proof(proof_path)
    assert err is None
    assert verify_file(f, parsed).status == VERIFIED


def test_verified_text_round_trip():
    items = build_text_proof_items("truth\n", created_at=FIXED_TIME)
    assert verify_text("truth\n", items).status == VERIFIED


def test_tampered_byte_change(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    with open(f, "wb") as fh:
        fh.write(b"changed\n")
    assert verify_file(f, items).status == TAMPERED


def test_tampered_text_crlf(tmp_path):
    items = build_text_proof_items("truth\n", created_at=FIXED_TIME)
    assert verify_text("truth\r\n", items).status == TAMPERED


def test_size_mismatch_short_circuits_to_tampered(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    with open(f, "wb") as fh:
        fh.write(b"truth\n\n")  # one byte longer
    r = verify_file(f, items)
    assert r.status == TAMPERED
    assert r.expected_size == 6
    assert r.observed_size == 7
    assert r.observed_digest is None  # short-circuit, no digest computed


def test_replay_against_other_artifact_is_tampered(tmp_path):
    f1 = _write_bytes(tmp_path, "a.txt", b"truth\n")
    f2 = _write_bytes(tmp_path, "b.txt", b"differs\n")
    items = build_file_proof_items(f1, created_at=FIXED_TIME)
    assert verify_file(f2, items).status == TAMPERED


def test_invalid_proof_when_body_mutated(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    items["origin.creator"] = "Attacker"
    assert verify_file(f, items).status == INVALID_PROOF


def test_invalid_proof_when_required_key_missing(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    del items["artifact.size_bytes"]
    assert verify_file(f, items).status == INVALID_PROOF


def test_unsupported_algorithm_field(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    items["measurement.algorithm"] = "MD5"
    assert verify_file(f, items).status == UNSUPPORTED_ALGORITHM


def test_unreadable_artifact(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    missing = os.path.join(tmp_path, "no.txt")
    assert verify_file(missing, items).status == UNREADABLE_ARTIFACT


def test_load_proof_rejects_bad_file(tmp_path):
    bad = os.path.join(tmp_path, "bad.wiseproof")
    with open(bad, "wb") as fh:
        fh.write(b"not a wiseproof\n")
    parsed, err = load_proof(bad)
    assert parsed is None
    assert err is not None
    assert err.status == INVALID_PROOF


def test_format_violation_in_proof_file_is_invalid_proof(tmp_path):
    """A handcrafted proof violating sort order parses as INVALID_PROOF."""
    bad = os.path.join(tmp_path, "bad.wiseproof")
    with open(bad, "wb") as fh:
        fh.write(b"WISEPROOF-V1\n\nz=1\na=2\n")  # keys out of order
    parsed, err = load_proof(bad)
    assert parsed is None and err is not None
    assert err.status == INVALID_PROOF


# ============================================================================
# v0.1.1 hardening tests
# ============================================================================

import pytest

from wise import MAX_PROOF_BYTES


# ---- C1: constant-time compare returns the same statuses ----
# We can't directly observe constant-time at the unit level, but we CAN
# prove that mismatches still produce the documented status (the goal of
# the change is "do not regress observable behavior").


def test_c1_wise_id_mismatch_still_invalid_proof(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    items["wise_id"] = "0" * 64  # forge
    assert verify_file(f, items).status == INVALID_PROOF


def test_c1_wise_seal_mismatch_still_invalid_proof(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    items["wise_seal"] = "f" * 64  # forge
    assert verify_file(f, items).status == INVALID_PROOF


def test_c1_measurement_digest_mismatch_still_tampered(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    # Replace artifact bytes — digest will mismatch.
    with open(f, "wb") as fh:
        fh.write(b"poison\n")
    assert verify_file(f, items).status == TAMPERED


# ---- C4: strict integer parsing for size_bytes ----


def _make_proof_with(tmp_path, name, mutator):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    mutator(items)
    return f, items


def test_c4_rejects_leading_zeros_in_size(tmp_path):
    f, items = _make_proof_with(tmp_path, "demo.txt", lambda d: d.update({"artifact.size_bytes": "00006"}))
    assert verify_file(f, items).status == INVALID_PROOF


def test_c4_rejects_plus_sign_in_size(tmp_path):
    f, items = _make_proof_with(tmp_path, "demo.txt", lambda d: d.update({"artifact.size_bytes": "+6"}))
    assert verify_file(f, items).status == INVALID_PROOF


def test_c4_rejects_unicode_digits_in_size(tmp_path):
    """Python int() accepts ５ (U+FF15) as 5; we must not."""
    f, items = _make_proof_with(tmp_path, "demo.txt", lambda d: d.update({"artifact.size_bytes": "５"}))
    assert verify_file(f, items).status == INVALID_PROOF


def test_c4_rejects_arabic_indic_digits_in_size(tmp_path):
    """٥ (U+0665, Arabic-Indic digit FIVE) is rejected even though Python
    int() would parse it."""
    f, items = _make_proof_with(tmp_path, "demo.txt", lambda d: d.update({"artifact.size_bytes": "٥"}))
    assert verify_file(f, items).status == INVALID_PROOF


def test_c4_rejects_negative_in_size(tmp_path):
    f, items = _make_proof_with(tmp_path, "demo.txt", lambda d: d.update({"artifact.size_bytes": "-1"}))
    assert verify_file(f, items).status == INVALID_PROOF


def test_c4_zero_size_is_valid_for_empty_text():
    # The empty-text proof has size_bytes=0; that single-digit zero is
    # explicitly permitted.
    items = build_text_proof_items("", created_at=FIXED_TIME)
    assert items["artifact.size_bytes"] == "0"
    assert verify_text("", items).status == VERIFIED


# ---- H2: ISO 8601 UTC strict ----


def test_h2_rejects_non_iso_timestamp(tmp_path):
    f, items = _make_proof_with(tmp_path, "demo.txt", lambda d: d.update({"origin.created_at": "yesterday"}))
    assert verify_file(f, items).status == INVALID_PROOF


def test_h2_rejects_impossible_date(tmp_path):
    f, items = _make_proof_with(tmp_path, "demo.txt", lambda d: d.update({"origin.created_at": "2099-99-99T00:00:00Z"}))
    assert verify_file(f, items).status == INVALID_PROOF


def test_h2_rejects_missing_z_suffix(tmp_path):
    f, items = _make_proof_with(tmp_path, "demo.txt", lambda d: d.update({"origin.created_at": "2026-04-27T00:00:00"}))
    assert verify_file(f, items).status == INVALID_PROOF


def test_h2_rejects_offset_form(tmp_path):
    f, items = _make_proof_with(tmp_path, "demo.txt", lambda d: d.update({"origin.created_at": "2026-04-27T00:00:00+00:00"}))
    assert verify_file(f, items).status == INVALID_PROOF


def test_h2_rejects_fractional_seconds(tmp_path):
    f, items = _make_proof_with(tmp_path, "demo.txt", lambda d: d.update({"origin.created_at": "2026-04-27T00:00:00.000Z"}))
    assert verify_file(f, items).status == INVALID_PROOF


def test_h2_rejects_terminal_escape_in_timestamp(tmp_path):
    """A timestamp field carrying ANSI escape would be filtered earlier
    (control char check), but if it slipped through it would still fail
    the regex. Belt-and-suspenders check."""
    f, items = _make_proof_with(
        tmp_path, "demo.txt",
        lambda d: d.update({"origin.created_at": "2026-04-27T00:00:00Z\x1b[2J"})
    )
    assert verify_file(f, items).status == INVALID_PROOF


# ---- H3: hard caps on proof file size ----


def test_h3_load_proof_rejects_oversize_file(tmp_path):
    bigp = os.path.join(tmp_path, "big.wiseproof")
    with open(bigp, "wb") as fh:
        fh.write(b"WISEPROOF-V1\n\n")
        fh.write(b"k=v\n" * (MAX_PROOF_BYTES // 4 + 100))  # > 1 MiB
    parsed, err = load_proof(bigp)
    assert parsed is None
    assert err is not None
    assert err.status == INVALID_PROOF


def test_h3_normal_proof_well_under_cap(tmp_path):
    """A normal proof is < 2 KB and must always load."""
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    proof_path = _write_proof(tmp_path, "demo.txt.wiseproof", items)
    assert os.path.getsize(proof_path) < 2048
    parsed, err = load_proof(proof_path)
    assert err is None and parsed is not None


# ---- H4: unknown keys rejected ----


def test_h4_rejects_unknown_key(tmp_path):
    f, items = _make_proof_with(tmp_path, "demo.txt", lambda d: d.update({"attacker.field": "blue"}))
    assert verify_file(f, items).status == INVALID_PROOF


def test_h4_rejects_artifact_encoding_on_file_artifact(tmp_path):
    """File proofs must not carry artifact.encoding."""
    f, items = _make_proof_with(tmp_path, "demo.txt", lambda d: d.update({"artifact.encoding": "utf-8"}))
    assert verify_file(f, items).status == INVALID_PROOF


# ---- H1/H5: attestation field + ASCII creator ----


def test_h1_rejects_missing_attestation(tmp_path):
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    del items["origin.attestation"]
    assert verify_file(f, items).status == INVALID_PROOF


def test_h1_rejects_unrecognized_attestation_value(tmp_path):
    f, items = _make_proof_with(tmp_path, "demo.txt", lambda d: d.update({"origin.attestation": "signed"}))
    # Until v0.4 ships, "signed" is not in ALLOWED_ATTESTATION.
    assert verify_file(f, items).status == INVALID_PROOF


def test_h1_rejects_homoglyph_creator(tmp_path):
    """Cyrillic 'А' (U+0410) instead of Latin 'A'. Visually identical to a
    human; completely different bytes to a computer."""
    f, items = _make_proof_with(tmp_path, "demo.txt", lambda d: d.update({"origin.creator": "Аnthropic"}))
    assert verify_file(f, items).status == INVALID_PROOF


def test_h1_rejects_fullwidth_creator(tmp_path):
    """U+FF21 etc. — homoglyph attack via fullwidth letters."""
    f, items = _make_proof_with(tmp_path, "demo.txt", lambda d: d.update({"origin.creator": "Ａnthropic"}))
    assert verify_file(f, items).status == INVALID_PROOF


def test_h1_rejects_creator_with_control_char_at_build_time(tmp_path):
    """build_*_proof_items() validates the creator at construction time."""
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    with pytest.raises(ValueError):
        build_file_proof_items(f, creator="Anthropic\x07", created_at=FIXED_TIME)


def test_h1_accepts_normal_ascii_creator():
    items = build_text_proof_items("hi\n", creator="Anthropic", created_at=FIXED_TIME)
    assert items["origin.creator"] == "Anthropic"
    assert verify_text("hi\n", items).status == VERIFIED


def test_h1_accepts_creator_with_punctuation():
    items = build_text_proof_items("hi\n", creator="Wise.Est Systems (2026)", created_at=FIXED_TIME)
    assert verify_text("hi\n", items).status == VERIFIED


# ============================================================================
# Adversarial torture: full round-trip on random artifacts
# ============================================================================
# Build a proof for a random byte sequence, render → decode → verify_file.
# Every random artifact in [0..4096] bytes must round-trip to VERIFIED.
# A failure here means either the encode/decode path or the verify path has
# an asymmetry an attacker could exploit.

import random


def test_torture_roundtrip_arbitrary_artifacts(tmp_path):
    rng = random.Random(0xB055_CAFE)
    n_trials = 500
    for trial in range(n_trials):
        size = rng.randint(0, 4096)
        data = bytes(rng.randint(0, 255) for _ in range(size))
        artifact_path = os.path.join(tmp_path, f"a_{trial}.bin")
        with open(artifact_path, "wb") as f:
            f.write(data)
        items = build_file_proof_items(artifact_path, created_at=FIXED_TIME)
        proof_bytes = render(items)
        # Round-trip: render → decode → verify must produce VERIFIED.
        from wise.format import decode
        parsed = decode(proof_bytes)
        assert parsed == items, f"trial {trial}: dict round-trip drifted"
        result = verify_file(artifact_path, parsed)
        assert result.status == VERIFIED, (
            f"trial {trial} (size={size}) failed: {result.status} {result.detail}"
        )


def test_torture_roundtrip_random_text():
    """Same but for text artifacts. UTF-8 only — the spec mandates utf-8."""
    rng = random.Random(0xBADD_F00D)
    n_trials = 500
    for trial in range(n_trials):
        # Build random valid UTF-8 text. Avoid surrogates and
        # forbidden code points (newline, etc., would be encoded by Python
        # but the proof format rejects newlines in values — text content is
        # not a value, it's the artifact, so newlines are fine in the artifact).
        n_chars = rng.randint(0, 200)
        chars = []
        for _ in range(n_chars):
            cp = rng.randint(0, 0x10FFFF)
            # Skip surrogates (U+D800..U+DFFF) which can't be encoded in UTF-8.
            while 0xD800 <= cp <= 0xDFFF:
                cp = rng.randint(0, 0x10FFFF)
            chars.append(chr(cp))
        text = "".join(chars)
        items = build_text_proof_items(text, created_at=FIXED_TIME)
        result = verify_text(text, items)
        assert result.status == VERIFIED, (
            f"trial {trial} (len={len(text)}) failed: {result.status} {result.detail}"
        )


def test_torture_tampering_detected_at_every_byte_position(tmp_path):
    """For a small artifact, flipping each byte must be detected as TAMPERED.
    Catches: a hash with a bit-flip blind spot. (Won't find subtle collisions
    but catches gross structural failures.)"""
    artifact = b"the quick brown fox jumps over the lazy dog"
    f = _write_bytes(tmp_path, "fox.txt", artifact)
    items = build_file_proof_items(f, created_at=FIXED_TIME)
    for i in range(len(artifact)):
        for bit in range(8):
            mutated = bytearray(artifact)
            mutated[i] ^= 1 << bit
            with open(f, "wb") as fh:
                fh.write(bytes(mutated))
            result = verify_file(f, items)
            assert result.status == TAMPERED, (
                f"bit flip at byte {i} bit {bit} not detected: {result.status}"
            )


# ============================================================================
# THE SOUL TESTS
# ============================================================================
# These tests don't probe attack surface. They verify the invariants that
# define WISEATA as a public-good protocol rather than a vendor product.
# If any of these break, WISEATA stopped being WISEATA.


def test_p12_proof_verifies_with_ONLY_python_stdlib(tmp_path):
    """**P12 — verifies without the issuer.**

    A SHA-256 proof produced by the full wise library must verify when the
    verifier uses ONLY Python stdlib — no imports from the wise package, no
    network, no platform. If Wise.Est Systems disappeared tomorrow, every
    proof ever produced still verifies. This test proves that property in
    code, not in marketing.
    """
    # Step 1: produce a proof using the full library (the issuer).
    f = _write_bytes(tmp_path, "demo.txt", b"truth\n")
    items = build_file_proof_items(f, algorithm="SHA-256", created_at=FIXED_TIME)
    proof_path = _write_proof(tmp_path, "demo.txt.wiseproof", items)

    # Step 2: stdlib-only verification. From here on we MUST NOT touch the
    # `wise` package. We re-derive every digest from the spec.
    import hashlib

    with open(proof_path, "rb") as fh:
        raw = fh.read()

    # Parse the canonical text format from scratch (spec §2).
    assert not raw.startswith(b"\xef\xbb\xbf"), "C7: BOM not permitted"
    text = raw.decode("utf-8")
    assert text.endswith("\n")
    lines = text[:-1].split("\n")
    assert lines[0] == "WISEPROOF-V1"
    assert lines[1] == ""
    parsed: dict[str, str] = {}
    for ln in lines[2:]:
        assert ln  # no empty body lines
        k, sep, v = ln.partition("=")
        assert sep == "="
        parsed[k] = v

    # Recompute measurement.digest using only hashlib SHA-256.
    h = hashlib.sha256()
    with open(f, "rb") as af:
        h.update(af.read())
    assert h.hexdigest() == parsed["measurement.digest"], (
        "stdlib verifier disagrees with library on measurement.digest"
    )

    # Recompute wise_id from spec §3.4.
    EXCLUDE_ID = {
        "wise_id", "wise_seal",
        "origin.created_at", "artifact.name", "origin.attestation",
    }
    body_lines = ["WISEPROOF-V1", ""]
    for k in sorted(
        (k for k in parsed if k not in EXCLUDE_ID),
        key=lambda s: s.encode("utf-8"),
    ):
        body_lines.append(f"{k}={parsed[k]}")
    body = ("\n".join(body_lines) + "\n").encode("utf-8")
    derived_id = hashlib.sha256(body).hexdigest()
    assert derived_id == parsed["wise_id"], (
        "stdlib verifier disagrees with library on wise_id"
    )

    # Recompute wise_seal from spec §3.4.
    EXCLUDE_SEAL = {"wise_seal"}
    body_lines = ["WISEPROOF-V1", ""]
    for k in sorted(
        (k for k in parsed if k not in EXCLUDE_SEAL),
        key=lambda s: s.encode("utf-8"),
    ):
        body_lines.append(f"{k}={parsed[k]}")
    body = ("\n".join(body_lines) + "\n").encode("utf-8")
    derived_seal = hashlib.sha256(body).hexdigest()
    assert derived_seal == parsed["wise_seal"], (
        "stdlib verifier disagrees with library on wise_seal"
    )

    # If we got here: a Python stdlib-only verifier matched the wise library
    # byte-for-byte on all three digests. The proof needed nothing from
    # Wise.Est Systems, no server, no account, no platform — just the spec
    # and a cryptographic library that exists in every operating system on
    # Earth. P12 is real.


def test_no_platform_no_network_no_account(tmp_path):
    """**No platform, no server, no account.**

    The wise package source must contain ZERO network imports and ZERO
    authentication code. If a future contributor adds `import requests` or
    a login flow, this test breaks the build. The discipline is mechanical,
    not aspirational.
    """
    import wise as _wise_pkg  # noqa: F401  (just to locate the package)
    import os
    import wise

    pkg_dir = os.path.dirname(wise.__file__)
    forbidden_imports = {
        "requests", "urllib", "urllib3", "httpx", "aiohttp",
        "http.client", "http.server", "socket", "smtplib", "ftplib",
        "telnetlib", "ssl", "websocket",
    }
    forbidden_keywords = {
        "oauth", "bearer", "username", "password", "session_id",
        "api_key", "api_token", "login(", "logout(", "authenticate(",
    }
    for fname in os.listdir(pkg_dir):
        if not fname.endswith(".py"):
            continue
        with open(os.path.join(pkg_dir, fname), "r", encoding="utf-8") as f:
            src = f.read()
        # Strip strings/comments to avoid false positives — but for these
        # specific terms even appearing in a comment is suspicious.
        for bad in forbidden_imports:
            assert f"import {bad}" not in src, (
                f"{fname}: forbidden import '{bad}' — P9 violation"
            )
            assert f"from {bad}" not in src, (
                f"{fname}: forbidden import '{bad}' — P9 violation"
            )
        for kw in forbidden_keywords:
            # Case-insensitive check for auth keywords.
            assert kw.lower() not in src.lower(), (
                f"{fname}: contains forbidden auth keyword {kw!r} — P9 violation"
            )


def test_no_urls_or_hostnames_in_runtime_code():
    """**Verification touches no URL.** A runtime path must not reference
    any URL or hostname. (Documentation/comments referencing GitHub for
    issue-reporting are tolerated; the test scans only `format`, `verify`,
    `proof`, `seal`, `digest`, `expansion`, `errors`, and `__init__`.)
    """
    import os
    import wise

    pkg_dir = os.path.dirname(wise.__file__)
    runtime_modules = (
        "__init__.py", "format.py", "verify.py", "proof.py",
        "seal.py", "digest.py", "expansion.py", "errors.py",
    )
    forbidden_substrings = ("http://", "https://", "ssh://", "ftp://", ".com/", ".io/", ".dev/")
    for mod in runtime_modules:
        path = os.path.join(pkg_dir, mod)
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()
        for sub in forbidden_substrings:
            assert sub not in src, (
                f"{mod}: contains URL-like substring {sub!r} on the runtime path"
            )


def test_wise_id_survives_attestation_upgrade(tmp_path):
    """**Identity is stable across attestation states.**

    A v0.1.1 self_declared proof and a hypothetical future v0.4 signed proof
    of the same artifact MUST produce identical wise_id values. This is the
    promise that content addressing survives every future protocol upgrade
    that touches attestation. We simulate the upgrade by mutating the
    attestation field (and recomputing wise_id manually); wise_id must not
    move.
    """
    items = build_text_proof_items("truth\n", created_at=FIXED_TIME)
    algo = items["measurement.algorithm"]
    id_self_declared = compute_wise_id(items, algo)

    # Simulate v0.4: replace attestation with "signed". (We're not adding
    # the signature field — just the attestation flip.)
    upgraded = dict(items)
    upgraded["origin.attestation"] = "signed"
    id_signed = compute_wise_id(upgraded, algo)
    assert id_self_declared == id_signed, (
        "wise_id moved across attestation upgrade — content addressing broken"
    )

    # And: removing attestation entirely also leaves wise_id unchanged
    # (the field is in the exclude set).
    no_att = {k: v for k, v in items.items() if k != "origin.attestation"}
    id_no_att = compute_wise_id(no_att, algo)
    assert id_self_declared == id_no_att


def test_wise_id_survives_clock_skew_and_filename_changes(tmp_path):
    """**Identity is stable across machines, time, and names.** Same
    artifact + same creator + same algorithm → identical wise_id, no matter
    what time it is or what the file is called locally.
    """
    f1 = _write_bytes(tmp_path, "alpha.txt", b"truth\n")
    f2 = _write_bytes(tmp_path, "beta.txt", b"truth\n")
    a = build_file_proof_items(f1, created_at="2026-01-01T00:00:00Z")
    b = build_file_proof_items(f2, created_at="2099-12-31T23:59:59Z")
    assert a["wise_id"] == b["wise_id"]
    # Sanity: different artifacts → different wise_id.
    f3 = _write_bytes(tmp_path, "gamma.txt", b"different\n")
    c = build_file_proof_items(f3, created_at="2026-01-01T00:00:00Z")
    assert a["wise_id"] != c["wise_id"]
