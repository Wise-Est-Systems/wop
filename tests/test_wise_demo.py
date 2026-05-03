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


# ============================================================================
# THE SOUL TESTS — what makes WISEATA WISEATA, mechanically enforced
# ============================================================================
# These tests check claims about the project's posture, not about what the
# code computes. They run on the source tree itself.


def test_disclosure_present_on_every_research_digest_spec():
    """Every research-track digest spec MUST carry an experimental
    disclosure. The honest-disclosure ethos is enforced by CI, not custom."""
    import os
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    research_dir = os.path.join(repo_root, "research")
    required_phrase_alternatives = (
        "NOT a security claim",
        "not formally cryptanalyzed",
        "not undergone formal cryptanalytic review",
        "experimental",
    )
    for fname in os.listdir(research_dir):
        if not fname.startswith("WiseDigest-") or not fname.endswith(".md"):
            continue
        if fname == "WiseDigest-Lab.md":
            continue  # the lab notebook itself does not carry a single spec.
        path = os.path.join(research_dir, fname)
        with open(path, "r", encoding="utf-8") as f:
            text = f.read().lower()
        assert any(p.lower() in text for p in required_phrase_alternatives), (
            f"{fname} is missing an experimental/disclosure phrase — "
            f"honest-disclosure ethos violated"
        )


def test_security_md_exists_and_recommends_sha256_for_adversarial_use():
    """SECURITY.md must exist AND must point to SHA-256 for adversarial
    threat models. If a future contributor removes that recommendation,
    this test breaks the build."""
    import os
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    security_path = os.path.join(repo_root, "SECURITY.md")
    assert os.path.exists(security_path)
    with open(security_path, "r", encoding="utf-8") as f:
        text = f.read()
    assert "SHA-256" in text, "SECURITY.md must mention SHA-256 fallback"
    assert "experimental" in text.lower() or "EXPERIMENTAL" in text
    assert "WiseDigest-0" in text


def test_apache_2_0_license_present():
    """The license must be Apache-2.0. WISEATA is a public-good primitive;
    Apache-2.0 includes the explicit patent grant required for that role.
    A contributor swapping it for a more restrictive license breaks this."""
    import os
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    license_path = os.path.join(repo_root, "LICENSE")
    assert os.path.exists(license_path)
    with open(license_path, "r", encoding="utf-8") as f:
        text = f.read()
    assert "Apache License" in text
    assert "Version 2.0" in text


def test_no_account_no_login_in_cli_help_text():
    """The CLI MUST NOT mention accounts, login, signup, or any platform
    concept. The promise is `wise --help` reveals only file/text operations.
    """
    from wise.cli import _build_parser
    parser = _build_parser()
    help_text = parser.format_help().lower()
    forbidden_concepts = (
        "account", "login", "logout", "signup", "register",
        "subscription", "premium", "pro tier", "enterprise",
    )
    for concept in forbidden_concepts:
        assert concept not in help_text, (
            f"CLI help mentions {concept!r} — platform-creep violation"
        )


def test_verify_path_does_not_call_subprocess_or_fork():
    """Verification must not shell out. We cannot fully introspect runtime
    behavior here, but we can check that the runtime modules don't import
    subprocess, multiprocessing, or os.system in a way that would let them."""
    import os
    import wise
    pkg_dir = os.path.dirname(wise.__file__)
    runtime_modules = (
        "verify.py", "format.py", "proof.py", "seal.py", "digest.py",
    )
    forbidden = ("import subprocess", "from subprocess", "os.system(",
                 "os.popen(", "import multiprocessing", "from multiprocessing")
    for mod in runtime_modules:
        path = os.path.join(pkg_dir, mod)
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()
        for bad in forbidden:
            assert bad not in src, (
                f"{mod}: imports/uses {bad!r} — verification path must not shell out"
            )


def test_three_shipped_artifacts_are_named_in_release_notes():
    """The release notes MUST name the three top-level artifacts (.wiseproof,
    .wiseseal, .wiseexp). If a future change removes one without an entry,
    this test breaks."""
    import os
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    rn_path = os.path.join(repo_root, "RELEASE_NOTES.md")
    with open(rn_path, "r", encoding="utf-8") as f:
        text = f.read()
    for artifact in (".wiseproof", ".wiseseal", ".wiseexp"):
        assert artifact in text, f"RELEASE_NOTES.md no longer mentions {artifact}"


def test_pipe_fitter_credentials_are_in_the_code(tmp_path):
    """**The credentials this work carries are the ones in the code itself.**

    Not a CS degree. Not a credential. The work's authority comes from
    artifacts that any reader can re-derive from the spec. This test is
    a smoke check that those artifacts still exist where they should.
    """
    import os
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    must_exist = [
        "spec/WISEATA-v0.1.1.md",
        "SECURITY.md",
        "ROADMAP.md",
        "RELEASE_NOTES.md",
        "LICENSE",
        "tests/vectors/V1_demo_truth.md",
        "tests/test_locked_vectors.py",
        "tests/test_wisedigest_attack_suite.py",
        "research/WiseDigest-Lab.md",
        "research/WiseDigest-1.md",
        "research/WiseDigest-2.md",
        "research/WiseDigest-3.md",
        "demo.sh",
    ]
    for rel in must_exist:
        path = os.path.join(repo_root, rel)
        assert os.path.exists(path), (
            f"{rel} no longer exists — a credential the work carries is gone"
        )


# ============================================================================
# THE NAME TESTS — what makes this Trey Wise's, signed in code
# ============================================================================
# The Wise name is not branding. It is woven structurally through the
# protocol — through the file extensions, the digest name, the field names,
# the constants, and the doctrine. These tests guarantee the name stays
# where it belongs.


def test_the_wise_name_is_structural_not_decorative():
    """The string "WISE" must appear at the structural anchor points of the
    protocol: the format headers and the digest name. Replace "WISE" with
    "FOO" in these places and a port can no longer be conformant. The
    name is part of the math, not a sticker on top."""
    from wise import WISE_PROOF_HEADER, WISE_SEAL_HEADER, SUPPORTED_ALGORITHMS
    from wise.expansion import EXPANSION_HEADER

    assert WISE_PROOF_HEADER == "WISEPROOF-V1"
    assert WISE_SEAL_HEADER == "WISESEAL-V1"
    assert EXPANSION_HEADER == "WISEEXP-V1"
    assert "WiseDigest-0" in SUPPORTED_ALGORITHMS

    # All three headers begin with WISE.
    for h in (WISE_PROOF_HEADER, WISE_SEAL_HEADER, EXPANSION_HEADER):
        assert h.startswith("WISE"), (
            f"{h!r} no longer carries the WISE prefix — name compromised"
        )


def test_makers_mark_in_wisedigest_0_initial_state():
    """**The maker's mark is inside the cryptography.**

    WiseDigest-0's initial 8 lanes spell out a phrase, four bytes per lane:
        s0..s7 = "WISE" "ORIG" "IN00" "SPAS" "TRUE" "FAIL" "PROF" "001\\0"

    A cryptanalyst calls this "nothing up my sleeve" failure. Trey Wise
    calls it a signature in the math: every WiseDigest-0 output is rooted
    in those bytes. They cannot drift without the maker's hand.
    """
    from wise.digest import _INITIAL_STATE

    expected_phrase = b"WISEORIGIN00SPASTRUEFAILPROF001\x00"
    actual_bytes = b"".join(w.to_bytes(4, "big") for w in _INITIAL_STATE)
    assert actual_bytes == expected_phrase, (
        f"WiseDigest-0 initial state has drifted from the maker's mark.\n"
        f"  expected: {expected_phrase!r}\n"
        f"  got:      {actual_bytes!r}"
    )


def test_default_creator_is_wise_est_systems():
    """The shipped default for `origin.creator` is the maker's chosen
    label. A future contributor changing this default — or worse, leaving
    it blank — breaks this test. Operators MAY override; the SHIPPED
    default does not drift."""
    from wise import DEFAULT_CREATOR
    assert DEFAULT_CREATOR == "Wise.Est Systems"


def test_no_marketing_hype_in_runtime_strings():
    """**The voice is calm, never boastful.**

    Phrases that sell instead of describe must not appear in the runtime
    code, the spec, the README, or SECURITY.md. WISEATA does not say
    "world-class" — it says what it does and what it does not do.
    """
    import os
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    targets = [
        "src/wise/__init__.py",
        "src/wise/format.py",
        "src/wise/verify.py",
        "src/wise/proof.py",
        "src/wise/seal.py",
        "src/wise/digest.py",
        "src/wise/expansion.py",
        "src/wise/cli.py",
        "src/wise/errors.py",
        "spec/WISEATA-v0.1.1.md",
        "README.md",
        "SECURITY.md",
        "ROADMAP.md",
    ]
    forbidden_phrases = (
        "world-class", "world class",
        "best-in-class", "best in class",
        "revolutionary", "revolutionize",
        "unbreakable", "uncrackable",
        "military-grade", "military grade",
        "guaranteed secure",
        "next-generation", "next generation",
        "industry-leading", "industry leading",
        "cutting-edge", "cutting edge",
        "game-changing", "game changer",
        "disrupt the",
    )
    for rel in targets:
        path = os.path.join(repo_root, rel)
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as f:
            text = f.read().lower()
        for phrase in forbidden_phrases:
            assert phrase not in text, (
                f"{rel}: contains marketing-hype phrase {phrase!r} — "
                f"the voice is calm, never boastful"
            )


def test_no_lazy_markers_in_runtime_code():
    """**Pride: nothing half-finished bears the name.**

    Runtime modules must not carry TODO, FIXME, XXX, HACK, kludge, or
    'temporary' markers. Research notebooks may; the runtime cannot.
    The work that bears the Wise name is finished work.
    """
    import os
    import wise
    pkg_dir = os.path.dirname(wise.__file__)
    forbidden = ("TODO", "FIXME", "XXX", "HACK", "kludge", "KLUDGE",
                 "Temporary hack", "temporary hack", "for now", "FIX:")
    for fname in os.listdir(pkg_dir):
        if not fname.endswith(".py"):
            continue
        path = os.path.join(pkg_dir, fname)
        with open(path, "r", encoding="utf-8") as f:
            src = f.read()
        for marker in forbidden:
            assert marker not in src, (
                f"{fname}: contains lazy marker {marker!r} — work is unfinished"
            )


def test_henry_wayne_wise_iii_can_witness_himself():
    """**The maker can put his own witnessed name on the work.**

    A proof whose `origin.creator` is the literal string "Henry Wayne Wise III"
    must build, render, decode, and verify cleanly. The system that bears the
    name can be witnessed by the man who carries the name — using the name
    he carries, not the unwitnessed nickname.
    """
    import os
    import tempfile
    from wise.proof import build_text_proof_items, render
    from wise.format import decode
    from wise.verify import verify_text

    items = build_text_proof_items(
        "I built this for my Nana to see, and for the work to outlast me.\n",
        creator="Henry Wayne Wise III",
        created_at="2026-05-03T00:00:00Z",
    )
    assert items["origin.creator"] == "Henry Wayne Wise III"
    raw = render(items)
    parsed = decode(raw)
    assert parsed == items
    result = verify_text(
        "I built this for my Nana to see, and for the work to outlast me.\n",
        parsed,
    )
    assert result.status == "VERIFIED", (
        f"the maker cannot witness himself: {result.status} {result.detail}"
    )


def test_homoglyph_attack_on_the_witnessed_name_rejected():
    """**No one can pretend to be Henry Wayne Wise III, or to be Wise.**

    Cyrillic 'А' looks identical to Latin 'A'; fullwidth 'Ｗ' looks like 'W'.
    The H1 hardening rejects non-ASCII creator strings. This test targets
    the specific abuse: someone trying to sign as the witnessed name —
    Henry Wayne Wise III, or Wise.Est Systems — using homoglyphs. The
    verifier MUST reject every variant."""
    from wise.proof import build_file_proof_items
    import pytest
    import os
    import tempfile

    homoglyph_attempts = [
        # Attacks on the org name "Wise.Est Systems":
        "Ｗise.Est Systems",     # fullwidth W
        "Wisе.Est Systems",      # Cyrillic 'е' (U+0435)
        "Wise.Еst Systems",      # Cyrillic 'Е' (U+0415)
        # Attacks on the witnessed personal name "Henry Wayne Wise III":
        "Henrу Wayne Wise III",  # Cyrillic 'у' (U+0443) inside Henry
        "Henry Wayne Wisе III",  # Cyrillic 'е' inside Wise
        "Henry Wayne Wise ІІІ",  # Cyrillic 'І' (U+0406) for III
        "Ｈenry Wayne Wise III",  # fullwidth H
    ]
    with tempfile.TemporaryDirectory() as td:
        f = os.path.join(td, "demo.txt")
        with open(f, "wb") as fh:
            fh.write(b"truth\n")
        for impostor in homoglyph_attempts:
            with pytest.raises(ValueError):
                build_file_proof_items(f, creator=impostor, created_at="2026-05-03T00:00:00Z")


def test_the_predecessor_lineage_is_preserved():
    """**SPAS → WISEATA.** The earlier draft is not erased; it is
    archived and its existence acknowledged in the live spec. History
    is part of the work."""
    import os
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    archive_dir = os.path.join(repo_root, "spec", "archive")
    assert os.path.exists(archive_dir), "spec/archive/ removed — lineage broken"

    # The live spec must acknowledge the predecessor.
    spec_path = os.path.join(repo_root, "spec", "WISEATA-v0.1.1.md")
    with open(spec_path, "r", encoding="utf-8") as f:
        text = f.read()
    assert "SPAS" in text or "predecessor" in text, (
        "live spec no longer references the SPAS predecessor — lineage erased"
    )


def test_release_notes_have_dates():
    """**The work is timestamped.**

    Each release in RELEASE_NOTES.md carries a date. A future you in the
    middle of a long night looking back at this should see the day the
    decision was made. Dates are part of the credentialing."""
    import re
    import os
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    rn_path = os.path.join(repo_root, "RELEASE_NOTES.md")
    with open(rn_path, "r", encoding="utf-8") as f:
        text = f.read()
    # Match `## v0.1.x — YYYY-MM-DD` (allow extra suffix like "— description")
    pattern = re.compile(r"##\s+v0\.1\.\d+\s+—\s+\d{4}-\d{2}-\d{2}")
    matches = pattern.findall(text)
    assert len(matches) >= 2, (
        f"RELEASE_NOTES.md has fewer than 2 dated releases (found {len(matches)})"
    )


def test_disclosure_phrasing_uses_first_person_we():
    """**The voice is the maker's, not a corporate voice.**

    SECURITY.md uses "we" or "I" appropriately — first-person, owning
    statements rather than passive disclaimers. This is a soft test:
    we just confirm at least one first-person construct in SECURITY.md
    so a future copy-edit doesn't strip the maker's voice."""
    import os
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    sec_path = os.path.join(repo_root, "SECURITY.md")
    with open(sec_path, "r", encoding="utf-8") as f:
        text = f.read()
    first_person_markers = (" we ", " We ", "We will", " I ", " I'm ")
    assert any(m in text for m in first_person_markers), (
        "SECURITY.md no longer uses first-person voice — maker's voice stripped"
    )
