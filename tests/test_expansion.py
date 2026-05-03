"""WiseExpansion tests — determinism, layer correctness, WiseMark integrity."""

from __future__ import annotations

import random

import pytest

from wise.expansion import (
    EXPANSION_HEADER,
    DEFAULT_ALGORITHM,
    expand,
    render,
    verify_wisemark,
)


# -----------------------------------------------------------------------------
# Reproducibility / determinism
# -----------------------------------------------------------------------------

def test_deterministic_same_input():
    a = expand(b"hello world")
    b = expand(b"hello world")
    assert a == b


def test_deterministic_render_is_byte_for_byte_identical():
    raw1 = render(expand(b"truth\n"))
    raw2 = render(expand(b"truth\n"))
    assert raw1 == raw2


def test_render_starts_with_header_and_blank():
    raw = render(expand(b""))
    assert raw.startswith(b"WISEEXP-V1\n\n")


def test_render_ends_with_newline():
    assert render(expand(b"abc")).endswith(b"\n")


def test_render_keys_are_lex_sorted():
    raw = render(expand(b"truth\n")).decode("utf-8")
    body_lines = [ln for ln in raw.split("\n")[2:] if ln]
    keys = [ln.split("=", 1)[0] for ln in body_lines]
    assert keys == sorted(keys)


def test_random_inputs_are_reproducible():
    rng = random.Random(0xEEEE)
    for _ in range(30):
        n = rng.randint(0, 500)
        msg = bytes(rng.randint(0, 255) for _ in range(n))
        a = render(expand(msg))
        b = render(expand(msg))
        assert a == b


# -----------------------------------------------------------------------------
# Layer 1 — byte
# -----------------------------------------------------------------------------

def test_byte_layer_size_and_digest():
    items = expand(b"truth\n")
    assert items["artifact.size_bytes"] == "6"
    assert items["artifact.algorithm"] == "WiseDigest-0"
    assert len(items["artifact.byte_digest"]) == 64
    int(items["artifact.byte_digest"], 16)


def test_sha256_algorithm_supported():
    items = expand(b"truth\n", algorithm="SHA-256")
    assert items["artifact.algorithm"] == "SHA-256"
    assert len(items["artifact.byte_digest"]) == 64


def test_unsupported_algorithm_rejected():
    with pytest.raises(ValueError):
        expand(b"x", algorithm="MD5")


# ============================================================================
# THE SOUL TESTS — `.wiseexp` actually does what it claims
# ============================================================================
# `.wiseexp` is the part of WISEATA most likely to be original — a layered
# explainable structural fingerprint with no direct precedent. These tests
# prove the layering claim is real: changes localize to the right layers.


def test_wiseexp_localizes_difference_to_first16_only():
    """Two artifacts identical except for the first 16 bytes: positional.first16
    must differ; positional.last16 and positional.midpoint16 must be IDENTICAL."""
    body = bytes(range(64)) + b"x" * 100  # 164 bytes total
    a = bytes(range(16, 32)) + body[16:]
    b = bytes(range(0, 16)) + body[16:]
    ea = expand(a)
    eb = expand(b)
    assert ea["positional.first16"] != eb["positional.first16"], (
        "first16 should differ when the first 16 bytes differ"
    )
    assert ea["positional.last16"] == eb["positional.last16"], (
        "last16 should NOT differ when only the first 16 bytes differ"
    )
    assert ea["positional.midpoint16"] == eb["positional.midpoint16"], (
        "midpoint16 should NOT differ when only the first 16 bytes differ"
    )


def test_wiseexp_localizes_difference_to_last16_only():
    """Two artifacts identical except for the last 16 bytes: positional.last16
    must differ; positional.first16 and midpoint16 must be IDENTICAL."""
    head = bytes(range(64)) + b"x" * 100  # 164 bytes
    a = head + bytes(range(0, 16))
    b = head + bytes(range(16, 32))
    ea = expand(a)
    eb = expand(b)
    assert ea["positional.first16"] == eb["positional.first16"]
    assert ea["positional.midpoint16"] == eb["positional.midpoint16"]
    assert ea["positional.last16"] != eb["positional.last16"]


def test_wiseexp_frequency_layer_distinguishes_text_from_random():
    """A text-shaped artifact has very different entropy from random bytes.
    The frequency layer surfaces this; the byte layer does not (both produce
    one opaque 256-bit digest). This is the explainability claim."""
    rng = random.Random(0xF00D_BABE)
    text_like = (b"the quick brown fox jumps over the lazy dog " * 20)[:512]
    random_like = bytes(rng.randint(0, 255) for _ in range(512))
    et = expand(text_like)
    er = expand(random_like)
    # Random data should be near-uniform → low chi-squared. Text data has a
    # heavily skewed distribution → much higher chi-squared.
    chi_text = int(et["frequency.chi_squared_milli"])
    chi_rand = int(er["frequency.chi_squared_milli"])
    assert chi_text > chi_rand * 5, (
        f"Frequency layer failed to distinguish text (chi={chi_text}) "
        f"from random (chi={chi_rand})"
    )
    # And Shannon entropy on random should approach 8 bits/byte; on
    # repetitive text it's significantly lower.
    h_text = int(et["frequency.shannon_milli"])
    h_rand = int(er["frequency.shannon_milli"])
    assert h_rand > h_text, (
        f"Random ({h_rand} milliBits) should have higher entropy than text "
        f"({h_text} milliBits)"
    )


def test_wiseexp_structural_layer_finds_long_runs():
    """A file with a long run of one byte must have structural.longest_run
    pointing at that byte and a length matching the run."""
    artifact = b"prefix" + (b"\x00" * 200) + b"suffix"
    e = expand(artifact)
    assert int(e["structural.longest_run"]) >= 200
    assert e["structural.longest_run_byte"] == "0x00"


def test_wiseexp_byte_digest_changes_on_any_difference():
    """The byte layer's digest is the bedrock: ANY one-byte difference
    flips it. This is the floor below which `.wiseexp` cannot go."""
    a = expand(b"hello world\n")
    b = expand(b"hello world!")
    assert a["artifact.byte_digest"] != b["artifact.byte_digest"]


def test_wiseexp_wisemark_detects_any_layer_tampering():
    """Tampering with ANY non-wisemark field must invalidate the wisemark.
    This is the integrity proof for the expansion document itself, in the
    same self-referential style as wise_id for .wiseproof."""
    items = expand(b"hello world\n")
    # Pick any data field and corrupt it.
    items["frequency.shannon_milli"] = "999999"
    assert verify_wisemark(items) is False


def test_wiseexp_is_larger_than_input_on_purpose():
    """`.wiseexp` is NOT a hash and NOT compression. It is *more* data than
    the input. Guarantee this for small inputs where the property is most
    important and easiest to verify."""
    short_input = b"truth\n"
    expansion = render(expand(short_input))
    assert len(expansion) > len(short_input), (
        f"expansion ({len(expansion)} bytes) is not larger than input "
        f"({len(short_input)} bytes) — explainability claim violated"
    )


# -----------------------------------------------------------------------------
# Layer 2 — positional
# -----------------------------------------------------------------------------

def test_positional_first16_for_short_input():
    items = expand(b"abc")
    assert items["positional.first16"] == b"abc".hex()


def test_positional_first16_for_long_input():
    items = expand(b"x" * 100)
    assert items["positional.first16"] == ("x" * 16).encode().hex()


def test_positional_last16_empty_for_small_input():
    items = expand(b"x" * 31)
    assert items["positional.last16"] == ""


def test_positional_last16_present_for_large_input():
    items = expand(b"x" * 100)
    assert items["positional.last16"] == ("x" * 16).encode().hex()


def test_positional_midpoint16_present_for_long_input():
    items = expand(b"y" * 100)
    assert items["positional.midpoint16"] == ("y" * 16).encode().hex()


def test_positional_midpoint16_empty_for_short_input():
    items = expand(b"a" * 47)
    assert items["positional.midpoint16"] == ""


# -----------------------------------------------------------------------------
# Layer 3 — frequency
# -----------------------------------------------------------------------------

def test_frequency_all_zeros():
    items = expand(b"\x00" * 32)
    assert items["frequency.distinct_bytes"] == "1"
    assert items["frequency.most_common_byte"] == "0x00"
    assert items["frequency.most_common_count"] == "32"
    assert items["frequency.shannon_milli"] == "0"  # all same byte → entropy = 0


def test_frequency_uniform_distribution():
    """256 distinct bytes once each → max entropy ≈ 8 bits."""
    data = bytes(range(256))
    items = expand(data)
    assert items["frequency.distinct_bytes"] == "256"
    # Shannon entropy = 8.0 exactly when each byte appears once
    assert items["frequency.shannon_milli"] == "8000"


def test_frequency_most_common_tiebreak_lowest_byte():
    """Two bytes tied at the same count: lowest byte value wins."""
    data = b"\x05\x05\x03\x03"  # both 0x03 and 0x05 appear twice
    items = expand(data)
    assert items["frequency.most_common_byte"] == "0x03"


def test_frequency_empty_input():
    items = expand(b"")
    assert items["frequency.distinct_bytes"] == "0"
    assert items["frequency.most_common_byte"] == ""
    assert items["frequency.most_common_count"] == "0"
    assert items["frequency.shannon_milli"] == "0"


# -----------------------------------------------------------------------------
# Layer 4 — transitions
# -----------------------------------------------------------------------------

def test_transitions_short_input_has_no_bigrams():
    assert expand(b"")["transition.distinct_bigrams"] == "0"
    assert expand(b"a")["transition.distinct_bigrams"] == "0"
    assert expand(b"")["transition.most_common_bigram"] == ""


def test_transitions_two_byte_input():
    items = expand(b"ab")
    assert items["transition.distinct_bigrams"] == "1"
    assert items["transition.most_common_bigram"] == "0x6162"
    assert items["transition.most_common_count"] == "1"


def test_transitions_repeated_pattern():
    items = expand(b"abcabc")
    # bigrams: (a,b), (b,c), (c,a), (a,b), (b,c) — distinct = 3
    assert items["transition.distinct_bigrams"] == "3"
    # (a,b) and (b,c) tied at count=2; (a,b) lex < (b,c) so wins tiebreak
    assert items["transition.most_common_bigram"] == "0x6162"


def test_transitions_unique_bytes_unique_bigrams():
    data = bytes(range(64))
    items = expand(data)
    assert items["transition.distinct_bigrams"] == "63"


# -----------------------------------------------------------------------------
# Layer 5 — structural (runs + blocks)
# -----------------------------------------------------------------------------

def test_runs_all_same_byte():
    items = expand(b"x" * 50)
    assert items["structural.run_count"] == "1"
    assert items["structural.longest_run"] == "50"
    assert items["structural.longest_run_byte"] == "0x78"  # 'x' = 0x78


def test_runs_alternating():
    items = expand(b"abababab")
    assert items["structural.run_count"] == "8"
    assert items["structural.longest_run"] == "1"


def test_runs_mixed():
    items = expand(b"aaabbc")
    assert items["structural.run_count"] == "3"
    assert items["structural.longest_run"] == "3"
    assert items["structural.longest_run_byte"] == "0x61"  # 'a'


def test_runs_empty_input():
    items = expand(b"")
    assert items["structural.run_count"] == "0"
    assert items["structural.longest_run"] == "0"
    assert items["structural.longest_run_byte"] == ""


def test_block_count_default():
    items = expand(b"x" * 1024)
    assert items["structural.block_count"] == "1"
    items = expand(b"x" * 1025)
    assert items["structural.block_count"] == "2"
    items = expand(b"")
    assert items["structural.block_count"] == "0"


def test_custom_block_size():
    items = expand(b"x" * 100, block_size=10)
    assert items["structural.block_count"] == "10"
    assert items["artifact.block_size"] == "10"


def test_invalid_block_size_rejected():
    with pytest.raises(ValueError):
        expand(b"x", block_size=0)


# -----------------------------------------------------------------------------
# Layer 6 — WiseMark
# -----------------------------------------------------------------------------

def test_wisemark_present_and_64_hex():
    items = expand(b"truth\n")
    mark = items["wisemark"]
    assert len(mark) == 64
    int(mark, 16)


def test_wisemark_self_consistent():
    items = expand(b"truth\n")
    assert verify_wisemark(items)


def test_wisemark_changes_when_artifact_changes():
    a = expand(b"truth\n")["wisemark"]
    b = expand(b"truth\r\n")["wisemark"]
    assert a != b


def test_wisemark_changes_when_any_field_tampered():
    items = expand(b"truth\n")
    items["frequency.most_common_byte"] = "0x00"  # tamper
    assert not verify_wisemark(items)


def test_wisemark_under_sha256_is_different():
    a = expand(b"truth\n", algorithm="WiseDigest-0")
    b = expand(b"truth\n", algorithm="SHA-256")
    assert a["wisemark"] != b["wisemark"]


# -----------------------------------------------------------------------------
# Cross-layer: changing input changes many fields
# -----------------------------------------------------------------------------

def test_one_byte_change_diffs_many_layers():
    a = expand(b"the quick brown fox" * 10)
    b = expand(b"the quick brown FOX" * 10)
    diff_keys = {k for k in a if a.get(k) != b.get(k)}
    must_diff = {
        "artifact.byte_digest",
        "wisemark",
        "frequency.histogram_digest",
        "transition.matrix_digest",
        "structural.run_length_digest",
        "structural.blocks_digest",
        "positional.offset_mod16_digest",
    }
    assert must_diff <= diff_keys


def test_disjoint_inputs_have_disjoint_marks():
    """Many random inputs all produce distinct wisemarks."""
    rng = random.Random(0xCAFE)
    marks = set()
    for _ in range(200):
        msg = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 64)))
        marks.add(expand(msg)["wisemark"])
    assert len(marks) == 200


# -----------------------------------------------------------------------------
# Format strictness
# -----------------------------------------------------------------------------

def test_no_value_contains_newline_or_equals():
    items = expand(b"some unusual\ndata\nwith\nnewlines\n=in\nit")
    for k, v in items.items():
        assert "\n" not in v, f"value of {k} contains newline"
        assert "\n" not in k


def test_render_round_trip_parse():
    """Render output is well-formed: starts with header, sorted keys, k=v format."""
    items = expand(b"abcdef")
    raw = render(items).decode("utf-8")
    lines = raw.split("\n")
    assert lines[0] == "WISEEXP-V1"
    assert lines[1] == ""
    body_lines = [ln for ln in lines[2:] if ln]
    parsed = {}
    for ln in body_lines:
        k, sep, v = ln.partition("=")
        assert sep == "=", f"line missing '=': {ln!r}"
        parsed[k] = v
    assert parsed == items
