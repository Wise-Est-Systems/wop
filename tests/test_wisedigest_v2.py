"""WiseDigest-2 functional tests + locked reference vectors."""

from __future__ import annotations

import pytest

from wise.digest_v2 import ALGORITHM_NAME, WiseDigest2, digest_bytes, digest_stream


def test_algorithm_name():
    assert ALGORITHM_NAME == "WiseDigest-2"


def test_output_is_64_lowercase_hex():
    h = digest_bytes(b"truth\n")
    assert len(h) == 64
    int(h, 16)
    assert h == h.lower()


def test_deterministic():
    a = digest_bytes(b"truth\n")
    b = digest_bytes(b"truth\n")
    assert a == b


def test_streaming_equals_one_shot():
    one_shot = digest_bytes(b"truth\nmore\nbytes\n")
    h = WiseDigest2()
    h.update(b"truth\n")
    h.update(b"more\n")
    h.update(b"bytes\n")
    assert h.hexdigest() == one_shot


def test_streaming_arbitrary_partition():
    msg = b"the quick brown fox jumps over the lazy dog" * 7
    one_shot = digest_bytes(msg)
    for split in (1, 7, 31, 32, 33, 100, len(msg) - 1):
        h = WiseDigest2()
        h.update(msg[:split])
        h.update(msg[split:])
        assert h.hexdigest() == one_shot, f"split at {split} disagrees"


def test_digest_stream_helper():
    chunks = [b"alpha", b"", b"beta", b"gamma"]
    one_shot = digest_bytes(b"".join(chunks))
    assert digest_stream(chunks) == one_shot


def test_update_after_finalize_raises():
    h = WiseDigest2()
    h.update(b"x")
    _ = h.hexdigest()
    with pytest.raises(RuntimeError):
        h.update(b"more")


def test_hexdigest_idempotent():
    h = WiseDigest2()
    h.update(b"truth\n")
    a = h.hexdigest()
    b = h.hexdigest()
    assert a == b


def test_empty_input_well_defined():
    e1 = digest_bytes(b"")
    e2 = digest_bytes(b"")
    assert e1 == e2
    assert len(e1) == 64


# -------- Locked reference vectors --------

_LOCKED_VECTORS: list[tuple[str, bytes, str]] = [
    ("empty", b"", "d71b0a2b351e225730cf339b97dba675175c947930fc455cac218d98b9482e92"),
    ("single_a", b"a", "950369d2421573d98d5e0894c6974c176ab71be35bbcbe2fe2578d2f61624889"),
    ("ab", b"ab", "01c6128204b558ef3d91218e700303672d8e778eecc8a6aaa0e0214152f59db5"),
    ("abc", b"abc", "5dc7284b3b965577a328b90c3da7d53d5cbc4f42893856b50c17a5aaf9bf8063"),
    ("a_then_nul", b"a\x00", "9b51e47ff9d49f69480e849b2a6ed9d350941bb55a98473b5f81896121635f8c"),
    ("double_a", b"aa", "453e56b9fcf381aae7d72721a5dcbdd75b31f2ce7c48365b50e49a014872d7e5"),
    ("rate_minus_one", b"x" * 31, "908c240aeb13edb85bf5f55a2177d3b394ddc33eec351a91e71919710b574f99"),
    ("rate_exact", b"x" * 32, "d85a4c594e4892a99f006209d6142056c3de418c2986061e22746d7a0afe17c4"),
    ("rate_plus_one", b"x" * 33, "1ddaad028361dd969a742417daf3325287305434951a0635d0a75f30e401c512"),
    ("rate_double", b"x" * 64, "51098494a543ccd80e2f6196d06928ec325000bba8c36f59a24f73b725c46e16"),
    ("truth_newline", b"truth\n", "0f54f5736045a61006389726bba9703b63cfd7ffa3c9d174239d3cfac6fbde5d"),
    ("kilobyte_x", b"x" * 1024, "7a93b8c8828dd065a4214dfd23aa6edce00454a2726d812978e90e411b972525"),
    ("zero_byte", b"\x00", "282c571e36e25fdcb2acbdc168c9e208d1fc030f9dd780cdfffe7f726a0448be"),
    ("ones_block", b"\xff" * 32, "ea30799721eefac6bb01b046f87b06200ee0b52c35690fca54402b0aabf70f55"),
]


@pytest.mark.parametrize(
    "label,data,expected", _LOCKED_VECTORS, ids=[v[0] for v in _LOCKED_VECTORS]
)
def test_locked_vector(label: str, data: bytes, expected: str):
    assert digest_bytes(data) == expected, f"vector {label!r} drifted"


def test_short_inputs_distinct():
    digests = {digest_bytes(bytes([b])) for b in range(256)}
    assert len(digests) == 256, "two single-byte inputs collided"


def test_length_distinguishability():
    a = digest_bytes(b"a")
    aa = digest_bytes(b"aa")
    a_nul = digest_bytes(b"a\x00")
    nul_a = digest_bytes(b"\x00a")
    assert len({a, aa, a_nul, nul_a}) == 4


def test_block_boundary_distinguishability():
    digests = {digest_bytes(b"x" * n) for n in (31, 32, 33, 63, 64, 65)}
    assert len(digests) == 6
