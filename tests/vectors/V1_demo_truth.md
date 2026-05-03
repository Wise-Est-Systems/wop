# WISE — locked test vectors

Currently locked at **v0.1.1** (2026-05-03). These values are normative.
Any future implementation that disagrees with them is not WISE-compatible.

> **v0.1.0 → v0.1.1 changes:**
> - `origin.attestation = self_declared` is now a required field (H1/H5).
> - `origin.attestation` is **excluded** from `wise_id` and **included**
>   in `wise_seal`. As a result, `wise_id` is unchanged from v0.1.0;
>   `wise_seal` values changed.
> - `measurement.digest` is unchanged (it is over artifact bytes, not body).

## Vector V1 — `"truth\n"` file artifact

### Inputs

```
artifact bytes (hex) : 74 72 75 74 68 0a
artifact bytes (utf8): "truth\n"
artifact size_bytes  : 6
artifact.type        : file
artifact.name        : demo.txt
measurement.algorithm: WiseDigest-0
origin.attestation   : self_declared      ← v0.1.1 required field
origin.mode          : local
origin.created_at    : 2026-04-27T00:00:00Z
origin.creator       : Wise.Est Systems
```

### Locked outputs (WiseDigest-0)

```
measurement.digest = 6f9bbc98288bfa8efd7b8ae37c0a0053716bb819688c448d27781a7252fdfd50
wise_id            = 5b0c31df07626993e386434b760539beeb19b9d941c865851a31cd3efa60b091
wise_seal          = c627baaf3cba95f030092ae2b73c9aea26e38b021b0c5327e2c32ad1e9387c57
```

> `wise_id` is unchanged from v0.1.0 (origin.attestation is excluded from
> wise_id). `wise_seal` changed (origin.attestation is included in wise_seal).

## Vector V2 — empty text artifact

For determinism testing, an empty-input vector with the same identity inputs:

```
artifact bytes (hex) : (none)
artifact size_bytes  : 0
artifact.type        : text
artifact.encoding    : utf-8
artifact.name        : (empty string)
measurement.algorithm: WiseDigest-0
origin.attestation   : self_declared      ← v0.1.1 required field
origin.mode          : local
origin.created_at    : 2026-04-27T00:00:00Z
origin.creator       : Wise.Est Systems

measurement.digest   = 2800f3b2e070ed0ce2886ad3a6b5f71cc6182611f9c2e5cfbe57429a0e119d59
wise_id              = df879162047721c0d83d2c53f3a7656b54abdf6085544746bb256fc6e587115e
wise_seal            = 3883f96cf3fffcc4e4542dee8631aab2ef8576e173b6f668734630ea06b9ae45
```

---

# Byte-level digest vectors (cross-language conformance)

These are byte-level vectors for each WiseDigest candidate. They are the
fastest path for an independent implementation in another language to verify
its digest layer matches the Python reference.

**Format.** Each algorithm has one JSON code block containing an array of
vectors. A vector has either `input_hex` (literal hex bytes) or `input_repeat`
(`{"byte_hex": "XX", "count": N}` — the byte `XX` repeated `N` times). All
`output_hex` values are 64 lowercase hex characters (256 bits).

**Status legend.**
- `WiseDigest-0` — normative in v0.1.0, EXPERIMENTAL. See [`SECURITY.md`](../../SECURITY.md).
- `WiseDigest-1`, `-2`, `-3` — research candidates. NOT in production. See [`research/`](../../research/).

A conformant implementation MUST agree with `WiseDigest-0` and SHA-256.
Research candidates are optional. Disagreement on any vector means either
the implementation is wrong or the spec is ambiguous; both are bugs we want
reported.

---

## WiseDigest-0 (normative)

```json
[
  {"name": "empty",
   "input_hex": "",
   "output_hex": "2800f3b2e070ed0ce2886ad3a6b5f71cc6182611f9c2e5cfbe57429a0e119d59"},
  {"name": "truth_newline",
   "input_hex": "74727574680a",
   "input_text": "truth\n",
   "output_hex": "6f9bbc98288bfa8efd7b8ae37c0a0053716bb819688c448d27781a7252fdfd50"}
]
```

---

## WiseDigest-1 (research — sponge, BLAKE2b primitives, 12 rounds)

```json
[
  {"name": "empty",
   "input_hex": "",
   "output_hex": "83fdedf78ebe416c64f140f8480e55f5f302e1b79258f37833fd9288b2211e48"},
  {"name": "single_a",
   "input_hex": "61",
   "output_hex": "3a129072a4d8aa950011cc22b957433f40be87302720c20ad4e2b3533c426022"},
  {"name": "double_a",
   "input_hex": "6161",
   "output_hex": "97ea05405e692b56fc2dd1304fd574850901898c89483809f11aa6dc5fb76383"},
  {"name": "a_then_nul",
   "input_hex": "6100",
   "output_hex": "f245c18066316a26517b92ceb490d51c8175a85cfa3a5ab521f597cd02d316f3"},
  {"name": "abc",
   "input_hex": "616263",
   "output_hex": "7e2582aa328fd6d3b4b855680eeaa2587cced6d39be87570c662dbf60aace937"},
  {"name": "rate_minus_one",
   "input_repeat": {"byte_hex": "78", "count": 31},
   "output_hex": "a817a471e6e3738c6bb20ea289e1dd2d723398778d9c3982f735ab20e2950b35"},
  {"name": "rate_exact",
   "input_repeat": {"byte_hex": "78", "count": 32},
   "output_hex": "65f8fc3b53eccbcd4265ae88fb6d6fb46c8c4a4e1af3274443781d0f301964c6"},
  {"name": "rate_plus_one",
   "input_repeat": {"byte_hex": "78", "count": 33},
   "output_hex": "79851b32a1a1de2fe886772c77b0d78bc17b67ff6c0a5b4a773416115b84d8c2"},
  {"name": "rate_double",
   "input_repeat": {"byte_hex": "78", "count": 64},
   "output_hex": "5c02c4318e3ccf508c4c0aa3a739053d1bfe34dfcf73ecccb9383f321dbe7d6e"},
  {"name": "truth_newline",
   "input_hex": "74727574680a",
   "output_hex": "1cb228f3c35b471a9430ef4cd5802275bdb7302c24289d9d7186da7a0f6c8834"},
  {"name": "kilobyte_x",
   "input_repeat": {"byte_hex": "78", "count": 1024},
   "output_hex": "aaeafa051e12cb556fec4ca1fef92925a99913712f594ecc7f88d0b44e5fb712"}
]
```

---

## WiseDigest-2 (research — originality-first, no borrowed cores, 12 lanes)

```json
[
  {"name": "empty",
   "input_hex": "",
   "output_hex": "d71b0a2b351e225730cf339b97dba675175c947930fc455cac218d98b9482e92"},
  {"name": "single_a",
   "input_hex": "61",
   "output_hex": "950369d2421573d98d5e0894c6974c176ab71be35bbcbe2fe2578d2f61624889"},
  {"name": "ab",
   "input_hex": "6162",
   "output_hex": "01c6128204b558ef3d91218e700303672d8e778eecc8a6aaa0e0214152f59db5"},
  {"name": "abc",
   "input_hex": "616263",
   "output_hex": "5dc7284b3b965577a328b90c3da7d53d5cbc4f42893856b50c17a5aaf9bf8063"},
  {"name": "a_then_nul",
   "input_hex": "6100",
   "output_hex": "9b51e47ff9d49f69480e849b2a6ed9d350941bb55a98473b5f81896121635f8c"},
  {"name": "double_a",
   "input_hex": "6161",
   "output_hex": "453e56b9fcf381aae7d72721a5dcbdd75b31f2ce7c48365b50e49a014872d7e5"},
  {"name": "rate_minus_one",
   "input_repeat": {"byte_hex": "78", "count": 31},
   "output_hex": "908c240aeb13edb85bf5f55a2177d3b394ddc33eec351a91e71919710b574f99"},
  {"name": "rate_exact",
   "input_repeat": {"byte_hex": "78", "count": 32},
   "output_hex": "d85a4c594e4892a99f006209d6142056c3de418c2986061e22746d7a0afe17c4"},
  {"name": "rate_plus_one",
   "input_repeat": {"byte_hex": "78", "count": 33},
   "output_hex": "1ddaad028361dd969a742417daf3325287305434951a0635d0a75f30e401c512"},
  {"name": "rate_double",
   "input_repeat": {"byte_hex": "78", "count": 64},
   "output_hex": "51098494a543ccd80e2f6196d06928ec325000bba8c36f59a24f73b725c46e16"},
  {"name": "truth_newline",
   "input_hex": "74727574680a",
   "output_hex": "0f54f5736045a61006389726bba9703b63cfd7ffa3c9d174239d3cfac6fbde5d"},
  {"name": "kilobyte_x",
   "input_repeat": {"byte_hex": "78", "count": 1024},
   "output_hex": "7a93b8c8828dd065a4214dfd23aa6edce00454a2726d812978e90e411b972525"},
  {"name": "zero_byte",
   "input_hex": "00",
   "output_hex": "282c571e36e25fdcb2acbdc168c9e208d1fc030f9dd780cdfffe7f726a0448be"},
  {"name": "ones_block",
   "input_repeat": {"byte_hex": "ff", "count": 32},
   "output_hex": "ea30799721eefac6bb01b046f87b06200ee0b52c35690fca54402b0aabf70f55"}
]
```

---

## WiseDigest-3 (research — 793-bit live state, 13 × 61-bit lanes)

```json
[
  {"name": "empty",
   "input_hex": "",
   "output_hex": "94f8a850b58985834a7e72864c0db6757d9864c5d5ab4ff31188b6323c43e999"},
  {"name": "single_a",
   "input_hex": "61",
   "output_hex": "339b6fd3cf5564a43b6aeaf4fb5541c7d81971da6a13f5b5cbac9f69f2d9e716"},
  {"name": "ab",
   "input_hex": "6162",
   "output_hex": "dd6bf5baf04fd981bd1c8c5e5c2502ae9f89e2a651eda341b253c6f12bf4eb46"},
  {"name": "abc",
   "input_hex": "616263",
   "output_hex": "7316f497541bb373d07a30be6fe0af0a25722b5c4adc98236fb27e0575ecec23"},
  {"name": "a_then_nul",
   "input_hex": "6100",
   "output_hex": "ba9e8aeff70b5d4b9e0e498fc6fd89feccb0a600b97de5e2896703d63deb7d80"},
  {"name": "double_a",
   "input_hex": "6161",
   "output_hex": "a03cbdbf5c6b5b90b1f8c9b660146a25aeeaa6030a0af8ca843e53aae2d0a2e6"},
  {"name": "rate_minus_one",
   "input_repeat": {"byte_hex": "78", "count": 31},
   "output_hex": "b3fad47a344d3aa014e6099959f6b3907bc25dc4d3bdaee8c94bc6ca4cd44f08"},
  {"name": "rate_exact",
   "input_repeat": {"byte_hex": "78", "count": 32},
   "output_hex": "4bc92233a1bb9a2748eccb8352e9b762c8e2e737832702dc9a8f4fbb45cf7c57"},
  {"name": "rate_plus_one",
   "input_repeat": {"byte_hex": "78", "count": 33},
   "output_hex": "83617500dfb4735370474a67b321ff844a6394ef3ec2d660aa21e994aa8597a3"},
  {"name": "rate_double",
   "input_repeat": {"byte_hex": "78", "count": 64},
   "output_hex": "ffb348a0242010a62a02defaa06fddef3901e2c07c7ecd454cd774961b3aab45"},
  {"name": "truth_newline",
   "input_hex": "74727574680a",
   "output_hex": "f3163db0ed191994acd9a309a6dc7eee6d08560b670b31f182c8ade17ccb89c8"},
  {"name": "kilobyte_x",
   "input_repeat": {"byte_hex": "78", "count": 1024},
   "output_hex": "d85c906e3e19cdd7c2536fa7fa06b29f0ab450f63957d2d9524f6af051d782ee"},
  {"name": "zero_byte",
   "input_hex": "00",
   "output_hex": "79ff08e1dfab4ccc95c7275da0c00752be91c69872b54dcf0fd939e8cbbe24ec"},
  {"name": "ones_block",
   "input_repeat": {"byte_hex": "ff", "count": 32},
   "output_hex": "9462c1a98d3ce53e97a67860e0b280b737fe6b77346c4f54792bf55f17aaaa9a"}
]
```
