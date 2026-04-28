# WISE v0.1.0 — locked test vector V1: "truth\n" file artifact

These values are normative. Any future implementation that disagrees with
them is not WISE-compatible.

## Inputs

```
artifact bytes (hex) : 74 72 75 74 68 0a
artifact bytes (utf8): "truth\n"
artifact size_bytes  : 6
artifact.type        : file
artifact.name        : demo.txt
measurement.algorithm: WiseDigest-0
origin.mode          : local
origin.created_at    : 2026-04-27T00:00:00Z
origin.creator       : Wise.Est Systems
```

## Locked outputs (WiseDigest-0)

```
measurement.digest = 6f9bbc98288bfa8efd7b8ae37c0a0053716bb819688c448d27781a7252fdfd50
wise_id            = 5b0c31df07626993e386434b760539beeb19b9d941c865851a31cd3efa60b091
wise_seal          = 5e9a0ddd0e23a9393302ae6c39e2f31692b597aabad4b89482d1483765dfa564
```

## Locked outputs — empty text artifact (WiseDigest-0)

For determinism testing, an empty-input vector with the same identity inputs:

```
artifact bytes (hex) : (none)
artifact size_bytes  : 0
artifact.type        : text
artifact.encoding    : utf-8
artifact.name        : (empty string)
measurement.algorithm: WiseDigest-0
origin.mode          : local
origin.created_at    : 2026-04-27T00:00:00Z
origin.creator       : Wise.Est Systems

measurement.digest   = 2800f3b2e070ed0ce2886ad3a6b5f71cc6182611f9c2e5cfbe57429a0e119d59
wise_id              = df879162047721c0d83d2c53f3a7656b54abdf6085544746bb256fc6e587115e
wise_seal            = edc67a15d60c20283f175dbfb87f2b98e46fd1f622e80cc726882e3d2323b94b
```
