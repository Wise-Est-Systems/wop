# WISE ORIGIN PROTOCOL

## Technical Specification v0.1.0-draft

### Codename: **Self-Proving Artifact System — SPAS**

---

## 0. Core Claim

**SPAS defines how a digital object proves its own existence, identity, origin, integrity, and rejection state without needing a platform, account, server, blockchain, or third-party trust system.**

The law:

> **An artifact is not accepted as real unless its proof reproduces.**

---

# 1. Terminology

### Artifact

Any digital object being proven.

Examples:

```text
file
text
image
video
AI output
contract
dataset
folder
message
```

### Proof

A deterministic record describing what the artifact was at a point in time.

### Seal

The final proof state after the artifact has been measured.

### Verification

The act of recomputing the artifact's identity and comparing it to the proof.

### Native Artifact

An artifact born inside SPAS rules.

### Imported Artifact

An artifact created outside SPAS, then sealed afterward.

### Dead Artifact

An artifact whose proof fails.

---

# 2. Status Codes

Every verification MUST return exactly one terminal status:

```text
VERIFIED
TAMPERED
INVALID_PROOF
UNREADABLE_ARTIFACT
UNSUPPORTED_VERSION
UNSUPPORTED_ALGORITHM
```

No "maybe."
No confidence score.
No AI judgment.

---

# 3. System Law

## Law 1 — No Silent Trust

A verifier MUST NOT trust metadata, filenames, extensions, timestamps, platform labels, or user claims.

Only measured bytes count.

---

## Law 2 — Byte Reality

For file artifacts:

```text
artifact_identity = exact raw byte sequence
```

Not visual appearance.
Not filename.
Not "same content."
Exact bytes.

---

## Law 3 — Canonical Proof Reality

Proofs MUST be encoded as canonical JSON:

```text
UTF-8
sorted object keys
no insignificant whitespace
no trailing commas
no comments
no NaN
no Infinity
```

Canonical serialization rule:

```python
json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
```

---

## Law 4 — Reproduction or Death

A proof is valid only if a verifier can independently reproduce the expected artifact measurement.

If reproduction fails:

```text
status = TAMPERED
```

---

# 4. SPAS Proof Object

Minimum proof:

```json
{
  "spas_version": "0.1.0",
  "proof_format": "spas-proof-v1",
  "artifact": {
    "type": "file",
    "name": "demo.txt",
    "size_bytes": 5
  },
  "measurement": {
    "algorithm": "WISE-DIGEST-0",
    "digest": "..."
  },
  "origin": {
    "mode": "local",
    "created_at_utc": "2026-04-27T00:00:00Z",
    "creator_label": "Wise.Est Systems"
  },
  "proof_id": "...",
  "status_rule": "REPRODUCE_OR_REJECT"
}
```

---

# 5. Proof ID

`proof_id` is NOT the artifact digest.

It is the digest of the canonical proof body **without** the `proof_id` field.

Procedure:

```text
1. Remove proof_id.
2. Canonicalize proof JSON.
3. Digest canonical bytes.
4. Store result as proof_id.
```

So:

```text
artifact_digest = identity of artifact
proof_id = identity of proof
```

---

# 6. Artifact Types

## 6.1 File Artifact

Measured as raw bytes:

```text
read file in binary mode
do not normalize line endings
do not decode text
do not trim whitespace
do not use file modified time
```

---

## 6.2 Text Artifact

Measured as UTF-8 bytes of the exact input string.

Rules:

```text
No trimming
No smart quote conversion
No newline normalization unless explicitly declared
```

Proof MUST include:

```json
"artifact": {
  "type": "text",
  "encoding": "utf-8",
  "size_bytes": 11
}
```

---

## 6.3 Directory Artifact

A directory proof MUST measure:

```text
relative path
file size
file digest
entry type
```

Directory ordering MUST be lexical byte-order ascending.

Directory proof root:

```text
directory_digest = digest(canonical_directory_manifest)
```

---

# 7. WISE-DIGEST-0

This is your experimental digest layer.

Truth note:

> This is not yet a globally trusted cryptographic primitive.
> It is a SPAS-native measurement function candidate.

For production security, SPAS can support `SHA-256`.

For native experimentation, define:

```text
WISE-DIGEST-0
```

Purpose:

```text
deterministic artifact measurement
not claimed collision-resistant yet
not claimed cryptographically secure yet
```

Output:

```text
64 lowercase hexadecimal characters
256-bit output
```

Internal state:

```text
8 unsigned 32-bit words
```

Initial state:

```text
s0 = 0x57495345   // "WISE"
s1 = 0x4f524947   // "ORIG"
s2 = 0x494e3030   // "IN00"
s3 = 0x53504153   // "SPAS"
s4 = 0x54525545   // "TRUE"
s5 = 0x4641494c   // "FAIL"
s6 = 0x50524f46   // "PROF"
s7 = 0x30303100   // "001\0"
```

For each byte `b` at index `i`:

```text
j = i mod 8

s[j] = s[j] XOR b
s[j] = ROTL32(s[j], (b mod 31) + 1)
s[j] = (s[j] + 0x9E3779B9 + i) mod 2^32
s[(j+1) mod 8] = s[(j+1) mod 8] XOR s[j]
s[(j+3) mod 8] = ROTL32(s[(j+3) mod 8], 7) XOR s[j]
```

Finalization:

```text
repeat 16 rounds:
  for j in 0..7:
    s[j] = s[j] XOR s[(j+1) mod 8]
    s[j] = ROTL32(s[j], 11)
    s[j] = (s[j] + s[(j+5) mod 8] + 0xA5A5A5A5) mod 2^32
```

Digest output:

```text
hex(s0 || s1 || s2 || s3 || s4 || s5 || s6 || s7)
```

Again: this is **native**, but experimental.

---

# 8. Verification Algorithm

Input:

```text
artifact
proof
```

Steps:

```text
1. Parse proof JSON.
2. Validate required fields.
3. Validate proof_format.
4. Validate spas_version.
5. Validate algorithm support.
6. Recompute artifact digest.
7. Compare recomputed digest to proof.measurement.digest.
8. Recompute proof_id.
9. Compare recomputed proof_id to proof.proof_id.
10. Return terminal status.
```

Decision table:

```text
proof JSON unreadable            -> INVALID_PROOF
missing required field           -> INVALID_PROOF
unsupported version              -> UNSUPPORTED_VERSION
unsupported algorithm            -> UNSUPPORTED_ALGORITHM
artifact cannot be read          -> UNREADABLE_ARTIFACT
artifact digest mismatch         -> TAMPERED
proof_id mismatch                -> INVALID_PROOF
all checks pass                  -> VERIFIED
```

---

# 9. CLI Specification

Command namespace:

```text
spas
```

## Create file proof

```bash
spas prove file demo.txt --out demo.spas.json
```

## Verify file

```bash
spas verify file demo.txt --proof demo.spas.json
```

## Prove text

```bash
spas prove text "hello world" --out text.spas.json
```

## Verify text

```bash
spas verify text "hello world" --proof text.spas.json
```

## Inspect proof

```bash
spas inspect demo.spas.json
```

---

# 10. Exit Codes

```text
0 = VERIFIED or proof created
1 = TAMPERED
2 = INVALID_PROOF
3 = UNREADABLE_ARTIFACT
4 = UNSUPPORTED_VERSION
5 = UNSUPPORTED_ALGORITHM
6 = USER_ERROR
```

---

# 11. Output Rules

Machine mode:

```json
{
  "status": "VERIFIED",
  "proof_id": "...",
  "artifact_digest": "..."
}
```

Tampered mode:

```json
{
  "status": "TAMPERED",
  "expected_digest": "...",
  "observed_digest": "..."
}
```

Human mode:

```text
VERIFIED
TAMPERED
INVALID_PROOF
```

---

# 12. Native SPAS File Extension

Proof files:

```text
.spas.json
```

Native packed artifacts:

```text
.spas
```

Future archive layout:

```text
artifact.bin
proof.spas.json
manifest.spas.json
```

---

# 13. Core Identity Statement

The technical identity of SPAS:

> **SPAS is a deterministic proof law for artifacts where existence, origin, and integrity are accepted only through reproducible measurement.**

Simpler:

> **If it cannot reproduce, it is rejected.**

---

# 14. First Build Target

Version:

```text
SPAS v0.1.0
```

Must support:

```text
file proof
file verify
text proof
text verify
proof inspect
WISE-DIGEST-0
SHA-256 optional fallback
canonical JSON
strict terminal statuses
```

This is the spec.

---

# 15. Canonical Byte Encoding (CRITICAL)

Everything depends on this. If this is wrong → entire system breaks.

---

## 15.1 File Read Rules

MUST:

```text
open(path, "rb")
read raw bytes exactly
```

MUST NOT:

```text
decode text
strip whitespace
convert line endings
skip null bytes
buffer-transform content
```

---

## 15.2 Text Encoding Rules

Input string → bytes:

```text
UTF-8 encoding
NO normalization
NO trimming
NO hidden transformations
```

Example:

```text
"hello\n" ≠ "hello"
```

Different digest. Always.

---

## 15.3 Canonical JSON Rules (STRICT)

All proof JSON MUST be serialized as:

```python
json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
```

Additional rules:

```text
keys sorted lexicographically (byte order)
strings must be UTF-8
no floating-point NaN or Infinity
no trailing commas
no comments
```

Failure → `INVALID_PROOF`

---

# 16. Attack Surface Model

You are not building a toy.
We define what attackers try to break.

---

## 16.1 Attack Classes

### A1 — Byte Mutation

Modify file content:

```text
flip 1 byte
insert newline
change encoding
```

Expected result:

```text
TAMPERED
```

---

### A2 — Metadata Spoofing

Change:

```text
filename
timestamp
file extension
OS metadata
```

Expected:

```text
VERIFIED (unchanged bytes)
```

---

### A3 — Proof Tampering

Modify:

```text
digest field
proof_id
timestamp
artifact name
```

Expected:

```text
INVALID_PROOF
```

---

### A4 — Encoding Drift

Example:

```text
Windows \r\n vs Unix \n
```

Expected:

```text
TAMPERED
```

(No normalization allowed)

---

### A5 — Truncation Attack

Remove bytes from end:

Expected:

```text
TAMPERED
```

---

### A6 — Replay Attack

Re-use valid proof on different artifact:

Expected:

```text
TAMPERED
```

---

### A7 — Partial Read Attack

If system reads only part of file:

Expected:

```text
INVALID_PROOF (size mismatch)
```

---

# 17. Artifact Size Enforcement

Proof MUST include:

```json
"size_bytes": 12345
```

Verification MUST check:

```text
actual_size == proof.size_bytes
```

Mismatch:

```text
TAMPERED
```

---

# 18. Deterministic Time Handling

SPAS does NOT trust system time.

---

## 18.1 Created Time

```json
"created_at_utc": "2026-04-27T14:32:11Z"
```

Rules:

```text
ISO 8601 only
UTC only
Z suffix required
no timezone offsets
```

---

## 18.2 Time Trust Level

SPAS treats time as:

```text
DECLARED, NOT VERIFIED
```

Meaning:

```text
time is recorded, not trusted
```

Future versions may add time authorities.

---

# 19. Proof Immutability

Once created:

```text
proof MUST NOT change
```

Any mutation:

```text
INVALID_PROOF
```

---

# 20. Proof Validation Schema

Minimum required fields:

```text
spas_version
proof_format
artifact
measurement
origin
proof_id
```

Missing ANY:

```text
INVALID_PROOF
```

---

# 21. Artifact Identity Expansion (FUTURE READY)

Prepare for:

```text
multi-file bundles
AI outputs
streamed data
network packets
```

SPAS identity model:

```text
artifact_identity = deterministic byte representation
```

Everything reduces to bytes.

---

# 22. Deterministic Directory Spec (FULL)

Directory proof MUST build manifest:

```json
[
  {
    "path": "a.txt",
    "type": "file",
    "size": 10,
    "digest": "..."
  },
  {
    "path": "sub/b.txt",
    "type": "file",
    "size": 20,
    "digest": "..."
  }
]
```

Rules:

```text
paths must be relative
paths must use forward slashes
entries sorted lexicographically
```

Directory digest:

```text
digest(canonical_json(manifest))
```

---

# 23. CLI Behavior (STRICT MODE)

---

## 23.1 No Silent Overwrites

If proof file exists:

```text
FAIL unless --force
```

---

## 23.2 Output Modes

### Human

```text
VERIFIED
TAMPERED
INVALID_PROOF
```

### JSON

```bash
--json
```

Returns machine-readable output.

---

## 23.3 Quiet Mode

```bash
--quiet
```

Only exit codes matter.

---

# 24. Error Model

Errors MUST be explicit:

```text
"Proof missing required field: measurement.digest"
"Unsupported algorithm: WISE-DIGEST-9"
"Artifact unreadable: permission denied"
```

No vague errors.

---

# 25. Deterministic Build Requirement

Given:

```text
same artifact
same algorithm
same proof structure
```

Output MUST be:

```text
identical proof file (bit-for-bit)
```

No randomness allowed.

---

# 26. Non-Goals (IMPORTANT)

SPAS does NOT:

```text
prove truth
prove authorship (yet)
prevent copying
prevent duplication
prevent replay
```

SPAS ONLY proves:

```text
integrity
identity
reproducibility
```

---

# 27. Extension Layer (FUTURE)

Where this becomes more powerful later:

---

## 27.1 Identity Layer

Add:

```text
public key
signature
```

Then:

```text
artifact = tied to identity
```

---

## 27.2 Lineage Layer

Add:

```text
parent_proof_id
```

Now:

```text
you can track history
```

---

## 27.3 Policy Layer

Add rules:

```text
reject unsigned artifacts
reject untrusted origins
require chain validation
```

---

## 27.4 WIN Layer Integration

This becomes:

> **The base truth layer of Wise.Est Systems**

---

# 28. Test Vectors (MANDATORY)

Example:

---

## Input:

```text
echo "truth" > demo.txt
```

---

## Expected:

```text
digest = X
proof_id = Y
```

Store known outputs.

Verification MUST match exactly.

---

# 29. System Identity

Final statement:

> **SPAS is not a tool.
> It is a deterministic law system that defines when an artifact is accepted or rejected based on reproducible measurement.**

---

# 30. SPEC LOCK (v0.1.0)

This section resolves every ambiguity in §0–§29. Where this section conflicts with earlier text, this section wins.

---

## 30.1 WISE-DIGEST-0 — mutation order (resolves Q1)

The per-byte loop in §7 mutates state sequentially. After the three operations on `s[j]`, the value of `s[j]` used in subsequent lines of the same byte round is the **current mutated value**, not a pre-round snapshot.

Reference per-byte round:

```text
j = i mod 8
s[j] = s[j] XOR b
s[j] = ROTL32(s[j], (b mod 31) + 1)
s[j] = (s[j] + 0x9E3779B9 + i) mod 2^32
s[(j+1) mod 8] = s[(j+1) mod 8] XOR s[j]    # uses MUTATED s[j]
s[(j+3) mod 8] = ROTL32(s[(j+3) mod 8], 7) XOR s[j]   # uses MUTATED s[j]
```

---

## 30.2 WISE-DIGEST-0 — finalization state reading (resolves Q2)

The 16-round finalization loop also mutates state sequentially. When `j=3` reads `s[(j+5) mod 8] = s[0]`, it reads the **already-mutated** value of `s[0]` from earlier in the same round. No round snapshot.

---

## 30.3 WISE-DIGEST-0 — length absorption (resolves Q3)

Before finalization, the input length in **bits** is appended to the byte stream as **8 bytes, big-endian**, and processed through the same per-byte loop using the next 8 sequential indices `i`.

```text
input_byte_count = N
input_bit_length = N * 8                  (computed in 64-bit unsigned)
length_bytes = big_endian_8(input_bit_length)

for k in 0..7:
    process_byte(length_bytes[k], i = N + k)

then run 16-round finalization
```

---

## 30.4 WISE-DIGEST-0 — empty input (resolves Q4)

Empty input is valid. The per-byte loop runs zero times, then the 8-byte length absorption (with length = 0) runs, then finalization runs. Result is a fixed constant for `b""`.

---

## 30.5 Identity model — `proof_id` and `seal_id` (resolves Q5)

Every proof carries TWO identity fields:

```text
proof_id  = digest of the proof body with proof_id, seal_id, and origin.created_at_utc REMOVED
seal_id   = digest of the proof body with proof_id and seal_id REMOVED (created_at_utc INCLUDED)
```

Procedure to compute, given a proof object `P`:

```text
1. P_pure = deep_copy(P); remove P_pure.proof_id, P_pure.seal_id, P_pure.origin.created_at_utc
2. proof_id = digest(canonical_json(P_pure))
3. P_sealed = deep_copy(P); remove P_sealed.proof_id, P_sealed.seal_id
4. seal_id  = digest(canonical_json(P_sealed))
```

Consequences:
- Same artifact, same algorithm, same creator label → identical `proof_id` across all sealings on all machines forever.
- Different creation time → identical `proof_id`, different `seal_id`.

---

## 30.6 `creator_label` — user-configurable (resolves Q6)

Default value when `--creator` is not passed:

```text
"Wise.Est Systems"
```

Override:

```bash
spas prove file demo.txt --creator "Trey / Wise.Est Systems"
```

`creator_label` IS part of the digested proof body, so it affects both `proof_id` and `seal_id`.

---

## 30.7 `origin.mode` — allowed values (resolves Q7)

v0.1.0 legal values:

```text
local
imported
```

Unknown value → `INVALID_PROOF`.

---

## 30.8 Version enforcement (resolves Q8)

Both fields must match exactly for v0.1.0 verifiers:

```text
spas_version  == "0.1.0"
proof_format  == "spas-proof-v1"
```

Either mismatch → `UNSUPPORTED_VERSION`.

---

## 30.9 Verification ordering — size vs digest (resolves Q9)

Size mismatch is checked **before** the digest is computed. On mismatch, return `TAMPERED` immediately without reading or hashing the rest of the artifact.

---

## 30.10 Verification ordering — proof_id vs artifact (resolves Q10)

`proof_id` is recomputed and compared **before** the artifact is opened. A bad proof short-circuits to `INVALID_PROOF`; the artifact is never read.

Final v0.1.0 verification order (replaces §8):

```text
1. Parse proof JSON (fail → INVALID_PROOF)
2. Validate required fields per §20 (fail → INVALID_PROOF)
3. Validate spas_version + proof_format per §30.8 (fail → UNSUPPORTED_VERSION)
4. Validate algorithm support (fail → UNSUPPORTED_ALGORITHM)
5. Validate origin.mode per §30.7 (fail → INVALID_PROOF)
6. Recompute proof_id; compare (fail → INVALID_PROOF)
7. Recompute seal_id; compare (fail → INVALID_PROOF)
8. Stat artifact for size; compare to artifact.size_bytes (fail → TAMPERED)
9. Open artifact (fail → UNREADABLE_ARTIFACT)
10. Recompute artifact digest; compare (fail → TAMPERED)
11. Return VERIFIED
```

---

## 30.11 Text artifact content (resolves Q11)

The text content itself is NEVER stored inside the proof. Only its digest, encoding, and `size_bytes` are recorded. Verifying a text proof requires the verifier to re-supply the exact original string at the CLI.

---

## 30.12 `artifact.name` — metadata only (resolves Q12)

`artifact.name` is included in the proof JSON for human readability. It is NOT part of the digested body for `proof_id` or `seal_id` (it is excluded alongside `proof_id`, `seal_id`, and `origin.created_at_utc` during canonicalization for hashing).

Verifier MUST ignore `name` when deciding VERIFIED vs TAMPERED. Only artifact bytes and `artifact.size_bytes` matter.

---

## 30.13 Directory digest algorithm (resolves Q13)

All nested file digests inside a directory manifest use the same algorithm declared in `proof.measurement.algorithm`. Mixing algorithms within one proof is forbidden → `INVALID_PROOF`.

---

## 30.14 Special files in directory walks (resolves Q14)

If `spas prove dir` encounters any of:

```text
symlink
socket
fifo
device file (block or character)
```

→ exit with `USER_ERROR`. SPAS does not silently include, exclude, or transform these.

Empty directories are skipped (a directory with no files contributes no manifest entries).

---

## 30.15 Path normalization (resolves Q15)

Paths in directory manifests are recorded byte-for-byte as the OS reports them. No lowercasing, no Unicode normalization, no whitespace trimming. Path separator is converted from native to `/` and that is the only transformation permitted.

---

## 30.16 Test vectors — hex-locked (resolves Q16)

Test vectors are defined as exact hex byte sequences, never as shell commands. Reference vector for v0.1.0:

```text
artifact name : demo.txt
artifact bytes (hex): 74 72 75 74 68 0a
artifact bytes (ascii): "truth\n"
size_bytes    : 6
```

Concrete digests, `proof_id`, and `seal_id` for this vector are computed by the v0.1.0 reference implementation and stored in `tests/vectors/`.

---

## 30.17 Required proof field list (supersedes §20)

For v0.1.0, every proof MUST contain exactly these top-level fields:

```text
spas_version
proof_format
artifact
measurement
origin
proof_id
seal_id
status_rule
```

Required nested fields:

```text
artifact.type           (enum: "file" | "text" | "directory")
artifact.name           (string; for "text" artifacts, empty string "")
artifact.size_bytes     (non-negative integer)
artifact.encoding       (only for type="text"; must be "utf-8")

measurement.algorithm   (enum: "WISE-DIGEST-0" | "SHA-256")
measurement.digest      (lowercase hex string)

origin.mode             (enum: "local" | "imported")
origin.created_at_utc   (ISO 8601, UTC, Z suffix)
origin.creator_label    (string)

status_rule             (must equal "REPRODUCE_OR_REJECT")
```

Any missing or extra field → `INVALID_PROOF`. v0.1.0 is strict; future versions may permit forward-compatible extension fields.

---

# 31. Wise Origin Protocol — WISE redesign (LOCKED)

§0–§30 describe SPAS, the predecessor draft. SPAS is preserved here for the audit trail. The live system is **WISE / Wise Origin Protocol**, defined in this section. Where this section conflicts with §0–§30, this section wins.

---

## 31.1 Names and identity

```text
System name      Wise Origin Protocol (WISE)
CLI binary       wise
Owner            Wise.Est Systems
Digest algorithm WiseDigest-0  (same math as WISE-DIGEST-0, new label)
Production hash  SHA-256 (optional fallback)
```

---

## 31.2 File formats

```text
.wiseproof   plain-text proof file (WISEPROOF-V1)
.wiseseal    container holding artifact + embedded proof (WISESEAL-V1)
```

JSON is forbidden. Standard archive formats (zip, tar, gzip) are forbidden in v0.1.0.

---

## 31.3 WISEPROOF-V1 format

A `.wiseproof` file is UTF-8 text. The first line is exactly:

```
WISEPROOF-V1
```

Followed by **one blank line**, then a body of `key=value` lines, one per line, terminated by `\n`. Final line ends with `\n`.

### 31.3.1 Required keys (v0.1.0)

```
artifact.size_bytes
artifact.type
measurement.algorithm
measurement.digest
origin.created_at
origin.creator
origin.mode
wise_id
wise_seal
```

For `artifact.type=text`, also required:

```
artifact.encoding         (must equal "utf-8")
```

For `artifact.type=file` and `artifact.type=text`:

```
artifact.name             (file basename or "" for text)
```

`artifact.name` is metadata only and is NOT included when computing `wise_id` or `wise_seal` (Q12 carryover from §30.12).

### 31.3.2 Canonical formatting (STRICT)

```
1. UTF-8 encoding only
2. First line exactly "WISEPROOF-V1\n"
3. Exactly one blank line ("\n") after the header
4. Body lines have the form  key=value\n
5. No leading or trailing whitespace on any line
6. No empty lines inside the body
7. Keys sorted by pure lexical full-key order (Q18)
8. Values are raw UTF-8 with no escaping; values MUST NOT contain "\n" or "="
9. The file ends with "\n" after the last value line
```

Example (illustrative — exact bytes are determined by the spec, not by formatting choices):

```
WISEPROOF-V1

artifact.name=demo.txt
artifact.size_bytes=6
artifact.type=file
measurement.algorithm=WiseDigest-0
measurement.digest=<hex>
origin.created_at=2026-04-27T00:00:00Z
origin.creator=Wise.Est Systems
origin.mode=local
wise_id=<hex>
wise_seal=<hex>
```

Canonical sort key order in v0.1.0 (when all required keys are present, file artifact):

```
artifact.name
artifact.size_bytes
artifact.type
measurement.algorithm
measurement.digest
origin.created_at
origin.creator
origin.mode
wise_id
wise_seal
```

Any violation of §31.3.2 → `INVALID_PROOF`.

---

## 31.4 Identity model — `wise_id` and `wise_seal` (Q5 + Q17 LOCKED)

Define the **canonical body** as the WISEPROOF-V1 file content (header + blank line + sorted key=value lines, all rules in §31.3.2 applied) restricted to a specified key set.

```
wise_id_body   = canonical body with these keys EXCLUDED:
                   wise_id
                   wise_seal
                   origin.created_at
                   artifact.name

wise_seal_body = canonical body with these keys EXCLUDED:
                   wise_seal
                 (wise_id, origin.created_at, artifact.name are INCLUDED)
```

```
wise_id   = digest(wise_id_body)        using measurement.algorithm
wise_seal = digest(wise_seal_body)      using measurement.algorithm
```

Consequences:
- Same artifact + same algorithm + same `origin.creator` → identical `wise_id` everywhere, forever.
- `wise_seal` commits to `wise_id` AND `origin.created_at`. A different sealing time produces a different `wise_seal`. Tampering with `wise_id` breaks `wise_seal`.

---

## 31.5 Algorithm name

The native digest is referred to as `WiseDigest-0` in the proof file and CLI. The mathematics are unchanged from §7 + §30.1 + §30.2 + §30.3 + §30.4. The label `WISE-DIGEST-0` from those sections is an alias retained only for cross-reference; new artifacts MUST use `WiseDigest-0`.

Supported algorithm values in v0.1.0:

```
WiseDigest-0
SHA-256
```

Unknown → `UNSUPPORTED_ALGORITHM`.

---

## 31.6 CLI

```bash
wise forge   <artifact>            # create .wiseproof next to artifact
wise check   <artifact> <proof>    # verify
wise inspect <proof>               # human-readable dump
wise bind    <artifact>            # produce .wiseseal container
```

Common flags: `--algorithm`, `--creator`, `--created-at`, `--origin-mode`, `--out`, `--force`, `--json`, `--quiet`.

Default output path for `forge`: `<artifact>.wiseproof`.
Default output path for `bind`: `<artifact>.wiseseal`.

---

## 31.7 WISESEAL-V1 container

Binary file. Layout:

```
header line     "WISESEAL-V1\n"
section header  "[ARTIFACT]\n"
4 bytes         big-endian uint32 = artifact byte length N
N bytes         raw artifact bytes (no transformation)
section header  "\n[PROOF]\n"
4 bytes         big-endian uint32 = proof byte length M
M bytes         exact .wiseproof file content
section header  "\n[END]\n"
```

No compression. The artifact is preserved byte-for-byte. The proof is preserved byte-for-byte.

`wise check` against a `.wiseseal` extracts and verifies in one shot.

---

## 31.8 Status codes (LOCKED for WISE)

```
VERIFIED
TAMPERED
INVALID_PROOF
UNREADABLE_ARTIFACT
UNSUPPORTED_ALGORITHM
USER_ERROR
```

Note: the SPAS-era `UNSUPPORTED_VERSION` is folded into `INVALID_PROOF` for WISE — a wrong header line means the file is not a valid WISEPROOF-V1 file at all.

Exit codes:

```
0  VERIFIED or success
1  TAMPERED
2  INVALID_PROOF
3  UNREADABLE_ARTIFACT
4  UNSUPPORTED_ALGORITHM
5  USER_ERROR
```

---

## 31.9 Verification order (WISE)

```
1. Read proof bytes               -> INVALID_PROOF on read failure
2. Parse WISEPROOF-V1 header      -> INVALID_PROOF
3. Parse body (sort + format)     -> INVALID_PROOF
4. Required-keys check            -> INVALID_PROOF
5. Algorithm support              -> UNSUPPORTED_ALGORITHM
6. origin.mode in {local,imported}-> INVALID_PROOF
7. Recompute wise_id; compare     -> INVALID_PROOF
8. Recompute wise_seal; compare   -> INVALID_PROOF
9. Stat artifact size; compare    -> TAMPERED  (short-circuit)
10. Open artifact                 -> UNREADABLE_ARTIFACT
11. Recompute artifact digest     -> TAMPERED
12. VERIFIED
```

---

## 31.10 Non-negotiables (WISE)

```
No silent fixes.
No fallback logic.
No guessing.
No hidden normalization.
Byte-exact comparison only.
No external trust.
No JSON.
No standard archive formats.
```


