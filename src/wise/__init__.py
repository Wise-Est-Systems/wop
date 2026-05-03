"""Wise Origin Protocol — reference implementation."""

__version__ = "0.1.1"

WISE_PROOF_HEADER = "WISEPROOF-V1"
WISE_SEAL_HEADER = "WISESEAL-V1"
DEFAULT_CREATOR = "Wise.Est Systems"
SUPPORTED_ALGORITHMS = ("WiseDigest-0", "SHA-256")
ALLOWED_ORIGIN_MODES = ("local", "imported")
ALLOWED_ARTIFACT_TYPES = ("file", "text")  # directory deferred to a later phase

# v0.1.1 hardening:
ALLOWED_ATTESTATION = ("self_declared",)  # v0.4 will add "signed"

# Hard caps on input bytes (defense against memory-exhaustion attacks).
# A real-world .wiseproof is well under 2 KB. 1 MiB is generous.
MAX_PROOF_BYTES = 1 * 1024 * 1024  # 1 MiB
MAX_SEAL_PROOF_SECTION_BYTES = 1 * 1024 * 1024  # 1 MiB

# v0.1.1 closed-set of permitted top-level keys for WISEPROOF-V1.
# Unknown keys are rejected as INVALID_PROOF (H4).
ALLOWED_KEYS_FILE = frozenset({
    "artifact.name",
    "artifact.size_bytes",
    "artifact.type",
    "measurement.algorithm",
    "measurement.digest",
    "origin.attestation",
    "origin.created_at",
    "origin.creator",
    "origin.mode",
    "wise_id",
    "wise_seal",
})

ALLOWED_KEYS_TEXT = ALLOWED_KEYS_FILE | frozenset({"artifact.encoding"})
