"""Wise Origin Protocol — reference implementation."""

__version__ = "0.1.0"

WISE_PROOF_HEADER = "WISEPROOF-V1"
WISE_SEAL_HEADER = "WISESEAL-V1"
DEFAULT_CREATOR = "Wise.Est Systems"
SUPPORTED_ALGORITHMS = ("WiseDigest-0", "SHA-256")
ALLOWED_ORIGIN_MODES = ("local", "imported")
ALLOWED_ARTIFACT_TYPES = ("file", "text")  # directory deferred to a later phase
