"""SPAS — Self-Proving Artifact System reference implementation."""

SPAS_VERSION = "0.1.0"
PROOF_FORMAT = "spas-proof-v1"
STATUS_RULE = "REPRODUCE_OR_REJECT"
DEFAULT_CREATOR = "Wise.Est Systems"
SUPPORTED_ALGORITHMS = ("WISE-DIGEST-0", "SHA-256")
ALLOWED_ORIGIN_MODES = ("local", "imported")
ALLOWED_ARTIFACT_TYPES = ("file", "text", "directory")
