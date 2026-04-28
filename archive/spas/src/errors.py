"""Terminal status codes and exit codes for SPAS v0.1.0."""

from __future__ import annotations

VERIFIED = "VERIFIED"
TAMPERED = "TAMPERED"
INVALID_PROOF = "INVALID_PROOF"
UNREADABLE_ARTIFACT = "UNREADABLE_ARTIFACT"
UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
USER_ERROR = "USER_ERROR"

EXIT_CODES = {
    VERIFIED: 0,
    TAMPERED: 1,
    INVALID_PROOF: 2,
    UNREADABLE_ARTIFACT: 3,
    UNSUPPORTED_VERSION: 4,
    UNSUPPORTED_ALGORITHM: 5,
    USER_ERROR: 6,
}


class SpasError(Exception):
    def __init__(self, status: str, detail: str) -> None:
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail
