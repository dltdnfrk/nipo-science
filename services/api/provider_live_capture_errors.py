"""Stable fail-closed errors shared by provider live capture boundaries."""

from __future__ import annotations

from typing import Final

ERROR_CASES_INVALID: Final = "capture cases are invalid"
ERROR_CASES_SCENARIOS: Final = "capture cases must be exactly GS01 through GS10"
ERROR_OUTPUT_EXISTS: Final = "capture output already exists"
ERROR_OUTPUT_BOUNDARY: Final = (
    "capture output must remain inside the configured output root"
)
ERROR_CAPTURE_ROOTS: Final = (
    "capture roots must be absolute owner-private directories"
)
ERROR_TEMPORARY_CLEANUP: Final = "capture temporary cleanup failed"
ERROR_VERSION_INVALID: Final = "codex version is invalid"
ERROR_SENSITIVE_OUTPUT: Final = "codex emitted sensitive output"
ERROR_OFFICIAL_LOGIN: Final = "official ChatGPT login is required"
ERROR_RESPONSE_MALFORMED: Final = "codex response is malformed"
ERROR_FORBIDDEN_CONTENT: Final = "codex response contains forbidden content"
ERROR_SAFETY_VALIDATION: Final = "codex response failed safety validation"
ERROR_PROTOCOL_MALFORMED: Final = "codex protocol is malformed"
ERROR_PROTOCOL_FAILED: Final = "codex protocol failed"
ERROR_PROTOCOL_INCOMPLETE: Final = "codex protocol is incomplete"
ERROR_BINARY_POLICY: Final = "codex binary policy is required"
ERROR_BINARY_INVALID: Final = "codex binary policy is invalid"
ERROR_BINARY_CHANGED: Final = "codex binary identity changed"
ERROR_BINARY_STAGING: Final = "codex executable staging failed"
ERROR_LIVE_QUALIFICATION: Final = "live qualification evaluation failed"
ERROR_RUNTIME_POLICY: Final = "approved runtime policy is invalid"
ERROR_OUTPUT_LIMIT: Final = "codex output exceeds limit"
ERROR_OUTPUT_ENCODING: Final = "codex output encoding is invalid"
ERROR_FINAL_LIMIT: Final = "codex final response exceeds limit"


class CaptureError(RuntimeError):
    """Stable failure which guarantees no live profile was published."""


def capture_error(message: str) -> CaptureError:
    """Build the stable public capture failure at an internal boundary."""
    return CaptureError(message)
