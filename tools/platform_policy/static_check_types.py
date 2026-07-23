"""Stable static-check modes and failures shared by policy modules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, override

if TYPE_CHECKING:
    from pathlib import Path


class StaticMode(StrEnum):
    """Supported machine-invoked static checks."""

    SBOM = "sbom"
    SECRET_SCAN = "secret-scan"  # noqa: S105 -- A mode label, never a credential.
    DRIFT_SCAN = "drift-scan"


class StaticCheckCode(StrEnum):
    """Stable failures emitted by static checks."""

    MISSING_UV_LOCK = "missing-uv-lock"
    MISSING_PNPM_LOCK = "missing-pnpm-lock"
    EMPTY_SBOM = "empty-sbom"
    CREDENTIAL_PLAINTEXT = "credential-plaintext"
    MACHINE_PATH_PLAINTEXT = "machine-path-plaintext"
    EMPTY_SECRET_SCAN = "empty-secret-scan"  # noqa: S105 -- Stable error code.
    USAGE = "usage"
    UNKNOWN_CHECK = "unknown-check"
    UNPINNED_WORKFLOW_ACTION = "unpinned-workflow-action"
    MISSING_EXTERNAL_CI_AUTHORITY = "missing-external-ci-authority"


@dataclass(frozen=True, slots=True)
class StaticCheckError(Exception):
    """Rejects an invalid static check request or discovered violation."""

    code: StaticCheckCode
    path: Path

    @override
    def __str__(self) -> str:
        """Describe the stable failure code and affected path."""
        return f"{self.code}: {self.path}"
