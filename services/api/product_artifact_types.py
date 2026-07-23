"""Typed immutable records for the test-principal Artifact fixture."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal


class ArtifactVersionConflictError(ValueError):
    """Reject stale immutable-Version creation."""


class UnsupportedArtifactMediaError(ValueError):
    """Reject active or unknown preview media."""


@dataclass(frozen=True, slots=True)
class ArtifactVersionDraft:
    """Validated caller intent for one immutable Version append."""

    organization_id: str
    artifact_id: str
    name: str
    media_type: str
    content: bytes
    producer_execution_id: str
    environment_sha256: str
    lineage_version_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ArtifactVersion:
    """One immutable tenant-owned Artifact Version."""

    id: str
    artifact_id: str
    organization_id: str
    name: str
    version_no: int
    media_type: str
    content: bytes
    sha256: str
    producer_execution_id: str
    environment_sha256: str
    lineage_version_ids: tuple[str, ...]
    preview_token: str
    created_at: datetime
    status: Literal["immutable"]


@dataclass(frozen=True, slots=True)
class ArtifactDetail:
    """Selected Version, predecessor diff, and Session associations."""

    versions: tuple[ArtifactVersion, ...]
    selected: ArtifactVersion
    previous: ArtifactVersion | None
    changed_bytes: int
    attached_session_ids: tuple[str, ...]
