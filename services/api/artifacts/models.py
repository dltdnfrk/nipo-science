"""Typed immutable Artifact service records and boundary commands."""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, ClassVar, Final, Protocol, final, override
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

UUID7_VERSION: Final = 7
UUID7_ERROR: Final = "uuid7"
MAX_ARTIFACT_OUTPUT_BYTES: Final = 50 * 1024 * 1024
MAX_ARTIFACT_PROVENANCE_ITEMS: Final = 1024


def _require_uuid7(value: UUID) -> UUID:
    if value.version != UUID7_VERSION:
        raise ValueError(UUID7_ERROR)
    return value


Uuid7 = Annotated[UUID, AfterValidator(_require_uuid7)]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class ArtifactScope(BaseModel):
    """Authenticated tenant, project, and requester context."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    org_id: Uuid7
    project_id: Uuid7
    requester_id: Uuid7


class VersionDraft(BaseModel):
    """Server-bound metadata accompanying one registered watcher output."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    artifact_id: Uuid7
    base_version_no: int = Field(ge=0)
    watcher_reference: str = Field(min_length=1, max_length=255)
    producing_execution_id: Uuid7
    environment_sha256: Sha256
    code_sha256: Sha256
    runtime_adapter_id: str = Field(min_length=1, max_length=255)
    runtime_connection_id: Uuid7
    skill_content_hashes: tuple[Sha256, ...] = Field(
        max_length=MAX_ARTIFACT_PROVENANCE_ITEMS
    )
    source_hashes: tuple[Sha256, ...] = Field(max_length=MAX_ARTIFACT_PROVENANCE_ITEMS)
    input_version_ids: tuple[Uuid7, ...] = Field(
        max_length=MAX_ARTIFACT_PROVENANCE_ITEMS
    )


class ArtifactErrorCode(StrEnum):
    """Stable Artifact boundary rejection codes."""

    NOT_FOUND = "artifact_not_found"
    PROJECT_ARCHIVED = "artifact_project_archived"
    STALE_BASE = "artifact_stale_base"
    INVALID_LINEAGE = "artifact_invalid_lineage"
    WATCHER_REFERENCE_INVALID = "artifact_watcher_reference_invalid"
    ASSOCIATION_EXISTS = "artifact_association_exists"
    CHECKSUM_MISMATCH = "artifact_checksum_mismatch"
    DOWNLOAD_TTL_INVALID = "artifact_download_ttl_invalid"
    DOWNLOAD_INVALID = "artifact_download_invalid"
    DOWNLOAD_EXPIRED = "artifact_download_expired"


@final
class ArtifactError(Exception):
    """Expose a stable code without reflecting untrusted payloads."""

    __slots__ = ("code",)

    def __init__(self, code: ArtifactErrorCode) -> None:
        """Retain the stable rejection code."""
        super().__init__(code)
        self.code = code

    @override
    def __str__(self) -> str:
        return str(self.code)


class Clock(Protocol):
    """Injected UTC clock used by immutable timestamps and expiry checks."""

    def now(self) -> datetime:
        """Return the current aware UTC time."""
        ...


class IdFactory(Protocol):
    """UUIDv7 source used by server-owned identities."""

    def new_uuid7(self) -> UUID:
        """Return one new UUIDv7."""
        ...


class ArtifactRecord(BaseModel):
    """Project-owned immutable Artifact identity."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    id: Uuid7
    org_id: Uuid7
    project_id: Uuid7
    name: str = Field(min_length=1, max_length=255)
    created_at: datetime


class ArtifactVersion(BaseModel):
    """Immutable content and provenance metadata for one monotonic Version."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    id: Uuid7
    org_id: Uuid7
    project_id: Uuid7
    artifact_id: Uuid7
    version_no: int = Field(ge=1)
    object_key: str = Field(min_length=1)
    content_sha256: Sha256
    size_bytes: int = Field(ge=0)
    media_type: str = Field(min_length=1, max_length=255)
    producing_execution_id: Uuid7
    environment_sha256: Sha256
    code_sha256: Sha256
    runtime_adapter_id: str = Field(min_length=1, max_length=255)
    runtime_connection_id: Uuid7
    skill_content_hashes: tuple[Sha256, ...] = Field(
        max_length=MAX_ARTIFACT_PROVENANCE_ITEMS
    )
    source_hashes: tuple[Sha256, ...] = Field(max_length=MAX_ARTIFACT_PROVENANCE_ITEMS)
    input_version_ids: tuple[Uuid7, ...] = Field(
        max_length=MAX_ARTIFACT_PROVENANCE_ITEMS
    )
    created_at: datetime


class SessionArtifactLink(BaseModel):
    """Unique version-level association to one Session."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    org_id: Uuid7
    project_id: Uuid7
    session_id: Uuid7
    artifact_version_id: Uuid7
    revision: int = Field(ge=1)
    created_at: datetime


class WatcherOutput(BaseModel):
    """Immutable bytes and checksum registered outside the sandbox."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
        ser_json_bytes="base64",
        val_json_bytes="base64",
    )

    reference: str = Field(min_length=1, max_length=255)
    org_id: Uuid7
    project_id: Uuid7
    requester_id: Uuid7
    execution_id: Uuid7
    runtime_adapter_id: str = Field(min_length=1, max_length=255)
    runtime_connection_id: Uuid7
    payload: bytes
    content_sha256: Sha256
    media_type: str = Field(min_length=1, max_length=255)


class WatcherClaim(BaseModel):
    """Opaque fenced ownership of one watcher output commit attempt."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    reference: str = Field(min_length=1, max_length=255)
    token: Uuid7
    output: WatcherOutput


class SignedDownload(BaseModel):
    """Opaque short-lived download token returned to an authorized caller."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    token: str = Field(min_length=1)
    expires_at: datetime


class DownloadClaims(BaseModel):
    """Authenticated claims carried inside one signed download token."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    org_id: Uuid7
    project_id: Uuid7
    version_id: Uuid7
    expires_unix_ms: int = Field(gt=0)
