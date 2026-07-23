"""Persistence contract shared by local and durable Artifact adapters."""

from enum import StrEnum
from typing import Protocol, final
from uuid import UUID

from .models import ArtifactRecord, ArtifactScope, ArtifactVersion, SessionArtifactLink


class StoreOutcome(StrEnum):
    """Closed outcomes returned by atomic store transitions."""

    CREATED = "created"
    NOT_FOUND = "not_found"
    ARCHIVED = "archived"
    STALE = "stale"
    INVALID_LINEAGE = "invalid_lineage"
    ASSOCIATION_EXISTS = "association_exists"


@final
class BlobIntegrityError(Exception):
    """Reject a blob whose stored bytes no longer match its immutable digest."""


class ArtifactStoreError(Exception):
    """Normalize an operational failure at a persistence adapter boundary."""


@final
class BlobWriteError(ArtifactStoreError):
    """Normalize a failed private-blob publication or compensation."""


@final
class ArtifactStoreIntegrityError(ArtifactStoreError):
    """Normalize a rejected durable integrity constraint."""


@final
class ArtifactCommitError(ArtifactStoreError):
    """Report a Version commit whose final durable outcome needs reconciliation."""


class ArtifactStore(Protocol):
    """Persistence boundary consumed by ArtifactService."""

    def object_key(self, scope: ArtifactScope, content_sha256: str) -> str:
        """Derive a server-controlled content address."""
        ...

    def create_artifact(
        self,
        scope: ArtifactScope,
        artifact: ArtifactRecord,
    ) -> StoreOutcome:
        """Create one Project-owned Artifact."""
        ...

    def artifact(
        self,
        scope: ArtifactScope,
        artifact_id: UUID,
    ) -> ArtifactRecord | None:
        """Read one exact authorized Artifact."""
        ...

    def commit_version(
        self,
        scope: ArtifactScope,
        base_version_no: int,
        version: ArtifactVersion,
        payload: bytes,
    ) -> StoreOutcome:
        """Atomically append one Version against its base."""
        ...

    def version(
        self,
        scope: ArtifactScope,
        version_id: UUID,
    ) -> ArtifactVersion | None:
        """Read an exact authorized Version."""
        ...

    def read_content(
        self,
        scope: ArtifactScope,
        version_id: UUID,
    ) -> bytes | None:
        """Read checksum-verified Version content."""
        ...

    def redeem_content(
        self,
        scope: ArtifactScope,
        version_id: UUID,
    ) -> tuple[StoreOutcome, ArtifactVersion | None, bytes | None]:
        """Read Version and content atomically with active-Project authorization."""
        ...

    def lineage(
        self,
        scope: ArtifactScope,
        version_id: UUID,
    ) -> tuple[UUID, ...] | None:
        """Read exact input Version references."""
        ...

    def attach_session(
        self,
        scope: ArtifactScope,
        link: SessionArtifactLink,
    ) -> StoreOutcome:
        """Create one Version-level Session association."""
        ...

    def project_archived(self, scope: ArtifactScope) -> bool:
        """Return whether writes and downloads are blocked."""
        ...
