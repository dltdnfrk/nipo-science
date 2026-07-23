"""Durable authority contract for watcher and commit recovery state."""

from contextlib import AbstractContextManager
from typing import ClassVar, Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from .models import (
    ArtifactScope,
    ArtifactVersion,
    VersionDraft,
    WatcherClaim,
    WatcherOutput,
)


class PendingArtifactCommit(BaseModel):
    """Integrity-bound commit intent retained until its outcome is known."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    kind: Literal["pending"] = "pending"
    scope: ArtifactScope
    draft: VersionDraft
    claim: WatcherClaim
    version: ArtifactVersion


class CompletedArtifactCommit(BaseModel):
    """Exact idempotency result for one consumed watcher reference."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    kind: Literal["completed"] = "completed"
    scope: ArtifactScope
    draft: VersionDraft
    version: ArtifactVersion


type ArtifactReconciliation = PendingArtifactCommit | CompletedArtifactCommit


class ArtifactRecoveryError(Exception):
    """Report unavailable or corrupted recovery authority state."""


class ArtifactRecovery(Protocol):
    """Atomic persistence boundary shared by watchers and Artifact services."""

    def locked(self, reference: str) -> AbstractContextManager[None]:
        """Serialize every state transition for one opaque reference."""
        ...

    def register_output(self, output: WatcherOutput) -> bool:
        """Persist a new integrity-bound output exactly once."""
        ...

    def resolve_output(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
        reference: str,
    ) -> WatcherOutput | None:
        """Resolve only an available output in its exact authority scope."""
        ...

    def claim_output(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
        reference: str,
        token: UUID,
    ) -> WatcherClaim | None:
        """Fence one available output to an exact claim token."""
        ...

    def claim_pending(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
        pending: PendingArtifactCommit,
    ) -> bool:
        """Atomically fence an output and persist its exact commit intent."""
        ...

    def release_claim(self, claim: WatcherClaim) -> bool:
        """Release only the exact active claim, idempotently after consumption."""
        ...

    def finalize_claim(self, claim: WatcherClaim) -> bool:
        """Persist an exact non-replayable consumed fence."""
        ...

    def reconciliation(self, reference: str) -> ArtifactReconciliation | None:
        """Load the exact pending or completed commit record."""
        ...

    def save_completed(self, pending: PendingArtifactCommit) -> bool:
        """Atomically replace an exact pending intent with its final result."""
        ...

    def discard_pending(self, pending: PendingArtifactCommit) -> bool:
        """Delete only the exact rejected commit intent."""
        ...
