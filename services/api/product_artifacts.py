"""Tenant-scoped immutable Artifact fixture for the test-principal UI."""

from __future__ import annotations

import hashlib
import secrets
from threading import Lock
from typing import Final, Self, final

from services.api.product_artifact_fixtures import seed_artifact_fixtures
from services.api.product_artifact_types import (
    ArtifactDetail,
    ArtifactVersion,
    ArtifactVersionConflictError,
    ArtifactVersionDraft,
    UnsupportedArtifactMediaError,
)
from services.api.product_artifact_validation import validate_artifact_draft

_SUPPORTED_MEDIA: Final = frozenset({"application/pdf", "image/png", "text/csv"})


@final
class ProductArtifactService:
    """Store bounded test-principal Versions without mutable content."""

    def __init__(self) -> None:
        """Initialize an empty Artifact fixture store."""
        self._lock: Lock = Lock()
        self._versions: dict[tuple[str, str], list[ArtifactVersion]] = {}
        self._attachments: set[tuple[str, str, str]] = set()

    @classmethod
    def with_fixture(cls) -> Self:
        """Create the CSV, PNG, and PDF Artifact fixture set."""
        service = cls()
        seed_artifact_fixtures(
            lambda draft, base: service.create_version(draft, base_version_no=base)
        )
        return service

    def create_version(
        self,
        draft: ArtifactVersionDraft,
        *,
        base_version_no: int,
    ) -> ArtifactVersion:
        """Append one Version when the caller pins the current base."""
        if draft.media_type not in _SUPPORTED_MEDIA:
            raise UnsupportedArtifactMediaError(draft.media_type)
        content = validate_artifact_draft(draft)
        key = (draft.organization_id, draft.artifact_id)
        with self._lock:
            versions = self._versions.setdefault(key, [])
            if len(versions) != base_version_no:
                raise ArtifactVersionConflictError(draft.artifact_id)
            version_no = base_version_no + 1
            version = ArtifactVersion(
                id=f"{draft.artifact_id}-v{version_no}",
                artifact_id=draft.artifact_id,
                organization_id=draft.organization_id,
                name=draft.name,
                version_no=version_no,
                media_type=draft.media_type,
                content=content,
                sha256=hashlib.sha256(content).hexdigest(),
                producer_execution_id=draft.producer_execution_id,
                environment_sha256=draft.environment_sha256,
                lineage_version_ids=draft.lineage_version_ids,
                preview_token=secrets.token_urlsafe(24),
            )
            versions.append(version)
            return version

    def list_latest(self, organization_id: str) -> tuple[ArtifactVersion, ...]:
        """List only latest Versions visible to one tenant."""
        with self._lock:
            return tuple(
                versions[-1]
                for (owner, _), versions in sorted(self._versions.items())
                if owner == organization_id
            )

    def detail(
        self,
        organization_id: str,
        artifact_id: str,
        version_id: str | None = None,
    ) -> ArtifactDetail | None:
        """Return one visible Artifact with the requested immutable Version selected."""
        with self._lock:
            versions = tuple(self._versions.get((organization_id, artifact_id), ()))
            if not versions:
                return None
            selected_index = len(versions) - 1
            if version_id is not None:
                selected_index = next(
                    (
                        index
                        for index, version in enumerate(versions)
                        if version.id == version_id
                    ),
                    -1,
                )
                if selected_index < 0:
                    return None
            selected = versions[selected_index]
            previous = versions[selected_index - 1] if selected_index > 0 else None
            changed = (
                0
                if previous is None
                else _changed_bytes(previous.content, selected.content)
            )
            sessions = tuple(
                sorted(
                    session_id
                    for owner, version_id, session_id in self._attachments
                    if owner == organization_id and version_id == selected.id
                )
            )
            return ArtifactDetail(versions, selected, previous, changed, sessions)

    def attach(
        self, organization_id: str, version_id: str, session_id: str
    ) -> tuple[str, ...]:
        """Attach exactly one visible Version to a Session."""
        with self._lock:
            if self._find_version(organization_id, version_id) is None:
                return ()
            self._attachments.add((organization_id, version_id, session_id))
            return self._sessions(organization_id, version_id)

    def detach(
        self, organization_id: str, version_id: str, session_id: str
    ) -> tuple[str, ...]:
        """Detach only the explicitly selected Version from a Session."""
        with self._lock:
            self._attachments.discard((organization_id, version_id, session_id))
            return self._sessions(organization_id, version_id)

    def download(self, organization_id: str, version_id: str) -> ArtifactVersion | None:
        """Return immutable bytes only for a tenant-visible Version."""
        with self._lock:
            return self._find_version(organization_id, version_id)

    def preview(self, token: str) -> ArtifactVersion | None:
        """Resolve an opaque preview token without accepting an Artifact ID."""
        with self._lock:
            return next(
                (
                    version
                    for versions in self._versions.values()
                    for version in versions
                    if secrets.compare_digest(version.preview_token, token)
                ),
                None,
            )

    def _find_version(
        self, organization_id: str, version_id: str
    ) -> ArtifactVersion | None:
        return next(
            (
                version
                for (owner, _), versions in self._versions.items()
                for version in versions
                if owner == organization_id and version.id == version_id
            ),
            None,
        )

    def _sessions(self, organization_id: str, version_id: str) -> tuple[str, ...]:
        return tuple(
            sorted(
                session_id
                for owner, attached_version, session_id in self._attachments
                if owner == organization_id and attached_version == version_id
            )
        )


def _changed_bytes(left: bytes, right: bytes) -> int:
    overlap = sum(a != b for a, b in zip(left, right, strict=False))
    return overlap + abs(len(left) - len(right))
