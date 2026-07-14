"""Atomic tenant-scoped in-memory Artifact and content-addressed blob store."""

import hashlib
from threading import RLock
from uuid import UUID

from .models import (
    ArtifactRecord,
    ArtifactScope,
    ArtifactVersion,
    SessionArtifactLink,
)
from .store_contract import BlobIntegrityError, StoreOutcome


class InMemoryArtifactStore:
    """Atomic local adapter mirroring the tenant-safe database contract."""

    def __init__(
        self,
        projects: frozenset[tuple[UUID, UUID]],
        sessions: frozenset[tuple[UUID, UUID, UUID]],
    ) -> None:
        """Seed trusted Project and Session identities for deterministic tests."""
        self._projects: frozenset[tuple[UUID, UUID]] = projects
        self._sessions: frozenset[tuple[UUID, UUID, UUID]] = sessions
        self._archived_projects: set[tuple[UUID, UUID]] = set()
        self._artifacts: dict[tuple[UUID, UUID], ArtifactRecord] = {}
        self._versions: dict[tuple[UUID, UUID], ArtifactVersion] = {}
        self._latest: dict[tuple[UUID, UUID], UUID] = {}
        self._blobs: dict[str, bytes] = {}
        self._links: dict[tuple[UUID, UUID, UUID], SessionArtifactLink] = {}
        self._lock: RLock = RLock()

    @staticmethod
    def object_key(scope: ArtifactScope, content_sha256: str) -> str:
        """Derive a private content address without sandbox-controlled segments."""
        return f"org/{scope.org_id}/project/{scope.project_id}/sha256/{content_sha256}"

    def create_artifact(
        self,
        scope: ArtifactScope,
        artifact: ArtifactRecord,
    ) -> StoreOutcome:
        """Create one Project-owned Artifact identity."""
        project = (scope.org_id, scope.project_id)
        key = (scope.org_id, artifact.id)
        with self._lock:
            if project not in self._projects:
                return StoreOutcome.NOT_FOUND
            if project in self._archived_projects:
                return StoreOutcome.ARCHIVED
            if key in self._artifacts:
                return StoreOutcome.NOT_FOUND
            self._artifacts[key] = artifact
        return StoreOutcome.CREATED

    def commit_version(
        self,
        scope: ArtifactScope,
        base_version_no: int,
        version: ArtifactVersion,
        payload: bytes,
    ) -> StoreOutcome:
        """Atomically validate CAS, lineage, content address, and Version insert."""
        project = (scope.org_id, scope.project_id)
        artifact_key = (scope.org_id, version.artifact_id)
        version_key = (scope.org_id, version.id)
        with self._lock:
            artifact = self._artifacts.get(artifact_key)
            if artifact is None or artifact.project_id != scope.project_id:
                return StoreOutcome.NOT_FOUND
            if project in self._archived_projects:
                return StoreOutcome.ARCHIVED
            latest_id = self._latest.get(artifact_key)
            current_no = (
                0
                if latest_id is None
                else self._versions[(scope.org_id, latest_id)].version_no
            )
            if current_no != base_version_no:
                return StoreOutcome.STALE
            if not self._lineage_valid(scope, version.input_version_ids):
                return StoreOutcome.INVALID_LINEAGE
            digest = hashlib.sha256(payload).hexdigest()
            expected_key = self.object_key(scope, digest)
            if (
                version_key in self._versions
                or version.version_no != current_no + 1
                or version.content_sha256 != digest
                or version.size_bytes != len(payload)
                or version.object_key != expected_key
            ):
                return StoreOutcome.INVALID_LINEAGE
            existing = self._blobs.get(expected_key)
            if existing is not None and existing != payload:
                raise BlobIntegrityError
            _ = self._blobs.setdefault(expected_key, payload)
            self._versions[version_key] = version
            self._latest[artifact_key] = version.id
        return StoreOutcome.CREATED

    def artifact(
        self,
        scope: ArtifactScope,
        artifact_id: UUID,
    ) -> ArtifactRecord | None:
        """Read one Artifact only in its exact tenant and Project."""
        with self._lock:
            artifact = self._artifacts.get((scope.org_id, artifact_id))
            if artifact is None or artifact.project_id != scope.project_id:
                return None
            return artifact

    def version(
        self,
        scope: ArtifactScope,
        version_id: UUID,
    ) -> ArtifactVersion | None:
        """Read one Version only in its exact tenant and Project."""
        with self._lock:
            version = self._versions.get((scope.org_id, version_id))
            if version is None or version.project_id != scope.project_id:
                return None
            return version

    def read_content(
        self,
        scope: ArtifactScope,
        version_id: UUID,
    ) -> bytes | None:
        """Return checksum-verified immutable bytes for one authorized Version."""
        with self._lock:
            version = self._versions.get((scope.org_id, version_id))
            if version is None or version.project_id != scope.project_id:
                return None
            payload = self._blobs.get(version.object_key)
            if (
                payload is None
                or hashlib.sha256(payload).hexdigest() != version.content_sha256
            ):
                raise BlobIntegrityError
            return payload

    def redeem_content(
        self,
        scope: ArtifactScope,
        version_id: UUID,
    ) -> tuple[StoreOutcome, bytes | None]:
        """Read content under the same lock as the active-Project check."""
        with self._lock:
            if (scope.org_id, scope.project_id) in self._archived_projects:
                return StoreOutcome.ARCHIVED, None
            version = self._versions.get((scope.org_id, version_id))
            if version is None or version.project_id != scope.project_id:
                return StoreOutcome.NOT_FOUND, None
            payload = self._blobs.get(version.object_key)
            if (
                payload is None
                or hashlib.sha256(payload).hexdigest() != version.content_sha256
            ):
                raise BlobIntegrityError
            return StoreOutcome.CREATED, payload

    def lineage(
        self,
        scope: ArtifactScope,
        version_id: UUID,
    ) -> tuple[UUID, ...] | None:
        """Return pinned input Version IDs without resolving latest."""
        version = self.version(scope, version_id)
        return None if version is None else version.input_version_ids

    def attach_session(
        self,
        scope: ArtifactScope,
        link: SessionArtifactLink,
    ) -> StoreOutcome:
        """Create one unique version-level Session association."""
        session = (scope.org_id, scope.project_id, link.session_id)
        key = (scope.org_id, link.session_id, link.artifact_version_id)
        with self._lock:
            if (scope.org_id, scope.project_id) in self._archived_projects:
                return StoreOutcome.ARCHIVED
            if session not in self._sessions:
                return StoreOutcome.NOT_FOUND
            version = self._versions.get((scope.org_id, link.artifact_version_id))
            if version is None or version.project_id != scope.project_id:
                return StoreOutcome.NOT_FOUND
            if key in self._links:
                return StoreOutcome.ASSOCIATION_EXISTS
            self._links[key] = link
        return StoreOutcome.CREATED

    def project_archived(self, scope: ArtifactScope) -> bool:
        """Return whether the authorized Project blocks downloads and writes."""
        with self._lock:
            return (scope.org_id, scope.project_id) in self._archived_projects

    def archive_project(self, scope: ArtifactScope) -> None:
        """Archive an existing Project for deterministic lifecycle tests."""
        project = (scope.org_id, scope.project_id)
        with self._lock:
            if project in self._projects:
                self._archived_projects.add(project)

    def version_count(self, scope: ArtifactScope, artifact_id: UUID) -> int:
        """Count immutable Versions for one authorized Artifact."""
        with self._lock:
            return sum(
                version.org_id == scope.org_id
                and version.project_id == scope.project_id
                and version.artifact_id == artifact_id
                for version in self._versions.values()
            )

    def object_count(self, scope: ArtifactScope) -> int:
        """Count tenant-specific content-addressed objects."""
        prefix = f"org/{scope.org_id}/project/{scope.project_id}/sha256/"
        with self._lock:
            return sum(key.startswith(prefix) for key in self._blobs)

    def corrupt_blob_for_test(self, version_id: UUID, replacement: bytes) -> None:
        """Simulate external object corruption in the deterministic local adapter."""
        with self._lock:
            version = next(
                item for item in self._versions.values() if item.id == version_id
            )
            self._blobs[version.object_key] = replacement

    def _lineage_valid(
        self,
        scope: ArtifactScope,
        input_version_ids: tuple[UUID, ...],
    ) -> bool:
        if len(set(input_version_ids)) != len(input_version_ids):
            return False
        return all(
            (version := self._versions.get((scope.org_id, version_id))) is not None
            and version.project_id == scope.project_id
            for version_id in input_version_ids
        )
