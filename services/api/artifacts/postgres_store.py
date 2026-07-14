"""PostgreSQL and private-blob durable Artifact store."""

from typing import final
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from .blob_store import PrivateBlobStore
from .models import ArtifactRecord, ArtifactScope, ArtifactVersion, SessionArtifactLink
from .postgres_downloads import redeem_content_operation
from .postgres_operations import (
    CommitVersionInput,
    commit_version_operation,
    lock_content_address,
)
from .postgres_queries import VERSION_JSON
from .postgres_runtime import exists, identity, run_scoped
from .store_contract import (
    ArtifactCommitError,
    ArtifactStoreError,
    ArtifactStoreIntegrityError,
    BlobIntegrityError,
    StoreOutcome,
)


@final
class PostgresArtifactStore:
    """Persist Artifact metadata transactionally and content in private blobs."""

    def __init__(self, database_url: str, blobs: PrivateBlobStore) -> None:
        """Bind the database DSN and durable blob adapter."""
        self._database_url = database_url
        self._blobs = blobs

    @staticmethod
    def object_key(scope: ArtifactScope, content_sha256: str) -> str:
        """Derive the only accepted tenant and Project content address."""
        return f"org/{scope.org_id}/project/{scope.project_id}/sha256/{content_sha256}"

    def create_artifact(
        self,
        scope: ArtifactScope,
        artifact: ArtifactRecord,
    ) -> StoreOutcome:
        """Create one durable Project Artifact through requester-scoped RLS."""

        async def operation(connection: AsyncConnection) -> StoreOutcome:
            active: bool | None = (
                await connection.execute(
                    text(
                        "SELECT archived_at IS NULL FROM projects "
                        "WHERE org_id = :org AND id = :project FOR UPDATE"
                    ),
                    {"org": scope.org_id, "project": scope.project_id},
                )
            ).scalar_one_or_none()
            if active is None:
                return StoreOutcome.NOT_FOUND
            if not active:
                return StoreOutcome.ARCHIVED
            duplicate = await exists(
                connection,
                "SELECT EXISTS (SELECT 1 FROM artifacts WHERE org_id = :org "
                "AND project_id = :project AND id = :identity)",
                identity(scope) | {"identity": artifact.id},
            )
            if duplicate:
                return StoreOutcome.NOT_FOUND
            _ = await connection.execute(
                text(
                    "INSERT INTO artifacts "
                    "(id, org_id, project_id, name, created_at) VALUES "
                    "(:id, :org, :project, :name, :created)"
                ),
                {
                    "id": artifact.id,
                    "org": scope.org_id,
                    "project": scope.project_id,
                    "name": artifact.name,
                    "created": artifact.created_at,
                },
            )
            return StoreOutcome.CREATED

        return run_scoped(self._database_url, scope, operation)

    def commit_version(
        self,
        scope: ArtifactScope,
        base_version_no: int,
        version: ArtifactVersion,
        payload: bytes,
    ) -> StoreOutcome:
        """Serialize CAS on the Artifact row and append metadata plus lineage."""
        expected = self.object_key(scope, version.content_sha256)
        touched: set[str] = set()

        async def operation(connection: AsyncConnection) -> StoreOutcome:
            return await commit_version_operation(
                connection,
                CommitVersionInput(scope, base_version_no, version, payload),
                self._blobs,
                touched,
            )

        try:
            return run_scoped(self._database_url, scope, operation)
        except ArtifactStoreIntegrityError:
            if touched:
                self._compensate(scope, expected)
            return StoreOutcome.INVALID_LINEAGE
        except ArtifactStoreError as error:
            if touched:
                self._compensate(scope, expected)
            raise ArtifactCommitError from error

    def version(
        self,
        scope: ArtifactScope,
        version_id: UUID,
    ) -> ArtifactVersion | None:
        """Read one immutable Version with exact dependency IDs."""

        async def operation(connection: AsyncConnection) -> str | None:
            value: str | None = (
                await connection.execute(
                    text(VERSION_JSON),
                    identity(scope) | {"identity": version_id},
                )
            ).scalar_one_or_none()
            return value

        value = run_scoped(self._database_url, scope, operation)
        return None if value is None else ArtifactVersion.model_validate_json(value)

    def read_content(self, scope: ArtifactScope, version_id: UUID) -> bytes | None:
        """Read checksum-verified durable bytes for an authorized Version."""
        version = self.version(scope, version_id)
        return None if version is None else self._blobs.read(version.object_key)

    def redeem_content(
        self,
        scope: ArtifactScope,
        version_id: UUID,
    ) -> tuple[StoreOutcome, bytes | None]:
        """Read bytes while holding the active Project row lock."""

        async def operation(
            connection: AsyncConnection,
        ) -> tuple[StoreOutcome, bytes | None]:
            return await redeem_content_operation(
                connection,
                scope,
                self._blobs,
                version_id,
            )

        return run_scoped(self._database_url, scope, operation)

    def lineage(
        self,
        scope: ArtifactScope,
        version_id: UUID,
    ) -> tuple[UUID, ...] | None:
        """Return exact persisted dependency Version IDs."""
        version = self.version(scope, version_id)
        return None if version is None else version.input_version_ids

    def attach_session(
        self,
        scope: ArtifactScope,
        link: SessionArtifactLink,
    ) -> StoreOutcome:
        """Persist one same-Project Version-level Session association."""

        async def operation(connection: AsyncConnection) -> StoreOutcome:
            active: bool | None = (
                await connection.execute(
                    text(
                        "SELECT archived_at IS NULL FROM projects "
                        "WHERE org_id = :org AND id = :project FOR UPDATE"
                    ),
                    identity(scope),
                )
            ).scalar_one_or_none()
            if active is None:
                return StoreOutcome.NOT_FOUND
            if not active:
                return StoreOutcome.ARCHIVED
            values = identity(scope) | {
                "session": link.session_id,
                "version": link.artifact_version_id,
                "revision": link.revision,
                "created": link.created_at,
            }
            valid = await exists(
                connection,
                "SELECT EXISTS (SELECT 1 FROM sessions s JOIN artifact_versions v "
                "ON v.org_id = s.org_id AND v.project_id = s.project_id "
                "WHERE s.org_id = :org AND s.project_id = :project "
                "AND s.id = :session AND s.archived_at IS NULL "
                "AND v.id = :version FOR UPDATE OF s)",
                values,
            )
            if not valid:
                return StoreOutcome.NOT_FOUND
            duplicate = await exists(
                connection,
                "SELECT EXISTS (SELECT 1 FROM session_artifact_versions "
                "WHERE org_id = :org AND project_id = :project "
                "AND session_id = :session AND artifact_version_id = :version)",
                values,
            )
            if duplicate:
                return StoreOutcome.ASSOCIATION_EXISTS
            _ = await connection.execute(
                text(
                    "INSERT INTO session_artifact_versions "
                    "(org_id, project_id, session_id, artifact_version_id, "
                    "revision, created_at) VALUES (:org, :project, :session, "
                    ":version, :revision, :created)"
                ),
                values,
            )
            return StoreOutcome.CREATED

        try:
            return run_scoped(self._database_url, scope, operation)
        except ArtifactStoreIntegrityError:
            return StoreOutcome.NOT_FOUND

    def project_archived(self, scope: ArtifactScope) -> bool:
        """Return true for archived or unauthorized Projects."""

        async def operation(connection: AsyncConnection) -> bool:
            active: bool | None = (
                await connection.execute(
                    text(
                        "SELECT archived_at IS NULL FROM projects "
                        "WHERE org_id = :org AND id = :project"
                    ),
                    identity(scope),
                )
            ).scalar_one_or_none()
            return active is not True

        return run_scoped(self._database_url, scope, operation)

    def _cleanup_orphan(self, scope: ArtifactScope, object_key: str) -> None:
        async def operation(connection: AsyncConnection) -> None:
            await lock_content_address(connection, object_key)
            referenced = await exists(
                connection,
                "SELECT EXISTS (SELECT 1 FROM artifact_versions "
                "WHERE org_id = :org AND project_id = :project "
                "AND object_key = :key)",
                identity(scope) | {"key": object_key},
            )
            if not referenced:
                self._blobs.discard(object_key)

        run_scoped(self._database_url, scope, operation)

    def _compensate(self, scope: ArtifactScope, object_key: str) -> None:
        try:
            self._cleanup_orphan(scope, object_key)
        except (ArtifactStoreError, BlobIntegrityError) as error:
            raise ArtifactCommitError from error
