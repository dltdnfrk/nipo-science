"""Forced-RLS Artifact project resolution from authenticated principal identity."""

from __future__ import annotations

from typing import TYPE_CHECKING, final

from sqlalchemy import text

from .models import ArtifactScope
from .postgres_runtime import run_principal_scoped

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncConnection


@final
class PostgresArtifactScopeResolver:
    """Derive Artifact scopes only from rows visible to the current principal."""

    def __init__(self, database_url: str) -> None:
        """Bind the same PostgreSQL authority used by the durable store."""
        self._database_url = database_url

    def artifact_scope(
        self,
        org_id: UUID,
        requester_id: UUID,
        artifact_id: UUID,
    ) -> ArtifactScope | None:
        """Resolve one active Artifact's Project under requester-scoped RLS."""
        return self._resolve(org_id, requester_id, artifact_id, None)

    def version_scope(
        self,
        org_id: UUID,
        requester_id: UUID,
        artifact_id: UUID,
        version_id: UUID,
    ) -> ArtifactScope | None:
        """Resolve one exact active Version and its parent Artifact scope."""
        return self._resolve(org_id, requester_id, artifact_id, version_id)

    def _resolve(
        self,
        org_id: UUID,
        requester_id: UUID,
        artifact_id: UUID,
        version_id: UUID | None,
    ) -> ArtifactScope | None:
        async def operation(connection: AsyncConnection) -> UUID | None:
            if version_id is None:
                query = (
                    "SELECT artifact.project_id FROM artifacts artifact "
                    "JOIN projects project ON project.org_id = artifact.org_id "
                    "AND project.id = artifact.project_id "
                    "WHERE artifact.org_id = :org AND artifact.id = :artifact "
                    "AND project.archived_at IS NULL"
                )
                values = {"org": org_id, "artifact": artifact_id}
            else:
                query = (
                    "SELECT version.project_id FROM artifact_versions version "
                    "JOIN projects project ON project.org_id = version.org_id "
                    "AND project.id = version.project_id "
                    "WHERE version.org_id = :org AND version.artifact_id = :artifact "
                    "AND version.id = :version AND project.archived_at IS NULL"
                )
                values = {
                    "org": org_id,
                    "artifact": artifact_id,
                    "version": version_id,
                }
            return (await connection.execute(text(query), values)).scalar_one_or_none()

        project_id = run_principal_scoped(
            self._database_url,
            org_id,
            requester_id,
            operation,
        )
        if project_id is None:
            return None
        return ArtifactScope(
            org_id=org_id,
            project_id=project_id,
            requester_id=requester_id,
        )
