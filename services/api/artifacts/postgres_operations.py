"""Atomic PostgreSQL writes and reference validation for Artifact Versions."""

from dataclasses import dataclass

from pydantic import TypeAdapter
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from .blob_store import PrivateBlobStore
from .models import ArtifactScope, ArtifactVersion
from .store_contract import StoreOutcome

BOOLEAN = TypeAdapter(bool)
INTEGER = TypeAdapter(int)


@dataclass(frozen=True, slots=True)
class CommitVersionInput:
    """Bound values for one durable Version transition."""

    scope: ArtifactScope
    base_version_no: int
    version: ArtifactVersion
    payload: bytes


async def lock_content_address(
    connection: AsyncConnection,
    object_key: str,
) -> None:
    """Serialize publication and compensation for one content address."""
    _ = await connection.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": object_key},
    )


async def references_valid(
    connection: AsyncConnection,
    scope: ArtifactScope,
    version: ArtifactVersion,
) -> bool:
    """Verify execution ownership and exact same-Project lineage."""
    if len(set(version.input_version_ids)) != len(version.input_version_ids):
        return False
    execution = BOOLEAN.validate_python(
        (
            await connection.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM executions e JOIN runs r "
                    "ON r.org_id = e.org_id AND r.id = e.run_id JOIN sessions s "
                    "ON s.org_id = r.org_id AND s.id = r.session_id "
                    "WHERE e.org_id = :org AND e.id = :execution "
                    "AND s.project_id = :project AND r.requester_id = :requester "
                    "AND r.provider_connection_id = :connection "
                    "AND s.archived_at IS NULL AND EXISTS "
                    "(SELECT 1 FROM provider_connections p WHERE p.org_id = r.org_id "
                    "AND p.id = r.provider_connection_id AND p.adapter_id = :adapter) "
                    "FOR UPDATE OF s)"
                ),
                {
                    "org": scope.org_id,
                    "execution": version.producing_execution_id,
                    "project": scope.project_id,
                    "requester": scope.requester_id,
                    "connection": version.runtime_connection_id,
                    "adapter": version.runtime_adapter_id,
                },
            )
        ).scalar_one()
    )
    if not execution:
        return False
    for input_id in version.input_version_ids:
        present = BOOLEAN.validate_python(
            (
                await connection.execute(
                    text(
                        "SELECT EXISTS (SELECT 1 FROM artifact_versions "
                        "WHERE org_id = :org AND project_id = :project AND id = :id)"
                    ),
                    {"org": scope.org_id, "project": scope.project_id, "id": input_id},
                )
            ).scalar_one()
        )
        if not present:
            return False
    return True


async def commit_version_operation(
    connection: AsyncConnection,
    command: CommitVersionInput,
    blobs: PrivateBlobStore,
    touched: set[str],
) -> StoreOutcome:
    """Lock Project and Artifact, validate CAS, then publish one Version."""
    scope = command.scope
    version = command.version
    archived: bool | None = (
        await connection.execute(
            text(
                "SELECT p.archived_at IS NOT NULL FROM artifacts a "
                "JOIN projects p ON p.org_id = a.org_id AND p.id = a.project_id "
                "WHERE a.org_id = :org AND a.project_id = :project "
                "AND a.id = :artifact FOR UPDATE OF a, p"
            ),
            {
                "org": scope.org_id,
                "project": scope.project_id,
                "artifact": version.artifact_id,
            },
        )
    ).scalar_one_or_none()
    if archived is None:
        return StoreOutcome.NOT_FOUND
    if archived:
        return StoreOutcome.ARCHIVED
    current = INTEGER.validate_python(
        (
            await connection.execute(
                text(
                    "SELECT COALESCE(MAX(version), 0) FROM artifact_versions "
                    "WHERE org_id = :org AND project_id = :project "
                    "AND artifact_id = :artifact"
                ),
                {
                    "org": scope.org_id,
                    "project": scope.project_id,
                    "artifact": version.artifact_id,
                },
            )
        ).scalar_one()
    )
    if current != command.base_version_no:
        return StoreOutcome.STALE
    if not await references_valid(connection, scope, version):
        return StoreOutcome.INVALID_LINEAGE
    expected = (
        f"org/{scope.org_id}/project/{scope.project_id}/sha256/{version.content_sha256}"
    )
    if (
        version.version_no != command.base_version_no + 1
        or version.object_key != expected
        or version.size_bytes != len(command.payload)
    ):
        return StoreOutcome.INVALID_LINEAGE
    await lock_content_address(connection, expected)
    touched.add(expected)
    _ = blobs.put(expected, command.payload, version.content_sha256)
    await insert_version(connection, version)
    return StoreOutcome.CREATED


async def insert_version(
    connection: AsyncConnection,
    version: ArtifactVersion,
) -> None:
    """Insert immutable Version metadata followed by exact dependencies."""
    _ = await connection.execute(
        text(
            "INSERT INTO artifact_versions (id, org_id, project_id, artifact_id, "
            "producing_execution_id, runtime_connection_id, version, object_key, "
            "content_sha256, size_bytes, media_type, environment_sha256, "
            "code_sha256, runtime_adapter_id, skill_content_hashes, source_hashes, "
            "created_at) VALUES (:id, :org, :project, :artifact, :execution, "
            ":connection, :version, :object_key, :sha, :size, :media, :environment, "
            ":code, :adapter, CAST(:skills AS text[]), CAST(:sources AS text[]), "
            ":created)"
        ),
        {
            "id": version.id,
            "org": version.org_id,
            "project": version.project_id,
            "artifact": version.artifact_id,
            "execution": version.producing_execution_id,
            "connection": version.runtime_connection_id,
            "version": version.version_no,
            "object_key": version.object_key,
            "sha": version.content_sha256,
            "size": version.size_bytes,
            "media": version.media_type,
            "environment": version.environment_sha256,
            "code": version.code_sha256,
            "adapter": version.runtime_adapter_id,
            "skills": list(version.skill_content_hashes),
            "sources": list(version.source_hashes),
            "created": version.created_at,
        },
    )
    for input_id in version.input_version_ids:
        _ = await connection.execute(
            text(
                "INSERT INTO artifact_dependencies "
                "(org_id, project_id, artifact_version_id, input_version_id) "
                "VALUES (:org, :project, :version, :input)"
            ),
            {
                "org": version.org_id,
                "project": version.project_id,
                "version": version.id,
                "input": input_id,
            },
        )
