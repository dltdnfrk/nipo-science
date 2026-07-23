"""Atomic durable download authorization and content reads."""

from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from .blob_store import PrivateBlobStore
from .models import ArtifactScope, ArtifactVersion
from .postgres_queries import VERSION_JSON
from .postgres_runtime import identity
from .store_contract import StoreOutcome


async def redeem_content_operation(
    connection: AsyncConnection,
    scope: ArtifactScope,
    blobs: PrivateBlobStore,
    version_id: UUID,
) -> tuple[StoreOutcome, ArtifactVersion | None, bytes | None]:
    """Read authorized Version and bytes under the active Project row lock."""
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
        return StoreOutcome.NOT_FOUND, None, None
    if not active:
        return StoreOutcome.ARCHIVED, None, None
    value: str | None = (
        await connection.execute(
            text(VERSION_JSON),
            identity(scope) | {"identity": version_id},
        )
    ).scalar_one_or_none()
    if value is None:
        return StoreOutcome.NOT_FOUND, None, None
    version = ArtifactVersion.model_validate_json(value)
    return StoreOutcome.CREATED, version, blobs.read(version.object_key)
