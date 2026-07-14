from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from services.api.migrations.migration_columns import (
    created_at,
    org_id,
    tenant_fk,
    tenant_unique,
    uuid_pk,
    uuid_ref,
)


def upgrade_artifacts() -> None:
    _ = op.create_table(
        "artifacts",
        uuid_pk(),
        org_id(),
        uuid_ref("project_id"),
        sa.Column("name", sa.Text(), nullable=False),
        created_at(),
        tenant_unique(),
        sa.UniqueConstraint(
            "org_id", "project_id", "id", name="uq_artifacts_project_identity"
        ),
        tenant_fk("project_id", "projects"),
    )
    _ = op.create_table(
        "artifact_versions",
        uuid_pk(),
        org_id(),
        uuid_ref("project_id"),
        uuid_ref("artifact_id"),
        uuid_ref("producing_execution_id"),
        uuid_ref("runtime_connection_id"),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("object_key", sa.Text(), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("media_type", sa.Text(), nullable=False),
        sa.Column("environment_sha256", sa.String(64), nullable=False),
        sa.Column("code_sha256", sa.String(64), nullable=False),
        sa.Column("runtime_adapter_id", sa.Text(), nullable=False),
        sa.Column("skill_content_hashes", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("source_hashes", postgresql.ARRAY(sa.Text()), nullable=False),
        created_at(),
        tenant_unique(),
        sa.UniqueConstraint(
            "org_id", "project_id", "id", name="uq_artifact_versions_project_identity"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "artifact_id"],
            ["artifacts.org_id", "artifacts.project_id", "artifacts.id"],
            name="fk_artifact_versions_project_artifact",
        ),
        tenant_fk("producing_execution_id", "executions"),
        tenant_fk("runtime_connection_id", "provider_connections"),
        sa.UniqueConstraint(
            "org_id", "artifact_id", "version", name="uq_artifact_versions_version"
        ),
        sa.CheckConstraint("version >= 1", name="artifact_version_number"),
        sa.CheckConstraint("size_bytes >= 0", name="artifact_version_size"),
        sa.CheckConstraint(
            "content_sha256 ~ '^[0-9a-f]{64}$'", name="artifact_content_hash"
        ),
        sa.CheckConstraint(
            "object_key = 'org/' || org_id::text || '/project/' || "
            "project_id::text || '/sha256/' || content_sha256",
            name="artifact_object_key",
        ),
    )
    _ = op.create_table(
        "artifact_dependencies",
        org_id(),
        uuid_ref("project_id"),
        uuid_ref("artifact_version_id"),
        uuid_ref("input_version_id"),
        created_at(),
        sa.PrimaryKeyConstraint(
            "org_id", "project_id", "artifact_version_id", "input_version_id"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "artifact_version_id"],
            [
                "artifact_versions.org_id",
                "artifact_versions.project_id",
                "artifact_versions.id",
            ],
            name="fk_artifact_dependencies_derived",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "input_version_id"],
            [
                "artifact_versions.org_id",
                "artifact_versions.project_id",
                "artifact_versions.id",
            ],
            name="fk_artifact_dependencies_input",
        ),
        sa.CheckConstraint(
            "artifact_version_id <> input_version_id", name="artifact_dependency_cycle"
        ),
    )
    _ = op.create_table(
        "session_artifact_versions",
        org_id(),
        uuid_ref("project_id"),
        uuid_ref("session_id"),
        uuid_ref("artifact_version_id"),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        created_at(),
        sa.PrimaryKeyConstraint(
            "org_id", "project_id", "session_id", "artifact_version_id"
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "session_id"],
            ["sessions.org_id", "sessions.project_id", "sessions.id"],
            name="fk_session_artifact_versions_project_session",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "project_id", "artifact_version_id"],
            [
                "artifact_versions.org_id",
                "artifact_versions.project_id",
                "artifact_versions.id",
            ],
            name="fk_session_artifact_versions_project_version",
        ),
        sa.CheckConstraint("revision >= 1", name="session_artifact_revision"),
    )


def drop_artifacts() -> None:
    for table in (
        "session_artifact_versions",
        "artifact_dependencies",
        "artifact_versions",
        "artifacts",
    ):
        op.drop_table(table)
