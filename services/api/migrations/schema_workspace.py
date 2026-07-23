from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from services.api.migrations.migration_columns import (
    created_at,
    org_id,
    tenant_fk,
    tenant_unique,
    uuid_pk,
    uuid_ref,
)


def upgrade_workspace() -> None:
    _ = op.create_table(
        "projects",
        uuid_pk(),
        org_id(),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("archived_at", sa.DateTime(timezone=True)),
        created_at(),
        tenant_unique(),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.CheckConstraint("revision >= 1", name="project_revision"),
    )
    _ = op.create_table(
        "sessions",
        uuid_pk(),
        org_id(),
        uuid_ref("project_id"),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("archived_at", sa.DateTime(timezone=True)),
        created_at(),
        tenant_unique(),
        sa.UniqueConstraint(
            "org_id", "project_id", "id", name="uq_sessions_project_identity"
        ),
        tenant_fk("project_id", "projects"),
        sa.CheckConstraint("revision >= 1", name="session_revision"),
    )
    _ = op.create_table(
        "uploaded_files",
        uuid_pk(),
        org_id(),
        uuid_ref("project_id"),
        sa.Column("filename", sa.Text(), nullable=False),
        sa.Column("media_type", sa.Text(), nullable=False),
        sa.Column("object_key", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        created_at(),
        tenant_unique(),
        tenant_fk("project_id", "projects"),
        sa.CheckConstraint(
            "status IN ('pending', 'clean', 'rejected')", name="upload_status"
        ),
    )
    _ = op.create_table(
        "skills",
        uuid_pk(),
        org_id(),
        uuid_ref("project_id"),
        sa.Column("skill_id", sa.Text(), nullable=False),
        sa.Column("semantic_version", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("kernel_hash", sa.String(64)),
        created_at(),
        tenant_unique(),
        tenant_fk("project_id", "projects"),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "skill_id",
            "semantic_version",
            name="uq_skills_version",
        ),
        sa.CheckConstraint(
            "skill_id IN ('literature-review', 'source-attribution', "
            "'probe-diagnostic')",
            name="canonical_skill_id",
        ),
    )
    _ = op.create_table(
        "connectors",
        uuid_pk(),
        org_id(),
        uuid_ref("project_id"),
        sa.Column("connector_id", sa.Text(), nullable=False),
        sa.Column("base_url", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        created_at(),
        tenant_unique(),
        tenant_fk("project_id", "projects"),
        sa.UniqueConstraint(
            "org_id",
            "project_id",
            "connector_id",
            name="uq_connectors_registry",
        ),
        sa.CheckConstraint(
            "(connector_id = 'pubmed' AND "
            "base_url = 'https://pubmed.ncbi.nlm.nih.gov') OR "
            "(connector_id = 'openalex' AND "
            "base_url = 'https://api.openalex.org')",
            name="canonical_connector_registry",
        ),
    )
    _ = op.create_table(
        "credentials",
        uuid_pk(),
        org_id(),
        uuid_ref("project_id"),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("encrypted_data_key", sa.LargeBinary(), nullable=False),
        sa.Column("kms_key_ref", sa.Text(), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        created_at(),
        tenant_unique(),
        tenant_fk("project_id", "projects"),
    )
    _ = op.create_table(
        "tool_grants",
        uuid_pk(),
        org_id(),
        uuid_ref("project_id"),
        sa.Column("tool", sa.Text(), nullable=False),
        sa.Column("effect", sa.Text(), nullable=False),
        created_at(),
        tenant_unique(),
        tenant_fk("project_id", "projects"),
        sa.UniqueConstraint(
            "org_id", "project_id", "tool", name="uq_tool_grants_project_tool"
        ),
        sa.CheckConstraint("effect IN ('allow', 'ask', 'deny')", name="grant_effect"),
    )


def drop_workspace() -> None:
    for table in (
        "tool_grants",
        "credentials",
        "connectors",
        "skills",
        "uploaded_files",
        "sessions",
        "projects",
    ):
        op.drop_table(table)
