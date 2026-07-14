from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from services.api.migrations.migration_columns import (
    created_at,
    org_id,
    tenant_unique,
    uuid_pk,
    uuid_ref,
)


def upgrade_identity() -> None:
    _ = op.create_table(
        "organizations",
        uuid_pk(),
        sa.Column("name", sa.Text(), nullable=False),
        created_at(),
    )
    _ = op.create_table(
        "users",
        uuid_pk(),
        sa.Column("email", sa.Text(), nullable=False, unique=True),
        created_at(),
    )
    _ = op.create_table(
        "memberships",
        org_id(),
        uuid_ref("user_id"),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        created_at(),
        sa.PrimaryKeyConstraint("org_id", "user_id"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.Index(
            "uq_memberships_active_user",
            "user_id",
            unique=True,
            postgresql_where=sa.text("revoked_at IS NULL"),
        ),
        sa.CheckConstraint("role IN ('owner', 'member')", name="membership_role"),
    )
    _ = op.create_table(
        "auth_sessions",
        uuid_pk(),
        org_id(),
        uuid_ref("user_id"),
        sa.Column("token_hash", sa.LargeBinary(), nullable=False, unique=True),
        sa.Column("csrf_hash", sa.LargeBinary(), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        created_at(),
        tenant_unique(),
        sa.ForeignKeyConstraint(
            ["org_id", "user_id"],
            ["memberships.org_id", "memberships.user_id"],
        ),
    )
    _ = op.create_table(
        "consents",
        uuid_pk(),
        org_id(),
        uuid_ref("user_id"),
        sa.Column("notice_version", sa.Text(), nullable=False),
        sa.Column("consented_at", sa.DateTime(timezone=True), nullable=False),
        tenant_unique(),
        sa.ForeignKeyConstraint(
            ["org_id", "user_id"],
            ["memberships.org_id", "memberships.user_id"],
        ),
        sa.UniqueConstraint(
            "org_id",
            "user_id",
            "notice_version",
            name="uq_consents_notice",
        ),
    )
    _ = op.create_table(
        "provider_connections",
        uuid_pk(),
        org_id(),
        uuid_ref("requester_user_id"),
        sa.Column("adapter_id", sa.Text(), nullable=False),
        sa.Column("encrypted_runtime_home_ref", sa.Text(), nullable=False),
        sa.Column(
            "account_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("selected_model", sa.Text()),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("qualified_at", sa.DateTime(timezone=True)),
        sa.Column("health_checked_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        created_at(),
        tenant_unique(),
        sa.UniqueConstraint(
            "org_id",
            "id",
            "requester_user_id",
            name="uq_provider_connections_requester",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "requester_user_id"],
            ["memberships.org_id", "memberships.user_id"],
        ),
        sa.CheckConstraint(
            "adapter_id IN ('openai_codex', 'anthropic_claude_code', "
            "'xai_grok_build', 'moonshot_kimi_code', 'zai_glm')",
            name="provider_adapter",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'healthy', 'reauth_required', 'revoked', "
            "'unsupported_auth')",
            name="provider_status",
        ),
        sa.CheckConstraint(
            "encrypted_runtime_home_ref ~ "
            "'^vault://runtime/[A-Za-z0-9][A-Za-z0-9._/-]*$' "
            "AND position('..' in encrypted_runtime_home_ref) = 0",
            name="provider_runtime_home_opaque_ref",
        ),
    )


def drop_identity() -> None:
    for table in (
        "provider_connections",
        "consents",
        "auth_sessions",
        "memberships",
        "users",
        "organizations",
    ):
        op.drop_table(table)
