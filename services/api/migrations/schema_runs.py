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


def upgrade_runs() -> None:
    _ = op.create_table(
        "runs",
        uuid_pk(),
        org_id(),
        uuid_ref("session_id"),
        uuid_ref("requester_id"),
        uuid_ref("provider_connection_id"),
        uuid_ref("retry_of_run_id", nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        created_at(),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        tenant_unique(),
        tenant_fk("session_id", "sessions"),
        sa.ForeignKeyConstraint(
            ["org_id", "provider_connection_id", "requester_id"],
            [
                "provider_connections.org_id",
                "provider_connections.id",
                "provider_connections.requester_user_id",
            ],
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "retry_of_run_id"],
            ["runs.org_id", "runs.id"],
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'awaiting_user', "
            "'awaiting_approval', 'completed', 'failed', 'cancelled')",
            name="run_status",
        ),
    )
    _ = op.create_table(
        "messages",
        uuid_pk(),
        org_id(),
        uuid_ref("run_id"),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        created_at(),
        tenant_unique(),
        tenant_fk("run_id", "runs"),
        sa.CheckConstraint(
            "role IN ('user', 'assistant', 'tool')", name="message_role"
        ),
    )
    _ = op.create_table(
        "run_events",
        uuid_pk(),
        org_id(),
        uuid_ref("run_id"),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column(
            "data",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        created_at(),
        tenant_unique(),
        tenant_fk("run_id", "runs"),
        sa.UniqueConstraint(
            "org_id", "run_id", "sequence", name="uq_run_events_sequence"
        ),
        sa.CheckConstraint("sequence >= 1", name="run_event_sequence"),
    )
    _ = op.create_table(
        "action_plans",
        uuid_pk(),
        org_id(),
        uuid_ref("run_id"),
        uuid_ref("requester_id"),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("tool", sa.Text(), nullable=False),
        sa.Column("arguments", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("arguments_hash", sa.String(64), nullable=False),
        sa.Column("network_scope", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("secret_scope", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("plan_digest", sa.String(64), nullable=False),
        created_at(),
        tenant_unique(),
        tenant_fk("run_id", "runs"),
        sa.ForeignKeyConstraint(
            ["org_id", "requester_id"],
            ["memberships.org_id", "memberships.user_id"],
        ),
        sa.UniqueConstraint(
            "org_id", "run_id", "version", name="uq_action_plans_version"
        ),
        sa.UniqueConstraint(
            "org_id", "id", "run_id", name="uq_action_plans_run_identity"
        ),
        sa.CheckConstraint("version >= 1", name="action_plan_version"),
    )


def drop_runs() -> None:
    for table in ("action_plans", "run_events", "messages", "runs"):
        op.drop_table(table)
