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


def upgrade_executions() -> None:
    _ = op.create_table(
        "approval_requests",
        uuid_pk(),
        org_id(),
        uuid_ref("run_id"),
        uuid_ref("action_plan_id"),
        uuid_ref("requester_id"),
        uuid_ref("decided_by", nullable=True),
        sa.Column("digest", sa.String(64), nullable=False, unique=True),
        sa.Column("revision", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        created_at(),
        tenant_unique(),
        tenant_fk("run_id", "runs"),
        sa.ForeignKeyConstraint(
            ["org_id", "action_plan_id", "run_id"],
            ["action_plans.org_id", "action_plans.id", "action_plans.run_id"],
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "requester_id"],
            ["memberships.org_id", "memberships.user_id"],
            name="fk_approval_requests_requester",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "decided_by"],
            ["memberships.org_id", "memberships.user_id"],
            name="fk_approval_requests_decider",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'expired', 'consumed')",
            name="approval_status",
        ),
        sa.CheckConstraint("revision >= 1", name="approval_revision"),
    )
    _ = op.create_table(
        "executions",
        uuid_pk(),
        org_id(),
        uuid_ref("run_id"),
        uuid_ref("action_plan_id"),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("attempt_token", sa.BigInteger(), nullable=False),
        sa.Column("result_ref", sa.Text()),
        created_at(),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        tenant_unique(),
        tenant_fk("run_id", "runs"),
        sa.ForeignKeyConstraint(
            ["org_id", "action_plan_id", "run_id"],
            ["action_plans.org_id", "action_plans.id", "action_plans.run_id"],
        ),
        sa.UniqueConstraint(
            "org_id", "id", "run_id", name="uq_executions_run_identity"
        ),
        sa.CheckConstraint("attempt_token >= 1", name="execution_attempt"),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')",
            name="execution_status",
        ),
        sa.CheckConstraint(
            "status <> 'completed' OR result_ref IS NOT NULL",
            name="completed_execution_result",
        ),
    )
    _ = op.create_table(
        "execution_leases",
        org_id(),
        uuid_ref("execution_id"),
        sa.Column("attempt_token", sa.BigInteger(), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("org_id", "execution_id"),
        tenant_fk("execution_id", "executions"),
        sa.CheckConstraint("attempt_token >= 1", name="lease_attempt"),
        sa.CheckConstraint("expires_at > heartbeat_at", name="lease_expiry"),
    )
    _ = op.create_table(
        "run_skill_snapshots",
        uuid_pk(),
        org_id(),
        uuid_ref("run_id"),
        uuid_ref("skill_id"),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("kernel_hash", sa.String(64)),
        created_at(),
        tenant_unique(),
        tenant_fk("run_id", "runs"),
        tenant_fk("skill_id", "skills"),
        sa.UniqueConstraint(
            "org_id", "run_id", "skill_id", name="uq_run_skill_snapshots_skill"
        ),
    )
    _ = op.create_table(
        "connector_calls",
        uuid_pk(),
        org_id(),
        uuid_ref("run_id"),
        uuid_ref("connector_id"),
        sa.Column("source_identifier", sa.Text()),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw_object_ref", sa.Text()),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("error_code", sa.Text()),
        created_at(),
        tenant_unique(),
        tenant_fk("run_id", "runs"),
        tenant_fk("connector_id", "connectors"),
        sa.CheckConstraint(
            "status IN ('completed', 'partial', 'failed')", name="connector_call_status"
        ),
    )


def drop_executions() -> None:
    for table in (
        "connector_calls",
        "run_skill_snapshots",
        "execution_leases",
        "executions",
        "approval_requests",
    ):
        op.drop_table(table)
