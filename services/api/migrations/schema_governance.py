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


def upgrade_governance() -> None:
    _ = op.create_table(
        "idempotency_records",
        uuid_pk(),
        org_id(),
        uuid_ref("requester_id"),
        sa.Column("idempotency_key", sa.Text(), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("response_status", sa.Integer()),
        sa.Column("response_ref", sa.Text()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        created_at(),
        tenant_unique(),
        sa.ForeignKeyConstraint(
            ["org_id", "requester_id"],
            ["memberships.org_id", "memberships.user_id"],
        ),
        sa.UniqueConstraint(
            "org_id",
            "requester_id",
            "idempotency_key",
            name="uq_idempotency_requester_key",
        ),
    )
    _ = op.create_table(
        "audit_logs",
        uuid_pk(),
        org_id(),
        uuid_ref("actor_user_id", nullable=True),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("resource_type", sa.Text(), nullable=False),
        uuid_ref("resource_id", nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        created_at(),
        tenant_unique(),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(
            ["org_id", "actor_user_id"],
            ["memberships.org_id", "memberships.user_id"],
        ),
    )
    _ = op.create_table(
        "audit_outbox",
        uuid_pk(),
        org_id(),
        uuid_ref("audit_log_id"),
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        created_at(),
        tenant_unique(),
        tenant_fk("audit_log_id", "audit_logs"),
        sa.UniqueConstraint("org_id", "audit_log_id", name="uq_audit_outbox_event"),
    )
    _ = op.create_table(
        "deletion_requests",
        uuid_pk(),
        org_id(),
        uuid_ref("project_id"),
        uuid_ref("requested_by"),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("held_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        created_at(),
        tenant_unique(),
        tenant_fk("project_id", "projects"),
        sa.ForeignKeyConstraint(
            ["org_id", "requested_by"],
            ["memberships.org_id", "memberships.user_id"],
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'held', 'failed')",
            name="deletion_status",
        ),
    )
    _ = op.create_table(
        "deletion_receipts",
        uuid_pk(),
        org_id(),
        uuid_ref("deletion_request_id"),
        sa.Column("system", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        created_at(),
        tenant_unique(),
        tenant_fk("deletion_request_id", "deletion_requests"),
        sa.UniqueConstraint(
            "org_id",
            "deletion_request_id",
            "system",
            name="uq_deletion_receipts_system",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'completed', 'failed', 'disabled')",
            name="receipt_status",
        ),
    )
    _ = op.create_table(
        "deletion_tombstones",
        uuid_pk(),
        org_id(),
        uuid_ref("deletion_request_id"),
        sa.Column("resource_type", sa.Text(), nullable=False),
        uuid_ref("resource_id"),
        sa.Column("tombstoned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "replay_generation", sa.BigInteger(), nullable=False, server_default="1"
        ),
        tenant_unique(),
        tenant_fk("deletion_request_id", "deletion_requests"),
        sa.UniqueConstraint(
            "org_id",
            "resource_type",
            "resource_id",
            name="uq_deletion_tombstones_resource",
        ),
        sa.CheckConstraint("replay_generation >= 1", name="tombstone_generation"),
    )
    _ = op.create_table(
        "legal_holds",
        uuid_pk(),
        org_id(),
        sa.Column("scope_type", sa.Text(), nullable=False),
        uuid_ref("scope_id"),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("actor_authority", sa.Text(), nullable=False),
        sa.Column("actor_ref", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        created_at(),
        tenant_unique(),
        tenant_fk("scope_id", "projects", "fk_legal_holds_project_scope"),
        sa.CheckConstraint("scope_type = 'project'", name="hold_scope_type"),
        sa.CheckConstraint("action IN ('place', 'release')", name="hold_action"),
        sa.CheckConstraint(
            "actor_authority = 'compliance_operator'", name="hold_authority"
        ),
    )


def drop_governance() -> None:
    for table in (
        "legal_holds",
        "deletion_tombstones",
        "deletion_receipts",
        "deletion_requests",
        "audit_outbox",
        "audit_logs",
        "idempotency_records",
    ):
        op.drop_table(table)
