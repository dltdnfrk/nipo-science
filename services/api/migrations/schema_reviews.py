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

REVIEWER_CAPABILITIES_SQL = (
    "jsonb_build_object('runner', false, 'python', false, 'bash', false, "
    "'connector', false, 'network', false, 'artifact_write', false, "
    "'tool_execute', false, 'version_update', false, 'reexecution', false)"
)


def upgrade_reviews() -> None:
    _ = op.create_table(
        "reviews",
        uuid_pk(),
        org_id(),
        uuid_ref("source_run_id"),
        uuid_ref("run_id"),
        uuid_ref("submission_id", nullable=True),
        sa.Column("revision", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("submitted_at", sa.DateTime(timezone=True)),
        sa.Column("pinned_input_sha256", sa.String(64), nullable=False),
        sa.Column(
            "reviewer_capabilities",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text(REVIEWER_CAPABILITIES_SQL),
        ),
        sa.Column("status", sa.Text(), nullable=False),
        created_at(),
        tenant_unique(),
        tenant_fk("source_run_id", "runs", "fk_reviews_source_run"),
        tenant_fk("run_id", "runs", "fk_reviews_review_run"),
        sa.UniqueConstraint(
            "org_id", "pinned_input_sha256", name="uq_reviews_pinned_input"
        ),
        sa.UniqueConstraint(
            "org_id", "id", "submission_id", name="uq_reviews_submission"
        ),
        sa.UniqueConstraint(
            "org_id", "submission_id", name="uq_reviews_submission_once"
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed')",
            name="review_status",
        ),
        sa.CheckConstraint("revision >= 1", name="review_revision"),
        sa.CheckConstraint(
            "(submission_id IS NULL) = (submitted_at IS NULL)",
            name="review_submission_lifecycle",
        ),
        sa.CheckConstraint(
            f"reviewer_capabilities = {REVIEWER_CAPABILITIES_SQL}",
            name="reviewer_nonexecution",
        ),
    )
    _ = op.create_table(
        "review_artifact_versions",
        org_id(),
        uuid_ref("review_id"),
        uuid_ref("artifact_version_id"),
        sa.PrimaryKeyConstraint("org_id", "review_id", "artifact_version_id"),
        tenant_fk("review_id", "reviews"),
        tenant_fk("artifact_version_id", "artifact_versions"),
    )
    _ = op.create_table(
        "review_execution_refs",
        org_id(),
        uuid_ref("review_id"),
        uuid_ref("execution_id"),
        sa.PrimaryKeyConstraint("org_id", "review_id", "execution_id"),
        tenant_fk("review_id", "reviews"),
        tenant_fk("execution_id", "executions"),
    )
    _ = op.create_table(
        "review_findings",
        uuid_pk(),
        org_id(),
        uuid_ref("review_id"),
        uuid_ref("submission_id"),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("verdict", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        uuid_ref("disposition_actor_id", nullable=True),
        sa.Column("disposition_reason", sa.Text()),
        created_at(),
        tenant_unique(),
        tenant_fk("review_id", "reviews", "fk_review_findings_review"),
        sa.ForeignKeyConstraint(
            ["org_id", "review_id", "submission_id"],
            ["reviews.org_id", "reviews.id", "reviews.submission_id"],
            name="fk_review_findings_submission",
        ),
        sa.CheckConstraint(
            "rule_id IN ('RV01', 'RV02', 'RV03', 'RV04', 'RV05')",
            name="review_rule",
        ),
        sa.CheckConstraint(
            "verdict IN ('pass', 'warn', 'fail', 'inconclusive')",
            name="finding_verdict",
        ),
        sa.CheckConstraint(
            "status IN ('open', 'resolved', 'rebutted', 'accepted_risk')",
            name="finding_status",
        ),
        sa.ForeignKeyConstraint(
            ["org_id", "disposition_actor_id"],
            ["memberships.org_id", "memberships.user_id"],
            name="fk_review_findings_disposition_actor",
        ),
        sa.CheckConstraint(
            "((status IN ('rebutted', 'accepted_risk')) = "
            "(disposition_actor_id IS NOT NULL AND disposition_reason IS NOT NULL)) "
            "AND (status IN ('rebutted', 'accepted_risk') OR "
            "(disposition_actor_id IS NULL AND disposition_reason IS NULL))",
            name="finding_disposition_audit",
        ),
    )
    _ = op.create_table(
        "review_finding_artifact_versions",
        org_id(),
        uuid_ref("finding_id"),
        uuid_ref("artifact_version_id"),
        sa.PrimaryKeyConstraint("org_id", "finding_id", "artifact_version_id"),
        tenant_fk("finding_id", "review_findings"),
        tenant_fk("artifact_version_id", "artifact_versions"),
    )
    _ = op.create_table(
        "review_finding_execution_refs",
        org_id(),
        uuid_ref("finding_id"),
        uuid_ref("execution_id"),
        sa.PrimaryKeyConstraint("org_id", "finding_id", "execution_id"),
        tenant_fk("finding_id", "review_findings"),
        tenant_fk("execution_id", "executions"),
    )
    _ = op.create_table(
        "export_jobs",
        uuid_pk(),
        org_id(),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("object_key", sa.Text()),
        sa.Column("manifest_sha256", sa.String(64)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        created_at(),
        tenant_unique(),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed')",
            name="export_status",
        ),
    )
    _ = op.create_table(
        "export_artifact_versions",
        org_id(),
        uuid_ref("export_id"),
        uuid_ref("artifact_version_id"),
        sa.Column("archive_path", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("org_id", "export_id", "artifact_version_id"),
        tenant_fk("export_id", "export_jobs"),
        tenant_fk("artifact_version_id", "artifact_versions"),
        sa.UniqueConstraint(
            "org_id",
            "export_id",
            "archive_path",
            name="uq_export_versions_archive_path",
        ),
    )


def drop_reviews() -> None:
    for table in (
        "export_artifact_versions",
        "export_jobs",
        "review_finding_execution_refs",
        "review_finding_artifact_versions",
        "review_findings",
        "review_execution_refs",
        "review_artifact_versions",
        "reviews",
    ):
        op.drop_table(table)
