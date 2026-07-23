from __future__ import annotations

from typing import TYPE_CHECKING, cast

import sqlalchemy as sa
from alembic import op

from services.api.migrations.versioned_0004_guards import (
    create_hardened_provider_guards,
    drop_provider_guards,
    restore_0003_provider_guards,
)
from services.api.migrations.versioned_0004_roles import (
    converge_provider_capability_roles,
    drop_provider_capability_roles,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

revision: str = "0004_provider_security"
down_revision: str | None = "0003_provider_qualification"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_QUALIFICATION_COLUMNS = (
    "qualification_receipt_id",
    "qualification_receipt_sha256",
    "qualification_connection_revision",
    "qualification_profile_sha256",
    "qualification_runtime_version",
    "qualification_executable_sha256",
)


def upgrade() -> None:
    _preserve_observable_unsigned_healthy()
    columns = {
        column["name"] for column in sa.inspect(op.get_bind()).get_columns("runs")
    }
    if "provider_model_id" not in columns:
        op.add_column("runs", sa.Column("provider_model_id", sa.Text()))
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM runs WHERE "
        "qualification_receipt_id IS NOT NULL AND provider_model_id IS NULL) "
        "THEN RAISE EXCEPTION 'pre-0004 qualified Runs require explicit model "
        "binding remediation' USING ERRCODE = '23514'; END IF; END $$"
    )
    _replace_run_binding_constraint(include_model=True)
    converge_provider_capability_roles()
    create_hardened_provider_guards()


def downgrade() -> None:
    _refuse_history_downgrade()
    drop_provider_guards()
    drop_provider_capability_roles()
    _replace_run_binding_constraint(include_model=False)
    op.drop_column("runs", "provider_model_id")
    restore_0003_provider_guards()


def _preserve_observable_unsigned_healthy() -> None:
    op.execute(
        "ALTER TABLE provider_connections DROP CONSTRAINT IF EXISTS "
        "provider_healthy_requires_qualification, DROP CONSTRAINT IF EXISTS "
        "ck_provider_connections_provider_healthy_requires_qualification"
    )
    op.execute(
        "INSERT INTO provider_qualification_legacy_evidence (org_id, "
        "requester_user_id, provider_connection_id, classification, "
        "legacy_status, legacy_qualified_at, legacy_connection_revision, "
        "legacy_profile_sha256, legacy_runtime_version, "
        "legacy_executable_sha256, historical_run_ids) SELECT p.org_id, "
        "p.requester_user_id, p.id, 'legacy_unverified', p.status, "
        "p.qualified_at, CASE WHEN p.account_metadata ->> 'revision' ~ "
        "'^[0-9]+$' THEN (p.account_metadata ->> 'revision')::bigint ELSE NULL "
        "END, p.account_metadata ->> 'qualification_profile_sha256', "
        "p.account_metadata ->> 'qualification_runtime_version', "
        "p.account_metadata ->> 'qualification_executable_sha256', "
        "COALESCE(array_agg(r.id ORDER BY r.created_at, r.id) FILTER (WHERE r.id "
        "IS NOT NULL), '{}'::uuid[]) FROM provider_connections p LEFT JOIN runs r "
        "ON r.org_id = p.org_id AND r.requester_id = p.requester_user_id AND "
        "r.provider_connection_id = p.id WHERE p.status = 'healthy' AND "
        "p.qualification_receipt_id IS NULL GROUP BY p.org_id, "
        "p.requester_user_id, p.id, p.status, p.qualified_at, p.account_metadata "
        "ON CONFLICT (org_id, requester_user_id, provider_connection_id) DO NOTHING"
    )
    op.execute(
        "UPDATE provider_connections SET qualified_at = NULL, status = 'pending', "
        "account_metadata = account_metadata - 'qualification_receipt_id' - "
        "'qualification_runtime_version' - 'qualification_executable_sha256' - "
        "'qualification_profile_sha256' WHERE status = 'healthy' AND "
        "qualification_receipt_id IS NULL"
    )
    op.create_check_constraint(
        "provider_healthy_requires_qualification",
        "provider_connections",
        "status <> 'healthy' OR (qualified_at IS NOT NULL AND "
        "qualification_receipt_id IS NOT NULL)",
    )


def _replace_run_binding_constraint(*, include_model: bool) -> None:
    op.execute(
        "ALTER TABLE runs DROP CONSTRAINT IF EXISTS "
        "run_qualification_binding_complete, DROP CONSTRAINT IF EXISTS "
        "ck_runs_run_qualification_binding_complete"
    )
    model_columns = ("provider_model_id",) if include_model else ()
    columns = (*_QUALIFICATION_COLUMNS, *model_columns)
    empty = " AND ".join(f"{column} IS NULL" for column in columns)
    complete = " AND ".join(f"{column} IS NOT NULL" for column in columns)
    op.create_check_constraint(
        "run_qualification_binding_complete",
        "runs",
        f"({empty}) OR ({complete})",
    )


def _refuse_history_downgrade() -> None:
    bind = op.get_bind()
    history_count = 0
    for table in (
        "provider_qualification_receipts",
        "provider_qualification_legacy_evidence",
    ):
        history = bind.execute(sa.text(f"SELECT count(*) FROM {table}"))
        history_count += cast("int", history.scalar_one())
    if history_count != 0:
        message = "cannot downgrade provider qualification history"
        raise RuntimeError(message)
