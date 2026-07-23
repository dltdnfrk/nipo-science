from __future__ import annotations

from typing import TYPE_CHECKING, cast

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from services.api.migrations.integrity_policies import (
    create_provider_qualification_guards,
)
from services.api.migrations.migration_columns import (
    created_at,
    org_id,
    tenant_unique,
    uuid_pk,
    uuid_ref,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

revision: str = "0003_provider_qualification"
down_revision: str | None = "0002_head_schema_upgrade"
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
_METADATA_KEYS_0002 = (
    "ARRAY['accountid','accountname','adoptionstatus','cleanuprequestedat',"
    "'cleanupstatus','destroyby','destroyedat','displayname','email',"
    "'evidencesha256','lastverifiedat','model','models','provider','revision',"
    "'qualificationexecutablesha256','qualificationprofilesha256',"
    "'qualificationruntimeversion','stagingleaseid','stagingleasedestroyby',"
    "'subscriptiontier','username','workspaceid']::text[]"
)
_METADATA_KEYS_0003 = _METADATA_KEYS_0002.replace(
    "'qualificationruntimeversion'",
    "'qualificationreceiptid','qualificationruntimeversion'",
)


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "provider_qualification_receipts" not in inspector.get_table_names():
        _create_receipt_table()
    if "provider_qualification_legacy_evidence" not in inspector.get_table_names():
        _create_legacy_evidence_table()
    provider_columns = {
        column["name"] for column in inspector.get_columns("provider_connections")
    }
    if "qualification_receipt_id" not in provider_columns:
        op.add_column(
            "provider_connections",
            sa.Column(
                "qualification_receipt_id",
                postgresql.UUID(as_uuid=True),
                nullable=True,
            ),
        )
    op.execute(
        "ALTER TABLE provider_connections DROP CONSTRAINT IF EXISTS "
        "fk_provider_connections_current_qualification"
    )
    op.create_foreign_key(
        "fk_provider_connections_current_qualification",
        "provider_connections",
        "provider_qualification_receipts",
        ["org_id", "qualification_receipt_id", "requester_user_id", "id"],
        ["org_id", "id", "requester_user_id", "provider_connection_id"],
    )
    _archive_legacy_qualification()
    op.execute(
        "UPDATE provider_connections SET qualified_at = NULL, "
        "qualification_receipt_id = NULL, status = CASE WHEN status = 'healthy' "
        "THEN 'pending' ELSE status END, account_metadata = account_metadata - "
        "'qualification_receipt_id' - 'qualification_runtime_version' - "
        "'qualification_executable_sha256' - 'qualification_profile_sha256' "
        "WHERE qualification_receipt_id IS NULL"
    )
    run_columns = {column["name"] for column in inspector.get_columns("runs")}
    _ensure_run_binding(run_columns)
    op.execute(
        "ALTER TABLE provider_connections DROP CONSTRAINT IF EXISTS "
        "provider_healthy_requires_qualification"
    )
    op.create_check_constraint(
        "provider_healthy_requires_qualification",
        "provider_connections",
        "status <> 'healthy' OR (qualified_at IS NOT NULL AND "
        "qualification_receipt_id IS NOT NULL)",
    )
    _apply_receipt_policy()
    _replace_metadata_guard(_METADATA_KEYS_0003)
    op.execute("DROP FUNCTION IF EXISTS validate_run_qualification_binding() CASCADE")
    op.execute(
        "DROP FUNCTION IF EXISTS validate_provider_qualification_pointer() CASCADE"
    )
    create_provider_qualification_guards()


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    history_count = 0
    for table in (
        "provider_qualification_receipts",
        "provider_qualification_legacy_evidence",
    ):
        if table in tables:
            history = bind.execute(sa.text(f"SELECT count(*) FROM {table}"))
            history_count += cast("int", history.scalar_one())
    if history_count != 0:
        msg = "cannot downgrade provider qualification history"
        raise RuntimeError(msg)
    op.execute("DROP FUNCTION IF EXISTS validate_run_qualification_binding() CASCADE")
    op.execute(
        "DROP FUNCTION IF EXISTS validate_provider_qualification_pointer() CASCADE"
    )
    _replace_metadata_guard(_METADATA_KEYS_0002)
    op.execute(
        "ALTER TABLE provider_connections DROP CONSTRAINT IF EXISTS "
        "provider_healthy_requires_qualification, DROP CONSTRAINT IF EXISTS "
        "fk_provider_connections_current_qualification"
    )
    op.execute(
        "ALTER TABLE runs DROP CONSTRAINT IF EXISTS "
        "fk_runs_exact_provider_qualification, DROP CONSTRAINT IF EXISTS "
        "run_qualification_binding_complete, DROP CONSTRAINT IF EXISTS "
        "ck_runs_run_qualification_binding_complete"
    )
    role = bind.execute(
        sa.text(
            "SELECT count(*) FROM pg_roles WHERE rolname = "
            "'science_workbench_qualification'"
        )
    )
    if cast("int", role.scalar_one()) == 1:
        op.execute(
            "REVOKE UPDATE (account_metadata, qualified_at, "
            "qualification_receipt_id) ON provider_connections "
            "FROM science_workbench_qualification"
        )
        op.execute(
            "REVOKE ALL ON provider_connections, "
            "provider_qualification_receipts, "
            "provider_qualification_legacy_evidence FROM "
            "science_workbench_qualification"
        )
        op.execute(
            "REVOKE USAGE ON SCHEMA public FROM science_workbench_qualification"
        )
        op.execute("DROP ROLE science_workbench_qualification")
    op.execute(
        "ALTER TABLE runs "
        + ", ".join(
            f"DROP COLUMN IF EXISTS {column}"
            for column in reversed(_QUALIFICATION_COLUMNS)
        )
    )
    op.execute(
        "ALTER TABLE provider_connections DROP COLUMN IF EXISTS "
        "qualification_receipt_id"
    )
    op.execute("DROP TABLE IF EXISTS provider_qualification_legacy_evidence")
    op.execute("DROP TABLE IF EXISTS provider_qualification_receipts")


def _create_receipt_table() -> None:
    _ = op.create_table(
        "provider_qualification_receipts",
        uuid_pk(),
        org_id(),
        uuid_ref("requester_user_id"),
        uuid_ref("provider_connection_id"),
        sa.Column("connection_revision", sa.BigInteger(), nullable=False),
        sa.Column("adapter_id", sa.Text(), nullable=False),
        sa.Column("profile_sha256", sa.String(length=64), nullable=False),
        sa.Column("cases_sha256", sa.String(length=64), nullable=False),
        sa.Column("operator_account_ref", sa.Text(), nullable=False),
        sa.Column("oauth_mode", sa.Text(), nullable=False),
        sa.Column("oauth_provider", sa.Text(), nullable=False),
        sa.Column("runtime_version", sa.Text(), nullable=False),
        sa.Column("executable_sha256", sa.String(length=64), nullable=False),
        sa.Column("protocol_attempts", sa.Integer(), nullable=False),
        sa.Column("cleanup_terminal", sa.Boolean(), nullable=False),
        sa.Column("cleanup_redaction_complete", sa.Boolean(), nullable=False),
        sa.Column("authority_key_id", sa.Text(), nullable=False),
        sa.Column("authority_issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authority_algorithm", sa.Text(), nullable=False),
        sa.Column("authority_signature", sa.Text(), nullable=False),
        sa.Column("receipt_sha256", sa.String(length=64), nullable=False),
        created_at(),
        tenant_unique(),
        sa.ForeignKeyConstraint(
            ["org_id", "provider_connection_id", "requester_user_id"],
            [
                "provider_connections.org_id",
                "provider_connections.id",
                "provider_connections.requester_user_id",
            ],
        ),
        sa.UniqueConstraint(
            "org_id",
            "requester_user_id",
            "provider_connection_id",
            "connection_revision",
            name="uq_provider_qualification_subject_revision",
        ),
        sa.UniqueConstraint(
            "org_id",
            "requester_user_id",
            "provider_connection_id",
            "id",
            "receipt_sha256",
            "connection_revision",
            "profile_sha256",
            "runtime_version",
            "executable_sha256",
            name="uq_provider_qualification_run_binding",
        ),
        sa.UniqueConstraint(
            "org_id",
            "id",
            "requester_user_id",
            "provider_connection_id",
            name="uq_provider_qualification_current_pointer",
        ),
        sa.CheckConstraint("connection_revision >= 2", name="qualification_revision"),
        sa.CheckConstraint(
            "adapter_id = 'openai_codex' AND "
            "oauth_mode = 'official_subscription_oauth' AND "
            "oauth_provider = 'openai'",
            name="qualification_oauth_adapter",
        ),
        sa.CheckConstraint(
            "profile_sha256 ~ '^[0-9a-f]{64}$' AND "
            "cases_sha256 ~ '^[0-9a-f]{64}$' AND "
            "executable_sha256 ~ '^[0-9a-f]{64}$' AND "
            "receipt_sha256 ~ '^[0-9a-f]{64}$'",
            name="qualification_digests",
        ),
        sa.CheckConstraint(
            "protocol_attempts = 30 AND cleanup_terminal AND "
            "cleanup_redaction_complete",
            name="qualification_capture_complete",
        ),
        sa.CheckConstraint(
            "authority_algorithm = 'RSASSA-PKCS1-v1_5/SHA-256' AND "
            "length(authority_signature) = 768 AND "
            "authority_signature ~ '^[0-9a-f]+$'",
            name="qualification_signature_policy",
        ),
        sa.CheckConstraint(
            "authority_issued_at <= created_at",
            name="qualification_issued_before_recorded",
        ),
    )


def _create_legacy_evidence_table() -> None:
    _ = op.create_table(
        "provider_qualification_legacy_evidence",
        uuid_pk(),
        org_id(),
        uuid_ref("requester_user_id"),
        uuid_ref("provider_connection_id"),
        sa.Column("classification", sa.Text(), nullable=False),
        sa.Column("legacy_status", sa.Text(), nullable=False),
        sa.Column("legacy_qualified_at", sa.DateTime(timezone=True)),
        sa.Column("legacy_connection_revision", sa.BigInteger()),
        sa.Column("legacy_profile_sha256", sa.String(length=64)),
        sa.Column("legacy_runtime_version", sa.Text()),
        sa.Column("legacy_executable_sha256", sa.String(length=64)),
        sa.Column(
            "historical_run_ids",
            postgresql.ARRAY(postgresql.UUID(as_uuid=True)),
            nullable=False,
            server_default=sa.text("'{}'::uuid[]"),
        ),
        created_at(),
        tenant_unique(),
        sa.ForeignKeyConstraint(
            ["org_id", "provider_connection_id", "requester_user_id"],
            [
                "provider_connections.org_id",
                "provider_connections.id",
                "provider_connections.requester_user_id",
            ],
        ),
        sa.UniqueConstraint(
            "org_id",
            "requester_user_id",
            "provider_connection_id",
            name="uq_provider_qualification_legacy_connection",
        ),
        sa.CheckConstraint(
            "classification = 'legacy_unverified'",
            name="qualification_legacy_classification",
        ),
        sa.CheckConstraint(
            "legacy_connection_revision IS NULL OR "
            "legacy_connection_revision >= 1",
            name="qualification_legacy_revision",
        ),
        sa.CheckConstraint(
            "(legacy_profile_sha256 IS NULL OR legacy_profile_sha256 ~ "
            "'^[0-9a-f]{64}$') AND (legacy_executable_sha256 IS NULL OR "
            "legacy_executable_sha256 ~ '^[0-9a-f]{64}$')",
            name="qualification_legacy_digests",
        ),
    )


def _archive_legacy_qualification() -> None:
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
        "COALESCE(array_agg(r.id ORDER BY r.created_at, r.id) FILTER (WHERE r.id IS "
        "NOT NULL), '{}'::uuid[]) FROM provider_connections p LEFT JOIN runs r "
        "ON r.org_id = p.org_id AND r.requester_id = p.requester_user_id AND "
        "r.provider_connection_id = p.id WHERE p.status = 'healthy' OR "
        "p.qualified_at IS NOT NULL OR "
        "p.account_metadata ?| ARRAY['qualification_profile_sha256', "
        "'qualification_runtime_version', 'qualification_executable_sha256'] "
        "GROUP BY p.org_id, p.requester_user_id, p.id, p.status, p.qualified_at, "
        "p.account_metadata ON CONFLICT (org_id, requester_user_id, "
        "provider_connection_id) DO NOTHING"
    )


def _ensure_run_binding(existing: set[str]) -> None:
    if "qualification_receipt_id" not in existing:
        op.add_column("runs", uuid_ref("qualification_receipt_id", nullable=True))
    if "qualification_receipt_sha256" not in existing:
        op.add_column(
            "runs", sa.Column("qualification_receipt_sha256", sa.String(64))
        )
    if "qualification_connection_revision" not in existing:
        op.add_column(
            "runs",
            sa.Column("qualification_connection_revision", sa.BigInteger()),
        )
    if "qualification_profile_sha256" not in existing:
        op.add_column(
            "runs", sa.Column("qualification_profile_sha256", sa.String(64))
        )
    if "qualification_runtime_version" not in existing:
        op.add_column("runs", sa.Column("qualification_runtime_version", sa.Text()))
    if "qualification_executable_sha256" not in existing:
        op.add_column(
            "runs",
            sa.Column("qualification_executable_sha256", sa.String(64)),
        )
    op.execute(
        "ALTER TABLE runs DROP CONSTRAINT IF EXISTS "
        "fk_runs_exact_provider_qualification"
    )
    op.execute(
        "ALTER TABLE runs DROP CONSTRAINT IF EXISTS "
        "ck_runs_run_qualification_binding_complete"
    )
    op.execute(
        "ALTER TABLE runs DROP CONSTRAINT IF EXISTS "
        "run_qualification_binding_complete"
    )
    op.create_foreign_key(
        "fk_runs_exact_provider_qualification",
        "runs",
        "provider_qualification_receipts",
        [
            "org_id",
            "requester_id",
            "provider_connection_id",
            *_QUALIFICATION_COLUMNS,
        ],
        [
            "org_id",
            "requester_user_id",
            "provider_connection_id",
            "id",
            "receipt_sha256",
            "connection_revision",
            "profile_sha256",
            "runtime_version",
            "executable_sha256",
        ],
    )
    op.create_check_constraint(
        "run_qualification_binding_complete",
        "runs",
        "(qualification_receipt_id IS NULL AND "
        "qualification_receipt_sha256 IS NULL AND "
        "qualification_connection_revision IS NULL AND "
        "qualification_profile_sha256 IS NULL AND "
        "qualification_runtime_version IS NULL AND "
        "qualification_executable_sha256 IS NULL) OR "
        "(qualification_receipt_id IS NOT NULL AND "
        "qualification_receipt_sha256 IS NOT NULL AND "
        "qualification_connection_revision IS NOT NULL AND "
        "qualification_profile_sha256 IS NOT NULL AND "
        "qualification_runtime_version IS NOT NULL AND "
        "qualification_executable_sha256 IS NOT NULL)",
    )


def _apply_receipt_policy() -> None:
    op.execute(
        "DO $$ BEGIN CREATE ROLE science_workbench_qualification NOLOGIN; "
        "EXCEPTION WHEN duplicate_object THEN NULL; END $$"
    )
    op.execute(
        "ALTER ROLE science_workbench_qualification WITH NOLOGIN NOSUPERUSER "
        "NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"
    )
    op.execute(
        "GRANT USAGE ON SCHEMA public TO science_workbench_qualification"
    )
    for table in (
        "provider_qualification_receipts",
        "provider_qualification_legacy_evidence",
    ):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} USING (org_id = "
            "current_principal_org() AND requester_user_id = NULLIF("
            "current_setting('app.user_id', true), '')::uuid) WITH CHECK (org_id "
            "= current_principal_org() AND requester_user_id = NULLIF("
            "current_setting('app.user_id', true), '')::uuid)"
        )
        op.execute(f"GRANT SELECT ON {table} TO science_workbench_app")
        op.execute(
            f"REVOKE INSERT, UPDATE, DELETE ON {table} FROM science_workbench_app"
        )
        op.execute(f"DROP TRIGGER IF EXISTS {table}_uuid7 ON {table}")
        op.execute(
            f"CREATE TRIGGER {table}_uuid7 BEFORE INSERT OR UPDATE OF id ON "
            f"{table} FOR EACH ROW EXECUTE FUNCTION enforce_uuid7_id()"
        )
        op.execute(f"DROP TRIGGER IF EXISTS {table}_immutable ON {table}")
        op.execute(
            f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation()"
        )
    op.execute(
        "REVOKE ALL ON provider_qualification_receipts FROM "
        "science_workbench_qualification"
    )
    op.execute(
        "GRANT SELECT, INSERT ON provider_qualification_receipts TO "
        "science_workbench_qualification"
    )
    op.execute(
        "REVOKE ALL ON provider_connections FROM science_workbench_qualification"
    )
    op.execute(
        "GRANT SELECT ON provider_connections TO science_workbench_qualification"
    )
    op.execute(
        "GRANT UPDATE (account_metadata, qualified_at, qualification_receipt_id) "
        "ON provider_connections TO science_workbench_qualification"
    )
    op.execute(
        "REVOKE INSERT, UPDATE, DELETE ON provider_qualification_legacy_evidence "
        "FROM science_workbench_qualification"
    )


def _replace_metadata_guard(allowed_keys: str) -> None:
    op.execute(
        "CREATE OR REPLACE FUNCTION public.jsonb_contains_secret(payload jsonb) "
        "RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog "
        "AS $$ DECLARE entry record; normalized_key text; scalar text; BEGIN CASE "
        "jsonb_typeof(payload) WHEN 'object' THEN FOR entry IN SELECT key, value "
        "FROM jsonb_each(payload) LOOP normalized_key := regexp_replace(lower("
        "normalize(entry.key, NFKC)), '[^a-z0-9]', '', 'g'); IF normalized_key "
        f"<> ALL ({allowed_keys}) OR public.jsonb_contains_secret(entry.value) "
        "THEN RETURN true; END IF; END LOOP; WHEN 'array' THEN FOR entry IN SELECT "
        "value FROM jsonb_array_elements(payload) LOOP IF "
        "public.jsonb_contains_secret(entry.value) THEN RETURN true; END IF; END "
        "LOOP; WHEN 'string' THEN scalar := normalize(payload #>> '{}', NFKC); "
        "IF scalar ~* '^[[:space:]]*(bearer|basic)[[:space:]]+"
        "[A-Za-z0-9._~+/=-]{8,}[[:space:]]*$' OR scalar ~* "
        "'^[[:space:]]*(sk-|xox[baprs]-|gh[pousr]_)[A-Za-z0-9._=-]{12,}"
        "[[:space:]]*$' OR scalar ~* 'ya29[.][A-Za-z0-9._=-]{8,}' OR scalar ~ "
        "'AKIA[A-Z0-9]{16}' OR scalar ~* '(client[_ -]?secret|access[_ -]?token|"
        "refresh[_ -]?token|api[_ -]?key|password|authorization)[[:space:]]*[:=]' "
        "OR scalar ~* '-----BEGIN[[:space:]]+[A-Z0-9 ]*PRIVATE KEY-----' THEN "
        "RETURN true; END IF; ELSE NULL; END CASE; RETURN false; END $$"
    )
