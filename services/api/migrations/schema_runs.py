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
    op.execute(
        "CREATE FUNCTION science_workbench_canonical_jsonb(value jsonb) "
        "RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$ "
        "SELECT CASE jsonb_typeof(value) "
        "WHEN 'object' THEN '{' || COALESCE((SELECT string_agg("
        "to_jsonb(entry.key)::text || ':' || "
        "science_workbench_canonical_jsonb(entry.value), ',' ORDER BY entry.key) "
        "FROM jsonb_each(value) AS entry), '') || '}' "
        "WHEN 'array' THEN '[' || COALESCE((SELECT string_agg("
        "science_workbench_canonical_jsonb(entry.value), ',' "
        "ORDER BY entry.ordinality) FROM jsonb_array_elements(value) "
        "WITH ORDINALITY AS entry(value, ordinality)), '') || ']' "
        "ELSE value::text END $$"
    )
    op.execute(
        "CREATE FUNCTION science_workbench_valid_research_text("
        "value text, maximum integer) RETURNS boolean LANGUAGE sql "
        "IMMUTABLE STRICT PARALLEL SAFE AS $$ SELECT length(value) BETWEEN 1 AND "
        "maximum AND normalize(value, NFC) = value AND NOT ("
        "ascii(left(value, 1)) BETWEEN 9 AND 13 OR "
        "ascii(left(value, 1)) BETWEEN 28 AND 32 OR "
        "ascii(left(value, 1)) IN (133,160,5760,8232,8233,8239,8287,12288,65279) "
        "OR ascii(left(value, 1)) BETWEEN 8192 AND 8202 OR "
        "ascii(right(value, 1)) BETWEEN 9 AND 13 OR "
        "ascii(right(value, 1)) BETWEEN 28 AND 32 OR "
        "ascii(right(value, 1)) IN (133,160,5760,8232,8233,8239,8287,12288,65279) "
        "OR ascii(right(value, 1)) BETWEEN 8192 AND 8202) $$"
    )
    op.execute(
        "CREATE FUNCTION science_workbench_valid_research_array(value jsonb) "
        "RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$ "
        "SELECT jsonb_typeof(value) = 'array' AND jsonb_array_length(value) "
        "BETWEEN 1 AND 8 AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(value) "
        "AS item WHERE jsonb_typeof(item) <> 'string' OR NOT "
        "science_workbench_valid_research_text(item #>> '{}', 500)) AND "
        "(SELECT count(*) = count(DISTINCT normalize(item #>> '{}', NFC)) "
        "FROM jsonb_array_elements(value) AS item) $$"
    )
    op.execute(
        "CREATE FUNCTION science_workbench_valid_research_intent(value jsonb) "
        "RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$ "
        "SELECT COALESCE(jsonb_typeof(value) = 'object' AND "
        "(SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(value) AS key) "
        "= ARRAY['constraints','data_origin','intended_benefit','question',"
        "'rationale','research_mode','stop_conditions','success_criteria',"
        "'synthetic_generator_ref','synthetic_validator_ref'] AND "
        "jsonb_typeof(value->'question') = 'string' AND "
        "jsonb_typeof(value->'rationale') = 'string' AND "
        "jsonb_typeof(value->'intended_benefit') = 'string' AND "
        "science_workbench_valid_research_text(value->>'question', 2000) AND "
        "science_workbench_valid_research_text(value->>'rationale', 2000) AND "
        "science_workbench_valid_research_text(value->>'intended_benefit', 2000) "
        "AND science_workbench_valid_research_array(value->'success_criteria') "
        "AND science_workbench_valid_research_array(value->'constraints') "
        "AND science_workbench_valid_research_array(value->'stop_conditions') "
        "AND jsonb_typeof(value->'research_mode') = 'string' AND "
        "value->>'research_mode' IN ('ai_for_science','copilot','bounded_agentic') "
        "AND jsonb_typeof(value->'data_origin') = 'string' AND "
        "value->>'data_origin' IN ('observed','synthetic','mixed') AND (("
        "value->>'data_origin' = 'observed' AND "
        "jsonb_typeof(value->'synthetic_generator_ref') = 'null' AND "
        "jsonb_typeof(value->'synthetic_validator_ref') = 'null') OR ("
        "value->>'data_origin' IN ('synthetic','mixed') AND "
        "jsonb_typeof(value->'synthetic_generator_ref') = 'string' AND "
        "jsonb_typeof(value->'synthetic_validator_ref') = 'string' AND "
        "science_workbench_valid_research_text("
        "value->>'synthetic_generator_ref', 500) AND "
        "science_workbench_valid_research_text("
        "value->>'synthetic_validator_ref', 500) AND "
        "value->>'synthetic_generator_ref' <> value->>'synthetic_validator_ref')), "
        "false) $$"
    )
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
        sa.Column(
            "research_intent",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("research_intent_sha256", sa.String(64), nullable=False),
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
        sa.CheckConstraint(
            "research_intent_sha256 ~ '^[0-9a-f]{64}$'",
            name="action_plan_research_intent_sha256",
        ),
        sa.CheckConstraint(
            "science_workbench_valid_research_intent(research_intent)",
            name="action_plan_research_intent_complete",
        ),
        sa.CheckConstraint(
            "research_intent_sha256 = encode(sha256(convert_to("
            "science_workbench_canonical_jsonb(research_intent), 'UTF8')), 'hex')",
            name="action_plan_research_intent_digest_binding",
        ),
    )


def drop_runs() -> None:
    for table in ("action_plans", "run_events", "messages", "runs"):
        op.drop_table(table)
    for function in (
        "science_workbench_valid_research_intent(jsonb)",
        "science_workbench_valid_research_array(jsonb)",
        "science_workbench_valid_research_text(text, integer)",
        "science_workbench_canonical_jsonb(jsonb)",
    ):
        op.execute(f"DROP FUNCTION IF EXISTS {function}")
