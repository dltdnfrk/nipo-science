from __future__ import annotations

from typing import TYPE_CHECKING, Final

from alembic import op

from services.api.migrations.auth_session_policies import (
    create_session_authentication_boundary,
    drop_session_authentication_boundary,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

revision: str = "0002_head_schema_upgrade"
down_revision: str | None = "0001_tenant_spine"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_REVIEW_LINK_TABLES: Final = (
    "review_artifact_versions",
    "review_execution_refs",
    "review_finding_artifact_versions",
    "review_finding_execution_refs",
    "export_artifact_versions",
)
_LEGACY_PROVIDER_METADATA_KEYS: Final = (
    "ARRAY['accountid','accountname','displayname','email','lastverifiedat',"
    "'model','models','provider','subscriptiontier','username','workspaceid']"
    "::text[]"
)
_HEAD_PROVIDER_METADATA_KEYS: Final = (
    "ARRAY['accountid','accountname','adoptionstatus','cleanuprequestedat',"
    "'cleanupstatus',"
    "'destroyby','destroyedat','displayname','email','evidencesha256',"
    "'lastverifiedat','model','models','provider','revision','subscriptiontier',"
    "'qualificationexecutablesha256','qualificationprofilesha256',"
    "'qualificationruntimeversion','stagingleaseid','stagingleasedestroyby',"
    "'username','workspaceid']::text[]"
)
_RESEARCH_INTENT_COMPLETE: Final = (
    "science_workbench_valid_research_intent(research_intent)"
)
_RESEARCH_INTENT_DIGEST: Final = (
    "research_intent_sha256 = encode(sha256(convert_to("
    "science_workbench_canonical_jsonb(research_intent), 'UTF8')), 'hex')"
)


def _replace_check(table: str, name: str, expression: str) -> None:
    op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name}")
    op.execute(
        f"ALTER TABLE {table} ADD CONSTRAINT {name} CHECK ({expression}) NOT VALID"
    )
    op.execute(f"ALTER TABLE {table} VALIDATE CONSTRAINT {name}")


def _replace_review_link_triggers(function: str) -> None:
    for table in _REVIEW_LINK_TABLES:
        op.execute(
            f"CREATE OR REPLACE TRIGGER {table}_immutable "
            f"BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW "
            f"EXECUTE FUNCTION {function}()"
        )


def _replace_provider_metadata_guard(allowed_keys: str) -> None:
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


def _create_research_intent_functions() -> None:
    op.execute(
        "CREATE OR REPLACE FUNCTION science_workbench_canonical_jsonb(value jsonb) "
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
        "CREATE OR REPLACE FUNCTION science_workbench_valid_research_text("
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
        "CREATE OR REPLACE FUNCTION science_workbench_valid_research_array("
        "value jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE "
        "AS $$ SELECT jsonb_typeof(value) = 'array' AND "
        "jsonb_array_length(value) BETWEEN 1 AND 8 AND NOT EXISTS (SELECT 1 FROM "
        "jsonb_array_elements(value) AS item WHERE jsonb_typeof(item) <> 'string' "
        "OR NOT science_workbench_valid_research_text(item #>> '{}', 500)) AND "
        "(SELECT count(*) = count(DISTINCT normalize(item #>> '{}', NFC)) "
        "FROM jsonb_array_elements(value) AS item) $$"
    )
    op.execute(
        "CREATE OR REPLACE FUNCTION science_workbench_valid_research_intent("
        "value jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE "
        "AS $$ SELECT COALESCE(jsonb_typeof(value) = 'object' AND "
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
        "value->>'synthetic_generator_ref' <> "
        "value->>'synthetic_validator_ref')), false) $$"
    )


def _canonicalize_action_plan_column_order() -> None:
    op.execute(
        "DO $$ BEGIN IF (SELECT attnum FROM pg_attribute WHERE attrelid = "
        "'action_plans'::regclass AND attname = 'research_intent' AND NOT "
        "attisdropped) > (SELECT attnum FROM pg_attribute WHERE attrelid = "
        "'action_plans'::regclass AND attname = 'version' AND NOT attisdropped) "
        "THEN ALTER TABLE approval_requests DROP CONSTRAINT IF EXISTS "
        "fk_approval_requests_org_id_action_plans; ALTER TABLE executions DROP "
        "CONSTRAINT IF EXISTS fk_executions_org_id_action_plans; ALTER TABLE "
        "action_plans RENAME TO action_plans_0002_legacy; CREATE TABLE action_plans "
        "(id uuid NOT NULL DEFAULT uuidv7(), org_id uuid NOT NULL, run_id uuid "
        "NOT NULL, requester_id uuid NOT NULL, research_intent jsonb NOT NULL, "
        "research_intent_sha256 varchar(64) NOT NULL, version bigint NOT NULL, "
        "tool text NOT NULL, arguments jsonb NOT NULL, arguments_hash varchar(64) "
        "NOT NULL, network_scope text[] NOT NULL, secret_scope text[] NOT NULL, "
        "reason text NOT NULL, plan_digest varchar(64) NOT NULL, created_at "
        "timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP); INSERT INTO action_plans "
        "(id, org_id, run_id, requester_id, research_intent, "
        "research_intent_sha256, version, tool, arguments, arguments_hash, "
        "network_scope, secret_scope, reason, plan_digest, created_at) SELECT id, "
        "org_id, run_id, requester_id, research_intent, research_intent_sha256, "
        "version, tool, arguments, arguments_hash, network_scope, secret_scope, "
        "reason, plan_digest, created_at FROM action_plans_0002_legacy; DROP TABLE "
        "action_plans_0002_legacy; ALTER TABLE action_plans ADD CONSTRAINT "
        "pk_action_plans PRIMARY KEY (id), ADD CONSTRAINT uq_action_plans_org_id "
        "UNIQUE (org_id, id), ADD CONSTRAINT fk_action_plans_org_id_runs FOREIGN "
        "KEY (org_id, run_id) REFERENCES runs (org_id, id), ADD CONSTRAINT "
        "fk_action_plans_org_id_memberships FOREIGN KEY (org_id, requester_id) "
        "REFERENCES memberships (org_id, user_id), ADD CONSTRAINT "
        "uq_action_plans_version UNIQUE (org_id, run_id, version), ADD CONSTRAINT "
        "uq_action_plans_run_identity UNIQUE (org_id, id, run_id), ADD CONSTRAINT "
        "ck_action_plans_action_plan_version CHECK (version >= 1), ADD CONSTRAINT "
        "ck_action_plans_action_plan_research_intent_sha256 CHECK "
        "(research_intent_sha256 ~ '^[0-9a-f]{64}$'), ADD CONSTRAINT "
        "ck_action_plans_action_plan_research_intent_complete CHECK "
        f"({_RESEARCH_INTENT_COMPLETE}), ADD CONSTRAINT "
        "ck_action_plans_action_plan_research_intent_digest_binding CHECK "
        f"({_RESEARCH_INTENT_DIGEST}); ALTER TABLE approval_requests ADD "
        "CONSTRAINT fk_approval_requests_org_id_action_plans FOREIGN KEY (org_id, "
        "action_plan_id, run_id) REFERENCES action_plans (org_id, id, run_id); "
        "ALTER TABLE executions ADD CONSTRAINT fk_executions_org_id_action_plans "
        "FOREIGN KEY (org_id, action_plan_id, run_id) REFERENCES action_plans "
        "(org_id, id, run_id); ALTER TABLE action_plans ENABLE ROW LEVEL SECURITY; "
        "ALTER TABLE action_plans FORCE ROW LEVEL SECURITY; CREATE POLICY "
        "tenant_isolation ON action_plans USING (org_id = current_principal_org()) "
        "WITH CHECK (org_id = current_principal_org()); GRANT SELECT, INSERT ON "
        "action_plans TO science_workbench_app; CREATE TRIGGER action_plans_uuid7 "
        "BEFORE INSERT OR UPDATE OF id ON action_plans FOR EACH ROW EXECUTE "
        "FUNCTION enforce_uuid7_id(); CREATE TRIGGER action_plans_immutable BEFORE "
        "UPDATE OR DELETE ON action_plans FOR EACH ROW EXECUTE FUNCTION "
        "reject_immutable_mutation(); END IF; END $$"
    )


def _canonicalize_provider_connection_column_order() -> None:
    op.execute(
        "DO $$ BEGIN IF (SELECT attnum FROM pg_attribute WHERE attrelid = "
        "'provider_connections'::regclass AND attname = "
        "'superseded_runtime_home_ref' AND NOT attisdropped) > (SELECT attnum FROM "
        "pg_attribute WHERE attrelid = 'provider_connections'::regclass AND "
        "attname = 'account_metadata' AND NOT attisdropped) THEN ALTER TABLE runs "
        "DROP CONSTRAINT IF EXISTS fk_runs_org_id_provider_connections; ALTER "
        "TABLE artifact_versions DROP CONSTRAINT IF EXISTS "
        "fk_artifact_versions_org_id_provider_connections; ALTER TABLE "
        "provider_connections RENAME TO provider_connections_0002_legacy; CREATE "
        "TABLE provider_connections (id uuid NOT NULL DEFAULT uuidv7(), org_id "
        "uuid NOT NULL, requester_user_id uuid NOT NULL, adapter_id text NOT NULL, "
        "encrypted_runtime_home_ref text NOT NULL, superseded_runtime_home_ref "
        "text, account_metadata jsonb NOT NULL DEFAULT '{}'::jsonb, selected_model "
        "text, status text NOT NULL, qualified_at timestamptz, health_checked_at "
        "timestamptz, revoked_at timestamptz, created_at timestamptz NOT NULL "
        "DEFAULT CURRENT_TIMESTAMP); INSERT INTO provider_connections (id, org_id, "
        "requester_user_id, adapter_id, encrypted_runtime_home_ref, "
        "superseded_runtime_home_ref, account_metadata, selected_model, status, "
        "qualified_at, health_checked_at, revoked_at, created_at) SELECT id, org_id, "
        "requester_user_id, adapter_id, encrypted_runtime_home_ref, "
        "superseded_runtime_home_ref, account_metadata, selected_model, status, "
        "qualified_at, health_checked_at, revoked_at, created_at FROM "
        "provider_connections_0002_legacy; DROP TABLE "
        "provider_connections_0002_legacy; ALTER TABLE provider_connections ADD "
        "CONSTRAINT pk_provider_connections PRIMARY KEY (id), ADD CONSTRAINT "
        "uq_provider_connections_org_id UNIQUE (org_id, id), ADD CONSTRAINT "
        "uq_provider_connections_requester UNIQUE (org_id, id, requester_user_id), "
        "ADD CONSTRAINT fk_provider_connections_org_id_memberships FOREIGN KEY "
        "(org_id, requester_user_id) REFERENCES memberships (org_id, user_id), ADD "
        "CONSTRAINT ck_provider_connections_provider_adapter CHECK (adapter_id IN "
        "('openai_codex', 'anthropic_claude_code', 'xai_grok_build', "
        "'moonshot_kimi_code', 'zai_glm')), ADD CONSTRAINT "
        "ck_provider_connections_provider_runtime_home_opaque_ref CHECK "
        "(encrypted_runtime_home_ref ~ "
        "'^vault://runtime/[A-Za-z0-9][A-Za-z0-9._/-]*$' AND position('..' in "
        "encrypted_runtime_home_ref) = 0), ADD CONSTRAINT "
        "ck_provider_connections_provider_status CHECK (status IN ('pending', "
        "'healthy', 'reauth_required', 'revoked', 'unavailable', "
        "'quota_exhausted', 'unsupported_auth')), ADD CONSTRAINT "
        "ck_provider_connections_provider_superseded_runtime_hom_56cd CHECK "
        "(superseded_runtime_home_ref IS NULL OR (superseded_runtime_home_ref ~ "
        "'^vault://runtime/[A-Za-z0-9][A-Za-z0-9._/-]*$' AND position('..' in "
        "superseded_runtime_home_ref) = 0 AND superseded_runtime_home_ref <> "
        "encrypted_runtime_home_ref)), ADD CONSTRAINT provider_status CHECK "
        "(status IN ('pending', 'healthy', 'reauth_required', 'revoked', "
        "'unavailable', 'quota_exhausted', 'unsupported_auth')), ADD CONSTRAINT "
        "provider_superseded_runtime_home_opaque_ref CHECK "
        "(superseded_runtime_home_ref IS NULL OR (superseded_runtime_home_ref ~ "
        "'^vault://runtime/[A-Za-z0-9][A-Za-z0-9._/-]*$' AND position('..' in "
        "superseded_runtime_home_ref) = 0 AND superseded_runtime_home_ref <> "
        "encrypted_runtime_home_ref)); ALTER TABLE runs ADD CONSTRAINT "
        "fk_runs_org_id_provider_connections FOREIGN KEY (org_id, "
        "provider_connection_id, requester_id) REFERENCES provider_connections "
        "(org_id, id, requester_user_id); ALTER TABLE artifact_versions ADD "
        "CONSTRAINT fk_artifact_versions_org_id_provider_connections FOREIGN KEY "
        "(org_id, runtime_connection_id) REFERENCES provider_connections (org_id, "
        "id); ALTER TABLE provider_connections ENABLE ROW LEVEL SECURITY; ALTER "
        "TABLE provider_connections FORCE ROW LEVEL SECURITY; CREATE POLICY "
        "tenant_isolation ON provider_connections USING (org_id = "
        "current_principal_org() AND requester_user_id = NULLIF(current_setting("
        "'app.user_id', true), '')::uuid) WITH CHECK (org_id = "
        "current_principal_org() AND requester_user_id = NULLIF(current_setting("
        "'app.user_id', true), '')::uuid); GRANT SELECT, INSERT, UPDATE, DELETE ON "
        "provider_connections TO science_workbench_app; CREATE TRIGGER "
        "provider_connections_uuid7 BEFORE INSERT OR UPDATE OF id ON "
        "provider_connections FOR EACH ROW EXECUTE FUNCTION enforce_uuid7_id(); "
        "CREATE TRIGGER provider_connections_metadata_secret BEFORE INSERT OR "
        "UPDATE OF account_metadata ON provider_connections FOR EACH ROW EXECUTE "
        "FUNCTION reject_provider_metadata_secret(); END IF; END $$"
    )


def upgrade() -> None:
    _create_research_intent_functions()
    create_session_authentication_boundary()
    op.execute(
        "CREATE TABLE IF NOT EXISTS provider_runtime_home_cleanups ("
        "org_id uuid NOT NULL, requester_user_id uuid NOT NULL, "
        "encrypted_runtime_home_ref text NOT NULL, connection_id uuid, "
        "reason text NOT NULL, status text NOT NULL, requested_at timestamptz "
        "NOT NULL, destroy_by timestamptz NOT NULL, "
        "destroyed_at timestamptz, evidence_sha256 varchar(64), "
        "created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, "
        "PRIMARY KEY (org_id, requester_user_id, encrypted_runtime_home_ref), "
        "FOREIGN KEY (org_id, requester_user_id) REFERENCES memberships "
        "(org_id, user_id), CONSTRAINT provider_cleanup_runtime_home_opaque_ref "
        "CHECK (encrypted_runtime_home_ref ~ "
        "'^vault://runtime/[A-Za-z0-9][A-Za-z0-9._/-]*$' AND "
        "position('..' in encrypted_runtime_home_ref) = 0), CONSTRAINT "
        "provider_cleanup_reason_scope CHECK ((reason = 'unbound' AND "
        "connection_id IS NULL) OR (reason = 'superseded' AND connection_id "
        "IS NOT NULL)), CONSTRAINT provider_cleanup_deadline CHECK (destroy_by "
        "> requested_at), CONSTRAINT "
        "provider_cleanup_state_complete CHECK ((status = 'scheduled' AND "
        "destroyed_at IS NULL AND evidence_sha256 IS NULL) OR (status = "
        "'completed' AND destroyed_at IS NOT NULL AND evidence_sha256 ~ "
        "'^[0-9a-f]{64}$')))"
    )
    op.execute(
        "ALTER TABLE provider_runtime_home_cleanups ENABLE ROW LEVEL SECURITY"
    )
    op.execute(
        "ALTER TABLE provider_runtime_home_cleanups FORCE ROW LEVEL SECURITY"
    )
    op.execute(
        "DROP POLICY IF EXISTS tenant_isolation ON "
        "provider_runtime_home_cleanups"
    )
    op.execute(
        "CREATE POLICY tenant_isolation ON provider_runtime_home_cleanups "
        "USING (org_id = current_principal_org() AND requester_user_id = "
        "NULLIF(current_setting('app.user_id', true), '')::uuid) WITH CHECK "
        "(org_id = current_principal_org() AND requester_user_id = "
        "NULLIF(current_setting('app.user_id', true), '')::uuid)"
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON "
        "provider_runtime_home_cleanups TO science_workbench_app"
    )
    op.execute(
        "ALTER TABLE provider_connections ADD COLUMN IF NOT EXISTS "
        "superseded_runtime_home_ref text"
    )
    _replace_check(
        "provider_connections",
        "provider_superseded_runtime_home_opaque_ref",
        "superseded_runtime_home_ref IS NULL OR ("
        "superseded_runtime_home_ref ~ "
        "'^vault://runtime/[A-Za-z0-9][A-Za-z0-9._/-]*$' AND "
        "position('..' in superseded_runtime_home_ref) = 0 AND "
        "superseded_runtime_home_ref <> encrypted_runtime_home_ref)",
    )
    op.execute(
        "ALTER TABLE action_plans ADD COLUMN IF NOT EXISTS research_intent jsonb"
    )
    op.execute(
        "ALTER TABLE action_plans ADD COLUMN IF NOT EXISTS "
        "research_intent_sha256 varchar(64)"
    )
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM action_plans WHERE "
        "research_intent IS NULL OR research_intent_sha256 IS NULL) THEN "
        "RAISE EXCEPTION 'legacy action_plans require explicit research intent "
        "remediation' USING ERRCODE = '23514'; END IF; END $$"
    )
    op.execute(
        "ALTER TABLE action_plans ALTER COLUMN research_intent SET NOT NULL, "
        "ALTER COLUMN research_intent_sha256 SET NOT NULL"
    )
    _canonicalize_action_plan_column_order()
    _replace_check(
        "action_plans",
        "action_plan_research_intent_sha256",
        "research_intent_sha256 ~ '^[0-9a-f]{64}$'",
    )
    _replace_check(
        "action_plans",
        "action_plan_research_intent_complete",
        _RESEARCH_INTENT_COMPLETE,
    )
    _replace_check(
        "action_plans",
        "action_plan_research_intent_digest_binding",
        _RESEARCH_INTENT_DIGEST,
    )
    _replace_check(
        "provider_connections",
        "provider_status",
        "status IN ('pending', 'healthy', 'reauth_required', 'revoked', "
        "'unavailable', 'quota_exhausted', 'unsupported_auth')",
    )
    _canonicalize_provider_connection_column_order()
    op.execute("ALTER TABLE connectors ALTER COLUMN enabled SET DEFAULT false")
    _replace_check(
        "connectors",
        "canonical_connector_registry",
        "(connector_id = 'pubmed' AND "
        "base_url = 'https://pubmed.ncbi.nlm.nih.gov') OR "
        "(connector_id = 'openalex' AND base_url = 'https://api.openalex.org')",
    )
    _replace_review_link_triggers("reject_immutable_mutation")
    _replace_provider_metadata_guard(_HEAD_PROVIDER_METADATA_KEYS)


def downgrade() -> None:
    drop_session_authentication_boundary()
    _replace_provider_metadata_guard(_LEGACY_PROVIDER_METADATA_KEYS)
    _replace_review_link_triggers("protect_review_delete")
    op.execute(
        "ALTER TABLE connectors DROP CONSTRAINT IF EXISTS canonical_connector_registry"
    )
    op.execute("ALTER TABLE connectors ALTER COLUMN enabled SET DEFAULT true")
    _replace_check(
        "provider_connections",
        "provider_status",
        "status IN ('pending', 'healthy', 'reauth_required', 'revoked', "
        "'unsupported_auth')",
    )
    for constraint in (
        "action_plan_research_intent_digest_binding",
        "action_plan_research_intent_complete",
        "action_plan_research_intent_sha256",
    ):
        op.execute(f"ALTER TABLE action_plans DROP CONSTRAINT IF EXISTS {constraint}")
    op.execute(
        "ALTER TABLE action_plans DROP COLUMN IF EXISTS research_intent_sha256, "
        "DROP COLUMN IF EXISTS research_intent"
    )
    op.execute(
        "ALTER TABLE provider_connections DROP CONSTRAINT IF EXISTS "
        "provider_superseded_runtime_home_opaque_ref, "
        "DROP COLUMN IF EXISTS superseded_runtime_home_ref"
    )
    op.execute("DROP TABLE IF EXISTS provider_runtime_home_cleanups")
    for function in (
        "science_workbench_valid_research_intent(jsonb)",
        "science_workbench_valid_research_array(jsonb)",
        "science_workbench_valid_research_text(text, integer)",
        "science_workbench_canonical_jsonb(jsonb)",
    ):
        op.execute(f"DROP FUNCTION IF EXISTS {function}")
