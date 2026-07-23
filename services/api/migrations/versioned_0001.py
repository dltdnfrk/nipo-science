"""Version-pinned normalization for the original 0001 catalog."""

from typing import Final

from alembic import op

_LEGACY_PROVIDER_METADATA_KEYS: Final = (
    "ARRAY['accountid','accountname','displayname','email','lastverifiedat',"
    "'model','models','provider','subscriptiontier','username','workspaceid']"
    "::text[]"
)
_REVIEW_LINK_TABLES: Final = (
    "review_artifact_versions",
    "review_execution_refs",
    "review_finding_artifact_versions",
    "review_finding_execution_refs",
    "export_artifact_versions",
)


def normalize_0001_contract() -> None:
    """Remove later helper drift from a freshly constructed 0001 schema."""
    op.execute(
        "ALTER TABLE connectors DROP CONSTRAINT IF EXISTS "
        "canonical_connector_registry, DROP CONSTRAINT IF EXISTS "
        "ck_connectors_canonical_connector_registry"
    )
    op.execute("ALTER TABLE connectors ALTER COLUMN enabled SET DEFAULT true")
    op.execute(
        "ALTER TABLE provider_connections DROP CONSTRAINT IF EXISTS "
        "provider_status, DROP CONSTRAINT IF EXISTS "
        "ck_provider_connections_provider_status, DROP CONSTRAINT IF EXISTS "
        "provider_superseded_runtime_home_opaque_ref, DROP CONSTRAINT IF EXISTS "
        "ck_provider_connections_provider_superseded_runtime_home_opaque_ref"
    )
    op.execute(
        "ALTER TABLE provider_connections ADD CONSTRAINT provider_status CHECK "
        "(status IN ('pending', 'healthy', 'reauth_required', 'revoked', "
        "'unsupported_auth')), DROP COLUMN IF EXISTS superseded_runtime_home_ref"
    )
    for constraint in (
        "action_plan_research_intent_digest_binding",
        "action_plan_research_intent_complete",
        "action_plan_research_intent_sha256",
        "ck_action_plans_action_plan_research_intent_digest_binding",
        "ck_action_plans_action_plan_research_intent_complete",
        "ck_action_plans_action_plan_research_intent_sha256",
    ):
        op.execute(
            f"ALTER TABLE action_plans DROP CONSTRAINT IF EXISTS {constraint}"
        )
    op.execute(
        "ALTER TABLE action_plans DROP COLUMN IF EXISTS research_intent_sha256, "
        "DROP COLUMN IF EXISTS research_intent"
    )
    op.execute("DROP TABLE IF EXISTS provider_runtime_home_cleanups")
    for function in (
        "science_workbench_valid_research_intent(jsonb)",
        "science_workbench_valid_research_array(jsonb)",
        "science_workbench_valid_research_text(text, integer)",
        "science_workbench_canonical_jsonb(jsonb)",
    ):
        op.execute(f"DROP FUNCTION IF EXISTS {function}")
    for table in _REVIEW_LINK_TABLES:
        op.execute(
            f"CREATE OR REPLACE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE "
            f"ON {table} FOR EACH ROW EXECUTE FUNCTION protect_review_delete()"
        )
    _replace_provider_metadata_guard()


def _replace_provider_metadata_guard() -> None:
    op.execute(
        "CREATE OR REPLACE FUNCTION public.jsonb_contains_secret(payload jsonb) "
        "RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog "
        "AS $$ DECLARE entry record; normalized_key text; scalar text; BEGIN CASE "
        "jsonb_typeof(payload) WHEN 'object' THEN FOR entry IN SELECT key, value "
        "FROM jsonb_each(payload) LOOP normalized_key := regexp_replace(lower("
        "normalize(entry.key, NFKC)), '[^a-z0-9]', '', 'g'); IF normalized_key "
        f"<> ALL ({_LEGACY_PROVIDER_METADATA_KEYS}) OR "
        "public.jsonb_contains_secret(entry.value) THEN RETURN true; END IF; END "
        "LOOP; WHEN 'array' THEN FOR entry IN SELECT value FROM "
        "jsonb_array_elements(payload) LOOP IF "
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
