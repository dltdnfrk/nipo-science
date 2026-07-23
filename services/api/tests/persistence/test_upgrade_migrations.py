from __future__ import annotations

from datetime import UTC, datetime
from typing import Final, override

import pytest

from services.api.provider_postgres import (
    PostgresProviderPersistence,
    RuntimeHomeDestroyer,
)
from services.api.provider_runtime import (
    PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    ProviderPrincipal,
    ProviderRuntimeService,
)
from services.api.tests.persistence.postgres_harness import (
    alembic,
    database_url_asyncpg,
    psql,
)

ORG: Final = "018f0d7d-6b17-7a91-8b31-2f7331677d01"
USER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677d02"
PROJECT: Final = "018f0d7d-6b17-7a91-8b31-2f7331677d03"
SESSION: Final = "018f0d7d-6b17-7a91-8b31-2f7331677d04"
PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677d05"
RUN: Final = "018f0d7d-6b17-7a91-8b31-2f7331677d06"
BARE_PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677d10"
BARE_RUN: Final = "018f0d7d-6b17-7a91-8b31-2f7331677d11"
PLAN: Final = "018f0d7d-6b17-7a91-8b31-2f7331677d07"
LEGACY_CONNECTOR: Final = "018f0d7d-6b17-7a91-8b31-2f7331677d08"
NEW_CONNECTOR: Final = "018f0d7d-6b17-7a91-8b31-2f7331677d09"
IMMUTABLE_TRIGGERS: Final = (
    "export_artifact_versions_immutable",
    "review_artifact_versions_immutable",
    "review_execution_refs_immutable",
    "review_finding_artifact_versions_immutable",
    "review_finding_execution_refs_immutable",
)
TRIGGER_NAMES_SQL: Final = ",".join(f"'{name}'" for name in IMMUTABLE_TRIGGERS)


class _LegacyDestroyer(RuntimeHomeDestroyer):
    @override
    def destroy(self, opaque_ref: str) -> str:
        del self, opaque_ref
        return "a" * 64


def _clock() -> datetime:
    return datetime(2026, 7, 16, tzinfo=UTC)


def _seed_legacy_graph() -> None:
    _ = psql(
        f"INSERT INTO organizations (id, name) VALUES ('{ORG}', 'Legacy') "
        "ON CONFLICT DO NOTHING; "
        f"INSERT INTO users (id, email) VALUES ('{USER}', 'legacy@example.test') "
        "ON CONFLICT DO NOTHING; "
        "INSERT INTO memberships (org_id, user_id, role) VALUES "
        f"('{ORG}', '{USER}', 'owner') ON CONFLICT DO NOTHING; "
        "INSERT INTO projects (id, org_id, name) VALUES "
        f"('{PROJECT}', '{ORG}', 'Legacy Project') ON CONFLICT (id) DO UPDATE "
        "SET name = EXCLUDED.name; "
        "INSERT INTO sessions (id, org_id, project_id, title) VALUES "
        f"('{SESSION}', '{ORG}', '{PROJECT}', 'Legacy') ON CONFLICT DO NOTHING; "
        "INSERT INTO provider_connections "
        "(id, org_id, requester_user_id, adapter_id, "
        "encrypted_runtime_home_ref, status) VALUES "
        f"('{PROVIDER}', '{ORG}', '{USER}', 'openai_codex', "
        "'vault://runtime/legacy', 'healthy') ON CONFLICT DO NOTHING; "
        "INSERT INTO runs "
        "(id, org_id, session_id, requester_id, provider_connection_id, status) "
        f"VALUES ('{RUN}', '{ORG}', '{SESSION}', '{USER}', '{PROVIDER}', 'queued') "
        "ON CONFLICT DO NOTHING; "
        "INSERT INTO connectors "
        "(id, org_id, project_id, connector_id, base_url) VALUES "
        f"('{LEGACY_CONNECTOR}', '{ORG}', '{PROJECT}', 'pubmed', "
        "'https://pubmed.ncbi.nlm.nih.gov') ON CONFLICT DO NOTHING"
    )


def _seed_bare_healthy_graph() -> None:
    _seed_legacy_graph()
    _ = psql(
        "INSERT INTO provider_connections "
        "(id, org_id, requester_user_id, adapter_id, "
        "encrypted_runtime_home_ref, status) VALUES "
        f"('{BARE_PROVIDER}', '{ORG}', '{USER}', 'openai_codex', "
        "'vault://runtime/bare-healthy', 'healthy'); "
        "INSERT INTO runs "
        "(id, org_id, session_id, requester_id, provider_connection_id, status) "
        f"VALUES ('{BARE_RUN}', '{ORG}', '{SESSION}', '{USER}', "
        f"'{BARE_PROVIDER}', 'completed')"
    )


@pytest.mark.usefixtures("postgres_database")
def test_upgrade_from_0001_preserves_legacy_rows_and_converges_to_head() -> None:
    _ = alembic(("upgrade", "head"))
    _ = alembic(("downgrade", "0001_tenant_spine"))
    legacy_contract = psql(
        "SELECT "
        "(SELECT count(*) FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = 'action_plans' "
        "AND column_name LIKE 'research_intent%') || ':' || "
        "(SELECT pg_get_expr(adbin, adrelid) FROM pg_attrdef "
        "WHERE adrelid = 'connectors'::regclass AND adnum = "
        "(SELECT attnum FROM pg_attribute WHERE attrelid = 'connectors'::regclass "
        "AND attname = 'enabled')) || ':' || "
        "(SELECT count(*) FROM pg_proc WHERE proname IN ("
        "'science_workbench_canonical_jsonb', "
        "'science_workbench_valid_research_text', "
        "'science_workbench_valid_research_array', "
        "'science_workbench_valid_research_intent')) || ':' || "
        "(SELECT string_agg(p.proname, ',' ORDER BY t.tgname) "
        "FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid "
        f"WHERE t.tgname IN ({TRIGGER_NAMES_SQL}) AND NOT t.tgisinternal) || ':' || "
        'public.jsonb_contains_secret(\'{"revision":"1"}\'::jsonb)::text'
    ).stdout.strip()
    _seed_legacy_graph()

    _ = alembic(("upgrade", "head"))

    revision = psql("SELECT version_num FROM alembic_version").stdout.strip()
    preserved_rows = psql(
        "SELECT p.name || '|' || pc.status || '|' || c.enabled::text "
        "FROM projects p JOIN provider_connections pc ON pc.org_id = p.org_id "
        "JOIN connectors c ON c.org_id = p.org_id AND c.project_id = p.id "
        f"WHERE p.id = '{PROJECT}' AND pc.id = '{PROVIDER}' "
        f"AND c.id = '{LEGACY_CONNECTOR}'"
    ).stdout.strip()
    connector_rows = psql(
        "INSERT INTO connectors "
        "(id, org_id, project_id, connector_id, base_url) VALUES "
        f"('{NEW_CONNECTOR}', '{ORG}', '{PROJECT}', 'openalex', "
        "'https://api.openalex.org') RETURNING enabled::text; "
        "SELECT enabled::text FROM connectors "
        f"WHERE id = '{LEGACY_CONNECTOR}'"
    ).stdout.splitlines()
    provider_statuses = psql(
        "UPDATE provider_connections SET status = 'unavailable' "
        f"WHERE id = '{PROVIDER}' RETURNING status; "
        "UPDATE provider_connections SET status = 'quota_exhausted' "
        f"WHERE id = '{PROVIDER}' RETURNING status"
    ).stdout.splitlines()
    constraints = psql(
        "SELECT conname FROM pg_constraint WHERE convalidated AND conname IN ("
        "'action_plan_research_intent_sha256', "
        "'action_plan_research_intent_complete', "
        "'action_plan_research_intent_digest_binding', "
        "'canonical_connector_registry') "
        "ORDER BY conname"
    ).stdout.splitlines()
    triggers = psql(
        "SELECT t.tgname || ':' || p.proname FROM pg_trigger t "
        "JOIN pg_proc p ON p.oid = t.tgfoid "
        f"WHERE t.tgname IN ({TRIGGER_NAMES_SQL}) AND t.tgenabled = 'O' "
        "AND NOT t.tgisinternal ORDER BY t.tgname"
    ).stdout.splitlines()
    metadata_guard = psql(
        "SELECT public.jsonb_contains_secret("
        '\'{"revision":"1","cleanup_status":"pending",'
        '"evidence_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        "aaaaaaaaaaaaaaaa\"}'::jsonb)::text"
    ).stdout.strip()
    incomplete_intent = psql(
        "BEGIN; INSERT INTO action_plans "
        "(id, org_id, run_id, requester_id, research_intent, "
        "research_intent_sha256, version, tool, arguments, arguments_hash, "
        "network_scope, secret_scope, reason, plan_digest) VALUES "
        f"('{PLAN}', '{ORG}', '{RUN}', '{USER}', '{{}}', "
        "encode(sha256(convert_to(science_workbench_canonical_jsonb('{}'::jsonb), "
        "'UTF8')), 'hex'), 1, 'legacy-tool', '{}', "
        "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', "
        "ARRAY[]::text[], ARRAY[]::text[], 'incomplete', 'incomplete'); ROLLBACK",
        check=False,
    )
    invalid_healthy = psql(
        f"UPDATE provider_connections SET status = 'healthy' WHERE id = '{PROVIDER}'",
        check=False,
    )
    _ = psql("TRUNCATE provider_connections CASCADE")
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "head"))

    assert legacy_contract == (
        "0:true:0:protect_review_delete,protect_review_delete,"
        "protect_review_delete,protect_review_delete,protect_review_delete:true"
    )
    assert revision == "0004_provider_security"
    assert preserved_rows == "Legacy Project|pending|true"
    assert connector_rows == ["false", "true"]
    assert provider_statuses == ["unavailable", "quota_exhausted"]
    assert metadata_guard == "false"
    assert incomplete_intent.returncode != 0
    assert "action_plan_research_intent_complete" in incomplete_intent.stderr
    assert "provider_healthy_requires_qualification" in invalid_healthy.stderr
    assert constraints == [
        "action_plan_research_intent_complete",
        "action_plan_research_intent_digest_binding",
        "action_plan_research_intent_sha256",
        "canonical_connector_registry",
    ]
    assert triggers == [
        f"{name}:reject_immutable_mutation" for name in sorted(IMMUTABLE_TRIGGERS)
    ]


@pytest.mark.usefixtures("postgres_database")
def test_upgrade_from_0001_fails_closed_for_unpinned_action_plans() -> None:
    _ = alembic(("upgrade", "head"))
    _ = alembic(("downgrade", "0001_tenant_spine"))
    _seed_legacy_graph()
    _ = psql(
        "INSERT INTO action_plans "
        "(id, org_id, run_id, requester_id, version, tool, arguments, "
        "arguments_hash, network_scope, secret_scope, reason, plan_digest) VALUES "
        f"('{PLAN}', '{ORG}', '{RUN}', '{USER}', 1, 'legacy-tool', "
        "'{\"sample\":true}', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaa', ARRAY[]::text[], ARRAY[]::text[], "
        "'human intent was never captured', 'legacy-plan-digest')"
    )

    failed = alembic(("upgrade", "head"), check=False)

    revision = psql("SELECT version_num FROM alembic_version").stdout.strip()
    preserved = psql(
        f"SELECT reason FROM action_plans WHERE id = '{PLAN}'"
    ).stdout.strip()
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "head"))
    assert failed.returncode != 0
    assert "legacy action_plans require explicit research intent remediation" in (
        failed.stderr
    )
    assert revision == "0001_tenant_spine"
    assert preserved == "human intent was never captured"


@pytest.mark.usefixtures("postgres_database")
def test_upgrade_archives_legacy_qualification_and_runtime_loads_pending() -> None:
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "0002_head_schema_upgrade"))
    _seed_legacy_graph()
    _ = psql(
        "UPDATE provider_connections SET selected_model = 'codex-mini', "
        "qualified_at = CURRENT_TIMESTAMP - interval '1 day', account_metadata = "
        "jsonb_build_object('account_id', 'legacy-account', 'models', "
        "jsonb_build_array('codex-mini'), 'provider', 'openai_codex', 'revision', "
        "'1', 'qualification_profile_sha256', repeat('a', 64), "
        "'qualification_runtime_version', 'codex-cli-legacy', "
        "'qualification_executable_sha256', repeat('b', 64)) "
        f"WHERE id = '{PROVIDER}'"
    )

    _ = alembic(("upgrade", "head"))

    archived = psql(
        "SELECT classification || '|' || legacy_status || '|' || "
        "legacy_profile_sha256 || '|' || legacy_runtime_version || '|' || "
        "legacy_executable_sha256 || '|' || "
        f"(historical_run_ids @> ARRAY['{RUN}'::uuid])::text FROM "
        "provider_qualification_legacy_evidence"
    ).stdout.strip()
    current = psql(
        "SELECT status || '|' || (qualified_at IS NULL)::text || '|' || "
        "(qualification_receipt_id IS NULL)::text || '|' || "
        "(NOT account_metadata ? 'qualification_profile_sha256')::text FROM "
        f"provider_connections WHERE id = '{PROVIDER}'"
    ).stdout.strip()
    runtime = ProviderRuntimeService(
        _clock,
        persistence=PostgresProviderPersistence(
            database_url_asyncpg(),
            _LegacyDestroyer(),
            clock=_clock,
            cleanup_window=(
                PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
            ),
        ),
        cleanup_policy=PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    )
    restored = runtime.list_connections(ProviderPrincipal(USER, ORG))
    _ = psql("TRUNCATE provider_connections CASCADE")

    assert archived == (
        "legacy_unverified|healthy|"
        + "a" * 64
        + "|codex-cli-legacy|"
        + "b" * 64
        + "|true"
    )
    assert current == "pending|true|true|true"
    assert len(restored) == 1
    assert restored[0].health == "pending"
    assert not restored[0].qualified_live


@pytest.mark.usefixtures("postgres_database")
def test_upgrade_archives_bare_unsigned_healthy_with_historical_runs() -> None:
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "0002_head_schema_upgrade"))
    _seed_bare_healthy_graph()

    _ = alembic(("upgrade", "head"))

    archived = psql(
        "SELECT classification || '|' || legacy_status || '|' || "
        "(legacy_qualified_at IS NULL)::text || '|' || "
        f"(historical_run_ids = ARRAY['{BARE_RUN}'::uuid])::text FROM "
        "provider_qualification_legacy_evidence WHERE "
        f"provider_connection_id = '{BARE_PROVIDER}'"
    ).stdout.strip()
    current = psql(
        "SELECT status || '|' || (qualified_at IS NULL)::text || '|' || "
        "(qualification_receipt_id IS NULL)::text FROM provider_connections "
        f"WHERE id = '{BARE_PROVIDER}'"
    ).stdout.strip()
    refused = alembic(("downgrade", "0002_head_schema_upgrade"), check=False)
    revision = psql("SELECT version_num FROM alembic_version").stdout.strip()
    _ = psql("TRUNCATE provider_connections CASCADE")
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "head"))

    assert archived == "legacy_unverified|healthy|true|true"
    assert current == "pending|true|true"
    assert refused.returncode != 0
    assert "cannot downgrade provider qualification history" in refused.stderr
    assert revision == "0004_provider_security"


@pytest.mark.usefixtures("postgres_database")
def test_upgrade_converges_from_an_already_stamped_0003_database() -> None:
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "0002_head_schema_upgrade"))
    _seed_bare_healthy_graph()
    _ = alembic(("upgrade", "0003_provider_qualification"))
    _ = psql(
        "ALTER TABLE provider_qualification_legacy_evidence DISABLE TRIGGER "
        "provider_qualification_legacy_evidence_immutable; "
        "DELETE FROM provider_qualification_legacy_evidence; "
        "ALTER TABLE provider_qualification_legacy_evidence ENABLE TRIGGER "
        "provider_qualification_legacy_evidence_immutable"
    )
    stamped = psql(
        "SELECT (SELECT version_num FROM alembic_version) || ':' || "
        f"(SELECT status FROM provider_connections WHERE id = '{BARE_PROVIDER}') "
        "|| ':' || (SELECT count(*) FROM "
        "provider_qualification_legacy_evidence)"
    ).stdout.strip()

    _ = alembic(("upgrade", "head"))

    converged = psql(
        "SELECT (SELECT version_num FROM alembic_version) || ':' || "
        "(SELECT count(*) FROM information_schema.columns WHERE table_schema = "
        "'public' AND table_name = 'runs' AND column_name = "
        "'provider_model_id') || ':' || "
        "(SELECT count(*) FROM pg_roles WHERE rolname = "
        "'science_workbench_dispatcher') || ':' || "
        "has_table_privilege('science_workbench_app', 'runs', 'INSERT')::text || "
        "':' || (SELECT count(*) FROM "
        "provider_qualification_legacy_evidence) || ':' || "
        f"(SELECT status FROM provider_connections WHERE id = '{BARE_PROVIDER}')"
    ).stdout.strip()
    _ = psql("TRUNCATE provider_connections CASCADE")
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "head"))

    assert stamped == "0003_provider_qualification:pending:0"
    assert converged == "0004_provider_security:1:1:false:0:pending"
