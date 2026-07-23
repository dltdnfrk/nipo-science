from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import ClassVar

import pytest
from pydantic import BaseModel, ConfigDict, RootModel

from services.api.tests.persistence.postgres_harness import alembic, psql

SEEDED_ORG = "018f0d7d-6b17-7a91-8b31-2f7331677d01"
SEEDED_USER = "018f0d7d-6b17-7a91-8b31-2f7331677d02"
SEEDED_PROJECT = "018f0d7d-6b17-7a91-8b31-2f7331677d03"
_CATALOG_0001_SHA256 = (
    "78635940b290f5201c2eac2831ef72199b01325b10f50e7c4fd6932df647eafa"
)


class SchemaManifest(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="ignore")

    revision: str
    catalog_sha256: str
    global_tables: tuple[str, ...]
    tenant_tables: tuple[str, ...]


class CatalogSnapshot(RootModel[dict[str, tuple[str, ...]]]):
    pass


def _app_auth_session_privileges() -> str:
    return psql(
        "SELECT has_table_privilege('science_workbench_app', 'auth_sessions', "
        "'SELECT')::text || ':' || has_table_privilege('science_workbench_app', "
        "'auth_sessions', 'INSERT')::text || ':' || has_table_privilege("
        "'science_workbench_app', 'auth_sessions', 'UPDATE')::text || ':' || "
        "has_table_privilege('science_workbench_app', 'auth_sessions', "
        "'DELETE')::text"
    ).stdout.strip()


def _public_execute_functions() -> tuple[str, ...]:
    return tuple(
        psql(
            "SELECT p.oid::regprocedure::text || ':' || entry.is_grantable::text "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace, LATERAL "
            "aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) entry "
            "WHERE n.nspname = 'public' AND entry.grantee = 0 AND "
            "entry.privilege_type = 'EXECUTE' ORDER BY 1"
        ).stdout.splitlines()
    )


def _public_function_default_acl() -> tuple[str, ...]:
    return tuple(
        psql(
            "WITH owner AS (SELECT oid FROM pg_roles WHERE rolname = "
            "current_user), configured AS (SELECT defaults.defaclacl FROM "
            "pg_default_acl defaults, owner WHERE defaults.defaclrole = owner.oid "
            "AND defaults.defaclnamespace = 0 AND "
            "defaults.defaclobjtype = 'f') SELECT entry.privilege_type || ':' || "
            "entry.is_grantable::text FROM owner, LATERAL aclexplode(COALESCE("
            "(SELECT defaclacl FROM configured), acldefault('f', owner.oid))) entry "
            "WHERE entry.grantee = 0 ORDER BY 1"
        ).stdout.splitlines()
    )


def _public_schema_function_default_acl() -> tuple[str, ...]:
    return tuple(
        psql(
            "WITH owner AS (SELECT oid FROM pg_roles WHERE rolname = current_user) "
            "SELECT entry.privilege_type || ':' || entry.is_grantable::text FROM "
            "pg_default_acl defaults JOIN owner ON owner.oid = defaults.defaclrole "
            "JOIN pg_namespace namespace ON namespace.oid = defaults."
            "defaclnamespace, LATERAL aclexplode(defaults.defaclacl) entry WHERE "
            "namespace.nspname = 'public' AND defaults.defaclobjtype = 'f' AND "
            "entry.grantee = 0 ORDER BY 1"
        ).stdout.splitlines()
    )


def _catalog_sha256() -> str:
    catalog = CatalogSnapshot.model_validate_json(
        psql(
            "SELECT json_object_agg(table_name, columns ORDER BY table_name) FROM "
            "(SELECT table_name, json_agg(column_name ORDER BY ordinal_position) "
            "AS columns FROM information_schema.columns "
            "WHERE table_schema = 'public' "
            "AND table_name <> 'alembic_version' GROUP BY table_name) snapshot"
        ).stdout
    )
    canonical = json.dumps(catalog.root, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _catalog_ordinals() -> str:
    return psql(
        "SELECT json_object_agg(table_name, columns ORDER BY table_name) FROM "
        "(SELECT table_name, json_agg(json_build_array(logical_position, "
        "column_name) ORDER BY logical_position) AS columns FROM (SELECT "
        "table_name, column_name, row_number() OVER (PARTITION BY table_name "
        "ORDER BY ordinal_position) AS logical_position FROM "
        "information_schema.columns WHERE table_schema = 'public' AND table_name "
        "<> 'alembic_version') live_columns GROUP BY table_name) snapshot"
    ).stdout.strip()


@pytest.mark.usefixtures("postgres_database")
def test_revision_round_trips_when_database_is_empty() -> None:
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "head"))
    first_revision = psql("SELECT version_num FROM alembic_version").stdout.strip()
    _ = alembic(("downgrade", "base"))
    remaining = psql(
        "SELECT count(*) FROM information_schema.tables "
        "WHERE table_schema = 'public' AND table_name <> 'alembic_version'"
    ).stdout.strip()
    retained_roles = psql(
        "SELECT count(*) FROM pg_roles WHERE rolname IN "
        "('science_workbench_app', 'science_workbench_compliance', "
        "'science_workbench_session_authenticator', "
        "'science_workbench_qualification', 'science_workbench_dispatcher')"
    ).stdout.strip()
    _ = psql("ALTER ROLE science_workbench_app LOGIN BYPASSRLS")
    _ = alembic(("upgrade", "head"))
    second_revision = psql("SELECT version_num FROM alembic_version").stdout.strip()
    hardened = psql(
        "SELECT rolcanlogin::text || ':' || rolbypassrls::text FROM pg_roles "
        "WHERE rolname = 'science_workbench_app'"
    ).stdout.strip()
    assert (first_revision, remaining, retained_roles, second_revision, hardened) == (
        "0004_provider_security",
        "0",
        "2",
        "0004_provider_security",
        "false:false",
    )


@pytest.mark.usefixtures("postgres_database")
def test_downgrade_refuses_to_destroy_qualification_history() -> None:
    provider = "018f0d7d-6b17-7a91-8b31-2f7331677d11"
    receipt = "018f0d7d-6b17-7a91-8b31-2f7331677d12"
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "head"))
    _ = psql(
        f"INSERT INTO organizations (id, name) VALUES ('{SEEDED_ORG}', 'History'); "
        "INSERT INTO users (id, email) VALUES "
        f"('{SEEDED_USER}', 'history@example.test'); "
        "INSERT INTO memberships (org_id, user_id, role) VALUES "
        f"('{SEEDED_ORG}', '{SEEDED_USER}', 'owner'); "
        "INSERT INTO provider_connections (id, org_id, requester_user_id, "
        "adapter_id, encrypted_runtime_home_ref, status) VALUES "
        f"('{provider}', '{SEEDED_ORG}', '{SEEDED_USER}', 'openai_codex', "
        "'vault://runtime/history', 'pending'); "
        "INSERT INTO provider_qualification_receipts (id, org_id, "
        "requester_user_id, provider_connection_id, connection_revision, "
        "adapter_id, profile_sha256, cases_sha256, operator_account_ref, "
        "oauth_mode, oauth_provider, runtime_version, executable_sha256, "
        "protocol_attempts, cleanup_terminal, cleanup_redaction_complete, "
        "authority_key_id, authority_issued_at, authority_algorithm, "
        f"authority_signature, receipt_sha256) VALUES ('{receipt}', "
        f"'{SEEDED_ORG}', '{SEEDED_USER}', '{provider}', 2, 'openai_codex', "
        f"'{'a' * 64}', '{'b' * 64}', 'acct_history', "
        "'official_subscription_oauth', 'openai', 'codex-cli-history', "
        f"'{'c' * 64}', 30, true, true, 'history-key', "
        "CURRENT_TIMESTAMP - interval '1 second', "
        "'RSASSA-PKCS1-v1_5/SHA-256', repeat('d', 768), "
        f"'{'e' * 64}')"
    )

    failed = alembic(("downgrade", "0002_head_schema_upgrade"), check=False)
    revision = psql("SELECT version_num FROM alembic_version").stdout.strip()
    history = psql(
        "SELECT count(*) FROM provider_qualification_receipts"
    ).stdout.strip()
    _ = psql("TRUNCATE provider_connections CASCADE")
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "head"))

    assert failed.returncode != 0
    assert "cannot downgrade provider qualification history" in failed.stderr
    assert revision == "0004_provider_security"
    assert history == "1"


@pytest.mark.usefixtures("postgres_database")
def test_session_authentication_boundary_belongs_only_to_head_revision() -> None:
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "0001_tenant_spine"))
    legacy_boundary = psql(
        "SELECT count(*) FROM pg_roles WHERE rolname = "
        "'science_workbench_session_authenticator'"
    ).stdout.strip()
    legacy_function = psql(
        "SELECT count(*) FROM pg_proc WHERE proname = 'resolve_auth_session'"
    ).stdout.strip()
    legacy_app_privileges = _app_auth_session_privileges()

    _ = alembic(("upgrade", "head"))
    head_boundary = psql(
        "SELECT count(*) FROM pg_roles WHERE rolname = "
        "'science_workbench_session_authenticator'"
    ).stdout.strip()
    head_function = psql(
        "SELECT count(*) FROM pg_proc WHERE proname = 'resolve_auth_session'"
    ).stdout.strip()
    head_app_privileges = _app_auth_session_privileges()

    _ = alembic(("downgrade", "0001_tenant_spine"))
    downgraded_boundary = psql(
        "SELECT count(*) FROM pg_roles WHERE rolname = "
        "'science_workbench_session_authenticator'"
    ).stdout.strip()
    downgraded_function = psql(
        "SELECT count(*) FROM pg_proc WHERE proname = 'resolve_auth_session'"
    ).stdout.strip()
    downgraded_app_privileges = _app_auth_session_privileges()
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "head"))

    assert (
        legacy_boundary,
        legacy_function,
        head_boundary,
        head_function,
        downgraded_boundary,
        downgraded_function,
        legacy_app_privileges,
        head_app_privileges,
        downgraded_app_privileges,
    ) == (
        "0",
        "0",
        "1",
        "1",
        "0",
        "0",
        "true:true:true:true",
        "false:false:false:false",
        "true:true:true:true",
    )


@pytest.mark.usefixtures("postgres_database")
def test_0004_public_function_acl_round_trip_is_exact() -> None:
    # Given the effective PUBLIC function surface of a clean 0003 database.
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "0003_provider_qualification"))
    _ = psql(
        "CREATE PROCEDURE public.provider_test_legacy_procedure() LANGUAGE sql "
        "AS $$ SELECT 1 $$; ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT "
        "EXECUTE ON FUNCTIONS TO PUBLIC"
    )
    before_upgrade = _public_execute_functions()
    default_before_upgrade = _public_function_default_acl()
    schema_default_before_upgrade = _public_schema_function_default_acl()

    # When 0004 is applied and then downgraded to its immediate predecessor.
    _ = alembic(("upgrade", "head"))
    at_head = _public_execute_functions()
    default_at_head = _public_function_default_acl()
    schema_default_at_head = _public_schema_function_default_acl()
    _ = alembic(("downgrade", "0003_provider_qualification"))
    after_downgrade = _public_execute_functions()
    default_after_downgrade = _public_function_default_acl()
    schema_default_after_downgrade = _public_schema_function_default_acl()
    _ = alembic(("upgrade", "head"))

    # Then head exposes no PUBLIC functions and downgrade restores the exact set.
    assert before_upgrade
    assert at_head == ()
    assert after_downgrade == before_upgrade
    assert default_before_upgrade
    assert default_at_head == ()
    assert default_after_downgrade == default_before_upgrade
    assert schema_default_before_upgrade
    assert schema_default_at_head == ()
    assert schema_default_after_downgrade == schema_default_before_upgrade


@pytest.mark.usefixtures("postgres_database")
def test_postgresql_refuses_a_public_function_grant_option() -> None:
    failed = psql(
        "GRANT EXECUTE ON FUNCTION public.current_principal_org() TO PUBLIC WITH "
        "GRANT OPTION",
        check=False,
    )

    assert failed.returncode != 0


@pytest.mark.usefixtures("postgres_database")
def test_0004_refuses_a_preexisting_snapshot_role() -> None:
    # Given an unrelated role occupying the migration-reserved snapshot name.
    snapshot_role = "science_workbench_0004_public_execute_snapshot"
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "0003_provider_qualification"))
    _ = psql(f"CREATE ROLE {snapshot_role} LOGIN INHERIT")

    # When revision 0004 attempts to create its privilege snapshot.
    failed = alembic(("upgrade", "head"), check=False)
    preserved = psql(
        "SELECT rolcanlogin::text || ':' || rolinherit::text FROM pg_roles WHERE "
        f"rolname = '{snapshot_role}'"
    ).stdout.strip()
    if failed.returncode == 0:
        _ = alembic(("downgrade", "0003_provider_qualification"))
    else:
        _ = psql(f"DROP ROLE {snapshot_role}")
    _ = alembic(("upgrade", "head"))

    # Then the migration fails closed before changing or adopting that role.
    assert failed.returncode != 0
    assert "reserved PUBLIC function privilege snapshot role already exists" in (
        failed.stderr
    )
    assert preserved == "true:true"


@pytest.mark.usefixtures("postgres_database")
def test_0004_refuses_a_preexisting_new_capability_role() -> None:
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "0003_provider_qualification"))
    _ = psql(
        "CREATE ROLE science_workbench_dispatcher NOLOGIN; CREATE ROLE "
        "provider_dispatcher_preexisting_rogue LOGIN; GRANT "
        "science_workbench_dispatcher TO provider_dispatcher_preexisting_rogue"
    )

    failed = alembic(("upgrade", "head"), check=False)
    preserved_members = psql(
        "SELECT count(*) FROM pg_auth_members WHERE roleid = "
        "'science_workbench_dispatcher'::regrole"
    ).stdout.strip()
    _ = psql(
        "REVOKE science_workbench_dispatcher FROM "
        "provider_dispatcher_preexisting_rogue"
    )
    if failed.returncode == 0:
        _ = alembic(("downgrade", "0003_provider_qualification"))
        _ = psql("DROP ROLE provider_dispatcher_preexisting_rogue")
    else:
        _ = psql(
            "DROP ROLE provider_dispatcher_preexisting_rogue; DROP ROLE "
            "science_workbench_dispatcher"
        )
    _ = alembic(("upgrade", "head"))

    assert failed.returncode != 0
    assert preserved_members == "1"


@pytest.mark.usefixtures("postgres_database")
def test_0004_replaces_qualification_without_existing_members() -> None:
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "0003_provider_qualification"))
    before_oid = psql(
        "SELECT oid FROM pg_roles WHERE rolname = 'science_workbench_qualification'"
    ).stdout.strip()
    _ = psql(
        "CREATE ROLE provider_qualification_preexisting_rogue LOGIN; GRANT "
        "science_workbench_qualification TO "
        "provider_qualification_preexisting_rogue; CREATE PROCEDURE "
        "public.provider_qualification_surplus_procedure() LANGUAGE sql AS $$ "
        "SELECT 1 $$; GRANT EXECUTE ON PROCEDURE "
        "public.provider_qualification_surplus_procedure() TO "
        "science_workbench_qualification"
    )

    _ = alembic(("upgrade", "head"))
    after = psql(
        "SELECT role.oid::text || ':' || (SELECT count(*) FROM pg_auth_members "
        "WHERE roleid = role.oid)::text || ':' || has_function_privilege(role."
        "rolname, 'public.provider_qualification_surplus_procedure()'::regprocedure, "
        "'EXECUTE')::text FROM pg_roles role WHERE role.rolname = "
        "'science_workbench_qualification'"
    ).stdout.strip()
    _ = alembic(("downgrade", "0003_provider_qualification"))
    _ = psql(
        "DROP ROLE provider_qualification_preexisting_rogue; DROP PROCEDURE "
        "public.provider_qualification_surplus_procedure()"
    )
    _ = alembic(("upgrade", "head"))

    after_oid, member_count, can_execute = after.split(":")
    assert after_oid != before_oid
    assert member_count == "0"
    assert can_execute == "false"


@pytest.mark.usefixtures("migrated_database")
def test_0004_downgrade_refuses_qualification_service_membership() -> None:
    login_role = "provider_qualification_deployed_login"
    _ = psql(
        f"CREATE ROLE {login_role} LOGIN NOINHERIT; GRANT "
        f"science_workbench_qualification TO {login_role}"
    )

    failed = alembic(("downgrade", "0003_provider_qualification"), check=False)
    revision = psql("SELECT version_num FROM alembic_version").stdout.strip()
    _ = psql(
        f"REVOKE science_workbench_qualification FROM {login_role}; "
        f"DROP ROLE {login_role}"
    )
    if failed.returncode == 0:
        _ = alembic(("upgrade", "head"))

    assert failed.returncode != 0
    assert "deprovision members of science_workbench_qualification" in failed.stderr
    assert revision == "0004_provider_security"


@pytest.mark.usefixtures("postgres_database")
def test_0004_refuses_another_owners_public_routine_default() -> None:
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "0003_provider_qualification"))
    _ = psql(
        "CREATE ROLE provider_test_default_owner NOLOGIN; ALTER DEFAULT PRIVILEGES "
        "FOR ROLE provider_test_default_owner IN SCHEMA public GRANT EXECUTE ON "
        "FUNCTIONS TO PUBLIC"
    )

    failed = alembic(("upgrade", "head"), check=False)
    preserved = psql(
        "SELECT count(*) FROM pg_default_acl defaults, LATERAL aclexplode(defaults."
        "defaclacl) entry WHERE defaults.defaclrole = "
        "'provider_test_default_owner'::regrole AND defaults.defaclobjtype = 'f' "
        "AND entry.grantee = 0 AND entry.privilege_type = 'EXECUTE'"
    ).stdout.strip()
    _ = psql(
        "ALTER DEFAULT PRIVILEGES FOR ROLE provider_test_default_owner IN SCHEMA "
        "public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC; DROP ROLE "
        "provider_test_default_owner"
    )
    _ = alembic(("upgrade", "head"))

    assert failed.returncode != 0
    assert "PUBLIC routine default owned outside the migration boundary" in (
        failed.stderr
    )
    assert preserved == "1"


@pytest.mark.usefixtures("migrated_database")
def test_0004_refuses_a_changed_function_snapshot() -> None:
    snapshot_role = "science_workbench_0004_public_execute_snapshot"
    _ = psql(
        "CREATE FUNCTION public.provider_test_snapshot_surplus() RETURNS boolean "
        "LANGUAGE sql IMMUTABLE AS $$ SELECT true $$; GRANT EXECUTE ON ROUTINE "
        f"public.provider_test_snapshot_surplus() TO {snapshot_role}"
    )

    failed = alembic(("downgrade", "0003_provider_qualification"), check=False)
    revision = psql("SELECT version_num FROM alembic_version").stdout.strip()
    public_execute = psql(
        "SELECT count(*) FROM pg_proc p, LATERAL aclexplode(p.proacl) entry WHERE "
        "p.oid = 'public.provider_test_snapshot_surplus()'::regprocedure AND "
        "entry.grantee = 0 AND entry.privilege_type = 'EXECUTE'"
    ).stdout.strip()
    _ = psql("DROP FUNCTION public.provider_test_snapshot_surplus()")

    assert failed.returncode != 0
    assert "PUBLIC function privilege snapshot has changed" in failed.stderr
    assert revision == "0004_provider_security"
    assert public_execute == "0"


@pytest.mark.usefixtures("postgres_database")
def test_0001_catalog_is_frozen_before_later_migrations_are_applied() -> None:
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "0001_tenant_spine"))

    later_artifacts = psql(
        "SELECT "
        "(SELECT count(*) FROM information_schema.tables WHERE table_schema = "
        "'public' AND table_name IN ('provider_runtime_home_cleanups', "
        "'provider_qualification_receipts', "
        "'provider_qualification_legacy_evidence')) || ':' || "
        "(SELECT count(*) FROM information_schema.columns WHERE table_schema = "
        "'public' AND ((table_name = 'provider_connections' AND column_name IN "
        "('superseded_runtime_home_ref', 'qualification_receipt_id')) OR "
        "(table_name = 'action_plans' AND column_name LIKE "
        "'research_intent%') OR (table_name = 'runs' AND column_name LIKE "
        "'qualification_%'))) || ':' || "
        "(SELECT count(*) FROM pg_proc WHERE proname IN ("
        "'science_workbench_canonical_jsonb', "
        "'science_workbench_valid_research_text', "
        "'science_workbench_valid_research_array', "
        "'science_workbench_valid_research_intent')) || ':' || "
        "(SELECT count(*) FROM pg_constraint WHERE conname = "
        "'canonical_connector_registry')"
    ).stdout.strip()
    catalog_hash = _catalog_sha256()

    _ = alembic(("upgrade", "head"))
    head_revision = psql("SELECT version_num FROM alembic_version").stdout.strip()
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "head"))

    assert later_artifacts == "0:0:0:0"
    assert catalog_hash == _CATALOG_0001_SHA256
    assert head_revision == "0004_provider_security"


@pytest.mark.usefixtures("postgres_database")
def test_catalog_hash_round_trips_when_head_is_downgraded_to_0001() -> None:
    manifest = SchemaManifest.model_validate_json(
        (Path(__file__).parents[2] / "persistence/schema_manifest.json").read_text()
    )
    _ = alembic(("downgrade", "base"))
    _ = alembic(("upgrade", "head"))
    fresh_head_hash = _catalog_sha256()
    fresh_head_ordinals = _catalog_ordinals()

    _ = alembic(("downgrade", "0001_tenant_spine"))
    _ = alembic(("upgrade", "head"))
    round_tripped_head_hash = _catalog_sha256()
    round_tripped_head_ordinals = _catalog_ordinals()

    assert (fresh_head_hash, round_tripped_head_hash) == (
        manifest.catalog_sha256,
        manifest.catalog_sha256,
    )
    assert round_tripped_head_ordinals == fresh_head_ordinals


@pytest.mark.usefixtures("migrated_database")
def test_schema_matches_snapshot_when_revision_is_current() -> None:
    manifest = SchemaManifest.model_validate_json(
        (Path(__file__).parents[2] / "persistence/schema_manifest.json").read_text()
    )
    actual = frozenset(
        psql(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_type = 'BASE TABLE' "
            "AND table_name <> 'alembic_version' ORDER BY table_name"
        ).stdout.splitlines()
    )
    assert actual == frozenset((*manifest.global_tables, *manifest.tenant_tables))
    assert _catalog_sha256() == manifest.catalog_sha256


@pytest.mark.usefixtures("postgres_database")
def test_upgrade_preserves_seeded_database_content() -> None:
    _ = alembic(("downgrade", "base"))
    _ = psql(
        "CREATE TABLE migration_seed_marker (id integer PRIMARY KEY, value text); "
        "INSERT INTO migration_seed_marker VALUES (1, 'preserve')"
    )
    _ = alembic(("upgrade", "head"))
    marker = psql("SELECT value FROM migration_seed_marker WHERE id = 1").stdout.strip()
    _ = psql(
        f"INSERT INTO organizations (id, name) VALUES ('{SEEDED_ORG}', 'Seeded'); "
        "INSERT INTO users (id, email) VALUES "
        f"('{SEEDED_USER}', 'seeded@example.test'); "
        "INSERT INTO memberships (org_id, user_id, role) VALUES "
        f"('{SEEDED_ORG}', '{SEEDED_USER}', 'owner'); "
        "INSERT INTO projects (id, org_id, name) VALUES "
        f"('{SEEDED_PROJECT}', '{SEEDED_ORG}', 'Seeded Project')"
    )
    count = psql(
        f"SELECT count(*) FROM projects WHERE id = '{SEEDED_PROJECT}' "
        f"AND org_id = '{SEEDED_ORG}'"
    ).stdout.strip()
    _ = psql("DROP TABLE migration_seed_marker")
    assert (marker, count) == ("preserve", "1")


@pytest.mark.usefixtures("postgres_database")
def test_postgresql_version_is_18_4_when_stack_is_running() -> None:
    version = psql("SHOW server_version").stdout.strip()
    assert version.startswith("18.4")
