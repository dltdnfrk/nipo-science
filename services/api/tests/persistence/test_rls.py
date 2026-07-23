from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final
from uuid import UUID

import pytest

from services.api.persistence.principal import TestPrincipal as Principal
from services.api.persistence.principal import TestPrincipalAdapter as PrincipalAdapter
from services.api.persistence.schema_inventory import (
    APPEND_ONLY_TABLES,
    GLOBAL_TABLES,
    TENANT_TABLES,
)
from services.api.tests.persistence.postgres_harness import psql

if TYPE_CHECKING:
    import subprocess

ORG_A: Final = "018f0d7d-6b17-7a91-8b31-2f7331677a01"
ORG_B: Final = "018f0d7d-6b17-7a91-8b31-2f7331677b01"
USER_A: Final = "018f0d7d-6b17-7a91-8b31-2f7331677a02"
USER_B: Final = "018f0d7d-6b17-7a91-8b31-2f7331677b02"
USER_C: Final = "018f0d7d-6b17-7a91-8b31-2f7331677a03"
PROJECT_A: Final = "018f0d7d-6b17-7a91-8b31-2f7331677a04"
PROJECT_B: Final = "018f0d7d-6b17-7a91-8b31-2f7331677b04"
AUDIT_A: Final = "018f0d7d-6b17-7a91-8b31-2f7331677a05"
ORG_C: Final = "018f0d7d-6b17-7a91-8b31-2f7331677c01"
USER_C1: Final = "018f0d7d-6b17-7a91-8b31-2f7331677c02"
USER_C2: Final = "018f0d7d-6b17-7a91-8b31-2f7331677c03"
pytestmark = pytest.mark.usefixtures("migrated_database")


def seed_tenants() -> None:
    _ = psql(
        f"INSERT INTO organizations (id, name) VALUES ('{ORG_A}', 'A'), "
        f"('{ORG_B}', 'B') ON CONFLICT DO NOTHING; "
        "INSERT INTO users (id, email) VALUES "
        f"('{USER_A}', 'a@example.test'), ('{USER_B}', 'b@example.test'), "
        f"('{USER_C}', 'c@example.test') ON CONFLICT DO NOTHING; "
        "INSERT INTO memberships "
        f"(org_id, user_id, role) VALUES ('{ORG_A}', '{USER_A}', 'owner'), "
        f"('{ORG_B}', '{USER_B}', 'owner'), ('{ORG_A}', '{USER_C}', 'member') "
        "ON CONFLICT DO NOTHING; "
        "INSERT INTO projects (id, org_id, name) "
        f"VALUES ('{PROJECT_A}', '{ORG_A}', 'Project A'), "
        f"('{PROJECT_B}', '{ORG_B}', 'Project B') ON CONFLICT DO NOTHING"
    )


def app_principal_sql(org_id: str = ORG_A, user_id: str = USER_A) -> str:
    return (
        f"SELECT set_config('app.org_id', '{org_id}', false); "
        f"SELECT set_config('app.user_id', '{user_id}', false); "
    )


def test_cross_org_rows_are_hidden_when_app_principal_is_scoped() -> None:
    seed_tenants()
    count = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql()
        + "SELECT count(*) FROM projects"
    ).stdout.splitlines()[-1]
    assert count == "1"


def test_verified_test_principal_drives_the_database_tenant_scope() -> None:
    seed_tenants()
    now = datetime(2026, 7, 13, tzinfo=UTC)
    principal = Principal(
        org_id=UUID(ORG_A),
        user_id=UUID(USER_A),
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    adapter = PrincipalAdapter(
        environment="test",
        signing_key=bytes(range(32)),
        active_memberships=frozenset({(UUID(ORG_A), UUID(USER_A))}),
    )
    verified = adapter.decode(adapter.encode(principal), now)
    count = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql(str(verified.org_id), str(verified.user_id))
        + "SELECT count(*) FROM projects"
    ).stdout.splitlines()[-1]
    assert verified.user_id == UUID(USER_A)
    assert count == "1"


def test_global_identity_tables_are_denied_to_the_tenant_app_role() -> None:
    seed_tenants()
    read = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql()
        + "SELECT * FROM users",
        check=False,
    )
    mutation = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql()
        + f"UPDATE organizations SET name = 'escape' WHERE id = '{ORG_B}'",
        check=False,
    )
    assert read.returncode != 0
    assert mutation.returncode != 0
    assert "permission denied" in read.stderr
    assert "permission denied" in mutation.stderr


def test_cross_org_insert_is_denied_when_app_principal_is_scoped() -> None:
    seed_tenants()
    result = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql()
        + f"INSERT INTO projects (org_id, name) VALUES ('{ORG_B}', 'escape')",
        check=False,
    )
    assert result.returncode != 0
    assert "row-level security" in result.stderr


def test_cross_org_parent_is_denied_when_composite_fk_is_checked() -> None:
    seed_tenants()
    result = psql(
        "INSERT INTO sessions (org_id, project_id, title) VALUES "
        f"('{ORG_A}', '{PROJECT_B}', 'forged parent')",
        check=False,
    )
    assert result.returncode != 0
    assert "foreign key constraint" in result.stderr


def test_audit_and_outbox_are_immutable_when_mutation_is_attempted() -> None:
    seed_tenants()
    _ = psql(
        "INSERT INTO audit_logs (id, org_id, actor_user_id, event_type, "
        f"resource_type, resource_id) VALUES ('{AUDIT_A}', '{ORG_A}', "
        f"'{USER_A}', 'project.read', 'project', '{PROJECT_A}')"
    )
    outbox_count = psql(
        f"SELECT count(*) FROM audit_outbox WHERE audit_log_id = '{AUDIT_A}'"
    ).stdout.strip()
    audit_update = psql(
        f"UPDATE audit_logs SET event_type = 'changed' WHERE id = '{AUDIT_A}'",
        check=False,
    )
    outbox_delete = psql("DELETE FROM audit_outbox", check=False)
    assert outbox_count == "1"
    assert "immutable table" in audit_update.stderr
    assert "immutable table" in outbox_delete.stderr


def test_last_owner_is_preserved_when_membership_is_removed() -> None:
    seed_tenants()
    rejected = psql(
        f"UPDATE memberships SET revoked_at = CURRENT_TIMESTAMP "
        f"WHERE org_id = '{ORG_A}' AND user_id = '{USER_A}'",
        check=False,
    )
    transferred = psql(
        "BEGIN; "
        f"UPDATE memberships SET role = 'owner' WHERE org_id = '{ORG_A}' "
        f"AND user_id = '{USER_C}'; UPDATE memberships SET revoked_at = "
        "CURRENT_TIMESTAMP "
        f"WHERE org_id = '{ORG_A}' AND user_id = '{USER_A}'; ROLLBACK"
    )
    assert "organization requires an owner" in rejected.stderr
    assert transferred.returncode == 0


def test_concurrent_owner_revocations_leave_one_owner() -> None:
    _ = psql(
        f"INSERT INTO organizations (id, name) VALUES ('{ORG_C}', 'C') "
        "ON CONFLICT DO NOTHING; INSERT INTO users (id, email) VALUES "
        f"('{USER_C1}', 'c1@example.test'), ('{USER_C2}', 'c2@example.test') "
        "ON CONFLICT DO NOTHING; INSERT INTO memberships (org_id, user_id, role) "
        f"VALUES ('{ORG_C}', '{USER_C1}', 'owner'), "
        f"('{ORG_C}', '{USER_C2}', 'owner') ON CONFLICT DO NOTHING"
    )

    def remove_owner(user_id: str) -> subprocess.CompletedProcess[str]:
        return psql(
            "BEGIN; "
            f"UPDATE memberships SET revoked_at = CURRENT_TIMESTAMP "
            f"WHERE org_id = '{ORG_C}' "
            f"AND user_id = '{user_id}'; SELECT pg_sleep(1); COMMIT",
            check=False,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(remove_owner, (USER_C1, USER_C2)))
    remaining = psql(
        f"SELECT count(*) FROM memberships WHERE org_id = '{ORG_C}' AND role = 'owner' "
        "AND revoked_at IS NULL"
    ).stdout.strip()
    assert sorted(result.returncode == 0 for result in results) == [False, True]
    assert remaining == "1"
    assert any(
        "concurrent owner membership change" in result.stderr for result in results
    )


def test_every_tenant_table_has_forced_rls_when_schema_is_current() -> None:
    policy_tables = tuple(
        psql(
            "SELECT tablename FROM pg_policies WHERE schemaname = 'public' "
            "AND policyname = 'tenant_isolation' ORDER BY tablename"
        ).stdout.splitlines()
    )
    forced_tables = tuple(
        psql(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n "
            "ON n.oid = c.relnamespace WHERE n.nspname = 'public' "
            "AND c.relrowsecurity AND c.relforcerowsecurity ORDER BY c.relname"
        ).stdout.splitlines()
    )
    global_status = tuple(
        psql(
            "SELECT c.relname || ':' || c.relrowsecurity::text || ':' || "
            "c.relforcerowsecurity::text FROM pg_class c JOIN pg_namespace n "
            "ON n.oid = c.relnamespace WHERE n.nspname = 'public' "
            f"AND c.relname IN ({', '.join(repr(table) for table in GLOBAL_TABLES)}) "
            "ORDER BY c.relname"
        ).stdout.splitlines()
    )
    immutable_tables = tuple(
        psql(
            "SELECT c.relname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
            "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' "
            "AND NOT t.tgisinternal AND t.tgname = c.relname || '_immutable' "
            "ORDER BY c.relname"
        ).stdout.splitlines()
    )
    provider_policy = psql(
        "SELECT coalesce(qual, '') || ' ' || coalesce(with_check, '') "
        "FROM pg_policies WHERE schemaname = 'public' "
        "AND tablename = 'provider_connections' "
        "AND policyname = 'tenant_isolation'"
    ).stdout.strip()

    assert policy_tables == tuple(sorted(TENANT_TABLES))
    assert forced_tables == tuple(sorted(TENANT_TABLES))
    assert global_status == tuple(f"{table}:false:false" for table in GLOBAL_TABLES)
    assert immutable_tables == tuple(sorted(APPEND_ONLY_TABLES))
    assert "requester_user_id" in provider_policy
    assert "app.user_id" in provider_policy


def test_monetary_schema_is_absent_when_catalog_is_inspected() -> None:
    counts = psql(
        "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' "
        "AND table_name ~ '(budget|cost|price|spend)'; SELECT count(*) FROM "
        "information_schema.columns WHERE table_schema = 'public' "
        "AND column_name ~ '(budget|cost|price|spend)'"
    ).stdout.splitlines()
    assert counts == ["0", "0"]


def test_non_uuid7_primary_id_is_denied_when_row_is_inserted() -> None:
    seed_tenants()
    result = psql(
        "INSERT INTO projects (id, org_id, name) VALUES "
        f"('123e4567-e89b-42d3-a456-426614174000', '{ORG_A}', 'wrong id')",
        check=False,
    )
    assert "primary id must be UUIDv7" in result.stderr
