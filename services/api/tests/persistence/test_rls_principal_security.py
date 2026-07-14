from __future__ import annotations

import pytest

from services.api.tests.persistence.postgres_harness import psql
from services.api.tests.persistence.test_rls import (
    ORG_A,
    ORG_B,
    USER_A,
    USER_B,
    USER_C,
    app_principal_sql,
    seed_tenants,
)

pytestmark = pytest.mark.usefixtures("migrated_database")
USER_D = "018f0d7d-6b17-7a91-8b31-2f7331677a11"
PROVIDER_D = "018f0d7d-6b17-7a91-8b31-2f7331677a12"


def test_membership_mismatch_cannot_select_tenant_rows() -> None:
    seed_tenants()
    result = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql(ORG_A, USER_B)
        + "SELECT count(*) FROM projects"
    )
    assert result.stdout.splitlines()[-1] == "0"


def test_member_cannot_promote_membership_to_owner() -> None:
    seed_tenants()
    result = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql(ORG_A, USER_C)
        + f"UPDATE memberships SET role = 'owner' WHERE org_id = '{ORG_A}' "
        f"AND user_id = '{USER_C}'",
        check=False,
    )
    role = psql(
        f"SELECT role FROM memberships WHERE org_id = '{ORG_A}' "
        f"AND user_id = '{USER_C}'"
    ).stdout.strip()
    owner_result = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql(ORG_A, USER_A)
        + f"BEGIN; UPDATE memberships SET role = 'owner' WHERE org_id = '{ORG_A}' "
        f"AND user_id = '{USER_C}'; ROLLBACK"
    )
    assert result.returncode != 0
    assert "membership mutation requires owner" in result.stderr
    assert owner_result.returncode == 0
    assert role == "member"


def test_provider_connection_is_visible_only_to_requester() -> None:
    seed_tenants()
    provider_id = "018f0d7d-6b17-7a91-8b31-2f7331677a09"
    _ = psql(
        "INSERT INTO provider_connections (id, org_id, requester_user_id, adapter_id, "
        "encrypted_runtime_home_ref, account_metadata, status) VALUES "
        f"('{provider_id}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        "'vault://runtime/requester-only', '{}', 'healthy') ON CONFLICT DO NOTHING"
    )
    count = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql(ORG_A, USER_C)
        + f"SELECT count(*) FROM provider_connections WHERE id = '{provider_id}'"
    ).stdout.splitlines()[-1]
    requester_count = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql(ORG_A, USER_A)
        + f"SELECT count(*) FROM provider_connections WHERE id = '{provider_id}'"
    ).stdout.splitlines()[-1]
    mutation = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql(ORG_A, USER_C)
        + "UPDATE provider_connections SET status = 'revoked' "
        f"WHERE id = '{provider_id}'"
    )
    status = psql(
        f"SELECT status FROM provider_connections WHERE id = '{provider_id}'"
    ).stdout.strip()
    assert count == "0"
    assert requester_count == "1"
    assert mutation.returncode == 0
    assert status == "healthy"


def test_owner_soft_revokes_member_without_deleting_history() -> None:
    seed_tenants()
    _ = psql(
        f"INSERT INTO users (id, email) VALUES ('{USER_D}', 'd@example.test'); "
        "INSERT INTO memberships (org_id, user_id, role) VALUES "
        f"('{ORG_A}', '{USER_D}', 'member'); INSERT INTO provider_connections "
        "(id, org_id, requester_user_id, adapter_id, encrypted_runtime_home_ref, "
        f"account_metadata, status) VALUES ('{PROVIDER_D}', '{ORG_A}', '{USER_D}', "
        "'openai_codex', 'vault://runtime/revoked-history', '{}', 'healthy')"
    )
    revoked = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql(ORG_A, USER_A)
        + "UPDATE memberships SET revoked_at = CURRENT_TIMESTAMP "
        f"WHERE org_id = '{ORG_A}' AND user_id = '{USER_D}'"
    )
    old_access = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql(ORG_A, USER_D)
        + "SELECT count(*) FROM provider_connections"
    ).stdout.splitlines()[-1]
    history = psql(
        f"SELECT count(*) FROM provider_connections WHERE id = '{PROVIDER_D}'"
    ).stdout.strip()
    rejoined = psql(
        "INSERT INTO memberships (org_id, user_id, role) VALUES "
        f"('{ORG_B}', '{USER_D}', 'member')"
    )
    active_org = psql(
        f"SELECT org_id FROM memberships WHERE user_id = '{USER_D}' "
        "AND revoked_at IS NULL"
    ).stdout.strip()
    assert revoked.returncode == 0
    assert old_access == "0"
    assert history == "1"
    assert rejoined.returncode == 0
    assert active_org == ORG_B
