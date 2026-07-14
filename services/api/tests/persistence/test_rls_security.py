from __future__ import annotations

import json
from typing import Final

import pytest

from services.api.tests.persistence.postgres_harness import psql
from services.api.tests.persistence.test_rls import (
    ORG_A,
    PROJECT_A,
    PROJECT_B,
    USER_A,
    app_principal_sql,
    seed_tenants,
)

PROVIDER_SAFE: Final = "018f0d7d-6b17-7a91-8b31-2f7331677a06"
PROVIDER_REJECTED: Final = "018f0d7d-6b17-7a91-8b31-2f7331677a07"
PROVIDER_UNICODE: Final = "018f0d7d-6b17-7a91-8b31-2f7331677a08"
PROVIDER_RAW_HOME: Final = "018f0d7d-6b17-7a91-8b31-2f7331677a10"
PROVIDER_INSERT: Final = (
    "INSERT INTO provider_connections (id, org_id, requester_user_id, "
    "adapter_id, encrypted_runtime_home_ref, account_metadata, status) VALUES "
)
pytestmark = pytest.mark.usefixtures("migrated_database")


def _metadata(key: str, value: str) -> str:
    return json.dumps({key: value}, separators=(",", ":"))


def test_legal_hold_mutation_requires_compliance_role() -> None:
    seed_tenants()
    owner_attempt = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql()
        + "INSERT INTO legal_holds (org_id, scope_type, scope_id, action, "
        f"actor_authority, actor_ref, reason) VALUES ('{ORG_A}', 'project', "
        f"'{PROJECT_A}', 'place', 'compliance_operator', 'owner', 'invalid')",
        check=False,
    )
    compliance_attempt = psql(
        "SET ROLE science_workbench_compliance; "
        f"SELECT set_config('app.org_id', '{ORG_A}', false); "
        "INSERT INTO legal_holds (org_id, scope_type, scope_id, action, "
        f"actor_authority, actor_ref, reason) VALUES ('{ORG_A}', 'project', "
        f"'{PROJECT_A}', 'place', 'compliance_operator', 'operator-1', 'preserve')"
    )
    assert "permission denied" in owner_attempt.stderr
    assert compliance_attempt.returncode == 0


def test_legal_hold_scope_cannot_reference_another_tenant() -> None:
    seed_tenants()
    result = psql(
        "SET ROLE science_workbench_compliance; "
        f"SELECT set_config('app.org_id', '{ORG_A}', false); "
        "INSERT INTO legal_holds (org_id, scope_type, scope_id, action, "
        f"actor_authority, actor_ref, reason) VALUES ('{ORG_A}', 'project', "
        f"'{PROJECT_B}', 'place', 'compliance_operator', 'operator-1', 'invalid')",
        check=False,
    )
    assert result.returncode != 0
    assert "foreign key constraint" in result.stderr


def test_provider_account_metadata_rejects_nested_plaintext_secrets() -> None:
    seed_tenants()
    safe = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql()
        + PROVIDER_INSERT
        + f"('{PROVIDER_SAFE}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        "'vault://runtime/safe', '{\"account_name\":\"lab\"}', 'healthy')",
        check=False,
    )
    rejected = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql()
        + PROVIDER_INSERT
        + f"('{PROVIDER_REJECTED}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        "'vault://runtime/rejected', "
        '\'{"nested":{"authorization":"Bearer abcdefghijklmnop"}}\', '
        "'healthy')",
        check=False,
    )
    unicode_key = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql()
        + PROVIDER_INSERT
        + f"('{PROVIDER_UNICODE}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        "'vault://runtime/rejected-unicode', "
        "'{\"\uff41\uff43\uff43\uff45\uff53\uff53\uff3f"
        "\uff54\uff4f\uff4b\uff45\uff4e\":\"abcdefghijklmnop\"}', 'healthy')",
        check=False,
    )
    assert safe.returncode == 0, safe.stderr
    assert rejected.returncode != 0
    assert unicode_key.returncode != 0
    assert "provider account metadata contains secret" in rejected.stderr
    assert "provider account metadata contains secret" in unicode_key.stderr


@pytest.mark.parametrize(
    "metadata",
    [
        _metadata("oauth_" + "access_" + "token", "ya29." + "abcdefghijklmnop"),
        _metadata("cookie", "session=" + "abcdefghijklmnop"),
        _metadata("note", "client_" + "secret=" + "abcdefghijklmnop"),
        _metadata("account_name", "AKIA" + "ABCDEFGHIJKLMNOP"),
        _metadata("display_name", "-----BEGIN " + "PRIVATE KEY-----"),
    ],
)
def test_provider_account_metadata_rejects_secret_bypass_shapes(
    metadata: str,
) -> None:
    seed_tenants()
    result = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql()
        + PROVIDER_INSERT
        + f"('{PROVIDER_REJECTED}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        f"'vault://runtime/rejected', '{metadata}', 'healthy')",
        check=False,
    )
    assert result.returncode != 0
    assert "provider account metadata contains secret" in result.stderr


def test_provider_secret_columns_are_absent_when_catalog_is_inspected() -> None:
    count = psql(
        "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' "
        "AND column_name ~ '(access_token|refresh_token|api_key)'"
    ).stdout.strip()
    assert count == "0"


def test_provider_runtime_home_requires_opaque_vault_reference() -> None:
    seed_tenants()
    raw_home = "Bearer " + "raw-" + "secret-material"
    result = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql()
        + PROVIDER_INSERT
        + f"('{PROVIDER_RAW_HOME}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        f"'{raw_home}', '{{}}', 'healthy')",
        check=False,
    )
    assert result.returncode != 0
    assert "provider_runtime_home_opaque_ref" in result.stderr
