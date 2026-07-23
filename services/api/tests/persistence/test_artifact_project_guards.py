from __future__ import annotations

from typing import Final

import pytest

from services.api.tests.persistence.postgres_harness import psql
from services.api.tests.persistence.test_rls import (
    ORG_A,
    PROJECT_A,
    USER_A,
    USER_C,
    app_principal_sql,
)
from services.api.tests.persistence.test_rls_contracts import (
    ARTIFACT,
    EXECUTION,
    PROVIDER,
    RECEIPT,
    RECEIPT_SHA,
    RESEARCH_INTENT_SHA,
    RESEARCH_INTENT_SQL,
    SHA,
    VERSION,
    seed_artifact_version,
)

PROJECT_C: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e30"
SESSION_C: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e31"
ARTIFACT_TWO: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e32"
VERSION_TWO: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e33"
VERSION_THREE: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e34"
VERSION_FOUR: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e39"
RUN_C: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e35"
PLAN_C: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e36"
EXECUTION_C: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e37"
PROVIDER_TWO: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e38"
pytestmark = pytest.mark.usefixtures("migrated_database")


def _seed_same_org_second_project() -> None:
    seed_artifact_version()
    _ = psql(
        "INSERT INTO projects (id, org_id, name) VALUES "
        f"('{PROJECT_C}', '{ORG_A}', 'Project C') ON CONFLICT DO NOTHING; "
        "INSERT INTO sessions (id, org_id, project_id, title) VALUES "
        f"('{SESSION_C}', '{ORG_A}', '{PROJECT_C}', 'Session C') "
        "ON CONFLICT DO NOTHING; INSERT INTO runs "
        "(id, org_id, session_id, requester_id, provider_connection_id, status, "
        "qualification_receipt_id, qualification_receipt_sha256, "
        "qualification_connection_revision, qualification_profile_sha256, "
        "qualification_runtime_version, qualification_executable_sha256, "
        "provider_model_id) "
        f"VALUES ('{RUN_C}', '{ORG_A}', '{SESSION_C}', '{USER_A}', '{PROVIDER}', "
        f"'running', '{RECEIPT}', '{RECEIPT_SHA}', 2, '{SHA}', "
        "'codex-cli-fixture', "
        f"'{SHA}', 'codex-mini') ON CONFLICT DO NOTHING; INSERT INTO action_plans "
        "(id, org_id, run_id, requester_id, research_intent, "
        "research_intent_sha256, version, tool, arguments, arguments_hash, "
        "network_scope, secret_scope, reason, plan_digest) VALUES "
        f"('{PLAN_C}', '{ORG_A}', '{RUN_C}', '{USER_A}', "
        f"'{RESEARCH_INTENT_SQL}', '{RESEARCH_INTENT_SHA}', 1, 'python', "
        f"'{{}}', '{SHA}', "
        f"'{{}}', '{{}}', 'project-c', '{SHA}') "
        "ON CONFLICT DO NOTHING; INSERT INTO executions "
        "(id, org_id, run_id, action_plan_id, status, attempt_token, result_ref) "
        f"VALUES ('{EXECUTION_C}', '{ORG_A}', '{RUN_C}', '{PLAN_C}', 'completed', "
        "1, 'artifact://project-c') ON CONFLICT DO NOTHING; INSERT INTO artifacts "
        "(id, org_id, project_id, name) VALUES "
        f"('{ARTIFACT_TWO}', '{ORG_A}', '{PROJECT_C}', 'Other') "
        "ON CONFLICT DO NOTHING; INSERT INTO artifact_versions "
        "(id, org_id, project_id, artifact_id, producing_execution_id, "
        "runtime_connection_id, version, object_key, content_sha256, size_bytes, "
        "media_type, environment_sha256, code_sha256, runtime_adapter_id, "
        f"skill_content_hashes, source_hashes) VALUES ('{VERSION_TWO}', '{ORG_A}', "
        f"'{PROJECT_C}', '{ARTIFACT_TWO}', '{EXECUTION_C}', '{PROVIDER}', 1, "
        f"'org/{ORG_A}/project/{PROJECT_C}/sha256/{SHA}', '{SHA}', 1, "
        f"'text/csv', '{SHA}', '{SHA}', 'openai_codex', '{{}}', '{{}}') "
        "ON CONFLICT DO NOTHING"
    )


def test_database_rejects_same_org_cross_project_lineage_and_session_links() -> None:
    _seed_same_org_second_project()
    dependency = psql(
        "INSERT INTO artifact_dependencies "
        "(org_id, project_id, artifact_version_id, input_version_id) VALUES "
        f"('{ORG_A}', '{PROJECT_A}', '{VERSION}', '{VERSION_TWO}')",
        check=False,
    )
    association = psql(
        "INSERT INTO session_artifact_versions "
        "(org_id, project_id, session_id, artifact_version_id, revision) VALUES "
        f"('{ORG_A}', '{PROJECT_A}', '{SESSION_C}', '{VERSION}', 1)",
        check=False,
    )
    assert dependency.returncode != 0
    assert association.returncode != 0
    assert "foreign key constraint" in dependency.stderr
    assert "artifact association scope is inactive" in association.stderr


def test_dependency_lineage_cannot_be_updated_or_deleted_by_app_role() -> None:
    seed_artifact_version()
    _ = psql(
        "INSERT INTO artifact_versions "
        "(id, org_id, project_id, artifact_id, producing_execution_id, "
        "runtime_connection_id, version, object_key, content_sha256, size_bytes, "
        "media_type, environment_sha256, code_sha256, runtime_adapter_id, "
        f"skill_content_hashes, source_hashes) VALUES ('{VERSION_THREE}', '{ORG_A}', "
        f"'{PROJECT_A}', '{ARTIFACT}', '{EXECUTION}', '{PROVIDER}', 2, "
        f"'org/{ORG_A}/project/{PROJECT_A}/sha256/{'b' * 64}', '{'b' * 64}', 1, "
        f"'text/csv', '{SHA}', '{SHA}', 'openai_codex', '{{}}', '{{}}'); "
        "INSERT INTO artifact_dependencies "
        "(org_id, project_id, artifact_version_id, input_version_id) VALUES "
        f"('{ORG_A}', '{PROJECT_A}', '{VERSION_THREE}', '{VERSION}')"
    )
    principal = "SET ROLE science_workbench_app; " + app_principal_sql(ORG_A, USER_A)
    update = psql(
        principal + "UPDATE artifact_dependencies SET created_at = CURRENT_TIMESTAMP "
        f"WHERE artifact_version_id = '{VERSION_THREE}'",
        check=False,
    )
    delete = psql(
        principal + "DELETE FROM artifact_dependencies "
        f"WHERE artifact_version_id = '{VERSION_THREE}'",
        check=False,
    )
    assert update.returncode != 0
    assert delete.returncode != 0
    assert "permission denied" in update.stderr
    assert "permission denied" in delete.stderr


def test_database_rejects_sandbox_selected_object_key() -> None:
    seed_artifact_version()
    result = psql(
        "INSERT INTO artifact_versions "
        "(id, org_id, project_id, artifact_id, producing_execution_id, "
        "runtime_connection_id, version, object_key, content_sha256, size_bytes, "
        "media_type, environment_sha256, code_sha256, runtime_adapter_id, "
        f"skill_content_hashes, source_hashes) VALUES ('{VERSION_THREE}', '{ORG_A}', "
        f"'{PROJECT_A}', '{ARTIFACT}', '{EXECUTION}', '{PROVIDER}', 2, "
        f"'../../sandbox-selected', '{'b' * 64}', 1, 'text/csv', '{SHA}', '{SHA}', "
        "'openai_codex', '{}', '{}')",
        check=False,
    )
    assert result.returncode != 0
    assert "artifact_object_key" in result.stderr


def test_database_rejects_other_requesters_execution_provenance() -> None:
    seed_artifact_version()
    result = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql(ORG_A, USER_C)
        + "INSERT INTO artifact_versions "
        "(id, org_id, project_id, artifact_id, producing_execution_id, "
        "runtime_connection_id, version, object_key, content_sha256, size_bytes, "
        "media_type, environment_sha256, code_sha256, runtime_adapter_id, "
        f"skill_content_hashes, source_hashes) VALUES ('{VERSION_FOUR}', '{ORG_A}', "
        f"'{PROJECT_A}', '{ARTIFACT}', '{EXECUTION}', '{PROVIDER}', 2, "
        f"'org/{ORG_A}/project/{PROJECT_A}/sha256/{'d' * 64}', '{'d' * 64}', 1, "
        f"'text/plain', '{SHA}', '{SHA}', 'openai_codex', '{{}}', '{{}}')",
        check=False,
    )
    assert result.returncode != 0
    assert "artifact version scope mismatch" in result.stderr


@pytest.mark.parametrize(
    ("runtime_connection_id", "runtime_adapter_id"),
    [(PROVIDER_TWO, "anthropic_claude_code"), (PROVIDER, "fabricated_adapter")],
)
def test_database_binds_runtime_provenance_to_the_producing_run(
    runtime_connection_id: str,
    runtime_adapter_id: str,
) -> None:
    seed_artifact_version()
    _ = psql(
        "INSERT INTO provider_connections "
        "(id, org_id, requester_user_id, adapter_id, encrypted_runtime_home_ref, "
        f"account_metadata, status) VALUES ('{PROVIDER_TWO}', '{ORG_A}', '{USER_A}', "
        "'anthropic_claude_code', 'vault://runtime/second', '{}', 'pending') "
        "ON CONFLICT DO NOTHING"
    )
    result = psql(
        "INSERT INTO artifact_versions "
        "(id, org_id, project_id, artifact_id, producing_execution_id, "
        "runtime_connection_id, version, object_key, content_sha256, size_bytes, "
        "media_type, environment_sha256, code_sha256, runtime_adapter_id, "
        f"skill_content_hashes, source_hashes) VALUES ('{VERSION_THREE}', '{ORG_A}', "
        f"'{PROJECT_A}', '{ARTIFACT}', '{EXECUTION}', '{runtime_connection_id}', 2, "
        f"'org/{ORG_A}/project/{PROJECT_A}/sha256/{'b' * 64}', '{'b' * 64}', 1, "
        f"'text/csv', '{SHA}', '{SHA}', '{runtime_adapter_id}', '{{}}', '{{}}')",
        check=False,
    )
    assert result.returncode != 0
    assert "artifact version scope mismatch" in result.stderr
