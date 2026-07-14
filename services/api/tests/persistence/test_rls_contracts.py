from __future__ import annotations

from typing import Final

import pytest

from services.api.tests.persistence.postgres_harness import psql
from services.api.tests.persistence.test_rls import (
    ORG_A,
    PROJECT_A,
    USER_A,
    seed_tenants,
)

SESSION: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e01"
PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e02"
RUN: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e03"
PLAN: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e04"
APPROVAL: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e05"
EXECUTION: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e06"
BAD_EXECUTION: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e07"
ARTIFACT: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e08"
VERSION: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e09"
REVIEW: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e10"
SUBMISSION: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e11"
FINDING: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e12"
BAD_FINDING: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e13"
SHA: Final = "a" * 64
pytestmark = pytest.mark.usefixtures("migrated_database")


def seed_execution_graph() -> None:
    seed_tenants()
    _ = psql(
        "INSERT INTO sessions (id, org_id, project_id, title) VALUES "
        f"('{SESSION}', '{ORG_A}', '{PROJECT_A}', 'Contract') ON CONFLICT DO NOTHING; "
        "INSERT INTO provider_connections (id, org_id, requester_user_id, adapter_id, "
        "encrypted_runtime_home_ref, account_metadata, status) VALUES "
        f"('{PROVIDER}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        "'vault://runtime/contract', '{}', 'healthy') ON CONFLICT DO NOTHING; "
        "INSERT INTO runs (id, org_id, session_id, requester_id, "
        "provider_connection_id, status) VALUES "
        f"('{RUN}', '{ORG_A}', '{SESSION}', '{USER_A}', '{PROVIDER}', 'running') "
        "ON CONFLICT DO NOTHING; "
        "INSERT INTO action_plans (id, org_id, run_id, requester_id, version, tool, "
        "arguments, arguments_hash, network_scope, secret_scope, reason, plan_digest) "
        f"VALUES ('{PLAN}', '{ORG_A}', '{RUN}', '{USER_A}', 1, 'python', '{{}}', "
        f"'{SHA}', '{{}}', '{{}}', 'contract', '{SHA}') ON CONFLICT DO NOTHING"
    )


def seed_artifact_version() -> None:
    seed_execution_graph()
    _ = psql(
        "INSERT INTO executions (id, org_id, run_id, action_plan_id, status, "
        f"attempt_token, result_ref) VALUES ('{EXECUTION}', '{ORG_A}', '{RUN}', "
        f"'{PLAN}', 'completed', 1, 'artifact://result') ON CONFLICT DO NOTHING; "
        "INSERT INTO artifacts (id, org_id, project_id, name) VALUES "
        f"('{ARTIFACT}', '{ORG_A}', '{PROJECT_A}', 'Result') ON CONFLICT DO NOTHING; "
        "INSERT INTO artifact_versions (id, org_id, project_id, artifact_id, "
        "producing_execution_id, runtime_connection_id, version, object_key, "
        "content_sha256, size_bytes, media_type, environment_sha256, code_sha256, "
        "runtime_adapter_id, skill_content_hashes, source_hashes) VALUES "
        f"('{VERSION}', '{ORG_A}', '{PROJECT_A}', '{ARTIFACT}', '{EXECUTION}', "
        f"'{PROVIDER}', 1, 'org/{ORG_A}/project/{PROJECT_A}/sha256/{SHA}', "
        f"'{SHA}', 1, 'text/csv', '{SHA}', '{SHA}', "
        "'openai_codex', '{}', '{}') ON CONFLICT DO NOTHING"
    )


def seed_completed_review() -> None:
    seed_artifact_version()
    _ = psql(
        "BEGIN; INSERT INTO reviews (id, org_id, source_run_id, run_id, "
        f"pinned_input_sha256, status) VALUES ('{REVIEW}', '{ORG_A}', '{RUN}', "
        f"'{RUN}', '{SHA}', 'running') ON CONFLICT DO NOTHING; "
        "INSERT INTO review_artifact_versions (org_id, review_id, artifact_version_id) "
        f"SELECT '{ORG_A}', '{REVIEW}', '{VERSION}' WHERE EXISTS (SELECT 1 FROM "
        f"reviews WHERE id = '{REVIEW}' AND status = 'running') AND NOT EXISTS "
        "(SELECT 1 FROM review_artifact_versions WHERE "
        f"review_id = '{REVIEW}' AND artifact_version_id = '{VERSION}'); "
        "INSERT INTO review_execution_refs (org_id, review_id, execution_id) "
        f"SELECT '{ORG_A}', '{REVIEW}', '{EXECUTION}' WHERE EXISTS (SELECT 1 FROM "
        f"reviews WHERE id = '{REVIEW}' AND status = 'running') AND NOT EXISTS "
        f"(SELECT 1 FROM review_execution_refs WHERE review_id = '{REVIEW}' "
        f"AND execution_id = '{EXECUTION}'); "
        f"UPDATE reviews SET revision = revision + 1, "
        f"submission_id = '{SUBMISSION}', submitted_at = CURRENT_TIMESTAMP "
        f"WHERE id = '{REVIEW}' AND status = 'running'; "
        "INSERT INTO review_findings (id, org_id, review_id, submission_id, rule_id, "
        f"verdict, status, message) SELECT '{FINDING}', '{ORG_A}', '{REVIEW}', "
        f"'{SUBMISSION}', 'RV01', 'pass', 'open', 'verified' WHERE EXISTS "
        f"(SELECT 1 FROM reviews WHERE id = '{REVIEW}' AND status = 'running') "
        f"AND NOT EXISTS (SELECT 1 FROM review_findings WHERE id = '{FINDING}'); "
        "INSERT INTO review_finding_artifact_versions "
        f"(org_id, finding_id, artifact_version_id) SELECT '{ORG_A}', '{FINDING}', "
        f"'{VERSION}' WHERE EXISTS (SELECT 1 FROM reviews WHERE id = '{REVIEW}' "
        f"AND status = 'running') AND NOT EXISTS (SELECT 1 FROM "
        f"review_finding_artifact_versions WHERE finding_id = '{FINDING}' AND "
        f"artifact_version_id = '{VERSION}'); UPDATE reviews SET "
        f"status = 'completed', revision = revision + 1 WHERE id = '{REVIEW}' "
        "AND status = 'running'; COMMIT"
    )


def test_approval_revision_and_completed_execution_result_are_enforced() -> None:
    seed_execution_graph()
    revision = psql(
        "INSERT INTO approval_requests (id, org_id, run_id, action_plan_id, "
        "requester_id, digest, status, expires_at) VALUES "
        f"('{APPROVAL}', '{ORG_A}', '{RUN}', '{PLAN}', '{USER_A}', '{SHA}', "
        "'pending', CURRENT_TIMESTAMP + interval '5 minutes') RETURNING revision"
    ).stdout.strip()
    rejected = psql(
        "INSERT INTO executions (id, org_id, run_id, action_plan_id, status, "
        f"attempt_token) VALUES ('{BAD_EXECUTION}', '{ORG_A}', '{RUN}', "
        f"'{PLAN}', 'completed', 1)",
        check=False,
    )
    accepted = psql(
        "INSERT INTO executions (id, org_id, run_id, action_plan_id, status, "
        f"attempt_token, result_ref) VALUES ('{EXECUTION}', '{ORG_A}', '{RUN}', "
        f"'{PLAN}', 'completed', 1, 'artifact://result')"
    )
    assert revision == "1"
    assert "completed_execution_result" in rejected.stderr
    assert accepted.returncode == 0


def test_review_cas_submission_and_finding_evidence_are_representable() -> None:
    seed_artifact_version()
    initial = psql(
        "BEGIN; INSERT INTO reviews (id, org_id, source_run_id, run_id, "
        f"pinned_input_sha256, status) VALUES ('{REVIEW}', '{ORG_A}', '{RUN}', "
        f"'{RUN}', '{SHA}', 'running'); INSERT INTO review_execution_refs "
        f"(org_id, review_id, execution_id) VALUES ('{ORG_A}', '{REVIEW}', "
        f"'{EXECUTION}'); INSERT INTO review_artifact_versions "
        f"(org_id, review_id, artifact_version_id) VALUES ('{ORG_A}', '{REVIEW}', "
        f"'{VERSION}'); COMMIT; SELECT revision || ':' || "
        f"(reviewer_capabilities->>'reexecution') FROM reviews WHERE id = '{REVIEW}'"
    ).stdout.strip()
    missing_submission = psql(
        f"UPDATE reviews SET status = 'completed', revision = 2 WHERE id = '{REVIEW}'",
        check=False,
    )
    missing_disposition = psql(
        f"BEGIN; UPDATE reviews SET revision = 2, submission_id = '{SUBMISSION}', "
        f"submitted_at = CURRENT_TIMESTAMP WHERE id = '{REVIEW}'; "
        "INSERT INTO review_findings (id, org_id, review_id, submission_id, rule_id, "
        f"verdict, status, message) VALUES ('{BAD_FINDING}', '{ORG_A}', '{REVIEW}', "
        f"'{SUBMISSION}', 'RV02', 'warn', 'accepted_risk', 'missing audit'); COMMIT",
        check=False,
    )
    submitted = psql(
        f"BEGIN; UPDATE reviews SET revision = 2, "
        f"submission_id = '{SUBMISSION}', submitted_at = CURRENT_TIMESTAMP "
        f"WHERE id = '{REVIEW}'; INSERT INTO review_findings (id, org_id, review_id, "
        "submission_id, rule_id, verdict, status, message) VALUES "
        f"('{FINDING}', '{ORG_A}', '{REVIEW}', '{SUBMISSION}', 'RV01', 'pass', "
        f"'open', 'verified'); INSERT INTO review_finding_artifact_versions "
        f"(org_id, finding_id, artifact_version_id) VALUES ('{ORG_A}', '{FINDING}', "
        f"'{VERSION}'); UPDATE reviews SET status = 'completed', revision = 3 "
        f"WHERE id = '{REVIEW}'; COMMIT",
        check=False,
    )
    assert initial == "1:false"
    assert "review submission lifecycle" in missing_submission.stderr
    assert submitted.returncode == 0, submitted.stderr
    assert "finding_disposition_audit" in missing_disposition.stderr
