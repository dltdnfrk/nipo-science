from __future__ import annotations

from typing import Final

import pytest

from services.api.tests.persistence.postgres_harness import psql
from services.api.tests.persistence.test_rls import (
    ORG_A,
    PROJECT_A,
    USER_A,
    app_principal_sql,
)
from services.api.tests.persistence.test_rls_contracts import (
    ARTIFACT,
    EXECUTION,
    FINDING,
    PROVIDER,
    REVIEW,
    RUN,
    SHA,
    VERSION,
    seed_artifact_version,
    seed_completed_review,
)

VERSION_TWO: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e14"
FINDING_TWO: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e15"
SUBMISSION: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e11"
EXPORT: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e16"
EMPTY_REVIEW: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e17"
EMPTY_SUBMISSION: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e18"
REVIEW_TWO: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e19"
SUBMISSION_TWO: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e20"
EMPTY_EXPORT: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e21"
pytestmark = pytest.mark.usefixtures("migrated_database")


def _seed_version_two() -> None:
    seed_completed_review()
    _ = psql(
        "INSERT INTO artifact_versions (id, org_id, project_id, artifact_id, "
        "producing_execution_id, runtime_connection_id, version, object_key, "
        "content_sha256, size_bytes, media_type, environment_sha256, code_sha256, "
        "runtime_adapter_id, skill_content_hashes, source_hashes) VALUES "
        f"('{VERSION_TWO}', '{ORG_A}', '{PROJECT_A}', '{ARTIFACT}', '{EXECUTION}', "
        f"'{PROVIDER}', 2, 'org/{ORG_A}/project/{PROJECT_A}/sha256/{SHA}', "
        f"'{SHA}', 1, 'text/csv', '{SHA}', '{SHA}', "
        "'openai_codex', '{}', '{}') ON CONFLICT DO NOTHING"
    )


def test_completed_review_inputs_and_findings_are_immutable() -> None:
    seed_completed_review()
    principal = "SET ROLE science_workbench_app; " + app_principal_sql()
    review_update = psql(
        principal
        + f"UPDATE reviews SET pinned_input_sha256 = '{'b' * 64}', revision = 3 "
        f"WHERE id = '{REVIEW}'",
        check=False,
    )
    review_pin_delete = psql(
        principal
        + f"DELETE FROM review_artifact_versions WHERE review_id = '{REVIEW}'",
        check=False,
    )
    finding_update = psql(
        principal
        + f"UPDATE review_findings SET message = 'rewritten' WHERE id = '{FINDING}'",
        check=False,
    )
    finding_delete = psql(
        principal + f"DELETE FROM review_findings WHERE id = '{FINDING}'",
        check=False,
    )
    evidence_append = psql(
        principal + "INSERT INTO review_finding_execution_refs "
        f"(org_id, finding_id, execution_id) VALUES ('{ORG_A}', '{FINDING}', "
        f"'{EXECUTION}')",
        check=False,
    )
    finding_append = psql(
        principal
        + "INSERT INTO review_findings (id, org_id, review_id, submission_id, "
        "rule_id, verdict, status, message) VALUES "
        f"('{FINDING_TWO}', '{ORG_A}', '{REVIEW}', '{SUBMISSION}', 'RV02', "
        "'warn', 'open', 'late')",
        check=False,
    )
    for result in (
        review_update,
        review_pin_delete,
        finding_update,
        finding_delete,
    ):
        assert result.returncode != 0
        assert "immutable" in result.stderr
    assert evidence_append.returncode != 0
    assert finding_append.returncode != 0
    assert "immutable" in finding_append.stderr


def test_finding_disposition_audit_cannot_be_erased() -> None:
    seed_completed_review()
    accepted = psql(
        f"UPDATE review_findings SET status = 'accepted_risk', "
        f"disposition_actor_id = '{USER_A}', disposition_reason = 'documented' "
        f"WHERE id = '{FINDING}'"
    )
    erased = psql(
        "UPDATE review_findings SET status = 'open', disposition_actor_id = NULL, "
        f"disposition_reason = NULL WHERE id = '{FINDING}'",
        check=False,
    )
    assert accepted.returncode == 0
    assert erased.returncode != 0
    assert "disposition audit is immutable" in erased.stderr


def test_finding_evidence_must_be_one_of_the_review_pins() -> None:
    _seed_version_two()
    result = psql(
        "SET ROLE science_workbench_app; "
        + app_principal_sql()
        + "BEGIN; INSERT INTO reviews (id, org_id, source_run_id, run_id, "
        f"pinned_input_sha256, status) VALUES ('{REVIEW_TWO}', '{ORG_A}', '{RUN}', "
        f"'{RUN}', '{'d' * 64}', 'running'); INSERT INTO review_artifact_versions "
        f"(org_id, review_id, artifact_version_id) VALUES ('{ORG_A}', '{REVIEW_TWO}', "
        f"'{VERSION}'); UPDATE reviews SET revision = 2, "
        f"submission_id = '{SUBMISSION_TWO}', submitted_at = CURRENT_TIMESTAMP "
        f"WHERE id = '{REVIEW_TWO}'; INSERT INTO review_findings "
        "(id, org_id, review_id, submission_id, "
        "rule_id, verdict, status, message) VALUES "
        f"('{FINDING_TWO}', '{ORG_A}', '{REVIEW_TWO}', '{SUBMISSION_TWO}', "
        "'RV02', 'warn', "
        "'open', 'not pinned'); INSERT INTO review_finding_artifact_versions "
        f"(org_id, finding_id, artifact_version_id) VALUES ('{ORG_A}', "
        f"'{FINDING_TWO}', '{VERSION_TWO}'); COMMIT",
        check=False,
    )
    assert result.returncode != 0
    assert "finding artifact must be pinned by review" in result.stderr


def test_export_selection_rejects_replacement_or_deletion() -> None:
    _seed_version_two()
    _ = psql(
        "BEGIN; INSERT INTO export_jobs (id, org_id, status) VALUES "
        f"('{EXPORT}', '{ORG_A}', 'queued') ON CONFLICT DO NOTHING; "
        "INSERT INTO export_artifact_versions "
        f"(org_id, export_id, artifact_version_id, archive_path) VALUES ('{ORG_A}', "
        f"'{EXPORT}', '{VERSION}', 'artifacts/result.csv') ON CONFLICT DO NOTHING; "
        "COMMIT"
    )
    principal = "SET ROLE science_workbench_app; " + app_principal_sql()
    update = psql(
        principal + "UPDATE export_artifact_versions SET archive_path = 'changed.csv' "
        f"WHERE export_id = '{EXPORT}'",
        check=False,
    )
    delete = psql(
        principal
        + f"DELETE FROM export_artifact_versions WHERE export_id = '{EXPORT}'",
        check=False,
    )
    _ = psql(f"UPDATE export_jobs SET status = 'running' WHERE id = '{EXPORT}'")
    reset_created_at = psql(
        principal + "UPDATE export_jobs SET created_at = CURRENT_TIMESTAMP "
        f"WHERE id = '{EXPORT}'",
        check=False,
    )
    append = psql(
        principal + "INSERT INTO export_artifact_versions "
        f"(org_id, export_id, artifact_version_id, archive_path) VALUES ('{ORG_A}', "
        f"'{EXPORT}', '{VERSION_TWO}', 'artifacts/result-2.csv')",
        check=False,
    )
    _ = psql(f"UPDATE export_jobs SET status = 'completed' WHERE id = '{EXPORT}'")
    rewind = psql(
        principal + f"UPDATE export_jobs SET status = 'running' WHERE id = '{EXPORT}'",
        check=False,
    )
    assert update.returncode != 0
    assert delete.returncode != 0
    assert reset_created_at.returncode != 0
    assert append.returncode != 0
    assert rewind.returncode != 0
    assert "immutable" in update.stderr
    assert "immutable" in delete.stderr
    assert "immutable" in reset_created_at.stderr
    assert "immutable" in append.stderr
    assert "immutable" in rewind.stderr


def test_export_requires_at_least_one_version_selection() -> None:
    seed_completed_review()
    result = psql(
        "INSERT INTO export_jobs (id, org_id, status) VALUES "
        f"('{EMPTY_EXPORT}', '{ORG_A}', 'queued')",
        check=False,
    )
    assert result.returncode != 0
    assert "export requires an artifact version selection" in result.stderr


def test_completed_review_requires_at_least_one_finding() -> None:
    seed_artifact_version()
    result = psql(
        "BEGIN; INSERT INTO reviews (id, org_id, source_run_id, run_id, "
        f"pinned_input_sha256, status) VALUES ('{EMPTY_REVIEW}', '{ORG_A}', '{RUN}', "
        f"'{RUN}', '{'c' * 64}', 'running'); INSERT INTO review_artifact_versions "
        f"(org_id, review_id, artifact_version_id) VALUES ('{ORG_A}', "
        f"'{EMPTY_REVIEW}', '{VERSION}'); UPDATE reviews SET status = 'completed', "
        f"revision = 2, submission_id = '{EMPTY_SUBMISSION}', "
        f"submitted_at = CURRENT_TIMESTAMP WHERE id = '{EMPTY_REVIEW}'; COMMIT",
        check=False,
    )
    assert result.returncode != 0
    assert "completed review requires findings" in result.stderr
