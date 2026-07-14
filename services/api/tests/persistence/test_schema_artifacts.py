from pathlib import Path
from typing import ClassVar, Final

from pydantic import BaseModel, ConfigDict

ROOT: Final = Path(__file__).parents[4]
REQUIRED_DATABASE_ARTIFACTS: Final = (
    ROOT / "services/api/alembic.ini",
    ROOT / "services/api/migrations/env.py",
    ROOT / "services/api/migrations/versions/0001_tenant_spine.py",
    ROOT / "services/api/persistence/schema_manifest.json",
)
REQUIRED_TENANT_TABLES: Final = frozenset(
    {
        "action_plans",
        "approval_requests",
        "artifact_dependencies",
        "artifact_versions",
        "artifacts",
        "audit_logs",
        "audit_outbox",
        "auth_sessions",
        "connector_calls",
        "connectors",
        "consents",
        "credentials",
        "deletion_receipts",
        "deletion_requests",
        "deletion_tombstones",
        "execution_leases",
        "executions",
        "export_artifact_versions",
        "export_jobs",
        "idempotency_records",
        "legal_holds",
        "memberships",
        "messages",
        "projects",
        "provider_connections",
        "review_artifact_versions",
        "review_execution_refs",
        "review_findings",
        "review_finding_artifact_versions",
        "review_finding_execution_refs",
        "reviews",
        "run_events",
        "run_skill_snapshots",
        "runs",
        "session_artifact_versions",
        "sessions",
        "skills",
        "tool_grants",
        "uploaded_files",
    }
)


class ManifestContract(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    schema_version: int
    postgresql: str
    revision: str
    table_count: int
    column_count: int
    catalog_sha256: str
    global_tables: tuple[str, ...]
    tenant_tables: tuple[str, ...]
    append_only_tables: tuple[str, ...]
    forbidden_schema_tokens: tuple[str, ...]


def test_task_8_artifacts_exist_when_database_contract_is_inspected() -> None:
    missing = tuple(
        path.relative_to(ROOT)
        for path in REQUIRED_DATABASE_ARTIFACTS
        if not path.is_file()
    )
    assert missing == ()


def test_all_p0_tables_are_declared_when_manifest_is_parsed() -> None:
    manifest = ManifestContract.model_validate_json(
        (ROOT / "services/api/persistence/schema_manifest.json").read_text()
    )
    assert manifest.postgresql == "18.4"
    assert manifest.table_count == 41
    assert manifest.column_count == 300
    assert frozenset(manifest.global_tables) == {"organizations", "users"}
    assert frozenset(manifest.tenant_tables) == REQUIRED_TENANT_TABLES
    assert frozenset(manifest.append_only_tables) == {
        "artifact_dependencies",
        "audit_logs",
        "audit_outbox",
        "legal_holds",
    }


def test_migration_builds_schema_and_rls_when_revision_runs() -> None:
    migration = (
        ROOT / "services/api/migrations/versions/0001_tenant_spine.py"
    ).read_text()
    assert "upgrade_schema()" in migration
    assert "apply_rls()" in migration
    assert "drop_schema()" in migration


def test_every_tenant_table_is_rls_scoped_when_policy_source_is_inspected() -> None:
    policy = (ROOT / "services/api/migrations/policies.py").read_text()
    missing = tuple(
        table for table in REQUIRED_TENANT_TABLES if f'"{table}"' not in policy
    )
    assert missing == ()


def test_monetary_terms_are_absent_when_schema_sources_are_inspected() -> None:
    migration_root = ROOT / "services/api/migrations"
    schema_text = "\n".join(
        path.read_text() for path in sorted(migration_root.glob("schema*.py"))
    ).lower()
    present = tuple(
        token for token in ("budget", "cost", "price", "spend") if token in schema_text
    )
    assert present == ()
