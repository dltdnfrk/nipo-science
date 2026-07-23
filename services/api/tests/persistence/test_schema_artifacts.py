import re
from configparser import ConfigParser
from pathlib import Path
from typing import ClassVar, Final

import pytest
from pydantic import BaseModel, ConfigDict

import services.api.migrations.policies as migration_policies
from services.api.persistence.schema_inventory import (
    APPEND_ONLY_TABLES,
    GLOBAL_TABLES,
    TABLE_BY_NAME,
    TABLE_POLICIES,
    TENANT_TABLES,
    UUID7_ID_TABLES,
)

ROOT: Final = Path(__file__).parents[4]
REQUIRED_DATABASE_ARTIFACTS: Final = (
    ROOT / "services/api/alembic.ini",
    ROOT / "services/api/migrations/env.py",
    ROOT / "services/api/migrations/versions/0001_tenant_spine.py",
    ROOT / "services/api/migrations/versions/0002_head_schema_upgrade.py",
    ROOT / "services/api/migrations/versions/0003_provider_qualification_receipts.py",
    ROOT / "services/api/migrations/versions/0004_provider_security.py",
    ROOT / "services/api/persistence/schema_manifest.json",
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


def test_migration_configuration_requires_explicit_database_url() -> None:
    configuration = ConfigParser()
    loaded = configuration.read(ROOT / "services/api/alembic.ini")
    environment_source = (ROOT / "services/api/migrations/env.py").read_text()

    assert loaded
    assert configuration.get("alembic", "sqlalchemy.url") == ""
    assert 'os.environ.get("DATABASE_URL", "").strip()' in environment_source
    assert "context.config.get_main_option" not in environment_source


def test_all_p0_tables_are_declared_when_manifest_is_parsed() -> None:
    manifest = ManifestContract.model_validate_json(
        (ROOT / "services/api/persistence/schema_manifest.json").read_text()
    )
    assert manifest.postgresql == "18.4"
    assert manifest.table_count == len(TABLE_POLICIES)
    assert manifest.column_count >= manifest.table_count
    assert manifest.global_tables == GLOBAL_TABLES
    assert manifest.tenant_tables == TENANT_TABLES
    assert manifest.append_only_tables == APPEND_ONLY_TABLES


def test_migration_builds_schema_and_rls_when_revision_runs() -> None:
    migration = (
        ROOT / "services/api/migrations/versions/0001_tenant_spine.py"
    ).read_text()
    assert "upgrade_schema()" in migration
    assert "apply_rls()" in migration
    assert "drop_schema()" in migration


def test_migration_renders_every_authoritative_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    statements: list[str] = []
    monkeypatch.setattr(
        "services.api.migrations.policies.op.execute", statements.append
    )
    migration_policies.apply_rls(include_provider_qualification=True)

    enabled = tuple(
        match.group(1)
        for statement in statements
        if (
            match := re.fullmatch(
                r"ALTER TABLE (\w+) ENABLE ROW LEVEL SECURITY", statement
            )
        )
    )
    uuid7 = tuple(
        match.group(1)
        for statement in statements
        if (match := re.match(r"CREATE TRIGGER (\w+)_uuid7 ", statement))
    )
    immutable = tuple(
        match.group(1)
        for statement in statements
        if (match := re.match(r"CREATE TRIGGER (\w+)_immutable ", statement))
    )
    assert enabled == TENANT_TABLES
    assert uuid7 == UUID7_ID_TABLES
    assert immutable == APPEND_ONLY_TABLES


def test_one_typed_schema_inventory_is_the_authority() -> None:
    """Require a typed inventory instead of three hand-copied table lists."""
    names = tuple(policy.name for policy in TABLE_POLICIES)
    assert tuple(TABLE_BY_NAME) == names
    assert len(names) == len(set(names))
    assert frozenset((*GLOBAL_TABLES, *TENANT_TABLES)) == frozenset(names)


def test_monetary_terms_are_absent_when_schema_sources_are_inspected() -> None:
    migration_root = ROOT / "services/api/migrations"
    schema_text = "\n".join(
        path.read_text() for path in sorted(migration_root.glob("schema*.py"))
    ).lower()
    present = tuple(
        token for token in ("budget", "cost", "price", "spend") if token in schema_text
    )
    assert present == ()
