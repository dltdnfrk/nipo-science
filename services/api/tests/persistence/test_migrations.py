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


class SchemaManifest(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="ignore")

    revision: str
    catalog_sha256: str
    global_tables: tuple[str, ...]
    tenant_tables: tuple[str, ...]


class CatalogSnapshot(RootModel[dict[str, tuple[str, ...]]]):
    pass


@pytest.mark.usefixtures("postgres_database")
def test_revision_round_trips_when_database_is_empty() -> None:
    _ = alembic(("upgrade", "head"))
    first_revision = psql("SELECT version_num FROM alembic_version").stdout.strip()
    _ = alembic(("downgrade", "base"))
    remaining = psql(
        "SELECT count(*) FROM information_schema.tables "
        "WHERE table_schema = 'public' AND table_name <> 'alembic_version'"
    ).stdout.strip()
    retained_roles = psql(
        "SELECT count(*) FROM pg_roles WHERE rolname IN "
        "('science_workbench_app', 'science_workbench_compliance')"
    ).stdout.strip()
    _ = psql("ALTER ROLE science_workbench_app LOGIN BYPASSRLS")
    _ = alembic(("upgrade", "head"))
    second_revision = psql("SELECT version_num FROM alembic_version").stdout.strip()
    hardened = psql(
        "SELECT rolcanlogin::text || ':' || rolbypassrls::text FROM pg_roles "
        "WHERE rolname = 'science_workbench_app'"
    ).stdout.strip()
    assert (first_revision, remaining, retained_roles, second_revision, hardened) == (
        "0001_tenant_spine",
        "0",
        "2",
        "0001_tenant_spine",
        "false:false",
    )


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
    assert hashlib.sha256(canonical.encode()).hexdigest() == manifest.catalog_sha256


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
