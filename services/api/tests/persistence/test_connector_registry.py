from __future__ import annotations

from typing import Final, NamedTuple

import pytest

from services.api.connector_registry import ConnectorBaseUrl
from services.api.tests.persistence.postgres_harness import psql

ORG_ID: Final = "018f0d7d-6b17-7a91-8b31-2f7331678d01"
PROJECT_ID: Final = "018f0d7d-6b17-7a91-8b31-2f7331678d02"
PUBMED_CONNECTOR_ID: Final = "018f0d7d-6b17-7a91-8b31-2f7331678d03"
OPENALEX_CONNECTOR_ID: Final = "018f0d7d-6b17-7a91-8b31-2f7331678d04"
PUBMED_URL: Final = ConnectorBaseUrl.PUBMED.value
OPENALEX_URL: Final = ConnectorBaseUrl.OPENALEX.value


class NoncanonicalConnectorCase(NamedTuple):
    row_id: str
    project_id: str
    connector_id: str
    base_url: str


def _seed_project(project_id: str) -> None:
    _ = psql(
        f"INSERT INTO organizations (id, name) VALUES ('{ORG_ID}', 'Connectors') "
        "ON CONFLICT DO NOTHING; "
        "INSERT INTO projects (id, org_id, name) VALUES "
        f"('{project_id}', '{ORG_ID}', 'Connector Registry') ON CONFLICT DO NOTHING"
    )


@pytest.mark.usefixtures("migrated_database")
def test_database_accepts_only_canonical_connectors_disabled_by_default() -> None:
    _seed_project(PROJECT_ID)
    rows = psql(
        "INSERT INTO connectors "
        "(id, org_id, project_id, connector_id, base_url) VALUES "
        f"('{PUBMED_CONNECTOR_ID}', '{ORG_ID}', '{PROJECT_ID}', "
        f"'pubmed', '{PUBMED_URL}'), "
        f"('{OPENALEX_CONNECTOR_ID}', '{ORG_ID}', '{PROJECT_ID}', "
        f"'openalex', '{OPENALEX_URL}') "
        "RETURNING connector_id || '|' || base_url || '|' || enabled::text"
    ).stdout.splitlines()

    assert sorted(rows) == [
        f"openalex|{OPENALEX_URL}|false",
        f"pubmed|{PUBMED_URL}|false",
    ]
    enabled = psql(
        "UPDATE connectors SET enabled = true "
        f"WHERE id = '{OPENALEX_CONNECTOR_ID}' RETURNING enabled::text"
    ).stdout.strip()
    assert enabled == "true"


@pytest.mark.usefixtures("migrated_database")
@pytest.mark.parametrize(
    "case",
    [
        NoncanonicalConnectorCase(
            "018f0d7d-6b17-7a91-8b31-2f7331678d11",
            "018f0d7d-6b17-7a91-8b31-2f7331678d21",
            "attacker-controlled",
            OPENALEX_URL,
        ),
        NoncanonicalConnectorCase(
            "018f0d7d-6b17-7a91-8b31-2f7331678d12",
            "018f0d7d-6b17-7a91-8b31-2f7331678d22",
            "pubmed",
            "http://169.254.169.254",
        ),
        NoncanonicalConnectorCase(
            "018f0d7d-6b17-7a91-8b31-2f7331678d13",
            "018f0d7d-6b17-7a91-8b31-2f7331678d23",
            "pubmed",
            "https://pubmed.ncbi.nlm.nih.gov.attacker.example",
        ),
        NoncanonicalConnectorCase(
            "018f0d7d-6b17-7a91-8b31-2f7331678d14",
            "018f0d7d-6b17-7a91-8b31-2f7331678d24",
            "openalex",
            PUBMED_URL,
        ),
    ],
)
def test_database_rejects_noncanonical_connector_pairs(
    case: NoncanonicalConnectorCase,
) -> None:
    _seed_project(case.project_id)
    result = psql(
        "INSERT INTO connectors "
        "(id, org_id, project_id, connector_id, base_url) VALUES "
        f"('{case.row_id}', '{ORG_ID}', '{case.project_id}', "
        f"'{case.connector_id}', '{case.base_url}')",
        check=False,
    )

    assert result.returncode != 0
    assert "canonical_connector_registry" in result.stderr
