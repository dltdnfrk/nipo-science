from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest
from pydantic import ValidationError
from services.api.connector_registry import ConnectorRegistration

if TYPE_CHECKING:
    from collections.abc import Mapping

PUBMED_URL: Final = "https://pubmed.ncbi.nlm.nih.gov"
OPENALEX_URL: Final = "https://api.openalex.org"


@pytest.mark.parametrize(
    ("connector_id", "base_url"),
    [("pubmed", PUBMED_URL), ("openalex", OPENALEX_URL)],
)
def test_canonical_connector_registrations_are_disabled_by_default(
    connector_id: str,
    base_url: str,
) -> None:
    registration = ConnectorRegistration.model_validate(
        {"connector_id": connector_id, "base_url": base_url}
    )

    assert registration.model_dump(mode="json") == {
        "connector_id": connector_id,
        "base_url": base_url,
        "enabled": False,
    }


@pytest.mark.parametrize(
    "payload",
    [
        {
            "connector_id": "attacker-controlled",
            "base_url": "https://api.openalex.org",
        },
        {"connector_id": "pubmed", "base_url": "http://169.254.169.254"},
        {
            "connector_id": "pubmed",
            "base_url": "https://pubmed.ncbi.nlm.nih.gov.attacker.example",
        },
        {"connector_id": "pubmed", "base_url": OPENALEX_URL},
        {"connector_id": "openalex", "base_url": PUBMED_URL},
        {
            "connector_id": "openalex",
            "base_url": OPENALEX_URL,
            "redirect_url": "http://127.0.0.1",
        },
    ],
)
def test_noncanonical_connector_registrations_are_rejected(
    payload: Mapping[str, str],
) -> None:
    with pytest.raises(ValidationError):
        _ = ConnectorRegistration.model_validate(payload)


def test_canonical_connector_can_be_explicitly_enabled() -> None:
    registration = ConnectorRegistration.model_validate(
        {"connector_id": "openalex", "base_url": OPENALEX_URL, "enabled": True}
    )

    assert registration.enabled is True
