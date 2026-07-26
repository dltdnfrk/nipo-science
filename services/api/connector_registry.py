"""Fail-closed registry for application-owned literature connectors."""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import ClassVar, Final, Self

from pydantic import BaseModel, ConfigDict, StrictBool, model_validator
from pydantic_core import PydanticCustomError

_PAIR_ERROR_CODE: Final = "canonical_connector_pair"
_PAIR_ERROR_MESSAGE: Final = "base_url must match the fixed host for connector_id"


class ConnectorId(StrEnum):
    """Connector identifiers supported by the MVP service."""

    PUBMED = "pubmed"
    OPENALEX = "openalex"
    ARXIV = "arxiv"
    SEMANTIC_SCHOLAR = "semantic_scholar"
    EUROPE_PMC = "europe_pmc"
    CORE = "core"
    CROSSREF = "crossref"


class ConnectorBaseUrl(StrEnum):
    """Exact outbound origins paired with supported connectors."""

    PUBMED = "https://pubmed.ncbi.nlm.nih.gov"
    OPENALEX = "https://api.openalex.org"
    ARXIV = "https://export.arxiv.org"
    SEMANTIC_SCHOLAR = "https://api.semanticscholar.org"
    EUROPE_PMC = "https://www.ebi.ac.uk"
    CORE = "https://api.core.ac.uk"
    CROSSREF = "https://api.crossref.org"


CANONICAL_CONNECTOR_REGISTRY: Final = MappingProxyType(
    {
        ConnectorId.PUBMED: ConnectorBaseUrl.PUBMED,
        ConnectorId.OPENALEX: ConnectorBaseUrl.OPENALEX,
        ConnectorId.ARXIV: ConnectorBaseUrl.ARXIV,
        ConnectorId.SEMANTIC_SCHOLAR: ConnectorBaseUrl.SEMANTIC_SCHOLAR,
        ConnectorId.EUROPE_PMC: ConnectorBaseUrl.EUROPE_PMC,
        ConnectorId.CORE: ConnectorBaseUrl.CORE,
        ConnectorId.CROSSREF: ConnectorBaseUrl.CROSSREF,
    }
)


class ConnectorRegistration(BaseModel):
    """Parse a connector registration into a canonical fixed-host pair."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    connector_id: ConnectorId
    base_url: ConnectorBaseUrl
    enabled: StrictBool = False

    @model_validator(mode="after")
    def require_canonical_pair(self) -> Self:
        """Reject valid IDs and URLs when they are paired incorrectly."""
        expected_url = CANONICAL_CONNECTOR_REGISTRY[self.connector_id]
        if self.base_url != expected_url:
            raise PydanticCustomError(
                _PAIR_ERROR_CODE,
                _PAIR_ERROR_MESSAGE,
            )
        return self
