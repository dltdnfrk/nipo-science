"""Deterministic G003 identities and tenant-owned fixture identifiers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class OrganizationFixture:
    """A typed organization identity used in tenancy assertions."""

    id: str
    name: str


PRIMARY_ORGANIZATION = OrganizationFixture("org-mineral", "Nipo Labs")
FOREIGN_ORGANIZATION = OrganizationFixture("org-foreign", "Foreign organization")

@dataclass(slots=True)
class MutableClock:
    """Injected UTC clock used by loopback product-server tests."""

    now: datetime

    def __call__(self) -> datetime:
        """Return the current injected time."""
        return self.now


FIXTURE_NOW = datetime(2026, 7, 13, tzinfo=UTC)
PRIMARY_ORGANIZATION_ID = "org-mineral"
FOREIGN_ORGANIZATION_ID = "org-foreign"
PRIMARY_PROJECT_ID = "018f0d7d-6b17-7a91-8b31-2f7331677b01"
ARCHIVED_PROJECT_ID = "018f0d7d-6b17-7a91-8b31-2f7331677b02"
FOREIGN_PROJECT_ID = "018f0d7d-6b17-7a91-8b31-2f7331677b03"
PRIMARY_SESSION_ID = "018f0d7d-6b17-7a91-8b31-2f7331677c01"
ARCHIVED_SESSION_ID = "018f0d7d-6b17-7a91-8b31-2f7331677c02"
FOREIGN_SESSION_ID = "018f0d7d-6b17-7a91-8b31-2f7331677c03"
