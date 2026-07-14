"""Deterministic G003 identities and tenant-owned fixture identifiers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class OrganizationFixture:
    """A typed organization identity used in tenancy assertions."""

    id: str
    name: str


PRIMARY_ORGANIZATION = OrganizationFixture("org-mineral", "한국 광물 연구실")
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
PRIMARY_PROJECT_ID = "project-demo"
ARCHIVED_PROJECT_ID = "project-archived"
FOREIGN_PROJECT_ID = "project-foreign"
PRIMARY_SESSION_ID = "session-demo"
ARCHIVED_SESSION_ID = "session-archived"
FOREIGN_SESSION_ID = "session-foreign"
