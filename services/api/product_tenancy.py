"""Tenant-scoped product reads backed by fixture records or forced PostgreSQL RLS."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Protocol, cast

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool


@dataclass(frozen=True, slots=True)
class TenantPrincipal:
    """Authenticated identity used to establish the database RLS principal."""

    user_id: str
    organization_id: str


@dataclass(frozen=True, slots=True)
class ProjectView:
    """Product-safe representation of a project."""

    id: str
    name: str
    archived: bool


@dataclass(frozen=True, slots=True)
class SessionView:
    """Product-safe representation of a research session."""

    id: str
    project_id: str
    name: str


@dataclass(frozen=True, slots=True)
class WorkspaceView:
    """Product-safe summary for the authenticated workspace."""

    projects: tuple[ProjectView, ...]


class TenantRepository(Protocol):
    """Synchronous tenant-scoped product reads."""

    def workspace(self, principal: TenantPrincipal) -> WorkspaceView:
        """Return the workspace visible to the principal."""
        ...

    def project(
        self, principal: TenantPrincipal, project_id: str
    ) -> ProjectView | None:
        """Return a visible project, or ``None`` when it is unavailable."""
        ...

    def session(
        self, principal: TenantPrincipal, session_id: str
    ) -> SessionView | None:
        """Return a visible session, or ``None`` when it is unavailable."""
        ...


@dataclass(frozen=True, slots=True)
class InMemoryTenantRepository:
    """Fixture-only repository populated with explicit browser-fixture records."""

    projects: tuple[tuple[str, ProjectView], ...]
    sessions: tuple[tuple[str, SessionView], ...]

    def workspace(self, principal: TenantPrincipal) -> WorkspaceView:
        """Return only fixture projects belonging to the server-derived principal."""
        return WorkspaceView(
            tuple(
                view
                for org_id, view in self.projects
                if org_id == principal.organization_id
            )
        )

    def project(
        self, principal: TenantPrincipal, project_id: str
    ) -> ProjectView | None:
        """Return a fixture project only when its supplied tenant matches."""
        return next(
            (
                view
                for org_id, view in self.projects
                if org_id == principal.organization_id and view.id == project_id
            ),
            None,
        )

    def session(
        self, principal: TenantPrincipal, session_id: str
    ) -> SessionView | None:
        """Return a fixture session only when its supplied tenant matches."""
        return next(
            (
                view
                for org_id, view in self.sessions
                if org_id == principal.organization_id and view.id == session_id
            ),
            None,
        )


def _project_view(row: dict[str, object]) -> ProjectView:
    return ProjectView(
        cast("str", row["id"]),
        cast("str", row["name"]),
        cast("bool", row["archived"]),
    )


def _session_view(row: dict[str, object]) -> SessionView:
    return SessionView(
        cast("str", row["id"]),
        cast("str", row["project_id"]),
        cast("str", row["name"]),
    )


@dataclass(frozen=True, slots=True)
class PostgresTenantRepository:
    """Read product resources through a transaction-scoped forced-RLS principal."""

    database_url: str

    def workspace(self, principal: TenantPrincipal) -> WorkspaceView:
        """Load visible projects under the authenticated principal's RLS scope."""
        rows = self._query(
            principal,
            "SELECT id::text AS id, name, archived_at IS NOT NULL AS archived "
            "FROM projects ORDER BY id",
            {},
        )
        return WorkspaceView(
            tuple(_project_view(row) for row in rows)
        )

    def project(
        self, principal: TenantPrincipal, project_id: str
    ) -> ProjectView | None:
        """Load one visible project; hidden and absent IDs both produce ``None``."""
        rows = self._query(
            principal,
            "SELECT id::text AS id, name, archived_at IS NOT NULL AS archived "
            "FROM projects WHERE id = CAST(:project_id AS uuid)",
            {"project_id": project_id},
        )
        return _project_view(rows[0]) if rows else None

    def session(
        self, principal: TenantPrincipal, session_id: str
    ) -> SessionView | None:
        """Load one visible session; hidden and absent IDs both produce ``None``."""
        rows = self._query(
            principal,
            "SELECT id::text AS id, project_id::text AS project_id, title AS name "
            "FROM sessions WHERE id = CAST(:session_id AS uuid)",
            {"session_id": session_id},
        )
        return _session_view(rows[0]) if rows else None

    def _query(
        self, principal: TenantPrincipal, query: str, parameters: dict[str, str]
    ) -> list[dict[str, object]]:
        return asyncio.run(self._query_async(principal, query, parameters))

    async def _query_async(
        self, principal: TenantPrincipal, query: str, parameters: dict[str, str]
    ) -> list[dict[str, object]]:
        engine = create_async_engine(self.database_url, poolclass=NullPool)
        try:
            async with engine.connect() as connection, connection.begin():
                _ = await connection.execute(
                    text("SET LOCAL ROLE science_workbench_app")
                )
                _ = await connection.execute(
                    text("SELECT set_config('app.org_id', :organization_id, true)"),
                    {"organization_id": principal.organization_id},
                )
                _ = await connection.execute(
                    text("SELECT set_config('app.user_id', :user_id, true)"),
                    {"user_id": principal.user_id},
                )
                result = await connection.execute(text(query), parameters)
                return [dict(row) for row in result.mappings()]
        finally:
            await engine.dispose()
