"""HTTP product reads exercised through PostgreSQL forced row-level security."""

from __future__ import annotations

from dataclasses import dataclass
from http.client import HTTPConnection

from services.api.product_app import (
    Principal,
    ProductServer,
    ProductServerOptions,
    run_product_server,
)
from services.api.product_tenancy import PostgresTenantRepository
from services.api.tests.persistence.postgres_harness import database_url_asyncpg
from services.api.tests.persistence.test_rls import (
    ORG_A,
    PROJECT_A,
    PROJECT_B,
    USER_A,
    seed_tenants,
)

pytest_plugins = ("services.api.tests.persistence.conftest",)


@dataclass(frozen=True, slots=True)
class _Response:
    """Fully buffered loopback HTTP response."""

    status: int
    body: bytes

    def read(self) -> bytes:
        """Return the buffered response body."""
        return self.body


def _request(
    server: ProductServer, method: str, path: str, *, headers: dict[str, str]
) -> _Response:
    connection = HTTPConnection(server.server_name, server.server_port)
    try:
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        return _Response(response.status, response.read())
    finally:
        connection.close()



def test_product_http_reads_use_forced_postgres_rls(migrated_database: None) -> None:
    """A fixture session reaches RLS rather than the product fixture records."""
    _ = migrated_database
    seed_tenants()
    server = run_product_server(
        authenticated_fixture=True,
        options=ProductServerOptions(
            repository=PostgresTenantRepository(database_url_asyncpg()),
            principal=Principal(USER_A, ORG_A, "a@example.test", "A"),
        ),
    )
    cookie = server.fixture_session_cookie()
    missing_id = "018f0d7d-6b17-7a91-8b31-2f7331677a99"
    try:
        workspace = _request(
            server, "GET", "/api/v1/workspace", headers={"Cookie": cookie}
        )
        own = _request(
            server,
            "GET",
            f"/api/v1/projects/{PROJECT_A}",
            headers={"Cookie": cookie},
        )
        foreign = _request(
            server,
            "GET",
            f"/api/v1/projects/{PROJECT_B}",
            headers={"Cookie": cookie},
        )
        missing = _request(
            server,
            "GET",
            f"/api/v1/projects/{missing_id}",
            headers={"Cookie": cookie},
        )

        assert workspace.status == 200
        assert own.status == 200
        assert b"Project A" in own.read()
        assert b"Project B" not in workspace.read()
        assert b"Project B" not in own.read()
        assert (foreign.status, foreign.read()) == (missing.status, missing.read()) == (
            404,
            b'{"error":"not_found"}',
        )
    finally:
        server.shutdown()
        server.server_close()
