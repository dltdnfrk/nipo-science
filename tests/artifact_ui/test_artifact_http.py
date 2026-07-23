import hashlib
import json
from dataclasses import dataclass
from http.client import HTTPConnection
from socket import AF_INET, AF_INET6
from typing import cast
from urllib.parse import urlsplit

from services.api.artifact_ui_app import (
    ArtifactUiPrincipal,
    ArtifactUiServer,
    run_artifact_ui_server,
)

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]
_UNSUPPORTED_ADDRESS = "unsupported address family"


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: bytes
    headers: tuple[tuple[str, str], ...]

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        return next(
            (value for key, value in self.headers if key.lower() == lowered),
            None,
        )


def _server_host_port(server: ArtifactUiServer) -> tuple[str, int]:
    address = server.server_address
    if server.address_family == AF_INET:
        return cast("tuple[str, int]", address)
    if server.address_family == AF_INET6:
        host, port, _, _ = cast("tuple[str, int, int, int]", address)
        return host, port
    raise ValueError(_UNSUPPORTED_ADDRESS)


def _request(
    address: tuple[str, int],
    method: str,
    path: str,
    *,
    body: JsonObject | None = None,
    headers: dict[str, str] | None = None,
) -> Response:
    connection = HTTPConnection(*address)
    try:
        encoded = json.dumps(body).encode() if body is not None else None
        request_headers = headers or {}
        if encoded is not None:
            request_headers = {**request_headers, "Content-Type": "application/json"}
        connection.request(method, path, encoded, request_headers)
        response = connection.getresponse()
        return Response(response.status, response.read(), tuple(response.getheaders()))
    finally:
        connection.close()


def test_authenticated_artifact_detail_attach_download_and_preview_headers() -> None:
    server = run_artifact_ui_server()
    host, port = _server_host_port(server)
    address = (host, port)
    cookie = server.fixture_cookie()
    origin_headers = {
        "Cookie": cookie,
        "Origin": f"http://{host}:{port}",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "X-CSRF-Token": server.fixture_csrf_token(),
    }
    try:
        blocked_page = _request(address, "GET", "/artifacts/artifact-spectrum")
        blocked_api = _request(address, "GET", "/api/v1/artifacts")
        assert blocked_page.status == 401
        assert blocked_api.status == 401

        favicon = _request(
            address,
            "GET",
            "/product/favicon.svg",
            headers={"Cookie": cookie},
        )
        assert favicon.status == 200
        assert favicon.header("Content-Type") == "image/svg+xml"

        listing = _request(
            address, "GET", "/api/v1/artifacts", headers={"Cookie": cookie}
        )
        assert listing.status == 200
        assert len(cast("list[JsonObject]", json.loads(listing.body)["artifacts"])) == 3

        detail_response = _request(
            address,
            "GET",
            "/api/v1/artifacts/artifact-spectrum",
            headers={"Cookie": cookie},
        )
        detail = cast("JsonObject", json.loads(detail_response.body))
        selected = cast("JsonObject", detail["selected"])
        assert detail_response.status == 200
        assert selected["version_no"] == 2
        assert selected["status"] == "immutable"
        assert cast("str", selected["created_at"]).endswith("Z")
        assert cast("str", detail["preview_url"]).startswith("http://localhost:")

        attached = _request(
            address,
            "POST",
            f"/api/v1/artifacts/artifact-spectrum/versions/{selected['id']}/attachments",
            body={"session_id": "session-demo"},
            headers=origin_headers,
        )
        assert cast("JsonObject", json.loads(attached.body))[
            "attached_session_ids"
        ] == ["session-demo"]
        detached = _request(
            address,
            "DELETE",
            f"/api/v1/artifacts/artifact-spectrum/versions/{selected['id']}/attachments",
            body={"session_id": "session-demo"},
            headers=origin_headers,
        )
        assert (
            cast("JsonObject", json.loads(detached.body))["attached_session_ids"] == []
        )

        download = _request(
            address,
            "GET",
            f"/api/v1/artifacts/artifact-spectrum/versions/{selected['id']}/download",
            headers={"Cookie": cookie},
        )
        assert download.status == 200
        assert hashlib.sha256(download.body).hexdigest() == selected["sha256"]
        assert download.header("X-Content-SHA256") == selected["sha256"]

        preview_url = urlsplit(cast("str", detail["preview_url"]))
        assert preview_url.hostname == "localhost"
        assert preview_url.hostname != host
        preview = _request(
            (cast("str", preview_url.hostname), cast("int", preview_url.port)),
            "GET",
            preview_url.path,
        )
        assert preview.status == 200
        assert preview.header("Content-Type") == "text/plain; charset=utf-8"
        assert preview.header("Content-Security-Policy") == "default-src 'none'"
        assert preview.header("X-Content-Type-Options") == "nosniff"
        assert preview.header("Set-Cookie") is None
        assert hashlib.sha256(preview.body).hexdigest() == selected["sha256"]

        hidden = _request(
            address,
            "GET",
            "/api/v1/artifacts/artifact-foreign",
            headers={"Cookie": cookie},
        )
        assert hidden.status == 404
    finally:
        server.shutdown()
        server.server_close()


def test_library_routes_explicit_version_and_version_level_attachment() -> None:
    server = run_artifact_ui_server()
    host, port = _server_host_port(server)
    address = (host, port)
    cookie = server.fixture_cookie()
    same_origin = {
        "Cookie": cookie,
        "Origin": f"http://{host}:{port}",
        "Sec-Fetch-Site": "same-origin",
        "X-CSRF-Token": server.fixture_csrf_token(),
    }
    try:
        for path in (
            "/artifacts",
            "/artifacts/artifact-spectrum",
            "/artifacts/artifact-image",
            "/artifacts/artifact-report",
        ):
            assert (
                _request(address, "GET", path, headers={"Cookie": cookie}).status == 200
            )

        selected_v1 = _request(
            address,
            "GET",
            "/api/v1/artifacts/artifact-spectrum/versions/artifact-spectrum-v1",
            headers={"Cookie": cookie},
        )
        detail = cast("JsonObject", json.loads(selected_v1.body))
        selected = cast("JsonObject", detail["selected"])
        assert selected_v1.status == 200
        assert selected["id"] == "artifact-spectrum-v1"
        assert detail["previous_version_id"] is None

        attached = _request(
            address,
            "POST",
            "/api/v1/artifacts/artifact-spectrum/versions/artifact-spectrum-v1/attachments",
            body={"session_id": "session-demo"},
            headers=same_origin,
        )
        assert attached.status == 200
        refreshed = _request(
            address,
            "GET",
            "/api/v1/artifacts/artifact-spectrum/versions/artifact-spectrum-v1",
            headers={"Cookie": cookie},
        )
        assert cast("JsonObject", json.loads(refreshed.body))[
            "attached_session_ids"
        ] == ["session-demo"]
    finally:
        server.shutdown()
        server.server_close()


def test_authenticated_principal_controls_artifact_tenant_and_session_ids() -> None:
    primary = ArtifactUiPrincipal(
        user_id="user-primary",
        organization_id="org-mineral",
        organization_name="Nipo Labs",
        projects=(("project-owned", "보정 프로젝트"),),
        session_ids=frozenset({"session-owned"}),
    )
    foreign = ArtifactUiPrincipal(
        user_id="user-foreign",
        organization_id="org-foreign",
        organization_name="외부 연구실",
        projects=(("project-foreign", "외부 프로젝트"),),
        session_ids=frozenset({"session-foreign"}),
    )
    server = run_artifact_ui_server(principal=primary)
    host, port = _server_host_port(server)
    address = (host, port)
    cookie = server.fixture_cookie()
    csrf_token = server.fixture_csrf_token()
    foreign_cookie, foreign_csrf = server.issue_fixture_session(foreign)
    origin = f"http://{host}:{port}"
    try:
        identity = _request(address, "GET", "/api/v1/me", headers={"Cookie": cookie})
        identity_body = cast("JsonObject", json.loads(identity.body))
        assert identity_body["csrf_token"] == csrf_token

        missing_csrf = _request(
            address,
            "POST",
            "/api/v1/artifacts/artifact-spectrum/versions/artifact-spectrum-v1/attachments",
            body={"session_id": "session-owned"},
            headers={
                "Cookie": cookie,
                "Origin": origin,
                "Sec-Fetch-Site": "same-origin",
            },
        )
        wrong_session = _request(
            address,
            "POST",
            "/api/v1/artifacts/artifact-spectrum/versions/artifact-spectrum-v1/attachments",
            body={"session_id": "session-demo"},
            headers={
                "Cookie": cookie,
                "Origin": origin,
                "Sec-Fetch-Site": "same-origin",
                "X-CSRF-Token": csrf_token,
            },
        )
        attached = _request(
            address,
            "POST",
            "/api/v1/artifacts/artifact-spectrum/versions/artifact-spectrum-v1/attachments",
            body={"session_id": "session-owned"},
            headers={
                "Cookie": cookie,
                "Origin": origin,
                "Sec-Fetch-Site": "same-origin",
                "X-CSRF-Token": csrf_token,
            },
        )
        assert missing_csrf.status == 403
        assert wrong_session.status == 404
        assert attached.status == 200

        hidden_primary = _request(
            address,
            "GET",
            "/api/v1/artifacts/artifact-spectrum",
            headers={"Cookie": foreign_cookie},
        )
        visible_foreign = _request(
            address,
            "GET",
            "/api/v1/artifacts/artifact-foreign",
            headers={"Cookie": foreign_cookie},
        )
        foreign_attachment = _request(
            address,
            "POST",
            "/api/v1/artifacts/artifact-foreign/versions/artifact-foreign-v1/attachments",
            body={"session_id": "session-foreign"},
            headers={
                "Cookie": foreign_cookie,
                "Origin": origin,
                "Sec-Fetch-Site": "same-origin",
                "X-CSRF-Token": foreign_csrf,
            },
        )
        assert hidden_primary.status == 404
        assert visible_foreign.status == 200
        assert foreign_attachment.status == 200
    finally:
        server.shutdown()
        server.server_close()


def test_artifact_fixture_rejects_the_removed_dry_lab_state_route() -> None:
    # Given: the authenticated Artifact-only browser fixture.
    server = run_artifact_ui_server()
    host, port = _server_host_port(server)

    try:
        # When: a stale client requests the removed dry-lab state route.
        response = _request(
            (host, port),
            "GET",
            "/api/v1/dry-lab/state",
            headers={"Cookie": server.fixture_cookie()},
        )

        # Then: the Artifact fixture exposes the same explicit 404 contract.
        assert response.status == 404
        assert json.loads(response.body) == {"error": "not_found"}
    finally:
        server.shutdown()
        server.server_close()
