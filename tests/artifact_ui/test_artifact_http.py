import hashlib
import json
from dataclasses import dataclass
from http.client import HTTPConnection
from socket import AF_INET, AF_INET6
from typing import cast
from urllib.parse import urlsplit

from services.api.artifact_ui_app import ArtifactUiServer, run_artifact_ui_server

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
    }
    try:
        blocked_page = _request(address, "GET", "/artifacts/artifact-spectrum")
        blocked_api = _request(address, "GET", "/api/v1/artifacts")
        assert blocked_page.status == 401
        assert blocked_api.status == 401

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


def test_artifact_fixture_exposes_an_empty_dry_lab_state() -> None:
    # Given: the authenticated Artifact-only browser fixture.
    server = run_artifact_ui_server()
    host, port = _server_host_port(server)

    try:
        # When: the shared product shell requests its optional dry-lab state.
        response = _request(
            (host, port),
            "GET",
            "/api/v1/dry-lab/state",
            headers={"Cookie": server.fixture_cookie()},
        )

        # Then: the fixture supplies a valid empty state without a console 404.
        assert response.status == 200
        assert json.loads(response.body) == {}
    finally:
        server.shutdown()
        server.server_close()
