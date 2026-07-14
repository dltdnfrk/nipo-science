import json
from dataclasses import dataclass
from http.client import HTTPConnection
from socket import AF_INET, AF_INET6, create_connection, socket
from threading import Event
from time import monotonic
from typing import cast

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


def _connection_closed(connection: socket) -> bool:
    try:
        return connection.recv(1) == b""
    except ConnectionResetError:
        return True
    except TimeoutError:
        return False


def test_host_alias_body_bounds_and_cross_org_download_are_denied() -> None:
    server = run_artifact_ui_server()
    host, port = _server_host_port(server)
    address = (host, port)
    cookie = server.fixture_cookie()
    try:
        alias = _request(
            address,
            "GET",
            "/artifacts",
            headers={"Cookie": cookie, "Host": f"localhost:{port}"},
        )
        negative = _request(
            address,
            "POST",
            "/api/v1/artifacts/artifact-spectrum/versions",
            headers={
                "Cookie": cookie,
                "Host": f"{host}:{port}",
                "Origin": f"http://{host}:{port}",
                "Sec-Fetch-Site": "same-origin",
                "Content-Length": "-1",
            },
        )
        missing = _request(
            address,
            "GET",
            "/api/v1/artifacts/artifact-spectrum/versions/missing-v1/download",
            headers={"Cookie": cookie},
        )
        foreign = _request(
            address,
            "GET",
            "/api/v1/artifacts/artifact-foreign/versions/artifact-foreign-v1/download",
            headers={"Cookie": cookie},
        )

        assert alias.status in {401, 403}
        assert negative.status == 400
        assert (
            (foreign.status, foreign.body)
            == (missing.status, missing.body)
            == (404, b'{"error":"not_found"}')
        )
    finally:
        server.shutdown()
        server.server_close()


def test_same_origin_can_create_a_bounded_csv_version() -> None:
    server = run_artifact_ui_server()
    host, port = _server_host_port(server)
    address = (host, port)
    cookie = server.fixture_cookie()
    headers = {
        "Cookie": cookie,
        "Origin": f"http://{host}:{port}",
        "Sec-Fetch-Site": "same-origin",
    }
    try:
        created = _request(
            address,
            "POST",
            "/api/v1/artifacts/artifact-spectrum/versions",
            body={
                "base_version_no": 2,
                "name": "normalized.csv",
                "media_type": "text/csv",
                "content": "wavelength,intensity\n500,21\n",
            },
            headers=headers,
        )
        detail = cast("JsonObject", json.loads(created.body))

        assert created.status == 201
        assert cast("JsonObject", detail["selected"])["version_no"] == 3
    finally:
        server.shutdown()
        server.server_close()


def test_preview_authority_and_artifact_routes_are_exact() -> None:
    server = run_artifact_ui_server()
    host, port = _server_host_port(server)
    cookie = server.fixture_cookie()
    detail = server.artifacts.detail(
        "org-mineral", "artifact-spectrum", "artifact-spectrum-v1"
    )
    preview_host, preview_port = cast(
        "tuple[str, int]", server.preview_server.server_address
    )
    assert detail is not None
    try:
        canonical_preview = _request(
            (preview_host, preview_port),
            "GET",
            f"/preview/{detail.selected.preview_token}",
            headers={"Host": f"localhost:{preview_port}"},
        )
        preview_aliases = [
            _request(
                (preview_host, preview_port),
                "GET",
                f"/preview/{detail.selected.preview_token}",
                headers={"Host": authority, "Cookie": cookie},
            )
            for authority in (
                f"{host}:{preview_port}",
                f"evil.example:{preview_port}",
            )
        ]
        route_aliases = [
            _request((host, port), "GET", path, headers={"Cookie": cookie})
            for path in (
                "/api/v1/artifactsXYZ/artifact-spectrum",
                "/api//v1/artifacts/artifact-spectrum",
                "/api/v1/artifacts/artifact-spectrum/versions/"
                "artifact-spectrum-v1/download/",
            )
        ]

        assert canonical_preview.status == 200
        assert all(response.status == 404 for response in preview_aliases)
        assert all(response.status == 404 for response in route_aliases)
    finally:
        server.shutdown()
        server.server_close()


def test_partial_request_headers_are_closed_during_server_shutdown() -> None:
    server = run_artifact_ui_server()
    host, port = _server_host_port(server)
    preview_host, preview_port = cast(
        "tuple[str, int]", server.preview_server.server_address
    )
    connections: list[socket] = []
    try:
        for address, authority in (
            ((host, port), f"{host}:{port}"),
            ((preview_host, preview_port), f"localhost:{preview_port}"),
        ):
            connection = create_connection(address)
            connection.settimeout(0.5)
            connection.sendall(
                f"GET /artifacts HTTP/1.1\r\nHost: {authority}".encode()
            )
            connections.append(connection)
        _ = Event().wait(0.05)

        started = monotonic()
        server.shutdown()
        server.server_close()

        assert monotonic() - started < 2.0
        assert all(_connection_closed(connection) for connection in connections)
    finally:
        for connection in connections:
            connection.close()
