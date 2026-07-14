"""Authenticated test-principal server for the isolated Artifact UI slice."""

from __future__ import annotations

import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from threading import Thread
from typing import TYPE_CHECKING, Final, cast, final, override
from urllib.parse import urlsplit

from services.api.artifact_ui_http import (
    FORBIDDEN,
    NOT_FOUND,
    REQUEST_TIMEOUT_SECONDS,
    UNAUTHORIZED,
    BoundedThreadingHttpServer,
    cookies,
    request_json,
    send_bytes,
    send_json,
    serve_product_asset,
)
from services.api.product_artifact_http import (
    ArtifactHttpContext,
    artifact_get,
    create_artifact_version,
    mutate_artifact_attachment,
)
from services.api.product_artifacts import ProductArtifactService
from services.api.product_preview import (
    ArtifactPreviewServer,
    run_artifact_preview_server,
)

if TYPE_CHECKING:
    from socket import socket

    from services.api.product_artifact_views import JsonObject

_COOKIE_NAME: Final = "artifact_test_principal"
_CREATE_PARTS: Final = 5
_ATTACHMENT_PARTS: Final = 7


@final
class ArtifactUiServer(BoundedThreadingHttpServer):
    """Carry the test principal, Artifact fixture, and preview origin."""

    def __init__(
        self, address: tuple[str, int], principal_token: str | None = None
    ) -> None:
        """Initialize isolated app and preview listeners."""
        super().__init__(address, ArtifactUiHandler)
        self.daemon_threads: bool = True
        self.artifacts: ProductArtifactService = ProductArtifactService.with_fixture()
        self.preview_server: ArtifactPreviewServer = run_artifact_preview_server(
            self.artifacts
        )
        self.artifact_origin: str = self.preview_server.public_origin
        self._principal_token = principal_token or secrets.token_urlsafe(32)

    @property
    def expected_host(self) -> str:
        """Return the sole app authority accepted by the fixture."""
        host, port = cast("tuple[str, int]", self.server_address)
        return f"{host}:{port}"

    def fixture_cookie(self) -> str:
        """Return the host-only test-principal cookie pair."""
        return f"{_COOKIE_NAME}={self._principal_token}"

    def authorized(self, cookie_header: str | None, host: str | None) -> bool:
        """Authenticate the opaque cookie only on the bound app authority."""
        supplied = cookies(cookie_header).get(_COOKIE_NAME, "")
        return host == self.expected_host and secrets.compare_digest(
            supplied, self._principal_token
        )

    @override
    def server_close(self) -> None:
        """Close both the app and isolated preview listeners."""
        self.preview_server.shutdown()
        self.preview_server.server_close()
        super().server_close()


@final
class ArtifactUiHandler(BaseHTTPRequestHandler):
    """Serve authenticated Artifact metadata, mutations, and app assets."""

    @property
    def app_server(self) -> ArtifactUiServer:
        """Return the typed server for this request."""
        return cast("ArtifactUiServer", self.server)

    @override
    def log_message(self, format: str, *args: str | float) -> None:
        """Suppress cookies and opaque Artifact tokens from logs."""
        del format, args

    def do_GET(self) -> None:
        """Serve only authenticated test-principal reads."""
        if not self._authorized():
            send_bytes(self, HTTPStatus.UNAUTHORIZED, UNAUTHORIZED)
            return
        path = urlsplit(self.path).path
        if path == "/api/v1/artifacts" or path.startswith("/api/v1/artifacts/"):
            self._artifact_get(path)
        elif path == "/api/v1/me":
            send_json(
                self,
                HTTPStatus.OK,
                {
                    "user": {"id": "test-principal"},
                    "organization": {"name": "한국 광물 연구실"},
                },
            )
        elif path == "/api/v1/workspace":
            send_json(
                self,
                HTTPStatus.OK,
                {
                    "projects": [{"id": "project-demo", "name": "스펙트럼 보정"}],
                    "recent_runs": [],
                },
            )
        elif path == "/api/v1/dry-lab/state":
            send_json(self, HTTPStatus.OK, {})
        else:
            serve_product_asset(self, path)

    def do_POST(self) -> None:
        """Create a Version or attach an explicitly selected Version."""
        self._mutation(attach=True)

    def do_DELETE(self) -> None:
        """Detach an explicitly selected Version from a visible Session."""
        self._mutation(attach=False)

    def _artifact_get(self, path: str) -> None:
        artifact_get(
            self,
            self._artifact_context(),
            path,
        )

    def _mutation(self, *, attach: bool) -> None:
        if not self._authorized():
            send_bytes(self, HTTPStatus.UNAUTHORIZED, UNAUTHORIZED)
            return
        if not self._same_origin():
            send_bytes(self, HTTPStatus.FORBIDDEN, FORBIDDEN)
            return
        path = urlsplit(self.path).path
        parts = _path_parts(path)
        if (
            parts[:3] == ("api", "v1", "artifacts")
            and len(parts) == _CREATE_PARTS
            and parts[4] == "versions"
            and attach
        ):
            create_artifact_version(
                self,
                self._artifact_context(),
                parts[3],
                self._json(),
            )
            return
        if (
            parts[:3] == ("api", "v1", "artifacts")
            and len(parts) == _ATTACHMENT_PARTS
            and parts[4] == "versions"
            and parts[6] == "attachments"
        ):
            mutate_artifact_attachment(
                self,
                self._artifact_context(),
                parts,
                self._json(),
                attach=attach,
            )
            return
        send_bytes(self, HTTPStatus.NOT_FOUND, NOT_FOUND)

    def _authorized(self) -> bool:
        return self.app_server.authorized(
            self.headers.get("Cookie"), self.headers.get("Host")
        )

    def _same_origin(self) -> bool:
        authority = self.app_server.expected_host
        return (
            self.headers.get("Host") == authority
            and self.headers.get("Origin") == f"http://{authority}"
            and self.headers.get("Sec-Fetch-Site") == "same-origin"
        )

    def _json(self) -> JsonObject | None:
        cast("socket", self.connection).settimeout(REQUEST_TIMEOUT_SECONDS)
        return request_json(self)

    def _artifact_context(self) -> ArtifactHttpContext:
        return ArtifactHttpContext(
            self.app_server.artifacts, self.app_server.artifact_origin
        )


def _path_parts(path: str) -> tuple[str, ...]:
    if not path.startswith("/") or path.endswith("/") or "//" in path:
        return ()
    return tuple(path.removeprefix("/").split("/"))


def run_artifact_ui_server(
    address: tuple[str, int] = ("127.0.0.1", 0),
    principal_token: str | None = None,
) -> ArtifactUiServer:
    """Start the authenticated Artifact UI fixture on the exact loopback host."""
    server = ArtifactUiServer(address, principal_token)
    Thread(target=server.serve_forever, daemon=True).start()
    return server
