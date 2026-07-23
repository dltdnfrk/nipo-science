"""Authenticated test-principal server for the isolated Artifact UI slice."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from hashlib import sha256
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
    request_json,
    send_bytes,
    send_json,
    serve_product_asset,
)
from services.api.bounded_http import BoundedThreadingHttpServer
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


@dataclass(frozen=True, slots=True)
class ArtifactUiPrincipal:
    """Authenticated Artifact UI scope derived from one browser session."""

    user_id: str
    organization_id: str
    organization_name: str
    projects: tuple[tuple[str, str], ...]
    session_ids: frozenset[str]


@dataclass(frozen=True, slots=True)
class _ArtifactUiSession:
    principal: ArtifactUiPrincipal
    csrf_token: str


def _default_principal() -> ArtifactUiPrincipal:
    return ArtifactUiPrincipal(
        "test-principal",
        "org-mineral",
        "Nipo Labs",
        (("project-demo", "스펙트럼 보정"),),
        frozenset({"session-demo"}),
    )


@final
class ArtifactUiServer(BoundedThreadingHttpServer):
    """Carry the test principal, Artifact fixture, and preview origin."""

    def __init__(
        self,
        address: tuple[str, int],
        principal_token: str | None = None,
        principal: ArtifactUiPrincipal | None = None,
    ) -> None:
        """Initialize isolated app and preview listeners."""
        super().__init__(address, ArtifactUiHandler)
        self.daemon_threads: bool = True
        self.artifacts: ProductArtifactService = ProductArtifactService.with_fixture()
        self.preview_server: ArtifactPreviewServer = run_artifact_preview_server(
            self.artifacts
        )
        self.artifact_origin: str = self.preview_server.public_origin
        self._sessions: dict[str, _ArtifactUiSession] = {}
        self._principal_token = principal_token or secrets.token_urlsafe(32)
        self._principal_session = self._register_session(
            self._principal_token, principal or _default_principal()
        )

    @property
    def expected_host(self) -> str:
        """Return the sole app authority accepted by the fixture."""
        host, port = cast("tuple[str, int]", self.server_address)
        return f"{host}:{port}"

    def fixture_cookie(self) -> str:
        """Return the host-only test-principal cookie pair."""
        return f"{_COOKIE_NAME}={self._principal_token}"

    def fixture_csrf_token(self) -> str:
        """Return the CSRF capability paired with the primary fixture session."""
        return self._principal_session.csrf_token

    def issue_fixture_session(self, principal: ArtifactUiPrincipal) -> tuple[str, str]:
        """Issue another opaque fixture session for cross-principal boundary tests."""
        token = secrets.token_urlsafe(32)
        session = self._register_session(token, principal)
        return f"{_COOKIE_NAME}={token}", session.csrf_token

    def authenticated_session(
        self, cookie_headers: list[str], host_headers: list[str]
    ) -> _ArtifactUiSession | None:
        """Resolve one unambiguous browser session on the bound app authority."""
        if host_headers != [self.expected_host] or len(cookie_headers) != 1:
            return None
        token = _single_cookie(cookie_headers[0], _COOKIE_NAME)
        if token is None:
            return None
        return self._sessions.get(sha256(token.encode("utf-8")).hexdigest())

    def _register_session(
        self, token: str, principal: ArtifactUiPrincipal
    ) -> _ArtifactUiSession:
        session = _ArtifactUiSession(principal, secrets.token_urlsafe(32))
        self._sessions[sha256(token.encode("utf-8")).hexdigest()] = session
        return session

    def csrf_matches(
        self, session: _ArtifactUiSession, csrf_headers: list[str]
    ) -> bool:
        """Verify one CSRF capability against its authenticated fixture session."""
        return len(csrf_headers) == 1 and secrets.compare_digest(
            csrf_headers[0], session.csrf_token
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
        session = self._authenticated_session()
        if session is None:
            send_bytes(self, HTTPStatus.UNAUTHORIZED, UNAUTHORIZED)
            return
        path = urlsplit(self.path).path
        if path == "/api/v1/artifacts" or path.startswith("/api/v1/artifacts/"):
            self._artifact_get(path, session.principal)
        elif path == "/api/v1/me":
            send_json(
                self,
                HTTPStatus.OK,
                {
                    "user": {"id": session.principal.user_id},
                    "organization": {
                        "id": session.principal.organization_id,
                        "name": session.principal.organization_name,
                    },
                    "csrf_token": session.csrf_token,
                },
            )
        elif path == "/api/v1/workspace":
            send_json(
                self,
                HTTPStatus.OK,
                {
                    "projects": [
                        {"id": project_id, "name": name}
                        for project_id, name in session.principal.projects
                    ],
                    "sessions": [
                        {"id": session_id, "name": session_id}
                        for session_id in sorted(session.principal.session_ids)
                    ],
                    "recent_runs": [],
                },
            )
        else:
            serve_product_asset(self, path)

    def do_POST(self) -> None:
        """Create a Version or attach an explicitly selected Version."""
        self._mutation(attach=True)

    def do_DELETE(self) -> None:
        """Detach an explicitly selected Version from a visible Session."""
        self._mutation(attach=False)

    def _artifact_get(self, path: str, principal: ArtifactUiPrincipal) -> None:
        artifact_get(
            self,
            self._artifact_context(principal),
            path,
        )

    def _mutation(self, *, attach: bool) -> None:
        session = self._authenticated_session()
        if session is None:
            send_bytes(self, HTTPStatus.UNAUTHORIZED, UNAUTHORIZED)
            return
        if not self._same_origin(session):
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
                self._artifact_context(session.principal),
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
                self._artifact_context(session.principal),
                parts,
                self._json(),
                attach=attach,
            )
            return
        send_bytes(self, HTTPStatus.NOT_FOUND, NOT_FOUND)

    def _authenticated_session(self) -> _ArtifactUiSession | None:
        return self.app_server.authenticated_session(
            self.headers.get_all("Cookie") or [], self.headers.get_all("Host") or []
        )

    def _same_origin(self, session: _ArtifactUiSession) -> bool:
        authority = self.app_server.expected_host
        return (
            self.headers.get_all("Host") == [authority]
            and self.headers.get_all("Origin") == [f"http://{authority}"]
            and self.headers.get_all("Sec-Fetch-Site") == ["same-origin"]
            and self.app_server.csrf_matches(
                session, self.headers.get_all("X-CSRF-Token") or []
            )
        )

    def _json(self) -> JsonObject | None:
        cast("socket", self.connection).settimeout(REQUEST_TIMEOUT_SECONDS)
        return request_json(self)

    def _artifact_context(self, principal: ArtifactUiPrincipal) -> ArtifactHttpContext:
        return ArtifactHttpContext(
            self.app_server.artifacts,
            self.app_server.artifact_origin,
            principal.organization_id,
            principal.session_ids,
        )


def _path_parts(path: str) -> tuple[str, ...]:
    if not path.startswith("/") or path.endswith("/") or "//" in path:
        return ()
    return tuple(path.removeprefix("/").split("/"))


def _single_cookie(header: str, target: str) -> str | None:
    matches = [
        value
        for part in header.split(";")
        for name, separator, value in (part.strip().partition("="),)
        if name == target and separator
    ]
    return matches[0] if len(matches) == 1 else None


def run_artifact_ui_server(
    address: tuple[str, int] = ("127.0.0.1", 0),
    principal_token: str | None = None,
    principal: ArtifactUiPrincipal | None = None,
) -> ArtifactUiServer:
    """Start the authenticated Artifact UI fixture on the exact loopback host."""
    server = ArtifactUiServer(address, principal_token, principal)
    Thread(target=server.serve_forever, daemon=True).start()
    return server
