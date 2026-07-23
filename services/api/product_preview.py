"""Cookie-free isolated Artifact preview origin for the test principal."""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from threading import Thread
from typing import TYPE_CHECKING, Final, cast, final, override
from urllib.parse import urlsplit

from services.api.bounded_http import BoundedThreadingHttpServer

if TYPE_CHECKING:
    from services.api.product_artifacts import ProductArtifactService

_PREVIEW_MEDIA_TYPES: Final[dict[str, str]] = {
    "application/json": "text/plain; charset=utf-8",
    "application/pdf": "application/pdf",
    "image/png": "image/png",
    "text/csv": "text/plain; charset=utf-8",
    "text/markdown": "text/plain; charset=utf-8",
}


@final
class ArtifactPreviewServer(BoundedThreadingHttpServer):
    """Serve only opaque-token Artifact previews on a separate origin."""

    def __init__(
        self, address: tuple[str, int], artifacts: ProductArtifactService
    ) -> None:
        """Bind a preview server to one Artifact service."""
        super().__init__(address, ArtifactPreviewHandler)
        self.daemon_threads: bool = True
        self.artifacts: ProductArtifactService = artifacts

    @property
    def public_origin(self) -> str:
        """Expose localhost so host-only app cookies for 127.0.0.1 do not match."""
        return f"http://{self.expected_host}"

    @property
    def expected_host(self) -> str:
        """Return the sole public preview authority accepted by the listener."""
        _, port = cast("tuple[str, int]", self.server_address)
        return f"localhost:{port}"


@final
class ArtifactPreviewHandler(BaseHTTPRequestHandler):
    """Return safe passive media with a deny-all content policy."""

    @override
    def log_message(self, format: str, *args: str | float) -> None:
        """Suppress opaque preview tokens from logs."""
        del format, args

    def do_GET(self) -> None:
        """Resolve one opaque token and emit passive bytes only."""
        server = cast("ArtifactPreviewServer", self.server)
        if self.headers.get("Host") != server.expected_host:
            self._send_not_found()
            return
        path = urlsplit(self.path).path
        prefix = "/preview/"
        if not path.startswith(prefix) or "/" in path.removeprefix(prefix):
            self._send_not_found()
            return
        version = server.artifacts.preview(path.removeprefix(prefix))
        if version is None:
            self._send_not_found()
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", _PREVIEW_MEDIA_TYPES[version.media_type])
        self.send_header("Content-Length", str(len(version.content)))
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "cross-origin")
        self.send_header("Cache-Control", "private, no-store")
        self.end_headers()
        _ = self.wfile.write(version.content)

    def _send_not_found(self) -> None:
        body = b"not found"
        self.send_response(HTTPStatus.NOT_FOUND)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        _ = self.wfile.write(body)


def run_artifact_preview_server(
    artifacts: ProductArtifactService,
) -> ArtifactPreviewServer:
    """Start the isolated preview origin on a loopback ephemeral port."""
    server = ArtifactPreviewServer(("127.0.0.1", 0), artifacts)
    Thread(target=server.serve_forever, daemon=True).start()
    return server
