"""Bounded HTTP parsing and static responses for the Artifact UI fixture."""

from __future__ import annotations

import json
import re
import sys
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path
from socket import socket
from threading import BoundedSemaphore, Lock
from typing import TYPE_CHECKING, Final, override

from pydantic import TypeAdapter, ValidationError

from services.api.product_artifact_views import JsonObject

if TYPE_CHECKING:
    from http.server import BaseHTTPRequestHandler
    from socketserver import BaseRequestHandler

    type RequestSocket = socket | tuple[bytes, socket]

NOT_FOUND: Final = b'{"error":"not_found"}'
UNAUTHORIZED: Final = b'{"error":"unauthorized"}'
FORBIDDEN: Final = b'{"error":"invalid_origin"}'
BAD_REQUEST: Final = b'{"error":"invalid_request"}'
CONFLICT: Final = b'{"error":"version_conflict"}'
MAX_JSON_BYTES: Final = 65_536
REQUEST_TIMEOUT_SECONDS: Final = 2.0

_JSON_ADAPTER: Final[TypeAdapter[JsonObject]] = TypeAdapter(JsonObject)
_ARTIFACT_PAGE: Final = re.compile(r"^/artifacts(?:/[A-Za-z0-9._-]+)?$")


class BoundedThreadingHttpServer(ThreadingHTTPServer):
    """Bound concurrent handlers so slow clients cannot grow threads without limit."""

    request_queue_size: int = 16

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[BaseRequestHandler],
    ) -> None:
        """Initialize a loopback server with a matching handler-slot bound."""
        self._request_slots: BoundedSemaphore = BoundedSemaphore(
            self.request_queue_size
        )
        self._request_lock: Lock = Lock()
        self._active_requests: set[RequestSocket] = set()
        super().__init__(address, handler)

    @override
    def process_request(
        self, request: RequestSocket, client_address: tuple[str, int]
    ) -> None:
        """Reject excess sockets before allocating another request thread."""
        if not self._request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        if isinstance(request, socket):
            request.settimeout(REQUEST_TIMEOUT_SECONDS)
        with self._request_lock:
            self._active_requests.add(request)
        try:
            super().process_request(request, client_address)
        except RuntimeError:
            with self._request_lock:
                self._active_requests.discard(request)
            self._request_slots.release()
            raise

    @override
    def process_request_thread(
        self, request: RequestSocket, client_address: tuple[str, int]
    ) -> None:
        """Release one handler slot after every request-thread outcome."""
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._request_lock:
                self._active_requests.discard(request)
            self._request_slots.release()

    @override
    def handle_error(
        self, request: RequestSocket, client_address: tuple[str, int]
    ) -> None:
        error = sys.exception()
        if isinstance(error, OSError):
            return
        super().handle_error(request, client_address)

    @override
    def server_close(self) -> None:
        with self._request_lock:
            active = tuple(self._active_requests)
        for request in active:
            self.shutdown_request(request)
        super().server_close()


def request_json(handler: BaseHTTPRequestHandler) -> JsonObject | None:
    """Parse one bounded JSON object without reading invalid lengths."""
    raw_length = handler.headers.get("Content-Length")
    try:
        length = int(raw_length) if raw_length is not None else -1
    except ValueError:
        return None
    if length < 0 or length > MAX_JSON_BYTES:
        return None
    try:
        return _JSON_ADAPTER.validate_json(handler.rfile.read(length))
    except (OSError, ValidationError):
        return None


def send_json(
    handler: BaseHTTPRequestHandler, status: HTTPStatus, payload: JsonObject
) -> None:
    """Serialize a bounded JSON response without optional whitespace."""
    send_bytes(handler, status, json.dumps(payload, separators=(",", ":")).encode())


def send_bytes(
    handler: BaseHTTPRequestHandler,
    status: HTTPStatus,
    body: bytes,
    headers: dict[str, str] | None = None,
) -> None:
    """Send a no-store response with explicit content length."""
    response_headers = headers or {}
    handler.send_response(status)
    handler.send_header(
        "Content-Type",
        response_headers.get("Content-Type", "application/json; charset=utf-8"),
    )
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    for key, value in response_headers.items():
        if key.lower() != "content-type":
            handler.send_header(key, value)
    handler.end_headers()
    _ = handler.wfile.write(body)


def serve_product_asset(handler: BaseHTTPRequestHandler, path: str) -> None:
    """Serve the product shell for library/detail routes or one static asset."""
    root = Path(__file__).resolve().parents[2] / "apps/web/product"
    requested = (
        "index.html"
        if _ARTIFACT_PAGE.fullmatch(path)
        else path.removeprefix("/product/")
    )
    candidate = (root / requested).resolve()
    if root not in candidate.parents or not candidate.is_file():
        send_bytes(handler, HTTPStatus.NOT_FOUND, NOT_FOUND)
        return
    media_type = {
        ".css": "text/css; charset=utf-8",
        ".html": "text/html; charset=utf-8",
        ".js": "text/javascript; charset=utf-8",
    }.get(candidate.suffix, "application/octet-stream")
    send_bytes(
        handler,
        HTTPStatus.OK,
        candidate.read_bytes(),
        {"Content-Type": media_type, "X-Content-Type-Options": "nosniff"},
    )


def cookies(header: str | None) -> dict[str, str]:
    """Parse only simple cookie name/value pairs used by the fixture."""
    if not header:
        return {}
    return {
        name: value
        for part in header.split(";")
        for name, separator, value in (part.strip().partition("="),)
        if name and separator
    }
