"""Bounded HTTP parsing and static responses for the Artifact UI fixture."""

from __future__ import annotations

import json
import re
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Final

from pydantic import TypeAdapter, ValidationError

from services.api.bounded_http import BoundedThreadingHttpServer
from services.api.product_artifact_views import JsonObject

if TYPE_CHECKING:
    from http.server import BaseHTTPRequestHandler

NOT_FOUND: Final = b'{"error":"not_found"}'
UNAUTHORIZED: Final = b'{"error":"unauthorized"}'
FORBIDDEN: Final = b'{"error":"invalid_origin"}'
BAD_REQUEST: Final = b'{"error":"invalid_request"}'
CONFLICT: Final = b'{"error":"version_conflict"}'
MAX_JSON_BYTES: Final = 65_536
REQUEST_TIMEOUT_SECONDS: Final = BoundedThreadingHttpServer.request_timeout_seconds

_JSON_ADAPTER: Final[TypeAdapter[JsonObject]] = TypeAdapter(JsonObject)
_ARTIFACT_PAGE: Final = re.compile(r"^/artifacts(?:/[A-Za-z0-9._-]+)?$")


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
        ".svg": "image/svg+xml",
    }.get(candidate.suffix, "application/octet-stream")
    send_bytes(
        handler,
        HTTPStatus.OK,
        candidate.read_bytes(),
        {"Content-Type": media_type, "X-Content-Type-Options": "nosniff"},
    )
