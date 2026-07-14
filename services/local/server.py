"""Deterministic HTTP stubs for local API and worker integration."""

import json
import os
import smtplib
import socket
from collections.abc import Iterator
from email.message import EmailMessage
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar, Final, final, override
from uuid import UUID

from pydantic import ValidationError

from services.api.upload import (
    IngestionService,
    InMemoryQuarantineStore,
    LocalClamScanner,
    UploadError,
    UploadErrorCode,
    UploadPart,
    UploadRequest,
    UploadScope,
)
from services.local.config import LocalConfig
from services.local.scanner import MAX_UPLOAD_BYTES

JSON_HEADERS: Final = (("Content-Type", "application/json"),)
UPLOAD_CHUNK_BYTES: Final = 64 * 1024
HEALTHY = json.dumps({"status": "ok"}, separators=(",", ":")).encode()
DEGRADED = json.dumps({"status": "degraded"}, separators=(",", ":")).encode()
UPLOAD_ACCEPTED = json.dumps({"status": "scan_accepted"}).encode()
UPLOAD_UNAVAILABLE = json.dumps({"error": "upload_scan_unavailable"}).encode()
UPLOAD_INVALID = json.dumps({"error": "upload_body_invalid"}).encode()
UPLOAD_TOO_LARGE = json.dumps({"error": "upload_too_large"}).encode()
UPLOAD_QUARANTINED = json.dumps(
    {"error": "malware_detected", "status": "quarantined"}
).encode()
MAGIC_LINK_ACCEPTED = json.dumps({"status": "accepted"}).encode()
NOT_FOUND = json.dumps({"error": "not_found"}).encode()
UPLOAD_ERRORS: Final[dict[UploadErrorCode, tuple[HTTPStatus, bytes]]] = {
    UploadErrorCode.MALWARE_DETECTED: (
        HTTPStatus.UNPROCESSABLE_ENTITY,
        UPLOAD_QUARANTINED,
    ),
    UploadErrorCode.SCANNER_FAILED: (
        HTTPStatus.SERVICE_UNAVAILABLE,
        UPLOAD_UNAVAILABLE,
    ),
    UploadErrorCode.STORAGE_FAILED: (
        HTTPStatus.SERVICE_UNAVAILABLE,
        UPLOAD_UNAVAILABLE,
    ),
    UploadErrorCode.FILE_TOO_LARGE: (
        HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
        UPLOAD_TOO_LARGE,
    ),
    UploadErrorCode.REQUEST_TOO_LARGE: (
        HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
        UPLOAD_TOO_LARGE,
    ),
}
LOCAL_UPLOAD_SCOPE = UploadScope(
    org_id=UUID("018f47a0-7b9c-7a01-8def-0123456789ab"),
    project_id=UUID("018f47a0-7b9c-7a03-8def-0123456789ab"),
    requester_id=UUID("018f47a0-7b9c-7a02-8def-0123456789ab"),
)


@final
class UploadReadError(Exception):
    """Translate an invalid HTTP upload body at the request boundary."""

    __slots__ = ("payload", "status")

    def __init__(self, status: HTTPStatus, payload: bytes) -> None:
        """Retain only the stable response status and payload."""
        super().__init__(status, payload)
        self.status = status
        self.payload = payload

    @override
    def __str__(self) -> str:
        """Describe the stable HTTP error without including upload bytes."""
        return self.status.phrase


def clamav_is_ready(config: LocalConfig) -> bool:
    """Return whether clamd responds to its protocol-level PING."""
    try:
        with socket.create_connection(
            (config.clamav_host, config.clamav_port), timeout=1.0
        ) as connection:
            connection.sendall(b"zPING\0")
            return connection.recv(16).rstrip(b"\0\n") == b"PONG"
    except OSError:
        return False


def deliver_magic_link(config: LocalConfig) -> None:
    """Deliver a deterministic local-only Magic Link through SMTP."""
    message = EmailMessage()
    message["From"] = "Science Workbench <local@science-workbench.test>"
    message["To"] = "researcher@example.test"
    message["Subject"] = "Science Workbench local Magic Link"
    message.set_content(
        f"{config.app_origin}auth/verify?token=local-smoke-token",
    )
    with smtplib.SMTP(
        host=config.smtp_host,
        port=config.smtp_port,
        timeout=3,
    ) as smtp:
        _ = smtp.send_message(message)


class LocalRequestHandler(BaseHTTPRequestHandler):
    """Expose observable health and fail-closed local integration seams."""

    config: ClassVar[LocalConfig]

    def _write_json(self, status: HTTPStatus, payload: bytes) -> None:
        self.send_response(status)
        for name, value in JSON_HEADERS:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        _ = self.wfile.write(payload)

    def _read_upload(self) -> Iterator[bytes]:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise UploadReadError(HTTPStatus.LENGTH_REQUIRED, UPLOAD_INVALID)
        try:
            length = int(raw_length)
        except ValueError:
            raise UploadReadError(HTTPStatus.BAD_REQUEST, UPLOAD_INVALID) from None
        if length < 0:
            raise UploadReadError(HTTPStatus.BAD_REQUEST, UPLOAD_INVALID)
        if length > MAX_UPLOAD_BYTES:
            raise UploadReadError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, UPLOAD_TOO_LARGE)
        return self._iter_upload(length)

    def _iter_upload(self, length: int) -> Iterator[bytes]:
        remaining = length
        while remaining:
            try:
                chunk = self.rfile.read(min(remaining, UPLOAD_CHUNK_BYTES))
            except OSError:
                raise UploadReadError(HTTPStatus.BAD_REQUEST, UPLOAD_INVALID) from None
            if not chunk:
                raise UploadReadError(HTTPStatus.BAD_REQUEST, UPLOAD_INVALID)
            remaining -= len(chunk)
            yield chunk

    def _ingest_upload(self, payload: Iterator[bytes]) -> None:
        filename = self.headers.get("X-Upload-Filename", "upload.txt")
        media_type = self.headers.get("X-Upload-Mime", "text/plain")
        service = IngestionService(
            InMemoryQuarantineStore(),
            LocalClamScanner(self.config),
        )
        _ = service.ingest(
            UploadRequest(
                scope=LOCAL_UPLOAD_SCOPE,
                files=(
                    UploadPart(
                        filename=filename,
                        declared_mime=media_type,
                        chunks=payload,
                    ),
                ),
            )
        )

    def do_GET(self) -> None:
        """Report healthy only while the upload scanner is reachable."""
        if self.path == "/health":
            ready = clamav_is_ready(self.config)
            status = HTTPStatus.OK if ready else HTTPStatus.SERVICE_UNAVAILABLE
            self._write_json(status, HEALTHY if ready else DEGRADED)
            return
        self._write_json(HTTPStatus.NOT_FOUND, NOT_FOUND)

    def do_POST(self) -> None:
        """Exercise local Magic Link and upload scanner boundaries."""
        if self.path == "/uploads":
            try:
                upload = self._read_upload()
                self._ingest_upload(upload)
            except UploadReadError as error:
                self._write_json(error.status, error.payload)
                return
            except ValidationError:
                self._write_json(HTTPStatus.UNPROCESSABLE_ENTITY, UPLOAD_INVALID)
                return
            except UploadError as error:
                status, response = UPLOAD_ERRORS.get(
                    error.code,
                    (HTTPStatus.UNPROCESSABLE_ENTITY, UPLOAD_INVALID),
                )
                self._write_json(status, response)
                return
            self._write_json(HTTPStatus.ACCEPTED, UPLOAD_ACCEPTED)
            return
        if self.path == "/magic-links":
            deliver_magic_link(self.config)
            self._write_json(HTTPStatus.ACCEPTED, MAGIC_LINK_ACCEPTED)
            return
        self._write_json(HTTPStatus.NOT_FOUND, NOT_FOUND)


def main() -> None:
    """Parse the environment once and serve the selected local role."""
    config = LocalConfig.from_env(os.environ)
    LocalRequestHandler.config = config
    server = ThreadingHTTPServer(
        (str(config.service_bind_host), config.service_port), LocalRequestHandler
    )
    with server:
        server.serve_forever()


if __name__ == "__main__":
    main()
