"""ClamAV INSTREAM integration tests over a real TCP socket."""

import socket
import threading
from collections.abc import Generator
from contextlib import contextmanager
from uuid import UUID

from pydantic import TypeAdapter
from services.api.upload import (
    IngestionService,
    InMemoryQuarantineStore,
    LocalClamScanner,
    UploadPart,
    UploadRequest,
    UploadScope,
)
from services.local.config import LocalConfig
from services.local.scanner import (
    MAX_UPLOAD_BYTES,
    ScanClean,
    ScannerUnavailable,
    ScanProtocolError,
    ThreatFound,
    UploadTooLarge,
    scan_stream,
)

LOCAL_SCOPE = UploadScope(
    org_id=UUID("018f47a0-7b9c-7a01-8def-0123456789ab"),
    project_id=UUID("018f47a0-7b9c-7a03-8def-0123456789ab"),
    requester_id=UUID("018f47a0-7b9c-7a02-8def-0123456789ab"),
)


def test_scan_stream_uses_the_task_10_file_limit() -> None:
    # Given / When: the scanner boundary exposes its enforced byte ceiling.
    limit = MAX_UPLOAD_BYTES

    # Then: quarantine scanning accepts at most 50 MiB per file.
    assert limit == 50 * 1024 * 1024


def _config(port: int) -> LocalConfig:
    return LocalConfig.from_env(
        {
            "APP_ORIGIN": "http://app.localhost:53000",
            "ARTIFACT_ORIGIN": "http://artifact.localhost:59000",
            "COOKIE_DOMAIN": "",
            "OBJECT_STORE_DRIVER": "s3",
            "OBJECT_STORE_ENDPOINT": "http://minio:9000",
            "MAIL_DRIVER": "mailpit",
            "SMTP_HOST": "mailpit",
            "SMTP_PORT": "1025",
            "CLAMAV_HOST": "127.0.0.1",
            "CLAMAV_PORT": str(port),
            "HOST_IP": "127.0.0.1",
            "SERVICE_ROLE": "api",
            "SERVICE_BIND_HOST": "127.0.0.1",
            "SERVICE_PORT": "8000",
        }
    )


def _receive_exact(connection: socket.socket, size: int) -> bytes:
    received = bytearray()
    while len(received) < size:
        chunk = connection.recv(size - len(received))
        if not chunk:
            break
        received.extend(chunk)
    return bytes(received)


@contextmanager
def _fake_clamd(response: bytes) -> Generator[int, None, None]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    address = TypeAdapter(tuple[str, int]).validate_python(listener.getsockname())
    port = address[1]

    def serve() -> None:
        with listener.accept()[0] as connection:
            assert _receive_exact(connection, 10) == b"zINSTREAM\0"
            while True:
                raw_size = _receive_exact(connection, 4)
                size = int.from_bytes(raw_size, byteorder="big")
                if size == 0:
                    break
                assert len(_receive_exact(connection, size)) == size
            connection.sendall(response)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        yield port
    finally:
        thread.join(timeout=3)
        assert not thread.is_alive()
        listener.close()


def test_scan_stream_accepts_only_explicit_clean_response() -> None:
    # Given: clamd completes INSTREAM with an explicit OK response.
    with _fake_clamd(b"stream: OK\0") as port:
        # When: clean bytes are scanned through the socket protocol.
        result = scan_stream(_config(port), b"clean scientific input")

    # Then: the result is explicitly clean.
    assert result == ScanClean()


def test_ingestion_uses_local_clam_adapter_before_clean_promotion() -> None:
    # Given: the real ingestion adapter points to an INSTREAM-speaking daemon.
    with _fake_clamd(b"stream: OK\0") as port:
        store = InMemoryQuarantineStore()
        service = IngestionService(store, LocalClamScanner(_config(port)))

        # When: one valid upload crosses the integrated boundary.
        uploads = service.ingest(
            UploadRequest(
                scope=LOCAL_SCOPE,
                files=(
                    UploadPart(
                        filename="notes.txt",
                        declared_mime="text/plain",
                        chunks=(b"scientific input",),
                    ),
                ),
            )
        )

    # Then: the scanner response gates the clean-only read.
    assert store.read_agent(LOCAL_SCOPE, uploads[0].key) == b"scientific input"


def test_scan_stream_returns_signature_when_clamd_finds_threat() -> None:
    # Given: clamd identifies the harmless EICAR test signature.
    with _fake_clamd(b"stream: Win.Test.EICAR_HDB-1 FOUND\0") as port:
        # When: the bytes cross the INSTREAM boundary.
        result = scan_stream(_config(port), b"eicar-like fixture")

    # Then: the finding is typed and cannot be accepted as clean.
    assert result == ThreatFound(signature="Win.Test.EICAR_HDB-1")


def test_scan_stream_fails_closed_on_protocol_error() -> None:
    # Given: clamd returns neither OK nor FOUND.
    with _fake_clamd(b"unexpected response\0") as port:
        # When: the scanner parses the response.
        result = scan_stream(_config(port), b"scientific input")

    # Then: a protocol error is distinct from a clean scan.
    assert result == ScanProtocolError()


def test_scan_stream_fails_closed_on_eof_truncated_clean_response() -> None:
    with _fake_clamd(b"stream: OK") as port:
        result = scan_stream(_config(port), b"scientific input")

    assert result == ScanProtocolError()


def test_scan_stream_fails_closed_when_daemon_is_unavailable() -> None:
    # Given: a loopback port with no listening clamd.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as unused:
        unused.bind(("127.0.0.1", 0))
        address = TypeAdapter(tuple[str, int]).validate_python(unused.getsockname())
        port = address[1]

    # When: scanning attempts to connect.
    result = scan_stream(_config(port), b"scientific input")

    # Then: scanner unavailability is explicit.
    assert result == ScannerUnavailable()


def test_scan_stream_rejects_oversize_before_connecting() -> None:
    # Given: bytes larger than the local upload envelope.
    payload = bytes(MAX_UPLOAD_BYTES + 1)

    # When: the upload reaches the scanner boundary.
    result = scan_stream(_config(1), payload)

    # Then: it is rejected without being classified as clean.
    assert result == UploadTooLarge()
