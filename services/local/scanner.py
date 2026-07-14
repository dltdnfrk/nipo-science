"""ClamAV INSTREAM boundary for local upload scanning."""

import socket
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar, Final

from services.local.config import LocalConfig

MAX_UPLOAD_BYTES: Final = 50 * 1024 * 1024
STREAM_CHUNK_BYTES: Final = 64 * 1024
RESPONSE_LIMIT_BYTES: Final = 4096
SCANNER_TIMEOUT_SECONDS: Final = 3.0


class ScanDisposition(StrEnum):
    """Closed scanner outcomes used by transport adapters."""

    CLEAN = "clean"
    THREAT = "threat"
    UNAVAILABLE = "unavailable"
    PROTOCOL_ERROR = "protocol_error"
    TOO_LARGE = "too_large"


@dataclass(frozen=True, slots=True)
class ScanClean:
    """A complete stream was scanned without a finding."""

    disposition: ClassVar[ScanDisposition] = ScanDisposition.CLEAN


@dataclass(frozen=True, slots=True)
class ThreatFound:
    """ClamAV rejected the stream with a malware signature."""

    signature: str
    disposition: ClassVar[ScanDisposition] = ScanDisposition.THREAT


@dataclass(frozen=True, slots=True)
class ScannerUnavailable:
    """ClamAV could not complete a trustworthy scan."""

    disposition: ClassVar[ScanDisposition] = ScanDisposition.UNAVAILABLE


@dataclass(frozen=True, slots=True)
class ScanProtocolError:
    """ClamAV returned a response outside the INSTREAM contract."""

    disposition: ClassVar[ScanDisposition] = ScanDisposition.PROTOCOL_ERROR


@dataclass(frozen=True, slots=True)
class UploadTooLarge:
    """The upload exceeded the bounded local scanning envelope."""

    disposition: ClassVar[ScanDisposition] = ScanDisposition.TOO_LARGE


type ScanResult = (
    ScanClean | ThreatFound | ScannerUnavailable | ScanProtocolError | UploadTooLarge
)


def _parse_response(response: bytearray) -> ScanClean | ThreatFound | ScanProtocolError:
    raw_response = bytes(response)
    if not raw_response.endswith(b"\0") or raw_response.count(b"\0") != 1:
        return ScanProtocolError()
    try:
        message = raw_response[:-1].decode("utf-8")
    except UnicodeDecodeError:
        return ScanProtocolError()
    if message == "stream: OK":
        return ScanClean()
    prefix = "stream: "
    suffix = " FOUND"
    if message.startswith(prefix) and message.endswith(suffix):
        signature = message[len(prefix) : -len(suffix)]
        if signature:
            return ThreatFound(signature=signature)
    return ScanProtocolError()


def scan_stream(config: LocalConfig, payload: bytes) -> ScanResult:
    """Scan bytes through ClamAV INSTREAM without storing the upload."""
    if len(payload) > MAX_UPLOAD_BYTES:
        return UploadTooLarge()
    try:
        with socket.create_connection(
            (config.clamav_host, config.clamav_port),
            timeout=SCANNER_TIMEOUT_SECONDS,
        ) as connection:
            connection.settimeout(SCANNER_TIMEOUT_SECONDS)
            connection.sendall(b"zINSTREAM\0")
            for offset in range(0, len(payload), STREAM_CHUNK_BYTES):
                chunk = payload[offset : offset + STREAM_CHUNK_BYTES]
                connection.sendall(len(chunk).to_bytes(4, byteorder="big"))
                connection.sendall(chunk)
            connection.sendall(bytes(4))
            response = bytearray()
            while len(response) < RESPONSE_LIMIT_BYTES:
                chunk = connection.recv(RESPONSE_LIMIT_BYTES - len(response))
                if not chunk:
                    break
                response.extend(chunk)
                if b"\0" in chunk or b"\n" in chunk:
                    break
    except OSError:
        return ScannerUnavailable()

    return _parse_response(response)
