"""Public-only client boundary for an external qualification authority."""

from __future__ import annotations

import os
import re
import socket
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
from typing import TYPE_CHECKING, Final, final, override

from services.api.provider_qualification_authority_files import (
    UnsafeAuthorityPathError,
    inspect_secure_authority_socket,
    read_secure_authority_file,
    require_connected_unix_socket,
)
from services.api.provider_qualification_authority_json import (
    JsonValue,
    QualificationAuthorityJsonError,
    canonical_json,
    claim_object,
    decode_json_object,
    parse_authority_response,
    parse_receipt_json,
    receipt_json,
    require_mapping,
)
from services.api.provider_qualification_receipt import (
    QUALIFICATION_SIGNATURE_ALGORITHM,
    QualificationReceipt,
    QualificationReceiptAdmissionPolicy,
    QualificationReceiptClaim,
    QualificationReceiptError,
    QualificationReceiptIssuer,
    RsaQualificationPublicKey,
    RsaQualificationReceiptVerifier,
)

_MAX_AUTHORITY_MESSAGE_BYTES: Final = 64 * 1024
_RSA_3072_HEX_LENGTH: Final = 768
_PROTOCOL_VERSION: Final = 1
_ISSUE_OPERATION: Final = "issue_provider_qualification"
_MAX_TIMEOUT_SECONDS: Final = 120
_RSA_PUBLIC_EXPONENT: Final = 65537
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")

if TYPE_CHECKING:
    from pathlib import Path

__all__ = [
    "QualificationAuthorityClientConfig",
    "QualificationAuthorityError",
    "UnixSocketQualificationIssuer",
    "load_qualification_admission_policy",
    "load_qualification_verifier",
    "parse_qualification_receipt_json",
    "qualification_receipt_json",
]


class QualificationAuthorityError(RuntimeError):
    """Raised when external authority configuration or transport fails closed."""


@dataclass(frozen=True, slots=True)
class QualificationAuthorityClientConfig:
    """Non-secret connection settings for the external signing service."""

    socket_path: Path
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        """Reject unsafe socket locations and unbounded timeouts."""
        if (
            not self.socket_path.is_absolute()
            or self.timeout_seconds <= 0
            or self.timeout_seconds > _MAX_TIMEOUT_SECONDS
        ):
            raise QualificationAuthorityError


@final
class UnixSocketQualificationIssuer(QualificationReceiptIssuer):
    """Request domain-specific receipts without receiving signing material."""

    def __init__(
        self,
        config: QualificationAuthorityClientConfig,
        verifier: RsaQualificationReceiptVerifier,
        *,
        active_key_id: str,
    ) -> None:
        """Bind one endpoint to historical verification and current admission."""
        self._config = config
        try:
            self._admission_policy = QualificationReceiptAdmissionPolicy(
                verifier,
                active_key_id,
            )
        except QualificationReceiptError as error:
            raise QualificationAuthorityError from error

    @override
    def issue(self, claim: QualificationReceiptClaim) -> QualificationReceipt:
        """Issue one exact claim through the protected local authority socket."""
        request = canonical_json(
            {
                "schema_version": _PROTOCOL_VERSION,
                "operation": _ISSUE_OPERATION,
                "claim": claim_object(claim),
            }
        )
        if len(request) + 1 > _MAX_AUTHORITY_MESSAGE_BYTES:
            raise QualificationAuthorityError
        try:
            expected_socket = inspect_secure_authority_socket(self._config.socket_path)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self._config.timeout_seconds)
                connection.connect(os.fspath(self._config.socket_path))
                require_connected_unix_socket(connection.fileno())
                if (
                    inspect_secure_authority_socket(self._config.socket_path)
                    != expected_socket
                ):
                    raise QualificationAuthorityError
                connection.sendall(request + b"\n")
                response = _receive_frame(connection)
                if (
                    inspect_secure_authority_socket(self._config.socket_path)
                    != expected_socket
                ):
                    raise QualificationAuthorityError
            receipt = parse_authority_response(
                response,
                maximum_bytes=_MAX_AUTHORITY_MESSAGE_BYTES,
            )
        except (
            OSError,
            TimeoutError,
            UnsafeAuthorityPathError,
            QualificationAuthorityJsonError,
        ) as error:
            raise QualificationAuthorityError from error
        if receipt.claim != claim or not self._admission_policy.admits(receipt):
            raise QualificationAuthorityError
        return receipt


def load_qualification_verifier(
    path: Path,
    *,
    expected_sha256: str,
) -> RsaQualificationReceiptVerifier:
    """Load an owner-protected public-key ring pinned to its exact bytes."""
    if not _sha256_text(expected_sha256):
        raise QualificationAuthorityError
    try:
        source = read_secure_authority_file(
            path,
            maximum_bytes=_MAX_AUTHORITY_MESSAGE_BYTES,
        )
        if not compare_digest(sha256(source).hexdigest(), expected_sha256):
            raise QualificationAuthorityError
        root = decode_json_object(
            source,
            maximum_bytes=_MAX_AUTHORITY_MESSAGE_BYTES,
        )
        if set(root) != {"schema_version", "keys"} or root.get("schema_version") != 1:
            raise QualificationAuthorityError
        raw_keys = root.get("keys")
        if not isinstance(raw_keys, list) or not raw_keys:
            raise QualificationAuthorityError
        keys = tuple(_parse_public_key(item) for item in raw_keys)
        return RsaQualificationReceiptVerifier(keys)
    except (
        OSError,
        UnsafeAuthorityPathError,
        QualificationAuthorityJsonError,
        QualificationReceiptError,
        ValueError,
    ) as error:
        raise QualificationAuthorityError from error


def load_qualification_admission_policy(
    path: Path,
    *,
    expected_sha256: str,
    active_key_id: str,
) -> QualificationReceiptAdmissionPolicy:
    """Load the pinned historical ring and select its sole admission key."""
    verifier = load_qualification_verifier(path, expected_sha256=expected_sha256)
    try:
        return QualificationReceiptAdmissionPolicy(verifier, active_key_id)
    except QualificationReceiptError as error:
        raise QualificationAuthorityError from error


def qualification_receipt_json(receipt: QualificationReceipt) -> bytes:
    """Serialize one signed receipt for durable transfer without ambiguity."""
    try:
        return receipt_json(receipt)
    except QualificationAuthorityJsonError as error:
        raise QualificationAuthorityError from error


def parse_qualification_receipt_json(source: bytes) -> QualificationReceipt:
    """Parse an exact receipt object without accepting unknown or duplicate keys."""
    try:
        return parse_receipt_json(
            source,
            maximum_bytes=_MAX_AUTHORITY_MESSAGE_BYTES,
        )
    except QualificationAuthorityJsonError as error:
        raise QualificationAuthorityError from error


def _parse_public_key(value: JsonValue) -> RsaQualificationPublicKey:
    key = require_mapping(value)
    if set(key) != {"key_id", "algorithm", "modulus_hex", "exponent"}:
        raise QualificationAuthorityError
    key_id = key.get("key_id")
    algorithm = key.get("algorithm")
    modulus_hex = key.get("modulus_hex")
    exponent = key.get("exponent")
    if (
        not isinstance(key_id, str)
        or algorithm != QUALIFICATION_SIGNATURE_ALGORITHM
        or not isinstance(modulus_hex, str)
        or len(modulus_hex) != _RSA_3072_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in modulus_hex)
        or exponent != _RSA_PUBLIC_EXPONENT
    ):
        raise QualificationAuthorityError
    return RsaQualificationPublicKey(
        key_id,
        int(modulus_hex, 16),
        _RSA_PUBLIC_EXPONENT,
    )


def _receive_frame(connection: socket.socket) -> bytes:
    chunks = bytearray()
    while len(chunks) <= _MAX_AUTHORITY_MESSAGE_BYTES:
        item = connection.recv(
            min(4096, _MAX_AUTHORITY_MESSAGE_BYTES + 1 - len(chunks))
        )
        if not item:
            break
        chunks.extend(item)
    if (
        len(chunks) > _MAX_AUTHORITY_MESSAGE_BYTES
        or not chunks.endswith(b"\n")
        or chunks.count(b"\n") != 1
    ):
        raise QualificationAuthorityError
    return bytes(chunks[:-1])


def _sha256_text(value: str) -> bool:
    return _SHA256.fullmatch(value) is not None
