"""HMAC-bound short-lived Artifact download claims."""

import base64
import binascii
import hashlib
import hmac
from datetime import datetime
from typing import final

from pydantic import ValidationError

from .models import (
    ArtifactError,
    ArtifactErrorCode,
    DownloadClaims,
)

MIN_SIGNING_KEY_BYTES = 32


@final
class DownloadSigner:
    """Issue and verify opaque authenticated download claims."""

    def __init__(self, signing_key: bytes) -> None:
        """Retain a signing key with at least 256 bits of material."""
        if len(signing_key) < MIN_SIGNING_KEY_BYTES:
            raise ArtifactError(ArtifactErrorCode.DOWNLOAD_INVALID)
        self._signing_key = signing_key

    def issue(self, claims: DownloadClaims) -> str:
        """Return an authenticated URL-safe token for exact claims."""
        payload = self._encode(claims.model_dump_json().encode())
        signature = hmac.digest(self._signing_key, payload.encode(), hashlib.sha256)
        return f"{payload}.{self._encode(signature)}"

    def verify(self, token: str, now: datetime) -> DownloadClaims:
        """Verify signature, typed claims, and expiry."""
        try:
            payload, supplied_signature = token.split(".", maxsplit=1)
            supplied = self._decode(supplied_signature)
            decoded_payload = self._decode(payload)
            if (
                self._encode(supplied) != supplied_signature
                or self._encode(decoded_payload) != payload
            ):
                raise ArtifactError(ArtifactErrorCode.DOWNLOAD_INVALID)
            expected = hmac.digest(
                self._signing_key,
                payload.encode(),
                hashlib.sha256,
            )
            if not hmac.compare_digest(supplied, expected):
                raise ArtifactError(ArtifactErrorCode.DOWNLOAD_INVALID)
            claims = DownloadClaims.model_validate_json(decoded_payload)
        except (
            binascii.Error,
            UnicodeDecodeError,
            ValidationError,
            ValueError,
        ) as error:
            raise ArtifactError(ArtifactErrorCode.DOWNLOAD_INVALID) from error
        if int(now.timestamp() * 1_000) >= claims.expires_unix_ms:
            raise ArtifactError(ArtifactErrorCode.DOWNLOAD_EXPIRED)
        return claims

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _decode(value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.b64decode(
            f"{value}{padding}",
            altchars=b"-_",
            validate=True,
        )
