"""Signed test-only tenant principal implementation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, Final, Literal, assert_never, override

from pydantic import BaseModel, ConfigDict, ValidationError

from science_workbench_contracts.common import UtcTimestamp, Uuid7

if TYPE_CHECKING:
    from datetime import datetime

MINIMUM_SIGNING_KEY_BYTES: Final = 32


class TestPrincipal(BaseModel):
    """Short-lived tenant principal accepted only by the test adapter."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    purpose: Literal["test_principal"] = "test_principal"
    org_id: Uuid7
    user_id: Uuid7
    issued_at: UtcTimestamp
    expires_at: UtcTimestamp


class PrincipalTokenError(Exception):
    """Stable rejection raised by the test principal boundary."""

    __slots__: ClassVar[tuple[str, ...]] = ("code",)
    code: Literal["disabled", "invalid", "expired", "unauthorized"]

    def __init__(
        self,
        code: Literal["disabled", "invalid", "expired", "unauthorized"],
    ) -> None:
        """Initialize the rejection with a stable machine code."""
        self.code = code
        super().__init__(code)

    @override
    def __str__(self) -> str:
        return f"test principal rejected: {self.code}"


@dataclass(frozen=True, slots=True)
class TestPrincipalAdapter:
    """Encode and verify principals only in explicit test environments."""

    environment: Literal["test", "production"]
    signing_key: bytes
    active_memberships: frozenset[tuple[Uuid7, Uuid7]]

    def __post_init__(self) -> None:
        """Reject signing keys below the minimum HMAC strength."""
        if len(self.signing_key) < MINIMUM_SIGNING_KEY_BYTES:
            raise PrincipalTokenError(code="invalid")

    def encode(self, principal: TestPrincipal) -> str:
        """Return an authenticated compact principal token."""
        self._require_test()
        payload = self._encode_bytes(principal.model_dump_json().encode())
        signature = hmac.digest(self.signing_key, payload.encode(), hashlib.sha256)
        return f"{payload}.{self._encode_bytes(signature)}"

    def decode(self, token: str, now: datetime) -> TestPrincipal:
        """Verify and decode a current compact principal token."""
        self._require_test()
        try:
            payload, signature = token.split(".", maxsplit=1)
            supplied = self._decode_bytes(signature)
            expected = hmac.digest(self.signing_key, payload.encode(), hashlib.sha256)
            if not hmac.compare_digest(supplied, expected):
                raise PrincipalTokenError(code="invalid")
            principal = TestPrincipal.model_validate_json(self._decode_bytes(payload))
        except (
            binascii.Error,
            UnicodeDecodeError,
            ValidationError,
            ValueError,
        ) as error:
            raise PrincipalTokenError(code="invalid") from error
        if principal.issued_at > now or principal.expires_at <= principal.issued_at:
            raise PrincipalTokenError(code="invalid")
        if now >= principal.expires_at:
            raise PrincipalTokenError(code="expired")
        if (principal.org_id, principal.user_id) not in self.active_memberships:
            raise PrincipalTokenError(code="unauthorized")
        return principal

    def _require_test(self) -> None:
        match self.environment:
            case "test":
                return
            case "production":
                raise PrincipalTokenError(code="disabled")
            case _:
                assert_never(self.environment)

    @staticmethod
    def _encode_bytes(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _decode_bytes(value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.b64decode(
            f"{value}{padding}",
            altchars=b"-_",
            validate=True,
        )
