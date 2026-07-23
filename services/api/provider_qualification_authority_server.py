"""Isolated qualification authority process that alone loads an RSA private key."""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast, final, override

from services.api.artifacts.runtime import SystemClock, Uuid7Factory
from services.api.provider_qualification_authority import qualification_receipt_json
from services.api.provider_qualification_private_key import (
    QualificationAuthorityServerError,
    RsaQualificationPrivateKey,
    load_qualification_private_key,
)
from services.api.provider_qualification_receipt import (
    QUALIFICATION_SIGNATURE_ALGORITHM,
    QualificationReceipt,
    QualificationReceiptClaim,
    QualificationReceiptIssuer,
    QualificationReceiptSubject,
    RsaQualificationPublicKey,
    RsaQualificationReceiptVerifier,
    qualification_receipt_payload,
)
from services.api.provider_uds import (
    SecureProviderUnixServer,
    canonical_provider_json,
    strict_provider_json,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

__all__ = [
    "QualificationAuthorityServerError",
    "RsaQualificationPrivateKey",
    "RsaQualificationReceiptSigner",
    "build_qualification_authority_server",
    "load_qualification_private_key",
    "main",
]

_RSA_3072_HEX_LENGTH: Final = 768
_PROTOCOL_VERSION: Final = 1
_ISSUE_OPERATION: Final = "issue_provider_qualification"


@final
class RsaQualificationReceiptSigner(QualificationReceiptIssuer):
    """Issue UUIDv7 receipts with one deployment-owned RSA-3072 key."""

    def __init__(
        self,
        key: RsaQualificationPrivateKey,
        *,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        """Bind private material only inside the isolated signer process."""
        self._key = key
        self._clock = clock or SystemClock().now
        self._id_factory = id_factory or (lambda: str(Uuid7Factory().new_uuid7()))
        self._verifier = RsaQualificationReceiptVerifier(
            (RsaQualificationPublicKey(key.key_id, key.modulus),)
        )

    @override
    def issue(self, claim: QualificationReceiptClaim) -> QualificationReceipt:
        """Sign one exact claim and verify the result before returning it."""
        unsigned = QualificationReceipt(
            receipt_id=self._id_factory(),
            issued_at=self._clock().astimezone(UTC),
            key_id=self._key.key_id,
            algorithm=QUALIFICATION_SIGNATURE_ALGORITHM,
            claim=claim,
            signature="0" * _RSA_3072_HEX_LENGTH,
        )
        signature = self._key.sign(qualification_receipt_payload(unsigned))
        receipt = replace(unsigned, signature=signature.hex())
        if not self._verifier.verify(receipt):
            raise QualificationAuthorityServerError
        return receipt


def build_qualification_authority_server(
    socket_path: Path,
    private_key_path: Path,
    *,
    clock: Callable[[], datetime] | None = None,
    id_factory: Callable[[], str] | None = None,
) -> SecureProviderUnixServer:
    """Compose the only production process permitted to load signing material."""
    signer = RsaQualificationReceiptSigner(
        load_qualification_private_key(private_key_path),
        clock=clock,
        id_factory=id_factory,
    )

    def operation(source: bytes) -> bytes:
        root = strict_provider_json(source)
        if set(root) != {"schema_version", "operation", "claim"} or (
            root.get("schema_version") != _PROTOCOL_VERSION
            or root.get("operation") != _ISSUE_OPERATION
        ):
            raise QualificationAuthorityServerError
        claim = _claim(_mapping(root.get("claim")))
        receipt = strict_provider_json(qualification_receipt_json(signer.issue(claim)))
        return canonical_provider_json(
            {"schema_version": _PROTOCOL_VERSION, "receipt": receipt}
        )

    return SecureProviderUnixServer(socket_path, operation)


def main() -> None:
    """Serve the deployment-configured signing authority until shutdown."""
    try:
        socket_path = Path(os.environ["PROVIDER_QUALIFICATION_AUTHORITY_SOCKET"])
        private_key = Path(os.environ["PROVIDER_QUALIFICATION_PRIVATE_KEY_FILE"])
    except (KeyError, ValueError) as error:
        raise SystemExit(2) from error
    with build_qualification_authority_server(socket_path, private_key) as server:
        server.serve_forever()


def _claim(root: Mapping[str, object]) -> QualificationReceiptClaim:
    expected = {
        "org_id",
        "user_id",
        "connection_id",
        "connection_revision",
        "profile_sha256",
        "cases_sha256",
        "adapter_id",
        "oauth_mode",
        "oauth_provider",
        "operator_account_ref",
        "runtime_version",
        "executable_sha256",
        "protocol_attempts",
        "cleanup_terminal",
        "cleanup_redaction_complete",
    }
    if set(root) != expected:
        raise QualificationAuthorityServerError
    strings = expected - {
        "connection_revision",
        "protocol_attempts",
        "cleanup_terminal",
        "cleanup_redaction_complete",
    }
    if not all(isinstance(root.get(name), str) for name in strings):
        raise QualificationAuthorityServerError
    revision = root.get("connection_revision")
    attempts = root.get("protocol_attempts")
    terminal = root.get("cleanup_terminal")
    redaction = root.get("cleanup_redaction_complete")
    if (
        not isinstance(revision, int)
        or isinstance(revision, bool)
        or not isinstance(attempts, int)
        or isinstance(attempts, bool)
        or not isinstance(terminal, bool)
        or not isinstance(redaction, bool)
    ):
        raise QualificationAuthorityServerError
    return QualificationReceiptClaim(
        QualificationReceiptSubject(
            cast("str", root["org_id"]),
            cast("str", root["user_id"]),
            cast("str", root["connection_id"]),
            revision,
        ),
        cast("str", root["profile_sha256"]),
        cast("str", root["cases_sha256"]),
        cast("str", root["adapter_id"]),
        cast("str", root["oauth_mode"]),
        cast("str", root["oauth_provider"]),
        cast("str", root["operator_account_ref"]),
        cast("str", root["runtime_version"]),
        cast("str", root["executable_sha256"]),
        attempts,
        terminal,
        redaction,
    )


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) for key in cast("dict[object, object]", value)
    ):
        raise QualificationAuthorityServerError
    return cast("dict[str, object]", value)


if __name__ == "__main__":
    main()
