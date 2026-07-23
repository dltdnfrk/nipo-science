"""Durable, externally signed provider qualification receipts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Final, Protocol, override
from uuid import RFC_4122, UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE: Final = re.compile(r"^[0-9a-f]+$")
_COMPACT: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
QUALIFICATION_SIGNATURE_ALGORITHM: Final = "RSASSA-PKCS1-v1_5/SHA-256"
QUALIFICATION_RECEIPT_DOMAIN: Final = "science-workbench/provider-qualification"
_RSA_BITS: Final = 3072
_RSA_PUBLIC_EXPONENT: Final = 65537
_UUID7_VERSION: Final = 7
_FIRST_QUALIFIED_REVISION: Final = 2


class QualificationReceiptError(ValueError):
    """Raised when a qualification receipt is structurally invalid."""


@dataclass(frozen=True, slots=True)
class QualificationReceiptSubject:
    """Requester-owned connection revision authorized for qualification."""

    org_id: str
    user_id: str
    connection_id: str
    connection_revision: int


@dataclass(frozen=True, slots=True)
class QualificationReceiptClaim:
    """Capture facts submitted to an external signing authority."""

    subject: QualificationReceiptSubject
    profile_sha256: str
    cases_sha256: str
    adapter_id: str
    oauth_mode: str
    oauth_provider: str
    operator_account_ref: str
    runtime_version: str
    executable_sha256: str
    protocol_attempts: int
    cleanup_terminal: bool
    cleanup_redaction_complete: bool


@dataclass(frozen=True, slots=True)
class QualificationReceipt:
    """Serializable authority output verified without a signing secret."""

    receipt_id: str
    issued_at: datetime
    key_id: str
    algorithm: str
    claim: QualificationReceiptClaim
    signature: str


class QualificationReceiptIssuer(Protocol):
    """Capability held only by the authorized live-capture process."""

    def issue(self, claim: QualificationReceiptClaim) -> QualificationReceipt:
        """Return an authority-assigned, signed receipt for exact capture facts."""
        ...


class QualificationReceiptVerifier(Protocol):
    """Public verification capability safe for ordinary runtime processes."""

    def verify(self, receipt: QualificationReceipt) -> bool:
        """Verify the durable receipt without access to signing material."""
        ...


@dataclass(frozen=True, slots=True)
class RsaQualificationPublicKey:
    """One pinned RSA public key selected by a stable authority key ID."""

    key_id: str
    modulus: int
    exponent: int = 65537
    _backend_key: rsa.RSAPublicKey = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Reject weak or malformed public-key policy."""
        if (
            type(self.modulus) is not int
            or type(self.exponent) is not int
            or not _compact(self.key_id)
            or self.modulus.bit_length() != _RSA_BITS
            or self.modulus % 2 == 0
            or self.exponent != _RSA_PUBLIC_EXPONENT
        ):
            raise QualificationReceiptError
        try:
            backend_key = rsa.RSAPublicNumbers(
                self.exponent,
                self.modulus,
            ).public_key()
        except ValueError as error:
            raise QualificationReceiptError from error
        object.__setattr__(self, "_backend_key", backend_key)

    def verify_signature(self, signature: bytes, payload: bytes) -> bool:
        """Verify one PKCS#1 v1.5 SHA-256 signature through the backend."""
        try:
            self._backend_key.verify(
                signature,
                payload,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature:
            return False
        return True


@dataclass(frozen=True, slots=True)
class RsaQualificationReceiptVerifier(QualificationReceiptVerifier):
    """Verify PKCS#1 v1.5 SHA-256 receipts using public keys only."""

    keys: tuple[RsaQualificationPublicKey, ...]

    def __post_init__(self) -> None:
        """Require a non-empty, unambiguous key ring."""
        key_ids = tuple(key.key_id for key in self.keys)
        if not key_ids or len(key_ids) != len(set(key_ids)):
            raise QualificationReceiptError

    @override
    def verify(self, receipt: QualificationReceipt) -> bool:
        """Return false for malformed, unknown-key, or invalid signatures."""
        if not qualification_receipt_is_well_formed(receipt):
            return False
        key = next((item for item in self.keys if item.key_id == receipt.key_id), None)
        if key is None:
            return False
        width = (key.modulus.bit_length() + 7) // 8
        if len(receipt.signature) != width * 2:
            return False
        signature = int(receipt.signature, 16)
        if signature >= key.modulus:
            return False
        return key.verify_signature(
            bytes.fromhex(receipt.signature),
            qualification_receipt_payload(receipt),
        )


@dataclass(frozen=True, slots=True)
class QualificationReceiptAdmissionPolicy:
    """Authorize only the current key while retaining historical verification."""

    verifier: RsaQualificationReceiptVerifier
    active_key_id: str

    def __post_init__(self) -> None:
        """Require the deployment-selected key to exist in the pinned ring."""
        if all(key.key_id != self.active_key_id for key in self.verifier.keys):
            raise QualificationReceiptError

    def admits(self, receipt: QualificationReceipt) -> bool:
        """Return whether a new receipt uses the active key and verifies."""
        return receipt.key_id == self.active_key_id and self.verifier.verify(receipt)


def qualification_receipt_payload(receipt: QualificationReceipt) -> bytes:
    """Return the canonical bytes covered by the external signature."""
    claim = receipt.claim
    subject = claim.subject
    payload: dict[str, str | int | bool] = {
        "schema_version": 1,
        "domain": QUALIFICATION_RECEIPT_DOMAIN,
        "receipt_id": receipt.receipt_id,
        "issued_at": _canonical_time(receipt.issued_at),
        "key_id": receipt.key_id,
        "algorithm": receipt.algorithm,
        "org_id": subject.org_id,
        "user_id": subject.user_id,
        "connection_id": subject.connection_id,
        "connection_revision": subject.connection_revision,
        "profile_sha256": claim.profile_sha256,
        "cases_sha256": claim.cases_sha256,
        "adapter_id": claim.adapter_id,
        "oauth_mode": claim.oauth_mode,
        "oauth_provider": claim.oauth_provider,
        "operator_account_ref": claim.operator_account_ref,
        "runtime_version": claim.runtime_version,
        "executable_sha256": claim.executable_sha256,
        "protocol_attempts": claim.protocol_attempts,
        "cleanup_terminal": claim.cleanup_terminal,
        "cleanup_redaction_complete": claim.cleanup_redaction_complete,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def qualification_receipt_sha256(receipt: QualificationReceipt) -> str:
    """Digest the signed payload and signature for immutable Run binding."""
    return sha256(
        qualification_receipt_payload(receipt) + b"." + receipt.signature.encode()
    ).hexdigest()


def qualification_receipt_is_well_formed(receipt: object) -> bool:
    """Validate receipt shape before public-key verification or persistence."""
    if type(receipt) is not QualificationReceipt:
        return False
    typed = receipt
    try:
        claim = typed.claim
        subject = claim.subject
        if (
            type(claim) is not QualificationReceiptClaim
            or type(subject) is not QualificationReceiptSubject
            or not _string(typed.receipt_id)
            or type(typed.issued_at) is not datetime
            or not _string(typed.key_id)
            or not _string(typed.algorithm)
            or not _string(typed.signature)
            or type(subject.connection_revision) is not int
            or type(claim.protocol_attempts) is not int
            or type(claim.cleanup_terminal) is not bool
            or type(claim.cleanup_redaction_complete) is not bool
        ):
            return False
        receipt_uuid = UUID(typed.receipt_id)
    except (AttributeError, TypeError, ValueError):
        return False
    return (
        receipt_uuid.version == _UUID7_VERSION
        and receipt_uuid.variant == RFC_4122
        and str(receipt_uuid) == typed.receipt_id
        and typed.issued_at.tzinfo is not None
        and typed.issued_at.utcoffset() == timedelta(0)
        and _compact(typed.key_id)
        and typed.algorithm == QUALIFICATION_SIGNATURE_ALGORITHM
        and _SIGNATURE.fullmatch(typed.signature) is not None
        and len(typed.signature) % 2 == 0
        and _compact(subject.org_id)
        and _compact(subject.user_id)
        and _compact(subject.connection_id)
        and subject.connection_revision >= _FIRST_QUALIFIED_REVISION
        and _sha256(claim.profile_sha256)
        and _sha256(claim.cases_sha256)
        and claim.adapter_id == "openai_codex"
        and claim.oauth_mode == "official_subscription_oauth"
        and claim.oauth_provider == "openai"
        and _compact(claim.operator_account_ref)
        and _compact(claim.runtime_version)
        and _sha256(claim.executable_sha256)
        and claim.protocol_attempts > 0
        and claim.cleanup_terminal
        and claim.cleanup_redaction_complete
    )


def _canonical_time(value: datetime) -> str:
    return (
        value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )


def _compact(value: object) -> bool:
    return isinstance(value, str) and _COMPACT.fullmatch(value) is not None


def _string(value: object) -> bool:
    return isinstance(value, str)


def _sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None
