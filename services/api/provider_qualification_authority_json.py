"""Strict JSON framing for qualification authority messages and receipts."""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING, Final, cast

from services.api.provider_qualification_receipt import (
    QualificationReceipt,
    QualificationReceiptClaim,
    QualificationReceiptSubject,
)

type JsonValue = (
    None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
)
type JsonObject = dict[str, JsonValue]

_PROTOCOL_VERSION: Final = 1

if TYPE_CHECKING:
    from collections.abc import Mapping


class QualificationAuthorityJsonError(RuntimeError):
    """Raised when authority JSON is ambiguous or structurally invalid."""


def canonical_json(value: JsonValue) -> bytes:
    """Encode one deterministic authority protocol value."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def claim_object(claim: QualificationReceiptClaim) -> JsonObject:
    """Return the exact authority wire shape for a qualification claim."""
    return {
        "org_id": claim.subject.org_id,
        "user_id": claim.subject.user_id,
        "connection_id": claim.subject.connection_id,
        "connection_revision": claim.subject.connection_revision,
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


def receipt_json(receipt: QualificationReceipt) -> bytes:
    """Serialize one signed receipt as an unambiguous canonical frame."""
    return canonical_json(_receipt_object(receipt)) + b"\n"


def parse_receipt_json(source: bytes, *, maximum_bytes: int) -> QualificationReceipt:
    """Parse an exact receipt object while rejecting duplicate keys."""
    return _receipt_from_object(decode_json_object(source, maximum_bytes=maximum_bytes))


def parse_authority_response(
    source: bytes,
    *,
    maximum_bytes: int,
) -> QualificationReceipt:
    """Parse the exact versioned response returned by the authority."""
    root = decode_json_object(source, maximum_bytes=maximum_bytes)
    if (
        set(root) != {"schema_version", "receipt"}
        or root.get("schema_version") != _PROTOCOL_VERSION
    ):
        raise QualificationAuthorityJsonError
    return _receipt_from_object(require_mapping(root.get("receipt")))


def decode_json_object(
    source: bytes,
    *,
    maximum_bytes: int,
) -> Mapping[str, JsonValue]:
    """Decode one bounded JSON object with recursive duplicate-key rejection."""
    if len(source) > maximum_bytes:
        raise QualificationAuthorityJsonError

    def unique_pairs(items: list[tuple[str, JsonValue]]) -> JsonObject:
        result: JsonObject = {}
        for key, value in items:
            if key in result:
                raise QualificationAuthorityJsonError
            result[key] = value
        return result

    try:
        decoded = cast(
            "JsonValue",
            json.loads(source, object_pairs_hook=unique_pairs),
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise QualificationAuthorityJsonError from error
    return require_mapping(decoded)


def require_mapping(value: JsonValue) -> Mapping[str, JsonValue]:
    """Narrow one decoded value to a string-keyed JSON object."""
    if not isinstance(value, dict):
        raise QualificationAuthorityJsonError
    return value


def _receipt_from_object(root: Mapping[str, JsonValue]) -> QualificationReceipt:
    if set(root) != {
        "receipt_id",
        "issued_at",
        "key_id",
        "algorithm",
        "claim",
        "signature",
    }:
        raise QualificationAuthorityJsonError
    claim = _claim_from_object(require_mapping(root.get("claim")))
    receipt_id = _require_string(root.get("receipt_id"))
    issued_at = _require_string(root.get("issued_at"))
    key_id = _require_string(root.get("key_id"))
    algorithm = _require_string(root.get("algorithm"))
    signature = _require_string(root.get("signature"))
    try:
        parsed_time = datetime.fromisoformat(issued_at)
    except ValueError as error:
        raise QualificationAuthorityJsonError from error
    return QualificationReceipt(
        receipt_id,
        parsed_time,
        key_id,
        algorithm,
        claim,
        signature,
    )


def _claim_from_object(root: Mapping[str, JsonValue]) -> QualificationReceiptClaim:
    string_names = {
        "org_id",
        "user_id",
        "connection_id",
        "profile_sha256",
        "cases_sha256",
        "adapter_id",
        "oauth_mode",
        "oauth_provider",
        "operator_account_ref",
        "runtime_version",
        "executable_sha256",
    }
    expected = string_names | {
        "connection_revision",
        "protocol_attempts",
        "cleanup_terminal",
        "cleanup_redaction_complete",
    }
    if set(root) != expected:
        raise QualificationAuthorityJsonError
    revision = root.get("connection_revision")
    attempts = root.get("protocol_attempts")
    terminal = root.get("cleanup_terminal")
    redaction = root.get("cleanup_redaction_complete")
    if (
        type(revision) is not int
        or type(attempts) is not int
        or type(terminal) is not bool
        or type(redaction) is not bool
    ):
        raise QualificationAuthorityJsonError
    return QualificationReceiptClaim(
        QualificationReceiptSubject(
            _require_string(root["org_id"]),
            _require_string(root["user_id"]),
            _require_string(root["connection_id"]),
            revision,
        ),
        _require_string(root["profile_sha256"]),
        _require_string(root["cases_sha256"]),
        _require_string(root["adapter_id"]),
        _require_string(root["oauth_mode"]),
        _require_string(root["oauth_provider"]),
        _require_string(root["operator_account_ref"]),
        _require_string(root["runtime_version"]),
        _require_string(root["executable_sha256"]),
        attempts,
        terminal,
        redaction,
    )


def _receipt_object(receipt: QualificationReceipt) -> JsonObject:
    return {
        "receipt_id": receipt.receipt_id,
        "issued_at": receipt.issued_at.isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        ),
        "key_id": receipt.key_id,
        "algorithm": receipt.algorithm,
        "claim": claim_object(receipt.claim),
        "signature": receipt.signature,
    }


def _require_string(value: JsonValue) -> str:
    if not isinstance(value, str):
        raise QualificationAuthorityJsonError
    return value
