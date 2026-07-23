"""Strict JSON primitives for provider qualification profiles."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Mapping
    from collections.abc import Set as AbstractSet

type JsonValue = (
    None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
)
type JsonObject = dict[str, JsonValue]

PROFILE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "evidence_kind",
        "adapter",
        "oauth",
        "runtime_version",
        "executable_sha256",
        "operator_account_ref",
        "sessions",
        "cleanup",
    }
)
ATTEMPT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "attempt_id",
        "events",
        "decision_code",
        "scientific_result",
        "artifact_manifest",
        "evidence_identifiers",
        "limitations",
        "scientific_hash",
        "artifact_hash",
    }
)

_FORBIDDEN_KEY_PARTS: Final[tuple[str, ...]] = (
    "token",
    "secret",
    "password",
    "credential",
    "authorization",
    "api_key",
    "apikey",
)
_TOKEN_VALUE: Final = re.compile(
    r"(?i)(?:bearer\s+\S+|sk-[a-z0-9_-]{8,}|"
    r"eyj[a-z0-9_-]{8,}\.[a-z0-9_-]+\.[a-z0-9_-]+)"
)
_MAX_OPAQUE_REF_LENGTH: Final = 256


class QualificationValidationError(ValueError):
    """Raised when qualification evidence is incomplete, unsafe, or malformed."""


def decode_profile_json(source: str | bytes) -> JsonValue:
    """Decode duplicate-free JSON while preserving boundary error semantics."""
    try:
        return cast(
            "JsonValue",
            json.loads(source, object_pairs_hook=_unique_json_object),
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        message = "profile must be valid JSON"
        raise QualificationValidationError(message) from error


def reject_sensitive_content(value: JsonValue, path: str = "profile") -> None:
    """Reject secret-shaped keys and values anywhere in a decoded profile."""
    mapping = _nested_mapping(value)
    if mapping is not None:
        for key, nested in mapping.items():
            if any(part in key.lower() for part in _FORBIDDEN_KEY_PARTS):
                message = f"{path} uses a forbidden sensitive key"
                raise QualificationValidationError(message)
            reject_sensitive_content(nested, f"{path}.{key}")
        return
    items = _nested_list(value)
    if items is not None:
        for index, nested in enumerate(items):
            reject_sensitive_content(nested, f"{path}[{index}]")
        return
    if isinstance(value, str) and _TOKEN_VALUE.search(value):
        message = f"{path} contains token-shaped content"
        raise QualificationValidationError(message)


def require_mapping(value: JsonValue, label: str) -> Mapping[str, JsonValue]:
    """Parse one object-shaped boundary value with string keys."""
    mapping = _nested_mapping(value)
    if mapping is None:
        message = f"{label} must be an object"
        raise QualificationValidationError(message)
    return mapping


def require_json_object(
    value: JsonValue,
    label: str,
) -> Mapping[str, JsonValue]:
    """Parse one non-empty object whose contents already crossed JSON decoding."""
    mapping = require_mapping(value, label)
    if not mapping:
        message = f"{label} must not be empty"
        raise QualificationValidationError(message)
    return mapping


def require_list(value: JsonValue, label: str) -> list[JsonValue]:
    """Parse one JSON array boundary value."""
    if not isinstance(value, list):
        message = f"{label} must be an array"
        raise QualificationValidationError(message)
    return value


def require_string_tuple(value: JsonValue, label: str) -> tuple[str, ...]:
    """Parse one duplicate-free sequence of non-empty strings."""
    values = tuple(
        require_string(item, f"{label}[{index}]")
        for index, item in enumerate(require_list(value, label))
    )
    if len(set(values)) != len(values):
        message = f"{label} must not contain duplicates"
        raise QualificationValidationError(message)
    return values


def require_string(value: JsonValue, label: str) -> str:
    """Parse one non-empty string boundary value."""
    if not isinstance(value, str) or not value:
        message = f"{label} must be a non-empty string"
        raise QualificationValidationError(message)
    return value


def require_opaque_ref(value: JsonValue, label: str) -> str:
    """Parse one bounded reference without whitespace."""
    text = require_string(value, label)
    if len(text) > _MAX_OPAQUE_REF_LENGTH or any(
        character.isspace() for character in text
    ):
        message = f"{label} must be a compact opaque reference"
        raise QualificationValidationError(message)
    return text


def require_sha256(value: JsonValue, label: str) -> str:
    """Parse one lowercase SHA-256 hexadecimal digest."""
    text = require_string(value, label)
    if re.fullmatch(r"[0-9a-f]{64}", text) is None:
        message = f"{label} must be a lowercase SHA-256 digest"
        raise QualificationValidationError(message)
    return text


def require_bool(value: JsonValue, label: str) -> bool:
    """Parse one exact JSON boolean boundary value."""
    if not isinstance(value, bool):
        message = f"{label} must be a boolean"
        raise QualificationValidationError(message)
    return value


def require_exact_keys(
    data: Mapping[str, JsonValue],
    expected: AbstractSet[str],
    label: str,
) -> None:
    """Reject every missing or unexpected object member."""
    if set(data) != expected:
        message = f"{label} has unexpected or missing fields"
        raise QualificationValidationError(message)


def canonical_object_hash(value: Mapping[str, JsonValue]) -> str:
    """Hash one object using the qualification canonical JSON projection."""
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return sha256(encoded.encode()).hexdigest()


def _unique_json_object(items: list[tuple[str, JsonValue]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in items:
        if key in result:
            message = "profile must be valid JSON"
            raise QualificationValidationError(message)
        result[key] = value
    return result


def _nested_mapping(value: JsonValue) -> Mapping[str, JsonValue] | None:
    if not isinstance(value, dict):
        return None
    return value


def _nested_list(value: JsonValue) -> list[JsonValue] | None:
    return value if isinstance(value, list) else None
