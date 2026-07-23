"""Bounded JSON, publication, and redaction boundaries for live capture."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from hashlib import sha256
from typing import TYPE_CHECKING, Final, cast

from services.api.provider_live_capture_errors import capture_error

if TYPE_CHECKING:
    from pathlib import Path

type ExternalJsonValue = (
    None
    | bool
    | int
    | float
    | str
    | list[ExternalJsonValue]
    | dict[str, ExternalJsonValue]
)
type ExternalJsonObject = dict[str, ExternalJsonValue]

SENSITIVE_VALUE: Final = re.compile(
    r"(?i)(?:bearer\s+\S+|sk-[a-z0-9_-]{8,}|"
    r"eyj[a-z0-9_-]{8,}\.[a-z0-9_-]+\.[a-z0-9_-]+)"
)


def decode_external_json(
    source: bytes,
    *,
    maximum_bytes: int,
    error_message: str,
) -> ExternalJsonValue:
    """Decode bounded JSON while rejecting duplicate keys at every depth."""

    def unique_pairs(
        items: list[tuple[str, ExternalJsonValue]],
    ) -> ExternalJsonObject:
        result: ExternalJsonObject = {}
        for key, value in items:
            if key in result:
                raise capture_error(error_message)
            result[key] = value
        return result

    try:
        if len(source) > maximum_bytes:
            raise capture_error(error_message)
        return cast(
            "ExternalJsonValue",
            json.loads(source, object_pairs_hook=unique_pairs),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise capture_error(error_message) from error


def read_bounded_external_json(
    path: Path,
    *,
    maximum_bytes: int,
    error_message: str,
) -> ExternalJsonValue:
    """Read at most one bounded JSON document from a filesystem boundary."""
    try:
        with path.open("rb") as source_file:
            source = source_file.read(maximum_bytes + 1)
    except OSError as error:
        raise capture_error(error_message) from error
    return decode_external_json(
        source,
        maximum_bytes=maximum_bytes,
        error_message=error_message,
    )


def mapping(value: object, label: str) -> Mapping[str, object]:
    """Parse an internal JSON object with string keys."""
    parsed = nested_mapping(value)
    if parsed is None:
        message = f"{label} is malformed"
        raise capture_error(message)
    return parsed


def nested_mapping(value: object) -> Mapping[str, object] | None:
    """Narrow a possible recursive JSON object without accepting non-string keys."""
    if not isinstance(value, Mapping):
        return None
    candidate = cast("Mapping[object, object]", value)
    if not all(isinstance(key, str) for key in candidate):
        return None
    return cast("Mapping[str, object]", candidate)


def list_value(value: object, label: str) -> list[object]:
    """Parse an internal JSON array."""
    items = nested_list(value)
    if items is None:
        message = f"{label} is malformed"
        raise capture_error(message)
    return items


def nested_list(value: object) -> list[object] | None:
    """Narrow a possible recursive JSON array."""
    if not isinstance(value, list):
        return None
    return cast("list[object]", value)


def text(value: object, label: str) -> str:
    """Parse an internal JSON string."""
    if not isinstance(value, str):
        message = f"{label} is malformed"
        raise capture_error(message)
    return value


def contains_value(value: object, needle: str) -> bool:
    """Find a forbidden string recursively in JSON-compatible data."""
    if isinstance(value, str):
        return needle in value
    parsed_mapping = nested_mapping(value)
    if parsed_mapping is not None:
        return any(contains_value(item, needle) for item in parsed_mapping.values())
    items = nested_list(value)
    if items is not None:
        return any(contains_value(item, needle) for item in items)
    return False


def contains_sensitive(value: str) -> bool:
    """Detect credential-shaped output before it crosses capture boundaries."""
    return bool(SENSITIVE_VALUE.search(value))


def object_hash(value: Mapping[str, object]) -> str:
    """Hash a JSON object using the canonical capture encoding."""
    return sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
    ).hexdigest()
