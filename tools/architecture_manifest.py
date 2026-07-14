"""Typed JSON boundary and collection access for architecture manifests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, override

from pydantic import TypeAdapter, ValidationError

if TYPE_CHECKING:
    from pathlib import Path

type JsonValue = (
    str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]
)
JsonObject = dict[str, JsonValue]
JSON_OBJECT_ADAPTER: Final = TypeAdapter(JsonObject)


@dataclass(frozen=True, slots=True)
class ManifestError(Exception):
    """Report a manifest path whose JSON cannot become a typed object."""

    path: Path
    detail: str

    @override
    def __str__(self) -> str:
        return f"{self.path}: {self.detail}"


def read_manifest(path: Path) -> JsonObject:
    """Read and parse one JSON object at the filesystem trust boundary."""
    try:
        return JSON_OBJECT_ADAPTER.validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as error:
        raise ManifestError(path, str(error)) from error


def object_items(
    document: JsonObject,
    key: str,
    violations: list[str],
) -> tuple[JsonObject, ...]:
    """Return object entries while recording malformed collection shapes."""
    value = document.get(key)
    if isinstance(value, list):
        objects = tuple(item for item in value if isinstance(item, dict))
        if len(objects) != len(value):
            violations.append(f"invalid-manifest-shape:{key}")
        return objects
    violations.append(f"invalid-manifest-shape:{key}")
    return ()
