from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Annotated, ClassVar, cast
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    JsonValue,
    PlainSerializer,
)
from pydantic_core import PydanticCustomError

UUID7_VERSION = 7
UUID7_ERROR = "uuid7"
UUID7_MESSAGE = "ID must be UUIDv7"
UTC_ERROR = "utc_timestamp"
UTC_MESSAGE = "timestamp must be UTC"

type JsonScalar = None | bool | int | float | str


def _prepare_frozen_json(value: object) -> object:
    if isinstance(value, list | tuple):
        items = cast("list[object] | tuple[object, ...]", value)
        return tuple(_prepare_frozen_json(item) for item in items)
    if isinstance(value, Mapping):
        mapping = cast("Mapping[object, object]", value)
        return {
            str(key): _prepare_frozen_json(item) for key, item in mapping.items()
        }
    return value


def _freeze_json_mapping(value: object) -> object:
    if isinstance(value, Mapping):
        mapping = cast("Mapping[str, object]", value)
        return MappingProxyType(dict(mapping))
    return value


def json_projection(value: object) -> JsonValue:
    """Project immutable JSON containers back to standard JSON wire values."""
    if isinstance(value, tuple | list):
        items = cast("list[object] | tuple[object, ...]", value)
        return [json_projection(item) for item in items]
    if isinstance(value, Mapping):
        return {
            str(key): json_projection(item)
            for key, item in cast("Mapping[object, object]", value).items()
        }
    return cast("JsonValue", value)


type FrozenJsonValue = Annotated[
    JsonScalar
    | tuple["FrozenJsonValue", ...]
    | Mapping[str, "FrozenJsonValue"],
    BeforeValidator(_prepare_frozen_json),
    AfterValidator(_freeze_json_mapping),
    PlainSerializer(json_projection, return_type=JsonValue),
]


class ContractModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)


def _uuid7(value: UUID) -> UUID:
    if value.version != UUID7_VERSION:
        raise PydanticCustomError(UUID7_ERROR, UUID7_MESSAGE)
    return value


def _utc(value: datetime) -> datetime:
    if value.utcoffset() != timedelta(0):
        raise PydanticCustomError(UTC_ERROR, UTC_MESSAGE)
    return value


Uuid7 = Annotated[UUID, AfterValidator(_uuid7)]
UtcTimestamp = Annotated[datetime, AfterValidator(_utc)]
NonEmptyText = Annotated[str, Field(min_length=1)]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Revision = Annotated[int, Field(ge=1)]
