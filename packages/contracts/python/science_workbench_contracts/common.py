from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, ClassVar
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field
from pydantic_core import PydanticCustomError

UUID7_VERSION = 7
UUID7_ERROR = "uuid7"
UUID7_MESSAGE = "ID must be UUIDv7"
UTC_ERROR = "utc_timestamp"
UTC_MESSAGE = "timestamp must be UTC"


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
