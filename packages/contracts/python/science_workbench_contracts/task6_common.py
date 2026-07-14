from typing import ClassVar

from pydantic import BaseModel, ConfigDict


class Task6ContractModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )
