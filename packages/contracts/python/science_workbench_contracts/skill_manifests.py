from typing import Annotated, Final, Literal, Self

from pydantic import Field, model_validator
from pydantic_core import PydanticCustomError

from .common import NonEmptyText, Sha256, Uuid7
from .task6_common import Task6ContractModel

CANONICAL_SKILL_IDS: Final = (
    "literature-review",
    "source-attribution",
    "probe-diagnostic",
)


class SkillNeeds(Task6ContractModel):
    tools: tuple[NonEmptyText, ...]
    connectors: tuple[NonEmptyText, ...]
    network_hosts: tuple[NonEmptyText, ...]
    secret_names: tuple[NonEmptyText, ...]
    kernel: bool


class SkillManifest(Task6ContractModel):
    id: Literal["literature-review", "source-attribution", "probe-diagnostic"]
    project_id: Uuid7
    run_id: Uuid7
    version: Annotated[
        str,
        Field(pattern=r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$"),
    ]
    content_sha256: Sha256
    kernel_sha256: Sha256 | None
    needs: SkillNeeds

    @model_validator(mode="after")
    def validate_kernel_pin(self) -> Self:
        if self.needs.kernel != (self.kernel_sha256 is not None):
            error = PydanticCustomError(
                "skill_kernel_pin",
                "kernel hash must be present exactly when a Skill needs a kernel",
            )
            raise error
        return self
