from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import Field, model_validator
from pydantic_core import PydanticCustomError

from .common import (
    ContractModel,
    NonEmptyText,
    Revision,
    Sha256,
    UtcTimestamp,
    Uuid7,
)


class ArtifactCreate(ContractModel):
    project_id: Uuid7
    name: NonEmptyText


class Artifact(ContractModel):
    id: Uuid7
    org_id: Uuid7
    project_id: Uuid7
    name: NonEmptyText
    created_at: UtcTimestamp


class ArtifactVersionCreate(ContractModel):
    base_version: Revision
    checksum_sha256: Sha256
    size_bytes: Annotated[int, Field(ge=0)]
    media_type: NonEmptyText
    producing_run_id: Uuid7


class ArtifactVersion(ContractModel):
    id: Uuid7
    org_id: Uuid7
    artifact_id: Uuid7
    version: Revision
    checksum_sha256: Sha256
    size_bytes: Annotated[int, Field(ge=0)]
    media_type: NonEmptyText
    producing_run_id: Uuid7
    created_at: UtcTimestamp


class ReviewCreate(ContractModel):
    source_run_id: Uuid7
    artifact_version_ids: tuple[Uuid7, ...] = ()
    execution_ids: tuple[Uuid7, ...] = ()

    @model_validator(mode="after")
    def validate_pins(self) -> Self:
        if not self.artifact_version_ids and not self.execution_ids:
            error = PydanticCustomError(
                "missing_review_pins",
                "Review requires Artifact Version or Execution pins",
            )
            raise error
        return self


class Review(ContractModel):
    id: Uuid7
    org_id: Uuid7
    source_run_id: Uuid7
    run_id: Uuid7
    status: Literal["queued", "running", "completed", "failed"]
    created_at: UtcTimestamp


class ExportCreate(ContractModel):
    artifact_version_ids: Annotated[tuple[Uuid7, ...], Field(min_length=1)]


class Export(ContractModel):
    id: Uuid7
    org_id: Uuid7
    status: Literal["queued", "running", "completed", "failed"]
    artifact_version_ids: tuple[Uuid7, ...]
    created_at: UtcTimestamp


class ProviderConnectionCreate(ContractModel):
    adapter_id: Literal[
        "openai_codex",
        "anthropic_claude_code",
        "xai_grok_build",
        "moonshot_kimi_code",
    ]


class ProviderConnection(ContractModel):
    id: Uuid7
    org_id: Uuid7
    requester_user_id: Uuid7
    adapter_id: Literal[
        "openai_codex",
        "anthropic_claude_code",
        "xai_grok_build",
        "moonshot_kimi_code",
        "zai_glm",
    ]
    status: Literal[
        "pending", "healthy", "reauth_required", "revoked", "unsupported_auth"
    ]
    created_at: UtcTimestamp


class DeletionCreate(ContractModel):
    project_id: Uuid7


class DeletionRequest(ContractModel):
    id: Uuid7
    org_id: Uuid7
    status: Literal["queued", "running", "completed", "held", "failed"]
    created_at: UtcTimestamp


class LegalHoldStatus(ContractModel):
    org_id: Uuid7
    active: bool
    updated_at: UtcTimestamp
