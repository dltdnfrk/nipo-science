from typing import Annotated, Literal, Self, assert_never

from pydantic import Field, model_validator
from pydantic_core import PydanticCustomError

from .common import (
    NonEmptyText,
    Revision,
    Sha256,
    UtcTimestamp,
    Uuid7,
)
from .task6_common import Task6ContractModel


class ArtifactVersionRecord(Task6ContractModel):
    id: Uuid7
    org_id: Uuid7
    project_id: Uuid7
    artifact_id: Uuid7
    version: Revision
    content_sha256: Sha256
    size_bytes: Annotated[int, Field(ge=0)]
    media_type: NonEmptyText
    producing_execution_id: Uuid7
    environment_sha256: Sha256
    input_version_ids: tuple[Uuid7, ...]
    code_sha256: Sha256
    runtime_adapter_id: NonEmptyText
    runtime_connection_id: Uuid7
    skill_content_hashes: tuple[Sha256, ...]
    source_hashes: tuple[Sha256, ...]
    immutable: Literal[True]
    created_at: UtcTimestamp


class ArtifactAttachmentState(Task6ContractModel):
    artifact_id: Uuid7
    org_id: Uuid7
    project_id: Uuid7
    revision: Revision
    version_ids: tuple[Uuid7, ...]

    @model_validator(mode="after")
    def validate_unique_versions(self) -> Self:
        if len(set(self.version_ids)) != len(self.version_ids):
            error = PydanticCustomError(
                "duplicate_attachment",
                "attached Artifact Version IDs must be unique",
            )
            raise error
        return self


class AttachArtifactVersion(Task6ContractModel):
    operation: Literal["attach"]
    base_revision: Revision
    version_id: Uuid7
    version_org_id: Uuid7
    version_project_id: Uuid7
    version_artifact_id: Uuid7


class DetachArtifactVersion(Task6ContractModel):
    operation: Literal["detach"]
    base_revision: Revision
    version_id: Uuid7


ArtifactAttachmentCommand = Annotated[
    AttachArtifactVersion | DetachArtifactVersion,
    Field(discriminator="operation"),
]


class AttachmentApplied(Task6ContractModel):
    ok: Literal[True]
    state: ArtifactAttachmentState


class AttachmentRejected(Task6ContractModel):
    ok: Literal[False]
    reason: Literal[
        "stale_revision", "context_mismatch", "already_attached", "not_attached"
    ]


ArtifactAttachmentResult = AttachmentApplied | AttachmentRejected


class ArtifactVersionCreateCommand(Task6ContractModel):
    base_version_id: Uuid7
    next_version: ArtifactVersionRecord


class ArtifactVersionCreated(Task6ContractModel):
    ok: Literal[True]
    previous: ArtifactVersionRecord
    created: ArtifactVersionRecord


class ArtifactVersionCreateRejected(Task6ContractModel):
    ok: Literal[False]
    reason: Literal["stale_base", "invalid_successor"]


ArtifactVersionCreateResult = ArtifactVersionCreated | ArtifactVersionCreateRejected


def create_artifact_version_cas(
    current: ArtifactVersionRecord,
    command: ArtifactVersionCreateCommand,
) -> ArtifactVersionCreateResult:
    if command.base_version_id != current.id:
        return ArtifactVersionCreateRejected(ok=False, reason="stale_base")
    if (
        command.next_version.org_id != current.org_id
        or command.next_version.project_id != current.project_id
        or command.next_version.artifact_id != current.artifact_id
        or command.next_version.id == current.id
        or command.next_version.version != current.version + 1
        or command.next_version.created_at < current.created_at
    ):
        return ArtifactVersionCreateRejected(ok=False, reason="invalid_successor")
    return ArtifactVersionCreated(
        ok=True,
        previous=current,
        created=command.next_version,
    )


def apply_artifact_attachment_cas(
    state: ArtifactAttachmentState,
    command: AttachArtifactVersion | DetachArtifactVersion,
) -> ArtifactAttachmentResult:
    if command.base_revision != state.revision:
        return AttachmentRejected(ok=False, reason="stale_revision")
    match command.operation:
        case "attach":
            version_id = command.version_id
            if (
                command.version_org_id != state.org_id
                or command.version_project_id != state.project_id
                or command.version_artifact_id != state.artifact_id
            ):
                return AttachmentRejected(ok=False, reason="context_mismatch")
            if version_id in state.version_ids:
                return AttachmentRejected(ok=False, reason="already_attached")
            return AttachmentApplied(
                ok=True,
                state=state.model_copy(
                    update={
                        "revision": state.revision + 1,
                        "version_ids": (*state.version_ids, version_id),
                    }
                ),
            )
        case "detach":
            version_id = command.version_id
            if version_id not in state.version_ids:
                return AttachmentRejected(ok=False, reason="not_attached")
            return AttachmentApplied(
                ok=True,
                state=state.model_copy(
                    update={
                        "revision": state.revision + 1,
                        "version_ids": tuple(
                            current
                            for current in state.version_ids
                            if current != version_id
                        ),
                    }
                ),
            )
        case _:
            assert_never(command.operation)
