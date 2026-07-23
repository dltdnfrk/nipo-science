import hashlib
import json
from typing import Annotated, Final, Self

from pydantic import Field, model_validator
from pydantic_core import PydanticCustomError

from .common import NonEmptyText, Sha256, Uuid7
from .task6_common import Task6ContractModel

MANIFEST_DIGEST_ERROR: Final = "provenance_manifest_digest"
MANIFEST_DIGEST_MESSAGE: Final = "provenance manifest digest mismatch"
PROVENANCE_REF_ERROR: Final = "provenance_ref_unique"
PROVENANCE_REF_MESSAGE: Final = (
    "provenance ref_id values must be unique within each pin class"
)


class HashPin(Task6ContractModel):
    ref_id: NonEmptyText
    sha256: Sha256


class ProvenanceManifest(Task6ContractModel):
    source_run_id: Uuid7
    action_plan_sha256: Sha256
    research_intent_sha256: Sha256
    code_sha256: Sha256
    environment_sha256: Sha256
    runtime_adapter_id: NonEmptyText
    runtime_connection_id: Uuid7
    input_hashes: Annotated[tuple[HashPin, ...], Field(min_length=1)]
    execution_hashes: Annotated[tuple[HashPin, ...], Field(min_length=1)]
    output_hashes: Annotated[tuple[HashPin, ...], Field(min_length=1)]
    skill_hashes: Annotated[tuple[HashPin, ...], Field(min_length=1)]
    source_hashes: tuple[HashPin, ...]
    manifest_sha256: Sha256

    @model_validator(mode="after")
    def validate_manifest_digest(self) -> Self:
        pin_groups = (
            self.input_hashes,
            self.execution_hashes,
            self.output_hashes,
            self.skill_hashes,
            self.source_hashes,
        )
        if any(len({pin.ref_id for pin in pins}) != len(pins) for pins in pin_groups):
            raise PydanticCustomError(
                PROVENANCE_REF_ERROR,
                PROVENANCE_REF_MESSAGE,
            )
        if self.manifest_sha256 != provenance_manifest_sha256(self):
            raise PydanticCustomError(
                MANIFEST_DIGEST_ERROR,
                MANIFEST_DIGEST_MESSAGE,
            )
        return self


def provenance_manifest_sha256(manifest: ProvenanceManifest) -> str:
    payload = json.dumps(
        manifest.model_dump(mode="json", exclude={"manifest_sha256"}),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
