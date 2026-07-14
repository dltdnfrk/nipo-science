from typing import Annotated, Final, Literal

from pydantic import Field

from .common import NonEmptyText, Sha256, UtcTimestamp, Uuid7
from .task6_common import Task6ContractModel

EVIDENCE_LEDGER_COLUMNS: Final = (
    "claim_id",
    "claim_text",
    "evidence_kind",
    "source_id",
    "artifact_version_id",
    "execution_id",
    "supporting_sha256",
    "locator",
    "retrieved_at",
)


class EvidenceLedgerRow(Task6ContractModel):
    claim_id: NonEmptyText
    claim_text: NonEmptyText
    evidence_kind: Literal["input", "execution_output", "literature_source"]
    source_id: NonEmptyText
    artifact_version_id: Uuid7
    execution_id: Uuid7
    supporting_sha256: Sha256
    locator: NonEmptyText
    retrieved_at: UtcTimestamp


class EvidenceLedger(Task6ContractModel):
    columns: tuple[
        Literal["claim_id"],
        Literal["claim_text"],
        Literal["evidence_kind"],
        Literal["source_id"],
        Literal["artifact_version_id"],
        Literal["execution_id"],
        Literal["supporting_sha256"],
        Literal["locator"],
        Literal["retrieved_at"],
    ]
    rows: Annotated[tuple[EvidenceLedgerRow, ...], Field(min_length=1)]
    json_artifact_version_id: Uuid7
    csv_artifact_version_id: Uuid7
