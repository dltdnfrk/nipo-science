from typing import Annotated, Literal

from pydantic import Field

from .common import NonEmptyText, Revision, Sha256, UtcTimestamp, Uuid7
from .task6_common import Task6ContractModel


class MeasurementUnit(Task6ContractModel):
    quantity: NonEmptyText
    ucum_code: NonEmptyText


class CalibrationContext(Task6ContractModel):
    method: NonEmptyText
    reference: NonEmptyText
    calibrated_at: UtcTimestamp
    calibration_sha256: Sha256


class ResearchContext(Task6ContractModel):
    purpose: Literal["research_only"]
    subject_scope: Literal["non_clinical"]
    description: NonEmptyText


class ScientificInput(Task6ContractModel):
    artifact_version_id: Uuid7
    kind: Literal["spectrum", "image", "table", "report"]
    units: Annotated[tuple[MeasurementUnit, ...], Field(min_length=1)]
    calibration: CalibrationContext
    context: ResearchContext


class ApprovedActionPlanRef(Task6ContractModel):
    action_plan_id: Uuid7
    version: Revision
    digest_sha256: Sha256
    approval_id: Uuid7
    approved_at: UtcTimestamp
    immutable: Literal[True]


class ApprovedExecutionRef(Task6ContractModel):
    execution_id: Uuid7
    action_plan_id: Uuid7
    approval_id: Uuid7
    status: Literal["completed"]
    execution_sha256: Sha256
