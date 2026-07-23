"""Strict research-only inputs for deterministic scientific transforms."""

from datetime import datetime, timedelta
from typing import Annotated, ClassVar, Literal
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

UUID7_VERSION = 7
UUID7_ERROR = "uuid7"
UTC_ERROR = "utc_timestamp"


def _require_uuid7(value: UUID) -> UUID:
    if value.version != UUID7_VERSION:
        raise ValueError(UUID7_ERROR)
    return value


def _require_utc(value: datetime) -> datetime:
    if value.utcoffset() != timedelta(0):
        raise ValueError(UTC_ERROR)
    return value


Uuid7 = Annotated[UUID, AfterValidator(_require_uuid7)]
UtcTimestamp = Annotated[datetime, AfterValidator(_require_utc)]


class ScienceInputModel(BaseModel):
    """Freeze and reject unknown scientific input fields."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )


class MeasurementUnit(ScienceInputModel):
    """Bind one measured quantity to an explicit UCUM code."""

    quantity: str = Field(min_length=1, max_length=100)
    ucum_code: str = Field(min_length=1, max_length=50)


class CalibrationMetadata(ScienceInputModel):
    """Pin the method, reference, and checksum used for calibration."""

    method: str = Field(min_length=1, max_length=200)
    reference: str = Field(min_length=1, max_length=500)
    calibrated_at: UtcTimestamp
    calibration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class InputMetadata(ScienceInputModel):
    """Carry units, calibration, immutable lineage, and research scope."""

    units: tuple[MeasurementUnit, ...] = ()
    calibration: CalibrationMetadata | None = None
    lineage_version_ids: tuple[Uuid7, ...]
    research_only: Literal[True]
    non_clinical: Literal[True]


class TableInput(ScienceInputModel):
    """Represent a bounded numeric table with explicit missing cells."""

    columns: tuple[str, ...]
    rows: tuple[tuple[float | None, ...], ...]
    metadata: InputMetadata


class SpectrumInput(ScienceInputModel):
    """Represent paired wavelength and intensity observations."""

    wavelengths: tuple[float, ...]
    intensities: tuple[float | None, ...]
    metadata: InputMetadata


class ImageInput(ScienceInputModel):
    """Represent row-major RGB pixels and a calibrated region threshold."""

    width: int
    height: int
    pixels: tuple[tuple[int, int, int], ...]
    region_threshold: float
    metadata: InputMetadata


class ReportInput(ScienceInputModel):
    """Represent bounded report text with scientific source metadata."""

    text: str
    metadata: InputMetadata


class ProbeInput(ScienceInputModel):
    """Collect optional modalities for one non-diagnostic probe analysis."""

    table: TableInput | None = None
    spectrum: SpectrumInput | None = None
    image: ImageInput | None = None
    report: ReportInput | None = None
