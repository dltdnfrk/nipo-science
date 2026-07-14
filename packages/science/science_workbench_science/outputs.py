"""Immutable outputs from deterministic scientific transforms."""

from enum import StrEnum
from typing import ClassVar, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from .inputs import CalibrationMetadata, MeasurementUnit


class ScienceOutputModel(BaseModel):
    """Freeze deterministic outputs and serialize bytes as base64."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
        ser_json_bytes="base64",
        val_json_bytes="base64",
    )


class OutcomeStatus(StrEnum):
    """Closed scientific processing outcomes."""

    VALID = "valid"
    INSUFFICIENT_DATA = "insufficient_data"
    INVALID_DATA = "invalid_data"


class AnalysisIssue(ScienceOutputModel):
    """Expose one stable bounded failure reason."""

    code: str
    message: str


class ColumnStatistics(ScienceOutputModel):
    """Summarize one numeric column without imputing missing values."""

    column: str
    count: int
    missing_count: int
    minimum: float | None
    maximum: float | None
    mean: float | None
    median: float | None
    population_stddev: float | None


class NormalizedTable(ScienceOutputModel):
    """Return normalized table values, units, missingness, and lineage."""

    status: OutcomeStatus
    columns: tuple[str, ...]
    rows: tuple[tuple[float | None, ...], ...]
    units: tuple[MeasurementUnit, ...]
    calibration: CalibrationMetadata | None
    missing_fraction: tuple[float, ...]
    statistics: tuple[ColumnStatistics, ...]
    lineage_version_ids: tuple[UUID, ...]
    issues: tuple[AnalysisIssue, ...]


class SpectrumPeak(ScienceOutputModel):
    """Identify one deterministic local maximum in corrected intensity."""

    index: int
    wavelength: float
    corrected_intensity: float
    prominence: float


class NormalizedSpectrum(ScienceOutputModel):
    """Return calibrated spectrum baseline, correction, peaks, and lineage."""

    status: OutcomeStatus
    wavelengths: tuple[float, ...]
    intensities: tuple[float | None, ...]
    missing_fraction: float
    baseline: tuple[float, ...]
    corrected: tuple[float, ...]
    peaks: tuple[SpectrumPeak, ...]
    units: tuple[MeasurementUnit, ...]
    calibration: CalibrationMetadata | None
    lineage_version_ids: tuple[UUID, ...]
    issues: tuple[AnalysisIssue, ...]


class ImageRegion(ScienceOutputModel):
    """Describe one four-connected calibrated color region."""

    bounds: tuple[int, int, int, int]
    pixel_count: int
    mean_rgb: tuple[float, float, float]


class NormalizedImage(ScienceOutputModel):
    """Return deterministic color statistics and connected regions."""

    status: OutcomeStatus
    width: int
    height: int
    mean_rgb: tuple[float, float, float] | None
    mean_luminance: float | None
    missing_fraction: float
    regions: tuple[ImageRegion, ...]
    units: tuple[MeasurementUnit, ...]
    calibration: CalibrationMetadata | None
    lineage_version_ids: tuple[UUID, ...]
    issues: tuple[AnalysisIssue, ...]


class NormalizedReport(ScienceOutputModel):
    """Return normalized paragraphs, word count, metadata, and lineage."""

    status: OutcomeStatus
    text: str
    paragraphs: tuple[str, ...]
    word_count: int
    missing_fraction: float
    units: tuple[MeasurementUnit, ...]
    calibration: CalibrationMetadata | None
    lineage_version_ids: tuple[UUID, ...]
    issues: tuple[AnalysisIssue, ...]


class HypothesisBranch(StrEnum):
    """Closed GS04 explanatory branches."""

    MOLECULAR = "molecular"
    OPTICAL = "optical"
    EXPERIMENTAL_ARTIFACT = "experimental_artifact"


class HypothesisState(StrEnum):
    """Bound branch support without asserting causality."""

    OBSERVED = "observed"
    PLAUSIBLE = "plausible"
    INSUFFICIENT = "insufficient"


class HypothesisRecord(ScienceOutputModel):
    """Expose one bounded branch observation and control check."""

    branch: HypothesisBranch
    state: HypothesisState
    observation: str
    control: str
    limitation: str
    conclusion_scope: Literal["non_diagnostic"]


class EvidenceRecord(ScienceOutputModel):
    """Bind one branch claim to immutable source lineage and checksum."""

    claim_id: str
    branch: HypothesisBranch
    evidence_kind: Literal["derived_observation", "insufficient"]
    source_version_ids: tuple[UUID, ...]
    supporting_sha256: str
    locator: str


class ProbeAnalysis(ScienceOutputModel):
    """Bundle normalized modalities, branches, evidence, and deterministic files."""

    status: OutcomeStatus
    table: NormalizedTable | None
    spectrum: NormalizedSpectrum | None
    image: NormalizedImage | None
    report: NormalizedReport | None
    hypotheses: tuple[HypothesisRecord, ...]
    evidence: tuple[EvidenceRecord, ...]
    spectrum_plot_png: bytes | None
    hypothesis_table_csv: bytes
    issues: tuple[AnalysisIssue, ...]
    limitations: tuple[str, ...]
