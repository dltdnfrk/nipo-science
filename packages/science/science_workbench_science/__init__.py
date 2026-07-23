"""Deterministic non-diagnostic scientific normalization and dry-lab primitives."""

from .analysis import analyze_probe
from .hypotheses import BRANCH_ORDER
from .image import normalize_image
from .inputs import (
    CalibrationMetadata,
    ImageInput,
    InputMetadata,
    MeasurementUnit,
    ProbeInput,
    ReportInput,
    SpectrumInput,
    TableInput,
)
from .normalization import normalize_report, normalize_table
from .outputs import (
    AnalysisIssue,
    ColumnStatistics,
    EvidenceRecord,
    HypothesisBranch,
    HypothesisRecord,
    HypothesisState,
    ImageRegion,
    NormalizedImage,
    NormalizedReport,
    NormalizedSpectrum,
    NormalizedTable,
    OutcomeStatus,
    ProbeAnalysis,
    SpectrumPeak,
)
from .plots import render_spectrum_png
from .research_intent import DataOrigin, ResearchIntent, ResearchMode
from .spectrum import normalize_spectrum

__all__ = [
    "BRANCH_ORDER",
    "AnalysisIssue",
    "CalibrationMetadata",
    "ColumnStatistics",
    "DataOrigin",
    "EvidenceRecord",
    "HypothesisBranch",
    "HypothesisRecord",
    "HypothesisState",
    "ImageInput",
    "ImageRegion",
    "InputMetadata",
    "MeasurementUnit",
    "NormalizedImage",
    "NormalizedReport",
    "NormalizedSpectrum",
    "NormalizedTable",
    "OutcomeStatus",
    "ProbeAnalysis",
    "ProbeInput",
    "ReportInput",
    "ResearchIntent",
    "ResearchMode",
    "SpectrumInput",
    "SpectrumPeak",
    "TableInput",
    "analyze_probe",
    "normalize_image",
    "normalize_report",
    "normalize_spectrum",
    "normalize_table",
    "render_spectrum_png",
]
