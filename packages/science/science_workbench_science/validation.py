"""Shared bounded validation for scientific metadata and numeric values."""

import math

from .inputs import InputMetadata
from .outputs import AnalysisIssue, OutcomeStatus

UNICODE_SURROGATE_START = 0xD800
UNICODE_SURROGATE_END = 0xDFFF
WAVELENGTH_UCUM_CODES = frozenset(
    {"km", "m", "dm", "cm", "mm", "um", "nm", "pm", "fm", "Ao"}
)


def round_fixed(value: float) -> float:
    """Round derived numeric output to six decimal places."""
    return round(value, 6)


def metadata_issues(
    metadata: InputMetadata,
    required_quantities: frozenset[str],
) -> tuple[AnalysisIssue, ...]:
    """Return explicit insufficiency reasons without inferring missing metadata."""
    issues: list[AnalysisIssue] = []
    if not metadata.units:
        issues.append(
            AnalysisIssue(code="units_required", message="Measurement units required")
        )
    else:
        quantities = tuple(unit.quantity for unit in metadata.units)
        if not required_quantities.issubset(quantities):
            issues.append(
                AnalysisIssue(
                    code="units_incomplete",
                    message="Required measurement quantities are not declared",
                )
            )
        if len(set(quantities)) != len(quantities):
            issues.append(
                AnalysisIssue(
                    code="units_ambiguous",
                    message="Measurement quantities must be unique",
                )
            )
        wavelength_codes = tuple(
            unit.ucum_code for unit in metadata.units if unit.quantity == "wavelength"
        )
        if any(code not in WAVELENGTH_UCUM_CODES for code in wavelength_codes):
            issues.append(
                AnalysisIssue(
                    code="wavelength_unit_incompatible",
                    message="Wavelength requires a supported UCUM length unit",
                )
            )
    if metadata.calibration is None:
        issues.append(
            AnalysisIssue(
                code="calibration_required",
                message="Calibration metadata required",
            )
        )
    text_values = tuple(
        value for unit in metadata.units for value in (unit.quantity, unit.ucum_code)
    )
    if metadata.calibration is not None:
        text_values = (
            *text_values,
            metadata.calibration.method,
            metadata.calibration.reference,
            metadata.calibration.calibration_sha256,
        )
    if any(not valid_unicode_scalar_text(value) for value in text_values):
        issues.append(
            AnalysisIssue(
                code="metadata_unicode_invalid",
                message="Scientific metadata contains invalid Unicode scalar data",
            )
        )
    if not metadata.lineage_version_ids:
        issues.append(
            AnalysisIssue(code="lineage_required", message="Source lineage required")
        )
    elif len(set(metadata.lineage_version_ids)) != len(metadata.lineage_version_ids):
        issues.append(
            AnalysisIssue(
                code="lineage_duplicate",
                message="Source lineage Version IDs must be unique",
            )
        )
    return tuple(issues)


def finite(values: tuple[float, ...]) -> bool:
    """Return whether every numeric observation is finite."""
    return all(math.isfinite(value) for value in values)


def valid_unicode_scalar_text(value: str) -> bool:
    """Return whether text excludes unpaired Unicode surrogate code points."""
    return all(
        not UNICODE_SURROGATE_START <= ord(character) <= UNICODE_SURROGATE_END
        for character in value
    )


def status_for_issues(
    issues: tuple[AnalysisIssue, ...],
    invalid: bool = False,
) -> OutcomeStatus:
    """Choose invalid over insufficient over valid deterministically."""
    if invalid:
        return OutcomeStatus.INVALID_DATA
    if issues:
        return OutcomeStatus.INSUFFICIENT_DATA
    return OutcomeStatus.VALID
