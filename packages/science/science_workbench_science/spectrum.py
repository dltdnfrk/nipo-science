"""Deterministic spectrum baseline correction and peak extraction."""

from .inputs import SpectrumInput
from .outputs import AnalysisIssue, NormalizedSpectrum, OutcomeStatus, SpectrumPeak
from .validation import finite, metadata_issues, round_fixed

MINIMUM_ANALYSIS_SAMPLES = 3
MAXIMUM_SPECTRUM_POINTS = 1_000_000


def normalize_spectrum(source: SpectrumInput) -> NormalizedSpectrum:
    """Correct a linear endpoint baseline and extract positive local peaks."""
    failures = metadata_issues(
        source.metadata,
        frozenset({"wavelength", "intensity"}),
    )
    missing_count = sum(value is None for value in source.intensities)
    missing_fraction = (
        round_fixed(missing_count / len(source.intensities))
        if source.intensities
        else 1.0
    )
    shape_valid = (
        len(source.wavelengths) >= MINIMUM_ANALYSIS_SAMPLES
        and len(source.wavelengths) <= MAXIMUM_SPECTRUM_POINTS
        and len(source.wavelengths) == len(source.intensities)
        and finite(source.wavelengths)
        and finite(tuple(value for value in source.intensities if value is not None))
        and all(
            left < right
            for left, right in zip(
                source.wavelengths,
                source.wavelengths[1:],
                strict=False,
            )
        )
    )
    if not shape_valid:
        issue = AnalysisIssue(
            code="spectrum_shape_invalid",
            message="Spectrum requires paired finite increasing observations",
        )
        return _invalid_spectrum(source, failures, missing_fraction, issue)
    if missing_count:
        issue = AnalysisIssue(
            code="spectrum_missing_values",
            message="Spectrum contains missing intensity observations",
        )
        return NormalizedSpectrum(
            status=OutcomeStatus.INSUFFICIENT_DATA,
            wavelengths=source.wavelengths,
            intensities=source.intensities,
            missing_fraction=missing_fraction,
            baseline=(),
            corrected=(),
            peaks=(),
            units=source.metadata.units,
            calibration=source.metadata.calibration,
            lineage_version_ids=source.metadata.lineage_version_ids,
            issues=(*failures, issue),
        )
    intensities = tuple(value for value in source.intensities if value is not None)
    first_x = next(iter(source.wavelengths))
    span = next(reversed(source.wavelengths)) - first_x
    first_y = next(iter(intensities))
    delta_y = next(reversed(intensities)) - first_y
    if not finite((span, delta_y)):
        return _numeric_invalid(source, failures, missing_fraction)
    raw_baseline = tuple(
        first_y + delta_y * ((wavelength - first_x) / span)
        for wavelength in source.wavelengths
    )
    raw_corrected = tuple(
        intensity - base
        for intensity, base in zip(intensities, raw_baseline, strict=True)
    )
    if not finite((*raw_baseline, *raw_corrected)):
        return _numeric_invalid(source, failures, missing_fraction)
    baseline = tuple(round_fixed(value) for value in raw_baseline)
    corrected = tuple(round_fixed(value) for value in raw_corrected)
    prominences = tuple(
        corrected[index] - max(corrected[index - 1], corrected[index + 1])
        for index in range(1, len(corrected) - 1)
    )
    if not finite(prominences):
        return _numeric_invalid(source, failures, missing_fraction)
    peaks = tuple(
        SpectrumPeak(
            index=index,
            wavelength=source.wavelengths[index],
            corrected_intensity=corrected[index],
            prominence=round_fixed(prominences[index - 1]),
        )
        for index in range(1, len(corrected) - 1)
        if corrected[index] > corrected[index - 1]
        and corrected[index] > corrected[index + 1]
        and prominences[index - 1] > 0
    )
    return NormalizedSpectrum(
        status=(OutcomeStatus.INSUFFICIENT_DATA if failures else OutcomeStatus.VALID),
        wavelengths=source.wavelengths,
        intensities=source.intensities,
        missing_fraction=missing_fraction,
        baseline=baseline,
        corrected=corrected,
        peaks=peaks,
        units=source.metadata.units,
        calibration=source.metadata.calibration,
        lineage_version_ids=source.metadata.lineage_version_ids,
        issues=failures,
    )


def _numeric_invalid(
    source: SpectrumInput,
    failures: tuple[AnalysisIssue, ...],
    missing_fraction: float,
) -> NormalizedSpectrum:
    issue = AnalysisIssue(
        code="spectrum_numeric_invalid",
        message="Spectrum arithmetic exceeds the finite processing range",
    )
    return _invalid_spectrum(source, failures, missing_fraction, issue)


def _invalid_spectrum(
    source: SpectrumInput,
    failures: tuple[AnalysisIssue, ...],
    missing_fraction: float,
    issue: AnalysisIssue,
) -> NormalizedSpectrum:
    return NormalizedSpectrum(
        status=OutcomeStatus.INVALID_DATA,
        wavelengths=source.wavelengths,
        intensities=source.intensities,
        missing_fraction=missing_fraction,
        baseline=(),
        corrected=(),
        peaks=(),
        units=source.metadata.units,
        calibration=source.metadata.calibration,
        lineage_version_ids=source.metadata.lineage_version_ids,
        issues=(*failures, issue),
    )
