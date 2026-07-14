from datetime import UTC, datetime
from uuid import UUID

from science_workbench_science import (
    CalibrationMetadata,
    ImageInput,
    InputMetadata,
    MeasurementUnit,
    ProbeInput,
    ReportInput,
    SpectrumInput,
    TableInput,
)

VERSION_TABLE = UUID("018f47a0-7b9c-7a10-8def-0123456789ab")
VERSION_SPECTRUM = UUID("018f47a0-7b9c-7a11-8def-0123456789ab")
VERSION_IMAGE = UUID("018f47a0-7b9c-7a12-8def-0123456789ab")
VERSION_REPORT = UUID("018f47a0-7b9c-7a13-8def-0123456789ab")
CALIBRATION_SHA = "a" * 64


def calibration() -> CalibrationMetadata:
    return CalibrationMetadata(
        method="reference-standard",
        reference="probe-calibration-v1",
        calibrated_at=datetime(2026, 7, 13, tzinfo=UTC),
        calibration_sha256=CALIBRATION_SHA,
    )


def metadata(
    version_id: UUID,
    units: tuple[MeasurementUnit, ...],
) -> InputMetadata:
    return InputMetadata(
        units=units,
        calibration=calibration(),
        lineage_version_ids=(version_id,),
        research_only=True,
        non_clinical=True,
    )


def table_input() -> TableInput:
    return TableInput(
        columns=("sample", "signal"),
        rows=((1.0, 10.0), (2.0, None), (3.0, 14.0)),
        metadata=metadata(
            VERSION_TABLE,
            (
                MeasurementUnit(quantity="sample", ucum_code="1"),
                MeasurementUnit(quantity="signal", ucum_code="1"),
            ),
        ),
    )


def spectrum_input() -> SpectrumInput:
    return SpectrumInput(
        wavelengths=(400.0, 450.0, 500.0, 550.0, 600.0),
        intensities=(10.0, 12.0, 30.0, 14.0, 12.0),
        metadata=metadata(
            VERSION_SPECTRUM,
            (
                MeasurementUnit(quantity="wavelength", ucum_code="nm"),
                MeasurementUnit(quantity="intensity", ucum_code="1"),
            ),
        ),
    )


def image_input() -> ImageInput:
    background = (10, 10, 10)
    signal = (200, 20, 20)
    return ImageInput(
        width=4,
        height=3,
        pixels=(
            background,
            background,
            background,
            background,
            background,
            signal,
            signal,
            background,
            background,
            background,
            background,
            background,
        ),
        region_threshold=48.0,
        metadata=metadata(
            VERSION_IMAGE,
            (MeasurementUnit(quantity="color", ucum_code="1"),),
        ),
    )


def report_input() -> ReportInput:
    return ReportInput(
        text="  Probe  report\n\n Signal increased at 500 nm.  ",
        metadata=metadata(
            VERSION_REPORT,
            (MeasurementUnit(quantity="document", ucum_code="1"),),
        ),
    )


def probe_input() -> ProbeInput:
    return ProbeInput(
        table=table_input(),
        spectrum=spectrum_input(),
        image=image_input(),
        report=report_input(),
    )
