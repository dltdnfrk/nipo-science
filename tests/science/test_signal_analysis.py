import hashlib
from io import BytesIO

import pytest
from PIL import Image
from pydantic import ValidationError

from science_workbench_science import (
    ImageInput,
    MeasurementUnit,
    OutcomeStatus,
    ProbeInput,
    analyze_probe,
    normalize_image,
    normalize_spectrum,
    render_spectrum_png,
)

from .fixtures import image_input, spectrum_input


def test_spectrum_baseline_and_peak_extraction_have_fixed_numeric_output() -> None:
    normalized = normalize_spectrum(spectrum_input())

    assert normalized.status is OutcomeStatus.VALID
    assert normalized.baseline == (10.0, 10.5, 11.0, 11.5, 12.0)
    assert normalized.corrected == (0.0, 1.5, 19.0, 2.5, 0.0)
    assert normalized.missing_fraction == 0.0
    assert len(normalized.peaks) == 1
    assert normalized.peaks[0].wavelength == 500.0
    assert normalized.peaks[0].corrected_intensity == 19.0
    assert normalized.peaks[0].prominence == 16.5


def test_image_color_and_connected_region_extraction_are_fixed() -> None:
    normalized = normalize_image(image_input())

    assert normalized.status is OutcomeStatus.VALID
    assert normalized.mean_rgb == (41.666667, 11.666667, 11.666667)
    assert normalized.mean_luminance == 18.044667
    assert normalized.missing_fraction == 0.0
    assert len(normalized.regions) == 1
    assert normalized.regions[0].bounds == (1, 1, 2, 1)
    assert normalized.regions[0].pixel_count == 2
    assert normalized.regions[0].mean_rgb == (200.0, 20.0, 20.0)


def test_image_region_threshold_is_required_at_the_input_boundary() -> None:
    payload = image_input().model_dump()
    del payload["region_threshold"]

    with pytest.raises(ValidationError, match="region_threshold"):
        _ = ImageInput.model_validate(payload)


def test_explicit_image_threshold_controls_region_segmentation() -> None:
    source = image_input()

    segmented = normalize_image(
        source.model_copy(update={"region_threshold": 48.0})
    )
    suppressed = normalize_image(
        source.model_copy(update={"region_threshold": 200.0})
    )

    assert len(segmented.regions) == 1
    assert suppressed.regions == ()


def test_spectrum_plot_is_byte_deterministic_across_two_runs() -> None:
    normalized = normalize_spectrum(spectrum_input())
    first = render_spectrum_png(normalized)
    second = render_spectrum_png(normalized)

    assert first == second
    assert first.startswith(b"\x89PNG\r\n\x1a\n")
    assert hashlib.sha256(second).hexdigest() == hashlib.sha256(first).hexdigest()

    # Platform-independent content invariants instead of a compressed-byte pin:
    # freetype (text antialiasing) and zlib (IDAT compression) versions differ
    # across OSes, so exact byte length/sha only ever held on one platform.
    # Determinism within the environment is asserted above; the rendered
    # structure is asserted on decoded pixels.
    image = Image.open(BytesIO(first))
    assert image.size == (640, 360)
    assert image.mode == "RGB"
    colors = {color for _, color in image.getcolors(maxcolors=100_000) or ()}
    assert (0x33, 0x41, 0x55) in colors  # axes
    assert (0x25, 0x63, 0xEB) in colors  # corrected-signal curve
    assert (0xDC, 0x26, 0x26) in colors  # peak markers


def test_unrepresentable_spectrum_arithmetic_is_explicit_invalid_data() -> None:
    spectrum = spectrum_input().model_copy(
        update={
            "wavelengths": (-1e308, 0.0, 1e308),
            "intensities": (1.0, 2.0, 3.0),
        }
    )

    result = analyze_probe(ProbeInput(spectrum=spectrum))

    assert result.status is OutcomeStatus.INVALID_DATA
    assert {issue.code for issue in result.issues} == {"spectrum_numeric_invalid"}
    assert result.spectrum_plot_png is None


def test_declared_wavelength_unit_is_used_in_claim_and_plot() -> None:
    spectrum = spectrum_input()
    units = (
        MeasurementUnit(quantity="wavelength", ucum_code="um"),
        spectrum.metadata.units[1],
    )
    micrometre_input = spectrum.model_copy(
        update={"metadata": spectrum.metadata.model_copy(update={"units": units})}
    )

    result = analyze_probe(ProbeInput(spectrum=micrometre_input))
    nanometre_plot = render_spectrum_png(normalize_spectrum(spectrum))

    assert result.status is OutcomeStatus.VALID
    assert "500 um" in result.hypotheses[0].observation
    assert result.spectrum_plot_png is not None
    assert result.spectrum_plot_png != nanometre_plot


def test_extreme_finite_corrected_range_renders_without_plot_exception() -> None:
    spectrum = spectrum_input().model_copy(
        update={"intensities": (0.0, -1e308, 0.0, 1e308, 0.0)}
    )

    result = analyze_probe(ProbeInput(spectrum=spectrum))

    assert result.status is OutcomeStatus.VALID
    assert result.spectrum_plot_png is not None
    assert result.spectrum_plot_png.startswith(b"\x89PNG\r\n\x1a\n")


def test_incompatible_wavelength_dimension_is_bounded_insufficient_data() -> None:
    spectrum = spectrum_input()
    units = (
        MeasurementUnit(quantity="wavelength", ucum_code="s"),
        spectrum.metadata.units[1],
    )
    incompatible = spectrum.model_copy(
        update={"metadata": spectrum.metadata.model_copy(update={"units": units})}
    )

    result = analyze_probe(ProbeInput(spectrum=incompatible))

    assert result.status is OutcomeStatus.INSUFFICIENT_DATA
    assert {issue.code for issue in result.issues} == {"wavelength_unit_incompatible"}
    assert result.spectrum_plot_png is None
    assert all(item.state == "insufficient" for item in result.hypotheses)
