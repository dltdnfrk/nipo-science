"""Deterministic PNG rendering for normalized spectra."""

from io import BytesIO

from PIL import Image, ImageDraw

from .outputs import NormalizedSpectrum, OutcomeStatus

WIDTH = 640
HEIGHT = 360
MARGIN = 40
MINIMUM_RENDERED_SPECTRUM_POINTS = 2


def render_spectrum_png(spectrum: NormalizedSpectrum) -> bytes:
    """Render fixed-size axes, corrected signal, and peaks as PNG bytes."""
    if (
        spectrum.status is not OutcomeStatus.VALID
        or len(spectrum.wavelengths) < MINIMUM_RENDERED_SPECTRUM_POINTS
    ):
        return b""
    image = Image.new("RGB", (WIDTH, HEIGHT), "white")
    drawing = ImageDraw.Draw(image)
    drawing.line((MARGIN, MARGIN, MARGIN, HEIGHT - MARGIN), fill="#334155", width=2)
    drawing.line(
        (MARGIN, HEIGHT - MARGIN, WIDTH - MARGIN, HEIGHT - MARGIN),
        fill="#334155",
        width=2,
    )
    drawing.text(
        (WIDTH // 2 - 45, HEIGHT - 28),
        f"Wavelength ({_wavelength_unit(spectrum)})",
        fill="#334155",
    )
    drawing.text((MARGIN + 8, 16), "Corrected intensity", fill="#334155")
    x_min = spectrum.wavelengths[0]
    x_max = spectrum.wavelengths[-1]
    y_min = min(spectrum.corrected)
    y_max = max(spectrum.corrected)
    points = tuple(
        (
            round(
                MARGIN + _relative_position(value, x_min, x_max) * (WIDTH - 2 * MARGIN)
            ),
            round(
                HEIGHT
                - MARGIN
                - _relative_position(corrected, y_min, y_max) * (HEIGHT - 2 * MARGIN)
            ),
        )
        for value, corrected in zip(
            spectrum.wavelengths,
            spectrum.corrected,
            strict=True,
        )
    )
    drawing.line(points, fill="#2563eb", width=3, joint="curve")
    for peak in spectrum.peaks:
        x, y = points[peak.index]
        drawing.ellipse((x - 5, y - 5, x + 5, y + 5), fill="#dc2626")
        drawing.text(
            (x + 8, y - 16),
            f"{peak.wavelength:g} {_wavelength_unit(spectrum)}",
            fill="#991b1b",
        )
    buffer = BytesIO()
    image.save(buffer, format="PNG", optimize=False, compress_level=9)
    return buffer.getvalue()


def _wavelength_unit(spectrum: NormalizedSpectrum) -> str:
    return next(
        unit.ucum_code for unit in spectrum.units if unit.quantity == "wavelength"
    )


def _relative_position(value: float, lower: float, upper: float) -> float:
    if lower == upper:
        return 0.0
    scale = max(abs(lower), abs(upper))
    scaled_lower = lower / scale
    scaled_upper = upper / scale
    position = (value / scale - scaled_lower) / (scaled_upper - scaled_lower)
    return min(1.0, max(0.0, position))
