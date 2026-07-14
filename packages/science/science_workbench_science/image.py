"""Deterministic RGB statistics and connected-region extraction."""

import math
import statistics
from collections import deque

from .inputs import ImageInput
from .outputs import AnalysisIssue, ImageRegion, NormalizedImage, OutcomeStatus
from .validation import metadata_issues, round_fixed

RGB_CHANNEL_COUNT = 3
MAX_RGB_CHANNEL_VALUE = 255
MAX_IMAGE_PIXELS = 50_000_000


def normalize_image(source: ImageInput) -> NormalizedImage:
    """Extract calibrated color regions with four-neighbor connectivity."""
    failures = metadata_issues(source.metadata, frozenset({"color"}))
    expected_pixels = source.width * source.height
    missing_fraction = (
        round_fixed(
            min(1.0, abs(expected_pixels - len(source.pixels)) / expected_pixels)
        )
        if expected_pixels > 0
        else 1.0
    )
    pixels_valid = (
        source.width > 0
        and source.height > 0
        and source.width * source.height <= MAX_IMAGE_PIXELS
        and len(source.pixels) == source.width * source.height
        and math.isfinite(source.region_threshold)
        and source.region_threshold >= 0
        and all(
            all(0 <= channel <= MAX_RGB_CHANNEL_VALUE for channel in pixel)
            for pixel in source.pixels
        )
    )
    if not pixels_valid:
        issue = AnalysisIssue(
            code="image_shape_invalid",
            message="Image dimensions, RGB pixels, or threshold are invalid",
        )
        return NormalizedImage(
            status=OutcomeStatus.INVALID_DATA,
            width=source.width,
            height=source.height,
            mean_rgb=None,
            mean_luminance=None,
            missing_fraction=missing_fraction,
            regions=(),
            units=source.metadata.units,
            calibration=source.metadata.calibration,
            lineage_version_ids=source.metadata.lineage_version_ids,
            issues=(*failures, issue),
        )
    mean_rgb = _mean_rgb(source.pixels)
    luminance = round_fixed(
        statistics.fmean(
            0.2126 * red + 0.7152 * green + 0.0722 * blue
            for red, green, blue in source.pixels
        )
    )
    background = tuple(
        statistics.median(pixel[channel] for pixel in source.pixels)
        for channel in range(RGB_CHANNEL_COUNT)
    )
    signal_indices = {
        index
        for index, pixel in enumerate(source.pixels)
        if math.dist(pixel, background) >= source.region_threshold
    }
    regions = _connected_regions(source, signal_indices)
    return NormalizedImage(
        status=(OutcomeStatus.INSUFFICIENT_DATA if failures else OutcomeStatus.VALID),
        width=source.width,
        height=source.height,
        mean_rgb=mean_rgb,
        mean_luminance=luminance,
        missing_fraction=0.0,
        regions=regions,
        units=source.metadata.units,
        calibration=source.metadata.calibration,
        lineage_version_ids=source.metadata.lineage_version_ids,
        issues=failures,
    )


def _connected_regions(
    source: ImageInput,
    signal_indices: set[int],
) -> tuple[ImageRegion, ...]:
    pending = set(signal_indices)
    regions: list[ImageRegion] = []
    while pending:
        start = min(pending)
        pending.remove(start)
        queue = deque((start,))
        component: list[int] = []
        while queue:
            index = queue.popleft()
            component.append(index)
            for neighbor in _neighbors(index, source.width, source.height):
                if neighbor in pending:
                    pending.remove(neighbor)
                    queue.append(neighbor)
        xs = tuple(index % source.width for index in component)
        ys = tuple(index // source.width for index in component)
        pixels = tuple(source.pixels[index] for index in component)
        regions.append(
            ImageRegion(
                bounds=(min(xs), min(ys), max(xs), max(ys)),
                pixel_count=len(component),
                mean_rgb=_mean_rgb(pixels),
            )
        )
    return tuple(regions)


def _neighbors(index: int, width: int, height: int) -> tuple[int, ...]:
    x = index % width
    y = index // width
    values: list[int] = []
    if x > 0:
        values.append(index - 1)
    if x + 1 < width:
        values.append(index + 1)
    if y > 0:
        values.append(index - width)
    if y + 1 < height:
        values.append(index + width)
    return tuple(values)


def _mean_rgb(
    pixels: tuple[tuple[int, int, int], ...],
) -> tuple[float, float, float]:
    return (
        round_fixed(statistics.fmean(pixel[0] for pixel in pixels)),
        round_fixed(statistics.fmean(pixel[1] for pixel in pixels)),
        round_fixed(statistics.fmean(pixel[2] for pixel in pixels)),
    )
