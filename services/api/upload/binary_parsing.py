"""Bounded structural parsing for PDF and raster inputs."""

import warnings
from io import BytesIO
from typing import Final

from PIL import Image, ImageSequence, UnidentifiedImageError
from pypdf import PdfReader
from pypdf.errors import PdfReadError

from .models import (
    DocumentPreview,
    ImagePreview,
    ScientificFormat,
    UploadError,
    UploadErrorCode,
)

PDF_PAGE_LIMIT: Final = 200
IMAGE_PIXEL_LIMIT: Final = 50_000_000
IMAGE_FORMATS: Final = {
    ScientificFormat.PNG: "PNG",
    ScientificFormat.JPEG: "JPEG",
    ScientificFormat.TIFF: "TIFF",
}


def parse_binary_preview(
    format_: ScientificFormat,
    payload: bytes,
    filename: str,
) -> DocumentPreview | ImagePreview:
    """Parse one complete document through its real format decoder."""
    if format_ is ScientificFormat.PDF:
        return _parse_pdf(payload, filename)
    expected = IMAGE_FORMATS.get(format_)
    if expected is None:
        raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename)
    return _parse_image(payload, filename, expected)


def _parse_pdf(payload: bytes, filename: str) -> DocumentPreview:
    try:
        reader = PdfReader(BytesIO(payload), strict=True)
        if reader.is_encrypted:
            raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename)
        page_count = len(reader.pages)
    except (PdfReadError, OSError, ValueError, TypeError, KeyError):
        raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename) from None
    if page_count <= 0:
        raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename)
    if page_count > PDF_PAGE_LIMIT:
        raise UploadError(UploadErrorCode.PDF_PAGE_LIMIT, filename)
    return DocumentPreview(page_count=page_count)


def _parse_image(payload: bytes, filename: str, expected: str) -> ImagePreview:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(payload)) as image:
                width, height = _validate_image_header(image, filename, expected)
                total_pixels = 0
                for frame in ImageSequence.Iterator(image):
                    frame_width, frame_height = frame.size
                    total_pixels += frame_width * frame_height
                    _enforce_total_pixels(total_pixels, filename)
                    _ = frame.load()
    except UploadError:
        raise
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        UnidentifiedImageError,
        OSError,
        SyntaxError,
        ValueError,
    ):
        raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename) from None
    return ImagePreview(width=width, height=height)


def _validate_image_header(
    image: Image.Image,
    filename: str,
    expected: str,
) -> tuple[int, int]:
    if image.format != expected:
        raise UploadError(UploadErrorCode.MEDIA_TYPE_MISMATCH, filename)
    width, height = image.size
    if width <= 0 or height <= 0:
        raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename)
    if width * height > IMAGE_PIXEL_LIMIT:
        raise UploadError(UploadErrorCode.IMAGE_PIXEL_LIMIT, filename)
    return width, height


def _enforce_total_pixels(total_pixels: int, filename: str) -> None:
    if total_pixels > IMAGE_PIXEL_LIMIT:
        raise UploadError(UploadErrorCode.IMAGE_PIXEL_LIMIT, filename)
