"""Passive-media validation before immutable Artifact creation."""

from __future__ import annotations

import csv
import io
import json
import re
import warnings
from decimal import Decimal, InvalidOperation
from typing import Final, Literal, TypeGuard, assert_never, cast

from PIL import Image, UnidentifiedImageError

from services.api.product_artifact_types import (
    ArtifactVersionDraft,
    UnsupportedArtifactMediaError,
)
from services.api.product_pdf_validation import validate_passive_pdf

_MAX_CONTENT_BYTES: Final = 1_048_576
_MAX_CSV_COLUMNS: Final = 256
type ArtifactMediaType = Literal[
    "application/json", "application/pdf", "image/png", "text/csv", "text/markdown"
]
_NAME: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}[A-Za-z0-9]$")
_EXTENSION: Final = {
    "application/json": ".json",
    "application/pdf": ".pdf",
    "image/png": ".png",
    "text/csv": ".csv",
    "text/markdown": ".md",
}
_ACTIVE_MARKERS: Final = (
    b"<!doctype",
    b"<html",
    b"<iframe",
    b"<script",
    b"<svg",
    b"javascript:",
)
_MAX_PREVIEW_PIXELS: Final = 50_000_000


def validate_artifact_draft(draft: ArtifactVersionDraft) -> bytes:
    """Return an immutable copy after filename, media, and byte validation."""
    if not _is_artifact_media_type(draft.media_type):
        raise UnsupportedArtifactMediaError(draft.media_type)
    expected_extension = _EXTENSION.get(draft.media_type)
    if expected_extension is None or not _valid_name(draft.name, expected_extension):
        raise UnsupportedArtifactMediaError(draft.media_type)
    try:
        content = bytes(draft.content)
    except (TypeError, ValueError) as error:
        raise UnsupportedArtifactMediaError(draft.media_type) from error
    if not content or len(content) > _MAX_CONTENT_BYTES:
        raise UnsupportedArtifactMediaError(draft.media_type)
    media_type = draft.media_type
    match media_type:
        case "text/csv":
            _validate_csv(content, draft.media_type)
        case "image/png":
            _validate_png(content, draft.media_type)
        case "application/pdf":
            validate_passive_pdf(content, draft.media_type)
        case "application/json" | "text/markdown":
            _validate_passive_text(content, draft.media_type)
        case _:
            assert_never(media_type)
    return content


def _valid_name(name: str, extension: str) -> bool:
    return (
        _NAME.fullmatch(name) is not None
        and ".." not in name
        and name.lower().endswith(extension)
    )


def _is_artifact_media_type(value: str) -> TypeGuard[ArtifactMediaType]:
    return value in _EXTENSION


def _validate_csv(content: bytes, media_type: str) -> None:
    lowered = content[:8192].lower()
    if b"\x00" in content or any(marker in lowered for marker in _ACTIVE_MARKERS):
        raise UnsupportedArtifactMediaError(media_type)
    try:
        text = content.decode("utf-8", errors="strict")
        rows = list(csv.reader(io.StringIO(text)))
    except (csv.Error, UnicodeDecodeError) as error:
        raise UnsupportedArtifactMediaError(media_type) from error
    if (
        not rows
        or any(len(row) > _MAX_CSV_COLUMNS for row in rows)
        or any(_is_formula_cell(cell) for row in rows for cell in row)
    ):
        raise UnsupportedArtifactMediaError(media_type)


def _validate_passive_text(content: bytes, media_type: str) -> None:
    lowered = content[:8192].lower()
    if b"\x00" in content or any(marker in lowered for marker in _ACTIVE_MARKERS):
        raise UnsupportedArtifactMediaError(media_type)
    try:
        text = content.decode("utf-8", errors="strict")
        if media_type == "application/json":
            _ = cast("object", json.loads(text))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise UnsupportedArtifactMediaError(media_type) from error


def _is_formula_cell(value: str) -> bool:
    stripped = value.lstrip()
    if not stripped or stripped[0] not in "=+-@":
        return False
    if stripped[0] in "=@":
        return True
    try:
        _ = Decimal(stripped)
    except InvalidOperation:
        return True
    return False


def _validate_png(content: bytes, media_type: str) -> None:
    if not content.startswith(b"\x89PNG\r\n\x1a\n") or b"IEND" not in content[-32:]:
        raise UnsupportedArtifactMediaError(media_type)
    image_format = ""
    width = 0
    height = 0
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(content)) as image:
                width, height = image.size
                image_format = image.format or ""
                image.verify()
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        UnidentifiedImageError,
        OSError,
        SyntaxError,
        ValueError,
    ) as error:
        raise UnsupportedArtifactMediaError(media_type) from error
    if (
        image_format != "PNG"
        or width <= 0
        or height <= 0
        or width * height > _MAX_PREVIEW_PIXELS
    ):
        raise UnsupportedArtifactMediaError(media_type)
