"""Bounded typed preview dispatch for accepted scientific formats."""

import json
from math import isfinite
from typing import Final, assert_never

from pydantic import JsonValue, TypeAdapter

from .binary_parsing import parse_binary_preview
from .models import (
    JsonPreview,
    ScientificFormat,
    ScientificPreview,
    TextPreview,
    UploadError,
    UploadErrorCode,
)
from .tabular import parse_tabular_preview
from .workbook import parse_workbook

MAX_PREVIEW_LINES: Final = 20
MAX_TEXT_CHARACTERS: Final = 4_096
MAX_PREVIEW_SOURCE_BYTES: Final = 1024 * 1024
JSON_ADAPTER: Final[TypeAdapter[JsonValue]] = TypeAdapter(JsonValue)


def parse_preview(
    format_: ScientificFormat,
    payload: bytes,
    filename: str,
) -> ScientificPreview:
    """Dispatch one trusted-format payload to a bounded parser."""
    match format_:
        case (
            ScientificFormat.PDF
            | ScientificFormat.PNG
            | ScientificFormat.JPEG
            | ScientificFormat.TIFF
        ):
            return parse_binary_preview(format_, payload, filename)
        case ScientificFormat.XLSX:
            return parse_workbook(payload, filename)
        case ScientificFormat.CSV:
            return parse_tabular_preview(payload, ",", filename)
        case ScientificFormat.TSV:
            return parse_tabular_preview(payload, "\t", filename)
        case ScientificFormat.JSON:
            return _json_preview(payload, filename)
        case ScientificFormat.TXT | ScientificFormat.MARKDOWN:
            return _text_preview(payload)
        case _:
            assert_never(format_)


def _text_preview(payload: bytes) -> TextPreview:
    source = payload[:MAX_PREVIEW_SOURCE_BYTES]
    text = source.decode("utf-8-sig", errors="ignore")
    all_lines = text.splitlines()
    lines = tuple(line[:MAX_TEXT_CHARACTERS] for line in all_lines[:MAX_PREVIEW_LINES])
    characters = sum(len(line) for line in lines)
    return TextPreview(
        lines=lines,
        truncated=(
            len(payload) > len(source)
            or len(all_lines) > MAX_PREVIEW_LINES
            or characters < len(text)
        ),
    )


def _json_preview(payload: bytes, filename: str) -> JsonPreview:
    try:
        parsed = JSON_ADAPTER.validate_json(payload)
    except ValueError:
        raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename) from None
    if not _json_numbers_are_finite(parsed):
        raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename)
    rendered = json.dumps(
        parsed,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )
    root_type = type(parsed).__name__
    return JsonPreview(
        root_type=root_type,
        excerpt=rendered[:MAX_TEXT_CHARACTERS],
        truncated=len(rendered) > MAX_TEXT_CHARACTERS,
    )


def _json_numbers_are_finite(value: JsonValue) -> bool:
    match value:
        case float() as number:
            return isfinite(number)
        case list() as items:
            return all(_json_numbers_are_finite(item) for item in items)
        case dict() as mapping:
            return all(_json_numbers_are_finite(item) for item in mapping.values())
        case None | str() | bool() | int():
            return True
        case _:
            assert_never(value)
