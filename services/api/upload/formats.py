"""Filename, media-type, magic-byte, and polyglot validation."""

import re
import unicodedata
from codecs import getincrementaldecoder
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final, assert_never

from .models import ScientificFormat, UploadError, UploadErrorCode


@dataclass(frozen=True, slots=True)
class FormatRule:
    """Canonical extension and MIME for one accepted format."""

    format: ScientificFormat
    media_type: str


FORMAT_RULES: Final[dict[str, FormatRule]] = {
    ".pdf": FormatRule(ScientificFormat.PDF, "application/pdf"),
    ".png": FormatRule(ScientificFormat.PNG, "image/png"),
    ".jpg": FormatRule(ScientificFormat.JPEG, "image/jpeg"),
    ".jpeg": FormatRule(ScientificFormat.JPEG, "image/jpeg"),
    ".tif": FormatRule(ScientificFormat.TIFF, "image/tiff"),
    ".tiff": FormatRule(ScientificFormat.TIFF, "image/tiff"),
    ".csv": FormatRule(ScientificFormat.CSV, "text/csv"),
    ".tsv": FormatRule(ScientificFormat.TSV, "text/tab-separated-values"),
    ".json": FormatRule(ScientificFormat.JSON, "application/json"),
    ".xlsx": FormatRule(
        ScientificFormat.XLSX,
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ),
    ".txt": FormatRule(ScientificFormat.TXT, "text/plain"),
    ".md": FormatRule(ScientificFormat.MARKDOWN, "text/markdown"),
}
ARCHIVE_MAGICS: Final = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\x1f\x8b\x08",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07",
)
CONTROL_CHARACTERS: Final = re.compile(r"[\x00-\x1f\x7f]")
MAX_FILENAME_BYTES: Final = 255
JSON_START_BYTES: Final = b'{["-0123456789tfn'


def normalize_filename(raw: str) -> str:
    """Normalize one basename with NFKC while rejecting path semantics."""
    normalized = unicodedata.normalize("NFKC", raw).strip()
    if (
        not normalized
        or "/" in normalized
        or "\\" in normalized
        or CONTROL_CHARACTERS.search(normalized) is not None
        or normalized in {".", ".."}
    ):
        raise UploadError(UploadErrorCode.FILENAME_INVALID)
    collapsed = " ".join(normalized.split())
    if len(collapsed.encode("utf-8")) > MAX_FILENAME_BYTES:
        raise UploadError(UploadErrorCode.FILENAME_INVALID)
    suffix = PurePosixPath(collapsed).suffix.lower()
    if not suffix:
        raise UploadError(UploadErrorCode.MEDIA_TYPE_NOT_ALLOWED, collapsed)
    return f"{collapsed[: -len(suffix)]}{suffix}"


def identify_format(filename: str, declared_mime: str, payload: bytes) -> FormatRule:
    """Require extension, declared MIME, and detected content to agree."""
    suffix = PurePosixPath(filename).suffix
    rule = FORMAT_RULES.get(suffix)
    if rule is None:
        code = (
            UploadErrorCode.ARCHIVE_REJECTED
            if _starts_with_archive(payload)
            else UploadErrorCode.MEDIA_TYPE_NOT_ALLOWED
        )
        raise UploadError(code, filename)
    if declared_mime.lower().strip() != rule.media_type:
        raise UploadError(UploadErrorCode.MEDIA_TYPE_MISMATCH, filename)
    _reject_polyglot(rule.format, payload, filename)
    if not _magic_matches(rule.format, payload):
        raise UploadError(UploadErrorCode.MEDIA_TYPE_MISMATCH, filename)
    return rule


def _starts_with_archive(payload: bytes) -> bool:
    return any(payload.startswith(signature) for signature in ARCHIVE_MAGICS)


def _reject_polyglot(
    format_: ScientificFormat,
    payload: bytes,
    filename: str,
) -> None:
    if format_ is ScientificFormat.XLSX:
        if any(
            signature not in {b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"}
            and payload.find(signature) >= 0
            for signature in ARCHIVE_MAGICS
        ):
            raise UploadError(UploadErrorCode.POLYGLOT_REJECTED, filename)
        return
    for signature in ARCHIVE_MAGICS:
        offset = payload.find(signature)
        if offset == 0:
            raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)
        if offset > 0:
            raise UploadError(UploadErrorCode.POLYGLOT_REJECTED, filename)


def _magic_matches(format_: ScientificFormat, payload: bytes) -> bool:
    match format_:
        case ScientificFormat.PDF:
            matches = payload.startswith(b"%PDF-") and payload.rstrip().endswith(
                b"%%EOF"
            )
        case ScientificFormat.PNG:
            matches = payload.startswith(b"\x89PNG\r\n\x1a\n")
        case ScientificFormat.JPEG:
            matches = payload.startswith(b"\xff\xd8\xff") and payload.endswith(
                b"\xff\xd9"
            )
        case ScientificFormat.TIFF:
            matches = payload.startswith((b"II*\x00", b"MM\x00*"))
        case ScientificFormat.XLSX:
            matches = payload.startswith(b"PK\x03\x04")
        case ScientificFormat.CSV | ScientificFormat.TSV:
            matches = _is_utf8_text(payload)
        case ScientificFormat.JSON:
            stripped = payload.lstrip()
            matches = (
                _is_utf8_text(payload)
                and bool(stripped)
                and stripped[0] in JSON_START_BYTES
            )
        case ScientificFormat.TXT | ScientificFormat.MARKDOWN:
            matches = _is_utf8_text(payload)
        case _:
            assert_never(format_)
    return matches


def _is_utf8_text(payload: bytes) -> bool:
    if not payload or b"\x00" in payload:
        return False
    try:
        decoder = getincrementaldecoder("utf-8-sig")()
        for offset in range(0, len(payload), 64 * 1024):
            text = decoder.decode(payload[offset : offset + 64 * 1024])
            if not _text_characters_allowed(text):
                return False
        tail = decoder.decode(b"", final=True)
    except UnicodeDecodeError:
        return False
    return _text_characters_allowed(tail)


def _text_characters_allowed(text: str) -> bool:
    return all(
        character in "\n\r\t" or unicodedata.category(character) != "Cc"
        for character in text
    )
