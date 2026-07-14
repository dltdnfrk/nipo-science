"""Bounded XLSX container validation and preview extraction."""

import stat
import unicodedata
import zipfile
import zlib
from io import BytesIO
from pathlib import PurePosixPath
from typing import Final

from .models import UploadError, UploadErrorCode, WorkbookPreview
from .workbook_graph import validate_workbook_graph
from .workbook_opc import read_xml, validate_package_controls
from .workbook_rules import OPTIONAL_PARTS

MAX_ARCHIVE_ENTRIES: Final = 1_000
MAX_UNCOMPRESSED_BYTES: Final = 100 * 1024 * 1024
MAX_PREVIEW_SHEETS: Final = 10
REQUIRED_XLSX_MEMBERS: Final = frozenset(
    {
        "[Content_Types].xml",
        "_rels/.rels",
        "xl/_rels/workbook.xml.rels",
        "xl/workbook.xml",
    }
)
FORBIDDEN_MEMBER_PARTS: Final = (
    "customui/",
    "embeddings/",
    "externallinks/",
    "vbaproject",
)
ZIP64_ENTRY_COUNT: Final = 0xFFFF
ALLOWED_FIXED_MEMBERS: Final = REQUIRED_XLSX_MEMBERS | OPTIONAL_PARTS.keys()


def parse_workbook(payload: bytes, filename: str) -> WorkbookPreview:
    """Validate the ZIP envelope and return only bounded workbook metadata."""
    _require_exact_zip_envelope(payload, filename)
    try:
        with zipfile.ZipFile(BytesIO(payload)) as workbook:
            members = workbook.infolist()
            if len(members) > MAX_ARCHIVE_ENTRIES:
                raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename)
            names = tuple(_safe_member_name(member, filename) for member in members)
            canonical_names = tuple(
                unicodedata.normalize("NFKC", name).casefold() for name in names
            )
            if len(set(canonical_names)) != len(canonical_names):
                raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)
            if not set(names) >= REQUIRED_XLSX_MEMBERS:
                raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)
            total_size = sum(member.file_size for member in members)
            if total_size > MAX_UNCOMPRESSED_BYTES:
                raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename)
            _validate_all_members(workbook, members, filename)
            validate_package_controls(workbook, members, filename)
            sheet_names = validate_workbook_graph(workbook, filename)
    except (
        zipfile.BadZipFile,
        KeyError,
        RuntimeError,
        NotImplementedError,
        zlib.error,
    ):
        raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename) from None
    if not sheet_names:
        raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename)
    return WorkbookPreview(
        sheet_names=sheet_names[:MAX_PREVIEW_SHEETS],
        truncated=len(sheet_names) > MAX_PREVIEW_SHEETS,
    )


def _safe_member_name(member: zipfile.ZipInfo, filename: str) -> str:
    raw_name = member.filename
    normalized = unicodedata.normalize("NFKC", raw_name)
    path = PurePosixPath(normalized)
    mode = member.external_attr >> 16
    if (
        not raw_name
        or normalized != raw_name
        or "%" in normalized
        or "\\" in raw_name
        or "\x00" in raw_name
        or path.is_absolute()
        or ".." in path.parts
        or stat.S_ISLNK(mode)
        or member.flag_bits & 1 != 0
        or member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
        or any(part in normalized.casefold() for part in FORBIDDEN_MEMBER_PARTS)
        or normalized.casefold().endswith((".bin", ".exe", ".dll", ".com"))
    ):
        raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)
    return normalized


def _validate_all_members(
    workbook: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    filename: str,
) -> None:
    for member in members:
        name = member.filename
        if not _is_allowed_member(name):
            raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)
        with workbook.open(member) as source:
            prefix = source.read(8)
            if prefix.startswith((b"PK\x03\x04", b"\x1f\x8b\x08", b"Rar!", b"7z")):
                raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)
            while source.read(64 * 1024):
                pass
        if name.casefold().endswith((".xml", ".rels")):
            _ = read_xml(workbook, name, filename)


def _is_allowed_member(name: str) -> bool:
    if name in ALLOWED_FIXED_MEMBERS:
        return True
    prefix = "xl/worksheets/"
    if not name.startswith(prefix) or not name.endswith(".xml"):
        return False
    stem = name.removeprefix(prefix).removesuffix(".xml")
    return stem.startswith("sheet") and stem.removeprefix("sheet").isdigit()


def _require_exact_zip_envelope(payload: bytes, filename: str) -> None:
    end_offset = payload.rfind(b"PK\x05\x06")
    if end_offset < 0 or end_offset + 22 > len(payload):
        raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename)
    comment_size = int.from_bytes(payload[end_offset + 20 : end_offset + 22], "little")
    entry_count = int.from_bytes(payload[end_offset + 10 : end_offset + 12], "little")
    if entry_count > MAX_ARCHIVE_ENTRIES or entry_count == ZIP64_ENTRY_COUNT:
        raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename)
    if end_offset + 22 + comment_size != len(payload):
        raise UploadError(UploadErrorCode.POLYGLOT_REJECTED, filename)
