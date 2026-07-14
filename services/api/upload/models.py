"""Typed upload boundary and bounded preview models."""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, ClassVar, Final, NewType, final, override
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StrictBytes

UploadKey = NewType("UploadKey", str)
UUID7_VERSION: Final = 7
UUID7_ERROR: Final = "uuid7"


def _require_uuid7(value: UUID) -> UUID:
    if value.version != UUID7_VERSION:
        raise ValueError(UUID7_ERROR)
    return value


UploadUuid7 = Annotated[UUID, AfterValidator(_require_uuid7)]


class ScientificFormat(StrEnum):
    """Accepted scientific input formats."""

    PDF = "pdf"
    PNG = "png"
    JPEG = "jpeg"
    TIFF = "tiff"
    CSV = "csv"
    TSV = "tsv"
    JSON = "json"
    XLSX = "xlsx"
    TXT = "txt"
    MARKDOWN = "md"


class UploadErrorCode(StrEnum):
    """Stable fail-closed rejection codes."""

    TOO_MANY_FILES = "upload_too_many_files"
    FILE_TOO_LARGE = "upload_file_too_large"
    REQUEST_TOO_LARGE = "upload_request_too_large"
    FILENAME_INVALID = "upload_filename_invalid"
    MEDIA_TYPE_NOT_ALLOWED = "upload_media_type_not_allowed"
    MEDIA_TYPE_MISMATCH = "upload_media_type_mismatch"
    ARCHIVE_REJECTED = "upload_archive_rejected"
    POLYGLOT_REJECTED = "upload_polyglot_rejected"
    STRUCTURE_INVALID = "upload_structure_invalid"
    PDF_PAGE_LIMIT = "upload_pdf_page_limit"
    IMAGE_PIXEL_LIMIT = "upload_image_pixel_limit"
    MALWARE_DETECTED = "upload_malware_detected"
    SCANNER_FAILED = "upload_scanner_failed"
    STORAGE_FAILED = "upload_storage_failed"
    TRANSPORT_INVALID = "upload_transport_invalid"


class UploadPart(BaseModel):
    """One multipart file represented as transport-provided chunks."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    filename: str = Field(min_length=1, max_length=1024)
    declared_mime: str = Field(min_length=1, max_length=255)
    chunks: Iterable[StrictBytes]


class UploadScope(BaseModel):
    """Authenticated tenant and requester binding for stored upload bytes."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    org_id: UploadUuid7
    project_id: UploadUuid7
    requester_id: UploadUuid7


class UploadRequest(BaseModel):
    """A bounded multipart request before scientific validation."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    scope: UploadScope
    files: tuple[UploadPart, ...] = Field(min_length=1)


@dataclass(frozen=True, slots=True)
class TextPreview:
    """A bounded UTF-8 text preview."""

    lines: tuple[str, ...]
    truncated: bool


@dataclass(frozen=True, slots=True)
class TabularPreview:
    """A bounded rectangular CSV or TSV preview."""

    rows: tuple[tuple[str, ...], ...]
    truncated: bool


@dataclass(frozen=True, slots=True)
class JsonPreview:
    """A bounded canonical JSON preview."""

    root_type: str
    excerpt: str
    truncated: bool


@dataclass(frozen=True, slots=True)
class DocumentPreview:
    """Bounded metadata for page-oriented documents."""

    page_count: int


@dataclass(frozen=True, slots=True)
class ImagePreview:
    """Bounded metadata for raster images."""

    width: int
    height: int


@dataclass(frozen=True, slots=True)
class WorkbookPreview:
    """Bounded XLSX workbook metadata."""

    sheet_names: tuple[str, ...]
    truncated: bool


type ScientificPreview = (
    TextPreview
    | TabularPreview
    | JsonPreview
    | DocumentPreview
    | ImagePreview
    | WorkbookPreview
)


@dataclass(frozen=True, slots=True)
class CleanUpload:
    """Agent-readable upload metadata emitted only after scanning."""

    key: UploadKey
    scope: UploadScope
    filename: str
    media_type: str
    format: ScientificFormat
    byte_size: int
    sha256: str
    preview: ScientificPreview


@final
class UploadError(Exception):
    """Stable upload rejection without reflecting untrusted content."""

    __slots__ = ("code", "filename")

    def __init__(self, code: UploadErrorCode, filename: str | None = None) -> None:
        """Retain only the stable code and normalized filename."""
        super().__init__(code, filename)
        self.code = code
        self.filename = filename

    @override
    def __str__(self) -> str:
        """Render only the stable error code and optional normalized filename."""
        return self.code if self.filename is None else f"{self.code}: {self.filename}"
