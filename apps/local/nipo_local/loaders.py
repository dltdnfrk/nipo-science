"""Load real measurement files into the science package's typed inputs.

The deterministic science package refuses to analyse data whose units,
calibration, and source lineage are not declared. That refusal is correct, but
it leaves a researcher holding a CSV with no way to supply the missing
declarations. This module closes that gap with a **sidecar manifest**: a small
hand-written file that sits next to the data and states what the numbers mean.

Manifest format
---------------
TOML, in a file named ``<data file name>.manifest.toml``. So
``spectrum-001.csv`` is described by ``spectrum-001.csv.manifest.toml``.

TOML was chosen over JSON for four reasons that all favour the human writing
it: ``tomllib`` is in the 3.12 standard library so this costs no dependency;
TOML has comments, and a calibration reference is exactly the kind of claim
that needs one; TOML has a native offset-aware date-time literal, so
``calibrated_at`` is a real timestamp rather than a string in an agreed-upon
format; and ``[[units]]`` array-of-tables syntax expresses "one entry per
measured quantity" without nesting punctuation. JSON's lack of comments alone
disqualifies it for a file whose whole purpose is recording provenance.

A complete spectrum manifest::

    manifest_version = "nipo.local.input-manifest.v1"
    kind = "spectrum"

    [scope]
    research_only = true
    non_clinical = true

    [[units]]
    quantity = "wavelength"
    ucum_code = "nm"

    [[units]]
    quantity = "intensity"
    ucum_code = "1"

    [calibration]
    method = "two-point NIST-traceable"
    reference = "SRM 2242a"
    calibrated_at = 2026-01-04T09:30:00Z
    calibration_sha256 = "<64 lowercase hex characters>"

    [lineage]
    version_ids = ["01900000-0000-7000-8000-00000000000a"]

Every key is required unless stated otherwise, and unknown keys are rejected by
name rather than ignored.

Design commitments
------------------
**Nothing is ever imputed.** A blank intensity cell loads as ``None`` and stays
``None``; it is not interpolated, zero-filled, or dropped. A missing
calibration is an error, never a default. ``[scope]`` is written by the
researcher rather than asserted by this module, because "this data is
research-only and non-clinical" is a claim only a person can make.

**Failures reuse the science package's vocabulary.** When a manifest is
well-formed but describes metadata the science package would reject,
:class:`MetadataRejectedError` carries that package's own
:class:`AnalysisIssue` codes (``units_incomplete``, ``lineage_required``, ...)
instead of a parallel set invented here.

**Offsets are converted, never guessed.** ``CalibrationMetadata`` accepts only
an exact-UTC timestamp, so ``2026-01-04T18:30:00+09:00`` is converted to its
UTC equivalent: that is a lossless restatement of one instant, not a
substitution. A TOML *local* date-time carrying no offset at all is rejected,
because honouring it would mean inventing the timezone the researcher omitted.

**Metadata rejection is a policy, not a law.** Under the default
:attr:`MetadataPolicy.STRICT` a loader refuses incomplete metadata up front, so
a researcher learns at load time. Under :attr:`MetadataPolicy.DEFER` the input
is built exactly as declared and the science package renders its own verdict,
which is what a caller wants when the point is to *observe* an
``insufficient_data`` outcome. Neither policy fills anything in.
"""

from __future__ import annotations

import csv
import math
import tomllib
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, ClassVar, Final, final
from uuid import UUID

from PIL import Image, UnidentifiedImageError
from pydantic import BaseModel, ConfigDict, Field, ValidationError

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
from science_workbench_science.validation import metadata_issues

if TYPE_CHECKING:
    from pathlib import Path

    from science_workbench_science import AnalysisIssue

MANIFEST_SUFFIX: Final = ".manifest.toml"
MANIFEST_VERSION: Final = "nipo.local.input-manifest.v1"

SPECTRUM_QUANTITIES: Final = frozenset({"wavelength", "intensity"})
IMAGE_QUANTITIES: Final = frozenset({"color"})
REPORT_QUANTITIES: Final = frozenset({"document"})

SPECTRUM_COLUMN_COUNT: Final = 2
SPECTRUM_HEADER: Final = ("wavelength", "intensity")
RGB_CHANNEL_COUNT: Final = 3

MAX_TEXT_BYTES: Final = 64 * 1024 * 1024
MAX_IMAGE_BYTES: Final = 64 * 1024 * 1024
MAX_IMAGE_PIXELS: Final = 4_000_000

TEXT_ENCODING: Final = "utf-8-sig"


class ManifestKind(StrEnum):
    """Declared modality of the data file a manifest describes."""

    SPECTRUM = "spectrum"
    TABLE = "table"
    IMAGE = "image"
    REPORT = "report"


class MetadataPolicy(StrEnum):
    """Whether a loader refuses incomplete metadata or defers to the science."""

    STRICT = "strict"
    DEFER = "defer"


class LoaderError(Exception):
    """Base class for every refusal to load a measurement file."""

    path: Path

    def __init__(self, message: str, path: Path) -> None:
        """Record the explanation alongside the file it concerns."""
        super().__init__(message)
        self.path = path


@final
class ManifestNotFoundError(LoaderError):
    """Raised when a data file has no sidecar manifest beside it."""

    def __init__(self, data_path: Path, manifest: Path) -> None:
        """Name the expected sidecar so the researcher knows what to write."""
        super().__init__(
            f"{data_path} has no sidecar manifest; expected {manifest.name} "
            f"beside it declaring units, calibration, and lineage.",
            manifest,
        )


@final
class DataFileNotFoundError(LoaderError):
    """Raised when the referenced measurement file does not exist."""

    def __init__(self, data_path: Path) -> None:
        """Name the missing measurement file."""
        super().__init__(f"{data_path} does not exist.", data_path)


@final
class ManifestSyntaxError(LoaderError):
    """Raised when a sidecar manifest is not parsable TOML."""

    def __init__(self, manifest: Path, detail: str) -> None:
        """Report the TOML parser's own position and complaint."""
        super().__init__(f"{manifest} is not valid TOML: {detail}", manifest)


@final
class ManifestSchemaError(LoaderError):
    """Raised when a manifest parses but violates the declared schema."""

    problems: tuple[str, ...]

    def __init__(self, manifest: Path, problems: tuple[str, ...]) -> None:
        """List every schema violation rather than only the first."""
        joined = "; ".join(problems)
        super().__init__(
            f"{manifest} is not a valid input manifest: {joined}",
            manifest,
        )
        self.problems = problems


@final
class ManifestKindMismatchError(LoaderError):
    """Raised when a manifest describes a different modality than requested."""

    declared: ManifestKind
    requested: ManifestKind

    def __init__(
        self,
        manifest: Path,
        declared: ManifestKind,
        requested: ManifestKind,
    ) -> None:
        """Explain that the manifest describes another kind of measurement."""
        super().__init__(
            f"{manifest} declares kind {declared.value!r} but was loaded as "
            f"{requested.value!r}; loading it as {requested.value!r} would "
            f"misread the file.",
            manifest,
        )
        self.declared = declared
        self.requested = requested


@final
class MalformedDataError(LoaderError):
    """Raised when a measurement file's own contents cannot be trusted."""

    detail: str

    def __init__(self, data_path: Path, detail: str) -> None:
        """Locate the offending part of the measurement file."""
        super().__init__(f"{data_path} is malformed: {detail}", data_path)
        self.detail = detail


@final
class MetadataRejectedError(LoaderError):
    """Raised when declared metadata is one the science package would refuse."""

    issues: tuple[AnalysisIssue, ...]

    def __init__(self, data_path: Path, issues: tuple[AnalysisIssue, ...]) -> None:
        """Surface the science package's own issue codes and messages."""
        rendered = "; ".join(f"{issue.code}: {issue.message}" for issue in issues)
        super().__init__(
            f"{data_path} declares metadata the science package rejects: {rendered}",
            data_path,
        )
        self.issues = issues


class _ManifestModel(BaseModel):
    """Reject unknown manifest keys and loose scalar types."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )


class UnitEntry(_ManifestModel):
    """One measured quantity bound to a UCUM code."""

    quantity: str
    ucum_code: str


class ScopeEntry(_ManifestModel):
    """The researcher's explicit affirmation of research-only scope."""

    research_only: bool
    non_clinical: bool


class CalibrationEntry(_ManifestModel):
    """The calibration claim recorded beside the data."""

    method: str
    reference: str
    calibrated_at: datetime
    calibration_sha256: str


class LineageEntry(_ManifestModel):
    """Source Version ids this measurement descends from."""

    version_ids: list[str]


class ImageEntry(_ManifestModel):
    """Image-only calibrated region threshold."""

    region_threshold: float


class InputManifest(_ManifestModel):
    """One parsed sidecar manifest, before science-level validation."""

    manifest_version: str
    # Coerced from the TOML string; strict mode would demand an enum instance.
    kind: ManifestKind = Field(strict=False)
    scope: ScopeEntry
    units: list[UnitEntry] = Field(default_factory=list)
    calibration: CalibrationEntry | None = None
    lineage: LineageEntry | None = None
    image: ImageEntry | None = None


def manifest_path_for(data_path: Path) -> Path:
    """Return the sidecar manifest path for one measurement file."""
    return data_path.with_name(data_path.name + MANIFEST_SUFFIX)


def read_manifest(data_path: Path) -> InputManifest:
    """Parse and strictly validate the sidecar manifest for a data file."""
    manifest = manifest_path_for(data_path)
    if not manifest.is_file():
        raise ManifestNotFoundError(data_path, manifest)
    try:
        with manifest.open("rb") as handle:
            # TOML guarantees the document root is a table, so this is a dict.
            raw = tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        raise ManifestSyntaxError(manifest, str(error)) from error
    except OSError as error:
        raise ManifestSyntaxError(manifest, str(error)) from error
    try:
        parsed = InputManifest.model_validate(raw)
    except ValidationError as error:
        raise ManifestSchemaError(manifest, _schema_problems(error)) from error
    _check_manifest_invariants(manifest, parsed)
    return parsed


def load_spectrum(
    data_path: Path,
    policy: MetadataPolicy = MetadataPolicy.STRICT,
) -> SpectrumInput:
    """Load a two-column spectrum CSV, keeping blank intensities missing."""
    manifest = _manifest_of_kind(data_path, ManifestKind.SPECTRUM)
    rows = _read_csv(data_path)
    header, body = _split_header(data_path, rows)
    if tuple(name.strip().lower() for name in header) != SPECTRUM_HEADER:
        raise MalformedDataError(
            data_path,
            f"header must be exactly {list(SPECTRUM_HEADER)}, found {header}",
        )
    wavelengths: list[float] = []
    intensities: list[float | None] = []
    for offset, row in enumerate(body):
        line = offset + 2
        if len(row) != SPECTRUM_COLUMN_COUNT:
            raise MalformedDataError(
                data_path,
                f"line {line} has {len(row)} fields, expected {SPECTRUM_COLUMN_COUNT}",
            )
        wavelengths.append(_required_number(data_path, row[0], line, "wavelength"))
        intensities.append(_optional_number(data_path, row[1], line, "intensity"))
    metadata = _build_metadata(data_path, manifest)
    _enforce(data_path, metadata, SPECTRUM_QUANTITIES, policy)
    return SpectrumInput(
        wavelengths=tuple(wavelengths),
        intensities=tuple(intensities),
        metadata=metadata,
    )


def load_table(
    data_path: Path,
    policy: MetadataPolicy = MetadataPolicy.STRICT,
) -> TableInput:
    """Load a numeric table CSV, keeping blank cells missing."""
    manifest = _manifest_of_kind(data_path, ManifestKind.TABLE)
    rows = _read_csv(data_path)
    header, body = _split_header(data_path, rows)
    columns = tuple(name.strip() for name in header)
    if any(not name for name in columns):
        raise MalformedDataError(data_path, "every column needs a non-blank name")
    if len(set(columns)) != len(columns):
        raise MalformedDataError(data_path, f"column names repeat: {list(columns)}")
    parsed: list[tuple[float | None, ...]] = []
    for offset, row in enumerate(body):
        line = offset + 2
        if len(row) != len(columns):
            raise MalformedDataError(
                data_path,
                f"line {line} has {len(row)} fields, expected {len(columns)}",
            )
        parsed.append(
            tuple(
                _optional_number(data_path, cell, line, columns[index])
                for index, cell in enumerate(row)
            )
        )
    metadata = _build_metadata(data_path, manifest)
    _enforce(data_path, metadata, frozenset(columns), policy)
    return TableInput(columns=columns, rows=tuple(parsed), metadata=metadata)


def load_image(
    data_path: Path,
    policy: MetadataPolicy = MetadataPolicy.STRICT,
) -> ImageInput:
    """Load a PNG or JPEG into row-major RGB pixels via Pillow."""
    manifest = _manifest_of_kind(data_path, ManifestKind.IMAGE)
    if manifest.image is None:
        raise ManifestSchemaError(
            manifest_path_for(data_path),
            ("[image] section with region_threshold is required for kind 'image'",),
        )
    _guard_size(data_path, MAX_IMAGE_BYTES)
    width, height, pixels = _read_pixels(data_path)
    metadata = _build_metadata(data_path, manifest)
    _enforce(data_path, metadata, IMAGE_QUANTITIES, policy)
    return ImageInput(
        width=width,
        height=height,
        pixels=pixels,
        region_threshold=manifest.image.region_threshold,
        metadata=metadata,
    )


def load_report(
    data_path: Path,
    policy: MetadataPolicy = MetadataPolicy.STRICT,
) -> ReportInput:
    """Load report text or Markdown as decoded UTF-8."""
    manifest = _manifest_of_kind(data_path, ManifestKind.REPORT)
    text = _read_text(data_path)
    metadata = _build_metadata(data_path, manifest)
    _enforce(data_path, metadata, REPORT_QUANTITIES, policy)
    return ReportInput(text=text, metadata=metadata)


def load_probe(
    spectrum: Path | None = None,
    table: Path | None = None,
    image: Path | None = None,
    report: Path | None = None,
    policy: MetadataPolicy = MetadataPolicy.STRICT,
) -> ProbeInput:
    """Compose one probe input from every supplied measurement file."""
    if spectrum is None and table is None and image is None and report is None:
        message = "load_probe needs at least one measurement file"
        raise ValueError(message)
    return ProbeInput(
        table=None if table is None else load_table(table, policy),
        spectrum=None if spectrum is None else load_spectrum(spectrum, policy),
        image=None if image is None else load_image(image, policy),
        report=None if report is None else load_report(report, policy),
    )


def _manifest_of_kind(data_path: Path, requested: ManifestKind) -> InputManifest:
    if not data_path.is_file():
        raise DataFileNotFoundError(data_path)
    manifest = read_manifest(data_path)
    if manifest.kind is not requested:
        raise ManifestKindMismatchError(
            manifest_path_for(data_path),
            manifest.kind,
            requested,
        )
    return manifest


def _check_manifest_invariants(manifest: Path, parsed: InputManifest) -> None:
    problems: list[str] = []
    if parsed.manifest_version != MANIFEST_VERSION:
        problems.append(
            f"manifest_version must be {MANIFEST_VERSION!r}, "
            f"found {parsed.manifest_version!r}"
        )
    if not parsed.scope.research_only:
        problems.append("scope.research_only must be true")
    if not parsed.scope.non_clinical:
        problems.append("scope.non_clinical must be true")
    if parsed.image is not None and parsed.kind is not ManifestKind.IMAGE:
        problems.append(f"[image] is only valid for kind 'image', not {parsed.kind!r}")
    if parsed.image is not None and not math.isfinite(parsed.image.region_threshold):
        problems.append("image.region_threshold must be a finite number")
    if problems:
        raise ManifestSchemaError(manifest, tuple(problems))


def _build_metadata(data_path: Path, manifest: InputManifest) -> InputMetadata:
    location = manifest_path_for(data_path)
    units = tuple(
        MeasurementUnit(quantity=entry.quantity, ucum_code=entry.ucum_code)
        for entry in manifest.units
    )
    calibration = _build_calibration(location, manifest.calibration)
    lineage = _build_lineage(location, manifest.lineage)
    try:
        return InputMetadata(
            units=units,
            calibration=calibration,
            lineage_version_ids=lineage,
            research_only=True,
            non_clinical=True,
        )
    except ValidationError as error:
        raise ManifestSchemaError(location, _schema_problems(error)) from error


def _build_calibration(
    manifest: Path,
    entry: CalibrationEntry | None,
) -> CalibrationMetadata | None:
    if entry is None:
        return None
    offset = entry.calibrated_at.utcoffset()
    if offset is None:
        raise ManifestSchemaError(
            manifest,
            (
                "calibration.calibrated_at has no UTC offset; write it as an "
                "offset date-time such as 2026-01-04T09:30:00Z",
            ),
        )
    try:
        return CalibrationMetadata(
            method=entry.method,
            reference=entry.reference,
            calibrated_at=entry.calibrated_at.astimezone(UTC),
            calibration_sha256=entry.calibration_sha256,
        )
    except ValidationError as error:
        raise ManifestSchemaError(manifest, _schema_problems(error)) from error


def _build_lineage(manifest: Path, entry: LineageEntry | None) -> tuple[UUID, ...]:
    if entry is None:
        return ()
    parsed: list[UUID] = []
    for text in entry.version_ids:
        try:
            parsed.append(UUID(text))
        except ValueError as error:
            raise ManifestSchemaError(
                manifest,
                (f"lineage.version_ids entry {text!r} is not a UUID",),
            ) from error
    return tuple(parsed)


def _enforce(
    data_path: Path,
    metadata: InputMetadata,
    required: frozenset[str],
    policy: MetadataPolicy,
) -> None:
    if policy is MetadataPolicy.DEFER:
        return
    issues = metadata_issues(metadata, required)
    if issues:
        raise MetadataRejectedError(data_path, issues)


def _schema_problems(error: ValidationError) -> tuple[str, ...]:
    problems: list[str] = []
    for detail in error.errors():
        location = ".".join(str(part) for part in detail["loc"]) or "<root>"
        if detail["type"] == "extra_forbidden":
            problems.append(f"unknown key {location!r}")
        elif detail["type"] == "missing":
            problems.append(f"missing required key {location!r}")
        else:
            problems.append(f"{location}: {detail['msg']}")
    return tuple(problems)


def _guard_size(data_path: Path, limit: int) -> None:
    size = data_path.stat().st_size
    if size > limit:
        raise MalformedDataError(
            data_path,
            f"file is {size} bytes, above the {limit} byte loader limit",
        )


def _read_text(data_path: Path) -> str:
    if not data_path.is_file():
        raise DataFileNotFoundError(data_path)
    _guard_size(data_path, MAX_TEXT_BYTES)
    try:
        return data_path.read_text(encoding=TEXT_ENCODING)
    except UnicodeDecodeError as error:
        raise MalformedDataError(
            data_path,
            f"is not valid UTF-8 at byte {error.start}",
        ) from error
    except OSError as error:
        raise MalformedDataError(data_path, str(error)) from error


def _read_csv(data_path: Path) -> list[list[str]]:
    text = _read_text(data_path)
    try:
        return [row for row in csv.reader(text.splitlines()) if row]
    except csv.Error as error:
        raise MalformedDataError(data_path, str(error)) from error


def _split_header(
    data_path: Path,
    rows: list[list[str]],
) -> tuple[list[str], list[list[str]]]:
    if not rows:
        raise MalformedDataError(data_path, "file is empty; a header row is required")
    return rows[0], rows[1:]


def _optional_number(
    data_path: Path,
    cell: str,
    line: int,
    column: str,
) -> float | None:
    if not cell.strip():
        return None
    return _required_number(data_path, cell, line, column)


def _required_number(
    data_path: Path,
    cell: str,
    line: int,
    column: str,
) -> float:
    text = cell.strip()
    if not text:
        raise MalformedDataError(
            data_path,
            f"line {line} column {column!r} is blank, and {column!r} cannot be missing",
        )
    try:
        value = float(text)
    except ValueError as error:
        raise MalformedDataError(
            data_path,
            f"line {line} column {column!r} is {cell!r}, which is not a number",
        ) from error
    if not math.isfinite(value):
        raise MalformedDataError(
            data_path,
            f"line {line} column {column!r} is {cell!r}, which is not finite",
        )
    return value


def _read_pixels(
    data_path: Path,
) -> tuple[int, int, tuple[tuple[int, int, int], ...]]:
    try:
        with Image.open(data_path) as opened:
            width, height = opened.size
            if width * height > MAX_IMAGE_PIXELS:
                raise MalformedDataError(
                    data_path,
                    f"{width}x{height} exceeds the {MAX_IMAGE_PIXELS} pixel "
                    f"loader limit; downsample before loading",
                )
            raw = opened.convert("RGB").tobytes()
    except UnidentifiedImageError as error:
        raise MalformedDataError(
            data_path,
            "is not an image Pillow can decode",
        ) from error
    except OSError as error:
        raise MalformedDataError(data_path, f"could not be decoded: {error}") from error
    expected = width * height * RGB_CHANNEL_COUNT
    if len(raw) != expected:
        raise MalformedDataError(
            data_path,
            f"decoded to {len(raw)} RGB bytes, expected {expected}",
        )
    pixels = tuple(
        (raw[start], raw[start + 1], raw[start + 2])
        for start in range(0, expected, RGB_CHANNEL_COUNT)
    )
    return width, height, pixels
