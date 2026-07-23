"""Deterministic, research-only dry-lab fixture vertical."""

from __future__ import annotations

import csv
import hashlib
import io
import itertools
import json
import math
import re
import struct
import subprocess
import sys
import tempfile
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hmac import compare_digest
from pathlib import PurePosixPath
from threading import Lock
from typing import TYPE_CHECKING, Final, Literal, TypedDict

if TYPE_CHECKING:
    from collections.abc import Callable

from .research_intent import (
    ResearchIntent,
    ResearchIntentError,
    ResearchIntentProjection,
    research_intent_from_mapping,
)

_CSV_COLUMN_COUNT: Final = 3
_CODE_APPROVAL_PLAN_MISMATCH: Final = "approval-plan-mismatch"
_CODE_APPROVAL_REPLAYED: Final = "approval-replayed"
_CODE_APPROVAL_BINDING_MISMATCH: Final = "approval-token-mismatch"
_CODE_APPROVAL_EXPIRED: Final = "approval-expired"
_CODE_CANCELLED_BEFORE_EXECUTION: Final = "cancelled-before-execution"
_CODE_EGRESS_REQUESTED: Final = "egress-requested"
_CODE_INVALID_ORDER: Final = "invalid-order"
_CODE_ISOLATED_CHILD_FAILED: Final = "isolated-child-failed"
_CODE_KERNEL_LOST_BEFORE_EXECUTION: Final = "kernel-lost-before-execution"
_CODE_MALFORMED_CSV: Final = "malformed-csv"
_CODE_MISSING_CALIBRATION: Final = "missing-calibration"
_CODE_NONFINITE_DATA: Final = "nonfinite-data"
_CODE_PACKAGE_INSTALL_REQUESTED: Final = "package-install-requested"
_CODE_RESEARCH_INTENT_INVALID: Final = "research-intent-invalid"
_CODE_STALE_LEASE: Final = "stale-lease"
_CODE_UNSAFE_EXPORT_PATH: Final = "unsafe-export-path"
_CODE_UNSAFE_FILENAME: Final = "unsafe-filename"
APPROVAL_TTL_SECONDS: Final = 10 * 60
_APPROVAL_TTL: Final = timedelta(seconds=APPROVAL_TTL_SECONDS)
_SAFE_FILENAME: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.csv$")
_FIXED_CHILD: Final = """import csv, io, sys
rows = list(csv.DictReader(io.StringIO(sys.stdin.read())))
out = io.StringIO(newline='')
writer = csv.writer(out, lineterminator='\\n')
writer.writerow(('sample', 'value', 'calibration'))
for row in sorted(rows, key=lambda item: item['sample']):
    writer.writerow((
        row['sample'],
        format(float(row['value']), '.12g'),
        row['calibration'],
    ))
sys.stdout.write(out.getvalue())
"""


class FixtureFailure(ValueError):  # noqa: N818 - public exception contract
    """A stable, non-secret fixture rejection."""

    code: str
    status: int

    def __init__(self, code: str, status: int = 400) -> None:
        """Initialize a failure with its stable code and HTTP status."""
        super().__init__(code)
        self.code = code
        self.status = status


class ArtifactProjection(TypedDict):
    """Public metadata for one generated artifact."""

    name: str
    category: str
    sha256: str


class ReviewProjection(TypedDict):
    """Public review state."""

    verdict: str
    pinned_hashes: dict[str, str]


class ExportProjection(TypedDict):
    """Public export state."""

    manifest_sha256: str
    paths: list[str]


class CleanupProjection(TypedDict):
    """Public cleanup state."""

    removed_runtime_data: bool
    preserved_artifact_hashes: list[str]


class VerticalProjection(TypedDict):
    """Public fixture state without artifact contents."""

    stage: str
    artifacts: list[ArtifactProjection]
    plan_digest: str | None
    research_intent: ResearchIntentProjection | None
    research_intent_sha256: str | None
    review: ReviewProjection | None
    export: ExportProjection | None
    cleanup: CleanupProjection | None
    child_succeeded: bool
    approval_expires_at: str | None
    approval_ttl_seconds: int


@dataclass(frozen=True, slots=True)
class Upload:
    """Validated CSV input for a fixture run."""

    filename: str
    content_sha256: str
    calibration: str
    rows: tuple[tuple[str, float, str], ...]


@dataclass(frozen=True, slots=True)
class ActionPlan:
    """Fixed execution plan bound to an uploaded fixture."""

    digest: str
    upload_sha256: str
    lease_id: str
    fixed_command: tuple[str, ...]
    research_intent_sha256: str


@dataclass(frozen=True, slots=True)
class ExternalExecutionBinding:
    """Immutable provider selection included in an ActionPlan digest."""

    execution_mode: Literal["provider_model"]
    prompt_sha256: str
    connection_id: str
    model_id: str


@dataclass(frozen=True, slots=True)
class Approval:
    """One-use approval for an action plan."""

    token: str
    plan_digest: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class Artifact:
    """Immutable generated artifact and integrity hash."""

    name: str
    category: str
    content: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class Provenance:
    """Canonical provenance payload and integrity hash."""

    content: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class Review:
    """Verification result over generated artifacts."""

    verdict: str
    pinned_hashes: tuple[tuple[str, str], ...]
    verified: bool


@dataclass(frozen=True, slots=True)
class ExportReceipt:
    """Export manifest and its pinned artifact metadata."""

    manifest: bytes
    manifest_sha256: str
    paths: tuple[str, ...]
    checksums: tuple[tuple[str, str], ...]
    action_plan_digest: str
    review_pins: tuple[tuple[str, str], ...]
    provenance_sha256: str
    research_intent_sha256: str


@dataclass(frozen=True, slots=True)
class CleanupReceipt:
    """Receipt proving runtime data was removed."""

    removed_runtime_data: bool
    preserved_artifact_hashes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RunResult:
    """Complete successful execution result."""

    artifacts: tuple[Artifact, ...]
    provenance: Provenance
    child_succeeded: bool


class DryLabVertical:
    """A deliberately small state machine for a deterministic fixture run."""

    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        """Initialize an empty deterministic fixture run."""
        self._upload: Upload | None = None
        self._plan: ActionPlan | None = None
        self._research_intent: ResearchIntent | None = None
        self._approval: Approval | None = None
        self._result: RunResult | None = None
        self._review: Review | None = None
        self._export: ExportReceipt | None = None
        self._cleanup: CleanupReceipt | None = None
        self._approval_used: bool = False
        self._rejected: bool = False
        self._cancelled: bool = False
        self._clock: Callable[[], datetime] = clock or _utc_now
        self._execution_lock: Lock = Lock()

    def upload(self, filename: str, csv_text: str, *, request: str = "") -> Upload:
        """Validate and retain one calibrated CSV upload."""
        self._require_stage(self._upload is None, _CODE_INVALID_ORDER)
        self._reject_request(request)
        if (
            not _SAFE_FILENAME.fullmatch(filename)
            or "/" in filename
            or "\\" in filename
        ):
            raise FixtureFailure(_CODE_UNSAFE_FILENAME)
        raw = csv_text.encode("utf-8")
        try:
            rows = tuple(
                tuple(row)
                for row in csv.reader(
                    io.StringIO(csv_text, newline=""),
                    strict=True,
                )
            )
        except csv.Error as error:
            raise FixtureFailure(_CODE_MALFORMED_CSV) from error
        if not rows or rows[0] != ("sample", "value", "calibration"):
            raise FixtureFailure(_CODE_MALFORMED_CSV)
        parsed = _parse_rows(rows[1:])
        self._upload = Upload(
            filename=filename,
            content_sha256=_sha256(raw),
            calibration=parsed[0][2],
            rows=parsed,
        )
        return self._upload

    def create_plan(
        self,
        *,
        research_intent: ResearchIntent | None = None,
        lease_id: str = "fresh",
        external_execution: ExternalExecutionBinding | None = None,
    ) -> ActionPlan:
        """Create the fixed plan for the validated upload."""
        self._require_stage(
            self._upload is not None and self._plan is None,
            _CODE_INVALID_ORDER,
        )
        if lease_id != "fresh":
            raise FixtureFailure(_CODE_STALE_LEASE, 409)
        if not isinstance(research_intent, ResearchIntent):
            raise FixtureFailure(_CODE_RESEARCH_INTENT_INVALID)
        try:
            canonical_research_intent = research_intent_from_mapping(
                research_intent.to_dict()
            )
        except (AttributeError, ResearchIntentError, TypeError) as error:
            raise FixtureFailure(_CODE_RESEARCH_INTENT_INVALID) from error
        if canonical_research_intent != research_intent:
            raise FixtureFailure(_CODE_RESEARCH_INTENT_INVALID)
        research_intent = canonical_research_intent
        upload = self._upload
        if upload is None:
            raise FixtureFailure(_CODE_INVALID_ORDER, 409)
        plan_payload: dict[str, object] = {
            "fixed_command": ["python", "normalize-calibrated-csv"],
            "lease_id": lease_id,
            "research_intent": research_intent.to_dict(),
            "research_intent_sha256": research_intent.sha256,
            "upload_sha256": upload.content_sha256,
        }
        if external_execution is not None:
            plan_payload["external_execution"] = {
                "connection_id": external_execution.connection_id,
                "execution_mode": external_execution.execution_mode,
                "model_id": external_execution.model_id,
                "prompt_sha256": external_execution.prompt_sha256,
            }
        digest = _sha256(_canonical_bytes(plan_payload))
        self._research_intent = research_intent
        self._plan = ActionPlan(
            digest=digest,
            upload_sha256=upload.content_sha256,
            lease_id=lease_id,
            fixed_command=(sys.executable, "-I", "-S", "-c", "fixed-normalizer"),
            research_intent_sha256=research_intent.sha256,
        )
        return self._plan

    def approve(self, plan_digest: str) -> Approval:
        """Approve the current plan exactly once."""
        self._require_stage(
            self._plan is not None and self._approval is None,
            _CODE_INVALID_ORDER,
        )
        plan = self._plan
        if plan is None:
            raise FixtureFailure(_CODE_INVALID_ORDER, 409)
        if not compare_digest(plan_digest.encode(), plan.digest.encode()):
            raise FixtureFailure(_CODE_APPROVAL_PLAN_MISMATCH, 409)
        token = _sha256((plan.digest + ":approved").encode("ascii"))
        self._approval = Approval(
            token=token,
            plan_digest=plan.digest,
            expires_at=self._clock() + _APPROVAL_TTL,
        )
        return self._approval

    def reject(self) -> None:
        """Reject the current plan before an approval is issued."""
        self._require_stage(
            self._plan is not None
            and self._approval is None
            and self._result is None
            and not self._rejected
            and not self._cancelled,
            _CODE_INVALID_ORDER,
        )
        self._rejected = True

    def cancel(self) -> None:
        """Cancel a planned or approved run before execution starts."""
        self._require_stage(
            self._plan is not None
            and self._result is None
            and not self._rejected
            and not self._cancelled
            and not self._approval_expired(),
            _CODE_INVALID_ORDER,
        )
        self._cancelled = True

    def execute(
        self, approval_token: str | None = None, *, request: str = ""
    ) -> RunResult:
        """Execute the approved fixed child and collect artifacts."""
        self.consume_approval(approval_token, request=request)
        upload, plan = self._upload, self._plan
        research_intent = self._research_intent
        if upload is None or plan is None or research_intent is None:
            raise FixtureFailure(_CODE_INVALID_ORDER, 409)
        normalized = self._run_fixed_child()
        base_artifacts = (
            _artifact("normalized.csv", "normalized-csv", normalized),
            _artifact("preview.png", "png-preview", _png()),
            _artifact("report.md", "markdown-report", _report(upload.rows)),
            _artifact("evidence.csv", "evidence-ledger", _evidence(upload.rows)),
        )
        provenance_content = _canonical_bytes(
            {
                "artifact_hashes": {item.name: item.sha256 for item in base_artifacts},
                "fixture": "g002-dry-lab-v1",
                "plan_digest": plan.digest,
                "research_intent": research_intent.to_dict(),
                "research_intent_sha256": research_intent.sha256,
                "upload_sha256": upload.content_sha256,
            }
        )
        provenance = Provenance(provenance_content, _sha256(provenance_content))
        artifacts = (
            *base_artifacts,
            _artifact("provenance.json", "provenance", provenance.content),
        )
        self._result = RunResult(
            artifacts=artifacts,
            provenance=provenance,
            child_succeeded=True,
        )
        return self._result

    def consume_approval(
        self, approval_token: str | None = None, *, request: str = ""
    ) -> None:
        """Consume one exact approval before any local or provider side effect."""
        self._require_stage(
            self._approval is not None
            and not self._rejected
            and not self._cancelled,
            _CODE_INVALID_ORDER,
        )
        with self._execution_lock:
            if self._approval_used:
                raise FixtureFailure(_CODE_APPROVAL_REPLAYED, 409)
            self._require_stage(self._result is None, _CODE_INVALID_ORDER)
            self._reject_request(request)
            approval = self._approval
            if approval is None:
                raise FixtureFailure(_CODE_INVALID_ORDER, 409)
            if self._approval_expired():
                raise FixtureFailure(_CODE_APPROVAL_EXPIRED, 409)
            if not approval_token or not compare_digest(
                approval_token.encode(), approval.token.encode()
            ):
                raise FixtureFailure(_CODE_APPROVAL_BINDING_MISMATCH, 409)
            self._approval_used = True
            if "cancel" in request.lower():
                raise FixtureFailure(_CODE_CANCELLED_BEFORE_EXECUTION, 409)
            if "kernel" in request.lower() or "loss" in request.lower():
                raise FixtureFailure(_CODE_KERNEL_LOST_BEFORE_EXECUTION, 409)

    def review(self) -> Review:
        """Verify artifact hashes and pin the reviewed result."""
        self._require_stage(
            self._result is not None and self._review is None,
            _CODE_INVALID_ORDER,
        )
        result = self._result
        if result is None:
            raise FixtureFailure(_CODE_INVALID_ORDER, 409)
        pins = tuple((item.name, item.sha256) for item in result.artifacts)
        verified = all(
            _sha256(item.content) == digest
            for item, (_, digest) in zip(result.artifacts, pins, strict=True)
        )
        self._review = Review("verified" if verified else "rejected", pins, verified)
        return self._review

    def export(self) -> ExportReceipt:
        """Create a manifest for the verified artifact set."""
        self._require_stage(
            self._review is not None and self._export is None,
            _CODE_INVALID_ORDER,
        )
        result, plan, review = self._result, self._plan, self._review
        research_intent = self._research_intent
        if result is None or plan is None or review is None or research_intent is None:
            raise FixtureFailure(_CODE_INVALID_ORDER, 409)
        paths = tuple(f"artifacts/{item.name}" for item in result.artifacts)
        if any(not _safe_relative_path(path) for path in paths):
            raise FixtureFailure(_CODE_UNSAFE_EXPORT_PATH)
        checksums = tuple(
            (path, item.sha256)
            for path, item in zip(paths, result.artifacts, strict=True)
        )
        manifest = _canonical_bytes(
            {
                "action_plan_digest": plan.digest,
                "checksums": dict(checksums),
                "paths": list(paths),
                "provenance_sha256": result.provenance.sha256,
                "research_intent_sha256": research_intent.sha256,
                "review_pins": dict(review.pinned_hashes),
            }
        )
        self._export = ExportReceipt(
            manifest,
            _sha256(manifest),
            paths,
            checksums,
            plan.digest,
            review.pinned_hashes,
            result.provenance.sha256,
            research_intent.sha256,
        )
        return self._export

    def cleanup(self) -> CleanupReceipt:
        """Remove runtime data after a completed export."""
        self._require_stage(
            self._export is not None and self._cleanup is None,
            _CODE_INVALID_ORDER,
        )
        result = self._result
        if result is None:
            raise FixtureFailure(_CODE_INVALID_ORDER, 409)
        self._cleanup = CleanupReceipt(
            removed_runtime_data=True,
            preserved_artifact_hashes=tuple(item.sha256 for item in result.artifacts),
        )
        self._upload = None
        self._plan = None
        self._approval = None
        return self._cleanup

    def read_projection(self) -> VerticalProjection:
        """Return the public state projection without artifact contents."""
        artifacts = () if self._result is None else self._result.artifacts
        return {
            "stage": self._stage(),
            "artifacts": [
                {
                    "name": item.name,
                    "category": item.category,
                    "sha256": item.sha256,
                }
                for item in artifacts
            ],
            "plan_digest": None if self._plan is None else self._plan.digest,
            "research_intent": (
                None
                if self._research_intent is None
                else self._research_intent.to_dict()
            ),
            "research_intent_sha256": (
                None if self._research_intent is None else self._research_intent.sha256
            ),
            "review": (
                None
                if self._review is None
                else {
                    "verdict": self._review.verdict,
                    "pinned_hashes": dict(self._review.pinned_hashes),
                }
            ),
            "export": (
                None
                if self._export is None
                else {
                    "manifest_sha256": self._export.manifest_sha256,
                    "paths": list(self._export.paths),
                }
            ),
            "cleanup": (
                None
                if self._cleanup is None
                else {
                    "removed_runtime_data": self._cleanup.removed_runtime_data,
                    "preserved_artifact_hashes": list(
                        self._cleanup.preserved_artifact_hashes
                    ),
                }
            ),
            "child_succeeded": (
                False if self._result is None else self._result.child_succeeded
            ),
            "approval_expires_at": (
                None
                if self._approval is None
                else _utc_timestamp(self._approval.expires_at)
            ),
            "approval_ttl_seconds": APPROVAL_TTL_SECONDS,
        }

    def read_artifact(self, name: str) -> bytes | None:
        """Return one artifact's immutable content by name."""
        if self._result is None:
            return None
        for artifact in self._result.artifacts:
            if artifact.name == name:
                return artifact.content
        return None

    def fork_for_execution(self) -> DryLabVertical:
        """Copy state so execution and output publication can commit together."""
        with self._execution_lock:
            candidate = DryLabVertical(self._clock)
            candidate._upload = self._upload
            candidate._plan = self._plan
            candidate._research_intent = self._research_intent
            candidate._approval = self._approval
            candidate._result = self._result
            candidate._review = self._review
            candidate._export = self._export
            candidate._cleanup = self._cleanup
            candidate._approval_used = self._approval_used
            candidate._rejected = self._rejected
            candidate._cancelled = self._cancelled
        return candidate

    def _run_fixed_child(self) -> bytes:
        upload = self._upload
        if upload is None:
            raise FixtureFailure(_CODE_INVALID_ORDER, 409)
        source = io.StringIO(newline="")
        writer = csv.writer(source, lineterminator="\n")
        writer.writerow(("sample", "value", "calibration"))
        writer.writerows(upload.rows)
        with tempfile.TemporaryDirectory(prefix="g002-dry-lab-") as directory:
            completed = subprocess.run(  # noqa: S603
                [sys.executable, "-I", "-S", "-c", _FIXED_CHILD],
                input=source.getvalue(),
                text=True,
                capture_output=True,
                cwd=directory,
                env={},
                timeout=5,
                check=False,
            )
        if completed.returncode != 0:
            raise FixtureFailure(_CODE_ISOLATED_CHILD_FAILED, 409)
        return completed.stdout.encode("utf-8")

    def _stage(self) -> str:
        states = (
            (self._cleanup is not None, "cleanup"),
            (self._export is not None, "export"),
            (self._review is not None, "review"),
            (self._result is not None, "execute"),
            (self._cancelled, "cancel"),
            (self._rejected, "reject"),
            (self._approval_expired(), "expire"),
            (self._approval is not None, "approve"),
            (self._plan is not None, "plan"),
            (self._upload is not None, "upload"),
            (True, "new"),
        )
        return next(stage for active, stage in states if active)

    def _approval_expired(self) -> bool:
        approval = self._approval
        return (
            approval is not None
            and not self._approval_used
            and self._result is None
            and self._clock() >= approval.expires_at
        )

    @staticmethod
    def _require_stage(condition: bool, code: str) -> None:
        if not condition:
            raise FixtureFailure(code, 409)

    @staticmethod
    def _reject_request(request: str) -> None:
        lowered = request.lower()
        if any(
            word in lowered for word in ("network", "egress", "http://", "https://")
        ):
            raise FixtureFailure(_CODE_EGRESS_REQUESTED)
        if any(
            word in lowered
            for word in ("pip install", "package install", "npm install")
        ):
            raise FixtureFailure(_CODE_PACKAGE_INSTALL_REQUESTED)


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _parse_rows(
    rows: tuple[tuple[str, ...], ...],
) -> tuple[tuple[str, float, str], ...]:
    if not rows:
        raise FixtureFailure(_CODE_MALFORMED_CSV)
    parsed: list[tuple[str, float, str]] = []
    for row in rows:
        if len(row) != _CSV_COLUMN_COUNT:
            raise FixtureFailure(_CODE_MALFORMED_CSV)
        sample, raw_value, calibration = (cell.strip() for cell in row)
        try:
            value = float(raw_value)
        except (TypeError, ValueError) as error:
            raise FixtureFailure(_CODE_MALFORMED_CSV) from error
        if not sample or not calibration:
            raise FixtureFailure(_CODE_MISSING_CALIBRATION)
        if not math.isfinite(value):
            raise FixtureFailure(_CODE_NONFINITE_DATA)
        parsed.append((sample, value, calibration))
    return tuple(parsed)


def _artifact(name: str, category: str, content: bytes) -> Artifact:
    return Artifact(name, category, content, _sha256(content))


def _report(rows: tuple[tuple[str, float, str], ...]) -> bytes:
    return (
        f"# Dry-lab fixture report\n\nCalibrated observations: {len(rows)}\n"
    ).encode()


def _evidence(rows: tuple[tuple[str, float, str], ...]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(("sample", "value", "calibration", "source"))
    for sample, value, calibration in sorted(rows):
        writer.writerow((sample, format(value, ".12g"), calibration, "fixture-input"))
    return stream.getvalue().encode("utf-8")


def _png() -> bytes:
    width, height = 320, 180
    paper = (247, 243, 232)
    pixels = bytearray(bytes(paper) * width * height)
    _draw_preview_grid(pixels, width, height)
    _draw_preview_signal(pixels, width, height)
    stride = width * 3
    raw = b"".join(
        b"\x00" + pixels[row * stride : (row + 1) * stride]
        for row in range(height)
    )

    def chunk(kind: bytes, data: bytes) -> bytes:
        checksum = zlib.crc32(kind + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", checksum)

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw, level=9))
        + chunk(b"IEND", b"")
    )


def _draw_preview_grid(pixels: bytearray, width: int, height: int) -> None:
    dimensions = (width, height)
    grid = (218, 211, 194)
    ink = (40, 51, 58)
    for x in range(32, width - 16, 48):
        for y in range(16, height - 24):
            _set_preview_pixel(pixels, dimensions, (x, y), grid)
    for y in range(20, height - 24, 32):
        for x in range(32, width - 16):
            _set_preview_pixel(pixels, dimensions, (x, y), grid)
    for x in range(31, width - 15):
        _set_preview_pixel(pixels, dimensions, (x, height - 24), ink)
    for y in range(16, height - 23):
        _set_preview_pixel(pixels, dimensions, (32, y), ink)


def _draw_preview_signal(pixels: bytearray, width: int, height: int) -> None:
    dimensions = (width, height)
    signal = (28, 105, 122)
    marker = (190, 91, 58)
    points = [
        (
            36 + index * 21,
            height
            - 28
            - round((0.55 + 0.28 * math.sin(index * 0.72) + index * 0.012) * 120),
        )
        for index in range(13)
    ]
    for start, end in itertools.pairwise(points):
        _draw_preview_line(pixels, dimensions, start, end, signal)
    for x, y in points:
        for dx in range(-3, 4):
            for dy in range(-3, 4):
                if dx * dx + dy * dy <= 3**2:
                    _set_preview_pixel(pixels, dimensions, (x + dx, y + dy), marker)


def _draw_preview_line(
    pixels: bytearray,
    dimensions: tuple[int, int],
    start: tuple[int, int],
    end: tuple[int, int],
    color: tuple[int, int, int],
) -> None:
    x0, y0 = start
    x1, y1 = end
    steps = max(abs(x1 - x0), abs(y1 - y0))
    for step in range(steps + 1):
        ratio = step / steps if steps else 0
        x = round(x0 + (x1 - x0) * ratio)
        y = round(y0 + (y1 - y0) * ratio)
        for offset in (-1, 0, 1):
            _set_preview_pixel(pixels, dimensions, (x, y + offset), color)


def _set_preview_pixel(
    pixels: bytearray,
    dimensions: tuple[int, int],
    coordinates: tuple[int, int],
    color: tuple[int, int, int],
) -> None:
    width, height = dimensions
    x, y = coordinates
    if 0 <= x < width and 0 <= y < height:
        offset = (y * width + x) * 3
        pixels[offset : offset + 3] = bytes(color)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _safe_relative_path(path: str) -> bool:
    candidate = PurePosixPath(path)
    return (
        not candidate.is_absolute()
        and ".." not in candidate.parts
        and all(candidate.parts)
    )
