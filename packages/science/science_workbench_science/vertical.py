"""Deterministic, research-only dry-lab fixture vertical."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import re
import struct
import subprocess
import sys
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final, TypedDict

_CSV_COLUMN_COUNT: Final = 3
_CODE_APPROVAL_PLAN_MISMATCH: Final = "approval-plan-mismatch"
_CODE_APPROVAL_REPLAYED: Final = "approval-replayed"
_CODE_APPROVAL_BINDING_MISMATCH: Final = "approval-token-mismatch"
_CODE_CANCELLED_BEFORE_EXECUTION: Final = "cancelled-before-execution"
_CODE_EGRESS_REQUESTED: Final = "egress-requested"
_CODE_INVALID_ORDER: Final = "invalid-order"
_CODE_ISOLATED_CHILD_FAILED: Final = "isolated-child-failed"
_CODE_KERNEL_LOST_BEFORE_EXECUTION: Final = "kernel-lost-before-execution"
_CODE_MALFORMED_CSV: Final = "malformed-csv"
_CODE_MISSING_CALIBRATION: Final = "missing-calibration"
_CODE_NONFINITE_DATA: Final = "nonfinite-data"
_CODE_PACKAGE_INSTALL_REQUESTED: Final = "package-install-requested"
_CODE_STALE_LEASE: Final = "stale-lease"
_CODE_UNSAFE_EXPORT_PATH: Final = "unsafe-export-path"
_CODE_UNSAFE_FILENAME: Final = "unsafe-filename"
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
    review: ReviewProjection | None
    export: ExportProjection | None
    cleanup: CleanupProjection | None
    child_succeeded: bool


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


@dataclass(frozen=True, slots=True)
class Approval:
    """One-use approval for an action plan."""
    token: str
    plan_digest: str


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


@dataclass(frozen=True, slots=True)
class CleanupReceipt:
    """Receipt proving runtime data was removed."""
    removed_runtime_data: bool
    preserved_artifact_hashes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RunResult:
    """Complete successful execution result."""
    upload: Upload
    plan: ActionPlan
    approval: Approval
    artifacts: tuple[Artifact, ...]
    provenance: Provenance
    child_succeeded: bool


class DryLabVertical:
    """A deliberately small state machine for a deterministic fixture run."""

    def __init__(self) -> None:
        """Initialize an empty deterministic fixture run."""
        self._upload: Upload | None = None
        self._plan: ActionPlan | None = None
        self._approval: Approval | None = None
        self._result: RunResult | None = None
        self._review: Review | None = None
        self._export: ExportReceipt | None = None
        self._cleanup: CleanupReceipt | None = None
        self._approval_used: bool = False

    def upload(
        self, filename: str, csv_text: str, *, request: str = ""
    ) -> Upload:
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
        if (
            not rows
            or rows[0] != ("sample", "value", "calibration")
        ):
            raise FixtureFailure(_CODE_MALFORMED_CSV)
        parsed = _parse_rows(rows[1:])
        self._upload = Upload(
            filename=filename,
            content_sha256=_sha256(raw),
            calibration=parsed[0][2],
            rows=parsed,
        )
        return self._upload

    def create_plan(self, *, lease_id: str = "fresh") -> ActionPlan:
        """Create the fixed plan for the validated upload."""
        self._require_stage(
            self._upload is not None and self._plan is None,
            _CODE_INVALID_ORDER,
        )
        if lease_id != "fresh":
            raise FixtureFailure(_CODE_STALE_LEASE, 409)
        upload = self._upload
        if upload is None:
            raise FixtureFailure(_CODE_INVALID_ORDER, 409)
        digest = _sha256(
            _canonical_bytes(
                {
                    "fixed_command": ["python", "normalize-calibrated-csv"],
                    "lease_id": lease_id,
                    "upload_sha256": upload.content_sha256,
                }
            )
        )
        self._plan = ActionPlan(
            digest=digest,
            upload_sha256=upload.content_sha256,
            lease_id=lease_id,
            fixed_command=(sys.executable, "-I", "-S", "-c", "fixed-normalizer"),
        )
        return self._plan

    def approve(self, plan_digest: str | None = None) -> Approval:
        """Approve the current plan exactly once."""
        self._require_stage(
            self._plan is not None and self._approval is None,
            _CODE_INVALID_ORDER,
        )
        plan = self._plan
        if plan is None:
            raise FixtureFailure(_CODE_INVALID_ORDER, 409)
        if plan_digest is not None and plan_digest != plan.digest:
            raise FixtureFailure(_CODE_APPROVAL_PLAN_MISMATCH, 409)
        token = _sha256((plan.digest + ":approved").encode("ascii"))
        self._approval = Approval(token=token, plan_digest=plan.digest)
        return self._approval

    def execute(
        self, approval_token: str | None = None, *, request: str = ""
    ) -> RunResult:
        """Execute the approved fixed child and collect artifacts."""
        self._require_stage(self._approval is not None, _CODE_INVALID_ORDER)
        if self._approval_used:
            raise FixtureFailure(_CODE_APPROVAL_REPLAYED, 409)
        self._require_stage(self._result is None, _CODE_INVALID_ORDER)
        self._reject_request(request)
        if "cancel" in request.lower():
            raise FixtureFailure(_CODE_CANCELLED_BEFORE_EXECUTION, 409)
        if "kernel" in request.lower() or "loss" in request.lower():
            raise FixtureFailure(_CODE_KERNEL_LOST_BEFORE_EXECUTION, 409)
        upload, plan, approval = self._upload, self._plan, self._approval
        if upload is None or plan is None or approval is None:
            raise FixtureFailure(_CODE_INVALID_ORDER, 409)
        if approval_token is not None and approval_token != approval.token:
            raise FixtureFailure(_CODE_APPROVAL_BINDING_MISMATCH, 409)
        self._approval_used = True
        normalized = self._run_fixed_child()
        base_artifacts = (
            _artifact("normalized.csv", "normalized-csv", normalized),
            _artifact("preview.png", "png-preview", _png()),
            _artifact("report.md", "markdown-report", _report(upload.rows)),
            _artifact("evidence.csv", "evidence-ledger", _evidence(upload.rows)),
        )
        provenance_content = _canonical_bytes(
            {
                "artifact_hashes": {
                    item.name: item.sha256 for item in base_artifacts
                },
                "fixture": "g002-dry-lab-v1",
                "plan_digest": plan.digest,
                "upload_sha256": upload.content_sha256,
            }
        )
        provenance = Provenance(provenance_content, _sha256(provenance_content))
        artifacts = (
            *base_artifacts,
            _artifact("provenance.json", "provenance", provenance.content),
        )
        self._result = RunResult(
            upload=upload,
            plan=plan,
            approval=approval,
            artifacts=artifacts,
            provenance=provenance,
            child_succeeded=True,
        )
        return self._result

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
        if result is None or plan is None or review is None:
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
        }

    def read_artifact(self, name: str) -> bytes | None:
        """Return one artifact's immutable content by name."""
        if self._result is None:
            return None
        for artifact in self._result.artifacts:
            if artifact.name == name:
                return artifact.content
        return None

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
        stage = "new"
        if self._upload is not None:
            stage = "upload"
        if self._plan is not None:
            stage = "plan"
        if self._approval is not None:
            stage = "approve"
        if self._result is not None:
            stage = "execute"
        if self._review is not None:
            stage = "review"
        if self._export is not None:
            stage = "export"
        if self._cleanup is not None:
            stage = "cleanup"
        return stage

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
        "# Dry-lab fixture report\n\n"
        f"Calibrated observations: {len(rows)}\n"
    ).encode()


def _evidence(rows: tuple[tuple[str, float, str], ...]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(("sample", "value", "calibration", "source"))
    for sample, value, calibration in sorted(rows):
        writer.writerow(
            (sample, format(value, ".12g"), calibration, "fixture-input")
        )
    return stream.getvalue().encode("utf-8")


def _png() -> bytes:
    raw = b"\x00\x12\x34\x56\xaa\xbb\xcc\x00\x99\x88\x77\x22\x44\x66"

    def chunk(kind: bytes, data: bytes) -> bytes:
        checksum = zlib.crc32(kind + data) & 0xFFFFFFFF
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", checksum)
        )

    header = struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw, level=9))
        + chunk(b"IEND", b"")
    )


def _safe_relative_path(path: str) -> bool:
    candidate = PurePosixPath(path)
    return (
        not candidate.is_absolute()
        and ".." not in candidate.parts
        and all(candidate.parts)
    )
