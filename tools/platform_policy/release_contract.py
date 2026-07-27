"""Fail-closed, canonical evidence contracts for a frozen release."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import (
    TYPE_CHECKING,
    ClassVar,
    Final,
    Literal,
    Protocol,
    TypeGuard,
    cast,
    override,
    runtime_checkable,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .ci_contract import (
    CiControlCatalog,
    CiExecutionAttestation,
    CiGenerationManifestAuthority,
    CiJob,
    CiRunState,
    EvidenceIntegrityError,
    GateResult,
    ci_requirement_case_evidence_bytes,
    rederive_gate_count,
    require_evidence_sanitized,
    verify_ci_requirement_case_output,
    verify_execution_attestations,
)

SHA256 = r"^[0-9a-f]{64}$"
NFR_COUNT = 10
MIN_FINALIZATION_NONCE_LENGTH: Final = 16
EXPECTED_REQUIREMENT_COUNT = 84
GOAL_STATUSES = frozenset(
    {
        "pending",
        "active",
        "complete",
        "failed",
        "blocked",
        "review_blocked",
        "superseded",
    }
)
REQUIREMENT_ID_PATTERN = re.compile(
    r"(?:F\d{2}|AC-[A-Z0-9]+(?:-[A-Z0-9]+)*|SEC\d{2}|NFR\d{2}|GS\d{2}|RV\d{2})"
)
MIN_SOAK_SECONDS = 72 * 3600
MIN_SUCCESS_PERCENT = 99.5
MAX_SUCCESS_PERCENT = 100.0
MAX_CONTINUOUS_FAILURE_SECONDS = 900
MAX_CRUD_P95_MS = 500
MAX_VISIBLE_TOKEN_P95_SECONDS = 3
MAX_SANDBOX_ALLOCATION_P95_SECONDS = 10
MAX_RECOVERY_SECONDS = 300
MIN_EXPORT_BYTES = 500 * 1024 * 1024
MAX_RPO_MINUTES = 15
MAX_RTO_MINUTES = 240
BROWSERS = ("chrome", "edge", "safari")
MIN_BROWSER_MAJOR_VERSIONS = 2
MIN_BROWSER_CASES = len(BROWSERS) * MIN_BROWSER_MAJOR_VERSIONS
REQUIRED_VISUAL_REVIEW_COUNT = 2
REQUIRED_EXTERNAL_CONTROL_IDS = frozenset(
    {
        "external-cleanup",
        "gke-production",
        "gke-staging",
        "nfr01-72h",
        "nfr02-07-production",
        "nfr09-browser-fleet",
        "nfr10-quarterly-pitr",
        "openai-codex-live",
        "postgres-forced-rls",
        "production-trust-authorities",
    }
)
REQUIRED_EXTERNAL_BINDINGS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "external-cleanup": (("AC-DATA", "SEC10", "SEC16"), ("G005", "G006")),
    "gke-production": (("SEC06", "NFR02", "NFR04"), ("G005", "G006")),
    "gke-staging": (("SEC06", "NFR02", "NFR04"), ("G005", "G006")),
    "nfr01-72h": (("NFR01",), ("G006",)),
    "nfr02-07-production": (
        ("NFR02", "NFR03", "NFR04", "NFR05", "NFR06", "NFR07"),
        ("G005", "G006"),
    ),
    "nfr09-browser-fleet": (("NFR09",), ("G003", "G006")),
    "nfr10-quarterly-pitr": (("NFR10",), ("G005", "G006")),
    "openai-codex-live": (("AC-F13-D", "NFR03"), ("G004", "G006")),
    "postgres-forced-rls": (
        ("AC-F02", "AC-TENANT", "SEC01"),
        ("G003", "G004", "G005", "G006"),
    ),
    "production-trust-authorities": (
        ("SEC04", "SEC06", "SEC10", "SEC14", "SEC16"),
        ("G005", "G006"),
    ),
}
AUTHORITY_INPUT_KEYS = frozenset(
    {
        "command_catalog",
        "dependency",
        "fixture",
        "revision",
        "toolchain",
    }
)

type JsonValue = (
    None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
)


def _json_value(value: object) -> JsonValue:
    """Validate and recursively normalize one JSON-compatible value."""
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, list):
        items = cast("list[object]", value)
        return [_json_value(item) for item in items]
    if isinstance(value, dict):
        items = cast("dict[object, object]", value)
        normalized: dict[str, JsonValue] = {}
        for key, item in items.items():
            if not isinstance(key, str):
                msg = "JSON object keys must be strings"
                raise TypeError(msg)
            normalized[key] = _json_value(item)
        return normalized
    msg = "value is not JSON-compatible"
    raise TypeError(msg)


type MeasurementValue = bool | int | float | str | tuple[int, ...]
type NfrRequirementId = Literal[
    "NFR01",
    "NFR02",
    "NFR03",
    "NFR04",
    "NFR05",
    "NFR06",
    "NFR07",
    "NFR08",
    "NFR09",
    "NFR10",
]
NFR_REQUIREMENT_IDS: tuple[NfrRequirementId, ...] = (
    "NFR01",
    "NFR02",
    "NFR03",
    "NFR04",
    "NFR05",
    "NFR06",
    "NFR07",
    "NFR08",
    "NFR09",
    "NFR10",
)


class ReleaseContractError(ValueError):
    """Raised when evidence cannot prove a release claim."""


class EvidenceCategory(StrEnum):
    """Canonical G006 evidence categories."""

    LINT = "lint"
    TYPECHECK = "typecheck"
    UNIT = "unit"
    INTEGRATION = "integration"
    CONTRACT = "contract"
    SECURITY = "security"
    RECOVERY = "recovery"
    PERFORMANCE = "performance"
    RELEASE = "release"


CI_JOB_CATEGORIES: dict[CiJob, EvidenceCategory] = {
    CiJob.LINT: EvidenceCategory.LINT,
    CiJob.TYPECHECK: EvidenceCategory.TYPECHECK,
    CiJob.PLATFORM_TESTS: EvidenceCategory.UNIT,
    CiJob.BOUNDARIES: EvidenceCategory.SECURITY,
    CiJob.SPEC: EvidenceCategory.CONTRACT,
    CiJob.ARCHITECTURE: EvidenceCategory.CONTRACT,
    CiJob.OPENAPI: EvidenceCategory.CONTRACT,
    CiJob.PROTOCOL_CONTRACTS: EvidenceCategory.CONTRACT,
    CiJob.ARTIFACT_CONTRACTS: EvidenceCategory.CONTRACT,
    CiJob.LOCAL_CONFIG: EvidenceCategory.INTEGRATION,
    CiJob.MIGRATIONS: EvidenceCategory.INTEGRATION,
    CiJob.RLS: EvidenceCategory.SECURITY,
    CiJob.UPLOAD: EvidenceCategory.INTEGRATION,
    CiJob.ARTIFACTS: EvidenceCategory.INTEGRATION,
    CiJob.SCIENCE: EvidenceCategory.INTEGRATION,
    CiJob.RETENTION: EvidenceCategory.RECOVERY,
    CiJob.GENERATED_DRIFT: EvidenceCategory.CONTRACT,
    CiJob.SBOM: EvidenceCategory.SECURITY,
    CiJob.SECRET_SCAN: EvidenceCategory.SECURITY,
    CiJob.DRY_LAB: EvidenceCategory.INTEGRATION,
    CiJob.LOCAL_WORKBENCH: EvidenceCategory.INTEGRATION,
    CiJob.SECURITY: EvidenceCategory.SECURITY,
    CiJob.RECOVERY: EvidenceCategory.RECOVERY,
    CiJob.PERFORMANCE: EvidenceCategory.PERFORMANCE,
    CiJob.RELEASE: EvidenceCategory.RELEASE,
}


class StrictModel(BaseModel):
    """Frozen strict base for release evidence."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True, extra="forbid", revalidate_instances="always"
    )

    @override
    def model_dump(self, *args: object, **kwargs: object) -> dict[str, JsonValue]:
        """Reject model_copy/model_construct invalid state before serialization."""
        raw = BaseModel.model_dump(self, *args, **kwargs)
        _ = type(self).model_validate(raw)
        normalized = _json_value(raw)
        if not isinstance(normalized, dict):
            msg = "model serialization must be a JSON object"
            raise TypeError(msg)
        return normalized

    def canonical_projection(
        self, *, exclude: set[str] | None = None
    ) -> dict[str, JsonValue]:
        """Deep-validate complete state before producing an unsigned projection."""
        raw = self.model_dump(mode="json", exclude_none=False)
        if exclude:
            for key in exclude:
                _ = raw.pop(key, None)
        return raw


class ClaimKind(StrEnum):
    """A non-interchangeable, role-owned success assertion."""

    CI = "ci"
    EXTERNAL = "external"
    REVIEW = "review"
    MANUAL_QA = "manual-qa"
    CLEANUP = "cleanup"
    NFR = "nfr"
    REVISION_ANCHOR = "revision-anchor"
    EXTERNAL_ANCHOR = "external-anchor"


class DetachedEvidenceSeal(StrictModel):
    """A role-issued detached signature over one exact typed success claim."""

    claim_kind: ClaimKind
    issuer_id: str = Field(min_length=1)
    release_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    attempt_id: str = Field(min_length=1)
    source_tree_sha256: str = Field(pattern=SHA256)
    verified_revision: str = Field(min_length=1)
    requirements_sha256: str = Field(pattern=SHA256)
    goals_sha256: str = Field(pattern=SHA256)
    goals_state_revision: int = Field(ge=0)
    command_catalog_sha256: str | None = Field(default=None, pattern=SHA256)
    toolchain_sha256: str | None = Field(default=None, pattern=SHA256)
    issued_at_utc: str
    claim_sha256: str = Field(pattern=SHA256)
    session_id: str = Field(min_length=1)
    lease_generation: str = Field(min_length=1)
    signature_b64: str = Field(min_length=1)

    @model_validator(mode="after")
    def issuer_timestamp_is_real(self) -> DetachedEvidenceSeal:
        """Require a real UTC issuer timestamp before seal verification."""
        _ = _parse_utc(self.issued_at_utc)
        return self


@runtime_checkable
class EvidenceIssuer(Protocol):
    """Role-specific signer/verifier owned by the runtime, never by a receipt."""

    issuer_id: str

    def verify(self, payload: bytes, signature: bytes) -> bool:
        """Verify one detached claim signature."""
        ...


class FrozenAuthority(StrictModel):
    """Revision, source, and durable-input identity for one release attempt."""

    verified_revision: str = Field(min_length=1)
    source_tree_sha256: str = Field(pattern=SHA256)
    dirty: bool
    requirements_sha256: str = Field(pattern=SHA256)
    goals_sha256: str = Field(pattern=SHA256)
    command_catalog_sha256: str | None = Field(default=None, pattern=SHA256)
    dependency_sha256: str | None = Field(default=None, pattern=SHA256)
    fixture_sha256: str | None = Field(default=None, pattern=SHA256)
    toolchain_sha256: str | None = Field(default=None, pattern=SHA256)
    revision_anchor_sha256: str | None = Field(default=None, pattern=SHA256)
    goals_state_revision: int = Field(ge=0)
    session_id: str = Field(min_length=1)
    lease_generation: str = Field(min_length=1)


class SiblingRoots(StrictModel):
    """Pre/post release and sibling-tree roots."""

    science_pre_sha256: str = Field(pattern=SHA256)
    science_post_sha256: str = Field(pattern=SHA256)
    drylab_pre_sha256: str = Field(pattern=SHA256)
    drylab_post_sha256: str = Field(pattern=SHA256)
    ontologylab_pre_sha256: str = Field(pattern=SHA256)
    ontologylab_post_sha256: str = Field(pattern=SHA256)

    @model_validator(mode="after")
    def siblings_and_release_tree_are_unchanged(self) -> SiblingRoots:
        """Reject release or sibling drift."""
        if self.science_pre_sha256 != self.science_post_sha256:
            message = "science-workbench tree drift"
            raise ValueError(message)
        if self.drylab_pre_sha256 != self.drylab_post_sha256:
            message = "drylab sibling drift"
            raise ValueError(message)
        if self.ontologylab_pre_sha256 != self.ontologylab_post_sha256:
            message = "ontologylab sibling drift"
            raise ValueError(message)
        return self


class CleanupEvidence(StrictModel):
    """External cleanup proof and remaining resource inventory."""

    complete: bool
    receipt_sha256: str | None = Field(default=None, pattern=SHA256)
    remaining_resource_ids: tuple[str, ...] = ()
    seal: DetachedEvidenceSeal | None = None

    @model_validator(mode="after")
    def cleanup_is_proven(self) -> CleanupEvidence:
        """Require a receipt and empty inventory for complete cleanup."""
        if self.complete and (
            self.receipt_sha256 is None or self.remaining_resource_ids
        ):
            message = "complete cleanup requires a receipt and no resources"
            raise ValueError(message)
        return self


class ControlEvidence(StrictModel):
    """One checksummed release control execution."""

    control_id: str = Field(min_length=1)
    category: EvidenceCategory
    argv: tuple[str, ...] = Field(min_length=1)
    outcome: Literal["success", "failure", "incomplete"]
    exit_code: int | None = None
    observed_positive_count: int = Field(ge=0)
    raw_log_sha256: str = Field(pattern=SHA256)
    attachment_sha256: tuple[str, ...] = ()
    requirement_ids: tuple[str, ...] = ()
    goal_ids: tuple[str, ...] = ()
    evidence_kind: Literal["machine", "external", "manual", "review"] = "machine"
    count_kind: Literal["analyzer-inventory", "pytest", "checks"] | None = None
    parser_version: int | None = None
    analyzer_inventory_root_sha256: str | None = Field(default=None, pattern=SHA256)
    catalog_root_sha256: str | None = Field(default=None, pattern=SHA256)
    catalog_source_root_sha256: str | None = Field(default=None, pattern=SHA256)
    catalog_run_id: str | None = None
    release_id: str | None = None
    run_id: str | None = None
    attempt_id: str | None = None
    source_root_sha256: str | None = Field(default=None, pattern=SHA256)
    toolchain_sha256: str | None = Field(default=None, pattern=SHA256)
    authority_context_id: str | None = None
    authority_generation_id: str | None = None
    manifest_sha256: str | None = Field(default=None, pattern=SHA256)
    observed_epoch: int | None = Field(default=None, ge=0)
    coverage_sha256: str | None = Field(default=None, pattern=SHA256)
    execution_attestation: CiExecutionAttestation | None = None
    seal: DetachedEvidenceSeal | None = None

    @model_validator(mode="after")
    def outcome_is_nonvacuous(self) -> ControlEvidence:
        """Bind each outcome to an exact exit and non-vacuous count."""
        if self.outcome == "success" and (
            self.exit_code != 0 or self.observed_positive_count < 1
        ):
            message = "successful control requires exit 0 and observations"
            raise ValueError(message)
        if self.outcome == "failure" and (
            self.exit_code is None or self.exit_code == 0
        ):
            message = "failed control requires a nonzero exit"
            raise ValueError(message)
        if self.outcome == "incomplete" and self.exit_code is not None:
            message = "incomplete control cannot claim an exit code"
            raise ValueError(message)
        if any(not item for item in self.argv):
            message = "control argv must be exact nonempty tokens"
            raise ValueError(message)
        if len(set(self.attachment_sha256)) != len(self.attachment_sha256):
            message = "duplicate attachment hash"
            raise ValueError(message)
        return self


class ExternalEvidence(StrictModel):
    """Availability and checksum for one external control."""

    control_id: str = Field(min_length=1)
    available: bool
    sha256: str | None = Field(default=None, pattern=SHA256)
    detail: str = Field(default="", max_length=500)
    requirement_ids: tuple[str, ...] = ()
    goal_ids: tuple[str, ...] = ()
    attachment_sha256: tuple[str, ...] = ()
    observed_at_utc: str | None = Field(
        default=None,
        pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
    )
    authority_id: str | None = None
    seal: DetachedEvidenceSeal | None = None

    @model_validator(mode="after")
    def external_evidence_is_not_prose(self) -> ExternalEvidence:
        """Require bytes, not prose, for available external evidence."""
        if self.available != (self.sha256 is not None):
            message = "external evidence availability must match checksum"
            raise ValueError(message)
        return self


class ReviewEvidence(StrictModel):
    """Checksummed independent code or visual review."""

    reviewer_id: str = Field(min_length=1)
    role: Literal["code", "visual"]
    independent: bool
    decision: Literal["pass", "fail", "incomplete"]
    blocker_count: int = Field(ge=0)
    sha256: str = Field(pattern=SHA256)
    reviewed_source_sha256: str | None = Field(default=None, pattern=SHA256)
    reviewed_capture_sha256: tuple[str, ...] = ()
    reviewed_at_utc: str | None = Field(
        default=None,
        pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
    )
    authority_id: str | None = None
    seal: DetachedEvidenceSeal | None = None

    @model_validator(mode="after")
    def passing_review_has_no_blockers(self) -> ReviewEvidence:
        """Reject a passing decision with blockers."""
        if self.decision == "pass" and self.blocker_count:
            message = "passing review cannot have blockers"
            raise ValueError(message)
        return self


class ManualQaEvidence(StrictModel):
    """Checksummed human manual-QA attestation."""

    performed: bool
    blocker_count: int = Field(default=0, ge=0)
    sha256: str | None = Field(default=None, pattern=SHA256)
    tested_source_sha256: str | None = Field(default=None, pattern=SHA256)
    performed_at_utc: str | None = Field(
        default=None,
        pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
    )
    operator_id: str | None = None
    seal: DetachedEvidenceSeal | None = None

    @model_validator(mode="after")
    def manual_qa_is_attested(self) -> ManualQaEvidence:
        """Require a checksum exactly when manual QA occurred."""
        if self.performed != (self.sha256 is not None):
            message = "manual QA requires a checksummed attestation"
            raise ValueError(message)
        return self


class NfrObservation(StrictModel):
    """Measured evidence for one normative nonfunctional requirement."""

    requirement_id: NfrRequirementId
    duration_seconds: float = Field(ge=0)
    sample_count: int = Field(ge=0)
    environment: str = Field(min_length=1)
    measurements: dict[str, MeasurementValue]
    report_sha256: str = Field(pattern=SHA256)
    observed_start_utc: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
    observed_end_utc: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
    environment_id: str = Field(min_length=1)
    workload_id: str = Field(min_length=1)
    raw_data_sha256: str = Field(pattern=SHA256)
    seal: DetachedEvidenceSeal | None = None

    @model_validator(mode="after")
    def observed_interval_is_real(self) -> NfrObservation:
        """Require real UTC endpoints and a duration derived from those endpoints."""
        start = _parse_utc(self.observed_start_utc)
        end = _parse_utc(self.observed_end_utc)
        if end <= start:
            msg = "NFR observation end must follow start"
            raise ValueError(msg)
        if self.duration_seconds != (end - start).total_seconds():
            msg = "NFR duration must equal its observed interval"
            raise ValueError(msg)
        return self


class AttachmentEvidence(StrictModel):
    """One immutable evidence file relative to the evidence root."""

    path: str = Field(min_length=1)
    sha256: str = Field(pattern=SHA256)

    @model_validator(mode="after")
    def path_is_relative_file(self) -> AttachmentEvidence:
        """Reject absolute paths and parent traversal."""
        if (
            self.path.startswith("/")
            or ".." in self.path.split("/")
            or self.path == "."
        ):
            msg = "attachment path must be a relative file"
            raise ValueError(msg)
        return self


class ReleaseReceipt(StrictModel):
    """Fail-closed aggregate evidence for one frozen release attempt."""

    schema_version: Literal[1] = 1
    release_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    attempt_id: str = Field(min_length=1)
    outcome: Literal["failure", "incomplete"]
    authority: FrozenAuthority
    siblings: SiblingRoots
    controls: tuple[ControlEvidence, ...]
    cleanup: CleanupEvidence
    external_evidence: tuple[ExternalEvidence, ...] = ()
    independent_reviews: tuple[ReviewEvidence, ...] = ()
    manual_qa: ManualQaEvidence
    nfr_observations: tuple[NfrObservation, ...] = ()
    missing_or_failed_controls: tuple[str, ...] = ()
    attachments: tuple[AttachmentEvidence, ...] = ()
    external_anchor_sha256: str | None = Field(default=None, pattern=SHA256)
    revision_anchor_seal: DetachedEvidenceSeal | None = None
    external_anchor_seal: DetachedEvidenceSeal | None = None

    @model_validator(mode="after")
    def release_is_fail_closed(self) -> ReleaseReceipt:
        """Forbid a successful release with any missing or failed proof."""
        duplicate_error = _duplicate_release_evidence_error(self)
        if duplicate_error is not None:
            raise ValueError(duplicate_error)

        declared_missing = set(self.missing_or_failed_controls)
        derived_missing = _derived_missing_controls(self)
        omitted = derived_missing - declared_missing
        if omitted:
            message = f"missing control list omits derived controls: {sorted(omitted)}"
            raise ValueError(message)
        return self


def _duplicate_release_evidence_error(receipt: ReleaseReceipt) -> str | None:
    control_ids = [item.control_id for item in receipt.controls]
    if len(control_ids) != len(set(control_ids)):
        return "duplicate control ID"
    external_ids = [item.control_id for item in receipt.external_evidence]
    if len(external_ids) != len(set(external_ids)):
        return "duplicate external control ID"
    reviewer_ids = [item.reviewer_id for item in receipt.independent_reviews]
    if len(reviewer_ids) != len(set(reviewer_ids)):
        return "duplicate reviewer ID"
    return None


def _derived_missing_controls(receipt: ReleaseReceipt) -> set[str]:
    missing = {
        item.control_id for item in receipt.controls if item.outcome != "success"
    }
    missing.update(
        item.control_id for item in receipt.external_evidence if not item.available
    )
    if not receipt.cleanup.complete:
        missing.add("cleanup")
    if not receipt.external_evidence:
        missing.add("external-evidence")
    if not receipt.manual_qa.performed or receipt.manual_qa.blocker_count:
        missing.add("manual-qa")

    code_reviews = tuple(
        review for review in receipt.independent_reviews if review.role == "code"
    )
    visual_reviews = tuple(
        review for review in receipt.independent_reviews if review.role == "visual"
    )
    if len(code_reviews) != 1 or any(
        not review.independent or review.decision != "pass" for review in code_reviews
    ):
        missing.add("independent-code-review")
    if len(visual_reviews) != REQUIRED_VISUAL_REVIEW_COUNT or any(
        not review.independent or review.decision != "pass" for review in visual_reviews
    ):
        missing.add("dual-visual-review")
    return missing


def canonical_bytes(value: object) -> bytes:
    """Return the one JSON representation used for all receipt digests."""
    document = (
        value.canonical_projection()
        if isinstance(value, StrictModel)
        else _json_value(value)
    )
    encoded = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return encoded.encode() + b"\n"


def sha256_bytes(value: bytes) -> str:
    """Return the lowercase SHA-256 checksum for immutable bytes."""
    return hashlib.sha256(value).hexdigest()


def canonical_sha256(value: object) -> str:
    """Return the checksum of the canonical JSON representation."""
    return sha256_bytes(canonical_bytes(value))


def _contract_error(message: str) -> ReleaseContractError:
    return ReleaseContractError(message)


SOURCE_HASH_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".basedpyright",
        ".cache",
        ".git",
        ".mypy_cache",
        ".next",
        ".nox",
        ".pytest_cache",
        ".ruff_cache",
        ".tools",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "playwright-report",
        "test-results",
    }
)
SOURCE_HASH_EXCLUDED_PREFIXES = frozenset(
    {
        (".ci", "evidence"),
        (".ci", "failed-attempts"),
        ("artifacts",),
    }
)


def tree_sha256(root: Path) -> str:
    """Hash a strict manifest that rejects every included symlink."""
    return _tree_sha256(
        root,
        excluded_directories=frozenset({".git"}),
        preserve_symlink_records=False,
    )


def sibling_tree_sha256(root: Path) -> str:
    """Hash exact sibling topology while recording links without following them."""
    return _tree_sha256(
        root,
        excluded_directories=frozenset({".git"}),
        preserve_symlink_records=True,
    )


def source_tree_sha256(root: Path) -> str:
    """Hash source while excluding mutable tooling, cache, and receipt directories."""
    return _tree_sha256(
        root,
        excluded_directories=SOURCE_HASH_EXCLUDED_DIRECTORIES,
        preserve_symlink_records=False,
    )


def _tree_entry_is_excluded(
    parts: tuple[str, ...],
    excluded_directories: frozenset[str],
) -> bool:
    """Apply the canonical source/sibling exclusions to descriptor-walk entries."""
    name = parts[-1]
    return any(part in excluded_directories for part in parts) or (
        excluded_directories == SOURCE_HASH_EXCLUDED_DIRECTORIES
        and (
            any(
                parts[: len(prefix)] == prefix
                for prefix in SOURCE_HASH_EXCLUDED_PREFIXES
            )
            or name in {".DS_Store", ".env"}
            or (name.startswith(".env.") and name != ".env.example")
            or name.endswith((".pyc", ".pyo"))
        )
    )


def _read_tree_file(
    directory_fd: int,
    name: str,
    expected: os.stat_result,
) -> bytes:
    """Read one descriptor-relative unique file and reject concurrent mutation."""
    file_descriptor = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW,
        dir_fd=directory_fd,
    )
    try:
        before = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino) != (expected.st_dev, expected.st_ino)
        ):
            msg = "included regular file changed while opening"
            raise _contract_error(msg)
        chunks: list[bytes] = []
        while block := os.read(file_descriptor, 65536):
            chunks.append(block)
        after = os.fstat(file_descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            before.st_nlink,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_nlink,
        )
        if before_identity != after_identity:
            msg = "included regular file changed while reading"
            raise _contract_error(msg)
        current_entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if _stat_record_identity(expected) != _stat_record_identity(current_entry):
            msg = "included regular file replaced while reading"
            raise _contract_error(msg)
        return b"".join(chunks)
    finally:
        os.close(file_descriptor)


class _Digest(Protocol):
    """Hash interface used by descriptor-confined tree traversal."""

    def update(self, value: bytes, /) -> None:
        """Add bytes to the digest."""
        ...

    def hexdigest(self) -> str:
        """Return the hexadecimal digest."""
        ...


@dataclass(slots=True)
class _TreeTraversal:
    digest: _Digest
    seen_files: set[tuple[int, int]]
    seen_directories: set[tuple[int, int]]


@dataclass(frozen=True, slots=True)
class _TreePolicy:
    excluded_directories: frozenset[str]
    preserve_symlink_records: bool


type _TreeEntry = tuple[str, tuple[str, ...], os.stat_result]


def _stat_record_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_mode,
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def _hash_sibling_symlink(
    directory_fd: int,
    name: str,
    metadata: os.stat_result,
    relative_path: str,
    traversal: _TreeTraversal,
) -> None:
    """Hash one stable symlink record without resolving its target."""
    identity = (metadata.st_dev, metadata.st_ino)
    if metadata.st_nlink != 1 or identity in traversal.seen_files:
        msg = f"included symlink is aliased sibling evidence: {relative_path}"
        raise _contract_error(msg)
    target = os.readlink(name, dir_fd=directory_fd)
    after = os.stat(
        name,
        dir_fd=directory_fd,
        follow_symlinks=False,
    )
    if _stat_record_identity(metadata) != _stat_record_identity(
        after
    ) or target != os.readlink(name, dir_fd=directory_fd):
        msg = f"included symlink changed while reading: {relative_path}"
        raise _contract_error(msg)
    target_bytes = os.fsencode(target)
    traversal.seen_files.add(identity)
    traversal.digest.update(b"L")
    traversal.digest.update(len(target_bytes).to_bytes(8, "big"))
    traversal.digest.update(target_bytes)


def _hash_tree_symlink(
    directory_fd: int,
    entry: tuple[str, str],
    metadata: os.stat_result,
    traversal: _TreeTraversal,
    *,
    preserve_symlink_records: bool,
) -> bool:
    name, relative_path = entry
    if not stat.S_ISLNK(metadata.st_mode):
        return False
    if not preserve_symlink_records:
        msg = f"included symlink is not release evidence: {relative_path}"
        raise _contract_error(msg)
    _hash_sibling_symlink(
        directory_fd,
        name,
        metadata,
        relative_path,
        traversal,
    )
    return True


def _hash_child_directory(
    directory_fd: int,
    entry: _TreeEntry,
    traversal: _TreeTraversal,
    policy: _TreePolicy,
) -> bool:
    name, child_parts, metadata = entry
    if not stat.S_ISDIR(metadata.st_mode):
        return False
    relative_path = "/".join(child_parts)
    identity = (metadata.st_dev, metadata.st_ino)
    if identity in traversal.seen_directories:
        message = f"included directory is aliased release evidence: {relative_path}"
        raise _contract_error(message)
    child_fd = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=directory_fd,
    )
    try:
        pinned = os.fstat(child_fd)
        if (
            not stat.S_ISDIR(pinned.st_mode)
            or (pinned.st_dev, pinned.st_ino) != identity
        ):
            message = "included directory changed while opening"
            raise _contract_error(message)
        traversal.seen_directories.add(identity)
        traversal.digest.update(b"D")
        _hash_tree_directory(
            child_fd,
            child_parts,
            traversal,
            policy,
        )
        after_entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if _stat_record_identity(metadata) != _stat_record_identity(after_entry):
            message = "included directory changed while reading"
            raise _contract_error(message)
    finally:
        os.close(child_fd)
    return True


def _hash_tree_directory(
    directory_fd: int,
    parts: tuple[str, ...],
    traversal: _TreeTraversal,
    policy: _TreePolicy,
) -> None:
    """Hash a directory exclusively through pinned no-follow descriptors."""
    names = tuple(sorted(os.listdir(directory_fd)))
    for name in names:
        child_parts = (*parts, name)
        if _tree_entry_is_excluded(child_parts, policy.excluded_directories):
            continue
        metadata = os.stat(
            name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        relative_path = "/".join(child_parts)
        relative = relative_path.encode()
        traversal.digest.update(len(relative).to_bytes(8, "big"))
        traversal.digest.update(relative)
        traversal.digest.update((metadata.st_mode & 0o7777).to_bytes(4, "big"))
        if _hash_tree_symlink(
            directory_fd,
            (name, relative_path),
            metadata,
            traversal,
            preserve_symlink_records=policy.preserve_symlink_records,
        ):
            continue
        if _hash_child_directory(
            directory_fd,
            (name, child_parts, metadata),
            traversal,
            policy,
        ):
            continue
        if stat.S_ISREG(metadata.st_mode):
            identity = (metadata.st_dev, metadata.st_ino)
            if metadata.st_nlink != 1 or identity in traversal.seen_files:
                msg = (
                    "included regular file is aliased release evidence: "
                    f"{relative_path}"
                )
                raise _contract_error(msg)
            traversal.seen_files.add(identity)
            traversal.digest.update(b"F")
            data = _read_tree_file(directory_fd, name, metadata)
            traversal.digest.update(len(data).to_bytes(8, "big"))
            traversal.digest.update(data)
        else:
            traversal.digest.update(b"O")
            traversal.digest.update(stat.S_IFMT(metadata.st_mode).to_bytes(4, "big"))
    if tuple(sorted(os.listdir(directory_fd))) != names:
        msg = "included directory changed while reading"
        raise _contract_error(msg)


def _tree_sha256(
    root: Path,
    *,
    excluded_directories: frozenset[str],
    preserve_symlink_records: bool,
) -> str:
    if root.is_symlink():
        msg = f"root symlink is not release evidence: {root}"
        raise _contract_error(msg)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        root_fd = os.open(root, flags)
    except OSError as exc:
        msg = f"release root is not a directory: {root}"
        raise _contract_error(msg) from exc
    try:
        metadata = os.fstat(root_fd)
        if not stat.S_ISDIR(metadata.st_mode):
            msg = f"release root is not a directory: {root}"
            raise _contract_error(msg)
        digest = hashlib.sha256()
        traversal = _TreeTraversal(
            digest=digest,
            seen_files=set(),
            seen_directories={(metadata.st_dev, metadata.st_ino)},
        )
        _hash_tree_directory(
            root_fd,
            (),
            traversal,
            _TreePolicy(
                excluded_directories=excluded_directories,
                preserve_symlink_records=preserve_symlink_records,
            ),
        )
        if _stat_record_identity(os.fstat(root_fd)) != _stat_record_identity(metadata):
            message = f"release root changed while reading: {root}"
            raise _contract_error(message)
        return digest.hexdigest()
    except OSError as exc:
        msg = f"release tree changed or became unreadable: {root}"
        raise _contract_error(msg) from exc
    finally:
        os.close(root_fd)


def _is_json_value(value: object) -> TypeGuard[JsonValue]:
    if value is None or isinstance(value, (bool, int, float, str)):
        return True
    if isinstance(value, list):
        items = cast("list[object]", value)
        return all(_is_json_value(item) for item in items)
    if isinstance(value, dict):
        items = cast("dict[object, object]", value)
        return all(
            isinstance(key, str) and _is_json_value(item) for key, item in items.items()
        )
    return False


def _is_json_object(value: object) -> TypeGuard[dict[str, JsonValue]]:
    if not isinstance(value, dict):
        return False
    document = cast("object", value)
    return _is_json_value(document)


def load_json_object_bytes(content: bytes, label: str) -> dict[str, JsonValue]:
    """Decode uniquely named JSON object bytes without reopening an authority path."""

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                msg = f"duplicate JSON key in authoritative input: {label}"
                raise _contract_error(msg)
            result[key] = value
        return result

    try:
        decoded = cast(
            "object",
            json.loads(content, object_pairs_hook=reject_duplicates),
        )
    except json.JSONDecodeError as exc:
        message = f"invalid JSON-formatted authoritative input: {label}"
        raise _contract_error(message) from exc
    if not _is_json_object(decoded):
        message = f"authoritative input must be a JSON object: {label}"
        raise _contract_error(message)
    return decoded


def load_json_object(path: Path) -> dict[str, JsonValue]:
    """Decode an authority file through a pinned unique-file descriptor."""
    return load_json_object_bytes(
        _read_regular_bytes(path, f"JSON input {path}"),
        str(path),
    )


def requirement_ids_from_document(
    document: dict[str, JsonValue],
) -> tuple[str, ...]:
    """Strictly return every normative requirement record."""
    requirements = document.get("requirements")
    if not isinstance(requirements, dict):
        msg = "requirements object is missing"
        raise _contract_error(msg)
    identifiers = tuple(sorted(requirements))
    for identifier, record in requirements.items():
        if REQUIREMENT_ID_PATTERN.fullmatch(identifier) is None:
            msg = f"unrecognized normative requirement IDs: {(identifier,)}"
            raise _contract_error(msg)
        if not isinstance(record, dict):
            msg = f"malformed requirement record: {identifier}"
            raise _contract_error(msg)
        values = (
            record.get("kind"),
            record.get("priority"),
            record.get("statement"),
        )
        if not all(isinstance(value, str) and value for value in values):
            msg = f"malformed requirement record: {identifier}"
            raise _contract_error(msg)
    if len(identifiers) != EXPECTED_REQUIREMENT_COUNT:
        msg = (
            "requirements authority must contain exactly "
            f"{EXPECTED_REQUIREMENT_COUNT} records"
        )
        raise _contract_error(msg)
    return identifiers


def requirement_ids(requirements_path: Path) -> tuple[str, ...]:
    """Read and return every normative requirement through a pinned descriptor."""
    return requirement_ids_from_document(load_json_object(requirements_path))


def durable_goal_ids_from_document(
    document: dict[str, JsonValue],
) -> tuple[str, ...]:
    """Strictly return every current and later-appended durable goal record."""
    goals = document.get("goals")
    if not isinstance(goals, list) or not goals:
        msg = "durable goals authority must contain a nonempty goal list"
        raise _contract_error(msg)
    identifiers: list[str] = []
    for item in goals:
        if not isinstance(item, dict):
            msg = "malformed durable goal record"
            raise _contract_error(msg)
        identifier = item.get("id")
        status = item.get("status")
        required_strings = (
            item.get("title"),
            item.get("objective"),
            item.get("createdAt"),
        )
        if (
            not isinstance(identifier, str)
            or re.fullmatch(r"G\d{3}", identifier) is None
        ):
            msg = "malformed durable goal ID"
            raise _contract_error(msg)
        if status not in GOAL_STATUSES or not all(
            isinstance(value, str) and value for value in required_strings
        ):
            msg = f"malformed durable goal record: {identifier}"
            raise _contract_error(msg)
        identifiers.append(identifier)
    if len(identifiers) != len(set(identifiers)):
        msg = "durable goals must have unique IDs"
        raise _contract_error(msg)
    expected = {f"G{number:03d}" for number in range(1, len(identifiers) + 1)}
    if set(identifiers) != expected:
        msg = "durable goals contain unknown or missing IDs"
        raise _contract_error(msg)
    return tuple(sorted(identifiers))


def durable_goal_ids(goals_path: Path) -> tuple[str, ...]:
    """Read and return durable goal IDs through a pinned descriptor."""
    return durable_goal_ids_from_document(load_json_object(goals_path))


def verify_coverage_matrix(
    receipt: ReleaseReceipt,
    requirements_bytes: bytes,
    goals_bytes: bytes,
) -> None:
    """Require exact, fresh, non-prose coverage of normative IDs and stories."""
    if receipt.authority.requirements_sha256 != sha256_bytes(requirements_bytes):
        message = "stale requirements source root"
        raise _contract_error(message)
    if receipt.authority.goals_sha256 != sha256_bytes(goals_bytes):
        message = "stale goals source root"
        raise _contract_error(message)
    requirements_document = load_json_object_bytes(requirements_bytes, "requirements")
    goals_document = load_json_object_bytes(goals_bytes, "goals")
    state_revision = goals_document.get("state_revision")
    if (
        not isinstance(state_revision, int)
        or isinstance(state_revision, bool)
        or receipt.authority.goals_state_revision != state_revision
    ):
        message = "stale durable goals revision"
        raise _contract_error(message)
    expected_requirements = set(requirement_ids_from_document(requirements_document))
    expected_goals = set(durable_goal_ids_from_document(goals_document))
    requirement_counts = Counter(
        identifier
        for control in receipt.controls
        for identifier in control.requirement_ids
    )
    goal_counts = Counter(
        identifier for control in receipt.controls for identifier in control.goal_ids
    )
    _verify_coverage(expected_requirements, requirement_counts, "requirement")
    _verify_coverage(expected_goals, goal_counts, "goal")
    missing_categories = set(EvidenceCategory) - {
        control.category for control in receipt.controls
    }
    if missing_categories:
        missing_values = sorted(item.value for item in missing_categories)
        message = f"missing release categories: {missing_values}"
        raise _contract_error(message)
    for control in receipt.controls:
        is_machine_success = (
            control.evidence_kind == "machine"
            and control.outcome == "success"
            and control.observed_positive_count > 0
        )
        if not is_machine_success:
            message = f"non-machine or non-vacuous coverage: {control.control_id}"
            raise _contract_error(message)
        if (
            control.requirement_ids or control.goal_ids
        ) and not control.attachment_sha256:
            msg = f"coverage mapping lacks attachments: {control.control_id}"
            raise _contract_error(msg)


def _verify_coverage(
    expected: set[str],
    actual: Counter[str],
    label: str,
) -> None:
    unknown = set(actual) - expected
    missing = expected - set(actual)
    duplicate = {identifier for identifier, count in actual.items() if count != 1}
    if unknown or missing or duplicate:
        message = (
            f"invalid {label} coverage: unknown={sorted(unknown)} "
            f"missing={sorted(missing)} duplicate={sorted(duplicate)}"
        )
        raise _contract_error(message)


def _number(value: MeasurementValue) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _integer(value: MeasurementValue) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _boolean(value: MeasurementValue) -> bool | None:
    return value if isinstance(value, bool) else None


def _measurement_number(
    measurements: dict[str, MeasurementValue],
    key: str,
) -> float | None:
    value = measurements.get(key)
    return _number(value) if value is not None else None


def _measurement_integer(
    measurements: dict[str, MeasurementValue],
    key: str,
) -> int | None:
    value = measurements.get(key)
    return _integer(value) if value is not None else None


def _measurement_boolean(
    measurements: dict[str, MeasurementValue],
    key: str,
) -> bool | None:
    value = measurements.get(key)
    return _boolean(value) if value is not None else None


def _meets_nfr01(observation: NfrObservation) -> bool:
    success = _measurement_number(observation.measurements, "success_percent")
    failure = _measurement_number(
        observation.measurements, "max_continuous_failure_seconds"
    )
    return (
        observation.duration_seconds >= MIN_SOAK_SECONDS
        and observation.sample_count > 0
        and success is not None
        and MIN_SUCCESS_PERCENT <= success <= MAX_SUCCESS_PERCENT
        and failure is not None
        and 0 <= failure < MAX_CONTINUOUS_FAILURE_SECONDS
    )


def _meets_nfr02(observation: NfrObservation) -> bool:
    crud = _measurement_number(observation.measurements, "crud_p95_ms")
    errors = _measurement_number(observation.measurements, "error_percent")
    return (
        observation.sample_count > 0
        and crud is not None
        and 0 <= crud <= MAX_CRUD_P95_MS
        and errors is not None
        and 0 <= errors < 1
    )


def _meets_nfr03(observation: NfrObservation) -> bool:
    samples = _measurement_integer(observation.measurements, "visible_token_samples")
    duration = _measurement_number(
        observation.measurements, "visible_token_p95_seconds"
    )
    return (
        observation.sample_count > 0
        and samples is not None
        and 0 < samples <= observation.sample_count
        and duration is not None
        and 0 <= duration <= MAX_VISIBLE_TOKEN_P95_SECONDS
    )


def _meets_nfr04(observation: NfrObservation) -> bool:
    duration = _measurement_number(
        observation.measurements, "sandbox_allocation_p95_seconds"
    )
    return (
        observation.sample_count > 0
        and duration is not None
        and 0 <= duration <= MAX_SANDBOX_ALLOCATION_P95_SECONDS
    )


def _meets_nfr05(observation: NfrObservation) -> bool:
    mismatches = _measurement_integer(observation.measurements, "checksum_mismatches")
    return observation.sample_count > 0 and mismatches == 0


def _meets_nfr06(observation: NfrObservation) -> bool:
    recovery = _measurement_number(observation.measurements, "recovery_seconds")
    replays = _measurement_integer(observation.measurements, "side_effect_replays")
    return (
        observation.sample_count > 0
        and recovery is not None
        and 0 <= recovery <= MAX_RECOVERY_SECONDS
        and replays == 0
    )


def _meets_nfr07(observation: NfrObservation) -> bool:
    exported = _measurement_integer(observation.measurements, "export_bytes")
    duration = _measurement_number(observation.measurements, "export_seconds")
    return (
        observation.sample_count > 0
        and exported is not None
        and exported >= MIN_EXPORT_BYTES
        and duration is not None
        and 0 <= duration <= MAX_RECOVERY_SECONDS
    )


def _meets_nfr08(observation: NfrObservation) -> bool:
    keyboard_complete = _measurement_boolean(
        observation.measurements, "keyboard_complete"
    )
    violations = _measurement_integer(
        observation.measurements, "serious_wcag_violations"
    )
    return (
        observation.sample_count > 0 and keyboard_complete is True and violations == 0
    )


def _meets_nfr09(observation: NfrObservation) -> bool:
    if observation.sample_count < MIN_BROWSER_CASES:
        return False
    for browser in BROWSERS:
        values = observation.measurements.get(f"{browser}_major_versions")
        latest = _measurement_integer(
            observation.measurements, f"{browser}_latest_major"
        )
        cases = _measurement_integer(observation.measurements, f"{browser}_p0_cases")
        failures = _measurement_integer(
            observation.measurements, f"{browser}_p0_failures"
        )
        if (
            not isinstance(values, tuple)
            or len(values) < MIN_BROWSER_MAJOR_VERSIONS
            or latest is None
            or latest < MIN_BROWSER_MAJOR_VERSIONS
            or cases is None
            or cases <= 0
            or failures != 0
        ):
            return False
        parsed = tuple(_integer(value) for value in values)
        if any(value is None or value <= 0 for value in parsed):
            return False
        observed = {value for value in parsed if value is not None}
        if not {latest - 1, latest}.issubset(observed):
            return False
    return True


def _meets_nfr10(observation: NfrObservation) -> bool:
    current = _measurement_boolean(
        observation.measurements, "quarterly_restore_current"
    )
    rpo = _measurement_number(observation.measurements, "rpo_minutes")
    rto = _measurement_number(observation.measurements, "rto_minutes")
    tombstones = _measurement_boolean(observation.measurements, "tombstones_replayed")
    replays = _measurement_integer(observation.measurements, "side_effect_replays")
    restore_evidence_date = observation.measurements.get("restore_evidence_date")
    observed_quarter = (int(observation.observed_end_utc[5:7]) - 1) // 3
    return (
        observation.sample_count > 0
        and current is True
        and rpo is not None
        and 0 <= rpo <= MAX_RPO_MINUTES
        and rto is not None
        and 0 <= rto <= MAX_RTO_MINUTES
        and tombstones is True
        and replays == 0
        and isinstance(restore_evidence_date, str)
        and re.fullmatch(r"\d{4}-\d{2}-\d{2}", restore_evidence_date) is not None
        and int(restore_evidence_date[:4]) == int(observation.observed_end_utc[:4])
        and (int(restore_evidence_date[5:7]) - 1) // 3 == observed_quarter
    )


NFR_EVALUATORS: dict[NfrRequirementId, Callable[[NfrObservation], bool]] = {
    "NFR01": _meets_nfr01,
    "NFR02": _meets_nfr02,
    "NFR03": _meets_nfr03,
    "NFR04": _meets_nfr04,
    "NFR05": _meets_nfr05,
    "NFR06": _meets_nfr06,
    "NFR07": _meets_nfr07,
    "NFR08": _meets_nfr08,
    "NFR09": _meets_nfr09,
    "NFR10": _meets_nfr10,
}


def evaluate_nfr(observation: NfrObservation | None) -> bool:
    """Evaluate one fully measured NFR; absent or malformed data fails closed."""
    if observation is None:
        return False
    return NFR_EVALUATORS[observation.requirement_id](observation)


def verify_nfrs(observations: Iterable[NfrObservation]) -> None:
    """Require exactly one passing observation for every G006 NFR."""
    raw = tuple(observations)
    indexed = {item.requirement_id: item for item in raw}
    if (
        len(raw) != NFR_COUNT
        or len(indexed) != NFR_COUNT
        or not all(
            evaluate_nfr(indexed.get(identifier)) for identifier in NFR_REQUIREMENT_IDS
        )
    ):
        msg = "NFR evidence is missing, duplicated, or below threshold"
        raise _contract_error(msg)


@dataclass(frozen=True, slots=True)
class ReleaseFinalizationContext:
    """Paths whose current bytes and trees an independent authority must resolve."""

    science_root: Path
    drylab_root: Path
    ontologylab_root: Path
    requirements_path: Path
    goals_path: Path
    evidence_root: Path
    command_catalog_path: Path
    dependency_path: Path
    fixture_path: Path
    toolchain_path: Path
    revision_anchor_path: Path
    external_anchor_path: Path


@dataclass(frozen=True, slots=True)
class ResolvedReleaseAuthority:
    """Exact bytes independently obtained for every non-tree release authority."""

    command_catalog: bytes
    dependency: bytes
    fixture: bytes
    toolchain: bytes
    revision_anchor: bytes
    requirements: bytes
    goals: bytes
    external_anchor: bytes


@runtime_checkable
class ReleaseAuthorityResolver(Protocol):
    """Independently resolve current release authority instead of caller claims."""

    def resolve(self, context: ReleaseFinalizationContext) -> ResolvedReleaseAuthority:
        """Return the exact bytes currently authorized for this finalization."""
        ...


def _read_regular_bytes(
    path: Path,
    label: str,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> bytes:
    """Read one authority file while rejecting links and non-regular entries."""
    try:
        metadata = path.lstat()
    except OSError as exc:
        msg = f"unavailable {label} authority"
        raise _contract_error(msg) from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        msg = f"{label} authority is not a unique regular file"
        raise _contract_error(msg)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            pinned = os.fstat(descriptor)
            identity = (pinned.st_dev, pinned.st_ino)
            if (
                not stat.S_ISREG(pinned.st_mode)
                or pinned.st_nlink != 1
                or pinned.st_dev != metadata.st_dev
                or pinned.st_ino != metadata.st_ino
                or (expected_identity is not None and identity != expected_identity)
            ):
                msg = f"{label} authority changed while opening"
                raise _contract_error(msg)
            chunks: list[bytes] = []
            while block := os.read(descriptor, 65536):
                chunks.append(block)
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except OSError as exc:
        msg = f"unreadable {label} authority"
        raise _contract_error(msg) from exc


def _verify_resolved_bytes(
    context: ReleaseFinalizationContext,
    resolved: ResolvedReleaseAuthority,
    receipt: ReleaseReceipt,
) -> None:
    """Require each independent authority response to equal current on-disk bytes."""
    inputs = (
        (
            "command_catalog",
            context.command_catalog_path,
            resolved.command_catalog,
            receipt.authority.command_catalog_sha256,
        ),
        (
            "dependency",
            context.dependency_path,
            resolved.dependency,
            receipt.authority.dependency_sha256,
        ),
        (
            "fixture",
            context.fixture_path,
            resolved.fixture,
            receipt.authority.fixture_sha256,
        ),
        (
            "toolchain",
            context.toolchain_path,
            resolved.toolchain,
            receipt.authority.toolchain_sha256,
        ),
        (
            "revision",
            context.revision_anchor_path,
            resolved.revision_anchor,
            receipt.authority.revision_anchor_sha256,
        ),
        (
            "requirements",
            context.requirements_path,
            resolved.requirements,
            receipt.authority.requirements_sha256,
        ),
        ("goals", context.goals_path, resolved.goals, receipt.authority.goals_sha256),
        (
            "external anchor",
            context.external_anchor_path,
            resolved.external_anchor,
            receipt.external_anchor_sha256,
        ),
    )
    for label, path, authority_bytes, expected_hash in inputs:
        current = _read_regular_bytes(path, label)
        if current != authority_bytes or expected_hash != sha256_bytes(current):
            msg = f"stale or untrusted {label} authority"
            raise _contract_error(msg)


def _declared_attachment_hashes(receipt: ReleaseReceipt) -> set[str]:
    """Return all evidence hashes that success proof must declare as attachments."""
    hashes = {control.raw_log_sha256 for control in receipt.controls}
    for control in receipt.controls:
        hashes.update(control.attachment_sha256)
    for external in receipt.external_evidence:
        if external.sha256 is not None:
            hashes.add(external.sha256)
        hashes.update(external.attachment_sha256)
    for review in receipt.independent_reviews:
        hashes.add(review.sha256)
        hashes.update(review.reviewed_capture_sha256)
    if receipt.manual_qa.sha256 is not None:
        hashes.add(receipt.manual_qa.sha256)
    if receipt.cleanup.receipt_sha256 is not None:
        hashes.add(receipt.cleanup.receipt_sha256)
    for observation in receipt.nfr_observations:
        hashes.update((observation.report_sha256, observation.raw_data_sha256))
    return hashes


@dataclass(slots=True)
class _EvidenceCollection:
    actual: dict[str, str]
    content_by_hash: dict[str, bytes]
    seen_files: set[tuple[int, int]]
    seen_directories: set[tuple[int, int]]


def _collect_evidence_files(
    directory_fd: int,
    parts: tuple[str, ...],
    collection: _EvidenceCollection,
) -> None:
    """Collect evidence only through a stable descriptor-relative traversal."""
    names = tuple(sorted(os.listdir(directory_fd)))
    for name in names:
        child_parts = (*parts, name)
        relative = "/".join(child_parts)
        metadata = os.stat(
            name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if stat.S_ISDIR(metadata.st_mode):
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in collection.seen_directories:
                msg = f"evidence contains aliased directory: {relative}"
                raise _contract_error(msg)
            child_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                pinned = os.fstat(child_fd)
                if (
                    not stat.S_ISDIR(pinned.st_mode)
                    or (pinned.st_dev, pinned.st_ino) != identity
                ):
                    msg = f"evidence directory changed while opening: {relative}"
                    raise _contract_error(msg)
                collection.seen_directories.add(identity)
                _collect_evidence_files(
                    child_fd,
                    child_parts,
                    collection,
                )
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            msg = f"evidence contains non-regular entry: {relative}"
            raise _contract_error(msg)
        identity = (metadata.st_dev, metadata.st_ino)
        if metadata.st_nlink != 1 or identity in collection.seen_files:
            msg = f"evidence contains aliased regular file: {relative}"
            raise _contract_error(msg)
        collection.seen_files.add(identity)
        content = _read_tree_file(directory_fd, name, metadata)
        try:
            require_evidence_sanitized(content)
        except EvidenceIntegrityError as exc:
            msg = f"evidence contains sensitive bytes: {relative}"
            raise _contract_error(msg) from exc
        digest = sha256_bytes(content)
        if digest in collection.content_by_hash:
            msg = f"evidence aliases a content digest: {relative}"
            raise _contract_error(msg)
        collection.actual[relative] = digest
        collection.content_by_hash[digest] = content
    if tuple(sorted(os.listdir(directory_fd))) != names:
        msg = "evidence directory changed while reading"
        raise _contract_error(msg)


def _verify_attachment_manifest(
    receipt: ReleaseReceipt, evidence_root: Path
) -> dict[str, bytes]:
    """Require a complete, sanitized regular-file manifest under the evidence root."""
    declared = {item.path: item.sha256 for item in receipt.attachments}
    if not declared or len(declared) != len(receipt.attachments):
        msg = "attachment manifest has duplicate or missing paths"
        raise _contract_error(msg)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        evidence_fd = os.open(evidence_root, flags)
    except OSError as exc:
        msg = "evidence root is not a directory"
        raise _contract_error(msg) from exc
    collection = _EvidenceCollection(
        actual={},
        content_by_hash={},
        seen_files=set(),
        seen_directories=set(),
    )
    try:
        root_metadata = os.fstat(evidence_fd)
        if not stat.S_ISDIR(root_metadata.st_mode):
            msg = "evidence root is not a directory"
            raise _contract_error(msg)
        collection.seen_directories.add((root_metadata.st_dev, root_metadata.st_ino))
        _collect_evidence_files(
            evidence_fd,
            (),
            collection,
        )
    except OSError as exc:
        msg = "evidence changed or became unreadable"
        raise _contract_error(msg) from exc
    finally:
        os.close(evidence_fd)
    if collection.actual != declared:
        msg = "attachment manifest is incomplete or mismatched"
        raise _contract_error(msg)
    if not _declared_attachment_hashes(receipt).issubset(set(declared.values())):
        msg = "referenced evidence is absent from attachment manifest"
        raise _contract_error(msg)
    return collection.content_by_hash


def _without_seals(value: JsonValue) -> JsonValue:
    """Remove detached seal fields from recursively typed JSON claim data."""
    if isinstance(value, dict):
        return {
            key: _without_seals(item)
            for key, item in value.items()
            if key not in {"seal", "revision_anchor_seal", "external_anchor_seal"}
        }
    if isinstance(value, list):
        return [_without_seals(item) for item in value]
    return value


def _claim_bytes(claim: StrictModel) -> bytes:
    """Canonical unsigned claim bytes; a seal cannot sign itself."""
    return canonical_bytes(_without_seals(claim.canonical_projection()))


@dataclass(frozen=True, slots=True)
class ClaimSealVerificationContext:
    """Trusted release values shared by detached claim-seal verification."""

    receipt: ReleaseReceipt
    trust: FinalizationTrust
    final_time: datetime


def _verify_claim_seal(
    claim: StrictModel,
    seal: DetachedEvidenceSeal | None,
    kind: ClaimKind,
    context: ClaimSealVerificationContext,
) -> None:
    """Verify one detached claim against its role-pinned release context."""
    if seal is None or seal.claim_kind != kind:
        msg = f"{kind.value} claim has no matching detached seal"
        raise _contract_error(msg)
    matches = [
        item for item in context.trust.evidence_issuers if item.claim_kind == kind
    ]
    if len(matches) != 1:
        msg = f"{kind.value} issuer trust is not uniquely pinned"
        raise _contract_error(msg)
    issuer = matches[0].pinned_issuer()
    if seal.issuer_id != issuer.issuer_id:
        msg = f"{kind.value} seal has an untrusted issuer"
        raise _contract_error(msg)
    authority = context.receipt.authority
    if (
        seal.release_id != context.receipt.release_id
        or seal.run_id != context.receipt.run_id
        or seal.attempt_id != context.receipt.attempt_id
        or seal.source_tree_sha256 != authority.source_tree_sha256
        or seal.verified_revision != authority.verified_revision
        or seal.requirements_sha256 != authority.requirements_sha256
        or seal.goals_sha256 != authority.goals_sha256
        or seal.goals_state_revision != authority.goals_state_revision
        or seal.session_id != authority.session_id
        or seal.lease_generation != authority.lease_generation
        or seal.command_catalog_sha256 != authority.command_catalog_sha256
        or seal.toolchain_sha256 != authority.toolchain_sha256
        or seal.claim_sha256 != sha256_bytes(_claim_bytes(claim))
    ):
        msg = f"{kind.value} seal is not bound to this release"
        raise _contract_error(msg)
    _ = _require_fresh_timestamp(
        seal.issued_at_utc, context.final_time, f"{kind.value} seal"
    )
    if not issuer.verify(
        canonical_bytes(seal.canonical_projection(exclude={"signature_b64"})),
        _decode_signature(seal.signature_b64, f"{kind.value} seal"),
    ):
        msg = f"{kind.value} seal signature verification failed"
        raise _contract_error(msg)


def _verify_success_seals(
    receipt: ReleaseReceipt, trust: FinalizationTrust, final_time: datetime
) -> None:
    for control in receipt.controls:
        _verify_claim_seal(
            control,
            control.seal,
            ClaimKind.CI,
            ClaimSealVerificationContext(receipt, trust, final_time),
        )
        if (
            not control.authority_context_id
            or not control.authority_generation_id
            or control.manifest_sha256 is None
            or control.observed_epoch != receipt.authority.goals_state_revision
            or control.coverage_sha256 not in control.attachment_sha256
        ):
            msg = "CI claim lacks current authority, epoch, or coverage binding"
            raise _contract_error(msg)
    ci_epochs = {
        (
            control.authority_context_id,
            control.authority_generation_id,
            control.manifest_sha256,
            control.observed_epoch,
        )
        for control in receipt.controls
    }
    if len(ci_epochs) != 1:
        msg = "CI claims do not share one current-run authority epoch"
        raise _contract_error(msg)
    for item in receipt.external_evidence:
        _verify_claim_seal(
            item,
            item.seal,
            ClaimKind.EXTERNAL,
            ClaimSealVerificationContext(receipt, trust, final_time),
        )
    for item in receipt.independent_reviews:
        _verify_claim_seal(
            item,
            item.seal,
            ClaimKind.REVIEW,
            ClaimSealVerificationContext(receipt, trust, final_time),
        )
    _verify_claim_seal(
        receipt.manual_qa,
        receipt.manual_qa.seal,
        ClaimKind.MANUAL_QA,
        ClaimSealVerificationContext(receipt, trust, final_time),
    )
    _verify_claim_seal(
        receipt.cleanup,
        receipt.cleanup.seal,
        ClaimKind.CLEANUP,
        ClaimSealVerificationContext(receipt, trust, final_time),
    )
    for item in receipt.nfr_observations:
        _verify_claim_seal(
            item,
            item.seal,
            ClaimKind.NFR,
            ClaimSealVerificationContext(receipt, trust, final_time),
        )
    _verify_claim_seal(
        receipt,
        receipt.revision_anchor_seal,
        ClaimKind.REVISION_ANCHOR,
        ClaimSealVerificationContext(receipt, trust, final_time),
    )
    _verify_claim_seal(
        receipt,
        receipt.external_anchor_seal,
        ClaimKind.EXTERNAL_ANCHOR,
        ClaimSealVerificationContext(receipt, trust, final_time),
    )


def _verify_success_human_evidence(receipt: ReleaseReceipt) -> None:
    """Require complete external, review, manual-QA, and cleanup success proof."""
    externals = {item.control_id: item for item in receipt.external_evidence}
    if set(externals) != set(REQUIRED_EXTERNAL_CONTROL_IDS):
        msg = "external control inventory is incomplete"
        raise _contract_error(msg)
    for item in externals.values():
        required_requirements, required_goals = REQUIRED_EXTERNAL_BINDINGS[
            item.control_id
        ]
        if (
            not item.available
            or item.sha256 is None
            or not item.authority_id
            or item.observed_at_utc is None
            or item.requirement_ids != required_requirements
            or item.goal_ids != required_goals
            or not item.attachment_sha256
        ):
            msg = "external control lacks exact source-bound authority"
            raise _contract_error(msg)
    code = [item for item in receipt.independent_reviews if item.role == "code"]
    visual = [item for item in receipt.independent_reviews if item.role == "visual"]
    if len(code) != 1 or len(visual) != REQUIRED_VISUAL_REVIEW_COUNT:
        msg = "independent review inventory is incomplete"
        raise _contract_error(msg)
    reviews = (*code, *visual)
    if (
        any(
            not item.independent
            or item.decision != "pass"
            or item.reviewed_source_sha256 != receipt.authority.source_tree_sha256
            or not item.authority_id
            or item.reviewed_at_utc is None
            or (item.role == "visual" and not item.reviewed_capture_sha256)
            for item in reviews
        )
        or len({item.reviewer_id for item in reviews}) != len(reviews)
        or len({item.authority_id for item in reviews}) != len(reviews)
        or len({item.reviewed_at_utc for item in reviews}) != len(reviews)
    ):
        msg = "reviews are not independent, passing, and source-bound"
        raise _contract_error(msg)
    qa = receipt.manual_qa
    if (
        not qa.performed
        or qa.blocker_count
        or qa.sha256 is None
        or qa.tested_source_sha256 != receipt.authority.source_tree_sha256
        or qa.performed_at_utc is None
        or not qa.operator_id
    ):
        msg = "manual QA is not complete and source-bound"
        raise _contract_error(msg)
    if not receipt.cleanup.complete or receipt.cleanup.receipt_sha256 is None:
        msg = "cleanup is not complete"
        raise _contract_error(msg)


def verify_and_finalize_success(
    receipt: ReleaseReceipt,
    *,
    context: ReleaseFinalizationContext,
    authority_resolver: object,
) -> None:
    """Retired unsafe API; success requires ``ReleaseFinalizer`` and a pinned seal."""
    _ = receipt, context, authority_resolver
    msg = (
        "caller-owned finalization is forbidden; use ReleaseFinalizer with pinned trust"
    )
    raise _contract_error(msg)


class EvidenceKind(StrEnum):
    """A non-interchangeable release evidence role."""

    CONTROL_LOG = "control-log"
    EXTERNAL_CONTROL = "external-control"
    REVIEW = "review"
    CAPTURE = "capture"
    MANUAL_QA = "manual-qa"
    CLEANUP = "cleanup"
    NFR_RAW = "nfr-raw"
    NFR_REPORT = "nfr-report"


class EvidenceReference(StrictModel):
    """Signed, epoch-bound pointer to one confined evidence file."""

    path: str = Field(min_length=1)
    sha256: str = Field(pattern=SHA256)
    kind: EvidenceKind
    issuer_id: str = Field(min_length=1)
    release_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    attempt_id: str = Field(min_length=1)
    source_tree_sha256: str = Field(pattern=SHA256)
    verified_revision: str = Field(min_length=1)
    requirements_sha256: str = Field(pattern=SHA256)
    goals_sha256: str = Field(pattern=SHA256)
    goals_state_revision: int = Field(ge=0)
    session_id: str = Field(min_length=1)
    lease_generation: str = Field(min_length=1)
    issued_at_utc: str
    signature_b64: str = Field(min_length=1)

    @model_validator(mode="after")
    def evidence_reference_is_confined(self) -> EvidenceReference:
        """Require one real timestamp and one confined relative attachment path."""
        _ = AttachmentEvidence(path=self.path, sha256=self.sha256)
        _ = _parse_utc(self.issued_at_utc)
        return self


class FinalizedReleasePayload(StrictModel):
    """The canonical success claim; its embedded receipt remains incomplete."""

    schema_version: Literal[1] = 1
    receipt: ReleaseReceipt
    finalized_at_utc: str
    finalization_nonce: str = Field(min_length=16)
    science_root_sha256: str = Field(pattern=SHA256)
    drylab_root_sha256: str = Field(pattern=SHA256)
    ontologylab_root_sha256: str = Field(pattern=SHA256)
    evidence_root_sha256: str = Field(pattern=SHA256)
    evidence_references: tuple[EvidenceReference, ...] = Field(min_length=1)
    session_id: str = Field(min_length=1)
    lease_generation: str = Field(min_length=1)

    @model_validator(mode="after")
    def success_payload_is_incomplete_receipt(self) -> FinalizedReleasePayload:
        """Keep ordinary receipts non-successful beneath the signed envelope."""
        if self.receipt.outcome != "incomplete":
            msg = "finalized payload must seal an incomplete receipt"
            raise ValueError(msg)
        _ = _parse_utc(self.finalized_at_utc)
        if len({(ref.kind, ref.path) for ref in self.evidence_references}) != len(
            self.evidence_references
        ):
            msg = "duplicate typed evidence reference"
            raise ValueError(msg)
        return self


class FinalizedReleaseEnvelope(StrictModel):
    """Detached, authority-sealed success boundary."""

    schema_version: Literal[1] = 1
    payload: FinalizedReleasePayload
    payload_sha256: str = Field(pattern=SHA256)
    authority_id: str = Field(min_length=1)
    key_id: str = Field(min_length=1)
    algorithm: str = Field(min_length=1)
    authority_version: str = Field(min_length=1)
    environment: Literal["production", "test"]
    signature_b64: str = Field(min_length=1)


@runtime_checkable
class FinalizationVerifier(Protocol):
    """Verify-only final-envelope authority exposed to consumers."""

    @property
    def authority_id(self) -> str:
        """Return the pinned verifier authority ID."""
        ...

    @property
    def key_id(self) -> str:
        """Return the pinned verification key ID."""
        ...

    @property
    def algorithm(self) -> str:
        """Return the pinned signature algorithm."""
        ...

    @property
    def authority_version(self) -> str:
        """Return the pinned authority version."""
        ...

    @property
    def environment(self) -> Literal["production", "test"]:
        """Return the verifier trust environment."""
        ...

    def verify(self, payload: bytes, signature: bytes) -> bool:
        """Verify one detached authorization signature."""
        ...


@runtime_checkable
class FinalizationIssuer(Protocol):
    """Issuance capability held only by ReleaseFinalizer."""

    @property
    def authority_id(self) -> str:
        """Return the issuer authority ID."""
        ...

    @property
    def key_id(self) -> str:
        """Return the issuer signing key ID."""
        ...

    @property
    def algorithm(self) -> str:
        """Return the issuer signature algorithm."""
        ...

    @property
    def authority_version(self) -> str:
        """Return the issuer authority version."""
        ...

    @property
    def environment(self) -> Literal["production", "test"]:
        """Return the issuer environment."""
        ...

    def sign(self, payload: bytes) -> bytes:
        """Sign one policy-approved authorization object."""
        ...

    def issue_finalization(self) -> tuple[str, str]:
        """Issue signer-owned UTC time and a unique nonce."""
        ...


@runtime_checkable
class ReleaseAuthorizationConsumer(Protocol):
    """Resolve-and-consume capability exposed to final-envelope verifiers."""

    @property
    def authority_id(self) -> str:
        """Return the authorization consumer ID."""
        ...

    @property
    def trust_domain(self) -> str:
        """Return the authorization consumer trust domain."""
        ...

    def consume(
        self,
        session_id: str,
        lease_generation: str,
        payload_sha256: str,
        nonce: str,
    ) -> bool:
        """Atomically authorize and consume one exact finalization nonce."""
        ...


@runtime_checkable
class ReleaseAuthorizationWriter(Protocol):
    """Binding capability held only by ReleaseFinalizer."""

    @property
    def authority_id(self) -> str:
        """Return the authorization writer ID."""
        ...

    @property
    def trust_domain(self) -> str:
        """Return the authorization writer trust domain."""
        ...

    def bind(self, session_id: str, lease_generation: str, payload_sha256: str) -> None:
        """Atomically authorize one exact policy-approved payload."""
        ...


@dataclass(frozen=True, slots=True)
class EvidenceIssuerTrust:
    """Pin one detached-claim kind to its runtime-owned evidence issuer."""

    claim_kind: ClaimKind
    issuer: object
    issuer_id: str

    def pinned_issuer(self) -> EvidenceIssuer:
        """Return the issuer only when it matches this pinned role identity."""
        issuer = self.issuer
        if not isinstance(issuer, EvidenceIssuer) or issuer.issuer_id != self.issuer_id:
            msg = "evidence issuer does not match pinned role trust"
            raise _contract_error(msg)
        return issuer


@dataclass(frozen=True, slots=True)
class FinalizationTrust:
    """Pinned runtime trust configuration for one finalization authority."""

    authority: FinalizationVerifier
    authority_id: str
    key_id: str
    algorithm: str
    authority_version: str
    environment: Literal["production", "test"]
    expected_session_id: str
    expected_lease_generation: str
    ci_execution_authority: CiGenerationManifestAuthority
    ci_execution_authority_context: str
    evidence_issuers: tuple[EvidenceIssuerTrust, ...]
    authorization_authority: ReleaseAuthorizationConsumer
    authorization_authority_id: str
    authorization_trust_domain: str

    def pinned_authority(self) -> FinalizationVerifier:
        """Return the structurally valid authority matching every pinned identity."""
        authority = self.authority
        if (
            authority.authority_id != self.authority_id
            or authority.key_id != self.key_id
            or authority.algorithm != self.algorithm
            or authority.authority_version != self.authority_version
            or authority.environment != self.environment
        ):
            msg = "finalization authority does not match pinned trust"
            raise _contract_error(msg)
        return authority


@dataclass(frozen=True, slots=True)
class ReleaseSnapshotLease:
    """Runtime-owned immutable release topology held through finalization."""

    context: ReleaseFinalizationContext
    revision: str


@runtime_checkable
class ReleaseSnapshotAuthority(Protocol):
    """Supervisor composition root for canonical workspace and active session."""

    def acquire(self) -> ReleaseSnapshotLease:
        """Acquire one pinned snapshot/lock lease."""
        ...

    def verify(self, lease: ReleaseSnapshotLease) -> None:
        """Verify the lease still represents the pinned snapshot."""
        ...

    def release(self, lease: ReleaseSnapshotLease) -> None:
        """Release the lease after finalization."""
        ...


@dataclass(frozen=True, slots=True)
class ReleaseFinalizer:
    """Finalize only from a supervisor-issued pinned snapshot lease."""

    snapshot_authority: ReleaseSnapshotAuthority
    trust: FinalizationTrust
    issuer: FinalizationIssuer
    authorization_writer: ReleaseAuthorizationWriter

    def context(self) -> ReleaseFinalizationContext:
        """Return one currently verified supervisor-owned context."""
        lease = self.snapshot_authority.acquire()
        try:
            self.snapshot_authority.verify(lease)
            return lease.context
        finally:
            self.snapshot_authority.release(lease)

    def finalize(
        self,
        receipt: ReleaseReceipt,
        *,
        finalized_at_utc: str | None = None,
        finalization_nonce: str | None = None,
        mutation_hook: Callable[[], None] | None = None,
    ) -> FinalizedReleaseEnvelope:
        """Validate a lease, sign its stable bytes, then verify/release it."""
        receipt = ReleaseReceipt.model_validate(receipt.model_dump(mode="json"))
        lease = self.snapshot_authority.acquire()
        try:
            context = lease.context
            if (
                receipt.authority.session_id
                != lease.context.goals_path.parent.parent.name.removeprefix("_session-")
                or receipt.authority.lease_generation != lease.revision
                or receipt.authority.session_id != self.trust.expected_session_id
                or receipt.authority.lease_generation
                != self.trust.expected_lease_generation
            ):
                msg = "receipt session does not match snapshot lease"
                raise _contract_error(msg)
            if not lease.revision:
                msg = "snapshot lease has no revision"
                raise _contract_error(msg)
            if any(
                path.is_symlink()
                for path in (
                    context.science_root,
                    context.drylab_root,
                    context.ontologylab_root,
                    context.evidence_root,
                )
            ):
                msg = "snapshot lease contains a root alias"
                raise _contract_error(msg)
            self.snapshot_authority.verify(lease)
            authority = self.issuer
            if (
                authority.authority_id != self.trust.authority_id
                or authority.key_id != self.trust.key_id
                or authority.algorithm != self.trust.algorithm
                or authority.authority_version != self.trust.authority_version
                or authority.environment != self.trust.environment
                or self.authorization_writer.authority_id
                != self.trust.authorization_authority_id
                or self.authorization_writer.trust_domain
                != self.trust.authorization_trust_domain
                or self.authorization_writer.authority_id == authority.authority_id
            ):
                msg = "finalization issuance capabilities are not pinned"
                raise _contract_error(msg)
            issued_at_utc, signer_nonce = authority.issue_finalization()
            _ = _parse_utc(issued_at_utc)
            if finalized_at_utc is not None or finalization_nonce is not None:
                msg = "caller-owned finalization time or nonce is forbidden"
                raise _contract_error(msg)
            if len(signer_nonce) < MIN_FINALIZATION_NONCE_LENGTH:
                msg = "finalization authority issued an invalid nonce"
                raise _contract_error(msg)
            before = _finalization_snapshot(context)
            _verify_finalization_candidate(
                receipt, context, issued_at_utc, before, self.trust
            )
            if mutation_hook is not None:
                mutation_hook()
            references = _references_from_manifest(receipt, issued_at_utc, authority)
            self.snapshot_authority.verify(lease)
            after = _finalization_snapshot(context)
            if before != after:
                msg = "release inputs changed during finalization"
                raise _contract_error(msg)
            payload = FinalizedReleasePayload(
                receipt=receipt,
                finalized_at_utc=issued_at_utc,
                finalization_nonce=signer_nonce,
                science_root_sha256=after[0],
                drylab_root_sha256=after[1],
                ontologylab_root_sha256=after[2],
                evidence_root_sha256=after[3],
                session_id=receipt.authority.session_id,
                lease_generation=lease.revision,
                evidence_references=references,
            )
            payload_bytes = canonical_bytes(payload)
            self.authorization_writer.bind(
                payload.session_id,
                payload.lease_generation,
                sha256_bytes(payload_bytes),
            )
            unsigned_envelope = FinalizedReleaseEnvelope(
                payload=payload,
                payload_sha256=sha256_bytes(payload_bytes),
                authority_id=authority.authority_id,
                key_id=authority.key_id,
                algorithm=authority.algorithm,
                authority_version=authority.authority_version,
                environment=self.trust.environment,
                signature_b64="pending",
            )
            signature_value = cast(
                "object", authority.sign(_envelope_authorization(unsigned_envelope))
            )
            if not isinstance(signature_value, bytes) or not signature_value:
                msg = "finalization authority returned an invalid signature"
                raise _contract_error(msg)
            return FinalizedReleaseEnvelope(
                payload=payload,
                payload_sha256=unsigned_envelope.payload_sha256,
                authority_id=authority.authority_id,
                key_id=authority.key_id,
                algorithm=authority.algorithm,
                authority_version=authority.authority_version,
                environment=self.trust.environment,
                signature_b64=base64.b64encode(signature_value).decode("ascii"),
            )
        finally:
            self.snapshot_authority.release(lease)


def _parse_utc(value: str) -> datetime:
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is None:
        msg = "timestamp must be strict UTC RFC3339 seconds"
        raise _contract_error(msg)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        msg = "timestamp is not a real UTC datetime"
        raise _contract_error(msg) from exc


def _finalization_snapshot(context: ReleaseFinalizationContext) -> tuple[str, ...]:
    return (
        source_tree_sha256(context.science_root),
        sibling_tree_sha256(context.drylab_root),
        sibling_tree_sha256(context.ontologylab_root),
        tree_sha256(context.evidence_root),
        *(
            sha256_bytes(_read_regular_bytes(path, label))
            for label, path in (
                ("requirements", context.requirements_path),
                ("goals", context.goals_path),
                ("command catalog", context.command_catalog_path),
                ("dependency", context.dependency_path),
                ("fixture", context.fixture_path),
                ("toolchain", context.toolchain_path),
                ("revision anchor", context.revision_anchor_path),
                ("external anchor", context.external_anchor_path),
            )
        ),
    )


def _verify_canonical_control_logs(
    receipt: ReleaseReceipt,
    catalog: CiControlCatalog,
    controls: dict[str, ControlEvidence],
    evidence_by_hash: dict[str, bytes],
    source_root: Path,
) -> None:
    """Verify each catalog control and rederive its count from the declared log."""
    if catalog.unverified_requirement_ids:
        msg = "CI catalog contains requirements without semantic evidence"
        raise _contract_error(msg)
    attachment_hashes = {item.sha256 for item in receipt.attachments}
    for job in catalog.jobs:
        control = controls[job.job.value]
        bindings = tuple(
            binding
            for binding in catalog.requirement_case_bindings
            if binding.job is job.job
        )
        if (
            control.category != CI_JOB_CATEGORIES[job.job]
            or control.argv != job.argv
            or control.outcome != "success"
            or control.count_kind != job.count_kind
            or control.parser_version != job.parser_version
            or control.analyzer_inventory_root_sha256
            != job.analyzer_inventory_root_sha256
            or control.catalog_root_sha256 != catalog.catalog_root_sha256
            or control.catalog_source_root_sha256 != catalog.source_root_sha256
            or control.requirement_ids != job.requirement_ids
            or control.catalog_run_id != receipt.run_id
            or control.release_id != receipt.release_id
            or control.run_id != receipt.run_id
            or control.attempt_id != receipt.attempt_id
            or control.source_root_sha256 != receipt.authority.source_tree_sha256
            or control.toolchain_sha256 != receipt.authority.toolchain_sha256
            or control.raw_log_sha256 not in attachment_hashes
        ):
            msg = f"control does not match canonical catalog: {job.job.value}"
            raise _contract_error(msg)
        for binding in bindings:
            expected_observation = ci_requirement_case_evidence_bytes(binding)
            if (
                sha256_bytes(expected_observation) != binding.observation_sha256
                or binding.observation_sha256 not in control.attachment_sha256
                or evidence_by_hash.get(binding.observation_sha256)
                != expected_observation
                or sha256_bytes(
                    _read_regular_bytes(
                        source_root / binding.source_path,
                        "CI requirement source",
                    )
                )
                != binding.source_sha256
                or sha256_bytes(
                    _read_regular_bytes(
                        source_root / binding.test_path,
                        "CI requirement test",
                    )
                )
                != binding.test_sha256
            ):
                msg = (
                    "requirement case evidence does not match its source and "
                    f"observation: {binding.case_id}"
                )
                raise _contract_error(msg)
        if (
            job.count_kind == "analyzer-inventory"
            and control.observed_positive_count != job.analyzer_inventory_count
        ):
            msg = f"control count does not match analyzer catalog: {job.job.value}"
            raise _contract_error(msg)
        gate_result = GateResult(
            job=job.job,
            executed_count=control.observed_positive_count,
            output_sha256=control.raw_log_sha256,
            argv=control.argv,
            count_kind=job.count_kind,
            parser_version=job.parser_version,
            analyzer_inventory_root_sha256=job.analyzer_inventory_root_sha256,
            category=job.category,
            environment_profile=job.environment_profile,
            control_ids=job.control_ids,
            attachment_sha256=control.attachment_sha256,
            outcome="success",
            catalog_root_sha256=catalog.catalog_root_sha256,
            catalog_source_root_sha256=catalog.source_root_sha256,
            catalog_run_id=receipt.run_id,
            requirement_ids=control.requirement_ids,
        )
        try:
            verify_ci_requirement_case_output(
                evidence_by_hash[control.raw_log_sha256],
                bindings,
            )
            rederive_gate_count(
                gate_result,
                evidence_by_hash[control.raw_log_sha256],
            )
        except EvidenceIntegrityError as exc:
            msg = f"control count is not derived from its log: {job.job.value}"
            raise _contract_error(msg) from exc


def _verify_control_execution_attestations(
    receipt: ReleaseReceipt,
    catalog: CiControlCatalog,
    controls: dict[str, ControlEvidence],
    trust: FinalizationTrust,
) -> None:
    """Require independent lease-bound receipts for all canonical CI controls."""
    authority = trust.ci_execution_authority
    authority_context = trust.ci_execution_authority_context
    try:
        current_run = authority.resolve_current(authority_context)
    except (AttributeError, LookupError, TypeError, ValueError):
        msg = "CI execution attestation authority is unavailable"
        raise _contract_error(msg) from None
    common_generations = {
        (control.authority_context_id, control.authority_generation_id)
        for control in controls.values()
    }
    common_manifests = {control.manifest_sha256 for control in controls.values()}
    if (
        current_run.state is not CiRunState.SUCCESS
        or current_run.authority_context != authority_context
        or current_run.run_id != receipt.run_id
        or current_run.attempt_id != receipt.attempt_id
        or current_run.source_tree_sha256 != receipt.authority.source_tree_sha256
        or current_run.generation_id is None
        or common_generations != {(authority_context, current_run.generation_id)}
        or len(common_manifests) != 1
        or None in common_manifests
    ):
        msg = "CI execution attestation does not match the current generation"
        raise _contract_error(msg)
    manifest_sha256 = next(item for item in common_manifests if item is not None)
    try:
        anchored_manifest = authority.resolve(
            authority_context,
            current_run.generation_id,
        )
    except (AttributeError, LookupError, TypeError, ValueError):
        msg = "CI execution attestation manifest is unavailable"
        raise _contract_error(msg) from None
    if anchored_manifest != manifest_sha256:
        msg = "CI execution attestation manifest is not authority-bound"
        raise _contract_error(msg)
    records: list[GateResult] = []
    for job in catalog.jobs:
        control = controls[job.job.value]
        attestation = control.execution_attestation
        if attestation is None:
            msg = f"CI execution attestation is missing: {job.job.value}"
            raise _contract_error(msg)
        records.append(
            GateResult(
                job=job.job,
                executed_count=control.observed_positive_count,
                output_sha256=control.raw_log_sha256,
                argv=control.argv,
                count_kind=job.count_kind,
                parser_version=job.parser_version,
                analyzer_inventory_root_sha256=job.analyzer_inventory_root_sha256,
                category=job.category,
                environment_profile=job.environment_profile,
                control_ids=job.control_ids,
                attachment_sha256=control.attachment_sha256,
                security_catalog_root_sha256=(attestation.security_catalog_root_sha256),
                security_threat_ids=attestation.security_threat_ids,
                security_evidence_roots=attestation.security_evidence_roots,
                started_at=attestation.started_at,
                finished_at=attestation.finished_at,
                outcome="success",
                catalog_root_sha256=catalog.catalog_root_sha256,
                catalog_source_root_sha256=catalog.source_root_sha256,
                catalog_run_id=receipt.run_id,
                requirement_ids=control.requirement_ids,
                prerequisites=job.prerequisites,
                blockers=job.blockers,
                execution_attestation=attestation,
            )
        )
    try:
        _ = verify_execution_attestations(authority, tuple(records), current_run)
        if authority.resolve_current(authority_context) != current_run:
            msg = "CI execution attestation generation changed during verification"
            raise _contract_error(msg)
    except (AttributeError, EvidenceIntegrityError, LookupError, TypeError, ValueError):
        msg = "CI execution attestation verification failed"
        raise _contract_error(msg) from None


def _verify_finalization_candidate(
    receipt: ReleaseReceipt,
    context: ReleaseFinalizationContext,
    finalized_at_utc: str,
    snapshot: tuple[str, ...],
    trust: FinalizationTrust,
) -> None:

    final_time = _parse_utc(finalized_at_utc)
    if receipt.outcome != "incomplete" or receipt.authority.dirty:
        msg = "only a clean incomplete receipt may be finalized"
        raise _contract_error(msg)
    _verify_success_seals(receipt, trust, final_time)
    resolved = ResolvedReleaseAuthority(
        command_catalog=_read_regular_bytes(
            context.command_catalog_path, "command catalog"
        ),
        dependency=_read_regular_bytes(context.dependency_path, "dependency"),
        fixture=_read_regular_bytes(context.fixture_path, "fixture"),
        toolchain=_read_regular_bytes(context.toolchain_path, "toolchain"),
        revision_anchor=_read_regular_bytes(
            context.revision_anchor_path, "revision anchor"
        ),
        requirements=_read_regular_bytes(context.requirements_path, "requirements"),
        goals=_read_regular_bytes(context.goals_path, "goals"),
        external_anchor=_read_regular_bytes(
            context.external_anchor_path, "external anchor"
        ),
    )
    _verify_resolved_bytes(context, resolved, receipt)
    if receipt.authority.source_tree_sha256 != snapshot[
        0
    ] or receipt.siblings != SiblingRoots(
        science_pre_sha256=snapshot[0],
        science_post_sha256=snapshot[0],
        drylab_pre_sha256=snapshot[1],
        drylab_post_sha256=snapshot[1],
        ontologylab_pre_sha256=snapshot[2],
        ontologylab_post_sha256=snapshot[2],
    ):
        msg = "frozen tree roots do not match canonical topology"
        raise _contract_error(msg)
    evidence_by_hash = _verify_attachment_manifest(receipt, context.evidence_root)
    catalog_document = load_json_object_bytes(
        resolved.command_catalog, "command catalog"
    )
    catalog_value = catalog_document.get("catalog")
    if not isinstance(catalog_value, dict):
        msg = "command catalog authority is missing its catalog"
        raise _contract_error(msg)
    try:
        catalog = CiControlCatalog.model_validate(catalog_value)
    except ValueError as exc:
        msg = "command catalog authority is invalid"
        raise _contract_error(msg) from exc
    if catalog.requirements_sha256 != sha256_bytes(resolved.requirements):
        msg = "CI catalog is stale for the requirements authority"
        raise _contract_error(msg)
    expected = {job.value: job for job in CiJob}
    controls = {item.control_id: item for item in receipt.controls}
    if len(controls) != len(receipt.controls) or set(controls) != set(expected):
        msg = "controls do not match the canonical 28-control catalog"
        raise _contract_error(msg)
    _verify_canonical_control_logs(
        receipt,
        catalog,
        controls,
        evidence_by_hash,
        context.science_root,
    )
    _verify_control_execution_attestations(receipt, catalog, controls, trust)
    verify_coverage_matrix(receipt, resolved.requirements, resolved.goals)
    goals = load_json_object_bytes(resolved.goals, "goals").get("goals")
    if not isinstance(goals, list) or any(
        not isinstance(goal, dict) or goal.get("status") != "complete" for goal in goals
    ):
        msg = "durable prerequisite goal is not terminally complete"
        raise _contract_error(msg)
    _verify_success_human_evidence(receipt)
    _verify_epoch_times(receipt, final_time)
    verify_nfrs(receipt.nfr_observations)
    if receipt.missing_or_failed_controls or _derived_missing_controls(receipt):
        msg = "success release has missing or failed controls"
        raise _contract_error(msg)
    revision = load_json_object_bytes(resolved.revision_anchor, "revision anchor")
    if (
        revision.get("revision") != receipt.authority.verified_revision
        or revision.get("source_tree_sha256") != receipt.authority.source_tree_sha256
        or revision.get("dirty") is not False
    ):
        msg = "revision anchor does not semantically bind clean revision"
        raise _contract_error(msg)


def _require_fresh_timestamp(
    value: str | None,
    final_time: datetime,
    label: str,
) -> datetime:
    if value is None:
        msg = f"{label} timestamp is missing"
        raise _contract_error(msg)
    observed = _parse_utc(value)
    if observed > final_time or final_time - observed > timedelta(days=7):
        msg = f"{label} evidence is future or stale"
        raise _contract_error(msg)
    return observed


def _verify_restore_quarter(
    observation: NfrObservation,
    final_time: datetime,
) -> None:
    restore_date = observation.measurements.get("restore_evidence_date")
    if not isinstance(restore_date, str):
        msg = "NFR10 restore date is missing"
        raise _contract_error(msg)
    try:
        restore = datetime.strptime(restore_date, "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError as exc:
        msg = "NFR10 restore date is invalid"
        raise _contract_error(msg) from exc
    if (restore.year, (restore.month - 1) // 3) != (
        final_time.year,
        (final_time.month - 1) // 3,
    ):
        msg = "NFR10 restore is not in the trusted current quarter"
        raise _contract_error(msg)


def _verify_nfr_epoch(
    observation: NfrObservation,
    final_time: datetime,
) -> None:
    start = _parse_utc(observation.observed_start_utc)
    end = _require_fresh_timestamp(
        observation.observed_end_utc,
        final_time,
        "NFR",
    )
    if observation.duration_seconds != (end - start).total_seconds():
        msg = "NFR duration must be derived from its interval"
        raise _contract_error(msg)
    if observation.requirement_id == "NFR01" and end - start < timedelta(hours=72):
        msg = "NFR01 requires a 72-hour observed interval"
        raise _contract_error(msg)
    if observation.requirement_id == "NFR10":
        _verify_restore_quarter(observation, final_time)


def _verify_epoch_times(receipt: ReleaseReceipt, final_time: datetime) -> None:
    timestamps = (
        [item.observed_at_utc for item in receipt.external_evidence]
        + [item.reviewed_at_utc for item in receipt.independent_reviews]
        + [receipt.manual_qa.performed_at_utc]
    )
    for value in timestamps:
        _ = _require_fresh_timestamp(value, final_time, "epoch")
    for observation in receipt.nfr_observations:
        _verify_nfr_epoch(observation, final_time)


def _references_from_manifest(
    receipt: ReleaseReceipt,
    issued_at_utc: str,
    authority: FinalizationIssuer,
) -> tuple[EvidenceReference, ...]:
    _ = _parse_utc(issued_at_utc)
    manifest = {item.sha256: item for item in receipt.attachments}
    hashes: list[tuple[str, EvidenceKind]] = [
        *((item.raw_log_sha256, EvidenceKind.CONTROL_LOG) for item in receipt.controls),
        *(
            (digest, EvidenceKind.CONTROL_LOG)
            for item in receipt.controls
            for digest in item.attachment_sha256
        ),
        *(
            (item.sha256, EvidenceKind.EXTERNAL_CONTROL)
            for item in receipt.external_evidence
            if item.sha256
        ),
        *(
            (digest, EvidenceKind.EXTERNAL_CONTROL)
            for item in receipt.external_evidence
            for digest in item.attachment_sha256
        ),
        *((item.sha256, EvidenceKind.REVIEW) for item in receipt.independent_reviews),
        *(
            (capture, EvidenceKind.CAPTURE)
            for item in receipt.independent_reviews
            for capture in item.reviewed_capture_sha256
        ),
        *(
            (item.report_sha256, EvidenceKind.NFR_REPORT)
            for item in receipt.nfr_observations
        ),
        *(
            (item.raw_data_sha256, EvidenceKind.NFR_RAW)
            for item in receipt.nfr_observations
        ),
    ]
    if receipt.manual_qa.sha256:
        hashes.append((receipt.manual_qa.sha256, EvidenceKind.MANUAL_QA))
    if receipt.cleanup.receipt_sha256:
        hashes.append((receipt.cleanup.receipt_sha256, EvidenceKind.CLEANUP))
    if len({digest for digest, _ in hashes}) != len(hashes):
        msg = "success proof cannot alias evidence across typed claims"
        raise _contract_error(msg)
    references: list[EvidenceReference] = []
    for digest, kind in hashes:
        attachment = manifest.get(digest)
        if attachment is None:
            msg = "typed evidence has no confined attachment"
            raise _contract_error(msg)
        unsigned = {
            "path": attachment.path,
            "sha256": digest,
            "kind": kind.value,
            "issuer_id": authority.authority_id,
            "release_id": receipt.release_id,
            "run_id": receipt.run_id,
            "attempt_id": receipt.attempt_id,
            "source_tree_sha256": receipt.authority.source_tree_sha256,
            "verified_revision": receipt.authority.verified_revision,
            "requirements_sha256": receipt.authority.requirements_sha256,
            "goals_sha256": receipt.authority.goals_sha256,
            "goals_state_revision": receipt.authority.goals_state_revision,
            "session_id": receipt.authority.session_id,
            "lease_generation": receipt.authority.lease_generation,
            "issued_at_utc": issued_at_utc,
        }
        signature_value = cast(
            "object",
            authority.sign(
                canonical_bytes(
                    {
                        "domain": "release-evidence-reference-v1",
                        "environment": authority.environment,
                        "authority_id": authority.authority_id,
                        "key_id": authority.key_id,
                        "algorithm": authority.algorithm,
                        "authority_version": authority.authority_version,
                        "reference": unsigned,
                    }
                )
            ),
        )
        if not isinstance(signature_value, bytes) or not signature_value:
            msg = "finalization authority returned an invalid evidence signature"
            raise _contract_error(msg)
        signature = signature_value
        references.append(
            EvidenceReference(
                path=attachment.path,
                sha256=digest,
                kind=kind,
                issuer_id=authority.authority_id,
                release_id=receipt.release_id,
                run_id=receipt.run_id,
                attempt_id=receipt.attempt_id,
                source_tree_sha256=receipt.authority.source_tree_sha256,
                verified_revision=receipt.authority.verified_revision,
                requirements_sha256=receipt.authority.requirements_sha256,
                goals_sha256=receipt.authority.goals_sha256,
                goals_state_revision=receipt.authority.goals_state_revision,
                session_id=receipt.authority.session_id,
                lease_generation=receipt.authority.lease_generation,
                issued_at_utc=issued_at_utc,
                signature_b64=base64.b64encode(signature).decode("ascii"),
            )
        )
    return tuple(references)


def _decode_signature(value: str, label: str) -> bytes:
    try:
        signature = base64.b64decode(value, validate=True)
    except ValueError as exc:
        msg = f"{label} signature is malformed"
        raise _contract_error(msg) from exc
    if not signature:
        msg = f"{label} signature is empty"
        raise _contract_error(msg)
    return signature


def _evidence_reference_authorization(
    reference: EvidenceReference, authority: FinalizationVerifier
) -> bytes:
    """Domain-separate attachment seals from final-envelope signatures."""
    return canonical_bytes(
        {
            "domain": "release-evidence-reference-v1",
            "environment": authority.environment,
            "authority_id": authority.authority_id,
            "key_id": authority.key_id,
            "algorithm": authority.algorithm,
            "authority_version": authority.authority_version,
            "reference": reference.canonical_projection(exclude={"signature_b64"}),
        }
    )


def _envelope_authorization(envelope: FinalizedReleaseEnvelope) -> bytes:
    """Domain-separate the signature from raw payload signatures."""
    return canonical_bytes(
        {
            "domain": "release-finalization-v1",
            "payload_sha256": envelope.payload_sha256,
            "environment": envelope.environment,
            "authority_id": envelope.authority_id,
            "key_id": envelope.key_id,
            "algorithm": envelope.algorithm,
            "authority_version": envelope.authority_version,
        }
    )


def _verify_envelope_header(
    envelope: FinalizedReleaseEnvelope,
    authority: FinalizationVerifier,
) -> None:
    if (
        envelope.authority_id != authority.authority_id
        or envelope.key_id != authority.key_id
        or envelope.algorithm != authority.algorithm
        or envelope.authority_version != authority.authority_version
    ):
        msg = "envelope authority is not pinned"
        raise _contract_error(msg)
    payload_bytes = canonical_bytes(envelope.payload)
    if envelope.payload_sha256 != sha256_bytes(payload_bytes):
        msg = "envelope payload hash mismatch"
        raise _contract_error(msg)
    signature = _decode_signature(envelope.signature_b64, "envelope")
    if not authority.verify(_envelope_authorization(envelope), signature):
        msg = "envelope signature verification failed"
        raise _contract_error(msg)


def _verify_evidence_reference(
    reference: EvidenceReference,
    receipt: ReleaseReceipt,
    authority: FinalizationVerifier,
) -> None:
    if reference.issuer_id != authority.authority_id:
        msg = "evidence issuer is not pinned"
        raise _contract_error(msg)
    if (
        reference.release_id != receipt.release_id
        or reference.run_id != receipt.run_id
        or reference.attempt_id != receipt.attempt_id
        or reference.source_tree_sha256 != receipt.authority.source_tree_sha256
        or reference.verified_revision != receipt.authority.verified_revision
        or reference.requirements_sha256 != receipt.authority.requirements_sha256
        or reference.goals_sha256 != receipt.authority.goals_sha256
        or reference.goals_state_revision != receipt.authority.goals_state_revision
        or reference.session_id != receipt.authority.session_id
        or reference.lease_generation != receipt.authority.lease_generation
    ):
        msg = "evidence reference is not bound to the finalized epoch"
        raise _contract_error(msg)
    signature = _decode_signature(reference.signature_b64, "evidence")
    if not authority.verify(
        _evidence_reference_authorization(reference, authority), signature
    ):
        msg = "evidence signature verification failed"
        raise _contract_error(msg)


def _expected_reference_tuples(
    receipt: ReleaseReceipt,
) -> set[tuple[str, EvidenceKind, str]]:
    """Derive the exact typed attachment projection required by a success receipt."""
    manifest = {item.sha256: item.path for item in receipt.attachments}
    typed: list[tuple[str, EvidenceKind]] = [
        *((item.raw_log_sha256, EvidenceKind.CONTROL_LOG) for item in receipt.controls),
        *(
            (digest, EvidenceKind.CONTROL_LOG)
            for item in receipt.controls
            for digest in item.attachment_sha256
        ),
        *(
            (item.sha256, EvidenceKind.EXTERNAL_CONTROL)
            for item in receipt.external_evidence
            if item.sha256
        ),
        *(
            (digest, EvidenceKind.EXTERNAL_CONTROL)
            for item in receipt.external_evidence
            for digest in item.attachment_sha256
        ),
        *((item.sha256, EvidenceKind.REVIEW) for item in receipt.independent_reviews),
        *(
            (digest, EvidenceKind.CAPTURE)
            for item in receipt.independent_reviews
            for digest in item.reviewed_capture_sha256
        ),
        *(
            (item.report_sha256, EvidenceKind.NFR_REPORT)
            for item in receipt.nfr_observations
        ),
        *(
            (item.raw_data_sha256, EvidenceKind.NFR_RAW)
            for item in receipt.nfr_observations
        ),
    ]
    if receipt.manual_qa.sha256:
        typed.append((receipt.manual_qa.sha256, EvidenceKind.MANUAL_QA))
    if receipt.cleanup.receipt_sha256:
        typed.append((receipt.cleanup.receipt_sha256, EvidenceKind.CLEANUP))
    try:
        return {(digest, kind, manifest[digest]) for digest, kind in typed}
    except KeyError as exc:
        msg = "typed evidence has no confined attachment"
        raise _contract_error(msg) from exc


def _verify_payload_authority_and_roots(
    payload: FinalizedReleasePayload, receipt: ReleaseReceipt
) -> None:
    """Enforce success predicates which require no filesystem reads."""
    if (
        receipt.authority.dirty
        or receipt.authority.command_catalog_sha256 is None
        or receipt.authority.dependency_sha256 is None
        or receipt.authority.fixture_sha256 is None
        or receipt.authority.toolchain_sha256 is None
        or receipt.authority.revision_anchor_sha256 is None
        or receipt.external_anchor_sha256 is None
        or payload.science_root_sha256 != receipt.authority.source_tree_sha256
        or payload.science_root_sha256 != receipt.siblings.science_post_sha256
        or payload.drylab_root_sha256 != receipt.siblings.drylab_post_sha256
        or payload.ontologylab_root_sha256 != receipt.siblings.ontologylab_post_sha256
    ):
        message = "finalized payload authority or roots are incomplete"
        raise _contract_error(message)
    controls = {item.control_id: item for item in receipt.controls}
    if len(controls) != len(CiJob) or set(controls) != {job.value for job in CiJob}:
        message = "finalized payload controls are not the exact catalog"
        raise _contract_error(message)
    for job in CiJob:
        control = controls[job.value]
        if (
            control.category != CI_JOB_CATEGORIES[job]
            or control.outcome != "success"
            or control.exit_code != 0
            or not control.argv
        ):
            message = "finalized payload control is not successful"
            raise _contract_error(message)


def _verify_finalized_success_payload(
    payload: FinalizedReleasePayload, trust: FinalizationTrust
) -> None:
    """Re-evaluate every document-contained success predicate before replay use."""
    receipt = ReleaseReceipt.model_validate(payload.receipt.model_dump(mode="json"))
    if (
        payload.session_id != receipt.authority.session_id
        or payload.lease_generation != receipt.authority.lease_generation
        or payload.session_id != trust.expected_session_id
        or payload.lease_generation != trust.expected_lease_generation
        or receipt.missing_or_failed_controls
        or _derived_missing_controls(receipt)
    ):
        msg = "finalized payload does not prove a complete release"
        raise _contract_error(msg)
    _verify_payload_authority_and_roots(payload, receipt)
    final_time = _parse_utc(payload.finalized_at_utc)
    _verify_success_seals(receipt, trust, final_time)
    _verify_success_human_evidence(receipt)
    _verify_epoch_times(receipt, final_time)
    verify_nfrs(receipt.nfr_observations)
    expected_hashes = _declared_attachment_hashes(receipt)
    references = payload.evidence_references
    if {
        (reference.sha256, reference.kind, reference.path)
        for reference in payload.evidence_references
    } != _expected_reference_tuples(receipt):
        msg = "finalized payload references are incomplete or retyped"
        raise _contract_error(msg)
    if (
        len(references) != len(expected_hashes)
        or {reference.sha256 for reference in references} != expected_hashes
        or len({(reference.kind, reference.path) for reference in references})
        != len(references)
    ):
        msg = "finalized payload references are incomplete"
        raise _contract_error(msg)


def verify_finalized_release_envelope(
    envelope: FinalizedReleaseEnvelope,
    *,
    trust: FinalizationTrust,
) -> FinalizedReleasePayload:
    """Verify canonical bytes and atomically consume an authoritative envelope."""
    authority = trust.pinned_authority()
    _verify_envelope_header(envelope, authority)
    if envelope.environment != trust.environment:
        msg = "envelope environment does not match pinned trust"
        raise _contract_error(msg)
    references = envelope.payload.evidence_references
    if len({reference.sha256 for reference in references}) != len(references):
        msg = "typed evidence references alias a digest"
        raise _contract_error(msg)
    receipt = envelope.payload.receipt
    _verify_finalized_success_payload(envelope.payload, trust)
    for reference in references:
        _verify_evidence_reference(reference, receipt, authority)
    authorization = trust.authorization_authority
    if (
        authorization.authority_id != trust.authorization_authority_id
        or authorization.trust_domain != trust.authorization_trust_domain
        or authorization.authority_id == trust.authority_id
        or envelope.payload.session_id != trust.expected_session_id
        or envelope.payload.lease_generation != trust.expected_lease_generation
        or not authorization.consume(
            envelope.payload.session_id,
            envelope.payload.lease_generation,
            envelope.payload_sha256,
            envelope.payload.finalization_nonce,
        )
    ):
        message = "finalized payload is not externally authorized or was replayed"
        raise _contract_error(message)
    return envelope.payload


def verify_finalized_release_document(
    document: bytes, *, trust: FinalizationTrust
) -> FinalizedReleasePayload:
    """Verify only the canonical serialized envelope; reject reserialized bytes."""
    try:
        decoded = cast("object", json.loads(document))
        envelope = FinalizedReleaseEnvelope.model_validate(decoded)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        msg = "finalized envelope document is malformed"
        raise _contract_error(msg) from exc
    if canonical_bytes(envelope) != document:
        msg = "finalized envelope document is not canonical"
        raise _contract_error(msg)
    return verify_finalized_release_envelope(envelope, trust=trust)
