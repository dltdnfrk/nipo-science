"""Non-vacuous CI evidence and generated-contract freshness checks."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import platform
import re
import secrets
import stat
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import (
    Annotated,
    ClassVar,
    Final,
    Literal,
    Protocol,
    Self,
    cast,
    override,
    runtime_checkable,
)
from urllib.parse import unquote

from pydantic import BaseModel, ConfigDict, Field, model_validator

type JsonValue = (
    str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]
)
type CountKindValue = Literal["analyzer-inventory", "pytest", "checks"]

SHA256_LENGTH: Final = 64
EVIDENCE_BUNDLE_VERSION: Final = 1
CI_REQUIREMENT_CASE_PREFIX: Final = b"CI_REQUIREMENT_CASE="
CI_REQUIREMENT_CASE_ERROR: Final = "CI requirement case evidence mismatch"
TRUSTED_REQUIREMENT_IDS: Final[frozenset[str]] = frozenset(
    (
        "AC-COMPLIANCE",
        "AC-DATA",
        "AC-F01",
        "AC-F01-B",
        "AC-F01-C",
        "AC-F01-D",
        "AC-F01-E",
        "AC-F02",
        "AC-F03",
        "AC-F04",
        "AC-F04-B",
        "AC-F05",
        "AC-F05-B",
        "AC-F06",
        "AC-F06-B",
        "AC-F07",
        "AC-F08",
        "AC-F09",
        "AC-F10",
        "AC-F11",
        "AC-F11-B",
        "AC-F13",
        "AC-F13-B",
        "AC-F13-C",
        "AC-F13-D",
        "AC-NFR",
        "AC-PROVIDER-AUTHORITY",
        "AC-PROVIDER-MIGRATION",
        "AC-PROVIDER-RUN-BINDING",
        "AC-SAFE",
        "AC-TENANT",
        "F01",
        "F02",
        "F03",
        "F04",
        "F05",
        "F06",
        "F07",
        "F08",
        "F09",
        "F10",
        "F11",
        "F13",
        "GS01",
        "GS02",
        "GS03",
        "GS04",
        "GS05",
        "GS06",
        "GS07",
        "GS08",
        "GS09",
        "GS10",
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
        "RV01",
        "RV02",
        "RV03",
        "RV04",
        "RV05",
        "SEC01",
        "SEC02",
        "SEC03",
        "SEC04",
        "SEC05",
        "SEC06",
        "SEC07",
        "SEC08",
        "SEC09",
        "SEC10",
        "SEC11",
        "SEC12",
        "SEC13",
        "SEC14",
        "SEC15",
        "SEC16",
    )
)

COMPLETED_FINISHED_AT_ERROR: Final = "completed evidence requires finished_at"
EVIDENCE_CHECKSUM_ERROR: Final = "checksum must be lowercase sha256"
EVERY_JOB_ERROR: Final = "must contain every job exactly once"
EXACT_JOB_LOG_SET_ERROR: Final = "must contain exact job log set"
FAILURE_EXIT_CODE_ERROR: Final = "failure evidence requires nonzero exit_code"
HIGH_THREAT_IDS_UNIQUE_ERROR: Final = "High threat IDs must be unique"
HIGH_THREAT_MAPPING_ERROR: Final = "must map every High threat exactly once"
INCOMPLETE_FINISHED_AT_ERROR: Final = "incomplete evidence cannot have finished_at"
NON_POSITIVE_EXECUTION_ERROR: Final = "executed_count must be positive"
RAW_LOG_CHECKSUM_ERROR: Final = "raw output checksum mismatch"
SECURITY_CASE_COUNT_ERROR: Final = "SECURITY case count must be positive"
SUCCESS_EXIT_CODE_ERROR: Final = "success evidence requires exit_code 0"
TASK_ATTEMPT_ANCHOR_ERROR: Final = "task attempt anchor mismatch"
TASK_ATTEMPT_EXISTS_ERROR: Final = "task attempt already exists"
TASK_ATTEMPT_ROOT_CHECKSUM_ERROR: Final = "task attempt root checksum mismatch"
TASK_ATTEMPT_PATH_ERROR: Final = "task attempt identifier is not path-safe"
CI_AUTHORITY_CONTEXT_ERROR: Final = "CI authority context is required"
CI_SOURCE_TREE_ERROR: Final = "CI source tree identity is required"
CI_GENERATIONS_DIRECTORY_ERROR: Final = "CI generations directory is unsafe"
CI_LATEST_POINTER_CHANGED_ERROR: Final = "CI latest pointer changed during verification"
CI_LATEST_POINTER_UNAVAILABLE_ERROR: Final = "CI latest pointer is unavailable"
CI_LATEST_POINTER_UNSAFE_ERROR: Final = "CI latest pointer is unsafe"
CI_MANIFEST_AGGREGATE_ERROR: Final = "CI manifest aggregate checksum mismatch"
CI_MANIFEST_ANCHOR_ERROR: Final = "CI manifest anchor mismatch"
CI_MANIFEST_AUTHORITY_ERROR: Final = "CI manifest authority or version mismatch"
CI_MANIFEST_MALFORMED_ERROR: Final = "CI manifest is malformed"
CI_MANIFEST_NONCANONICAL_ERROR: Final = "CI manifest is not canonical"
CI_MANIFEST_SHAPE_ERROR: Final = "CI manifest has an invalid shape"
CI_PUBLISHED_GENERATION_ERROR: Final = "CI published generation is unavailable"
DUPLICATE_JSON_KEY_ERROR: Final = "duplicate JSON key"
CURRENT_RUN_ANCHOR_ERROR: Final = "CI current run authority mismatch"
CURRENT_RUN_REPLAY_ERROR: Final = "CI current run transition is invalid"
CURRENT_RUN_SHAPE_ERROR: Final = "CI current run has an invalid shape"
SENSITIVE_EVIDENCE_ERROR: Final = "evidence contains unredacted secret material"
MAX_SECRET_DECODE_PASSES: Final = 32
EVIDENCE_DESCRIPTOR_ERROR: Final = "evidence descriptor is incomplete or inconsistent"
EVIDENCE_REDERIVATION_ERROR: Final = "evidence count cannot be rederived"
MAX_EVIDENCE_FILE_BYTES: Final = 8 * 1024 * 1024
MAX_EVIDENCE_AGGREGATE_BYTES: Final = 32 * 1024 * 1024
EVIDENCE_REDACTION_RULES: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (
        re.compile(r"(?i)(\bauthorization\s*:\s*(?:bearer|basic)\s+)([^\s,;]+)"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"""(?ix)
            (["']?(?:access_token|refresh_token|id_token|client_secret|
            client_assertion|device_code|authorization_code|session_token|
            api_key|openai_api_key)["']?\s*[:=]\s*["']?)
            ([^"',&;\s}]+)
            """
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"""(?ix)
            ([?&](?:access_token|refresh_token|id_token|client_secret|
            client_assertion|device_code|authorization_code|session_token|
            api_key|openai_api_key)=)([^&#\s]+)
            """
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(\b(?:cookie|set-cookie)\s*:\s*)([^\r\n]+)"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(\b(?:x-api-key|api-key)\s*:\s*)([^\s,;]+)"),
        r"\1[REDACTED]",
    ),
)


class CiJob(StrEnum):
    """Release-blocking local and hosted CI jobs."""

    LINT = "lint"
    TYPECHECK = "typecheck"
    PLATFORM_TESTS = "platform-tests"
    BOUNDARIES = "boundaries"
    SPEC = "spec"
    ARCHITECTURE = "architecture"
    OPENAPI = "openapi"
    PROTOCOL_CONTRACTS = "protocol-contracts"
    ARTIFACT_CONTRACTS = "artifact-contracts"
    LOCAL_CONFIG = "local-config"
    MIGRATIONS = "migrations"
    RLS = "rls"
    UPLOAD = "upload"
    ARTIFACTS = "artifacts"
    SCIENCE = "science"
    ARTIFACT_UI = "artifact-ui"
    RETENTION = "retention"
    GENERATED_DRIFT = "generated-drift"
    SBOM = "sbom"
    SECRET_SCAN = b"secret-scan".decode()
    DRY_LAB = "dry-lab"
    PRODUCT_UI = "product-ui"
    LOCAL_WORKBENCH = "local-workbench"
    PROVIDER_RUNTIME = "provider-runtime"
    SECURITY = "security"
    RECOVERY = "recovery"
    PERFORMANCE = "performance"
    RELEASE = "release"


class CiExecutionLease(BaseModel):
    """Opaque externally issued authorization for one CI job."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    lease_id: str = Field(min_length=1)
    authority_context: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    attempt_id: str = Field(min_length=1)
    source_tree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    job: CiJob


class CiExecutionAttestation(BaseModel):
    """Detached authority receipt for an exact observed CI job."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    lease_id: str = Field(min_length=1)
    authority_context: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    attempt_id: str = Field(min_length=1)
    source_tree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    catalog_root_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    catalog_source_root_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    job: CiJob
    argv: tuple[str, ...] = Field(min_length=1)
    requirement_ids: tuple[str, ...] = ()
    control_ids: tuple[str, ...] = Field(min_length=1)
    toolchain: str = Field(min_length=1)
    executed_count: int = Field(ge=1)
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    attachment_sha256: tuple[Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")], ...] = ()
    security_catalog_root_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    security_threat_ids: tuple[str, ...] = ()
    security_evidence_roots: tuple[
        Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")], ...
    ] = ()
    outcome: Literal["success"]
    started_at: str = Field(min_length=1)
    finished_at: str = Field(min_length=1)
    signature: str = Field(min_length=1)


class GateResult(BaseModel):
    """Sealed per-job execution evidence, not a job-name success label."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    job: CiJob
    executed_count: int
    output_sha256: str = Field(min_length=1)
    argv: tuple[str, ...] = ()
    count_kind: CountKindValue = "pytest"
    parser_version: Literal[1] = 1
    analyzer_inventory_root_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    category: str = ""
    environment_profile: str = ""
    control_ids: tuple[str, ...] = ()
    attachment_sha256: tuple[Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")], ...] = ()
    started_at: str = ""
    finished_at: str = ""
    outcome: Literal["success", "failure", "incomplete"] = "success"
    blockers: tuple[str, ...] = ()
    cleanup_state: Literal["clean", "retained", "incomplete"] = "clean"
    catalog_root_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    catalog_source_root_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    catalog_run_id: str = ""
    requirement_ids: tuple[str, ...] = ()
    prerequisites: tuple[str, ...] = ()
    security_catalog_root_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    security_threat_ids: tuple[str, ...] = ()
    security_evidence_roots: tuple[
        Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")], ...
    ] = ()
    execution_attestation: CiExecutionAttestation | None = None


class CiRequirementCaseBinding(BaseModel):
    """One authority-pinned executable case for a normative requirement."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    requirement_id: str = Field(min_length=1)
    job: CiJob
    case_id: str = Field(min_length=1)
    source_path: str = Field(min_length=1)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    test_path: str = Field(min_length=1)
    test_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    test_node_id: str = Field(min_length=1)
    observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def paths_are_repository_relative(self) -> Self:
        """Reject paths that can escape or ambiguously address the source tree."""
        for raw_path in (self.source_path, self.test_path):
            path = PurePosixPath(raw_path)
            if path.is_absolute() or ".." in path.parts or str(path) != raw_path:
                msg = "invalid CI requirement case binding"
                raise ValueError(msg)
        if (
            self.source_path == self.test_path
            or not self.test_path.endswith(".py")
            or not self.test_node_id.startswith(f"{self.test_path}::")
            or any(character in self.test_node_id for character in "\x00\r\n")
        ):
            msg = "invalid CI requirement case binding"
            raise ValueError(msg)
        return self


class CiRequirementCaseObservation(BaseModel):
    """Trusted-parent observation of one exact executable requirement case."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    requirement_id: str = Field(min_length=1)
    job: CiJob
    case_id: str = Field(min_length=1)
    source_path: str = Field(min_length=1)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    test_path: str = Field(min_length=1)
    test_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    test_node_id: str = Field(min_length=1)
    execution_output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_executed_count: Literal[1]
    outcome: Literal["passed"]


def ci_requirement_case_evidence_bytes(binding: CiRequirementCaseBinding) -> bytes:
    """Return canonical success evidence expected for one requirement case."""
    content = {
        "case_id": binding.case_id,
        "job": binding.job.value,
        "outcome": "passed",
        "requirement_id": binding.requirement_id,
        "source_path": binding.source_path,
        "source_sha256": binding.source_sha256,
        "test_path": binding.test_path,
        "test_sha256": binding.test_sha256,
        "test_node_id": binding.test_node_id,
    }
    return (json.dumps(content, separators=(",", ":"), sort_keys=True) + "\n").encode()


def ci_requirement_case_attachment_sha256(
    bindings: tuple[CiRequirementCaseBinding, ...],
) -> tuple[str, ...]:
    """Return the canonical observation attachment order for mapped cases."""
    return tuple(
        binding.observation_sha256
        for binding in sorted(
            bindings,
            key=lambda item: (item.requirement_id, item.case_id),
        )
    )


def ci_requirement_case_marker_bytes(
    observation: CiRequirementCaseObservation,
) -> bytes:
    """Serialize one trusted-parent case observation as a reserved log record."""
    content = json.dumps(
        observation.model_dump(mode="json"),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return CI_REQUIREMENT_CASE_PREFIX + content + b"\n"


def verify_ci_requirement_case_output(
    output: bytes,
    bindings: tuple[CiRequirementCaseBinding, ...],
) -> None:
    """Require exact parent-observed case markers for every mapped requirement."""
    ordered = tuple(
        sorted(bindings, key=lambda item: (item.requirement_id, item.case_id))
    )
    observed_payloads = tuple(
        line.removeprefix(CI_REQUIREMENT_CASE_PREFIX)
        for line in output.splitlines()
        if line.startswith(CI_REQUIREMENT_CASE_PREFIX)
    )
    if len(observed_payloads) != len(ordered):
        job = ordered[0].job if ordered else None
        raise _evidence_error(CI_REQUIREMENT_CASE_ERROR, job)
    try:
        observed = tuple(
            CiRequirementCaseObservation.model_validate_json(payload)
            for payload in observed_payloads
        )
    except (TypeError, ValueError):
        job = ordered[0].job if ordered else None
        raise _evidence_error(CI_REQUIREMENT_CASE_ERROR, job) from None
    for binding, observation in zip(ordered, observed, strict=True):
        if (
            observation.requirement_id != binding.requirement_id
            or observation.job is not binding.job
            or observation.case_id != binding.case_id
            or observation.source_path != binding.source_path
            or observation.source_sha256 != binding.source_sha256
            or observation.test_path != binding.test_path
            or observation.test_sha256 != binding.test_sha256
            or observation.test_node_id != binding.test_node_id
        ):
            raise _evidence_error(CI_REQUIREMENT_CASE_ERROR, binding.job)


class CiCatalogJob(BaseModel):
    """One immutable externally-authorized CI command contract."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    job: CiJob
    argv: tuple[str, ...] = Field(min_length=1)
    count_kind: CountKindValue
    parser_version: Literal[1] = 1
    analyzer_inventory_root_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    analyzer_inventory_count: int | None = Field(default=None, ge=1)
    category: str = Field(min_length=1)
    environment_profile: str = Field(min_length=1)
    control_ids: tuple[str, ...] = Field(min_length=1)
    requirement_ids: tuple[str, ...] = ()
    prerequisites: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()

    @model_validator(mode="after")
    def identifiers_are_unique_and_inventory_is_exact(self) -> Self:
        """Reject duplicate mappings and mismatched analyzer inventory roots."""
        if (
            len(set(self.control_ids)) != len(self.control_ids)
            or len(set(self.requirement_ids)) != len(self.requirement_ids)
            or any(
                not identifier for identifier in self.control_ids + self.requirement_ids
            )
            or (
                self.count_kind == "analyzer-inventory"
                and (
                    self.analyzer_inventory_root_sha256 is None
                    or self.analyzer_inventory_count is None
                )
            )
            or (
                self.count_kind != "analyzer-inventory"
                and (
                    self.analyzer_inventory_root_sha256 is not None
                    or self.analyzer_inventory_count is not None
                )
            )
        ):
            msg = "invalid CI catalog job"
            raise ValueError(msg)
        return self


class CiControlCatalog(BaseModel):
    """Canonical 28-job catalog resolved from an independent authority."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    version: Literal[1] = 1
    source_identity: str = Field(min_length=1)
    requirements_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_root_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    catalog_root_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    security_catalog_id: str = Field(min_length=1)
    jobs: tuple[CiCatalogJob, ...] = Field(min_length=1)
    requirement_case_bindings: tuple[CiRequirementCaseBinding, ...] = ()
    unverified_requirement_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def exact_jobs_and_roots_are_current(self) -> Self:
        """Reject incomplete, duplicate, and self-inconsistent catalogs."""
        mapped_requirement_ids = tuple(
            requirement for item in self.jobs for requirement in item.requirement_ids
        )
        requirement_ids = (
            *mapped_requirement_ids,
            *self.unverified_requirement_ids,
        )
        binding_requirement_ids = tuple(
            binding.requirement_id for binding in self.requirement_case_bindings
        )
        job_requirements = {
            item.job: frozenset(item.requirement_ids) for item in self.jobs
        }
        if (
            len(self.jobs) != len(CiJob)
            or {item.job for item in self.jobs} != set(CiJob)
            or len({item.job for item in self.jobs}) != len(self.jobs)
            or len({control for item in self.jobs for control in item.control_ids})
            != sum(len(item.control_ids) for item in self.jobs)
            or len(requirement_ids) != len(TRUSTED_REQUIREMENT_IDS)
            or len(set(requirement_ids)) != len(requirement_ids)
            or frozenset(requirement_ids) != TRUSTED_REQUIREMENT_IDS
            or frozenset(binding_requirement_ids) != frozenset(mapped_requirement_ids)
            or len({binding.case_id for binding in self.requirement_case_bindings})
            != len(self.requirement_case_bindings)
            or len({binding.test_node_id for binding in self.requirement_case_bindings})
            != len(self.requirement_case_bindings)
            or any(
                binding.requirement_id not in job_requirements[binding.job]
                for binding in self.requirement_case_bindings
            )
            or self.source_root_sha256 != ci_catalog_source_root(self)
            or self.catalog_root_sha256 != ci_catalog_root(self)
        ):
            msg = "invalid CI control catalog"
            raise ValueError(msg)
        return self


def _catalog_content(catalog: CiControlCatalog, *, include_source_root: bool) -> bytes:
    content: dict[str, object] = {
        "jobs": [
            item.model_dump(mode="json")
            for item in sorted(catalog.jobs, key=lambda item: item.job)
        ],
        "requirement_case_bindings": [
            item.model_dump(mode="json")
            for item in sorted(
                catalog.requirement_case_bindings,
                key=lambda item: (item.requirement_id, item.case_id),
            )
        ],
        "security_catalog_id": catalog.security_catalog_id,
        "source_identity": catalog.source_identity,
        "requirements_sha256": catalog.requirements_sha256,
        "unverified_requirement_ids": list(catalog.unverified_requirement_ids),
        "version": catalog.version,
    }
    if include_source_root:
        content["source_root_sha256"] = catalog.source_root_sha256
    return (json.dumps(content, separators=(",", ":"), sort_keys=True) + "\n").encode()


def ci_catalog_source_root(catalog: CiControlCatalog) -> str:
    """Hash canonical source content excluding its self-referential source root."""
    return hashlib.sha256(
        _catalog_content(catalog, include_source_root=False)
    ).hexdigest()


def ci_catalog_root(catalog: CiControlCatalog) -> str:
    """Hash canonical source-bound catalog content excluding its own root."""
    return hashlib.sha256(
        _catalog_content(catalog, include_source_root=True)
    ).hexdigest()


@runtime_checkable
class CiControlCatalogAuthority(Protocol):
    """Independent resolver for the current command/control catalog."""

    def resolve_control_catalog(
        self, authority_context: str, source_identity: str, run_id: str
    ) -> CiControlCatalog:
        """Freshly resolve the exact catalog for this CI invocation."""
        ...


def resolve_ci_control_catalog(
    authority: CiControlCatalogAuthority,
    authority_context: str,
    source_identity: str,
    run_id: str,
) -> CiControlCatalog:
    """Resolve only a source- and run-bound canonical catalog."""
    try:
        resolved = authority.resolve_control_catalog(
            authority_context, source_identity, run_id
        )
        # model_copy() bypasses Pydantic's after validators; this does not.
        catalog = CiControlCatalog.model_validate_json(resolved.model_dump_json())
    except (AttributeError, LookupError, TypeError, ValueError):
        raise EvidenceIntegrityError(
            None, "CI control catalog authority is unavailable"
        ) from None
    if catalog.source_identity != source_identity or not catalog.source_identity:
        raise EvidenceIntegrityError(None, "CI control catalog authority mismatch")
    return catalog


def load_checked_in_ci_catalog(path: Path) -> CiControlCatalog:
    """Load the canonical checked-in catalog with duplicate-key rejection."""
    try:
        decoded = cast(
            "object",
            json.loads(
                path.read_bytes(),
                object_pairs_hook=_reject_duplicate_json_keys,
            ),
        )
    except (OSError, TypeError, ValueError):
        msg = "checked-in CI control catalog is invalid"
        raise _evidence_error(msg) from None
    if not isinstance(decoded, dict):
        msg = "checked-in CI control catalog is invalid"
        raise _evidence_error(msg)
    document = cast("dict[object, object]", decoded)
    if (
        not all(isinstance(key, str) for key in document)
        or set(document) - {"catalog", "evidence", "generated_contracts"}
        or "catalog" not in document
    ):
        msg = "checked-in CI control catalog is invalid"
        raise _evidence_error(msg)
    try:
        catalog = CiControlCatalog.model_validate(document["catalog"])
    except (TypeError, ValueError):
        msg = "checked-in CI control catalog is invalid"
        raise _evidence_error(msg) from None
    if (
        any(job.requirement_ids for job in catalog.jobs)
        or frozenset(catalog.unverified_requirement_ids) != TRUSTED_REQUIREMENT_IDS
    ):
        msg = "checked-in CI catalog cannot claim semantic requirement evidence"
        raise _evidence_error(msg)
    return catalog


class RequiredSecurityCaseBinding(BaseModel):
    """Externally pinned meaning and source identity of one SECURITY case."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    threat_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    test_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    denial_observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    postcondition_observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class RequiredSecurityCatalog(BaseModel):
    """Trusted High-threat set supplied independently of task bundle mappings."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    version: Literal[1] = 1
    high_threat_ids: tuple[str, ...] = Field(min_length=1)
    case_bindings: tuple[RequiredSecurityCaseBinding, ...] = ()
    source_root_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def high_threat_ids_are_unique(self) -> Self:
        """Reject ambiguous independently supplied required threat sets."""
        binding_threat_ids = tuple(binding.threat_id for binding in self.case_bindings)
        if len(set(self.high_threat_ids)) != len(self.high_threat_ids) or (
            self.case_bindings
            and (
                binding_threat_ids != self.high_threat_ids
                or len({binding.case_id for binding in self.case_bindings})
                != len(self.case_bindings)
                or any(
                    binding.denial_observation_sha256
                    == binding.postcondition_observation_sha256
                    for binding in self.case_bindings
                )
            )
        ):
            raise ValueError(HIGH_THREAT_IDS_UNIQUE_ERROR)
        return self


class SecurityCaseEvidence(RequiredSecurityCaseBinding):
    """One structured, independently countable successful SECURITY case."""

    outcome: Literal["passed"]


class SecurityEvidenceMapping(BaseModel):
    """One High-threat control mapping with non-vacuous evidence."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    threat_id: str = Field(min_length=1)
    job: Literal["SECURITY"] = "SECURITY"
    positive_case_count: int = Field(ge=1)
    evidence_root_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def parse_security_evidence_output(
    catalog: RequiredSecurityCatalog,
    output: bytes,
) -> tuple[SecurityEvidenceMapping, ...]:
    """Parse exact High-threat mappings bound to the non-marker log bytes."""
    marker = b"SECURITY_EVIDENCE="
    lines = output.splitlines(keepends=True)
    payloads = tuple(
        line[len(marker) :].strip() for line in lines if line.startswith(marker)
    )
    if len(payloads) != 1:
        raise _evidence_error(HIGH_THREAT_MAPPING_ERROR, CiJob.SECURITY)
    try:
        decoded = cast("object", json.loads(payloads[0]))
    except (TypeError, ValueError):
        raise _evidence_error(HIGH_THREAT_MAPPING_ERROR, CiJob.SECURITY) from None
    if not isinstance(decoded, list):
        raise _evidence_error(HIGH_THREAT_MAPPING_ERROR, CiJob.SECURITY)
    try:
        claimed_mappings = tuple(
            SecurityEvidenceMapping.model_validate(item)
            for item in cast("list[object]", decoded)
        )
    except (TypeError, ValueError):
        raise _evidence_error(HIGH_THREAT_MAPPING_ERROR, CiJob.SECURITY) from None
    case_marker = b"SECURITY_CASE="
    case_lines = tuple(line for line in lines if line.startswith(case_marker))
    try:
        cases = tuple(
            SecurityCaseEvidence.model_validate_json(line[len(case_marker) :])
            for line in case_lines
        )
    except ValueError:
        raise _evidence_error(HIGH_THREAT_MAPPING_ERROR, CiJob.SECURITY) from None
    case_ids = tuple(case.case_id for case in cases)
    case_threat_order = tuple(dict.fromkeys(case.threat_id for case in cases))
    observed_bindings = tuple(
        RequiredSecurityCaseBinding.model_validate(
            case.model_dump(mode="python", exclude={"outcome"})
        )
        for case in cases
    )
    if (
        len(set(case_ids)) != len(case_ids)
        or case_threat_order != catalog.high_threat_ids
        or not catalog.case_bindings
        or observed_bindings != catalog.case_bindings
    ):
        raise _evidence_error(HIGH_THREAT_MAPPING_ERROR, CiJob.SECURITY)
    mappings = tuple(
        SecurityEvidenceMapping(
            threat_id=threat_id,
            positive_case_count=sum(case.threat_id == threat_id for case in cases),
            evidence_root_sha256=hashlib.sha256(
                b"".join(
                    line
                    for line, case in zip(case_lines, cases, strict=True)
                    if case.threat_id == threat_id
                )
            ).hexdigest(),
        )
        for threat_id in catalog.high_threat_ids
    )
    non_marker_output = b"".join(
        line
        for line in lines
        if not line.startswith(marker) and not line.startswith(case_marker)
    )
    if re.search(
        (
            rb"(?:CHECKS_EXECUTED=|"
            rb"(?:^|\s)Ran \d+ tests?(?:[.\s]|$)|"
            rb"(?:^|\s)\d+ passed(?:[,\s]|$))"
        ),
        non_marker_output,
    ):
        raise _evidence_error(SECURITY_CASE_COUNT_ERROR, CiJob.SECURITY)
    if claimed_mappings != mappings:
        raise _evidence_error(HIGH_THREAT_MAPPING_ERROR, CiJob.SECURITY)
    verify_security_evidence_mapping(
        catalog, mappings, tuple(mapping.evidence_root_sha256 for mapping in mappings)
    )
    return mappings


class TaskAttemptBundle(BaseModel):
    """Content-addressed evidence for one immutable task attempt."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    version: Literal[1] = EVIDENCE_BUNDLE_VERSION
    task_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    attempt_id: str = Field(min_length=1)
    revision: int = Field(ge=1)
    outcome: Literal["failure", "incomplete"]
    exit_code: int | None = None
    started_at: str = Field(min_length=1)
    finished_at: str | None = None
    command: Annotated[tuple[str, ...], Field(min_length=1)]
    control_id: str = Field(min_length=1)
    attachment_sha256: tuple[Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")], ...] = ()
    high_threat_evidence: tuple[SecurityEvidenceMapping, ...] = ()
    security_catalog_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    security_catalog_id: str | None = Field(default=None, min_length=1)
    raw_log_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    root_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_tree_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    count_kind: Literal["analyzer-inventory", "pytest", "checks"] | None = None
    parser_version: Literal[1] | None = None
    analyzer_inventory_root_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    category: str = ""
    environment_profile: str = ""
    requirement_ids: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    cleanup_state: Literal["clean", "retained", "incomplete"] = "clean"

    @model_validator(mode="after")
    def outcome_is_complete(self) -> Self:
        """Require terminal timestamps and outcome-specific exit codes."""
        if self.outcome == "incomplete" and self.finished_at is not None:
            raise ValueError(INCOMPLETE_FINISHED_AT_ERROR)
        if self.outcome != "incomplete" and self.finished_at is None:
            raise ValueError(COMPLETED_FINISHED_AT_ERROR)
        if self.outcome == "failure" and (
            self.exit_code is None or self.exit_code == 0
        ):
            raise ValueError(FAILURE_EXIT_CODE_ERROR)
        if not _path_identifier_is_safe(self.task_id) or not _path_identifier_is_safe(
            self.attempt_id
        ):
            raise ValueError(TASK_ATTEMPT_PATH_ERROR)
        return self


class _PathItem(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="allow")

    delete: JsonValue = None
    get: JsonValue = None
    patch: JsonValue = None
    post: JsonValue = None
    put: JsonValue = None

    def methods(self) -> tuple[str, ...]:
        result: list[str] = []
        if self.delete is not None:
            result.append("delete")
        if self.get is not None:
            result.append("get")
        if self.patch is not None:
            result.append("patch")
        if self.post is not None:
            result.append("post")
        if self.put is not None:
            result.append("put")
        return tuple(result)


class _Components(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="allow")

    schemas: dict[str, JsonValue]


class _OpenApiInput(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="allow")

    paths: dict[str, _PathItem]
    components: _Components


@dataclass(frozen=True, slots=True)
class GeneratedContract:
    """Expected and checked-in projections of one source contract."""

    source_path: Path
    generated_path: Path
    expected: bytes
    actual: bytes

    @classmethod
    def from_paths(cls, source_path: Path, generated_path: Path) -> GeneratedContract:
        """Load both sides of a generated-contract freshness check."""
        return cls(
            source_path,
            generated_path,
            render_openapi_catalog(source_path),
            generated_path.read_bytes(),
        )


@dataclass
class EvidenceIntegrityError(Exception):
    """Rejects missing counts, checksums, or required jobs."""

    job: CiJob | None
    issue: str

    @override
    def __str__(self) -> str:
        """Describe the non-vacuous evidence failure."""
        prefix = "CI evidence" if self.job is None else str(self.job)
        return f"{prefix} {self.issue}"


@dataclass(frozen=True, slots=True)
class StaleGeneratedContractError(Exception):
    """Rejects checked-in generated data that differs from its source."""

    path: Path

    @override
    def __str__(self) -> str:
        """Identify the stale generated path."""
        return f"generated contract is stale: {self.path}"


def _evidence_error(issue: str, job: CiJob | None = None) -> EvidenceIntegrityError:
    """Build a stable evidence-integrity exception."""
    return EvidenceIntegrityError(job, issue)


def _normalized_secret_text(content: bytes) -> str:
    """Decode common structured encodings before applying the secret policy."""
    text = content.decode(errors="replace")
    for _ in range(MAX_SECRET_DECODE_PASSES):
        decoded = unquote(text)
        decoded = re.sub(
            r"\\u([0-9a-fA-F]{4})",
            lambda match: chr(int(match.group(1), 16)),
            decoded,
        )
        decoded = re.sub(
            r"\\x([0-9a-fA-F]{2})",
            lambda match: chr(int(match.group(1), 16)),
            decoded,
        )
        if decoded == text:
            return text
        text = decoded
    raise _evidence_error(SENSITIVE_EVIDENCE_ERROR)


def redact_evidence_bytes(content: bytes) -> bytes:
    """Redact recognized OAuth, session, cookie, and API secret forms."""
    text = content.decode(errors="replace")
    redacted = text
    for pattern, replacement in EVIDENCE_REDACTION_RULES:
        redacted = pattern.sub(replacement, redacted)
    return content if redacted == text else redacted.encode()


def require_evidence_sanitized(content: bytes) -> None:
    """Reject evidence bytes, including encoded forms, containing secret material."""
    normalized = _normalized_secret_text(content).encode()
    if (
        redact_evidence_bytes(content) != content
        or redact_evidence_bytes(normalized) != normalized
    ):
        raise _evidence_error(SENSITIVE_EVIDENCE_ERROR)


@dataclass(frozen=True, slots=True)
class SecurityCatalogAuthorityError(Exception):
    """The external catalog authority did not resolve a catalog."""


def resolve_security_catalog(
    catalog_authority: SecurityCatalogAuthority, catalog_id: str
) -> RequiredSecurityCatalog:
    """Resolve a catalog through the only accepted SECURITY trust boundary."""
    try:
        catalog = catalog_authority(catalog_id)
    except ValueError as error:
        raise SecurityCatalogAuthorityError from error
    if (
        hashlib.sha256(security_catalog_source_bytes(catalog)).hexdigest()
        != catalog.source_root_sha256
    ):
        raise SecurityCatalogAuthorityError
    return catalog


def verify_evidence(records: tuple[GateResult, ...]) -> str:
    """Require every CI job to have an executed count and output checksum."""
    for record in records:
        if record.executed_count <= 0:
            raise _evidence_error(NON_POSITIVE_EXECUTION_ERROR, record.job)
        checksum_valid = len(record.output_sha256) == SHA256_LENGTH and all(
            character in "0123456789abcdef" for character in record.output_sha256
        )
        if not checksum_valid:
            raise _evidence_error(EVIDENCE_CHECKSUM_ERROR, record.job)
        if record.outcome != "success" or record.cleanup_state != "clean":
            raise _evidence_error(EVIDENCE_DESCRIPTOR_ERROR, record.job)
        if record.argv and (
            not record.category
            or not record.environment_profile
            or not record.control_ids
            or not record.started_at.endswith("Z")
            or not record.finished_at.endswith("Z")
        ):
            raise _evidence_error(EVIDENCE_DESCRIPTOR_ERROR, record.job)
    jobs = tuple(record.job for record in records)
    if len(set(jobs)) != len(jobs) or set(jobs) != set(CiJob):
        raise _evidence_error(EVERY_JOB_ERROR)
    ordered = sorted(records, key=lambda item: item.job)
    canonical = json.dumps(
        [_gate_result_content(record) for record in ordered],
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


CI_EVIDENCE_MANIFEST_VERSION: Final = 4


class CiRunState(StrEnum):
    """Externally coordinated lifecycle states for the one current CI run."""

    ACTIVE = "active"
    SUCCESS = "success"
    FAILURE = "failure"
    INCOMPLETE = "incomplete"


class CiCurrentRun(BaseModel):
    """The external freshness authority for one CI invocation."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    run_id: str = Field(min_length=1)
    attempt_id: str = Field(min_length=1)
    authority_context: str = Field(min_length=1)
    source_tree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    started_at: str = Field(min_length=1)
    finished_at: str | None = None
    state: CiRunState
    generation_id: str | None = None
    attempt_root_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def terminal_binding_is_exact(self) -> Self:
        """Forbid selecting evidence before success or omitting failed evidence."""
        if not self.started_at.endswith("Z"):
            raise ValueError(CURRENT_RUN_SHAPE_ERROR)
        if self.state is CiRunState.ACTIVE:
            if (
                self.finished_at is not None
                or self.generation_id is not None
                or self.attempt_root_sha256 is not None
            ):
                raise ValueError(CURRENT_RUN_SHAPE_ERROR)
        elif self.state is CiRunState.SUCCESS:
            if (
                self.finished_at is None
                or self.generation_id is None
                or self.attempt_root_sha256 is not None
            ):
                raise ValueError(CURRENT_RUN_SHAPE_ERROR)
        elif (
            self.finished_at is None
            or self.attempt_root_sha256 is None
            or self.generation_id is not None
        ):
            raise ValueError(CURRENT_RUN_SHAPE_ERROR)
        return self


@runtime_checkable
class CiGenerationManifestAuthority(Protocol):
    """Independent authority that binds and resolves CI generation manifests."""

    def bind(
        self, authority_context: str, generation_id: str, manifest_sha256: str
    ) -> None:
        """Persist an external binding before a generation is published."""
        ...

    def resolve(self, authority_context: str, generation_id: str) -> str:
        """Freshly resolve the bound manifest checksum for a generation."""
        ...

    def begin(self, current_run: CiCurrentRun) -> None:
        """Atomically supersede the prior current run with an active run."""
        ...

    def complete(self, current_run: CiCurrentRun) -> None:
        """Atomically transition the active run to one terminal state."""
        ...

    def issue_execution_lease(
        self, current_run: CiCurrentRun, job: CiJob
    ) -> CiExecutionLease:
        """Issue a non-transferable lease for one active-run job."""
        ...

    def authorize_execution_lease(
        self,
        lease: CiExecutionLease,
        current_run: CiCurrentRun,
        catalog: CiControlCatalog,
        job: CiCatalogJob,
    ) -> None:
        """Atomically validate and consume an exact pre-spawn execution lease."""
        ...

    def attest_execution(
        self, lease: CiExecutionLease, record: GateResult, toolchain: str
    ) -> CiExecutionAttestation:
        """Externally attest one lease-bound observed job result."""
        ...

    def verify_execution_attestation(
        self,
        attestation: CiExecutionAttestation,
        record: GateResult,
        current_run: CiCurrentRun,
    ) -> None:
        """Verify an external receipt against the authority's run."""
        ...

    def finalize_attested_generation(
        self,
        current_run: CiCurrentRun,
        published_run: CiCurrentRun,
        manifest_sha256: str,
        attestations: tuple[CiExecutionAttestation, ...],
    ) -> None:
        """Atomically validate receipts and complete the active run."""
        ...

    def resolve_current(self, authority_context: str) -> CiCurrentRun:
        """Freshly resolve the sole current run for this authority context."""
        ...

    def resolve_control_catalog(
        self,
        authority_context: str,
        source_identity: str,
        run_id: str,
    ) -> CiControlCatalog:
        """Freshly resolve the exact catalog for this CI invocation."""
        ...

    def resolve_security_catalog(
        self,
        catalog_id: str,
    ) -> RequiredSecurityCatalog:
        """Freshly resolve the required High-threat catalog."""
        ...


def verify_ci_manifest_anchor(
    authority: CiGenerationManifestAuthority,
    authority_context: str,
    generation_id: str,
    manifest_bytes: bytes,
) -> None:
    """Require the independently resolved binding for immutable manifest bytes."""
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    try:
        anchored_sha256 = authority.resolve(authority_context, generation_id)
    except LookupError:
        raise _evidence_error(CI_MANIFEST_ANCHOR_ERROR) from None
    if anchored_sha256 != manifest_sha256:
        raise _evidence_error(CI_MANIFEST_ANCHOR_ERROR)


@dataclass(frozen=True, slots=True)
class PublishedCiGeneration:
    """Verified, immutable bytes from the current published CI generation."""

    authority_context: str
    source_tree_sha256: str
    records: tuple[GateResult, ...]
    logs: Mapping[CiJob, bytes]


def canonical_ci_manifest(
    authority_context: str,
    source_tree_sha256: str,
    records: tuple[GateResult, ...],
    current_run: CiCurrentRun,
) -> bytes:
    """Serialize a current-run- and source-tree-bound CI manifest canonically."""
    if (
        not authority_context
        or current_run.authority_context != authority_context
        or current_run.source_tree_sha256 != source_tree_sha256
        or current_run.state is not CiRunState.SUCCESS
    ):
        raise _evidence_error(CI_MANIFEST_AUTHORITY_ERROR)
    if not re.fullmatch(r"[0-9a-f]{64}", source_tree_sha256):
        raise _evidence_error(CI_SOURCE_TREE_ERROR)
    return (
        json.dumps(
            {
                "aggregate_sha256": verify_evidence(records),
                "attempt_id": current_run.attempt_id,
                "authority_context": authority_context,
                "finished_at": current_run.finished_at,
                "results": [
                    _gate_result_content(record)
                    for record in sorted(records, key=lambda item: item.job)
                ],
                "run_id": current_run.run_id,
                "source_tree_sha256": source_tree_sha256,
                "started_at": current_run.started_at,
                "version": CI_EVIDENCE_MANIFEST_VERSION,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()


def verify_records_against_catalog(
    records: tuple[GateResult, ...],
    catalog: CiControlCatalog,
    run_id: str,
) -> None:
    """Require every published descriptor to equal its fresh catalog entry."""
    catalog_jobs = {item.job: item for item in catalog.jobs}
    if set(catalog_jobs) != set(CiJob) or len(catalog_jobs) != len(catalog.jobs):
        raise _evidence_error(CI_MANIFEST_AUTHORITY_ERROR)
    for record in records:
        item = catalog_jobs.get(record.job)
        if (
            item is None
            or record.argv != item.argv
            or record.count_kind != item.count_kind
            or record.parser_version != item.parser_version
            or record.analyzer_inventory_root_sha256
            != item.analyzer_inventory_root_sha256
            or (
                item.count_kind == "analyzer-inventory"
                and record.executed_count != item.analyzer_inventory_count
            )
            or record.category != item.category
            or record.environment_profile != item.environment_profile
            or record.control_ids != item.control_ids
            or record.requirement_ids != item.requirement_ids
            or record.prerequisites != item.prerequisites
            or record.blockers != item.blockers
            or record.catalog_root_sha256 != catalog.catalog_root_sha256
            or record.catalog_source_root_sha256 != catalog.source_root_sha256
            or record.catalog_run_id != run_id
        ):
            raise _evidence_error(CI_MANIFEST_AUTHORITY_ERROR, record.job)


def verify_execution_attestation(
    authority: CiGenerationManifestAuthority,
    record: GateResult,
    current_run: CiCurrentRun,
) -> CiExecutionAttestation:
    """Externally and structurally verify one exact current-run receipt."""
    receipt = record.execution_attestation
    if receipt is None:
        raise _evidence_error(CI_MANIFEST_AUTHORITY_ERROR, record.job)
    try:
        authority.verify_execution_attestation(receipt, record, current_run)
    except (AttributeError, LookupError, TypeError, ValueError):
        raise _evidence_error(CI_MANIFEST_AUTHORITY_ERROR, record.job) from None
    if (
        receipt.authority_context != current_run.authority_context
        or receipt.run_id != current_run.run_id
        or receipt.attempt_id != current_run.attempt_id
        or receipt.source_tree_sha256 != current_run.source_tree_sha256
        or receipt.job != record.job
        or receipt.catalog_root_sha256 != record.catalog_root_sha256
        or receipt.catalog_source_root_sha256 != record.catalog_source_root_sha256
        or receipt.argv != record.argv
        or receipt.requirement_ids != record.requirement_ids
        or receipt.control_ids != record.control_ids
        or receipt.executed_count != record.executed_count
        or receipt.output_sha256 != record.output_sha256
        or receipt.attachment_sha256 != record.attachment_sha256
        or receipt.security_catalog_root_sha256 != record.security_catalog_root_sha256
        or receipt.security_threat_ids != record.security_threat_ids
        or receipt.security_evidence_roots != record.security_evidence_roots
        or receipt.outcome != record.outcome
        or receipt.started_at != record.started_at
        or receipt.finished_at != record.finished_at
    ):
        raise _evidence_error(CI_MANIFEST_AUTHORITY_ERROR, record.job)
    return receipt


def verify_execution_attestations(
    authority: CiGenerationManifestAuthority,
    records: tuple[GateResult, ...],
    current_run: CiCurrentRun,
) -> tuple[CiExecutionAttestation, ...]:
    """Require exactly one externally verified current-run receipt per job."""
    receipts = [
        verify_execution_attestation(authority, record, current_run)
        for record in records
    ]
    if (
        len(receipts) != len(CiJob)
        or {item.job for item in receipts} != set(CiJob)
        or len({item.lease_id for item in receipts}) != len(receipts)
    ):
        raise _evidence_error(CI_MANIFEST_AUTHORITY_ERROR)
    return tuple(receipts)


def load_published_ci_generation(
    root: Path,
    expected_authority_context: str,
    expected_source_tree_sha256: str,
    authority: CiGenerationManifestAuthority | None = None,
) -> PublishedCiGeneration:
    """Open and verify the externally anchored current CI generation without links."""
    if authority is None:
        raise _evidence_error(CI_MANIFEST_ANCHOR_ERROR)
    if not expected_authority_context:
        raise _evidence_error(CI_AUTHORITY_CONTEXT_ERROR)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_source_tree_sha256):
        raise _evidence_error(CI_SOURCE_TREE_ERROR)

    current_run = _resolve_successful_current_run(
        authority,
        expected_authority_context,
        expected_source_tree_sha256,
    )
    evidence_fd = open_confined_directory(root / ".ci/evidence", create=False)
    try:
        generation_name = _read_latest_generation_name(evidence_fd)
        if generation_name != current_run.generation_id:
            raise _evidence_error(CURRENT_RUN_ANCHOR_ERROR)
        generation_fd = _open_published_generation(evidence_fd, generation_name)
        try:
            manifest_bytes, manifest = _read_published_manifest(generation_fd)
            records = _parse_published_manifest(
                manifest,
                manifest_bytes,
                expected_authority_context,
                expected_source_tree_sha256,
                current_run,
            )
            catalog = resolve_ci_control_catalog(
                authority,
                expected_authority_context,
                expected_source_tree_sha256,
                current_run.run_id,
            )
            verify_records_against_catalog(records, catalog, current_run.run_id)
            _ = verify_execution_attestations(authority, records, current_run)
            try:
                security_catalog = resolve_security_catalog(
                    authority.resolve_security_catalog,
                    catalog.security_catalog_id,
                )
            except SecurityCatalogAuthorityError:
                raise _evidence_error(CI_MANIFEST_AUTHORITY_ERROR) from None
            security = next(
                (record for record in records if record.job is CiJob.SECURITY), None
            )
            if (
                security is None
                or security.security_catalog_root_sha256
                != security_catalog.source_root_sha256
                or set(security.security_threat_ids)
                != set(security_catalog.high_threat_ids)
                or len(security.security_evidence_roots)
                != len(security_catalog.high_threat_ids)
            ):
                raise _evidence_error(CI_MANIFEST_AUTHORITY_ERROR)
            verify_ci_manifest_anchor(
                authority,
                expected_authority_context,
                generation_name,
                manifest_bytes,
            )
            _require_current_run_unchanged(
                authority,
                expected_authority_context,
                current_run,
            )
            logs = _load_verified_generation_logs(generation_fd, records)
            for record in records:
                verify_ci_requirement_case_output(
                    logs[record.job],
                    tuple(
                        binding
                        for binding in catalog.requirement_case_bindings
                        if binding.job is record.job
                    ),
                )
            mappings = parse_security_evidence_output(
                security_catalog,
                logs[CiJob.SECURITY],
            )
            mapped_ids = tuple(item.threat_id for item in mappings)
            evidence_roots = tuple(item.evidence_root_sha256 for item in mappings)
            requirement_roots = ci_requirement_case_attachment_sha256(
                tuple(
                    binding
                    for binding in catalog.requirement_case_bindings
                    if binding.job is CiJob.SECURITY
                )
            )
            if (
                security.security_threat_ids != mapped_ids
                or security.security_evidence_roots != evidence_roots
                or security.attachment_sha256 != (*requirement_roots, *evidence_roots)
            ):
                raise _evidence_error(
                    CI_MANIFEST_AUTHORITY_ERROR,
                    CiJob.SECURITY,
                )
            if _read_latest_generation_name(evidence_fd) != generation_name:
                raise _evidence_error(CI_LATEST_POINTER_CHANGED_ERROR)
            _require_current_run_unchanged(
                authority,
                expected_authority_context,
                current_run,
            )
            return PublishedCiGeneration(
                expected_authority_context,
                expected_source_tree_sha256,
                records,
                MappingProxyType(logs),
            )
        finally:
            os.close(generation_fd)
    finally:
        os.close(evidence_fd)


def _resolve_successful_current_run(
    authority: CiGenerationManifestAuthority,
    authority_context: str,
    source_tree_sha256: str,
) -> CiCurrentRun:
    try:
        current_run = authority.resolve_current(authority_context)
    except LookupError:
        raise _evidence_error(CURRENT_RUN_ANCHOR_ERROR) from None
    if (
        current_run.state is not CiRunState.SUCCESS
        or current_run.source_tree_sha256 != source_tree_sha256
        or current_run.authority_context != authority_context
        or current_run.generation_id is None
    ):
        raise _evidence_error(CURRENT_RUN_ANCHOR_ERROR)
    return current_run


def _require_current_run_unchanged(
    authority: CiGenerationManifestAuthority,
    authority_context: str,
    expected: CiCurrentRun,
) -> None:
    try:
        current_run = authority.resolve_current(authority_context)
    except LookupError:
        raise _evidence_error(CURRENT_RUN_ANCHOR_ERROR) from None
    if current_run != expected:
        raise _evidence_error(CURRENT_RUN_ANCHOR_ERROR)


def _read_published_manifest(generation_fd: int) -> tuple[bytes, object]:
    manifest_bytes = read_generation_file(generation_fd, "manifest.json")
    try:
        manifest = cast(
            "object",
            json.loads(
                manifest_bytes,
                object_pairs_hook=_reject_duplicate_json_keys,
            ),
        )
    except (TypeError, ValueError):
        raise _evidence_error(CI_MANIFEST_MALFORMED_ERROR) from None
    return manifest_bytes, manifest


def _load_verified_generation_logs(
    generation_fd: int,
    records: tuple[GateResult, ...],
) -> dict[CiJob, bytes]:
    expected_names = {"manifest.json"} | {f"{record.job}.log" for record in records}
    with os.scandir(generation_fd) as entries:
        entries_by_name = {entry.name: entry for entry in entries}
    if set(entries_by_name) != expected_names or any(
        not entry.is_file(follow_symlinks=False) for entry in entries_by_name.values()
    ):
        raise _evidence_error(EXACT_JOB_LOG_SET_ERROR)

    logs: dict[CiJob, bytes] = {}
    aggregate_size = 0
    for record in records:
        output = read_generation_file(generation_fd, f"{record.job}.log")
        aggregate_size += len(output)
        if aggregate_size > MAX_EVIDENCE_AGGREGATE_BYTES:
            raise _evidence_error(EXACT_JOB_LOG_SET_ERROR)
        if hashlib.sha256(output).hexdigest() != record.output_sha256:
            raise _evidence_error(RAW_LOG_CHECKSUM_ERROR, record.job)
        require_evidence_sanitized(output)
        rederive_gate_count(record, output)
        logs[record.job] = output
    return logs


def _read_latest_generation_name(evidence_fd: int) -> str:
    """Read only the expected relative latest pointer target."""
    try:
        target = os.readlink("latest", dir_fd=evidence_fd)
    except OSError:
        raise _evidence_error(CI_LATEST_POINTER_UNAVAILABLE_ERROR) from None
    prefix = "generations/"
    generation_name = target.removeprefix(prefix)
    if (
        not target.startswith(prefix)
        or "/" in generation_name
        or re.fullmatch(r"[0-9a-f]{32}", generation_name) is None
    ):
        raise _evidence_error(CI_LATEST_POINTER_UNSAFE_ERROR)
    return generation_name


def _open_published_generation(evidence_fd: int, generation_name: str) -> int:
    """Open the pointer-selected generation using no-follow descriptors."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        generations_fd = os.open("generations", flags, dir_fd=evidence_fd)
    except OSError:
        raise _evidence_error(CI_GENERATIONS_DIRECTORY_ERROR) from None
    try:
        return os.open(generation_name, flags, dir_fd=generations_fd)
    except OSError:
        raise _evidence_error(CI_PUBLISHED_GENERATION_ERROR) from None
    finally:
        os.close(generations_fd)


def _tamper_fstat_signature(
    result: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    """Tamper signature for read-back checks, excluding access time.

    Reading the descriptor legitimately updates atime on relatime mounts
    (freshly written evidence files have atime == mtime, so the very next read
    bumps atime), and a full stat_result comparison intermittently misreported
    that as concurrent modification. Identity (dev/ino), link count, mode,
    size, and mtime still pin replace/append/chmod races.
    """
    return (
        result.st_dev,
        result.st_ino,
        result.st_mode,
        result.st_nlink,
        result.st_size,
        result.st_mtime_ns,
    )


def _bounded_descriptor_read(file_descriptor: int, issue: str) -> bytes:
    """Read a pinned regular file with a cap and concurrent-growth detection."""
    before = os.fstat(file_descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 0
        or before.st_size > MAX_EVIDENCE_FILE_BYTES
    ):
        raise _evidence_error(issue)
    content = os.read(file_descriptor, before.st_size + 1)
    after = os.fstat(file_descriptor)
    if len(content) > before.st_size or _tamper_fstat_signature(
        after
    ) != _tamper_fstat_signature(before):
        raise _evidence_error(issue)
    return content


def read_generation_file(generation_fd: int, name: str) -> bytes:
    """Read one regular generation file through its pinned directory descriptor."""
    try:
        file_fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
            dir_fd=generation_fd,
        )
    except OSError:
        raise _evidence_error(EXACT_JOB_LOG_SET_ERROR) from None
    with os.fdopen(file_fd, "rb") as evidence_file:
        return _bounded_descriptor_read(evidence_file.fileno(), EXACT_JOB_LOG_SET_ERROR)


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    """Reject duplicate JSON names before validating the strict manifest shape."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(DUPLICATE_JSON_KEY_ERROR)
        result[key] = value
    return result


def _parse_published_manifest(
    manifest: object,
    manifest_bytes: bytes,
    expected_authority_context: str,
    expected_source_tree_sha256: str,
    current_run: CiCurrentRun,
) -> tuple[GateResult, ...]:
    """Validate canonical manifest bytes, authority binding, and aggregate."""
    if not isinstance(manifest, dict):
        raise _evidence_error(CI_MANIFEST_SHAPE_ERROR)
    typed_manifest = cast("dict[str, object]", manifest)
    if set(typed_manifest) != {
        "aggregate_sha256",
        "attempt_id",
        "authority_context",
        "finished_at",
        "results",
        "run_id",
        "source_tree_sha256",
        "started_at",
        "version",
    }:
        raise _evidence_error(CI_MANIFEST_SHAPE_ERROR)
    version = typed_manifest["version"]
    authority_context = typed_manifest["authority_context"]
    raw_results = typed_manifest["results"]
    source_tree_sha256 = typed_manifest["source_tree_sha256"]
    aggregate_sha256 = typed_manifest["aggregate_sha256"]
    run_id = typed_manifest["run_id"]
    attempt_id = typed_manifest["attempt_id"]
    started_at = typed_manifest["started_at"]
    finished_at = typed_manifest["finished_at"]
    if (
        version != CI_EVIDENCE_MANIFEST_VERSION
        or not isinstance(authority_context, str)
        or authority_context != expected_authority_context
        or not isinstance(source_tree_sha256, str)
        or source_tree_sha256 != expected_source_tree_sha256
        or not re.fullmatch(r"[0-9a-f]{64}", source_tree_sha256)
        or not isinstance(raw_results, list)
        or run_id != current_run.run_id
        or attempt_id != current_run.attempt_id
        or started_at != current_run.started_at
        or finished_at != current_run.finished_at
    ):
        raise _evidence_error(CI_MANIFEST_AUTHORITY_ERROR)
    if not isinstance(aggregate_sha256, str):
        raise _evidence_error(CI_MANIFEST_MALFORMED_ERROR)
    try:
        typed_results = cast("list[object]", raw_results)
        records = tuple(_parse_published_gate_result(item) for item in typed_results)
    except (TypeError, ValueError):
        raise _evidence_error(CI_MANIFEST_MALFORMED_ERROR) from None
    if aggregate_sha256 != verify_evidence(records):
        raise _evidence_error(CI_MANIFEST_AGGREGATE_ERROR)
    if manifest_bytes != canonical_ci_manifest(
        expected_authority_context,
        expected_source_tree_sha256,
        records,
        current_run,
    ):
        raise _evidence_error(CI_MANIFEST_NONCANONICAL_ERROR)
    return records


def _parse_published_gate_result(item: object) -> GateResult:
    """Parse one manifest result only after checking its complete primitive shape."""
    if not isinstance(item, dict):
        raise TypeError(CI_MANIFEST_MALFORMED_ERROR)
    record = cast("dict[str, object]", item)
    expected = {
        "analyzer_inventory_root_sha256",
        "argv",
        "attachment_sha256",
        "blockers",
        "category",
        "cleanup_state",
        "control_ids",
        "catalog_root_sha256",
        "catalog_run_id",
        "catalog_source_root_sha256",
        "count_kind",
        "environment_profile",
        "executed_count",
        "finished_at",
        "job",
        "outcome",
        "prerequisites",
        "requirement_ids",
        "security_catalog_root_sha256",
        "security_evidence_roots",
        "security_threat_ids",
        "output_sha256",
        "parser_version",
        "started_at",
        "execution_attestation",
    }
    legacy = {"executed_count", "job", "output_sha256"}
    if set(record) != expected and set(record) != legacy:
        raise ValueError(CI_MANIFEST_MALFORMED_ERROR)
    try:
        return GateResult.model_validate_json(json.dumps(record))
    except ValueError:
        raise ValueError(CI_MANIFEST_MALFORMED_ERROR) from None


def _gate_result_content(record: GateResult) -> dict[str, object]:
    """Return the explicitly typed JSON-compatible gate result."""
    legacy = not record.argv and not record.category and not record.environment_profile
    if legacy:
        return {
            "executed_count": record.executed_count,
            "job": str(record.job),
            "output_sha256": record.output_sha256,
        }
    return record.model_dump(mode="json")


def rederive_gate_count(record: GateResult, output: bytes) -> None:
    """Derive the claimed non-vacuous count from pinned sanitized log bytes."""
    if not record.argv:
        return
    if record.job is CiJob.SECURITY:
        marker = b"SECURITY_EVIDENCE="
        try:
            cases = tuple(
                SecurityCaseEvidence.model_validate_json(line[len(b"SECURITY_CASE=") :])
                for line in output.splitlines(keepends=True)
                if line.startswith(b"SECURITY_CASE=")
            )
            payloads = tuple(
                line[len(marker) :].strip()
                for line in output.splitlines(keepends=True)
                if line.startswith(marker)
            )
            mappings = tuple(
                SecurityEvidenceMapping.model_validate(item)
                for item in cast("list[object]", json.loads(payloads[0]))
            )
        except (IndexError, TypeError, ValueError):
            raise _evidence_error(EVIDENCE_REDERIVATION_ERROR, record.job) from None
        count = len(cases)
        if (
            len(payloads) != 1
            or count == 0
            or len({case.case_id for case in cases}) != count
            or sum(case.outcome == "passed" for case in cases) != count
            or len({mapping.threat_id for mapping in mappings}) != len(mappings)
            or sum(mapping.positive_case_count for mapping in mappings) != count
        ):
            raise _evidence_error(EVIDENCE_REDERIVATION_ERROR, record.job)
    elif record.count_kind == "analyzer-inventory":
        if record.analyzer_inventory_root_sha256 is None:
            raise _evidence_error(EVIDENCE_REDERIVATION_ERROR, record.job)
        # The inventory root binds the externally cataloged analyzer input; its
        # cardinality is attested by the sealed executor descriptor.
        count = record.executed_count
    else:
        text = output.decode(errors="replace")
        patterns = (
            (
                r"(?:^|\s)(\d+) passed(?:[,\s]|$)",
                r"(?:^|\s)Ran (\d+) tests?(?:[.\s]|$)",
                r"CHECKS_EXECUTED=(\d+)",
            )
            if record.count_kind == "pytest"
            else (r"CHECKS_EXECUTED=(\d+)",)
        )
        count = sum(
            int(match.group(1))
            for pattern in patterns
            for match in re.finditer(pattern, text)
        )
    if count != record.executed_count or count <= 0:
        raise _evidence_error(EVIDENCE_REDERIVATION_ERROR, record.job)


def verify_generated_contract(contract: GeneratedContract) -> None:
    """Reject a generated projection unless its exact bytes are current."""
    if contract.actual != contract.expected:
        raise StaleGeneratedContractError(contract.generated_path)


def task_attempt_root(bundle: TaskAttemptBundle) -> str:
    """Return the canonical root independent of its self-referential field."""
    return hashlib.sha256(
        json.dumps(
            _task_attempt_content(bundle, include_root_sha256=False),
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()


def _task_attempt_content(
    bundle: TaskAttemptBundle, *, include_root_sha256: bool
) -> dict[str, object]:
    """Return the explicitly typed JSON-compatible task-attempt content."""
    content: dict[str, object] = {
        "analyzer_inventory_root_sha256": bundle.analyzer_inventory_root_sha256,
        "attachment_sha256": list(bundle.attachment_sha256),
        "attempt_id": bundle.attempt_id,
        "blockers": list(bundle.blockers),
        "category": bundle.category,
        "cleanup_state": bundle.cleanup_state,
        "command": list(bundle.command),
        "control_id": bundle.control_id,
        "count_kind": bundle.count_kind,
        "environment_profile": bundle.environment_profile,
        "execution_id": bundle.execution_id,
        "exit_code": bundle.exit_code,
        "finished_at": bundle.finished_at,
        "outcome": bundle.outcome,
        "parser_version": bundle.parser_version,
        "raw_log_sha256": bundle.raw_log_sha256,
        "requirement_ids": list(bundle.requirement_ids),
        "revision": bundle.revision,
        "run_id": bundle.run_id,
        "security_catalog_sha256": bundle.security_catalog_sha256,
        "security_catalog_id": bundle.security_catalog_id,
        "source_tree_sha256": bundle.source_tree_sha256,
        "started_at": bundle.started_at,
        "task_id": bundle.task_id,
        "version": bundle.version,
    }
    if bundle.high_threat_evidence:
        content["high_threat_evidence"] = [
            {
                "evidence_root_sha256": mapping.evidence_root_sha256,
                "job": mapping.job,
                "positive_case_count": mapping.positive_case_count,
                "threat_id": mapping.threat_id,
            }
            for mapping in bundle.high_threat_evidence
        ]
    if include_root_sha256:
        content["root_sha256"] = bundle.root_sha256
    return content


@dataclass(frozen=True, slots=True)
class TaskAttemptEvidence:
    """Observed evidence bytes and authority-resolved security catalog."""

    raw_log: bytes
    attachments: tuple[bytes, ...] = ()
    security_catalog: RequiredSecurityCatalog | None = None
    security_catalog_bytes: bytes | None = None


type SecurityCatalogAuthority = Callable[[str], RequiredSecurityCatalog]


@dataclass(frozen=True, slots=True)
class _AttemptPublication:
    """Prepared final namespace and bytes for one atomic attempt publication."""

    attempt_id: str
    raw_log: bytes
    serialized_bundle: bytes
    attachments: tuple[bytes, ...]
    security_catalog_bytes: bytes | None


def persist_task_attempt_bundle(
    evidence_dir: Path,
    bundle: TaskAttemptBundle,
    evidence: TaskAttemptEvidence,
) -> Path:
    """Atomically publish one fsynced, immutable task-attempt directory."""
    validated_bundle = _validate_task_attempt_bundle(bundle, evidence)
    serialized_bundle = _serialize_task_attempt_bundle(validated_bundle)
    task_dir, task_fd = _open_task_directory(evidence_dir, validated_bundle.task_id)
    temp_name = f".{validated_bundle.attempt_id}.tmp-{secrets.token_hex(16)}"
    try:
        _publish_attempt(
            task_fd,
            temp_name,
            _AttemptPublication(
                attempt_id=validated_bundle.attempt_id,
                raw_log=evidence.raw_log,
                serialized_bundle=serialized_bundle,
                attachments=evidence.attachments,
                security_catalog_bytes=evidence.security_catalog_bytes,
            ),
        )
    except (EvidenceIntegrityError, OSError):
        _remove_temp_attempt(task_fd, temp_name)
        raise
    finally:
        os.close(task_fd)
    return task_dir / validated_bundle.attempt_id


def _validate_task_attempt_bundle(
    bundle: TaskAttemptBundle, evidence: TaskAttemptEvidence
) -> TaskAttemptBundle:
    """Validate the complete immutable content before any filesystem mutation."""
    require_evidence_sanitized(evidence.raw_log)
    for attachment in evidence.attachments:
        require_evidence_sanitized(attachment)
    require_evidence_sanitized(_serialize_task_attempt_bundle(bundle))
    validated_bundle = TaskAttemptBundle.model_validate_json(bundle.model_dump_json())
    if hashlib.sha256(evidence.raw_log).hexdigest() != validated_bundle.raw_log_sha256:
        raise _evidence_error(RAW_LOG_CHECKSUM_ERROR)
    attachment_hashes = tuple(
        hashlib.sha256(attachment).hexdigest() for attachment in evidence.attachments
    )
    if attachment_hashes != validated_bundle.attachment_sha256:
        raise _evidence_error(RAW_LOG_CHECKSUM_ERROR)
    is_security = validated_bundle.control_id == "SECURITY"
    if not is_security and (
        evidence.security_catalog is not None
        or evidence.security_catalog_bytes is not None
        or validated_bundle.high_threat_evidence
        or validated_bundle.security_catalog_sha256 is not None
        or validated_bundle.security_catalog_id is not None
    ):
        raise _evidence_error(HIGH_THREAT_MAPPING_ERROR)
    if is_security and (
        evidence.security_catalog is None
        or evidence.security_catalog_bytes is None
        or validated_bundle.security_catalog_sha256 is None
        or validated_bundle.security_catalog_id is None
    ):
        raise _evidence_error(HIGH_THREAT_MAPPING_ERROR)
    if evidence.security_catalog is not None:
        catalog_bytes = canonical_security_catalog_bytes(evidence.security_catalog)
        if (
            evidence.security_catalog_bytes != catalog_bytes
            or hashlib.sha256(
                security_catalog_source_bytes(evidence.security_catalog)
            ).hexdigest()
            != evidence.security_catalog.source_root_sha256
            or hashlib.sha256(catalog_bytes).hexdigest()
            != validated_bundle.security_catalog_sha256
        ):
            raise _evidence_error(HIGH_THREAT_MAPPING_ERROR)
        verify_security_evidence_mapping(
            evidence.security_catalog,
            validated_bundle.high_threat_evidence,
            attachment_hashes,
        )
    elif (
        validated_bundle.high_threat_evidence
        or validated_bundle.security_catalog_sha256 is not None
        or validated_bundle.security_catalog_id is not None
    ):
        raise _evidence_error(HIGH_THREAT_MAPPING_ERROR)
    if task_attempt_root(validated_bundle) != validated_bundle.root_sha256:
        raise _evidence_error(TASK_ATTEMPT_ROOT_CHECKSUM_ERROR)
    return validated_bundle


def canonical_security_catalog_bytes(catalog: RequiredSecurityCatalog) -> bytes:
    """Serialize independently supplied catalog content deterministically."""
    return (
        json.dumps(
            catalog.model_dump(mode="json"), separators=(",", ":"), sort_keys=True
        )
        + "\n"
    ).encode()


def security_catalog_source_bytes(catalog: RequiredSecurityCatalog) -> bytes:
    """Return independent catalog content bytes excluding its source anchor."""
    source = {
        "case_bindings": [
            binding.model_dump(mode="json") for binding in catalog.case_bindings
        ],
        "high_threat_ids": list(catalog.high_threat_ids),
        "version": catalog.version,
    }
    serialized_source = json.dumps(source, separators=(",", ":"), sort_keys=True)
    return (serialized_source + "\n").encode()


def _serialize_task_attempt_bundle(bundle: TaskAttemptBundle) -> bytes:
    """Serialize the sealed task attempt deterministically."""
    return (
        json.dumps(
            _task_attempt_content(bundle, include_root_sha256=True),
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()


def atomic_rename_no_replace(
    source: str, destination: str, *, source_dir_fd: int, destination_dir_fd: int
) -> None:
    """Atomically move a namespace only when its destination does not exist."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename: Callable[[int, bytes, int, bytes, int], int]
    if platform.system() == "Darwin":
        rename = cast(
            "Callable[[int, bytes, int, bytes, int], int]",
            libc.renameatx_np,
        )
        flags = 0x00000004  # RENAME_EXCL
    else:
        try:
            rename = cast(
                "Callable[[int, bytes, int, bytes, int], int]",
                libc.renameat2,
            )
        except AttributeError as error:
            message = "atomic no-replace rename is unavailable on this platform"
            raise OSError(message) from error
        flags = 1  # RENAME_NOREPLACE
    result: int = rename(
        source_dir_fd,
        source.encode(),
        destination_dir_fd,
        destination.encode(),
        flags,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        message = "atomic no-replace rename failed"
        raise OSError(error_number, message)


def _publish_attempt(
    task_fd: int, temp_name: str, publication: _AttemptPublication
) -> None:
    """Write, fsync, and atomically rename a new contained attempt directory."""
    os.mkdir(temp_name, 0o700, dir_fd=task_fd)
    temp_fd = os.open(
        temp_name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=task_fd,
    )
    try:
        write_confined_file(temp_fd, "raw.log", publication.raw_log)
        write_confined_file(temp_fd, "bundle.json", publication.serialized_bundle)
        for index, attachment in enumerate(publication.attachments):
            write_confined_file(temp_fd, f"attachment-{index}", attachment)
        if publication.security_catalog_bytes is not None:
            write_confined_file(
                temp_fd,
                "security-catalog.json",
                publication.security_catalog_bytes,
            )
        os.fsync(temp_fd)
    finally:
        os.close(temp_fd)
    try:
        atomic_rename_no_replace(
            temp_name,
            publication.attempt_id,
            source_dir_fd=task_fd,
            destination_dir_fd=task_fd,
        )
    except FileExistsError:
        raise _evidence_error(TASK_ATTEMPT_EXISTS_ERROR) from None
    os.fsync(task_fd)


def _path_identifier_is_safe(identifier: str) -> bool:
    """Allow only opaque identifiers that cannot express filesystem navigation."""
    return re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", identifier) is not None


def open_confined_directory(path: Path, *, create: bool) -> int:
    """Walk an absolute directory path from descriptors without following links."""
    absolute_path = path if path.is_absolute() else Path.cwd() / path
    parts = absolute_path.parts[1:]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        directory_fd = os.open(os.sep, flags)
    except OSError:
        raise _evidence_error(TASK_ATTEMPT_PATH_ERROR) from None
    try:
        for part in parts:
            try:
                next_fd = os.open(part, flags, dir_fd=directory_fd)
            except FileNotFoundError:
                if not create:
                    raise _evidence_error(TASK_ATTEMPT_PATH_ERROR) from None
                with suppress(FileExistsError):
                    os.mkdir(part, 0o700, dir_fd=directory_fd)
                os.fsync(directory_fd)
                try:
                    next_fd = os.open(part, flags, dir_fd=directory_fd)
                except OSError:
                    raise _evidence_error(TASK_ATTEMPT_PATH_ERROR) from None
            except OSError:
                raise _evidence_error(TASK_ATTEMPT_PATH_ERROR) from None
            os.close(directory_fd)
            directory_fd = next_fd
    except (EvidenceIntegrityError, OSError):
        os.close(directory_fd)
        raise
    return directory_fd


def _open_task_directory(evidence_dir: Path, task_id: str) -> tuple[Path, int]:
    """Create and open a task directory through trusted descriptors."""
    root_fd = open_confined_directory(evidence_dir, create=True)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        with suppress(FileExistsError):
            os.mkdir(task_id, 0o700, dir_fd=root_fd)
        os.fsync(root_fd)
        try:
            task_fd = os.open(task_id, flags, dir_fd=root_fd)
        except OSError:
            raise _evidence_error(TASK_ATTEMPT_PATH_ERROR) from None
    finally:
        os.close(root_fd)
    return evidence_dir / task_id, task_fd


def _remove_temp_attempt(task_fd: int, temp_name: str) -> None:
    """Remove only this invocation's unpublished temporary state."""
    try:
        temp_fd = os.open(
            temp_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=task_fd,
        )
    except OSError:
        return
    try:
        with os.scandir(temp_fd) as entries:
            names = tuple(entry.name for entry in entries)
        for name in names:
            try:
                os.unlink(name, dir_fd=temp_fd)
            except FileNotFoundError:
                continue
        os.rmdir(temp_name, dir_fd=task_fd)
        os.fsync(task_fd)
    except OSError:
        return
    finally:
        os.close(temp_fd)


def write_confined_file(directory_fd: int, name: str, content: bytes) -> None:
    """Write and fsync a new evidence file through a no-follow descriptor."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    file_fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    with os.fdopen(file_fd, "wb") as evidence_file:
        _ = evidence_file.write(content)
        evidence_file.flush()
        fsync_confined_file(evidence_file.fileno())


def fsync_confined_file(file_descriptor: int) -> None:
    """Durably flush one descriptor-confined evidence file."""
    os.fsync(file_descriptor)


def load_task_attempt_bundle(
    attempt_dir: Path,
    independent_anchor_sha256: str,
    catalog_authority: SecurityCatalogAuthority | None = None,
) -> TaskAttemptBundle:
    """Reload sealed evidence and independently re-resolve SECURITY catalogs."""
    directory_fd = open_confined_directory(attempt_dir, create=False)
    try:
        bundle_bytes = _read_attempt_file_from_directory(directory_fd, "bundle.json")
        require_evidence_sanitized(bundle_bytes)
        bundle = TaskAttemptBundle.model_validate_json(bundle_bytes)
        _verify_attempt_file_set(directory_fd, bundle)
        raw_log = _read_attempt_file_from_directory(directory_fd, "raw.log")
        require_evidence_sanitized(raw_log)
        if hashlib.sha256(raw_log).hexdigest() != bundle.raw_log_sha256:
            raise _evidence_error(RAW_LOG_CHECKSUM_ERROR)
        attachment_roots: list[str] = []
        aggregate_size = len(bundle_bytes) + len(raw_log)
        for index, expected_digest in enumerate(bundle.attachment_sha256):
            attachment = _read_attempt_file_from_directory(
                directory_fd, f"attachment-{index}"
            )
            aggregate_size += len(attachment)
            if aggregate_size > MAX_EVIDENCE_AGGREGATE_BYTES:
                raise _evidence_error(TASK_ATTEMPT_PATH_ERROR)
            if hashlib.sha256(attachment).hexdigest() != expected_digest:
                raise _evidence_error(RAW_LOG_CHECKSUM_ERROR)
            require_evidence_sanitized(attachment)
            attachment_roots.append(expected_digest)
        if bundle.control_id == "SECURITY":
            _verify_loaded_security_catalog(
                directory_fd,
                bundle,
                tuple(attachment_roots),
                catalog_authority,
            )
        elif (
            bundle.high_threat_evidence
            or bundle.security_catalog_sha256 is not None
            or bundle.security_catalog_id is not None
        ):
            raise _evidence_error(HIGH_THREAT_MAPPING_ERROR)
        computed_root = task_attempt_root(bundle)
        if (
            computed_root != bundle.root_sha256
            or computed_root != independent_anchor_sha256
        ):
            raise _evidence_error(TASK_ATTEMPT_ANCHOR_ERROR)
        return bundle
    finally:
        os.close(directory_fd)


def _verify_loaded_security_catalog(
    directory_fd: int,
    bundle: TaskAttemptBundle,
    attachment_roots: tuple[str, ...],
    catalog_authority: SecurityCatalogAuthority | None,
) -> None:
    """Verify the persisted catalog against a newly resolved authority result."""
    if (
        bundle.security_catalog_sha256 is None
        or bundle.security_catalog_id is None
        or catalog_authority is None
    ):
        raise _evidence_error(HIGH_THREAT_MAPPING_ERROR)
    catalog_bytes = _read_attempt_file_from_directory(
        directory_fd, "security-catalog.json"
    )
    require_evidence_sanitized(catalog_bytes)
    try:
        persisted_catalog = RequiredSecurityCatalog.model_validate_json(catalog_bytes)
    except ValueError:
        raise _evidence_error(HIGH_THREAT_MAPPING_ERROR) from None
    try:
        resolved_catalog = resolve_security_catalog(
            catalog_authority, bundle.security_catalog_id
        )
    except SecurityCatalogAuthorityError:
        raise _evidence_error(HIGH_THREAT_MAPPING_ERROR) from None
    canonical_bytes = canonical_security_catalog_bytes(resolved_catalog)
    if (
        catalog_bytes != canonical_bytes
        or hashlib.sha256(security_catalog_source_bytes(resolved_catalog)).hexdigest()
        != resolved_catalog.source_root_sha256
        or hashlib.sha256(catalog_bytes).hexdigest() != bundle.security_catalog_sha256
        or persisted_catalog != resolved_catalog
    ):
        raise _evidence_error(HIGH_THREAT_MAPPING_ERROR)
    verify_security_evidence_mapping(
        resolved_catalog, bundle.high_threat_evidence, attachment_roots
    )


def _verify_attempt_file_set(directory_fd: int, bundle: TaskAttemptBundle) -> None:
    """Reject missing or unexpected sealed attempt files."""
    expected_names = {"bundle.json", "raw.log"} | {
        f"attachment-{index}" for index in range(len(bundle.attachment_sha256))
    }
    if bundle.control_id == "SECURITY":
        expected_names.add("security-catalog.json")
    with os.scandir(directory_fd) as entries:
        if {entry.name for entry in entries} != expected_names:
            raise _evidence_error(EXACT_JOB_LOG_SET_ERROR)


def _read_attempt_file_from_directory(directory_fd: int, name: str) -> bytes:
    """Read a single-link regular sidecar from a pinned attempt directory."""
    try:
        file_fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
    except OSError:
        raise _evidence_error(TASK_ATTEMPT_PATH_ERROR) from None
    with os.fdopen(file_fd, "rb") as evidence_file:
        return _bounded_descriptor_read(evidence_file.fileno(), TASK_ATTEMPT_PATH_ERROR)


def verify_security_evidence_mapping(
    catalog: RequiredSecurityCatalog,
    mappings: tuple[SecurityEvidenceMapping, ...],
    attachment_roots: tuple[str, ...] = (),
) -> None:
    """Require the independently cataloged High threat set exactly once."""
    mapped_ids = tuple(mapping.threat_id for mapping in mappings)
    missing_or_duplicate_mappings = (
        not catalog.high_threat_ids
        or len(set(mapped_ids)) != len(mapped_ids)
        or set(mapped_ids) != set(catalog.high_threat_ids)
    )
    invalid_evidence = any(
        mapping.positive_case_count <= 0 for mapping in mappings
    ) or any(
        mapping.evidence_root_sha256 not in attachment_roots for mapping in mappings
    )
    if missing_or_duplicate_mappings:
        raise _evidence_error(HIGH_THREAT_MAPPING_ERROR)
    if invalid_evidence:
        raise _evidence_error(SECURITY_CASE_COUNT_ERROR)


def verify_evidence_files(
    evidence_dir: Path,
    records: tuple[GateResult, ...],
) -> None:
    """Bind each evidence record to single-link regular descriptor-pinned logs."""
    expected_names = {f"{record.job}.log" for record in records}
    directory_fd = open_confined_directory(evidence_dir, create=False)
    try:
        with os.scandir(directory_fd) as entries:
            if {entry.name for entry in entries} != expected_names:
                raise _evidence_error(EXACT_JOB_LOG_SET_ERROR)
        for record in records:
            raw_output = _read_evidence_file_from_directory(
                directory_fd, f"{record.job}.log"
            )
            if hashlib.sha256(raw_output).hexdigest() != record.output_sha256:
                raise _evidence_error(RAW_LOG_CHECKSUM_ERROR, record.job)
    finally:
        os.close(directory_fd)


def _read_evidence_file_from_directory(directory_fd: int, name: str) -> bytes:
    """Read one single-link regular CI log without path traversal or blocking."""
    try:
        file_fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
    except OSError:
        raise _evidence_error(EXACT_JOB_LOG_SET_ERROR) from None
    with os.fdopen(file_fd, "rb") as evidence_file:
        return _bounded_descriptor_read(evidence_file.fileno(), EXACT_JOB_LOG_SET_ERROR)


def render_openapi_catalog(source_path: Path) -> bytes:
    """Render deterministic schema names, typed routes, and mock routes."""
    source = source_path.read_bytes()
    document = _OpenApiInput.model_validate_json(source)
    routes = [
        {"methods": item.methods(), "path": path}
        for path, item in sorted(document.paths.items())
    ]
    catalog = {
        "mock_routes": [
            {"method": method, "path": route["path"], "status": 501}
            for route in routes
            for method in route["methods"]
        ],
        "routes": routes,
        "schema_names": sorted(document.components.schemas),
        "source_sha256": hashlib.sha256(source).hexdigest(),
    }
    return (json.dumps(catalog, separators=(",", ":"), sort_keys=True) + "\n").encode()
