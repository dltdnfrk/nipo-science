"""Execute the local CI contract and seal its raw evidence."""

from __future__ import annotations

import fcntl
import hashlib
import importlib
import json
import os
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, Final, Literal, NoReturn, cast, override

from . import ci_contract
from .ci_contract import (
    HIGH_THREAT_MAPPING_ERROR,
    CiCatalogJob,
    CiControlCatalog,
    CiCurrentRun,
    CiExecutionAttestation,
    CiExecutionLease,
    CiGenerationManifestAuthority,
    CiJob,
    CiRunState,
    CountKindValue,
    EvidenceIntegrityError,
    GateResult,
    RequiredSecurityCatalog,
    SecurityCatalogAuthority,
    SecurityCatalogAuthorityError,
    SecurityEvidenceMapping,
    TaskAttemptBundle,
    TaskAttemptEvidence,
    atomic_rename_no_replace,
    canonical_ci_manifest,
    canonical_security_catalog_bytes,
    open_confined_directory,
    parse_security_evidence_output,
    persist_task_attempt_bundle,
    redact_evidence_bytes,
    rederive_gate_count,
    require_evidence_sanitized,
    resolve_ci_control_catalog,
    resolve_security_catalog,
    task_attempt_root,
    verify_evidence,
    verify_execution_attestations,
    verify_records_against_catalog,
)
from .ci_paths import RELEASE_PYTHON_PATHS
from .release_contract import source_tree_sha256

CLI_ARG_COUNT = 2
CI_AUTHORITY_REQUIRED_ERROR: Final = (
    "CI publication requires an external generation authority"
)
CI_AUTHORITY_FACTORY_ENV: Final = "CI_GENERATION_MANIFEST_AUTHORITY"
CI_SOURCE_TREE_ENV: Final = "CI_SOURCE_TREE_SHA256"
CI_SOURCE_TREE_MISMATCH_ERROR: Final = (
    "CI source tree identity does not match the checkout"
)
CI_SOURCE_TREE_CHANGED_ERROR: Final = "CI source tree changed during execution"
CI_CONTROL_CATALOG_ROOT_ENV: Final = "CI_CONTROL_CATALOG_ROOT_SHA256"
CI_SECURITY_CATALOG_ROOT_ENV: Final = "CI_SECURITY_CATALOG_ROOT_SHA256"
PARSER_VERSION: Final = 1
PUBLICATION_LOCK_OPEN_ATTEMPTS: Final = 3
RESERVED_PORTABLE_ARGUMENTS: Final = frozenset(
    {"<python>", "<ruff>", "<basedpyright>", "<root>"}
)


class CountKind(StrEnum):
    """Machine-observed count formats emitted by CI commands."""

    ANALYZER_INVENTORY = "analyzer-inventory"
    PYTEST = "pytest"
    CHECKS = "checks"


COUNT_PATTERNS: Final[dict[CountKind, tuple[str, ...]]] = {
    CountKind.PYTEST: (
        r"(?:^|\s)(\d+) passed(?:[,\s]|$)",
        r"(?:^|\s)Ran (\d+) tests?(?:[.\s]|$)",
        r"CHECKS_EXECUTED=(\d+)",
    ),
    CountKind.CHECKS: (r"CHECKS_EXECUTED=(\d+)",),
}
PROCESS_TIMEOUT_SECONDS: Final = 15 * 60
PROCESS_OUTPUT_LIMIT_BYTES: Final = 8 * 1024 * 1024
SCRUBBED_ENVIRONMENT_NAMES: Final = frozenset(
    {"HOME", "PATH", "LANG", "LC_ALL", "PYTHONUTF8"}
)
PROCESS_FACTORY: Final[type[subprocess.Popen[bytes]]] = subprocess.Popen
SELECTOR_FACTORY: Final = selectors.DefaultSelector


def _raise_process_timeout() -> NoReturn:
    message = "CI command timed out"
    raise TimeoutError(message)


def _raise_process_output_limit() -> NoReturn:
    message = "CI command output exceeded limit"
    raise OverflowError(message)


@dataclass(frozen=True, slots=True)
class CiCommand:
    """Trusted argv and count parser for one CI job."""

    job: CiJob
    argv: tuple[str, ...]
    count_kind: CountKind
    inventory: tuple[Path, ...] = ()
    category: str = ""
    environment_profile: str = "local-ci"
    control_ids: tuple[str, ...] = ()
    requirement_ids: tuple[str, ...] = ()
    prerequisites: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CiExecutionBinding:
    """Fresh catalog authorities bound to one command execution."""

    catalog_job: CiCatalogJob
    catalog: CiControlCatalog
    current_run: CiCurrentRun
    lease: CiExecutionLease
    authority: CiGenerationManifestAuthority
    security_catalog: RequiredSecurityCatalog | None = None


@dataclass(frozen=True, slots=True)
class CiPublicationBinding:
    """External authority and frozen source identity for one CI publication."""

    authority_context: str
    source_tree_sha256: str
    authority: CiGenerationManifestAuthority
    current_run: CiCurrentRun


@dataclass(frozen=True, slots=True)
class CiStagedPublication:
    """Source-bound material required to stage one CI generation."""

    root: Path
    records: tuple[GateResult, ...]
    outputs: tuple[bytes, ...]
    binding: CiPublicationBinding
    published_run: CiCurrentRun


@dataclass(frozen=True, slots=True)
class CiJobFailedError(Exception):
    """Reports a nonzero CI command without echoing sensitive output."""

    job: CiJob
    return_code: int
    raw_output: bytes
    command: tuple[str, ...] = ()
    started_at: str = ""
    finished_at: str = ""

    @override
    def __str__(self) -> str:
        """Identify the failed job and exit status."""
        return f"CI job {self.job} failed with exit {self.return_code}"


@dataclass(frozen=True, slots=True)
class MissingExecutedCountError(Exception):
    """Rejects successful output that reports no executed work."""

    job: CiJob
    raw_output: bytes = b""
    command: tuple[str, ...] = ()
    started_at: str = ""
    finished_at: str = ""

    @override
    def __str__(self) -> str:
        """Identify the job with vacuous success output."""
        return f"CI job {self.job} did not report an executed count"


def scrubbed_subprocess_environment() -> dict[str, str]:
    """Pass runtime configuration only; children never inherit authority secrets."""
    return {
        name: value
        for name, value in os.environ.items()
        if name in SCRUBBED_ENVIRONMENT_NAMES
    }


def run_bounded_process(argv: tuple[str, ...], root: Path) -> tuple[int, bytes]:
    """Run an isolated process group with bounded combined output."""
    process: subprocess.Popen[bytes] = PROCESS_FACTORY(
        argv,
        cwd=root,
        env=scrubbed_subprocess_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    stream = process.stdout
    selector: selectors.BaseSelector | None = None
    try:
        if stream is None:
            message = "CI process has no output pipe"
            raise RuntimeError(message)
        selector = SELECTOR_FACTORY()
        _ = selector.register(stream, selectors.EVENT_READ)
        output = bytearray()
        deadline = time.monotonic() + PROCESS_TIMEOUT_SECONDS
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _raise_process_timeout()
            for key, _ in selector.select(remaining):
                selected = cast("BinaryIO", key.fileobj)
                chunk = os.read(selected.fileno(), 65536)
                if not chunk:
                    _ = selector.unregister(selected)
                    continue
                output.extend(chunk)
                if len(output) > PROCESS_OUTPUT_LIMIT_BYTES:
                    _raise_process_output_limit()
        try:
            return process.wait(timeout=max(0.1, deadline - time.monotonic())), bytes(
                output
            )
        except subprocess.TimeoutExpired:
            _raise_process_timeout()
    finally:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        with suppress(subprocess.TimeoutExpired):
            _ = process.wait(timeout=5)
        if selector is not None:
            selector.close()
        if stream is not None:
            stream.close()


RUN_PROCESS = run_bounded_process


def _verify_execution_binding(
    command: CiCommand, root: Path, binding: CiExecutionBinding, *, consume: bool
) -> None:
    """Reject substituted commands or stale leases before any child is spawned."""
    current = binding.authority.resolve_current(binding.current_run.authority_context)
    inventory_root = (
        inventory_root_sha256(command.inventory, root)
        if command.count_kind is CountKind.ANALYZER_INVENTORY
        else None
    )
    try:
        resolved_catalog = _require_fresh_catalog(
            binding.authority,
            binding.current_run.authority_context,
            binding.current_run.source_tree_sha256,
            binding.current_run.run_id,
            binding.catalog.catalog_root_sha256,
        )
        if consume:
            binding.authority.authorize_execution_lease(
                binding.lease,
                binding.current_run,
                resolved_catalog,
                binding.catalog_job,
            )
    except (AttributeError, LookupError, TypeError, ValueError, EvidenceIntegrityError):
        raise EvidenceIntegrityError(
            command.job, "CI execution lease is missing or mismatched"
        ) from None
    if (
        resolved_catalog != binding.catalog
        or current != binding.current_run
        or current.state is not CiRunState.ACTIVE
        or binding.catalog_job not in binding.catalog.jobs
        or binding.catalog_job.job is not command.job
        or binding.catalog_job.argv != portable_ci_argv(command, root)
        or binding.catalog_job.count_kind != command.count_kind
        or binding.catalog_job.parser_version != PARSER_VERSION
        or binding.catalog_job.analyzer_inventory_root_sha256 != inventory_root
        or binding.lease.authority_context != current.authority_context
        or binding.lease.run_id != current.run_id
        or binding.lease.attempt_id != current.attempt_id
        or binding.lease.source_tree_sha256 != current.source_tree_sha256
        or binding.lease.job is not command.job
        or any(argument in RESERVED_PORTABLE_ARGUMENTS for argument in command.argv)
        or source_tree_identity(root) != current.source_tree_sha256
    ):
        raise EvidenceIntegrityError(
            command.job, "CI execution lease is missing or mismatched"
        )


def execute_job(
    command: CiCommand,
    root: Path,
    binding: CiExecutionBinding | None = None,
) -> tuple[GateResult, bytes]:
    """Execute a trusted argv and return its bound raw output."""
    if binding is None:
        raise EvidenceIntegrityError(
            command.job, "CI execution lease is missing or mismatched"
        )
    _verify_execution_binding(command, root, binding, consume=True)
    catalog_job = binding.catalog_job
    catalog = binding.catalog
    catalog_run_id = binding.current_run.run_id
    security_catalog = binding.security_catalog
    started_at = _utc_now()
    try:
        return_code, captured_output = RUN_PROCESS(command.argv, root)
    except (OSError, OverflowError, RuntimeError, TimeoutError) as error:
        raise MissingExecutedCountError(
            command.job,
            f"{type(error).__name__}\n".encode(),
            command.argv,
            started_at,
            _utc_now(),
        ) from error
    finished_at = _utc_now()
    raw_output = _redact_raw_output(captured_output)
    if return_code != 0:
        raise CiJobFailedError(
            command.job,
            return_code,
            raw_output,
            command.argv,
            started_at,
            finished_at,
        )
    security_mappings = _security_mappings_from_output(
        command, raw_output, security_catalog
    )
    try:
        executed_count = (
            sum(item.positive_case_count for item in security_mappings)
            if command.job is CiJob.SECURITY
            else _parse_executed_count(command, raw_output.decode(errors="replace"))
        )
    except MissingExecutedCountError as error:
        raise MissingExecutedCountError(
            command.job, raw_output, command.argv, started_at, finished_at
        ) from error
    inventory_root = (
        inventory_root_sha256(command.inventory, root)
        if command.count_kind is CountKind.ANALYZER_INVENTORY
        else None
    )
    record = GateResult(
        job=command.job,
        executed_count=executed_count,
        output_sha256=hashlib.sha256(raw_output).hexdigest(),
        argv=catalog_job.argv if catalog_job else command.argv,
        count_kind=cast("CountKindValue", str(command.count_kind)),
        parser_version=PARSER_VERSION,
        analyzer_inventory_root_sha256=inventory_root,
        category=catalog_job.category
        if catalog_job
        else command.category or str(command.job),
        environment_profile=(
            catalog_job.environment_profile
            if catalog_job
            else command.environment_profile
        ),
        control_ids=(
            catalog_job.control_ids
            if catalog_job
            else command.control_ids or (str(command.job),)
        ),
        requirement_ids=catalog_job.requirement_ids
        if catalog_job
        else command.requirement_ids,
        prerequisites=catalog_job.prerequisites
        if catalog_job
        else command.prerequisites,
        blockers=catalog_job.blockers if catalog_job else command.blockers,
        catalog_root_sha256=catalog.catalog_root_sha256 if catalog else None,
        catalog_source_root_sha256=catalog.source_root_sha256 if catalog else None,
        catalog_run_id=catalog_run_id,
        security_catalog_root_sha256=(
            security_catalog.source_root_sha256 if security_catalog else None
        ),
        security_threat_ids=tuple(item.threat_id for item in security_mappings),
        security_evidence_roots=tuple(
            item.evidence_root_sha256 for item in security_mappings
        ),
        attachment_sha256=tuple(
            item.evidence_root_sha256 for item in security_mappings
        ),
        started_at=started_at,
        finished_at=finished_at,
    )
    _verify_execution_binding(command, root, binding, consume=False)
    try:
        attestation = binding.authority.attest_execution(
            binding.lease, record, f"python={sys.version.split()[0]}"
        )
        attested = record.model_copy(update={"execution_attestation": attestation})
        _ = ci_contract.verify_execution_attestation(
            binding.authority, attested, binding.current_run
        )
    except (AttributeError, LookupError, TypeError, ValueError, EvidenceIntegrityError):
        message = "CI execution authority rejected its lease"
        raise EvidenceIntegrityError(command.job, message) from None
    _verify_execution_binding(command, root, binding, consume=False)
    return attested, raw_output


def _security_mappings_from_output(
    command: CiCommand, output: bytes, catalog: RequiredSecurityCatalog | None
) -> tuple[SecurityEvidenceMapping, ...]:
    """Require sealed per-threat SECURITY evidence; pytest counts are insufficient."""
    if command.job is not CiJob.SECURITY:
        return ()
    if catalog is None:
        raise MissingExecutedCountError(command.job, output, command.argv)
    try:
        return parse_security_evidence_output(catalog, output)
    except EvidenceIntegrityError:
        raise MissingExecutedCountError(command.job, output, command.argv) from None


def _resolve_run_security_catalog(
    authority: CiGenerationManifestAuthority, catalog_id: str
) -> RequiredSecurityCatalog:
    try:
        return resolve_security_catalog(authority.resolve_security_catalog, catalog_id)
    except SecurityCatalogAuthorityError:
        raise EvidenceIntegrityError(
            CiJob.SECURITY, "SECURITY catalog authority is unavailable"
        ) from None


def portable_ci_argv(command: CiCommand, root: Path) -> tuple[str, ...]:
    """Normalize only deterministic interpreter, tool, and checkout placeholders."""
    python = sys.executable
    replacements = {
        python: "<python>",
        str(Path(python).with_name("ruff")): "<ruff>",
        str(Path(python).with_name("basedpyright")): "<basedpyright>",
        str(root): "<root>",
    }
    return tuple(replacements.get(argument, argument) for argument in command.argv)


def verify_ci_control_catalog_commands(
    catalog: CiControlCatalog, commands: tuple[CiCommand, ...], root: Path
) -> dict[CiJob, CiCatalogJob]:
    """Reject autonomous, duplicate, or semantically drifted command definitions."""
    expected = {item.job: item for item in catalog.jobs}
    if (
        len(expected) != len(catalog.jobs)
        or len(commands) != len(CiJob)
        or {item.job for item in commands} != set(CiJob)
    ):
        raise EvidenceIntegrityError(None, "CI control catalog job set mismatch")
    for command in commands:
        item = expected.get(command.job)
        inventory_root = (
            inventory_root_sha256(command.inventory, root)
            if command.count_kind is CountKind.ANALYZER_INVENTORY
            else None
        )
        if (
            item is None
            or item.argv != portable_ci_argv(command, root)
            or item.count_kind != command.count_kind
            or item.parser_version != PARSER_VERSION
            or item.analyzer_inventory_root_sha256 != inventory_root
        ):
            raise EvidenceIntegrityError(
                command.job, "CI control catalog command mismatch"
            )
    return expected


def _require_catalog_bound_records(
    records: tuple[GateResult, ...],
    catalog: CiControlCatalog,
    run_id: str,
    security_catalog: RequiredSecurityCatalog,
) -> None:
    if any(
        record.catalog_root_sha256 != catalog.catalog_root_sha256
        or record.catalog_source_root_sha256 != catalog.source_root_sha256
        or record.catalog_run_id != run_id
        for record in records
    ):
        raise EvidenceIntegrityError(None, "CI result is not catalog-bound")
    _ = verify_evidence(records)
    security = next(record for record in records if record.job is CiJob.SECURITY)
    if (
        security.security_catalog_root_sha256 != security_catalog.source_root_sha256
        or set(security.security_threat_ids) != set(security_catalog.high_threat_ids)
        or len(security.security_evidence_roots)
        != len(security_catalog.high_threat_ids)
    ):
        raise EvidenceIntegrityError(
            CiJob.SECURITY, "SECURITY evidence is not authority-bound"
        )


def _require_fresh_catalog(
    authority: CiGenerationManifestAuthority,
    authority_context: str,
    source_identity: str,
    run_id: str,
    expected_root: str | None = None,
) -> CiControlCatalog:
    catalog = resolve_ci_control_catalog(
        authority,
        authority_context,
        source_identity,
        run_id,
    )
    if expected_root is not None and catalog.catalog_root_sha256 != expected_root:
        raise EvidenceIntegrityError(None, "CI control catalog replayed or changed")
    return catalog


@dataclass(frozen=True, slots=True)
class CiPreparedRun:
    """Fresh catalogs and observed outputs for one current run."""

    catalog: CiControlCatalog
    security_catalog: RequiredSecurityCatalog
    completed: tuple[tuple[GateResult, bytes], ...]


def _execute_catalog_commands(
    authority: CiGenerationManifestAuthority,
    authority_context: str,
    source_identity: str,
    run_id: str,
    root: Path,
) -> CiPreparedRun:
    """Resolve fresh catalogs, compare commands, and execute the exact job set."""
    catalog = _require_fresh_catalog(
        authority,
        authority_context,
        source_identity,
        run_id,
    )
    commands = ci_commands(root)
    catalog_jobs = verify_ci_control_catalog_commands(catalog, commands, root)
    security_catalog = _resolve_run_security_catalog(
        authority,
        catalog.security_catalog_id,
    )
    current_run = authority.resolve_current(authority_context)
    completed = tuple(
        execute_job(
            command,
            root,
            CiExecutionBinding(
                catalog_job=catalog_jobs[command.job],
                catalog=catalog,
                current_run=current_run,
                security_catalog=(
                    security_catalog if command.job is CiJob.SECURITY else None
                ),
                lease=authority.issue_execution_lease(current_run, command.job),
                authority=authority,
            ),
        )
        for command in commands
    )
    return CiPreparedRun(catalog, security_catalog, completed)


def _require_security_catalog_unchanged(
    authority: CiGenerationManifestAuthority,
    catalog: CiControlCatalog,
    expected: RequiredSecurityCatalog,
) -> None:
    """Reject a changed High-threat authority before publication."""
    current = _resolve_run_security_catalog(authority, catalog.security_catalog_id)
    if current.source_root_sha256 != expected.source_root_sha256:
        raise EvidenceIntegrityError(
            CiJob.SECURITY,
            "SECURITY catalog replayed or changed",
        )


def _require_configured_source_identity(
    root: Path,
    current_run: CiCurrentRun,
    authority: CiGenerationManifestAuthority,
    actual_source_tree_sha256: str,
) -> None:
    """Seal an incomplete run when the externally configured source is stale."""
    if os.environ.get(CI_SOURCE_TREE_ENV) == actual_source_tree_sha256:
        return
    error = MissingExecutedCountError(
        CiJob.RELEASE,
        CI_SOURCE_TREE_MISMATCH_ERROR.encode(),
        ("source-tree-identity",),
        current_run.started_at,
        _utc_now(),
    )
    attempt_root = _seal_incomplete_ci_attempt(root, error, current_run)
    authority.complete(
        _failed_current_run(current_run, CiRunState.INCOMPLETE, attempt_root)
    )
    raise ValueError(CI_SOURCE_TREE_MISMATCH_ERROR)


def run_ci(
    root: Path, authority: CiGenerationManifestAuthority | None = None
) -> tuple[GateResult, ...]:
    """Run every job under one externally anchored, fail-closed current run."""
    if authority is None:
        raise ValueError(CI_AUTHORITY_REQUIRED_ERROR)
    checkout_root = root.resolve()
    authority_context = os.environ.get("GITHUB_SHA")
    if not authority_context:
        message = "CI publication requires GITHUB_SHA authority context"
        raise ValueError(message)

    actual_source_tree_sha256 = source_tree_identity(checkout_root)
    current_run = CiCurrentRun(
        run_id=secrets.token_hex(16),
        attempt_id=secrets.token_hex(16),
        authority_context=authority_context,
        source_tree_sha256=actual_source_tree_sha256,
        started_at=_utc_now(),
        state=CiRunState.ACTIVE,
    )
    authority.begin(current_run)

    _require_configured_source_identity(
        checkout_root,
        current_run,
        authority,
        actual_source_tree_sha256,
    )

    try:
        prepared = _execute_catalog_commands(
            authority,
            authority_context,
            actual_source_tree_sha256,
            current_run.run_id,
            checkout_root,
        )
    except CiJobFailedError as error:
        attempt_root = _seal_failed_ci_attempt(checkout_root, error, current_run)
        authority.complete(
            _failed_current_run(current_run, CiRunState.FAILURE, attempt_root)
        )
        raise
    except MissingExecutedCountError as error:
        attempt_root = _seal_incomplete_ci_attempt(checkout_root, error, current_run)
        authority.complete(
            _failed_current_run(current_run, CiRunState.INCOMPLETE, attempt_root)
        )
        raise
    except (EvidenceIntegrityError, OSError, RuntimeError, ValueError) as error:
        incomplete = _infrastructure_incomplete_error(
            "ci-execution", current_run, error
        )
        attempt_root = _seal_incomplete_ci_attempt(
            checkout_root, incomplete, current_run
        )
        authority.complete(
            _failed_current_run(current_run, CiRunState.INCOMPLETE, attempt_root)
        )
        raise

    catalog = prepared.catalog
    security_catalog = prepared.security_catalog
    completed = prepared.completed
    records = tuple(item[0] for item in completed)
    _require_catalog_bound_records(
        records, catalog, current_run.run_id, security_catalog
    )
    outputs = tuple(item[1] for item in completed)
    try:
        _ = _require_fresh_catalog(
            authority,
            authority_context,
            actual_source_tree_sha256,
            current_run.run_id,
            catalog.catalog_root_sha256,
        )
        _require_security_catalog_unchanged(
            authority,
            catalog,
            security_catalog,
        )
        _require_source_unchanged(
            checkout_root,
            actual_source_tree_sha256,
        )
        _generation_id, _published_run = publish_ci_generation(
            checkout_root,
            records,
            outputs,
            CiPublicationBinding(
                authority_context,
                actual_source_tree_sha256,
                authority,
                current_run,
            ),
        )
    except (EvidenceIntegrityError, OSError, RuntimeError, ValueError) as error:
        incomplete = _infrastructure_incomplete_error(
            "ci-publication", current_run, error
        )
        attempt_root = _seal_incomplete_ci_attempt(
            checkout_root, incomplete, current_run
        )
        authority.complete(
            _failed_current_run(current_run, CiRunState.INCOMPLETE, attempt_root)
        )
        raise

    return records


def _require_active_publication_run(binding: CiPublicationBinding) -> None:
    """Require the authority's current run to be this exact active invocation."""
    try:
        current_run = binding.authority.resolve_current(binding.authority_context)
    except LookupError:
        raise EvidenceIntegrityError(
            None, "CI current run authority is unavailable"
        ) from None
    if (
        current_run != binding.current_run
        or current_run.state is not CiRunState.ACTIVE
        or current_run.authority_context != binding.authority_context
        or current_run.source_tree_sha256 != binding.source_tree_sha256
    ):
        raise EvidenceIntegrityError(None, "CI current run is stale or superseded")


def _finalize_attested_generation(
    binding: CiPublicationBinding,
    published_run: CiCurrentRun,
    manifest_bytes: bytes,
    attestations: tuple[CiExecutionAttestation, ...],
) -> None:
    """Translate rejected authority transitions into evidence-integrity failures."""
    try:
        binding.authority.finalize_attested_generation(
            binding.current_run,
            published_run,
            hashlib.sha256(manifest_bytes).hexdigest(),
            attestations,
        )
    except (AttributeError, LookupError, TypeError, ValueError):
        message = "CI current run is stale or superseded"
        raise EvidenceIntegrityError(None, message) from None


def _require_finalized_publication_run(
    root: Path,
    binding: CiPublicationBinding,
    published_run: CiCurrentRun,
    generation_name: str,
    manifest_bytes: bytes,
) -> None:
    """Verify the authority committed the exact generation before latest can move."""
    try:
        current_run = binding.authority.resolve_current(binding.authority_context)
    except LookupError:
        message = "CI finalized run authority is unavailable"
        raise EvidenceIntegrityError(None, message) from None
    if (
        current_run != published_run
        or current_run.state is not CiRunState.SUCCESS
        or current_run.generation_id != generation_name
        or current_run.authority_context != binding.authority_context
        or current_run.source_tree_sha256 != binding.source_tree_sha256
    ):
        message = "CI finalized run is stale or substituted"
        raise EvidenceIntegrityError(None, message)
    if source_tree_identity(root) != binding.source_tree_sha256:
        raise EvidenceIntegrityError(None, CI_SOURCE_TREE_MISMATCH_ERROR)
    ci_contract.verify_ci_manifest_anchor(
        binding.authority,
        binding.authority_context,
        generation_name,
        manifest_bytes,
    )
    evidence_fd = open_confined_directory(root / ".ci/evidence", create=False)
    try:
        latest_target = os.readlink("latest", dir_fd=evidence_fd)
    except OSError:
        latest_target = ""
    finally:
        os.close(evidence_fd)
    if latest_target != f"generations/{generation_name}":
        message = "CI latest generation is stale or substituted"
        raise EvidenceIntegrityError(None, message)


def _verify_publication_authorities(
    root: Path,
    records: tuple[GateResult, ...],
    outputs: tuple[bytes, ...],
    binding: CiPublicationBinding,
) -> None:
    """Independently rederive every authority commitment before publication."""
    _require_active_publication_run(binding)
    if source_tree_identity(root) != binding.source_tree_sha256:
        raise EvidenceIntegrityError(None, CI_SOURCE_TREE_MISMATCH_ERROR)
    catalog = _require_fresh_catalog(
        binding.authority,
        binding.authority_context,
        binding.source_tree_sha256,
        binding.current_run.run_id,
    )
    verify_records_against_catalog(records, catalog, binding.current_run.run_id)
    _ = verify_execution_attestations(binding.authority, records, binding.current_run)
    security_catalog = _resolve_run_security_catalog(
        binding.authority,
        catalog.security_catalog_id,
    )
    _require_catalog_bound_records(
        records,
        catalog,
        binding.current_run.run_id,
        security_catalog,
    )
    evidence = {
        record.job: (record, output)
        for record, output in zip(records, outputs, strict=True)
    }
    if set(evidence) != set(CiJob):
        raise EvidenceIntegrityError(None, "CI result set is incomplete")
    for record, output in evidence.values():
        if hashlib.sha256(output).hexdigest() != record.output_sha256:
            raise EvidenceIntegrityError(record.job, "CI output checksum drift")
        rederive_gate_count(record, output)
    security, output = evidence[CiJob.SECURITY]
    mappings = parse_security_evidence_output(security_catalog, output)
    mapped_ids = tuple(item.threat_id for item in mappings)
    evidence_roots = tuple(item.evidence_root_sha256 for item in mappings)
    if (
        security.security_threat_ids != mapped_ids
        or security.security_evidence_roots != evidence_roots
        or security.attachment_sha256 != evidence_roots
    ):
        raise EvidenceIntegrityError(
            CiJob.SECURITY,
            "SECURITY evidence is not authority-bound",
        )


def _require_bounded_outputs(outputs: tuple[bytes, ...]) -> None:
    """Apply the same evidence limits before any durable publication."""
    if (
        any(len(output) > ci_contract.MAX_EVIDENCE_FILE_BYTES for output in outputs)
        or sum(len(output) for output in outputs)
        > ci_contract.MAX_EVIDENCE_AGGREGATE_BYTES
    ):
        raise EvidenceIntegrityError(None, "CI evidence exceeds publication limits")


def _validate_publication_lock(lock_fd: int) -> None:
    status = os.fstat(lock_fd)
    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
        message = "CI publication lock is unsafe"
        raise RuntimeError(message)


def _open_publication_lock_file(control_fd: int, flags: int) -> int:
    """Tolerate the Darwin first-creator race for O_CREAT plus O_NOFOLLOW."""
    for attempt in range(PUBLICATION_LOCK_OPEN_ATTEMPTS):
        try:
            return os.open(
                ".publication-lock",
                flags,
                0o600,
                dir_fd=control_fd,
            )
        except FileNotFoundError:
            if attempt == PUBLICATION_LOCK_OPEN_ATTEMPTS - 1:
                raise
    message = "CI publication lock could not be opened"
    raise RuntimeError(message)


def _acquire_publication_lock(evidence_fd: int) -> int:
    """Serialize publication through a descriptor-confined evidence lock."""
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    lock_fd = _open_publication_lock_file(evidence_fd, flags)
    try:
        _validate_publication_lock(lock_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
    except BaseException:
        os.close(lock_fd)
        raise
    return lock_fd


def _open_publication_directories(root: Path) -> tuple[int, int]:
    """Open the evidence and lock descriptors without leaking."""
    evidence_fd = open_confined_directory(root / ".ci/evidence", create=True)
    try:
        lock_fd = _acquire_publication_lock(evidence_fd)
    except BaseException:
        os.close(evidence_fd)
        raise
    return lock_fd, evidence_fd


def _unlink_latest_if_owned(evidence_fd: int, generation_name: str) -> None:
    """Remove latest only when it still names this failed invocation's generation."""
    try:
        target = os.readlink("latest", dir_fd=evidence_fd)
    except OSError:
        return
    if target == f"generations/{generation_name}":
        os.unlink("latest", dir_fd=evidence_fd)
        fsync_generation(evidence_fd)


def publish_ci_generation(
    root: Path,
    records: tuple[GateResult, ...],
    outputs: tuple[bytes, ...],
    binding: CiPublicationBinding,
) -> tuple[str, CiCurrentRun]:
    """Durably externally anchor one generation before replacing latest."""
    if len(records) != len(outputs):
        message = "CI records and outputs must have matching lengths"
        raise ValueError(message)
    _require_bounded_outputs(outputs)
    for output in outputs:
        require_evidence_sanitized(output)
    _ = verify_evidence(records)
    lock_fd, evidence_fd = _open_publication_directories(root)
    generation_name = secrets.token_hex(16)
    published_run = binding.current_run.model_copy(
        update={
            "finished_at": _utc_now(),
            "generation_id": generation_name,
            "state": CiRunState.SUCCESS,
        }
    )
    pointer_name: str | None = None
    pointer_switched = False
    finalized = False
    try:
        _verify_publication_authorities(root, records, outputs, binding)
        manifest_bytes = _stage_and_publish_generation(
            evidence_fd,
            generation_name,
            CiStagedPublication(root, records, outputs, binding, published_run),
        )
        _verify_publication_authorities(root, records, outputs, binding)
        attestations = verify_execution_attestations(
            binding.authority, records, binding.current_run
        )
        pointer_name = f".latest-{secrets.token_hex(16)}"
        create_latest_pointer(evidence_fd, generation_name, pointer_name)
        fsync_generation(evidence_fd)
        switch_latest_pointer(evidence_fd, pointer_name)
        pointer_switched = True
        fsync_generation(evidence_fd)
        try:
            _finalize_attested_generation(
                binding,
                published_run,
                manifest_bytes,
                attestations,
            )
        except (
            AttributeError,
            LookupError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
            EvidenceIntegrityError,
        ) as finalization_error:
            try:
                _require_finalized_publication_run(
                    root,
                    binding,
                    published_run,
                    generation_name,
                    manifest_bytes,
                )
            except EvidenceIntegrityError as reconciliation_error:
                raise finalization_error from reconciliation_error
        finalized = True
        _require_finalized_publication_run(
            root,
            binding,
            published_run,
            generation_name,
            manifest_bytes,
        )
    except Exception:
        if pointer_name is not None and not finalized:
            with suppress(OSError):
                if pointer_switched:
                    _unlink_latest_if_owned(evidence_fd, generation_name)
                else:
                    os.unlink(pointer_name, dir_fd=evidence_fd)
                    fsync_generation(evidence_fd)
        raise
    finally:
        os.close(evidence_fd)
        with suppress(OSError):
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    return generation_name, published_run


def _stage_and_publish_generation(
    evidence_fd: int,
    generation_name: str,
    publication: CiStagedPublication,
) -> bytes:
    """Seal, verify, and atomically publish one staged generation directory."""
    staging_name = f".staging-{generation_name}"
    published = False
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with suppress(FileExistsError):
        os.mkdir("generations", 0o700, dir_fd=evidence_fd)
    fsync_generation(evidence_fd)
    generations_fd = os.open("generations", flags, dir_fd=evidence_fd)
    try:
        os.mkdir(staging_name, 0o700, dir_fd=generations_fd)
        fsync_generation(generations_fd)
        staging_fd = os.open(staging_name, flags, dir_fd=generations_fd)
        try:
            manifest_bytes = _write_and_verify_staged_generation(
                staging_fd, publication
            )
        finally:
            os.close(staging_fd)
        atomic_rename_no_replace(
            staging_name,
            generation_name,
            source_dir_fd=generations_fd,
            destination_dir_fd=generations_fd,
        )
        published = True
        fsync_generation(generations_fd)
    finally:
        if not published:
            if sys.exc_info()[0] is None:
                _remove_invocation_staging(generations_fd, staging_name)
            else:
                with suppress(OSError, RuntimeError):
                    _remove_invocation_staging(generations_fd, staging_name)
        os.close(generations_fd)
    return manifest_bytes


def _write_and_verify_staged_generation(
    staging_fd: int, publication: CiStagedPublication
) -> bytes:
    """Write, flush, and independently verify an unpublished generation."""
    for record, output in zip(publication.records, publication.outputs, strict=True):
        write_generation_file(staging_fd, f"{record.job}.log", output)
    manifest_bytes = canonical_ci_manifest(
        publication.binding.authority_context,
        publication.binding.source_tree_sha256,
        publication.records,
        publication.published_run,
    )
    write_generation_file(staging_fd, "manifest.json", manifest_bytes)
    _verify_generation_files(
        staging_fd,
        publication.records,
        publication.binding.authority_context,
        publication.binding.source_tree_sha256,
        publication.published_run,
    )
    fsync_generation(staging_fd)
    staged_outputs = tuple(
        read_staged_generation_file(staging_fd, f"{record.job}.log")
        for record in publication.records
    )
    _verify_publication_authorities(
        publication.root,
        publication.records,
        staged_outputs,
        publication.binding,
    )
    return manifest_bytes


def fsync_generation(file_descriptor: int) -> None:
    """Durably flush one CI-generation publication boundary."""
    os.fsync(file_descriptor)


def _remove_invocation_staging(generations_fd: int, staging_name: str) -> None:
    """Delete only this invocation's staging namespace through pinned descriptors."""
    try:
        staging_fd = os.open(
            staging_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=generations_fd,
        )
    except FileNotFoundError:
        return
    try:
        with os.scandir(staging_fd) as entries:
            names = tuple(entry.name for entry in entries)
        for name in names:
            file_fd = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                dir_fd=staging_fd,
            )
            try:
                status = os.fstat(file_fd)
                if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                    msg = "invocation staging contains unsafe entry"
                    raise RuntimeError(msg)
            finally:
                os.close(file_fd)
            os.unlink(name, dir_fd=staging_fd)
    finally:
        os.close(staging_fd)
    os.rmdir(staging_name, dir_fd=generations_fd)
    fsync_generation(generations_fd)


def write_generation_file(directory_fd: int, name: str, content: bytes) -> None:
    """Write one staged generation file through the confined writer."""
    ci_contract.write_confined_file(directory_fd, name, content)


def create_latest_pointer(
    evidence_fd: int, generation_name: str, pointer_name: str
) -> None:
    """Create an unpublished latest-generation pointer."""
    os.symlink(f"generations/{generation_name}", pointer_name, dir_fd=evidence_fd)


def switch_latest_pointer(evidence_fd: int, pointer_name: str) -> None:
    """Atomically replace latest with a fully durable pointer."""
    os.rename(
        pointer_name,
        "latest",
        src_dir_fd=evidence_fd,
        dst_dir_fd=evidence_fd,
    )


def read_staged_generation_file(generation_fd: int, name: str) -> bytes:
    """Read a single-link regular staged file without following or blocking."""
    try:
        file_fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
            dir_fd=generation_fd,
        )
    except OSError as error:
        message = f"staged CI evidence is unsafe: {name}"
        raise RuntimeError(message) from error
    with os.fdopen(file_fd, "rb") as evidence_file:
        file_status = os.fstat(evidence_file.fileno())
        if not stat.S_ISREG(file_status.st_mode) or file_status.st_nlink != 1:
            message = f"staged CI evidence is unsafe: {name}"
            raise RuntimeError(message)
        return evidence_file.read()


def _verify_generation_files(
    generation_fd: int,
    records: tuple[GateResult, ...],
    authority_context: str,
    source_tree_sha256: str,
    current_run: CiCurrentRun,
) -> None:
    """Verify each sealed staged log through its descriptor before publication."""
    expected_names = {"manifest.json"} | {f"{record.job}.log" for record in records}
    with os.scandir(generation_fd) as entries:
        if {entry.name for entry in entries} != expected_names:
            message = "staged CI evidence has an unexpected file set"
            raise RuntimeError(message)
    for record in records:
        raw_output = read_staged_generation_file(
            generation_fd,
            f"{record.job}.log",
        )
        if hashlib.sha256(raw_output).hexdigest() != record.output_sha256:
            message = f"staged CI evidence changed for {record.job}"
            raise RuntimeError(message)
    manifest_bytes = read_staged_generation_file(generation_fd, "manifest.json")
    if manifest_bytes != canonical_ci_manifest(
        authority_context, source_tree_sha256, records, current_run
    ):
        message = "staged CI manifest does not bind its logs"
        raise RuntimeError(message)


@dataclass(frozen=True, slots=True)
class TaskAttemptRequest:
    """Inputs that identify and describe one sealed task attempt."""

    task_id: str
    run_id: str
    execution_id: str
    attempt_id: str
    revision: int
    outcome: Literal["failure", "incomplete"]
    exit_code: int | None
    started_at: str
    finished_at: str | None
    command: tuple[str, ...]
    control_id: str
    attachments: tuple[bytes, ...] = ()
    security_catalog_id: str | None = None
    high_threat_evidence: tuple[SecurityEvidenceMapping, ...] = ()
    source_tree_sha256: str | None = None
    count_kind: CountKind | None = None
    parser_version: Literal[1] | None = None
    analyzer_inventory_root_sha256: str | None = None
    category: str = ""
    environment_profile: str = "local-ci"
    requirement_ids: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    cleanup_state: Literal["clean", "retained", "incomplete"] = "clean"


def seal_task_attempt_evidence(
    evidence_dir: Path,
    request: TaskAttemptRequest,
    raw_log: bytes,
    catalog_authority: SecurityCatalogAuthority | None = None,
) -> Path:
    """Build a sealed bundle using a SECURITY catalog resolved by authority."""
    security_catalog: RequiredSecurityCatalog | None = None
    security_catalog_bytes: bytes | None = None
    if request.control_id == "SECURITY":
        if request.security_catalog_id is None or catalog_authority is None:
            raise EvidenceIntegrityError(None, HIGH_THREAT_MAPPING_ERROR)
        try:
            security_catalog = resolve_security_catalog(
                catalog_authority, request.security_catalog_id
            )
        except SecurityCatalogAuthorityError:
            raise EvidenceIntegrityError(None, HIGH_THREAT_MAPPING_ERROR) from None
        security_catalog_bytes = canonical_security_catalog_bytes(security_catalog)
    elif request.security_catalog_id is not None:
        raise EvidenceIntegrityError(None, HIGH_THREAT_MAPPING_ERROR)
    provisional = TaskAttemptBundle(
        task_id=request.task_id,
        run_id=request.run_id,
        execution_id=request.execution_id,
        attempt_id=request.attempt_id,
        revision=request.revision,
        outcome=request.outcome,
        exit_code=request.exit_code,
        started_at=request.started_at,
        finished_at=request.finished_at,
        command=request.command,
        control_id=request.control_id,
        attachment_sha256=tuple(
            hashlib.sha256(attachment).hexdigest() for attachment in request.attachments
        ),
        high_threat_evidence=request.high_threat_evidence,
        security_catalog_sha256=(
            hashlib.sha256(security_catalog_bytes).hexdigest()
            if security_catalog_bytes is not None
            else None
        ),
        security_catalog_id=request.security_catalog_id,
        raw_log_sha256=hashlib.sha256(raw_log).hexdigest(),
        root_sha256="0" * 64,
        source_tree_sha256=request.source_tree_sha256,
        count_kind=(
            cast("CountKindValue", str(request.count_kind))
            if request.count_kind is not None
            else None
        ),
        parser_version=request.parser_version,
        analyzer_inventory_root_sha256=request.analyzer_inventory_root_sha256,
        category=request.category,
        environment_profile=request.environment_profile,
        requirement_ids=request.requirement_ids,
        blockers=request.blockers,
        cleanup_state=request.cleanup_state,
    )
    bundle = provisional.model_copy(
        update={"root_sha256": task_attempt_root(provisional)}
    )
    return persist_task_attempt_bundle(
        evidence_dir,
        bundle,
        TaskAttemptEvidence(
            raw_log=raw_log,
            attachments=request.attachments,
            security_catalog=security_catalog,
            security_catalog_bytes=security_catalog_bytes,
        ),
    )


def _parse_executed_count(command: CiCommand, output: str) -> int:
    if command.count_kind is CountKind.ANALYZER_INVENTORY:
        if not command.inventory or any(
            not path.is_file() for path in command.inventory
        ):
            raise MissingExecutedCountError(command.job)
        return len(command.inventory)
    return _positive_count(
        command.job,
        sum(
            int(match.group(1))
            for pattern in COUNT_PATTERNS[command.count_kind]
            for match in re.finditer(pattern, output)
        ),
    )


def _positive_count(job: CiJob, count: int) -> int:
    if count <= 0:
        raise MissingExecutedCountError(job)
    return count


def source_tree_identity(root: Path) -> str:
    """Return the shared frozen source-tree identity."""
    return source_tree_sha256(root)


def inventory_root_sha256(inventory: tuple[Path, ...], root: Path) -> str:
    """Bind the exact analyzer inventory names and content to the job receipt."""
    content = [
        (
            path.relative_to(root).as_posix(),
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in sorted(inventory)
    ]
    return hashlib.sha256(
        json.dumps(content, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()


def _redact_raw_output(raw_output: bytes) -> bytes:
    """Apply the centralized evidence sanitizer before hashing or persistence."""
    return redact_evidence_bytes(raw_output)


def _utc_now() -> str:
    """Return canonical UTC timestamps used at every run transition."""
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _infrastructure_incomplete_error(
    operation: str,
    current_run: CiCurrentRun,
    error: Exception,
) -> MissingExecutedCountError:
    """Describe infrastructure failure without persisting exception secrets."""
    return MissingExecutedCountError(
        CiJob.RELEASE,
        f"{type(error).__name__}\n".encode(),
        (operation,),
        current_run.started_at,
        _utc_now(),
    )


def _require_source_unchanged(root: Path, expected_sha256: str) -> None:
    """Reject any checkout mutation observed during the current run."""
    if source_tree_identity(root) != expected_sha256:
        raise ValueError(CI_SOURCE_TREE_CHANGED_ERROR)


def _failed_current_run(
    current_run: CiCurrentRun, state: CiRunState, attempt_root_sha256: str
) -> CiCurrentRun:
    """Build one terminal failure/incomplete transition for the active run."""
    return current_run.model_copy(
        update={
            "attempt_root_sha256": attempt_root_sha256,
            "finished_at": _utc_now(),
            "state": state,
        }
    )


def _seal_failed_ci_attempt(
    root: Path, error: CiJobFailedError, current_run: CiCurrentRun
) -> str:
    """Persist exact current-run failed output before surfacing command failure."""
    request = TaskAttemptRequest(
        task_id="ci-command-failure",
        run_id=current_run.run_id,
        execution_id=current_run.authority_context,
        attempt_id=current_run.attempt_id,
        revision=1,
        outcome="failure",
        exit_code=error.return_code,
        started_at=error.started_at,
        finished_at=error.finished_at,
        command=error.command,
        control_id=str(error.job),
        source_tree_sha256=current_run.source_tree_sha256,
        category=str(error.job),
        requirement_ids=(str(error.job),),
        cleanup_state="retained",
    )
    sealed = seal_task_attempt_evidence(
        root / ".ci" / "failed-attempts", request, error.raw_output
    )
    return cast("str", json.loads((sealed / "bundle.json").read_text())["root_sha256"])


def _seal_incomplete_ci_attempt(
    root: Path, error: MissingExecutedCountError, current_run: CiCurrentRun
) -> str:
    """Persist a current run whose output cannot prove executed work."""
    request = TaskAttemptRequest(
        task_id="ci-command-incomplete",
        run_id=current_run.run_id,
        execution_id=current_run.authority_context,
        attempt_id=current_run.attempt_id,
        revision=1,
        outcome="incomplete",
        exit_code=None,
        started_at=error.started_at or current_run.started_at,
        finished_at=None,
        command=error.command or ("ci-publication", str(error.job)),
        control_id=str(error.job),
        source_tree_sha256=current_run.source_tree_sha256,
        category=str(error.job),
        requirement_ids=(str(error.job),),
        blockers=(str(error),),
        cleanup_state="incomplete",
    )
    sealed = seal_task_attempt_evidence(
        root / ".ci" / "failed-attempts", request, error.raw_output
    )
    return cast("str", json.loads((sealed / "bundle.json").read_text())["root_sha256"])


def ci_commands(root: Path) -> tuple[CiCommand, ...]:
    """Return the release-blocking commands executed by local and hosted CI."""
    python = sys.executable
    ruff = str(Path(python).with_name("ruff"))
    basedpyright = str(Path(python).with_name("basedpyright"))
    pytest = (python, "-m", "pytest", "-q")
    platform = "tests/platform"
    static = (python, "-m", "tools.platform_policy.static_checks")
    make = ("make", "--no-print-directory", "-C", str(root))
    return (
        CiCommand(
            CiJob.LINT,
            (ruff, "check", *RELEASE_PYTHON_PATHS),
            CountKind.ANALYZER_INVENTORY,
            _analyzer_inventory(root),
        ),
        CiCommand(
            CiJob.TYPECHECK,
            (basedpyright, *RELEASE_PYTHON_PATHS),
            CountKind.ANALYZER_INVENTORY,
            _analyzer_inventory(root),
        ),
        CiCommand(
            CiJob.PLATFORM_TESTS,
            (*pytest, platform),
            CountKind.PYTEST,
        ),
        CiCommand(CiJob.BOUNDARIES, (*make, "test-boundaries"), CountKind.PYTEST),
        CiCommand(CiJob.SPEC, (*make, "verify-spec"), CountKind.PYTEST),
        CiCommand(
            CiJob.ARCHITECTURE,
            (*make, "verify-architecture"),
            CountKind.PYTEST,
        ),
        CiCommand(CiJob.OPENAPI, (*make, "test-openapi"), CountKind.PYTEST),
        CiCommand(
            CiJob.PROTOCOL_CONTRACTS,
            (*make, "test-protocol-contracts"),
            CountKind.PYTEST,
        ),
        CiCommand(
            CiJob.ARTIFACT_CONTRACTS,
            (*make, "test-artifact-contracts"),
            CountKind.PYTEST,
        ),
        CiCommand(
            CiJob.LOCAL_CONFIG,
            (*make, "test-local-config"),
            CountKind.PYTEST,
        ),
        CiCommand(CiJob.MIGRATIONS, (*make, "test-migrations"), CountKind.PYTEST),
        CiCommand(CiJob.RLS, (*make, "test-rls"), CountKind.PYTEST),
        CiCommand(CiJob.UPLOAD, (*make, "test-upload"), CountKind.PYTEST),
        CiCommand(CiJob.ARTIFACTS, (*make, "test-artifacts"), CountKind.PYTEST),
        CiCommand(CiJob.SCIENCE, (*make, "test-science"), CountKind.PYTEST),
        CiCommand(
            CiJob.ARTIFACT_UI,
            (*make, "test-e2e-artifacts"),
            CountKind.PYTEST,
        ),
        CiCommand(CiJob.RETENTION, (*make, "test-retention"), CountKind.PYTEST),
        CiCommand(
            CiJob.GENERATED_DRIFT,
            (*make, "check-generated-contracts"),
            CountKind.PYTEST,
        ),
        CiCommand(CiJob.SBOM, (*static, "sbom", str(root)), CountKind.CHECKS),
        CiCommand(
            CiJob.SECRET_SCAN,
            (*static, "secret-scan", str(root)),
            CountKind.CHECKS,
        ),
        CiCommand(CiJob.DRY_LAB, (*make, "test-dry-lab"), CountKind.PYTEST),
        CiCommand(CiJob.PRODUCT_UI, (*make, "test-product-ui"), CountKind.PYTEST),
        CiCommand(
            CiJob.PROVIDER_RUNTIME, (*make, "test-provider-runtime"), CountKind.PYTEST
        ),
        CiCommand(
            CiJob.SECURITY,
            (python, "-m", "tools.platform_policy.security_gate"),
            CountKind.PYTEST,
        ),
        CiCommand(
            CiJob.RECOVERY,
            (*pytest, "tests/platform/test_g005_recovery_contract.py"),
            CountKind.PYTEST,
        ),
        CiCommand(
            CiJob.PERFORMANCE,
            (*pytest, "tests/platform/test_deployment_contract.py"),
            CountKind.PYTEST,
        ),
        CiCommand(
            CiJob.RELEASE,
            (*pytest, "tests/platform/test_release_contract.py"),
            CountKind.PYTEST,
        ),
    )


def _analyzer_inventory(root: Path) -> tuple[Path, ...]:
    """Return stable existing Python files supplied to both static analyzers."""
    inventory: list[Path] = []
    for relative_path in RELEASE_PYTHON_PATHS:
        path = root / relative_path
        if path.is_file():
            inventory.append(path)
        elif path.is_dir():
            inventory.extend(
                candidate for candidate in path.rglob("*.py") if candidate.is_file()
            )
    return tuple(sorted(set(inventory)))


def configured_ci_generation_manifest_authority() -> CiGenerationManifestAuthority:
    """Load the externally configured manifest authority without creating trust."""
    reference = os.environ.get(CI_AUTHORITY_FACTORY_ENV)
    if not reference or reference.count(":") != 1:
        raise ValueError(CI_AUTHORITY_REQUIRED_ERROR)
    module_name, attribute_name = reference.split(":", maxsplit=1)
    if not module_name or not attribute_name:
        raise ValueError(CI_AUTHORITY_REQUIRED_ERROR)
    try:
        authority = cast(
            "object",
            getattr(importlib.import_module(module_name), attribute_name),
        )
    except (AttributeError, ImportError) as error:
        raise ValueError(CI_AUTHORITY_REQUIRED_ERROR) from error
    if not isinstance(authority, CiGenerationManifestAuthority):
        raise TypeError(CI_AUTHORITY_REQUIRED_ERROR)
    return authority


def main(authority: CiGenerationManifestAuthority | None = None) -> int:
    """Run the local CI contract with an externally configured authority."""
    root = Path(sys.argv[1]).resolve() if len(sys.argv) == CLI_ARG_COUNT else Path.cwd()
    records = run_ci(
        root,
        authority
        if authority is not None
        else configured_ci_generation_manifest_authority(),
    )
    executed = sum(item.executed_count for item in records)
    _ = sys.stdout.write(f"CI_EXECUTED={executed}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
