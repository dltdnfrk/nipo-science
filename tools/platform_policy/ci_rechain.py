"""Re-chain the checked-in CI control catalog after contract edits.

The checked-in catalog binds every CI job's argv, analyzer inventory, and
self-referential root hashes to the platform sources that define them. When
those sources change -- jobs added to or removed from the CiJob vocabulary,
argv edits with an unchanged job count, analyzer inventory growth, or a
TRUSTED_REQUIREMENT_IDS replacement -- this tool derives the fresh catalog
from the edited sources, regenerates the unverified requirement set, and
atomically rewrites .ci/ci-contract.json only after the candidate bytes pass
the checked-in catalog gate itself.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, TypeGuard, cast

from . import ci_contract
from .ci_contract import (
    CiCatalogJob,
    CiControlCatalog,
    CiJob,
    CountKindValue,
    EvidenceIntegrityError,
    ci_catalog_root,
    ci_catalog_source_root,
)
from .ci_runner import (
    PARSER_VERSION,
    CiCommand,
    CountKind,
    ci_commands,
    inventory_root_sha256,
    portable_ci_argv,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

COMMAND_SET_ERROR: Final = "CI command set does not match the CI job vocabulary"
DUPLICATE_KEY_ERROR: Final = "duplicate JSON key"
INVALID_CATALOG_ERROR: Final = "checked-in CI control catalog is invalid"
METADATA_DOCUMENT_ERROR: Final = "CI re-chain metadata document is invalid"
MISSING_JOB_METADATA_ERROR: Final = "CI catalog job metadata is missing"
RECHAIN_INVALID_ERROR: Final = "re-chained CI control catalog is invalid"
REQUIREMENTS_UNAVAILABLE_ERROR: Final = "CI requirements authority is unavailable"
UNCONSUMABLE_METADATA_ERROR: Final = "CI job metadata was supplied but not needed"

_DOCUMENT_KEYS: Final = frozenset({"catalog", "evidence", "generated_contracts"})
_METADATA_KEYS: Final = frozenset(
    {"blockers", "category", "control_ids", "environment_profile", "prerequisites"}
)
_MAX_CLI_ARGS: Final = 3
_MIN_CLI_ARGS: Final = 2
_USAGE: Final = (
    "usage: python -m tools.platform_policy.ci_rechain [root] [new-job-metadata.json]\n"
)


@dataclass(frozen=True, slots=True)
class RechainJobMetadata:
    """Control metadata for one catalog job not derivable from commands."""

    control_ids: tuple[str, ...]
    category: str
    environment_profile: str = "local-ci"
    prerequisites: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RechainResult:
    """One rebuilt catalog plus the drift summary that produced it."""

    catalog: CiControlCatalog
    content: bytes
    added_jobs: tuple[str, ...]
    removed_jobs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _PriorCatalog:
    """Tolerantly parsed durable fields of one checked-in catalog."""

    source_identity: str
    security_catalog_id: str
    job_metadata: dict[CiJob, RechainJobMetadata]
    removed_jobs: tuple[str, ...]
    evidence: object
    generated_contracts: object


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON object names before tolerant parsing."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(DUPLICATE_KEY_ERROR)
        result[key] = value
    return result


def _is_string_list(value: object) -> TypeGuard[list[str]]:
    """Narrow one decoded JSON value to a list of strings."""
    return isinstance(value, list) and all(
        isinstance(item, str) for item in cast("list[object]", value)
    )


def _prior_job_metadata(raw_job: dict[str, object]) -> RechainJobMetadata:
    """Extract durable control metadata from one surviving catalog job."""
    try:
        parsed = CiCatalogJob.model_validate(raw_job)
    except (TypeError, ValueError):
        raise EvidenceIntegrityError(None, INVALID_CATALOG_ERROR) from None
    return RechainJobMetadata(
        control_ids=parsed.control_ids,
        category=parsed.category,
        environment_profile=parsed.environment_profile,
        prerequisites=parsed.prerequisites,
        blockers=parsed.blockers,
    )


def _prior_jobs(
    raw_jobs: list[object],
) -> tuple[dict[CiJob, RechainJobMetadata], tuple[str, ...]]:
    """Extract surviving job metadata, collecting retired job names."""
    job_metadata: dict[CiJob, RechainJobMetadata] = {}
    removed: list[str] = []
    for raw_job in raw_jobs:
        if not isinstance(raw_job, dict):
            raise EvidenceIntegrityError(None, INVALID_CATALOG_ERROR)
        job_entry = cast("dict[str, object]", raw_job)
        job_name = job_entry.get("job")
        if not isinstance(job_name, str):
            raise EvidenceIntegrityError(None, INVALID_CATALOG_ERROR)
        try:
            job = CiJob(job_name)
        except ValueError:
            removed.append(job_name)
            continue
        if job in job_metadata:
            raise EvidenceIntegrityError(None, INVALID_CATALOG_ERROR)
        job_metadata[job] = _prior_job_metadata(job_entry)
    return job_metadata, tuple(sorted(removed))


def _load_prior_catalog(path: Path) -> _PriorCatalog:
    """Parse durable catalog fields, tolerating the drift re-chain repairs."""
    try:
        decoded = cast(
            "object",
            json.loads(path.read_bytes(), object_pairs_hook=_reject_duplicate_keys),
        )
    except (OSError, TypeError, ValueError):
        raise EvidenceIntegrityError(None, INVALID_CATALOG_ERROR) from None
    if not isinstance(decoded, dict):
        raise EvidenceIntegrityError(None, INVALID_CATALOG_ERROR)
    document = cast("dict[str, object]", decoded)
    if "catalog" not in document or set(document) - _DOCUMENT_KEYS:
        raise EvidenceIntegrityError(None, INVALID_CATALOG_ERROR)
    catalog_value = document["catalog"]
    if not isinstance(catalog_value, dict):
        raise EvidenceIntegrityError(None, INVALID_CATALOG_ERROR)
    catalog = cast("dict[str, object]", catalog_value)
    source_identity = catalog.get("source_identity")
    security_catalog_id = catalog.get("security_catalog_id")
    raw_jobs = catalog.get("jobs")
    if (
        catalog.get("version") != 1
        or not isinstance(source_identity, str)
        or not source_identity
        or not isinstance(security_catalog_id, str)
        or not security_catalog_id
        or not isinstance(raw_jobs, list)
    ):
        raise EvidenceIntegrityError(None, INVALID_CATALOG_ERROR)
    job_metadata, removed = _prior_jobs(cast("list[object]", raw_jobs))
    return _PriorCatalog(
        source_identity=source_identity,
        security_catalog_id=security_catalog_id,
        job_metadata=job_metadata,
        removed_jobs=removed,
        evidence=document.get("evidence"),
        generated_contracts=document.get("generated_contracts"),
    )


def _catalog_job(
    command: CiCommand, root: Path, metadata: RechainJobMetadata
) -> CiCatalogJob:
    """Project one command into its catalog contract with a fresh inventory."""
    analyzer_root = (
        inventory_root_sha256(command.inventory, root)
        if command.count_kind is CountKind.ANALYZER_INVENTORY
        else None
    )
    return CiCatalogJob(
        job=command.job,
        argv=portable_ci_argv(command, root),
        count_kind=cast("CountKindValue", str(command.count_kind)),
        parser_version=PARSER_VERSION,
        analyzer_inventory_root_sha256=analyzer_root,
        analyzer_inventory_count=(
            len(command.inventory) if analyzer_root is not None else None
        ),
        category=metadata.category,
        environment_profile=metadata.environment_profile,
        control_ids=metadata.control_ids,
        requirement_ids=(),
        prerequisites=metadata.prerequisites,
        blockers=metadata.blockers,
    )


def _build_catalog_jobs(
    root: Path,
    prior: _PriorCatalog,
    supplied: Mapping[CiJob, RechainJobMetadata],
) -> tuple[tuple[CiCatalogJob, ...], tuple[str, ...]]:
    """Project every current command, adding and removing jobs as edited."""
    commands = ci_commands(root)
    if len(commands) != len(CiJob) or {item.job for item in commands} != set(CiJob):
        raise EvidenceIntegrityError(None, COMMAND_SET_ERROR)
    metadata = dict(prior.job_metadata)
    remaining = dict(supplied)
    jobs: list[CiCatalogJob] = []
    added: list[str] = []
    missing: list[str] = []
    for command in commands:
        job_metadata = metadata.pop(command.job, None)
        if job_metadata is None:
            job_metadata = remaining.pop(command.job, None)
            if job_metadata is None:
                missing.append(str(command.job))
                continue
            added.append(str(command.job))
        jobs.append(_catalog_job(command, root, job_metadata))
    if missing:
        msg = f"{MISSING_JOB_METADATA_ERROR}: {', '.join(sorted(missing))}"
        raise EvidenceIntegrityError(None, msg)
    if remaining:
        unconsumable = sorted(str(job) for job in remaining)
        msg = f"{UNCONSUMABLE_METADATA_ERROR}: {', '.join(unconsumable)}"
        raise EvidenceIntegrityError(None, msg)
    return tuple(jobs), tuple(sorted(added))


def _build_catalog(
    root: Path,
    prior: _PriorCatalog,
    supplied: Mapping[CiJob, RechainJobMetadata],
) -> tuple[CiControlCatalog, tuple[str, ...]]:
    """Derive the fresh catalog and recompute both self-referential roots."""
    jobs, added = _build_catalog_jobs(root, prior, supplied)
    requirements = root / "docs" / "requirements" / "requirements.yaml"
    try:
        requirements_sha256 = hashlib.sha256(requirements.read_bytes()).hexdigest()
    except OSError:
        raise EvidenceIntegrityError(None, REQUIREMENTS_UNAVAILABLE_ERROR) from None
    provisional = CiControlCatalog.model_construct(
        version=1,
        source_identity=prior.source_identity,
        requirements_sha256=requirements_sha256,
        source_root_sha256="0" * 64,
        catalog_root_sha256="0" * 64,
        security_catalog_id=prior.security_catalog_id,
        jobs=jobs,
        requirement_case_bindings=(),
        unverified_requirement_ids=tuple(sorted(ci_contract.TRUSTED_REQUIREMENT_IDS)),
    )
    with_source = provisional.model_copy(
        update={"source_root_sha256": ci_catalog_source_root(provisional)}
    )
    complete = with_source.model_copy(
        update={"catalog_root_sha256": ci_catalog_root(with_source)}
    )
    try:
        catalog = CiControlCatalog.model_validate(complete.model_dump())
    except (TypeError, ValueError):
        raise EvidenceIntegrityError(None, RECHAIN_INVALID_ERROR) from None
    return catalog, added


def _serialize_document(catalog: CiControlCatalog, prior: _PriorCatalog) -> bytes:
    """Serialize the catalog with its preserved envelope keys canonically."""
    document: dict[str, object] = {"catalog": catalog.model_dump(mode="json")}
    if prior.evidence is not None:
        document["evidence"] = prior.evidence
    if prior.generated_contracts is not None:
        document["generated_contracts"] = prior.generated_contracts
    return (json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n").encode()


def build_rechained_catalog(
    root: Path, *, new_job_metadata: Mapping[CiJob, RechainJobMetadata] | None = None
) -> RechainResult:
    """Rebuild the checked-in catalog in memory without writing it."""
    prior = _load_prior_catalog(root / ".ci" / "ci-contract.json")
    catalog, added = _build_catalog(root, prior, new_job_metadata or {})
    return RechainResult(
        catalog=catalog,
        content=_serialize_document(catalog, prior),
        added_jobs=added,
        removed_jobs=prior.removed_jobs,
    )


def _fsync_directory(directory: Path) -> None:
    """Order the atomic rename durably by syncing the containing directory."""
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def rechain_checked_in_catalog(
    root: Path, *, new_job_metadata: Mapping[CiJob, RechainJobMetadata] | None = None
) -> RechainResult:
    """Self-check and atomically rewrite the checked-in CI control catalog."""
    result = build_rechained_catalog(root, new_job_metadata=new_job_metadata)
    catalog = root / ".ci" / "ci-contract.json"
    temporary = root / ".ci" / "ci-contract.json.rechain-tmp"
    created = False
    published = False
    try:
        with temporary.open("xb") as stream:
            created = True
            _ = stream.write(result.content)
            stream.flush()
            os.fsync(stream.fileno())
        _ = ci_contract.load_checked_in_ci_catalog(temporary)
        _ = temporary.replace(catalog)
        published = True
        _fsync_directory(root / ".ci")
    finally:
        if created and not published:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
    return result


def _parse_metadata_fields(fields: object) -> RechainJobMetadata:
    """Validate one caller-supplied job metadata record."""
    if not isinstance(fields, dict):
        raise TypeError(METADATA_DOCUMENT_ERROR)
    record = cast("dict[str, object]", fields)
    if set(record) - _METADATA_KEYS:
        raise ValueError(METADATA_DOCUMENT_ERROR)
    control_ids = record.get("control_ids")
    category = record.get("category")
    environment_profile = record.get("environment_profile", "local-ci")
    prerequisites = record.get("prerequisites", [])
    blockers = record.get("blockers", [])
    if (
        not _is_string_list(control_ids)
        or not control_ids
        or not isinstance(category, str)
        or not category
        or not isinstance(environment_profile, str)
        or not environment_profile
        or not _is_string_list(prerequisites)
        or not _is_string_list(blockers)
    ):
        raise ValueError(METADATA_DOCUMENT_ERROR)
    return RechainJobMetadata(
        control_ids=tuple(control_ids),
        category=category,
        environment_profile=environment_profile,
        prerequisites=tuple(prerequisites),
        blockers=tuple(blockers),
    )


def _load_metadata_file(path: Path) -> dict[CiJob, RechainJobMetadata]:
    """Parse caller-supplied control metadata for jobs new to the catalog."""
    try:
        decoded = cast(
            "object",
            json.loads(path.read_bytes(), object_pairs_hook=_reject_duplicate_keys),
        )
    except (OSError, TypeError, ValueError):
        raise ValueError(METADATA_DOCUMENT_ERROR) from None
    if not isinstance(decoded, dict):
        raise TypeError(METADATA_DOCUMENT_ERROR)
    metadata: dict[CiJob, RechainJobMetadata] = {}
    for name, fields in cast("dict[str, object]", decoded).items():
        try:
            job = CiJob(name)
        except ValueError:
            raise ValueError(METADATA_DOCUMENT_ERROR) from None
        metadata[job] = _parse_metadata_fields(fields)
    return metadata


def main() -> int:
    """Re-chain the checked-in catalog for one checkout root."""
    if len(sys.argv) > _MAX_CLI_ARGS:
        _ = sys.stderr.write(_USAGE)
        return 2
    root = Path(sys.argv[1]).resolve() if len(sys.argv) >= _MIN_CLI_ARGS else Path.cwd()
    try:
        metadata = (
            _load_metadata_file(Path(sys.argv[2]))
            if len(sys.argv) == _MAX_CLI_ARGS
            else None
        )
        result = rechain_checked_in_catalog(root, new_job_metadata=metadata)
    except (EvidenceIntegrityError, OSError, TypeError, ValueError) as error:
        _ = sys.stderr.write(f"CI re-chain failed: {error}\n")
        return 1
    added = ",".join(result.added_jobs) or "-"
    removed = ",".join(result.removed_jobs) or "-"
    _ = sys.stdout.write(
        f"CI_RECHAINED jobs={len(result.catalog.jobs)} "
        f"added={added} removed={removed}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
