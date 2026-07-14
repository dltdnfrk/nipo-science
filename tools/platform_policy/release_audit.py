"""Read-only frozen-input release audit and canonical receipt CLI."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, TypeGuard, cast

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

from . import ci_contract
from .release_contract import (
    NFR_REQUIREMENT_IDS,
    REQUIRED_EXTERNAL_CONTROL_IDS,
    CleanupEvidence,
    ExternalEvidence,
    FrozenAuthority,
    ManualQaEvidence,
    ReleaseContractError,
    ReleaseReceipt,
    SiblingRoots,
    canonical_bytes,
    canonical_sha256,
    durable_goal_ids_from_document,
    load_json_object_bytes,
    requirement_ids_from_document,
    sha256_bytes,
    sibling_tree_sha256,
    source_tree_sha256,
)

RUN_SUBPROCESS: Final = subprocess.run
GIT_EXECUTABLE: Final = shutil.which("git")
GIT_TIMEOUT_SECONDS: Final = 10
_SESSION_ID: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


@dataclass(frozen=True, slots=True)
class ReleaseAuditRequest:
    """Frozen input paths and identifiers for one release audit."""

    workspace: Path
    release_id: str
    run_id: str
    attempt_id: str
    requirements_path: Path | None = None


@dataclass(frozen=True, slots=True)
class _AuditPaths:
    workspace: Path
    requirements: Path
    goals: Path
    drylab: Path
    ontologylab: Path
    session_id: str


@dataclass(frozen=True, slots=True)
class _AuthorityCapture:
    requirements: bytes
    goals: bytes
    catalog: bytes
    optional: dict[str, bytes | None]

    def documents(self) -> dict[str, bytes | None]:
        """Return every captured authority under its canonical audit label."""
        return {
            "requirements": self.requirements,
            "goals": self.goals,
            "command catalog": self.catalog,
            **self.optional,
        }


@dataclass(frozen=True, slots=True)
class _AuditSemantics:
    requirements: tuple[str, ...]
    goals_state_revision: int
    nonterminal_goals: tuple[str, ...]
    catalog: ci_contract.CiControlCatalog


@dataclass(frozen=True, slots=True)
class _AuditState:
    request: ReleaseAuditRequest
    paths: _AuditPaths
    capture: _AuthorityCapture
    semantics: _AuditSemantics
    verified_revision: str
    dirty: bool
    topology: tuple[str, str, str]


def _revision(workspace: Path) -> str:
    """Read a revision using a fixed argv, never caller-provided shell text."""
    if GIT_EXECUTABLE is None:
        return "unverified-no-git-revision"
    try:
        result = RUN_SUBPROCESS(
            (GIT_EXECUTABLE, "rev-parse", "HEAD"),
            check=False,
            capture_output=True,
            cwd=workspace,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return "unverified-no-git-revision"
    revision = result.stdout.strip()
    return (
        revision
        if result.returncode == 0 and revision
        else "unverified-no-git-revision"
    )


def _dirty(workspace: Path) -> bool:
    if GIT_EXECUTABLE is None:
        return True
    try:
        result = RUN_SUBPROCESS(
            (GIT_EXECUTABLE, "status", "--porcelain=v1"),
            check=False,
            capture_output=True,
            cwd=workspace,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return True
    return result.returncode != 0 or bool(result.stdout.strip())


type _EntryIdentity = tuple[int, int, int, int, int, int, int]
type _DirectoryEntry = tuple[int, str, _EntryIdentity]


def _entry_identity(metadata: os.stat_result) -> _EntryIdentity:
    return (
        metadata.st_mode,
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def _authority_components(path: Path, label: str) -> tuple[str, ...]:
    if not path.is_absolute():
        message = f"{label} authority path is not absolute"
        raise ReleaseContractError(message)
    components = path.parts[1:]
    if not components:
        message = f"{label} authority is not a file"
        raise ReleaseContractError(message)
    return components


def _require_directory_entry(entry: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(entry.st_mode):
        message = f"{label} authority has unsafe ancestor"
        raise ReleaseContractError(message)


def _require_pinned_directory(
    child_fd: int,
    entry: os.stat_result,
    label: str,
) -> None:
    if _entry_identity(os.fstat(child_fd)) != _entry_identity(entry):
        os.close(child_fd)
        message = f"{label} authority ancestor changed while opening"
        raise ReleaseContractError(message)


def _open_authority_chain(
    path: Path, label: str
) -> tuple[list[int], list[_DirectoryEntry], str]:
    components = _authority_components(path, label)
    descriptors = [os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    entries: list[_DirectoryEntry] = []
    try:
        for component in components[:-1]:
            parent_fd = descriptors[-1]
            entry = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            _require_directory_entry(entry, label)
            child_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            _require_pinned_directory(child_fd, entry, label)
            entries.append((parent_fd, component, _entry_identity(entry)))
            descriptors.append(child_fd)
        return descriptors, entries, components[-1]
    except BaseException:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def _read_authority_entry(parent_fd: int, name: str, label: str) -> bytes:
    entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1:
        message = f"{label} authority is not a unique regular file"
        raise ReleaseContractError(message)
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        pinned = os.fstat(descriptor)
        if _entry_identity(pinned) != _entry_identity(entry):
            message = f"{label} authority changed while opening"
            raise ReleaseContractError(message)
        chunks: list[bytes] = []
        while block := os.read(descriptor, 65536):
            chunks.append(block)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        after = os.fstat(descriptor)
        if _entry_identity(current) != _entry_identity(entry) or _entry_identity(
            after
        ) != _entry_identity(pinned):
            message = f"{label} authority changed while reading"
            raise ReleaseContractError(message)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _verify_authority_chain(entries: list[_DirectoryEntry], label: str) -> None:
    for parent_fd, name, expected in entries:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if _entry_identity(current) != expected:
            message = f"{label} authority ancestor changed while reading"
            raise ReleaseContractError(message)


def _regular_bytes(path: Path, label: str, *, required: bool) -> bytes | None:
    """Read a unique authority through a no-follow descriptor walk from root."""
    descriptors: list[int] = []
    content: bytes | None = None
    try:
        descriptors, entries, name = _open_authority_chain(path, label)
        content = _read_authority_entry(descriptors[-1], name, label)
        _verify_authority_chain(entries, label)
    except FileNotFoundError:
        if required:
            message = f"unavailable {label} authority"
            raise ReleaseContractError(message) from None
    except OSError as exc:
        message = f"unreadable {label} authority"
        raise ReleaseContractError(message) from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    return content


def _goals_state_revision(goals_path: Path) -> int:
    content = _regular_bytes(goals_path, "goals", required=True)
    if content is None:
        message = "durable goals authority is unavailable"
        raise ReleaseContractError(message)
    state_revision = load_json_object_bytes(content, "goals").get("state_revision")
    if isinstance(state_revision, bool) or not isinstance(state_revision, int):
        msg = "durable goals state revision must be an integer"
        raise TypeError(msg)
    if state_revision < 0:
        msg = "durable goals state revision cannot be negative"
        raise ValueError(msg)
    return state_revision


def _trusted_session_id() -> str:
    session_id = os.environ.get("GJC_SESSION_ID")
    if session_id is None or _SESSION_ID.fullmatch(session_id) is None:
        msg = "GJC_SESSION_ID must be a valid trusted session identifier"
        raise ReleaseContractError(msg)
    return session_id


def _active_goals_path(workspace: Path) -> Path:
    """Derive the supervisor-selected session authority without alias resolution."""
    session_id = _trusted_session_id()
    session_root = workspace.parent / ".gjc" / f"_session-{session_id}"
    for directory in (
        workspace.parent / ".gjc",
        session_root,
        session_root / "ultragoal",
    ):
        try:
            metadata = directory.lstat()
        except OSError as exc:
            msg = "active session authority is unavailable"
            raise ReleaseContractError(msg) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            msg = "active session authority is not canonical"
            raise ReleaseContractError(msg)
    return session_root / "ultragoal" / "goals.json"


def _canonical_authority_paths(workspace: Path) -> dict[str, Path]:
    return {
        "command catalog": workspace / ".ci/ci-contract.json",
        "dependency": workspace / "uv.lock",
        "fixture": workspace / "artifacts/ulw-g006/fixture.json",
        "toolchain": workspace / "pyproject.toml",
        "revision": workspace / "artifacts/ulw-g006/revision-anchor.json",
        "external anchor": workspace / "artifacts/ulw-g006/external-anchor.json",
    }


def _authority_inventory(
    optional: Mapping[str, bytes | None], verified_revision: str, dirty: bool
) -> tuple[str, ...]:
    inventory = [
        f"absent-authority:{name.replace(' ', '-')}"
        for name, value in optional.items()
        if value is None
    ]
    if dirty:
        inventory.append("dirty-source")
    if verified_revision == "unverified-no-git-revision":
        inventory.append("unverified-revision")
    return tuple(sorted(inventory))


def _exact_missing_inventory(
    *,
    ci_job_ids: tuple[str, ...],
    requirements: tuple[str, ...],
    goals: tuple[str, ...],
    authority_inventory: tuple[str, ...],
) -> tuple[str, ...]:
    """Name every unavailable proof without umbrella claims or invented evidence."""
    return tuple(
        sorted(
            {
                *(f"ci-job:{job_id}" for job_id in ci_job_ids),
                *REQUIRED_EXTERNAL_CONTROL_IDS,
                *(
                    f"nfr-observation:{requirement_id}"
                    for requirement_id in NFR_REQUIREMENT_IDS
                ),
                *(
                    f"normative-requirement:{requirement_id}"
                    for requirement_id in requirements
                ),
                *(f"durable-goal:{goal_id}" for goal_id in goals),
                *authority_inventory,
                "cleanup",
                "dual-visual-review",
                "independent-code-review",
                "manual-qa",
            }
        )
    )


def _audit_paths(request: ReleaseAuditRequest) -> _AuditPaths:
    workspace = request.workspace
    if (
        not workspace.is_absolute()
        or workspace.name != "science-workbench"
        or workspace.is_symlink()
        or not workspace.is_dir()
    ):
        message = "workspace must be the canonical science-workbench root"
        raise ValueError(message)
    requirements = request.requirements_path or (
        workspace / "docs/requirements/requirements.yaml"
    )
    if requirements != workspace / "docs/requirements/requirements.yaml":
        message = "requirements path must be the canonical workspace authority"
        raise ValueError(message)
    drylab = workspace.parent / "drylab"
    ontologylab = workspace.parent / "ontologylab"
    if any(path.is_symlink() or not path.is_dir() for path in (drylab, ontologylab)):
        message = "sibling root is not canonical"
        raise ReleaseContractError(message)
    return _AuditPaths(
        workspace=workspace,
        requirements=requirements,
        goals=_active_goals_path(workspace),
        drylab=drylab,
        ontologylab=ontologylab,
        session_id=_trusted_session_id(),
    )


def _required_authority(path: Path, label: str) -> bytes:
    content = _regular_bytes(path, label, required=True)
    if content is None:
        message = f"required {label} authority is unavailable"
        raise ReleaseContractError(message)
    return content


def _capture_authorities(
    paths: _AuditPaths, authorities: Mapping[str, Path]
) -> _AuthorityCapture:
    return _AuthorityCapture(
        requirements=_required_authority(paths.requirements, "requirements"),
        goals=_required_authority(paths.goals, "goals"),
        catalog=_required_authority(
            authorities["command catalog"],
            "command catalog",
        ),
        optional={
            name: _regular_bytes(path, name, required=False)
            for name, path in authorities.items()
            if name != "command catalog"
        },
    )


def _parse_audit_semantics(capture: _AuthorityCapture) -> _AuditSemantics:
    requirements_document = load_json_object_bytes(capture.requirements, "requirements")
    goals_document = load_json_object_bytes(capture.goals, "goals")
    catalog_document = load_json_object_bytes(capture.catalog, "command catalog")
    requirements = requirement_ids_from_document(requirements_document)
    _ = durable_goal_ids_from_document(goals_document)
    revision = goals_document.get("state_revision")
    if isinstance(revision, bool) or not isinstance(revision, int):
        message = "durable goals state revision must be an integer"
        raise ReleaseContractError(message)
    goals = goals_document.get("goals")
    if not isinstance(goals, list):
        message = "durable goals authority must contain a goal list"
        raise ReleaseContractError(message)
    nonterminal: list[str] = []
    for item in goals:
        if not isinstance(item, dict):
            continue
        goal_id = item.get("id")
        status = item.get("status")
        if (
            isinstance(goal_id, str)
            and isinstance(status, str)
            and status != "complete"
        ):
            nonterminal.append(goal_id)
    catalog_value = catalog_document.get("catalog")
    if not isinstance(catalog_value, dict):
        message = "command catalog wrapper is malformed"
        raise ReleaseContractError(message)
    return _AuditSemantics(
        requirements=requirements,
        goals_state_revision=revision,
        nonterminal_goals=tuple(sorted(nonterminal)),
        catalog=ci_contract.CiControlCatalog.model_validate(catalog_value),
    )


def _topology(paths: _AuditPaths) -> tuple[str, str, str]:
    return (
        source_tree_sha256(paths.workspace),
        sibling_tree_sha256(paths.drylab),
        sibling_tree_sha256(paths.ontologylab),
    )


def _require_capture_unchanged(
    paths: _AuditPaths,
    authorities: Mapping[str, Path],
    capture: _AuthorityCapture,
    topology: tuple[str, str, str],
) -> None:
    if (
        _capture_authorities(paths, authorities).documents() != capture.documents()
        or _topology(paths) != topology
    ):
        message = "stale release audit authority"
        raise ReleaseContractError(message)


def _receipt_from_state(state: _AuditState) -> ReleaseReceipt:
    capture = state.capture
    semantics = state.semantics
    optional = capture.optional
    science, drylab, ontologylab = state.topology
    revision = semantics.goals_state_revision
    return ReleaseReceipt(
        release_id=state.request.release_id,
        run_id=state.request.run_id,
        attempt_id=state.request.attempt_id,
        outcome="incomplete",
        authority=FrozenAuthority(
            verified_revision=state.verified_revision,
            source_tree_sha256=science,
            dirty=state.dirty,
            requirements_sha256=sha256_bytes(capture.requirements),
            goals_sha256=sha256_bytes(capture.goals),
            command_catalog_sha256=sha256_bytes(capture.catalog),
            dependency_sha256=(
                sha256_bytes(optional["dependency"])
                if optional["dependency"] is not None
                else None
            ),
            fixture_sha256=(
                sha256_bytes(optional["fixture"])
                if optional["fixture"] is not None
                else None
            ),
            toolchain_sha256=(
                sha256_bytes(optional["toolchain"])
                if optional["toolchain"] is not None
                else None
            ),
            revision_anchor_sha256=(
                sha256_bytes(optional["revision"])
                if optional["revision"] is not None
                else None
            ),
            goals_state_revision=revision,
            session_id=state.paths.session_id,
            lease_generation=str(revision),
        ),
        siblings=SiblingRoots(
            science_pre_sha256=science,
            science_post_sha256=science,
            drylab_pre_sha256=drylab,
            drylab_post_sha256=drylab,
            ontologylab_pre_sha256=ontologylab,
            ontologylab_post_sha256=ontologylab,
        ),
        controls=(),
        external_evidence=tuple(
            ExternalEvidence(control_id=control_id, available=False)
            for control_id in sorted(REQUIRED_EXTERNAL_CONTROL_IDS)
        ),
        cleanup=CleanupEvidence(complete=False),
        manual_qa=ManualQaEvidence(performed=False),
        external_anchor_sha256=(
            sha256_bytes(optional["external anchor"])
            if optional["external anchor"] is not None
            else None
        ),
        missing_or_failed_controls=_exact_missing_inventory(
            ci_job_ids=tuple(job.job.value for job in semantics.catalog.jobs),
            requirements=semantics.requirements,
            goals=semantics.nonterminal_goals,
            authority_inventory=_authority_inventory(
                optional,
                state.verified_revision,
                state.dirty,
            ),
        ),
    )


def _require_state_current(state: _AuditState, authorities: Mapping[str, Path]) -> None:
    _require_capture_unchanged(
        state.paths,
        authorities,
        state.capture,
        state.topology,
    )
    if (
        _trusted_session_id() != state.paths.session_id
        or _revision(state.paths.workspace) != state.verified_revision
        or _dirty(state.paths.workspace) != state.dirty
    ):
        message = "stale release audit authority"
        raise ReleaseContractError(message)


def build_incomplete_receipt(request: ReleaseAuditRequest) -> ReleaseReceipt:
    """Hash only supervisor-derived canonical authorities for an incomplete receipt."""
    paths = _audit_paths(request)
    authorities = _canonical_authority_paths(paths.workspace)
    topology = _topology(paths)
    capture = _capture_authorities(paths, authorities)
    semantics = _parse_audit_semantics(capture)
    state = _AuditState(
        request=request,
        paths=paths,
        capture=capture,
        semantics=semantics,
        verified_revision=_revision(paths.workspace),
        dirty=_dirty(paths.workspace),
        topology=topology,
    )
    _require_capture_unchanged(paths, authorities, capture, topology)
    receipt = _receipt_from_state(state)
    _require_state_current(state, authorities)
    return receipt


def receipt_document(receipt: ReleaseReceipt) -> dict[str, object]:
    """Return canonical receipt data plus its content checksum."""
    data: object = receipt.model_dump(mode="json", exclude_none=False)
    return {"receipt": data, "receipt_sha256": canonical_sha256(data)}


@dataclass(slots=True)
class _ArtifactManifestState:
    entries: dict[str, tuple[int, str]]
    seen_files: set[tuple[int, int]]
    seen_directories: set[tuple[int, int]]


def _read_artifact_file(
    directory_fd: int,
    name: str,
    expected: os.stat_result,
) -> bytes:
    """Read one unique artifact file through its containing directory."""
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=directory_fd,
    )
    try:
        before = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            before.st_nlink,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino) != (expected.st_dev, expected.st_ino)
        ):
            msg = "artifact file changed while opening"
            raise ValueError(msg)
        chunks: list[bytes] = []
        while block := os.read(descriptor, 65536):
            chunks.append(block)
        after = os.fstat(descriptor)
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_nlink,
        )
        if after_identity != before_identity:
            msg = "artifact file changed while reading"
            raise ValueError(msg)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _collect_artifact_manifest(
    directory_fd: int,
    parts: tuple[str, ...],
    excluded_direct_child: str,
    state: _ArtifactManifestState,
) -> None:
    """Collect stable artifact metadata through descriptor-relative traversal."""
    names = tuple(sorted(os.listdir(directory_fd)))
    for name in names:
        if not parts and name == excluded_direct_child:
            continue
        child_parts = (*parts, name)
        relative = "/".join(child_parts)
        metadata = os.stat(
            name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        mode = metadata.st_mode & 0o7777
        if stat.S_ISDIR(metadata.st_mode):
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in state.seen_directories:
                msg = "artifact topology contains aliased directory"
                raise ValueError(msg)
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
                    msg = "artifact directory changed while opening"
                    raise ValueError(msg)
                state.seen_directories.add(identity)
                state.entries[relative] = (mode, "directory")
                _collect_artifact_manifest(
                    child_fd,
                    child_parts,
                    excluded_direct_child,
                    state,
                )
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            msg = "artifact topology contains unsafe entry"
            raise ValueError(msg)
        identity = (metadata.st_dev, metadata.st_ino)
        if metadata.st_nlink != 1 or identity in state.seen_files:
            msg = "artifact topology contains aliased regular file"
            raise ValueError(msg)
        state.seen_files.add(identity)
        content = _read_artifact_file(directory_fd, name, metadata)
        state.entries[relative] = (mode, sha256_bytes(content))
    if tuple(sorted(os.listdir(directory_fd))) != names:
        msg = "artifact directory changed while reading"
        raise ValueError(msg)


def _artifact_manifest(
    root: Path, destination: Path | None
) -> dict[str, tuple[int, str]]:
    """Capture strict artifact topology, omitting only this new descriptor."""
    try:
        root_metadata = root.lstat()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        msg = "artifact root became unavailable"
        raise ValueError(msg) from exc
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        msg = "artifact root must be a canonical directory"
        raise ValueError(msg)
    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        msg = "artifact root became unavailable"
        raise ValueError(msg) from exc
    state = _ArtifactManifestState(
        entries={},
        seen_files=set(),
        seen_directories={(root_metadata.st_dev, root_metadata.st_ino)},
    )
    try:
        pinned = os.fstat(root_fd)
        if not stat.S_ISDIR(pinned.st_mode) or (pinned.st_dev, pinned.st_ino) != (
            root_metadata.st_dev,
            root_metadata.st_ino,
        ):
            msg = "artifact root changed while opening"
            raise ValueError(msg)
        _collect_artifact_manifest(
            root_fd,
            (),
            destination.name if destination is not None else "",
            state,
        )
    except OSError as exc:
        msg = "artifact topology changed or became unreadable"
        raise ValueError(msg) from exc
    finally:
        os.close(root_fd)
    return state.entries


def _verify_write_authority(receipt: ReleaseReceipt, artifact_root: Path) -> None:
    workspace = artifact_root.parents[1]
    drylab_path = workspace.parent / "drylab"
    ontologylab_path = workspace.parent / "ontologylab"
    if (
        not workspace.is_absolute()
        or workspace.name != "science-workbench"
        or workspace.is_symlink()
        or not workspace.is_dir()
        or any(
            path.is_symlink() or not path.is_dir()
            for path in (drylab_path, ontologylab_path)
        )
    ):
        msg = "artifact root must have canonical sibling topology"
        raise ValueError(msg)
    requirements_path = workspace / "docs/requirements/requirements.yaml"
    goals_path = _active_goals_path(workspace)
    authorities = _canonical_authority_paths(workspace)
    expected_hashes = {
        "requirements": receipt.authority.requirements_sha256,
        "goals": receipt.authority.goals_sha256,
        "command catalog": receipt.authority.command_catalog_sha256,
        "dependency": receipt.authority.dependency_sha256,
        "fixture": receipt.authority.fixture_sha256,
        "toolchain": receipt.authority.toolchain_sha256,
        "revision": receipt.authority.revision_anchor_sha256,
        "external anchor": receipt.external_anchor_sha256,
    }
    paths = {
        "requirements": requirements_path,
        "goals": goals_path,
        **authorities,
    }
    for name, path in paths.items():
        current = _regular_bytes(
            path, name, required=name in {"requirements", "goals", "command catalog"}
        )
        actual_hash = sha256_bytes(current) if current is not None else None
        if actual_hash != expected_hashes[name]:
            msg = f"stale {name} authority"
            raise ReleaseContractError(msg)
    if receipt.authority.session_id != _trusted_session_id():
        msg = "stale active session authority"
        raise ReleaseContractError(msg)
    if _goals_state_revision(goals_path) != receipt.authority.goals_state_revision:
        msg = "stale durable goals revision"
        raise ReleaseContractError(msg)
    if (
        _revision(workspace) != receipt.authority.verified_revision
        or _dirty(workspace) != receipt.authority.dirty
    ):
        msg = "stale revision authority"
        raise ReleaseContractError(msg)
    science = source_tree_sha256(workspace)
    drylab = sibling_tree_sha256(drylab_path)
    ontologylab = sibling_tree_sha256(ontologylab_path)
    if (
        science != receipt.authority.source_tree_sha256
        or science != receipt.siblings.science_pre_sha256
        or science != receipt.siblings.science_post_sha256
        or drylab != receipt.siblings.drylab_pre_sha256
        or drylab != receipt.siblings.drylab_post_sha256
        or ontologylab != receipt.siblings.ontologylab_pre_sha256
        or ontologylab != receipt.siblings.ontologylab_post_sha256
    ):
        msg = "stale receipt authority or sibling root"
        raise ReleaseContractError(msg)


def write_receipt(
    receipt: ReleaseReceipt, artifact_path: Path, artifact_root: Path
) -> Path:
    """Create a confined receipt while source and sibling roots remain current."""
    if (
        not artifact_root.is_absolute()
        or artifact_root.is_symlink()
        or artifact_root.name != "ulw-g006"
    ):
        msg = "artifact root must be science-workbench/artifacts/ulw-g006"
        raise ValueError(msg)
    workspace = artifact_root.parents[1]
    expected_root = workspace / "artifacts" / "ulw-g006"
    if artifact_root != expected_root or workspace.name != "science-workbench":
        msg = "artifact root must be science-workbench/artifacts/ulw-g006"
        raise ValueError(msg)
    destination = artifact_path
    try:
        relative = destination.relative_to(artifact_root)
    except ValueError as exc:
        msg = "artifact path must remain under artifact root"
        raise ValueError(msg) from exc
    if len(relative.parts) != 1:
        msg = "artifact path must be a direct child of artifact root"
        raise ValueError(msg)
    before = _artifact_manifest(artifact_root, destination)
    _verify_write_authority(receipt, artifact_root)
    artifact_fd = ci_contract.open_confined_directory(artifact_root, create=True)
    expected_bytes = canonical_bytes(receipt_document(receipt))
    try:
        ci_contract.write_confined_file(artifact_fd, relative.name, expected_bytes)
        _verify_written_receipt(artifact_fd, relative.name, expected_bytes)
        os.fsync(artifact_fd)
    finally:
        os.close(artifact_fd)
    _verify_write_authority(receipt, artifact_root)
    final_manifest = _artifact_manifest(artifact_root, None)
    expected_manifest = dict(before)
    destination_entry = final_manifest.get(relative.name)
    if destination_entry is None or destination_entry[1] != sha256_bytes(
        expected_bytes
    ):
        message = "receipt artifact changed during write"
        raise ReleaseContractError(message)
    expected_manifest[relative.name] = destination_entry
    if final_manifest != expected_manifest:
        message = "artifact topology changed during receipt write"
        raise ReleaseContractError(message)
    return destination


def _verify_written_receipt(directory_fd: int, name: str, expected: bytes) -> None:
    """Verify the created direct child before releasing the pinned directory."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        file_descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        msg = "receipt artifact changed during write"
        raise ReleaseContractError(msg) from exc
    try:
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            msg = "receipt artifact changed during write"
            raise ReleaseContractError(msg)
        with os.fdopen(file_descriptor, "rb", closefd=False) as receipt_file:
            actual = receipt_file.read(len(expected) + 1)
    except OSError as exc:
        msg = "receipt artifact changed during write"
        raise ReleaseContractError(msg) from exc
    finally:
        os.close(file_descriptor)
    if actual != expected:
        msg = "receipt artifact changed during write"
        raise ReleaseContractError(msg)


def _is_object_mapping(value: object) -> TypeGuard[Mapping[str, object]]:
    if not isinstance(value, dict):
        return False
    items = cast("dict[object, object]", value)
    return all(isinstance(key, str) for key in items)


def _required_string(arguments: Mapping[str, object], name: str) -> str:
    value = arguments.get(name)
    if not isinstance(value, str) or not value:
        msg = f"{name} must be a nonempty string"
        raise ValueError(msg)
    return value


def _optional_path(arguments: Mapping[str, object], name: str) -> Path | None:
    value = arguments.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        msg = f"{name} must be a path string"
        raise ValueError(msg)
    return Path(value)


def _required_path(arguments: Mapping[str, object], name: str) -> Path:
    value = _optional_path(arguments, name)
    if value is None:
        msg = f"{name} is required"
        raise ValueError(msg)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    """Write an incomplete receipt and return the non-success audit status."""
    parser = argparse.ArgumentParser(
        description="Emit fail-closed G006 release audit evidence"
    )
    _ = parser.add_argument("--workspace", required=True)
    _ = parser.add_argument("--artifact-root", required=True)
    _ = parser.add_argument("--artifact", required=True)
    _ = parser.add_argument("--release-id", required=True)
    _ = parser.add_argument("--run-id", required=True)
    _ = parser.add_argument("--attempt-id", required=True)
    _ = parser.add_argument("--requirements")
    parsed: object = vars(parser.parse_args(argv))
    if not _is_object_mapping(parsed):
        msg = "argument parser returned malformed values"
        raise ValueError(msg)
    receipt = build_incomplete_receipt(
        ReleaseAuditRequest(
            workspace=_required_path(parsed, "workspace"),
            release_id=_required_string(parsed, "release_id"),
            run_id=_required_string(parsed, "run_id"),
            attempt_id=_required_string(parsed, "attempt_id"),
            requirements_path=_optional_path(parsed, "requirements"),
        )
    )
    _ = write_receipt(
        receipt,
        _required_path(parsed, "artifact"),
        _required_path(parsed, "artifact_root"),
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
