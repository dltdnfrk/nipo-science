"""Behavioural tests for the local SQLite and blob Artifact store."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast
from uuid import UUID

import pytest
from services.api.artifacts.models import (
    ArtifactRecord,
    ArtifactScope,
    ArtifactVersion,
    SessionArtifactLink,
)
from services.api.artifacts.store_contract import (
    ArtifactCommitError,
    ArtifactStore,
    ArtifactStoreError,
    BlobIntegrityError,
    BlobWriteError,
    StoreOutcome,
)

from nipo_local.config import (
    DEFAULT_PROJECT_ID,
    LOCAL_ORG_ID,
    LOCAL_RUNTIME_ADAPTER_ID,
    LOCAL_RUNTIME_CONNECTION_ID,
    LOCAL_USER_ID,
    LocalPaths,
    resolve_paths,
)
from nipo_local.store import (
    ActionPlanRecord,
    ApprovalOutcome,
    ExecutionInputKind,
    ExecutionRecord,
    FindingStatus,
    LocalArtifactStore,
    PlanApprovalRecord,
    ProjectRecord,
    ReviewFindingRecord,
    ReviewRecord,
    ReviewRuleId,
    ReviewState,
    ReviewSubmission,
    ReviewVerdict,
    RunClaim,
    RunCompletion,
    RunOutputRecord,
    RunRecord,
    RunState,
    SessionRecord,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence

    type TransactCall = Callable[
        [LocalArtifactStore, Callable[[], StoreOutcome], StoreOutcome, StoreOutcome],
        StoreOutcome,
    ]

SECOND_PROJECT_ID: Final = UUID("01900000-0000-7000-8000-000000000009")
# A tenant this installation is not. Only ever written directly, to prove the
# reader filters on `org_id` rather than assuming a single tenant.
SECOND_ORG_ID: Final = UUID("01900000-0000-7000-8000-00000000000b")
SCOPE: Final = ArtifactScope(
    org_id=LOCAL_ORG_ID,
    project_id=DEFAULT_PROJECT_ID,
    requester_id=LOCAL_USER_ID,
)
SCOPE_B: Final = ArtifactScope(
    org_id=LOCAL_ORG_ID,
    project_id=SECOND_PROJECT_ID,
    requester_id=LOCAL_USER_ID,
)
CREATED_AT: Final = datetime(2026, 7, 13, 6, tzinfo=UTC)
LATER_AT: Final = datetime(2026, 7, 13, 7, tzinfo=UTC)
LATEST_AT: Final = datetime(2026, 7, 13, 8, tzinfo=UTC)
SHA_ENVIRONMENT: Final = "a" * 64
SHA_CODE: Final = "b" * 64
EXECUTION: Final = UUID("018f47a0-7b9c-7f01-8def-0123456789ab")
SESSION: Final = UUID("018f47a0-7b9c-7f02-8def-0123456789ab")
# The second Project needs its own execution identity: `executions` is keyed on
# (org_id, id), so one identifier cannot be claimed under two Projects.
EXECUTION_B: Final = UUID("018f47a0-7b9c-7f03-8def-0123456789ab")
SIMULATED_FAILURE: Final = "simulated local failure"

REPO_ROOT: Final = Path(__file__).resolve().parents[3]
APP_ROOT: Final = Path(__file__).resolve().parents[1]
TESTS_ROOT: Final = Path(__file__).resolve().parent
SYNC_DIRECTORY: Final = "nipo_local.store._sync_directory"
INSERT_VERSION: Final = "nipo_local.store.LocalArtifactStore._insert_version"

CHILD_PROGRAM: Final = """
import sys
sys.path.insert(0, sys.argv[1])
from test_store import child_commit
sys.stdout.write(child_commit(sys.argv[2:]))
"""

CHILD_SESSION_PROGRAM: Final = """
import sys
sys.path.insert(0, sys.argv[1])
from test_store import child_session
sys.stdout.write(child_session(sys.argv[2:]))
"""

CHILD_BLOCKER_PROGRAM: Final = """
import sys
sys.path.insert(0, sys.argv[1])
from test_store import child_block
sys.stdout.write(child_block(sys.argv[2:]))
"""

CHILD_CLAIM_PROGRAM: Final = """
import sys
sys.path.insert(0, sys.argv[1])
from test_store import child_claim
sys.stdout.write(child_claim(sys.argv[2:]))
"""

CHILD_INPUT_PROGRAM: Final = """
import sys
sys.path.insert(0, sys.argv[1])
from test_store import child_input
sys.stdout.write(child_input(sys.argv[2:]))
"""

OTHER_USER: Final = UUID("01900000-0000-7000-8000-00000000000a")
SCOPE_OTHER_USER: Final = ArtifactScope(
    org_id=LOCAL_ORG_ID,
    project_id=DEFAULT_PROJECT_ID,
    requester_id=OTHER_USER,
)
INTENT_SHA: Final = "e" * 64
EDITED_INTENT_SHA: Final = "f" * 64
INPUT_SHA: Final = "1" * 64
CLAIMED_AT: Final = datetime(2026, 7, 13, 6, 30, tzinfo=UTC)
EXPIRES_AT: Final = datetime(2026, 7, 13, 9, tzinfo=UTC)
IN_PROCESS: Final = "in_process"
PLAN_BASE: Final = 0x400
APPROVAL_BASE: Final = 0x500
RUN_BASE: Final = 0x600
EXECUTION_BASE: Final = 0x700
# Reserved for the plan, approval, and Run that own `EXECUTION`, which every
# test Version pins as its producing execution.
ATTACH_SEED_INDEX: Final = 7
# Reserved for the same chain in the second Project, which owns `EXECUTION_B`.
SECOND_SEED_INDEX: Final = 8
# Reserved for the chain whose execution pins the digests of the two canonical
# documents below, so real bytes can be recorded against a real execution.
INPUT_SEED_INDEX: Final = 9

# Stand-ins for the two documents whose digests an execution pins. Their exact
# bytes never matter to the store -- only that they hash to what was pinned --
# so they are short, obvious, and distinguishable from each other in a dump.
INTENT_DOCUMENT: Final = b'{"question":"does the 430 nm band persist?"}'
INPUT_DOCUMENT: Final = b'{"spectrum":[400,410,420,430]}'
INTENT_DOCUMENT_SHA: Final = hashlib.sha256(INTENT_DOCUMENT).hexdigest()
INPUT_DOCUMENT_SHA: Final = hashlib.sha256(INPUT_DOCUMENT).hexdigest()
FORGED_DOCUMENT: Final = b'{"question":"a question nobody approved"}'


def _uuid7(index: int) -> UUID:
    return UUID(f"018f47a0-7b9c-7{index:03x}-8def-0123456789ab")


# Rows no seeding helper ever creates. They are written directly so a chain can
# be broken in shapes `create_run` and `start_run` could never produce: a Run in
# a tenant this installation is not, an execution naming a Run that is not its
# own, and a Run identity nothing answers for.
FOREIGN_RUN: Final = _uuid7(RUN_BASE + 0x0E)
ABSENT_RUN: Final = _uuid7(RUN_BASE + 0x0F)
IMPOSTOR_EXECUTION: Final = _uuid7(EXECUTION_BASE + 0x0F)


@dataclass(frozen=True, slots=True)
class VersionSpec:
    scope: ArtifactScope
    artifact_id: UUID
    version_id: UUID
    payload: bytes
    version_no: int = 1
    inputs: tuple[UUID, ...] = ()
    # Committing requires this execution and its Run to resolve in the spec's
    # own Project, so a Version built for `SCOPE_B` must name that Project's
    # execution rather than the default one.
    execution_id: UUID = EXECUTION


@dataclass(frozen=True, slots=True)
class ChildCommit:
    root: Path
    artifact_index: int
    version_index: int
    payload: bytes
    base: int = 0
    timeout: float = 5.0

    def arguments(self) -> list[str]:
        return [
            str(self.root),
            str(self.artifact_index),
            str(self.version_index),
            self.payload.decode(),
            str(self.base),
            str(self.timeout),
        ]


@dataclass(frozen=True, slots=True)
class ChildSession:
    root: Path
    operation: str
    session_index: int
    version_index: int = 0
    timeout: float = 5.0

    def arguments(self) -> list[str]:
        return [
            str(self.root),
            self.operation,
            str(self.session_index),
            str(self.version_index),
            str(self.timeout),
        ]


@dataclass(slots=True)
class Recorder:
    tokens: list[str] = field(default_factory=list)
    flags: list[bool] = field(default_factory=list)


def _artifact(artifact_id: UUID, name: str = "spectrum") -> ArtifactRecord:
    return ArtifactRecord(
        id=artifact_id,
        org_id=LOCAL_ORG_ID,
        project_id=DEFAULT_PROJECT_ID,
        name=name,
        created_at=CREATED_AT,
    )


def _artifact_in(scope: ArtifactScope, artifact_id: UUID) -> ArtifactRecord:
    return ArtifactRecord(
        id=artifact_id,
        org_id=scope.org_id,
        project_id=scope.project_id,
        name="spectrum",
        created_at=CREATED_AT,
    )


def _build_version(spec: VersionSpec) -> ArtifactVersion:
    digest = hashlib.sha256(spec.payload).hexdigest()
    return ArtifactVersion(
        id=spec.version_id,
        org_id=spec.scope.org_id,
        project_id=spec.scope.project_id,
        artifact_id=spec.artifact_id,
        version_no=spec.version_no,
        object_key=LocalArtifactStore.object_key(spec.scope, digest),
        content_sha256=digest,
        size_bytes=len(spec.payload),
        media_type="application/json",
        producing_execution_id=spec.execution_id,
        environment_sha256=SHA_ENVIRONMENT,
        code_sha256=SHA_CODE,
        runtime_adapter_id=LOCAL_RUNTIME_ADAPTER_ID,
        runtime_connection_id=LOCAL_RUNTIME_CONNECTION_ID,
        skill_content_hashes=(SHA_ENVIRONMENT,),
        source_hashes=(SHA_CODE,),
        input_version_ids=spec.inputs,
        created_at=CREATED_AT,
    )


def _version(
    artifact_id: UUID,
    version_id: UUID,
    version_no: int,
    payload: bytes,
    inputs: tuple[UUID, ...] = (),
) -> ArtifactVersion:
    """Build a Version for the default Project without reordering its lineage."""
    return _build_version(
        VersionSpec(SCOPE, artifact_id, version_id, payload, version_no, inputs)
    )


def _blob_files(paths: LocalPaths) -> list[Path]:
    return sorted(item for item in paths.blobs.rglob("*") if item.is_file())


def _blob_path(paths: LocalPaths, payload: bytes) -> Path:
    digest = hashlib.sha256(payload).hexdigest()
    return paths.blobs / digest[:2] / digest[2:4] / digest


def _project(
    scope: ArtifactScope,
    name: str = "dry lab",
    created_at: datetime = CREATED_AT,
) -> ProjectRecord:
    return ProjectRecord(
        id=scope.project_id,
        org_id=scope.org_id,
        name=name,
        created_at=created_at,
    )


def _session_in(
    scope: ArtifactScope,
    session_id: UUID,
    title: str = "probe review",
    last_active_at: datetime = CREATED_AT,
) -> SessionRecord:
    return SessionRecord(
        id=session_id,
        org_id=scope.org_id,
        project_id=scope.project_id,
        title=title,
        created_at=CREATED_AT,
        last_active_at=last_active_at,
    )


def _session(
    session_id: UUID,
    title: str = "probe review",
    last_active_at: datetime = CREATED_AT,
) -> SessionRecord:
    return _session_in(SCOPE, session_id, title, last_active_at)


def _link(
    session_id: UUID,
    version_id: UUID,
    project_id: UUID = DEFAULT_PROJECT_ID,
) -> SessionArtifactLink:
    return SessionArtifactLink(
        org_id=LOCAL_ORG_ID,
        project_id=project_id,
        session_id=session_id,
        artifact_version_id=version_id,
        revision=1,
        created_at=CREATED_AT,
    )


def _child_outcome(
    store: LocalArtifactStore,
    operation: str,
    session_id: UUID,
    version_id: UUID,
) -> StoreOutcome:
    if operation == "create":
        return store.create_session(SCOPE, _session(session_id))
    if operation == "archive":
        return store.archive_session(SCOPE, session_id)
    if operation == "resume":
        return store.resume_session(SCOPE, session_id, LATER_AT)
    if operation == "attach":
        return store.attach_session(SCOPE, _link(session_id, version_id))
    return store.create_project(SCOPE, _project(SCOPE))


def child_session(arguments: Sequence[str]) -> str:
    """Run one lifecycle operation from a child process and report a token."""
    root, operation, session_index, version_index, timeout = arguments
    paths = resolve_paths(Path(root))
    try:
        with LocalArtifactStore(paths, timeout=float(timeout)) as store:
            return str(
                _child_outcome(
                    store,
                    operation,
                    _uuid7(int(session_index)),
                    _uuid7(int(version_index)),
                )
            )
    except (ArtifactStoreError, BlobIntegrityError) as error:
        return type(error).__name__


def _expected_plan_digest(
    scope: ArtifactScope,
    plan_id: UUID,
    intent_sha256: str,
) -> str:
    """Recompute the plan digest independently of the module under test.

    The schema string and the serialization are spelled out here on purpose:
    importing the producer's own constant would let a mutated digest satisfy
    its own assertion.
    """
    return hashlib.sha256(
        json.dumps(
            {
                "org_id": str(scope.org_id),
                "plan_id": str(plan_id),
                "project_id": str(scope.project_id),
                "requester_id": str(scope.requester_id),
                "research_intent_sha256": intent_sha256,
                "schema": "nipo.local.action-plan.v1",
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _plan(
    plan_id: UUID,
    intent_sha256: str = INTENT_SHA,
    scope: ArtifactScope = SCOPE,
    plan_sha256: str | None = None,
) -> ActionPlanRecord:
    return ActionPlanRecord(
        id=plan_id,
        org_id=scope.org_id,
        project_id=scope.project_id,
        requester_id=scope.requester_id,
        research_intent_sha256=intent_sha256,
        plan_sha256=(
            _expected_plan_digest(scope, plan_id, intent_sha256)
            if plan_sha256 is None
            else plan_sha256
        ),
        created_at=CREATED_AT,
    )


def _approval(
    approval_id: UUID,
    plan: ActionPlanRecord,
    approver_id: UUID = LOCAL_USER_ID,
    expires_at: datetime = EXPIRES_AT,
) -> PlanApprovalRecord:
    return PlanApprovalRecord(
        id=approval_id,
        org_id=plan.org_id,
        project_id=plan.project_id,
        plan_id=plan.id,
        approver_id=approver_id,
        research_intent_sha256=plan.research_intent_sha256,
        plan_sha256=plan.plan_sha256,
        granted_at=CREATED_AT,
        expires_at=expires_at,
    )


def _run(
    run_id: UUID,
    plan: ActionPlanRecord,
    approval: PlanApprovalRecord,
    session_id: UUID | None = None,
) -> RunRecord:
    return RunRecord(
        id=run_id,
        org_id=plan.org_id,
        project_id=plan.project_id,
        plan_id=plan.id,
        approval_id=approval.id,
        requester_id=plan.requester_id,
        session_id=session_id,
        state=RunState.QUEUED,
        research_intent_sha256=plan.research_intent_sha256,
        created_at=CREATED_AT,
        updated_at=CREATED_AT,
    )


def _execution(
    execution_id: UUID,
    run_id: UUID,
    intent_sha256: str = INTENT_SHA,
    scope: ArtifactScope = SCOPE,
) -> ExecutionRecord:
    return ExecutionRecord(
        id=execution_id,
        org_id=scope.org_id,
        project_id=scope.project_id,
        run_id=run_id,
        execution_isolation=IN_PROCESS,
        input_sha256=INPUT_SHA,
        research_intent_sha256=intent_sha256,
        code_sha256=SHA_CODE,
        environment_sha256=SHA_ENVIRONMENT,
        created_at=CREATED_AT,
    )


def _claim(
    run_id: UUID,
    approval_id: UUID,
    execution_id: UUID,
    intent_sha256: str = INTENT_SHA,
    started_at: datetime = CLAIMED_AT,
) -> RunClaim:
    return RunClaim(
        run_id=run_id,
        approval_id=approval_id,
        research_intent_sha256=intent_sha256,
        execution=_execution(execution_id, run_id, intent_sha256),
        started_at=started_at,
    )


def _completion(
    run_id: UUID,
    state: RunState,
    error_type: str | None = None,
    error_code: str | None = None,
) -> RunCompletion:
    return RunCompletion(
        run_id=run_id,
        state=state,
        finished_at=LATER_AT,
        error_type=error_type,
        error_code=error_code,
    )


def _seed_claimable(
    store: LocalArtifactStore,
    index: int,
    scope: ArtifactScope = SCOPE,
    session_id: UUID | None = None,
) -> tuple[ActionPlanRecord, PlanApprovalRecord, RunRecord]:
    """Create one plan, its single approval, and one queued Run."""
    plan = _plan(_uuid7(PLAN_BASE + index), INTENT_SHA, scope)
    approval = _approval(_uuid7(APPROVAL_BASE + index), plan)
    run = _run(_uuid7(RUN_BASE + index), plan, approval, session_id)
    assert store.create_action_plan(scope, plan) is StoreOutcome.CREATED
    assert store.grant_approval(scope, approval) is StoreOutcome.CREATED
    assert store.create_run(scope, run) is StoreOutcome.CREATED
    return plan, approval, run


def _seed_owning_execution(
    store: LocalArtifactStore,
    scope: ArtifactScope = SCOPE,
    execution_id: UUID = EXECUTION,
    index: int = ATTACH_SEED_INDEX,
    session_id: UUID | None = None,
) -> None:
    """Start one Run that really claims the execution a test Version pins.

    Committing a Version requires its producing execution and that execution's
    Run to resolve in this exact Project; attaching one requires the same plus
    the Run's own Session. A test that skipped this would be refused for
    provenance rather than for what it was written to prove.

    `session_id` defaults to None so the commit path is exercised against a Run
    that recorded no Session -- the state it must keep accepting. Attaching
    needs the binding and every attaching seed asks for it explicitly.
    """
    _, approval, run = _seed_claimable(store, index, scope, session_id)
    claim = RunClaim(
        run_id=run.id,
        approval_id=approval.id,
        research_intent_sha256=INTENT_SHA,
        execution=_execution(execution_id, run.id, INTENT_SHA, scope),
        started_at=CLAIMED_AT,
    )
    assert store.start_run(scope, claim) is ApprovalOutcome.CONSUMED


def child_claim(arguments: Sequence[str]) -> str:
    """Claim one approval from a child process and report a single token."""
    root, run_index, approval_index, execution_index, timeout = arguments
    paths = resolve_paths(Path(root))
    claim = _claim(
        _uuid7(int(run_index)),
        _uuid7(int(approval_index)),
        _uuid7(int(execution_index)),
    )
    try:
        with LocalArtifactStore(paths, timeout=float(timeout)) as store:
            return str(store.start_run(SCOPE, claim))
    except (ArtifactStoreError, BlobIntegrityError) as error:
        return type(error).__name__


def child_block(arguments: Sequence[str]) -> str:
    """Hold the database write lock until the parent closes this child's stdin."""
    paths = resolve_paths(Path(arguments[0]))
    connection = sqlite3.connect(paths.database, isolation_level=None)
    try:
        _ = connection.execute("BEGIN IMMEDIATE")
        _ = sys.stdout.write("locked\n")
        _ = sys.stdout.flush()
        _ = sys.stdin.read()
    finally:
        connection.close()
    return "released"


def child_commit(arguments: Sequence[str]) -> str:
    """Commit one Version from a child process and report a single token."""
    root, artifact_index, version_index, payload_text, base, timeout = arguments
    paths = resolve_paths(Path(root))
    payload = payload_text.encode()
    version = _version(
        _uuid7(int(artifact_index)),
        _uuid7(int(version_index)),
        int(base) + 1,
        payload,
    )
    try:
        with LocalArtifactStore(paths, timeout=float(timeout)) as store:
            return str(store.commit_version(SCOPE, int(base), version, payload))
    except (ArtifactStoreError, BlobIntegrityError) as error:
        return type(error).__name__


def _child_environment() -> dict[str, str]:
    return {
        **os.environ,
        "PYTHONPATH": os.pathsep.join([str(REPO_ROOT), str(APP_ROOT)]),
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _spawn(request: ChildCommit) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, "-c", CHILD_PROGRAM, str(TESTS_ROOT), *request.arguments()],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_child_environment(),
    )


def _collect(process: subprocess.Popen[str]) -> str:
    stdout, stderr = process.communicate(timeout=120)
    assert process.returncode == 0, stderr
    return stdout


def _run_child(request: ChildCommit) -> str:
    return _collect(_spawn(request))


def _spawn_session(request: ChildSession) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            CHILD_SESSION_PROGRAM,
            str(TESTS_ROOT),
            *request.arguments(),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_child_environment(),
    )


def _run_session_child(request: ChildSession) -> str:
    return _collect(_spawn_session(request))


@dataclass(frozen=True, slots=True)
class ChildClaim:
    root: Path
    run_index: int
    approval_index: int
    execution_index: int
    timeout: float = 30.0

    def arguments(self) -> list[str]:
        return [
            str(self.root),
            str(self.run_index),
            str(self.approval_index),
            str(self.execution_index),
            str(self.timeout),
        ]


@dataclass(frozen=True, slots=True)
class ChildInput:
    root: Path
    execution_index: int
    timeout: float = 30.0

    def arguments(self) -> list[str]:
        return [str(self.root), str(self.execution_index), str(self.timeout)]


def child_input(arguments: Sequence[str]) -> str:
    """Record one canonical input from a child process and report a token."""
    root, execution_index, timeout = arguments
    paths = resolve_paths(Path(root))
    try:
        with LocalArtifactStore(paths, timeout=float(timeout)) as store:
            return str(
                store.record_execution_input(
                    SCOPE,
                    _uuid7(int(execution_index)),
                    ExecutionInputKind.RESEARCH_INTENT,
                    INTENT_DOCUMENT,
                )
            )
    except (ArtifactStoreError, BlobIntegrityError) as error:
        return type(error).__name__


def _spawn_input(request: ChildInput) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            CHILD_INPUT_PROGRAM,
            str(TESTS_ROOT),
            *request.arguments(),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_child_environment(),
    )


def _spawn_claim(request: ChildClaim) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            CHILD_CLAIM_PROGRAM,
            str(TESTS_ROOT),
            *request.arguments(),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_child_environment(),
    )


def _spawn_blocker(root: Path) -> subprocess.Popen[str]:
    """Start a child that holds the write lock and wait until it really does."""
    process = subprocess.Popen(
        [sys.executable, "-c", CHILD_BLOCKER_PROGRAM, str(TESTS_ROOT), str(root)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_child_environment(),
    )
    assert process.stdout is not None
    assert process.stdout.readline() == "locked\n"
    return process


def _release_blocker(process: subprocess.Popen[str]) -> None:
    """Close the child's stdin so it releases the lock, then reap it."""
    stdout, stderr = process.communicate(input="", timeout=120)
    assert process.returncode == 0, stderr
    assert stdout == "released"


def _original_insert() -> Callable[[LocalArtifactStore, ArtifactVersion], None]:
    return cast(
        "Callable[[LocalArtifactStore, ArtifactVersion], None]",
        vars(LocalArtifactStore)["_insert_version"],
    )


def _failing_insert(_instance: LocalArtifactStore, _target: ArtifactVersion) -> None:
    raise sqlite3.OperationalError(SIMULATED_FAILURE)


def _unbound_transact() -> TransactCall:
    return cast("TransactCall", vars(LocalArtifactStore)["_transact"])


def _store_connection(store: LocalArtifactStore) -> sqlite3.Connection:
    return cast("sqlite3.Connection", vars(store)["_connection"])


def _row_count(paths: LocalPaths) -> int:
    connection = sqlite3.connect(paths.database)
    try:
        row = cast(
            "tuple[object, ...]",
            connection.execute("SELECT COUNT(*) FROM artifact_versions").fetchone(),
        )
    finally:
        connection.close()
    return cast("int", row[0])


def _count(paths: LocalPaths, query: str) -> int:
    connection = sqlite3.connect(paths.database)
    try:
        row = cast("tuple[object, ...]", connection.execute(query).fetchone())
    finally:
        connection.close()
    return cast("int", row[0])


@pytest.fixture(name="paths")
def paths_fixture(tmp_path: Path) -> LocalPaths:
    return resolve_paths(tmp_path)


@pytest.fixture(name="store")
def store_fixture(paths: LocalPaths) -> Iterator[LocalArtifactStore]:
    with LocalArtifactStore(paths) as opened:
        yield opened


def _seed_artifact(store: LocalArtifactStore, artifact_id: UUID) -> None:
    assert store.create_artifact(SCOPE, _artifact(artifact_id)) is StoreOutcome.CREATED


def _seed_committable(store: LocalArtifactStore, artifact_id: UUID) -> None:
    """Seed one Artifact and the Run whose execution every test Version pins.

    Seeding only the Artifact would leave every commit below refused for an
    unresolvable producing execution, so each test would stop testing its own
    subject.
    """
    _seed_artifact(store, artifact_id)
    _seed_owning_execution(store)


def _seed_two_versions(
    store: LocalArtifactStore,
) -> tuple[ArtifactVersion, ArtifactVersion]:
    first_artifact = _uuid7(1)
    second_artifact = _uuid7(2)
    _seed_committable(store, first_artifact)
    assert (
        store.create_artifact(SCOPE, _artifact(second_artifact, name="peaks"))
        is StoreOutcome.CREATED
    )
    base = _version(first_artifact, _uuid7(0x11), 1, b"base")
    side = _version(second_artifact, _uuid7(0x12), 1, b"side")
    assert store.commit_version(SCOPE, 0, base, b"base") is StoreOutcome.CREATED
    assert store.commit_version(SCOPE, 0, side, b"side") is StoreOutcome.CREATED
    return base, side


def test_satisfies_the_artifact_store_protocol(store: LocalArtifactStore) -> None:
    contract: ArtifactStore = store

    assert contract.project_archived(SCOPE) is False


def test_database_uses_write_ahead_logging(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _seed_artifact(store, _uuid7(1))

    assert paths.database.with_suffix(".sqlite3-wal").exists()


def test_create_and_read_artifact_round_trip(store: LocalArtifactStore) -> None:
    artifact = _artifact(_uuid7(1), name="raman baseline")

    assert store.create_artifact(SCOPE, artifact) is StoreOutcome.CREATED
    assert store.artifact(SCOPE, artifact.id) == artifact


def test_duplicate_artifact_is_rejected(store: LocalArtifactStore) -> None:
    artifact = _artifact(_uuid7(1))
    assert store.create_artifact(SCOPE, artifact) is StoreOutcome.CREATED

    assert store.create_artifact(SCOPE, artifact) is StoreOutcome.NOT_FOUND


def test_unknown_artifact_reads_as_missing(store: LocalArtifactStore) -> None:
    assert store.artifact(SCOPE, _uuid7(9)) is None
    assert store.version(SCOPE, _uuid7(9)) is None
    assert store.lineage(SCOPE, _uuid7(9)) is None


def test_commit_version_advances_head(store: LocalArtifactStore) -> None:
    artifact_id = _uuid7(1)
    _seed_committable(store, artifact_id)
    first = _version(artifact_id, _uuid7(0x11), 1, b"first")
    second = _version(artifact_id, _uuid7(0x12), 2, b"second")
    third = _version(artifact_id, _uuid7(0x13), 3, b"third")

    assert store.commit_version(SCOPE, 0, first, b"first") is StoreOutcome.CREATED
    assert store.commit_version(SCOPE, 1, second, b"second") is StoreOutcome.CREATED
    # A third Version separates MAX from MIN: a head taken from the lowest
    # Version number would reject this base.
    assert store.commit_version(SCOPE, 2, third, b"third") is StoreOutcome.CREATED

    assert store.version(SCOPE, first.id) == first
    assert store.version(SCOPE, third.id) == third
    assert store.read_content(SCOPE, third.id) == b"third"
    replay = _version(artifact_id, _uuid7(0x14), 2, b"replay")
    assert store.commit_version(SCOPE, 1, replay, b"replay") is StoreOutcome.STALE


def test_commit_version_requires_existing_artifact(store: LocalArtifactStore) -> None:
    orphan = _version(_uuid7(7), _uuid7(0x11), 1, b"first")

    assert store.commit_version(SCOPE, 0, orphan, b"first") is StoreOutcome.NOT_FOUND


def test_stale_base_version_is_rejected_without_write(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    artifact_id = _uuid7(1)
    _seed_committable(store, artifact_id)
    first = _version(artifact_id, _uuid7(0x11), 1, b"first")
    assert store.commit_version(SCOPE, 0, first, b"first") is StoreOutcome.CREATED
    stale = _version(artifact_id, _uuid7(0x12), 1, b"stale payload")

    assert store.commit_version(SCOPE, 0, stale, b"stale payload") is StoreOutcome.STALE

    assert store.version(SCOPE, stale.id) is None
    assert store.version(SCOPE, first.id) == first
    assert not _blob_path(paths, b"stale payload").exists()
    assert len(_blob_files(paths)) == 1


def test_commit_rejects_payload_contradicting_its_digest(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    artifact_id = _uuid7(1)
    _seed_committable(store, artifact_id)
    version = _version(artifact_id, _uuid7(0x11), 1, b"declared")

    with pytest.raises(BlobIntegrityError):
        _ = store.commit_version(SCOPE, 0, version, b"actual!!")

    assert store.version(SCOPE, version.id) is None
    assert _blob_files(paths) == []


def test_commit_rejects_a_foreign_object_key(store: LocalArtifactStore) -> None:
    artifact_id = _uuid7(1)
    _seed_committable(store, artifact_id)
    forged = _version(artifact_id, _uuid7(0x11), 1, b"body").model_copy(
        update={"object_key": f"org/elsewhere/project/x/sha256/{'0' * 64}"}
    )

    outcome = store.commit_version(SCOPE, 0, forged, b"body")

    assert outcome is StoreOutcome.INVALID_LINEAGE
    assert store.version(SCOPE, forged.id) is None


def test_commit_rejects_a_contradictory_size(store: LocalArtifactStore) -> None:
    artifact_id = _uuid7(1)
    _seed_committable(store, artifact_id)
    forged = _version(artifact_id, _uuid7(0x11), 1, b"body").model_copy(
        update={"size_bytes": 4096}
    )

    outcome = store.commit_version(SCOPE, 0, forged, b"body")

    assert outcome is StoreOutcome.INVALID_LINEAGE
    assert store.version(SCOPE, forged.id) is None


def test_commit_rejects_a_reused_version_id(store: LocalArtifactStore) -> None:
    first_artifact = _uuid7(1)
    second_artifact = _uuid7(2)
    _seed_committable(store, first_artifact)
    assert (
        store.create_artifact(SCOPE, _artifact(second_artifact, name="peaks"))
        is StoreOutcome.CREATED
    )
    reused = _uuid7(0x11)
    first = _version(first_artifact, reused, 1, b"first")
    assert store.commit_version(SCOPE, 0, first, b"first") is StoreOutcome.CREATED
    clash = _version(second_artifact, reused, 1, b"second")

    outcome = store.commit_version(SCOPE, 0, clash, b"second")

    assert outcome is StoreOutcome.INVALID_LINEAGE
    assert store.version(SCOPE, reused) == first


def test_unknown_input_version_is_invalid_lineage(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    artifact_id = _uuid7(1)
    _seed_committable(store, artifact_id)
    dangling = _version(artifact_id, _uuid7(0x11), 1, b"body", (_uuid7(0xEE),))

    outcome = store.commit_version(SCOPE, 0, dangling, b"body")

    assert outcome is StoreOutcome.INVALID_LINEAGE
    assert store.version(SCOPE, dangling.id) is None
    assert _blob_files(paths) == []


def test_commit_rejects_duplicate_input_version_ids(store: LocalArtifactStore) -> None:
    base, _ = _seed_two_versions(store)
    duplicated = (base.id, base.id)
    derived = _version(base.artifact_id, _uuid7(0x13), 2, b"derived", duplicated)

    outcome = store.commit_version(SCOPE, 1, derived, b"derived")

    assert outcome is StoreOutcome.INVALID_LINEAGE


def test_commit_rejects_unsorted_input_version_ids(store: LocalArtifactStore) -> None:
    base, side = _seed_two_versions(store)
    unsorted = tuple(sorted((base.id, side.id), reverse=True))
    derived = _version(base.artifact_id, _uuid7(0x13), 2, b"derived", unsorted)

    outcome = store.commit_version(SCOPE, 1, derived, b"derived")

    assert outcome is StoreOutcome.INVALID_LINEAGE
    assert store.version(SCOPE, derived.id) is None


def test_commit_refuses_a_version_whose_execution_exists_nowhere(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # A Version asserting "this execution produced these bytes" for an
    # execution that never ran is a fabricated provenance claim, and the
    # durable adapter refuses exactly this in `references_valid`.
    artifact_id = _uuid7(1)
    _seed_artifact(store, artifact_id)
    fabricated = _version(artifact_id, _uuid7(0x11), 1, b"body")

    outcome = store.commit_version(SCOPE, 0, fabricated, b"body")

    # `invalid_lineage`, never `not_found`: the Artifact being appended to
    # does exist, and a provenance refusal must not read as a missing one.
    assert outcome is StoreOutcome.INVALID_LINEAGE
    assert str(outcome) == "invalid_lineage"
    assert store.version(SCOPE, fabricated.id) is None
    assert _blob_files(paths) == []
    assert _count(paths, "SELECT COUNT(*) FROM artifact_versions") == 0


@dataclass(frozen=True, slots=True)
class _ForeignExecution:
    """One way a producing execution can fail to belong to this Project."""

    org_id: UUID = LOCAL_ORG_ID
    project_id: UUID = DEFAULT_PROJECT_ID
    run_org_id: UUID = LOCAL_ORG_ID
    run_project_id: UUID = DEFAULT_PROJECT_ID
    run_exists: bool = True


@pytest.mark.parametrize(
    "foreign",
    [
        _ForeignExecution(org_id=SECOND_ORG_ID, run_org_id=SECOND_ORG_ID),
        _ForeignExecution(project_id=SECOND_PROJECT_ID),
        _ForeignExecution(run_project_id=SECOND_PROJECT_ID),
        _ForeignExecution(run_exists=False),
    ],
)
def test_commit_refuses_an_execution_this_project_does_not_own(
    store: LocalArtifactStore,
    paths: LocalPaths,
    foreign: _ForeignExecution,
) -> None:
    # A whole chain filed under another tenant, an execution filed under
    # another Project, one whose Run sits in another Project, and one whose
    # Run row is gone are all equally unusable as a producer. A chain that
    # resolves partway is not ownership, so each must refuse identically.
    #
    # The tenant case carries its Run into the foreign tenant too, so the
    # execution -> run join really does resolve there and nothing but the
    # tenant filter can be what refuses it.
    artifact_id = _uuid7(1)
    _seed_artifact(store, artifact_id)
    if foreign.run_exists:
        _insert_run_row(paths, FOREIGN_RUN, foreign.run_project_id, foreign.run_org_id)
    _insert_execution_row(
        paths,
        EXECUTION,
        FOREIGN_RUN,
        foreign.project_id,
        foreign.org_id,
    )
    borrowed = _version(artifact_id, _uuid7(0x11), 1, b"body")

    outcome = store.commit_version(SCOPE, 0, borrowed, b"body")

    assert outcome is StoreOutcome.INVALID_LINEAGE
    assert store.version(SCOPE, borrowed.id) is None
    assert _blob_files(paths) == []


def test_commit_refuses_an_execution_bound_to_a_run_that_is_not_its_own(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # A genuine Run in this Project must not launder an execution that names a
    # different one. Ownership is the execution's *own* Run resolving, so a
    # reader that merely asked whether some Run exists here would accept this.
    artifact_id = _uuid7(1)
    _seed_committable(store, artifact_id)
    _insert_execution_row(paths, IMPOSTOR_EXECUTION, ABSENT_RUN, DEFAULT_PROJECT_ID)
    borrowed = _build_version(
        VersionSpec(
            SCOPE,
            artifact_id,
            _uuid7(0x11),
            b"body",
            execution_id=IMPOSTOR_EXECUTION,
        )
    )

    outcome = store.commit_version(SCOPE, 0, borrowed, b"body")

    assert outcome is StoreOutcome.INVALID_LINEAGE
    assert store.version(SCOPE, borrowed.id) is None
    # The Project's genuine chain is untouched, so the refusal is about this
    # execution's own binding and not about the Project being empty.
    assert store.execution(SCOPE, EXECUTION) is not None
    assert store.run(SCOPE, _uuid7(RUN_BASE + ATTACH_SEED_INDEX)) is not None


def test_commit_accepts_a_version_produced_by_an_already_finished_run(
    store: LocalArtifactStore,
) -> None:
    # Ownership is resolution, not liveness. A Run that failed or was
    # cancelled still produced whatever it produced, and refusing its outputs
    # would delete the truncation record instead of preserving it.
    artifact_id = _uuid7(1)
    _seed_committable(store, artifact_id)
    run_id = _uuid7(RUN_BASE + ATTACH_SEED_INDEX)
    assert store.finish_run(SCOPE, _completion(run_id, RunState.FAILED, "OSError")) is (
        StoreOutcome.CREATED
    )
    version = _version(artifact_id, _uuid7(0x11), 1, b"body")

    assert store.commit_version(SCOPE, 0, version, b"body") is StoreOutcome.CREATED

    assert store.version(SCOPE, version.id) == version


def test_concurrent_commits_all_refuse_an_execution_that_exists_nowhere(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # Four real writers contending for the same database write lock. The
    # producer is resolved inside each writer's own `BEGIN IMMEDIATE`, so no
    # window between the compare-and-swap and the insert can let a fabricated
    # producer through, and a refusal must leave nothing behind.
    artifact_id = _uuid7(1)
    _seed_artifact(store, artifact_id)
    requests = [
        ChildCommit(
            paths.root,
            1,
            0x20 + index,
            f"payload-{index}".encode(),
            timeout=30.0,
        )
        for index in range(4)
    ]

    processes = [_spawn(request) for request in requests]
    outcomes = sorted(_collect(process) for process in processes)

    assert outcomes == [
        "invalid_lineage",
        "invalid_lineage",
        "invalid_lineage",
        "invalid_lineage",
    ]
    assert _row_count(paths) == 0
    assert _blob_files(paths) == []


def test_a_child_process_refuses_a_version_whose_execution_exists_nowhere(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # A second real process on the same database, with its own connection and
    # its own cache, must reach the same refusal -- and must accept the same
    # request once the parent has really started the Run.
    artifact_id = _uuid7(1)
    _seed_artifact(store, artifact_id)

    refused = _run_child(ChildCommit(paths.root, 1, 0x11, b"body", timeout=30.0))

    assert refused == "invalid_lineage"
    assert _row_count(paths) == 0
    _seed_owning_execution(store)

    accepted = _run_child(ChildCommit(paths.root, 1, 0x11, b"body", timeout=30.0))

    assert accepted == "created"
    assert _row_count(paths) == 1


def test_lineage_returns_exact_input_version_ids(store: LocalArtifactStore) -> None:
    base, side = _seed_two_versions(store)
    inputs = tuple(sorted((side.id, base.id)))
    derived = _version(base.artifact_id, _uuid7(0x13), 2, b"derived", inputs)
    assert store.commit_version(SCOPE, 1, derived, b"derived") is StoreOutcome.CREATED

    assert store.lineage(SCOPE, derived.id) == inputs
    assert store.version(SCOPE, derived.id) == derived
    assert store.lineage(SCOPE, base.id) == ()


def test_lineage_projection_orders_externally_written_edges(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    base, side = _seed_two_versions(store)
    inputs = tuple(sorted((side.id, base.id)))
    derived = _version(base.artifact_id, _uuid7(0x13), 2, b"derived", inputs)
    assert store.commit_version(SCOPE, 1, derived, b"derived") is StoreOutcome.CREATED
    # Rewrite the lineage edges in reverse insertion order, as a restored
    # backup or a future writer might, so row order contradicts digest order.
    connection = sqlite3.connect(paths.database, isolation_level=None)
    try:
        _ = connection.execute(
            "DELETE FROM version_inputs WHERE artifact_version_id = ?",
            (str(derived.id),),
        )
        _ = connection.executemany(
            "INSERT INTO version_inputs (org_id, project_id, artifact_version_id, "
            "input_version_id) VALUES (?, ?, ?, ?)",
            [
                (
                    str(LOCAL_ORG_ID),
                    str(DEFAULT_PROJECT_ID),
                    str(derived.id),
                    str(input_id),
                )
                for input_id in reversed(inputs)
            ],
        )
        stored = cast(
            "list[tuple[object, ...]]",
            connection.execute(
                "SELECT input_version_id FROM version_inputs "
                "WHERE artifact_version_id = ?",
                (str(derived.id),),
            ).fetchall(),
        )
    finally:
        connection.close()

    # The adversarial state exists only if the rows really were rewritten.
    assert len(stored) == len(inputs)
    assert store.lineage(SCOPE, derived.id) == inputs
    assert store.version(SCOPE, derived.id) == derived


def test_tampered_blob_raises_blob_integrity_error(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    artifact_id = _uuid7(1)
    _seed_committable(store, artifact_id)
    version = _version(artifact_id, _uuid7(0x11), 1, b"trusted")
    assert store.commit_version(SCOPE, 0, version, b"trusted") is StoreOutcome.CREATED
    _ = _blob_path(paths, b"trusted").write_bytes(b"tampered")

    with pytest.raises(BlobIntegrityError):
        _ = store.read_content(SCOPE, version.id)

    with pytest.raises(BlobIntegrityError):
        _ = store.redeem_content(SCOPE, version.id)


def test_missing_blob_raises_blob_integrity_error(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    artifact_id = _uuid7(1)
    _seed_committable(store, artifact_id)
    version = _version(artifact_id, _uuid7(0x11), 1, b"trusted")
    assert store.commit_version(SCOPE, 0, version, b"trusted") is StoreOutcome.CREATED
    _blob_path(paths, b"trusted").unlink()

    with pytest.raises(BlobIntegrityError):
        _ = store.read_content(SCOPE, version.id)


def test_commit_rejects_content_colliding_with_different_bytes(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    first_artifact = _uuid7(1)
    second_artifact = _uuid7(2)
    _seed_committable(store, first_artifact)
    assert (
        store.create_artifact(SCOPE, _artifact(second_artifact, name="peaks"))
        is StoreOutcome.CREATED
    )
    payload = b"original"
    first = _version(first_artifact, _uuid7(0x11), 1, payload)
    assert store.commit_version(SCOPE, 0, first, payload) is StoreOutcome.CREATED
    _ = _blob_path(paths, payload).write_bytes(b"replaced")
    second = _version(second_artifact, _uuid7(0x12), 1, payload)

    with pytest.raises(BlobIntegrityError):
        _ = store.commit_version(SCOPE, 0, second, payload)

    assert store.version(SCOPE, second.id) is None


def test_identical_content_is_stored_once_across_projects(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    first_artifact = _uuid7(1)
    second_artifact = _uuid7(2)
    _seed_committable(store, first_artifact)
    assert (
        store.create_artifact(SCOPE_B, _artifact_in(SCOPE_B, second_artifact))
        is StoreOutcome.CREATED
    )
    # Each Project owns its own Run and execution: ownership is Project-local,
    # so the second Project cannot borrow the first Project's producer.
    _seed_owning_execution(store, SCOPE_B, EXECUTION_B, SECOND_SEED_INDEX)
    shared = b"identical bytes"
    first = _version(first_artifact, _uuid7(0x11), 1, shared)
    second = _build_version(
        VersionSpec(
            SCOPE_B,
            second_artifact,
            _uuid7(0x12),
            shared,
            execution_id=EXECUTION_B,
        )
    )

    assert store.commit_version(SCOPE, 0, first, shared) is StoreOutcome.CREATED
    assert store.commit_version(SCOPE_B, 0, second, shared) is StoreOutcome.CREATED

    # Distinct Project-scoped addresses, one shared physical object.
    assert first.object_key != second.object_key
    assert _blob_files(paths) == [_blob_path(paths, shared)]
    assert store.read_content(SCOPE, first.id) == shared
    assert store.read_content(SCOPE_B, second.id) == shared


def test_blob_is_published_before_the_metadata_row(
    store: LocalArtifactStore,
    paths: LocalPaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_id = _uuid7(1)
    _seed_committable(store, artifact_id)
    payload = b"ordered"
    recorder = Recorder()
    original = _original_insert()

    def spy(instance: LocalArtifactStore, version: ArtifactVersion) -> None:
        recorder.flags.append(_blob_path(paths, payload).exists())
        original(instance, version)

    monkeypatch.setattr(INSERT_VERSION, spy)
    version = _version(artifact_id, _uuid7(0x11), 1, payload)

    assert store.commit_version(SCOPE, 0, version, payload) is StoreOutcome.CREATED

    monkeypatch.undo()
    assert recorder.flags == [True]


def test_failed_publish_leaves_no_partial_blob(
    store: LocalArtifactStore,
    paths: LocalPaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_id = _uuid7(1)
    _seed_committable(store, artifact_id)
    payload = b"never lands"

    def explode(_descriptor: int) -> None:
        raise OSError(SIMULATED_FAILURE)

    monkeypatch.setattr("os.fsync", explode)
    version = _version(artifact_id, _uuid7(0x11), 1, payload)

    with pytest.raises(ArtifactCommitError):
        _ = store.commit_version(SCOPE, 0, version, payload)

    monkeypatch.undo()
    assert not _blob_path(paths, payload).exists()
    assert _blob_files(paths) == []
    assert store.version(SCOPE, version.id) is None


def test_failed_metadata_write_preserves_adoptable_bytes(
    store: LocalArtifactStore,
    paths: LocalPaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_id = _uuid7(1)
    _seed_committable(store, artifact_id)
    payload = b"doomed"
    doomed = _version(artifact_id, _uuid7(0x11), 1, payload)

    monkeypatch.setattr(INSERT_VERSION, _failing_insert)
    with pytest.raises(ArtifactCommitError):
        _ = store.commit_version(SCOPE, 0, doomed, payload)

    monkeypatch.undo()
    # The failure deletes nothing: the orphan stays and a retry adopts it.
    assert _blob_files(paths) == [_blob_path(paths, payload)]
    assert store.version(SCOPE, doomed.id) is None
    assert store.commit_version(SCOPE, 0, doomed, payload) is StoreOutcome.CREATED
    assert store.read_content(SCOPE, doomed.id) == payload
    assert _blob_files(paths) == [_blob_path(paths, payload)]


def test_failed_commit_preserves_content_referenced_by_another_project(
    store: LocalArtifactStore,
    paths: LocalPaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keeper_artifact = _uuid7(2)
    doomed_artifact = _uuid7(1)
    _seed_committable(store, doomed_artifact)
    assert (
        store.create_artifact(SCOPE_B, _artifact_in(SCOPE_B, keeper_artifact))
        is StoreOutcome.CREATED
    )
    _seed_owning_execution(store, SCOPE_B, EXECUTION_B, SECOND_SEED_INDEX)
    shared = b"shared bytes"
    keeper = _build_version(
        VersionSpec(
            SCOPE_B,
            keeper_artifact,
            _uuid7(0x11),
            shared,
            execution_id=EXECUTION_B,
        )
    )
    assert store.commit_version(SCOPE_B, 0, keeper, shared) is StoreOutcome.CREATED
    doomed = _version(doomed_artifact, _uuid7(0x12), 1, shared)

    monkeypatch.setattr(INSERT_VERSION, _failing_insert)
    with pytest.raises(ArtifactCommitError):
        _ = store.commit_version(SCOPE, 0, doomed, shared)

    monkeypatch.undo()
    assert _blob_files(paths) == [_blob_path(paths, shared)]
    assert store.read_content(SCOPE_B, keeper.id) == shared


def test_concurrent_commits_serialize_on_the_base_version(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    artifact_id = _uuid7(1)
    _seed_committable(store, artifact_id)
    requests = [
        ChildCommit(paths.root, 1, 0x20 + index, f"payload-{index}".encode())
        for index in range(4)
    ]

    processes = [_spawn(request) for request in requests]
    outcomes = sorted(_collect(process) for process in processes)

    assert outcomes == ["created", "stale", "stale", "stale"]
    assert _row_count(paths) == 1


def test_failed_commit_in_another_process_preserves_in_flight_content(
    store: LocalArtifactStore,
    paths: LocalPaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_artifact = _uuid7(1)
    second_artifact = _uuid7(2)
    _seed_committable(store, first_artifact)
    assert (
        store.create_artifact(SCOPE, _artifact(second_artifact, name="peaks"))
        is StoreOutcome.CREATED
    )
    shared = b"contended bytes"
    recorder = Recorder()

    def pause(_directory: Path) -> None:
        # Runs inside our BEGIN IMMEDIATE, after the blob reached its final
        # path and before our metadata row exists. A second process commits
        # the same content here, fails on the write lock, and must not treat
        # our unreferenced bytes as its own garbage.
        recorder.tokens.append(
            _run_child(ChildCommit(paths.root, 2, 0x12, shared, 0, 0.2))
        )

    monkeypatch.setattr(SYNC_DIRECTORY, pause)
    version = _version(first_artifact, _uuid7(0x11), 1, shared)

    assert store.commit_version(SCOPE, 0, version, shared) is StoreOutcome.CREATED

    monkeypatch.undo()
    assert recorder.tokens == ["ArtifactCommitError"]
    assert _blob_path(paths, shared).exists()
    assert store.read_content(SCOPE, version.id) == shared


def test_sweep_reclaims_only_aged_unreferenced_blobs(
    store: LocalArtifactStore,
    paths: LocalPaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_id = _uuid7(1)
    _seed_committable(store, artifact_id)
    kept = b"referenced"
    version = _version(artifact_id, _uuid7(0x11), 1, kept)
    assert store.commit_version(SCOPE, 0, version, kept) is StoreOutcome.CREATED
    orphan = b"orphaned"
    doomed = _version(artifact_id, _uuid7(0x12), 2, orphan)

    monkeypatch.setattr(INSERT_VERSION, _failing_insert)
    with pytest.raises(ArtifactCommitError):
        _ = store.commit_version(SCOPE, 1, doomed, orphan)
    monkeypatch.undo()

    # A freshly published orphan is protected by the grace period.
    assert store.sweep_unreferenced_blobs() == ()
    assert _blob_path(paths, orphan).exists()

    digest = hashlib.sha256(orphan).hexdigest()
    assert store.sweep_unreferenced_blobs(min_age_seconds=0.0) == (digest,)
    assert not _blob_path(paths, orphan).exists()
    assert _blob_files(paths) == [_blob_path(paths, kept)]
    assert store.read_content(SCOPE, version.id) == kept


def test_operational_failures_surface_as_store_errors(paths: LocalPaths) -> None:
    with LocalArtifactStore(paths, timeout=0.05) as blocked:
        _seed_artifact(blocked, _uuid7(1))
        version = _version(_uuid7(1), _uuid7(0x11), 1, b"body")
        link = SessionArtifactLink(
            org_id=LOCAL_ORG_ID,
            project_id=DEFAULT_PROJECT_ID,
            session_id=SESSION,
            artifact_version_id=version.id,
            revision=1,
            created_at=CREATED_AT,
        )
        blocker = sqlite3.connect(paths.database, isolation_level=None)
        try:
            _ = blocker.execute("BEGIN IMMEDIATE")
            with pytest.raises(ArtifactStoreError):
                _ = blocked.create_artifact(SCOPE, _artifact(_uuid7(2)))
            with pytest.raises(ArtifactStoreError):
                _ = blocked.attach_session(SCOPE, link)
            with pytest.raises(ArtifactStoreError):
                blocked.archive_project(SCOPE)
            with pytest.raises(ArtifactCommitError):
                _ = blocked.commit_version(SCOPE, 0, version, b"body")
        finally:
            blocker.close()


def test_duplicate_session_attach_reports_association_exists(
    store: LocalArtifactStore,
) -> None:
    # A live Session that owns the producing Run is now a precondition of
    # attaching, not an assumption.
    version = _seed_attachable(store)
    link = _link(SESSION, version.id)

    assert store.attach_session(SCOPE, link) is StoreOutcome.CREATED
    assert store.attach_session(SCOPE, link) is StoreOutcome.ASSOCIATION_EXISTS


def test_attach_session_requires_known_version(store: LocalArtifactStore) -> None:
    # The Session is live and owns the whole execution chain, so only the
    # missing Version can reject this.
    _seed_session(store)
    _seed_owning_execution(store, session_id=SESSION)
    link = _link(SESSION, _uuid7(0xAA))

    assert store.attach_session(SCOPE, link) is StoreOutcome.NOT_FOUND


def test_unknown_project_is_not_archived(store: LocalArtifactStore) -> None:
    assert store.project_archived(SCOPE) is False


def test_archived_project_blocks_writes_and_reads(store: LocalArtifactStore) -> None:
    artifact_id = _uuid7(1)
    _seed_committable(store, artifact_id)
    version = _version(artifact_id, _uuid7(0x11), 1, b"body")
    assert store.commit_version(SCOPE, 0, version, b"body") is StoreOutcome.CREATED
    store.archive_project(SCOPE)

    assert store.project_archived(SCOPE) is True
    assert store.artifact(SCOPE, artifact_id) is None
    assert store.version(SCOPE, version.id) is None
    assert store.redeem_content(SCOPE, version.id) == (
        StoreOutcome.ARCHIVED,
        None,
        None,
    )
    next_version = _version(artifact_id, _uuid7(0x12), 2, b"next")
    blocked = store.commit_version(SCOPE, 1, next_version, b"next")
    assert blocked is StoreOutcome.ARCHIVED


def test_object_key_is_server_derived(store: LocalArtifactStore) -> None:
    digest = hashlib.sha256(b"body").hexdigest()

    assert store.object_key(SCOPE, digest) == (
        f"org/{LOCAL_ORG_ID}/project/{DEFAULT_PROJECT_ID}/sha256/{digest}"
    )


def test_state_survives_reopening_the_database(paths: LocalPaths) -> None:
    artifact_id = _uuid7(1)
    version = _version(artifact_id, _uuid7(0x11), 1, b"durable")
    with LocalArtifactStore(paths) as first:
        _seed_committable(first, artifact_id)
        created = first.commit_version(SCOPE, 0, version, b"durable")
        assert created is StoreOutcome.CREATED

    with LocalArtifactStore(paths) as second:
        assert second.artifact(SCOPE, artifact_id) == _artifact(artifact_id)
        assert second.version(SCOPE, version.id) == version
        assert second.read_content(SCOPE, version.id) == b"durable"


def _seed_session(store: LocalArtifactStore, session_id: UUID = SESSION) -> None:
    assert store.create_session(SCOPE, _session(session_id)) is StoreOutcome.CREATED


def _seed_owned_version(store: LocalArtifactStore) -> ArtifactVersion:
    """Seed one Version whose producing execution exists but records no Session.

    This is the shape a local analysis run outside any Session leaves behind:
    a whole, committable, readable chain whose last ownership link is absent.
    """
    artifact_id = _uuid7(1)
    _seed_committable(store, artifact_id)
    version = _version(artifact_id, _uuid7(0x11), 1, b"body")
    assert store.commit_version(SCOPE, 0, version, b"body") is StoreOutcome.CREATED
    return version


def _seed_attachable(
    store: LocalArtifactStore,
    session_id: UUID = SESSION,
) -> ArtifactVersion:
    """Seed a Version whose Run belongs to one live Session, ready to associate.

    The Session is registered before the Run, because a Run naming a Session
    that is not yet live is refused. Every ownership link therefore resolves
    and any refusal below is attributable to whatever the test broke.
    """
    artifact_id = _uuid7(1)
    _seed_session(store, session_id)
    _seed_artifact(store, artifact_id)
    _seed_owning_execution(store, session_id=session_id)
    version = _version(artifact_id, _uuid7(0x11), 1, b"body")
    assert store.commit_version(SCOPE, 0, version, b"body") is StoreOutcome.CREATED
    return version


def test_create_and_read_project_round_trip(store: LocalArtifactStore) -> None:
    project = _project(SCOPE, name="raman dry lab")

    assert store.create_project(SCOPE, project) is StoreOutcome.CREATED
    assert store.project(SCOPE) == project
    assert store.project(SCOPE_B) is None


def test_duplicate_project_registration_is_rejected(store: LocalArtifactStore) -> None:
    assert store.create_project(SCOPE, _project(SCOPE)) is StoreOutcome.CREATED

    assert (
        store.create_project(SCOPE, _project(SCOPE, name="renamed"))
        is StoreOutcome.NOT_FOUND
    )
    assert store.project(SCOPE) == _project(SCOPE)


def test_an_unregistered_project_is_readable_as_absent_but_stays_active(
    store: LocalArtifactStore,
) -> None:
    # The archival-marker semantics: no row means active and unprovisioned, so
    # the fixed local Project works without any provisioning step.
    assert store.project(SCOPE) is None
    assert store.project_archived(SCOPE) is False
    assert store.projects(LOCAL_ORG_ID) == ()

    assert store.create_artifact(SCOPE, _artifact(_uuid7(1))) is StoreOutcome.CREATED
    assert store.create_session(SCOPE, _session(SESSION)) is StoreOutcome.CREATED


def test_archiving_an_unregistered_project_leaves_it_unlisted(
    store: LocalArtifactStore,
) -> None:
    store.archive_project(SCOPE)

    assert store.project_archived(SCOPE) is True
    assert store.project(SCOPE) is None
    assert store.projects(LOCAL_ORG_ID) == ()


def test_archiving_a_registered_project_preserves_its_record(
    store: LocalArtifactStore,
) -> None:
    assert store.create_project(SCOPE, _project(SCOPE)) is StoreOutcome.CREATED

    store.archive_project(SCOPE)

    archived = store.project(SCOPE)
    assert archived is not None
    assert archived.archived is True
    assert archived.name == "dry lab"
    assert archived.created_at == CREATED_AT
    assert store.projects(LOCAL_ORG_ID) == (archived,)


def test_projects_are_listed_newest_first_within_one_tenant(
    store: LocalArtifactStore,
) -> None:
    first = _project(SCOPE, name="older", created_at=CREATED_AT)
    second = _project(SCOPE_B, name="newer", created_at=LATER_AT)
    assert store.create_project(SCOPE, first) is StoreOutcome.CREATED
    assert store.create_project(SCOPE_B, second) is StoreOutcome.CREATED

    assert store.projects(LOCAL_ORG_ID) == (second, first)
    assert store.projects(SECOND_PROJECT_ID) == ()


def test_create_project_rejects_a_record_contradicting_the_scope(
    store: LocalArtifactStore,
) -> None:
    foreign = _project(SCOPE_B)

    assert store.create_project(SCOPE, foreign) is StoreOutcome.NOT_FOUND
    assert store.project(SCOPE) is None
    assert store.project(SCOPE_B) is None


def test_create_project_refuses_to_register_an_archived_record(
    store: LocalArtifactStore,
) -> None:
    born_archived = _project(SCOPE).model_copy(update={"archived": True})

    assert store.create_project(SCOPE, born_archived) is StoreOutcome.NOT_FOUND
    assert store.project(SCOPE) is None
    assert store.project_archived(SCOPE) is False


def test_create_project_is_refused_after_archiving(store: LocalArtifactStore) -> None:
    store.archive_project(SCOPE)

    assert store.create_project(SCOPE, _project(SCOPE)) is StoreOutcome.ARCHIVED
    assert store.project(SCOPE) is None


def test_create_and_read_session_round_trip(store: LocalArtifactStore) -> None:
    session = _session(_uuid7(0x301), title="peak triage")

    assert store.create_session(SCOPE, session) is StoreOutcome.CREATED
    assert store.session(SCOPE, session.id) == session
    assert store.sessions(SCOPE) == (session,)
    assert store.session(SCOPE, _uuid7(0x302)) is None


def test_create_session_is_refused_for_an_archived_project(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    store.archive_project(SCOPE)

    assert store.create_session(SCOPE, _session(_uuid7(0x301))) is StoreOutcome.ARCHIVED
    assert _count(paths, "SELECT COUNT(*) FROM sessions") == 0


def test_a_session_identity_cannot_belong_to_two_projects(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    shared = _uuid7(0x301)
    owned = _session_in(SCOPE, shared)
    assert store.create_session(SCOPE, owned) is StoreOutcome.CREATED

    stolen = _session_in(SCOPE_B, shared, title="hijack")
    assert store.create_session(SCOPE_B, stolen) is StoreOutcome.NOT_FOUND

    assert store.session(SCOPE, shared) == owned
    assert store.session(SCOPE_B, shared) is None
    assert store.sessions(SCOPE_B) == ()
    assert _count(paths, "SELECT COUNT(*) FROM sessions") == 1


def test_duplicate_session_identity_in_one_project_is_rejected(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    session = _session(_uuid7(0x301))
    assert store.create_session(SCOPE, session) is StoreOutcome.CREATED

    replay = _session(_uuid7(0x301), title="replay")
    assert store.create_session(SCOPE, replay) is StoreOutcome.NOT_FOUND

    assert store.session(SCOPE, session.id) == session
    assert _count(paths, "SELECT COUNT(*) FROM sessions") == 1


def test_create_session_rejects_a_record_contradicting_the_scope(
    store: LocalArtifactStore,
) -> None:
    foreign = _session_in(SCOPE_B, _uuid7(0x301))

    assert store.create_session(SCOPE, foreign) is StoreOutcome.NOT_FOUND
    assert store.session(SCOPE, foreign.id) is None
    assert store.session(SCOPE_B, foreign.id) is None


def test_create_session_refuses_a_record_that_is_already_archived(
    store: LocalArtifactStore,
) -> None:
    born_archived = _session(_uuid7(0x301)).model_copy(update={"archived": True})

    assert store.create_session(SCOPE, born_archived) is StoreOutcome.NOT_FOUND
    assert store.sessions(SCOPE) == ()


def test_sessions_are_listed_most_recently_active_first(
    store: LocalArtifactStore,
) -> None:
    older = _session(_uuid7(0x301), title="older", last_active_at=CREATED_AT)
    newer = _session(_uuid7(0x302), title="newer", last_active_at=LATER_AT)
    assert store.create_session(SCOPE, older) is StoreOutcome.CREATED
    assert store.create_session(SCOPE, newer) is StoreOutcome.CREATED

    assert store.sessions(SCOPE) == (newer, older)


def test_resume_advances_the_session_history_order(store: LocalArtifactStore) -> None:
    first = _session(_uuid7(0x301), title="first", last_active_at=CREATED_AT)
    second = _session(_uuid7(0x302), title="second", last_active_at=LATER_AT)
    assert store.create_session(SCOPE, first) is StoreOutcome.CREATED
    assert store.create_session(SCOPE, second) is StoreOutcome.CREATED
    assert store.sessions(SCOPE) == (second, first)

    assert store.resume_session(SCOPE, first.id, LATEST_AT) is StoreOutcome.CREATED

    resumed = store.session(SCOPE, first.id)
    assert resumed is not None
    assert resumed.last_active_at == LATEST_AT
    assert resumed.created_at == CREATED_AT
    assert store.sessions(SCOPE) == (resumed, second)


def test_resume_rejects_unknown_archived_and_foreign_sessions(
    store: LocalArtifactStore,
) -> None:
    live = _uuid7(0x301)
    _seed_session(store, live)
    elsewhere = _uuid7(0x302)
    assert (
        store.create_session(SCOPE_B, _session_in(SCOPE_B, elsewhere))
        is StoreOutcome.CREATED
    )

    unknown = store.resume_session(SCOPE, _uuid7(0x303), LATER_AT)
    assert unknown is StoreOutcome.NOT_FOUND
    assert store.resume_session(SCOPE, elsewhere, LATER_AT) is StoreOutcome.NOT_FOUND
    assert store.archive_session(SCOPE, live) is StoreOutcome.CREATED
    assert store.resume_session(SCOPE, live, LATER_AT) is StoreOutcome.ARCHIVED

    still_created = store.session(SCOPE, live)
    assert still_created is not None
    assert still_created.last_active_at == CREATED_AT


def test_archive_session_reports_one_transition_then_stays_archived(
    store: LocalArtifactStore,
) -> None:
    session = _session(_uuid7(0x301))
    assert store.create_session(SCOPE, session) is StoreOutcome.CREATED

    assert store.archive_session(SCOPE, session.id) is StoreOutcome.CREATED
    assert store.archive_session(SCOPE, session.id) is StoreOutcome.ARCHIVED

    archived = store.session(SCOPE, session.id)
    assert archived is not None
    assert archived.archived is True
    assert store.sessions(SCOPE) == (archived,)


def test_archive_session_rejects_unknown_and_foreign_sessions(
    store: LocalArtifactStore,
) -> None:
    elsewhere = _uuid7(0x302)
    assert (
        store.create_session(SCOPE_B, _session_in(SCOPE_B, elsewhere))
        is StoreOutcome.CREATED
    )

    assert store.archive_session(SCOPE, _uuid7(0x301)) is StoreOutcome.NOT_FOUND
    assert store.archive_session(SCOPE, elsewhere) is StoreOutcome.NOT_FOUND

    intact = store.session(SCOPE_B, elsewhere)
    assert intact is not None
    assert intact.archived is False


def test_an_archived_project_hides_and_freezes_its_sessions(
    store: LocalArtifactStore,
) -> None:
    session = _session(_uuid7(0x301))
    assert store.create_session(SCOPE, session) is StoreOutcome.CREATED
    store.archive_project(SCOPE)

    assert store.session(SCOPE, session.id) is None
    assert store.sessions(SCOPE) == ()
    assert store.resume_session(SCOPE, session.id, LATER_AT) is StoreOutcome.ARCHIVED
    assert store.archive_session(SCOPE, session.id) is StoreOutcome.ARCHIVED


def test_session_lifecycle_survives_reopening_the_database(paths: LocalPaths) -> None:
    session = _session(_uuid7(0x301), title="durable session")
    with LocalArtifactStore(paths) as first:
        assert first.create_project(SCOPE, _project(SCOPE)) is StoreOutcome.CREATED
        assert first.create_session(SCOPE, session) is StoreOutcome.CREATED
        resumed = first.resume_session(SCOPE, session.id, LATEST_AT)
        assert resumed is StoreOutcome.CREATED

    with LocalArtifactStore(paths) as second:
        assert second.project(SCOPE) == _project(SCOPE)
        reopened = second.session(SCOPE, session.id)
        assert reopened is not None
        assert reopened.title == "durable session"
        assert reopened.last_active_at == LATEST_AT
        assert reopened.archived is False


def test_attach_session_rejects_an_unknown_session(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # The Run still names this Session, so the ownership walk resolves and only
    # the Session's own absence can reject the association. Deleting the row is
    # how an older build or a lossy restore leaves that state; `create_run`
    # itself refuses to write a Run naming a Session that is not there.
    version = _seed_attachable(store)
    _delete_session_row(paths, SESSION)

    assert store.attach_session(SCOPE, _link(SESSION, version.id)) is (
        StoreOutcome.NOT_FOUND
    )
    assert _count(paths, "SELECT COUNT(*) FROM session_links") == 0


def test_attach_session_rejects_an_archived_session(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # The Run owns this Session and the chain is whole, so archival is the one
    # thing rejecting the association.
    version = _seed_attachable(store)
    assert store.archive_session(SCOPE, SESSION) is StoreOutcome.CREATED

    assert store.attach_session(SCOPE, _link(SESSION, version.id)) is (
        StoreOutcome.NOT_FOUND
    )
    assert _count(paths, "SELECT COUNT(*) FROM session_links") == 0


def test_attach_session_rejects_a_foreign_project_session(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # Filed under another Project while the Run still names it, so the
    # ownership walk resolves and only the Project mismatch rejects this.
    # `create_run` cannot produce this state either -- it requires a Session
    # live in its own Project -- so the row is moved directly.
    version = _seed_attachable(store)
    _reproject_session(paths, SESSION, SECOND_PROJECT_ID)

    assert store.attach_session(SCOPE, _link(SESSION, version.id)) is (
        StoreOutcome.NOT_FOUND
    )
    assert _count(paths, "SELECT COUNT(*) FROM session_links") == 0


def test_attach_session_refuses_a_run_that_recorded_no_session(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # The Version, its execution, its Run, and the Session are all whole and
    # live; the only thing missing is the Run's own Session reference. Absence
    # must refuse, not pass: a Version whose Run never named a Session is
    # evidence of nothing about this one.
    version = _seed_owned_version(store)
    _seed_session(store)
    assert _run_session_ids(paths) == [None]

    assert store.attach_session(SCOPE, _link(SESSION, version.id)) is (
        StoreOutcome.NOT_FOUND
    )
    assert _count(paths, "SELECT COUNT(*) FROM session_links") == 0


def test_attach_session_refuses_a_session_that_did_not_commission_the_run(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # Two live Sessions in one Project. The Version belongs to the first, so
    # attaching it to the second must be refused even though that Session is
    # perfectly usable and the rest of the chain resolves.
    version = _seed_attachable(store)
    other = _uuid7(0x303)
    _seed_session(store, other)

    assert store.attach_session(SCOPE, _link(other, version.id)) is (
        StoreOutcome.NOT_FOUND
    )
    assert store.attach_session(SCOPE, _link(SESSION, version.id)) is (
        StoreOutcome.CREATED
    )
    assert _count(paths, "SELECT COUNT(*) FROM session_links") == 1


def test_attach_session_is_refused_for_an_archived_project(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    version = _seed_attachable(store)
    store.archive_project(SCOPE)

    assert store.attach_session(SCOPE, _link(SESSION, version.id)) is (
        StoreOutcome.ARCHIVED
    )
    assert _count(paths, "SELECT COUNT(*) FROM session_links") == 0


def test_attach_session_accepts_only_a_live_same_project_session(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    version = _seed_attachable(store)

    assert store.attach_session(SCOPE, _link(SESSION, version.id)) is (
        StoreOutcome.CREATED
    )
    assert _count(paths, "SELECT COUNT(*) FROM session_links") == 1
    # Archiving afterwards preserves the association it already authorized.
    assert store.archive_session(SCOPE, SESSION) is StoreOutcome.CREATED
    assert _count(paths, "SELECT COUNT(*) FROM session_links") == 1


def _link_execution_ids(paths: LocalPaths) -> list[str]:
    connection = sqlite3.connect(paths.database)
    try:
        rows = cast(
            "list[tuple[object, ...]]",
            connection.execute(
                "SELECT producing_execution_id FROM session_links"
            ).fetchall(),
        )
    finally:
        connection.close()
    return [cast("str", row[0]) for row in rows]


def _insert_run_row(
    paths: LocalPaths,
    run_id: UUID,
    project_id: UUID,
    org_id: UUID = LOCAL_ORG_ID,
) -> None:
    """Write one Run row directly, in a tenant `create_run` would refuse.

    `create_run` only ever writes into the caller's own tenant and Project, so
    a foreign chain that really resolves end to end has to be built here.
    """
    connection = sqlite3.connect(paths.database)
    try:
        _ = connection.execute(
            "INSERT INTO runs (org_id, project_id, id, plan_id, approval_id, "
            "requester_id, state, research_intent_sha256, created_at, "
            "updated_at, error_type, error_code) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
            (
                str(org_id),
                str(project_id),
                str(run_id),
                str(_uuid7(PLAN_BASE + 0x0E)),
                str(_uuid7(APPROVAL_BASE + 0x0E)),
                str(LOCAL_USER_ID),
                "running",
                INTENT_SHA,
                CREATED_AT.isoformat(),
                CREATED_AT.isoformat(),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _insert_execution_row(
    paths: LocalPaths,
    execution_id: UUID,
    run_id: UUID,
    project_id: UUID,
    org_id: UUID = LOCAL_ORG_ID,
) -> None:
    """Write one execution row directly, bypassing the claiming transaction.

    `start_run` cannot produce an execution outside the caller's own tenant
    and Project, nor one without its Run, so a broken chain has to be
    manufactured here. The schema permits it -- `executions` carries no
    foreign key -- which is exactly why the reader must check.
    """
    connection = sqlite3.connect(paths.database)
    try:
        _ = connection.execute(
            "INSERT INTO executions (org_id, project_id, id, run_id, "
            "execution_isolation, input_sha256, research_intent_sha256, "
            "code_sha256, environment_sha256, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(org_id),
                str(project_id),
                str(execution_id),
                str(run_id),
                IN_PROCESS,
                INPUT_SHA,
                INTENT_SHA,
                SHA_CODE,
                SHA_ENVIRONMENT,
                CREATED_AT.isoformat(),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _delete_session_row(paths: LocalPaths, session_id: UUID) -> None:
    """Remove one Session row, leaving its Run naming an identity nothing answers.

    `create_run` refuses a Run whose Session is not live, so this state cannot
    be reached through the module at all; a lossy restore or an older build is
    what leaves it, and the reader still has to refuse it.
    """
    connection = sqlite3.connect(paths.database)
    try:
        deleted = connection.execute(
            "DELETE FROM sessions WHERE org_id = ? AND id = ?",
            (str(LOCAL_ORG_ID), str(session_id)),
        )
        assert deleted.rowcount == 1
        connection.commit()
    finally:
        connection.close()


def _reproject_session(
    paths: LocalPaths,
    session_id: UUID,
    project_id: UUID,
) -> None:
    """Move one Session row to another Project without touching its Run."""
    connection = sqlite3.connect(paths.database)
    try:
        moved = connection.execute(
            "UPDATE sessions SET project_id = ? WHERE org_id = ? AND id = ?",
            (str(project_id), str(LOCAL_ORG_ID), str(session_id)),
        )
        assert moved.rowcount == 1
        connection.commit()
    finally:
        connection.close()


def _run_session_ids(paths: LocalPaths) -> list[str | None]:
    """Read the Session reference every Run row carries, in insertion order."""
    connection = sqlite3.connect(paths.database)
    try:
        rows = cast(
            "list[tuple[object, ...]]",
            connection.execute("SELECT session_id FROM runs").fetchall(),
        )
    finally:
        connection.close()
    return [cast("str | None", row[0]) for row in rows]


def _delete_execution_row(paths: LocalPaths, execution_id: UUID) -> None:
    """Remove one execution row the way a lossy restore would."""
    connection = sqlite3.connect(paths.database)
    try:
        deleted = connection.execute(
            "DELETE FROM executions WHERE org_id = ? AND id = ?",
            (str(LOCAL_ORG_ID), str(execution_id)),
        )
        assert deleted.rowcount == 1
        connection.commit()
    finally:
        connection.close()


def _delete_run_row(paths: LocalPaths, run_id: UUID) -> None:
    """Remove one Run row, leaving its execution pointing at nothing."""
    connection = sqlite3.connect(paths.database)
    try:
        deleted = connection.execute(
            "DELETE FROM runs WHERE org_id = ? AND id = ?",
            (str(LOCAL_ORG_ID), str(run_id)),
        )
        assert deleted.rowcount == 1
        connection.commit()
    finally:
        connection.close()


def _reproject_execution(
    paths: LocalPaths,
    execution_id: UUID,
    project_id: UUID,
) -> None:
    """Move one execution row to another Project to break the chain."""
    connection = sqlite3.connect(paths.database)
    try:
        _ = connection.execute(
            "UPDATE executions SET project_id = ? WHERE org_id = ? AND id = ?",
            (str(project_id), str(LOCAL_ORG_ID), str(execution_id)),
        )
        connection.commit()
    finally:
        connection.close()


def test_attach_session_refuses_a_version_whose_execution_exists_nowhere(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # `commit_version` refuses such a Version outright now, so the only way
    # one exists is the way this test makes it: a Version published by a real
    # execution whose row later went missing, as an older build or a lossy
    # restore would leave it. Attaching must still refuse to publish a
    # reference that resolves to nothing.
    version = _seed_attachable(store)
    _delete_execution_row(paths, EXECUTION)

    assert store.attach_session(SCOPE, _link(SESSION, version.id)) is (
        StoreOutcome.NOT_FOUND
    )
    assert _count(paths, "SELECT COUNT(*) FROM session_links") == 0


def test_attach_session_records_the_execution_that_produced_the_version(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # The stored reference is derived from the Version row, never from the
    # link the caller passed, so the literal here is the execution identity
    # the Version itself pins.
    version = _seed_attachable(store)

    assert store.attach_session(SCOPE, _link(SESSION, version.id)) is (
        StoreOutcome.CREATED
    )

    assert _link_execution_ids(paths) == ["018f47a0-7b9c-7f01-8def-0123456789ab"]


def test_a_link_cannot_carry_an_execution_reference_a_caller_chose(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # `SessionArtifactLink` has no execution field at all, so the only way
    # the column can be wrong is if this module derived it wrongly.
    version = _seed_attachable(store)
    assert "producing_execution_id" not in SessionArtifactLink.model_fields

    assert store.attach_session(SCOPE, _link(SESSION, version.id)) is (
        StoreOutcome.CREATED
    )

    assert _link_execution_ids(paths) == [str(version.producing_execution_id)]


@pytest.mark.parametrize(
    ("execution_project", "run_project", "keep_run"),
    [
        (SECOND_PROJECT_ID, DEFAULT_PROJECT_ID, True),
        (DEFAULT_PROJECT_ID, SECOND_PROJECT_ID, True),
        (DEFAULT_PROJECT_ID, DEFAULT_PROJECT_ID, False),
    ],
)
def test_attach_session_refuses_a_broken_ownership_chain(
    store: LocalArtifactStore,
    paths: LocalPaths,
    execution_project: UUID,
    run_project: UUID,
    keep_run: bool,
) -> None:
    # A chain that resolves partway is not ownership: an execution filed under
    # another Project, a Run filed under another Project, and an execution
    # whose Run row is gone must all refuse equally.
    #
    # Each chain is whole while the Version commits and is broken exactly one
    # way afterwards, because committing already refuses every one of these
    # shapes. What is under test here is the attaching backstop over rows this
    # module did not write.
    version = _seed_attachable(store)
    run_id = _uuid7(RUN_BASE + ATTACH_SEED_INDEX)
    _reproject_execution(paths, EXECUTION, execution_project)
    _reproject_run(paths, run_id, run_project)
    if not keep_run:
        _delete_run_row(paths, run_id)

    assert store.attach_session(SCOPE, _link(SESSION, version.id)) is (
        StoreOutcome.NOT_FOUND
    )
    assert _count(paths, "SELECT COUNT(*) FROM session_links") == 0


def _reproject_run(paths: LocalPaths, run_id: UUID, project_id: UUID) -> None:
    """Move one Run row to another Project to break the ownership chain."""
    connection = sqlite3.connect(paths.database)
    try:
        _ = connection.execute(
            "UPDATE runs SET project_id = ? WHERE org_id = ? AND id = ?",
            (str(project_id), str(LOCAL_ORG_ID), str(run_id)),
        )
        connection.commit()
    finally:
        connection.close()


def test_an_execution_claimed_by_another_process_authorizes_committing(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # The long-lived parent connection must not serve stale execution state,
    # exactly as it must not serve stale Session state. Both provenance gates
    # are driven from one real second process here: before the child claims
    # the approval the execution answers nothing and committing is refused;
    # after it commits, the same parent connection sees the child's row and
    # both committing and attaching are authorized.
    artifact_id = _uuid7(1)
    _seed_artifact(store, artifact_id)
    _seed_session(store)
    _, approval, run = _seed_claimable(store, ATTACH_SEED_INDEX, session_id=SESSION)
    version = _version(artifact_id, _uuid7(0x11), 1, b"body")
    assert store.commit_version(SCOPE, 0, version, b"body") is (
        StoreOutcome.INVALID_LINEAGE
    )

    claimed = _collect(
        _spawn_claim(ChildClaim(paths.root, _index(run.id), _index(approval.id), 0xF01))
    )

    assert claimed == "consumed"
    assert store.commit_version(SCOPE, 0, version, b"body") is StoreOutcome.CREATED
    assert store.attach_session(SCOPE, _link(SESSION, version.id)) is (
        StoreOutcome.CREATED
    )
    assert _count(paths, "SELECT COUNT(*) FROM session_links") == 1
    assert _link_execution_ids(paths) == ["018f47a0-7b9c-7f01-8def-0123456789ab"]


def _index(identifier: UUID) -> int:
    """Recover the index `_uuid7` encoded, so child arguments stay in sync."""
    return int(str(identifier)[15:18], 16)


def test_concurrent_session_creation_registers_exactly_one(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    requests = [
        ChildSession(paths.root, "create", 0x301, timeout=30.0) for _ in range(4)
    ]

    processes = [_spawn_session(request) for request in requests]
    outcomes = sorted(_collect(process) for process in processes)

    assert outcomes == ["created", "not_found", "not_found", "not_found"]
    assert _count(paths, "SELECT COUNT(*) FROM sessions") == 1
    assert store.session(SCOPE, _uuid7(0x301)) is not None


def test_concurrent_session_archive_reports_one_transition(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _seed_session(store, _uuid7(0x301))
    requests = [
        ChildSession(paths.root, "archive", 0x301, timeout=30.0) for _ in range(4)
    ]

    processes = [_spawn_session(request) for request in requests]
    outcomes = sorted(_collect(process) for process in processes)

    assert outcomes == ["archived", "archived", "archived", "created"]
    archived = store.session(SCOPE, _uuid7(0x301))
    assert archived is not None
    assert archived.archived is True


def test_concurrent_attach_registers_exactly_one_association(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    version = _seed_attachable(store)
    requests = [
        ChildSession(paths.root, "attach", 0xF02, 0x11, timeout=30.0) for _ in range(4)
    ]
    assert version.id == _uuid7(0x11)

    processes = [_spawn_session(request) for request in requests]
    outcomes = sorted(_collect(process) for process in processes)

    assert outcomes == [
        "association_exists",
        "association_exists",
        "association_exists",
        "created",
    ]
    assert _count(paths, "SELECT COUNT(*) FROM session_links") == 1


def test_attach_observes_a_session_archived_by_another_process(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    version = _seed_attachable(store)

    reported = _run_session_child(ChildSession(paths.root, "archive", 0xF02))

    assert reported == "created"
    # The long-lived parent connection must not serve stale Session state.
    assert store.attach_session(SCOPE, _link(SESSION, version.id)) is (
        StoreOutcome.NOT_FOUND
    )


def test_a_session_created_by_another_process_authorizes_the_whole_chain(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # The long-lived parent connection must not serve stale Session state, and
    # the Session is now load-bearing at both ends of the chain. Before the
    # child registers it the parent cannot even queue a Run naming it;
    # afterwards the same connection sees the row, the Run binds, and the
    # Version that Run produces attaches to exactly that Session.
    elsewhere = _uuid7(0x301)
    artifact_id = _uuid7(1)
    _seed_artifact(store, artifact_id)
    plan = _plan(_uuid7(PLAN_BASE + ATTACH_SEED_INDEX))
    approval = _approval(_uuid7(APPROVAL_BASE + ATTACH_SEED_INDEX), plan)
    run = _run(_uuid7(RUN_BASE + ATTACH_SEED_INDEX), plan, approval, elsewhere)
    assert store.create_action_plan(SCOPE, plan) is StoreOutcome.CREATED
    assert store.grant_approval(SCOPE, approval) is StoreOutcome.CREATED
    assert store.create_run(SCOPE, run) is StoreOutcome.NOT_FOUND

    assert _run_session_child(ChildSession(paths.root, "create", 0x301)) == "created"

    assert store.create_run(SCOPE, run) is StoreOutcome.CREATED
    assert store.start_run(SCOPE, _claim(run.id, approval.id, EXECUTION)) is (
        ApprovalOutcome.CONSUMED
    )
    version = _version(artifact_id, _uuid7(0x11), 1, b"body")
    assert store.commit_version(SCOPE, 0, version, b"body") is StoreOutcome.CREATED
    assert store.attach_session(SCOPE, _link(elsewhere, version.id)) is (
        StoreOutcome.CREATED
    )


def test_lifecycle_operations_surface_store_errors_under_a_foreign_write_lock(
    paths: LocalPaths,
) -> None:
    with LocalArtifactStore(paths, timeout=0.05) as blocked:
        _seed_session(blocked, _uuid7(0x301))
        blocker = _spawn_blocker(paths.root)
        try:
            for operation in ("create", "resume", "archive", "attach", "project"):
                with pytest.raises(ArtifactStoreError):
                    _ = _child_outcome(
                        blocked,
                        operation,
                        _uuid7(0x301),
                        _uuid7(0x11),
                    )
        finally:
            _release_blocker(blocker)


def test_a_blocked_child_reports_a_store_error_rather_than_a_raw_failure(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _seed_session(store, _uuid7(0x301))
    blocker = sqlite3.connect(paths.database, isolation_level=None)
    try:
        _ = blocker.execute("BEGIN IMMEDIATE")
        tokens = [
            _run_session_child(ChildSession(paths.root, operation, 0x301, timeout=0.2))
            for operation in ("create", "resume", "archive")
        ]
    finally:
        blocker.close()

    assert tokens == ["ArtifactStoreError", "ArtifactStoreError", "ArtifactStoreError"]
    resumable = store.session(SCOPE, _uuid7(0x301))
    assert resumable is not None
    assert resumable.archived is False
    assert resumable.last_active_at == CREATED_AT


def _seed_started(store: LocalArtifactStore) -> RunRecord:
    """Create one plan, its approval, and one Run, then start that Run."""
    _, approval, run = _seed_claimable(store, 1)
    claim = _claim(run.id, approval.id, _uuid7(EXECUTION_BASE + 1))
    assert store.start_run(SCOPE, claim) is ApprovalOutcome.CONSUMED
    return run


def _output(
    run_id: UUID,
    sequence: int,
    version: ArtifactVersion,
    role: str = "csv",
) -> RunOutputRecord:
    return RunOutputRecord(
        org_id=LOCAL_ORG_ID,
        project_id=DEFAULT_PROJECT_ID,
        run_id=run_id,
        sequence=sequence,
        role=role,
        name=f"{role}-output",
        artifact_id=version.artifact_id,
        artifact_version_id=version.id,
        content_sha256=version.content_sha256,
        created_at=CREATED_AT,
    )


def test_action_plan_binds_one_intent_under_a_derived_digest(
    store: LocalArtifactStore,
) -> None:
    plan = _plan(_uuid7(PLAN_BASE))

    assert store.create_action_plan(SCOPE, plan) is StoreOutcome.CREATED

    stored = store.action_plan(SCOPE, plan.id)
    assert stored == plan
    assert stored is not None
    assert stored.research_intent_sha256 == "e" * 64
    assert stored.plan_sha256 == _expected_plan_digest(SCOPE, plan.id, "e" * 64)
    # A different intent digest is a different plan digest, so an approval
    # granted against one can never describe the other.
    assert _expected_plan_digest(SCOPE, plan.id, "f" * 64) != stored.plan_sha256


def test_action_plan_rejects_a_digest_derived_from_another_intent(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    borrowed = _expected_plan_digest(SCOPE, _uuid7(PLAN_BASE), EDITED_INTENT_SHA)
    forged = _plan(_uuid7(PLAN_BASE), INTENT_SHA, SCOPE, borrowed)

    assert store.create_action_plan(SCOPE, forged) is StoreOutcome.INVALID_LINEAGE

    assert store.action_plan(SCOPE, forged.id) is None
    assert _count(paths, "SELECT COUNT(*) FROM action_plans") == 0


def test_action_plan_identity_cannot_be_reused_or_rewritten(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    original = _plan(_uuid7(PLAN_BASE))
    assert store.create_action_plan(SCOPE, original) is StoreOutcome.CREATED
    rebound = _plan(_uuid7(PLAN_BASE), EDITED_INTENT_SHA)

    assert store.create_action_plan(SCOPE, rebound) is StoreOutcome.NOT_FOUND

    assert store.action_plan(SCOPE, original.id) == original
    assert _count(paths, "SELECT COUNT(*) FROM action_plans") == 1


def test_action_plan_rejects_a_record_contradicting_the_scope(
    store: LocalArtifactStore,
) -> None:
    elsewhere = _plan(_uuid7(PLAN_BASE), INTENT_SHA, SCOPE_B)

    assert store.create_action_plan(SCOPE, elsewhere) is StoreOutcome.NOT_FOUND
    assert store.action_plan(SCOPE, elsewhere.id) is None
    assert store.action_plan(SCOPE_B, elsewhere.id) is None


def test_plans_approvals_and_runs_are_refused_for_an_archived_project(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    plan, approval, run = _seed_claimable(store, 1)
    store.archive_project(SCOPE)
    later_plan = _plan(_uuid7(PLAN_BASE + 2))

    assert store.create_action_plan(SCOPE, later_plan) is StoreOutcome.ARCHIVED
    assert (
        store.grant_approval(SCOPE, _approval(_uuid7(APPROVAL_BASE + 2), plan))
        is StoreOutcome.ARCHIVED
    )
    assert (
        store.create_run(SCOPE, _run(_uuid7(RUN_BASE + 2), plan, approval))
        is StoreOutcome.ARCHIVED
    )
    claim = _claim(run.id, approval.id, _uuid7(EXECUTION_BASE + 1))
    assert store.start_run(SCOPE, claim) is ApprovalOutcome.ARCHIVED
    assert _count(paths, "SELECT COUNT(*) FROM executions") == 0


def test_only_the_plans_own_requester_may_approve_it(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    plan = _plan(_uuid7(PLAN_BASE))
    assert store.create_action_plan(SCOPE, plan) is StoreOutcome.CREATED
    stolen = _approval(_uuid7(APPROVAL_BASE), plan, approver_id=OTHER_USER)

    assert store.grant_approval(SCOPE_OTHER_USER, stolen) is StoreOutcome.NOT_FOUND
    assert store.grant_approval(SCOPE, stolen) is StoreOutcome.NOT_FOUND

    assert store.plan_approval(SCOPE, stolen.id) is None
    assert _count(paths, "SELECT COUNT(*) FROM plan_approvals") == 0


def test_a_plan_carries_at_most_one_approval(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    plan = _plan(_uuid7(PLAN_BASE))
    assert store.create_action_plan(SCOPE, plan) is StoreOutcome.CREATED
    first = _approval(_uuid7(APPROVAL_BASE), plan)
    assert store.grant_approval(SCOPE, first) is StoreOutcome.CREATED
    second = _approval(_uuid7(APPROVAL_BASE + 1), plan)

    assert store.grant_approval(SCOPE, second) is StoreOutcome.ASSOCIATION_EXISTS

    assert store.plan_approval(SCOPE, second.id) is None
    assert _count(paths, "SELECT COUNT(*) FROM plan_approvals") == 1


def test_approval_rejects_a_binding_the_plan_does_not_carry(
    store: LocalArtifactStore,
) -> None:
    plan = _plan(_uuid7(PLAN_BASE))
    assert store.create_action_plan(SCOPE, plan) is StoreOutcome.CREATED
    drifted = _approval(_uuid7(APPROVAL_BASE), plan).model_copy(
        update={"research_intent_sha256": EDITED_INTENT_SHA}
    )

    assert store.grant_approval(SCOPE, drifted) is StoreOutcome.INVALID_LINEAGE
    assert store.plan_approval(SCOPE, drifted.id) is None


def test_approval_refuses_a_pre_consumed_or_expired_record(
    store: LocalArtifactStore,
) -> None:
    plan = _plan(_uuid7(PLAN_BASE))
    assert store.create_action_plan(SCOPE, plan) is StoreOutcome.CREATED
    consumed = _approval(_uuid7(APPROVAL_BASE), plan).model_copy(
        update={"consumed_at": CREATED_AT}
    )
    expired = _approval(_uuid7(APPROVAL_BASE + 1), plan, expires_at=CREATED_AT)

    assert store.grant_approval(SCOPE, consumed) is StoreOutcome.NOT_FOUND
    assert store.grant_approval(SCOPE, expired) is StoreOutcome.NOT_FOUND

    assert store.plan_approval(SCOPE, consumed.id) is None
    assert store.plan_approval(SCOPE, expired.id) is None


def test_start_run_consumes_the_approval_and_claims_the_execution(
    store: LocalArtifactStore,
) -> None:
    _, approval, run = _seed_claimable(store, 1)
    execution_id = _uuid7(EXECUTION_BASE + 1)

    outcome = store.start_run(SCOPE, _claim(run.id, approval.id, execution_id))

    assert outcome is ApprovalOutcome.CONSUMED
    started = store.run(SCOPE, run.id)
    assert started is not None
    assert started.state is RunState.RUNNING
    assert started.updated_at == CLAIMED_AT
    spent = store.plan_approval(SCOPE, approval.id)
    assert spent is not None
    assert spent.consumed_at == CLAIMED_AT
    assert spent.consumed_by_run_id == run.id
    execution = store.execution(SCOPE, execution_id)
    assert execution is not None
    assert execution.run_id == run.id
    assert execution.execution_isolation == "in_process"
    assert execution.input_sha256 == "1" * 64


def test_a_replayed_approval_is_refused_and_creates_no_execution(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    plan, approval, first = _seed_claimable(store, 1)
    second = _run(_uuid7(RUN_BASE + 9), plan, approval)
    assert store.create_run(SCOPE, second) is StoreOutcome.CREATED
    consumed = store.start_run(SCOPE, _claim(first.id, approval.id, _uuid7(0x701)))
    assert consumed is ApprovalOutcome.CONSUMED

    replay = store.start_run(SCOPE, _claim(second.id, approval.id, _uuid7(0x702)))

    assert replay is ApprovalOutcome.REPLAYED
    assert store.execution(SCOPE, _uuid7(0x702)) is None
    assert _count(paths, "SELECT COUNT(*) FROM executions") == 1
    still_queued = store.run(SCOPE, second.id)
    assert still_queued is not None
    assert still_queued.state is RunState.QUEUED
    spent = store.plan_approval(SCOPE, approval.id)
    assert spent is not None
    assert spent.consumed_by_run_id == first.id


def test_an_expired_approval_is_refused_and_creates_no_execution(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    plan = _plan(_uuid7(PLAN_BASE))
    approval = _approval(_uuid7(APPROVAL_BASE), plan, expires_at=CLAIMED_AT)
    run = _run(_uuid7(RUN_BASE), plan, approval)
    assert store.create_action_plan(SCOPE, plan) is StoreOutcome.CREATED
    assert store.grant_approval(SCOPE, approval) is StoreOutcome.CREATED
    assert store.create_run(SCOPE, run) is StoreOutcome.CREATED

    outcome = store.start_run(SCOPE, _claim(run.id, approval.id, _uuid7(0x701)))

    assert outcome is ApprovalOutcome.EXPIRED
    assert _count(paths, "SELECT COUNT(*) FROM executions") == 0
    unspent = store.plan_approval(SCOPE, approval.id)
    assert unspent is not None
    assert unspent.consumed_at is None
    still_queued = store.run(SCOPE, run.id)
    assert still_queued is not None
    assert still_queued.state is RunState.QUEUED


def test_an_edited_intent_field_invalidates_the_approval(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, approval, run = _seed_claimable(store, 1)

    outcome = store.start_run(
        SCOPE,
        _claim(run.id, approval.id, _uuid7(0x701), intent_sha256=EDITED_INTENT_SHA),
    )

    assert outcome is ApprovalOutcome.DIGEST_MISMATCH
    assert _count(paths, "SELECT COUNT(*) FROM executions") == 0
    unspent = store.plan_approval(SCOPE, approval.id)
    assert unspent is not None
    assert unspent.consumed_at is None
    # The original digest still consumes it, proving only the edit was refused.
    assert store.start_run(SCOPE, _claim(run.id, approval.id, _uuid7(0x701))) is (
        ApprovalOutcome.CONSUMED
    )


def test_a_tampered_stored_intent_digest_still_fails_the_derived_plan_digest(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    plan, approval, run = _seed_claimable(store, 1)
    # Rewrite every stored copy of the intent digest so the mutated intent
    # agrees with all of them; only the derived plan digest can catch this.
    connection = sqlite3.connect(paths.database, isolation_level=None)
    try:
        for statement in (
            "UPDATE action_plans SET research_intent_sha256 = ?",
            "UPDATE plan_approvals SET research_intent_sha256 = ?",
            "UPDATE runs SET research_intent_sha256 = ?",
        ):
            _ = connection.execute(statement, (EDITED_INTENT_SHA,))
    finally:
        connection.close()
    rewritten = store.action_plan(SCOPE, plan.id)
    assert rewritten is not None
    assert rewritten.research_intent_sha256 == "f" * 64

    outcome = store.start_run(
        SCOPE,
        _claim(run.id, approval.id, _uuid7(0x701), intent_sha256=EDITED_INTENT_SHA),
    )

    assert outcome is ApprovalOutcome.DIGEST_MISMATCH
    assert _count(paths, "SELECT COUNT(*) FROM executions") == 0
    unspent = store.plan_approval(SCOPE, approval.id)
    assert unspent is not None
    assert unspent.consumed_at is None


def test_only_the_requester_may_claim_an_approval(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, approval, run = _seed_claimable(store, 1)

    outcome = store.start_run(
        SCOPE_OTHER_USER,
        _claim(run.id, approval.id, _uuid7(0x701)),
    )

    assert outcome is ApprovalOutcome.FORBIDDEN
    assert _count(paths, "SELECT COUNT(*) FROM executions") == 0
    unspent = store.plan_approval(SCOPE, approval.id)
    assert unspent is not None
    assert unspent.consumed_at is None


def test_two_runs_cannot_claim_one_execution_id(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, first_approval, first_run = _seed_claimable(store, 1)
    _, second_approval, second_run = _seed_claimable(store, 2)
    shared = _uuid7(EXECUTION_BASE)
    claimed = store.start_run(SCOPE, _claim(first_run.id, first_approval.id, shared))
    assert claimed is ApprovalOutcome.CONSUMED

    outcome = store.start_run(
        SCOPE,
        _claim(second_run.id, second_approval.id, shared),
    )

    assert outcome is ApprovalOutcome.EXECUTION_CLAIMED
    assert _count(paths, "SELECT COUNT(*) FROM executions") == 1
    claimed_execution = store.execution(SCOPE, shared)
    assert claimed_execution is not None
    assert claimed_execution.run_id == first_run.id
    unspent = store.plan_approval(SCOPE, second_approval.id)
    assert unspent is not None
    assert unspent.consumed_at is None


def test_run_outputs_require_a_running_run_and_a_gapless_sequence(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    base, side = _seed_two_versions(store)
    _, approval, run = _seed_claimable(store, 1)

    assert store.append_run_output(SCOPE, _output(run.id, 1, base)) is (
        StoreOutcome.STALE
    )

    claim = _claim(run.id, approval.id, _uuid7(EXECUTION_BASE + 1))
    assert store.start_run(SCOPE, claim) is ApprovalOutcome.CONSUMED
    assert store.append_run_output(SCOPE, _output(run.id, 2, base)) is (
        StoreOutcome.STALE
    )
    assert store.append_run_output(SCOPE, _output(run.id, 1, base)) is (
        StoreOutcome.CREATED
    )
    assert store.append_run_output(SCOPE, _output(run.id, 1, side, "png")) is (
        StoreOutcome.STALE
    )
    assert store.append_run_output(SCOPE, _output(run.id, 3, side, "png")) is (
        StoreOutcome.STALE
    )
    assert store.append_run_output(SCOPE, _output(run.id, 2, side, "png")) is (
        StoreOutcome.CREATED
    )
    assert store.append_run_output(SCOPE, _output(run.id, 3, base, "md")) is (
        StoreOutcome.ASSOCIATION_EXISTS
    )
    assert _count(paths, "SELECT COUNT(*) FROM run_outputs") == 2
    assert [item.sequence for item in store.run_outputs(SCOPE, run.id)] == [1, 2]
    assert [item.role for item in store.run_outputs(SCOPE, run.id)] == ["csv", "png"]


def test_run_outputs_reject_a_version_that_exists_nowhere(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    base, _ = _seed_two_versions(store)
    run = _seed_started(store)
    dangling = _output(run.id, 1, base).model_copy(
        update={"artifact_version_id": _uuid7(0xEE)}
    )

    assert store.append_run_output(SCOPE, dangling) is StoreOutcome.NOT_FOUND
    assert _count(paths, "SELECT COUNT(*) FROM run_outputs") == 0


def test_run_outputs_project_in_sequence_order_after_rewritten_rows(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    base, side = _seed_two_versions(store)
    run = _seed_started(store)
    assert store.append_run_output(SCOPE, _output(run.id, 1, base)) is (
        StoreOutcome.CREATED
    )
    assert store.append_run_output(SCOPE, _output(run.id, 2, side, "png")) is (
        StoreOutcome.CREATED
    )
    # Rewrite the rows in reverse insertion order, as a restored backup might,
    # so physical row order contradicts publication order.
    connection = sqlite3.connect(paths.database, isolation_level=None)
    try:
        rows = cast(
            "list[tuple[object, ...]]",
            connection.execute(
                "SELECT org_id, project_id, run_id, sequence, role, name, "
                "artifact_id, artifact_version_id, content_sha256, created_at "
                "FROM run_outputs ORDER BY sequence DESC"
            ).fetchall(),
        )
        _ = connection.execute("DELETE FROM run_outputs")
        _ = connection.executemany(
            "INSERT INTO run_outputs (org_id, project_id, run_id, sequence, "
            "role, name, artifact_id, artifact_version_id, content_sha256, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
    finally:
        connection.close()

    projected = store.run_outputs(SCOPE, run.id)

    assert len(rows) == 2
    assert [item.sequence for item in projected] == [1, 2]
    assert [item.role for item in projected] == ["csv", "png"]


def test_a_run_reaches_exactly_one_terminal_state(
    store: LocalArtifactStore,
) -> None:
    run = _seed_started(store)

    assert store.finish_run(SCOPE, _completion(run.id, RunState.COMPLETED)) is (
        StoreOutcome.CREATED
    )

    assert store.finish_run(SCOPE, _completion(run.id, RunState.COMPLETED)) is (
        StoreOutcome.STALE
    )
    assert store.finish_run(
        SCOPE,
        _completion(run.id, RunState.FAILED, "ArtifactError"),
    ) is (StoreOutcome.STALE)
    assert store.finish_run(SCOPE, _completion(run.id, RunState.CANCELLED)) is (
        StoreOutcome.STALE
    )
    finished = store.run(SCOPE, run.id)
    assert finished is not None
    assert finished.state is RunState.COMPLETED
    assert finished.updated_at == LATER_AT
    assert finished.error_type is None


def test_a_queued_run_may_be_cancelled_or_failed_but_never_completed(
    store: LocalArtifactStore,
) -> None:
    _, _, first = _seed_claimable(store, 1)
    _, _, second = _seed_claimable(store, 2)

    assert store.finish_run(SCOPE, _completion(first.id, RunState.COMPLETED)) is (
        StoreOutcome.STALE
    )
    assert store.finish_run(SCOPE, _completion(first.id, RunState.CANCELLED)) is (
        StoreOutcome.CREATED
    )
    assert store.finish_run(
        SCOPE,
        _completion(second.id, RunState.FAILED, "PlanApprovalError", "expired"),
    ) is (StoreOutcome.CREATED)

    cancelled = store.run(SCOPE, first.id)
    assert cancelled is not None
    assert cancelled.state is RunState.CANCELLED
    refused = store.run(SCOPE, second.id)
    assert refused is not None
    assert refused.state is RunState.FAILED
    assert refused.error_type == "PlanApprovalError"
    assert refused.error_code == "expired"


def test_failure_marking_requires_an_error_type_and_success_forbids_one(
    store: LocalArtifactStore,
) -> None:
    run = _seed_started(store)

    assert store.finish_run(SCOPE, _completion(run.id, RunState.FAILED)) is (
        StoreOutcome.NOT_FOUND
    )
    assert store.finish_run(
        SCOPE,
        _completion(run.id, RunState.COMPLETED, "ArtifactError"),
    ) is (StoreOutcome.NOT_FOUND)
    assert store.finish_run(SCOPE, _completion(run.id, RunState.RUNNING)) is (
        StoreOutcome.NOT_FOUND
    )
    assert store.finish_run(SCOPE, _completion(run.id, RunState.QUEUED)) is (
        StoreOutcome.NOT_FOUND
    )

    unchanged = store.run(SCOPE, run.id)
    assert unchanged is not None
    assert unchanged.state is RunState.RUNNING


def test_unfinished_runs_lists_only_queued_and_running_runs(
    store: LocalArtifactStore,
) -> None:
    _, first_approval, first = _seed_claimable(store, 1)
    _, _, second = _seed_claimable(store, 2)
    _, third_approval, third = _seed_claimable(store, 3)
    claim = _claim(first.id, first_approval.id, _uuid7(EXECUTION_BASE + 1))
    assert store.start_run(SCOPE, claim) is ApprovalOutcome.CONSUMED
    started = _claim(third.id, third_approval.id, _uuid7(EXECUTION_BASE + 3))
    assert store.start_run(SCOPE, started) is ApprovalOutcome.CONSUMED
    assert store.finish_run(SCOPE, _completion(third.id, RunState.COMPLETED)) is (
        StoreOutcome.CREATED
    )

    unfinished = store.unfinished_runs(SCOPE)

    # Equal creation times fall back to descending identity order.
    assert [item.id for item in unfinished] == [second.id, first.id]
    assert [item.state for item in unfinished] == [RunState.QUEUED, RunState.RUNNING]
    assert store.unfinished_runs(SCOPE_B) == ()


def test_terminal_marking_and_output_recording_survive_project_archival(
    store: LocalArtifactStore,
) -> None:
    base, side = _seed_two_versions(store)
    run = _seed_started(store)
    assert store.append_run_output(SCOPE, _output(run.id, 1, base)) is (
        StoreOutcome.CREATED
    )

    store.archive_project(SCOPE)

    assert store.append_run_output(SCOPE, _output(run.id, 2, side, "png")) is (
        StoreOutcome.CREATED
    )
    assert store.finish_run(
        SCOPE,
        _completion(run.id, RunState.FAILED, "ArtifactError"),
    ) is (StoreOutcome.CREATED)
    truncated = store.run(SCOPE, run.id)
    assert truncated is not None
    assert truncated.state is RunState.FAILED
    assert truncated.error_type == "ArtifactError"
    assert [item.sequence for item in store.run_outputs(SCOPE, run.id)] == [1, 2]
    assert store.execution(SCOPE, _uuid7(EXECUTION_BASE + 1)) is not None


def test_run_and_execution_state_survive_reopening_the_database(
    paths: LocalPaths,
) -> None:
    with LocalArtifactStore(paths) as first:
        run = _seed_started(first)
        assert first.finish_run(
            SCOPE,
            _completion(run.id, RunState.FAILED, "ArtifactCommitError"),
        ) is (StoreOutcome.CREATED)

    with LocalArtifactStore(paths) as second:
        reopened = second.run(SCOPE, run.id)
        assert reopened is not None
        assert reopened.state is RunState.FAILED
        assert reopened.error_type == "ArtifactCommitError"
        execution = second.execution(SCOPE, _uuid7(EXECUTION_BASE + 1))
        assert execution is not None
        assert execution.execution_isolation == "in_process"
        assert second.unfinished_runs(SCOPE) == ()


def test_create_run_records_the_session_that_commissioned_it(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _seed_session(store)

    _, _, run = _seed_claimable(store, 1, session_id=SESSION)

    # The literal is the Session identity, spelled out rather than compared
    # against the same value the seed passed in.
    assert _run_session_ids(paths) == ["018f47a0-7b9c-7f02-8def-0123456789ab"]
    stored = store.run(SCOPE, run.id)
    assert stored is not None
    assert stored.session_id == UUID("018f47a0-7b9c-7f02-8def-0123456789ab")
    assert [item.session_id for item in store.runs(SCOPE)] == [stored.session_id]
    assert [item.session_id for item in store.unfinished_runs(SCOPE)] == [
        stored.session_id
    ]


def test_create_run_accepts_a_run_that_names_no_session(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # Running an analysis outside any Session is a supported local workflow.
    # Requiring the reference would refuse every such run, which is why the
    # column is nullable rather than mandatory.
    _, _, run = _seed_claimable(store, 1)

    assert _run_session_ids(paths) == [None]
    stored = store.run(SCOPE, run.id)
    assert stored is not None
    assert stored.session_id is None


@pytest.mark.parametrize("state", ["absent", "archived", "foreign"])
def test_create_run_refuses_a_session_it_cannot_resolve(
    store: LocalArtifactStore,
    paths: LocalPaths,
    state: str,
) -> None:
    # A Run may name no Session, but it may never name one that is not live
    # here: a recorded reference that answers to nothing is exactly the
    # fabricated parent this module refuses everywhere else.
    if state != "absent":
        _seed_session(store)
    if state == "archived":
        assert store.archive_session(SCOPE, SESSION) is StoreOutcome.CREATED
    if state == "foreign":
        _reproject_session(paths, SESSION, SECOND_PROJECT_ID)
    plan = _plan(_uuid7(PLAN_BASE + 1))
    approval = _approval(_uuid7(APPROVAL_BASE + 1), plan)
    assert store.create_action_plan(SCOPE, plan) is StoreOutcome.CREATED
    assert store.grant_approval(SCOPE, approval) is StoreOutcome.CREATED

    assert store.create_run(
        SCOPE,
        _run(_uuid7(RUN_BASE + 1), plan, approval, SESSION),
    ) is (StoreOutcome.NOT_FOUND)
    assert _count(paths, "SELECT COUNT(*) FROM runs") == 0


def test_the_session_reference_survives_reopening_the_database(
    paths: LocalPaths,
) -> None:
    with LocalArtifactStore(paths) as first:
        _seed_session(first)
        _, _, run = _seed_claimable(first, 1, session_id=SESSION)

    with LocalArtifactStore(paths) as second:
        reopened = second.run(SCOPE, run.id)
        assert reopened is not None
        assert reopened.session_id == UUID("018f47a0-7b9c-7f02-8def-0123456789ab")


def _seed_input_execution(
    store: LocalArtifactStore,
    index: int = INPUT_SEED_INDEX,
    execution_id: UUID = EXECUTION,
    scope: ArtifactScope = SCOPE,
) -> UUID:
    """Start one Run whose execution pins the digests of the test documents.

    The pinned intent digest has to travel through the plan and its approval,
    because the claiming transaction checks all four against each other, so
    this seeds a whole chain rather than writing an execution row directly.
    """
    plan = _plan(_uuid7(PLAN_BASE + index), INTENT_DOCUMENT_SHA, scope)
    approval = _approval(_uuid7(APPROVAL_BASE + index), plan)
    run = _run(_uuid7(RUN_BASE + index), plan, approval)
    assert store.create_action_plan(scope, plan) is StoreOutcome.CREATED
    assert store.grant_approval(scope, approval) is StoreOutcome.CREATED
    assert store.create_run(scope, run) is StoreOutcome.CREATED
    claim = RunClaim(
        run_id=run.id,
        approval_id=approval.id,
        research_intent_sha256=INTENT_DOCUMENT_SHA,
        execution=ExecutionRecord(
            id=execution_id,
            org_id=scope.org_id,
            project_id=scope.project_id,
            run_id=run.id,
            execution_isolation=IN_PROCESS,
            input_sha256=INPUT_DOCUMENT_SHA,
            research_intent_sha256=INTENT_DOCUMENT_SHA,
            code_sha256=SHA_CODE,
            environment_sha256=SHA_ENVIRONMENT,
            created_at=CREATED_AT,
        ),
        started_at=CLAIMED_AT,
    )
    assert store.start_run(scope, claim) is ApprovalOutcome.CONSUMED
    return execution_id


def _record_documents(store: LocalArtifactStore, execution_id: UUID) -> None:
    """Persist both canonical documents against one execution."""
    assert store.record_execution_input(
        SCOPE,
        execution_id,
        ExecutionInputKind.RESEARCH_INTENT,
        INTENT_DOCUMENT,
    ) is (StoreOutcome.CREATED)
    assert store.record_execution_input(
        SCOPE,
        execution_id,
        ExecutionInputKind.SCIENTIFIC_INPUT,
        INPUT_DOCUMENT,
    ) is (StoreOutcome.CREATED)


def test_execution_inputs_round_trip_the_canonical_bytes(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    execution_id = _seed_input_execution(store)

    _record_documents(store, execution_id)

    intent = store.execution_input(
        SCOPE,
        execution_id,
        ExecutionInputKind.RESEARCH_INTENT,
    )
    source = store.execution_input(
        SCOPE,
        execution_id,
        ExecutionInputKind.SCIENTIFIC_INPUT,
    )
    assert intent == b'{"question":"does the 430 nm band persist?"}'
    assert source == b'{"spectrum":[400,410,420,430]}'
    # The whole point: a reader holding only these bytes recomputes the two
    # digests the execution pinned, which is what a pack could not do before.
    stored = store.execution(SCOPE, execution_id)
    assert stored is not None
    assert hashlib.sha256(intent).hexdigest() == stored.research_intent_sha256
    assert hashlib.sha256(source).hexdigest() == stored.input_sha256
    assert _count(paths, "SELECT COUNT(*) FROM execution_inputs") == 2


def test_an_unrecorded_execution_input_reads_as_absent(
    store: LocalArtifactStore,
) -> None:
    execution_id = _seed_input_execution(store)

    assert (
        store.execution_input(
            SCOPE,
            execution_id,
            ExecutionInputKind.RESEARCH_INTENT,
        )
        is None
    )


@pytest.mark.parametrize(
    "kind",
    [ExecutionInputKind.RESEARCH_INTENT, ExecutionInputKind.SCIENTIFIC_INPUT],
)
def test_execution_input_refuses_bytes_that_miss_the_pinned_digest(
    store: LocalArtifactStore,
    paths: LocalPaths,
    kind: ExecutionInputKind,
) -> None:
    # Bytes that do not hash to the digest the execution already pinned are a
    # corruption, not a second answer, and neither the row nor the blob may
    # survive. The refusal also carries nothing of the payload: it is a closed
    # outcome, and the rejected document appears nowhere on disk.
    execution_id = _seed_input_execution(store)

    outcome = store.record_execution_input(SCOPE, execution_id, kind, FORGED_DOCUMENT)

    assert outcome is StoreOutcome.INVALID_LINEAGE
    assert str(outcome) == "invalid_lineage"
    assert FORGED_DOCUMENT.decode() not in str(outcome)
    assert _count(paths, "SELECT COUNT(*) FROM execution_inputs") == 0
    assert _blob_files(paths) == []
    assert store.execution_input(SCOPE, execution_id, kind) is None


def test_the_two_kinds_cannot_be_swapped_for_each_other(
    store: LocalArtifactStore,
) -> None:
    # Each kind is checked against its own pinned digest, so the intent bytes
    # are not accepted as the scientific input and the reverse.
    execution_id = _seed_input_execution(store)

    assert store.record_execution_input(
        SCOPE,
        execution_id,
        ExecutionInputKind.RESEARCH_INTENT,
        INPUT_DOCUMENT,
    ) is (StoreOutcome.INVALID_LINEAGE)
    assert store.record_execution_input(
        SCOPE,
        execution_id,
        ExecutionInputKind.SCIENTIFIC_INPUT,
        INTENT_DOCUMENT,
    ) is (StoreOutcome.INVALID_LINEAGE)


def test_execution_input_is_recorded_at_most_once_per_kind(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    execution_id = _seed_input_execution(store)
    _record_documents(store, execution_id)

    assert store.record_execution_input(
        SCOPE,
        execution_id,
        ExecutionInputKind.RESEARCH_INTENT,
        INTENT_DOCUMENT,
    ) is (StoreOutcome.ASSOCIATION_EXISTS)
    assert _count(paths, "SELECT COUNT(*) FROM execution_inputs") == 2


def test_the_primary_key_refuses_a_second_record_on_its_own(
    store: LocalArtifactStore,
) -> None:
    # The application-level lookup is not the only guard. Writing the row
    # directly, exactly as the store would, must still collide.
    execution_id = _seed_input_execution(store)
    _record_documents(store, execution_id)

    with pytest.raises(sqlite3.IntegrityError):
        _ = _store_connection(store).execute(
            "INSERT INTO execution_inputs (org_id, project_id, execution_id, "
            "kind, content_sha256, size_bytes, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(LOCAL_ORG_ID),
                str(DEFAULT_PROJECT_ID),
                str(execution_id),
                "research_intent",
                INTENT_DOCUMENT_SHA,
                len(INTENT_DOCUMENT),
                CREATED_AT.isoformat(),
            ),
        )


@pytest.mark.parametrize("break_chain", ["absent", "reprojected", "run_missing"])
def test_execution_input_refuses_an_ownership_chain_that_does_not_resolve(
    store: LocalArtifactStore,
    paths: LocalPaths,
    break_chain: str,
) -> None:
    # Persisting bytes for an execution this Project does not own would file
    # research content under a chain that answers for nothing.
    execution_id = _seed_input_execution(store)
    if break_chain == "reprojected":
        _reproject_execution(paths, execution_id, SECOND_PROJECT_ID)
    if break_chain == "run_missing":
        _delete_run_row(paths, _uuid7(RUN_BASE + INPUT_SEED_INDEX))
    target = _uuid7(0xABC) if break_chain == "absent" else execution_id

    assert store.record_execution_input(
        SCOPE,
        target,
        ExecutionInputKind.RESEARCH_INTENT,
        INTENT_DOCUMENT,
    ) is (StoreOutcome.NOT_FOUND)
    assert _count(paths, "SELECT COUNT(*) FROM execution_inputs") == 0
    assert _blob_files(paths) == []


def _input_rows(paths: LocalPaths) -> list[tuple[str, str, int]]:
    """Read every recorded input as (kind, digest, size), in kind order."""
    connection = sqlite3.connect(paths.database)
    try:
        rows = cast(
            "list[tuple[object, ...]]",
            connection.execute(
                "SELECT kind, content_sha256, size_bytes FROM execution_inputs "
                "ORDER BY kind"
            ).fetchall(),
        )
    finally:
        connection.close()
    return [
        (cast("str", row[0]), cast("str", row[1]), cast("int", row[2])) for row in rows
    ]


def test_a_recorded_input_row_describes_the_bytes_it_addresses(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # The row is the only description of an object a reader inspecting the data
    # root has, so its digest and size must agree with the payload rather than
    # merely exist.
    execution_id = _seed_input_execution(store)

    _record_documents(store, execution_id)

    assert _input_rows(paths) == [
        ("research_intent", INTENT_DOCUMENT_SHA, len(INTENT_DOCUMENT)),
        ("scientific_input", INPUT_DOCUMENT_SHA, len(INPUT_DOCUMENT)),
    ]
    assert [size for _, _, size in _input_rows(paths)] == [44, 30]


def test_a_refused_input_record_deletes_no_content(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # The failure path deletes nothing; reclamation lives only in
    # `sweep_unreferenced_blobs`. Compensating here would race a writer that
    # published the same content first -- content addressing gives them one
    # file -- and would destroy bytes that writer has already committed.
    execution_id = _seed_input_execution(store)
    occupied = _blob_path(paths, INTENT_DOCUMENT)
    occupied.parent.mkdir(parents=True, exist_ok=True)
    _ = occupied.write_bytes(FORGED_DOCUMENT)

    with pytest.raises(BlobIntegrityError):
        _ = store.record_execution_input(
            SCOPE,
            execution_id,
            ExecutionInputKind.RESEARCH_INTENT,
            INTENT_DOCUMENT,
        )

    assert occupied.read_bytes() == FORGED_DOCUMENT
    assert _count(paths, "SELECT COUNT(*) FROM execution_inputs") == 0
    # The connection is usable afterwards, so the escape rolled back on its way
    # out rather than leaving a transaction open.
    assert store.record_execution_input(
        SCOPE,
        execution_id,
        ExecutionInputKind.SCIENTIFIC_INPUT,
        INPUT_DOCUMENT,
    ) is (StoreOutcome.CREATED)


def test_an_unwritable_blob_directory_leaves_no_transaction_open(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # Publishing content is the one step of this write that raises something
    # `_transact` does not normalize, so the escape has to roll back on its own
    # way out. If it did not, the connection would still be inside a
    # transaction and the very next write would fail on `BEGIN IMMEDIATE`
    # rather than succeed.
    execution_id = _seed_input_execution(store)
    paths.blobs.chmod(0o500)
    try:
        with pytest.raises(BlobWriteError):
            _ = store.record_execution_input(
                SCOPE,
                execution_id,
                ExecutionInputKind.RESEARCH_INTENT,
                INTENT_DOCUMENT,
            )
    finally:
        paths.blobs.chmod(0o700)

    assert store.record_execution_input(
        SCOPE,
        execution_id,
        ExecutionInputKind.RESEARCH_INTENT,
        INTENT_DOCUMENT,
    ) is (StoreOutcome.CREATED)
    # The refused attempt wrote nothing at all, so this is the only row.
    assert _count(paths, "SELECT COUNT(*) FROM execution_inputs") == 1


def test_execution_inputs_are_refused_and_hidden_for_an_archived_project(
    store: LocalArtifactStore,
) -> None:
    # These bytes are research content, so archival gates them exactly as it
    # gates Version content rather than as it leaves Run records readable.
    execution_id = _seed_input_execution(store)
    _record_documents(store, execution_id)
    store.archive_project(SCOPE)

    assert (
        store.execution_input(
            SCOPE,
            execution_id,
            ExecutionInputKind.RESEARCH_INTENT,
        )
        is None
    )
    assert store.record_execution_input(
        SCOPE,
        execution_id,
        ExecutionInputKind.SCIENTIFIC_INPUT,
        INPUT_DOCUMENT,
    ) is (StoreOutcome.ARCHIVED)


def test_a_tampered_execution_input_reads_as_absent(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # Content that no longer hashes to the digest recorded for it is withheld.
    # A pack then reports the digest as self-reported, which is the honest
    # outcome; handing the bytes back would ship a document that contradicts
    # the provenance printed beside it.
    execution_id = _seed_input_execution(store)
    _record_documents(store, execution_id)
    _ = _blob_path(paths, INTENT_DOCUMENT).write_bytes(FORGED_DOCUMENT)

    assert (
        store.execution_input(
            SCOPE,
            execution_id,
            ExecutionInputKind.RESEARCH_INTENT,
        )
        is None
    )
    # The other kind is a separate object and is unaffected.
    assert (
        store.execution_input(
            SCOPE,
            execution_id,
            ExecutionInputKind.SCIENTIFIC_INPUT,
        )
        == b'{"spectrum":[400,410,420,430]}'
    )


def test_an_execution_input_whose_object_is_gone_reads_as_absent(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # A row without its object is evidence that is simply missing, and it must
    # read as absence rather than raise out of a read path.
    execution_id = _seed_input_execution(store)
    _record_documents(store, execution_id)
    _blob_path(paths, INTENT_DOCUMENT).unlink()

    assert (
        store.execution_input(
            SCOPE,
            execution_id,
            ExecutionInputKind.RESEARCH_INTENT,
        )
        is None
    )


def test_execution_inputs_are_readable_only_in_their_own_project(
    store: LocalArtifactStore,
) -> None:
    # Research content is filed under exactly one Project, and a reader
    # addressing another one gets absence rather than the bytes.
    execution_id = _seed_input_execution(store)
    _record_documents(store, execution_id)

    assert (
        store.execution_input(
            SCOPE_B,
            execution_id,
            ExecutionInputKind.RESEARCH_INTENT,
        )
        is None
    )


def test_sweeping_never_reclaims_a_persisted_execution_input(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # The canonical inputs share the blob directory with Version content and no
    # Version row references them, so a sweep that only consulted
    # `artifact_versions` would delete exactly the evidence this table exists
    # to keep.
    execution_id = _seed_input_execution(store)
    _record_documents(store, execution_id)
    orphan = b"referenced by nothing at all"
    _write_orphan_blob(paths, orphan)

    removed = store.sweep_unreferenced_blobs(min_age_seconds=0.0)

    assert removed == (hashlib.sha256(orphan).hexdigest(),)
    assert (
        store.execution_input(
            SCOPE,
            execution_id,
            ExecutionInputKind.RESEARCH_INTENT,
        )
        == b'{"question":"does the 430 nm band persist?"}'
    )
    assert sorted(item.name for item in _blob_files(paths)) == sorted(
        [INTENT_DOCUMENT_SHA, INPUT_DOCUMENT_SHA]
    )


def _write_orphan_blob(paths: LocalPaths, payload: bytes) -> None:
    """Place one content file no durable row refers to."""
    path = _blob_path(paths, payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_bytes(payload)


def test_recording_an_input_adopts_bytes_that_are_already_published(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # Publication is idempotent and adoption is automatic, exactly as it is for
    # Version content: an identical object left by an earlier crash is adopted
    # rather than rewritten or refused.
    execution_id = _seed_input_execution(store)
    _write_orphan_blob(paths, INTENT_DOCUMENT)

    assert store.record_execution_input(
        SCOPE,
        execution_id,
        ExecutionInputKind.RESEARCH_INTENT,
        INTENT_DOCUMENT,
    ) is (StoreOutcome.CREATED)
    assert (
        store.execution_input(
            SCOPE,
            execution_id,
            ExecutionInputKind.RESEARCH_INTENT,
        )
        == b'{"question":"does the 430 nm band persist?"}'
    )


def test_recording_an_input_under_a_foreign_write_lock_surfaces_a_store_error(
    paths: LocalPaths,
) -> None:
    with LocalArtifactStore(paths, timeout=0.05) as blocked:
        execution_id = _seed_input_execution(blocked)
        blocker = sqlite3.connect(paths.database, isolation_level=None)
        try:
            _ = blocker.execute("BEGIN IMMEDIATE")
            with pytest.raises(ArtifactStoreError):
                _ = blocked.record_execution_input(
                    SCOPE,
                    execution_id,
                    ExecutionInputKind.RESEARCH_INTENT,
                    INTENT_DOCUMENT,
                )
        finally:
            blocker.close()
    # A refused transaction publishes nothing, so no orphan is left behind.
    assert _blob_files(paths) == []


def test_concurrent_input_records_register_exactly_one(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    execution_id = _seed_input_execution(store)
    requests = [ChildInput(paths.root, _index(execution_id)) for _ in range(4)]

    processes = [_spawn_input(request) for request in requests]
    outcomes = sorted(_collect(process) for process in processes)

    assert outcomes == [
        "association_exists",
        "association_exists",
        "association_exists",
        "created",
    ]
    assert _count(paths, "SELECT COUNT(*) FROM execution_inputs") == 1
    assert (
        store.execution_input(
            SCOPE,
            execution_id,
            ExecutionInputKind.RESEARCH_INTENT,
        )
        == b'{"question":"does the 430 nm band persist?"}'
    )


def test_an_input_recorded_by_another_process_is_readable_here(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # The long-lived parent connection must not serve a stale answer for the
    # canonical bytes any more than it may for Sessions or executions.
    execution_id = _seed_input_execution(store)
    assert (
        store.execution_input(
            SCOPE,
            execution_id,
            ExecutionInputKind.RESEARCH_INTENT,
        )
        is None
    )

    reported = _collect(_spawn_input(ChildInput(paths.root, _index(execution_id))))

    assert reported == "created"
    assert (
        store.execution_input(
            SCOPE,
            execution_id,
            ExecutionInputKind.RESEARCH_INTENT,
        )
        == b'{"question":"does the 430 nm band persist?"}'
    )


def test_a_rejecting_outcome_rolls_back_everything_it_already_wrote(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # Every production transition writes last, but the compare-and-swap inside
    # `_apply_claim` returns a rejection *after* an UPDATE and an INSERT. The
    # guarantee that only the success value commits is therefore load-bearing
    # and is asserted here directly rather than inferred from callers.
    plan = _plan(_uuid7(PLAN_BASE))
    connection = _store_connection(store)

    def write_then_reject() -> StoreOutcome:
        _ = connection.execute(
            "INSERT INTO action_plans (org_id, project_id, id, requester_id, "
            "research_intent_sha256, plan_sha256, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(plan.org_id),
                str(plan.project_id),
                str(plan.id),
                str(plan.requester_id),
                plan.research_intent_sha256,
                plan.plan_sha256,
                plan.created_at.isoformat(),
            ),
        )
        return StoreOutcome.STALE

    outcome = _unbound_transact()(
        store,
        write_then_reject,
        StoreOutcome.CREATED,
        StoreOutcome.NOT_FOUND,
    )

    assert outcome is StoreOutcome.STALE
    assert store.action_plan(SCOPE, plan.id) is None
    assert _count(paths, "SELECT COUNT(*) FROM action_plans") == 0


def _consumption(store: LocalArtifactStore, approval_id: UUID) -> datetime | None:
    """Return when one approval was consumed, or None while it is unspent."""
    stored = store.plan_approval(SCOPE, approval_id)
    assert stored is not None
    return stored.consumed_at


def test_concurrent_claims_consume_one_approval_exactly_once(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    plan, approval, _ = _seed_claimable(store, 1)
    contenders = [RUN_BASE + 1, *(RUN_BASE + 0x10 + offset for offset in range(3))]
    for index in contenders[1:]:
        assert (
            store.create_run(SCOPE, _run(_uuid7(index), plan, approval))
            is StoreOutcome.CREATED
        )
    requests = [
        ChildClaim(
            paths.root,
            index,
            APPROVAL_BASE + 1,
            EXECUTION_BASE + 0x10 + offset,
        )
        for offset, index in enumerate(contenders)
    ]

    processes = [_spawn_claim(request) for request in requests]
    outcomes = sorted(_collect(process) for process in processes)

    assert outcomes == ["consumed", "replayed", "replayed", "replayed"]
    assert _count(paths, "SELECT COUNT(*) FROM executions") == 1
    spent = store.plan_approval(SCOPE, approval.id)
    assert spent is not None
    assert spent.consumed_at is not None
    running = [
        item for item in store.unfinished_runs(SCOPE) if item.state.value == "running"
    ]
    assert len(running) == 1
    assert running[0].id == spent.consumed_by_run_id


def test_concurrent_claims_fence_one_produced_execution_id(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    seeded = [_seed_claimable(store, index) for index in range(1, 5)]
    shared = EXECUTION_BASE
    requests = [
        ChildClaim(paths.root, RUN_BASE + index, APPROVAL_BASE + index, shared)
        for index in range(1, 5)
    ]

    processes = [_spawn_claim(request) for request in requests]
    outcomes = sorted(_collect(process) for process in processes)

    assert outcomes == [
        "consumed",
        "execution_claimed",
        "execution_claimed",
        "execution_claimed",
    ]
    assert _count(paths, "SELECT COUNT(*) FROM executions") == 1
    claimed = store.execution(SCOPE, _uuid7(shared))
    assert claimed is not None
    spent = [
        approval
        for _, approval, _ in seeded
        if _consumption(store, approval.id) is not None
    ]
    assert len(spent) == 1
    assert _count(paths, "SELECT COUNT(*) FROM runs") == 4


REVIEW_BASE: Final = 0x800
FINDING_BASE: Final = 0x900


def _review(run: RunRecord, index: int) -> ReviewRecord:
    """Build one Review pinned to the execution a started Run claimed."""
    executions = (_uuid7(EXECUTION_BASE + 1),)
    return ReviewRecord(
        id=_uuid7(REVIEW_BASE + index),
        org_id=SCOPE.org_id,
        project_id=SCOPE.project_id,
        source_run_id=run.id,
        state=ReviewState.QUEUED,
        pinned_input_sha256=LocalArtifactStore.pinned_input_digest(
            SCOPE, run.id, (), executions
        ),
        pinned_artifact_version_ids=(),
        pinned_execution_ids=executions,
        created_at=CREATED_AT,
        updated_at=CREATED_AT,
    )


def _review_finding(review: ReviewRecord, index: int) -> ReviewFindingRecord:
    """Build one open finding bound to a Review's own pinned evidence."""
    return ReviewFindingRecord(
        id=_uuid7(FINDING_BASE + index),
        org_id=review.org_id,
        project_id=review.project_id,
        review_id=review.id,
        sequence=index,
        rule_id=ReviewRuleId.RV03,
        verdict=ReviewVerdict.INCONCLUSIVE,
        status=FindingStatus.OPEN,
        code="rv03_evidence_unavailable",
        message="no pinned content was readable",
        artifact_version_ids=(),
        execution_ids=review.pinned_execution_ids,
        created_at=CREATED_AT,
    )


def test_review_tables_are_strict_and_survive_reopening(paths: LocalPaths) -> None:
    with LocalArtifactStore(paths):
        pass
    with LocalArtifactStore(paths):
        pass
    connection = sqlite3.connect(paths.database)
    try:
        rows = cast(
            "list[tuple[str, str]]",
            connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'table' "
                "AND name IN ('reviews', 'review_findings') ORDER BY name"
            ).fetchall(),
        )
    finally:
        connection.close()

    assert [name for name, _ in rows] == ["review_findings", "reviews"]
    assert all(statement.rstrip().endswith("STRICT") for _, statement in rows)


def test_a_rejected_review_transition_rolls_back_its_own_write(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    run = _seed_started(store)
    review = _review(run, 1)
    connection = _store_connection(store)

    def write_then_reject() -> StoreOutcome:
        _ = connection.execute(
            "INSERT INTO reviews (org_id, project_id, id, source_run_id, state, "
            "pinned_input_sha256, pinned_artifact_version_ids, "
            "pinned_execution_ids, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, '[]', '[]', ?, ?)",
            (
                str(review.org_id),
                str(review.project_id),
                str(review.id),
                str(review.source_run_id),
                review.state.value,
                review.pinned_input_sha256,
                review.created_at.isoformat(),
                review.updated_at.isoformat(),
            ),
        )
        return StoreOutcome.STALE

    outcome = _unbound_transact()(
        store,
        write_then_reject,
        StoreOutcome.CREATED,
        StoreOutcome.NOT_FOUND,
    )

    assert outcome is StoreOutcome.STALE
    assert store.review(SCOPE, review.id) is None
    assert _count(paths, "SELECT COUNT(*) FROM reviews") == 0


def test_one_rule_may_be_recorded_once_per_review(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    run = _seed_started(store)
    review = _review(run, 2)
    assert store.open_review(SCOPE, review) is StoreOutcome.CREATED
    assert store.start_review(SCOPE, review.id, LATER_AT) is StoreOutcome.CREATED
    submission = ReviewSubmission(
        review_id=review.id,
        submitted_at=LATER_AT,
        findings=(_review_finding(review, 1),),
    )
    assert store.submit_review_findings(SCOPE, submission) is StoreOutcome.CREATED

    repeated = ReviewSubmission(
        review_id=review.id,
        submitted_at=LATEST_AT,
        findings=(
            _review_finding(review, 1).model_copy(
                update={"id": _uuid7(FINDING_BASE + 0x20)}
            ),
        ),
    )

    assert (
        store.submit_review_findings(SCOPE, repeated) is StoreOutcome.ASSOCIATION_EXISTS
    )
    assert _count(paths, "SELECT COUNT(*) FROM review_findings") == 1


def test_a_review_over_an_unknown_run_is_refused_without_a_write(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    run = _seed_started(store)
    unknown = _uuid7(RUN_BASE + 0x40)
    orphan = _review(run, 3).model_copy(
        update={
            "source_run_id": unknown,
            "pinned_input_sha256": LocalArtifactStore.pinned_input_digest(
                SCOPE,
                unknown,
                (),
                (_uuid7(EXECUTION_BASE + 1),),
            ),
        }
    )

    assert store.open_review(SCOPE, orphan) is StoreOutcome.NOT_FOUND
    assert _count(paths, "SELECT COUNT(*) FROM reviews") == 0


def test_review_reads_survive_project_archival(store: LocalArtifactStore) -> None:
    run = _seed_started(store)
    review = _review(run, 4)
    assert store.open_review(SCOPE, review) is StoreOutcome.CREATED
    store.archive_project(SCOPE)

    stored = store.review(SCOPE, review.id)

    assert stored is not None
    assert stored.state is ReviewState.QUEUED
    assert store.open_review(SCOPE, _review(run, 5)) is StoreOutcome.ARCHIVED
