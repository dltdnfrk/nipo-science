"""Wire the deterministic science package onto immutable Artifact Versions.

One local run takes a `ResearchIntent` plus one scientific input, executes
`science_workbench_science.analyze_probe`, and persists the produced outputs as
immutable Artifact Versions through the shared Artifact subsystem.

Approval gate
-------------
`run_analysis` publishes nothing without an approved plan. An `ActionPlan` is
immutable and binds exactly one complete `ResearchIntent` by its canonical
digest; its own digest is derived by the store from that binding, so the two
cannot be separated. Its approval is one-use: `start_run` consumes it, claims
the produced-execution identity, and moves the Run out of `queued` in a single
transaction, so an approval is never spent without an execution and an
execution never begins without spending its approval.

The digest passed to `start_run` is recomputed from the live `ResearchIntent`
about to shape the bytes, never read back from a stored row. Changing any
intent field therefore changes that digest, disagrees with the plan and the
approval, and refuses the run with `ApprovalOutcome.DIGEST_MISMATCH` before any
Artifact identity exists. The same comparison rejects an expired approval, a
replayed one, and an approver who is not the plan's own requester, each leaving
zero Artifacts, zero Versions, and zero blobs behind.

Corrections are Versions, never overwrites
------------------------------------------
`run_analysis` mints a fresh Artifact per output and commits Version 1.
`correct_analysis` publishes onto the *same* Artifacts, compare-and-swapping
against the exact base Version its caller pinned, so a corrected chain is
Version 2 and the Version it corrects keeps its identifier, its bytes, and its
digest. Both paths funnel through one `_execute`, so a correction cannot drift
into a weaker version of the approval, fencing, ordering, or failure contract.
A correction is a full run: it needs its own produced-execution identity and
its own one-use approval, and it is followed by a new Review rather than
amending the earlier one.

Scope and disclosed gaps
------------------------
This slice covers the `csv -> png -> markdown -> ledger` segment of the
normative `dry_lab.ordered_chain`. Two deviations are disclosed rather than
hidden, and are recorded in the ledger itself:

- `isolated_python` (chain entry 4) is **bypassed**. `analyze_probe` runs in the
  producer's own interpreter with no subprocess, no sandbox, and no resource
  fence. The ledger records `"execution_isolation": "in_process"` so a reader
  never has to infer this from absence.
- `skill_content_hashes` is empty **by construction**: no Skill participates in
  a local deterministic run, so there is no Skill content to pin. The ledger
  states this explicitly instead of leaving an unexplained empty tuple.

Failure model
-------------
Four immutable Versions cannot be committed in one transaction, so truncation is
made *detectable* rather than impossible. Each run is recorded twice: as durable
`runs`, `executions`, and `run_outputs` rows, which are the authority and make a
truncated chain queryable, and as a mirrored JSON document under
`<root>/runs/<execution_id>.json`.

The mirror is kept, not replaced. Its whole value is that it survives the
failure of the thing it mirrors: when the database is itself what failed --
blocked write lock, restored-from-backup file, lost WAL -- the file still
distinguishes a complete chain from a dead one, and folding truncation
detection into the single durable object whose partial failure it exists to
detect would be strictly weaker. The row is written before the file at every
step, so the authority is never behind its mirror.

Both records are created before anything is published, updated after every
committed output, and closed as `completed` only once the ledger commits. Any
escaping exception marks both `failed` with a non-secret reason and exactly the
outputs committed so far; the row is attempted first and its own failure is
suppressed so a bookkeeping error can never replace the real cause or leave the
run unmarked in both records. The produced-execution id is fenced twice: by the
`executions` primary key inside the claiming transaction, and by the `O_EXCL`
creation of the mirror. One execution id publishes at most one chain, and a
retry must use a new one.

Every payload is registered with `OutputWatcher` before an Artifact identity
exists and before `ArtifactService` creates its Version, so the producer never
chooses an object key. Provenance is pinned from real values: the canonical
digest of the scientific input, the canonical digest of the `ResearchIntent` as
defined by `research_intent.py`, the produced-execution id, and content digests
of the interpreter environment and of the deterministic science sources that
shaped the bytes.

The bytes behind the first two digests are persisted as well, not only their
digests. `_persist_inputs` hands the store the exact serializations the digests
were taken over, the store refuses anything that does not hash to what the
execution already pinned, and a refusal fails the run before a single output is
published. Without them an Export Pack can print `research_intent_sha256` and
`input_sha256` but cannot let a reader recompute either, which is the weakest
point of an otherwise checkable record.

Sessions
--------
`assemble_artifact_runtime` takes an optional `session_id`, beside the Project
and the produced-execution identity it already binds. Every Run the runtime
queues records it, and the durable ownership chain then reaches from a
published Version through its execution and Run to that Session, which is what
`attach_session` checks. When none is given the analysis still runs -- working
outside a Session is a supported local workflow -- and the Versions it publishes
can be associated with no Session at all, because the store refuses on the
absence rather than reading it as agreement.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from functools import cache
from importlib.metadata import version as distribution_version
from importlib.util import find_spec
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast, final

from services.api.artifacts.memory_recovery import InMemoryArtifactRecovery
from services.api.artifacts.models import ArtifactError, ArtifactScope, VersionDraft
from services.api.artifacts.runtime import SystemClock, Uuid7Factory
from services.api.artifacts.service import ArtifactService
from services.api.artifacts.store_contract import ArtifactStoreError, StoreOutcome
from services.api.artifacts.watcher import OutputWatcher

from science_workbench_science import OutcomeStatus, analyze_probe

from .config import (
    DEFAULT_PROJECT_ID,
    LOCAL_ORG_ID,
    LOCAL_RUNTIME_ADAPTER_ID,
    LOCAL_RUNTIME_CONNECTION_ID,
    LOCAL_USER_ID,
)
from .store import (
    ActionPlanRecord,
    ApprovalOutcome,
    ExecutionInputKind,
    ExecutionRecord,
    LocalArtifactStore,
    PlanApprovalRecord,
    RunClaim,
    RunCompletion,
    RunOutputRecord,
    RunRecord,
    RunState,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from uuid import UUID

    from services.api.artifacts.models import ArtifactRecord, ArtifactVersion

    from science_workbench_science import (
        AnalysisIssue,
        EvidenceRecord,
        HypothesisRecord,
        NormalizedSpectrum,
        ProbeAnalysis,
        ProbeInput,
        ResearchIntent,
    )

    from .config import LocalPaths

SIGNING_KEY_NAME: Final = "download-signing.key"
SIGNING_KEY_BYTES: Final = 32
OWNER_ONLY_MODE: Final = 0o600

RUNS_DIRECTORY: Final = "runs"
# v2 adds the Run, plan, and approval identities that authorized the chain.
RUN_RECORD_SCHEMA: Final = "nipo.local.run-record.v2"

# An approval is short-lived on purpose: it authorizes one execution the
# researcher is about to start, not a standing permission.
DEFAULT_APPROVAL_TTL: Final = timedelta(hours=1)

SCIENCE_PACKAGE: Final = "science_workbench_science"

BYTE_SHAPING_DISTRIBUTIONS: Final = ("pillow", "pydantic", "pydantic-core")
"""Every installed distribution whose version can move a pinned digest.

SPEC-v0.5 section 6 requires the environment digest to cover *every* dependency
whose version can change a pinned digest or an artifact byte, and each name
here earns its place by naming the byte it shapes:

* `pillow` encodes the PNG. A different encoder is a different image.
* `pydantic` and `pydantic-core` produce `ProbeInput.model_dump_json()`, which
  is the exact serialization `input_sha256` is taken over. That digest is then
  embedded in the Markdown report and in the evidence ledger, so a serializer
  change moves three pinned digests at once. `pydantic-core` is named
  separately because it is the Rust serializer that actually emits those bytes
  and it version-drifts independently of the Python package in front of it.
  Covering only the interpreter -- as this digest once did -- let a pydantic
  upgrade change a pinned digest while the environment digest stayed
  identical, which is provenance that silently lies.

A dependency that cannot reach an output byte is deliberately absent. An
environment digest that moved for an unrelated upgrade would make every pinned
artifact look stale and would teach a reader to ignore it.
"""

CHAIN_ROLES: Final = ("csv", "png", "markdown", "ledger")
"""The ordered chain roles every run publishes, exactly once each."""

CSV_NAME: Final = "hypothesis-table.csv"
PNG_NAME: Final = "spectrum-plot.png"
MARKDOWN_NAME: Final = "analysis-report.md"
LEDGER_NAME: Final = "evidence-ledger.json"

CSV_MEDIA_TYPE: Final = "text/csv"
PNG_MEDIA_TYPE: Final = "image/png"
MARKDOWN_MEDIA_TYPE: Final = "text/markdown"
LEDGER_MEDIA_TYPE: Final = "application/json"

LEDGER_SCHEMA: Final = "nipo.local.evidence-ledger.v1"
EXECUTION_ISOLATION: Final = "in_process"
SKILL_DISCLOSURE: Final = (
    "No Skill participates in a local in-process deterministic run, so no "
    "Skill content hash exists to pin."
)


class WorkbenchRejection(StrEnum):
    """Stable reasons for refusing a run before any Version is created."""

    SCIENCE_REJECTED = "science_rejected"
    SPECTRUM_REQUIRED = "spectrum_required"
    EXECUTION_REPLAYED = "execution_replayed"
    PLAN_REJECTED = "plan_rejected"
    APPROVAL_REJECTED = "approval_rejected"
    RUN_REJECTED = "run_rejected"
    CORRECTION_INCOMPLETE = "correction_incomplete"
    CORRECTION_TARGET_MISSING = "correction_target_missing"


@final
class WorkbenchRunError(ValueError):
    """Refuse one run and surface the science package's own outcome."""

    __slots__ = ("code", "issues", "status")

    code: WorkbenchRejection
    status: OutcomeStatus
    issues: tuple[AnalysisIssue, ...]

    def __init__(
        self,
        code: WorkbenchRejection,
        status: OutcomeStatus,
        issues: tuple[AnalysisIssue, ...],
    ) -> None:
        """Retain the rejection code with the package's status and issues."""
        super().__init__(code)
        self.code = code
        self.status = status
        self.issues = issues


@final
class ActionPlanError(ValueError):
    """Refuse to create or approve one ActionPlan, keeping the store outcome."""

    __slots__ = ("code", "outcome")

    code: WorkbenchRejection
    outcome: StoreOutcome

    def __init__(self, code: WorkbenchRejection, outcome: StoreOutcome) -> None:
        """Retain the rejection code together with the store's own outcome."""
        super().__init__(code)
        self.code = code
        self.outcome = outcome


@final
class PlanApprovalError(ValueError):
    """Refuse one run whose approval could not be consumed exactly once."""

    __slots__ = ("outcome",)

    outcome: ApprovalOutcome

    def __init__(self, outcome: ApprovalOutcome) -> None:
        """Retain the exact reason consumption was refused."""
        super().__init__(outcome)
        self.outcome = outcome


@final
class CorrectionTargetError(ValueError):
    """Refuse a correction whose superseded Versions are not the whole chain.

    Raised before `analyze_probe` runs and therefore before any Run row,
    execution identity, Artifact, Version, or blob exists: a malformed
    correction must not consume the approval it was going to publish under.
    """

    __slots__ = ("code",)

    code: WorkbenchRejection

    def __init__(self, code: WorkbenchRejection) -> None:
        """Retain the rejection code without quoting any caller value."""
        super().__init__(code)
        self.code = code


@final
class RunRecordError(ArtifactStoreError):
    """Refuse to continue when the durable Run record rejects a transition."""

    __slots__ = ("outcome",)

    outcome: StoreOutcome

    def __init__(self, outcome: StoreOutcome) -> None:
        """Retain the rejecting store outcome as a non-secret reason."""
        super().__init__(outcome)
        self.outcome = outcome


@dataclass(frozen=True, slots=True)
class LocalArtifactRuntime:
    """One assembled Artifact subsystem bound to a single local execution.

    `session_id` is the working Session this execution belongs to, and sits
    beside `scope` and `execution_id` because it is the same kind of binding:
    which tenant, which Project, which requester, which execution, which
    Session. It is optional because a local analysis may legitimately run
    outside any Session; the Runs such an execution queues record none, and
    the Versions they publish can be associated with no Session at all.
    """

    service: ArtifactService
    watcher: OutputWatcher
    scope: ArtifactScope
    execution_id: UUID
    paths: LocalPaths
    store: LocalArtifactStore
    ids: Uuid7Factory
    clock: SystemClock
    session_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class ApprovedPlan:
    """One immutable ActionPlan and the one-use approval that authorizes it."""

    plan: ActionPlanRecord
    approval: PlanApprovalRecord


@dataclass(frozen=True, slots=True)
class RunProvenance:
    """Immutable provenance pinned onto every Version of one run."""

    execution_id: UUID
    input_sha256: str
    research_intent_sha256: str
    environment_sha256: str
    code_sha256: str


@dataclass(frozen=True, slots=True)
class OutputRecord:
    """One persisted output and its immutable Artifact coordinates."""

    role: str
    name: str
    artifact: ArtifactRecord
    version: ArtifactVersion


@dataclass(frozen=True, slots=True)
class CorrectionTarget:
    """One existing Artifact and the exact Version a correction supersedes.

    `base_version_no` is the compare-and-swap base, not a hint. The store
    refuses the commit with `ArtifactErrorCode.STALE_BASE` when it is not the
    Artifact's current head, so two concurrent corrections of the same Version
    cannot both win and the loser publishes nothing.
    """

    role: str
    artifact_id: UUID
    base_version_no: int


@dataclass(frozen=True, slots=True)
class WorkbenchRun:
    """Outputs of one deterministic local analysis in ordered-chain order."""

    run_id: UUID
    provenance: RunProvenance
    analysis: ProbeAnalysis
    csv: OutputRecord
    png: OutputRecord
    markdown: OutputRecord
    ledger: OutputRecord

    @property
    def outputs(self) -> tuple[OutputRecord, ...]:
        """Return the persisted outputs in normative chain order."""
        return (self.csv, self.png, self.markdown, self.ledger)


@dataclass(frozen=True, slots=True)
class _OutputRequest:
    """One payload awaiting watcher registration and Version creation."""

    role: str
    name: str
    media_type: str
    payload: bytes
    input_version_ids: tuple[UUID, ...]


@dataclass(frozen=True, slots=True)
class _RunContext:
    """The durable identities one publishing chain writes into both records."""

    run_id: UUID
    plan_id: UUID
    approval_id: UUID
    plan_sha256: str
    provenance: RunProvenance


def signing_key_path(paths: LocalPaths) -> Path:
    """Return the on-disk location of the local download signing key."""
    return paths.root / SIGNING_KEY_NAME


def load_download_signing_key(paths: LocalPaths) -> bytes:
    """Return the persisted signing key, generating it once at mode 0600."""
    paths.ensure()
    path = signing_key_path(paths)
    created = _create_signing_key(path)
    return path.read_bytes() if created is None else created


def runs_path(paths: LocalPaths) -> Path:
    """Return the directory holding one record per produced execution."""
    return paths.root / RUNS_DIRECTORY


def run_record_path(paths: LocalPaths, execution_id: UUID) -> Path:
    """Return the record path that fences one produced-execution id."""
    return runs_path(paths) / f"{execution_id}.json"


def read_run_record(
    paths: LocalPaths,
    execution_id: UUID,
) -> Mapping[str, object] | None:
    """Read one run record, or None when that execution never published."""
    path = run_record_path(paths, execution_id)
    if not path.exists():
        return None
    return cast("dict[str, object]", json.loads(path.read_bytes()))


def local_scope(project_id: UUID = DEFAULT_PROJECT_ID) -> ArtifactScope:
    """Return the fixed single-user scope for one local Project."""
    return ArtifactScope(
        org_id=LOCAL_ORG_ID,
        project_id=project_id,
        requester_id=LOCAL_USER_ID,
    )


def assemble_artifact_runtime(
    store: LocalArtifactStore,
    paths: LocalPaths,
    *,
    project_id: UUID = DEFAULT_PROJECT_ID,
    execution_id: UUID | None = None,
    session_id: UUID | None = None,
) -> LocalArtifactRuntime:
    """Build a ready ArtifactService from the local store, ids, clock, and key.

    `session_id` binds every Run this runtime queues to one Session, which is
    the last step of the ownership chain `attach_session` checks. It is not
    validated here: the store refuses a Run naming a Session that is not live
    in this exact Project, and validating twice would put the enforcement point
    in two places that could drift apart.
    """
    ids = Uuid7Factory()
    execution = ids.new_uuid7() if execution_id is None else execution_id
    scope = local_scope(project_id)
    watcher = OutputWatcher(
        ids,
        frozenset(
            {
                (
                    scope.org_id,
                    scope.project_id,
                    scope.requester_id,
                    execution,
                    LOCAL_RUNTIME_ADAPTER_ID,
                    LOCAL_RUNTIME_CONNECTION_ID,
                )
            }
        ),
        InMemoryArtifactRecovery(),
    )
    service = ArtifactService(
        store,
        watcher,
        ids,
        SystemClock(),
        load_download_signing_key(paths),
    )
    return LocalArtifactRuntime(
        service=service,
        watcher=watcher,
        scope=scope,
        execution_id=execution,
        paths=paths,
        store=store,
        ids=ids,
        clock=SystemClock(),
        session_id=session_id,
    )


def create_action_plan(
    runtime: LocalArtifactRuntime,
    intent: ResearchIntent,
) -> ActionPlanRecord:
    """Create one immutable ActionPlan binding exactly this `ResearchIntent`.

    The plan digest is not chosen here: it is the value `plan_digest` derives
    from the intent digest and the plan's own identities, and the store refuses
    any other. A plan therefore cannot outlive an edit to the intent it binds.
    """
    plan_id = runtime.ids.new_uuid7()
    plan = ActionPlanRecord(
        id=plan_id,
        org_id=runtime.scope.org_id,
        project_id=runtime.scope.project_id,
        requester_id=runtime.scope.requester_id,
        research_intent_sha256=intent.sha256,
        plan_sha256=LocalArtifactStore.plan_digest(
            runtime.scope,
            plan_id,
            intent.sha256,
        ),
        created_at=runtime.clock.now(),
    )
    outcome = runtime.store.create_action_plan(runtime.scope, plan)
    if outcome is not StoreOutcome.CREATED:
        raise ActionPlanError(WorkbenchRejection.PLAN_REJECTED, outcome)
    return plan


def approve_action_plan(
    runtime: LocalArtifactRuntime,
    plan: ActionPlanRecord,
    ttl: timedelta = DEFAULT_APPROVAL_TTL,
) -> PlanApprovalRecord:
    """Grant the one approval this plan may ever carry, for its requester."""
    granted_at = runtime.clock.now()
    approval = PlanApprovalRecord(
        id=runtime.ids.new_uuid7(),
        org_id=runtime.scope.org_id,
        project_id=runtime.scope.project_id,
        plan_id=plan.id,
        approver_id=runtime.scope.requester_id,
        research_intent_sha256=plan.research_intent_sha256,
        plan_sha256=plan.plan_sha256,
        granted_at=granted_at,
        expires_at=granted_at + ttl,
    )
    outcome = runtime.store.grant_approval(runtime.scope, approval)
    if outcome is not StoreOutcome.CREATED:
        raise ActionPlanError(WorkbenchRejection.APPROVAL_REJECTED, outcome)
    return approval


def approve_analysis(
    runtime: LocalArtifactRuntime,
    intent: ResearchIntent,
    ttl: timedelta = DEFAULT_APPROVAL_TTL,
) -> ApprovedPlan:
    """Create and approve one plan for exactly this `ResearchIntent`."""
    plan = create_action_plan(runtime, intent)
    return ApprovedPlan(plan=plan, approval=approve_action_plan(runtime, plan, ttl))


def run_analysis(
    runtime: LocalArtifactRuntime,
    intent: ResearchIntent,
    source: ProbeInput,
    approved: ApprovedPlan,
) -> WorkbenchRun:
    """Execute one approved deterministic analysis and publish four outputs.

    `approved` has no default on purpose: a default would be a silent
    self-approval, which is exactly the control this gate exists to provide.

    The Run records `runtime.session_id`, which is what later lets the produced
    Versions be associated with that Session. A runtime assembled without one
    still runs; its Versions are associable with no Session.
    """
    return _execute(runtime, intent, source, approved, {})


def correction_targets(
    store: LocalArtifactStore,
    scope: ArtifactScope,
    run_id: UUID,
) -> tuple[CorrectionTarget, ...]:
    """Read the exact Versions one earlier Run committed, in chain order.

    The base version numbers come from the Version rows the Run recorded, not
    from an Artifact's head, so a correction is pinned to the Version the
    researcher actually looked at. If someone else corrected the same chain in
    between, the recorded base is stale and the store refuses the commit
    instead of silently rebasing onto whatever is newest.

    Raises:
        CorrectionTargetError: A recorded output no longer resolves to a
            Version, so there is nothing well-defined to supersede.
    """
    targets: list[CorrectionTarget] = []
    for output in store.run_outputs(scope, run_id):
        version = store.version(scope, output.artifact_version_id)
        if version is None:
            raise CorrectionTargetError(WorkbenchRejection.CORRECTION_TARGET_MISSING)
        targets.append(
            CorrectionTarget(
                role=output.role,
                artifact_id=output.artifact_id,
                base_version_no=version.version_no,
            )
        )
    return tuple(targets)


def correct_analysis(
    runtime: LocalArtifactRuntime,
    intent: ResearchIntent,
    source: ProbeInput,
    approved: ApprovedPlan,
    superseded: Sequence[CorrectionTarget],
) -> WorkbenchRun:
    """Re-run one analysis and publish the result as the next Version.

    This is the producing path SPEC-v0.5 sections 1 and 8 require: a
    correction is a new Version, never an overwrite, and it is made by a new
    execution under a fresh approval followed by a new Review. Nothing here
    mutates, deletes, or re-addresses the Versions it supersedes -- they keep
    their identifiers, their bytes, and their digests, and stay readable and
    exportable exactly as before.

    `runtime` must carry an unclaimed produced-execution id and `approved` an
    unspent approval, because a correction is a *run* in every respect the
    contract cares about. Passing the earlier run's runtime is refused by the
    execution fence, not accepted as a re-render.

    Args:
        runtime: The Artifact subsystem bound to this correction's own
            produced-execution identity.
        intent: The live `ResearchIntent`; its digest must still match the
            approval, so a correction cannot smuggle in an edited question.
        source: The corrected scientific input.
        approved: The one-use approval authorizing this execution.
        superseded: One target per committed output of the run being
            corrected, normally from :func:`correction_targets`.

    Returns:
        The corrected run, whose outputs are Version `base + 1` of the same
        Artifacts.

    Raises:
        CorrectionTargetError: `superseded` is not exactly one target for each
            role in the ordered chain. Raised before any Artifact identity or
            approval consumption exists.
    """
    return _execute(runtime, intent, source, approved, _targets_by_role(superseded))


def _targets_by_role(
    superseded: Sequence[CorrectionTarget],
) -> dict[str, CorrectionTarget]:
    """Index correction targets by role, refusing a partial chain.

    A correction that superseded only some of the four outputs would leave the
    Artifact set describing two different executions at once -- a corrected CSV
    beside an uncorrected report -- so an incomplete selection is refused
    rather than published.
    """
    indexed = {target.role: target for target in superseded}
    if len(indexed) != len(superseded) or set(indexed) != set(CHAIN_ROLES):
        raise CorrectionTargetError(WorkbenchRejection.CORRECTION_INCOMPLETE)
    return indexed


def _execute(
    runtime: LocalArtifactRuntime,
    intent: ResearchIntent,
    source: ProbeInput,
    approved: ApprovedPlan,
    targets: Mapping[str, CorrectionTarget],
) -> WorkbenchRun:
    """Publish one approved chain, creating or superseding Artifacts.

    `targets` is empty for a first run and carries one entry per role for a
    correction. It is the only difference between the two paths: everything
    about approval consumption, execution fencing, ordering, run recording,
    and failure marking is shared, so a correction cannot drift into a weaker
    version of the publishing contract.

    The input is serialized exactly once. `input_sha256` and the bytes handed
    to the store are then the same object rather than two calls that are only
    expected to agree, so the store's verification cannot be satisfied by a
    serialization that differs from the one the digest was taken over.
    """
    analysis = analyze_probe(source)
    plot = _accepted_plot(analysis)
    canonical_input = source.model_dump_json().encode()
    provenance = RunProvenance(
        execution_id=runtime.execution_id,
        input_sha256=_sha256(canonical_input),
        research_intent_sha256=intent.sha256,
        environment_sha256=_environment_sha256(),
        code_sha256=_code_sha256(),
    )
    context = _queue_run(runtime, approved, provenance)
    _claim_execution(runtime, context, analysis)
    _open_record(runtime, context, analysis)
    committed: list[OutputRecord] = []
    try:
        _persist_inputs(runtime, context, intent.canonical_bytes, canonical_input)
        for request in _derived_requests(analysis, plot, intent, provenance):
            committed.append(
                _publish(runtime, provenance, request, targets.get(request.role))
            )
            _record_progress(runtime, context, tuple(committed))
        ledger = _ledger_request(provenance, tuple(committed), analysis.evidence)
        committed.append(
            _publish(runtime, provenance, ledger, targets.get(ledger.role))
        )
        _record_progress(runtime, context, tuple(committed))
        _mark_completed(runtime, context, tuple(committed))
    except BaseException as error:
        _mark_failed(runtime, context, tuple(committed), error)
        raise
    csv_record, png_record, markdown_record, ledger_record = committed
    return WorkbenchRun(
        run_id=context.run_id,
        provenance=provenance,
        analysis=analysis,
        csv=csv_record,
        png=png_record,
        markdown=markdown_record,
        ledger=ledger_record,
    )


def render_markdown(
    intent: ResearchIntent,
    analysis: ProbeAnalysis,
    input_sha256: str,
) -> bytes:
    """Render one byte-deterministic report free of clocks and identities."""
    issues = tuple(f"`{item.code}`: {item.message}" for item in analysis.issues)
    lines = [
        "# Local deterministic analysis report",
        "",
        "## Research intent",
        "",
        f"- Question: {intent.question}",
        f"- Rationale: {intent.rationale}",
        f"- Intended benefit: {intent.intended_benefit}",
        f"- Research mode: {intent.research_mode.value}",
        f"- Data origin: {intent.data_origin.value}",
        f"- Canonical digest: `{intent.sha256}`",
        "",
        *_bullets("### Success criteria", intent.success_criteria),
        *_bullets("### Constraints", intent.constraints),
        *_bullets("### Stop conditions", intent.stop_conditions),
        "## Scientific input",
        "",
        f"- Canonical digest: `{input_sha256}`",
        f"- Outcome status: {analysis.status.value}",
        "",
        *_spectrum_lines(analysis.spectrum),
        *_hypothesis_lines(analysis.hypotheses),
        *_bullets("## Analysis issues", issues or ("None recorded.",)),
        *_bullets("## Limitations", analysis.limitations),
    ]
    return "\n".join(lines).encode()


def render_ledger(
    provenance: RunProvenance,
    outputs: tuple[OutputRecord, ...],
    evidence: tuple[EvidenceRecord, ...],
) -> bytes:
    """Render the canonical evidence ledger binding outputs to provenance."""
    payload: dict[str, object] = {
        "schema": LEDGER_SCHEMA,
        "code_sha256": provenance.code_sha256,
        "environment_sha256": provenance.environment_sha256,
        "execution_isolation": EXECUTION_ISOLATION,
        "input_sha256": provenance.input_sha256,
        "producing_execution_id": str(provenance.execution_id),
        "research_intent_sha256": provenance.research_intent_sha256,
        "runtime_adapter_id": LOCAL_RUNTIME_ADAPTER_ID,
        "runtime_connection_id": str(LOCAL_RUNTIME_CONNECTION_ID),
        "skill_content_hashes": [],
        "skill_content_note": SKILL_DISCLOSURE,
        "outputs": [
            {
                "role": item.role,
                "name": item.name,
                "artifact_id": str(item.artifact.id),
                "version_id": str(item.version.id),
                "version_no": item.version.version_no,
                "content_sha256": item.version.content_sha256,
                "media_type": item.version.media_type,
                "size_bytes": item.version.size_bytes,
                "input_version_ids": [
                    str(value) for value in item.version.input_version_ids
                ],
            }
            for item in outputs
        ],
        "science_evidence": [
            {
                "claim_id": record.claim_id,
                "branch": record.branch.value,
                "evidence_kind": record.evidence_kind,
                "locator": record.locator,
                "source_version_ids": [
                    str(value) for value in record.source_version_ids
                ],
                "supporting_sha256": record.supporting_sha256,
            }
            for record in evidence
        ],
    }
    return _canonical_bytes(payload)


def code_sha256(science_root: Path, module_path: Path) -> str:
    """Digest one science package tree together with one producing module."""
    sources = {
        f"{SCIENCE_PACKAGE}/{path.relative_to(science_root).as_posix()}": _sha256(
            path.read_bytes()
        )
        for path in sorted(science_root.rglob("*.py"))
    }
    sources[f"nipo_local/{module_path.name}"] = _sha256(module_path.read_bytes())
    return canonical_sha256(sources)


def environment_facts() -> Mapping[str, str]:
    """Report every interpreter and dependency version that shapes the bytes.

    The distribution half is driven by :data:`BYTE_SHAPING_DISTRIBUTIONS`
    rather than written out here, so adding a byte-shaping dependency to that
    tuple is the only edit needed to widen the digest -- and forgetting to
    widen it is visible in one place instead of buried in a literal.
    """
    facts: dict[str, str] = {
        "implementation": sys.implementation.name,
        "platform": sys.platform,
        "python": ".".join(str(part) for part in sys.version_info[:3]),
    }
    for name in BYTE_SHAPING_DISTRIBUTIONS:
        facts[name] = distribution_version(name)
    return facts


def canonical_sha256(payload: Mapping[str, str]) -> str:
    """Digest one string mapping under a single canonical serialization."""
    return _sha256(_canonical_bytes(payload))


def _accepted_plot(analysis: ProbeAnalysis) -> bytes:
    """Return the deterministic plot, refusing whatever the package rejects."""
    if analysis.status is not OutcomeStatus.VALID:
        raise WorkbenchRunError(
            WorkbenchRejection.SCIENCE_REJECTED,
            analysis.status,
            analysis.issues,
        )
    plot = analysis.spectrum_plot_png
    if not plot:
        raise WorkbenchRunError(
            WorkbenchRejection.SPECTRUM_REQUIRED,
            analysis.status,
            analysis.issues,
        )
    return plot


def _derived_requests(
    analysis: ProbeAnalysis,
    plot: bytes,
    intent: ResearchIntent,
    provenance: RunProvenance,
) -> tuple[_OutputRequest, ...]:
    """Return the csv, png, and markdown payloads in normative chain order."""
    return (
        _OutputRequest(
            role="csv",
            name=CSV_NAME,
            media_type=CSV_MEDIA_TYPE,
            payload=analysis.hypothesis_table_csv,
            input_version_ids=(),
        ),
        _OutputRequest(
            role="png",
            name=PNG_NAME,
            media_type=PNG_MEDIA_TYPE,
            payload=plot,
            input_version_ids=(),
        ),
        _OutputRequest(
            role="markdown",
            name=MARKDOWN_NAME,
            media_type=MARKDOWN_MEDIA_TYPE,
            payload=render_markdown(intent, analysis, provenance.input_sha256),
            input_version_ids=(),
        ),
    )


def _ledger_request(
    provenance: RunProvenance,
    derived: tuple[OutputRecord, ...],
    evidence: tuple[EvidenceRecord, ...],
) -> _OutputRequest:
    """Return the ledger payload deriving from the already committed outputs."""
    return _OutputRequest(
        role="ledger",
        name=LEDGER_NAME,
        media_type=LEDGER_MEDIA_TYPE,
        payload=render_ledger(provenance, derived, evidence),
        input_version_ids=tuple(item.version.id for item in derived),
    )


def _publish(
    runtime: LocalArtifactRuntime,
    provenance: RunProvenance,
    request: _OutputRequest,
    target: CorrectionTarget | None,
) -> OutputRecord:
    """Register bytes first, then bind an Artifact identity to one Version.

    `target` is `None` for a first run, which mints a new Artifact and commits
    Version 1. For a correction it names the Artifact and the exact base
    Version the new bytes supersede, so the commit is a compare-and-swap onto
    an existing lineage rather than a new Artifact that would strand the
    original.
    """
    reference = runtime.watcher.register(
        runtime.scope,
        provenance.execution_id,
        request.payload,
        request.media_type,
    )
    artifact = (
        runtime.service.create_artifact(runtime.scope, request.name)
        if target is None
        else _superseded_artifact(runtime, target)
    )
    draft = VersionDraft(
        artifact_id=artifact.id,
        base_version_no=0 if target is None else target.base_version_no,
        watcher_reference=reference,
        producing_execution_id=provenance.execution_id,
        environment_sha256=provenance.environment_sha256,
        code_sha256=provenance.code_sha256,
        runtime_adapter_id=LOCAL_RUNTIME_ADAPTER_ID,
        runtime_connection_id=LOCAL_RUNTIME_CONNECTION_ID,
        skill_content_hashes=(),
        source_hashes=(provenance.input_sha256, provenance.research_intent_sha256),
        input_version_ids=request.input_version_ids,
    )
    version = runtime.service.create_version(runtime.scope, draft)
    return OutputRecord(
        role=request.role,
        name=request.name,
        artifact=artifact,
        version=version,
    )


def _superseded_artifact(
    runtime: LocalArtifactRuntime,
    target: CorrectionTarget,
) -> ArtifactRecord:
    """Read the Artifact a correction extends, refusing to invent one.

    Creating an Artifact here would silently turn a correction into a parallel
    lineage, which is exactly the overwrite-shaped failure the Version
    contract exists to prevent -- just in the other direction.
    """
    record = runtime.store.artifact(runtime.scope, target.artifact_id)
    if record is None:
        raise CorrectionTargetError(WorkbenchRejection.CORRECTION_TARGET_MISSING)
    return record


def _persist_inputs(
    runtime: LocalArtifactRuntime,
    context: _RunContext,
    intent_bytes: bytes,
    input_bytes: bytes,
) -> None:
    """Persist the canonical bytes behind the two digests this execution pinned.

    Both payloads are the exact serializations the digests were taken over, so
    the store's check against the pinned digest is a real verification of this
    run rather than a restatement of it, and it refuses anything else.

    A refusal fails the run. It happens before any Artifact identity, Version,
    or blob of this chain exists, so nothing is left half-published; and a
    chain that quietly continued would produce a pack whose two most important
    digests silently stay self-reported, which is a weaker record than one that
    stops here and says why.
    """
    for kind, payload in (
        (ExecutionInputKind.RESEARCH_INTENT, intent_bytes),
        (ExecutionInputKind.SCIENTIFIC_INPUT, input_bytes),
    ):
        outcome = runtime.store.record_execution_input(
            runtime.scope,
            context.provenance.execution_id,
            kind,
            payload,
        )
        if outcome is not StoreOutcome.CREATED:
            raise RunRecordError(outcome)


def _queue_run(
    runtime: LocalArtifactRuntime,
    approved: ApprovedPlan,
    provenance: RunProvenance,
) -> _RunContext:
    """Queue one Run bound to the plan, approval, and Session that own it.

    The queued row carries the *plan's* intent digest, not the live one, so a
    mutated intent is refused by the atomic approval consumption rather than
    here. That keeps one enforcement point instead of two competing ones.

    `runtime.session_id` is recorded on the Run and is the last step of the
    ownership chain a later association is checked against. The store refuses a
    Run naming a Session that is not live in this Project, so an unusable
    Session stops the run here rather than producing Versions nothing can
    associate.
    """
    queued_at = runtime.clock.now()
    run = RunRecord(
        id=runtime.ids.new_uuid7(),
        org_id=runtime.scope.org_id,
        project_id=runtime.scope.project_id,
        plan_id=approved.plan.id,
        approval_id=approved.approval.id,
        requester_id=runtime.scope.requester_id,
        session_id=runtime.session_id,
        state=RunState.QUEUED,
        research_intent_sha256=approved.plan.research_intent_sha256,
        created_at=queued_at,
        updated_at=queued_at,
    )
    outcome = runtime.store.create_run(runtime.scope, run)
    if outcome is not StoreOutcome.CREATED:
        raise ActionPlanError(WorkbenchRejection.RUN_REJECTED, outcome)
    return _RunContext(
        run_id=run.id,
        plan_id=approved.plan.id,
        approval_id=approved.approval.id,
        plan_sha256=approved.plan.plan_sha256,
        provenance=provenance,
    )


def _claim_execution(
    runtime: LocalArtifactRuntime,
    context: _RunContext,
    analysis: ProbeAnalysis,
) -> None:
    """Consume the approval and claim the produced-execution id atomically.

    The digest submitted here is recomputed from the live `ResearchIntent`, so
    an edited intent field cannot be reconciled with the approval that was
    granted for the original one. Every refusal happens before any Artifact
    identity, Version, blob, or mirror file exists.
    """
    provenance = context.provenance
    claimed_at = runtime.clock.now()
    claim = RunClaim(
        run_id=context.run_id,
        approval_id=context.approval_id,
        research_intent_sha256=provenance.research_intent_sha256,
        execution=ExecutionRecord(
            id=provenance.execution_id,
            org_id=runtime.scope.org_id,
            project_id=runtime.scope.project_id,
            run_id=context.run_id,
            execution_isolation=EXECUTION_ISOLATION,
            input_sha256=provenance.input_sha256,
            research_intent_sha256=provenance.research_intent_sha256,
            code_sha256=provenance.code_sha256,
            environment_sha256=provenance.environment_sha256,
            created_at=claimed_at,
        ),
        started_at=claimed_at,
    )
    outcome = runtime.store.start_run(runtime.scope, claim)
    if outcome is ApprovalOutcome.CONSUMED:
        return
    _abandon_run(runtime, context, outcome)
    if outcome is ApprovalOutcome.EXECUTION_CLAIMED:
        raise WorkbenchRunError(
            WorkbenchRejection.EXECUTION_REPLAYED,
            analysis.status,
            analysis.issues,
        )
    raise PlanApprovalError(outcome)


def _abandon_run(
    runtime: LocalArtifactRuntime,
    context: _RunContext,
    outcome: ApprovalOutcome,
) -> None:
    """Fail a queued Run that never started, leaving no mirror behind.

    No mirror file is created for a refused approval: writing one would fence
    a produced-execution id that never executed. The store outcome is
    deliberately not asserted, because raising here would replace the precise
    refusal reason with a bookkeeping error; an unmarked Run stays visible
    through `unfinished_runs`.
    """
    with suppress(ArtifactStoreError):
        _ = runtime.store.finish_run(
            runtime.scope,
            RunCompletion(
                run_id=context.run_id,
                state=RunState.FAILED,
                finished_at=runtime.clock.now(),
                error_type=PlanApprovalError.__name__,
                error_code=outcome.value,
            ),
        )


def _open_record(
    runtime: LocalArtifactRuntime,
    context: _RunContext,
    analysis: ProbeAnalysis,
) -> None:
    """Create the mirror, failing the Run rather than losing the record.

    A pre-existing mirror belongs to another execution, so this never writes
    over one: the Run row alone is marked and the refusal is re-raised.
    """
    try:
        _begin_run(runtime, context, analysis)
    except BaseException as error:
        with suppress(ArtifactStoreError):
            _finish_run(runtime, context, RunState.FAILED, _failure(error))
        raise


def _record_progress(
    runtime: LocalArtifactRuntime,
    context: _RunContext,
    committed: tuple[OutputRecord, ...],
) -> None:
    """Record the newest output as a durable row, then refresh the mirror."""
    _append_output(runtime, context, committed[-1], len(committed))
    _write_run(runtime, context, RunState.RUNNING, committed, None)


def _append_output(
    runtime: LocalArtifactRuntime,
    context: _RunContext,
    record: OutputRecord,
    sequence: int,
) -> None:
    """Record one committed output at its exact position in the chain."""
    outcome = runtime.store.append_run_output(
        runtime.scope,
        RunOutputRecord(
            org_id=runtime.scope.org_id,
            project_id=runtime.scope.project_id,
            run_id=context.run_id,
            sequence=sequence,
            role=record.role,
            name=record.name,
            artifact_id=record.artifact.id,
            artifact_version_id=record.version.id,
            content_sha256=record.version.content_sha256,
            created_at=record.version.created_at,
        ),
    )
    if outcome is not StoreOutcome.CREATED:
        raise RunRecordError(outcome)


def _mark_completed(
    runtime: LocalArtifactRuntime,
    context: _RunContext,
    committed: tuple[OutputRecord, ...],
) -> None:
    """Close both records as completed, mirror first.

    Mirror first only here: if either write fails the Run row is still
    `running`, so the failure path can legally mark both records `failed` and
    they never come to rest disagreeing.
    """
    _write_run(runtime, context, RunState.COMPLETED, committed, None)
    _finish_run(runtime, context, RunState.COMPLETED, None)


def _mark_failed(
    runtime: LocalArtifactRuntime,
    context: _RunContext,
    committed: tuple[OutputRecord, ...],
    error: BaseException,
) -> None:
    """Mark both records failed before the original error escapes.

    The row is attempted first because it is the authority, and its own
    failure is suppressed: the mirror exists precisely for a database that is
    itself what failed, and replacing the real cause with a bookkeeping error
    would leave the Run unmarked in both records.
    """
    failure = _failure(error)
    with suppress(ArtifactStoreError):
        _finish_run(runtime, context, RunState.FAILED, failure)
    _write_run(runtime, context, RunState.FAILED, committed, failure)


def _finish_run(
    runtime: LocalArtifactRuntime,
    context: _RunContext,
    state: RunState,
    failure: Mapping[str, object] | None,
) -> None:
    """Move the durable Run row onto exactly one terminal state."""
    outcome = runtime.store.finish_run(
        runtime.scope,
        RunCompletion(
            run_id=context.run_id,
            state=state,
            finished_at=runtime.clock.now(),
            error_type=None if failure is None else cast("str", failure["error"]),
            error_code=None if failure is None else cast("str | None", failure["code"]),
        ),
    )
    if outcome is not StoreOutcome.CREATED:
        raise RunRecordError(outcome)


def _begin_run(
    runtime: LocalArtifactRuntime,
    context: _RunContext,
    analysis: ProbeAnalysis,
) -> None:
    """Fence one produced-execution id and record that publishing started."""
    directory = runs_path(runtime.paths)
    directory.mkdir(parents=True, exist_ok=True)
    path = run_record_path(runtime.paths, context.provenance.execution_id)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, OWNER_ONLY_MODE)
    except FileExistsError:
        raise WorkbenchRunError(
            WorkbenchRejection.EXECUTION_REPLAYED,
            analysis.status,
            analysis.issues,
        ) from None
    payload = _canonical_bytes(_run_payload(context, RunState.RUNNING, (), None))
    with os.fdopen(descriptor, "wb") as handle:
        _ = handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    _sync_directory(directory)


def _write_run(
    runtime: LocalArtifactRuntime,
    context: _RunContext,
    state: RunState,
    committed: tuple[OutputRecord, ...],
    failure: Mapping[str, object] | None,
) -> None:
    """Atomically publish the current lifecycle record for one execution."""
    directory = runs_path(runtime.paths)
    path = run_record_path(runtime.paths, context.provenance.execution_id)
    payload = _canonical_bytes(_run_payload(context, state, committed, failure))
    descriptor, name = tempfile.mkstemp(dir=directory, suffix=".tmp")
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            _ = handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(OWNER_ONLY_MODE)
        _ = temporary.replace(path)
        _sync_directory(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _run_payload(
    context: _RunContext,
    state: RunState,
    committed: tuple[OutputRecord, ...],
    failure: Mapping[str, object] | None,
) -> dict[str, object]:
    """Build the canonical lifecycle document for one produced execution."""
    provenance = context.provenance
    return {
        "schema": RUN_RECORD_SCHEMA,
        "state": state.value,
        "run_id": str(context.run_id),
        "action_plan_id": str(context.plan_id),
        "action_plan_sha256": context.plan_sha256,
        "plan_approval_id": str(context.approval_id),
        "producing_execution_id": str(provenance.execution_id),
        "research_intent_sha256": provenance.research_intent_sha256,
        "input_sha256": provenance.input_sha256,
        "code_sha256": provenance.code_sha256,
        "environment_sha256": provenance.environment_sha256,
        "execution_isolation": EXECUTION_ISOLATION,
        "committed_outputs": [
            {
                "sequence": index,
                "role": item.role,
                "artifact_id": str(item.artifact.id),
                "version_id": str(item.version.id),
                "content_sha256": item.version.content_sha256,
            }
            for index, item in enumerate(committed, start=1)
        ],
        "failure": dict(failure) if failure is not None else None,
    }


def _failure(error: BaseException) -> dict[str, object]:
    """Record a non-secret failure reason without reflecting payloads."""
    stable = isinstance(
        error,
        ArtifactError
        | WorkbenchRunError
        | ActionPlanError
        | PlanApprovalError
        | RunRecordError,
    )
    return {"error": type(error).__name__, "code": str(error) if stable else None}


def _create_signing_key(path: Path) -> bytes | None:
    """Publish one complete key atomically, or report that one exists."""
    if path.exists():
        return None
    key = secrets.token_bytes(SIGNING_KEY_BYTES)
    descriptor, name = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            _ = handle.write(key)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(OWNER_ONLY_MODE)
        try:
            os.link(temporary, path)
        except FileExistsError:
            return None
        _sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)
    return key


def _sync_directory(directory: Path) -> None:
    """Flush one directory entry so a published file survives a crash."""
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _bullets(heading: str, items: tuple[str, ...]) -> list[str]:
    """Render one deterministic bullet section under a stable heading."""
    return [heading, "", *[f"- {item}" for item in items], ""]


def _spectrum_lines(spectrum: NormalizedSpectrum | None) -> list[str]:
    """Render the normalized spectrum summary and its deterministic peaks."""
    if spectrum is None:
        return ["## Spectrum", "", "- No spectrum modality was supplied.", ""]
    return [
        "## Spectrum",
        "",
        f"- Observations: {len(spectrum.wavelengths)}",
        f"- Missing fraction: {spectrum.missing_fraction:.6f}",
        f"- Peaks: {len(spectrum.peaks)}",
        "",
        "| index | wavelength | corrected_intensity | prominence |",
        "| --- | --- | --- | --- |",
        *[
            f"| {peak.index} | {peak.wavelength:g} "
            f"| {peak.corrected_intensity:.6f} | {peak.prominence:.6f} |"
            for peak in spectrum.peaks
        ],
        "",
    ]


def _hypothesis_lines(hypotheses: tuple[HypothesisRecord, ...]) -> list[str]:
    """Render every bounded branch in the package's fixed branch order."""
    lines = ["## Hypothesis branches", ""]
    for record in hypotheses:
        lines.extend(
            [
                f"### {record.branch.value} ({record.state.value})",
                "",
                f"- Observation: {record.observation}",
                f"- Control: {record.control}",
                f"- Limitation: {record.limitation}",
                f"- Conclusion scope: {record.conclusion_scope}",
                "",
            ]
        )
    return lines


@cache
def _environment_sha256() -> str:
    """Digest the interpreter and rendering environment once per process."""
    return canonical_sha256(environment_facts())


@cache
def _code_sha256() -> str:
    """Digest every deterministic source file that can shape an output."""
    return code_sha256(_science_root(), Path(__file__).resolve())


def _science_root() -> Path:
    """Locate the installed deterministic science package directory."""
    spec = find_spec(SCIENCE_PACKAGE)
    if spec is None or spec.origin is None:
        raise ModuleNotFoundError(name=SCIENCE_PACKAGE)
    return Path(spec.origin).parent


def _canonical_bytes(payload: Mapping[str, object]) -> bytes:
    """Serialize deterministically with sorted keys and compact separators."""
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _sha256(payload: bytes) -> str:
    """Return the lowercase hexadecimal SHA-256 digest of one payload."""
    return hashlib.sha256(payload).hexdigest()
