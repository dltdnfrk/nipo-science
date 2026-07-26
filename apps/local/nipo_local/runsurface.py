"""Bind the API's declared Run seam to the durable `runs` tables.

`nipo_local.api.RunSurface` was declared before a Run implementation existed,
and while nothing was bound `/runs` answered `501 run_surface_unavailable` and
`ProvenanceBody.execution_isolation` read `null` on every Version. The rows
were being written the whole time -- `workbench.py` records `runs`,
`executions`, and `run_outputs` on the way through -- so the seam was a read
path that never reached the writes on the other side of it.

This module is that read path and nothing else. It holds a
`LocalArtifactStore` and projects rows onto the JSON shape the front end
already renders. It creates no Run, consumes no approval, claims no execution,
and commits no Version: every method here is a `SELECT`.

Null stays reachable
--------------------
`execution_isolation` returns `None` when the `executions` row does not exist,
and that is a supported outcome rather than a gap to be papered over. A Run
refused at approval consumption never claims an execution; a Version produced
outside a Run has a `producing_execution_id` no execution row answers for.
SPEC-v0.5 section 5 forbids presenting an isolation level that was not
actually recorded, so the honest answer is the absent one and the front end
renders its "assume nothing" disclosure for it. Defaulting to `"in_process"`
here would be a fabricated confinement claim about an execution this
installation cannot see.

Isolation is likewise never *derived*. It is read verbatim from the column the
producing execution wrote, so a future run recording a stronger level surfaces
that level, and a run recording nothing surfaces nothing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, final

from services.api.artifacts.store_contract import ArtifactStoreError

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from uuid import UUID

    from services.api.artifacts.models import ArtifactScope

    from .store import (
        ExecutionRecord,
        LocalArtifactStore,
        RunOutputRecord,
        RunRecord,
    )

__all__ = ["StoreRunSurface", "run_projection"]


def run_projection(
    run: RunRecord,
    execution: ExecutionRecord | None,
    outputs: Sequence[RunOutputRecord],
) -> dict[str, object]:
    """Project one Run, its execution, and its outputs onto the wire.

    Every provenance digest is read from the `executions` row rather than
    recomputed, because this is a read path: recomputing here would report
    what *this* process would produce today, not what the execution actually
    pinned. When no execution was claimed each of those fields is `None`,
    which the front end renders as "기록 없음" rather than as a zero digest.

    `committed_outputs` is projected in the `sequence` the store recorded, so
    a truncated chain reads as the prefix it is instead of as a complete one
    in a different order.
    """
    return {
        "run_id": str(run.id),
        "project_id": str(run.project_id),
        "state": run.state.value,
        "action_plan_id": str(run.plan_id),
        "plan_approval_id": str(run.approval_id),
        "research_intent_sha256": run.research_intent_sha256,
        "created_at": run.created_at.isoformat(),
        "updated_at": run.updated_at.isoformat(),
        "producing_execution_id": None if execution is None else str(execution.id),
        "execution_isolation": (
            None if execution is None else execution.execution_isolation
        ),
        "input_sha256": None if execution is None else execution.input_sha256,
        "code_sha256": None if execution is None else execution.code_sha256,
        "environment_sha256": (
            None if execution is None else execution.environment_sha256
        ),
        "committed_outputs": [
            {
                "sequence": output.sequence,
                "role": output.role,
                "name": output.name,
                "artifact_id": str(output.artifact_id),
                "version_id": str(output.artifact_version_id),
                "content_sha256": output.content_sha256,
            }
            for output in outputs
        ],
        "failure": (
            None
            if run.error_type is None
            else {"error": run.error_type, "code": run.error_code}
        ),
    }


@final
class StoreRunSurface:
    """Answer the API's Run questions from the durable tables.

    Structurally read-only: the only store methods reachable from here are
    `runs`, `run`, `run_outputs`, `execution_for_run`, and `execution`, all of
    which are `SELECT` projections. There is no path from this object to
    `create_run`, `start_run`, `finish_run`, or `commit_version`, so binding
    the Run surface cannot turn a read of a Run into a write of one.
    """

    __slots__ = ("_store",)

    def __init__(self, store: LocalArtifactStore) -> None:
        """Bind this surface to the store that owns the durable Run rows."""
        self._store = store

    def list_runs(self, scope: ArtifactScope) -> tuple[Mapping[str, object], ...]:
        """Return one Project's Run projections, newest first.

        Failed and cancelled Runs are included deliberately. A listing that
        showed only completed chains would hide exactly the truncation the
        Run record exists to make visible.
        """
        return tuple(
            run_projection(
                run,
                self._store.execution_for_run(scope, run.id),
                self._store.run_outputs(scope, run.id),
            )
            for run in self._store.runs(scope)
        )

    def read_run(
        self,
        scope: ArtifactScope,
        run_id: UUID,
    ) -> Mapping[str, object] | None:
        """Return one Run projection, or None when it does not exist."""
        run = self._store.run(scope, run_id)
        if run is None:
            return None
        return run_projection(
            run,
            self._store.execution_for_run(scope, run_id),
            self._store.run_outputs(scope, run_id),
        )

    def execution_isolation(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
    ) -> str | None:
        """Return one execution's disclosed isolation, or None when unrecorded.

        A store failure is reported as "unrecorded" rather than raised: this
        answers one advisory field on a provenance response, and refusing the
        whole response would hide every digest that *is* readable. `None` is
        already the value the front end must treat as "assume nothing", so a
        failure lands on the conservative side of the same disclosure.
        """
        try:
            execution = self._store.execution(scope, execution_id)
        except ArtifactStoreError:
            return None
        return None if execution is None else execution.execution_isolation
