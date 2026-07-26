"""Local single-user SQLite and content-addressed blob Artifact store.

The durable deployment splits Artifact state across PostgreSQL row-level
security and a private object store. A local installation has exactly one
operator, one machine, and no network boundary, so the same `ArtifactStore`
contract is satisfied here by a single SQLite database plus a sharded blob
directory beneath `LocalPaths.blobs`.

Multi-tenant identity fields are persisted faithfully and filtered on exact
match so that records stay portable, but no authorization is derived from
them: on this machine the operator already owns every row.

Project and Session lifecycle
----------------------------
`projects` is a registry and an archival marker in one table. An absent row
is an active, unregistered Project, because the local runtime addresses a
fixed `DEFAULT_PROJECT_ID` that no provisioning step ever creates. Archiving
a Project that was never registered writes a marker row whose `name` is NULL;
only a row carrying a `name` is a readable `ProjectRecord`. `project_archived`
therefore keeps reading an absent row as active, and `create_artifact`,
`commit_version`, and `create_session` keep working against a Project that no
caller provisioned.

`sessions` is a full registry with no marker semantics. A Session belongs to
exactly one Project: the primary key is `(org_id, id)` rather than the Project
triple, so one Session identity can never be registered under two Projects
even if an application-level check were removed.

Plans, approvals, Runs, and executions
--------------------------------------
`action_plans` is append-only by construction: no statement in this module
updates it, so a plan is immutable once created and the digest it binds cannot
drift. `plan_sha256` is derived by `plan_digest` from the plan's own bindings
including the canonical `ResearchIntent` digest, exactly as `object_key` is
derived rather than accepted, so a caller can neither choose a plan digest nor
keep one after changing an intent field.

`plan_approvals` is one-use. `start_run` consumes it, inserts the `executions`
row, and advances the Run out of `queued` in a single `BEGIN IMMEDIATE`
transaction, so an approval is never consumed without an execution and an
execution never begins without consuming its approval. Consumption is a
compare-and-swap on `consumed_at IS NULL`; a replay, an expiry, a mismatched
digest, or a foreign approver rolls the whole transaction back and writes
nothing at all.

`runs` and `executions` make a truncated chain queryable rather than merely
readable as a file. A Run is born `queued`, advances to `running` only through
approval consumption, and reaches exactly one of `completed`, `failed`, or
`cancelled`. `executions.id` is the produced-execution identity and its primary
key is the fence: two Runs cannot claim one execution id. `run_outputs` records
each committed output under a gapless `sequence` validated against the current
head, and the projection orders by that column explicitly.

Terminal marking and output recording deliberately survive Project archival.
Refusing them would leave a Run permanently `running` precisely when a Project
was archived mid-chain, which is the moment the truncation record matters most.
Authorizing *new* work -- creating a plan, granting an approval, creating a Run,
or starting one -- remains blocked by archival.

Reviews and findings
--------------------
`reviews` pins an exact, immutable evidence set and is deduplicated by the
canonical digest `pinned_input_digest` derives from those pins. The digest is
server-derived exactly as `object_key` and `plan_sha256` are, and pins are
sorted and deduplicated before hashing, so no caller can reorder or repeat
evidence to obtain a second digest for the same Review. `UNIQUE (org_id,
project_id, pinned_input_sha256)` is the schema backstop under the
application-level lookup.

`review_findings` is written exactly once per Review. `submit_review_findings`
completes the Review and writes every finding in one `BEGIN IMMEDIATE`
transaction, guarded by a compare-and-swap on `findings_submitted_at IS NULL`,
and carries two independent `UNIQUE` backstops -- one on `(review_id,
sequence)` and one on `(review_id, rule_id)` -- so a second submission is
refused by the schema even if that check were deleted.

`pinned_run_evidence` is the read-only boundary the Reviewer is built on. It
returns inert values only: records, digests, and bytes, with no connection, no
store, and no callable attached. A Version whose stored bytes disagree with
their recorded digest is reported as `ContentState.TAMPERED` and carries no
content, because the Reviewer must be able to record that mismatch rather than
be stopped by it; `read_content` is unchanged and still refuses to hand back
bytes that fail verification.

Execution ownership on `commit_version` and `attach_session`
------------------------------------------------------------
The durable execution-ownership walk lives in
`services/api/artifacts/postgres_operations.references_valid`, on the *commit*
path, and it goes version -> execution -> run -> session and on into
`provider_connections`. The durable `attach_session` has no such check at all;
it validates a live same-Project Session and a same-Project Version, which this
module also does.

`commit_version` binds `EXECUTION_OWNED`: the execution named by
`producing_execution_id` must exist and its Run must resolve, both in exactly
this tenant and Project. It reports `INVALID_LINEAGE`, the same outcome the
durable adapter returns when `references_valid` fails. There is no Version at
all whose producing execution exists nowhere.

`attach_session` reads the producing execution back off the committed Version
row and binds the strictly stronger `EXECUTION_SESSION_OWNED`, which adds the
last step of the durable walk: the Run that owns that execution must be the
Run of *the Session being attached*. `runs` carries `session_id` for exactly
this, and the comparison is made in SQL against the Run row rather than against
anything the caller supplied.

`session_links` carries `producing_execution_id`, derived from the Version row
inside the attaching transaction and never accepted from a caller, so the
ownership chain is readable from the association itself rather than only
re-derivable from a join.

`runs.session_id` is nullable, and deliberately so. A local analysis has always
been able to run with no Session -- `run_analysis` takes one only when its
caller has one, and the HTTP surface registers Sessions without binding a Run
to them -- so a `NOT NULL` column would refuse every existing producing path
rather than strengthen it. Absence is therefore a real state, and it is
resolved by *refusing*: `r.session_id = ?` is NULL for a session-less Run, that
comparison is never true, and the predicate returns no row. A Version produced
by a Run that recorded no Session can be committed, read, reviewed, and
exported, and can be associated with no Session at all.

That is exactly what a null weakens, stated plainly: the ownership chain of a
session-less Run stops at the Run, so such a Version carries no evidence of
which Session commissioned it and can never acquire any. The remaining
asymmetry with `commit_version` follows from the same fact and is not a gap:
association is a predicate over one *pair*, so a Version is legitimately
attachable to its own Run's Session and refused for every other, and a Version
whose Run recorded no Session is refused for all of them.

`create_run` refuses a Run naming a Session that is not live in exactly this
tenant and Project, so a recorded `session_id` always named a real Session when
it was written. Archiving that Session afterwards leaves the Run row untouched
and its earlier associations intact, exactly as archiving a Project leaves a
finished chain readable; it only stops new associations, because
`attach_session` still requires a live Session in its own right.

What remains open, and why it cannot be closed here:

- There is no `provider_connections` table, so the durable walk's requirement
  that the Run's provider connection carry the Version's runtime adapter has
  no local counterpart at all. `runtime_adapter_id` and
  `runtime_connection_id` are therefore still recorded exactly as submitted
  and are checked against nothing.
- The durable walk also pins the Run to `scope.requester_id`. `runs` does
  carry `requester_id`, but a local installation has exactly one operator and
  `create_run` already refuses a Run whose requester is not the caller, so the
  column can only ever hold that one value; binding it again here would assert
  an authorization boundary this module does not have.
- A Run's terminal state is not consulted. A Version committed against a Run
  that later failed or was cancelled keeps its ownership chain, because the
  truncated chain is the record and refusing it would delete the evidence.

Canonical execution inputs
--------------------------
`executions` pins `research_intent_sha256` and `input_sha256` but stored only
those digests, so the two documents that matter most to a reader -- the
`ResearchIntent` and the scientific input -- could not travel in an Export
Pack and stayed self-reported in every pack's
`verification.not_recomputable_from_pack`.

`execution_inputs` persists the canonical bytes behind both digests.
`record_execution_input` refuses any payload that does not hash to the digest
the execution *already* pinned, so a stored blob is never a new truth: the
digest is read back off the `executions` row inside the write transaction and
is never accepted from the caller, exactly as `object_key` and `plan_sha256`
are derived rather than submitted. The primary key `(org_id, execution_id,
kind)` is the schema backstop under the application-level lookup, so one
execution records each kind at most once even if that check were removed.

The bytes live in the same content-addressed blob directory as Version
content, beneath the same owner-only data root, published by the same
fsync-and-rename path and adopted rather than rewritten when identical bytes
already exist. `_referenced_digests` therefore counts them: a canonical input
is a referenced blob, and `sweep_unreferenced_blobs` must not reclaim one.
Nothing about these payloads is ever quoted -- not in a refusal, not in an
exception -- because they are research content; a refusal reports only a
`StoreOutcome`. `execution_input` verifies the stored bytes against the
recorded digest on the way back out and reports absence rather than handing
back content that disagrees with it, so a corrupted blob degrades a pack to
self-reported instead of shipping a document that contradicts the provenance
printed beside it.

Migrations
----------
This module creates its schema with `CREATE TABLE IF NOT EXISTS` and has no
versioning, so every schema change above is visible to a data root written by
an earlier build as a loud failure rather than a silent one. The
`session_links.producing_execution_id` column fails such a root on insert.
`runs.session_id` fails it on every `runs` read and write, because the
projections name the column; that is the intended behaviour, since a missing
column reported as a null Session would be indistinguishable from a Run that
genuinely recorded none. `execution_inputs` is a new table and is simply
created. Tightening `commit_version` needs no migration -- it reads tables that
already exist -- but it does change what an old data root accepts: a Version
committed by an earlier build with an execution that exists nowhere stays
readable and stays attachable-refusing, and no new one can join it.

One remaining divergence from the durable adapter:

- Blobs are addressed by content digest alone, so identical bytes are stored
  once for the whole installation rather than once per Project.

That last point drives the failure policy. Because publication is idempotent
and adoption is automatic, an unreferenced blob is inert: a later commit of
the same content simply adopts the existing file. A failed commit therefore
deletes nothing. Deleting on the failure path would mean racing another
process that has published the same content but not yet committed its row,
and would destroy that process's bytes permanently. Reclamation is instead an
explicit `sweep_unreferenced_blobs` call which serializes against committers
on the database write lock and refuses to touch recently written files.
"""

import hashlib
import json
import os
import re
import sqlite3
import tempfile
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from threading import RLock
from types import TracebackType
from typing import TYPE_CHECKING, ClassVar, Final, Self, cast, final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter
from services.api.artifacts.models import (
    ArtifactRecord,
    ArtifactScope,
    ArtifactVersion,
    SessionArtifactLink,
    Sha256,
    Uuid7,
)
from services.api.artifacts.store_contract import (
    ArtifactCommitError,
    ArtifactStoreError,
    BlobIntegrityError,
    BlobWriteError,
    StoreOutcome,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from .config import LocalPaths

Row = tuple[object, ...]

INTEGER: Final = TypeAdapter(int)
TEXT: Final = TypeAdapter(str)

SHA256_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")
SHARD_WIDTH: Final = 2

# `json_group_array(x ORDER BY x)` is the ordered-aggregate form used by
# VERSION_JSON; SQLite gained aggregate ORDER BY in 3.44.0.
MINIMUM_SQLITE: Final = (3, 44, 0)
UNSUPPORTED_SQLITE: Final = "local Artifact store requires SQLite 3.44 or newer"

DEFAULT_TIMEOUT_SECONDS: Final = 5.0

# A blob published but not yet committed is unreferenced and must survive a
# concurrent sweep. The grace period is orders of magnitude wider than the
# database busy timeout that bounds any in-flight commit.
DEFAULT_SWEEP_GRACE_SECONDS: Final = 86_400.0

MAX_LOCAL_NAME_CHARACTERS: Final = 255

# Domain separator for the derived plan digest. Changing it changes every plan
# digest, which is why it is pinned here rather than assembled at a call site.
ACTION_PLAN_DIGEST_SCHEMA: Final = "nipo.local.action-plan.v1"

# Domain separator for the derived pinned-input digest that deduplicates one
# Review. Pinned here for the same reason the plan schema is: changing it
# changes every digest, and a caller must never be able to pick one.
REVIEW_PINNED_INPUT_DIGEST_SCHEMA: Final = "nipo.local.review-pinned-input.v1"

MAX_LOCAL_MESSAGE_CHARACTERS: Final = 4_000

SCHEMA: Final = (
    # `name` and `created_at` are nullable because this one table carries both
    # roles: a registered Project has them, while a bare archival marker
    # written for a never-registered Project has neither.
    """
    CREATE TABLE IF NOT EXISTS projects (
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      name TEXT,
      created_at TEXT,
      archived INTEGER NOT NULL,
      PRIMARY KEY (org_id, id)
    ) STRICT
    """,
    # The primary key deliberately omits project_id. One Session identity
    # resolves to exactly one Project row, so a Session cannot be registered
    # under two Projects even if the application-level check were removed.
    """
    CREATE TABLE IF NOT EXISTS sessions (
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      id TEXT NOT NULL,
      title TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_active_at TEXT NOT NULL,
      archived INTEGER NOT NULL,
      PRIMARY KEY (org_id, id)
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS artifacts (
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      id TEXT NOT NULL,
      name TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (org_id, id)
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS artifact_versions (
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      id TEXT NOT NULL,
      artifact_id TEXT NOT NULL,
      version_no INTEGER NOT NULL,
      object_key TEXT NOT NULL,
      content_sha256 TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      media_type TEXT NOT NULL,
      producing_execution_id TEXT NOT NULL,
      environment_sha256 TEXT NOT NULL,
      code_sha256 TEXT NOT NULL,
      runtime_adapter_id TEXT NOT NULL,
      runtime_connection_id TEXT NOT NULL,
      skill_content_hashes TEXT NOT NULL,
      source_hashes TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (org_id, id),
      UNIQUE (org_id, project_id, artifact_id, version_no)
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS version_inputs (
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      artifact_version_id TEXT NOT NULL,
      input_version_id TEXT NOT NULL,
      PRIMARY KEY (org_id, artifact_version_id, input_version_id)
    ) STRICT
    """,
    # `producing_execution_id` is derived from the Version row inside the
    # attaching transaction, never accepted from the caller, exactly as
    # `object_key` and `plan_sha256` are. It records which execution owns the
    # Version this association published, so the ownership chain is readable
    # from the association itself rather than only re-derivable from a join.
    """
    CREATE TABLE IF NOT EXISTS session_links (
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      artifact_version_id TEXT NOT NULL,
      producing_execution_id TEXT NOT NULL,
      revision INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (org_id, project_id, session_id, artifact_version_id)
    ) STRICT
    """,
    # No statement in this module updates this table: an ActionPlan is
    # immutable, and `plan_sha256` is always the derived value, never a
    # caller-supplied one.
    """
    CREATE TABLE IF NOT EXISTS action_plans (
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      id TEXT NOT NULL,
      requester_id TEXT NOT NULL,
      research_intent_sha256 TEXT NOT NULL,
      plan_sha256 TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (org_id, id)
    ) STRICT
    """,
    # `UNIQUE (org_id, plan_id)` is the backstop for one-use approval: a plan
    # cannot accumulate a second approval to launder a consumed one. Consuming
    # is a compare-and-swap on `consumed_at IS NULL`.
    """
    CREATE TABLE IF NOT EXISTS plan_approvals (
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      id TEXT NOT NULL,
      plan_id TEXT NOT NULL,
      approver_id TEXT NOT NULL,
      research_intent_sha256 TEXT NOT NULL,
      plan_sha256 TEXT NOT NULL,
      granted_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      consumed_at TEXT,
      consumed_by_run_id TEXT,
      PRIMARY KEY (org_id, id),
      UNIQUE (org_id, plan_id)
    ) STRICT
    """,
    # `session_id` is nullable because a local analysis may legitimately run
    # with no Session, and it is the last step of the ownership chain when it
    # is present. A NULL never compares equal to anything, so the association
    # predicate refuses a session-less Run rather than passing it.
    """
    CREATE TABLE IF NOT EXISTS runs (
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      id TEXT NOT NULL,
      plan_id TEXT NOT NULL,
      approval_id TEXT NOT NULL,
      requester_id TEXT NOT NULL,
      session_id TEXT,
      state TEXT NOT NULL,
      research_intent_sha256 TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      error_type TEXT,
      error_code TEXT,
      PRIMARY KEY (org_id, id)
    ) STRICT
    """,
    # `id` is the produced-execution identity, so this primary key is the
    # execution fence: two Runs cannot claim one execution id. `UNIQUE
    # (org_id, run_id)` is the matching fence in the other direction.
    """
    CREATE TABLE IF NOT EXISTS executions (
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      id TEXT NOT NULL,
      run_id TEXT NOT NULL,
      execution_isolation TEXT NOT NULL,
      input_sha256 TEXT NOT NULL,
      research_intent_sha256 TEXT NOT NULL,
      code_sha256 TEXT NOT NULL,
      environment_sha256 TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (org_id, id),
      UNIQUE (org_id, run_id)
    ) STRICT
    """,
    # One row per execution and kind, holding the digest of the canonical bytes
    # rather than the bytes themselves: the payload lives in the same
    # content-addressed blob directory as Version content. The primary key is
    # the exactly-once backstop under `_input_recorded`, and `content_sha256`
    # is always the digest the execution already pinned, never a submitted one.
    """
    CREATE TABLE IF NOT EXISTS execution_inputs (
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      execution_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      content_sha256 TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (org_id, execution_id, kind)
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS run_outputs (
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      run_id TEXT NOT NULL,
      sequence INTEGER NOT NULL,
      role TEXT NOT NULL,
      name TEXT NOT NULL,
      artifact_id TEXT NOT NULL,
      artifact_version_id TEXT NOT NULL,
      content_sha256 TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (org_id, run_id, sequence),
      UNIQUE (org_id, run_id, artifact_version_id)
    ) STRICT
    """,
    # `UNIQUE (org_id, project_id, pinned_input_sha256)` is the deduplication
    # backstop: the same pinned evidence cannot be reviewed twice even if the
    # application-level lookup in `_open_review_locked` were removed. The digest
    # is derived by `pinned_input_digest`, never accepted from a caller.
    """
    CREATE TABLE IF NOT EXISTS reviews (
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      id TEXT NOT NULL,
      source_run_id TEXT NOT NULL,
      state TEXT NOT NULL,
      pinned_input_sha256 TEXT NOT NULL,
      pinned_artifact_version_ids TEXT NOT NULL,
      pinned_execution_ids TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      findings_submitted_at TEXT,
      error_type TEXT,
      error_code TEXT,
      PRIMARY KEY (org_id, id),
      UNIQUE (org_id, project_id, pinned_input_sha256)
    ) STRICT
    """,
    # Two independent uniqueness backstops for exactly-once submission. A
    # second submission repeats sequence 1 and repeats every rule id, so it
    # collides on both even when the compare-and-swap on
    # `findings_submitted_at IS NULL` is removed.
    """
    CREATE TABLE IF NOT EXISTS review_findings (
      org_id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      review_id TEXT NOT NULL,
      id TEXT NOT NULL,
      sequence INTEGER NOT NULL,
      rule_id TEXT NOT NULL,
      verdict TEXT NOT NULL,
      status TEXT NOT NULL,
      code TEXT NOT NULL,
      message TEXT NOT NULL,
      artifact_version_ids TEXT NOT NULL,
      execution_ids TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (org_id, id),
      UNIQUE (org_id, review_id, sequence),
      UNIQUE (org_id, review_id, rule_id)
    ) STRICT
    """,
    """
    CREATE INDEX IF NOT EXISTS artifact_versions_head
    ON artifact_versions (org_id, project_id, artifact_id, version_no)
    """,
    """
    CREATE INDEX IF NOT EXISTS reviews_by_source_run
    ON reviews (org_id, project_id, source_run_id, created_at DESC, id DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS artifact_versions_content
    ON artifact_versions (content_sha256)
    """,
    """
    CREATE INDEX IF NOT EXISTS sessions_project_history
    ON sessions (org_id, project_id, last_active_at DESC, id DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS runs_unfinished
    ON runs (org_id, project_id, state, created_at DESC, id DESC)
    """,
)


class RunState(StrEnum):
    """Durable lifecycle states of one local research Run."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_RUN_STATES: Final = frozenset(
    {RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED}
)
UNFINISHED_RUN_STATES: Final = (RunState.QUEUED, RunState.RUNNING)


class ApprovalOutcome(StrEnum):
    """Closed outcomes of one atomic approval consumption.

    Every value other than `CONSUMED` rolls the transaction back, so a refused
    claim leaves no approval consumed, no execution row, and no Run started.
    """

    CONSUMED = "consumed"
    NOT_FOUND = "not_found"
    ARCHIVED = "archived"
    FORBIDDEN = "forbidden"
    EXPIRED = "expired"
    REPLAYED = "replayed"
    DIGEST_MISMATCH = "digest_mismatch"
    EXECUTION_CLAIMED = "execution_claimed"


class ExecutionInputKind(StrEnum):
    """The canonical documents whose bytes one execution may persist.

    Each member names a digest the `executions` row already pinned, which is
    the digest the stored bytes are verified against. There is no member for a
    digest the store does not pin, because there would be nothing to check the
    bytes with.
    """

    RESEARCH_INTENT = "research_intent"
    SCIENTIFIC_INPUT = "scientific_input"


class ReviewState(StrEnum):
    """Durable lifecycle states of one persisted trace-only Review."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


OPEN_REVIEW_STATES: Final = (ReviewState.QUEUED, ReviewState.RUNNING)


class ReviewRuleId(StrEnum):
    """The exact review rule identifiers the specification enumerates."""

    RV01 = "RV01"
    RV02 = "RV02"
    RV03 = "RV03"
    RV04 = "RV04"
    RV05 = "RV05"


class ReviewVerdict(StrEnum):
    """Closed finding verdicts.

    `INCONCLUSIVE` is a normal outcome, not a Reviewer failure: evidence that
    is missing, unreachable, or uncheckable takes this verdict and must never
    be recorded as `PASS`.
    """

    PASS = "pass"  # noqa: S105 - a review verdict, not a credential
    WARN = "warn"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


class FindingStatus(StrEnum):
    """Closed dispositions of one recorded finding."""

    OPEN = "open"
    RESOLVED = "resolved"
    REBUTTED = "rebutted"
    ACCEPTED_RISK = "accepted_risk"


class ContentState(StrEnum):
    """How one pinned Version's bytes presented themselves to a reader.

    `TAMPERED` is reported rather than raised so a Reviewer can record the
    mismatch as a finding. `read_content` still refuses to hand back bytes that
    disagree with their recorded digest; this vocabulary adds a diagnosis, it
    does not add a way to obtain unverified content.
    """

    AVAILABLE = "available"
    ABSENT = "absent"
    TAMPERED = "tampered"


class LocalRecord(BaseModel):
    """Shared strict, frozen configuration for local-only durable records."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )


class ActionPlanRecord(LocalRecord):
    """One immutable ActionPlan binding exactly one `ResearchIntent` digest.

    `plan_sha256` is never accepted as submitted: `create_action_plan` rejects
    any value other than the one `plan_digest` derives from this record's own
    bindings, so changing the bound intent digest necessarily changes the plan
    digest too.
    """

    id: Uuid7
    org_id: Uuid7
    project_id: Uuid7
    requester_id: Uuid7
    research_intent_sha256: Sha256
    plan_sha256: Sha256
    created_at: datetime


class PlanApprovalRecord(LocalRecord):
    """One immutable, one-use approval of exactly one ActionPlan."""

    id: Uuid7
    org_id: Uuid7
    project_id: Uuid7
    plan_id: Uuid7
    approver_id: Uuid7
    research_intent_sha256: Sha256
    plan_sha256: Sha256
    granted_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None
    consumed_by_run_id: Uuid7 | None = None


class RunRecord(LocalRecord):
    """One durable Run bound to the plan and approval that authorized it.

    `session_id` is the last step of the ownership chain a Version's
    association is checked against. It is optional because a local analysis may
    run with no Session at all; when it is absent the chain stops at this Run
    and `attach_session` refuses every association for the Versions it
    produced, rather than treating the absence as agreement.
    """

    id: Uuid7
    org_id: Uuid7
    project_id: Uuid7
    plan_id: Uuid7
    approval_id: Uuid7
    requester_id: Uuid7
    session_id: Uuid7 | None = None
    state: RunState
    research_intent_sha256: Sha256
    created_at: datetime
    updated_at: datetime
    error_type: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_LOCAL_NAME_CHARACTERS,
    )
    error_code: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_LOCAL_NAME_CHARACTERS,
    )


class ExecutionRecord(LocalRecord):
    """One produced-execution identity and the provenance it pinned.

    `execution_isolation` is recorded exactly as the producer disclosed it and
    is never defaulted here: the store must not invent an isolation claim.
    """

    id: Uuid7
    org_id: Uuid7
    project_id: Uuid7
    run_id: Uuid7
    execution_isolation: str = Field(
        min_length=1,
        max_length=MAX_LOCAL_NAME_CHARACTERS,
    )
    input_sha256: Sha256
    research_intent_sha256: Sha256
    code_sha256: Sha256
    environment_sha256: Sha256
    created_at: datetime


class RunOutputRecord(LocalRecord):
    """One committed output at its exact position in the ordered chain."""

    org_id: Uuid7
    project_id: Uuid7
    run_id: Uuid7
    sequence: int = Field(ge=1)
    role: str = Field(min_length=1, max_length=MAX_LOCAL_NAME_CHARACTERS)
    name: str = Field(min_length=1, max_length=MAX_LOCAL_NAME_CHARACTERS)
    artifact_id: Uuid7
    artifact_version_id: Uuid7
    content_sha256: Sha256
    created_at: datetime


class ReviewRecord(LocalRecord):
    """One persisted Review over an exact, immutable set of pinned evidence.

    `pinned_input_sha256` is never accepted as submitted: `open_review` rejects
    any value other than the one `pinned_input_digest` derives from this
    record's own pins, exactly as `object_key` and `plan_sha256` are derived.
    Two Reviews therefore cannot pin the same evidence under different digests.
    """

    id: Uuid7
    org_id: Uuid7
    project_id: Uuid7
    source_run_id: Uuid7
    state: ReviewState
    pinned_input_sha256: Sha256
    pinned_artifact_version_ids: tuple[Uuid7, ...]
    pinned_execution_ids: tuple[Uuid7, ...]
    created_at: datetime
    updated_at: datetime
    findings_submitted_at: datetime | None = None
    error_type: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_LOCAL_NAME_CHARACTERS,
    )
    error_code: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_LOCAL_NAME_CHARACTERS,
    )


class ReviewFindingRecord(LocalRecord):
    """One immutable finding recorded against exactly one review rule."""

    id: Uuid7
    org_id: Uuid7
    project_id: Uuid7
    review_id: Uuid7
    sequence: int = Field(ge=1)
    rule_id: ReviewRuleId
    verdict: ReviewVerdict
    status: FindingStatus
    code: str = Field(min_length=1, max_length=MAX_LOCAL_NAME_CHARACTERS)
    message: str = Field(min_length=1, max_length=MAX_LOCAL_MESSAGE_CHARACTERS)
    artifact_version_ids: tuple[Uuid7, ...]
    execution_ids: tuple[Uuid7, ...]
    created_at: datetime


class ReviewSubmission(LocalRecord):
    """One whole-Review findings submission, accepted at most once."""

    review_id: Uuid7
    submitted_at: datetime
    findings: tuple[ReviewFindingRecord, ...] = Field(min_length=1)


class RunClaim(LocalRecord):
    """One atomic request to consume an approval and start its execution.

    `research_intent_sha256` is recomputed by the caller from the live
    `ResearchIntent` about to shape the outputs, not read back from any stored
    row, which is what makes a changed intent field invalidate the approval.
    """

    run_id: Uuid7
    approval_id: Uuid7
    research_intent_sha256: Sha256
    execution: ExecutionRecord
    started_at: datetime


class RunCompletion(LocalRecord):
    """One terminal transition for a Run and its non-secret failure reason."""

    run_id: Uuid7
    state: RunState
    finished_at: datetime
    error_type: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_LOCAL_NAME_CHARACTERS,
    )
    error_code: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_LOCAL_NAME_CHARACTERS,
    )


@dataclass(frozen=True, slots=True)
class PinnedOutput:
    """One pinned Version, its disclosed content state, and its bytes.

    Pure data. This object holds no connection, no store, and no callable, so
    anything built from it -- the Reviewer in particular -- has no reachable
    way back to a write or execute path.

    `recorded_sha256` comes from the Run's own output row and `version` from
    the Artifact Version row. They are carried separately on purpose: a reader
    that only ever saw one of them could not detect the two disagreeing.
    """

    role: str
    name: str
    artifact_version_id: UUID
    recorded_sha256: str
    version: ArtifactVersion | None
    content_state: ContentState
    content: bytes | None


@dataclass(frozen=True, slots=True)
class PinnedRunEvidence:
    """One immutable read-only snapshot of everything a Review may inspect.

    Captured by the store, which legitimately owns read access, and handed on
    as inert values. `execution` is `None` when a Run never claimed one, which
    is evidence a Reviewer must be able to report rather than a reason to fail.
    """

    run: RunRecord
    execution: ExecutionRecord | None
    outputs: tuple[PinnedOutput, ...]

    @property
    def artifact_version_ids(self) -> tuple[UUID, ...]:
        """Return each pinned Version identifier in publication order."""
        return tuple(item.artifact_version_id for item in self.outputs)

    @property
    def execution_ids(self) -> tuple[UUID, ...]:
        """Return the produced-execution identity this Run pinned, if any."""
        return () if self.execution is None else (self.execution.id,)


@dataclass(frozen=True, slots=True)
class _ResolvedClaim:
    """The three rows one claim must agree with, read under the write lock."""

    run: RunRecord
    approval: PlanApprovalRecord
    plan: ActionPlanRecord


class ProjectRecord(BaseModel):
    """One registered local Project identity and its archive state."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    id: Uuid7
    org_id: Uuid7
    name: str = Field(min_length=1, max_length=MAX_LOCAL_NAME_CHARACTERS)
    created_at: datetime
    archived: bool = False


class SessionRecord(BaseModel):
    """One local Session identity bound to exactly one Project.

    `last_active_at` is persisted verbatim on creation and is the only field
    `resume_session` advances, so listing orders real resume history rather
    than registration order.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    id: Uuid7
    org_id: Uuid7
    project_id: Uuid7
    title: str = Field(min_length=1, max_length=MAX_LOCAL_NAME_CHARACTERS)
    created_at: datetime
    last_active_at: datetime
    archived: bool = False


ARTIFACT_JSON: Final = """
SELECT json_object(
  'id', a.id, 'org_id', a.org_id, 'project_id', a.project_id,
  'name', a.name, 'created_at', a.created_at
)
FROM artifacts a
WHERE a.org_id = ? AND a.project_id = ? AND a.id = ?
"""

# `archived` is projected through json() so the flag arrives as a JSON boolean
# rather than the stored 0/1 integer, which strict validation would reject.
PROJECT_JSON: Final = """
SELECT json_object(
  'id', p.id, 'org_id', p.org_id, 'name', p.name,
  'created_at', p.created_at,
  'archived', json(CASE WHEN p.archived = 0 THEN 'false' ELSE 'true' END)
)
FROM projects p
WHERE p.org_id = ? AND p.id = ? AND p.name IS NOT NULL
"""

PROJECT_LIST_JSON: Final = """
SELECT json_object(
  'id', p.id, 'org_id', p.org_id, 'name', p.name,
  'created_at', p.created_at,
  'archived', json(CASE WHEN p.archived = 0 THEN 'false' ELSE 'true' END)
)
FROM projects p
WHERE p.org_id = ? AND p.name IS NOT NULL
ORDER BY p.created_at DESC, p.id DESC
"""

SESSION_JSON: Final = """
SELECT json_object(
  'id', s.id, 'org_id', s.org_id, 'project_id', s.project_id,
  'title', s.title, 'created_at', s.created_at,
  'last_active_at', s.last_active_at,
  'archived', json(CASE WHEN s.archived = 0 THEN 'false' ELSE 'true' END)
)
FROM sessions s
WHERE s.org_id = ? AND s.project_id = ? AND s.id = ?
"""

SESSION_LIST_JSON: Final = """
SELECT json_object(
  'id', s.id, 'org_id', s.org_id, 'project_id', s.project_id,
  'title', s.title, 'created_at', s.created_at,
  'last_active_at', s.last_active_at,
  'archived', json(CASE WHEN s.archived = 0 THEN 'false' ELSE 'true' END)
)
FROM sessions s
WHERE s.org_id = ? AND s.project_id = ?
ORDER BY s.last_active_at DESC, s.id DESC
"""

PLAN_JSON: Final = """
SELECT json_object(
  'id', p.id, 'org_id', p.org_id, 'project_id', p.project_id,
  'requester_id', p.requester_id,
  'research_intent_sha256', p.research_intent_sha256,
  'plan_sha256', p.plan_sha256, 'created_at', p.created_at
)
FROM action_plans p
WHERE p.org_id = ? AND p.project_id = ? AND p.id = ?
"""

APPROVAL_JSON: Final = """
SELECT json_object(
  'id', a.id, 'org_id', a.org_id, 'project_id', a.project_id,
  'plan_id', a.plan_id, 'approver_id', a.approver_id,
  'research_intent_sha256', a.research_intent_sha256,
  'plan_sha256', a.plan_sha256, 'granted_at', a.granted_at,
  'expires_at', a.expires_at, 'consumed_at', a.consumed_at,
  'consumed_by_run_id', a.consumed_by_run_id
)
FROM plan_approvals a
WHERE a.org_id = ? AND a.project_id = ? AND a.id = ?
"""

RUN_JSON: Final = """
SELECT json_object(
  'id', r.id, 'org_id', r.org_id, 'project_id', r.project_id,
  'plan_id', r.plan_id, 'approval_id', r.approval_id,
  'requester_id', r.requester_id, 'session_id', r.session_id,
  'state', r.state,
  'research_intent_sha256', r.research_intent_sha256,
  'created_at', r.created_at, 'updated_at', r.updated_at,
  'error_type', r.error_type, 'error_code', r.error_code
)
FROM runs r
WHERE r.org_id = ? AND r.project_id = ? AND r.id = ?
"""

# Every Run of one Project, terminal or not. A reader must be able to see a
# `failed` chain beside a `completed` one without re-executing anything, so
# this projection filters on nothing but the Project.
RUN_LIST_JSON: Final = """
SELECT json_object(
  'id', r.id, 'org_id', r.org_id, 'project_id', r.project_id,
  'plan_id', r.plan_id, 'approval_id', r.approval_id,
  'requester_id', r.requester_id, 'session_id', r.session_id,
  'state', r.state,
  'research_intent_sha256', r.research_intent_sha256,
  'created_at', r.created_at, 'updated_at', r.updated_at,
  'error_type', r.error_type, 'error_code', r.error_code
)
FROM runs r
WHERE r.org_id = ? AND r.project_id = ?
ORDER BY r.created_at DESC, r.id DESC
"""

# The unfinished states are bound as parameters rather than inlined, so the
# queryable definition of "unfinished" cannot drift away from `RunState`.
UNFINISHED_RUN_LIST_JSON: Final = """
SELECT json_object(
  'id', r.id, 'org_id', r.org_id, 'project_id', r.project_id,
  'plan_id', r.plan_id, 'approval_id', r.approval_id,
  'requester_id', r.requester_id, 'session_id', r.session_id,
  'state', r.state,
  'research_intent_sha256', r.research_intent_sha256,
  'created_at', r.created_at, 'updated_at', r.updated_at,
  'error_type', r.error_type, 'error_code', r.error_code
)
FROM runs r
WHERE r.org_id = ? AND r.project_id = ? AND r.state IN (?, ?)
ORDER BY r.created_at DESC, r.id DESC
"""

EXECUTION_JSON: Final = """
SELECT json_object(
  'id', e.id, 'org_id', e.org_id, 'project_id', e.project_id,
  'run_id', e.run_id, 'execution_isolation', e.execution_isolation,
  'input_sha256', e.input_sha256,
  'research_intent_sha256', e.research_intent_sha256,
  'code_sha256', e.code_sha256,
  'environment_sha256', e.environment_sha256,
  'created_at', e.created_at
)
FROM executions e
WHERE e.org_id = ? AND e.project_id = ? AND e.id = ?
"""

# SQL guarantees no row order without an explicit ORDER BY. The whole point of
# `sequence` is the publication order of a possibly truncated chain, so the
# ordering is stated here rather than inherited from the primary key.
RUN_OUTPUT_LIST_JSON: Final = """
SELECT json_object(
  'org_id', o.org_id, 'project_id', o.project_id, 'run_id', o.run_id,
  'sequence', o.sequence, 'role', o.role, 'name', o.name,
  'artifact_id', o.artifact_id,
  'artifact_version_id', o.artifact_version_id,
  'content_sha256', o.content_sha256, 'created_at', o.created_at
)
FROM run_outputs o
WHERE o.org_id = ? AND o.project_id = ? AND o.run_id = ?
ORDER BY o.sequence
"""

REVIEW_JSON: Final = """
SELECT json_object(
  'id', r.id, 'org_id', r.org_id, 'project_id', r.project_id,
  'source_run_id', r.source_run_id, 'state', r.state,
  'pinned_input_sha256', r.pinned_input_sha256,
  'pinned_artifact_version_ids', json(r.pinned_artifact_version_ids),
  'pinned_execution_ids', json(r.pinned_execution_ids),
  'created_at', r.created_at, 'updated_at', r.updated_at,
  'findings_submitted_at', r.findings_submitted_at,
  'error_type', r.error_type, 'error_code', r.error_code
)
FROM reviews r
WHERE r.org_id = ? AND r.project_id = ? AND r.id = ?
"""

REVIEW_BY_PINS_JSON: Final = """
SELECT json_object(
  'id', r.id, 'org_id', r.org_id, 'project_id', r.project_id,
  'source_run_id', r.source_run_id, 'state', r.state,
  'pinned_input_sha256', r.pinned_input_sha256,
  'pinned_artifact_version_ids', json(r.pinned_artifact_version_ids),
  'pinned_execution_ids', json(r.pinned_execution_ids),
  'created_at', r.created_at, 'updated_at', r.updated_at,
  'findings_submitted_at', r.findings_submitted_at,
  'error_type', r.error_type, 'error_code', r.error_code
)
FROM reviews r
WHERE r.org_id = ? AND r.project_id = ? AND r.pinned_input_sha256 = ?
"""

# Findings are the durable record of what was checked, so their order is the
# submitted order and is stated explicitly rather than inherited.
REVIEW_FINDING_LIST_JSON: Final = """
SELECT json_object(
  'id', f.id, 'org_id', f.org_id, 'project_id', f.project_id,
  'review_id', f.review_id, 'sequence', f.sequence,
  'rule_id', f.rule_id, 'verdict', f.verdict, 'status', f.status,
  'code', f.code, 'message', f.message,
  'artifact_version_ids', json(f.artifact_version_ids),
  'execution_ids', json(f.execution_ids),
  'created_at', f.created_at
)
FROM review_findings f
WHERE f.org_id = ? AND f.project_id = ? AND f.review_id = ?
ORDER BY f.sequence
"""

# One execution and the Run it belongs to, resolved in exactly one tenant and
# Project. This is what `commit_version` binds: at commit time there is no
# Session to compare against, so the chain is proven as far as the Run.
EXECUTION_OWNED: Final = """
SELECT e.id FROM executions e
JOIN runs r ON r.org_id = e.org_id AND r.id = e.run_id
WHERE e.org_id = ? AND e.project_id = ? AND e.id = ? AND r.project_id = ?
"""

# The same walk carried its last step, to the Session that owns the Run. This
# is what `attach_session` binds, and it is strictly stronger than
# `EXECUTION_OWNED` on purpose: association is a claim about one (Version,
# Session) pair, not about a Version alone.
#
# `r.session_id = ?` is the refusal for a Run that recorded no Session. SQL
# three-valued logic never makes a NULL comparison true, so absence yields no
# row and the association is refused -- it is not treated as a Session that
# happens to match.
EXECUTION_SESSION_OWNED: Final = """
SELECT e.id FROM executions e
JOIN runs r ON r.org_id = e.org_id AND r.id = e.run_id
WHERE e.org_id = ? AND e.project_id = ? AND e.id = ? AND r.project_id = ?
  AND r.session_id = ?
"""

# The digest of the canonical bytes one execution persisted for one kind. The
# bytes themselves live in the content-addressed blob directory, so this
# projection returns an address rather than research content.
EXECUTION_INPUT: Final = """
SELECT i.content_sha256 FROM execution_inputs i
WHERE i.org_id = ? AND i.project_id = ? AND i.execution_id = ? AND i.kind = ?
"""

# The producing execution one Version pins, read from the Version row rather
# than from any caller-supplied field.
VERSION_EXECUTION: Final = """
SELECT v.producing_execution_id FROM artifact_versions v
WHERE v.org_id = ? AND v.project_id = ? AND v.id = ?
"""

VERSION_JSON: Final = """
SELECT json_object(
  'id', v.id, 'org_id', v.org_id, 'project_id', v.project_id,
  'artifact_id', v.artifact_id, 'version_no', v.version_no,
  'object_key', v.object_key, 'content_sha256', v.content_sha256,
  'size_bytes', v.size_bytes, 'media_type', v.media_type,
  'producing_execution_id', v.producing_execution_id,
  'environment_sha256', v.environment_sha256, 'code_sha256', v.code_sha256,
  'runtime_adapter_id', v.runtime_adapter_id,
  'runtime_connection_id', v.runtime_connection_id,
  'skill_content_hashes', json(v.skill_content_hashes),
  'source_hashes', json(v.source_hashes),
  -- Ordering is currently guaranteed twice: the version_inputs primary key
  -- ends in input_version_id, so the planner already returns digest order.
  -- The explicit ORDER BY is what the contract actually rests on; SQL
  -- guarantees no row order without it, and a future primary-key change
  -- would otherwise break lineage round-tripping silently.
  'input_version_ids', json((
    SELECT json_group_array(d.input_version_id ORDER BY d.input_version_id)
    FROM version_inputs d
    WHERE d.org_id = v.org_id AND d.project_id = v.project_id
      AND d.artifact_version_id = v.id
  )),
  'created_at', v.created_at
)
FROM artifact_versions v
WHERE v.org_id = ? AND v.project_id = ? AND v.id = ?
"""


def _fetch_one(cursor: sqlite3.Cursor) -> Row | None:
    """Return at most one row as an opaque tuple."""
    return cast("Row | None", cursor.fetchone())


def _fetch_all(cursor: sqlite3.Cursor) -> list[Row]:
    """Return every row as opaque tuples."""
    return cast("list[Row]", cursor.fetchall())


def _uuid_json(values: "Sequence[UUID]") -> str:
    """Serialize one identifier list into the canonical stored JSON array."""
    return json.dumps(
        [str(value) for value in values],
        ensure_ascii=True,
        separators=(",", ":"),
    )


def _sync_directory(directory: Path) -> None:
    """Flush one directory entry so a published blob survives a crash."""
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_atomically(path: Path, payload: bytes) -> None:
    """Publish bytes through a temporary file so no reader sees a partial object."""
    descriptor, name = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            _ = handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _ = temporary.replace(path)
        _sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _approval_well_formed(scope: ArtifactScope, approval: PlanApprovalRecord) -> bool:
    """Return whether one submitted approval may be registered at all."""
    return (
        approval.org_id == scope.org_id
        and approval.project_id == scope.project_id
        and approval.approver_id == scope.requester_id
        and approval.consumed_at is None
        and approval.consumed_by_run_id is None
        and approval.granted_at < approval.expires_at
    )


def _run_well_formed(scope: ArtifactScope, run: RunRecord) -> bool:
    """Return whether one submitted Run may be queued at all."""
    return (
        run.org_id == scope.org_id
        and run.project_id == scope.project_id
        and run.requester_id == scope.requester_id
        and run.state is RunState.QUEUED
        and run.error_type is None
        and run.error_code is None
        and run.created_at == run.updated_at
    )


def _claim_consistent(scope: ArtifactScope, claim: RunClaim) -> bool:
    """Return whether one claim's execution record matches the claim itself."""
    return (
        claim.execution.org_id == scope.org_id
        and claim.execution.project_id == scope.project_id
        and claim.execution.run_id == claim.run_id
    )


def _claim_authorized(scope: ArtifactScope, resolved: "_ResolvedClaim") -> bool:
    """Return whether exactly the plan's own requester is claiming it."""
    return (
        resolved.plan.requester_id == scope.requester_id
        and resolved.approval.approver_id == scope.requester_id
        and resolved.run.requester_id == scope.requester_id
    )


def _sorted_unique(values: "Sequence[UUID]") -> bool:
    """Return whether identifiers arrived already sorted and duplicate-free."""
    rendered = [str(value) for value in values]
    return rendered == sorted(set(rendered))


def _review_well_formed(scope: ArtifactScope, review: ReviewRecord) -> bool:
    """Return whether one submitted Review may be queued at all."""
    return (
        review.org_id == scope.org_id
        and review.project_id == scope.project_id
        and review.state is ReviewState.QUEUED
        and review.findings_submitted_at is None
        and review.error_type is None
        and review.error_code is None
        and review.created_at == review.updated_at
        and bool(review.pinned_artifact_version_ids or review.pinned_execution_ids)
        and _sorted_unique(review.pinned_artifact_version_ids)
        and _sorted_unique(review.pinned_execution_ids)
    )


def _submission_well_formed(
    scope: ArtifactScope,
    review: ReviewRecord,
    submission: ReviewSubmission,
) -> bool:
    """Return whether one findings submission matches the Review it names.

    Every finding must reference evidence the Review already pinned, so a
    Reviewer cannot widen the evidence set at submission time, and the rules
    must be distinct so one submission carries at most one verdict per rule.
    """
    pinned_versions = set(review.pinned_artifact_version_ids)
    pinned_executions = set(review.pinned_execution_ids)
    findings = submission.findings
    return (
        submission.review_id == review.id
        and [item.sequence for item in findings] == list(range(1, len(findings) + 1))
        and len({item.rule_id for item in findings}) == len(findings)
        and len({item.id for item in findings}) == len(findings)
        and all(
            item.org_id == scope.org_id
            and item.project_id == scope.project_id
            and item.review_id == review.id
            and item.status is FindingStatus.OPEN
            and set(item.artifact_version_ids) <= pinned_versions
            and set(item.execution_ids) <= pinned_executions
            for item in findings
        )
    )


def _pinned_execution_digest(
    execution: ExecutionRecord,
    kind: ExecutionInputKind,
) -> str:
    """Return the digest this execution already pinned for one input kind.

    The mapping is exhaustive over `ExecutionInputKind` by construction: every
    member names a digest the `executions` row carries, so adding a member with
    no pinned digest fails to type-check here rather than silently storing
    bytes nothing can check.
    """
    if kind is ExecutionInputKind.RESEARCH_INTENT:
        return execution.research_intent_sha256
    return execution.input_sha256


def _completion_well_formed(completion: RunCompletion) -> bool:
    """Return whether one terminal transition is internally consistent."""
    failed = completion.state is RunState.FAILED
    reported = completion.error_type is not None
    return (
        completion.state in TERMINAL_RUN_STATES
        and failed == reported
        and (failed or completion.error_code is None)
    )


def _terminal_sources(state: RunState) -> frozenset[RunState]:
    """Return the states from which one terminal transition is legal.

    Only a Run that actually started may complete. A Run may fail or be
    cancelled before it starts, because a refused approval and an operator
    cancellation both terminate a `queued` Run that never ran.
    """
    if state is RunState.COMPLETED:
        return frozenset({RunState.RUNNING})
    return frozenset({RunState.QUEUED, RunState.RUNNING})


def _sweep_blobs(
    root: Path,
    referenced: frozenset[str],
    deadline: float,
) -> tuple[str, ...]:
    """Remove aged unreferenced content files and report their digests."""
    removed: list[str] = []
    for path in sorted(root.rglob("*")):
        name = path.name
        if SHA256_PATTERN.fullmatch(name) is None or name in referenced:
            continue
        if not path.is_file() or path.stat().st_mtime > deadline:
            continue
        path.unlink(missing_ok=True)
        removed.append(name)
    return tuple(removed)


@final
class LocalArtifactStore:
    """Persist Artifact metadata in SQLite and content in sharded local blobs."""

    def __init__(
        self,
        paths: "LocalPaths",
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        """Open the local database in WAL mode and create the schema once."""
        if sqlite3.sqlite_version_info < MINIMUM_SQLITE:
            raise ArtifactStoreError(UNSUPPORTED_SQLITE)
        paths.ensure()
        self._paths = paths
        self._lock = RLock()
        try:
            self._connection = sqlite3.connect(
                paths.database,
                isolation_level=None,
                check_same_thread=False,
                timeout=timeout,
            )
            _ = self._connection.execute("PRAGMA journal_mode = WAL")
            _ = self._connection.execute("PRAGMA synchronous = FULL")
            for statement in SCHEMA:
                _ = self._connection.execute(statement)
        except sqlite3.Error as error:
            raise ArtifactStoreError from error

    def __enter__(self) -> Self:
        """Return the open store for scoped local use."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the underlying database connection."""
        self.close()

    def close(self) -> None:
        """Release the SQLite connection held by this installation."""
        with self._lock, suppress(sqlite3.Error):
            self._connection.close()

    @staticmethod
    def object_key(scope: ArtifactScope, content_sha256: str) -> str:
        """Derive the only accepted tenant and Project content address."""
        return f"org/{scope.org_id}/project/{scope.project_id}/sha256/{content_sha256}"

    def create_artifact(
        self,
        scope: ArtifactScope,
        artifact: ArtifactRecord,
    ) -> StoreOutcome:
        """Create one Project-owned Artifact identity."""
        return self._transact(
            lambda: self._create_locked(scope, artifact),
            StoreOutcome.CREATED,
            StoreOutcome.NOT_FOUND,
        )

    def artifact(
        self,
        scope: ArtifactScope,
        artifact_id: UUID,
    ) -> ArtifactRecord | None:
        """Read one Artifact only in its exact tenant and Project."""
        with self._lock:
            try:
                if self._archived(scope):
                    return None
                row = _fetch_one(
                    self._connection.execute(
                        ARTIFACT_JSON,
                        (str(scope.org_id), str(scope.project_id), str(artifact_id)),
                    )
                )
            except sqlite3.Error as error:
                raise ArtifactStoreError from error
        if row is None:
            return None
        return ArtifactRecord.model_validate_json(TEXT.validate_python(row[0]))

    def commit_version(
        self,
        scope: ArtifactScope,
        base_version_no: int,
        version: ArtifactVersion,
        payload: bytes,
    ) -> StoreOutcome:
        """Atomically append one Version against its base."""
        with self._lock:
            return self._commit_guarded(scope, base_version_no, version, payload)

    def version(
        self,
        scope: ArtifactScope,
        version_id: UUID,
    ) -> ArtifactVersion | None:
        """Read one Version only in its exact tenant and Project."""
        with self._lock:
            try:
                if self._archived(scope):
                    return None
                return self._version_locked(scope, version_id)
            except sqlite3.Error as error:
                raise ArtifactStoreError from error

    def read_content(self, scope: ArtifactScope, version_id: UUID) -> bytes | None:
        """Read checksum-verified local bytes for an authorized Version."""
        outcome, _, payload = self.redeem_content(scope, version_id)
        return payload if outcome is StoreOutcome.CREATED else None

    def redeem_content(
        self,
        scope: ArtifactScope,
        version_id: UUID,
    ) -> tuple[StoreOutcome, ArtifactVersion | None, bytes | None]:
        """Read Version and content atomically for an active Project."""
        with self._lock:
            try:
                if self._archived(scope):
                    return StoreOutcome.ARCHIVED, None, None
                version = self._version_locked(scope, version_id)
            except sqlite3.Error as error:
                raise ArtifactStoreError from error
            if version is None:
                return StoreOutcome.NOT_FOUND, None, None
            return StoreOutcome.CREATED, version, self._read_blob(version)

    def lineage(
        self,
        scope: ArtifactScope,
        version_id: UUID,
    ) -> tuple[UUID, ...] | None:
        """Return pinned input Version IDs without resolving latest."""
        version = self.version(scope, version_id)
        return None if version is None else version.input_version_ids

    def attach_session(
        self,
        scope: ArtifactScope,
        link: SessionArtifactLink,
    ) -> StoreOutcome:
        """Create one unique version-level association to a live Session."""
        return self._transact(
            lambda: self._attach_locked(scope, link),
            StoreOutcome.CREATED,
            StoreOutcome.ASSOCIATION_EXISTS,
        )

    def project_archived(self, scope: ArtifactScope) -> bool:
        """Return whether writes and downloads are blocked."""
        with self._lock:
            try:
                return self._archived(scope)
            except sqlite3.Error as error:
                raise ArtifactStoreError from error

    def archive_project(self, scope: ArtifactScope) -> None:
        """Mark the authorized Project archived for the local lifecycle."""
        with self._lock:
            try:
                _ = self._connection.execute("BEGIN IMMEDIATE")
                _ = self._connection.execute(
                    "INSERT INTO projects (org_id, id, archived) VALUES (?, ?, 1) "
                    "ON CONFLICT (org_id, id) DO UPDATE SET archived = 1",
                    (str(scope.org_id), str(scope.project_id)),
                )
                _ = self._connection.execute("COMMIT")
            except sqlite3.Error as error:
                self._rollback()
                raise ArtifactStoreError from error

    def create_project(
        self,
        scope: ArtifactScope,
        project: ProjectRecord,
    ) -> StoreOutcome:
        """Register one active Project identity for the authorized tenant."""
        return self._transact(
            lambda: self._create_project_locked(scope, project),
            StoreOutcome.CREATED,
            StoreOutcome.NOT_FOUND,
        )

    def project(self, scope: ArtifactScope) -> ProjectRecord | None:
        """Read the authorized Project, or None when it was never registered.

        Unlike `artifact` and `version` this does not hide an archived
        Project: archival is a lifecycle state the operator must be able to
        observe and list.
        """
        with self._lock:
            try:
                row = _fetch_one(
                    self._connection.execute(
                        PROJECT_JSON,
                        (str(scope.org_id), str(scope.project_id)),
                    )
                )
            except sqlite3.Error as error:
                raise ArtifactStoreError from error
        if row is None:
            return None
        return ProjectRecord.model_validate_json(TEXT.validate_python(row[0]))

    def projects(self, org_id: UUID) -> tuple[ProjectRecord, ...]:
        """List every registered Project newest first within one tenant."""
        with self._lock:
            try:
                rows = _fetch_all(
                    self._connection.execute(PROJECT_LIST_JSON, (str(org_id),))
                )
            except sqlite3.Error as error:
                raise ArtifactStoreError from error
        return tuple(
            ProjectRecord.model_validate_json(TEXT.validate_python(row[0]))
            for row in rows
        )

    def create_session(
        self,
        scope: ArtifactScope,
        session: SessionRecord,
    ) -> StoreOutcome:
        """Register one Session owned by exactly the authorized Project."""
        return self._transact(
            lambda: self._create_session_locked(scope, session),
            StoreOutcome.CREATED,
            StoreOutcome.NOT_FOUND,
        )

    def session(
        self,
        scope: ArtifactScope,
        session_id: UUID,
    ) -> SessionRecord | None:
        """Read one Session only in its exact tenant and active Project."""
        with self._lock:
            try:
                if self._archived(scope):
                    return None
                row = _fetch_one(
                    self._connection.execute(
                        SESSION_JSON,
                        (
                            str(scope.org_id),
                            str(scope.project_id),
                            str(session_id),
                        ),
                    )
                )
            except sqlite3.Error as error:
                raise ArtifactStoreError from error
        if row is None:
            return None
        return SessionRecord.model_validate_json(TEXT.validate_python(row[0]))

    def sessions(self, scope: ArtifactScope) -> tuple[SessionRecord, ...]:
        """List one active Project's Sessions most recently active first."""
        with self._lock:
            try:
                if self._archived(scope):
                    return ()
                rows = _fetch_all(
                    self._connection.execute(
                        SESSION_LIST_JSON,
                        (str(scope.org_id), str(scope.project_id)),
                    )
                )
            except sqlite3.Error as error:
                raise ArtifactStoreError from error
        return tuple(
            SessionRecord.model_validate_json(TEXT.validate_python(row[0]))
            for row in rows
        )

    def resume_session(
        self,
        scope: ArtifactScope,
        session_id: UUID,
        resumed_at: datetime,
    ) -> StoreOutcome:
        """Advance one live same-Project Session's last active timestamp."""
        return self._transact(
            lambda: self._resume_session_locked(scope, session_id, resumed_at),
            StoreOutcome.CREATED,
            StoreOutcome.NOT_FOUND,
        )

    def archive_session(
        self,
        scope: ArtifactScope,
        session_id: UUID,
    ) -> StoreOutcome:
        """Archive one live same-Project Session, reporting a prior archive."""
        return self._transact(
            lambda: self._archive_session_locked(scope, session_id),
            StoreOutcome.CREATED,
            StoreOutcome.NOT_FOUND,
        )

    @staticmethod
    def plan_digest(
        scope: ArtifactScope,
        plan_id: UUID,
        research_intent_sha256: str,
    ) -> str:
        """Derive the only accepted plan digest from one plan's bindings.

        Server-derived exactly as `object_key` is: the producer never chooses
        a plan digest, and a plan bound to a different `ResearchIntent` digest
        cannot keep the digest that authorized the first one.
        """
        return hashlib.sha256(
            json.dumps(
                {
                    "schema": ACTION_PLAN_DIGEST_SCHEMA,
                    "org_id": str(scope.org_id),
                    "project_id": str(scope.project_id),
                    "requester_id": str(scope.requester_id),
                    "plan_id": str(plan_id),
                    "research_intent_sha256": research_intent_sha256,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()

    def create_action_plan(
        self,
        scope: ArtifactScope,
        plan: ActionPlanRecord,
    ) -> StoreOutcome:
        """Create one immutable ActionPlan bound to one intent digest."""
        return self._transact(
            lambda: self._create_plan_locked(scope, plan),
            StoreOutcome.CREATED,
            StoreOutcome.NOT_FOUND,
        )

    def action_plan(
        self,
        scope: ArtifactScope,
        plan_id: UUID,
    ) -> ActionPlanRecord | None:
        """Read one ActionPlan only in its exact tenant and Project."""
        with self._lock:
            try:
                return self._plan_locked(scope, plan_id)
            except sqlite3.Error as error:
                raise ArtifactStoreError from error

    def grant_approval(
        self,
        scope: ArtifactScope,
        approval: PlanApprovalRecord,
    ) -> StoreOutcome:
        """Approve one plan once, for its own requester only."""
        return self._transact(
            lambda: self._grant_approval_locked(scope, approval),
            StoreOutcome.CREATED,
            StoreOutcome.ASSOCIATION_EXISTS,
        )

    def plan_approval(
        self,
        scope: ArtifactScope,
        approval_id: UUID,
    ) -> PlanApprovalRecord | None:
        """Read one approval and its consumption state."""
        with self._lock:
            try:
                return self._approval_locked(scope, approval_id)
            except sqlite3.Error as error:
                raise ArtifactStoreError from error

    def create_run(self, scope: ArtifactScope, run: RunRecord) -> StoreOutcome:
        """Queue one Run against the plan and approval that must authorize it."""
        return self._transact(
            lambda: self._create_run_locked(scope, run),
            StoreOutcome.CREATED,
            StoreOutcome.NOT_FOUND,
        )

    def start_run(self, scope: ArtifactScope, claim: RunClaim) -> ApprovalOutcome:
        """Consume one approval and start its execution in one transaction.

        Consumption, execution creation, and the `queued -> running` transition
        commit together, so an approval is never spent without an execution and
        an execution never begins without spending its approval. Every refusal
        rolls back and leaves no durable trace of the attempt.
        """
        return self._transact(
            lambda: self._start_run_locked(scope, claim),
            ApprovalOutcome.CONSUMED,
            ApprovalOutcome.EXECUTION_CLAIMED,
        )

    def append_run_output(
        self,
        scope: ArtifactScope,
        output: RunOutputRecord,
    ) -> StoreOutcome:
        """Append one committed output at the next position in the chain."""
        return self._transact(
            lambda: self._append_output_locked(scope, output),
            StoreOutcome.CREATED,
            StoreOutcome.ASSOCIATION_EXISTS,
        )

    def finish_run(
        self,
        scope: ArtifactScope,
        completion: RunCompletion,
    ) -> StoreOutcome:
        """Move one Run to a terminal state, recording any failure reason.

        Deliberately not blocked by Project archival: refusing to mark a Run
        would leave it `running` forever exactly when a Project was archived
        mid-chain, destroying the truncation record instead of preserving it.
        """
        return self._transact(
            lambda: self._finish_run_locked(scope, completion),
            StoreOutcome.CREATED,
            StoreOutcome.NOT_FOUND,
        )

    def run(self, scope: ArtifactScope, run_id: UUID) -> RunRecord | None:
        """Read one Run regardless of archival, because it is the evidence."""
        with self._lock:
            try:
                return self._run_locked(scope, run_id)
            except sqlite3.Error as error:
                raise ArtifactStoreError from error

    def runs(self, scope: ArtifactScope) -> tuple[RunRecord, ...]:
        """List every Run of one Project, newest first, regardless of state.

        Archival is not a filter here for the same reason `run` is not: a Run
        record is the evidence that a chain completed or died, and hiding it
        when a Project is archived would make truncation undetectable exactly
        when it matters most.
        """
        with self._lock:
            try:
                rows = _fetch_all(
                    self._connection.execute(
                        RUN_LIST_JSON,
                        (str(scope.org_id), str(scope.project_id)),
                    )
                )
            except sqlite3.Error as error:
                raise ArtifactStoreError from error
        return tuple(
            RunRecord.model_validate_json(TEXT.validate_python(row[0])) for row in rows
        )

    def unfinished_runs(self, scope: ArtifactScope) -> tuple[RunRecord, ...]:
        """List every Run still `queued` or `running`, newest first."""
        with self._lock:
            try:
                rows = _fetch_all(
                    self._connection.execute(
                        UNFINISHED_RUN_LIST_JSON,
                        (
                            str(scope.org_id),
                            str(scope.project_id),
                            *(state.value for state in UNFINISHED_RUN_STATES),
                        ),
                    )
                )
            except sqlite3.Error as error:
                raise ArtifactStoreError from error
        return tuple(
            RunRecord.model_validate_json(TEXT.validate_python(row[0])) for row in rows
        )

    def execution(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
    ) -> ExecutionRecord | None:
        """Read one produced execution and its disclosed isolation."""
        with self._lock:
            try:
                row = _fetch_one(
                    self._connection.execute(
                        EXECUTION_JSON,
                        (
                            str(scope.org_id),
                            str(scope.project_id),
                            str(execution_id),
                        ),
                    )
                )
            except sqlite3.Error as error:
                raise ArtifactStoreError from error
        if row is None:
            return None
        return ExecutionRecord.model_validate_json(TEXT.validate_python(row[0]))

    def execution_for_run(
        self,
        scope: ArtifactScope,
        run_id: UUID,
    ) -> ExecutionRecord | None:
        """Read the one execution a Run claimed, or None when it claimed none.

        `None` is a real answer, not an error: a Run refused at approval
        consumption never claims an execution, and a reader must be able to
        see that rather than be handed an invented isolation level.
        """
        with self._lock:
            try:
                return self._execution_for_run_locked(scope, run_id)
            except sqlite3.Error as error:
                raise ArtifactStoreError from error

    def record_execution_input(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
        kind: ExecutionInputKind,
        payload: bytes,
    ) -> StoreOutcome:
        """Persist the canonical bytes behind one digest this execution pinned.

        The digest is read back off the `executions` row inside the write
        transaction, never accepted from the caller, and the payload must hash
        to it. Bytes that do not are refused as `INVALID_LINEAGE`: a stored
        blob that disagrees with the pinned digest would be a second, silently
        contradictory answer to a question the execution already answered.

        Nothing about the payload appears in the outcome. These are research
        content, so a refusal reports only which rule refused it.

        Returns:
            `CREATED` when the bytes were published and recorded, `ARCHIVED`
            for an archived Project, `NOT_FOUND` when the execution or its Run
            does not resolve in this exact tenant and Project,
            `INVALID_LINEAGE` when the payload does not hash to the pinned
            digest, and `ASSOCIATION_EXISTS` when this execution already
            recorded this kind.
        """
        with self._lock:
            try:
                return self._transact(
                    lambda: self._record_input_locked(
                        scope,
                        execution_id,
                        kind,
                        payload,
                    ),
                    StoreOutcome.CREATED,
                    StoreOutcome.ASSOCIATION_EXISTS,
                )
            except (BlobIntegrityError, BlobWriteError):
                # `_transact` normalizes sqlite failures only, so a blob
                # failure would otherwise escape with the transaction still
                # open. The outer lock makes the rollback race-free, and
                # nothing is deleted: an orphaned blob is inert and is
                # reclaimed by `sweep_unreferenced_blobs`.
                self._rollback()
                raise

    def execution_input(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
        kind: ExecutionInputKind,
    ) -> bytes | None:
        """Read one execution's persisted canonical bytes, verified on the way out.

        `None` means the bytes cannot be handed back: never recorded, blocked
        by Project archival exactly as Version content is, missing from disk,
        or disagreeing with the digest recorded for them. Content that fails
        verification is withheld rather than returned, so a caller can only
        ever attest bytes that still hash to what the execution pinned.
        """
        with self._lock:
            try:
                if self._archived(scope):
                    return None
                row = _fetch_one(
                    self._connection.execute(
                        EXECUTION_INPUT,
                        (
                            str(scope.org_id),
                            str(scope.project_id),
                            str(execution_id),
                            kind.value,
                        ),
                    )
                )
            except sqlite3.Error as error:
                raise ArtifactStoreError from error
            if row is None:
                return None
            return self._verified_blob(TEXT.validate_python(row[0]))

    def run_outputs(
        self,
        scope: ArtifactScope,
        run_id: UUID,
    ) -> tuple[RunOutputRecord, ...]:
        """List one Run's committed outputs in ascending sequence order."""
        with self._lock:
            try:
                rows = _fetch_all(
                    self._connection.execute(
                        RUN_OUTPUT_LIST_JSON,
                        (str(scope.org_id), str(scope.project_id), str(run_id)),
                    )
                )
            except sqlite3.Error as error:
                raise ArtifactStoreError from error
        return tuple(
            RunOutputRecord.model_validate_json(TEXT.validate_python(row[0]))
            for row in rows
        )

    @staticmethod
    def pinned_input_digest(
        scope: ArtifactScope,
        source_run_id: UUID,
        artifact_version_ids: "Sequence[UUID]",
        execution_ids: "Sequence[UUID]",
    ) -> str:
        """Derive the only accepted canonical digest of one Review's pins.

        Server-derived exactly as `object_key` and `plan_digest` are. Pins are
        sorted and deduplicated before hashing, so a caller cannot reorder or
        repeat the same evidence to obtain a second digest and run the same
        Review twice.
        """
        return hashlib.sha256(
            json.dumps(
                {
                    "schema": REVIEW_PINNED_INPUT_DIGEST_SCHEMA,
                    "org_id": str(scope.org_id),
                    "project_id": str(scope.project_id),
                    "source_run_id": str(source_run_id),
                    "artifact_version_ids": sorted(
                        {str(value) for value in artifact_version_ids}
                    ),
                    "execution_ids": sorted({str(value) for value in execution_ids}),
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()

    def open_review(self, scope: ArtifactScope, review: ReviewRecord) -> StoreOutcome:
        """Queue one Review over an exact set of already-pinned evidence.

        Returns `ASSOCIATION_EXISTS` when the same pinned-input digest has
        already been reviewed, which is the deduplication the contract
        requires: the same evidence is never reviewed twice.
        """
        return self._transact(
            lambda: self._open_review_locked(scope, review),
            StoreOutcome.CREATED,
            StoreOutcome.ASSOCIATION_EXISTS,
        )

    def start_review(
        self,
        scope: ArtifactScope,
        review_id: UUID,
        started_at: datetime,
    ) -> StoreOutcome:
        """Advance exactly one queued Review into `running`."""
        return self._transact(
            lambda: self._start_review_locked(scope, review_id, started_at),
            StoreOutcome.CREATED,
            StoreOutcome.ASSOCIATION_EXISTS,
        )

    def submit_review_findings(
        self,
        scope: ArtifactScope,
        submission: ReviewSubmission,
    ) -> StoreOutcome:
        """Record one Review's findings exactly once and complete it.

        Completion and the findings commit together. The compare-and-swap on
        `findings_submitted_at IS NULL` refuses a second submission, and the
        two `UNIQUE` constraints on `review_findings` refuse it again at the
        schema level if that check is ever removed.
        """
        return self._transact(
            lambda: self._submit_findings_locked(scope, submission),
            StoreOutcome.CREATED,
            StoreOutcome.ASSOCIATION_EXISTS,
        )

    def fail_review(
        self,
        scope: ArtifactScope,
        review_id: UUID,
        failed_at: datetime,
        error_type: str,
        error_code: str | None = None,
    ) -> StoreOutcome:
        """Close one unfinished Review as `failed` with a non-secret reason."""
        return self._transact(
            lambda: self._fail_review_locked(
                scope,
                review_id,
                failed_at,
                error_type,
                error_code,
            ),
            StoreOutcome.CREATED,
            StoreOutcome.ASSOCIATION_EXISTS,
        )

    def review(self, scope: ArtifactScope, review_id: UUID) -> ReviewRecord | None:
        """Read one Review regardless of archival, because it is the evidence."""
        with self._lock:
            try:
                return self._review_locked(scope, review_id)
            except sqlite3.Error as error:
                raise ArtifactStoreError from error

    def review_for_pinned_inputs(
        self,
        scope: ArtifactScope,
        pinned_input_sha256: str,
    ) -> ReviewRecord | None:
        """Read the Review already covering one canonical pinned-input digest."""
        with self._lock:
            try:
                row = _fetch_one(
                    self._connection.execute(
                        REVIEW_BY_PINS_JSON,
                        (
                            str(scope.org_id),
                            str(scope.project_id),
                            pinned_input_sha256,
                        ),
                    )
                )
            except sqlite3.Error as error:
                raise ArtifactStoreError from error
        if row is None:
            return None
        return ReviewRecord.model_validate_json(TEXT.validate_python(row[0]))

    def review_findings(
        self,
        scope: ArtifactScope,
        review_id: UUID,
    ) -> tuple[ReviewFindingRecord, ...]:
        """List one Review's findings in ascending submitted order."""
        with self._lock:
            try:
                rows = _fetch_all(
                    self._connection.execute(
                        REVIEW_FINDING_LIST_JSON,
                        (str(scope.org_id), str(scope.project_id), str(review_id)),
                    )
                )
            except sqlite3.Error as error:
                raise ArtifactStoreError from error
        return tuple(
            ReviewFindingRecord.model_validate_json(TEXT.validate_python(row[0]))
            for row in rows
        )

    def pinned_run_evidence(
        self,
        scope: ArtifactScope,
        run_id: UUID,
    ) -> PinnedRunEvidence | None:
        """Capture one Run's pinned Versions and bytes as inert read-only data.

        This is the whole boundary between the producing side and the Reviewer.
        What leaves here is values -- records, digests, and bytes -- with no
        connection, no store, and no callable attached, so a Reviewer built on
        the result has no reachable route to a write or execute path.

        A Version whose stored bytes disagree with their recorded digest is
        reported as `ContentState.TAMPERED` with no content rather than
        raising, because a Reviewer must be able to record that mismatch as a
        finding. `read_content` is untouched and still refuses such bytes.
        """
        with self._lock:
            try:
                run = self._run_locked(scope, run_id)
                if run is None:
                    return None
                outputs = self.run_outputs(scope, run_id)
                execution = self._execution_for_run_locked(scope, run_id)
                pinned = tuple(
                    self._pinned_output_locked(scope, output) for output in outputs
                )
            except sqlite3.Error as error:
                raise ArtifactStoreError from error
            return PinnedRunEvidence(run=run, execution=execution, outputs=pinned)

    def sweep_unreferenced_blobs(
        self,
        min_age_seconds: float = DEFAULT_SWEEP_GRACE_SECONDS,
    ) -> tuple[str, ...]:
        """Reclaim aged unreferenced content and report the digests removed.

        Held under the database write lock so no other process can commit a
        Version while the reference set is computed, and bounded by an age
        filter so content published by an in-flight commit is never swept.
        """
        deadline = time.time() - min_age_seconds
        with self._lock:
            try:
                _ = self._connection.execute("BEGIN IMMEDIATE")
                referenced = self._referenced_digests()
                removed = _sweep_blobs(self._paths.blobs, referenced, deadline)
                _ = self._connection.execute("COMMIT")
            except sqlite3.Error as error:
                self._rollback()
                raise ArtifactStoreError from error
            except OSError as error:
                self._rollback()
                raise BlobWriteError from error
            return removed

    def _transact[OutcomeT: StrEnum](
        self,
        operation: "Callable[[], OutcomeT]",
        committed: OutcomeT,
        integrity: OutcomeT,
    ) -> OutcomeT:
        """Run one guarded transition and normalize its failure modes.

        `BEGIN IMMEDIATE` is issued inside the try so a busy or locked
        database surfaces as `ArtifactStoreError` rather than a raw sqlite3
        exception, and only the caller's success value commits: every
        rejecting outcome rolls back and writes nothing. The outcome vocabulary
        is a type parameter so approval consumption can report why it refused
        without borrowing an unrelated `StoreOutcome` member.
        """
        with self._lock:
            try:
                _ = self._connection.execute("BEGIN IMMEDIATE")
                outcome = operation()
                if outcome is committed:
                    _ = self._connection.execute("COMMIT")
                else:
                    self._rollback()
            except sqlite3.IntegrityError:
                self._rollback()
                return integrity
            except sqlite3.Error as error:
                self._rollback()
                raise ArtifactStoreError from error
            return outcome

    def _create_project_locked(
        self,
        scope: ArtifactScope,
        project: ProjectRecord,
    ) -> StoreOutcome:
        """Validate the submitted identity then register one Project row."""
        if (
            project.org_id != scope.org_id
            or project.id != scope.project_id
            or project.archived
        ):
            return StoreOutcome.NOT_FOUND
        if self._archived(scope):
            return StoreOutcome.ARCHIVED
        if self._project_registered(scope):
            return StoreOutcome.NOT_FOUND
        _ = self._connection.execute(
            "INSERT INTO projects (org_id, id, name, created_at, archived) "
            "VALUES (?, ?, ?, ?, 0)",
            (
                str(scope.org_id),
                str(scope.project_id),
                project.name,
                project.created_at.isoformat(),
            ),
        )
        return StoreOutcome.CREATED

    def _create_session_locked(
        self,
        scope: ArtifactScope,
        session: SessionRecord,
    ) -> StoreOutcome:
        """Validate the Project and Session identity then insert one row."""
        if (
            session.org_id != scope.org_id
            or session.project_id != scope.project_id
            or session.archived
        ):
            return StoreOutcome.NOT_FOUND
        if self._archived(scope):
            return StoreOutcome.ARCHIVED
        # Scoped to the tenant rather than the Project: a Session identity
        # already used under another Project is taken, not creatable here.
        if self._session_taken(scope, session.id):
            return StoreOutcome.NOT_FOUND
        _ = self._connection.execute(
            "INSERT INTO sessions (org_id, project_id, id, title, created_at, "
            "last_active_at, archived) VALUES (?, ?, ?, ?, ?, ?, 0)",
            (
                str(scope.org_id),
                str(scope.project_id),
                str(session.id),
                session.title,
                session.created_at.isoformat(),
                session.last_active_at.isoformat(),
            ),
        )
        return StoreOutcome.CREATED

    def _resume_session_locked(
        self,
        scope: ArtifactScope,
        session_id: UUID,
        resumed_at: datetime,
    ) -> StoreOutcome:
        """Validate the Project and Session then advance the resume time."""
        if self._archived(scope):
            return StoreOutcome.ARCHIVED
        state = self._session_state(scope, session_id)
        if state is None:
            return StoreOutcome.NOT_FOUND
        if state != 0:
            return StoreOutcome.ARCHIVED
        _ = self._connection.execute(
            "UPDATE sessions SET last_active_at = ? "
            "WHERE org_id = ? AND project_id = ? AND id = ?",
            (
                resumed_at.isoformat(),
                str(scope.org_id),
                str(scope.project_id),
                str(session_id),
            ),
        )
        return StoreOutcome.CREATED

    def _archive_session_locked(
        self,
        scope: ArtifactScope,
        session_id: UUID,
    ) -> StoreOutcome:
        """Archive one live Session, reporting an already archived Session."""
        if self._archived(scope):
            return StoreOutcome.ARCHIVED
        state = self._session_state(scope, session_id)
        if state is None:
            return StoreOutcome.NOT_FOUND
        if state != 0:
            return StoreOutcome.ARCHIVED
        _ = self._connection.execute(
            "UPDATE sessions SET archived = 1 "
            "WHERE org_id = ? AND project_id = ? AND id = ?",
            (str(scope.org_id), str(scope.project_id), str(session_id)),
        )
        return StoreOutcome.CREATED

    def _create_plan_locked(
        self,
        scope: ArtifactScope,
        plan: ActionPlanRecord,
    ) -> StoreOutcome:
        """Validate one submitted plan then insert it exactly once."""
        if (
            plan.org_id != scope.org_id
            or plan.project_id != scope.project_id
            or plan.requester_id != scope.requester_id
        ):
            return StoreOutcome.NOT_FOUND
        if plan.plan_sha256 != self.plan_digest(
            scope,
            plan.id,
            plan.research_intent_sha256,
        ):
            return StoreOutcome.INVALID_LINEAGE
        if self._archived(scope):
            return StoreOutcome.ARCHIVED
        if self._plan_taken(scope, plan.id):
            return StoreOutcome.NOT_FOUND
        _ = self._connection.execute(
            "INSERT INTO action_plans (org_id, project_id, id, requester_id, "
            "research_intent_sha256, plan_sha256, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(scope.org_id),
                str(scope.project_id),
                str(plan.id),
                str(plan.requester_id),
                plan.research_intent_sha256,
                plan.plan_sha256,
                plan.created_at.isoformat(),
            ),
        )
        return StoreOutcome.CREATED

    def _grant_approval_locked(
        self,
        scope: ArtifactScope,
        approval: PlanApprovalRecord,
    ) -> StoreOutcome:
        """Validate one submitted approval then register it exactly once."""
        if not _approval_well_formed(scope, approval):
            return StoreOutcome.NOT_FOUND
        if self._archived(scope):
            return StoreOutcome.ARCHIVED
        plan = self._plan_locked(scope, approval.plan_id)
        if plan is None or plan.requester_id != approval.approver_id:
            return StoreOutcome.NOT_FOUND
        if (
            approval.research_intent_sha256 != plan.research_intent_sha256
            or approval.plan_sha256 != plan.plan_sha256
        ):
            return StoreOutcome.INVALID_LINEAGE
        if self._approval_taken(scope, approval.id) or self._plan_approved(
            scope,
            approval.plan_id,
        ):
            return StoreOutcome.ASSOCIATION_EXISTS
        _ = self._connection.execute(
            "INSERT INTO plan_approvals (org_id, project_id, id, plan_id, "
            "approver_id, research_intent_sha256, plan_sha256, granted_at, "
            "expires_at, consumed_at, consumed_by_run_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
            (
                str(scope.org_id),
                str(scope.project_id),
                str(approval.id),
                str(approval.plan_id),
                str(approval.approver_id),
                approval.research_intent_sha256,
                approval.plan_sha256,
                approval.granted_at.isoformat(),
                approval.expires_at.isoformat(),
            ),
        )
        return StoreOutcome.CREATED

    def _create_run_locked(
        self,
        scope: ArtifactScope,
        run: RunRecord,
    ) -> StoreOutcome:
        """Validate one queued Run against its plan, approval, and Session.

        A named Session must be live in exactly this tenant and Project, so a
        recorded `session_id` always answered to a real Session when it was
        written. A Run that names none is accepted: running an analysis outside
        any Session is a supported local workflow, and the association path
        refuses on that absence rather than this one.
        """
        if not _run_well_formed(scope, run):
            return StoreOutcome.NOT_FOUND
        if self._archived(scope):
            return StoreOutcome.ARCHIVED
        plan = self._plan_locked(scope, run.plan_id)
        approval = self._approval_locked(scope, run.approval_id)
        if (
            plan is None
            or approval is None
            or plan.requester_id != run.requester_id
            or approval.plan_id != run.plan_id
            or approval.approver_id != run.requester_id
            or self._run_taken(scope, run.id)
        ):
            return StoreOutcome.NOT_FOUND
        if run.session_id is not None and not self._session_live(scope, run.session_id):
            return StoreOutcome.NOT_FOUND
        if run.research_intent_sha256 != plan.research_intent_sha256:
            return StoreOutcome.INVALID_LINEAGE
        _ = self._connection.execute(
            "INSERT INTO runs (org_id, project_id, id, plan_id, approval_id, "
            "requester_id, session_id, state, research_intent_sha256, "
            "created_at, updated_at, error_type, error_code) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
            (
                str(scope.org_id),
                str(scope.project_id),
                str(run.id),
                str(run.plan_id),
                str(run.approval_id),
                str(run.requester_id),
                None if run.session_id is None else str(run.session_id),
                run.state.value,
                run.research_intent_sha256,
                run.created_at.isoformat(),
                run.updated_at.isoformat(),
            ),
        )
        return StoreOutcome.CREATED

    def _start_run_locked(
        self,
        scope: ArtifactScope,
        claim: RunClaim,
    ) -> ApprovalOutcome:
        """Reject or perform one atomic approval consumption."""
        resolved = self._resolve_claim(scope, claim)
        if isinstance(resolved, ApprovalOutcome):
            return resolved
        rejection = self._reject_claim(scope, claim, resolved)
        if rejection is not None:
            return rejection
        return self._apply_claim(scope, claim)

    def _resolve_claim(
        self,
        scope: ArtifactScope,
        claim: RunClaim,
    ) -> "_ResolvedClaim | ApprovalOutcome":
        """Read the Run, approval, and plan one claim must agree with."""
        if self._archived(scope):
            return ApprovalOutcome.ARCHIVED
        if not _claim_consistent(scope, claim):
            return ApprovalOutcome.NOT_FOUND
        run = self._run_locked(scope, claim.run_id)
        if run is None or run.approval_id != claim.approval_id:
            return ApprovalOutcome.NOT_FOUND
        approval = self._approval_locked(scope, claim.approval_id)
        plan = self._plan_locked(scope, run.plan_id)
        if approval is None or plan is None or approval.plan_id != run.plan_id:
            return ApprovalOutcome.NOT_FOUND
        return _ResolvedClaim(run=run, approval=approval, plan=plan)

    def _reject_claim(
        self,
        scope: ArtifactScope,
        claim: RunClaim,
        resolved: "_ResolvedClaim",
    ) -> ApprovalOutcome | None:
        """Return the rejecting outcome for one claim, or None when valid."""
        if not _claim_authorized(scope, resolved):
            return ApprovalOutcome.FORBIDDEN
        if (
            resolved.approval.consumed_at is not None
            or resolved.approval.consumed_by_run_id is not None
            or resolved.run.state is not RunState.QUEUED
        ):
            return ApprovalOutcome.REPLAYED
        if not self._claim_digests_agree(scope, claim, resolved):
            return ApprovalOutcome.DIGEST_MISMATCH
        if claim.started_at >= resolved.approval.expires_at:
            return ApprovalOutcome.EXPIRED
        if self._execution_taken(scope, claim.execution.id):
            return ApprovalOutcome.EXECUTION_CLAIMED
        return None

    def _claim_digests_agree(
        self,
        scope: ArtifactScope,
        claim: RunClaim,
        resolved: "_ResolvedClaim",
    ) -> bool:
        """Verify the live intent digest against every stored binding.

        The recomputed plan digest is the load-bearing check: an intent field
        edited after approval changes `claim.research_intent_sha256`, and a
        stored intent digest edited to match it no longer derives the plan
        digest the approval was granted against.
        """
        live = claim.research_intent_sha256
        return (
            live == resolved.plan.research_intent_sha256
            and live == resolved.approval.research_intent_sha256
            and live == resolved.run.research_intent_sha256
            and live == claim.execution.research_intent_sha256
            and resolved.approval.plan_sha256 == resolved.plan.plan_sha256
            and resolved.plan.plan_sha256
            == self.plan_digest(scope, resolved.plan.id, live)
        )

    def _apply_claim(self, scope: ArtifactScope, claim: RunClaim) -> ApprovalOutcome:
        """Consume, create the execution, and start the Run in one commit."""
        consumed = self._connection.execute(
            "UPDATE plan_approvals SET consumed_at = ?, consumed_by_run_id = ? "
            "WHERE org_id = ? AND project_id = ? AND id = ? "
            "AND consumed_at IS NULL AND consumed_by_run_id IS NULL",
            (
                claim.started_at.isoformat(),
                str(claim.run_id),
                str(scope.org_id),
                str(scope.project_id),
                str(claim.approval_id),
            ),
        )
        if consumed.rowcount != 1:
            return ApprovalOutcome.REPLAYED
        self._insert_execution(claim.execution)
        started = self._connection.execute(
            "UPDATE runs SET state = ?, updated_at = ? "
            "WHERE org_id = ? AND project_id = ? AND id = ? AND state = ?",
            (
                RunState.RUNNING.value,
                claim.started_at.isoformat(),
                str(scope.org_id),
                str(scope.project_id),
                str(claim.run_id),
                RunState.QUEUED.value,
            ),
        )
        if started.rowcount != 1:
            return ApprovalOutcome.REPLAYED
        return ApprovalOutcome.CONSUMED

    def _insert_execution(self, execution: ExecutionRecord) -> None:
        """Claim one produced-execution identity behind its primary key."""
        _ = self._connection.execute(
            "INSERT INTO executions (org_id, project_id, id, run_id, "
            "execution_isolation, input_sha256, research_intent_sha256, "
            "code_sha256, environment_sha256, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(execution.org_id),
                str(execution.project_id),
                str(execution.id),
                str(execution.run_id),
                execution.execution_isolation,
                execution.input_sha256,
                execution.research_intent_sha256,
                execution.code_sha256,
                execution.environment_sha256,
                execution.created_at.isoformat(),
            ),
        )

    def _append_output_locked(
        self,
        scope: ArtifactScope,
        output: RunOutputRecord,
    ) -> StoreOutcome:
        """Append one output only at the exact next chain position."""
        if output.org_id != scope.org_id or output.project_id != scope.project_id:
            return StoreOutcome.NOT_FOUND
        run = self._run_locked(scope, output.run_id)
        if (
            run is None
            or not self._artifact_exists(scope, output.artifact_id)
            or not self._version_exists(scope, output.artifact_version_id)
        ):
            return StoreOutcome.NOT_FOUND
        if run.state is not RunState.RUNNING:
            return StoreOutcome.STALE
        if output.sequence != self._output_head(scope, output.run_id) + 1:
            return StoreOutcome.STALE
        _ = self._connection.execute(
            "INSERT INTO run_outputs (org_id, project_id, run_id, sequence, "
            "role, name, artifact_id, artifact_version_id, content_sha256, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(scope.org_id),
                str(scope.project_id),
                str(output.run_id),
                output.sequence,
                output.role,
                output.name,
                str(output.artifact_id),
                str(output.artifact_version_id),
                output.content_sha256,
                output.created_at.isoformat(),
            ),
        )
        return StoreOutcome.CREATED

    def _finish_run_locked(
        self,
        scope: ArtifactScope,
        completion: RunCompletion,
    ) -> StoreOutcome:
        """Compare-and-swap one Run onto exactly one terminal state."""
        if not _completion_well_formed(completion):
            return StoreOutcome.NOT_FOUND
        run = self._run_locked(scope, completion.run_id)
        if run is None:
            return StoreOutcome.NOT_FOUND
        if run.state not in _terminal_sources(completion.state):
            return StoreOutcome.STALE
        updated = self._connection.execute(
            "UPDATE runs SET state = ?, updated_at = ?, error_type = ?, "
            "error_code = ? WHERE org_id = ? AND project_id = ? AND id = ? "
            "AND state = ?",
            (
                completion.state.value,
                completion.finished_at.isoformat(),
                completion.error_type,
                completion.error_code,
                str(scope.org_id),
                str(scope.project_id),
                str(completion.run_id),
                run.state.value,
            ),
        )
        if updated.rowcount != 1:
            return StoreOutcome.STALE
        return StoreOutcome.CREATED

    def _open_review_locked(
        self,
        scope: ArtifactScope,
        review: ReviewRecord,
    ) -> StoreOutcome:
        """Validate one Review's pins then queue it, refusing a duplicate."""
        refusal = self._review_refusal(scope, review)
        if refusal is not None:
            return refusal
        _ = self._connection.execute(
            "INSERT INTO reviews (org_id, project_id, id, source_run_id, state, "
            "pinned_input_sha256, pinned_artifact_version_ids, "
            "pinned_execution_ids, created_at, updated_at, findings_submitted_at, "
            "error_type, error_code) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)",
            (
                str(scope.org_id),
                str(scope.project_id),
                str(review.id),
                str(review.source_run_id),
                review.state.value,
                review.pinned_input_sha256,
                _uuid_json(review.pinned_artifact_version_ids),
                _uuid_json(review.pinned_execution_ids),
                review.created_at.isoformat(),
                review.updated_at.isoformat(),
            ),
        )
        return StoreOutcome.CREATED

    def _review_refusal(
        self,
        scope: ArtifactScope,
        review: ReviewRecord,
    ) -> StoreOutcome | None:
        """Return why one Review is refused, or None when it may be queued."""
        if not _review_well_formed(scope, review) or (
            review.pinned_input_sha256
            != self.pinned_input_digest(
                scope,
                review.source_run_id,
                review.pinned_artifact_version_ids,
                review.pinned_execution_ids,
            )
        ):
            return StoreOutcome.NOT_FOUND
        if self._archived(scope):
            return StoreOutcome.ARCHIVED
        if self._run_locked(scope, review.source_run_id) is None:
            return StoreOutcome.NOT_FOUND
        if not self._pins_resolve(scope, review):
            return StoreOutcome.INVALID_LINEAGE
        if self._review_taken(scope, review.id) or self._pins_reviewed(
            scope, review.pinned_input_sha256
        ):
            return StoreOutcome.ASSOCIATION_EXISTS
        return None

    def _pins_resolve(self, scope: ArtifactScope, review: ReviewRecord) -> bool:
        """Return whether every pinned Version and execution actually exists."""
        return all(
            self._version_exists(scope, value)
            for value in review.pinned_artifact_version_ids
        ) and all(
            self._execution_exists(scope, value)
            for value in review.pinned_execution_ids
        )

    def _start_review_locked(
        self,
        scope: ArtifactScope,
        review_id: UUID,
        started_at: datetime,
    ) -> StoreOutcome:
        """Compare-and-swap exactly one queued Review into `running`."""
        review = self._review_locked(scope, review_id)
        if review is None:
            return StoreOutcome.NOT_FOUND
        if review.state is not ReviewState.QUEUED:
            return StoreOutcome.STALE
        updated = self._connection.execute(
            "UPDATE reviews SET state = ?, updated_at = ? "
            "WHERE org_id = ? AND project_id = ? AND id = ? AND state = ?",
            (
                ReviewState.RUNNING.value,
                started_at.isoformat(),
                str(scope.org_id),
                str(scope.project_id),
                str(review_id),
                ReviewState.QUEUED.value,
            ),
        )
        if updated.rowcount != 1:
            return StoreOutcome.STALE
        return StoreOutcome.CREATED

    def _submit_findings_locked(
        self,
        scope: ArtifactScope,
        submission: ReviewSubmission,
    ) -> StoreOutcome:
        """Complete one running Review and write its findings exactly once."""
        review = self._review_locked(scope, submission.review_id)
        if review is None:
            return StoreOutcome.NOT_FOUND
        if not _submission_well_formed(scope, review, submission):
            return StoreOutcome.NOT_FOUND
        # Already submitted and never started are different refusals, and the
        # caller needs to tell them apart: one means the findings are safely
        # recorded, the other means this Review never ran.
        if review.findings_submitted_at is not None:
            return StoreOutcome.ASSOCIATION_EXISTS
        if review.state is not ReviewState.RUNNING:
            return StoreOutcome.STALE
        completed = self._connection.execute(
            "UPDATE reviews SET state = ?, updated_at = ?, findings_submitted_at = ? "
            "WHERE org_id = ? AND project_id = ? AND id = ? AND state = ? "
            "AND findings_submitted_at IS NULL",
            (
                ReviewState.COMPLETED.value,
                submission.submitted_at.isoformat(),
                submission.submitted_at.isoformat(),
                str(scope.org_id),
                str(scope.project_id),
                str(submission.review_id),
                ReviewState.RUNNING.value,
            ),
        )
        if completed.rowcount != 1:
            return StoreOutcome.ASSOCIATION_EXISTS
        for finding in submission.findings:
            self._insert_finding_locked(finding)
        return StoreOutcome.CREATED

    def _insert_finding_locked(self, finding: ReviewFindingRecord) -> None:
        """Write one immutable finding row."""
        _ = self._connection.execute(
            "INSERT INTO review_findings (org_id, project_id, review_id, id, "
            "sequence, rule_id, verdict, status, code, message, "
            "artifact_version_ids, execution_ids, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(finding.org_id),
                str(finding.project_id),
                str(finding.review_id),
                str(finding.id),
                finding.sequence,
                finding.rule_id.value,
                finding.verdict.value,
                finding.status.value,
                finding.code,
                finding.message,
                _uuid_json(finding.artifact_version_ids),
                _uuid_json(finding.execution_ids),
                finding.created_at.isoformat(),
            ),
        )

    def _fail_review_locked(
        self,
        scope: ArtifactScope,
        review_id: UUID,
        failed_at: datetime,
        error_type: str,
        error_code: str | None,
    ) -> StoreOutcome:
        """Compare-and-swap one unfinished Review onto `failed`."""
        review = self._review_locked(scope, review_id)
        if review is None:
            return StoreOutcome.NOT_FOUND
        if review.state not in OPEN_REVIEW_STATES:
            return StoreOutcome.STALE
        updated = self._connection.execute(
            "UPDATE reviews SET state = ?, updated_at = ?, error_type = ?, "
            "error_code = ? WHERE org_id = ? AND project_id = ? AND id = ? "
            "AND state = ?",
            (
                ReviewState.FAILED.value,
                failed_at.isoformat(),
                error_type,
                error_code,
                str(scope.org_id),
                str(scope.project_id),
                str(review_id),
                review.state.value,
            ),
        )
        if updated.rowcount != 1:
            return StoreOutcome.STALE
        return StoreOutcome.CREATED

    def _review_locked(
        self,
        scope: ArtifactScope,
        review_id: UUID,
    ) -> ReviewRecord | None:
        """Project one Review row into a typed record."""
        row = _fetch_one(
            self._connection.execute(
                REVIEW_JSON,
                (str(scope.org_id), str(scope.project_id), str(review_id)),
            )
        )
        if row is None:
            return None
        return ReviewRecord.model_validate_json(TEXT.validate_python(row[0]))

    def _review_taken(self, scope: ArtifactScope, review_id: UUID) -> bool:
        """Return whether this Review identity is used in any Project."""
        return (
            _fetch_one(
                self._connection.execute(
                    "SELECT 1 FROM reviews WHERE org_id = ? AND id = ?",
                    (str(scope.org_id), str(review_id)),
                )
            )
            is not None
        )

    def _pins_reviewed(self, scope: ArtifactScope, pinned_input_sha256: str) -> bool:
        """Return whether this exact pinned evidence was already reviewed."""
        return (
            _fetch_one(
                self._connection.execute(
                    "SELECT 1 FROM reviews "
                    "WHERE org_id = ? AND project_id = ? AND pinned_input_sha256 = ?",
                    (
                        str(scope.org_id),
                        str(scope.project_id),
                        pinned_input_sha256,
                    ),
                )
            )
            is not None
        )

    def _execution_exists(self, scope: ArtifactScope, execution_id: UUID) -> bool:
        """Return whether one execution exists in the exact authorized Project."""
        return (
            _fetch_one(
                self._connection.execute(
                    "SELECT 1 FROM executions "
                    "WHERE org_id = ? AND project_id = ? AND id = ?",
                    (str(scope.org_id), str(scope.project_id), str(execution_id)),
                )
            )
            is not None
        )

    def _record_input_locked(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
        kind: ExecutionInputKind,
        payload: bytes,
    ) -> StoreOutcome:
        """Verify one payload against its pinned digest then publish and record it.

        The ordering matches `_commit_transaction`: the content is fsync'd and
        renamed into place before the row that references it exists, so a
        crash can leave an unreferenced blob but never a row pointing at bytes
        that are not there.
        """
        if self._archived(scope):
            return StoreOutcome.ARCHIVED
        execution = self._execution_locked(scope, execution_id)
        if execution is None or not self._execution_owned(scope, str(execution_id)):
            return StoreOutcome.NOT_FOUND
        pinned = _pinned_execution_digest(execution, kind)
        if hashlib.sha256(payload).hexdigest() != pinned:
            return StoreOutcome.INVALID_LINEAGE
        if self._input_recorded(scope, execution_id, kind):
            return StoreOutcome.ASSOCIATION_EXISTS
        self._publish_blob(pinned, payload)
        _ = self._connection.execute(
            "INSERT INTO execution_inputs (org_id, project_id, execution_id, "
            "kind, content_sha256, size_bytes, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(scope.org_id),
                str(scope.project_id),
                str(execution_id),
                kind.value,
                pinned,
                len(payload),
                execution.created_at.isoformat(),
            ),
        )
        return StoreOutcome.CREATED

    def _input_recorded(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
        kind: ExecutionInputKind,
    ) -> bool:
        """Return whether this execution already recorded bytes for this kind."""
        return (
            _fetch_one(
                self._connection.execute(
                    "SELECT 1 FROM execution_inputs "
                    "WHERE org_id = ? AND execution_id = ? AND kind = ?",
                    (str(scope.org_id), str(execution_id), kind.value),
                )
            )
            is not None
        )

    def _verified_blob(self, content_sha256: str) -> bytes | None:
        """Read one content object, reporting absence rather than bad bytes."""
        try:
            payload = self._blob_path(content_sha256).read_bytes()
        except (OSError, BlobIntegrityError):
            return None
        if hashlib.sha256(payload).hexdigest() != content_sha256:
            return None
        return payload

    def _execution_locked(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
    ) -> ExecutionRecord | None:
        """Project one execution row into a typed record."""
        row = _fetch_one(
            self._connection.execute(
                EXECUTION_JSON,
                (str(scope.org_id), str(scope.project_id), str(execution_id)),
            )
        )
        if row is None:
            return None
        return ExecutionRecord.model_validate_json(TEXT.validate_python(row[0]))

    def _execution_for_run_locked(
        self,
        scope: ArtifactScope,
        run_id: UUID,
    ) -> ExecutionRecord | None:
        """Project the one execution this Run claimed, if it claimed one."""
        row = _fetch_one(
            self._connection.execute(
                "SELECT id FROM executions "
                "WHERE org_id = ? AND project_id = ? AND run_id = ?",
                (str(scope.org_id), str(scope.project_id), str(run_id)),
            )
        )
        if row is None:
            return None
        identifier = UUID(TEXT.validate_python(row[0]))
        record = _fetch_one(
            self._connection.execute(
                EXECUTION_JSON,
                (str(scope.org_id), str(scope.project_id), str(identifier)),
            )
        )
        if record is None:
            return None
        return ExecutionRecord.model_validate_json(TEXT.validate_python(record[0]))

    def _pinned_output_locked(
        self,
        scope: ArtifactScope,
        output: RunOutputRecord,
    ) -> PinnedOutput:
        """Capture one committed output's Version row and verified bytes.

        Absence and disagreement are reported apart. Evidence that is simply
        gone cannot be checked and must reach the Reviewer as `ABSENT`, while
        evidence that contradicts its own recorded digest is a defect and must
        reach it as `TAMPERED`. Collapsing the two would turn every unreadable
        artifact into a manufactured `fail`.
        """
        version = self._version_locked(scope, output.artifact_version_id)
        state = ContentState.ABSENT
        payload: bytes | None = None
        if version is not None and self._blob_present(version.content_sha256):
            try:
                payload = self._read_blob(version)
            except BlobIntegrityError:
                state = ContentState.TAMPERED
            else:
                state = ContentState.AVAILABLE
        return PinnedOutput(
            role=output.role,
            name=output.name,
            artifact_version_id=output.artifact_version_id,
            recorded_sha256=output.content_sha256,
            version=version,
            content_state=state,
            content=payload,
        )

    def _plan_locked(
        self,
        scope: ArtifactScope,
        plan_id: UUID,
    ) -> ActionPlanRecord | None:
        """Project one ActionPlan row into a typed record."""
        row = _fetch_one(
            self._connection.execute(
                PLAN_JSON,
                (str(scope.org_id), str(scope.project_id), str(plan_id)),
            )
        )
        if row is None:
            return None
        return ActionPlanRecord.model_validate_json(TEXT.validate_python(row[0]))

    def _approval_locked(
        self,
        scope: ArtifactScope,
        approval_id: UUID,
    ) -> PlanApprovalRecord | None:
        """Project one approval row into a typed record."""
        row = _fetch_one(
            self._connection.execute(
                APPROVAL_JSON,
                (str(scope.org_id), str(scope.project_id), str(approval_id)),
            )
        )
        if row is None:
            return None
        return PlanApprovalRecord.model_validate_json(TEXT.validate_python(row[0]))

    def _run_locked(self, scope: ArtifactScope, run_id: UUID) -> RunRecord | None:
        """Project one Run row into a typed record."""
        row = _fetch_one(
            self._connection.execute(
                RUN_JSON,
                (str(scope.org_id), str(scope.project_id), str(run_id)),
            )
        )
        if row is None:
            return None
        return RunRecord.model_validate_json(TEXT.validate_python(row[0]))

    def _plan_taken(self, scope: ArtifactScope, plan_id: UUID) -> bool:
        """Return whether this plan identity is used in any Project."""
        return (
            _fetch_one(
                self._connection.execute(
                    "SELECT 1 FROM action_plans WHERE org_id = ? AND id = ?",
                    (str(scope.org_id), str(plan_id)),
                )
            )
            is not None
        )

    def _approval_taken(self, scope: ArtifactScope, approval_id: UUID) -> bool:
        """Return whether this approval identity is used in any Project."""
        return (
            _fetch_one(
                self._connection.execute(
                    "SELECT 1 FROM plan_approvals WHERE org_id = ? AND id = ?",
                    (str(scope.org_id), str(approval_id)),
                )
            )
            is not None
        )

    def _run_taken(self, scope: ArtifactScope, run_id: UUID) -> bool:
        """Return whether this Run identity is used in any Project."""
        return (
            _fetch_one(
                self._connection.execute(
                    "SELECT 1 FROM runs WHERE org_id = ? AND id = ?",
                    (str(scope.org_id), str(run_id)),
                )
            )
            is not None
        )

    def _execution_taken(self, scope: ArtifactScope, execution_id: UUID) -> bool:
        """Return whether this produced-execution id was already claimed."""
        return (
            _fetch_one(
                self._connection.execute(
                    "SELECT 1 FROM executions WHERE org_id = ? AND id = ?",
                    (str(scope.org_id), str(execution_id)),
                )
            )
            is not None
        )

    def _plan_approved(self, scope: ArtifactScope, plan_id: UUID) -> bool:
        """Return whether this plan already carries its one approval."""
        row = _fetch_one(
            self._connection.execute(
                "SELECT 1 FROM plan_approvals WHERE org_id = ? AND plan_id = ?",
                (str(scope.org_id), str(plan_id)),
            )
        )
        return row is not None

    def _output_head(self, scope: ArtifactScope, run_id: UUID) -> int:
        """Return the highest recorded sequence, or zero before any output."""
        row = _fetch_one(
            self._connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) FROM run_outputs "
                "WHERE org_id = ? AND project_id = ? AND run_id = ?",
                (str(scope.org_id), str(scope.project_id), str(run_id)),
            )
        )
        if row is None:
            return 0
        return INTEGER.validate_python(row[0])

    def _create_locked(
        self,
        scope: ArtifactScope,
        artifact: ArtifactRecord,
    ) -> StoreOutcome:
        """Validate the Project and identity then insert one Artifact row."""
        if self._archived(scope):
            return StoreOutcome.ARCHIVED
        if self._artifact_exists(scope, artifact.id):
            return StoreOutcome.NOT_FOUND
        _ = self._connection.execute(
            "INSERT INTO artifacts (org_id, project_id, id, name, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                str(scope.org_id),
                str(scope.project_id),
                str(artifact.id),
                artifact.name,
                artifact.created_at.isoformat(),
            ),
        )
        return StoreOutcome.CREATED

    def _attach_locked(
        self,
        scope: ArtifactScope,
        link: SessionArtifactLink,
    ) -> StoreOutcome:
        """Validate the Project, Version, Session, execution chain, and prior link.

        The Session requirement matches the durable reference exactly: an
        unknown, archived, or foreign-Project Session is `NOT_FOUND`, so a
        Version can never be associated with a Session that exists nowhere.

        The ownership requirement is this module's own and binds
        `EXECUTION_SESSION_OWNED`: the Version's producing execution, that
        execution's Run, and the Run's own Session must all resolve, and the
        Run's Session must be exactly the one being attached. A Run that
        recorded no Session matches nothing and is refused, which is the whole
        point -- absence of the last link is not agreement with it.

        The two requirements are checked in this order so each keeps its own
        meaning. A Session that is unknown, archived, or filed under another
        Project is refused for *being unusable*, before any question of which
        Run it owns arises; a live Session that simply did not commission this
        Version is refused for *not owning it*. Collapsing the order would make
        one refusal answer for both.

        The ownership check also bites on rows this module never wrote. A
        Version row written by an earlier build, restored from a backup, or
        edited outside this module can name an execution that exists nowhere,
        and associating one with a Session would publish a reference the
        storage contract forbids -- every parent reference must resolve to a
        row that exists.
        """
        if self._archived(scope):
            return StoreOutcome.ARCHIVED
        if not self._version_exists(scope, link.artifact_version_id):
            return StoreOutcome.NOT_FOUND
        if not self._session_live(scope, link.session_id):
            return StoreOutcome.NOT_FOUND
        execution_id = self._owning_execution(
            scope,
            link.artifact_version_id,
            link.session_id,
        )
        if execution_id is None:
            return StoreOutcome.NOT_FOUND
        existing = _fetch_one(
            self._connection.execute(
                "SELECT 1 FROM session_links WHERE org_id = ? AND project_id = ? "
                "AND session_id = ? AND artifact_version_id = ?",
                (
                    str(scope.org_id),
                    str(scope.project_id),
                    str(link.session_id),
                    str(link.artifact_version_id),
                ),
            )
        )
        if existing is not None:
            return StoreOutcome.ASSOCIATION_EXISTS
        _ = self._connection.execute(
            "INSERT INTO session_links (org_id, project_id, session_id, "
            "artifact_version_id, producing_execution_id, revision, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(scope.org_id),
                str(scope.project_id),
                str(link.session_id),
                str(link.artifact_version_id),
                execution_id,
                link.revision,
                link.created_at.isoformat(),
            ),
        )
        return StoreOutcome.CREATED

    def _commit_guarded(
        self,
        scope: ArtifactScope,
        base_version_no: int,
        version: ArtifactVersion,
        payload: bytes,
    ) -> StoreOutcome:
        """Normalize local write failures onto the shared commit contract.

        Nothing is deleted here. A rolled-back commit may leave an
        unreferenced blob, which is inert under global content addressing and
        is reclaimed by `sweep_unreferenced_blobs`.
        """
        try:
            return self._commit_transaction(scope, base_version_no, version, payload)
        except BlobIntegrityError:
            self._rollback()
            raise
        except (sqlite3.Error, ArtifactStoreError, OSError) as error:
            self._rollback()
            raise ArtifactCommitError from error

    def _commit_transaction(
        self,
        scope: ArtifactScope,
        base_version_no: int,
        version: ArtifactVersion,
        payload: bytes,
    ) -> StoreOutcome:
        """Serialize CAS on the database then publish bytes before metadata."""
        _ = self._connection.execute("BEGIN IMMEDIATE")
        rejection = self._reject_commit(scope, base_version_no, version, payload)
        if rejection is not None:
            self._rollback()
            return rejection
        self._publish_blob(version.content_sha256, payload)
        self._insert_version(version)
        _ = self._connection.execute("COMMIT")
        return StoreOutcome.CREATED

    def _reject_commit(
        self,
        scope: ArtifactScope,
        base_version_no: int,
        version: ArtifactVersion,
        payload: bytes,
    ) -> StoreOutcome | None:
        """Return the rejecting outcome for one commit or None when valid."""
        if not self._artifact_exists(scope, version.artifact_id):
            return StoreOutcome.NOT_FOUND
        if self._archived(scope):
            return StoreOutcome.ARCHIVED
        if self._head_version_no(scope, version.artifact_id) != base_version_no:
            return StoreOutcome.STALE
        if not self._references_valid(scope, base_version_no, version, payload):
            return StoreOutcome.INVALID_LINEAGE
        return None

    def _references_valid(
        self,
        scope: ArtifactScope,
        base_version_no: int,
        version: ArtifactVersion,
        payload: bytes,
    ) -> bool:
        """Verify every reference and derived field one Version asserts.

        Named after `postgres_operations.references_valid` because it answers
        the same question at the same point on the commit path: the producing
        execution must resolve in this exact tenant and Project, every input
        Version must resolve in this Project, and the address, size, and
        position must be the server-derived ones. Any of these failing is
        `INVALID_LINEAGE`, exactly as the durable adapter reports it.

        The producer is checked first because it is the claim the Version is
        *for*: an unresolvable producer makes "this execution produced these
        bytes" a fabrication, whatever the inputs say.

        `NOT_FOUND` is deliberately not reused for the producer. The Artifact
        being appended to does exist, and reporting its absence would make a
        fabricated provenance claim indistinguishable from a mistyped
        Artifact id.
        """
        return (
            self._execution_owned(scope, str(version.producing_execution_id))
            and self._lineage_valid(scope, version.input_version_ids)
            and self._version_consistent(scope, base_version_no, version, payload)
        )

    def _version_consistent(
        self,
        scope: ArtifactScope,
        base_version_no: int,
        version: ArtifactVersion,
        payload: bytes,
    ) -> bool:
        """Verify the server-derived address, size, and monotonic position."""
        return (
            version.version_no == base_version_no + 1
            and version.object_key == self.object_key(scope, version.content_sha256)
            and version.size_bytes == len(payload)
            and not self._version_exists(scope, version.id)
        )

    def _lineage_valid(
        self,
        scope: ArtifactScope,
        input_version_ids: tuple[UUID, ...],
    ) -> bool:
        """Verify sorted, unique, same-Project lineage references.

        Sorted order is required rather than merely reconstructed: reads
        project lineage back in digest order, so accepting an unsorted commit
        would leave the stored Version unequal to the one the caller
        committed and break the service's reconciliation comparison.
        """
        if tuple(sorted(input_version_ids)) != input_version_ids:
            return False
        if len(set(input_version_ids)) != len(input_version_ids):
            return False
        return all(
            self._version_exists(scope, version_id) for version_id in input_version_ids
        )

    def _insert_version(self, version: ArtifactVersion) -> None:
        """Insert immutable Version metadata followed by exact dependencies."""
        _ = self._connection.execute(
            "INSERT INTO artifact_versions (org_id, project_id, id, artifact_id, "
            "version_no, object_key, content_sha256, size_bytes, media_type, "
            "producing_execution_id, environment_sha256, code_sha256, "
            "runtime_adapter_id, runtime_connection_id, skill_content_hashes, "
            "source_hashes, created_at) VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(version.org_id),
                str(version.project_id),
                str(version.id),
                str(version.artifact_id),
                version.version_no,
                version.object_key,
                version.content_sha256,
                version.size_bytes,
                version.media_type,
                str(version.producing_execution_id),
                version.environment_sha256,
                version.code_sha256,
                version.runtime_adapter_id,
                str(version.runtime_connection_id),
                json.dumps(list(version.skill_content_hashes)),
                json.dumps(list(version.source_hashes)),
                version.created_at.isoformat(),
            ),
        )
        _ = self._connection.executemany(
            "INSERT INTO version_inputs (org_id, project_id, artifact_version_id, "
            "input_version_id) VALUES (?, ?, ?, ?)",
            [
                (
                    str(version.org_id),
                    str(version.project_id),
                    str(version.id),
                    str(input_id),
                )
                for input_id in version.input_version_ids
            ],
        )

    def _version_locked(
        self,
        scope: ArtifactScope,
        version_id: UUID,
    ) -> ArtifactVersion | None:
        """Project one Version row and its pinned lineage into a typed record."""
        row = _fetch_one(
            self._connection.execute(
                VERSION_JSON,
                (str(scope.org_id), str(scope.project_id), str(version_id)),
            )
        )
        if row is None:
            return None
        return ArtifactVersion.model_validate_json(TEXT.validate_python(row[0]))

    def _referenced_digests(self) -> frozenset[str]:
        """Return every content digest still referenced by a durable row.

        Canonical execution inputs share the blob directory with Version
        content, so they are counted here too. Reading only
        `artifact_versions` would let the sweep reclaim the very bytes an
        Export Pack needs to make `research_intent_sha256` and `input_sha256`
        recomputable, which is deletion of evidence rather than reclamation.
        """
        rows = _fetch_all(
            self._connection.execute(
                "SELECT DISTINCT content_sha256 FROM artifact_versions "
                "UNION SELECT DISTINCT content_sha256 FROM execution_inputs"
            )
        )
        return frozenset(TEXT.validate_python(row[0]) for row in rows)

    def _archived(self, scope: ArtifactScope) -> bool:
        """Return whether a recorded Project marker blocks this Project."""
        row = _fetch_one(
            self._connection.execute(
                "SELECT archived FROM projects WHERE org_id = ? AND id = ?",
                (str(scope.org_id), str(scope.project_id)),
            )
        )
        if row is None:
            return False
        return INTEGER.validate_python(row[0]) != 0

    def _project_registered(self, scope: ArtifactScope) -> bool:
        """Return whether this Project carries a registration, not a marker."""
        row = _fetch_one(
            self._connection.execute(
                "SELECT 1 FROM projects "
                "WHERE org_id = ? AND id = ? AND name IS NOT NULL",
                (str(scope.org_id), str(scope.project_id)),
            )
        )
        return row is not None

    def _session_taken(self, scope: ArtifactScope, session_id: UUID) -> bool:
        """Return whether this Session identity is used in any Project."""
        row = _fetch_one(
            self._connection.execute(
                "SELECT 1 FROM sessions WHERE org_id = ? AND id = ?",
                (str(scope.org_id), str(session_id)),
            )
        )
        return row is not None

    def _session_state(self, scope: ArtifactScope, session_id: UUID) -> int | None:
        """Return one same-Project Session's archive flag, or None if absent."""
        row = _fetch_one(
            self._connection.execute(
                "SELECT archived FROM sessions "
                "WHERE org_id = ? AND project_id = ? AND id = ?",
                (str(scope.org_id), str(scope.project_id), str(session_id)),
            )
        )
        if row is None:
            return None
        return INTEGER.validate_python(row[0])

    def _session_live(self, scope: ArtifactScope, session_id: UUID) -> bool:
        """Return whether a non-archived Session exists in this exact Project."""
        return self._session_state(scope, session_id) == 0

    def _artifact_exists(self, scope: ArtifactScope, artifact_id: UUID) -> bool:
        """Return whether one Artifact exists in the exact authorized Project."""
        row = _fetch_one(
            self._connection.execute(
                "SELECT 1 FROM artifacts "
                "WHERE org_id = ? AND project_id = ? AND id = ?",
                (str(scope.org_id), str(scope.project_id), str(artifact_id)),
            )
        )
        return row is not None

    def _execution_owned(self, scope: ArtifactScope, execution_id: str) -> bool:
        """Return whether one execution and its Run resolve in this Project.

        The execution row belongs to a Run, and both rows must sit in exactly
        this tenant and Project. A break anywhere is a refusal, because a
        partially resolvable chain is not ownership.

        This is the commit-time predicate and stops at the Run, because a
        Version being appended names no Session to be checked against.
        `_execution_owned_by_session` carries the same walk its last step for
        the association path.

        The identifier is passed as text rather than as a `UUID` so a column
        that some other writer left unparseable is simply an execution that
        does not resolve, instead of a `ValueError` escaping a store method.
        """
        row = _fetch_one(
            self._connection.execute(
                EXECUTION_OWNED,
                (
                    str(scope.org_id),
                    str(scope.project_id),
                    execution_id,
                    str(scope.project_id),
                ),
            )
        )
        return row is not None

    def _execution_owned_by_session(
        self,
        scope: ArtifactScope,
        execution_id: str,
        session_id: UUID,
    ) -> bool:
        """Return whether one execution's Run belongs to exactly this Session.

        The last step of the durable ownership walk. A Run that recorded no
        Session compares equal to nothing, so this returns False for it rather
        than reading the absence as a match.
        """
        row = _fetch_one(
            self._connection.execute(
                EXECUTION_SESSION_OWNED,
                (
                    str(scope.org_id),
                    str(scope.project_id),
                    execution_id,
                    str(scope.project_id),
                    str(session_id),
                ),
            )
        )
        return row is not None

    def _owning_execution(
        self,
        scope: ArtifactScope,
        version_id: UUID,
        session_id: UUID,
    ) -> str | None:
        """Return the execution owning one Version for one Session, else None.

        The producing execution is read from the Version row, never from the
        link the caller passed, and is then put through the whole ownership
        walk including the Session step.
        """
        row = _fetch_one(
            self._connection.execute(
                VERSION_EXECUTION,
                (str(scope.org_id), str(scope.project_id), str(version_id)),
            )
        )
        if row is None:
            return None
        execution_id = TEXT.validate_python(row[0])
        if not self._execution_owned_by_session(scope, execution_id, session_id):
            return None
        return execution_id

    def _version_exists(self, scope: ArtifactScope, version_id: UUID) -> bool:
        """Return whether one Version exists in the exact authorized Project."""
        row = _fetch_one(
            self._connection.execute(
                "SELECT 1 FROM artifact_versions "
                "WHERE org_id = ? AND project_id = ? AND id = ?",
                (str(scope.org_id), str(scope.project_id), str(version_id)),
            )
        )
        return row is not None

    def _head_version_no(self, scope: ArtifactScope, artifact_id: UUID) -> int:
        """Return the current head Version number or zero before any commit."""
        row = _fetch_one(
            self._connection.execute(
                "SELECT COALESCE(MAX(version_no), 0) FROM artifact_versions "
                "WHERE org_id = ? AND project_id = ? AND artifact_id = ?",
                (str(scope.org_id), str(scope.project_id), str(artifact_id)),
            )
        )
        if row is None:
            return 0
        return INTEGER.validate_python(row[0])

    def _rollback(self) -> None:
        """Abandon any transaction still open on the shared connection."""
        with suppress(sqlite3.Error):
            if self._connection.in_transaction:
                _ = self._connection.execute("ROLLBACK")

    def _blob_path(self, content_sha256: str) -> Path:
        """Derive the sharded on-disk address for one content digest."""
        if SHA256_PATTERN.fullmatch(content_sha256) is None:
            raise BlobIntegrityError
        first = content_sha256[:SHARD_WIDTH]
        second = content_sha256[SHARD_WIDTH : SHARD_WIDTH * 2]
        return self._paths.blobs / first / second / content_sha256

    def _publish_blob(self, content_sha256: str, payload: bytes) -> None:
        """Create one immutable object or adopt an identical existing object."""
        if hashlib.sha256(payload).hexdigest() != content_sha256:
            raise BlobIntegrityError
        path = self._blob_path(content_sha256)
        try:
            if path.exists():
                if path.read_bytes() != payload:
                    raise BlobIntegrityError
                return
            path.parent.mkdir(parents=True, exist_ok=True)
            _write_atomically(path, payload)
        except OSError as error:
            raise BlobWriteError from error

    def _blob_present(self, content_sha256: str) -> bool:
        """Return whether one content object exists on disk at all."""
        try:
            return self._blob_path(content_sha256).is_file()
        except BlobIntegrityError:
            return False

    def _read_blob(self, version: ArtifactVersion) -> bytes:
        """Read one object and verify it against its immutable recorded digest."""
        try:
            payload = self._blob_path(version.content_sha256).read_bytes()
        except OSError as error:
            raise BlobIntegrityError from error
        if hashlib.sha256(payload).hexdigest() != version.content_sha256:
            raise BlobIntegrityError
        return payload
