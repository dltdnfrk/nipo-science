"""Version-pinned, checksummed reproducibility Export Pack.

This is the last stage of the local dry-lab chain: the file a researcher hands
to a colleague or a reviewer so a published result can be re-verified by
someone who does not have this repository, this database, or this machine.

Pinning, never resolution
-------------------------
Every exported artifact is named by an explicit Artifact Version identifier.
`ExportEntry.artifact_version_id` is `UUID | None` at the boundary for exactly
one reason: an unpinned selection must be *refused*, and a refusal that cannot
be expressed cannot be tested. A `None` version is rejected with
`ExportRejection.VERSION_NOT_PINNED`; it is never resolved to the artifact's
head Version. There is no code path in this module that reads a head version
number, orders versions by time, or otherwise turns an Artifact identity into
a Version identity. That race is the reason the requirement exists.

The declared selection and the exported entries are two separate caller
statements and both are recorded. `ExportRequest.selection` is what the
researcher says they pinned; `ExportRequest.entries` is the file layout that
will be written. They must be equal as sets, and the selection must already be
sorted and free of repeats. A caller that assembles the two lists from
different places -- a checkbox list and a download plan, say -- is exactly the
caller this check exists for.

Pack layout
-----------
```
manifest.json          every entry, its digest, provenance, plan, review
checksums.sha256       sha256sum-compatible lines covering every other member
provenance.json        the pinned provenance of each exported Version
action-plan.json       the immutable ActionPlan and its one-use approval
review.json            Review status and every finding, or a recorded absence
run-record.json        the run mirror, when the producing run wrote one
research-intent.json   the intent's own canonical bytes, when attested
scientific-input.json  the input's own canonical bytes, when attested
environment.json       the recorded environment facts, when attested
<caller paths>         the selected Artifact Version payloads
```

The nine names above are reserved pack roots. A caller entry equal to one, or
beneath one, is refused rather than renamed; so is one that merely collides
with one after NFKC normalization and case folding, because `MANIFEST.JSON`
and `manifest.json` are the same file on macOS.

Independent verification
------------------------
`manifest.json` carries a `verification` section stating, in the pack itself,
how to check the pack without this codebase: the digest algorithm, the exact
canonical-JSON rule, the `checksums.sha256` line format and ordering, and the
ordered steps. Two independent statements of every artifact digest are
recorded -- one in `manifest.json`, one in `checksums.sha256` -- and a verifier
recomputes both from the bytes and confirms all three agree.

`manifest.json` records no digest of itself. Its digest appears once, in
`checksums.sha256`, which is the only member no line covers.

What a pack cannot prove
------------------------
Honesty about the gap is part of the contract, so the manifest states it
rather than leaving a reader to infer it:

- `execution_isolation` is `in_process`. The analysis ran in the application's
  own interpreter with no subprocess boundary and no confinement of any kind.
  The pack records the disclosed value and explicitly denies that it is a
  sandbox.
- The store persists digests, not the bytes they were taken over. Neither the
  `ResearchIntent`, nor the scientific input, nor the environment facts have a
  table. A pack therefore cannot recompute `research_intent_sha256`,
  `input_sha256`, or `environment_sha256` from its own contents unless the
  producer attests those bytes at export time. `AttestedInputs` accepts them,
  every one is checked against the pinned digest before it is written, a
  mismatch refuses the pack, and `verification.recomputable_from_pack` states
  per digest which side of that line it fell on.
- `code_sha256` is a digest of source files that are not artifacts and are not
  in the pack. The manifest records the exact recipe so a third party holding
  the pinned toolchain can redo it, and records that the pack alone cannot.

No credential material, ever
----------------------------
The exporter never reads the Keychain, so the master key has no path into a
pack. For the material that does live under the data root -- the sealed
provider store and the download signing key -- absence is checked rather than
assumed: every assembled member's bytes and path are scanned for those exact
fragments, and a hit refuses the pack. An Artifact Version whose content
happens to be the signing key is therefore refused at export, not shipped.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
import zipfile
from base64 import b64encode
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Final, cast, final

from services.api.artifacts.store_contract import StoreOutcome

from .store import LocalArtifactStore
from .workbench import run_record_path, signing_key_path

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence
    from datetime import datetime
    from pathlib import Path
    from uuid import UUID

    from services.api.artifacts.models import ArtifactScope, ArtifactVersion

    from .config import LocalPaths
    from .store import (
        ActionPlanRecord,
        ExecutionRecord,
        PlanApprovalRecord,
        ReviewFindingRecord,
        ReviewRecord,
        RunOutputRecord,
        RunRecord,
    )

PACK_SCHEMA: Final = "nipo.local.export-pack.v1"
PROVENANCE_SCHEMA: Final = "nipo.local.export-provenance.v1"
ACTION_PLAN_SCHEMA: Final = "nipo.local.export-action-plan.v1"
REVIEW_SCHEMA: Final = "nipo.local.export-review.v1"

MANIFEST_PATH: Final = "manifest.json"
CHECKSUMS_PATH: Final = "checksums.sha256"
PROVENANCE_PATH: Final = "provenance.json"
ACTION_PLAN_PATH: Final = "action-plan.json"
REVIEW_PATH: Final = "review.json"
RUN_RECORD_PATH: Final = "run-record.json"
RESEARCH_INTENT_PATH: Final = "research-intent.json"
SCIENTIFIC_INPUT_PATH: Final = "scientific-input.json"
ENVIRONMENT_PATH: Final = "environment.json"

# Reserved unconditionally, not only when the corresponding document is
# written, so that whether a caller path is refused never depends on how much
# evidence this particular run happened to leave behind.
RESERVED_ROOTS: Final = (
    ACTION_PLAN_PATH,
    CHECKSUMS_PATH,
    ENVIRONMENT_PATH,
    MANIFEST_PATH,
    PROVENANCE_PATH,
    RESEARCH_INTENT_PATH,
    REVIEW_PATH,
    RUN_RECORD_PATH,
    SCIENTIFIC_INPUT_PATH,
)

MAX_PACK_PATH_CHARACTERS: Final = 1024
MAX_PACK_SEGMENT_CHARACTERS: Final = 255

# MS-DOS device names are still special on Windows with any extension and in
# any case, so `aux.csv` names a device rather than a file once the pack is
# extracted there.
RESERVED_DEVICE_NAMES: Final = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)

_DRIVE_QUALIFIED: Final = re.compile(r"^[A-Za-z]:")
_CONTROL_CHARACTERS: Final = re.compile(r"[\x00-\x1f\x7f]")

# A shorter run of bytes is not distinctive enough to be evidence of a leak and
# would refuse packs over a coincidence.
MIN_CREDENTIAL_FRAGMENT_BYTES: Final = 16

ENVIRONMENT_KEY_PREFIX: Final = "NIPO_"
ENVIRONMENT_KEY_SUFFIX: Final = "_API_KEY"

# Fixed so that two exports of the same evidence produce the same bytes. The
# MS-DOS epoch is the lowest value the ZIP format can express.
ZIP_EPOCH: Final = (1980, 1, 1, 0, 0, 0)
ZIP_UNIX_SYSTEM: Final = 3
OWNER_ONLY_MODE: Final = 0o600
REGULAR_FILE_ATTRIBUTE: Final = (stat.S_IFREG | OWNER_ONLY_MODE) << 16

CANONICAL_JSON_RULE: Final = (
    "json.dumps(value, sort_keys=True, separators=(',', ':'), "
    "ensure_ascii=True).encode('utf-8')"
)
INTENT_JSON_RULE: Final = (
    "json.dumps(value, sort_keys=True, separators=(',', ':'), "
    "ensure_ascii=False).encode('utf-8')"
)

ISOLATION_NOT_A_SANDBOX: Final = (
    "Analysis ran in the application's own interpreter process. There is no "
    "subprocess boundary, no filesystem, network or syscall confinement, no "
    "CPU, memory, wall-time or process-count fence, and no privilege "
    "reduction relative to the researcher's own account. This pack asserts no "
    "confinement and no isolation control it did not measure."
)
SKILL_HASHES_NOTE: Final = (
    "Empty by construction: no Skill participates in a local deterministic "
    "run, so no Skill content hash exists to pin."
)
ENVIRONMENT_COVERAGE_NOTE: Final = (
    "Incomplete. The recorded environment facts do not cover every dependency "
    "whose version can change a pinned digest or an artifact byte; pydantic "
    "shapes input_sha256 and is not covered."
)
MASTER_KEY_NOTE: Final = (
    "Never read by the exporter. No code path in this module opens the "
    "Keychain, so the master key has no route into a pack."
)
SELECTION_PERSISTENCE_NOTE: Final = (
    "The storage manifest enumerates an export_selections entity. This "
    "implementation records the selection in manifest.json and writes no "
    "export_selections row, so an export is evidenced by the pack rather than "
    "by a durable row."
)
CODE_DIGEST_NOTE: Final = (
    "Recomputable only with the pinned toolchain, never from the pack alone: "
    "the digested source files are not artifacts and are not exported."
)
SELECTION_ORDER_NOTE: Final = (
    "Ascending lexicographic order of the canonical lowercase hyphenated UUID "
    "text, which for that form is also ascending numeric order."
)


class ExportRejection(StrEnum):
    """Closed reasons for refusing to produce a pack.

    Every value refuses the whole pack. Nothing here sanitizes, renames,
    truncates, or drops an entry to make an export succeed.
    """

    PATH_EMPTY = "path_empty"
    PATH_ABSOLUTE = "path_absolute"
    PATH_DRIVE_QUALIFIED = "path_drive_qualified"
    PATH_BACKSLASH = "path_backslash"
    PATH_CONTROL_CHARACTER = "path_control_character"
    PATH_DOT_SEGMENT = "path_dot_segment"
    PATH_EMPTY_SEGMENT = "path_empty_segment"
    PATH_SEGMENT_TRAILING_DOT = "path_segment_trailing_dot"
    PATH_SEGMENT_TRAILING_SPACE = "path_segment_trailing_space"
    PATH_RESERVED_DEVICE = "path_reserved_device"
    PATH_TOO_LONG = "path_too_long"
    PATH_RESERVED_ROOT = "path_reserved_root"
    PATH_COLLISION = "path_collision"
    PATH_DIRECTORY_PREFIX = "path_directory_prefix"
    LINK_ENTRY = "link_entry"
    VERSION_NOT_PINNED = "version_not_pinned"
    SELECTION_EMPTY = "selection_empty"
    SELECTION_UNSORTED = "selection_unsorted"
    SELECTION_DUPLICATE = "selection_duplicate"
    SELECTION_MISMATCH = "selection_mismatch"
    ENTRY_ARTIFACT_MISMATCH = "entry_artifact_mismatch"
    VERSION_NOT_FOUND = "version_not_found"
    CONTENT_UNAVAILABLE = "content_unavailable"
    CONTENT_DIGEST_MISMATCH = "content_digest_mismatch"
    PROJECT_ARCHIVED = "project_archived"
    RUN_NOT_FOUND = "run_not_found"
    EXECUTION_MISSING = "execution_missing"
    PLAN_NOT_FOUND = "plan_not_found"
    APPROVAL_NOT_FOUND = "approval_not_found"
    INTENT_DIGEST_MISMATCH = "intent_digest_mismatch"
    INPUT_DIGEST_MISMATCH = "input_digest_mismatch"
    ENVIRONMENT_DIGEST_MISMATCH = "environment_digest_mismatch"
    CREDENTIAL_MATERIAL = "credential_material"
    DESTINATION_EXISTS = "destination_exists"
    DESTINATION_NOT_A_DIRECTORY = "destination_not_a_directory"


@final
class ExportError(ValueError):
    """Refuse one export, carrying a typed reason rather than prose.

    `reason` is the assertion surface. `entry_path` is a pack-relative path
    supplied by the caller and is never an absolute filesystem path, so a
    message can never carry the exporting machine's directory layout into a
    log, a test assertion, or a pack.
    """

    __slots__ = ("entry_path", "reason")

    def __init__(self, reason: ExportRejection, entry_path: str | None = None) -> None:
        """Retain the closed rejection reason and the offending pack path."""
        super().__init__(reason.value if entry_path is None else entry_path)
        self.reason = reason
        self.entry_path = entry_path


@dataclass(frozen=True, slots=True)
class ExportEntry:
    """One selected Artifact Version and the pack path it will occupy.

    `artifact_version_id` is optional at this boundary so that refusing an
    unpinned selection is a tested outcome instead of an untestable claim
    about a type. A `None` version is refused, never resolved.
    """

    artifact_id: UUID
    artifact_version_id: UUID | None
    path: str


@dataclass(frozen=True, slots=True)
class AttestedInputs:
    """Producer-supplied bytes behind digests the store does not persist.

    Each value is checked against the digest already pinned on the execution
    before it is written, so attesting the wrong bytes refuses the pack rather
    than shipping a document that disagrees with the provenance beside it.
    """

    research_intent_json: bytes | None = None
    scientific_input_json: bytes | None = None
    environment_facts: Mapping[str, str] | None = None


@dataclass(frozen=True, slots=True)
class ExportRequest:
    """One export of one Run's pinned evidence.

    `selection` and `entries` are deliberately separate statements: the first
    is what the researcher pinned, the second is what will be written. They
    must agree.
    """

    pack_id: UUID
    run_id: UUID
    selection: tuple[UUID, ...]
    entries: tuple[ExportEntry, ...]
    created_at: datetime
    attested: AttestedInputs = field(default_factory=AttestedInputs)


@dataclass(frozen=True, slots=True)
class PackMember:
    """One regular file in the pack, its bytes, and its digest."""

    path: str
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class ExportPack:
    """One assembled pack, in path order, ready to be written."""

    pack_id: UUID
    members: tuple[PackMember, ...]
    manifest_sha256: str


@dataclass(frozen=True, slots=True)
class _PinnedEntry:
    """One validated entry whose Version identifier is no longer optional."""

    entry: ExportEntry
    version_id: UUID


@dataclass(frozen=True, slots=True)
class _ResolvedEntry:
    """One selected Version resolved to its record, bytes, and pack path."""

    entry: ExportEntry
    version: ArtifactVersion
    payload: bytes
    output: RunOutputRecord | None


@dataclass(frozen=True, slots=True)
class _RunEvidence:
    """The durable records one pack is built from, all read before assembly."""

    run: RunRecord
    execution: ExecutionRecord
    plan: ActionPlanRecord
    approval: PlanApprovalRecord
    outputs: tuple[RunOutputRecord, ...]
    review: ReviewRecord | None
    findings: tuple[ReviewFindingRecord, ...]
    pinned_input_sha256: str


def canonical_json(payload: Mapping[str, object]) -> bytes:
    """Serialize one document exactly as the pack's canonical rule requires."""
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(payload: bytes) -> str:
    """Return the lowercase hexadecimal SHA-256 digest of one payload."""
    return hashlib.sha256(payload).hexdigest()


def entries_for_run(
    store: LocalArtifactStore,
    scope: ArtifactScope,
    run_id: UUID,
    prefix: str = "artifacts",
) -> tuple[ExportEntry, ...]:
    """Build one entry per committed output, pinned to the Version it wrote.

    This reads the exact Version identifiers the Run recorded when it
    published. It does not consult an artifact's head Version and has no way
    to reach one. The caller still states the selection itself, because a
    selection derived from the same call it is checked against would check
    nothing.
    """
    return tuple(
        ExportEntry(
            artifact_id=output.artifact_id,
            artifact_version_id=output.artifact_version_id,
            path=f"{prefix}/{output.name}" if prefix else output.name,
        )
        for output in store.run_outputs(scope, run_id)
    )


def build_pack(
    store: LocalArtifactStore,
    scope: ArtifactScope,
    paths: LocalPaths,
    request: ExportRequest,
) -> ExportPack:
    """Assemble one whole pack in memory, refusing rather than sanitizing.

    Every check runs before any byte is written, so a refused export leaves no
    partial pack behind.
    """
    _validate_selection(request.selection)
    pinned = _validate_entries(request.entries)
    _validate_selection_matches_entries(request.selection, request.entries)
    evidence = _read_evidence(store, scope, request.run_id)
    resolved = tuple(
        _resolve_entry(store, scope, item, evidence.outputs) for item in pinned
    )
    mirror = _run_record_member(paths, evidence.execution.id)
    supplied = (
        *_attested_members(evidence, request.attested),
        *(() if mirror is None else (mirror,)),
    )
    documents = _documents(scope, request, evidence, resolved, supplied)
    members = _finalize(resolved, supplied, documents)
    _reject_credential_material(members, _credential_fragments(paths))
    manifest = next(item for item in members if item.path == MANIFEST_PATH)
    return ExportPack(
        pack_id=request.pack_id,
        members=members,
        manifest_sha256=manifest.sha256,
    )


def write_pack(pack: ExportPack, destination: Path) -> None:
    """Write one assembled pack as an owner-only, uncompressed ZIP archive.

    Members are stored rather than deflated. That keeps the pack's own bytes a
    faithful copy of every member, so a leak scan over the archive is
    meaningful instead of being defeated by compression, and it is the fastest
    path for the large packs the non-functional budget sizes.
    """
    _validate_destination(destination)
    descriptor = os.open(
        destination,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        OWNER_ONLY_MODE,
    )
    with os.fdopen(descriptor, "wb") as handle:
        with zipfile.ZipFile(handle, "w", zipfile.ZIP_STORED) as archive:
            for member in pack.members:
                info = zipfile.ZipInfo(filename=member.path, date_time=ZIP_EPOCH)
                info.create_system = ZIP_UNIX_SYSTEM
                info.external_attr = REGULAR_FILE_ATTRIBUTE
                info.compress_type = zipfile.ZIP_STORED
                archive.writestr(info, member.payload)
        handle.flush()
        os.fsync(handle.fileno())


def export_run(
    store: LocalArtifactStore,
    scope: ArtifactScope,
    paths: LocalPaths,
    request: ExportRequest,
    destination: Path,
) -> ExportPack:
    """Assemble and write one pack, validating everything before it exists."""
    pack = build_pack(store, scope, paths, request)
    write_pack(pack, destination)
    return pack


def _validate_selection(selection: Sequence[UUID]) -> None:
    """Refuse an empty, unsorted, or repeating explicit selection."""
    if not selection:
        raise ExportError(ExportRejection.SELECTION_EMPTY)
    text = [str(value) for value in selection]
    if len(set(text)) != len(text):
        raise ExportError(ExportRejection.SELECTION_DUPLICATE)
    if text != sorted(text):
        raise ExportError(ExportRejection.SELECTION_UNSORTED)


def _validate_selection_matches_entries(
    selection: Sequence[UUID],
    entries: Sequence[ExportEntry],
) -> None:
    """Refuse a selection that is not exactly what the entries will export."""
    pinned = sorted(
        str(entry.artifact_version_id)
        for entry in entries
        if entry.artifact_version_id is not None
    )
    if pinned != [str(value) for value in selection]:
        raise ExportError(ExportRejection.SELECTION_MISMATCH)


def _validate_entries(entries: Sequence[ExportEntry]) -> tuple[_PinnedEntry, ...]:
    """Refuse an unpinned Version or any path the specification rejects.

    The pinned Version identifiers leave here as a non-optional type, so the
    rest of the assembly has no `None` case to handle and therefore no second
    place where an unpinned entry could quietly be given a default.
    """
    pinned: list[_PinnedEntry] = []
    for entry in entries:
        if entry.artifact_version_id is None:
            raise ExportError(ExportRejection.VERSION_NOT_PINNED, entry.path)
        _validate_path(entry.path)
        pinned.append(_PinnedEntry(entry=entry, version_id=entry.artifact_version_id))
    _validate_namespace([entry.path for entry in entries])
    return tuple(pinned)


def _validate_path(path: str) -> None:
    """Refuse one pack path on its own shape, before any cross-entry check."""
    if not path:
        raise ExportError(ExportRejection.PATH_EMPTY, path)
    if _CONTROL_CHARACTERS.search(path) is not None:
        raise ExportError(ExportRejection.PATH_CONTROL_CHARACTER, path)
    if "\\" in path:
        raise ExportError(ExportRejection.PATH_BACKSLASH, path)
    if _DRIVE_QUALIFIED.match(path) is not None:
        raise ExportError(ExportRejection.PATH_DRIVE_QUALIFIED, path)
    if path.startswith("/"):
        raise ExportError(ExportRejection.PATH_ABSOLUTE, path)
    if len(path) > MAX_PACK_PATH_CHARACTERS:
        raise ExportError(ExportRejection.PATH_TOO_LONG, path)
    for segment in path.split("/"):
        _validate_segment(segment, path)
    _validate_reserved_root(path)


def _validate_segment(segment: str, path: str) -> None:
    """Refuse one path segment that no filesystem should be asked to create."""
    if not segment:
        raise ExportError(ExportRejection.PATH_EMPTY_SEGMENT, path)
    if segment in {".", ".."}:
        raise ExportError(ExportRejection.PATH_DOT_SEGMENT, path)
    if segment.endswith("."):
        raise ExportError(ExportRejection.PATH_SEGMENT_TRAILING_DOT, path)
    if segment.endswith(" "):
        raise ExportError(ExportRejection.PATH_SEGMENT_TRAILING_SPACE, path)
    if len(segment) > MAX_PACK_SEGMENT_CHARACTERS:
        raise ExportError(ExportRejection.PATH_TOO_LONG, path)
    if segment.split(".", maxsplit=1)[0].upper() in RESERVED_DEVICE_NAMES:
        raise ExportError(ExportRejection.PATH_RESERVED_DEVICE, path)


def _validate_reserved_root(path: str) -> None:
    """Refuse a path equal to, or beneath, a name the pack owns."""
    for reserved in RESERVED_ROOTS:
        if path == reserved or path.startswith(f"{reserved}/"):
            raise ExportError(ExportRejection.PATH_RESERVED_ROOT, path)


def _validate_namespace(paths: Sequence[str]) -> None:
    """Refuse two entries that cannot coexist as files in one directory tree.

    The reserved roots take part in both checks. A filesystem that folds case
    or normalizes Unicode would let `MANIFEST.JSON` overwrite the manifest, and
    `manifest.json/child` would need the manifest to be a directory.
    """
    namespace = [*RESERVED_ROOTS, *paths]
    seen: set[str] = set()
    for path in namespace:
        key = unicodedata.normalize("NFKC", path).casefold()
        if key in seen:
            raise ExportError(ExportRejection.PATH_COLLISION, path)
        seen.add(key)
    _validate_no_directory_prefix(namespace)


def _validate_no_directory_prefix(paths: Sequence[str]) -> None:
    """Refuse a path that must be both a file and a directory."""
    files = set(paths)
    for path in paths:
        segments = path.split("/")
        for index in range(1, len(segments)):
            if "/".join(segments[:index]) in files:
                raise ExportError(ExportRejection.PATH_DIRECTORY_PREFIX, path)


def _validate_destination(destination: Path) -> None:
    """Refuse to write through a link, over an existing pack, or into a file."""
    if destination.is_symlink():
        raise ExportError(ExportRejection.LINK_ENTRY)
    # `lexists` rather than `exists`: a dangling link is still an occupant.
    if os.path.lexists(destination):
        raise ExportError(ExportRejection.DESTINATION_EXISTS)
    parent = destination.parent
    if parent.is_symlink():
        raise ExportError(ExportRejection.LINK_ENTRY)
    if not parent.is_dir():
        raise ExportError(ExportRejection.DESTINATION_NOT_A_DIRECTORY)


def _read_evidence(
    store: LocalArtifactStore,
    scope: ArtifactScope,
    run_id: UUID,
) -> _RunEvidence:
    """Read every durable record one pack needs, refusing an incomplete chain."""
    run = store.run(scope, run_id)
    if run is None:
        raise ExportError(ExportRejection.RUN_NOT_FOUND)
    outputs = store.run_outputs(scope, run_id)
    execution = _execution_for(store, scope, outputs)
    plan = store.action_plan(scope, run.plan_id)
    if plan is None:
        raise ExportError(ExportRejection.PLAN_NOT_FOUND)
    approval = store.plan_approval(scope, run.approval_id)
    if approval is None:
        raise ExportError(ExportRejection.APPROVAL_NOT_FOUND)
    pinned_input_sha256 = LocalArtifactStore.pinned_input_digest(
        scope,
        run_id,
        [output.artifact_version_id for output in outputs],
        [execution.id],
    )
    review = store.review_for_pinned_inputs(scope, pinned_input_sha256)
    findings = () if review is None else store.review_findings(scope, review.id)
    return _RunEvidence(
        run=run,
        execution=execution,
        plan=plan,
        approval=approval,
        outputs=outputs,
        review=review,
        findings=findings,
        pinned_input_sha256=pinned_input_sha256,
    )


def _execution_for(
    store: LocalArtifactStore,
    scope: ArtifactScope,
    outputs: Sequence[RunOutputRecord],
) -> ExecutionRecord:
    """Resolve the one produced execution the Run's outputs were pinned to.

    Read from a committed Version rather than from a Run field, because the
    execution identity that shaped the bytes is the one recorded on the bytes.
    """
    if not outputs:
        raise ExportError(ExportRejection.EXECUTION_MISSING)
    version = store.version(scope, outputs[0].artifact_version_id)
    if version is None:
        raise ExportError(ExportRejection.VERSION_NOT_FOUND)
    execution = store.execution(scope, version.producing_execution_id)
    if execution is None:
        raise ExportError(ExportRejection.EXECUTION_MISSING)
    return execution


def _resolve_entry(
    store: LocalArtifactStore,
    scope: ArtifactScope,
    pinned: _PinnedEntry,
    outputs: Sequence[RunOutputRecord],
) -> _ResolvedEntry:
    """Read one pinned Version and re-verify its bytes independently.

    The digest and length are recomputed here even though the store verifies
    its own blobs, because a pack must not rest on a statement the producing
    side made about itself.
    """
    entry, version_id = pinned.entry, pinned.version_id
    outcome, version, payload = store.redeem_content(scope, version_id)
    if outcome is StoreOutcome.ARCHIVED:
        raise ExportError(ExportRejection.PROJECT_ARCHIVED, entry.path)
    if version is None:
        raise ExportError(ExportRejection.VERSION_NOT_FOUND, entry.path)
    if payload is None:
        raise ExportError(ExportRejection.CONTENT_UNAVAILABLE, entry.path)
    if version.artifact_id != entry.artifact_id:
        raise ExportError(ExportRejection.ENTRY_ARTIFACT_MISMATCH, entry.path)
    if (
        sha256_hex(payload) != version.content_sha256
        or len(payload) != version.size_bytes
    ):
        raise ExportError(ExportRejection.CONTENT_DIGEST_MISMATCH, entry.path)
    output = next(
        (item for item in outputs if item.artifact_version_id == version_id),
        None,
    )
    return _ResolvedEntry(entry=entry, version=version, payload=payload, output=output)


def _attested_members(
    evidence: _RunEvidence,
    attested: AttestedInputs,
) -> tuple[PackMember, ...]:
    """Write attested bytes only when they hash to the already pinned digest."""
    members: list[PackMember] = []
    intent = attested.research_intent_json
    if intent is not None:
        if sha256_hex(intent) != evidence.execution.research_intent_sha256:
            raise ExportError(ExportRejection.INTENT_DIGEST_MISMATCH)
        members.append(_member(RESEARCH_INTENT_PATH, intent))
    source = attested.scientific_input_json
    if source is not None:
        if sha256_hex(source) != evidence.execution.input_sha256:
            raise ExportError(ExportRejection.INPUT_DIGEST_MISMATCH)
        members.append(_member(SCIENTIFIC_INPUT_PATH, source))
    facts = attested.environment_facts
    if facts is not None:
        payload = canonical_json(dict(facts))
        if sha256_hex(payload) != evidence.execution.environment_sha256:
            raise ExportError(ExportRejection.ENVIRONMENT_DIGEST_MISMATCH)
        members.append(_member(ENVIRONMENT_PATH, payload))
    return tuple(members)


def _run_record_member(paths: LocalPaths, execution_id: UUID) -> PackMember | None:
    """Read the run mirror, refusing a link where a regular file must be.

    The mirror is the one pack member read from an arbitrary filesystem path
    rather than from content-addressed storage, so it is the one place a link
    could substitute the data root's own credential files for run evidence.
    """
    path = run_record_path(paths, execution_id)
    if path.is_symlink():
        raise ExportError(ExportRejection.LINK_ENTRY, RUN_RECORD_PATH)
    # Already proven not to be a link, so `lexists` and `exists` agree here.
    if not os.path.lexists(path):
        return None
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ExportError(ExportRejection.LINK_ENTRY, RUN_RECORD_PATH)
    return _member(RUN_RECORD_PATH, path.read_bytes())


def _member(path: str, payload: bytes) -> PackMember:
    """Bind one pack path to its bytes and their digest."""
    return PackMember(path=path, payload=payload, sha256=sha256_hex(payload))


def _documents(
    scope: ArtifactScope,
    request: ExportRequest,
    evidence: _RunEvidence,
    resolved: Sequence[_ResolvedEntry],
    attested: Sequence[PackMember],
) -> tuple[PackMember, ...]:
    """Build every pack-owned document except `checksums.sha256`."""
    plan_document = _plan_document(evidence)
    provenance_document = _provenance_document(evidence, resolved)
    review_document = _review_document(evidence)
    members = [
        _member(ACTION_PLAN_PATH, canonical_json(plan_document)),
        _member(PROVENANCE_PATH, canonical_json(provenance_document)),
        _member(REVIEW_PATH, canonical_json(review_document)),
    ]
    manifest = _manifest_document(
        scope,
        request,
        evidence,
        resolved,
        _described(members, attested),
        plan_document,
        provenance_document,
        review_document,
    )
    members.append(_member(MANIFEST_PATH, canonical_json(manifest)))
    return tuple(members)


def _described(
    documents: Sequence[PackMember],
    attested: Sequence[PackMember],
) -> tuple[PackMember, ...]:
    """Return the pack documents that `manifest.json` itself lists."""
    return (*documents, *attested)


def _plan_document(evidence: _RunEvidence) -> dict[str, object]:
    """Project the immutable ActionPlan and the one-use approval that spent it."""
    plan, approval = evidence.plan, evidence.approval
    return {
        "schema": ACTION_PLAN_SCHEMA,
        "research_intent_sha256": plan.research_intent_sha256,
        "plan": {
            "id": str(plan.id),
            "org_id": str(plan.org_id),
            "project_id": str(plan.project_id),
            "requester_id": str(plan.requester_id),
            "plan_sha256": plan.plan_sha256,
            "research_intent_sha256": plan.research_intent_sha256,
            "created_at": plan.created_at.isoformat(),
        },
        "approval": {
            "id": str(approval.id),
            "plan_id": str(approval.plan_id),
            "approver_id": str(approval.approver_id),
            "plan_sha256": approval.plan_sha256,
            "research_intent_sha256": approval.research_intent_sha256,
            "granted_at": approval.granted_at.isoformat(),
            "expires_at": approval.expires_at.isoformat(),
            "consumed_at": _isoformat(approval.consumed_at),
            "consumed_by_run_id": _text(approval.consumed_by_run_id),
            "one_use": True,
        },
        "digest_recipe": {
            "plan_sha256": (
                "sha256 of "
                '{"org_id","plan_id","project_id","requester_id",'
                '"research_intent_sha256","schema"} serialized by the canonical '
                "JSON rule, with schema "
                '"nipo.local.action-plan.v1". Server-derived: a producer cannot '
                "choose it, and changing the bound intent digest changes it."
            ),
        },
    }


def _provenance_document(
    evidence: _RunEvidence,
    resolved: Sequence[_ResolvedEntry],
) -> dict[str, object]:
    """Project the pinned provenance of the execution and of every Version."""
    execution = evidence.execution
    return {
        "schema": PROVENANCE_SCHEMA,
        "execution": {
            "id": str(execution.id),
            "run_id": str(execution.run_id),
            "execution_isolation": execution.execution_isolation,
            "execution_isolation_is_a_sandbox": False,
            "input_sha256": execution.input_sha256,
            "research_intent_sha256": execution.research_intent_sha256,
            "code_sha256": execution.code_sha256,
            "environment_sha256": execution.environment_sha256,
            "created_at": execution.created_at.isoformat(),
        },
        "run": {
            "id": str(evidence.run.id),
            "state": evidence.run.state.value,
            "plan_id": str(evidence.run.plan_id),
            "approval_id": str(evidence.run.approval_id),
            "research_intent_sha256": evidence.run.research_intent_sha256,
            "created_at": evidence.run.created_at.isoformat(),
            "updated_at": evidence.run.updated_at.isoformat(),
            "error_type": evidence.run.error_type,
            "error_code": evidence.run.error_code,
            "committed_output_count": len(evidence.outputs),
        },
        "versions": [_version_provenance(item) for item in resolved],
    }


def _version_provenance(resolved: _ResolvedEntry) -> dict[str, object]:
    """Project every provenance field one Version records."""
    version = resolved.version
    return {
        "path": resolved.entry.path,
        "artifact_id": str(version.artifact_id),
        "artifact_version_id": str(version.id),
        "version_no": version.version_no,
        "object_key": version.object_key,
        "content_sha256": version.content_sha256,
        "size_bytes": version.size_bytes,
        "media_type": version.media_type,
        "producing_execution_id": str(version.producing_execution_id),
        "environment_sha256": version.environment_sha256,
        "code_sha256": version.code_sha256,
        "runtime_adapter_id": version.runtime_adapter_id,
        "runtime_connection_id": str(version.runtime_connection_id),
        "skill_content_hashes": [str(value) for value in version.skill_content_hashes],
        "source_hashes": [str(value) for value in version.source_hashes],
        "input_version_ids": [str(value) for value in version.input_version_ids],
        "created_at": version.created_at.isoformat(),
        "role": None if resolved.output is None else resolved.output.role,
        "output_name": None if resolved.output is None else resolved.output.name,
        "output_sequence": (
            None if resolved.output is None else resolved.output.sequence
        ),
    }


def _review_document(evidence: _RunEvidence) -> dict[str, object]:
    """Project the Review that covers this Run's pinned evidence, or its absence.

    The Review is looked up from the Run's own pinned-input digest rather than
    named by the caller, so an export cannot omit a Review that exists or
    substitute a more favourable one.
    """
    review = evidence.review
    if review is None:
        return {
            "schema": REVIEW_SCHEMA,
            "present": False,
            "reason": "no Review pins this Run's evidence",
            "pinned_input_sha256": evidence.pinned_input_sha256,
            "findings": [],
        }
    return {
        "schema": REVIEW_SCHEMA,
        "present": True,
        "id": str(review.id),
        "state": review.state.value,
        "source_run_id": str(review.source_run_id),
        "pinned_input_sha256": review.pinned_input_sha256,
        "pinned_artifact_version_ids": [
            str(value) for value in review.pinned_artifact_version_ids
        ],
        "pinned_execution_ids": [str(value) for value in review.pinned_execution_ids],
        "created_at": review.created_at.isoformat(),
        "updated_at": review.updated_at.isoformat(),
        "findings_submitted_at": _isoformat(review.findings_submitted_at),
        "error_type": review.error_type,
        "error_code": review.error_code,
        "findings": [_finding(item) for item in evidence.findings],
    }


def _finding(finding: ReviewFindingRecord) -> dict[str, object]:
    """Project one immutable Review finding."""
    return {
        "id": str(finding.id),
        "sequence": finding.sequence,
        "rule_id": finding.rule_id.value,
        "verdict": finding.verdict.value,
        "status": finding.status.value,
        "code": finding.code,
        "message": finding.message,
        "artifact_version_ids": [str(value) for value in finding.artifact_version_ids],
        "execution_ids": [str(value) for value in finding.execution_ids],
        "created_at": finding.created_at.isoformat(),
    }


def _manifest_document(  # noqa: PLR0913 - one document, one assembly point
    scope: ArtifactScope,
    request: ExportRequest,
    evidence: _RunEvidence,
    resolved: Sequence[_ResolvedEntry],
    documents: Sequence[PackMember],
    plan_document: Mapping[str, object],
    provenance_document: Mapping[str, object],
    review_document: Mapping[str, object],
) -> dict[str, object]:
    """Assemble `manifest.json`, which records no digest of itself."""
    entries = [_artifact_entry(item) for item in resolved]
    entries.extend(_document_entry(item) for item in documents)
    entries.sort(key=lambda item: str(item["path"]))
    return {
        "schema": PACK_SCHEMA,
        "pack_id": str(request.pack_id),
        "created_at": request.created_at.isoformat(),
        "org_id": str(scope.org_id),
        "project_id": str(scope.project_id),
        "research_intent_sha256": evidence.execution.research_intent_sha256,
        "selection": {
            "resolution": "explicit_version_ids_never_latest",
            "order": SELECTION_ORDER_NOTE,
            "artifact_version_ids": [str(value) for value in request.selection],
        },
        "entries": entries,
        "action_plan": dict(plan_document),
        "provenance": dict(provenance_document),
        "review": dict(review_document),
        "disclosures": _disclosures(evidence),
        "verification": _verification(evidence, documents),
    }


def _artifact_entry(resolved: _ResolvedEntry) -> dict[str, object]:
    """Describe one exported Artifact Version entry."""
    version = resolved.version
    return {
        "kind": "artifact_version",
        "path": resolved.entry.path,
        "sha256": version.content_sha256,
        "size_bytes": version.size_bytes,
        "media_type": version.media_type,
        "artifact_id": str(version.artifact_id),
        "artifact_version_id": str(version.id),
        "version_no": version.version_no,
        "producing_execution_id": str(version.producing_execution_id),
    }


def _document_entry(member: PackMember) -> dict[str, object]:
    """Describe one pack-owned document entry."""
    return {
        "kind": "pack_document",
        "path": member.path,
        "sha256": member.sha256,
        "size_bytes": len(member.payload),
        "media_type": "application/json",
    }


def _disclosures(evidence: _RunEvidence) -> dict[str, object]:
    """State what this pack does not prove, rather than leaving it inferable."""
    return {
        "execution_isolation": evidence.execution.execution_isolation,
        "execution_isolation_is_a_sandbox": False,
        "execution_isolation_note": ISOLATION_NOT_A_SANDBOX,
        "skill_content_hashes": SKILL_HASHES_NOTE,
        "environment_digest_coverage": ENVIRONMENT_COVERAGE_NOTE,
        "keychain_master_key": MASTER_KEY_NOTE,
        "export_selections_not_persisted": SELECTION_PERSISTENCE_NOTE,
        "code_digest": CODE_DIGEST_NOTE,
    }


def _verification(
    evidence: _RunEvidence,
    documents: Sequence[PackMember],
) -> dict[str, object]:
    """State, inside the pack, how to check the pack without this codebase."""
    written = {member.path for member in documents}
    return {
        "digest_algorithm": "sha256",
        "digest_encoding": "lowercase hexadecimal",
        "canonical_json": CANONICAL_JSON_RULE,
        "checksums_file": CHECKSUMS_PATH,
        "checksums_line_format": (
            "<64 lowercase hex digits><two spaces><pack-relative path>"
        ),
        "checksums_line_terminator": "\\n",
        "checksums_encoding": "utf-8",
        "checksums_ordering": (
            "ascending by pack-relative path compared as Unicode code points"
        ),
        "checksums_covers": (
            f"every pack member except {CHECKSUMS_PATH}, which no line covers"
        ),
        "manifest_self_digest": (
            f"absent by construction; the digest of {MANIFEST_PATH} is recorded "
            f"once, in {CHECKSUMS_PATH}"
        ),
        "archive_format": (
            "ZIP with every member stored uncompressed and marked as a regular "
            "file; the pack contains no link, device, or directory entry"
        ),
        "path_rules": (
            "No entry is absolute or drive-qualified, contains a backslash, a "
            "dot or dot-dot segment, a segment ending in a dot or a space, a "
            "control character, or a reserved device name. No two entries "
            "collide after NFKC normalization and case folding, and no entry "
            "is a directory prefix of another."
        ),
        "steps": _verification_steps(),
        "recomputable_from_pack": _recomputable(written),
        "recomputable_with_pinned_toolchain": {
            "code_sha256": (
                "sha256 of the canonical JSON of {source path: sha256 of that "
                "file's bytes} over every .py file of the pinned science "
                "package plus the producing module, keyed "
                '"science_workbench_science/<relative posix path>" and '
                '"nipo_local/workbench.py".'
            ),
        },
        "not_recomputable_from_pack": _not_recomputable(written),
        "pinned_input_sha256": evidence.pinned_input_sha256,
        "pinned_input_sha256_recipe": (
            "sha256 of the canonical JSON of "
            '{"artifact_version_ids","execution_ids","org_id","project_id",'
            '"schema","source_run_id"} with schema '
            '"nipo.local.review-pinned-input.v1", identifiers sorted, '
            "deduplicated, and rendered as canonical lowercase UUID text. It "
            "is the value that deduplicates one Review over one evidence set."
        ),
    }


def _verification_steps() -> list[str]:
    """Return the ordered instructions a third party follows."""
    return [
        f"1. Extract the pack with any ZIP reader. Confirm every member is a "
        f"regular file and that {CHECKSUMS_PATH} and {MANIFEST_PATH} exist.",
        f"2. For each line of {CHECKSUMS_PATH}, recompute the SHA-256 of the "
        f"named file and compare. `sha256sum -c {CHECKSUMS_PATH}` does this.",
        f"3. Parse {MANIFEST_PATH}. For each object in `entries`, recompute the "
        "SHA-256 and byte length of `path` and compare against `sha256` and "
        "`size_bytes`.",
        f"4. Confirm the two independent statements agree: each entry's "
        f"`sha256` in {MANIFEST_PATH} equals the digest recorded for the same "
        f"path in {CHECKSUMS_PATH}.",
        "5. Confirm `selection.artifact_version_ids` is sorted, has no repeat, "
        "and equals the multiset of `artifact_version_id` over the entries "
        "whose `kind` is `artifact_version`.",
        f"6. Re-serialize {MANIFEST_PATH}'s `action_plan`, `provenance` and "
        f"`review` objects with `canonical_json` and compare byte for byte "
        f"against {ACTION_PLAN_PATH}, {PROVENANCE_PATH} and {REVIEW_PATH}.",
        "7. Confirm every `provenance.versions[]` entry repeats the "
        "`content_sha256` recomputed in step 3 for the same `path`.",
        f"8. For each digest listed in `verification.recomputable_from_pack`, "
        "recompute it from the named member and compare against the pinned "
        f"value in {PROVENANCE_PATH}.",
        "9. Read `disclosures`. `execution_isolation` is the isolation the run "
        "actually had; the pack claims no confinement beyond it.",
        "10. Read `not_recomputable_from_pack`. Any digest listed there is "
        "self-reported by this pack and must not be treated as independently "
        "verified provenance.",
    ]


def _recomputable(written: Iterable[str]) -> dict[str, object]:
    """Name each pinned digest a verifier can rebuild from the pack alone."""
    present = set(written)
    recomputable: dict[str, object] = {
        "entry_sha256": (
            f"SHA-256 of each entry's own bytes, stated twice in {MANIFEST_PATH} "
            f"and {CHECKSUMS_PATH}."
        ),
        "manifest_sha256": (
            f"SHA-256 of {MANIFEST_PATH}'s bytes, stated once in {CHECKSUMS_PATH}."
        ),
    }
    if RESEARCH_INTENT_PATH in present:
        recomputable["research_intent_sha256"] = (
            f"SHA-256 of {RESEARCH_INTENT_PATH}, whose bytes are the intent's "
            f"own canonical serialization: {INTENT_JSON_RULE}. Note the "
            "ensure_ascii=False: the intent digest predates this pack's "
            "canonical rule and is not re-serialized here."
        )
    if SCIENTIFIC_INPUT_PATH in present:
        recomputable["input_sha256"] = (
            f"SHA-256 of {SCIENTIFIC_INPUT_PATH}, whose bytes are the declared "
            "scientific input's own canonical serialization."
        )
    if ENVIRONMENT_PATH in present:
        recomputable["environment_sha256"] = (
            f"SHA-256 of {ENVIRONMENT_PATH}, serialized by `canonical_json` "
            "over the recorded environment facts."
        )
    return recomputable


def _not_recomputable(written: Iterable[str]) -> dict[str, object]:
    """Name each pinned digest this pack can only report, not prove."""
    present = set(written)
    absent: dict[str, object] = {
        "code_sha256": CODE_DIGEST_NOTE,
    }
    if RESEARCH_INTENT_PATH not in present:
        absent["research_intent_sha256"] = (
            "Self-reported. The store persists the intent digest but not the "
            "intent, and this export was not given the canonical bytes, so the "
            "digest cannot be recomputed from the pack."
        )
    if SCIENTIFIC_INPUT_PATH not in present:
        absent["input_sha256"] = (
            "Self-reported. The store persists the input digest but not the "
            "declared scientific input, and this export was not given its "
            "canonical bytes."
        )
    if ENVIRONMENT_PATH not in present:
        absent["environment_sha256"] = (
            "Self-reported. The store persists the environment digest but not "
            "the environment facts it was taken over, and this export was not "
            "given them."
        )
    return absent


def _finalize(
    resolved: Sequence[_ResolvedEntry],
    attested: Sequence[PackMember],
    documents: Sequence[PackMember],
) -> tuple[PackMember, ...]:
    """Order every member and append the checksum file that covers them all."""
    members = [
        PackMember(
            path=item.entry.path,
            payload=item.payload,
            sha256=item.version.content_sha256,
        )
        for item in resolved
    ]
    members.extend(attested)
    members.extend(documents)
    members.sort(key=lambda item: item.path)
    checksums = _member(CHECKSUMS_PATH, _checksums_payload(members))
    return (*members, checksums)


def _checksums_payload(members: Sequence[PackMember]) -> bytes:
    """Render sha256sum-compatible lines for every member but this one."""
    return "".join(
        f"{member.sha256}  {member.path}\n"
        for member in sorted(members, key=lambda item: item.path)
    ).encode("utf-8")


def _credential_fragments(paths: LocalPaths) -> tuple[bytes, ...]:
    """Collect the exact byte runs that must never appear in a pack.

    The Keychain master key is deliberately absent: reading it to search for
    it would be the very access this module refuses to have.
    """
    fragments = [
        *_signing_key_fragments(paths),
        *_credential_store_fragments(paths),
        *_environment_key_fragments(),
    ]
    return tuple(dict.fromkeys(fragments))


def _signing_key_fragments(paths: LocalPaths) -> tuple[bytes, ...]:
    """Return the download signing key in every encoding it could be leaked in."""
    path = signing_key_path(paths)
    if path.is_symlink() or not path.is_file():
        return ()
    raw = path.read_bytes()
    if len(raw) < MIN_CREDENTIAL_FRAGMENT_BYTES:
        return ()
    return (
        raw,
        b64encode(raw),
        raw.hex().encode("ascii"),
        raw.hex().upper().encode("ascii"),
    )


def _credential_store_fragments(paths: LocalPaths) -> tuple[bytes, ...]:
    """Return the sealed provider store's bytes and every sealed value in it."""
    path = paths.credentials
    if path.is_symlink() or not path.is_file():
        return ()
    raw = path.read_bytes()
    fragments = [raw] if len(raw) >= MIN_CREDENTIAL_FRAGMENT_BYTES else []
    try:
        document = cast("object", json.loads(raw))
    except (ValueError, UnicodeDecodeError):
        # A corrupt store is never quarantined or rewritten; the raw bytes are
        # still searched for.
        return tuple(fragments)
    fragments.extend(_string_values(document))
    return tuple(fragments)


def _string_values(value: object) -> list[bytes]:
    """Collect every distinctive string value, ignoring keys, at any depth."""
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return [encoded] if len(encoded) >= MIN_CREDENTIAL_FRAGMENT_BYTES else []
    if isinstance(value, dict):
        nested: list[bytes] = []
        for item in cast("dict[str, object]", value).values():
            nested.extend(_string_values(item))
        return nested
    if isinstance(value, list):
        nested = []
        for item in cast("list[object]", value):
            nested.extend(_string_values(item))
        return nested
    return []


def _environment_key_fragments() -> tuple[bytes, ...]:
    """Return every provider key the process environment is currently exposing."""
    return tuple(
        value.encode("utf-8")
        for name, value in os.environ.items()
        if name.startswith(ENVIRONMENT_KEY_PREFIX)
        and name.endswith(ENVIRONMENT_KEY_SUFFIX)
        and len(value.encode("utf-8")) >= MIN_CREDENTIAL_FRAGMENT_BYTES
    )


def _reject_credential_material(
    members: Sequence[PackMember],
    fragments: Sequence[bytes],
) -> None:
    """Refuse the whole pack when any member carries credential material."""
    if not fragments:
        return
    for member in members:
        haystack = member.payload + member.path.encode("utf-8")
        for fragment in fragments:
            if fragment in haystack:
                raise ExportError(ExportRejection.CREDENTIAL_MATERIAL, member.path)


def _isoformat(value: datetime | None) -> str | None:
    """Render one optional timestamp without inventing a value for absence."""
    return None if value is None else value.isoformat()


def _text(value: UUID | None) -> str | None:
    """Render one optional identifier without inventing a value for absence."""
    return None if value is None else str(value)
