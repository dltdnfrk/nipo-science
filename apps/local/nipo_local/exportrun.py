"""Join a Run's durable evidence to an Export Pack, and hand out one download.

`exportpack.py` assembles and refuses; `store.py` remembers; neither knows
about the other or about HTTP. Like :mod:`nipo_local.reviewrun`, this module is
the only place they meet and is deliberately the thinnest join that can exist:

    candidates = export_candidates(store, scope, run_id)  # inert values leave the store
    request    = ExportRequest(...)                       # the caller's explicit pins
    pack       = export_run(store, scope, paths, request, destination)

Never "latest", stated twice so it can be broken only twice
-----------------------------------------------------------
`exportpack.build_pack` refuses an unpinned entry, and that refusal is only
worth anything if the layer above cannot quietly supply a pin of its own
choosing. So this module reaches a Version identifier exactly one way: it reads
the `artifact_version_id` the Run itself recorded on `run_outputs` when it
published. There is no call here that lists an Artifact's Versions, orders them
by `version_no` or by time, or otherwise turns an Artifact identity into a
Version identity -- `LocalReadModel` is not imported, and `store.artifact` is
consulted only for a display name.

A caller therefore cannot ask for "the latest": every identifier it submits is
checked for membership in the set the Run published, and one that is not a
member is refused with :data:`ExportRunRejection.SELECTION_NOT_PINNED_TO_RUN`.
An Artifact identifier submitted in a Version's place fails that same
membership test, so it is refused rather than resolved.

The selection is ordered here, and checked there
------------------------------------------------
`ExportRequest.selection` must arrive sorted and duplicate-free.
:func:`produce_pack` renders the caller's set in the canonical ascending order
the manifest documents, because ordering a set is a rendering decision and not
a fact about what the researcher pinned -- a list of checkboxes has no order.
What is *not* normalized is membership: a repeat is refused rather than
collapsed, an empty selection is refused rather than widened, and the entries
handed to `build_pack` are built from the same validated set as the declared
selection, so this caller can never be the one that assembles the two lists
from different places.

Download is a capability URL, not a second session
--------------------------------------------------
`GET .../content` cannot carry `X-Nipo-Token`: a browser attaches no custom
header to a download navigation, and buffering a pack the non-functional budget
sizes at up to 500 MiB into a blob to work around that is not a download, it is
a second copy of the file in the tab's heap. So the pack is streamed from disk
and the browser is given a URL it can fetch by itself.

:class:`DownloadTickets` is what makes that URL safe to exist. A ticket:

* is not the session credential and grants nothing the session credential
  grants -- it opens one pack and answers nothing else;
* is minted only by a request that already presented the session credential;
* is bound to the exact request path it was minted for, so a ticket for one
  pack presented at another pack's path is refused rather than honoured;
* expires after :data:`TICKET_TTL_SECONDS`; and
* is spent by its first acceptance, after which the same URL answers
  `download_ticket_spent` rather than the pack.

The secret lives in the URL path, which is the one place a browser will carry
it without a header. Two things keep that from being a leak. Every response
this listener emits carries `referrer-policy: no-referrer`, so no request the
page makes ever names the URL that produced it; and the response is an
attachment, so no document exists that could emit a `Referer` at all. What is
left -- a spent, expired capability in a download history -- is worth nothing
to whoever finds it.

The registry is keyed by the SHA-256 of the presented secret rather than by the
secret, so the dictionary lookup a guard performs on every request is not a
timing oracle on the secret itself.

A pack has a lifecycle, and nothing here ever ends it on its own
--------------------------------------------------------------
Every export used to be a one-way door: a file appeared under
`<root>/exports/<project>/`, no route listed it, no route removed it, and a
researcher who exported twice a day grew their data root by up to a gigabyte
without a surface that even showed the fact. :func:`list_packs` and
:func:`delete_pack` close that, and the shape they take is a deliberate
decision rather than a convenience:

* **Listing reports the filesystem, and quotes the pack for the rest.** Size and
  modification time come from `stat`, because those are facts only the
  filesystem has; the Run, the creation instant, and the pinned selection come
  from the pack's own `manifest.json`, because those are facts only the pack
  has. A pack whose manifest cannot be read is still listed -- with its real
  size, and `manifest_readable` false -- rather than hidden, because a file
  taking up space is exactly the thing this surface exists to show.
* **There is no route that chooses what to delete.** No retention horizon, no
  sweep that selects its own victims, no eviction when a budget is exceeded.
  :func:`delete_pack` removes exactly one pack named by its identifier, and a
  UUIDv7 pack identifier is only learnable from a listing or from the produce
  response -- both of which a researcher was shown. That is what makes "never
  delete evidence nobody saw" a property of the design instead of a promise
  about how the screen is used. Bounded growth is answered by making the cost
  visible (:data:`EXPORTS_BUDGET_BYTES`, reported beside a real byte total) and
  by an explicit, per-pack sweep the researcher confirms over rows already on
  the screen.

Deletion is confined by descriptor, not by string
-------------------------------------------------
A sibling surface learned the hard way that a confinement check which resolves
*too many* path segments is satisfiable by swapping a directory for a link:
resolve the Project segment and the comparison agrees with wherever the link
points. So deletion never walks a path at all. Each segment below the data root
is opened with `O_NOFOLLOW | O_DIRECTORY` -- a symlinked `exports/` or
`exports/<project>/` fails to open rather than being followed -- the entry is
`lstat`ed through that descriptor and must be a regular file, and the unlink is
performed relative to that same descriptor. There is no window in which the
directory can be substituted between the check and the removal, because the
check and the removal address the same open directory. The path-shaped rule
`read_pack` already applied is kept as well, in :func:`_refuse_unconfined`, so a
pack that cannot be downloaded cannot be deleted and vice versa.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import zipfile
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Final, cast, final
from uuid import UUID

from services.api.artifacts.store_contract import ArtifactStoreError

from .exportpack import (
    ACTION_PLAN_PATH,
    CHECKSUMS_PATH,
    ENVIRONMENT_PATH,
    MANIFEST_PATH,
    PROVENANCE_PATH,
    RESEARCH_INTENT_PATH,
    REVIEW_PATH,
    RUN_RECORD_PATH,
    SCIENTIFIC_INPUT_PATH,
    AttestedInputs,
    ExportEntry,
    ExportError,
    ExportRejection,
    ExportRequest,
    export_run,
)
from .store import ExecutionInputKind
from .workbench import canonical_sha256, environment_facts

if TYPE_CHECKING:
    from collections.abc import Generator, Mapping, Sequence
    from pathlib import Path

    from services.api.artifacts.models import ArtifactScope, Clock, IdFactory

    from .config import LocalPaths
    from .exportpack import ExportPack
    from .store import LocalArtifactStore, RunOutputRecord

__all__ = [
    "ALWAYS_WRITTEN_DOCUMENTS",
    "ARTIFACT_PREFIX",
    "CONDITIONAL_DOCUMENTS",
    "DOWNLOAD_ROUTE",
    "EXPORTS_BUDGET_BYTES",
    "EXPORTS_DIRECTORY",
    "MAX_LISTED_SELECTION",
    "MAX_MANIFEST_BYTES",
    "MAX_OPEN_TICKETS",
    "PACK_MEDIA_TYPE",
    "RESERVED_DOCUMENTS",
    "TICKET_TTL_SECONDS",
    "DeletedPack",
    "DownloadGrant",
    "DownloadTicket",
    "DownloadTickets",
    "ExportCandidate",
    "ExportJob",
    "ExportRunError",
    "ExportRunRejection",
    "PackEntry",
    "ProducedPack",
    "StoredPack",
    "StoredPacks",
    "TicketOutcome",
    "delete_pack",
    "export_candidates",
    "exports_root",
    "list_packs",
    "pack_documents",
    "pack_file",
    "produce_pack",
    "read_pack",
    "stream_pack",
]

EXPORTS_DIRECTORY: Final = "exports"
"""Directory under the data root that holds produced packs, one file each."""

EXPORTS_MODE: Final = 0o700
PACK_SUFFIX: Final = ".zip"
PACK_MEDIA_TYPE: Final = "application/zip"

ARTIFACT_PREFIX: Final = "artifacts"
"""Pack-relative directory every exported Artifact Version is written under.

Fixed, never a caller value. It also keeps every Artifact one segment deep
inside a directory that is not a reserved pack root, so a producer-chosen
output name cannot land on `manifest.json`.
"""

DOWNLOAD_ROUTE: Final = "/projects/{project_id}/exports/{pack_id}/content/{ticket}"
"""The one download path, used to register the route and to mint every ticket.

One template rather than two statements: the path a ticket is bound to and the
path the router answers cannot drift apart, because both are formatted from
this string.
"""

TICKET_TTL_SECONDS: Final = 60
"""How long a minted download URL stays usable. Long enough for one click."""

TICKET_ENTROPY_BYTES: Final = 32
"""Entropy behind one capability URL, matching the session credential's."""

MAX_OPEN_TICKETS: Final = 64
"""Upper bound on remembered tickets, so minting cannot grow this unbounded."""

PACK_READ_CHUNK: Final = 1 << 20
"""Bytes read per streamed chunk, so a whole pack is never read at once."""

EXPORTS_BUDGET_BYTES: Final = 2 * (1 << 30)
"""The point at which exports are reported as costing more than they should.

Two gibibytes, which the non-functional budget's 500 MiB pack reaches in four
exports. It is a *reporting* threshold and nothing else: crossing it removes
nothing, expires nothing, and blocks no further export. Automatic eviction
would mean deleting evidence a researcher may never have looked at, and losing
a pack silently is worse than a full disk -- a full disk is loud.
"""

MAX_MANIFEST_BYTES: Final = 8 * (1 << 20)
"""Largest `manifest.json` this listing will decode out of a stored pack.

A listing reads one member of every file in a directory, so the work it does
has to be bounded by something other than the trust it places in the file. A
manifest over this size is reported as unreadable rather than parsed.
"""

MAX_LISTED_SELECTION: Final = 1024
"""Longest pinned selection a listed row will render.

Matched to the surface's own submission bound. A manifest declaring more is
reported as unreadable rather than truncated: a row showing half a selection
would be a quieter error than a row saying it could not read one.
"""

_DIRECTORY_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
"""How every directory below the data root is opened: never through a link.

`O_NOFOLLOW` applies to the final component, so each segment is opened in its
own call relative to the previous descriptor. Ancestors of the data root are
deliberately not covered: a researcher may legitimately keep `~/.nipo-science`
behind a link, and the boundary this enforces is the exports tree.
"""

_FILE_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW
"""How a stored pack is opened for reading its manifest: never through a link."""

_MANIFEST_FAILURES: Final = (
    OSError,
    KeyError,
    ValueError,
    EOFError,
    zipfile.BadZipFile,
    zlib.error,
)
"""Every way a file that is not a readable pack can fail to be read as one.

Enumerated rather than caught blind, so a failure this list does not name
surfaces as a defect instead of quietly becoming "manifest unreadable".
"""

ALWAYS_WRITTEN_DOCUMENTS: Final = (
    MANIFEST_PATH,
    CHECKSUMS_PATH,
    PROVENANCE_PATH,
    ACTION_PLAN_PATH,
    REVIEW_PATH,
)
"""The pack documents every export writes, whatever evidence a Run left."""

CONDITIONAL_DOCUMENTS: Final = (
    RUN_RECORD_PATH,
    RESEARCH_INTENT_PATH,
    SCIENTIFIC_INPUT_PATH,
    ENVIRONMENT_PATH,
)
"""The pack documents an export writes only when the bytes exist to write.

Whether each one reaches a pack is decided at produce time -- the run mirror
must be on disk, and an attested digest must match what the execution pinned --
so a plan can name them but must not promise them.
"""

RESERVED_DOCUMENTS: Final = (*ALWAYS_WRITTEN_DOCUMENTS, *CONDITIONAL_DOCUMENTS)
"""Every reserved pack root, which is also every name a caller entry may not
take."""


class ExportRunRejection(StrEnum):
    """Closed reasons one export could not be planned, produced, or read.

    Separate from :class:`~nipo_local.exportpack.ExportRejection`, which names
    the reasons the *packer* refuses. These belong to the join: they are about
    the Run, the caller's selection, and the destination, never about the
    pack's own bytes.
    """

    RUN_NOT_FOUND = "run_not_found"
    NO_COMMITTED_OUTPUTS = "no_committed_outputs"
    SELECTION_EMPTY = "selection_empty"
    SELECTION_DUPLICATE = "selection_duplicate"
    SELECTION_NOT_PINNED_TO_RUN = "selection_not_pinned_to_run"
    PACK_REFUSED = "pack_refused"
    PACK_NOT_FOUND = "pack_not_found"
    STORE_UNAVAILABLE = "store_unavailable"
    EXPORTS_UNREADABLE = "exports_unreadable"


@final
class ExportRunError(ValueError):
    """Refuse one export with a closed reason and no caller input.

    `pack_reason` carries the packer's own refusal when the packer is what
    refused, so a caller learns that its pack was declined for, say,
    `credential_material` rather than only that something failed. Both fields
    are closed enum values; neither is derived from a submitted name, path, or
    identifier, and `ExportError.entry_path` -- the one field that can carry a
    caller-supplied pack path -- is deliberately dropped here.
    """

    __slots__ = ("pack_reason", "reason")

    def __init__(
        self,
        reason: ExportRunRejection,
        pack_reason: ExportRejection | None = None,
    ) -> None:
        """Record the closed refusal reason, and the packer's when there is one."""
        super().__init__(reason.value)
        self.reason = reason
        self.pack_reason = pack_reason


@dataclass(frozen=True, slots=True)
class ExportCandidate:
    """One Artifact Version this Run published, as a selectable export entry.

    `artifact_version_id` is the identifier the Run recorded, never a head
    Version: nothing in this module can produce any other value for it.
    """

    artifact_id: UUID
    artifact_version_id: UUID
    artifact_name: str
    output_name: str
    role: str
    sequence: int
    version_no: int
    pack_path: str
    size_bytes: int
    media_type: str
    content_sha256: str


@dataclass(frozen=True, slots=True)
class PackEntry:
    """One member the produced pack holds, as its own manifest describes it."""

    kind: str
    path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class ProducedPack:
    """One written pack and the statements the pack itself makes about it.

    `disclosures` and `verification` are read back out of the pack's own
    `manifest.json` bytes rather than rebuilt here. A screen that renders them
    is therefore quoting the artifact a colleague will receive, not this
    process's opinion of what it wrote.
    """

    pack_id: UUID
    run_id: UUID
    path: Path
    created_at: datetime
    size_bytes: int
    manifest_sha256: str
    selection: tuple[UUID, ...]
    entries: tuple[PackEntry, ...]
    documents: tuple[tuple[str, bool], ...]
    attested: tuple[str, ...]
    disclosures: Mapping[str, object]
    verification: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class StoredPack:
    """One pack that is really on disk, described by disk and by the pack.

    The split is deliberate and is the whole reason this type exists rather
    than a reuse of :class:`ProducedPack`. `size_bytes` and `modified_at` are
    read from `stat`, because the filesystem is the only thing that knows what
    a file costs and when it was last written. `run_id`, `created_at`,
    `selection`, and `entry_count` are read out of the pack's own
    `manifest.json`, because nothing else remembers them -- the store keeps no
    row for an export.

    `manifest_readable` is false when the file is present but its manifest
    could not be decoded. Such a pack still appears, with its real size, so a
    corrupt file can be seen and removed rather than silently occupying a
    gigabyte no screen accounts for. Its pack fields are `None` and empty
    rather than guessed.
    """

    pack_id: UUID
    size_bytes: int
    modified_at: datetime
    manifest_readable: bool
    run_id: UUID | None = None
    created_at: datetime | None = None
    selection: tuple[UUID, ...] = ()
    entry_count: int = 0


@dataclass(frozen=True, slots=True)
class StoredPacks:
    """Every pack one Project holds, newest first, and what they cost.

    `total_size_bytes` is the sum of the `st_size` values in `packs` and is
    never derived from what a manifest claims a pack contains: a manifest
    describes members, and a member total is not a file size.

    `undescribed_count` counts the entries that name a pack but that this
    listing could not fully describe -- a corrupt archive, or something that is
    not a regular file. It travels so a screen can say the total is incomplete
    instead of presenting it as exhaustive.
    """

    packs: tuple[StoredPack, ...]
    total_size_bytes: int
    undescribed_count: int


@dataclass(frozen=True, slots=True)
class DeletedPack:
    """One pack that was really removed, and the bytes that removal returned.

    `freed_bytes` is the size the entry had at the moment it was unlinked,
    taken from the same `lstat` that established it was a regular file, so it
    is what was actually released rather than what a listing said earlier.
    """

    pack_id: UUID
    freed_bytes: int


@dataclass(frozen=True, slots=True)
class _ManifestFacts:
    """What one stored pack's own manifest says, or that it said nothing."""

    readable: bool
    run_id: UUID | None = None
    created_at: datetime | None = None
    selection: tuple[UUID, ...] = ()
    entry_count: int = 0


_UNREADABLE_MANIFEST: Final = _ManifestFacts(readable=False)
"""The one answer for a file whose manifest this listing declined to read."""


@dataclass(frozen=True, slots=True)
class ExportJob:
    """Everything one export needs, and deliberately nothing more."""

    store: LocalArtifactStore
    scope: ArtifactScope
    paths: LocalPaths
    ids: IdFactory
    clock: Clock


def exports_root(paths: LocalPaths) -> Path:
    """Return the owner-only directory produced packs are written into."""
    return paths.root / EXPORTS_DIRECTORY


def pack_file(paths: LocalPaths, scope: ArtifactScope, pack_id: UUID) -> Path:
    """Return the one file path a pack identifier names.

    Every segment is a canonical UUID rendered by `str`, so no separator, no
    relative segment, and no caller text reaches the path. The result is
    re-checked against the exports root by :func:`read_pack` before a byte of
    it is ever read back.
    """
    return exports_root(paths) / str(scope.project_id) / f"{pack_id}{PACK_SUFFIX}"


def pack_documents(present: Sequence[str]) -> tuple[tuple[str, bool], ...]:
    """Pair every reserved pack root with whether this pack really holds it.

    All nine are listed, present or not, so a screen can show that
    `research-intent.json` is a document this pack does *not* carry rather than
    omit the row and leave a reader to assume it does. Nothing here is
    hard-coded to `True`: the caller supplies what the pack contains, so a
    document that failed to be written reads as absent instead of as promised.
    """
    written = set(present)
    return tuple((path, path in written) for path in RESERVED_DOCUMENTS)


def export_candidates(
    store: LocalArtifactStore,
    scope: ArtifactScope,
    run_id: UUID,
) -> tuple[ExportCandidate, ...]:
    """List exactly the Versions this Run published, in publication order.

    Raises:
        ExportRunError: The Run does not exist, published nothing, or the
            store could not be read.
    """
    try:
        if store.run(scope, run_id) is None:
            raise ExportRunError(ExportRunRejection.RUN_NOT_FOUND)
        outputs = store.run_outputs(scope, run_id)
    except ArtifactStoreError as error:
        raise ExportRunError(ExportRunRejection.STORE_UNAVAILABLE) from error
    if not outputs:
        raise ExportRunError(ExportRunRejection.NO_COMMITTED_OUTPUTS)
    return tuple(_candidate(store, scope, output) for output in outputs)


def _candidate(
    store: LocalArtifactStore,
    scope: ArtifactScope,
    output: RunOutputRecord,
) -> ExportCandidate:
    """Describe one committed output at the exact Version it published."""
    version = store.version(scope, output.artifact_version_id)
    if version is None:
        raise ExportRunError(ExportRunRejection.RUN_NOT_FOUND)
    record = store.artifact(scope, output.artifact_id)
    return ExportCandidate(
        artifact_id=output.artifact_id,
        artifact_version_id=output.artifact_version_id,
        artifact_name=output.name if record is None else record.name,
        output_name=output.name,
        role=output.role,
        sequence=output.sequence,
        version_no=version.version_no,
        pack_path=f"{ARTIFACT_PREFIX}/{output.name}",
        size_bytes=version.size_bytes,
        media_type=version.media_type,
        content_sha256=version.content_sha256,
    )


def _validated_selection(
    candidates: Sequence[ExportCandidate],
    selection: Sequence[UUID],
) -> tuple[ExportCandidate, ...]:
    """Return the candidates one explicit selection names, or refuse.

    Membership is tested against the Run's published Versions rather than
    against the store, which is what makes "no latest" a property of this
    function instead of a promise about how it is called.
    """
    if not selection:
        raise ExportRunError(ExportRunRejection.SELECTION_EMPTY)
    rendered = [str(value) for value in selection]
    if len(set(rendered)) != len(rendered):
        raise ExportRunError(ExportRunRejection.SELECTION_DUPLICATE)
    published = {str(item.artifact_version_id): item for item in candidates}
    chosen: list[ExportCandidate] = []
    for value in rendered:
        candidate = published.get(value)
        if candidate is None:
            raise ExportRunError(ExportRunRejection.SELECTION_NOT_PINNED_TO_RUN)
        chosen.append(candidate)
    return tuple(sorted(chosen, key=lambda item: str(item.artifact_version_id)))


def _attested_inputs(
    store: LocalArtifactStore,
    scope: ArtifactScope,
    run_id: UUID,
) -> tuple[AttestedInputs, tuple[str, ...]]:
    """Attest whichever pinned inputs this installation can actually supply.

    The `ResearchIntent` and scientific-input bytes are read back from the
    store, which recorded them against the producing execution and verifies
    them against the pinned digest on the way out. A corrupt or absent record
    yields `None` rather than a substitute, so the pack degrades to reporting
    that digest as self-reported instead of shipping a document that
    contradicts the provenance beside it.

    The environment facts are not persisted, only their digest, so they are
    attested only when this process still hashes to it. That comparison is
    made here rather than left to the packer, because a mismatch there refuses
    the whole pack. A machine whose dependencies have moved since the run must
    still be able to export; it simply exports a pack that says the
    environment digest is self-reported.
    """
    execution = store.execution_for_run(scope, run_id)
    if execution is None:
        return AttestedInputs(), ()
    intent = store.execution_input(
        scope,
        execution.id,
        ExecutionInputKind.RESEARCH_INTENT,
    )
    source = store.execution_input(
        scope,
        execution.id,
        ExecutionInputKind.SCIENTIFIC_INPUT,
    )
    facts = environment_facts()
    attested_facts = canonical_sha256(facts) == execution.environment_sha256
    paths: list[str] = []
    if intent is not None:
        paths.append(RESEARCH_INTENT_PATH)
    if source is not None:
        paths.append(SCIENTIFIC_INPUT_PATH)
    if attested_facts:
        paths.append(ENVIRONMENT_PATH)
    return (
        AttestedInputs(
            research_intent_json=intent,
            scientific_input_json=source,
            environment_facts=facts if attested_facts else None,
        ),
        tuple(paths),
    )


def produce_pack(
    job: ExportJob,
    run_id: UUID,
    selection: Sequence[UUID],
) -> ProducedPack:
    """Assemble and write one pack from an explicit set of Version identifiers.

    Args:
        job: The store, scope, layout, identity factory, and clock this export
            runs against.
        run_id: The Run whose published evidence the pack pins.
        selection: The exact Artifact Version identifiers the researcher
            chose. Never resolved, never widened, never defaulted.

    Returns:
        The written pack, together with the disclosures and verification notes
        read back out of its own manifest.

    Raises:
        ExportRunError: The Run is absent, published nothing, the selection is
            empty, repeats, or names a Version this Run did not publish, the
            packer refused, or the store was unreadable.
    """
    candidates = export_candidates(job.store, job.scope, run_id)
    chosen = _validated_selection(candidates, selection)
    try:
        attested, attested_paths = _attested_inputs(job.store, job.scope, run_id)
    except ArtifactStoreError as error:
        raise ExportRunError(ExportRunRejection.STORE_UNAVAILABLE) from error
    pack_id = job.ids.new_uuid7()
    request = ExportRequest(
        pack_id=pack_id,
        run_id=run_id,
        selection=tuple(item.artifact_version_id for item in chosen),
        entries=tuple(
            ExportEntry(
                artifact_id=item.artifact_id,
                artifact_version_id=item.artifact_version_id,
                path=item.pack_path,
            )
            for item in chosen
        ),
        created_at=job.clock.now(),
        attested=attested,
    )
    destination = _prepared_destination(job.paths, job.scope, pack_id)
    try:
        pack = export_run(job.store, job.scope, job.paths, request, destination)
    except ExportError as error:
        raise ExportRunError(ExportRunRejection.PACK_REFUSED, error.reason) from error
    except ArtifactStoreError as error:
        raise ExportRunError(ExportRunRejection.STORE_UNAVAILABLE) from error
    return _produced(request, pack, destination, attested_paths)


def _prepared_destination(
    paths: LocalPaths,
    scope: ArtifactScope,
    pack_id: UUID,
) -> Path:
    """Create the owner-only destination directory and return the pack path."""
    destination = pack_file(paths, scope, pack_id)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=EXPORTS_MODE)
    destination.parent.chmod(EXPORTS_MODE)
    return destination


def _produced(
    request: ExportRequest,
    pack: ExportPack,
    destination: Path,
    attested: Sequence[str],
) -> ProducedPack:
    """Describe one written pack by reading its own manifest back.

    `documents` is derived from the manifest's `entries` rather than from this
    module's bookkeeping about what it asked for, so the table a screen renders
    is what the pack contains and not what the producer intended it to.
    """
    manifest = _manifest_document(pack)
    entries = tuple(
        PackEntry(
            kind=_text(item.get("kind")),
            path=_text(item.get("path")),
            sha256=_text(item.get("sha256")),
            size_bytes=_number(item.get("size_bytes")),
        )
        for item in _objects(manifest.get("entries"))
    )
    return ProducedPack(
        pack_id=request.pack_id,
        run_id=request.run_id,
        path=destination,
        created_at=request.created_at,
        size_bytes=destination.stat().st_size,
        manifest_sha256=pack.manifest_sha256,
        selection=request.selection,
        entries=entries,
        documents=pack_documents(
            # Two members no manifest entry names, both by construction:
            # `manifest.json` records nothing about itself, and
            # `checksums.sha256` is the one member no checksum line covers.
            # They are recovered from `pack.members`, which is what was really
            # written, rather than assumed to be there.
            [
                *(
                    item.path
                    for item in pack.members
                    if item.path in {MANIFEST_PATH, CHECKSUMS_PATH}
                ),
                *(item.path for item in entries),
            ]
        ),
        attested=tuple(sorted(attested)),
        disclosures=_mapping(manifest.get("disclosures")),
        verification=_mapping(manifest.get("verification")),
    )


def _manifest_document(pack: ExportPack) -> Mapping[str, object]:
    """Return the pack's own `manifest.json`, parsed from the bytes written."""
    for member in pack.members:
        if member.path == MANIFEST_PATH:
            return _mapping(cast("object", json.loads(member.payload)))
    return {}


def _mapping(value: object) -> Mapping[str, object]:
    """Narrow one decoded JSON value to an object, or to an empty one."""
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in cast("dict[object, object]", value).items()}


def _objects(value: object) -> tuple[Mapping[str, object], ...]:
    """Narrow one decoded JSON value to an array of objects."""
    if not isinstance(value, list):
        return ()
    return tuple(_mapping(item) for item in cast("list[object]", value))


def _text(value: object) -> str:
    """Render one manifest field as text without inventing a value."""
    return value if isinstance(value, str) else ""


def _number(value: object) -> int:
    """Render one manifest field as a count without inventing a value."""
    return value if isinstance(value, int) else 0


def _refuse_unconfined(
    path: Path,
    paths: LocalPaths,
    scope: ArtifactScope,
) -> None:
    """Refuse a pack path that is a link or that leaves this Project's directory.

    Two independent refusals, because a path built from canonical UUID text
    cannot tell you where a link points. The pack file itself must not be a
    link, and once resolved it must still sit directly inside this Project's
    own export directory -- which catches a link substituted for the *directory*
    rather than for the file.

    Stated once and used by both the read and the delete side, so the set of
    packs that can be downloaded and the set that can be removed cannot drift
    into being two different sets.

    Raises:
        ExportRunError: Nothing is there, it is a link, the exports root is a
            link, or the pack resolves outside this Project's own export
            directory.
    """
    # The exports root is checked for being a link before anything is resolved,
    # because the comparison below cannot see one: both of its sides resolve
    # through the same link and would agree with wherever it points. That is
    # the failure mode a resolve-based check has, and it is answered here
    # rather than left to the descriptor chain the delete side happens to also
    # have -- `read_pack` has only this function.
    if exports_root(paths).is_symlink():
        raise ExportRunError(ExportRunRejection.PACK_NOT_FOUND)
    if path.is_symlink() or not os.path.lexists(path):
        raise ExportRunError(ExportRunRejection.PACK_NOT_FOUND)
    # The expected parent is resolved as far as the exports root and no
    # further. Resolving the Project segment too would follow a link that had
    # been put in its place, and then the comparison would agree with whatever
    # that link pointed at -- which is exactly the substitution this check is
    # here to refuse.
    if path.resolve().parent != exports_root(paths).resolve() / str(scope.project_id):
        raise ExportRunError(ExportRunRejection.PACK_NOT_FOUND)


def read_pack(
    paths: LocalPaths,
    scope: ArtifactScope,
    pack_id: UUID,
) -> tuple[Path, int]:
    """Return one produced pack's path and length, refusing anything odd.

    Raises:
        ExportRunError: No such pack, or what is there is not a regular file
            this Project owns.
    """
    path = pack_file(paths, scope, pack_id)
    _refuse_unconfined(path, paths, scope)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ExportRunError(ExportRunRejection.PACK_NOT_FOUND)
    return path, info.st_size


# ------------------------------------------------------------------ lifecycle


def _exports_directory(paths: LocalPaths, scope: ArtifactScope) -> int:
    """Open this Project's export directory, following not one link on the way.

    Returns:
        An open directory descriptor the caller owns and must close.

    Raises:
        FileNotFoundError: Nothing has been exported for this Project yet,
            which is an empty listing rather than a failure.
        OSError: `exports/` or the Project's directory inside it is a link, is
            not a directory, or could not be opened. `O_NOFOLLOW` is what turns
            a substituted directory into this refusal instead of a traversal.
    """
    root = os.open(exports_root(paths), _DIRECTORY_FLAGS)
    try:
        return os.open(str(scope.project_id), _DIRECTORY_FLAGS, dir_fd=root)
    finally:
        os.close(root)


def _pack_identifier(name: str) -> UUID | None:
    """Return the pack one directory entry names, or None when it names none.

    The name has to be exactly the canonical UUID text this module writes plus
    the suffix. Anything else in the directory -- a partial write, a colleague's
    note, a nested directory -- is not a pack and is not listed as one.
    """
    if not name.endswith(PACK_SUFFIX):
        return None
    try:
        identifier = UUID(name[: -len(PACK_SUFFIX)])
    except ValueError:
        return None
    return identifier if f"{identifier}{PACK_SUFFIX}" == name else None


def _identifier(value: object) -> UUID | None:
    """Read one manifest field as an identifier without inventing one."""
    if not isinstance(value, str):
        return None
    try:
        return UUID(value)
    except ValueError:
        return None


def _moment(value: object) -> datetime | None:
    """Read one manifest field as an instant without inventing one."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _selection(value: object) -> tuple[UUID, ...] | None:
    """Read a manifest's pinned selection, or None when it cannot be rendered."""
    if not isinstance(value, list):
        return None
    items = cast("list[object]", value)
    if len(items) > MAX_LISTED_SELECTION:
        return None
    pinned: list[UUID] = []
    for item in items:
        identifier = _identifier(item)
        if identifier is None:
            return None
        pinned.append(identifier)
    return tuple(pinned)


def _manifest_facts(handle: int, name: str) -> _ManifestFacts:
    """Read one stored pack's own statements about itself, or report it unread.

    The file is opened relative to the already-open directory descriptor and
    with `O_NOFOLLOW`, so a link left in a pack's place is refused here exactly
    as it is on the download path rather than followed into somewhere else.
    Only five scalar facts are lifted out; no part of the manifest's
    `action_plan`, `provenance`, `review`, `disclosures`, or `verification`
    objects is forwarded, so nothing a pack carries can reach a listing by
    being copied through wholesale.
    """
    try:
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=handle)
    except OSError:
        return _UNREADABLE_MANIFEST
    try:
        stream = os.fdopen(descriptor, "rb")
    except OSError:
        os.close(descriptor)
        return _UNREADABLE_MANIFEST
    try:
        with stream, zipfile.ZipFile(stream) as archive:
            if archive.getinfo(MANIFEST_PATH).file_size > MAX_MANIFEST_BYTES:
                return _UNREADABLE_MANIFEST
            document = _mapping(cast("object", json.loads(archive.read(MANIFEST_PATH))))
    except _MANIFEST_FAILURES:
        return _UNREADABLE_MANIFEST
    declared = _mapping(document.get("selection"))
    selection = _selection(declared.get("artifact_version_ids"))
    if selection is None:
        return _UNREADABLE_MANIFEST
    provenance = _mapping(document.get("provenance"))
    return _ManifestFacts(
        readable=True,
        run_id=_identifier(_mapping(provenance.get("run")).get("id")),
        created_at=_moment(document.get("created_at")),
        selection=selection,
        entry_count=len(_objects(document.get("entries"))),
    )


def _stored_pack(
    handle: int,
    name: str,
    pack_id: UUID,
    info: os.stat_result,
) -> StoredPack:
    """Describe one pack from the filesystem first and the manifest second."""
    facts = _manifest_facts(handle, name)
    return StoredPack(
        pack_id=pack_id,
        # Both from `stat`. A manifest describes the members a pack holds, and
        # the sum of member sizes is not the size of the file on disk.
        size_bytes=info.st_size,
        modified_at=datetime.fromtimestamp(info.st_mtime, tz=UTC),
        manifest_readable=facts.readable,
        run_id=facts.run_id,
        created_at=facts.created_at,
        selection=facts.selection,
        entry_count=facts.entry_count,
    )


def list_packs(paths: LocalPaths, scope: ArtifactScope) -> StoredPacks:
    """List the packs one Project really has on disk, newest written first.

    Nothing is remembered between exports, so this is a directory read and not
    a query: the answer is whatever is there now, which is the only answer that
    can be true after a researcher deletes a file by hand.

    Args:
        paths: The resolved local layout.
        scope: The Project whose export directory is read.

    Returns:
        Every pack found, the bytes they occupy, and how many entries this
        listing could not fully describe.

    Raises:
        ExportRunError: The export directory exists but is a link, is not a
            directory, or could not be read.
    """
    try:
        handle = _exports_directory(paths, scope)
    except FileNotFoundError:
        # Nothing has been exported for this Project. An empty listing is the
        # honest answer; a refusal would read as "something is wrong".
        return StoredPacks(packs=(), total_size_bytes=0, undescribed_count=0)
    except OSError as error:
        raise ExportRunError(ExportRunRejection.EXPORTS_UNREADABLE) from error
    try:
        found, undescribed = _scan_packs(handle)
    except OSError as error:
        raise ExportRunError(ExportRunRejection.EXPORTS_UNREADABLE) from error
    finally:
        os.close(handle)
    return StoredPacks(
        packs=tuple(sorted(found, key=_written_last, reverse=True)),
        total_size_bytes=sum(item.size_bytes for item in found),
        undescribed_count=undescribed,
    )


def _written_last(pack: StoredPack) -> tuple[datetime, str]:
    """Order packs by when they were written, breaking a tie on identity."""
    return pack.modified_at, str(pack.pack_id)


def _scan_packs(handle: int) -> tuple[list[StoredPack], int]:
    """Read one open export directory into described packs and a shortfall."""
    found: list[StoredPack] = []
    undescribed = 0
    with os.scandir(handle) as entries:
        for entry in entries:
            identifier = _pack_identifier(entry.name)
            if identifier is None:
                continue
            info = entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                # A link or a directory wearing a pack's name. It is not listed
                # -- there is no file here whose bytes could be freed -- but it
                # is counted, so the total is never presented as exhaustive
                # when something in the directory went unaccounted for.
                undescribed += 1
                continue
            described = _stored_pack(handle, entry.name, identifier, info)
            if not described.manifest_readable:
                undescribed += 1
            found.append(described)
    return found, undescribed


def delete_pack(paths: LocalPaths, scope: ArtifactScope, pack_id: UUID) -> DeletedPack:
    """Remove exactly one named pack from this Project's export directory.

    The only destructive primitive this module has, and it chooses nothing: it
    removes the pack whose identifier the caller states and no other. There is
    no age, no count, and no budget that can make this function remove a second
    file, which is what keeps a researcher from losing a pack they were never
    shown.

    Confinement is by descriptor rather than by string. The exports root and
    the Project directory are each opened with `O_NOFOLLOW | O_DIRECTORY`, so a
    substituted directory link fails to open instead of redirecting the unlink;
    the entry is `lstat`ed through that descriptor, so a link in a pack's place
    is refused rather than followed; and the unlink is issued relative to the
    same descriptor, so the directory cannot be swapped between the check and
    the removal.

    Args:
        paths: The resolved local layout.
        scope: The Project that owns the pack.
        pack_id: The exact pack to remove.

    Returns:
        The identifier removed and the bytes that removal returned.

    Raises:
        ExportRunError: No such pack, what is there is not a regular file, or
            the path escapes this Project's own export directory.
    """
    name = f"{pack_id}{PACK_SUFFIX}"
    _refuse_unconfined(pack_file(paths, scope, pack_id), paths, scope)
    try:
        handle = _exports_directory(paths, scope)
    except OSError as error:
        raise ExportRunError(ExportRunRejection.PACK_NOT_FOUND) from error
    try:
        freed = _unlink_pack(handle, name)
    finally:
        os.close(handle)
    return DeletedPack(pack_id=pack_id, freed_bytes=freed)


def _unlink_pack(handle: int, name: str) -> int:
    """Remove one entry of an already-open directory and report its size.

    `lstat` rather than `stat`: a link named like a pack must be refused, not
    resolved and then followed to whatever it points at.

    Raises:
        ExportRunError: The entry is absent, is not a regular file, or could
            not be removed.
    """
    try:
        info = os.lstat(name, dir_fd=handle)
    except OSError as error:
        raise ExportRunError(ExportRunRejection.PACK_NOT_FOUND) from error
    if not stat.S_ISREG(info.st_mode):
        raise ExportRunError(ExportRunRejection.PACK_NOT_FOUND)
    try:
        os.unlink(name, dir_fd=handle)
    except OSError as error:
        raise ExportRunError(ExportRunRejection.PACK_NOT_FOUND) from error
    return info.st_size


def stream_pack(path: Path) -> Generator[bytes, None, None]:
    """Yield one pack's bytes in bounded chunks.

    A generator rather than a `bytes`, so neither this process nor the ASGI
    server ever holds a whole pack: `apiserver._Wire` writes each chunk to the
    socket and drains before the next one is read. The file is opened when
    iteration starts, which is after the guard has already accepted the
    request.

    Declared as a `Generator` rather than an `Iterator` because the caller is
    expected to `close()` it. A download the researcher cancels abandons this
    loop part way through, and the `with` below is what releases the descriptor
    when it does.
    """
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(PACK_READ_CHUNK)
            if not chunk:
                return
            yield chunk


# --------------------------------------------------------------- capabilities


class TicketOutcome(StrEnum):
    """What one presented download capability turned out to be."""

    ACCEPTED = "accepted"
    UNKNOWN = "unknown"
    EXPIRED = "expired"
    SPENT = "spent"
    PATH_MISMATCH = "path_mismatch"


@dataclass(frozen=True, slots=True)
class DownloadGrant:
    """One minted capability URL and the moment it stops working."""

    url: str
    expires_at: datetime
    expires_in_seconds: int


@dataclass(frozen=True, slots=True)
class DownloadTicket:
    """One accepted capability, resolved to the pack it opens."""

    project_id: UUID
    pack_id: UUID
    path: str


@dataclass(slots=True)
class _Record:
    """One remembered ticket. `spent` is why a replay is not merely unknown."""

    project_id: UUID
    pack_id: UUID
    path: str
    expires_at: datetime
    spent: bool = False


@final
class DownloadTickets:
    """Mint, remember, and spend one-use download capabilities.

    Every entry is remembered by the SHA-256 of its secret, never by the
    secret. Expired entries are dropped, and `MAX_OPEN_TICKETS` bounds the
    table so a caller that mints without downloading cannot grow it: the oldest
    entry goes first, which costs that caller its own stale URL rather than
    anyone else's live one.
    """

    __slots__ = ("_clock", "_prefix", "_records", "_ttl")

    def __init__(
        self,
        clock: Clock,
        prefix: str,
        ttl_seconds: int = TICKET_TTL_SECONDS,
    ) -> None:
        """Bind the registry to one clock, one URL prefix, and one lifetime."""
        self._clock = clock
        self._prefix = prefix
        self._ttl = ttl_seconds
        self._records: dict[str, _Record] = {}

    def mint(self, project_id: UUID, pack_id: UUID) -> DownloadGrant:
        """Return one fresh capability URL for exactly one pack.

        The secret is generated here and returned in no other form: the URL is
        the only place it exists, and nothing retains it, because the table is
        keyed by its digest.
        """
        now = self._clock.now()
        self._prune(now)
        secret = secrets.token_urlsafe(TICKET_ENTROPY_BYTES)
        url = self._prefix + DOWNLOAD_ROUTE.format(
            project_id=project_id,
            pack_id=pack_id,
            ticket=secret,
        )
        expires_at = now + timedelta(seconds=self._ttl)
        self._records[_digest(secret)] = _Record(
            project_id=project_id,
            pack_id=pack_id,
            path=url,
            expires_at=expires_at,
        )
        return DownloadGrant(
            url=url,
            expires_at=expires_at,
            expires_in_seconds=self._ttl,
        )

    def holds(self, path: str) -> bool:
        """Report whether one request path carries a capability this issued.

        Deliberately side-effect free, and deliberately separate from
        :meth:`present`. A guard has to decide whether a *capability was
        presented at all* before it decides whether the capability is good,
        because those two questions have different answers for an ordinary API
        path and because asking the second one spends the ticket.
        """
        return _digest(path.rsplit("/", maxsplit=1)[-1]) in self._records

    def present(self, path: str) -> tuple[TicketOutcome, DownloadTicket | None]:
        """Judge one request path, spending the capability it carries.

        `UNKNOWN` means the last segment is not a capability this registry ever
        issued, which is what every ordinary API path is. A guard must read it
        as "no download credential was presented" and go on to require the
        session credential, never as a refusal in its own right.
        """
        key = _digest(path.rsplit("/", maxsplit=1)[-1])
        record = self._records.get(key)
        if record is None:
            return TicketOutcome.UNKNOWN, None
        if record.path != path:
            return TicketOutcome.PATH_MISMATCH, None
        if self._clock.now() >= record.expires_at:
            del self._records[key]
            return TicketOutcome.EXPIRED, None
        if record.spent:
            return TicketOutcome.SPENT, None
        record.spent = True
        return TicketOutcome.ACCEPTED, DownloadTicket(
            project_id=record.project_id,
            pack_id=record.pack_id,
            path=record.path,
        )

    def _prune(self, now: datetime) -> None:
        """Forget everything already expired, then everything over the bound."""
        for key in [
            key for key, record in self._records.items() if now >= record.expires_at
        ]:
            del self._records[key]
        while len(self._records) >= MAX_OPEN_TICKETS:
            del self._records[next(iter(self._records))]


def _digest(value: str) -> str:
    """Return the lookup key one presented secret has."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
