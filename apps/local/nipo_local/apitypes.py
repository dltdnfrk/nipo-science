"""Wire contracts and name discipline for the local loopback HTTP surface.

Everything the browser front end can observe is declared here, so a reviewer
can answer "can a provider key reach a response?" by reading one file. The
answer is no by construction: no model in this module has a field capable of
carrying key material, and the provider models carry a
:class:`~nipo_local.providers.ProviderStatus` rather than a value.

Names are validated rather than sanitized. A Project name or Session title
that a caller submits is rejected when it could later be interpreted as a
path -- a separator, a relative segment, an absolute or drive-qualified
prefix, a reserved device name, a trailing dot -- or when it is not already
NFC-normalized, is boundary-padded, or carries an invisible code point. That
matches the Export path discipline in SPEC-v0.5 section 9 and LS07, applied at
the boundary where the name first enters the system rather than at the point
where it would first be used as a file name.

Rejection reasons are closed enum values, never the offending input. A caller
learns *why* its name was refused without the local surface echoing bytes it
declined to store.
"""

import re
import unicodedata
from datetime import datetime
from enum import StrEnum
from typing import Annotated, ClassVar, Final, final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .exportpack import ExportRejection
from .exportrun import ExportRunRejection

MAX_NAME_CHARACTERS: Final = 255
"""Longest storable Project name or Session title, matching the store."""

MAX_SUBMITTED_NAME_CHARACTERS: Final = 4096
"""Longest name a request body may carry.

Deliberately wider than what is storable. If the request model rejected at
exactly the storable limit, :data:`NameRejection.TOO_LONG` would be an
unreachable branch and the caller would get an untyped `invalid_request`
instead of being told which rule it broke.
"""

MAX_DOWNLOAD_NAME_CHARACTERS: Final = 100
"""Longest `Content-Disposition` file name this surface will emit."""

MAX_ENABLED_MODELS: Final = 256
"""Upper bound on the composer picker, so one request cannot grow unbounded."""

MAX_API_KEY_CHARACTERS: Final = 512
"""Upper bound on a submitted key; the registry owns every other key rule."""

MAX_EXPORT_SELECTION: Final = 1024
"""Upper bound on one Export selection, so a request cannot grow unbounded.

Wider than any Run this product can produce. The membership check in
:mod:`nipo_local.exportrun` is what actually decides an Export selection; this
only stops a body from being arbitrarily large before that check runs.
"""

# `Cn` (unassigned) is included deliberately: an unassigned code point today is
# an assigned one after a Unicode release, which would silently change how a
# stored name normalizes.
INVISIBLE_CATEGORIES: Final = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})

PATH_SEPARATORS: Final = frozenset({"/", "\\"})

RELATIVE_SEGMENTS: Final = frozenset({".", ".."})

RESERVED_DEVICE_NAMES: Final = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{digit}" for digit in range(10)}
    | {f"lpt{digit}" for digit in range(10)}
)
"""Windows reserved device names, refused so an Export Pack stays portable."""

DRIVE_QUALIFIED: Final = re.compile(r"^[A-Za-z]:")

UNSAFE_DOWNLOAD_CHARACTERS: Final = re.compile(r"[^A-Za-z0-9._-]+")

_RFC9110_WORD: Final = r"[A-Za-z0-9!#$%&'*+.^_`|~-]+"
SAFE_MEDIA_TYPE: Final = re.compile(rf"^{_RFC9110_WORD}/{_RFC9110_WORD}$")
"""RFC 9110 token/token. Anything else is served as opaque bytes."""

FALLBACK_MEDIA_TYPE: Final = "application/octet-stream"


class ApiErrorCode(StrEnum):
    """Stable machine-readable rejection codes for the local surface.

    Every value is a closed constant. None of them is derived from caller
    input, so an error body can never reflect a submitted key, name, or path.
    """

    LOCAL_TOKEN_REQUIRED = "local_token_required"  # noqa: S105 - a code, not a secret
    LOCAL_TOKEN_INVALID = "local_token_invalid"  # noqa: S105 - a code, not a secret
    CROSS_ORIGIN_DENIED = "cross_origin_denied"
    HOST_NOT_ALLOWED = "host_not_allowed"
    PREFLIGHT_DENIED = "preflight_denied"
    PROTOCOL_NOT_SUPPORTED = "protocol_not_supported"
    NOT_FOUND = "not_found"
    INVALID_REQUEST = "invalid_request"
    INVALID_NAME = "invalid_name"
    NAME_IN_USE = "name_in_use"
    PROJECT_ARCHIVED = "project_archived"
    SESSION_ARCHIVED = "session_archived"
    UNKNOWN_PROVIDER = "unknown_provider"
    KEY_NOT_REQUIRED = "key_not_required"
    KEY_REJECTED = "key_rejected"
    MODEL_ID_MALFORMED = "model_id_malformed"
    MODEL_NOT_ENABLED = "model_not_enabled"
    CREDENTIAL_BACKEND_UNAVAILABLE = "credential_backend_unavailable"
    LOCAL_STATE_UNREADABLE = "local_state_unreadable"
    STORE_UNAVAILABLE = "store_unavailable"
    CONTENT_CORRUPT = "content_corrupt"
    RUN_SURFACE_UNAVAILABLE = "run_surface_unavailable"
    REVIEW_NOT_FOUND = "review_not_found"
    REVIEW_EVIDENCE_MISSING = "review_evidence_missing"
    EXPORT_EVIDENCE_MISSING = "export_evidence_missing"
    EXPORT_SELECTION_REJECTED = "export_selection_rejected"
    EXPORT_REFUSED = "export_refused"
    EXPORT_PACK_NOT_FOUND = "export_pack_not_found"
    DOWNLOAD_TICKET_INVALID = "download_ticket_invalid"
    DOWNLOAD_TICKET_EXPIRED = "download_ticket_expired"
    DOWNLOAD_TICKET_SPENT = "download_ticket_spent"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    INTERNAL_ERROR = "internal_error"


class KeyRejection(StrEnum):
    """Why a submitted provider key was refused, never quoting the key."""

    EMPTY = "empty"
    SURROUNDING_WHITESPACE = "surrounding_whitespace"
    INVISIBLE_CHARACTER = "invisible_character"
    TOO_LONG = "too_long"


class NameRejection(StrEnum):
    """Why a submitted name was refused, never quoting the name."""

    EMPTY = "empty"
    TOO_LONG = "too_long"
    NOT_NFC = "not_nfc"
    BOUNDARY_WHITESPACE = "boundary_whitespace"
    INVISIBLE_CHARACTER = "invisible_character"
    PATH_SEPARATOR = "path_separator"
    RELATIVE_SEGMENT = "relative_segment"
    TRAILING_DOT = "trailing_dot"
    RESERVED_DEVICE_NAME = "reserved_device_name"
    ABSOLUTE_PATH = "absolute_path"
    DRIVE_QUALIFIED = "drive_qualified"


@final
class LocalNameError(ValueError):
    """Reject one name, carrying a closed reason instead of the input."""

    reason: NameRejection

    def __init__(self, reason: NameRejection) -> None:
        """Record the closed rejection reason without the offending value."""
        super().__init__(str(reason))
        self.reason = reason


def normalized_name_key(value: str) -> str:
    """Return the collision key two names share when they are the same name.

    NFKC folding plus case folding is the same comparison SPEC-v0.5 section 9
    requires of Export entries, so a name accepted here can never collide with
    a sibling once it reaches a pack.
    """
    return unicodedata.normalize("NFKC", value).casefold()


def _reject_shape(value: str) -> NameRejection | None:
    """Return the structural rejection for one candidate name, if any."""
    if not value:
        return NameRejection.EMPTY
    if len(value) > MAX_NAME_CHARACTERS:
        return NameRejection.TOO_LONG
    if unicodedata.normalize("NFC", value) != value:
        return NameRejection.NOT_NFC
    if value != value.strip():
        return NameRejection.BOUNDARY_WHITESPACE
    return None


def _reject_path_shape(value: str) -> NameRejection | None:
    """Return the separator or relative-segment rejection, if any."""
    if any(character in PATH_SEPARATORS for character in value):
        return NameRejection.PATH_SEPARATOR
    if value in RELATIVE_SEGMENTS:
        return NameRejection.RELATIVE_SEGMENT
    if value.endswith("."):
        return NameRejection.TRAILING_DOT
    return None


def _reject_rooted_shape(value: str) -> NameRejection | None:
    """Return the rooted-path or reserved-device rejection, if any."""
    if value.startswith("~"):
        return NameRejection.ABSOLUTE_PATH
    if DRIVE_QUALIFIED.match(value) is not None:
        return NameRejection.DRIVE_QUALIFIED
    if value.split(".", 1)[0].casefold() in RESERVED_DEVICE_NAMES:
        return NameRejection.RESERVED_DEVICE_NAME
    return None


def validate_local_name(value: str) -> str:
    """Return one accepted Project name or Session title, or raise.

    Args:
        value: The exact characters the caller submitted.

    Returns:
        The same string, unchanged. This function never rewrites its input:
        a name that would have to be normalized to be storable is refused so
        what the researcher typed is what the researcher gets back.

    Raises:
        LocalNameError: The name is empty, over-long, not NFC-normalized,
            boundary-padded, carries an invisible code point, or could be
            read as a path.
    """
    shape = _reject_shape(value)
    if shape is not None:
        raise LocalNameError(shape)
    for character in value:
        if unicodedata.category(character) in INVISIBLE_CATEGORIES:
            raise LocalNameError(NameRejection.INVISIBLE_CHARACTER)
    path_shape = _reject_path_shape(value) or _reject_rooted_shape(value)
    if path_shape is not None:
        raise LocalNameError(path_shape)
    return value


def safe_download_name(name: str, fallback: str) -> str:
    """Return a `Content-Disposition` file name that is only ever a leaf.

    Args:
        name: The Artifact name, which a producer chose.
        fallback: An opaque identifier used when nothing safe survives.

    Returns:
        A dot-free-prefixed leaf name drawn from `[A-Za-z0-9._-]` only, so no
        header value can carry a separator, a control character, or a CR/LF
        sequence into the response.
    """
    reduced = UNSAFE_DOWNLOAD_CHARACTERS.sub("_", name).lstrip(".")
    trimmed = reduced[:MAX_DOWNLOAD_NAME_CHARACTERS].strip("._")
    return trimmed or fallback


def safe_media_type(media_type: str) -> str:
    """Return a media type safe to place in a response header.

    A stored media type was chosen by a producer, so it is caller data at the
    response boundary. Anything that is not a bare `type/subtype` token pair
    becomes opaque bytes rather than reaching a header verbatim.
    """
    return media_type if SAFE_MEDIA_TYPE.match(media_type) else FALLBACK_MEDIA_TYPE


class LocalModel(BaseModel):
    """Base wire model: frozen, closed, and strict about types."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )


class ErrorBody(LocalModel):
    """The only error shape this surface emits.

    `reason` widens to the Export refusals so that a declined pack can say
    *which* rule declined it -- `credential_material`, `path_reserved_root`,
    `selection_not_pinned_to_run`. Every member of the union is a closed enum
    whose values are literals in this repository; none of them is derived from
    a submitted name, key, path, or identifier, which is the property that lets
    this field exist at all.
    """

    error: ApiErrorCode
    reason: (
        NameRejection | KeyRejection | ExportRunRejection | ExportRejection | None
    ) = None


class HealthBody(LocalModel):
    """Liveness plus the fixed local identity the front end renders against."""

    status: str
    org_id: UUID
    requester_id: UUID
    run_surface: bool


class ProviderCard(LocalModel):
    """One Settings > Models card.

    There is no field here that can hold key material. `status` is resolved
    live by the registry and `env_var` names the variable consulted when no
    credential is stored -- the name, never the value.
    """

    provider_id: str
    display_name: str
    status: str
    requires_key: bool
    env_var: str | None
    is_ready: bool


class ProviderList(LocalModel):
    """Every provider card in Settings card order."""

    providers: tuple[ProviderCard, ...]


class SetKeyRequest(LocalModel):
    """One submitted provider key.

    This model exists only as an input. It is never returned, never logged,
    and never embedded in an error body.
    """

    key: str = Field(min_length=1, max_length=MAX_API_KEY_CHARACTERS)


class ComposerModelEntry(LocalModel):
    """One entry of the composer model picker."""

    model_id: str
    provider_id: str
    display_name: str
    is_default: bool


class ComposerPicker(LocalModel):
    """The persisted composer picker state."""

    enabled_models: tuple[str, ...]
    default_model: str | None
    models: tuple[ComposerModelEntry, ...]


class ComposerUpdate(LocalModel):
    """A replacement composer picker.

    `enabled_models` is a list rather than a tuple because this model is
    validated from decoded JSON in strict mode, where a JSON array is a
    `list` and nothing else.

    `default_model` must be present in `enabled_models`; the registry enforces
    that and this surface reports the refusal rather than silently dropping it.
    """

    enabled_models: list[str] = Field(max_length=MAX_ENABLED_MODELS)
    default_model: str | None = None


class CreateProjectRequest(LocalModel):
    """A new Project identity request. The server mints the identifier."""

    name: str = Field(min_length=1, max_length=MAX_SUBMITTED_NAME_CHARACTERS)


class ProjectBody(LocalModel):
    """One registered local Project."""

    id: UUID
    name: str
    created_at: datetime
    archived: bool


class ProjectList(LocalModel):
    """Registered Projects, newest first."""

    projects: tuple[ProjectBody, ...]


class CreateSessionRequest(LocalModel):
    """A new Session request. The server mints the identifier and timestamps."""

    title: str = Field(min_length=1, max_length=MAX_SUBMITTED_NAME_CHARACTERS)


class SessionBody(LocalModel):
    """One local Session bound to exactly one Project."""

    id: UUID
    project_id: UUID
    title: str
    created_at: datetime
    last_active_at: datetime
    archived: bool


class SessionList(LocalModel):
    """One Project's Sessions, most recently active first."""

    sessions: tuple[SessionBody, ...]


class VersionBody(LocalModel):
    """One immutable Artifact Version as the front end renders it.

    `object_key` is deliberately absent. It is a server-derived storage
    address, so exposing it would publish an internal layout that the
    producer is explicitly forbidden from choosing.
    """

    id: UUID
    artifact_id: UUID
    version_no: int
    media_type: str
    size_bytes: int
    content_sha256: str
    created_at: datetime
    immutable: bool = True


class VersionList(LocalModel):
    """One Artifact's Version history in commit order."""

    artifact_id: UUID
    versions: tuple[VersionBody, ...]


class ArtifactSummary(LocalModel):
    """One Artifact identity plus its head Version position."""

    id: UUID
    name: str
    created_at: datetime
    version_count: int
    head_version_no: int


class ArtifactList(LocalModel):
    """One Project's Artifacts, newest first."""

    artifacts: tuple[ArtifactSummary, ...]


class ArtifactDetail(LocalModel):
    """One Artifact identity together with its full Version history."""

    id: UUID
    name: str
    created_at: datetime
    versions: tuple[VersionBody, ...]


class ReviewFindingBody(LocalModel):
    """One immutable finding of one review rule.

    `verdict` carries `inconclusive` as an ordinary value beside `pass`,
    `warn`, and `fail`. It is not an error channel: a surface that rendered it
    as a failure would push a researcher to treat unreachable evidence as a
    defect in the Reviewer rather than as the limit of what was checked.
    """

    sequence: int
    rule_id: str
    verdict: str
    status: str
    code: str
    message: str
    artifact_version_ids: tuple[UUID, ...]
    execution_ids: tuple[UUID, ...]
    created_at: datetime


class ReviewCoverageBody(LocalModel):
    """What one review rule checked, and what it structurally could not.

    `limits` travels with every Review response rather than living only in
    documentation, because the screen that shows a verdict is the one place a
    reader decides how much that verdict covers. There is no field here for a
    bare "verified" claim, and none of these values is derived from a run: they
    describe the rule, not the outcome.
    """

    rule_id: str
    statement: str
    checks: tuple[str, ...]
    limits: tuple[str, ...]


class ReviewBody(LocalModel):
    """One persisted, trace-only Review over an exact pinned evidence set.

    `verdict` is the highest-precedence verdict across the findings, computed
    by the Reviewer's own precedence so a Review that could not check
    something never summarizes as `pass`. It is `inconclusive` while no
    finding has been submitted, which is the honest reading of a Review that
    has not yet said anything.
    """

    id: UUID
    source_run_id: UUID
    state: str
    verdict: str
    pinned_input_sha256: str
    pinned_artifact_version_ids: tuple[UUID, ...]
    pinned_execution_ids: tuple[UUID, ...]
    created_at: datetime
    updated_at: datetime
    findings_submitted_at: datetime | None
    error_type: str | None
    error_code: str | None
    findings: tuple[ReviewFindingBody, ...]
    coverage: tuple[ReviewCoverageBody, ...]


class ProvenanceBody(LocalModel):
    """The pinned provenance record for exactly one Version.

    Every digest here is recomputable by a third party from the exported
    bytes, which is what SPEC-v0.5 section 6 means by independently
    verifiable. `execution_isolation` is `None` rather than a default string:
    the Version row does not carry it, and section 5 forbids presenting an
    isolation level that was not actually recorded. It is populated only when
    a run surface is bound and can answer for the producing execution.
    """

    version_id: UUID
    artifact_id: UUID
    version_no: int
    content_sha256: str
    size_bytes: int
    media_type: str
    producing_execution_id: UUID
    environment_sha256: str
    code_sha256: str
    runtime_adapter_id: str
    runtime_connection_id: UUID
    skill_content_hashes: tuple[str, ...]
    source_hashes: tuple[str, ...]
    input_version_ids: tuple[UUID, ...]
    created_at: datetime
    execution_isolation: str | None = None


class ExportCandidateBody(LocalModel):
    """One Artifact Version a Run published, offered for explicit selection.

    `artifact_version_id` is the identifier the Run recorded when it
    published. There is no field here naming an Artifact's head Version, and no
    field a caller could set to mean "the latest": SPEC-v0.5 section 9 requires
    Export to pin explicit Version identifiers, so the only identity this
    surface offers is the pinned one.
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


class PackDocumentBody(LocalModel):
    """One reserved pack root and whether the produced pack really holds it."""

    path: str
    included: bool


class ExportPlanBody(LocalModel):
    """What one Run offers for export, before anything is produced.

    `execution_isolation` is `str | None` for the same reason
    :class:`ProvenanceBody` makes it optional: an execution this installation
    cannot answer for reports `null`, never a defaulted `"in_process"`.

    The two document lists are separate because a plan can name a conditional
    document but must not promise it. Whether the run mirror is on disk, and
    whether an attested digest still matches what the execution pinned, is
    decided while the pack is being assembled -- so a plan that listed them as
    included would be predicting rather than reporting.
    """

    run_id: UUID
    project_id: UUID
    execution_isolation: str | None
    candidates: tuple[ExportCandidateBody, ...]
    always_included_documents: tuple[str, ...]
    conditional_documents: tuple[str, ...]
    selection_resolution: str


SubmittedUuid = Annotated[UUID, Field(strict=False)]
"""A UUID a JSON body may state as text.

This model set is strict everywhere else, and strict mode admits no `str` where
a `UUID` is declared -- FastAPI validates an already-decoded body, so an
identifier arriving as JSON text would be refused as malformed rather than
parsed. Relaxing the identifier itself keeps the field's declared type a `UUID`
instead of widening it to `str` and parsing by hand: a value that is not a UUID
is still refused, and every spelling a UUID has canonicalizes to the one form
the membership check compares.
"""


class CreateExportRequest(LocalModel):
    """One explicit Export selection.

    A list of Artifact Version identifiers and nothing else. There is no
    `artifact_ids` field, no `all` flag, and no default: a body that omits this
    field is refused as malformed rather than widened to every output, which is
    the "latest at pack time" race SPEC-v0.5 section 9 exists to prevent.

    `list` rather than `tuple` because this model is validated from decoded
    JSON in strict mode, where a JSON array is a `list` and nothing else.
    """

    artifact_version_ids: list[SubmittedUuid] = Field(max_length=MAX_EXPORT_SELECTION)


class PackEntryBody(LocalModel):
    """One member of a produced pack, as the pack's own manifest describes it."""

    kind: str
    path: str
    sha256: str
    size_bytes: int


class ExportPackBody(LocalModel):
    """One produced pack, quoting the statements the pack makes about itself.

    `disclosures` and `verification` are the manifest's own objects, read back
    out of the written bytes. They are `dict` rather than a typed model on
    purpose: the pack owns that vocabulary, and a model here would silently
    drop a disclosure the packer added -- which is the one direction of drift
    this field must not have.

    `manifest_sha256` is reported even though `manifest.json` records no digest
    of itself; the pack states it once, in `checksums.sha256`, and this is the
    same value.
    """

    pack_id: UUID
    run_id: UUID
    project_id: UUID
    created_at: datetime
    size_bytes: int
    manifest_sha256: str
    selection: tuple[UUID, ...]
    entries: tuple[PackEntryBody, ...]
    pack_documents: tuple[PackDocumentBody, ...]
    attested_documents: tuple[str, ...]
    disclosures: dict[str, object]
    verification: dict[str, object]


class StoredPackBody(LocalModel):
    """One pack that is really on disk, as the lifecycle screen renders it.

    Every field is either a filesystem fact or a quotation from the pack's own
    `manifest.json`, and the two are not mixed: `size_bytes` and `modified_at`
    come from `stat`, and `run_id`, `created_at`, `selection`, and
    `entry_count` come from the manifest. A pack whose manifest could not be
    decoded reports `manifest_readable` false and leaves the manifest fields
    null and empty rather than substituting a plausible value.

    There is deliberately no path field. A listing that named where a pack sits
    would publish a filesystem layout the researcher never chose, and a bug in
    that field would be a disclosure rather than a cosmetic error. The
    identifier is the only address any route here accepts.
    """

    pack_id: UUID
    size_bytes: int
    modified_at: datetime
    manifest_readable: bool
    run_id: UUID | None = None
    created_at: datetime | None = None
    selection: tuple[UUID, ...] = ()
    entry_count: int = 0


class ExportPackListBody(LocalModel):
    """Every pack one Project holds, and what holding them costs.

    `total_size_bytes` is the sum of real file sizes, never of what a manifest
    says a pack contains. `budget_bytes` and `over_budget` exist so the screen
    can show a cost the researcher currently cannot see; neither removes
    anything, and no field here is a schedule, a horizon, or an expiry, because
    this surface never deletes a pack on its own.

    `undescribed_count` reports how many entries the listing could not fully
    describe, so a total is never presented as exhaustive when it is not.
    """

    project_id: UUID
    packs: tuple[StoredPackBody, ...]
    pack_count: int
    total_size_bytes: int
    budget_bytes: int
    over_budget: bool
    undescribed_count: int


class DeletedPackBody(LocalModel):
    """The receipt for one removed pack.

    `freed_bytes` is what the file really was at the moment it was unlinked,
    and the two remaining totals are re-read from the directory afterwards
    rather than computed by subtraction, so the receipt states the disk's
    answer instead of this process's arithmetic about it.
    """

    pack_id: UUID
    project_id: UUID
    freed_bytes: int
    pack_count: int
    total_size_bytes: int
    over_budget: bool


class DownloadGrantBody(LocalModel):
    """One single-use, short-lived, pack-scoped download URL.

    This is not the session credential and cannot be used as one: it opens
    exactly the pack it was minted for and answers nothing else. `single_use`
    is a literal `True` rather than a setting, because a reusable download URL
    is a different object with different consequences and this surface does not
    have one to offer.
    """

    url: str
    expires_at: datetime
    expires_in_seconds: int
    single_use: bool = True
