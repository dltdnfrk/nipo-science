"""Loopback HTTP surface over the local Nipo Science core.

This is the "local interface" SPEC-v0.5 section 10 permits and section 2
constrains. It is a browser-facing API on a single-user machine, which is a
narrow but genuinely hostile position: any web page the researcher happens to
visit can issue requests to `http://127.0.0.1:<port>` from their browser, with
their network position and, for a rebound host name, their same-origin
privileges. Four independent controls answer that, and each one is asserted
against a real socket in `apps/local/tests/test_api.py`:

1. **Loopback only.** :mod:`nipo_local.apiserver` binds only an address
   :mod:`ipaddress` calls loopback and re-verifies `getsockname()` afterwards.
2. **A per-run session credential.** Every request must carry the exact token
   in the `X-Nipo-Token` request header. The token is minted per run, written
   to `<root>/api-token.json` at mode `0600` before the listener starts, and
   never appears in a response, an error body, or a log -- there is no log.
   Because it is a *custom header*, a cross-origin `fetch` cannot send it
   without a preflight, and this surface refuses every preflight.
3. **Same-origin discipline.** A present `Origin` must be one of this
   listener's own origins, and a state-changing request must not declare a
   cross-site `Sec-Fetch-Site`.
4. **A pinned `Host` authority.** DNS rebinding is the attack that defeats
   `Origin` checks on a loopback server, because the attacker's page becomes
   same-origin with it. The `Host` header is therefore pinned to this
   listener's own authorities.

The guard is the outermost ASGI layer and :func:`create_app` returns nothing
else, so no route can be added that forgets it.

The front end is served from this same origin (see :mod:`nipo_local.webui`),
which is what makes control 2 usable at all: a browser can attach a custom
header only to a request from the listener's own origin. The document and its
two assets are the one surface that cannot itself carry that header, so on
exactly those paths -- a closed set of literal paths taken from the static
surface's own enumeration -- the guard substitutes a stricter check rather
than dropping one: `Sec-Fetch-Site` is enforced for *every* method, not only
the state-changing ones. Controls 1, 3, and 4 apply unchanged everywhere.

Provider endpoints report presence, never value: no model in
:mod:`nipo_local.apitypes` has a field able to carry key material, the
credential registry is only ever asked for `status`, and the framework's
validation-error handler is replaced precisely because the default one echoes
the rejected input -- which for `PUT /providers/{id}/key` would be the key.

Runs remain a seam so the durable Run implementation stays swappable; see
:class:`RunSurface` and :class:`~nipo_local.runsurface.StoreRunSurface`, which
binds it to the real `runs` and `executions` tables. `execution_isolation`
stays `str | None` on the wire either way: an execution this installation
cannot answer for reports `null`, never a defaulted `"in_process"`, because
SPEC-v0.5 section 5 forbids presenting an isolation level that was not
recorded.

Review is an independently persisted resource over pinned evidence, never an
inline mutation of the Run it reviews. The routes here read and write nothing
but `reviews` and `review_findings`; the `Reviewer` itself is constructed on
the other side of :mod:`nipo_local.reviewrun` from an inert evidence snapshot,
so it never receives the store.

Export is the same shape, joined on the other side of
:mod:`nipo_local.exportrun`, with one addition the other resources do not need.
A pack can approach 500 MiB and a browser cannot attach `X-Nipo-Token` to a
download navigation, so the pack is streamed from disk to a URL the browser
fetches by itself. That URL carries a *capability*, not the session
credential: minted only under the credential, bound to one pack, expiring,
spent by its first use, and screened by the guard under the same
`Sec-Fetch-Site`-on-every-method rule the document surface gets. It is a second
kind of credential, never an exemption -- `LocalGuard.documents` stays exactly
the static surface's own enumeration.

A produced pack also has a lifecycle, which is two ordinary routes and no
exemption at all: `GET .../exports` lists what is on disk beside what it costs,
and `DELETE .../exports/{pack_id}` removes exactly one named pack. Neither is a
capability path, so both require the session credential, and the delete is
state-changing and therefore also refused cross-site. There is deliberately no
route that decides *which* packs to remove: see :func:`_export_router`.
"""

import base64
import hashlib
import json
import os
import secrets
import shutil
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from http import HTTPStatus
from pathlib import Path
from threading import Lock
from typing import Final, Protocol, cast, final, override
from uuid import UUID

from fastapi import APIRouter, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from services.api.artifacts.memory_recovery import InMemoryArtifactRecovery
from services.api.artifacts.models import (
    ArtifactRecord,
    ArtifactScope,
    ArtifactVersion,
    Clock,
    IdFactory,
)
from services.api.artifacts.runtime import SystemClock, Uuid7Factory
from services.api.artifacts.service import ArtifactService
from services.api.artifacts.store_contract import (
    ArtifactStoreError,
    BlobIntegrityError,
    StoreOutcome,
)
from services.api.artifacts.watcher import OutputWatcher
from starlette.concurrency import iterate_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from science_workbench_science import ProbeInput, ResearchIntent
from science_workbench_science.research_intent import (
    ResearchIntentError,
    research_intent_from_mapping,
)

from .apiquery import LocalReadModel
from .apiserver import (
    LOOPBACK_HOST,
    LoopbackServer,
    bind_loopback,
    loopback_authorities,
    loopback_origins,
)
from .apitypes import (
    ActionPlanBody,
    ActionPlanCreatedBody,
    ApiErrorCode,
    ApprovalBody,
    ArtifactDetail,
    ArtifactList,
    ArtifactSummary,
    ComposerModelEntry,
    ComposerPicker,
    ComposerUpdate,
    CreateActionPlanRequest,
    CreateApprovalRequest,
    CreateExportRequest,
    CreateProjectRequest,
    CreateRunRequest,
    CreateSessionRequest,
    CreateTurnRequest,
    DeletedPackBody,
    DownloadGrantBody,
    ErrorBody,
    ExportCandidateBody,
    ExportPackBody,
    ExportPackListBody,
    ExportPlanBody,
    HealthBody,
    KeyRejection,
    LoaderRejection,
    LocalNameError,
    NameRejection,
    PackDocumentBody,
    PackEntryBody,
    ProbeKind,
    ProbeUploadBody,
    ProbeUploadRequest,
    ProjectBody,
    ProjectList,
    ProvenanceBody,
    ProviderCard,
    ProviderList,
    ResearchIntentBody,
    ReviewBody,
    ReviewCoverageBody,
    ReviewFindingBody,
    RunCreatedBody,
    RunRejection,
    SessionBody,
    SessionList,
    SetKeyRequest,
    StoredPackBody,
    TurnBody,
    TurnFailedBody,
    VersionBody,
    VersionList,
    normalized_name_key,
    safe_download_name,
    safe_media_type,
    validate_local_name,
)
from .config import (
    LOCAL_ORG_ID,
    LOCAL_RUNTIME_ADAPTER_ID,
    LOCAL_RUNTIME_CONNECTION_ID,
    LOCAL_USER_ID,
    LocalPaths,
)
from .exportpack import ExportRejection
from .exportrun import (
    ALWAYS_WRITTEN_DOCUMENTS,
    CONDITIONAL_DOCUMENTS,
    DOWNLOAD_ROUTE,
    EXPORTS_BUDGET_BYTES,
    PACK_MEDIA_TYPE,
    DownloadTicket,
    DownloadTickets,
    ExportCandidate,
    ExportJob,
    ExportRunError,
    ExportRunRejection,
    ProducedPack,
    StoredPack,
    StoredPacks,
    TicketOutcome,
    delete_pack,
    export_candidates,
    list_packs,
    produce_pack,
    read_pack,
    stream_pack,
)
from .loaders import (
    DataFileNotFoundError,
    LoaderError,
    MalformedDataError,
    ManifestKindMismatchError,
    ManifestNotFoundError,
    ManifestSchemaError,
    ManifestSyntaxError,
    MetadataPolicy,
    MetadataRejectedError,
    load_probe,
)
from .modelcall import (
    Completed,
    ModelCallClient,
    ModelCallError,
    ModelCallFailure,
    ModelRequest,
    TextDelta,
    TurnRecord,
)
from .modelcall import Message as CallMessage
from .providers import (
    CredentialBackendError,
    CredentialStoreCorruptError,
    EmptyKeyError,
    InvisibleCharacterError,
    KeyNotRequiredError,
    LocalStateUnreadableError,
    MalformedModelIdError,
    ModelNotEnabledError,
    ProviderError,
    ProviderRegistry,
    ProviderStatus,
    SurroundingWhitespaceError,
    UnknownProviderError,
    parse_model_id,
)
from .reviewer import RULE_COVERAGE, summary_verdict
from .reviewrun import (
    PersistedReview,
    ReviewJob,
    ReviewRejection,
    ReviewRejectionError,
    persisted_review,
    review_run,
)
from .store import (
    ActionPlanRecord,
    ApprovalOutcome,
    LocalArtifactStore,
    PlanApprovalRecord,
    ProjectRecord,
    RunTurnDraft,
    SessionRecord,
)
from .webui import StaticAsset, StaticSurface, inject_token
from .workbench import (
    DEFAULT_APPROVAL_TTL,
    ActionPlanError,
    ApprovedPlan,
    LocalArtifactRuntime,
    PlanApprovalError,
    WorkbenchRejection,
    WorkbenchRun,
    WorkbenchRunError,
    approve_action_plan,
    create_action_plan,
    load_download_signing_key,
    local_scope,
    run_analysis,
)

API_PREFIX: Final = "/api/v1"

TOKEN_HEADER: Final = "x-nipo-token"  # noqa: S105 - a header name, not a secret
"""Custom request header carrying the local session credential."""

TOKEN_FILE_NAME: Final = "api-token.json"  # noqa: S105 - a file name, not a secret
TOKEN_ENTROPY_BYTES: Final = 32
TOKEN_FILE_MODE: Final = 0o600

STATE_CHANGING_METHODS: Final = frozenset({"POST", "PUT", "PATCH", "DELETE"})
ACCEPTABLE_FETCH_SITES: Final = frozenset({"same-origin", "none"})

SECURITY_HEADERS: Final = (
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"x-frame-options", b"DENY"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"vary", b"Origin"),
)
"""Injected on every response. No `access-control-allow-*` header is ever set."""

TICKET_STATE: Final = "nipo_download_ticket"
"""Where the guard puts the capability it accepted, for the route to read.

The download route serves nothing without this. Two independent statements have
to hold for a pack to leave this listener -- the guard accepted a live,
unspent, correctly bound capability, *and* the route found that acceptance --
so a request that merely carries the session credential cannot read a pack by
guessing at a download URL.
"""

_MODE_MESSAGE: Final = "local credential file is not owner-only"
_TOKEN_PARENT_MESSAGE: Final = "local data root does not exist"  # noqa: S105 - a message, not a secret
_REDACTED_REPR: Final = "LocalToken(value=<redacted>)"
PRODUCT_UPLOAD_DATA_BYTES: Final = 16 * 1024 * 1024
"""Decoded measurement-file cap on the product upload path.

base64(16 MiB) ≈ 21.4 MiB + manifest + JSON overhead stays under the 32 MiB
shared body cap; loaders.MAX_* stay at 64 MiB for module/CLI users.
"""

PRODUCT_UPLOAD_IMAGE_PIXELS: Final = 250_000
"""Product-path pixel cap enforced after a successful image load.

250k px at ~14 B per RGB triple is ~3.5 MB serialized ProbeInput, well under
the 32 MiB body cap. Module loaders keep MAX_IMAGE_PIXELS = 4_000_000.
"""

PRODUCT_UPLOAD_SPECTRUM_POINTS: Final = 400_000
"""Product-path spectrum point cap, pinned against real JSON expansion.

A 16 MiB CSV can hold ~840k points; long float reprs push the serialized
ProbeInput past the shared body budget. 400k points keeps the worst-case
document under PRODUCT_PROBE_JSON_BYTES.
"""

PRODUCT_PROBE_JSON_BYTES: Final = 24 * 1024 * 1024
"""Upper bound on serialized ProbeInput JSON returned by the upload route.

24 MiB ≤ 32 MiB body cap with headroom for the run-start envelope fields.
Measured via ``len(ProbeInput.model_dump_json().encode())`` after load.
"""

STAGING_DIR_NAME: Final = "staging"
STAGING_DIR_MODE: Final = 0o700
STAGING_FILE_MODE: Final = 0o600


@final
class LocalApiError(Exception):
    """One boundary refusal carrying a closed code and no caller input."""

    status: HTTPStatus
    code: ApiErrorCode
    reason: (
        NameRejection
        | KeyRejection
        | ExportRunRejection
        | ExportRejection
        | RunRejection
        | LoaderRejection
        | None
    )
    science_issue: str | None

    def __init__(
        self,
        status: HTTPStatus,
        code: ApiErrorCode,
        reason: NameRejection
        | KeyRejection
        | ExportRunRejection
        | ExportRejection
        | RunRejection
        | LoaderRejection
        | None = None,
        *,
        science_issue: str | None = None,
    ) -> None:
        """Record the refusal without retaining anything the caller sent."""
        super().__init__(str(code))
        self.status = status
        self.code = code
        self.reason = reason
        self.science_issue = science_issue


@final
@dataclass(frozen=True, slots=True, repr=False)
class LocalToken:
    """The per-run local session credential.

    `__repr__` and `__str__` are redacted so the value cannot reach a
    traceback, a log line, or a debugger transcript by accident.
    """

    value: str

    @override
    def __repr__(self) -> str:
        """Describe the token without disclosing it."""
        return _REDACTED_REPR

    @override
    def __str__(self) -> str:
        """Describe the token without disclosing it."""
        return _REDACTED_REPR

    def matches(self, presented: bytes | None) -> bool:
        """Compare a presented credential in constant time.

        The comparison is on raw bytes rather than decoded text on purpose:
        `secrets.compare_digest` raises `TypeError` for a `str` carrying a
        non-ASCII character, so comparing decoded header text would turn a
        malformed credential into a server error instead of a refusal.
        """
        if presented is None:
            return False
        return secrets.compare_digest(presented, self.value.encode("utf-8"))


def new_local_token() -> LocalToken:
    """Mint one fresh per-run session credential."""
    return LocalToken(secrets.token_urlsafe(TOKEN_ENTROPY_BYTES))


def token_file(paths: LocalPaths) -> Path:
    """Return the path the local front end reads the credential from."""
    return paths.root / TOKEN_FILE_NAME


def write_token_file(paths: LocalPaths, token: LocalToken, base_url: str) -> Path:
    """Publish the credential owner-only, from the instant the file exists.

    The data root must already exist. This function never creates it: a
    parent.mkdir here would apply the process umask and could leave a
    world-readable layout on a fresh install. Call
    :meth:`~nipo_local.config.LocalPaths.ensure` first (as
    :func:`start_local_api` does) so the root and blob directories are
    owner-only before any credential lands.

    Args:
        paths: The resolved local layout.
        token: The per-run credential.
        base_url: The loopback URL the front end should call.

    Returns:
        The path written.

    Raises:
        OSError: The data root is missing, or the file could not be
            created owner-only. A widened file is removed first so it is
            never left behind.
    """
    path = token_file(paths)
    if not path.parent.is_dir():
        raise OSError(_TOKEN_PARENT_MESSAGE)
    path.unlink(missing_ok=True)
    payload = json.dumps(
        {"base_url": base_url, "header": TOKEN_HEADER, "token": token.value},
        sort_keys=True,
    )
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        TOKEN_FILE_MODE,
    )
    try:
        # `os.open` masks its mode with the process umask, so the mode is set
        # explicitly on the descriptor before any byte is written.
        os.fchmod(descriptor, TOKEN_FILE_MODE)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            _ = handle.write(f"{payload}\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    if stat.S_IMODE(path.stat().st_mode) != TOKEN_FILE_MODE:
        path.unlink(missing_ok=True)
        raise OSError(_MODE_MESSAGE)
    return path


class RunSurface(Protocol):
    """The seam a durable Run *read* implementation binds into this API.

    ActionPlans, approvals, and Run *starts* are owned by
    :mod:`nipo_local.store` and :mod:`nipo_local.workbench`, and the plan /
    approval / run-start routes call those modules directly. This Protocol is
    deliberately read-only: it answers only the questions the list/detail and
    provenance surfaces need, and never mutates store state.

    * `list_runs` and `read_run` return already-projected JSON objects.
    * `execution_isolation` answers the one provenance question SPEC-v0.5
      section 5 requires and the `artifact_versions` row cannot answer.

    While nothing is bound, the GET `/runs` endpoints answer `501` with
    `run_surface_unavailable`. They are declared and refused rather than
    absent, so the front end can render the capability as not-yet-implemented
    instead of discovering a 404 and guessing why. The POST `/runs` route
    that starts an approved analysis does not use this Protocol.
    """

    def list_runs(self, scope: ArtifactScope) -> Sequence[Mapping[str, object]]:
        """Return one Project's Run projections, newest first."""
        ...

    def read_run(
        self,
        scope: ArtifactScope,
        run_id: UUID,
    ) -> Mapping[str, object] | None:
        """Return one Run projection, or None when it does not exist."""
        ...

    def execution_isolation(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
    ) -> str | None:
        """Return the disclosed isolation level of one produced execution."""
        ...


@final
@dataclass(frozen=True, slots=True)
class _RunLockOwner:
    """Bounded API-runtime serialization for turns of the same Run."""

    locks: tuple[Lock, ...] = field(
        default_factory=lambda: tuple(Lock() for _ in range(64)),
    )

    def for_run(self, run_id: UUID) -> Lock:
        """Return the fixed stripe that serializes one Run's turn request."""
        return self.locks[hash(run_id) % len(self.locks)]


@final
@dataclass(frozen=True, slots=True)
class LocalApiDeps:
    """Everything the routers read, injected rather than constructed.

    `paths` is required rather than optional. Export writes a pack into the
    data root and reads the run mirror out of it, so a surface without a
    resolved layout cannot answer for Export at all -- and an optional field
    would mean a "not configured" branch that no shipped arrangement ever
    reaches, which is worse than a constructor argument.
    """

    store: LocalArtifactStore
    registry: ProviderRegistry
    read_model: LocalReadModel
    paths: LocalPaths
    clock: Clock
    ids: IdFactory
    org_id: UUID = LOCAL_ORG_ID
    requester_id: UUID = LOCAL_USER_ID
    runs: RunSurface | None = None
    turn_client: ModelCallClient | None = None
    """The client the turn route streams through.

    `None` binds the route to `ModelCallClient(registry)` with the default
    endpoint table; a test injects a client over loopback endpoints so no
    turn ever leaves this machine. The client never chooses a provider --
    the route hands it exactly the requested `provider:model` id.
    """
    turn_locks: _RunLockOwner = field(default_factory=_RunLockOwner)


def _ticket_refusal(code: ApiErrorCode) -> Callable[[], LocalApiError]:
    """Build one closed refusal for a capability that was not honoured."""
    return lambda: LocalApiError(HTTPStatus.UNAUTHORIZED, code)


_TICKET_REFUSALS: Final[dict[TicketOutcome, Callable[[], LocalApiError]]] = {
    TicketOutcome.EXPIRED: _ticket_refusal(ApiErrorCode.DOWNLOAD_TICKET_EXPIRED),
    TicketOutcome.SPENT: _ticket_refusal(ApiErrorCode.DOWNLOAD_TICKET_SPENT),
    TicketOutcome.PATH_MISMATCH: _ticket_refusal(ApiErrorCode.DOWNLOAD_TICKET_INVALID),
    TicketOutcome.UNKNOWN: _ticket_refusal(ApiErrorCode.DOWNLOAD_TICKET_INVALID),
}
"""Every way a presented capability can fail, each with its own closed code.

`401` rather than `403` in all four cases: a capability that expired, was
already spent, or was presented at a pack it does not open is a credential
problem, and the researcher's recovery is the same in each -- mint another one.
"""


@final
class LocalGuard:
    """Refuse every request that is not a token-bearing same-origin local call."""

    def __init__(  # noqa: PLR0913 - one guard, one binding point
        self,
        app: ASGIApp,
        *,
        token: LocalToken,
        origins: frozenset[str],
        authorities: frozenset[str],
        documents: frozenset[str] | None = None,
        tickets: DownloadTickets | None = None,
    ) -> None:
        """Bind the guard to one listener's credential, origins, and authorities.

        Args:
            app: The application to screen.
            token: The per-run credential every API request must present.
            origins: Browser origins this listener accepts.
            authorities: `Host` values this listener answers.
            documents: The exact request paths served to a browser that
                cannot attach a custom header -- the page and its assets. It
                is a closed set of literal paths, never a prefix and never a
                pattern, so a future API route cannot fall into it by
                resembling one. `None` means no front end is served and every
                single path requires the credential.
            tickets: The registry of one-use Export download capabilities. A
                capability is a *second kind of credential*, never an
                exemption: it is minted only by a credential-bearing request,
                opens exactly one pack, expires, is spent by its first use,
                and is checked under a fetch-metadata rule stricter than the
                one the credential path applies. `None` means this listener
                issues none and the credential is the only way in.
        """
        self._app = app
        self._token = token
        self._origins = origins
        self._authorities = authorities
        self._documents: frozenset[str] = (
            frozenset() if documents is None else documents
        )
        self._tickets = tickets

    @property
    def documents(self) -> frozenset[str]:
        """Return the exact paths exempt from the credential check.

        Readable on purpose. This is the one place this surface relaxes a
        control, so what it covers must be inspectable -- and assertable --
        rather than a private detail a reviewer has to infer from behaviour.

        A download capability path is deliberately *not* here. Those paths are
        not exempt from anything: they present a credential of their own, and
        they are screened more strictly than a credential-bearing request, not
        less.
        """
        return self._documents

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Screen one connection before the application ever sees it."""
        kind = cast("str", scope.get("type", ""))
        if kind == "lifespan":
            await self._app(scope, receive, send)
            return
        if kind != "http":
            await _deny_protocol(send)
            return
        refusal = self._refuse(scope)
        if refusal is not None:
            await _send_error(send, refusal)
            return
        await self._app(scope, receive, _hardened(send))

    def _refuse(self, scope: Scope) -> LocalApiError | None:
        """Return the refusal for one HTTP request, or None to let it through.

        Origin discipline is evaluated before the credential deliberately.
        A cross-site caller is refused as cross-site whether or not it also
        guessed a token, which keeps the same-origin check observable in its
        own right rather than dead code behind the credential check.

        The document surface then substitutes a stricter fetch-metadata check
        for the credential rather than dropping a control: see
        :meth:`_refuse_navigation`.
        """
        headers = _headers(scope)
        method = cast("str", scope.get("method", ""))
        refusal = self._refuse_origin(headers, method)
        if refusal is not None:
            return refusal
        path = cast("str", scope.get("path", ""))
        if path in self._documents:
            return self._refuse_navigation(headers)
        return self._refuse_credential(scope, headers, path)

    def _refuse_credential(
        self,
        scope: Scope,
        headers: dict[bytes, bytes],
        path: str,
    ) -> LocalApiError | None:
        """Require the session credential, or one capability minted under it.

        A download capability is presented in the URL because that is the only
        position a browser will carry it to a download navigation. It is
        therefore held to *more* than the credential path, not less: the
        fetch-metadata rule that the document surface applies to every method
        is applied here too, before the capability is even looked up, so a page
        on another site cannot spend a capability it somehow learned by
        navigating this browser to it.

        A path this registry never issued is every ordinary path in this
        application. It means no capability was presented at all, and the
        session credential is then required exactly as before -- so no route
        becomes credential-free by resembling a download URL, and no ordinary
        request is judged under the stricter rule.
        """
        if self._tickets is None or not self._tickets.holds(path):
            return self._refuse_token(headers)
        navigation = self._refuse_navigation(headers)
        if navigation is not None:
            return navigation
        outcome, ticket = self._tickets.present(path)
        if ticket is None:
            return _TICKET_REFUSALS[outcome]()
        # The accepted capability travels to the route, which serves nothing
        # without it. The guard stays the single authority on who may read a
        # pack: a request bearing the session credential but no capability
        # reaches the route with nothing here and is refused there.
        cast("dict[str, object]", scope.setdefault("state", {}))[TICKET_STATE] = ticket
        return None

    def _refuse_navigation(
        self,
        headers: dict[bytes, bytes],
    ) -> LocalApiError | None:
        """Refuse a cross-site load of a page that cannot carry the credential.

        A top-level navigation, a stylesheet, and a script cannot attach a
        custom header, so the session credential cannot guard these paths.
        `Sec-Fetch-Site` is therefore enforced here for *every* method, not
        only the state-changing ones the API surface checks: that is what
        stops a page on another site from pulling this document into an
        iframe, a `<script src>`, or a navigation it controls.

        A caller that sends no fetch metadata at all -- the researcher's own
        launcher, or a command-line client -- is treated as `none` and
        allowed, exactly as a browser labels a user-initiated navigation.
        """
        site = headers.get(b"sec-fetch-site")
        if site is not None and site.decode("latin-1") not in ACCEPTABLE_FETCH_SITES:
            return LocalApiError(HTTPStatus.FORBIDDEN, ApiErrorCode.CROSS_ORIGIN_DENIED)
        return None

    def _refuse_origin(
        self,
        headers: dict[bytes, bytes],
        method: str,
    ) -> LocalApiError | None:
        """Refuse a rebound authority, a preflight, or a cross-site caller."""
        if headers.get(b"host", b"").decode("latin-1") not in self._authorities:
            return LocalApiError(HTTPStatus.FORBIDDEN, ApiErrorCode.HOST_NOT_ALLOWED)
        if method == "OPTIONS":
            return LocalApiError(HTTPStatus.FORBIDDEN, ApiErrorCode.PREFLIGHT_DENIED)
        origin = headers.get(b"origin")
        if origin is not None and origin.decode("latin-1") not in self._origins:
            return LocalApiError(HTTPStatus.FORBIDDEN, ApiErrorCode.CROSS_ORIGIN_DENIED)
        site = headers.get(b"sec-fetch-site")
        cross_site = site is not None and site.decode("latin-1") not in (
            ACCEPTABLE_FETCH_SITES
        )
        if method in STATE_CHANGING_METHODS and cross_site:
            return LocalApiError(HTTPStatus.FORBIDDEN, ApiErrorCode.CROSS_ORIGIN_DENIED)
        return None

    def _refuse_token(self, headers: dict[bytes, bytes]) -> LocalApiError | None:
        """Refuse a caller that does not present the exact local credential."""
        presented = headers.get(TOKEN_HEADER.encode("ascii"))
        if presented is None:
            return LocalApiError(
                HTTPStatus.UNAUTHORIZED,
                ApiErrorCode.LOCAL_TOKEN_REQUIRED,
            )
        if not self._token.matches(presented):
            return LocalApiError(
                HTTPStatus.UNAUTHORIZED,
                ApiErrorCode.LOCAL_TOKEN_INVALID,
            )
        return None


def _headers(scope: Scope) -> dict[bytes, bytes]:
    """Return the first value of each request header, lower-cased."""
    raw = cast("Sequence[tuple[bytes, bytes]]", scope.get("headers", ()))
    collected: dict[bytes, bytes] = {}
    for name, value in raw:
        _ = collected.setdefault(name.lower(), value)
    return collected


def _hardened(send: Send) -> Send:
    """Wrap `send` so every response carries the fixed security headers."""

    async def wrapped(message: Message) -> None:
        if message.get("type") == "http.response.start":
            existing = cast("list[tuple[bytes, bytes]]", message.get("headers", []))
            present = {name.lower() for name, _ in existing}
            message["headers"] = [
                *existing,
                *(pair for pair in SECURITY_HEADERS if pair[0] not in present),
            ]
        await send(message)

    return wrapped


async def _deny_protocol(send: Send) -> None:
    """Close a non-HTTP connection without ever running the application."""
    await send({"type": "websocket.close", "code": 1008})


async def _send_error(send: Send, error: LocalApiError) -> None:
    """Emit one guard refusal as the surface's only error shape."""
    body = _error_body(error)
    await send(
        {
            "type": "http.response.start",
            "status": int(error.status),
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", b"%d" % len(body)),
                *SECURITY_HEADERS,
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


def _error_body(error: LocalApiError) -> bytes:
    """Serialize one refusal, quoting nothing the caller supplied."""
    payload = ErrorBody(
        error=error.code,
        reason=error.reason,
        science_issue=error.science_issue,
    )
    return payload.model_dump_json(exclude_none=True).encode("utf-8")


def _no_content() -> Response:
    """Return the surface's one empty success response."""
    return Response(status_code=int(HTTPStatus.NO_CONTENT))


def _error_response(error: LocalApiError) -> Response:
    """Build the framework response for one refusal."""
    return Response(
        content=_error_body(error),
        status_code=int(error.status),
        media_type="application/json",
    )


def _scope_for(deps: LocalApiDeps, project_id: UUID) -> ArtifactScope:
    """Build the fixed single-user scope for one Project path parameter."""
    try:
        return ArtifactScope(
            org_id=deps.org_id,
            project_id=project_id,
            requester_id=deps.requester_id,
        )
    except ValidationError as error:
        raise LocalApiError(HTTPStatus.NOT_FOUND, ApiErrorCode.NOT_FOUND) from error


def _checked_name(value: str) -> str:
    """Validate one submitted name, mapping its rejection onto the wire."""
    try:
        return validate_local_name(value)
    except LocalNameError as error:
        raise LocalApiError(
            HTTPStatus.BAD_REQUEST,
            ApiErrorCode.INVALID_NAME,
            error.reason,
        ) from error


def _reject_collision(existing: Sequence[str], candidate: str) -> None:
    """Refuse a name that normalizes onto a sibling that already exists."""
    key = normalized_name_key(candidate)
    if any(normalized_name_key(name) == key for name in existing):
        raise LocalApiError(HTTPStatus.CONFLICT, ApiErrorCode.NAME_IN_USE)


def _outcome_error(outcome: StoreOutcome) -> LocalApiError:
    """Translate one store outcome into the local refusal it means."""
    if outcome is StoreOutcome.ARCHIVED:
        return LocalApiError(HTTPStatus.CONFLICT, ApiErrorCode.PROJECT_ARCHIVED)
    if outcome is StoreOutcome.ASSOCIATION_EXISTS:
        return LocalApiError(HTTPStatus.CONFLICT, ApiErrorCode.NAME_IN_USE)
    return LocalApiError(HTTPStatus.NOT_FOUND, ApiErrorCode.NOT_FOUND)


def _project_body(record: ProjectRecord) -> ProjectBody:
    """Project one Project record onto the wire."""
    return ProjectBody(
        id=record.id,
        name=record.name,
        created_at=record.created_at,
        archived=record.archived,
    )


def _session_body(record: SessionRecord) -> SessionBody:
    """Project one Session record onto the wire."""
    return SessionBody(
        id=record.id,
        project_id=record.project_id,
        title=record.title,
        created_at=record.created_at,
        last_active_at=record.last_active_at,
        archived=record.archived,
    )


def _version_body(version: ArtifactVersion) -> VersionBody:
    """Project one Version onto the wire, withholding its storage address."""
    return VersionBody(
        id=version.id,
        artifact_id=version.artifact_id,
        version_no=version.version_no,
        media_type=version.media_type,
        size_bytes=version.size_bytes,
        content_sha256=version.content_sha256,
        created_at=version.created_at,
    )


def _provenance_body(version: ArtifactVersion, isolation: str | None) -> ProvenanceBody:
    """Project one Version's pinned provenance onto the wire."""
    return ProvenanceBody(
        version_id=version.id,
        artifact_id=version.artifact_id,
        version_no=version.version_no,
        content_sha256=version.content_sha256,
        size_bytes=version.size_bytes,
        media_type=version.media_type,
        producing_execution_id=version.producing_execution_id,
        environment_sha256=version.environment_sha256,
        code_sha256=version.code_sha256,
        runtime_adapter_id=version.runtime_adapter_id,
        runtime_connection_id=version.runtime_connection_id,
        skill_content_hashes=version.skill_content_hashes,
        source_hashes=version.source_hashes,
        input_version_ids=version.input_version_ids,
        created_at=version.created_at,
        execution_isolation=isolation,
    )


_PROVIDER_REFUSALS: Final[
    tuple[
        tuple[
            type[ProviderError],
            HTTPStatus,
            ApiErrorCode,
            KeyRejection | None,
        ],
        ...,
    ]
] = (
    (
        UnknownProviderError,
        HTTPStatus.NOT_FOUND,
        ApiErrorCode.UNKNOWN_PROVIDER,
        None,
    ),
    (
        KeyNotRequiredError,
        HTTPStatus.CONFLICT,
        ApiErrorCode.KEY_NOT_REQUIRED,
        None,
    ),
    (
        EmptyKeyError,
        HTTPStatus.BAD_REQUEST,
        ApiErrorCode.KEY_REJECTED,
        KeyRejection.EMPTY,
    ),
    (
        SurroundingWhitespaceError,
        HTTPStatus.BAD_REQUEST,
        ApiErrorCode.KEY_REJECTED,
        KeyRejection.SURROUNDING_WHITESPACE,
    ),
    (
        InvisibleCharacterError,
        HTTPStatus.BAD_REQUEST,
        ApiErrorCode.KEY_REJECTED,
        KeyRejection.INVISIBLE_CHARACTER,
    ),
    (
        MalformedModelIdError,
        HTTPStatus.BAD_REQUEST,
        ApiErrorCode.MODEL_ID_MALFORMED,
        None,
    ),
    (
        ModelNotEnabledError,
        HTTPStatus.CONFLICT,
        ApiErrorCode.MODEL_NOT_ENABLED,
        None,
    ),
    (
        LocalStateUnreadableError,
        HTTPStatus.SERVICE_UNAVAILABLE,
        ApiErrorCode.LOCAL_STATE_UNREADABLE,
        None,
    ),
    (
        CredentialStoreCorruptError,
        HTTPStatus.SERVICE_UNAVAILABLE,
        ApiErrorCode.LOCAL_STATE_UNREADABLE,
        None,
    ),
)


def _provider_error(error: ProviderError) -> LocalApiError:
    """Translate a registry failure, never quoting the submitted key.

    `InvisibleCharacterError` carries the offending position and code point.
    Neither is forwarded: a position is a partial oracle on a secret the
    caller may have pasted from elsewhere, and the reason alone is actionable.
    """
    for kind, status, code, reason in _PROVIDER_REFUSALS:
        if isinstance(error, kind):
            return LocalApiError(status, code, reason)
    return LocalApiError(
        HTTPStatus.SERVICE_UNAVAILABLE,
        ApiErrorCode.CREDENTIAL_BACKEND_UNAVAILABLE,
    )


def _provider_cards(registry: ProviderRegistry) -> ProviderList:
    """Read every provider card, resolving status without unsealing anything."""
    return ProviderList(
        providers=tuple(
            ProviderCard(
                provider_id=view.provider_id,
                display_name=view.display_name,
                status=str(view.status),
                requires_key=view.requires_key,
                env_var=view.env_var,
                is_ready=view.is_ready,
            )
            for view in registry.list_providers()
        )
    )


def _composer(registry: ProviderRegistry) -> ComposerPicker:
    """Read the persisted composer picker state."""
    return ComposerPicker(
        enabled_models=registry.enabled_models(),
        default_model=registry.default_model(),
        models=tuple(
            ComposerModelEntry(
                model_id=entry.model_id,
                provider_id=entry.provider_id,
                display_name=entry.display_name,
                is_default=entry.is_default,
            )
            for entry in registry.composer_models()
        ),
    )


def _provider_call[ResultT](operation: Callable[[], ResultT]) -> ResultT:
    """Run one registry operation, normalizing its failures onto the wire."""
    try:
        return operation()
    except ProviderError as error:
        raise _provider_error(error) from error


def _provider_card(registry: ProviderRegistry, provider_id: str) -> ProviderCard:
    """Read one provider card, resolving status without unsealing anything."""
    view = _provider_call(lambda: registry.describe(provider_id))
    return ProviderCard(
        provider_id=view.provider_id,
        display_name=view.display_name,
        status=str(view.status),
        requires_key=view.requires_key,
        env_var=view.env_var,
        is_ready=view.is_ready,
    )


def _replace_composer(
    registry: ProviderRegistry,
    update: ComposerUpdate,
) -> ComposerPicker:
    """Replace the composer picker, keeping the default inside the new set."""

    def apply() -> ComposerPicker:
        _ = registry.set_enabled_models(update.enabled_models)
        registry.set_default_model(update.default_model)
        return _composer(registry)

    return _provider_call(apply)


def _provider_router(deps: LocalApiDeps) -> APIRouter:
    """Build the provider registry and composer routes."""
    router = APIRouter()
    registry = deps.registry

    def list_providers() -> ProviderList:
        """List every provider card with a live, non-secret status."""
        return _provider_call(lambda: _provider_cards(registry))

    def read_provider(provider_id: str) -> ProviderCard:
        """Read one provider card."""
        return _provider_card(registry, provider_id)

    def set_provider_key(provider_id: str, body: SetKeyRequest) -> Response:
        """Store one provider key. Nothing about the key is ever echoed."""
        _provider_call(lambda: registry.set_key(provider_id, body.key))
        return _no_content()

    def clear_provider_key(provider_id: str) -> Response:
        """Forget one provider key; safe when none is stored."""
        _provider_call(lambda: registry.clear_key(provider_id))
        return _no_content()

    def read_composer() -> ComposerPicker:
        """Read the composer model picker."""
        return _provider_call(lambda: _composer(registry))

    def write_composer(body: ComposerUpdate) -> ComposerPicker:
        """Replace the composer model picker and its default."""
        return _replace_composer(registry, body)

    router.add_api_route("/providers", list_providers, methods=["GET"])
    router.add_api_route("/providers/{provider_id}", read_provider, methods=["GET"])
    router.add_api_route(
        "/providers/{provider_id}/key",
        set_provider_key,
        methods=["PUT"],
        status_code=int(HTTPStatus.NO_CONTENT),
    )
    router.add_api_route(
        "/providers/{provider_id}/key",
        clear_provider_key,
        methods=["DELETE"],
        status_code=int(HTTPStatus.NO_CONTENT),
    )
    router.add_api_route("/composer", read_composer, methods=["GET"])
    router.add_api_route("/composer", write_composer, methods=["PUT"])
    return router


def _read_project(deps: LocalApiDeps, project_id: UUID) -> ProjectRecord:
    """Read one registered Project or refuse."""
    scope = _scope_for(deps, project_id)
    record = deps.store.project(scope)
    if record is None:
        raise LocalApiError(HTTPStatus.NOT_FOUND, ApiErrorCode.NOT_FOUND)
    return record


def _live_project(deps: LocalApiDeps, project_id: UUID) -> ArtifactScope:
    """Return the scope of a Project that exists and is not archived."""
    record = _read_project(deps, project_id)
    if record.archived:
        raise LocalApiError(HTTPStatus.CONFLICT, ApiErrorCode.PROJECT_ARCHIVED)
    return _scope_for(deps, project_id)


def _known_project(deps: LocalApiDeps, project_id: UUID) -> ArtifactScope:
    """Return the scope of a Project that exists, archived or not.

    Archiving blocks writes to a Project's evidence. A produced pack is not
    that evidence -- it is a derived file sitting in a directory -- and the
    bytes it occupies do not stop costing anything when the Project is
    archived. Refusing to list or remove those packs would be the one branch in
    which disk use becomes unrecoverable, which is the opposite of what a
    lifecycle is for. `GET /projects/{id}` already answers for an archived
    Project on the same reasoning.
    """
    _ = _read_project(deps, project_id)
    return _scope_for(deps, project_id)


def _project_router(deps: LocalApiDeps) -> APIRouter:
    """Build the Project lifecycle routes."""
    router = APIRouter()
    store = deps.store

    def create_project(body: CreateProjectRequest) -> ProjectBody:
        """Register one Project under a server-minted identity."""
        name = _checked_name(body.name)
        existing = store.projects(deps.org_id)
        _reject_collision([record.name for record in existing], name)
        record = ProjectRecord(
            id=deps.ids.new_uuid7(),
            org_id=deps.org_id,
            name=name,
            created_at=deps.clock.now(),
        )
        outcome = store.create_project(_scope_for(deps, record.id), record)
        if outcome is not StoreOutcome.CREATED:
            raise _outcome_error(outcome)
        return _project_body(record)

    def list_projects() -> ProjectList:
        """List every registered Project, newest first."""
        return ProjectList(
            projects=tuple(_project_body(item) for item in store.projects(deps.org_id))
        )

    def read_project(project_id: UUID) -> ProjectBody:
        """Read one registered Project, archived or not."""
        return _project_body(_read_project(deps, project_id))

    def archive_project(project_id: UUID) -> Response:
        """Archive one live Project, blocking further writes and downloads."""
        outcome = store.archive_registered_project(_scope_for(deps, project_id))
        if outcome is not StoreOutcome.CREATED:
            raise _outcome_error(outcome)
        return _no_content()

    router.add_api_route(
        "/projects",
        create_project,
        methods=["POST"],
        status_code=int(HTTPStatus.CREATED),
    )
    router.add_api_route("/projects", list_projects, methods=["GET"])
    router.add_api_route("/projects/{project_id}", read_project, methods=["GET"])
    router.add_api_route(
        "/projects/{project_id}/archive",
        archive_project,
        methods=["POST"],
        status_code=int(HTTPStatus.NO_CONTENT),
    )
    return router


def _read_session(
    deps: LocalApiDeps,
    scope: ArtifactScope,
    session_id: UUID,
) -> SessionRecord:
    """Read one Session in an active Project or refuse."""
    record = deps.store.session(scope, session_id)
    if record is None:
        raise LocalApiError(HTTPStatus.NOT_FOUND, ApiErrorCode.NOT_FOUND)
    return record


def _session_transition(outcome: StoreOutcome) -> None:
    """Raise the refusal one Session transition outcome means, if any."""
    if outcome is StoreOutcome.ARCHIVED:
        raise LocalApiError(HTTPStatus.CONFLICT, ApiErrorCode.SESSION_ARCHIVED)
    if outcome is not StoreOutcome.CREATED:
        raise _outcome_error(outcome)


def _create_session(
    deps: LocalApiDeps,
    project_id: UUID,
    title: str,
) -> SessionBody:
    """Register one Session under a server-minted identity and timestamps."""
    scope = _live_project(deps, project_id)
    checked = _checked_name(title)
    live = [item.title for item in deps.store.sessions(scope) if not item.archived]
    _reject_collision(live, checked)
    moment = deps.clock.now()
    record = SessionRecord(
        id=deps.ids.new_uuid7(),
        org_id=deps.org_id,
        project_id=project_id,
        title=checked,
        created_at=moment,
        last_active_at=moment,
    )
    outcome = deps.store.create_session(scope, record)
    if outcome is not StoreOutcome.CREATED:
        raise _outcome_error(outcome)
    return _session_body(record)


def _resume_session(
    deps: LocalApiDeps,
    project_id: UUID,
    session_id: UUID,
) -> SessionBody:
    """Advance one live Session's last active time and read it back."""
    scope = _live_project(deps, project_id)
    _session_transition(deps.store.resume_session(scope, session_id, deps.clock.now()))
    return _session_body(_read_session(deps, scope, session_id))


def _session_router(deps: LocalApiDeps) -> APIRouter:
    """Build the Session lifecycle routes."""
    router = APIRouter()
    store = deps.store

    def create_session(project_id: UUID, body: CreateSessionRequest) -> SessionBody:
        """Register one Session owned by exactly this Project."""
        return _create_session(deps, project_id, body.title)

    def list_sessions(project_id: UUID) -> SessionList:
        """List this Project's Sessions, most recently active first."""
        scope = _live_project(deps, project_id)
        return SessionList(
            sessions=tuple(_session_body(item) for item in store.sessions(scope))
        )

    def read_session(project_id: UUID, session_id: UUID) -> SessionBody:
        """Read one Session."""
        scope = _live_project(deps, project_id)
        return _session_body(_read_session(deps, scope, session_id))

    def resume_session(project_id: UUID, session_id: UUID) -> SessionBody:
        """Advance one live Session's last active time and return it."""
        return _resume_session(deps, project_id, session_id)

    def archive_session(project_id: UUID, session_id: UUID) -> Response:
        """Archive one live Session."""
        scope = _live_project(deps, project_id)
        _session_transition(store.archive_session(scope, session_id))
        return _no_content()

    sessions = "/projects/{project_id}/sessions"
    router.add_api_route(
        sessions,
        create_session,
        methods=["POST"],
        status_code=int(HTTPStatus.CREATED),
    )
    router.add_api_route(sessions, list_sessions, methods=["GET"])
    router.add_api_route(f"{sessions}/{{session_id}}", read_session, methods=["GET"])
    router.add_api_route(
        f"{sessions}/{{session_id}}/resume",
        resume_session,
        methods=["POST"],
    )
    router.add_api_route(
        f"{sessions}/{{session_id}}/archive",
        archive_session,
        methods=["POST"],
        status_code=int(HTTPStatus.NO_CONTENT),
    )
    return router


def _read_artifact(
    deps: LocalApiDeps,
    scope: ArtifactScope,
    artifact_id: UUID,
) -> ArtifactRecord:
    """Read one Artifact in an active Project or refuse."""
    try:
        record = deps.store.artifact(scope, artifact_id)
    except ArtifactStoreError as error:
        raise LocalApiError(
            HTTPStatus.SERVICE_UNAVAILABLE,
            ApiErrorCode.STORE_UNAVAILABLE,
        ) from error
    if record is None:
        raise LocalApiError(HTTPStatus.NOT_FOUND, ApiErrorCode.NOT_FOUND)
    return record


def _artifact_versions(
    deps: LocalApiDeps,
    scope: ArtifactScope,
    artifact_id: UUID,
) -> tuple[ArtifactVersion, ...]:
    """Read one Artifact's Version history in commit order."""
    versions: list[ArtifactVersion] = []
    for identifier in deps.read_model.version_ids(scope, artifact_id):
        version = deps.store.version(scope, identifier)
        if version is not None:
            versions.append(version)
    return tuple(versions)


def _owned_version(
    deps: LocalApiDeps,
    scope: ArtifactScope,
    artifact_id: UUID,
    version_id: UUID,
) -> ArtifactVersion:
    """Read one Version and confirm the route's Artifact really owns it."""
    version = deps.store.version(scope, version_id)
    if version is None or version.artifact_id != artifact_id:
        raise LocalApiError(HTTPStatus.NOT_FOUND, ApiErrorCode.NOT_FOUND)
    return version


def _list_artifacts(deps: LocalApiDeps, scope: ArtifactScope) -> ArtifactList:
    """Project one Project's Artifacts with their head Version position."""
    summaries: list[ArtifactSummary] = []
    for identifier in deps.read_model.artifact_ids(scope):
        record = deps.store.artifact(scope, identifier)
        if record is None:
            continue
        versions = _artifact_versions(deps, scope, identifier)
        summaries.append(
            ArtifactSummary(
                id=record.id,
                name=record.name,
                created_at=record.created_at,
                version_count=len(versions),
                head_version_no=versions[-1].version_no if versions else 0,
            )
        )
    return ArtifactList(artifacts=tuple(summaries))


def _download(
    deps: LocalApiDeps,
    scope: ArtifactScope,
    record: ArtifactRecord,
    version: ArtifactVersion,
) -> Response:
    """Return one Version's digest-verified bytes as an attachment."""
    try:
        outcome, _, payload = deps.store.redeem_content(scope, version.id)
    except BlobIntegrityError as error:
        raise LocalApiError(
            HTTPStatus.SERVICE_UNAVAILABLE,
            ApiErrorCode.CONTENT_CORRUPT,
        ) from error
    except ArtifactStoreError as error:
        raise LocalApiError(
            HTTPStatus.SERVICE_UNAVAILABLE,
            ApiErrorCode.STORE_UNAVAILABLE,
        ) from error
    if outcome is not StoreOutcome.CREATED or payload is None:
        raise _outcome_error(outcome)
    leaf = safe_download_name(record.name, str(version.id))
    # The content type is set as a header rather than through `media_type`
    # so the framework does not append a charset the Version never recorded:
    # an immutable artifact is returned exactly as it was committed.
    return Response(
        content=payload,
        headers={
            "content-type": safe_media_type(version.media_type),
            "content-disposition": f'attachment; filename="{leaf}"',
            "x-content-sha256": version.content_sha256,
        },
    )


def _artifact_router(deps: LocalApiDeps) -> APIRouter:
    """Build the Artifact, Version, content, and provenance routes."""
    router = APIRouter()

    def list_artifacts(project_id: UUID) -> ArtifactList:
        """List this Project's Artifacts with their head Version position."""
        return _list_artifacts(deps, _live_project(deps, project_id))

    def read_artifact(project_id: UUID, artifact_id: UUID) -> ArtifactDetail:
        """Read one Artifact together with its Version history."""
        scope = _live_project(deps, project_id)
        record = _read_artifact(deps, scope, artifact_id)
        return ArtifactDetail(
            id=record.id,
            name=record.name,
            created_at=record.created_at,
            versions=tuple(
                _version_body(item)
                for item in _artifact_versions(deps, scope, artifact_id)
            ),
        )

    def list_versions(project_id: UUID, artifact_id: UUID) -> VersionList:
        """List one Artifact's Version history in commit order."""
        scope = _live_project(deps, project_id)
        _ = _read_artifact(deps, scope, artifact_id)
        return VersionList(
            artifact_id=artifact_id,
            versions=tuple(
                _version_body(item)
                for item in _artifact_versions(deps, scope, artifact_id)
            ),
        )

    def read_version(
        project_id: UUID,
        artifact_id: UUID,
        version_id: UUID,
    ) -> VersionBody:
        """Read one exact immutable Version."""
        scope = _live_project(deps, project_id)
        _ = _read_artifact(deps, scope, artifact_id)
        return _version_body(_owned_version(deps, scope, artifact_id, version_id))

    def read_provenance(
        project_id: UUID,
        artifact_id: UUID,
        version_id: UUID,
    ) -> ProvenanceBody:
        """Read one Version's pinned, independently recomputable provenance."""
        scope = _live_project(deps, project_id)
        _ = _read_artifact(deps, scope, artifact_id)
        version = _owned_version(deps, scope, artifact_id, version_id)
        isolation = (
            None
            if deps.runs is None
            else deps.runs.execution_isolation(scope, version.producing_execution_id)
        )
        return _provenance_body(version, isolation)

    def download_version(
        project_id: UUID,
        artifact_id: UUID,
        version_id: UUID,
    ) -> Response:
        """Return one Version's checksum-verified immutable bytes."""
        scope = _live_project(deps, project_id)
        record = _read_artifact(deps, scope, artifact_id)
        version = _owned_version(deps, scope, artifact_id, version_id)
        return _download(deps, scope, record, version)

    artifacts = "/projects/{project_id}/artifacts"
    one = f"{artifacts}/{{artifact_id}}"
    version = f"{one}/versions/{{version_id}}"
    router.add_api_route(artifacts, list_artifacts, methods=["GET"])
    router.add_api_route(one, read_artifact, methods=["GET"])
    router.add_api_route(f"{one}/versions", list_versions, methods=["GET"])
    router.add_api_route(version, read_version, methods=["GET"])
    router.add_api_route(f"{version}/provenance", read_provenance, methods=["GET"])
    router.add_api_route(f"{version}/content", download_version, methods=["GET"])
    return router


def _loader_refusal(
    reason: LoaderRejection,
    *,
    science_issue: str | None = None,
) -> LocalApiError:
    """Refuse a measurement intake with a closed LoaderRejection token."""
    return LocalApiError(
        HTTPStatus.UNPROCESSABLE_ENTITY,
        ApiErrorCode.INVALID_REQUEST,
        reason,
        science_issue=science_issue,
    )


def _decoded_size_from_base64(encoded: str) -> int:
    """Return the byte length of base64 payload without decoding it.

    Standard base64 expands 3 input bytes to 4 characters. Trailing ``=``
    pads mark missing terminal bytes, so the decoded size is
    ``len(encoded) * 3 // 4 - pad``. Computed before any allocation so a
    hostile base64 bomb is refused against PRODUCT_UPLOAD_DATA_BYTES without
    materializing the decoded buffer.
    """
    length = len(encoded)
    pad = encoded.endswith("==") * 2 or encoded.endswith("=")
    return length * 3 // 4 - pad


def _checked_data_filename(value: str) -> str:
    """Validate one upload leaf name; map any refusal to unsafe_filename."""
    try:
        return validate_local_name(value)
    except LocalNameError as error:
        raise _loader_refusal(LoaderRejection.UNSAFE_FILENAME) from error


def _prepare_stage_dir(parent: Path, leaf: str) -> Path:
    """Create one owner-only staging directory under an ensured parent.

    ``mkdir`` then ``chmod`` like :meth:`LocalPaths.ensure`: the mode is
    applied on the path itself, never trusted to ``mkdir``'s umask-masked
    argument, so a permissive umask cannot widen the layout.
    """
    stage = parent / leaf
    stage.mkdir(parents=True, exist_ok=True, mode=STAGING_DIR_MODE)
    stage.chmod(STAGING_DIR_MODE)
    return stage


def _write_staging_file(stage: Path, leaf: str, payload: bytes) -> Path:
    """Create one owner-only staging file from the first byte.

    Matches :func:`write_token_file`: ``O_EXCL|O_NOFOLLOW``, ``fchmod`` before
    the first write, never relying on umask-masked ``os.open`` mode alone.
    Returns the staged path so the loader can consume it.
    """
    staged_path = stage / leaf
    descriptor = os.open(
        staged_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        STAGING_FILE_MODE,
    )
    try:
        os.fchmod(descriptor, STAGING_FILE_MODE)
        with os.fdopen(descriptor, "wb") as handle:
            _ = handle.write(payload)
    except BaseException:
        staged_path.unlink(missing_ok=True)
        raise
    return staged_path


_LOADER_ERROR_TOKENS: Final[tuple[tuple[type[LoaderError], LoaderRejection], ...]] = (
    (ManifestNotFoundError, LoaderRejection.MANIFEST_NOT_FOUND),
    (DataFileNotFoundError, LoaderRejection.DATA_FILE_NOT_FOUND),
    (ManifestSyntaxError, LoaderRejection.MANIFEST_SYNTAX),
    (ManifestSchemaError, LoaderRejection.MANIFEST_SCHEMA),
    (ManifestKindMismatchError, LoaderRejection.MANIFEST_KIND_MISMATCH),
    (MalformedDataError, LoaderRejection.MALFORMED_DATA),
)


def _map_loader_error(error: LoaderError) -> LocalApiError:
    """Translate one loader refusal onto a closed LoaderRejection wire token."""
    if isinstance(error, MetadataRejectedError):
        issue = error.issues[0].code if error.issues else None
        return _loader_refusal(
            LoaderRejection.METADATA_REJECTED,
            science_issue=issue,
        )
    for error_type, token in _LOADER_ERROR_TOKENS:
        if isinstance(error, error_type):
            return _loader_refusal(token)
    return _loader_refusal(LoaderRejection.MALFORMED_DATA)


def _load_staged_probe(kind: str, data_path: Path) -> ProbeInput:
    """Dispatch load_probe by the required-explicit kind (keyword-only)."""
    policy = MetadataPolicy.STRICT
    modality = ProbeKind(kind)
    if modality is ProbeKind.SPECTRUM:
        return load_probe(spectrum=data_path, policy=policy)
    if modality is ProbeKind.TABLE:
        return load_probe(table=data_path, policy=policy)
    if modality is ProbeKind.IMAGE:
        return load_probe(image=data_path, policy=policy)
    return load_probe(report=data_path, policy=policy)


def _enforce_product_caps(kind: str, probe: ProbeInput) -> None:
    """Refuse product-path size limits that the module loaders leave open."""
    modality = ProbeKind(kind)
    if modality is ProbeKind.IMAGE and probe.image is not None:
        pixels = probe.image.width * probe.image.height
        if pixels > PRODUCT_UPLOAD_IMAGE_PIXELS:
            raise _loader_refusal(LoaderRejection.IMAGE_EXCEEDS_PRODUCT_PIXEL_CAP)
    if (
        modality is ProbeKind.SPECTRUM
        and probe.spectrum is not None
        and len(probe.spectrum.wavelengths) > PRODUCT_UPLOAD_SPECTRUM_POINTS
    ):
        raise _loader_refusal(LoaderRejection.SPECTRUM_EXCEEDS_PRODUCT_POINT_CAP)
    serialized = probe.model_dump_json().encode("utf-8")
    if len(serialized) > PRODUCT_PROBE_JSON_BYTES:
        raise _loader_refusal(LoaderRejection.DATA_TOO_LARGE)


def _probe_upload(
    deps: LocalApiDeps,
    project_id: UUID,
    body: ProbeUploadRequest,
) -> ProbeUploadBody:
    """Stage, load, and wipe one measurement; never create a durable record."""
    _ = _live_project(deps, project_id)
    filename = _checked_data_filename(body.data_filename)
    decoded_size = _decoded_size_from_base64(body.data_base64)
    if decoded_size > PRODUCT_UPLOAD_DATA_BYTES:
        raise _loader_refusal(LoaderRejection.DATA_TOO_LARGE)
    try:
        data_bytes = base64.b64decode(body.data_base64, validate=True)
    except ValueError as error:
        raise _loader_refusal(LoaderRejection.INVALID_BASE64) from error
    if len(data_bytes) > PRODUCT_UPLOAD_DATA_BYTES:
        raise _loader_refusal(LoaderRejection.DATA_TOO_LARGE)

    staging_root = deps.paths.root / STAGING_DIR_NAME
    staging_root.mkdir(parents=True, exist_ok=True, mode=STAGING_DIR_MODE)
    staging_root.chmod(STAGING_DIR_MODE)
    stage = _prepare_stage_dir(staging_root, str(deps.ids.new_uuid7()))
    manifest_leaf = f"{filename}.manifest.toml"
    try:
        data_path = _write_staging_file(stage, filename, data_bytes)
        _ = _write_staging_file(
            stage, manifest_leaf, body.manifest_toml.encode("utf-8")
        )
        try:
            probe = _load_staged_probe(body.kind, data_path)
        except LoaderError as error:
            raise _map_loader_error(error) from error
        _enforce_product_caps(body.kind, probe)
        document = probe.model_dump_json()
        digest = hashlib.sha256(document.encode("utf-8")).hexdigest()
        return ProbeUploadBody(
            scientific_input=cast(
                "dict[str, object]",
                json.loads(document),
            ),
            input_sha256=digest,
            kind=body.kind,
        )
    finally:
        if sys.exc_info()[0] is None:
            # No refusal in flight: a wipe that fails leaves measurement bytes
            # behind, so surface it instead of claiming a clean wipe.
            shutil.rmtree(stage)
        else:
            # The refusal being raised takes precedence; the loader retrying
            # an upload collides on O_EXCL and fails closed, so a leftover
            # directory cannot silently widen into a reused identity.
            shutil.rmtree(stage, ignore_errors=True)


def _input_router(deps: LocalApiDeps) -> APIRouter:
    """Build the project-scoped measurement-file intake route."""
    router = APIRouter()

    def probe_upload(
        project_id: UUID,
        body: ProbeUploadRequest,
    ) -> ProbeUploadBody:
        """Load one measurement file into typed ProbeInput JSON; no durable write."""
        return _probe_upload(deps, project_id, body)

    router.add_api_route(
        "/projects/{project_id}/inputs/probe",
        probe_upload,
        methods=["POST"],
        status_code=int(HTTPStatus.CREATED),
    )
    return router


def _invalid_request() -> LocalApiError:
    """Refuse a malformed plan, intent, or probe without quoting the input."""
    return LocalApiError(HTTPStatus.UNPROCESSABLE_ENTITY, ApiErrorCode.INVALID_REQUEST)


def _research_intent(body: ResearchIntentBody) -> ResearchIntent:
    """Parse one submitted intent through the science package, closed-code only."""
    try:
        return research_intent_from_mapping(
            body.model_dump(exclude_none=False),
        )
    except ResearchIntentError as error:
        raise _invalid_request() from error


def _probe_input(payload: Mapping[str, object]) -> ProbeInput:
    """Parse one ProbeInput JSON document without echoing caller values."""
    try:
        # Strict ProbeInput rejects Python lists for tuple fields; round-trip
        # through JSON so the same document a browser would send is accepted.
        return ProbeInput.model_validate_json(json.dumps(payload))
    except ValidationError as error:
        raise _invalid_request() from error


def _live_session(
    deps: LocalApiDeps,
    scope: ArtifactScope,
    session_id: UUID,
) -> SessionRecord:
    """Read one live Session in an active Project, or refuse closed-code."""
    record = deps.store.session(scope, session_id)
    if record is None:
        raise LocalApiError(HTTPStatus.NOT_FOUND, ApiErrorCode.NOT_FOUND)
    if record.archived:
        raise LocalApiError(HTTPStatus.CONFLICT, ApiErrorCode.SESSION_ARCHIVED)
    return record


def _bound_runtime(
    deps: LocalApiDeps,
    *,
    project_id: UUID,
    session_id: UUID | None,
) -> LocalArtifactRuntime:
    """Assemble one execution runtime on the surface's injected clock.

    `assemble_artifact_runtime` hardcodes :class:`SystemClock`. Plan, approval,
    and run-start routes must share `deps.clock` so a test can advance time and
    so granted/expired timestamps agree with the rest of the surface.
    """
    execution = deps.ids.new_uuid7()
    scope = local_scope(project_id)
    watcher = OutputWatcher(
        deps.ids,
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
        deps.store,
        watcher,
        deps.ids,
        deps.clock,
        load_download_signing_key(deps.paths),
    )
    return LocalArtifactRuntime(
        service=service,
        watcher=watcher,
        scope=scope,
        execution_id=execution,
        paths=deps.paths,
        store=deps.store,
        ids=deps.ids,
        clock=deps.clock,
        session_id=session_id,
    )


def _plan_body(record: ActionPlanRecord) -> ActionPlanBody:
    """Project one ActionPlan onto the wire."""
    return ActionPlanBody(
        plan_id=record.id,
        plan_sha256=record.plan_sha256,
        research_intent_sha256=record.research_intent_sha256,
        created_at=record.created_at,
    )


def _approval_body(record: PlanApprovalRecord) -> ApprovalBody:
    """Project one approval and its consumption state onto the wire."""
    return ApprovalBody(
        approval_id=record.id,
        plan_id=record.plan_id,
        plan_sha256=record.plan_sha256,
        research_intent_sha256=record.research_intent_sha256,
        granted_at=record.granted_at,
        expires_at=record.expires_at,
        consumed_at=record.consumed_at,
        consumed_by_run_id=record.consumed_by_run_id,
    )


def _action_plan_error(error: ActionPlanError) -> LocalApiError:
    """Translate one plan/approval/run-queue refusal onto a closed code."""
    if error.outcome is StoreOutcome.ARCHIVED:
        return LocalApiError(HTTPStatus.CONFLICT, ApiErrorCode.PROJECT_ARCHIVED)
    if error.outcome is StoreOutcome.ASSOCIATION_EXISTS:
        if error.code is WorkbenchRejection.APPROVAL_REJECTED:
            return LocalApiError(HTTPStatus.CONFLICT, ApiErrorCode.APPROVAL_EXISTS)
        return LocalApiError(HTTPStatus.CONFLICT, ApiErrorCode.NAME_IN_USE)
    if error.code is WorkbenchRejection.PLAN_REJECTED:
        return LocalApiError(HTTPStatus.NOT_FOUND, ApiErrorCode.NOT_FOUND)
    return LocalApiError(HTTPStatus.NOT_FOUND, ApiErrorCode.NOT_FOUND)


_APPROVAL_OUTCOME_ERRORS: Final[Mapping[ApprovalOutcome, LocalApiError]] = {
    ApprovalOutcome.NOT_FOUND: LocalApiError(
        HTTPStatus.NOT_FOUND, ApiErrorCode.APPROVAL_NOT_FOUND
    ),
    ApprovalOutcome.EXPIRED: LocalApiError(
        HTTPStatus.CONFLICT, ApiErrorCode.APPROVAL_EXPIRED
    ),
    ApprovalOutcome.REPLAYED: LocalApiError(
        HTTPStatus.CONFLICT, ApiErrorCode.APPROVAL_CONSUMED
    ),
    ApprovalOutcome.DIGEST_MISMATCH: LocalApiError(
        HTTPStatus.CONFLICT, ApiErrorCode.APPROVAL_DIGEST_MISMATCH
    ),
    ApprovalOutcome.FORBIDDEN: LocalApiError(
        HTTPStatus.FORBIDDEN, ApiErrorCode.APPROVAL_FORBIDDEN
    ),
    ApprovalOutcome.ARCHIVED: LocalApiError(
        HTTPStatus.CONFLICT, ApiErrorCode.PROJECT_ARCHIVED
    ),
    ApprovalOutcome.EXECUTION_CLAIMED: LocalApiError(
        HTTPStatus.CONFLICT,
        ApiErrorCode.RUN_REJECTED,
        RunRejection.EXECUTION_REPLAYED,
    ),
}


def _approval_outcome_error(outcome: ApprovalOutcome) -> LocalApiError:
    """Translate one approval-consumption refusal onto a closed wire code."""
    return _APPROVAL_OUTCOME_ERRORS.get(
        outcome,
        LocalApiError(HTTPStatus.NOT_FOUND, ApiErrorCode.APPROVAL_NOT_FOUND),
    )


def _run_created(run: WorkbenchRun) -> RunCreatedBody:
    """Project one completed workbench run onto the create-run receipt."""
    return RunCreatedBody(
        run_id=run.run_id,
        execution_id=run.provenance.execution_id,
        state="completed",
        output_version_ids=tuple(item.version.id for item in run.outputs),
        execution_isolation="in_process",
    )


def _require_unspent_approval(
    deps: LocalApiDeps,
    scope: ArtifactScope,
    approval_id: UUID,
    intent: ResearchIntent,
) -> tuple[ActionPlanRecord, PlanApprovalRecord]:
    """Load one usable approval and its plan, refusing before any mutation.

    Digest mismatch, expiry, and prior consumption are decided here so a
    refused run-start never queues a Run, claims an execution, or spends the
    approval. The store still re-enforces the same checks inside `start_run`.
    """
    approval = deps.store.plan_approval(scope, approval_id)
    if approval is None:
        raise LocalApiError(HTTPStatus.NOT_FOUND, ApiErrorCode.APPROVAL_NOT_FOUND)
    if intent.sha256 != approval.research_intent_sha256:
        raise LocalApiError(
            HTTPStatus.CONFLICT,
            ApiErrorCode.APPROVAL_DIGEST_MISMATCH,
        )
    if approval.consumed_at is not None or approval.consumed_by_run_id is not None:
        raise LocalApiError(HTTPStatus.CONFLICT, ApiErrorCode.APPROVAL_CONSUMED)
    if deps.clock.now() >= approval.expires_at:
        raise LocalApiError(HTTPStatus.CONFLICT, ApiErrorCode.APPROVAL_EXPIRED)
    plan = deps.store.action_plan(scope, approval.plan_id)
    if plan is None:
        raise LocalApiError(HTTPStatus.NOT_FOUND, ApiErrorCode.PLAN_NOT_FOUND)
    return plan, approval


def _plan_router(deps: LocalApiDeps) -> APIRouter:
    """Build the ActionPlan and approval routes that gate Run starts."""
    router = APIRouter()
    store = deps.store

    def create_plan(
        project_id: UUID,
        body: CreateActionPlanRequest,
    ) -> ActionPlanCreatedBody:
        """Create one immutable ActionPlan bound to a live Session."""
        scope = _live_project(deps, project_id)
        _ = _live_session(deps, scope, body.session_id)
        intent = _research_intent(body.research_intent)
        runtime = _bound_runtime(
            deps,
            project_id=project_id,
            session_id=body.session_id,
        )
        try:
            plan = create_action_plan(runtime, intent)
        except ActionPlanError as error:
            raise _action_plan_error(error) from error
        return ActionPlanCreatedBody(
            plan_id=plan.id,
            session_id=body.session_id,
            plan_sha256=plan.plan_sha256,
            research_intent_sha256=plan.research_intent_sha256,
            created_at=plan.created_at,
        )

    def read_plan(project_id: UUID, plan_id: UUID) -> ActionPlanBody:
        """Read one ActionPlan by identity."""
        scope = _live_project(deps, project_id)
        plan = store.action_plan(scope, plan_id)
        if plan is None:
            raise LocalApiError(HTTPStatus.NOT_FOUND, ApiErrorCode.PLAN_NOT_FOUND)
        return _plan_body(plan)

    def create_approval(
        project_id: UUID,
        plan_id: UUID,
        body: CreateApprovalRequest,
    ) -> ApprovalBody:
        """Grant the one approval this plan may ever carry, with a fixed TTL."""
        _ = body
        scope = _live_project(deps, project_id)
        plan = store.action_plan(scope, plan_id)
        if plan is None:
            raise LocalApiError(HTTPStatus.NOT_FOUND, ApiErrorCode.PLAN_NOT_FOUND)
        # Approval needs no Session binding: granting consumes nothing and the
        # runtime's session_id is only read by the run path.
        runtime = _bound_runtime(
            deps,
            project_id=project_id,
            session_id=None,
        )
        try:
            approval = approve_action_plan(
                runtime,
                plan,
                ttl=DEFAULT_APPROVAL_TTL,
            )
        except ActionPlanError as error:
            raise _action_plan_error(error) from error
        return _approval_body(approval)

    def read_approval(project_id: UUID, approval_id: UUID) -> ApprovalBody:
        """Read one approval and whether it has been consumed."""
        scope = _live_project(deps, project_id)
        approval = store.plan_approval(scope, approval_id)
        if approval is None:
            raise LocalApiError(HTTPStatus.NOT_FOUND, ApiErrorCode.APPROVAL_NOT_FOUND)
        return _approval_body(approval)

    plans = "/projects/{project_id}/action-plans"
    router.add_api_route(
        plans,
        create_plan,
        methods=["POST"],
        status_code=int(HTTPStatus.CREATED),
    )
    router.add_api_route(f"{plans}/{{plan_id}}", read_plan, methods=["GET"])
    router.add_api_route(
        f"{plans}/{{plan_id}}/approvals",
        create_approval,
        methods=["POST"],
        status_code=int(HTTPStatus.CREATED),
    )
    router.add_api_route(
        "/projects/{project_id}/approvals/{approval_id}",
        read_approval,
        methods=["GET"],
    )
    return router


def _start_run(
    deps: LocalApiDeps,
    project_id: UUID,
    body: CreateRunRequest,
) -> RunCreatedBody:
    """Start one approved analysis synchronously under a live Session."""
    intent = _research_intent(body.research_intent)
    source = _probe_input(body.scientific_input)
    if body.input_sha256 is not None:
        digest = hashlib.sha256(source.model_dump_json().encode("utf-8")).hexdigest()
        if digest != body.input_sha256:
            raise LocalApiError(
                HTTPStatus.CONFLICT,
                ApiErrorCode.INPUT_DIGEST_MISMATCH,
            )
    scope = _live_project(deps, project_id)
    _ = _live_session(deps, scope, body.session_id)
    plan, approval = _require_unspent_approval(
        deps,
        scope,
        body.approval_id,
        intent,
    )
    runtime = _bound_runtime(
        deps,
        project_id=project_id,
        session_id=body.session_id,
    )
    approved = ApprovedPlan(plan=plan, approval=approval)
    try:
        run = run_analysis(runtime, intent, source, approved)
    except PlanApprovalError as error:
        raise _approval_outcome_error(error.outcome) from error
    except WorkbenchRunError as error:
        if error.code is WorkbenchRejection.EXECUTION_REPLAYED:
            raise LocalApiError(
                HTTPStatus.CONFLICT,
                ApiErrorCode.RUN_REJECTED,
                RunRejection.EXECUTION_REPLAYED,
            ) from error
        raise LocalApiError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            ApiErrorCode.INVALID_REQUEST,
        ) from error
    except ActionPlanError as error:
        raise _action_plan_error(error) from error
    return _run_created(run)


def _run_router(deps: LocalApiDeps) -> APIRouter:
    """Build the Run start route and the optional read surface.

    POST `/runs` starts an approved analysis through the workbench and is
    always registered. GET `/runs` still answers through :class:`RunSurface`
    and remains `501 run_surface_unavailable` until a read implementation is
    bound, so an empty list is never fabricated for an unbound surface.
    """
    router = APIRouter()

    def _surface() -> RunSurface:
        surface = deps.runs
        if surface is None:
            raise LocalApiError(
                HTTPStatus.NOT_IMPLEMENTED,
                ApiErrorCode.RUN_SURFACE_UNAVAILABLE,
            )
        return surface

    def create_run(project_id: UUID, body: CreateRunRequest) -> RunCreatedBody:
        """Start one approved analysis and return its completed receipt."""
        return _start_run(deps, project_id, body)

    def list_runs(project_id: UUID) -> Response:
        """List one Project's Runs, once a Run implementation is bound."""
        surface = _surface()
        scope = _live_project(deps, project_id)
        return JSONResponse(content={"runs": list(surface.list_runs(scope))})

    def read_run(project_id: UUID, run_id: UUID) -> Response:
        """Read one Run, once a Run implementation is bound."""
        surface = _surface()
        scope = _live_project(deps, project_id)
        record = surface.read_run(scope, run_id)
        if record is None:
            raise LocalApiError(HTTPStatus.NOT_FOUND, ApiErrorCode.NOT_FOUND)
        return JSONResponse(content=dict(record))

    runs = "/projects/{project_id}/runs"
    router.add_api_route(
        runs,
        create_run,
        methods=["POST"],
        status_code=int(HTTPStatus.CREATED),
    )
    router.add_api_route(runs, list_runs, methods=["GET"])
    router.add_api_route(f"{runs}/{{run_id}}", read_run, methods=["GET"])
    return router


def _turn_refusal(failure: ModelCallFailure) -> Response:
    """Answer one provider-side failure token with the closed `turn_failed` shape.

    `timeout` maps to 504 and every other provider-neutral failure token to
    502. The body carries the failure token and nothing else.
    """
    status = (
        HTTPStatus.GATEWAY_TIMEOUT
        if failure is ModelCallFailure.TIMEOUT
        else HTTPStatus.BAD_GATEWAY
    )
    body = TurnFailedBody(reason=failure)
    return Response(
        content=body.model_dump_json().encode("utf-8"),
        status_code=int(status),
        media_type="application/json",
    )


def _turn_failed(error: ModelCallError) -> Response:
    """Answer one provider error with the closed `turn_failed` shape.

    The error is already constant-assembled inside :mod:`nipo_local.modelcall`,
    so no provider prose, header, or echoed credential can reach it here.
    """
    return _turn_refusal(error.failure)


def _parse_turn_model(model_id: str) -> str:
    """Shape-check one requested selection without any provider contact.

    Returns the provider id the parsed id names. Every refusal here is
    caller-side: no provider is contacted, no credential is unsealed, and
    no row is written.
    """
    try:
        spec, _ = parse_model_id(model_id)
    except MalformedModelIdError as error:
        raise LocalApiError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            ApiErrorCode.MODEL_ID_MALFORMED,
        ) from error
    except UnknownProviderError as error:
        raise LocalApiError(
            HTTPStatus.NOT_FOUND,
            ApiErrorCode.UNKNOWN_PROVIDER,
        ) from error
    return spec.provider_id


def _turn_selection(deps: LocalApiDeps, model_id: str) -> str:
    """Gate the requested selection's availability before provider contact.

    Every refusal here is caller-side: no provider is contacted, no
    credential is unsealed, and no row is written. Status resolution goes
    through :meth:`ProviderRegistry.status`, which answers from `has` and the
    environment without decrypting anything. Returns the provider id the
    parsed id named.
    """
    provider_id = _parse_turn_model(model_id)
    spec, _ = parse_model_id(model_id)
    try:
        if model_id not in deps.registry.enabled_models():
            raise LocalApiError(
                HTTPStatus.CONFLICT,
                ApiErrorCode.MODEL_NOT_ENABLED,
            )
        if (
            spec.requires_key
            and deps.registry.status(spec.provider_id) is ProviderStatus.NOT_SET_UP
        ):
            raise LocalApiError(
                HTTPStatus.CONFLICT,
                ApiErrorCode.PROVIDER_NOT_CONFIGURED,
            )
    except LocalStateUnreadableError as error:
        raise LocalApiError(
            HTTPStatus.SERVICE_UNAVAILABLE,
            ApiErrorCode.LOCAL_STATE_UNREADABLE,
        ) from error
    except CredentialBackendError as error:
        raise LocalApiError(
            HTTPStatus.SERVICE_UNAVAILABLE,
            ApiErrorCode.CREDENTIAL_BACKEND_UNAVAILABLE,
        ) from error
    return provider_id


def _turn_draft(  # noqa: PLR0913 - one parameter per wire field keeps the call site honest
    deps: LocalApiDeps,
    scope: ArtifactScope,
    run_id: UUID,
    record: TurnRecord,
    *,
    prompt_digest: str,
    response_digest: str,
) -> RunTurnDraft:
    """Assemble the non-secret turn draft the store positions in-transaction."""
    return RunTurnDraft(
        org_id=scope.org_id,
        project_id=scope.project_id,
        run_id=run_id,
        turn_id=deps.ids.new_uuid7(),
        provider_id=record.provider_id,
        model_id=record.model_id,
        model_name=record.model_name,
        adapter=record.adapter.value,
        connection=record.connection,
        request_count=record.request_count,
        response_bytes=record.response_bytes,
        text_characters=record.text_characters,
        stop_reason=record.stop_reason,
        input_tokens=record.input_tokens,
        output_tokens=record.output_tokens,
        prompt_sha256=prompt_digest,
        response_sha256=response_digest,
        created_at=deps.clock.now(),
    )


def _pinned_turn_selection(
    deps: LocalApiDeps,
    scope: ArtifactScope,
    run_id: UUID,
) -> tuple[str, str] | None:
    """Read the canonical completed seq-1 selection, if the Run has one."""
    turn = deps.store.first_run_turn(scope, run_id)
    if turn is None:
        return None
    return turn.provider_id, turn.model_id


def _create_turn(
    deps: LocalApiDeps,
    project_id: UUID,
    run_id: UUID,
    body: CreateTurnRequest,
) -> TurnBody | Response:
    """Serialize one Run's turn through its canonical completed selection."""
    scope = _live_project(deps, project_id)
    if deps.store.run(scope, run_id) is None:
        raise LocalApiError(HTTPStatus.NOT_FOUND, ApiErrorCode.NOT_FOUND)
    provider_id = _parse_turn_model(body.model_id)
    with deps.turn_locks.for_run(run_id):
        pinned = _pinned_turn_selection(deps, scope, run_id)
        if pinned is not None and pinned != (provider_id, body.model_id):
            raise LocalApiError(
                HTTPStatus.CONFLICT,
                ApiErrorCode.MODEL_SELECTION_LOCKED,
            )
        return _create_turn_locked(deps, scope, run_id, body)


def _create_turn_locked(
    deps: LocalApiDeps,
    scope: ArtifactScope,
    run_id: UUID,
    body: CreateTurnRequest,
) -> TurnBody | Response:
    """Call and record one turn while the API-runtime Run lock is held."""
    _ = _turn_selection(deps, body.model_id)
    client = deps.turn_client
    if client is None:
        client = ModelCallClient(deps.registry)
    request = ModelRequest(
        messages=tuple(
            CallMessage(role=message.role, content=message.content)
            for message in body.messages
        ),
        max_output_tokens=body.max_output_tokens,
    )
    parts: list[str] = []
    record: TurnRecord | None = None
    try:
        for event in client.stream(body.model_id, request):
            if isinstance(event, TextDelta):
                parts.append(event.text)
            elif isinstance(event, Completed):
                record = event.turn
    except ModelCallError as error:
        return _turn_failed(error)
    if record is None:  # pragma: no cover - stream always ends completed/failed
        raise LocalApiError(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            ApiErrorCode.INTERNAL_ERROR,
        )
    text = "".join(parts)
    # `prompt_sha256` covers the canonical request document exactly as
    # validated; `response_sha256` covers the exact UTF-8 bytes of the
    # answer returned below. Both are recomputable from what the caller sent
    # and received, which is the audit linkage that replaces retained prose.
    prompt_digest = hashlib.sha256(
        body.model_dump_json().encode("utf-8"),
    ).hexdigest()
    response_digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if record.model_id != body.model_id:
        # The provider answered as a model other than the one requested; the
        # run's pin must never record a selection the caller did not make.
        return _turn_refusal(ModelCallFailure.MALFORMED_RESPONSE)
    draft = _turn_draft(
        deps,
        scope,
        run_id,
        record,
        prompt_digest=prompt_digest,
        response_digest=response_digest,
    )
    outcome, stored = deps.store.record_run_turn(scope, draft)
    if outcome is not StoreOutcome.CREATED or stored is None:
        raise LocalApiError(
            HTTPStatus.CONFLICT,
            ApiErrorCode.RUN_REJECTED,
            RunRejection.TURN_CONFLICT,
        )
    turn = stored
    return TurnBody(
        turn_id=turn.turn_id,
        run_id=turn.run_id,
        seq=turn.seq,
        provider_id=turn.provider_id,
        model_id=turn.model_id,
        model_name=turn.model_name,
        adapter=turn.adapter,
        connection=turn.connection,
        request_count=turn.request_count,
        response_bytes=turn.response_bytes,
        text_characters=turn.text_characters,
        stop_reason=turn.stop_reason,
        input_tokens=turn.input_tokens,
        output_tokens=turn.output_tokens,
        prompt_sha256=turn.prompt_sha256,
        response_sha256=turn.response_sha256,
        created_at=turn.created_at,
        text=text,
    )


def _turn_router(deps: LocalApiDeps) -> APIRouter:
    """Build the run-bound model turn route.

    One synchronous turn: the credential is resolved at call time, the
    stream is aggregated server-side, and the answer returns as one JSON
    body. There is no streaming to the browser, no retry, and no second
    provider, model, or credential attempt -- `request_count` on the
    persisted record is the observable form of that rule. A caller that
    disconnects mid-request simply never receives the response; a stream
    cut on the provider side surfaces as `transport` (or `timeout`) and
    persists no row.
    """
    router = APIRouter()

    def create_turn(
        project_id: UUID,
        run_id: UUID,
        body: CreateTurnRequest,
    ) -> TurnBody | Response:
        """Run one turn and return the aggregated answer and its record."""
        return _create_turn(deps, project_id, run_id, body)

    router.add_api_route(
        "/projects/{project_id}/runs/{run_id}/turns",
        create_turn,
        methods=["POST"],
        status_code=int(HTTPStatus.CREATED),
        # The union return annotation is TurnBody on success or an already
        # built refusal Response; a response model cannot express that, and
        # the refusal path must stay the closed TurnFailedBody shape.
        response_model=None,
    )
    return router


_REVIEW_REFUSALS: Final[dict[ReviewRejection, tuple[HTTPStatus, ApiErrorCode]]] = {
    ReviewRejection.RUN_NOT_FOUND: (HTTPStatus.NOT_FOUND, ApiErrorCode.NOT_FOUND),
    ReviewRejection.PROJECT_ARCHIVED: (
        HTTPStatus.CONFLICT,
        ApiErrorCode.PROJECT_ARCHIVED,
    ),
    ReviewRejection.NO_PINNED_EVIDENCE: (
        HTTPStatus.CONFLICT,
        ApiErrorCode.REVIEW_EVIDENCE_MISSING,
    ),
    ReviewRejection.STORE_UNAVAILABLE: (
        HTTPStatus.SERVICE_UNAVAILABLE,
        ApiErrorCode.STORE_UNAVAILABLE,
    ),
}


def _review_coverage() -> tuple[ReviewCoverageBody, ...]:
    """Project every rule's declared coverage and its structural limits.

    Sent with every Review response rather than published once, because the
    limits are only useful beside the verdict they qualify. `limits` is never
    empty for any rule: a rule that could establish everything it names would
    not need a disclosure, and none of RV01-RV05 is in that position.
    """
    return tuple(
        ReviewCoverageBody(
            rule_id=item.rule_id.value,
            statement=item.statement,
            checks=item.checks,
            limits=item.limits,
        )
        for item in RULE_COVERAGE
    )


def _review_body(persisted: PersistedReview) -> ReviewBody:
    """Project one stored Review, its findings, and its coverage onto the wire.

    The summary verdict is computed from the persisted findings using the
    Reviewer's own precedence, in which `inconclusive` outranks `pass`. A
    Review with no submitted finding summarizes as `inconclusive`: nothing was
    checked, so nothing passed.
    """
    record = persisted.review
    findings = persisted.findings
    return ReviewBody(
        id=record.id,
        source_run_id=record.source_run_id,
        state=record.state.value,
        verdict=summary_verdict(item.verdict for item in findings).value,
        pinned_input_sha256=record.pinned_input_sha256,
        pinned_artifact_version_ids=record.pinned_artifact_version_ids,
        pinned_execution_ids=record.pinned_execution_ids,
        created_at=record.created_at,
        updated_at=record.updated_at,
        findings_submitted_at=record.findings_submitted_at,
        error_type=record.error_type,
        error_code=record.error_code,
        findings=tuple(
            ReviewFindingBody(
                sequence=item.sequence,
                rule_id=item.rule_id.value,
                verdict=item.verdict.value,
                status=item.status.value,
                code=item.code,
                message=item.message,
                artifact_version_ids=item.artifact_version_ids,
                execution_ids=item.execution_ids,
                created_at=item.created_at,
            )
            for item in findings
        ),
        coverage=_review_coverage(),
    )


def _review_error(error: ReviewRejectionError) -> LocalApiError:
    """Translate one Review refusal onto the surface's closed error shape."""
    status, code = _REVIEW_REFUSALS[error.reason]
    return LocalApiError(status, code)


def _review_router(deps: LocalApiDeps) -> APIRouter:
    """Build the persisted, trace-only Review routes.

    Review is its own resource over pinned evidence, never an inline mutation
    of the Run: neither route below touches the Run, its outputs, or any
    Version. `POST` is idempotent by pinned evidence rather than by request,
    so a researcher who submits twice gets the same Review both times instead
    of two Reviews that could disagree about the same bytes.
    """
    router = APIRouter()

    def open_review(project_id: UUID, run_id: UUID) -> ReviewBody:
        """Review one Run's pinned evidence, or return the existing Review."""
        scope = _live_project(deps, project_id)
        job = ReviewJob(
            store=deps.store,
            scope=scope,
            ids=deps.ids,
            clock=deps.clock,
        )
        try:
            persisted = review_run(job, run_id)
        except ReviewRejectionError as error:
            raise _review_error(error) from error
        return _review_body(persisted)

    def read_review(project_id: UUID, run_id: UUID) -> ReviewBody:
        """Read the Review of one Run, refusing to invent one that is absent.

        A missing Review is `review_not_found`, distinct from a missing Run.
        Reporting "no findings" here would read as "this Run was reviewed and
        nothing was wrong", which is the opposite of the truth.
        """
        scope = _live_project(deps, project_id)
        try:
            persisted = persisted_review(deps.store, scope, run_id)
        except ArtifactStoreError as error:
            raise LocalApiError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                ApiErrorCode.STORE_UNAVAILABLE,
            ) from error
        if persisted is None:
            raise LocalApiError(HTTPStatus.NOT_FOUND, ApiErrorCode.REVIEW_NOT_FOUND)
        return _review_body(persisted)

    review = "/projects/{project_id}/runs/{run_id}/review"
    router.add_api_route(review, read_review, methods=["GET"])
    router.add_api_route(
        review,
        open_review,
        methods=["POST"],
        status_code=int(HTTPStatus.CREATED),
    )
    return router


# -------------------------------------------------------------------- export
#
# `exportpack.py` was complete and fully tested, and there was no way to reach
# it from the product: Export was the one stage of the ordered chain with no
# route and no screen. These routes are that reach, and they are deliberately
# unable to choose a Version on the caller's behalf.


_EXPORT_REFUSALS: Final[
    dict[ExportRunRejection, tuple[HTTPStatus, ApiErrorCode, bool]]
] = {
    ExportRunRejection.RUN_NOT_FOUND: (
        HTTPStatus.NOT_FOUND,
        ApiErrorCode.NOT_FOUND,
        False,
    ),
    ExportRunRejection.NO_COMMITTED_OUTPUTS: (
        HTTPStatus.CONFLICT,
        ApiErrorCode.EXPORT_EVIDENCE_MISSING,
        False,
    ),
    ExportRunRejection.SELECTION_EMPTY: (
        HTTPStatus.BAD_REQUEST,
        ApiErrorCode.EXPORT_SELECTION_REJECTED,
        True,
    ),
    ExportRunRejection.SELECTION_DUPLICATE: (
        HTTPStatus.BAD_REQUEST,
        ApiErrorCode.EXPORT_SELECTION_REJECTED,
        True,
    ),
    ExportRunRejection.SELECTION_NOT_PINNED_TO_RUN: (
        HTTPStatus.BAD_REQUEST,
        ApiErrorCode.EXPORT_SELECTION_REJECTED,
        True,
    ),
    ExportRunRejection.PACK_REFUSED: (
        HTTPStatus.CONFLICT,
        ApiErrorCode.EXPORT_REFUSED,
        True,
    ),
    ExportRunRejection.PACK_NOT_FOUND: (
        HTTPStatus.NOT_FOUND,
        ApiErrorCode.EXPORT_PACK_NOT_FOUND,
        False,
    ),
    ExportRunRejection.STORE_UNAVAILABLE: (
        HTTPStatus.SERVICE_UNAVAILABLE,
        ApiErrorCode.STORE_UNAVAILABLE,
        False,
    ),
    ExportRunRejection.EXPORTS_UNREADABLE: (
        HTTPStatus.SERVICE_UNAVAILABLE,
        ApiErrorCode.LOCAL_STATE_UNREADABLE,
        True,
    ),
}
"""Every Export refusal, its status, its code, and whether it names a reason.

The reason is withheld for the four refusals where it would only repeat the
code. It is carried for the rest, because "the pack was refused" and "the pack
was refused because a member carried credential material" are different
sentences and a researcher needs the second one.
"""


def _export_error(error: ExportRunError) -> LocalApiError:
    """Translate one Export refusal onto the surface's closed error shape."""
    status, code, detailed = _EXPORT_REFUSALS[error.reason]
    if not detailed:
        return LocalApiError(status, code)
    return LocalApiError(status, code, error.pack_reason or error.reason)


def _export_call[ResultT](operation: Callable[[], ResultT]) -> ResultT:
    """Run one Export operation, normalizing its refusals onto the wire."""
    try:
        return operation()
    except ExportRunError as error:
        raise _export_error(error) from error
    except ArtifactStoreError as error:
        raise LocalApiError(
            HTTPStatus.SERVICE_UNAVAILABLE,
            ApiErrorCode.STORE_UNAVAILABLE,
        ) from error


def _candidate_body(candidate: ExportCandidate) -> ExportCandidateBody:
    """Project one selectable, already-pinned Artifact Version onto the wire."""
    return ExportCandidateBody(
        artifact_id=candidate.artifact_id,
        artifact_version_id=candidate.artifact_version_id,
        artifact_name=candidate.artifact_name,
        output_name=candidate.output_name,
        role=candidate.role,
        sequence=candidate.sequence,
        version_no=candidate.version_no,
        pack_path=candidate.pack_path,
        size_bytes=candidate.size_bytes,
        media_type=candidate.media_type,
        content_sha256=candidate.content_sha256,
    )


def _pack_body(pack: ProducedPack, project_id: UUID) -> ExportPackBody:
    """Project one produced pack, quoting its own manifest for the disclosures."""
    return ExportPackBody(
        pack_id=pack.pack_id,
        run_id=pack.run_id,
        project_id=project_id,
        created_at=pack.created_at,
        size_bytes=pack.size_bytes,
        manifest_sha256=pack.manifest_sha256,
        selection=pack.selection,
        entries=tuple(
            PackEntryBody(
                kind=item.kind,
                path=item.path,
                sha256=item.sha256,
                size_bytes=item.size_bytes,
            )
            for item in pack.entries
        ),
        pack_documents=tuple(
            PackDocumentBody(path=path, included=included)
            for path, included in pack.documents
        ),
        attested_documents=pack.attested,
        disclosures=dict(pack.disclosures),
        verification=dict(pack.verification),
    )


def _stored_pack_body(pack: StoredPack) -> StoredPackBody:
    """Project one pack found on disk, without naming where it sits.

    The only fields copied out of the pack's manifest are the four scalars
    :class:`StoredPack` already lifted. Nothing here forwards a manifest object
    wholesale, so no value a pack carries can reach a listing by being passed
    through untouched.
    """
    return StoredPackBody(
        pack_id=pack.pack_id,
        size_bytes=pack.size_bytes,
        modified_at=pack.modified_at,
        manifest_readable=pack.manifest_readable,
        run_id=pack.run_id,
        created_at=pack.created_at,
        selection=pack.selection,
        entry_count=pack.entry_count,
    )


def _pack_list_body(stored: StoredPacks, project_id: UUID) -> ExportPackListBody:
    """Project one Project's stored packs together with what they cost."""
    return ExportPackListBody(
        project_id=project_id,
        packs=tuple(_stored_pack_body(item) for item in stored.packs),
        pack_count=len(stored.packs),
        total_size_bytes=stored.total_size_bytes,
        budget_bytes=EXPORTS_BUDGET_BYTES,
        over_budget=stored.total_size_bytes > EXPORTS_BUDGET_BYTES,
        undescribed_count=stored.undescribed_count,
    )


def _export_isolation(
    deps: LocalApiDeps,
    scope: ArtifactScope,
    run_id: UUID,
) -> str | None:
    """Return the isolation this Run's execution disclosed, or None.

    `None` is a real answer, exactly as it is on a Version's provenance: an
    execution this installation cannot answer for reports nothing rather than a
    defaulted `"in_process"`, and the screen renders its "assume nothing"
    disclosure for it.
    """
    try:
        execution = deps.store.execution_for_run(scope, run_id)
    except ArtifactStoreError:
        return None
    return None if execution is None else execution.execution_isolation


@final
class _PackResponse(Response):
    """Send one produced pack to the wire in bounded chunks.

    Not `StreamingResponse`. That class races a `http.disconnect` listener
    against the body, and :mod:`nipo_local.apiserver` -- the small HTTP/1.1
    server this application ships, which answers one request per connection --
    queues the disconnect as soon as the request body is delivered. The race is
    always lost there and the pack is sent as zero bytes, which is precisely
    the kind of green-but-empty result a download must not produce.

    The file is read on a worker thread, exactly as `StreamingResponse` reads
    an iterator, so a 500 MiB pack never blocks the single event loop this
    listener runs on.

    The chunks are now genuinely end to end. :class:`nipo_local.apiserver._Wire`
    writes each `http.response.body` event to the socket and drains before
    accepting the next, so what this response reads a mebibyte at a time is
    also *sent* a mebibyte at a time and nothing holds the pack whole. The
    declared `content-length` is what the server frames the response with,
    which is why it is stated from the `stat` size rather than discovered while
    sending: it gives a browser a real progress bar for a half-gigabyte
    download, and it turns a transfer that dies half way through into a
    truncation the client detects rather than a short file that looks complete.

    `accept-ranges` is deliberately absent: a capability is spent by its first
    use, so a ranged re-request could not be honoured, and advertising range
    support would be a promise this surface cannot keep.

    The generator is closed on the way out whatever happens, including when
    `send` raises because the researcher cancelled the download. Leaving it to
    be finalized whenever the loop next collects async generators would hold
    the pack's file descriptor open for an indefinite stretch after the socket
    is already gone.
    """

    def __init__(self, path: Path, size: int, pack_id: UUID) -> None:
        """Bind this response to one pack file and the length it will send."""
        super().__init__(
            content=b"",
            headers={
                "content-type": PACK_MEDIA_TYPE,
                "content-length": str(size),
                "content-disposition": (
                    f'attachment; filename="nipo-export-{pack_id}.zip"'
                ),
            },
        )
        self._path = path

    @override
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Emit the status line, then the file, then the terminating event."""
        del receive
        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": self.raw_headers,
            }
        )
        if cast("str", scope.get("method", "")) != "HEAD":
            await self._emit(send)
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    async def _emit(self, send: Send) -> None:
        """Read the pack a chunk at a time and hand each one straight on."""
        chunks = stream_pack(self._path)
        try:
            async for chunk in iterate_in_threadpool(chunks):
                await send(
                    {"type": "http.response.body", "body": chunk, "more_body": True}
                )
        finally:
            chunks.close()


def _download_response(deps: LocalApiDeps, ticket: DownloadTicket) -> Response:
    """Return one produced pack as an attachment, read in bounded chunks."""
    scope = _scope_for(deps, ticket.project_id)
    path, size = _export_call(lambda: read_pack(deps.paths, scope, ticket.pack_id))
    return _PackResponse(path, size, ticket.pack_id)


def _export_router(deps: LocalApiDeps, tickets: DownloadTickets) -> APIRouter:
    """Build the Export plan, produce, list, delete, and download routes.

    Nothing here can resolve "latest". The plan route reads the Versions the
    Run recorded when it published; the produce route accepts only identifiers
    the caller states and checks each one for membership in that same set. No
    route reads an Artifact's head Version, and there is no request field that
    could ask one to.

    Nothing here can decide what to delete, either. `DELETE .../exports/{id}`
    removes one named pack; there is no sweep endpoint that picks its own
    victims, no retention horizon, and no eviction when the reported budget is
    exceeded. Bounded growth is answered by *showing* the cost -- a real byte
    total beside a budget on the listing -- and leaving every removal to a
    request that names a pack the researcher has already been shown.

    `tickets` is the same registry the guard screens against, handed to both
    from one place, so the capability this router mints and the capability the
    guard will accept cannot be two different things. Neither the listing nor
    the deletion is exempt from anything: both are ordinary credential-bearing
    API calls, and `DELETE` is a state-changing method, so it also passes the
    cross-site `Sec-Fetch-Site` refusal every mutation here passes.
    """
    router = APIRouter()

    def read_export_plan(project_id: UUID, run_id: UUID) -> ExportPlanBody:
        """List what this Run offers for export, pinned Version by pinned Version."""
        scope = _live_project(deps, project_id)
        candidates = _export_call(lambda: export_candidates(deps.store, scope, run_id))
        return ExportPlanBody(
            run_id=run_id,
            project_id=project_id,
            execution_isolation=_export_isolation(deps, scope, run_id),
            candidates=tuple(_candidate_body(item) for item in candidates),
            # A plan names the conditional documents but does not promise
            # them: whether the run mirror is on disk, and whether the
            # environment facts still hash to the digest the execution pinned,
            # is settled while the pack is assembled. The produced pack states
            # which of them it really carries.
            always_included_documents=ALWAYS_WRITTEN_DOCUMENTS,
            conditional_documents=CONDITIONAL_DOCUMENTS,
            selection_resolution="explicit_version_ids_never_latest",
        )

    def create_export(
        project_id: UUID,
        run_id: UUID,
        body: CreateExportRequest,
    ) -> ExportPackBody:
        """Produce one pack from exactly the Versions the caller pinned."""
        scope = _live_project(deps, project_id)
        job = ExportJob(
            store=deps.store,
            scope=scope,
            paths=deps.paths,
            ids=deps.ids,
            clock=deps.clock,
        )
        pack = _export_call(
            lambda: produce_pack(job, run_id, body.artifact_version_ids)
        )
        return _pack_body(pack, project_id)

    def list_stored_packs(project_id: UUID) -> ExportPackListBody:
        """List the packs this Project really has on disk, and what they cost.

        A directory read rather than a query: nothing persists a row for an
        export, so the only honest answer is the one the filesystem gives now.
        """
        scope = _known_project(deps, project_id)
        stored = _export_call(lambda: list_packs(deps.paths, scope))
        return _pack_list_body(stored, project_id)

    def remove_stored_pack(project_id: UUID, pack_id: UUID) -> DeletedPackBody:
        """Remove exactly the one pack this request names, and nothing else.

        There is no route that selects packs for removal, by age, by count, or
        by any budget. A pack identifier is only learnable from the listing or
        from the produce response, both of which the researcher was shown, so
        "no pack disappears unseen" is a consequence of there being no other
        way to say which pack to remove.

        The remaining totals are re-read from the directory after the unlink
        rather than derived by subtraction, so the receipt reports the disk.
        """
        scope = _known_project(deps, project_id)
        removed = _export_call(lambda: delete_pack(deps.paths, scope, pack_id))
        remaining = _export_call(lambda: list_packs(deps.paths, scope))
        return DeletedPackBody(
            pack_id=removed.pack_id,
            project_id=project_id,
            freed_bytes=removed.freed_bytes,
            pack_count=len(remaining.packs),
            total_size_bytes=remaining.total_size_bytes,
            over_budget=remaining.total_size_bytes > EXPORTS_BUDGET_BYTES,
        )

    def create_download(project_id: UUID, pack_id: UUID) -> DownloadGrantBody:
        """Mint one single-use, short-lived URL for exactly one produced pack.

        The pack is read back from disk before a capability is minted, so a
        URL is never handed out for something that is not there.
        """
        scope = _live_project(deps, project_id)
        _ = _export_call(lambda: read_pack(deps.paths, scope, pack_id))
        grant = tickets.mint(project_id, pack_id)
        return DownloadGrantBody(
            url=grant.url,
            expires_at=grant.expires_at,
            expires_in_seconds=grant.expires_in_seconds,
        )

    def download_pack(
        request: Request,
        project_id: UUID,
        pack_id: UUID,
        ticket: str,
    ) -> Response:
        """Return one produced pack to a browser that carried a capability.

        The three path parameters are declared because the router needs them
        to match; none of them authorizes anything. The only thing this route
        trusts is the capability the guard already accepted and spent, which
        carries its own Project and pack. A request that reached here with the
        session credential and a guessed URL has no such capability and is
        refused.
        """
        del project_id, pack_id, ticket
        accepted = cast(
            "DownloadTicket | None",
            getattr(request.state, TICKET_STATE, None),
        )
        if accepted is None:
            raise LocalApiError(
                HTTPStatus.UNAUTHORIZED,
                ApiErrorCode.DOWNLOAD_TICKET_INVALID,
            )
        return _download_response(deps, accepted)

    export = "/projects/{project_id}/runs/{run_id}/export"
    router.add_api_route(export, read_export_plan, methods=["GET"])
    router.add_api_route(
        export,
        create_export,
        methods=["POST"],
        status_code=int(HTTPStatus.CREATED),
    )
    packs = "/projects/{project_id}/exports"
    router.add_api_route(packs, list_stored_packs, methods=["GET"])
    router.add_api_route(f"{packs}/{{pack_id}}", remove_stored_pack, methods=["DELETE"])
    router.add_api_route(
        f"{packs}/{{pack_id}}/download",
        create_download,
        methods=["POST"],
        status_code=int(HTTPStatus.CREATED),
    )
    router.add_api_route(DOWNLOAD_ROUTE, download_pack, methods=["GET"])
    return router


def _static_response(asset: StaticAsset, token: LocalToken) -> Response:
    """Serve one shipped asset, injecting the credential into the document.

    The document's own `content-security-policy` is set here rather than left
    to :data:`SECURITY_HEADERS`, and `_hardened` only adds a header that is
    not already present, so the relaxed policy reaches the page while every
    other response -- including this surface's stylesheet and script -- keeps
    `default-src 'none'`.
    """
    payload = (
        inject_token(asset.payload, token.value)
        if asset.is_document
        else (asset.payload)
    )
    headers = {"content-type": asset.media_type}
    if asset.is_document:
        headers["content-security-policy"] = asset.content_security_policy
    return Response(content=payload, headers=headers)


def _static_router(surface: StaticSurface, token: LocalToken) -> APIRouter:
    """Build one route per shipped asset, with no path parameter anywhere.

    Every route is registered from an exact literal path taken from the
    surface's own enumeration, so no request can name a file this listener did
    not already decide to serve. There is nothing here for a traversal
    sequence to act on because there is no caller-supplied path segment at
    all.
    """
    router = APIRouter()
    for asset in surface.served():

        def serve(bound: StaticAsset = asset) -> Response:
            """Return one shipped asset from the listener's own origin."""
            return _static_response(bound, token)

        router.add_api_route(asset.path, serve, methods=["GET"])
    return router


def _install_handlers(app: FastAPI) -> None:
    """Replace every default error shape with one that quotes no input.

    FastAPI's stock `RequestValidationError` body includes an `input` field
    holding the rejected value. On `PUT /providers/{id}/key` that value is a
    provider API key, so the default handler is a credential-disclosure bug
    and is replaced rather than augmented.
    """

    async def local_error(_request: Request, exc: Exception) -> Response:
        return _error_response(cast("LocalApiError", exc))

    async def invalid_request(_request: Request, _exc: Exception) -> Response:
        return _error_response(
            LocalApiError(HTTPStatus.BAD_REQUEST, ApiErrorCode.INVALID_REQUEST)
        )

    async def http_error(_request: Request, exc: Exception) -> Response:
        status = HTTPStatus(cast("StarletteHTTPException", exc).status_code)
        code = (
            ApiErrorCode.METHOD_NOT_ALLOWED
            if status is HTTPStatus.METHOD_NOT_ALLOWED
            else ApiErrorCode.NOT_FOUND
        )
        return _error_response(LocalApiError(status, code))

    async def unexpected(_request: Request, _exc: Exception) -> Response:
        return _error_response(
            LocalApiError(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                ApiErrorCode.INTERNAL_ERROR,
            )
        )

    app.add_exception_handler(LocalApiError, local_error)
    app.add_exception_handler(RequestValidationError, invalid_request)
    app.add_exception_handler(ValidationError, invalid_request)
    app.add_exception_handler(StarletteHTTPException, http_error)
    app.add_exception_handler(Exception, unexpected)


def create_app(
    deps: LocalApiDeps,
    token: LocalToken,
    *,
    origins: frozenset[str],
    authorities: frozenset[str],
    web: StaticSurface | None = None,
) -> ASGIApp:
    """Build the guarded local ASGI application.

    Args:
        deps: The local core this surface reads and writes.
        token: The per-run session credential every request must carry.
        origins: The browser origins this listener accepts, from
            :func:`~nipo_local.apiserver.loopback_origins`.
        authorities: The `Host` values this listener answers, from
            :func:`~nipo_local.apiserver.loopback_authorities`.
        web: The shipped front end to serve from this same origin. `None`
            leaves the listener API-only, with every path outside
            `/api/v1` a `404` and every path requiring the credential.

    Returns:
        The guarded application. There is no accessor for the unguarded one,
        so a future route cannot be added outside the credential and
        same-origin checks. The one set of paths exempt from the credential
        is taken from the static surface's own enumeration and handed to the
        guard here, so the routes registered and the routes exempted are a
        single statement.
    """
    app = FastAPI(
        title="Nipo Science local",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        # A path this listener does not serve answers `404`, never a redirect
        # to one it does. The framework's trailing-slash redirect would make
        # `/index.html/` a `307` to `/index.html`, which is a second way to
        # reach a served path and a response shape this surface otherwise
        # never emits. There is one answer for an unknown path.
        redirect_slashes=False,
    )
    _install_handlers(app)

    def health() -> HealthBody:
        """Report liveness and the fixed local identity."""
        return HealthBody(
            status="ok",
            org_id=deps.org_id,
            requester_id=deps.requester_id,
            run_surface=deps.runs is not None,
        )

    app.add_api_route(f"{API_PREFIX}/health", health, methods=["GET"])
    # One registry, handed to the router that mints capabilities and to the
    # guard that spends them. Its URL prefix is this surface's own, so a minted
    # path and a registered route are formatted from a single template.
    tickets = DownloadTickets(deps.clock, API_PREFIX)
    for router in (
        _provider_router(deps),
        _project_router(deps),
        _session_router(deps),
        _artifact_router(deps),
        _input_router(deps),
        _plan_router(deps),
        _run_router(deps),
        _turn_router(deps),
        _review_router(deps),
        _export_router(deps, tickets),
    ):
        app.include_router(router, prefix=API_PREFIX)
    documents: frozenset[str] = frozenset()
    if web is not None:
        documents = web.paths
        app.include_router(_static_router(web, token))
    return LocalGuard(
        app,
        token=token,
        origins=origins,
        authorities=authorities,
        documents=documents,
        tickets=tickets,
    )


@final
@dataclass(frozen=True, slots=True)
class RunningLocalApi:
    """One started local API: its listener, its credential, and its token file."""

    server: LoopbackServer
    token: LocalToken
    token_path: Path

    @property
    def base_url(self) -> str:
        """Return the only URL the local front end should call."""
        return self.server.base_url

    @property
    def port(self) -> int:
        """Return the loopback port the kernel bound."""
        return self.server.port

    def close(self) -> None:
        """Stop the listener and remove the per-run credential file."""
        self.server.stop()
        self.token_path.unlink(missing_ok=True)


def start_local_api(
    paths: LocalPaths,
    deps: LocalApiDeps,
    *,
    host: str = LOOPBACK_HOST,
    port: int = 0,
    web: StaticSurface | None = None,
) -> RunningLocalApi:
    """Bind loopback, publish a fresh credential, and start serving.

    The owner-only data root is ensured *before* the socket is bound and
    before the token file is written. A fresh install must never create
    the data root as a side effect of the token write under the process
    umask; :meth:`~nipo_local.config.LocalPaths.ensure` is the sole layout
    creator and chmods each directory to owner-only after mkdir.

    The socket is bound *before* the application is built, because the
    accepted origins and `Host` authorities are derived from the port the
    kernel actually assigned rather than from one this process hoped for.

    Args:
        paths: The resolved local layout that receives the token file.
        deps: The local core this surface reads and writes.
        host: A loopback host. Any other value raises before a socket exists.
        port: A TCP port, or 0 for a kernel-assigned ephemeral port.
        web: The shipped front end to serve from this origin. Defaults to
            :class:`~nipo_local.webui.StaticSurface`, so a stock start serves
            a usable UI; pass an explicit surface to serve a different tree.

    Returns:
        The running API, its credential, and the path that credential was
        published to.
    """
    paths.ensure()
    listener = bind_loopback(host, port)
    try:
        bound = cast("tuple[object, ...]", listener.getsockname())
        assigned = cast("int", bound[1])
        token = new_local_token()
        app = create_app(
            deps,
            token,
            origins=loopback_origins(assigned),
            authorities=loopback_authorities(assigned),
            web=StaticSurface() if web is None else web,
        )
        server = LoopbackServer(app, listener)
    except BaseException:
        listener.close()
        raise
    path = write_token_file(paths, token, server.base_url)
    try:
        server.start()
    except BaseException:
        path.unlink(missing_ok=True)
        server.stop()
        raise
    return RunningLocalApi(server=server, token=token, token_path=path)


def default_deps(
    store: LocalArtifactStore,
    registry: ProviderRegistry,
    read_model: LocalReadModel,
    paths: LocalPaths,
    runs: RunSurface | None = None,
) -> LocalApiDeps:
    """Bind the local core to the production clock and identity factory."""
    return LocalApiDeps(
        store=store,
        registry=registry,
        read_model=read_model,
        paths=paths,
        clock=SystemClock(),
        ids=Uuid7Factory(),
        runs=runs,
    )


__all__ = [
    "API_PREFIX",
    "TICKET_STATE",
    "TOKEN_FILE_NAME",
    "TOKEN_HEADER",
    "LocalApiDeps",
    "LocalApiError",
    "LocalGuard",
    "LocalToken",
    "RunSurface",
    "RunningLocalApi",
    "create_app",
    "default_deps",
    "new_local_token",
    "start_local_api",
    "token_file",
    "write_token_file",
]
