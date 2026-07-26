"""Session-scoped browser fixture for the deterministic dry-lab vertical."""

from __future__ import annotations

import hashlib
import sys
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Lock, RLock
from typing import TYPE_CHECKING, Final, Literal, NoReturn, Protocol, final
from uuid import UUID

from science_workbench_science.research_intent import (
    ResearchIntentError,
    research_intent_from_mapping,
)
from science_workbench_science.vertical import (
    DryLabVertical,
    ExternalExecutionBinding,
    FixtureFailure,
    VerticalProjection,
)
from services.api.artifacts.runtime import UUID7_VERSION, Uuid7Factory
from services.api.product_artifact_types import (
    ArtifactVersionConflictError,
    ArtifactVersionDraft,
    UnsupportedArtifactMediaError,
)
from services.api.product_artifact_views import artifact_detail_json, artifact_list_json
from services.api.provider_run_dispatch_contracts import (
    DispatchedProviderRun,
    ProviderRunDispatcher,
    ProviderRunDispatchError,
    ProviderRunDispatchRequest,
)

if TYPE_CHECKING:
    from services.api.product_artifacts import ProductArtifactService
    from services.api.provider_runtime_contracts import (
        DispatchAuthorization,
        ProviderPrincipal,
    )

type JsonScalar = None | bool | int | float | str
type JsonList = list[JsonValue]
type JsonObject = dict[str, JsonValue]
type JsonValue = JsonScalar | JsonList | JsonObject

type DryLabAction = Literal[
    "approve", "reject", "cancel", "execute", "review", "export", "cleanup"
]
type DryLabResourceKind = Literal["run", "review", "export", "artifact"]

_UNAUTHORIZED_STATUS = 401
_NOT_FOUND_STATUS = 404
_BAD_REQUEST_STATUS = 400
_CONFLICT_STATUS = 409
_SERVER_ERROR_STATUS = 500
_SERVICE_UNAVAILABLE_STATUS = 503
_CREATED_STATUS = 201
_ACCEPTED_STATUS = 202
_OK_STATUS = 200
_UNAUTHORIZED_CODE = "unauthorized"
_PROVIDER_DISPATCH_UNAVAILABLE = "provider_dispatch_unavailable"
_NOT_FOUND_CODE = "not-found"
_INVALID_ID_FACTORY_MESSAGE = "dry-lab id factory must return canonical UUIDv7"
_ARTIFACT_MATERIALIZATION_FAILURE_MESSAGE = (
    "dry-lab Artifact materialization contract failed"
)
_CLEANUP_CONFIRMATION_REQUIRED: Final = "cleanup-confirmation-required"
_ENVIRONMENT_SHA256 = hashlib.sha256(sys.version.encode("utf-8")).hexdigest()
_ARTIFACT_MEDIA_TYPES: Final[dict[str, str]] = {
    ".csv": "text/csv",
    ".json": "application/json",
    ".md": "text/markdown",
    ".png": "image/png",
}
_STAGES: Final[tuple[str, ...]] = (
    "new",
    "upload",
    "plan",
    "approve",
    "reject",
    "cancel",
    "expire",
    "execute",
    "review",
    "export",
    "cleanup",
)
_STAGE_LABELS: Final[dict[str, str]] = {
    "new": "새 실행 준비",
    "upload": "입력 검증 완료",
    "plan": "계획 승인 대기",
    "approve": "계획 승인 완료",
    "reject": "계획 승인 거절",
    "cancel": "실행 취소 완료",
    "expire": "계획 승인 만료",
    "execute": "격리 실행 완료",
    "review": "근거 검토 완료",
    "export": "내보내기 준비 완료",
    "cleanup": "런타임 정리 완료",
}
_STAGE_TONES: Final[dict[str, str]] = {
    "new": "neutral",
    "upload": "attention",
    "plan": "attention",
    "approve": "attention",
    "reject": "danger",
    "cancel": "danger",
    "expire": "danger",
    "execute": "positive",
    "review": "positive",
    "export": "positive",
    "cleanup": "positive",
}
_ACTION_PRESENTATION: Final[dict[str, tuple[str, bool]]] = {
    "create-run": ("연구 시작하기", False),
    "approve": ("계획 승인", False),
    "reject": ("계획 거절", False),
    "cancel": ("실행 취소", False),
    "execute": ("승인된 계획 실행", True),
    "review": ("검토 결과 생성", False),
    "export": ("재현성 매니페스트 준비", False),
    "cleanup": ("런타임 데이터 정리", False),
}
_STAGE_ACTIONS: Final[dict[str, tuple[str, ...]]] = {
    "plan": ("approve", "reject", "cancel"),
    "approve": ("execute", "cancel"),
    "execute": ("review",),
    "review": ("export",),
    "export": ("cleanup",),
}
type ActionHandler = Callable[[DryLabVertical, JsonObject], DryLabResponse]


@dataclass(frozen=True, slots=True)
class DryLabResponse:
    """One JSON-safe response from the dry-lab product adapter."""

    status: int
    payload: JsonObject


@dataclass(frozen=True, slots=True)
class LocalRunCreate:
    """Validated local dry-lab creation fields from the authenticated boundary."""

    research_session_id: str
    prompt: str
    research_intent: JsonValue
    filename: str
    media_type: str
    content: str
    collection_id: str | None = None


@dataclass(frozen=True, slots=True)
class ProviderRunCreate:
    """Validated provider creation fields from the authenticated boundary."""

    research_session_id: str
    prompt: str
    research_intent: JsonValue
    filename: str
    media_type: str
    content: str
    connection_id: str
    model_id: str
    collection_id: str | None = None


class _RunCreateFields(Protocol):
    @property
    def research_session_id(self) -> str: ...

    @property
    def prompt(self) -> str: ...

    @property
    def research_intent(self) -> JsonValue: ...

    @property
    def filename(self) -> str: ...

    @property
    def media_type(self) -> str: ...

    @property
    def content(self) -> str: ...

    @property
    def collection_id(self) -> str | None: ...


@dataclass(frozen=True, slots=True)
class _ProviderTarget:
    session_id: str
    connection_id: str
    model_id: str


@final
class _ResourceIds:
    __slots__ = ("artifact_ids", "export_id", "review_id", "run_id")

    def __init__(self, run_id: str | None = None) -> None:
        self.run_id = run_id
        self.review_id: str | None = None
        self.export_id: str | None = None
        self.artifact_ids: dict[str, str] | None = None


@final
class _RunRecord:
    __slots__ = (
        "artifacts",
        "context",
        "created_at",
        "provider_authorization",
        "provider_target",
        "resources",
        "vertical",
    )

    def __init__(
        self,
        vertical: DryLabVertical,
        resources: _ResourceIds,
        created_at: datetime,
        context: JsonObject | None = None,
        provider_target: _ProviderTarget | None = None,
    ) -> None:
        self.vertical = vertical
        self.resources = resources
        self.created_at = created_at
        self.context = context or {}
        self.provider_target = provider_target
        self.provider_authorization: DispatchAuthorization | None = None
        self.artifacts: ProductArtifactService | None = None


@final
class _SessionLock:
    __slots__ = ("lock", "users")

    def __init__(self, lock: RLock) -> None:
        self.lock = lock
        self.users = 0


@dataclass(frozen=True, slots=True)
class DryLabArtifactDownload:
    """Immutable Artifact bytes and safe response metadata."""

    name: str
    media_type: str
    content: bytes
    sha256: str


@final
class ProductDryLabService:
    """Own non-production Runs inside one authenticated browser fixture process."""

    def __init__(
        self,
        artifact_service_factory: Callable[[], ProductArtifactService],
        id_factory: Callable[[], str] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize an empty session-to-Run registry with explicit artifacts."""
        self._lock = Lock()
        self._runs: dict[str, dict[str, _RunRecord]] = {}
        self._session_locks: dict[str, _SessionLock] = {}
        self._artifact_service_factory = artifact_service_factory
        self._id_factory = id_factory or _new_resource_id
        self._clock = clock or _utc_now
        self._handlers: dict[str, ActionHandler] = {
            "approve": self._approve,
            "reject": self._reject,
            "cancel": self._cancel,
            "execute": self._execute,
            "review": self._review,
            "export": self._export,
            "cleanup": self._cleanup,
        }

    @property
    def session_count(self) -> int:
        """Return the number of authenticated sessions retaining Runs."""
        with self._lock:
            return len(self._runs)

    def drop_session(self, session_key: str) -> None:
        """Remove every Run retained for a logged-out browser session."""
        with self._locked_session(session_key), self._lock:
            _ = self._runs.pop(session_key, None)

    def dispatch(
        self, session_key: str, action: str, body: JsonObject
    ) -> DryLabResponse:
        """Run one fixed action against an explicitly selected session Run."""
        if not session_key:
            return DryLabResponse(_UNAUTHORIZED_STATUS, {"code": _UNAUTHORIZED_CODE})
        handler = self._handlers.get(action)
        if handler is None:
            return DryLabResponse(_NOT_FOUND_STATUS, {"code": _NOT_FOUND_CODE})

        with self._locked_session(session_key):
            try:
                record = self._selected_run(session_key, body)
                if record is None:
                    return DryLabResponse(_NOT_FOUND_STATUS, {"code": _NOT_FOUND_CODE})
                if action == "execute":
                    candidate = record.vertical.fork_for_execution()
                    response = handler(candidate, body)
                    artifact_ids = {
                        artifact["name"]: self._new_id()
                        for artifact in candidate.read_projection()["artifacts"]
                    }
                    artifacts = self._build_artifact_service(
                        session_key,
                        record.resources.run_id,
                        artifact_ids,
                        candidate,
                    )
                    record.vertical = candidate
                    record.resources.artifact_ids = artifact_ids
                    record.artifacts = artifacts
                else:
                    response = handler(record.vertical, body)
            except FixtureFailure as error:
                return DryLabResponse(error.status, {"code": error.code})
            except (
                ArtifactVersionConflictError,
                OSError,
                RuntimeError,
                UnsupportedArtifactMediaError,
                ValueError,
            ):
                return DryLabResponse(
                    _SERVER_ERROR_STATUS, {"code": "artifact-unavailable"}
                )
            self._record_resource_ids(record.resources, action)
            return DryLabResponse(
                response.status,
                _record_resource_payload(record, response.payload),
            )

    def dispatch_provider_run(
        self,
        session_key: str,
        body: JsonObject,
        principal: ProviderPrincipal,
        dispatcher: ProviderRunDispatcher | None,
    ) -> DryLabResponse | None:
        """Consume approval and dispatch only a provider-backed Run."""
        if not session_key:
            return DryLabResponse(_UNAUTHORIZED_STATUS, {"code": _UNAUTHORIZED_CODE})
        with self._locked_session(session_key):
            record = self._selected_run(session_key, body)
            if record is None or record.provider_target is None:
                return None
            rejected = _provider_dispatch_request_error(body, dispatcher)
            if rejected is not None or dispatcher is None:
                return rejected
            candidate = record.vertical.fork_for_execution()
            try:
                dispatched = _dispatch_provider_execution(
                    candidate,
                    record,
                    body,
                    principal,
                    dispatcher,
                )
            except FixtureFailure as error:
                return DryLabResponse(error.status, {"code": error.code})
            except ProviderRunDispatchError:
                return DryLabResponse(
                    _SERVICE_UNAVAILABLE_STATUS,
                    {"code": _PROVIDER_DISPATCH_UNAVAILABLE},
                )
            record.vertical = candidate
            record.provider_authorization = dispatched.authorization
            return DryLabResponse(
                _ACCEPTED_STATUS,
                _record_resource_payload(record, {}),
            )

    def create_local_run(
        self,
        session_key: str,
        request: LocalRunCreate,
    ) -> DryLabResponse:
        """Atomically validate input, bind ResearchIntent, and retain one Run."""
        return self._create_run(session_key, request, "local_dry_lab", None)

    def create_provider_run(
        self,
        session_key: str,
        request: ProviderRunCreate,
    ) -> DryLabResponse:
        """Create an approval-pending provider Run without dispatching it."""
        target = _ProviderTarget(
            request.research_session_id,
            request.connection_id,
            request.model_id,
        )
        external = ExternalExecutionBinding(
            execution_mode="provider_model",
            prompt_sha256=hashlib.sha256(request.prompt.encode("utf-8")).hexdigest(),
            connection_id=request.connection_id,
            model_id=request.model_id,
        )
        return self._create_run(
            session_key,
            request,
            "provider_model",
            target,
            external_execution=external,
        )

    def _create_run(
        self,
        session_key: str,
        request: _RunCreateFields,
        execution_mode: Literal["local_dry_lab", "provider_model"],
        provider_target: _ProviderTarget | None,
        *,
        external_execution: ExternalExecutionBinding | None = None,
    ) -> DryLabResponse:
        if not session_key:
            return DryLabResponse(_UNAUTHORIZED_STATUS, {"code": _UNAUTHORIZED_CODE})
        if request.media_type != "text/csv":
            return DryLabResponse(
                _BAD_REQUEST_STATUS, {"code": "unsupported-media-type"}
            )
        with self._locked_session(session_key):
            vertical = DryLabVertical(self._clock)
            try:
                upload = vertical.upload(request.filename, request.content, request="")
                intent = research_intent_from_mapping(request.research_intent)
                plan = vertical.create_plan(
                    research_intent=intent,
                    lease_id="fresh",
                    external_execution=external_execution,
                )
            except (FixtureFailure, ResearchIntentError) as error:
                code = error.code
                status = (
                    error.status
                    if isinstance(error, FixtureFailure)
                    else _BAD_REQUEST_STATUS
                )
                return DryLabResponse(status, {"code": code})
            run_id = self._new_id()
            resources = _ResourceIds(run_id=run_id)
            context: JsonObject = {
                "execution_mode": execution_mode,
                "session_id": request.research_session_id,
                "prompt": request.prompt,
                "plan_digest": plan.digest,
                "input_provenance": (
                    {"collection_id": request.collection_id}
                    if request.collection_id is not None
                    else None
                ),
            }
            record = _RunRecord(
                vertical,
                resources,
                self._clock(),
                context,
                provider_target,
            )
            with self._lock:
                self._runs.setdefault(session_key, {})[run_id] = record
            return DryLabResponse(
                _CREATED_STATUS,
                _record_resource_payload(
                    record,
                    {
                        "filename": upload.filename,
                        "sha256": upload.content_sha256,
                        "digest": plan.digest,
                    },
                ),
            )

    def artifact_detail(
        self, session_key: str, artifact_id: str, version_id: str | None = None
    ) -> JsonObject | None:
        """Return immutable Version detail from this dry-lab browser session."""
        with self._locked_session(session_key):
            record = self._artifact_run(session_key, artifact_id)
            if record is None or record.artifacts is None:
                return None
            detail = record.artifacts.detail(session_key, artifact_id, version_id)
            return artifact_detail_json(detail, None) if detail is not None else None

    def artifact_library(self, session_key: str) -> JsonObject:
        """List the latest immutable Version from the integrated Artifact store."""
        with self._locked_session(session_key):
            with self._lock:
                records = tuple(self._runs.get(session_key, {}).values())
            versions = tuple(
                version
                for record in records
                if record.artifacts is not None
                for version in record.artifacts.list_latest(session_key)
            )
            return artifact_list_json(versions)

    def create_artifact_version(
        self, session_key: str, artifact_id: str, body: JsonObject
    ) -> DryLabResponse:
        """Append one validated CSV Version to a session-owned Artifact."""
        with self._locked_session(session_key):
            record = self._artifact_run(session_key, artifact_id)
            service = record.artifacts if record is not None else None
            base = body.get("base_version_no")
            name = body.get("name")
            media_type = body.get("media_type")
            content = body.get("content")
            current = service.detail(session_key, artifact_id) if service else None
            if (
                service is None
                or current is None
                or type(base) is not int
                or not isinstance(name, str)
                or media_type != "text/csv"
                or not isinstance(content, str)
            ):
                return DryLabResponse(_BAD_REQUEST_STATUS, {"code": "invalid-request"})
            try:
                created = service.create_version(
                    ArtifactVersionDraft(
                        organization_id=session_key,
                        artifact_id=artifact_id,
                        name=name,
                        media_type="text/csv",
                        content=content.encode("utf-8"),
                        producer_execution_id=self._new_id(),
                        environment_sha256=_ENVIRONMENT_SHA256,
                        lineage_version_ids=(current.selected.id,),
                    ),
                    base_version_no=base,
                )
            except ArtifactVersionConflictError:
                return DryLabResponse(_CONFLICT_STATUS, {"code": "version-conflict"})
            except (UnicodeEncodeError, UnsupportedArtifactMediaError):
                return DryLabResponse(_BAD_REQUEST_STATUS, {"code": "invalid-request"})
            detail = service.detail(session_key, artifact_id, created.id)
            if detail is None:
                return DryLabResponse(
                    _SERVER_ERROR_STATUS, {"code": "artifact-unavailable"}
                )
            return DryLabResponse(_CREATED_STATUS, artifact_detail_json(detail, None))

    def mutate_artifact_attachment(
        self,
        session_key: str,
        artifact_id: str,
        version_id: str,
        research_session_id: str,
        *,
        attach: bool,
    ) -> JsonObject | None:
        """Attach only an exact Version already visible in this browser session."""
        with self._locked_session(session_key):
            record = self._artifact_run(session_key, artifact_id)
            service = record.artifacts if record is not None else None
            if (
                service is None
                or service.detail(session_key, artifact_id, version_id) is None
            ):
                return None
            sessions = (
                service.attach(session_key, version_id, research_session_id)
                if attach
                else service.detach(session_key, version_id, research_session_id)
            )
            return {"version_id": version_id, "attached_session_ids": list(sessions)}

    def download_artifact(
        self, session_key: str, artifact_id: str, version_id: str
    ) -> DryLabArtifactDownload | None:
        """Return bytes only when Artifact and Version URL identities both match."""
        with self._locked_session(session_key):
            record = self._artifact_run(session_key, artifact_id)
            service = record.artifacts if record is not None else None
            version = service.download(session_key, version_id) if service else None
            if version is None or version.artifact_id != artifact_id:
                return None
            return DryLabArtifactDownload(
                version.name, version.media_type, version.content, version.sha256
            )

    def resource(
        self, session_key: str, kind: DryLabResourceKind, resource_id: str
    ) -> DryLabResponse | None:
        """Resolve one URL resource only inside its authenticated browser session."""
        with self._locked_session(session_key):
            record = self._resource_run(session_key, kind, resource_id)
            if record is None:
                return None
            return DryLabResponse(
                _OK_STATUS,
                _record_resource_payload(record, {}),
            )

    def workspace_runs(self, session_key: str) -> tuple[JsonObject, ...]:
        """Return server-owned links for every Run retained by this session."""
        with self._locked_session(session_key):
            with self._lock:
                records = tuple(self._runs.get(session_key, {}).values())
            return tuple(
                _workspace_run_json(record, run_id)
                for record in records
                if (run_id := record.resources.run_id) is not None
            )

    def _approve(self, vertical: DryLabVertical, body: JsonObject) -> DryLabResponse:
        """Approve the current plan and return its session projection."""
        approval = vertical.approve(_string_value(body, "plan_digest"))
        return DryLabResponse(
            _ACCEPTED_STATUS,
            {
                "token": approval.token,
                "plan_digest": approval.plan_digest,
                **_projection_json(vertical.read_projection()),
            },
        )

    def _execute(self, vertical: DryLabVertical, body: JsonObject) -> DryLabResponse:
        """Execute an approved plan and return its session projection."""
        result = vertical.execute(
            _optional_string(body.get("token")),
            request=_string_value(body, "request"),
        )
        return DryLabResponse(
            _OK_STATUS,
            {
                "child_succeeded": result.child_succeeded,
                **_projection_json(vertical.read_projection()),
            },
        )

    def _reject(self, vertical: DryLabVertical, body: JsonObject) -> DryLabResponse:
        del body
        vertical.reject()
        return DryLabResponse(_OK_STATUS, _projection_json(vertical.read_projection()))

    def _cancel(self, vertical: DryLabVertical, body: JsonObject) -> DryLabResponse:
        del body
        vertical.cancel()
        return DryLabResponse(_OK_STATUS, _projection_json(vertical.read_projection()))

    def _review(self, vertical: DryLabVertical, body: JsonObject) -> DryLabResponse:
        """Review the completed execution and return its session projection."""
        del body
        review = vertical.review()
        return DryLabResponse(
            _CREATED_STATUS,
            {
                "verdict": review.verdict,
                "pinned_hashes": dict(review.pinned_hashes),
                **_projection_json(vertical.read_projection()),
            },
        )

    def _export(self, vertical: DryLabVertical, body: JsonObject) -> DryLabResponse:
        """Export the review receipt and return its session projection."""
        del body
        receipt = vertical.export()
        return DryLabResponse(
            _OK_STATUS,
            {
                "manifest_sha256": receipt.manifest_sha256,
                "paths": list(receipt.paths),
                **_projection_json(vertical.read_projection()),
            },
        )

    def _cleanup(self, vertical: DryLabVertical, body: JsonObject) -> DryLabResponse:
        """Clean up runtime data and return its session projection."""
        if body.get("confirmed") is not True or set(body) != {"confirmed", "run_id"}:
            raise FixtureFailure(_CLEANUP_CONFIRMATION_REQUIRED)
        receipt = vertical.cleanup()
        return DryLabResponse(
            _OK_STATUS,
            {
                "removed_runtime_data": receipt.removed_runtime_data,
                "preserved_artifact_hashes": list(receipt.preserved_artifact_hashes),
                **_projection_json(vertical.read_projection()),
            },
        )

    def _selected_run(self, session_key: str, body: JsonObject) -> _RunRecord | None:
        run_id = _optional_string(body.get("run_id"))
        with self._lock:
            return self._runs.get(session_key, {}).get(run_id) if run_id else None

    def _resource_run(
        self, session_key: str, kind: DryLabResourceKind, resource_id: str
    ) -> _RunRecord | None:
        with self._lock:
            records = tuple(self._runs.get(session_key, {}).values())
        for record in records:
            resources = record.resources
            if kind == "run" and resources.run_id == resource_id:
                return record
            if kind == "review" and resources.review_id == resource_id:
                return record
            if kind == "export" and resources.export_id == resource_id:
                return record
            if (
                kind == "artifact"
                and resource_id in (resources.artifact_ids or {}).values()
            ):
                return record
        return None

    def _artifact_run(self, session_key: str, artifact_id: str) -> _RunRecord | None:
        return self._resource_run(session_key, "artifact", artifact_id)

    def _build_artifact_service(
        self,
        session_key: str,
        run_id: str | None,
        artifact_ids: dict[str, str],
        vertical: DryLabVertical,
    ) -> ProductArtifactService:
        if run_id is None or not artifact_ids:
            raise RuntimeError(_ARTIFACT_MATERIALIZATION_FAILURE_MESSAGE)
        service = self._artifact_service_factory()
        for artifact in vertical.read_projection()["artifacts"]:
            name = artifact["name"]
            content = vertical.read_artifact(name)
            media_type = next(
                (
                    value
                    for suffix, value in _ARTIFACT_MEDIA_TYPES.items()
                    if name.lower().endswith(suffix)
                ),
                None,
            )
            artifact_id = artifact_ids.get(name)
            if content is None or media_type is None or artifact_id is None:
                raise RuntimeError(_ARTIFACT_MATERIALIZATION_FAILURE_MESSAGE)
            _ = service.create_version(
                ArtifactVersionDraft(
                    organization_id=session_key,
                    artifact_id=artifact_id,
                    name=name,
                    media_type=media_type,
                    content=content,
                    producer_execution_id=run_id,
                    environment_sha256=_ENVIRONMENT_SHA256,
                    lineage_version_ids=(),
                ),
                base_version_no=0,
            )
        return service

    def _record_resource_ids(
        self,
        resources: _ResourceIds,
        action: str,
    ) -> None:
        with self._lock:
            if action == "review" and resources.review_id is None:
                resources.review_id = self._new_id()
            if action == "export" and resources.export_id is None:
                resources.export_id = self._new_id()

    def _new_id(self) -> str:
        value = self._id_factory()
        try:
            parsed = UUID(value)
        except ValueError as error:
            raise RuntimeError(_INVALID_ID_FACTORY_MESSAGE) from error
        if str(parsed) != value or parsed.version != UUID7_VERSION:
            raise RuntimeError(_INVALID_ID_FACTORY_MESSAGE)
        return value

    @contextmanager
    def _locked_session(self, session_key: str) -> Generator[None, None, None]:
        """Serialize a complete state transition for one browser session."""
        with self._lock:
            entry = self._session_locks.setdefault(session_key, _SessionLock(RLock()))
            entry.users += 1
        try:
            with entry.lock:
                yield
        finally:
            with self._lock:
                entry.users -= 1
                if entry.users == 0 and self._session_locks.get(session_key) is entry:
                    del self._session_locks[session_key]


def _provider_dispatch_request_error(
    body: JsonObject,
    dispatcher: ProviderRunDispatcher | None,
) -> DryLabResponse | None:
    if dispatcher is None:
        return DryLabResponse(
            _SERVICE_UNAVAILABLE_STATUS,
            {"code": _PROVIDER_DISPATCH_UNAVAILABLE},
        )
    if set(body) != {"run_id", "token"}:
        return DryLabResponse(_BAD_REQUEST_STATUS, {"code": "invalid-request"})
    return None


def _dispatch_provider_execution(
    candidate: DryLabVertical,
    record: _RunRecord,
    body: JsonObject,
    principal: ProviderPrincipal,
    dispatcher: ProviderRunDispatcher,
) -> DispatchedProviderRun:
    def _invalid_order() -> NoReturn:
        failure_code = "invalid-order"
        raise FixtureFailure(failure_code, _CONFLICT_STATUS)

    candidate.consume_approval(_optional_string(body.get("token")))
    projection = candidate.read_projection()
    plan_digest = projection["plan_digest"]
    research_intent_sha256 = projection["research_intent_sha256"]
    run_id = record.resources.run_id
    target = record.provider_target
    if (
        run_id is not None
        and target is not None
        and plan_digest is not None
        and research_intent_sha256 is not None
    ):
        return dispatcher.dispatch(
            principal,
            ProviderRunDispatchRequest(
                run_id,
                target.session_id,
                target.connection_id,
                target.model_id,
                plan_digest,
                research_intent_sha256,
            ),
        )
    return _invalid_order()


def _workspace_run_json(record: _RunRecord, run_id: str) -> JsonObject:
    resources = record.resources
    projection = record.vertical.read_projection()
    stage = (
        "execute"
        if record.provider_authorization is not None
        else projection["stage"]
    )
    stage_label = (
        "제공자 실행 대기열 등록"
        if record.provider_authorization is not None
        else _STAGE_LABELS[stage]
    )
    return {
        "id": run_id,
        "display_id": f"Run {run_id[-8:]}",
        "name": "드라이랩 연구 실행",
        "created_at": _utc_timestamp(record.created_at),
        "stage": stage,
        "stage_label": stage_label,
        "links": [
            link
            for link in _resource_links(resources, stage)
            if isinstance(link, dict)
            and link.get("kind") != "artifacts"
            and (
                record.provider_authorization is None
                or link.get("kind") == "run"
            )
        ],
    }


def _record_payload(record: _RunRecord, payload: JsonObject) -> JsonObject:
    return {
        **record.context,
        "provider": _provider_payload(record),
        **payload,
        "created_at": _utc_timestamp(record.created_at),
    }


def _provider_payload(record: _RunRecord) -> JsonObject | None:
    target = record.provider_target
    if target is None:
        return None
    authorization = record.provider_authorization
    stage = record.vertical.read_projection()["stage"]
    dispatch_status = {
        "approve": "approved",
        "reject": "rejected",
        "cancel": "cancelled",
        "expire": "expired",
    }.get(stage, "awaiting_approval")
    return {
        "connection_id": target.connection_id,
        "model_id": target.model_id,
        "dispatch_status": "queued" if authorization is not None else dispatch_status,
        "adapter_id": None if authorization is None else authorization.adapter_id,
        "qualification_receipt_id": (
            None
            if authorization is None
            else authorization.qualification_receipt_id
        ),
    }


def _record_resource_payload(
    record: _RunRecord,
    response_payload: JsonObject,
) -> JsonObject:
    projection = record.vertical.read_projection()
    payload = _resource_payload(
        projection,
        record.resources,
        _record_payload(record, response_payload),
    )
    action_plan = payload.get("action_plan")
    if isinstance(action_plan, dict) and record.provider_target is not None:
        action_plan["scope_label"] = "현재 ActionPlan의 제공자 모델 실행 1회"
    if record.provider_authorization is None:
        return payload
    run_id = record.resources.run_id
    payload.update(
        {
            "stage": "execute",
            "child_succeeded": False,
            "display": {
                "stage_label": "제공자 실행 대기열 등록",
                "stage_tone": "attention",
            },
            "links": (
                []
                if run_id is None
                else [
                    {
                        "kind": "run",
                        "href": f"/runs/{run_id}",
                        "label": "실행 보기",
                    }
                ]
            ),
            "actions": _resource_actions(record.resources, "provider-queued"),
            "timeline": _provider_dispatch_timeline(),
        }
    )
    if isinstance(action_plan, dict):
        action_plan["approval_status_label"] = "승인 사용 완료"
    return payload


def _provider_dispatch_timeline() -> JsonList:
    return [
        {
            "step": step,
            "name": (
                "제공자 실행 대기열 등록" if step == "execute" else _STAGE_LABELS[step]
            ),
            "status": "현재 단계" if step == "execute" else "완료",
            "tone": "attention" if step == "execute" else "positive",
        }
        for step in ("upload", "plan", "approve", "execute")
    ]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _new_resource_id() -> str:
    return str(Uuid7Factory().new_uuid7())


def _resource_payload(
    projection: VerticalProjection,
    resources: _ResourceIds,
    response_payload: JsonObject,
) -> JsonObject:
    state = _projection_json(projection)
    retained_plan_digest = response_payload.get("plan_digest")
    if state["plan_digest"] is None and isinstance(retained_plan_digest, str):
        state["plan_digest"] = retained_plan_digest
    artifact_ids = resources.artifact_ids or {}
    artifacts = state["artifacts"]
    if isinstance(artifacts, list):
        state["artifacts"] = [
            {
                **artifact,
                "artifact_id": artifact_ids.get(str(artifact.get("name"))),
            }
            if isinstance(artifact, dict)
            else artifact
            for artifact in artifacts
        ]
    return {
        **response_payload,
        **state,
        "run_id": resources.run_id,
        "review_id": resources.review_id,
        "export_id": resources.export_id,
        "display": {
            "stage_label": _STAGE_LABELS[projection["stage"]],
            "stage_tone": _STAGE_TONES[projection["stage"]],
        },
        "action_plan": _action_plan_json(projection, state["plan_digest"]),
        "links": _resource_links(resources, projection["stage"]),
        "actions": _resource_actions(resources, projection["stage"]),
        "timeline": _timeline_json(projection["stage"]),
    }


def _resource_links(resources: _ResourceIds, stage: str) -> JsonList:
    links: JsonList = []
    if resources.run_id is not None:
        links.append(
            {
                "kind": "run",
                "href": f"/runs/{resources.run_id}",
                "label": "실행 보기",
            }
        )
        if stage in {"plan", "approve"}:
            links.append(
                {
                    "kind": "approval",
                    "href": f"/runs/{resources.run_id}/approval",
                    "label": "계획 승인 보기",
                }
            )
        if stage in {"execute", "review", "export", "cleanup"}:
            links.append(
                {"kind": "artifacts", "href": "/artifacts", "label": "아티팩트 보기"}
            )
    if resources.review_id is not None:
        links.append(
            {
                "kind": "review",
                "href": f"/reviews/{resources.review_id}",
                "label": "검토 보기",
            }
        )
    if resources.export_id is not None:
        links.append(
            {
                "kind": "export",
                "href": f"/exports/{resources.export_id}",
                "label": "내보내기 보기",
            }
        )
    return links


def _resource_actions(resources: _ResourceIds, stage: str) -> JsonList:
    create_label, _ = _ACTION_PRESENTATION["create-run"]
    actions: JsonList = [
        {
            "id": "create-run",
            "href": "/api/v1/runs",
            "method": "POST",
            "label": create_label,
            "requires_ephemeral_approval": False,
        }
    ]
    if resources.run_id is None:
        return actions
    for action in _STAGE_ACTIONS.get(stage, ()):
        label, requires_token = _ACTION_PRESENTATION[action]
        actions.append(
            {
                "id": action,
                "href": f"/api/v1/runs/{resources.run_id}/{action}",
                "method": "POST",
                "label": label,
                "requires_ephemeral_approval": requires_token,
            }
        )
    return actions


def _action_plan_json(
    projection: VerticalProjection, retained_digest: JsonValue = None
) -> JsonObject | None:
    digest = projection["plan_digest"]
    if digest is None and isinstance(retained_digest, str):
        digest = retained_digest
    if digest is None:
        return None
    stage = projection["stage"]
    approval_status = {
        "plan": "승인 대기",
        "approve": "승인 완료",
        "reject": "승인 거절",
        "cancel": "실행 취소",
        "expire": "승인 만료",
    }.get(stage, "승인 사용 완료")
    return {
        "digest": digest,
        "scope_label": "현재 ActionPlan의 격리 실행 1회",
        "approval_status_label": approval_status,
        "approval_expires_at": projection["approval_expires_at"],
        "approval_ttl_seconds": projection["approval_ttl_seconds"],
    }


def _timeline_json(stage: str) -> JsonList:
    paths = {
        "reject": ("upload", "plan", "reject"),
        "cancel": ("upload", "plan", "cancel"),
        "expire": ("upload", "plan", "approve", "expire"),
    }
    current_index = _STAGES.index(stage) if stage in _STAGES else -1
    stages = paths.get(stage, _STAGES[1 : current_index + 1])
    timeline: JsonList = []
    for item in stages:
        timeline.append(
            {
                "step": item,
                "name": _STAGE_LABELS[item],
                "status": "현재 단계" if item == stage else "완료",
                "tone": _STAGE_TONES[item] if item == stage else "positive",
            }
        )
    return timeline


def _projection_json(projection: VerticalProjection) -> JsonObject:
    """Deep-copy a vertical projection into JSON-compatible containers."""
    artifacts: JsonList = []
    for artifact in projection["artifacts"]:
        artifacts.append(
            {
                "name": artifact["name"],
                "category": artifact["category"],
                "sha256": artifact["sha256"],
            }
        )

    review_json: JsonObject | None = None
    review = projection["review"]
    if review is not None:
        pinned_hashes: JsonObject = {}
        for name, artifact_hash in review["pinned_hashes"].items():
            pinned_hashes[name] = artifact_hash
        review_json = {
            "verdict": review["verdict"],
            "pinned_hashes": pinned_hashes,
        }

    export_json: JsonObject | None = None
    export = projection["export"]
    if export is not None:
        paths: JsonList = []
        for path in export["paths"]:
            paths.append(path)
        export_json = {
            "manifest_sha256": export["manifest_sha256"],
            "paths": paths,
        }

    cleanup_json: JsonObject | None = None
    cleanup = projection["cleanup"]
    if cleanup is not None:
        preserved_artifact_hashes: JsonList = []
        for artifact_hash in cleanup["preserved_artifact_hashes"]:
            preserved_artifact_hashes.append(artifact_hash)
        cleanup_json = {
            "removed_runtime_data": cleanup["removed_runtime_data"],
            "preserved_artifact_hashes": preserved_artifact_hashes,
        }

    research_intent_json: JsonObject | None = None
    research_intent = projection["research_intent"]
    if research_intent is not None:
        success_criteria: JsonList = list(research_intent["success_criteria"])
        constraints: JsonList = list(research_intent["constraints"])
        stop_conditions: JsonList = list(research_intent["stop_conditions"])
        research_intent_json = {
            "question": research_intent["question"],
            "rationale": research_intent["rationale"],
            "intended_benefit": research_intent["intended_benefit"],
            "success_criteria": success_criteria,
            "constraints": constraints,
            "stop_conditions": stop_conditions,
            "research_mode": research_intent["research_mode"],
            "data_origin": research_intent["data_origin"],
            "synthetic_generator_ref": research_intent["synthetic_generator_ref"],
            "synthetic_validator_ref": research_intent["synthetic_validator_ref"],
        }

    return {
        "stage": projection["stage"],
        "artifacts": artifacts,
        "plan_digest": projection["plan_digest"],
        "research_intent": research_intent_json,
        "research_intent_sha256": projection["research_intent_sha256"],
        "review": review_json,
        "export": export_json,
        "cleanup": cleanup_json,
        "child_succeeded": projection["child_succeeded"],
        "approval_expires_at": projection["approval_expires_at"],
        "approval_ttl_seconds": projection["approval_ttl_seconds"],
    }


def _string_value(body: JsonObject, key: str, default: str = "") -> str:
    """Read a string request value without coercing other JSON values."""
    value = body.get(key)
    return value if isinstance(value, str) else default


def _optional_string(value: JsonValue | None) -> str | None:
    """Read a nullable string request value without coercing other JSON values."""
    return value if isinstance(value, str) else None
