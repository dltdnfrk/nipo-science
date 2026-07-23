"""Authenticated HTTP translation for the durable Artifact domain service."""

from __future__ import annotations

from dataclasses import dataclass
from http import HTTPStatus
from typing import TYPE_CHECKING, ClassVar, Protocol, cast, final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .models import (
    ArtifactError,
    ArtifactErrorCode,
    ArtifactScope,
    ArtifactVersion,
    Sha256,
    Uuid7,
    VersionDraft,
)
from .recovery import ArtifactRecoveryError
from .store_contract import ArtifactStoreError

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .service import ArtifactService

type JsonScalar = None | bool | int | float | str
type JsonList = list[JsonValue]
type JsonObject = dict[str, JsonValue]
type JsonValue = JsonScalar | JsonList | JsonObject


class ArtifactScopeResolver(Protocol):
    """Resolve active Artifact scope under one authenticated principal."""

    def artifact_scope(
        self,
        org_id: UUID,
        requester_id: UUID,
        artifact_id: UUID,
    ) -> ArtifactScope | None:
        """Resolve an Artifact's active Project or disclose nothing."""
        ...

    def version_scope(
        self,
        org_id: UUID,
        requester_id: UUID,
        artifact_id: UUID,
        version_id: UUID,
    ) -> ArtifactScope | None:
        """Resolve an exact Version's active Project or disclose nothing."""
        ...


class _ArtifactCreate(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")

    project_id: Uuid7
    name: str = Field(min_length=1, max_length=255)


class _VersionCreate(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")

    base_version_no: int = Field(ge=0)
    watcher_reference: str = Field(min_length=1, max_length=255)
    producing_execution_id: Uuid7
    environment_sha256: Sha256
    code_sha256: Sha256
    runtime_adapter_id: str = Field(min_length=1, max_length=255)
    runtime_connection_id: Uuid7
    skill_content_hashes: tuple[Sha256, ...]
    source_hashes: tuple[Sha256, ...]
    input_version_ids: tuple[Uuid7, ...]

    def draft(self, artifact_id: UUID) -> VersionDraft:
        return VersionDraft(
            artifact_id=artifact_id,
            base_version_no=self.base_version_no,
            watcher_reference=self.watcher_reference,
            producing_execution_id=self.producing_execution_id,
            environment_sha256=self.environment_sha256,
            code_sha256=self.code_sha256,
            runtime_adapter_id=self.runtime_adapter_id,
            runtime_connection_id=self.runtime_connection_id,
            skill_content_hashes=self.skill_content_hashes,
            source_hashes=self.source_hashes,
            input_version_ids=self.input_version_ids,
        )


@dataclass(frozen=True, slots=True)
class ArtifactHttpResponse:
    """One normalized response with either JSON metadata or immutable bytes."""

    status: HTTPStatus
    payload: JsonObject | None = None
    content: bytes | None = None
    media_type: str | None = None
    content_sha256: str | None = None


@final
class ArtifactHttpService:
    """Translate authenticated Artifact requests without accepting identity fields."""

    def __init__(
        self,
        service: ArtifactService,
        scopes: ArtifactScopeResolver,
    ) -> None:
        """Bind the durable domain and forced-RLS scope authority."""
        self._service = service
        self._scopes = scopes

    def resolve_artifact_scope(
        self,
        org_id: UUID,
        requester_id: UUID,
        artifact_id: UUID,
    ) -> ArtifactScope | None:
        """Expose the same principal-scoped lookup used by output registration."""
        return self._scopes.artifact_scope(org_id, requester_id, artifact_id)

    def create_artifact(
        self,
        organization_id: str,
        requester_id: str,
        body: Mapping[str, JsonValue],
    ) -> ArtifactHttpResponse:
        """Create one Artifact from server-derived principal and client Project."""
        try:
            principal = _principal_ids(organization_id, requester_id)
            command = _ArtifactCreate.model_validate(body)
            scope = ArtifactScope(
                org_id=principal[0],
                project_id=command.project_id,
                requester_id=principal[1],
            )
            artifact = self._service.create_artifact(scope, command.name)
        except ValidationError:
            return _invalid_request()
        except ArtifactError as error:
            return _domain_error(error)
        except ArtifactStoreError:
            return _unavailable()
        return ArtifactHttpResponse(
            HTTPStatus.CREATED,
            cast("JsonObject", artifact.model_dump(mode="json")),
        )

    def read_artifact(
        self,
        organization_id: str,
        requester_id: str,
        artifact_id: str,
    ) -> ArtifactHttpResponse:
        """Read one exact Artifact through its principal-scoped Project."""
        try:
            principal = _principal_ids(organization_id, requester_id)
            identity = UUID(artifact_id)
            scope = self._scopes.artifact_scope(*principal, identity)
            if scope is None:
                return _not_found()
            artifact = self._service.read_artifact(scope, identity)
        except (ValueError, ValidationError):
            return _not_found()
        except (ArtifactError, ArtifactStoreError) as error:
            return _normalized_error(error)
        return ArtifactHttpResponse(
            HTTPStatus.OK,
            cast("JsonObject", artifact.model_dump(mode="json")),
        )

    def create_version(
        self,
        organization_id: str,
        requester_id: str,
        artifact_id: str,
        body: Mapping[str, JsonValue],
    ) -> ArtifactHttpResponse:
        """Append one Version while binding its parent ID from the route."""
        try:
            principal = _principal_ids(organization_id, requester_id)
            identity = UUID(artifact_id)
            scope = self._scopes.artifact_scope(*principal, identity)
            if scope is None:
                return _not_found()
            command = _VersionCreate.model_validate(body)
            version = self._service.create_version(scope, command.draft(identity))
        except (ValueError, ValidationError):
            return _invalid_request()
        except ArtifactError as error:
            return _domain_error(error)
        except (ArtifactRecoveryError, ArtifactStoreError):
            return _unavailable()
        return ArtifactHttpResponse(HTTPStatus.CREATED, _version_payload(version))

    def read_version(
        self,
        organization_id: str,
        requester_id: str,
        artifact_id: str,
        version_id: str,
    ) -> ArtifactHttpResponse:
        """Read one exact Version without exposing its private object key."""
        resolved = self._resolve_version(
            organization_id,
            requester_id,
            artifact_id,
            version_id,
        )
        if isinstance(resolved, ArtifactHttpResponse):
            return resolved
        scope, identity = resolved
        try:
            version = self._service.read_version(scope, identity)
        except (ArtifactError, ArtifactStoreError) as error:
            return _normalized_error(error)
        return ArtifactHttpResponse(HTTPStatus.OK, _version_payload(version))

    def download_version(
        self,
        organization_id: str,
        requester_id: str,
        artifact_id: str,
        version_id: str,
    ) -> ArtifactHttpResponse:
        """Read checksum-verified bytes only for an exact active Version scope."""
        resolved = self._resolve_version(
            organization_id,
            requester_id,
            artifact_id,
            version_id,
        )
        if isinstance(resolved, ArtifactHttpResponse):
            return resolved
        scope, identity = resolved
        try:
            version, content = self._service.read_active_content(scope, identity)
        except (ArtifactError, ArtifactStoreError) as error:
            return _normalized_error(error)
        return ArtifactHttpResponse(
            HTTPStatus.OK,
            content=content,
            media_type=version.media_type,
            content_sha256=version.content_sha256,
        )

    def _resolve_version(
        self,
        organization_id: str,
        requester_id: str,
        artifact_id: str,
        version_id: str,
    ) -> tuple[ArtifactScope, UUID] | ArtifactHttpResponse:
        try:
            principal = _principal_ids(organization_id, requester_id)
            artifact_identity = UUID(artifact_id)
            version_identity = UUID(version_id)
            scope = self._scopes.version_scope(
                *principal,
                artifact_identity,
                version_identity,
            )
        except (ValueError, ValidationError):
            return _not_found()
        except ArtifactStoreError:
            return _unavailable()
        if scope is None:
            return _not_found()
        return scope, version_identity


def _principal_ids(organization_id: str, requester_id: str) -> tuple[UUID, UUID]:
    return UUID(organization_id), UUID(requester_id)


def _version_payload(version: ArtifactVersion) -> JsonObject:
    values = version.model_dump(mode="json", exclude={"object_key", "version_no"})
    values["version"] = version.version_no
    values["immutable"] = True
    return cast("JsonObject", values)


def _not_found() -> ArtifactHttpResponse:
    return ArtifactHttpResponse(HTTPStatus.NOT_FOUND, {"error": "not_found"})


def _invalid_request() -> ArtifactHttpResponse:
    return ArtifactHttpResponse(
        HTTPStatus.BAD_REQUEST,
        {"error": "invalid_request"},
    )


def _unavailable() -> ArtifactHttpResponse:
    return ArtifactHttpResponse(
        HTTPStatus.SERVICE_UNAVAILABLE,
        {"error": "service_unavailable"},
    )


def _domain_error(error: ArtifactError) -> ArtifactHttpResponse:
    if error.code in {ArtifactErrorCode.NOT_FOUND, ArtifactErrorCode.PROJECT_ARCHIVED}:
        return _not_found()
    if error.code is ArtifactErrorCode.CHECKSUM_MISMATCH:
        return _unavailable()
    return ArtifactHttpResponse(HTTPStatus.CONFLICT, {"error": "version_conflict"})


def _normalized_error(
    error: ArtifactError | ArtifactStoreError,
) -> ArtifactHttpResponse:
    return _domain_error(error) if isinstance(error, ArtifactError) else _unavailable()
