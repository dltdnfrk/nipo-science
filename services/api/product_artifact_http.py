"""Tenant-scoped HTTP projection for immutable Artifact Versions."""

from __future__ import annotations

from dataclasses import dataclass
from http import HTTPStatus
from typing import TYPE_CHECKING

from services.api.artifact_ui_http import (
    BAD_REQUEST,
    CONFLICT,
    NOT_FOUND,
    send_bytes,
    send_json,
)
from services.api.product_artifact_types import (
    ArtifactVersionConflictError,
    ArtifactVersionDraft,
    UnsupportedArtifactMediaError,
)
from services.api.product_artifact_views import (
    artifact_detail_json,
    artifact_list_json,
)

if TYPE_CHECKING:
    from http.server import BaseHTTPRequestHandler

    from services.api.product_artifact_views import JsonObject
    from services.api.product_artifacts import ProductArtifactService

_ENVIRONMENT_SHA256 = "e" * 64
_DETAIL_PARTS = 4
_VERSION_PARTS = 6
_DOWNLOAD_PARTS = 7
_ARTIFACT_BASE = ("api", "v1", "artifacts")


@dataclass(frozen=True, slots=True)
class ArtifactHttpContext:
    """Tenant-safe service and preview-origin dependencies."""

    artifacts: ProductArtifactService
    artifact_origin: str
    organization_id: str
    session_ids: frozenset[str]


def artifact_get(
    handler: BaseHTTPRequestHandler,
    context: ArtifactHttpContext,
    path: str,
) -> None:
    """Serve a list, selected detail, or immutable Version download."""
    parts = _path_parts(path)
    if parts == _ARTIFACT_BASE:
        send_json(
            handler,
            HTTPStatus.OK,
            artifact_list_json(context.artifacts.list_latest(context.organization_id)),
        )
        return
    if parts[:3] != _ARTIFACT_BASE:
        send_bytes(handler, HTTPStatus.NOT_FOUND, NOT_FOUND)
        return
    if len(parts) == _DETAIL_PARTS:
        _detail(handler, context, parts[3])
        return
    if len(parts) == _VERSION_PARTS and parts[4] == "versions":
        _detail(handler, context, parts[3], parts[5])
        return
    if (
        len(parts) == _DOWNLOAD_PARTS
        and parts[4] == "versions"
        and parts[6] == "download"
    ):
        _download(handler, context, parts[3], parts[5])
        return
    send_bytes(handler, HTTPStatus.NOT_FOUND, NOT_FOUND)


def create_artifact_version(
    handler: BaseHTTPRequestHandler,
    context: ArtifactHttpContext,
    artifact_id: str,
    body: JsonObject | None,
) -> None:
    """Append a bounded passive CSV Version against an explicit base."""
    base = body.get("base_version_no") if body else None
    name = body.get("name") if body else None
    media_type = body.get("media_type") if body else None
    content = body.get("content") if body else None
    current = context.artifacts.detail(context.organization_id, artifact_id)
    if (
        current is None
        or type(base) is not int
        or not isinstance(name, str)
        or not isinstance(media_type, str)
        or not isinstance(content, str)
    ):
        send_bytes(handler, HTTPStatus.BAD_REQUEST, BAD_REQUEST)
        return
    try:
        created = context.artifacts.create_version(
            ArtifactVersionDraft(
                organization_id=context.organization_id,
                artifact_id=artifact_id,
                name=name,
                media_type=media_type,
                content=content.encode(),
                producer_execution_id=f"execution-ui-{base + 1}",
                environment_sha256=_ENVIRONMENT_SHA256,
                lineage_version_ids=(current.selected.id,),
            ),
            base_version_no=base,
        )
    except ArtifactVersionConflictError:
        send_bytes(handler, HTTPStatus.CONFLICT, CONFLICT)
        return
    except (UnicodeEncodeError, UnsupportedArtifactMediaError):
        send_bytes(handler, HTTPStatus.BAD_REQUEST, BAD_REQUEST)
        return
    _detail(handler, context, artifact_id, created.id, status=HTTPStatus.CREATED)


def mutate_artifact_attachment(
    handler: BaseHTTPRequestHandler,
    context: ArtifactHttpContext,
    parts: tuple[str, ...],
    body: JsonObject | None,
    *,
    attach: bool,
) -> None:
    """Mutate only the Version named in the tenant-scoped route."""
    artifact_id, version_id = parts[3], parts[5]
    session_id = body.get("session_id") if body else None
    selected = context.artifacts.detail(
        context.organization_id, artifact_id, version_id
    )
    if (
        not isinstance(session_id, str)
        or session_id not in context.session_ids
        or selected is None
    ):
        send_bytes(handler, HTTPStatus.NOT_FOUND, NOT_FOUND)
        return
    sessions = (
        context.artifacts.attach(context.organization_id, version_id, session_id)
        if attach
        else context.artifacts.detach(context.organization_id, version_id, session_id)
    )
    send_json(
        handler,
        HTTPStatus.OK,
        {"version_id": version_id, "attached_session_ids": list(sessions)},
    )


def _detail(
    handler: BaseHTTPRequestHandler,
    context: ArtifactHttpContext,
    artifact_id: str,
    version_id: str | None = None,
    *,
    status: HTTPStatus = HTTPStatus.OK,
) -> None:
    detail = context.artifacts.detail(context.organization_id, artifact_id, version_id)
    if detail is None:
        send_bytes(handler, HTTPStatus.NOT_FOUND, NOT_FOUND)
        return
    send_json(
        handler,
        status,
        artifact_detail_json(detail, context.artifact_origin),
    )


def _download(
    handler: BaseHTTPRequestHandler,
    context: ArtifactHttpContext,
    artifact_id: str,
    version_id: str,
) -> None:
    version = context.artifacts.download(context.organization_id, version_id)
    if version is None or version.artifact_id != artifact_id:
        send_bytes(handler, HTTPStatus.NOT_FOUND, NOT_FOUND)
        return
    send_bytes(
        handler,
        HTTPStatus.OK,
        version.content,
        {
            "Content-Type": version.media_type,
            "Content-Disposition": f'attachment; filename="{version.name}"',
            "X-Content-SHA256": version.sha256,
            "X-Content-Type-Options": "nosniff",
        },
    )


def _path_parts(path: str) -> tuple[str, ...]:
    if not path.startswith("/") or path.endswith("/") or "//" in path:
        return ()
    return tuple(path.removeprefix("/").split("/"))
