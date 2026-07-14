"""Session-scoped product adapter for the deterministic dry-lab vertical."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from typing import Literal, final

from science_workbench_science.vertical import (
    DryLabVertical,
    FixtureFailure,
    VerticalProjection,
)

type JsonScalar = None | bool | int | float | str
type JsonList = list[JsonValue]
type JsonObject = dict[str, JsonValue]
type JsonValue = JsonScalar | JsonList | JsonObject

type DryLabAction = Literal[
    "upload", "plan", "approve", "execute", "review", "export", "cleanup", "state"
]

_UNAUTHORIZED_STATUS = 401
_NOT_FOUND_STATUS = 404
_CREATED_STATUS = 201
_ACCEPTED_STATUS = 202
_OK_STATUS = 200
_UNAUTHORIZED_CODE = "unauthorized"
_NOT_FOUND_CODE = "not-found"
type ActionHandler = Callable[[DryLabVertical, JsonObject], DryLabResponse]


@dataclass(frozen=True, slots=True)
class DryLabResponse:
    """One JSON-safe response from the dry-lab product adapter."""

    status: int
    payload: JsonObject


@final
class ProductDryLabService:
    """Own one dry-lab vertical for each authenticated opaque session key."""

    def __init__(self) -> None:
        """Initialize an empty session-to-vertical registry."""
        self._lock = Lock()
        self._verticals: dict[str, DryLabVertical] = {}
        self._handlers: dict[str, ActionHandler] = {
            "upload": self._upload,
            "plan": self._plan,
            "approve": self._approve,
            "execute": self._execute,
            "review": self._review,
            "export": self._export,
            "cleanup": self._cleanup,
            "state": self._state,
        }

    @property
    def session_count(self) -> int:
        """Return the number of retained authenticated session verticals."""
        with self._lock:
            return len(self._verticals)

    def drop_session(self, session_key: str) -> None:
        """Remove the vertical retained for a logged-out session key."""
        with self._lock:
            _ = self._verticals.pop(session_key, None)

    def dispatch(
        self, session_key: str, action: str, body: JsonObject
    ) -> DryLabResponse:
        """Run one fixed dry-lab action for an authenticated session."""
        if not session_key:
            return DryLabResponse(_UNAUTHORIZED_STATUS, {"code": _UNAUTHORIZED_CODE})
        handler = self._handlers.get(action)
        if handler is None:
            return DryLabResponse(_NOT_FOUND_STATUS, {"code": _NOT_FOUND_CODE})

        vertical = self._vertical_for(session_key)
        try:
            return handler(vertical, body)
        except FixtureFailure as error:
            return DryLabResponse(error.status, {"code": error.code})

    def _upload(self, vertical: DryLabVertical, body: JsonObject) -> DryLabResponse:
        """Upload a dataset and return its session projection."""
        upload = vertical.upload(
            _string_value(body, "filename"),
            _string_value(body, "csv"),
            request=_string_value(body, "request"),
        )
        return DryLabResponse(
            _CREATED_STATUS,
            {
                "filename": upload.filename,
                "sha256": upload.content_sha256,
                **_projection_json(vertical.read_projection()),
            },
        )

    def _plan(self, vertical: DryLabVertical, body: JsonObject) -> DryLabResponse:
        """Create a plan and return its session projection."""
        plan = vertical.create_plan(
            lease_id=_string_value(body, "lease_id", "fresh")
        )
        return DryLabResponse(
            _CREATED_STATUS,
            {"digest": plan.digest, **_projection_json(vertical.read_projection())},
        )

    def _approve(self, vertical: DryLabVertical, body: JsonObject) -> DryLabResponse:
        """Approve the current plan and return its session projection."""
        approval = vertical.approve(
            _optional_string(body.get("plan_digest"))
        )
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
        del body
        receipt = vertical.cleanup()
        return DryLabResponse(
            _OK_STATUS,
            {
                "removed_runtime_data": receipt.removed_runtime_data,
                "preserved_artifact_hashes": list(
                    receipt.preserved_artifact_hashes
                ),
                **_projection_json(vertical.read_projection()),
            },
        )

    def _state(self, vertical: DryLabVertical, body: JsonObject) -> DryLabResponse:
        """Read the current session projection."""
        del body
        return DryLabResponse(_OK_STATUS, _projection_json(vertical.read_projection()))

    def _vertical_for(self, session_key: str) -> DryLabVertical:
        """Get or create a session vertical while holding only the map lock."""
        with self._lock:
            vertical = self._verticals.get(session_key)
            if vertical is None:
                vertical = DryLabVertical()
                self._verticals[session_key] = vertical
            return vertical


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

    return {
        "stage": projection["stage"],
        "artifacts": artifacts,
        "plan_digest": projection["plan_digest"],
        "review": review_json,
        "export": export_json,
        "cleanup": cleanup_json,
        "child_succeeded": projection["child_succeeded"],
    }

def _string_value(body: JsonObject, key: str, default: str = "") -> str:
    """Read a string request value without coercing other JSON values."""
    value = body.get(key)
    return value if isinstance(value, str) else default


def _optional_string(value: JsonValue | None) -> str | None:
    """Read a nullable string request value without coercing other JSON values."""
    return value if isinstance(value, str) else None
