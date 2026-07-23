"""JSON-safe projections for the test-principal Artifact UI."""

from datetime import UTC

from services.api.product_artifact_types import ArtifactDetail, ArtifactVersion

type JsonScalar = None | bool | int | float | str
type JsonList = list[JsonValue]
type JsonObject = dict[str, JsonValue]
type JsonValue = JsonScalar | JsonList | JsonObject


def artifact_list_json(versions: tuple[ArtifactVersion, ...]) -> JsonObject:
    """Serialize a tenant-filtered latest-Version list."""
    return {"artifacts": [_version_json(version) for version in versions]}


def artifact_detail_json(
    detail: ArtifactDetail, artifact_origin: str | None
) -> JsonObject:
    """Serialize safe Artifact detail and the isolated preview URL."""
    selected = detail.selected
    return {
        "artifact_id": selected.artifact_id,
        "name": selected.name,
        "selected": _version_json(selected),
        "versions": [_version_json(version) for version in detail.versions],
        "previous_version_id": None if detail.previous is None else detail.previous.id,
        "changed_bytes": detail.changed_bytes,
        "attached_session_ids": list(detail.attached_session_ids),
        "preview_url": (
            f"{artifact_origin}/preview/{selected.preview_token}"
            if artifact_origin is not None
            else None
        ),
        "artifact_origin": artifact_origin,
        "download_url": (
            f"/api/v1/artifacts/{selected.artifact_id}/versions/{selected.id}/download"
        ),
    }


def _version_json(version: ArtifactVersion) -> JsonObject:
    return {
        "id": version.id,
        "artifact_id": version.artifact_id,
        "name": version.name,
        "version_no": version.version_no,
        "media_type": version.media_type,
        "sha256": version.sha256,
        "producer_execution_id": version.producer_execution_id,
        "environment_sha256": version.environment_sha256,
        "lineage_version_ids": list(version.lineage_version_ids),
        "created_at": version.created_at.astimezone(UTC)
        .isoformat()
        .replace("+00:00", "Z"),
        "status": version.status,
    }
