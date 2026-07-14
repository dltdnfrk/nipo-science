from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .openapi_semantics import OpenApiDocument

UUID7_REF = "#/components/schemas/Uuid7"


def validate_export_openapi(document: OpenApiDocument) -> tuple[str, ...]:
    schemas = document.components.schemas
    fields = ("path", "artifact_version_id", "sha256", "media_type", "entry_kind")
    entry = schemas.get("ArtifactExportEntry")
    valid = (
        entry is not None
        and entry.schema_type == "object"
        and entry.additional_properties is False
        and entry.required == fields
        and set(entry.properties) == set(fields)
    )
    if valid and entry is not None:
        path = entry.properties["path"]
        valid = (
            path.schema_type == "string"
            and path.min_length == 1
            and path.pattern == "^[A-Za-z0-9._/-]+$"
            and path.safe_export_path is True
            and entry.properties["artifact_version_id"].ref == UUID7_REF
            and entry.properties["sha256"].pattern == "^[0-9a-f]{64}$"
            and entry.properties["media_type"].min_length == 1
            and entry.properties["entry_kind"].const_value == "file"
        )
    manifest = schemas.get("ExportManifest")
    entries = None if manifest is None else manifest.properties.get("artifact_entries")
    if (
        valid
        and entries is not None
        and entries.schema_type == "array"
        and entries.min_items == 1
        and entries.items is not None
        and entries.items.ref == "#/components/schemas/ArtifactExportEntry"
    ):
        return ()
    return ("artifact-export-entry",)
