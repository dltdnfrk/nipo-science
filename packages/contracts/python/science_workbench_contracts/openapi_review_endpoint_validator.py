from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .openapi_semantics import OpenApiDocument, SchemaDefinition, SchemaProperty

UUID7_REF = "#/components/schemas/Uuid7"


def _has_object_shape(
    schema: SchemaDefinition,
    required: tuple[str, ...],
    properties: tuple[str, ...] | None = None,
) -> bool:
    expected = required if properties is None else properties
    return (
        schema.schema_type == "object"
        and schema.additional_properties is False
        and schema.required == required
        and set(schema.properties) == set(expected)
    )


def _is_uuid_array(property_schema: SchemaProperty) -> bool:
    return (
        property_schema.schema_type == "array"
        and property_schema.min_items == 1
        and property_schema.items is not None
        and property_schema.items.ref == UUID7_REF
    )


def validate_review_endpoint_openapi(document: OpenApiDocument) -> tuple[str, ...]:
    issues: list[str] = []
    create = document.components.schemas.get("ReviewCreate")
    create_fields = ("source_run_id", "artifact_version_ids", "execution_ids")
    valid = create is not None and _has_object_shape(
        create, ("source_run_id",), create_fields
    )
    if valid and create is not None:
        valid = (
            create.properties["source_run_id"].ref == UUID7_REF
            and _is_uuid_array(create.properties["artifact_version_ids"])
            and _is_uuid_array(create.properties["execution_ids"])
            and tuple(option.required for option in create.any_of)
            == (("artifact_version_ids",), ("execution_ids",))
        )
    if not valid:
        issues.append("review-create-pins")
    path = document.paths.get("/api/v1/reviews")
    post = None if path is None else path.post
    accepted = None if post is None else post.responses.get("202")
    media = None if accepted is None else accepted.content.get("application/json")
    accepted_schema = document.components.schemas.get("ReviewCreateAccepted")
    accepted_fields = ("review_id", "run_id", "status")
    if (
        media is None
        or media.schema_definition.ref != "#/components/schemas/ReviewCreateAccepted"
        or accepted_schema is None
        or not _has_object_shape(accepted_schema, accepted_fields)
        or accepted_schema.properties["review_id"].ref != UUID7_REF
        or accepted_schema.properties["run_id"].ref != UUID7_REF
        or accepted_schema.properties["status"].const_value != "queued"
    ):
        issues.append("review-create-response")
    return tuple(issues)
