from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .openapi_semantics import OpenApiDocument, SchemaDefinition, SchemaProperty

UUID7_REF = "#/components/schemas/Uuid7"
NULLABLE_VARIANT_COUNT = 2


def _has_object_shape(
    schema: SchemaDefinition,
    required: tuple[str, ...],
    properties: tuple[str, ...] | None = None,
) -> bool:
    expected_properties = required if properties is None else properties
    return (
        schema.schema_type == "object"
        and schema.additional_properties is False
        and schema.required == required
        and set(schema.properties) == set(expected_properties)
    )


def _is_ref_or_null(property_schema: SchemaProperty, expected_ref: str) -> bool:
    variants = property_schema.any_of
    return (
        len(variants) == NULLABLE_VARIANT_COUNT
        and variants[0].ref == expected_ref
        and variants[1].schema_type == "null"
    )


def _is_uuid_array(property_schema: SchemaProperty, min_items: int | None) -> bool:
    return (
        property_schema.schema_type == "array"
        and property_schema.min_items == min_items
        and property_schema.items is not None
        and property_schema.items.ref == UUID7_REF
    )


def _review_schema_issues(document: OpenApiDocument) -> tuple[str, ...]:
    issues: list[str] = []
    schemas = document.components.schemas
    capability_names = (
        "runner",
        "python",
        "bash",
        "connector",
        "network",
        "artifact_write",
        "tool_execute",
        "version_update",
        "reexecution",
    )
    capabilities = schemas.get("ReviewerCapabilities")
    if (
        capabilities is None
        or not _has_object_shape(capabilities, capability_names)
        or any(
            property_schema.const_value is not False
            for property_schema in capabilities.properties.values()
        )
    ):
        issues.append("reviewer-capabilities")

    finding_fields = (
        "id",
        "rule_id",
        "verdict",
        "status",
        "artifact_version_ids",
        "execution_ids",
        "message",
        "disposition_actor_id",
        "disposition_reason",
    )
    finding = schemas.get("ReviewFinding")
    finding_valid = finding is not None and _has_object_shape(finding, finding_fields)
    if finding_valid and finding is not None:
        actor = finding.properties["disposition_actor_id"]
        reason = finding.properties["disposition_reason"]
        audit_rule = (
            finding.all_of[0] if len(finding.all_of) == NULLABLE_VARIANT_COUNT else None
        )
        audit_if = None if audit_rule is None else audit_rule.if_schema
        audit_then = None if audit_rule is None else audit_rule.then_schema
        audit_status = None if audit_if is None else audit_if.properties.get("status")
        normal_rule = (
            finding.all_of[1] if len(finding.all_of) == NULLABLE_VARIANT_COUNT else None
        )
        normal_if = None if normal_rule is None else normal_rule.if_schema
        normal_then = None if normal_rule is None else normal_rule.then_schema
        normal_status = (
            None if normal_if is None else normal_if.properties.get("status")
        )
        audit_actor = (
            None
            if audit_then is None
            else audit_then.properties.get("disposition_actor_id")
        )
        audit_reason = (
            None
            if audit_then is None
            else audit_then.properties.get("disposition_reason")
        )
        normal_actor = (
            None
            if normal_then is None
            else normal_then.properties.get("disposition_actor_id")
        )
        normal_reason = (
            None
            if normal_then is None
            else normal_then.properties.get("disposition_reason")
        )
        finding_valid = (
            finding.properties["id"].ref == UUID7_REF
            and finding.properties["rule_id"].enum
            == ("RV01", "RV02", "RV03", "RV04", "RV05")
            and finding.properties["verdict"].enum
            == ("pass", "warn", "fail", "inconclusive")
            and finding.properties["status"].enum
            == ("open", "resolved", "rebutted", "accepted_risk")
            and _is_uuid_array(finding.properties["artifact_version_ids"], 1)
            and _is_uuid_array(finding.properties["execution_ids"], None)
            and finding.properties["message"].min_length == 1
            and _is_ref_or_null(actor, UUID7_REF)
            and len(reason.any_of) == NULLABLE_VARIANT_COUNT
            and reason.any_of[0].schema_type == "string"
            and reason.any_of[0].min_length == 1
            and reason.any_of[1].schema_type == "null"
            and audit_status is not None
            and audit_status.enum == ("rebutted", "accepted_risk")
            and audit_then is not None
            and audit_then.required == ("disposition_actor_id", "disposition_reason")
            and audit_actor is not None
            and audit_actor.ref == UUID7_REF
            and audit_reason is not None
            and audit_reason.min_length == 1
            and normal_status is not None
            and normal_status.enum == ("open", "resolved")
            and normal_then is not None
            and normal_actor is not None
            and normal_actor.schema_type == "null"
            and normal_reason is not None
            and normal_reason.schema_type == "null"
        )
    if not finding_valid:
        issues.append("review-finding")

    submission_fields = ("submission_id", "exactly_once", "submitted_at", "findings")
    submission = schemas.get("FindingsSubmission")
    submission_valid = submission is not None and _has_object_shape(
        submission, submission_fields
    )
    if submission_valid and submission is not None:
        findings = submission.properties["findings"]
        submission_valid = (
            submission.properties["submission_id"].ref == UUID7_REF
            and submission.properties["exactly_once"].const_value is True
            and findings.schema_type == "array"
            and findings.min_items == 1
            and findings.items is not None
            and findings.items.ref == "#/components/schemas/ReviewFinding"
        )
    if not submission_valid:
        issues.append("findings-submission")

    persisted_fields = (
        "id",
        "revision",
        "run_id",
        "source_run_id",
        "status",
        "pinned_artifact_version_ids",
        "pinned_execution_ids",
        "pinned_input_sha256",
        "reviewer_capabilities",
        "submission",
        "created_at",
    )
    persisted = schemas.get("PersistedReview")
    persisted_valid = persisted is not None and _has_object_shape(
        persisted, persisted_fields
    )
    if persisted_valid and persisted is not None:
        reviewer = persisted.properties["reviewer_capabilities"]
        persisted_submission = persisted.properties["submission"]
        persisted_valid = (
            reviewer.ref == "#/components/schemas/ReviewerCapabilities"
            and _is_uuid_array(
                persisted.properties["pinned_artifact_version_ids"], None
            )
            and _is_uuid_array(persisted.properties["pinned_execution_ids"], None)
            and len(persisted.any_of) == NULLABLE_VARIANT_COUNT
            and persisted.any_of[0].properties["pinned_artifact_version_ids"].min_items
            == 1
            and persisted.any_of[1].properties["pinned_execution_ids"].min_items == 1
            and _is_ref_or_null(
                persisted_submission, "#/components/schemas/FindingsSubmission"
            )
        )
    if not persisted_valid:
        issues.append("persisted-review-submission")
    return tuple(issues)


def validate_review_openapi(document: OpenApiDocument) -> tuple[str, ...]:
    return _review_schema_issues(document)
