from __future__ import annotations

from .openapi_export_validator import validate_export_openapi
from .openapi_review_endpoint_validator import validate_review_endpoint_openapi
from .openapi_review_validator import validate_review_openapi
from .openapi_semantics import (
    IF_MATCH_OPERATIONS,
    REQUIRED_PATHS,
    OpenApiDocument,
    Operation,
    operations,
)

ERROR_REF = "#/components/responses/Error"
IDEMPOTENCY_REF = "#/components/parameters/IdempotencyKey"
IF_MATCH_REF = "#/components/parameters/IfMatch"
CROSS_TENANT_NOT_FOUND = 404
ERROR_STATUS_MINIMUM = 400


def _has_parameter(operation: Operation, expected: str) -> bool:
    return any(parameter.ref == expected for parameter in operation.parameters)


def validate_openapi(document: OpenApiDocument) -> tuple[str, ...]:
    issues = [
        *validate_review_openapi(document),
        *validate_review_endpoint_openapi(document),
        *validate_export_openapi(document),
    ]
    tenancy = document.tenancy
    auth = document.auth_contract
    cookie = document.components.security_schemes.get("HostSession")

    if tenancy.org_id != "server-derived" or tenancy.client_authority:
        issues.append("server-derived-tenancy")
    if tenancy.cross_tenant_status != CROSS_TENANT_NOT_FOUND:
        issues.append("cross-tenant-404")
    if not REQUIRED_PATHS.issubset(document.paths):
        issues.append("required-api-surfaces")
    if cookie is None or (
        cookie.name != "__Host-swb_session"
        or not cookie.host_only
        or not cookie.secure
        or not cookie.http_only
        or cookie.same_site != "Lax"
    ):
        issues.append("host-only-secure-cookie")
    if (
        auth.csrf_header != "X-CSRF-Token"
        or not auth.origin_required
        or auth.fetch_metadata_header != "Sec-Fetch-Site"
        or auth.fetch_metadata_allowed != ("same-origin",)
    ):
        issues.append("cookie-csrf-origin-fetch-metadata")

    for path, method, operation in operations(document):
        if method in {"post", "patch", "delete"} and not operation.mutation_protection:
            issues.append(f"mutation-protection:{method}:{path}")
        if operation.tenant_scoped:
            tenant_missing = "404" not in operation.responses
            tenant_disclosing = (
                "403" in operation.responses and not operation.capability_forbidden
            )
            if tenant_missing or tenant_disclosing:
                issues.append(f"cross-tenant-404:{method}:{path}")
            if method == "post" and not _has_parameter(operation, IDEMPOTENCY_REF):
                issues.append(f"idempotency-key:{method}:{path}")
        if (path, method) in IF_MATCH_OPERATIONS and not _has_parameter(
            operation, IF_MATCH_REF
        ):
            issues.append(f"if-match:{method}:{path}")
        for status, response in operation.responses.items():
            if int(status) >= ERROR_STATUS_MINIMUM and response.ref != ERROR_REF:
                issues.append(f"canonical-error-envelope:{method}:{path}:{status}")

    schemas = document.components.schemas
    uuid7 = schemas.get("Uuid7")
    timestamp = schemas.get("UtcTimestamp")
    error = schemas.get("ErrorEnvelope")
    if uuid7 is None or uuid7.pattern is None or "-7" not in uuid7.pattern:
        issues.append("uuidv7-primary-ids")
    if timestamp is None or timestamp.pattern != "Z$" or not timestamp.utc_only:
        issues.append("utc-timestamps")
    if error is None or error.required != ("error",):
        issues.append("canonical-error-envelope")
    else:
        inner = error.properties.get("error")
        if inner is None or inner.required != ("code", "message", "request_id"):
            issues.append("canonical-error-envelope")
    for name, schema in schemas.items():
        if name.endswith("Create") and "org_id" in schema.properties:
            issues.append(f"client-org-id-authority:{name}")

    return tuple(issues)
