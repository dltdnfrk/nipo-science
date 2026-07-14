from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Final

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from collections.abc import Iterator


class SemanticModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", frozen=True)


class Reference(SemanticModel):
    ref: str | None = Field(default=None, alias="$ref")


class SchemaProperty(Reference):
    schema_type: str | tuple[str, ...] | None = Field(default=None, alias="type")
    const_value: str | bool | None = Field(default=None, alias="const")
    enum: tuple[str, ...] = ()
    pattern: str | None = None
    min_length: int | None = Field(default=None, alias="minLength")
    min_items: int | None = Field(default=None, alias="minItems")
    read_only: bool | None = Field(default=None, alias="readOnly")
    utc_only: bool | None = Field(default=None, alias="x-utc-only")
    safe_export_path: bool | None = Field(
        default=None, alias="x-safe-relative-posix-path"
    )
    required: tuple[str, ...] = ()
    properties: dict[str, SchemaProperty] = Field(default_factory=dict)
    items: SchemaProperty | None = None
    any_of: tuple[SchemaProperty, ...] = Field(default=(), alias="anyOf")
    all_of: tuple[SchemaProperty, ...] = Field(default=(), alias="allOf")
    if_schema: SchemaProperty | None = Field(default=None, alias="if")
    then_schema: SchemaProperty | None = Field(default=None, alias="then")


class MediaType(SemanticModel):
    schema_definition: SchemaProperty = Field(alias="schema")


class Response(Reference):
    description: str | None = None
    content: dict[str, MediaType] = Field(default_factory=dict)


class Parameter(SemanticModel):
    name: str
    location: str = Field(alias="in")
    required: bool


class SecurityScheme(SemanticModel):
    type: str
    location: str = Field(alias="in")
    name: str
    host_only: bool = Field(alias="x-host-only")
    secure: bool = Field(alias="x-secure")
    http_only: bool = Field(alias="x-http-only")
    same_site: str = Field(alias="x-same-site")


class SchemaDefinition(SchemaProperty):
    additional_properties: bool | None = Field(
        default=None, alias="additionalProperties"
    )


class Operation(SemanticModel):
    tenant_scoped: bool = Field(default=False, alias="x-tenant-scoped")
    capability_forbidden: bool = Field(default=False, alias="x-capability-forbidden")
    mutation_protection: bool = Field(default=False, alias="x-mutation-protection")
    parameters: tuple[Reference, ...] = ()
    responses: dict[str, Response]


class PathItem(SemanticModel):
    get: Operation | None = None
    post: Operation | None = None
    patch: Operation | None = None
    delete: Operation | None = None


class Tenancy(SemanticModel):
    org_id: str
    client_authority: bool
    cross_tenant_status: int


class AuthContract(SemanticModel):
    cookie_name: str
    host_only: bool
    secure: bool
    http_only: bool
    same_site: str
    path: str
    csrf_header: str
    origin_required: bool
    fetch_metadata_header: str
    fetch_metadata_allowed: tuple[str, ...]


class Components(SemanticModel):
    security_schemes: dict[str, SecurityScheme] = Field(alias="securitySchemes")
    parameters: dict[str, Parameter]
    schemas: dict[str, SchemaDefinition]


class OpenApiDocument(SemanticModel):
    openapi: str
    tenancy: Tenancy = Field(alias="x-tenancy")
    auth_contract: AuthContract = Field(alias="x-auth-contract")
    paths: dict[str, PathItem]
    components: Components


REQUIRED_PATHS: Final = frozenset(
    {
        "/api/v1/auth/session",
        "/api/v1/organization",
        "/api/v1/projects/{project_id}",
        "/api/v1/sessions/{session_id}",
        "/api/v1/uploads/{upload_id}",
        "/api/v1/runs/{run_id}",
        "/api/v1/runs/{run_id}/events",
        "/api/v1/runs/{run_id}/approvals",
        "/api/v1/runs/{run_id}/cancel",
        "/api/v1/runs/{run_id}/retry",
        "/api/v1/artifacts/{artifact_id}",
        "/api/v1/artifacts/{artifact_id}/versions/{version_id}",
        "/api/v1/reviews/{review_id}",
        "/api/v1/exports/{export_id}",
        "/api/v1/provider-connections/{connection_id}",
        "/api/v1/deletions/{deletion_id}",
        "/api/v1/legal-hold",
    }
)
IF_MATCH_OPERATIONS: Final = frozenset(
    {
        ("/api/v1/projects/{project_id}", "patch"),
        ("/api/v1/sessions/{session_id}", "patch"),
        ("/api/v1/artifacts/{artifact_id}/versions", "post"),
        ("/api/v1/provider-connections/{connection_id}", "patch"),
        ("/api/v1/provider-connections/{connection_id}", "delete"),
    }
)


def operations(document: OpenApiDocument) -> Iterator[tuple[str, str, Operation]]:
    for path, item in document.paths.items():
        for method, operation in (
            ("get", item.get),
            ("post", item.post),
            ("patch", item.patch),
            ("delete", item.delete),
        ):
            if operation is not None:
                yield path, method, operation
