from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Final, NamedTuple

from pydantic import TypeAdapter

ROOT = Path(__file__).parents[1]
OPENAPI = ROOT / "packages" / "contracts" / "openapi" / "openapi.json"
VALIDATOR = ROOT / "packages" / "contracts" / "python" / "validate_openapi.py"
type JsonValue = (
    None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
)
type JsonObject = dict[str, JsonValue]

_JSON_OBJECT_ADAPTER: Final[TypeAdapter[JsonObject]] = TypeAdapter(JsonObject)


def _json_object(payload: str) -> JsonObject:
    return _JSON_OBJECT_ADAPTER.validate_json(payload)


def _object_value(value: JsonValue) -> JsonObject:
    assert isinstance(value, dict)
    return value


def _list_value(value: JsonValue) -> list[JsonValue]:
    assert isinstance(value, list)
    return value


def _boolean_value(value: JsonValue) -> bool:
    assert isinstance(value, bool)
    return value


def _string_or_none_value(value: JsonValue | None) -> str | None:
    assert value is None or isinstance(value, str)
    return value


def _boolean_or_none_value(value: JsonValue | None) -> bool | None:
    assert value is None or isinstance(value, bool)
    return value


class ContractMutation(NamedTuple):
    before: str
    after: str
    expected: str


class OpenApiAcceptanceTests(unittest.TestCase):
    def run_validator(self, document: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VALIDATOR), str(document)],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_accepts_complete_openapi_contract(self) -> None:
        # Given: the versioned public API contract.
        self.assertTrue(OPENAPI.is_file(), "OpenAPI contract is not implemented")

        # When: the parsed document is checked through its CLI boundary.
        result = self.run_validator(OPENAPI)

        # Then: every required security and tenancy invariant is present.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("openapi-contract: PASS", result.stdout)

    def test_research_intent_rejects_the_shared_unicode_boundary_set(self) -> None:
        document = _json_object(OPENAPI.read_text(encoding="utf-8"))
        components = _object_value(document["components"])
        schemas = _object_value(components["schemas"])
        intent = _object_value(schemas["ResearchIntent"])
        properties = _object_value(intent["properties"])
        question = _object_value(properties["question"])
        pattern = question["pattern"]
        assert isinstance(pattern, str)
        boundary = re.compile(pattern)

        for value in (" boundary", "boundary ", "\u0085boundary", "\ufeffboundary"):
            self.assertIsNone(boundary.fullmatch(value))
        self.assertIsNotNone(boundary.fullmatch("내부\u0085공백"))

    def test_research_intent_declares_nfc_validation_and_collision_rejection(
        self,
    ) -> None:
        document = _json_object(OPENAPI.read_text(encoding="utf-8"))
        schemas = _object_value(_object_value(document["components"])["schemas"])
        intent = _object_value(schemas["ResearchIntent"])
        properties = _object_value(intent["properties"])
        for field in (
            "question",
            "rationale",
            "intended_benefit",
            "synthetic_generator_ref",
            "synthetic_validator_ref",
        ):
            self.assertEqual(
                _object_value(properties[field])["x-unicode-normalization"], "NFC"
            )
        for field in ("synthetic_generator_ref", "synthetic_validator_ref"):
            reference = _object_value(properties[field])
            self.assertEqual(reference["type"], ["string", "null"])
            self.assertTrue(reference["x-canonical-null-when-absent"])
        for field in ("success_criteria", "constraints", "stop_conditions"):
            items = _object_value(properties[field])
            self.assertEqual(items["x-unique-after-normalization"], "NFC")
            self.assertEqual(
                _object_value(items["items"])["x-unicode-normalization"], "NFC"
            )
        conditions = intent["allOf"]
        self.assertIsInstance(conditions, list)
        assert isinstance(conditions, list)
        self.assertEqual(len(conditions), 2)
        observed_then = _object_value(_object_value(conditions[0])["then"])
        observed_properties = _object_value(observed_then["properties"])
        self.assertIsNone(
            _object_value(observed_properties["synthetic_generator_ref"])["const"]
        )
        synthetic_then = _object_value(_object_value(conditions[1])["then"])
        self.assertEqual(
            synthetic_then["required"],
            ["synthetic_generator_ref", "synthetic_validator_ref"],
        )
        self.assertEqual(
            synthetic_then["x-distinct-fields"],
            ["synthetic_generator_ref", "synthetic_validator_ref"],
        )

    def test_rejects_research_intent_normalization_policy_drift(self) -> None:
        contents = OPENAPI.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            mutated = Path(directory) / "openapi.json"
            _ = mutated.write_text(
                contents.replace(
                    '"x-unicode-normalization": "NFC"',
                    '"x-unicode-normalization": "NFD"',
                    1,
                ),
                encoding="utf-8",
            )
            result = self.run_validator(mutated)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("research-intent-canonicalization", result.stderr)

    def test_export_manifest_requires_research_intent_digest(self) -> None:
        document = _json_object(OPENAPI.read_text(encoding="utf-8"))
        schemas = _object_value(_object_value(document["components"])["schemas"])
        manifest = _object_value(schemas["ExportManifest"])
        self.assertIn("research_intent_sha256", _list_value(manifest["required"]))
        digest = _object_value(
            _object_value(manifest["properties"])["research_intent_sha256"]
        )
        self.assertEqual(digest["pattern"], "^[0-9a-f]{64}$")

    def test_run_creation_contract_requires_intent_for_local_and_provider_modes(
        self,
    ) -> None:
        document = _json_object(OPENAPI.read_text(encoding="utf-8"))
        schemas = _object_value(_object_value(document["components"])["schemas"])
        run_create = _object_value(schemas["RunCreate"])
        self.assertEqual(
            run_create["oneOf"],
            [
                {"$ref": "#/components/schemas/LocalDryLabRunCreate"},
                {"$ref": "#/components/schemas/ProviderModelRunCreate"},
            ],
        )
        self.assertEqual(
            _object_value(run_create["discriminator"])["propertyName"],
            "execution_mode",
        )
        local = _object_value(schemas["LocalDryLabRunCreate"])
        local_properties = _object_value(local["properties"])
        self.assertEqual(
            _list_value(local["required"]),
            ["execution_mode", "session_id", "prompt", "research_intent", "input"],
        )
        self.assertNotIn("provider_connection_id", local_properties)
        provider = _object_value(schemas["ProviderModelRunCreate"])
        self.assertEqual(
            _list_value(provider["required"]),
            [
                "execution_mode",
                "session_id",
                "prompt",
                "research_intent",
                "input",
                "connection_id",
                "model_id",
            ],
        )
        provider_properties = _object_value(provider["properties"])
        self.assertEqual(provider_properties["execution_mode"], {"const": "provider_model"})
        self.assertEqual(
            provider_properties["research_intent"],
            {"$ref": "#/components/schemas/ResearchIntent"},
        )
        paths = _object_value(document["paths"])
        operation = _object_value(_object_value(paths["/api/v1/runs"])["post"])
        responses = _object_value(operation["responses"])
        self.assertIn("201", responses)
        created = _object_value(responses["201"])
        content = _object_value(created["content"])
        media = _object_value(content["application/json"])
        self.assertEqual(media["schema"], {"$ref": "#/components/schemas/RunResource"})
        run_read = _object_value(_object_value(paths["/api/v1/runs/{run_id}"])["get"])
        read_responses = _object_value(run_read["responses"])
        read_content = _object_value(_object_value(read_responses["200"])["content"])
        read_media = _object_value(read_content["application/json"])
        self.assertEqual(
            read_media["schema"], {"$ref": "#/components/schemas/RunResource"}
        )
        resource = _object_value(schemas["RunResource"])
        resource_properties = _object_value(resource["properties"])
        expected_resource_fields = {
            "run_id",
            "session_id",
            "execution_mode",
            "provider",
            "prompt",
            "filename",
            "sha256",
            "digest",
            "stage",
            "artifacts",
            "plan_digest",
            "research_intent",
            "research_intent_sha256",
            "review",
            "export",
            "cleanup",
            "child_succeeded",
            "review_id",
            "export_id",
            "created_at",
            "display",
            "action_plan",
            "links",
            "actions",
            "timeline",
        }
        self.assertEqual(
            set(_list_value(resource["required"])), expected_resource_fields
        )
        self.assertEqual(set(resource_properties), expected_resource_fields)
        self.assertEqual(
            resource_properties["created_at"],
            {"$ref": "#/components/schemas/UtcTimestamp"},
        )
        self.assertEqual(
            resource_properties["execution_mode"],
            {"enum": ["local_dry_lab", "provider_model"]},
        )

    def test_rejects_provider_run_research_intent_boundary_drift(self) -> None:
        document = _json_object(OPENAPI.read_text(encoding="utf-8"))
        schemas = _object_value(_object_value(document["components"])["schemas"])
        provider = _object_value(schemas["ProviderModelRunCreate"])
        required = _list_value(provider["required"])
        required.remove("research_intent")
        with tempfile.TemporaryDirectory() as directory:
            mutated = Path(directory) / "openapi.json"
            _ = mutated.write_text(
                json.dumps(document, ensure_ascii=False),
                encoding="utf-8",
            )
            result = self.run_validator(mutated)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("run-create-intent-approval-boundary", result.stderr)

    def assert_rejected(self, mutation: ContractMutation) -> None:
        contents = OPENAPI.read_text(encoding="utf-8")
        self.assertEqual(contents.count(mutation.before), 1)
        with tempfile.TemporaryDirectory() as directory:
            mutated = Path(directory) / "openapi.json"
            _ = mutated.write_text(
                contents.replace(mutation.before, mutation.after),
                encoding="utf-8",
            )
            result = self.run_validator(mutated)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(mutation.expected, result.stdout + result.stderr)

    def test_rejects_cross_tenant_403_drift(self) -> None:
        # Given: a tenant endpoint changed from non-disclosing 404 to 403.
        mutation = ContractMutation(
            '"#/components/schemas/Project"}}}}, "404":',
            '"#/components/schemas/Project"}}}}, "403":',
            "cross-tenant-404",
        )

        # When: semantic validation checks the parsed mutation.
        self.assert_rejected(mutation)

        # Then: the named tenant disclosure invariant rejects it.

    def test_rejects_missing_tenancy_envelope(self) -> None:
        # Given: the server-derived tenancy declaration is absent.
        mutation = ContractMutation(
            '  "x-tenancy": {"org_id": "server-derived", "client_authority": false, "cross_tenant_status": 404},\n',
            "",
            "x-tenancy",
        )

        # When: semantic validation checks the parsed mutation.
        self.assert_rejected(mutation)

        # Then: boundary parsing rejects the missing tenancy contract.

    def test_rejects_noncanonical_error_response(self) -> None:
        # Given: the canonical error response loses its required envelope.
        mutation = ContractMutation(
            '"ErrorEnvelope": {"type": "object", "additionalProperties": false, "required": ["error"]',
            '"ErrorEnvelope": {"type": "object", "additionalProperties": false, "required": ["message"]',
            "canonical-error-envelope",
        )

        # When: semantic validation checks the parsed mutation.
        self.assert_rejected(mutation)

        # Then: the error envelope invariant rejects it.

    def test_rejects_missing_idempotency_key(self) -> None:
        # Given: authenticated Run creation lacks its idempotency header.
        mutation = ContractMutation(
            '"/api/v1/runs": {"post": {"x-tenant-scoped": true, "x-mutation-protection": true, "parameters": [{"$ref": "#/components/parameters/IdempotencyKey"}],',
            '"/api/v1/runs": {"post": {"x-tenant-scoped": true, "x-mutation-protection": true, "parameters": [],',
            "idempotency-key",
        )

        # When: semantic validation checks the parsed mutation.
        self.assert_rejected(mutation)

        # Then: the creation replay invariant rejects it.

    def test_rejects_missing_if_match(self) -> None:
        # Given: mutable Project update lacks compare-and-swap protection.
        mutation = ContractMutation(
            '"#/components/schemas/Project"}}}}, "404": {"$ref": "#/components/responses/Error"}}}, "patch": {"x-tenant-scoped": true, "x-mutation-protection": true, "parameters": [{"$ref": "#/components/parameters/IfMatch"}],',
            '"#/components/schemas/Project"}}}}, "404": {"$ref": "#/components/responses/Error"}}}, "patch": {"x-tenant-scoped": true, "x-mutation-protection": true, "parameters": [],',
            "if-match",
        )

        # When: semantic validation checks the parsed mutation.
        self.assert_rejected(mutation)

        # Then: the lost-update invariant rejects it.

    def test_rejects_insecure_cookie(self) -> None:
        # Given: the session cookie loses its host-only property.
        mutation = ContractMutation(
            '"x-host-only": true, "x-secure": true',
            '"x-host-only": false, "x-secure": true',
            "host-only-secure-cookie",
        )

        # When: semantic validation checks the parsed mutation.
        self.assert_rejected(mutation)

        # Then: the cookie policy invariant rejects it.

    def test_rejects_missing_csrf_origin_fetch_metadata(self) -> None:
        # Given: cookie-authenticated mutation no longer requires Origin.
        mutation = ContractMutation(
            '"origin_required": true, "fetch_metadata_header"',
            '"origin_required": false, "fetch_metadata_header"',
            "cookie-csrf-origin-fetch-metadata",
        )

        # When: semantic validation checks the parsed mutation.
        self.assert_rejected(mutation)

        # Then: the CSRF/Origin/Fetch Metadata invariant rejects it.

    def test_rejects_executable_reviewer_capability_schema(self) -> None:
        # Given: OpenAPI permits one Reviewer capability to become true.
        mutation = ContractMutation(
            '"runner": {"const": false}',
            '"runner": {"type": "boolean"}',
            "reviewer-capabilities",
        )

        # When/Then: nested semantic validation rejects the escalation.
        self.assert_rejected(mutation)

    def test_rejects_untyped_persisted_submission(self) -> None:
        # Given: PersistedReview loses the typed FindingsSubmission reference.
        mutation = ContractMutation(
            '"submission": {"anyOf": [{"$ref": "#/components/schemas/FindingsSubmission"}, {"type": "null"}]}',
            '"submission": {"type": ["object", "null"]}',
            "persisted-review-submission",
        )

        # When/Then: nested semantic validation rejects the opaque object.
        self.assert_rejected(mutation)

    def test_rejects_unsafe_artifact_export_entry_schema(self) -> None:
        # Given: export entry paths lose their safe relative-path pattern.
        mutation = ContractMutation(
            '"path": {"type": "string", "minLength": 1, "pattern": "^[A-Za-z0-9._/-]+$", "x-safe-relative-posix-path": true}',
            '"path": {"type": "string", "minLength": 1, "x-safe-relative-posix-path": true}',
            "artifact-export-entry",
        )

        # When/Then: semantic validation rejects unsafe export path drift.
        self.assert_rejected(mutation)

    def test_rejects_review_create_without_execution_only_pins(self) -> None:
        # Given: ReviewCreate again requires Artifact pins and omits the either-pin rule.
        mutation = ContractMutation(
            '"anyOf": [{"required": ["artifact_version_ids"]}, {"required": ["execution_ids"]}]',
            '"required": ["artifact_version_ids"]',
            "review-create-pins",
        )

        # When/Then: semantic validation preserves execution-only Review creation.
        self.assert_rejected(mutation)

    def test_rejects_review_create_202_without_typed_body(self) -> None:
        # Given: POST /reviews returns 202 without its accepted-resource body.
        mutation = ContractMutation(
            '"202": {"description": "Review queued", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ReviewCreateAccepted"}}}}',
            '"202": {"description": "Review queued"}',
            "review-create-response",
        )

        # When/Then: semantic validation rejects the response-body regression.
        self.assert_rejected(mutation)

    def test_provider_connection_lifecycle_contract(self) -> None:
        document = _json_object(OPENAPI.read_text(encoding="utf-8"))
        paths = _object_value(document["paths"])

        self._assert_provider_operations(paths)
        self._assert_provider_responses(paths)
        self._assert_provider_parameters_and_bodies(paths)

    def _assert_provider_operations(self, paths: JsonObject) -> None:
        provider_paths = {
            "/api/v1/provider-connections": ("get", "post"),
            "/api/v1/provider-connections/registry": ("get",),
            "/api/v1/provider-connections/oauth/complete": ("post",),
            "/api/v1/provider-connections/oauth/cancel": ("post",),
            "/api/v1/provider-connections/{connection_id}": ("get", "delete"),
            "/api/v1/provider-connections/{connection_id}/model": ("post",),
            "/api/v1/provider-connections/{connection_id}/health": ("post",),
            "/api/v1/provider-connections/{connection_id}/reauth": ("post",),
        }
        for path, methods in provider_paths.items():
            self.assertIn(path, paths)
            operations = _object_value(paths[path])
            self.assertEqual(set(operations), set(methods))
            for method in methods:
                operation = _object_value(operations[method])
                self.assertTrue(_boolean_value(operation["x-tenant-scoped"]))
                if method in {"post", "delete"}:
                    self.assertTrue(_boolean_value(operation["x-mutation-protection"]))

    def _assert_provider_responses(self, paths: JsonObject) -> None:
        error_response = {"$ref": "#/components/responses/Error"}
        expected_responses = {
            ("/api/v1/provider-connections", "get"): (
                {"200", "401", "403", "404"},
                "ProviderConnectionList",
            ),
            ("/api/v1/provider-connections", "post"): (
                {"202", "400", "401", "403", "404", "409", "503"},
                "ProviderInitiation",
            ),
            ("/api/v1/provider-connections/registry", "get"): (
                {"200", "401", "403", "404"},
                "ProviderRegistry",
            ),
            ("/api/v1/provider-connections/oauth/complete", "post"): (
                {"200", "400", "401", "403", "404", "409", "503"},
                "ProviderConnection",
            ),
            ("/api/v1/provider-connections/oauth/cancel", "post"): (
                {"200", "400", "401", "403", "404", "409", "503"},
                "ProviderOAuthCancellation",
            ),
            ("/api/v1/provider-connections/{connection_id}", "get"): (
                {"200", "401", "403", "404"},
                "ProviderConnection",
            ),
            ("/api/v1/provider-connections/{connection_id}", "delete"): (
                {"200", "400", "401", "403", "404", "412", "503"},
                "ProviderRevokeAccepted",
            ),
            ("/api/v1/provider-connections/{connection_id}/model", "post"): (
                {"200", "400", "401", "403", "404", "409", "412", "503"},
                "ProviderConnection",
            ),
            ("/api/v1/provider-connections/{connection_id}/health", "post"): (
                {"200", "400", "401", "403", "404", "409", "412", "503"},
                "ProviderConnection",
            ),
            ("/api/v1/provider-connections/{connection_id}/reauth", "post"): (
                {"202", "400", "401", "403", "404", "409", "412", "503"},
                "ProviderInitiation",
            ),
        }
        for (path, method), (statuses, schema_name) in expected_responses.items():
            operation = _object_value(_object_value(paths[path])[method])
            responses = _object_value(operation["responses"])
            self.assertEqual(set(responses), statuses)
            for status, response in responses.items():
                if status[0] in {"4", "5"}:
                    self.assertEqual(_object_value(response), error_response)
            success = next(
                _object_value(response)
                for status, response in responses.items()
                if status[0] == "2"
            )
            self.assertEqual(
                _object_value(
                    _object_value(
                        _object_value(success["content"])["application/json"]
                    )["schema"]
                ),
                {"$ref": f"#/components/schemas/{schema_name}"},
            )

    def _assert_provider_parameters_and_bodies(self, paths: JsonObject) -> None:
        idempotency_parameter = {"$ref": "#/components/parameters/IdempotencyKey"}
        if_match_parameter = {"$ref": "#/components/parameters/IfMatch"}
        expected_parameters = {
            "/api/v1/provider-connections": [idempotency_parameter],
            "/api/v1/provider-connections/oauth/complete": [idempotency_parameter],
            "/api/v1/provider-connections/oauth/cancel": [idempotency_parameter],
            "/api/v1/provider-connections/{connection_id}/model": [
                idempotency_parameter,
                if_match_parameter,
            ],
            "/api/v1/provider-connections/{connection_id}/health": [
                idempotency_parameter,
                if_match_parameter,
            ],
            "/api/v1/provider-connections/{connection_id}/reauth": [
                idempotency_parameter,
                if_match_parameter,
            ],
        }
        for path, parameters in expected_parameters.items():
            self.assertEqual(
                _list_value(
                    _object_value(_object_value(paths[path])["post"])["parameters"]
                ),
                parameters,
            )
        self.assertEqual(
            _list_value(
                _object_value(
                    _object_value(
                        paths["/api/v1/provider-connections/{connection_id}"]
                    )["delete"]
                )["parameters"]
            ),
            [if_match_parameter],
        )

        expected_request_bodies = {
            "/api/v1/provider-connections": "ProviderConnectionInitiate",
            "/api/v1/provider-connections/oauth/complete": "ProviderOAuthComplete",
            "/api/v1/provider-connections/oauth/cancel": "ProviderOAuthCancel",
            "/api/v1/provider-connections/{connection_id}/model": "ProviderModelSelect",
        }
        for path, body_name in expected_request_bodies.items():
            self.assertEqual(
                _object_value(
                    _object_value(_object_value(paths[path])["post"])["requestBody"]
                ),
                {"$ref": f"#/components/requestBodies/{body_name}"},
            )
        for path in (
            "/api/v1/provider-connections/{connection_id}/health",
            "/api/v1/provider-connections/{connection_id}/reauth",
        ):
            self.assertNotIn(
                "requestBody", _object_value(_object_value(paths[path])["post"])
            )

    def test_provider_schemas_are_redacted_and_strict(self) -> None:
        document = _json_object(OPENAPI.read_text(encoding="utf-8"))
        schemas = _object_value(_object_value(document["components"])["schemas"])
        provider_schemas = {
            name: _object_value(schema)
            for name, schema in schemas.items()
            if name.startswith("Provider")
        }
        forbidden = {
            "access_token",
            "refresh_token",
            "authorization_response",
            "api_key",
            "token",
            "vault",
            "runtime_home",
            "built_in_tools",
            "fallback",
            "budget",
            "cost",
            "organization_default",
        }

        def walk(value: JsonValue) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    self.assertNotIn(key.lower(), forbidden)
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        for schema in provider_schemas.values():
            self.assertFalse(
                _string_or_none_value(schema.get("type")) == "object"
                and _boolean_or_none_value(schema.get("additionalProperties"))
                is not False
            )
            walk(schema)

        self.assertEqual(
            _list_value(_object_value(schemas["ProviderAdapterId"])["enum"]),
            [
                "openai_codex",
                "anthropic_claude_code",
                "xai_grok_build",
                "moonshot_kimi_code",
                "zai_glm",
            ],
        )
        self.assertEqual(
            _list_value(_object_value(schemas["ProviderRegistryEntry"])["required"]),
            [
                "id",
                "name",
                "availability_label",
                "required",
                "default",
                "connectable",
                "disabled_reason",
            ],
        )
        self.assertEqual(
            set(
                _object_value(
                    _object_value(schemas["ProviderRegistryEntry"])["properties"]
                )
            ),
            {
                "id",
                "name",
                "availability_label",
                "required",
                "default",
                "connectable",
                "disabled_reason",
            },
        )
        self.assertEqual(
            _list_value(_object_value(schemas["ProviderConnection"])["required"]),
            [
                "id",
                "adapter_id",
                "account",
                "models",
                "selected_model",
                "status",
                "health",
                "qualification",
                "revision",
                "created_at",
            ],
        )
        self.assertNotIn(
            "adapter",
            _object_value(_object_value(schemas["ProviderConnection"])["properties"]),
        )
        self.assertEqual(
            _list_value(_object_value(schemas["ProviderOAuthComplete"])["required"]),
            ["state", "flow", "redirect_uri"],
        )
        self.assertEqual(
            set(
                _object_value(
                    _object_value(schemas["ProviderOAuthComplete"])["properties"]
                )
            ),
            {"state", "flow", "redirect_uri"},
        )
        self.assertEqual(
            _list_value(_object_value(schemas["ProviderCleanupReceipt"])["required"]),
            [
                "connection_id",
                "adapter_id",
                "requested_at",
                "destroy_by",
                "destroyed_at",
                "evidence_sha256",
                "redacted",
            ],
        )
        self.assertEqual(
            _object_value(
                _object_value(
                    _object_value(schemas["ProviderCleanupReceipt"])["properties"]
                )["redacted"]
            ),
            {"const": True},
        )


if __name__ == "__main__":
    _ = unittest.main()
