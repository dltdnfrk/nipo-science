from __future__ import annotations

import importlib
from pathlib import Path
from types import ModuleType
from typing import cast
from urllib.request import Request

import pytest
from tools.platform_policy import ci_runner
from tools.platform_policy.ci_contract import (
    CiCurrentRun,
    CiExecutionAttestation,
    CiExecutionLease,
    CiGenerationManifestAuthority,
    CiJob,
    CiRunState,
    GateResult,
)
from tools.platform_policy.ci_remote_authority import (
    AUTHORITY_AUDIENCE_ENV,
    AUTHORITY_URL_ENV,
    OIDC_REQUEST_TOKEN_ENV,
    OIDC_REQUEST_URL_ENV,
    AuthorityOperation,
    JsonObject,
    OidcHttpTransport,
    RemoteAuthorityError,
    RemoteCiAuthority,
)

ROOT = Path(__file__).parents[2]
SOURCE_SHA256 = "a" * 64


def _current_run() -> CiCurrentRun:
    return CiCurrentRun(
        run_id="run-1",
        attempt_id="attempt-1",
        authority_context="commit-1",
        source_tree_sha256=SOURCE_SHA256,
        started_at="2026-07-14T00:00:00Z",
        state=CiRunState.ACTIVE,
    )


class RecordingTransport:
    calls: list[tuple[AuthorityOperation, JsonObject]]

    def __init__(self) -> None:
        self.calls = []

    def request(self, operation: AuthorityOperation, payload: JsonObject) -> JsonObject:
        self.calls.append((operation, payload))
        current = _current_run()
        if operation in {"begin", "authorize_execution_lease"}:
            return {"ok": True}
        if operation == "issue_execution_lease":
            return {
                "lease": CiExecutionLease(
                    lease_id="lease-1",
                    authority_context=current.authority_context,
                    run_id=current.run_id,
                    attempt_id=current.attempt_id,
                    source_tree_sha256=current.source_tree_sha256,
                    job=CiJob.LINT,
                ).model_dump(mode="json")
            }
        if operation == "resolve_current":
            return {"current_run": current.model_dump(mode="json")}
        raise RemoteAuthorityError


def test_remote_authority_serializes_run_and_returns_external_lease() -> None:
    transport = RecordingTransport()
    authority = RemoteCiAuthority(transport)
    current = _current_run()

    authority.begin(current)
    lease = authority.issue_execution_lease(current, CiJob.LINT)
    resolved = authority.resolve_current(current.authority_context)

    assert lease.lease_id == "lease-1"
    assert resolved == current
    assert transport.calls[0] == (
        "begin",
        {"current_run": current.model_dump(mode="json")},
    )
    assert transport.calls[1][0] == "issue_execution_lease"
    assert transport.calls[2] == (
        "resolve_current",
        {"authority_context": "commit-1"},
    )


def test_remote_execution_receipt_binds_every_record_attachment() -> None:
    current = _current_run()
    lease = CiExecutionLease(
        lease_id="lease-attachments",
        authority_context=current.authority_context,
        run_id=current.run_id,
        attempt_id=current.attempt_id,
        source_tree_sha256=current.source_tree_sha256,
        job=CiJob.LINT,
    )
    record = GateResult(
        job=CiJob.LINT,
        executed_count=1,
        output_sha256="b" * 64,
        argv=("ruff", "check"),
        control_ids=("lint",),
        attachment_sha256=("c" * 64,),
        started_at="2026-07-14T00:00:00Z",
        finished_at="2026-07-14T00:00:01Z",
        catalog_root_sha256="d" * 64,
        catalog_source_root_sha256="e" * 64,
        catalog_run_id=current.run_id,
    )
    attestation = CiExecutionAttestation(
        lease_id=lease.lease_id,
        authority_context=lease.authority_context,
        run_id=lease.run_id,
        attempt_id=lease.attempt_id,
        source_tree_sha256=lease.source_tree_sha256,
        catalog_root_sha256="d" * 64,
        catalog_source_root_sha256="e" * 64,
        job=record.job,
        argv=record.argv,
        control_ids=record.control_ids,
        toolchain="test-toolchain",
        executed_count=record.executed_count,
        output_sha256=record.output_sha256,
        attachment_sha256=record.attachment_sha256,
        outcome="success",
        started_at=record.started_at,
        finished_at=record.finished_at,
        signature="external-signature",
    )

    class AttestationTransport:
        def __init__(self) -> None:
            self.calls: list[tuple[AuthorityOperation, JsonObject]] = []

        def request(
            self,
            operation: AuthorityOperation,
            payload: JsonObject,
        ) -> JsonObject:
            self.calls.append((operation, payload))
            if operation == "attest_execution":
                return {"attestation": attestation.model_dump(mode="json")}
            if operation == "verify_execution_attestation":
                return {"ok": True}
            raise RemoteAuthorityError

    transport = AttestationTransport()
    authority = RemoteCiAuthority(transport)

    issued = authority.attest_execution(lease, record, "test-toolchain")
    authority.verify_execution_attestation(issued, record, current)

    assert issued.attachment_sha256 == record.attachment_sha256
    assert transport.calls == [
        (
            "attest_execution",
            {
                "lease": lease.model_dump(mode="json"),
                "record": record.model_dump(mode="json"),
                "toolchain": "test-toolchain",
            },
        ),
        (
            "verify_execution_attestation",
            {
                "attestation": attestation.model_dump(mode="json"),
                "record": record.model_dump(mode="json"),
                "current_run": current.model_dump(mode="json"),
            },
        ),
    ]


def test_remote_authority_rejects_malformed_acknowledgement() -> None:
    class MalformedTransport:
        def request(
            self, operation: AuthorityOperation, payload: JsonObject
        ) -> JsonObject:
            del operation, payload
            return {"ok": False}

    authority = RemoteCiAuthority(MalformedTransport())

    with pytest.raises(RemoteAuthorityError, match="remote CI authority rejected"):
        authority.begin(_current_run())


def test_oidc_transport_uses_bounded_https_requests_and_caches_short_lived_token() -> (
    None
):
    requests: list[tuple[str, str, int]] = []

    def request(request: object, timeout: float, limit: int) -> bytes:
        assert isinstance(request, Request)
        requests.append((request.full_url, request.get_method(), limit))
        assert timeout == 15.0
        if request.get_method() == "GET":
            assert request.get_header("Authorization") == "Bearer oidc-request"
            return b'{"value":"short-lived-jwt"}'
        assert request.get_header("Authorization") == "Bearer short-lived-jwt"
        assert request.get_header("X-ci-authority-protocol") == "2"
        return b'{"ok":true}'

    transport = OidcHttpTransport(
        "https://authority.example.test/v1/ci",
        "science-workbench-ci",
        "https://oidc.actions.example.test/token?run=1",
        "oidc-request",
        http_request=request,
    )

    assert transport.request("begin", {"current_run": {}}) == {"ok": True}
    assert transport.request("complete", {"current_run": {}}) == {"ok": True}
    assert requests == [
        (
            "https://oidc.actions.example.test/token?run=1&audience=science-workbench-ci",
            "GET",
            64 * 1024,
        ),
        ("https://authority.example.test/v1/ci", "POST", 1024 * 1024),
        ("https://authority.example.test/v1/ci", "POST", 1024 * 1024),
    ]


@pytest.mark.parametrize(
    ("authority_url", "oidc_url"),
    [
        ("http://authority.example.test/v1", "https://oidc.example.test/token"),
        ("https://user@authority.example.test/v1", "https://oidc.example.test/token"),
        (
            "https://authority.example.test/v1?redirect=yes",
            "https://oidc.example.test/token",
        ),
        ("https://authority.example.test/v1", "file:///tmp/token"),
    ],
)
def test_oidc_transport_rejects_non_https_or_ambiguous_endpoints(
    authority_url: str,
    oidc_url: str,
) -> None:
    with pytest.raises(RemoteAuthorityError):
        _ = OidcHttpTransport(
            authority_url,
            "science-workbench-ci",
            oidc_url,
            "oidc-request",
        )


def test_oidc_environment_configuration_fails_closed_when_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        AUTHORITY_AUDIENCE_ENV,
        AUTHORITY_URL_ENV,
        OIDC_REQUEST_TOKEN_ENV,
        OIDC_REQUEST_URL_ENV,
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(RemoteAuthorityError):
        _ = OidcHttpTransport.from_environment()


def test_configured_authority_reference_may_be_a_zero_argument_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = RemoteCiAuthority(RecordingTransport())
    module = ModuleType("external_ci_authority")

    def build_authority() -> RemoteCiAuthority:
        return authority

    module.__dict__["build_authority"] = build_authority

    def import_module(_name: str) -> ModuleType:
        return module

    monkeypatch.setenv(
        ci_runner.CI_AUTHORITY_FACTORY_ENV,
        "external_ci_authority:build_authority",
    )
    monkeypatch.setattr(importlib, "import_module", import_module)

    resolved = ci_runner.configured_ci_generation_manifest_authority()

    assert resolved is cast("CiGenerationManifestAuthority", authority)


def test_checked_in_workflow_separates_untrusted_validation_from_oidc_authority() -> (
    None
):
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    for contract in (
        "id-token: write",
        "contents: none",
        "persist-credentials: false",
        "environment: ci-attestation",
        "CI_AUTHORITY_URL: ${{ vars.CI_AUTHORITY_URL }}",
        "CI_AUTHORITY_AUDIENCE: ${{ vars.CI_AUTHORITY_AUDIENCE }}",
        "run: make ci-validate",
        'operation:"execute_and_publish"',
    ):
        assert contract in workflow
    attest = workflow.split("  attest:", maxsplit=1)[1]
    assert "actions/checkout" not in attest
    assert "make ci-local" not in workflow
    assert workflow.count("id-token: write") == 1
    assert "ci-validate:" in makefile
    assert "ci-source-identity:" in makefile
