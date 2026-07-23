"""OIDC-authenticated client for an external CI generation authority."""

from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Final, Literal, Protocol, Self, cast, final, override

from pydantic import BaseModel, TypeAdapter, ValidationError

from .ci_contract import (
    CiCatalogJob,
    CiControlCatalog,
    CiCurrentRun,
    CiExecutionAttestation,
    CiExecutionLease,
    CiJob,
    GateResult,
    RequiredSecurityCatalog,
)

type JsonValue = (
    None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
)
type JsonObject = dict[str, JsonValue]
type AuthorityOperation = Literal[
    "bind",
    "resolve",
    "begin",
    "complete",
    "issue_execution_lease",
    "authorize_execution_lease",
    "attest_execution",
    "verify_execution_attestation",
    "finalize_attested_generation",
    "resolve_current",
    "resolve_control_catalog",
    "resolve_security_catalog",
]
type HttpRequest = Callable[[urllib.request.Request, float, int], bytes]

AUTHORITY_URL_ENV: Final = "CI_AUTHORITY_URL"
AUTHORITY_AUDIENCE_ENV: Final = "CI_AUTHORITY_AUDIENCE"
OIDC_REQUEST_URL_ENV: Final = "ACTIONS_ID_TOKEN_REQUEST_URL"
OIDC_REQUEST_TOKEN_ENV: Final = b"ACTIONS_ID_TOKEN_REQUEST_TOKEN".decode()
MAX_HTTP_RESPONSE_BYTES: Final = 1024 * 1024
MAX_OIDC_RESPONSE_BYTES: Final = 64 * 1024
MAX_AUDIENCE_BYTES: Final = 512
MAX_OIDC_REQUEST_TOKEN_BYTES: Final = 4096
MAX_OIDC_TOKEN_BYTES: Final = 16 * 1024
MAX_URL_BYTES: Final = 2048
HTTP_TIMEOUT_SECONDS: Final = 15.0
OIDC_REFRESH_SECONDS: Final = 4 * 60
PROTOCOL_VERSION: Final = "2"
_SHA256_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")
_JSON_OBJECT_ADAPTER: Final[TypeAdapter[JsonObject]] = TypeAdapter(JsonObject)


class RemoteAuthorityError(RuntimeError):
    """Stable fail-closed error for unavailable or malformed authority replies."""

    def __init__(self) -> None:
        """Avoid leaking authority response or token material."""
        super().__init__("remote CI authority rejected the request")


class AuthorityTransport(Protocol):
    """Transport boundary used by the external authority client."""

    def request(self, operation: AuthorityOperation, payload: JsonObject) -> JsonObject:
        """Submit one typed authority operation and return one JSON object."""
        ...


class _HttpResponse(Protocol):
    def read(self, amount: int = -1) -> bytes: ...

    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exception_type: object,
        exception: object,
        traceback: object,
    ) -> bool | None: ...


@final
class RemoteCiAuthority:
    """Implement the CI authority protocol through an external transport."""

    def __init__(self, transport: AuthorityTransport) -> None:
        """Retain only the transport; all authoritative state stays external."""
        self._transport = transport

    def bind(
        self, authority_context: str, generation_id: str, manifest_sha256: str
    ) -> None:
        """Bind one manifest checksum outside the checkout."""
        self._ack(
            "bind",
            {
                "authority_context": authority_context,
                "generation_id": generation_id,
                "manifest_sha256": manifest_sha256,
            },
        )

    def resolve(self, authority_context: str, generation_id: str) -> str:
        """Resolve one externally bound manifest checksum."""
        response = self._request(
            "resolve",
            {
                "authority_context": authority_context,
                "generation_id": generation_id,
            },
        )
        if set(response) != {"manifest_sha256"}:
            raise RemoteAuthorityError
        value = response["manifest_sha256"]
        if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
            raise RemoteAuthorityError
        return value

    def begin(self, current_run: CiCurrentRun) -> None:
        """Atomically supersede the prior external current run."""
        self._ack("begin", {"current_run": _model_json(current_run)})

    def complete(self, current_run: CiCurrentRun) -> None:
        """Commit one non-success terminal transition externally."""
        self._ack("complete", {"current_run": _model_json(current_run)})

    def issue_execution_lease(
        self, current_run: CiCurrentRun, job: CiJob
    ) -> CiExecutionLease:
        """Request a non-transferable lease for one exact job."""
        response = self._request(
            "issue_execution_lease",
            {"current_run": _model_json(current_run), "job": str(job)},
        )
        return _response_model(response, "lease", CiExecutionLease)

    def authorize_execution_lease(
        self,
        lease: CiExecutionLease,
        current_run: CiCurrentRun,
        catalog: CiControlCatalog,
        job: CiCatalogJob,
    ) -> None:
        """Consume the exact lease immediately before its child starts."""
        self._ack(
            "authorize_execution_lease",
            {
                "lease": _model_json(lease),
                "current_run": _model_json(current_run),
                "catalog": _model_json(catalog),
                "job": _model_json(job),
            },
        )

    def attest_execution(
        self, lease: CiExecutionLease, record: GateResult, toolchain: str
    ) -> CiExecutionAttestation:
        """Request a detached receipt for one observed lease-bound result."""
        response = self._request(
            "attest_execution",
            {
                "lease": _model_json(lease),
                "record": _model_json(record),
                "toolchain": toolchain,
            },
        )
        return _response_model(response, "attestation", CiExecutionAttestation)

    def verify_execution_attestation(
        self,
        attestation: CiExecutionAttestation,
        record: GateResult,
        current_run: CiCurrentRun,
    ) -> None:
        """Ask the external authority to reverify an exact receipt."""
        self._ack(
            "verify_execution_attestation",
            {
                "attestation": _model_json(attestation),
                "record": _model_json(record),
                "current_run": _model_json(current_run),
            },
        )

    def finalize_attested_generation(
        self,
        current_run: CiCurrentRun,
        published_run: CiCurrentRun,
        manifest_sha256: str,
        attestations: tuple[CiExecutionAttestation, ...],
    ) -> None:
        """Atomically bind the manifest and successful external transition."""
        self._ack(
            "finalize_attested_generation",
            {
                "current_run": _model_json(current_run),
                "published_run": _model_json(published_run),
                "manifest_sha256": manifest_sha256,
                "attestations": [_model_json(item) for item in attestations],
            },
        )

    def resolve_current(self, authority_context: str) -> CiCurrentRun:
        """Freshly resolve the external current-run record."""
        response = self._request(
            "resolve_current", {"authority_context": authority_context}
        )
        return _response_model(response, "current_run", CiCurrentRun)

    def resolve_control_catalog(
        self, authority_context: str, source_identity: str, run_id: str
    ) -> CiControlCatalog:
        """Resolve the source- and run-bound command catalog externally."""
        response = self._request(
            "resolve_control_catalog",
            {
                "authority_context": authority_context,
                "source_identity": source_identity,
                "run_id": run_id,
            },
        )
        return _response_model(response, "catalog", CiControlCatalog)

    def resolve_security_catalog(self, catalog_id: str) -> RequiredSecurityCatalog:
        """Resolve the independently governed High-threat catalog."""
        response = self._request("resolve_security_catalog", {"catalog_id": catalog_id})
        return _response_model(
            response,
            "security_catalog",
            RequiredSecurityCatalog,
        )

    def _request(
        self, operation: AuthorityOperation, payload: JsonObject
    ) -> JsonObject:
        try:
            response = self._transport.request(operation, payload)
        except RemoteAuthorityError:
            raise
        except (OSError, RuntimeError, TypeError, ValueError):
            raise RemoteAuthorityError from None
        try:
            return _JSON_OBJECT_ADAPTER.validate_python(response)
        except ValidationError:
            raise RemoteAuthorityError from None

    def _ack(self, operation: AuthorityOperation, payload: JsonObject) -> None:
        if self._request(operation, payload) != {"ok": True}:
            raise RemoteAuthorityError


@final
class OidcHttpTransport:
    """POST authority operations with a short-lived GitHub Actions OIDC token."""

    def __init__(
        self,
        endpoint: str,
        audience: str,
        oidc_request_url: str,
        oidc_request_token: str,
        *,
        http_request: HttpRequest | None = None,
    ) -> None:
        """Validate endpoints and retain the GitHub-issued request credential."""
        self._endpoint = _https_url(endpoint, allow_query=False)
        self._audience = _bounded_value(audience, MAX_AUDIENCE_BYTES)
        self._oidc_request_url = _https_url(oidc_request_url, allow_query=True)
        self._oidc_request_token = _bounded_value(
            oidc_request_token, MAX_OIDC_REQUEST_TOKEN_BYTES
        )
        self._http_request = http_request or _bounded_http_request
        self._lock = threading.Lock()
        self._cached_oidc_token = ""
        self._refresh_at = 0.0

    @classmethod
    def from_environment(cls) -> OidcHttpTransport:
        """Build the transport only from explicit workflow and GitHub inputs."""
        try:
            return cls(
                os.environ[AUTHORITY_URL_ENV],
                os.environ[AUTHORITY_AUDIENCE_ENV],
                os.environ[OIDC_REQUEST_URL_ENV],
                os.environ[OIDC_REQUEST_TOKEN_ENV],
            )
        except (KeyError, ValueError):
            raise RemoteAuthorityError from None

    def request(self, operation: AuthorityOperation, payload: JsonObject) -> JsonObject:
        """Send one canonical bounded request without following redirects."""
        body = json.dumps(
            {"operation": operation, "payload": payload},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        request = urllib.request.Request(  # noqa: S310 - URL is prevalidated HTTPS.
            self._endpoint,
            data=body,
            headers={
                "Authorization": f"Bearer {self._oidc_token()}",
                "Content-Type": "application/json",
                "X-CI-Authority-Protocol": PROTOCOL_VERSION,
            },
            method="POST",
        )
        raw = self._http_request(
            request,
            HTTP_TIMEOUT_SECONDS,
            MAX_HTTP_RESPONSE_BYTES,
        )
        return _decode_json_object(raw)

    def _oidc_token(self) -> str:
        with self._lock:
            now = time.monotonic()
            if self._cached_oidc_token and now < self._refresh_at:
                return self._cached_oidc_token
            query = urllib.parse.urlencode({"audience": self._audience})
            delimiter = (
                "&" if urllib.parse.urlsplit(self._oidc_request_url).query else "?"
            )
            request = urllib.request.Request(  # noqa: S310 - Prevalidated HTTPS.
                f"{self._oidc_request_url}{delimiter}{query}",
                headers={"Authorization": f"Bearer {self._oidc_request_token}"},
                method="GET",
            )
            response = _decode_json_object(
                self._http_request(
                    request,
                    HTTP_TIMEOUT_SECONDS,
                    MAX_OIDC_RESPONSE_BYTES,
                )
            )
            if set(response) != {"value"} or not isinstance(response["value"], str):
                raise RemoteAuthorityError
            token = _bounded_value(response["value"], MAX_OIDC_TOKEN_BYTES)
            self._cached_oidc_token = token
            self._refresh_at = now + OIDC_REFRESH_SECONDS
            return token


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    @override
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        raise RemoteAuthorityError


def configured_authority() -> RemoteCiAuthority:
    """Construct the workflow's external OIDC authority client."""
    return RemoteCiAuthority(OidcHttpTransport.from_environment())


def _model_json(model: BaseModel) -> JsonObject:
    try:
        return _JSON_OBJECT_ADAPTER.validate_python(model.model_dump(mode="json"))
    except ValidationError:
        raise RemoteAuthorityError from None


def _response_model[ModelT: BaseModel](
    response: JsonObject, key: str, model_type: type[ModelT]
) -> ModelT:
    if set(response) != {key}:
        raise RemoteAuthorityError
    try:
        return model_type.model_validate(response[key])
    except (TypeError, ValidationError, ValueError):
        raise RemoteAuthorityError from None


def _decode_json_object(raw: bytes) -> JsonObject:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise RemoteAuthorityError
            result[key] = value
        return result

    try:
        decoded = cast(
            "object",
            json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates),
        )
        return _JSON_OBJECT_ADAPTER.validate_python(decoded)
    except (UnicodeDecodeError, ValidationError, ValueError):
        raise RemoteAuthorityError from None


def _bounded_value(value: str, limit: int) -> str:
    if (
        not value
        or len(value.encode()) > limit
        or any(character in value for character in "\r\n")
    ):
        raise RemoteAuthorityError
    return value


def _https_url(value: str, *, allow_query: bool) -> str:
    value = _bounded_value(value, MAX_URL_BYTES)
    try:
        parsed = urllib.parse.urlsplit(value)
        _ = parsed.port
    except ValueError:
        raise RemoteAuthorityError from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (parsed.query and not allow_query)
    ):
        raise RemoteAuthorityError
    return value


def _bounded_http_request(
    request: urllib.request.Request, timeout: float, limit: int
) -> bytes:
    opener = urllib.request.build_opener(_RejectRedirects())
    try:
        response = cast("_HttpResponse", opener.open(request, timeout=timeout))
        with response:
            content = response.read(limit + 1)
    except (OSError, urllib.error.HTTPError, urllib.error.URLError):
        raise RemoteAuthorityError from None
    if len(content) > limit:
        raise RemoteAuthorityError
    return content
