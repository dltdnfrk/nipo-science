"""Provider-neutral streaming model calls against the researcher's own account.

SPEC-v0.5 section 7 and L10 bind a model turn to exactly one explicitly
selected provider and model. This module is that turn, and the invariants it
carries are the ones the specification makes release-blocking.

No automatic fallback
---------------------
:meth:`ModelCallClient.stream` issues **at most one** HTTP request. There is no
retry loop, no alternate endpoint list, no "try the next provider", and no
unauthenticated second attempt. Every failure -- authentication, quota, rate
limit, unavailability, timeout, transport, malformed response -- is raised as a
provider-neutral :class:`ModelCallError` subclass and the turn ends. The count
of requests actually issued is recorded in :attr:`TurnRecord.request_count`, so
"exactly one provider was contacted" is an observable property of the durable
record rather than a claim about the code.

Credential handling
-------------------
The key is resolved from :class:`~nipo_local.providers.ProviderRegistry` at call
time, never cached, and lives only inside :meth:`ModelCallClient._send`, whose
`finally` clears the header mapping that held it. Nothing in this module logs,
and no error message, ``__repr__``, or ``TurnRecord`` field carries provider
prose: an error records only its category, the HTTP status, and -- when the
provider's structured error code is a token this module already knows by name --
that token. A provider therefore cannot smuggle text of its choosing, including
a credential echoed back at us, into a message a renderer might display. Keys
travel in headers only; :attr:`ProviderEndpoint.stream_query` is a fixed
non-credential query string, and nothing else ever reaches a URL.

Transport
---------
:mod:`http.client` from the standard library, not :mod:`urllib.request`. The
repository adds no HTTP dependency, and the two stdlib options are not
equivalent here:

* ``urllib.request`` builds an opener chain that follows redirects and honours
  ``http_proxy``/``https_proxy``. Following a 302 would send the researcher's
  key to a host the researcher did not select, and a proxy variable would route
  the whole turn through a third party -- both are exactly what LS10 (egress
  limited to the selected provider) forbids, and the redirect case is automatic
  fallback wearing a different hat.
* ``http.client`` connects to the host named in the endpoint, follows nothing,
  reads no environment, and exposes the raw response as a buffered reader, so
  ``read1`` returns bytes as they arrive. That is what makes the streaming here
  real incremental delivery rather than a buffered body replayed in pieces.

Bounds
------
Response size, single-frame size, per-socket time, and total wall-clock time are
all capped by :class:`CallLimits`, and each cap has its own typed error. A
hostile endpoint that never terminates a line, never finishes a body, or answers
one byte per minute is refused rather than allowed to exhaust memory or hang.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import time
from dataclasses import dataclass, field
from enum import StrEnum
from http import HTTPStatus
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, Final, Protocol, cast, final, override
from urllib.parse import quote, urlsplit

from nipo_local.providers import ProviderStatus, parse_model_id

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence

    from nipo_local.providers import ProviderRegistry, ProviderSpec

ANTHROPIC_VERSION: Final = "2023-06-01"
"""Value of the `anthropic-version` header the Messages API requires."""

OLLAMA_ORIGIN: Final = "http://127.0.0.1:11434"
"""Default Ollama origin; loopback, so no key and no TLS are involved."""

DEFAULT_MAX_RESPONSE_BYTES: Final = 8 * 1024 * 1024
"""Total decoded body cap for one turn."""

DEFAULT_MAX_FRAME_BYTES: Final = 512 * 1024
"""Cap on one unterminated line, so a never-newline body cannot buffer freely."""

DEFAULT_SOCKET_TIMEOUT_SECONDS: Final = 30.0
"""Per-operation socket timeout: connect, and each individual read."""

DEFAULT_TOTAL_TIMEOUT_SECONDS: Final = 300.0
"""Wall-clock cap on a whole turn, so a slow drip cannot run forever."""

READ_CHUNK_BYTES: Final = 8192
"""Requested read size; `read1` returns whatever has actually arrived."""

MAX_ERROR_BODY_BYTES: Final = 16 * 1024
"""Bounded read of a non-200 body, consulted only for its structured code."""

MAX_MODEL_NAME_LENGTH: Final = 200
"""Length cap on a model name, which for Gemini becomes part of the path."""

_HTTP_SCHEMES: Final = frozenset({"http", "https"})
_LOOPBACK_NAME: Final = "localhost"
_DEFAULT_PORTS: Final[Mapping[str, int]] = MappingProxyType({"http": 80, "https": 443})

_DONE_SENTINEL: Final = "[DONE]"


class Adapter(StrEnum):
    """Wire format one provider speaks."""

    OPENAI_COMPATIBLE = "openai_compatible"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    OLLAMA = "ollama"


class ModelCallFailure(StrEnum):
    """Provider-neutral classification of a failed model turn.

    A caller distinguishes "your key is wrong" from "you are rate limited"
    by this value or by the exception class, never by reading a message.
    """

    AUTHENTICATION = "authentication"
    RATE_LIMIT = "rate_limit"
    QUOTA = "quota"
    MODEL_UNAVAILABLE = "model_unavailable"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    INVALID_REQUEST = "invalid_request"
    TIMEOUT = "timeout"
    TRANSPORT = "transport"
    MALFORMED_RESPONSE = "malformed_response"
    RESPONSE_TOO_LARGE = "response_too_large"
    UNCLASSIFIED = "unclassified"


@final
@dataclass(frozen=True, slots=True)
class TurnRecord:
    """Terminal, non-secret record of which connection produced an output.

    This is what a Run record pins. It names the provider, the model, and the
    exact connection reached, and it counts the requests actually issued, which
    is the observable form of the no-fallback rule.
    """

    provider_id: str
    model_id: str
    model_name: str
    adapter: Adapter
    connection: str
    request_count: int
    response_bytes: int
    text_characters: int
    stop_reason: str | None
    input_tokens: int | None
    output_tokens: int | None


class EventKind(StrEnum):
    """Discriminant of a streamed event, for callers that serialize them."""

    TEXT_DELTA = "text_delta"
    COMPLETED = "completed"
    FAILED = "failed"


@final
@dataclass(frozen=True, slots=True)
class TextDelta:
    """One incremental piece of assistant text."""

    text: str

    @property
    def kind(self) -> EventKind:
        """Return this event's discriminant."""
        return EventKind.TEXT_DELTA


@final
@dataclass(frozen=True, slots=True)
class Completed:
    """Terminal event of a turn that finished normally."""

    turn: TurnRecord

    @property
    def kind(self) -> EventKind:
        """Return this event's discriminant."""
        return EventKind.COMPLETED


@final
@dataclass(frozen=True, slots=True)
class Failed:
    """Terminal event of a turn that failed, carrying the typed error."""

    turn: TurnRecord
    error: ModelCallError

    @property
    def kind(self) -> EventKind:
        """Return this event's discriminant."""
        return EventKind.FAILED


type ModelEvent = TextDelta | Completed | Failed
"""Everything :meth:`ModelCallClient.stream` yields."""


class ModelCallError(Exception):
    """Base class for every provider-neutral model turn failure.

    The message is assembled from this module's own constants plus the provider
    id, the model id, and an HTTP status. Provider prose never reaches it, so a
    response body -- including one echoing the credential back -- cannot become
    part of an exception string, a log line, or a rendered traceback.
    """

    failure: ClassVar[ModelCallFailure] = ModelCallFailure.UNCLASSIFIED

    provider_id: str
    model_id: str
    http_status: int | None
    provider_code: str | None
    turn: TurnRecord | None

    def __init__(
        self,
        provider_id: str,
        model_id: str,
        reason: str,
        http_status: int | None = None,
        provider_code: str | None = None,
    ) -> None:
        """Record a non-secret failure and render a message from known tokens."""
        detail = f"provider={provider_id} model={model_id} reason={reason}"
        if http_status is not None:
            detail = f"{detail} status={http_status}"
        if provider_code is not None:
            detail = f"{detail} code={provider_code}"
        super().__init__(f"{type(self).failure.value}: {detail}")
        self.provider_id = provider_id
        self.model_id = model_id
        self.http_status = http_status
        self.provider_code = provider_code
        self.turn = None


@final
class AuthenticationError(ModelCallError):
    """The provider rejected, or the researcher never supplied, the credential."""

    failure: ClassVar[ModelCallFailure] = ModelCallFailure.AUTHENTICATION


@final
class RateLimitError(ModelCallError):
    """The provider is throttling this account right now."""

    failure: ClassVar[ModelCallFailure] = ModelCallFailure.RATE_LIMIT


@final
class QuotaExhaustedError(ModelCallError):
    """The researcher's own provider allowance is spent."""

    failure: ClassVar[ModelCallFailure] = ModelCallFailure.QUOTA


@final
class ModelUnavailableError(ModelCallError):
    """The selected model is not available on the selected provider."""

    failure: ClassVar[ModelCallFailure] = ModelCallFailure.MODEL_UNAVAILABLE


@final
class ProviderUnavailableError(ModelCallError):
    """The provider reported a server-side failure."""

    failure: ClassVar[ModelCallFailure] = ModelCallFailure.PROVIDER_UNAVAILABLE


@final
class InvalidRequestError(ModelCallError):
    """The request was refused as malformed, locally or by the provider."""

    failure: ClassVar[ModelCallFailure] = ModelCallFailure.INVALID_REQUEST


@final
class ModelCallTimeoutError(ModelCallError):
    """A socket operation or the whole turn exceeded its time bound."""

    failure: ClassVar[ModelCallFailure] = ModelCallFailure.TIMEOUT


@final
class TransportError(ModelCallError):
    """The connection failed, was refused, or was cut mid-stream."""

    failure: ClassVar[ModelCallFailure] = ModelCallFailure.TRANSPORT


@final
class MalformedResponseError(ModelCallError):
    """The response did not parse as the wire format the provider promises."""

    failure: ClassVar[ModelCallFailure] = ModelCallFailure.MALFORMED_RESPONSE


@final
class ResponseTooLargeError(ModelCallError):
    """The response exceeded a declared size bound and was abandoned."""

    failure: ClassVar[ModelCallFailure] = ModelCallFailure.RESPONSE_TOO_LARGE


@final
class UnclassifiedProviderError(ModelCallError):
    """The provider reported a terminal failure this build does not map.

    This is the honest residual, not a dumping ground: it is reached only when
    the provider answered with a code outside :data:`KNOWN_PROVIDER_CODES` and
    the HTTP status gave no classification either.
    """

    failure: ClassVar[ModelCallFailure] = ModelCallFailure.UNCLASSIFIED


@final
class EndpointConfigurationError(ValueError):
    """An endpoint would send a credential somewhere it must never go."""


_REASON_NO_CREDENTIAL: Final = "no_credential_configured"
_REASON_REJECTED: Final = "provider_rejected_credential"
_REASON_THROTTLED: Final = "provider_throttled_request"
_REASON_ALLOWANCE: Final = "provider_allowance_exhausted"
_REASON_NO_MODEL: Final = "provider_has_no_such_model"
_REASON_SERVER: Final = "provider_server_failure"
_REASON_REFUSED: Final = "provider_refused_request"
_REASON_STATUS: Final = "provider_returned_unmapped_status"
_REASON_INBAND: Final = "provider_reported_failure_in_stream"
_REASON_SOCKET_TIMEOUT: Final = "socket_operation_timed_out"
_REASON_TOTAL_TIMEOUT: Final = "turn_exceeded_total_time_budget"
_REASON_CONNECT: Final = "connection_failed"
_REASON_STREAM_CUT: Final = "stream_ended_before_completion"
_REASON_BAD_JSON: Final = "frame_was_not_json"
_REASON_BAD_FRAME: Final = "frame_was_not_the_promised_shape"
_REASON_NO_TERMINAL: Final = "stream_ended_without_a_terminal_frame"
_REASON_BODY_CAP: Final = "response_exceeded_size_bound"
_REASON_FRAME_CAP: Final = "frame_exceeded_size_bound"
_REASON_EMPTY_MESSAGES: Final = "request_carried_no_messages"
_REASON_BAD_TOKENS: Final = "max_output_tokens_was_not_positive"
_REASON_BAD_MODEL_NAME: Final = "model_name_is_not_a_safe_token"
_REASON_NO_ENDPOINT: Final = "provider_has_no_configured_endpoint"


KNOWN_PROVIDER_CODES: Final[Mapping[str, ModelCallFailure]] = MappingProxyType(
    {
        # Every token here is a literal in this source file. A structured code that
        # is not one of these is discarded rather than stored, which is what makes
        # it impossible for a provider to place text of its choosing into an error.
        "authentication_error": ModelCallFailure.AUTHENTICATION,
        "invalid_api_key": ModelCallFailure.AUTHENTICATION,
        "invalid_request_error": ModelCallFailure.INVALID_REQUEST,
        "permission_error": ModelCallFailure.AUTHENTICATION,
        "not_found_error": ModelCallFailure.MODEL_UNAVAILABLE,
        "model_not_found": ModelCallFailure.MODEL_UNAVAILABLE,
        "rate_limit_error": ModelCallFailure.RATE_LIMIT,
        "rate_limit_exceeded": ModelCallFailure.RATE_LIMIT,
        "insufficient_quota": ModelCallFailure.QUOTA,
        "quota_exceeded": ModelCallFailure.QUOTA,
        "billing_hard_limit_reached": ModelCallFailure.QUOTA,
        "overloaded_error": ModelCallFailure.PROVIDER_UNAVAILABLE,
        "api_error": ModelCallFailure.PROVIDER_UNAVAILABLE,
        "UNAUTHENTICATED": ModelCallFailure.AUTHENTICATION,
        "PERMISSION_DENIED": ModelCallFailure.AUTHENTICATION,
        "RESOURCE_EXHAUSTED": ModelCallFailure.RATE_LIMIT,
        "NOT_FOUND": ModelCallFailure.MODEL_UNAVAILABLE,
        "INVALID_ARGUMENT": ModelCallFailure.INVALID_REQUEST,
        "UNAVAILABLE": ModelCallFailure.PROVIDER_UNAVAILABLE,
        "INTERNAL": ModelCallFailure.PROVIDER_UNAVAILABLE,
    }
)
"""Structured provider codes this build recognises, and what each one means."""

_STATUS_FAILURES: Final[Mapping[int, ModelCallFailure]] = MappingProxyType(
    {
        HTTPStatus.BAD_REQUEST: ModelCallFailure.INVALID_REQUEST,
        HTTPStatus.UNAUTHORIZED: ModelCallFailure.AUTHENTICATION,
        HTTPStatus.PAYMENT_REQUIRED: ModelCallFailure.QUOTA,
        HTTPStatus.FORBIDDEN: ModelCallFailure.AUTHENTICATION,
        HTTPStatus.NOT_FOUND: ModelCallFailure.MODEL_UNAVAILABLE,
        HTTPStatus.REQUEST_TIMEOUT: ModelCallFailure.TIMEOUT,
        HTTPStatus.UNPROCESSABLE_ENTITY: ModelCallFailure.INVALID_REQUEST,
        HTTPStatus.TOO_MANY_REQUESTS: ModelCallFailure.RATE_LIMIT,
        HTTPStatus.INTERNAL_SERVER_ERROR: ModelCallFailure.PROVIDER_UNAVAILABLE,
        HTTPStatus.BAD_GATEWAY: ModelCallFailure.PROVIDER_UNAVAILABLE,
        HTTPStatus.SERVICE_UNAVAILABLE: ModelCallFailure.PROVIDER_UNAVAILABLE,
        HTTPStatus.GATEWAY_TIMEOUT: ModelCallFailure.TIMEOUT,
        529: ModelCallFailure.PROVIDER_UNAVAILABLE,
    }
)
"""HTTP status to classification, consulted when no known code refines it."""

_ERROR_CLASSES: Final[Mapping[ModelCallFailure, type[ModelCallError]]] = (
    MappingProxyType(
        {
            ModelCallFailure.AUTHENTICATION: AuthenticationError,
            ModelCallFailure.RATE_LIMIT: RateLimitError,
            ModelCallFailure.QUOTA: QuotaExhaustedError,
            ModelCallFailure.MODEL_UNAVAILABLE: ModelUnavailableError,
            ModelCallFailure.PROVIDER_UNAVAILABLE: ProviderUnavailableError,
            ModelCallFailure.INVALID_REQUEST: InvalidRequestError,
            ModelCallFailure.TIMEOUT: ModelCallTimeoutError,
            ModelCallFailure.TRANSPORT: TransportError,
            ModelCallFailure.MALFORMED_RESPONSE: MalformedResponseError,
            ModelCallFailure.RESPONSE_TOO_LARGE: ResponseTooLargeError,
            ModelCallFailure.UNCLASSIFIED: UnclassifiedProviderError,
        }
    )
)

_FAILURE_REASONS: Final[Mapping[ModelCallFailure, str]] = MappingProxyType(
    {
        ModelCallFailure.AUTHENTICATION: _REASON_REJECTED,
        ModelCallFailure.RATE_LIMIT: _REASON_THROTTLED,
        ModelCallFailure.QUOTA: _REASON_ALLOWANCE,
        ModelCallFailure.MODEL_UNAVAILABLE: _REASON_NO_MODEL,
        ModelCallFailure.PROVIDER_UNAVAILABLE: _REASON_SERVER,
        ModelCallFailure.INVALID_REQUEST: _REASON_REFUSED,
        ModelCallFailure.TIMEOUT: _REASON_SOCKET_TIMEOUT,
        ModelCallFailure.TRANSPORT: _REASON_CONNECT,
        ModelCallFailure.MALFORMED_RESPONSE: _REASON_BAD_FRAME,
        ModelCallFailure.RESPONSE_TOO_LARGE: _REASON_BODY_CAP,
        ModelCallFailure.UNCLASSIFIED: _REASON_STATUS,
    }
)


@final
@dataclass(frozen=True, slots=True)
class CallLimits:
    """Size and time bounds one turn may not exceed."""

    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES
    socket_timeout_seconds: float = DEFAULT_SOCKET_TIMEOUT_SECONDS
    total_timeout_seconds: float = DEFAULT_TOTAL_TIMEOUT_SECONDS


DEFAULT_LIMITS: Final = CallLimits()


@final
@dataclass(frozen=True, slots=True)
class Message:
    """One conversational turn supplied by the caller."""

    role: str
    content: str


USER_ROLE: Final = "user"
ASSISTANT_ROLE: Final = "assistant"


@final
@dataclass(frozen=True, slots=True)
class ModelRequest:
    """A provider-neutral request; adapters translate it to a wire body."""

    messages: tuple[Message, ...]
    max_output_tokens: int
    system: str | None = None
    temperature: float | None = None


@final
@dataclass(frozen=True, slots=True)
class ProviderEndpoint:
    """Where one provider is reached and by which wire adapter.

    Raises:
        EndpointConfigurationError: The origin is not an absolute `http`/`https`
            URL, or is plain `http` to a host that is not loopback -- which
            would put the researcher's key on the wire in clear text.
    """

    provider_id: str
    adapter: Adapter
    origin: str
    path: str
    stream_query: str = ""
    max_tokens_field: str = "max_tokens"

    def __post_init__(self) -> None:
        """Reject an origin that could expose a credential, at build time."""
        _ = self.address()
        if not self.path.startswith("/"):
            raise EndpointConfigurationError(_ORIGIN_MESSAGE)

    def address(self) -> tuple[str, str, int]:
        """Return the scheme, host, and port this endpoint resolves to."""
        parts = urlsplit(self.origin)
        host = parts.hostname
        if parts.scheme not in _HTTP_SCHEMES or not host or parts.path:
            raise EndpointConfigurationError(_ORIGIN_MESSAGE)
        if parts.scheme == "http" and not _is_loopback(host):
            raise EndpointConfigurationError(_INSECURE_MESSAGE)
        return parts.scheme, host, parts.port or _DEFAULT_PORTS[parts.scheme]


_ORIGIN_MESSAGE: Final = "endpoint origin must be scheme://host[:port] with no path"
_INSECURE_MESSAGE: Final = "refusing a plaintext http endpoint off loopback"


def _is_loopback(host: str) -> bool:
    """Report whether a host is loopback, without ever resolving a name."""
    if host == _LOOPBACK_NAME:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _openai_compatible(
    provider_id: str,
    origin: str,
    path: str = "/v1/chat/completions",
    max_tokens_field: str = "max_tokens",
) -> ProviderEndpoint:
    """Build one entry of the OpenAI-compatible group."""
    return ProviderEndpoint(
        provider_id=provider_id,
        adapter=Adapter.OPENAI_COMPATIBLE,
        origin=origin,
        path=path,
        max_tokens_field=max_tokens_field,
    )


PROVIDER_ENDPOINTS: Final[Mapping[str, ProviderEndpoint]] = MappingProxyType(
    {
        # Each URL below was read from that provider's own current API reference,
        # not inferred from a sibling. The differences are real: Fireworks prefixes
        # `/inference`, DeepSeek documents its base without `/v1`, Z AI serves under
        # `/api/paas/v4`, Qwen under DashScope's `compatible-mode`, and MiniMax does
        # not use the `/chat/completions` name at all.
        "openai": _openai_compatible(
            "openai",
            "https://api.openai.com",
            max_tokens_field="max_completion_tokens",
        ),
        "together": _openai_compatible("together", "https://api.together.ai"),
        "fireworks": _openai_compatible(
            "fireworks",
            "https://api.fireworks.ai",
            path="/inference/v1/chat/completions",
        ),
        "deepseek": _openai_compatible(
            "deepseek",
            "https://api.deepseek.com",
            path="/chat/completions",
        ),
        "moonshot": _openai_compatible("moonshot", "https://api.moonshot.ai"),
        "qwen": _openai_compatible(
            "qwen",
            "https://dashscope-intl.aliyuncs.com",
            path="/compatible-mode/v1/chat/completions",
        ),
        "minimax": _openai_compatible(
            "minimax",
            "https://api.minimax.io",
            path="/v1/text/chatcompletion_v2",
        ),
        "xai": _openai_compatible("xai", "https://api.x.ai"),
        "zai": _openai_compatible(
            "zai",
            "https://api.z.ai",
            path="/api/paas/v4/chat/completions",
        ),
        "mistral": _openai_compatible("mistral", "https://api.mistral.ai"),
        "anthropic": ProviderEndpoint(
            provider_id="anthropic",
            adapter=Adapter.ANTHROPIC,
            origin="https://api.anthropic.com",
            path="/v1/messages",
        ),
        "google": ProviderEndpoint(
            provider_id="google",
            adapter=Adapter.GOOGLE,
            origin="https://generativelanguage.googleapis.com",
            path="/v1beta/models/{model}:streamGenerateContent",
            # `alt=sse` selects the event-stream framing. It is a fixed literal and
            # carries nothing about the researcher; the key stays in a header.
            stream_query="alt=sse",
        ),
        "ollama": ProviderEndpoint(
            provider_id="ollama",
            adapter=Adapter.OLLAMA,
            origin=OLLAMA_ORIGIN,
            path="/api/chat",
        ),
    }
)
"""Confirmed endpoint for each of the thirteen registry providers."""


@final
@dataclass(frozen=True, slots=True)
class _Frame:
    """One decoded step of a provider stream, in neutral terms."""

    text: str = ""
    stop_reason: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    terminal: bool = False


@final
class _InbandFaultError(Exception):
    """Private signal that a stream frame carried a provider failure."""

    code: str | None

    def __init__(self, code: str | None) -> None:
        """Carry only a structured code, never provider prose."""
        super().__init__(_REASON_INBAND)
        self.code = code


def _as_mapping(value: object) -> Mapping[str, object] | None:
    """Narrow a decoded JSON value to an object, or None."""
    if isinstance(value, dict):
        return cast("dict[str, object]", value)
    return None


def _as_sequence(value: object) -> Sequence[object] | None:
    """Narrow a decoded JSON value to an array, or None."""
    if isinstance(value, list):
        return cast("list[object]", value)
    return None


def _as_text(value: object) -> str | None:
    """Narrow a decoded JSON value to a non-empty string, or None."""
    if isinstance(value, str) and value:
        return value
    return None


def _as_count(value: object) -> int | None:
    """Narrow a decoded JSON value to a non-negative count, or None."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _walk(value: object, *keys: str) -> object:
    """Follow a chain of object keys, returning None at the first miss."""
    current = value
    for key in keys:
        mapping = _as_mapping(current)
        if mapping is None:
            return None
        current = mapping.get(key)
    return current


def _first(value: object) -> object:
    """Return the first element of an array, or None."""
    items = _as_sequence(value)
    if not items:
        return None
    return items[0]


def _known_code(value: object) -> str | None:
    """Return a structured code only when this build already knows the token.

    An unrecognised code is discarded rather than stored. That is deliberate:
    the only strings that can reach an error object are literals from this
    source file, so a provider cannot inject text -- a credential echoed back
    included -- into anything a renderer might display.
    """
    token = _as_text(value)
    if token is not None and token in KNOWN_PROVIDER_CODES:
        return token
    return None


def _decode_json(payload: bytes) -> object:
    """Decode one JSON document, or raise the private malformed signal."""
    try:
        return cast("object", json.loads(payload.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _MalformedFrameError(_REASON_BAD_JSON) from error


@final
class _MalformedFrameError(Exception):
    """Private signal that a frame did not parse as its promised format."""

    reason: str

    def __init__(self, reason: str) -> None:
        """Carry a reason token drawn from this module's own constants."""
        super().__init__(reason)
        self.reason = reason


@final
@dataclass(frozen=True, slots=True)
class _SseEvent:
    """One dispatched server-sent event."""

    name: str
    data: bytes


def _iter_lines(chunks: Iterator[bytes], max_frame_bytes: int) -> Iterator[bytes]:
    """Split a byte stream into lines without ever buffering an unbounded one.

    Raises:
        _MalformedFrameError: A single line exceeded `max_frame_bytes`, which is how
            a body that never sends a newline is refused rather than absorbed.
    """
    pending = bytearray()
    for chunk in chunks:
        pending.extend(chunk)
        while True:
            index = pending.find(b"\n")
            if index < 0:
                break
            line = bytes(pending[:index])
            del pending[: index + 1]
            yield line.removesuffix(b"\r")
        if len(pending) > max_frame_bytes:
            raise _MalformedFrameError(_REASON_FRAME_CAP)
    if pending:
        yield bytes(pending).removesuffix(b"\r")


def _iter_sse(lines: Iterator[bytes]) -> Iterator[_SseEvent]:
    """Reassemble server-sent events from lines, per the SSE framing rules."""
    name = ""
    data: list[bytes] = []
    for line in lines:
        if not line:
            if data:
                yield _SseEvent(name=name, data=b"\n".join(data))
            name = ""
            data = []
            continue
        if line.startswith(b":"):
            continue
        field_name, separator, value = line.partition(b":")
        if not separator:
            continue
        payload = value[1:] if value.startswith(b" ") else value
        if field_name == b"data":
            data.append(payload)
        elif field_name == b"event":
            name = payload.decode("utf-8", errors="replace")
    if data:
        yield _SseEvent(name=name, data=b"\n".join(data))


class WireAdapter(Protocol):
    """Translation between the neutral surface and one provider wire format."""

    def request_path(self, endpoint: ProviderEndpoint, model_name: str) -> str:
        """Return the request target, including any fixed query string."""
        ...

    def headers(self, key: str | None) -> dict[str, str]:
        """Return the request headers, with the credential in a header only."""
        ...

    def encode(
        self,
        endpoint: ProviderEndpoint,
        model_name: str,
        request: ModelRequest,
    ) -> bytes:
        """Serialize the neutral request into this provider's body."""
        ...

    def decode(self, chunks: Iterator[bytes], limits: CallLimits) -> Iterator[_Frame]:
        """Turn raw response bytes into neutral frames, incrementally."""
        ...


def _neutral_messages(request: ModelRequest) -> list[dict[str, str]]:
    """Project the neutral messages into role/content objects."""
    return [{"role": item.role, "content": item.content} for item in request.messages]


@final
class OpenAiCompatibleAdapter:
    """`/chat/completions` with `data:` framed deltas, terminated by `[DONE]`."""

    @override
    def __repr__(self) -> str:
        """Describe the adapter; it holds no state and no credential."""
        return f"{type(self).__name__}()"

    def request_path(self, endpoint: ProviderEndpoint, model_name: str) -> str:
        """Return the fixed chat-completions path for this provider."""
        del model_name
        return endpoint.path

    def headers(self, key: str | None) -> dict[str, str]:
        """Return bearer authorization plus the streaming content headers."""
        headers = _base_headers()
        if key is not None:
            headers["Authorization"] = f"Bearer {key}"
        return headers

    def encode(
        self,
        endpoint: ProviderEndpoint,
        model_name: str,
        request: ModelRequest,
    ) -> bytes:
        """Serialize an OpenAI-shaped streaming chat completion request."""
        messages: list[dict[str, str]] = []
        if request.system is not None:
            messages.append({"role": "system", "content": request.system})
        messages.extend(_neutral_messages(request))
        body: dict[str, object] = {
            "model": model_name,
            "messages": messages,
            "stream": True,
            endpoint.max_tokens_field: request.max_output_tokens,
        }
        if request.temperature is not None:
            body["temperature"] = request.temperature
        return _encode_body(body)

    def decode(self, chunks: Iterator[bytes], limits: CallLimits) -> Iterator[_Frame]:
        """Decode `data:` frames into text deltas and a terminal frame."""
        for event in _iter_sse(_iter_lines(chunks, limits.max_frame_bytes)):
            if event.data.strip() == _DONE_SENTINEL.encode("ascii"):
                yield _Frame(terminal=True)
                return
            yield self._frame(_decode_json(event.data))

    def _frame(self, document: object) -> _Frame:
        """Project one chunk object into a neutral frame."""
        _reject_inband_error(document)
        _reject_base_resp(document)
        choice = _first(_walk(document, "choices"))
        text = _as_text(_walk(choice, "delta", "content")) or ""
        stop = _as_text(_walk(choice, "finish_reason"))
        return _Frame(
            text=text,
            stop_reason=stop,
            input_tokens=_as_count(_walk(document, "usage", "prompt_tokens")),
            output_tokens=_as_count(_walk(document, "usage", "completion_tokens")),
        )


def _reject_inband_error(document: object) -> None:
    """Raise when a frame carries an `error` object instead of content."""
    error = _as_mapping(_walk(document, "error"))
    if error is None:
        return
    raise _InbandFaultError(
        _known_code(error.get("type")) or _known_code(error.get("code")),
    )


def _reject_base_resp(document: object) -> None:
    """Raise when a MiniMax-style `base_resp` reports a non-zero status.

    MiniMax answers HTTP 200 and reports the real outcome in `base_resp`. The
    numeric codes are not published in the reference this module was written
    against, so a non-zero value is surfaced as a terminal failure with no
    invented meaning attached rather than guessed into a category.
    """
    status = _as_count(_walk(document, "base_resp", "status_code"))
    if status is not None and status != 0:
        raise _InbandFaultError(None)


@final
class AnthropicAdapter:
    """`/v1/messages` with named SSE events and `text_delta` content deltas."""

    @override
    def __repr__(self) -> str:
        """Describe the adapter; it holds no state and no credential."""
        return f"{type(self).__name__}()"

    def request_path(self, endpoint: ProviderEndpoint, model_name: str) -> str:
        """Return the fixed messages path."""
        del model_name
        return endpoint.path

    def headers(self, key: str | None) -> dict[str, str]:
        """Return `x-api-key` and the required API version header."""
        headers = _base_headers()
        headers["anthropic-version"] = ANTHROPIC_VERSION
        if key is not None:
            headers["x-api-key"] = key
        return headers

    def encode(
        self,
        endpoint: ProviderEndpoint,
        model_name: str,
        request: ModelRequest,
    ) -> bytes:
        """Serialize a Messages API streaming request."""
        del endpoint
        body: dict[str, object] = {
            "model": model_name,
            "messages": _neutral_messages(request),
            "stream": True,
            "max_tokens": request.max_output_tokens,
        }
        if request.system is not None:
            body["system"] = request.system
        if request.temperature is not None:
            body["temperature"] = request.temperature
        return _encode_body(body)

    def decode(self, chunks: Iterator[bytes], limits: CallLimits) -> Iterator[_Frame]:
        """Decode the Messages event stream into neutral frames."""
        for event in _iter_sse(_iter_lines(chunks, limits.max_frame_bytes)):
            document = _decode_json(event.data)
            kind = _as_text(_walk(document, "type")) or event.name
            if kind == "error":
                raise _InbandFaultError(_known_code(_walk(document, "error", "type")))
            if kind == "message_stop":
                yield _Frame(terminal=True)
                return
            yield self._frame(kind, document)

    def _frame(self, kind: str, document: object) -> _Frame:
        """Project one named event into a neutral frame."""
        if kind == "content_block_delta":
            delta = _walk(document, "delta")
            if _as_text(_walk(delta, "type")) == "text_delta":
                return _Frame(text=_as_text(_walk(delta, "text")) or "")
            return _Frame()
        if kind == "message_start":
            tokens = _walk(document, "message", "usage", "input_tokens")
            return _Frame(input_tokens=_as_count(tokens))
        if kind == "message_delta":
            return _Frame(
                stop_reason=_as_text(_walk(document, "delta", "stop_reason")),
                output_tokens=_as_count(_walk(document, "usage", "output_tokens")),
            )
        return _Frame()


@final
class GoogleAdapter:
    """`streamGenerateContent?alt=sse` with `candidates[].content.parts[].text`."""

    @override
    def __repr__(self) -> str:
        """Describe the adapter; it holds no state and no credential."""
        return f"{type(self).__name__}()"

    def request_path(self, endpoint: ProviderEndpoint, model_name: str) -> str:
        """Return the model-templated path, percent-encoding the model name."""
        path = endpoint.path.replace("{model}", quote(model_name, safe=""))
        if endpoint.stream_query:
            return f"{path}?{endpoint.stream_query}"
        return path

    def headers(self, key: str | None) -> dict[str, str]:
        """Return the API key header; Gemini also accepts it as a query
        parameter, which this module never uses.
        """  # noqa: D205
        headers = _base_headers()
        if key is not None:
            headers["x-goog-api-key"] = key
        return headers

    def encode(
        self,
        endpoint: ProviderEndpoint,
        model_name: str,
        request: ModelRequest,
    ) -> bytes:
        """Serialize a `GenerateContentRequest`."""
        del endpoint, model_name
        contents = [
            {
                "role": "model" if item.role == ASSISTANT_ROLE else USER_ROLE,
                "parts": [{"text": item.content}],
            }
            for item in request.messages
        ]
        generation: dict[str, object] = {"maxOutputTokens": request.max_output_tokens}
        if request.temperature is not None:
            generation["temperature"] = request.temperature
        body: dict[str, object] = {
            "contents": contents,
            "generationConfig": generation,
        }
        if request.system is not None:
            body["systemInstruction"] = {"parts": [{"text": request.system}]}
        return _encode_body(body)

    def decode(self, chunks: Iterator[bytes], limits: CallLimits) -> Iterator[_Frame]:
        """Decode the SSE-framed `GenerateContentResponse` chunks."""
        seen = False
        for event in _iter_sse(_iter_lines(chunks, limits.max_frame_bytes)):
            document = _decode_json(event.data)
            _reject_google_error(document)
            seen = True
            yield self._frame(document)
        if seen:
            # Gemini closes the stream rather than sending a sentinel, so the
            # clean end of a stream that produced chunks is the terminal event.
            yield _Frame(terminal=True)

    def _frame(self, document: object) -> _Frame:
        """Project one candidate chunk into a neutral frame."""
        candidate = _first(_walk(document, "candidates"))
        parts = _as_sequence(_walk(candidate, "content", "parts")) or ()
        text = "".join(_as_text(_walk(part, "text")) or "" for part in parts)
        usage = _walk(document, "usageMetadata")
        return _Frame(
            text=text,
            stop_reason=_as_text(_walk(candidate, "finishReason")),
            input_tokens=_as_count(_walk(usage, "promptTokenCount")),
            output_tokens=_as_count(_walk(usage, "candidatesTokenCount")),
        )


def _reject_google_error(document: object) -> None:
    """Raise when a Gemini chunk carries an `error` object."""
    error = _as_mapping(_walk(document, "error"))
    if error is not None:
        raise _InbandFaultError(_known_code(error.get("status")))


@final
class OllamaAdapter:
    """Local `/api/chat`, newline-delimited JSON, no credential at all."""

    @override
    def __repr__(self) -> str:
        """Describe the adapter; it holds no state and no credential."""
        return f"{type(self).__name__}()"

    def request_path(self, endpoint: ProviderEndpoint, model_name: str) -> str:
        """Return the fixed chat path."""
        del model_name
        return endpoint.path

    def headers(self, key: str | None) -> dict[str, str]:
        """Return content headers only; Ollama is local and takes no key."""
        del key
        headers = _base_headers()
        headers["Accept"] = "application/x-ndjson"
        return headers

    def encode(
        self,
        endpoint: ProviderEndpoint,
        model_name: str,
        request: ModelRequest,
    ) -> bytes:
        """Serialize an Ollama chat request."""
        del endpoint
        messages: list[dict[str, str]] = []
        if request.system is not None:
            messages.append({"role": "system", "content": request.system})
        messages.extend(_neutral_messages(request))
        options: dict[str, object] = {"num_predict": request.max_output_tokens}
        if request.temperature is not None:
            options["temperature"] = request.temperature
        return _encode_body(
            {
                "model": model_name,
                "messages": messages,
                "stream": True,
                "options": options,
            }
        )

    def decode(self, chunks: Iterator[bytes], limits: CallLimits) -> Iterator[_Frame]:
        """Decode newline-delimited JSON objects into neutral frames."""
        for line in _iter_lines(chunks, limits.max_frame_bytes):
            if not line.strip():
                continue
            document = _decode_json(line)
            _reject_ollama_error(document)
            frame = self._frame(document)
            yield frame
            if frame.terminal:
                return

    def _frame(self, document: object) -> _Frame:
        """Project one NDJSON object into a neutral frame."""
        done = _walk(document, "done") is True
        return _Frame(
            text=_as_text(_walk(document, "message", "content")) or "",
            stop_reason=_as_text(_walk(document, "done_reason")),
            input_tokens=_as_count(_walk(document, "prompt_eval_count")),
            output_tokens=_as_count(_walk(document, "eval_count")),
            terminal=done,
        )


def _reject_ollama_error(document: object) -> None:
    """Raise when an Ollama frame carries an `error` string."""
    mapping = _as_mapping(document)
    if mapping is not None and "error" in mapping:
        raise _InbandFaultError(None)


def _base_headers() -> dict[str, str]:
    """Return the headers every adapter shares."""
    return {
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        "Connection": "close",
    }


def _encode_body(body: Mapping[str, object]) -> bytes:
    """Serialize a request body deterministically."""
    return json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


_ADAPTERS: Final[Mapping[Adapter, WireAdapter]] = MappingProxyType(
    {
        Adapter.OPENAI_COMPATIBLE: OpenAiCompatibleAdapter(),
        Adapter.ANTHROPIC: AnthropicAdapter(),
        Adapter.GOOGLE: GoogleAdapter(),
        Adapter.OLLAMA: OllamaAdapter(),
    }
)


def adapter_for(endpoint: ProviderEndpoint) -> WireAdapter:
    """Return the wire adapter one endpoint speaks."""
    return _ADAPTERS[endpoint.adapter]


@final
@dataclass(slots=True)
class _TurnState:
    """Mutable accumulation behind the immutable :class:`TurnRecord`."""

    provider_id: str
    model_id: str
    model_name: str
    adapter: Adapter
    connection: str
    request_count: int = 0
    response_bytes: int = 0
    text_characters: int = 0
    stop_reason: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    _terminal_seen: bool = field(default=False)

    def absorb(self, frame: _Frame) -> None:
        """Fold one decoded frame into the accumulating record."""
        self.text_characters += len(frame.text)
        if frame.stop_reason is not None:
            self.stop_reason = frame.stop_reason
        if frame.input_tokens is not None:
            self.input_tokens = frame.input_tokens
        if frame.output_tokens is not None:
            self.output_tokens = frame.output_tokens
        if frame.terminal:
            self._terminal_seen = True

    @property
    def terminal_seen(self) -> bool:
        """Report whether the provider signalled a complete stream."""
        return self._terminal_seen

    def record(self) -> TurnRecord:
        """Freeze the accumulated state into the durable turn record."""
        return TurnRecord(
            provider_id=self.provider_id,
            model_id=self.model_id,
            model_name=self.model_name,
            adapter=self.adapter,
            connection=self.connection,
            request_count=self.request_count,
            response_bytes=self.response_bytes,
            text_characters=self.text_characters,
            stop_reason=self.stop_reason,
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
        )


@final
@dataclass(slots=True)
class _Turn:
    """Everything one in-flight turn needs, so no signature grows unreadable."""

    spec: ProviderSpec
    endpoint: ProviderEndpoint
    adapter: WireAdapter
    target: str
    state: _TurnState

    def error(
        self,
        failure: ModelCallFailure,
        reason: str,
        http_status: int | None = None,
        provider_code: str | None = None,
    ) -> ModelCallError:
        """Build the typed error for one classification of this turn."""
        return _ERROR_CLASSES[failure](
            self.state.provider_id,
            self.state.model_id,
            reason,
            http_status=http_status,
            provider_code=provider_code,
        )


@final
class ModelCallClient:
    """One model turn against one explicitly selected provider and model.

    The client never chooses a provider. It is handed a `provider:model` id,
    resolves that provider's credential at call time, issues exactly one
    request, and reports whatever happened in provider-neutral terms.
    """

    def __init__(
        self,
        registry: ProviderRegistry,
        endpoints: Mapping[str, ProviderEndpoint] | None = None,
        limits: CallLimits = DEFAULT_LIMITS,
    ) -> None:
        """Bind the client to a provider registry, endpoint table, and bounds."""
        self._registry = registry
        self._endpoints: Mapping[str, ProviderEndpoint] = (
            PROVIDER_ENDPOINTS if endpoints is None else dict(endpoints)
        )
        self._limits = limits

    @override
    def __repr__(self) -> str:
        """Describe the client without touching any credential state."""
        return f"{type(self).__name__}(providers={sorted(self._endpoints)!r})"

    def stream(self, model_id: str, request: ModelRequest) -> Iterator[ModelEvent]:
        """Stream one model turn, validating everything before any egress.

        Args:
            model_id: A `<provider_id>:<model_name>` reference, exactly as the
                composer persisted it.
            request: The neutral request to translate for the selected provider.

        Returns:
            An iterator of :class:`TextDelta` events followed by exactly one
            terminal event. A failed turn yields :class:`Failed` and then raises
            the same error, so a failure cannot be consumed silently.

        Raises:
            ModelCallError: Any failure of the selected provider or model. No
                other provider, model, or credential is ever tried.
        """
        spec, model_name = parse_model_id(model_id)
        endpoint = self._endpoints.get(spec.provider_id)
        if endpoint is None:
            raise InvalidRequestError(spec.provider_id, model_id, _REASON_NO_ENDPOINT)
        _validate_model_name(spec.provider_id, model_id, model_name)
        _validate_request(spec.provider_id, model_id, request)
        self._require_credential(spec, model_id)
        return self._run(spec, model_id, model_name, endpoint, request)

    def _require_credential(self, spec: ProviderSpec, model_id: str) -> None:
        """Fail before opening a socket when no credential is configured.

        The registry resolves status without decrypting anything, so this check
        costs no unlock and -- crucially -- issues no request, which is what
        makes "a provider without a key contacts nobody" testable.
        """
        if self._registry.status(spec.provider_id) is ProviderStatus.NOT_SET_UP:
            raise AuthenticationError(spec.provider_id, model_id, _REASON_NO_CREDENTIAL)

    def _run(
        self,
        spec: ProviderSpec,
        model_id: str,
        model_name: str,
        endpoint: ProviderEndpoint,
        request: ModelRequest,
    ) -> Iterator[ModelEvent]:
        """Drive the single request and project its response into events."""
        adapter = _ADAPTERS[endpoint.adapter]
        target = adapter.request_path(endpoint, model_name)
        turn = _Turn(
            spec=spec,
            endpoint=endpoint,
            adapter=adapter,
            target=target,
            state=_TurnState(
                provider_id=spec.provider_id,
                model_id=model_id,
                model_name=model_name,
                adapter=endpoint.adapter,
                connection=f"{endpoint.origin}{target.partition('?')[0]}",
            ),
        )
        body = adapter.encode(endpoint, model_name, request)
        connection: http.client.HTTPConnection | None = None
        response: http.client.HTTPResponse | None = None
        try:
            connection = self._connect(turn)
            deadline = time.monotonic() + self._limits.total_timeout_seconds
            response = self._send(connection, turn, body)
            turn.state.request_count = 1
            self._check_status(response, turn)
            yield from self._consume(response, turn, deadline)
            yield Completed(turn=turn.state.record())
        except ModelCallError as error:
            error.turn = turn.state.record()
            yield Failed(turn=error.turn, error=error)
            raise
        finally:
            # Both, and in this order. A response carrying `Connection: close`
            # makes `getresponse` detach the socket from the connection, so
            # closing the connection alone leaves the response's file object --
            # and with it the socket -- open until the collector notices.
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()

    def _connect(self, turn: _Turn) -> http.client.HTTPConnection:
        """Open one connection to the selected provider, and nowhere else."""
        scheme, host, port = turn.endpoint.address()
        timeout = self._limits.socket_timeout_seconds
        if scheme == "https":
            return http.client.HTTPSConnection(host, port, timeout=timeout)
        return http.client.HTTPConnection(host, port, timeout=timeout)

    def _send(
        self,
        connection: http.client.HTTPConnection,
        turn: _Turn,
        body: bytes,
    ) -> http.client.HTTPResponse:
        """Resolve the credential, issue the one request, and drop the key.

        The key exists only as a local of this frame and as a value of the
        header mapping, which `finally` clears. Nothing that could raise while
        holding it is allowed to escape with its traceback attached: the
        transport failure is re-raised *after* the `try` statement has finished,
        so the new exception has no `__context__` and therefore no reference to
        a frame whose locals contained the header mapping.
        """
        key = self._registry.resolve_key(turn.spec.provider_id)
        if turn.spec.requires_key and key is None:
            raise turn.error(ModelCallFailure.AUTHENTICATION, _REASON_NO_CREDENTIAL)
        headers = turn.adapter.headers(key)
        del key
        response: http.client.HTTPResponse | None = None
        timed_out = False
        transport_failed = False
        try:
            connection.request("POST", turn.target, body=body, headers=headers)
            response = connection.getresponse()
        except TimeoutError:
            timed_out = True
        except (OSError, http.client.HTTPException):
            transport_failed = True
        finally:
            headers.clear()
        if timed_out:
            raise turn.error(ModelCallFailure.TIMEOUT, _REASON_SOCKET_TIMEOUT)
        if transport_failed or response is None:
            raise turn.error(ModelCallFailure.TRANSPORT, _REASON_CONNECT)
        return response

    def _check_status(
        self,
        response: http.client.HTTPResponse,
        turn: _Turn,
    ) -> None:
        """Classify a non-200 status from its code and structured error token."""
        status = response.status
        if status == HTTPStatus.OK:
            return
        # `_error_code` returns rather than raises, so the decoded body -- which
        # the provider controls and could have echoed a credential into -- is
        # never a local of a frame this raise puts into a traceback.
        code = _error_code(response)
        failure = KNOWN_PROVIDER_CODES.get(code) if code is not None else None
        if failure is None:
            failure = _STATUS_FAILURES.get(status, ModelCallFailure.UNCLASSIFIED)
        raise turn.error(
            failure,
            _FAILURE_REASONS[failure],
            http_status=status,
            provider_code=code,
        )

    def _consume(
        self,
        response: http.client.HTTPResponse,
        turn: _Turn,
        deadline: float,
    ) -> Iterator[ModelEvent]:
        """Yield text deltas as they arrive, converting private signals."""
        chunks = self._read(response, turn, deadline)
        outcome: tuple[ModelCallFailure, str, str | None] | None = None
        try:
            for frame in turn.adapter.decode(chunks, self._limits):
                turn.state.absorb(frame)
                if frame.text:
                    yield TextDelta(text=frame.text)
        except _MalformedFrameError as signal:
            outcome = (_frame_failure(signal.reason), signal.reason, None)
        except _InbandFaultError as signal:
            outcome = (_code_failure(signal.code), _REASON_INBAND, signal.code)
        if outcome is not None:
            # Raised outside the handler on purpose. Chaining -- with `from` or
            # implicitly through `__context__` -- would keep the decoder's
            # traceback reachable, and those frames hold the provider's raw
            # bytes, which may contain a credential the endpoint echoed back.
            failure, reason, code = outcome
            raise turn.error(failure, reason, provider_code=code)
        if not turn.state.terminal_seen:
            # A stream that stops without its terminal frame is truncated, and
            # a truncated answer must never be presented as a complete one.
            raise turn.error(ModelCallFailure.TRANSPORT, _REASON_NO_TERMINAL)

    def _read(
        self,
        response: http.client.HTTPResponse,
        turn: _Turn,
        deadline: float,
    ) -> Iterator[bytes]:
        """Read the body in bounded chunks under both size and time bounds."""
        limit = self._limits.max_response_bytes
        while True:
            if time.monotonic() > deadline:
                raise turn.error(ModelCallFailure.TIMEOUT, _REASON_TOTAL_TIMEOUT)
            chunk = self._read_once(response, turn)
            if not chunk:
                return
            turn.state.response_bytes += len(chunk)
            if turn.state.response_bytes > limit:
                raise turn.error(ModelCallFailure.RESPONSE_TOO_LARGE, _REASON_BODY_CAP)
            yield chunk

    def _read_once(
        self,
        response: http.client.HTTPResponse,
        turn: _Turn,
    ) -> bytes:
        """Read whatever has arrived, classifying a stall or a severed stream."""
        try:
            return response.read1(READ_CHUNK_BYTES)
        except TimeoutError as error:
            raise turn.error(
                ModelCallFailure.TIMEOUT, _REASON_SOCKET_TIMEOUT
            ) from error
        except (OSError, http.client.HTTPException) as error:
            raise turn.error(ModelCallFailure.TRANSPORT, _REASON_STREAM_CUT) from error


def _frame_failure(reason: str) -> ModelCallFailure:
    """Classify a decoder signal by which bound or shape rule it broke."""
    if reason == _REASON_FRAME_CAP:
        return ModelCallFailure.RESPONSE_TOO_LARGE
    return ModelCallFailure.MALFORMED_RESPONSE


def _code_failure(code: str | None) -> ModelCallFailure:
    """Classify an in-band fault by its structured code, when one is known."""
    if code is None:
        return ModelCallFailure.UNCLASSIFIED
    return KNOWN_PROVIDER_CODES[code]


def _error_code(response: http.client.HTTPResponse) -> str | None:
    """Return the one code token a bounded error body carries, if any.

    Everything else the body held is discarded here, in a function that returns
    rather than raises, so no provider-controlled value ever survives as the
    local of a frame that an eventual traceback can reach.
    """
    document = _read_error_document(response)
    for name in ("type", "code", "status"):
        token = _known_code(_walk(document, "error", name))
        if token is not None:
            return token
    return None


def _read_error_document(response: http.client.HTTPResponse) -> object:
    """Read a bounded error body once and decode it, or return None.

    The body is consulted for its structured code and nothing else; its prose
    is never retained, so an error message cannot carry provider text. The read
    is capped because an error body is as attacker-controlled as any other.
    """
    try:
        payload = response.read(MAX_ERROR_BODY_BYTES)
    except (OSError, http.client.HTTPException):
        return None
    try:
        return cast("object", json.loads(payload.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _validate_model_name(provider_id: str, model_id: str, model_name: str) -> None:
    """Reject a model name that is not a safe, path-embeddable token.

    Gemini puts the model name in the request path, so a name carrying a
    separator, a query character, or whitespace could otherwise retarget the
    request. Rejecting it for every provider keeps one rule rather than a
    per-adapter exception nobody remembers.
    """
    if not model_name or len(model_name) > MAX_MODEL_NAME_LENGTH:
        raise InvalidRequestError(provider_id, model_id, _REASON_BAD_MODEL_NAME)
    if not model_name.isascii() or not model_name.isprintable():
        raise InvalidRequestError(provider_id, model_id, _REASON_BAD_MODEL_NAME)
    if any(character in model_name for character in " /?#\\@"):
        raise InvalidRequestError(provider_id, model_id, _REASON_BAD_MODEL_NAME)


def _validate_request(provider_id: str, model_id: str, request: ModelRequest) -> None:
    """Reject a request no provider could honour, before any egress."""
    if not request.messages:
        raise InvalidRequestError(provider_id, model_id, _REASON_EMPTY_MESSAGES)
    if request.max_output_tokens <= 0:
        raise InvalidRequestError(provider_id, model_id, _REASON_BAD_TOKENS)
    for message in request.messages:
        if message.role not in {USER_ROLE, ASSISTANT_ROLE}:
            raise InvalidRequestError(provider_id, model_id, _REASON_REFUSED)
