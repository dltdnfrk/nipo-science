"""Outcome tests for `nipo_local.modelcall`, driven against a real HTTP server.

Nothing here mocks the transport. Every test starts `WireServer` on a loopback
port, writes real chunked HTTP/1.1 with real SSE or NDJSON framing, and drives
the client against it. The defects this module exists to prevent -- a stream cut
mid-frame, an unbounded line, a stalled socket, a fallback to a second provider,
a key on a URL, a key surviving in a traceback frame -- are all invisible to a
mocked `urlopen`, which proves only that the author can write a mock.

Assertions are on typed fields (`type(error)`, `error.failure`, `turn.*`,
recorded request paths and headers), never on substrings of a message that
happens to contain a temporary path. A sibling module was burned exactly that
way: `tmp_path` embeds the test's own function name, so a substring assertion
passed on the path rather than on the behaviour.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import MappingProxyType, TracebackType
from typing import TYPE_CHECKING, Final, cast, final, override
from urllib.parse import urlsplit

import pytest

from nipo_local.config import LocalPaths
from nipo_local.modelcall import PROVIDER_ENDPOINTS as DEFAULT_ENDPOINTS
from nipo_local.modelcall import (
    Adapter,
    AuthenticationError,
    CallLimits,
    Completed,
    EndpointConfigurationError,
    EventKind,
    Failed,
    InvalidRequestError,
    MalformedResponseError,
    Message,
    ModelCallClient,
    ModelCallError,
    ModelCallFailure,
    ModelCallTimeoutError,
    ModelRequest,
    ModelUnavailableError,
    ProviderEndpoint,
    ProviderUnavailableError,
    QuotaExhaustedError,
    RateLimitError,
    ResponseTooLargeError,
    TextDelta,
    TransportError,
    TurnRecord,
    UnclassifiedProviderError,
    adapter_for,
)
from nipo_local.providers import PROVIDERS, InMemoryCredentialBackend, ProviderRegistry

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable, Iterator, Mapping
    from pathlib import Path

    from nipo_local.modelcall import ModelEvent

# --------------------------------------------------------------------------
# A real loopback HTTP/1.1 server speaking each provider's wire format.
# --------------------------------------------------------------------------

LOOPBACK: Final = "127.0.0.1"
CHUNK_TERMINATOR: Final = b"0\r\n\r\n"
NOT_FOUND_BODY: Final = b'{"error":{"type":"not_found_error"}}'


@final
@dataclass(frozen=True, slots=True)
class RecordedRequest:
    method: str
    target: str
    path: str
    query: str
    headers: Mapping[str, str]
    body: bytes


@final
@dataclass(slots=True)
class Route:
    """What the server does for one path.

    `gate_after` blocks the server mid-stream on an event only the test can
    open, and it opens it only once the client has already produced a delta. A
    client that buffered the whole body could never reach that point, so the
    gate timing out -- recorded in `gate_expired` -- is a positive detection of
    buffered-pretending-to-stream. `cut_after` severs the socket inside a chunk
    whose header promised more bytes, reproducing a dropped connection.
    """

    status: int = 200
    content_type: str = "text/event-stream"
    chunks: tuple[bytes, ...] = ()
    body: bytes | None = None
    chunk_delay: float = 0.0
    gate_after: int | None = None
    gate: threading.Event = field(default_factory=threading.Event)
    gate_timeout: float = 3.0
    gate_expired: bool = False
    cut_after: int | None = None


@final
class _Server(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, address: tuple[str, int], routes: Mapping[str, Route]) -> None:
        self.routes: dict[str, Route] = dict(routes)
        self.log_lock = threading.Lock()
        self.log: list[RecordedRequest] = []
        super().__init__(address, _Handler)

    @override
    def handle_error(self, request: object, client_address: object) -> None:
        del request, client_address


@final
class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @override
    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def do_POST(self) -> None:
        owner = cast("_Server", self.server)
        parts = urlsplit(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        record = RecordedRequest(
            method=self.command,
            target=self.path,
            path=parts.path,
            query=parts.query,
            headers=MappingProxyType(
                {name.lower(): value for name, value in self.headers.items()}
            ),
            body=self.rfile.read(length) if length else b"",
        )
        with owner.log_lock:
            owner.log.append(record)
        route = owner.routes.get(parts.path)
        if route is None:
            self._answer_whole(Route(status=404, body=NOT_FOUND_BODY))
            return
        if route.body is not None:
            self._answer_whole(route)
            return
        self._answer_stream(route)

    def _answer_whole(self, route: Route) -> None:
        payload = route.body or b""
        self.send_response(route.status)
        self.send_header("Content-Type", route.content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        _ = self.wfile.write(payload)

    def _answer_stream(self, route: Route) -> None:
        self.send_response(route.status)
        self.send_header("Content-Type", route.content_type)
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self._stream(route)
        except OSError:
            # The client aborted on purpose -- an oversized body, a tripped
            # deadline, a closed generator. Not a failure of this server.
            self.close_connection = True

    def _stream(self, route: Route) -> None:
        for index, chunk in enumerate(route.chunks):
            if route.cut_after is not None and index >= route.cut_after:
                self._cut()
                return
            gated = route.gate_after is not None and index == route.gate_after
            if gated and not route.gate.wait(route.gate_timeout):
                route.gate_expired = True
            if route.chunk_delay:
                time.sleep(route.chunk_delay)
            self._write_chunk(chunk)
        _ = self.wfile.write(CHUNK_TERMINATOR)
        self.wfile.flush()

    def _write_chunk(self, payload: bytes) -> None:
        header = f"{len(payload):X}\r\n".encode("ascii")
        _ = self.wfile.write(header + payload + b"\r\n")
        self.wfile.flush()

    def _cut(self) -> None:
        # A chunk header promising 0x400 bytes followed by nine, then a closed
        # socket: severed mid-frame, so the client cannot mistake the end of
        # the bytes for the end of the answer.
        _ = self.wfile.write(b"400\r\ntruncated")
        self.wfile.flush()
        self.close_connection = True


@final
class WireServer:
    def __init__(self, routes: Mapping[str, Route]) -> None:
        self._server = _Server((LOOPBACK, 0), routes)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="nipo-wire-server",
            daemon=True,
        )
        self._thread.start()

    @property
    def origin(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host!s}:{port!s}"

    @property
    def requests(self) -> tuple[RecordedRequest, ...]:
        with self._server.log_lock:
            return tuple(self._server.log)

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5.0)

    def __enter__(self) -> WireServer:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        self.close()


def sse(payloads: Iterable[str]) -> tuple[bytes, ...]:
    return tuple(f"data: {item}\n\n".encode() for item in payloads)


def named_sse(events: Iterable[tuple[str, str]]) -> tuple[bytes, ...]:
    return tuple(
        f"event: {name}\ndata: {payload}\n\n".encode() for name, payload in events
    )


def ndjson(payloads: Iterable[str]) -> tuple[bytes, ...]:
    return tuple(f"{item}\n".encode() for item in payloads)


# --------------------------------------------------------------------------
# Fixtures.
# --------------------------------------------------------------------------

# Long, unique, and shaped like a current `sk-proj-` key: long enough that no
# temporary path or test name could ever contain it by accident, so asserting
# its absence is an assertion about leakage and nothing else.
CANARY_KEY: Final = "sk-proj-canarykey-" + "Zq7xV" * 26 + "-TAIL"
SECOND_KEY: Final = "sk-ant-secondkey-" + "Wm3pR" * 20 + "-TAIL"

OPENAI_PATH: Final = "/openai/v1/chat/completions"
ANTHROPIC_PATH: Final = "/anthropic/v1/messages"
GOOGLE_TEMPLATE: Final = "/google/v1beta/models/{model}:streamGenerateContent"
GOOGLE_PATH: Final = "/google/v1beta/models/gemini-test:streamGenerateContent"
OLLAMA_PATH: Final = "/ollama/api/chat"

OPENAI_MODEL: Final = "openai:gpt-test"
ANTHROPIC_MODEL: Final = "anthropic:claude-test"
GOOGLE_MODEL: Final = "google:gemini-test"
OLLAMA_MODEL: Final = "ollama:llama-test"

REQUEST: Final = ModelRequest(
    messages=(Message(role="user", content="Summarise the spectrum."),),
    max_output_tokens=256,
    system="You are a careful research assistant.",
    temperature=0.0,
)

OPENAI_CHUNKS: Final = sse(
    [
        json.dumps({"choices": [{"delta": {"role": "assistant"}}]}),
        json.dumps({"choices": [{"delta": {"content": "Hel"}}]}),
        json.dumps({"choices": [{"delta": {"content": "lo"}}]}),
        json.dumps(
            {
                "choices": [{"delta": {}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 11, "completion_tokens": 2},
            }
        ),
        "[DONE]",
    ]
)

ANTHROPIC_CHUNKS: Final = named_sse(
    [
        (
            "message_start",
            json.dumps(
                {
                    "type": "message_start",
                    "message": {"usage": {"input_tokens": 25}},
                }
            ),
        ),
        (
            "content_block_start",
            json.dumps(
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""},
                }
            ),
        ),
        ("ping", json.dumps({"type": "ping"})),
        (
            "content_block_delta",
            json.dumps(
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": "Hel"},
                }
            ),
        ),
        (
            "content_block_delta",
            json.dumps(
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": "lo"},
                }
            ),
        ),
        ("content_block_stop", json.dumps({"type": "content_block_stop", "index": 0})),
        (
            "message_delta",
            json.dumps(
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn"},
                    "usage": {"output_tokens": 2},
                }
            ),
        ),
        ("message_stop", json.dumps({"type": "message_stop"})),
    ]
)

GOOGLE_CHUNKS: Final = sse(
    [
        json.dumps({"candidates": [{"content": {"parts": [{"text": "Hel"}]}}]}),
        json.dumps(
            {
                "candidates": [
                    {"content": {"parts": [{"text": "lo"}]}, "finishReason": "STOP"}
                ],
                "usageMetadata": {"promptTokenCount": 11, "candidatesTokenCount": 2},
            }
        ),
    ]
)

OLLAMA_CHUNKS: Final = ndjson(
    [
        json.dumps({"message": {"role": "assistant", "content": "Hel"}, "done": False}),
        json.dumps({"message": {"role": "assistant", "content": "lo"}, "done": False}),
        json.dumps(
            {
                "message": {"role": "assistant", "content": ""},
                "done": True,
                "done_reason": "stop",
                "prompt_eval_count": 11,
                "eval_count": 2,
            }
        ),
    ]
)


def build_registry(root: Path, keys: Mapping[str, str]) -> ProviderRegistry:
    registry = ProviderRegistry(LocalPaths(root=root), InMemoryCredentialBackend(), {})
    for provider_id, key in keys.items():
        registry.set_key(provider_id, key)
    return registry


def endpoints_for(origin: str) -> dict[str, ProviderEndpoint]:
    return {
        "openai": ProviderEndpoint(
            "openai", Adapter.OPENAI_COMPATIBLE, origin, OPENAI_PATH
        ),
        "anthropic": ProviderEndpoint(
            "anthropic", Adapter.ANTHROPIC, origin, ANTHROPIC_PATH
        ),
        "google": ProviderEndpoint(
            "google", Adapter.GOOGLE, origin, GOOGLE_TEMPLATE, stream_query="alt=sse"
        ),
        "ollama": ProviderEndpoint("ollama", Adapter.OLLAMA, origin, OLLAMA_PATH),
    }


def client_for(
    root: Path,
    origin: str,
    limits: CallLimits | None = None,
) -> ModelCallClient:
    registry = build_registry(
        root, {"openai": CANARY_KEY, "anthropic": SECOND_KEY, "google": SECOND_KEY}
    )
    return ModelCallClient(registry, endpoints_for(origin), limits or CallLimits())


def build_client(
    root: Path,
    server: WireServer,
    limits: CallLimits | None = None,
) -> ModelCallClient:
    return client_for(root, server.origin, limits)


@final
class RecordingBackend:
    """Credential backend that records every attempt to read a secret.

    SPEC-v0.5 section 7 requires provider status to be resolvable "without
    decrypting or unlocking anything". This makes that observable: an
    unconfigured provider must be detected without a single `read`.
    """

    def __init__(self) -> None:
        self._inner = InMemoryCredentialBackend()
        self.reads: list[str] = []

    def available(self) -> bool:
        return self._inner.available()

    def has(self, account: str) -> bool:
        return self._inner.has(account)

    def read(self, account: str) -> str | None:
        self.reads.append(account)
        return self._inner.read(account)

    def write(self, account: str, secret: str) -> None:
        self._inner.write(account, secret)

    def remove(self, account: str) -> None:
        self._inner.remove(account)


def drain(events: Iterator[ModelEvent]) -> tuple[str, TurnRecord]:
    parts: list[str] = []
    record: TurnRecord | None = None
    for event in events:
        if isinstance(event, TextDelta):
            parts.append(event.text)
        elif isinstance(event, Completed):
            record = event.turn
    assert record is not None
    return "".join(parts), record


def json_body(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload).encode("utf-8")


def decoded_body(raw: bytes) -> Mapping[str, object]:
    document = cast("object", json.loads(raw.decode("utf-8")))
    assert isinstance(document, dict)
    return cast("dict[str, object]", document)


def error_body(**fields: str) -> bytes:
    return json_body({"error": dict(fields)})


# --------------------------------------------------------------------------
# Correct streamed responses, one per wire format.
# --------------------------------------------------------------------------


def test_openai_compatible_stream_yields_deltas_and_a_turn_record(
    tmp_path: Path,
) -> None:
    with WireServer({OPENAI_PATH: Route(chunks=OPENAI_CHUNKS)}) as server:
        client = build_client(tmp_path, server)
        text, record = drain(client.stream(OPENAI_MODEL, REQUEST))
        origin = server.origin
        log = server.requests
    assert text == "Hello"
    assert record.provider_id == "openai"
    assert record.model_id == OPENAI_MODEL
    assert record.model_name == "gpt-test"
    assert record.adapter is Adapter.OPENAI_COMPATIBLE
    assert record.connection == f"{origin}{OPENAI_PATH}"
    assert record.request_count == 1
    assert record.stop_reason == "stop"
    assert record.input_tokens == 11
    assert record.output_tokens == 2
    assert record.text_characters == 5
    body = decoded_body(log[0].body)
    assert body["model"] == "gpt-test"
    assert body["stream"] is True
    assert body["max_tokens"] == 256
    assert body["messages"] == [
        {"role": "system", "content": "You are a careful research assistant."},
        {"role": "user", "content": "Summarise the spectrum."},
    ]


def test_anthropic_stream_decodes_named_events(tmp_path: Path) -> None:
    with WireServer({ANTHROPIC_PATH: Route(chunks=ANTHROPIC_CHUNKS)}) as server:
        client = build_client(tmp_path, server)
        text, record = drain(client.stream(ANTHROPIC_MODEL, REQUEST))
        log = server.requests
    assert text == "Hello"
    assert record.adapter is Adapter.ANTHROPIC
    assert record.stop_reason == "end_turn"
    assert record.input_tokens == 25
    assert record.output_tokens == 2
    assert log[0].headers["anthropic-version"] == "2023-06-01"
    assert log[0].headers["x-api-key"] == SECOND_KEY
    body = decoded_body(log[0].body)
    assert body["max_tokens"] == 256
    assert body["system"] == "You are a careful research assistant."
    assert body["messages"] == [{"role": "user", "content": "Summarise the spectrum."}]


def test_google_stream_decodes_candidates_and_templates_the_path(
    tmp_path: Path,
) -> None:
    with WireServer({GOOGLE_PATH: Route(chunks=GOOGLE_CHUNKS)}) as server:
        client = build_client(tmp_path, server)
        text, record = drain(client.stream(GOOGLE_MODEL, REQUEST))
        origin = server.origin
        log = server.requests
    assert text == "Hello"
    assert record.adapter is Adapter.GOOGLE
    assert record.stop_reason == "STOP"
    assert record.input_tokens == 11
    assert record.output_tokens == 2
    # The connection recorded for provenance carries no query string at all.
    assert record.connection == f"{origin}{GOOGLE_PATH}"
    assert log[0].path == GOOGLE_PATH
    assert log[0].query == "alt=sse"
    assert log[0].headers["x-goog-api-key"] == SECOND_KEY
    body = decoded_body(log[0].body)
    assert body["contents"] == [
        {"role": "user", "parts": [{"text": "Summarise the spectrum."}]}
    ]
    assert body["systemInstruction"] == {
        "parts": [{"text": "You are a careful research assistant."}]
    }
    assert body["generationConfig"] == {"maxOutputTokens": 256, "temperature": 0.0}


def test_ollama_stream_decodes_ndjson_and_sends_no_credential(tmp_path: Path) -> None:
    with WireServer({OLLAMA_PATH: Route(chunks=OLLAMA_CHUNKS)}) as server:
        client = build_client(tmp_path, server)
        text, record = drain(client.stream(OLLAMA_MODEL, REQUEST))
        log = server.requests
    assert text == "Hello"
    assert record.adapter is Adapter.OLLAMA
    assert record.stop_reason == "stop"
    assert "authorization" not in log[0].headers
    assert "x-api-key" not in log[0].headers
    assert "x-goog-api-key" not in log[0].headers


def test_endpoint_controls_the_max_tokens_field_name(tmp_path: Path) -> None:
    with WireServer({OPENAI_PATH: Route(chunks=OPENAI_CHUNKS)}) as server:
        registry = build_registry(tmp_path, {"openai": CANARY_KEY})
        endpoint = ProviderEndpoint(
            "openai",
            Adapter.OPENAI_COMPATIBLE,
            server.origin,
            OPENAI_PATH,
            max_tokens_field="max_completion_tokens",
        )
        client = ModelCallClient(registry, {"openai": endpoint})
        _ = drain(client.stream(OPENAI_MODEL, REQUEST))
        log = server.requests
    body = decoded_body(log[0].body)
    assert body["max_completion_tokens"] == 256
    assert "max_tokens" not in body


def test_events_carry_their_own_discriminant(tmp_path: Path) -> None:
    with WireServer({OPENAI_PATH: Route(chunks=OPENAI_CHUNKS)}) as server:
        client = build_client(tmp_path, server)
        kinds = [event.kind for event in client.stream(OPENAI_MODEL, REQUEST)]
    assert kinds[-1] is EventKind.COMPLETED
    assert set(kinds[:-1]) == {EventKind.TEXT_DELTA}


# --------------------------------------------------------------------------
# Streaming is incremental, not a buffered body replayed in pieces.
# --------------------------------------------------------------------------


def test_deltas_arrive_before_the_server_finishes_the_body(tmp_path: Path) -> None:
    route = Route(chunks=OPENAI_CHUNKS, gate_after=2, gate_timeout=3.0)
    with WireServer({OPENAI_PATH: route}) as server:
        client = build_client(tmp_path, server)
        events = client.stream(OPENAI_MODEL, REQUEST)
        first = next(events)
        assert isinstance(first, TextDelta)
        assert first.text == "Hel"
        assert route.gate_expired is False
        route.gate.set()
        rest = [event for event in events if isinstance(event, TextDelta)]
    assert [item.text for item in rest] == ["lo"]
    # Had the client buffered the body, the gate would have timed out before
    # this test could ever reach `gate.set()`.
    assert route.gate_expired is False


# --------------------------------------------------------------------------
# Bounds: a hostile or broken endpoint cannot hang or exhaust memory.
# --------------------------------------------------------------------------


def test_mid_stream_disconnect_is_a_transport_failure(tmp_path: Path) -> None:
    route = Route(chunks=OPENAI_CHUNKS, cut_after=2)
    with WireServer({OPENAI_PATH: route}) as server:
        client = build_client(tmp_path, server)
        with pytest.raises(ModelCallError) as caught:
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
        log = server.requests
    error = caught.value
    assert isinstance(error, TransportError)
    assert error.failure is ModelCallFailure.TRANSPORT
    assert len(log) == 1


def test_oversized_body_is_refused_without_reading_it_all(tmp_path: Path) -> None:
    filler = json.dumps({"choices": [{"delta": {"content": "x" * 900}}]})
    route = Route(chunks=sse([filler] * 64))
    with WireServer({OPENAI_PATH: route}) as server:
        client = build_client(tmp_path, server, CallLimits(max_response_bytes=2048))
        with pytest.raises(ResponseTooLargeError) as caught:
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
    error = caught.value
    assert error.failure is ModelCallFailure.RESPONSE_TOO_LARGE
    assert error.turn is not None
    # The server offered roughly 60 KiB. Stopping near the bound is the whole
    # difference between a limit and a comment about a limit.
    assert error.turn.response_bytes < 16 * 1024


def test_unterminated_frame_is_refused_rather_than_buffered(tmp_path: Path) -> None:
    route = Route(chunks=(b"data: " + b"x" * 20000,))
    with WireServer({OPENAI_PATH: route}) as server:
        client = build_client(tmp_path, server, CallLimits(max_frame_bytes=1024))
        with pytest.raises(ResponseTooLargeError) as caught:
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
    assert caught.value.failure is ModelCallFailure.RESPONSE_TOO_LARGE


def test_slow_body_trips_the_socket_timeout(tmp_path: Path) -> None:
    route = Route(chunks=OPENAI_CHUNKS[:3], chunk_delay=0.6)
    limits = CallLimits(socket_timeout_seconds=0.25, total_timeout_seconds=30.0)
    with WireServer({OPENAI_PATH: route}) as server:
        client = build_client(tmp_path, server, limits)
        with pytest.raises(ModelCallTimeoutError) as caught:
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
    assert caught.value.failure is ModelCallFailure.TIMEOUT


def test_total_time_budget_is_enforced_across_a_drip(tmp_path: Path) -> None:
    route = Route(chunks=OPENAI_CHUNKS, chunk_delay=0.15)
    limits = CallLimits(socket_timeout_seconds=5.0, total_timeout_seconds=0.35)
    with WireServer({OPENAI_PATH: route}) as server:
        client = build_client(tmp_path, server, limits)
        with pytest.raises(ModelCallTimeoutError) as caught:
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
    assert caught.value.failure is ModelCallFailure.TIMEOUT


# --------------------------------------------------------------------------
# Classification: every failure is typed, none needs prose parsing.
# --------------------------------------------------------------------------

STATUS_CASES: Final[list[tuple[int, bytes, type[ModelCallError]]]] = [
    (401, error_body(type="authentication_error"), AuthenticationError),
    (401, json_body({}), AuthenticationError),
    (403, json_body({}), AuthenticationError),
    (402, json_body({}), QuotaExhaustedError),
    (404, error_body(code="model_not_found"), ModelUnavailableError),
    (404, json_body({}), ModelUnavailableError),
    (400, error_body(type="invalid_request_error"), InvalidRequestError),
    (429, error_body(type="rate_limit_error"), RateLimitError),
    (429, json_body({}), RateLimitError),
    (429, error_body(code="insufficient_quota"), QuotaExhaustedError),
    (500, json_body({}), ProviderUnavailableError),
    (503, error_body(type="overloaded_error"), ProviderUnavailableError),
    (529, json_body({}), ProviderUnavailableError),
    (504, json_body({}), ModelCallTimeoutError),
    (418, json_body({}), UnclassifiedProviderError),
]


@pytest.mark.parametrize(("status", "payload", "expected"), STATUS_CASES)
def test_error_status_is_classified(
    tmp_path: Path,
    status: int,
    payload: bytes,
    expected: type[ModelCallError],
) -> None:
    route = Route(status=status, body=payload, content_type="application/json")
    with WireServer({OPENAI_PATH: route}) as server:
        client = build_client(tmp_path, server)
        with pytest.raises(ModelCallError) as caught:
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
    error = caught.value
    assert type(error) is expected
    assert error.failure is expected.failure
    assert error.http_status == status
    assert error.provider_id == "openai"
    assert error.model_id == OPENAI_MODEL


def test_structured_code_overrides_the_status_classification(tmp_path: Path) -> None:
    # A 429 normally means throttling. `insufficient_quota` means the allowance
    # is gone, which is a different thing to tell the researcher.
    route = Route(
        status=429,
        body=error_body(code="insufficient_quota"),
        content_type="application/json",
    )
    with WireServer({OPENAI_PATH: route}) as server:
        client = build_client(tmp_path, server)
        with pytest.raises(QuotaExhaustedError) as caught:
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
    assert caught.value.provider_code == "insufficient_quota"


def test_unknown_structured_code_is_discarded_not_stored(tmp_path: Path) -> None:
    route = Route(
        status=500,
        body=error_body(code="some_code_this_build_never_heard_of"),
        content_type="application/json",
    )
    with WireServer({OPENAI_PATH: route}) as server:
        client = build_client(tmp_path, server)
        with pytest.raises(ProviderUnavailableError) as caught:
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
    assert caught.value.provider_code is None


def test_inband_error_frame_is_classified(tmp_path: Path) -> None:
    route = Route(chunks=sse([json.dumps({"error": {"type": "rate_limit_error"}})]))
    with WireServer({OPENAI_PATH: route}) as server:
        client = build_client(tmp_path, server)
        with pytest.raises(RateLimitError) as caught:
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
    error = caught.value
    assert error.failure is ModelCallFailure.RATE_LIMIT
    assert error.provider_code == "rate_limit_error"
    assert error.http_status is None


def test_minimax_style_base_resp_failure_is_surfaced(tmp_path: Path) -> None:
    # MiniMax answers HTTP 200 and reports the real outcome inside `base_resp`.
    # The numeric codes are absent from the reference this build was written
    # against, so the failure surfaces as unclassified rather than guessed at.
    payload = json.dumps({"base_resp": {"status_code": 1004, "status_msg": "auth"}})
    with WireServer({OPENAI_PATH: Route(chunks=sse([payload]))}) as server:
        client = build_client(tmp_path, server)
        with pytest.raises(UnclassifiedProviderError) as caught:
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
    assert caught.value.failure is ModelCallFailure.UNCLASSIFIED
    assert caught.value.provider_code is None


def test_minimax_style_base_resp_zero_is_not_a_failure(tmp_path: Path) -> None:
    chunks = sse(
        [
            json.dumps(
                {
                    "base_resp": {"status_code": 0, "status_msg": ""},
                    "choices": [{"delta": {"content": "ok"}, "finish_reason": "stop"}],
                }
            ),
            "[DONE]",
        ]
    )
    with WireServer({OPENAI_PATH: Route(chunks=chunks)}) as server:
        client = build_client(tmp_path, server)
        text, _ = drain(client.stream(OPENAI_MODEL, REQUEST))
    assert text == "ok"


def test_anthropic_error_event_is_classified(tmp_path: Path) -> None:
    chunks = named_sse(
        [
            (
                "error",
                json.dumps({"type": "error", "error": {"type": "overloaded_error"}}),
            )
        ]
    )
    with WireServer({ANTHROPIC_PATH: Route(chunks=chunks)}) as server:
        client = build_client(tmp_path, server)
        with pytest.raises(ProviderUnavailableError) as caught:
            _ = drain(client.stream(ANTHROPIC_MODEL, REQUEST))
    assert caught.value.provider_code == "overloaded_error"


def test_google_inband_error_is_classified(tmp_path: Path) -> None:
    payload = json.dumps({"error": {"status": "RESOURCE_EXHAUSTED", "code": 429}})
    with WireServer({GOOGLE_PATH: Route(chunks=sse([payload]))}) as server:
        client = build_client(tmp_path, server)
        with pytest.raises(RateLimitError) as caught:
            _ = drain(client.stream(GOOGLE_MODEL, REQUEST))
    assert caught.value.provider_code == "RESOURCE_EXHAUSTED"


def test_ollama_inband_error_is_surfaced(tmp_path: Path) -> None:
    payload = json.dumps({"error": "model not loaded"})
    with WireServer({OLLAMA_PATH: Route(chunks=ndjson([payload]))}) as server:
        client = build_client(tmp_path, server)
        with pytest.raises(UnclassifiedProviderError) as caught:
            _ = drain(client.stream(OLLAMA_MODEL, REQUEST))
    assert caught.value.failure is ModelCallFailure.UNCLASSIFIED


def test_non_json_frame_is_malformed(tmp_path: Path) -> None:
    with WireServer({OPENAI_PATH: Route(chunks=sse(["not json at all"]))}) as server:
        client = build_client(tmp_path, server)
        with pytest.raises(MalformedResponseError) as caught:
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
    assert caught.value.failure is ModelCallFailure.MALFORMED_RESPONSE


def test_stream_without_a_terminal_frame_is_not_a_success(tmp_path: Path) -> None:
    # Everything but `[DONE]`. A truncated answer must never be handed back as
    # a complete one just because the socket closed politely.
    with WireServer({OPENAI_PATH: Route(chunks=OPENAI_CHUNKS[:-1])}) as server:
        client = build_client(tmp_path, server)
        with pytest.raises(TransportError) as caught:
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
    assert caught.value.failure is ModelCallFailure.TRANSPORT


def test_failed_event_precedes_the_raised_error(tmp_path: Path) -> None:
    route = Route(
        status=401,
        body=error_body(type="authentication_error"),
        content_type="application/json",
    )
    seen: list[ModelEvent] = []
    with WireServer({OPENAI_PATH: route}) as server:
        client = build_client(tmp_path, server)
        events = client.stream(OPENAI_MODEL, REQUEST)
        with pytest.raises(AuthenticationError) as caught:
            seen.extend(events)
    terminal = seen[-1]
    assert isinstance(terminal, Failed)
    assert terminal.error is caught.value
    assert terminal.turn.request_count == 1
    assert caught.value.turn is not None
    assert caught.value.turn.provider_id == "openai"


# --------------------------------------------------------------------------
# No automatic fallback. This is a spec rule, not a preference.
# --------------------------------------------------------------------------


def fallback_server(failing: Route) -> WireServer:
    """Serve a failing OpenAI route beside three providers that would succeed."""
    return WireServer(
        {
            OPENAI_PATH: failing,
            ANTHROPIC_PATH: Route(chunks=ANTHROPIC_CHUNKS),
            GOOGLE_PATH: Route(chunks=GOOGLE_CHUNKS),
            OLLAMA_PATH: Route(chunks=OLLAMA_CHUNKS),
        }
    )


FAILING_ROUTES: Final[list[Route]] = [
    Route(
        status=401,
        body=error_body(type="authentication_error"),
        content_type="application/json",
    ),
    Route(
        status=429,
        body=error_body(type="rate_limit_error"),
        content_type="application/json",
    ),
    Route(status=402, body=json_body({}), content_type="application/json"),
    Route(status=500, body=json_body({}), content_type="application/json"),
    Route(chunks=OPENAI_CHUNKS, cut_after=1),
    Route(chunks=sse(["not json at all"])),
    Route(chunks=sse([json.dumps({"error": {"type": "rate_limit_error"}})])),
]


@pytest.mark.parametrize("failing", FAILING_ROUTES)
def test_a_failing_provider_contacts_no_other_provider(
    tmp_path: Path,
    failing: Route,
) -> None:
    with fallback_server(failing) as server:
        client = build_client(tmp_path, server)
        with pytest.raises(ModelCallError) as caught:
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
        origin = server.origin
        log = server.requests
    # One request, to the selected provider, and to nothing else. Anthropic,
    # Google, and Ollama were all reachable and all would have succeeded.
    assert len(log) == 1
    assert log[0].path == OPENAI_PATH
    assert {entry.path for entry in log} == {OPENAI_PATH}
    assert caught.value.provider_id == "openai"
    assert caught.value.turn is not None
    assert caught.value.turn.request_count == 1
    assert caught.value.turn.connection == f"{origin}{OPENAI_PATH}"


def test_a_provider_without_a_credential_contacts_nobody(tmp_path: Path) -> None:
    with fallback_server(Route(chunks=OPENAI_CHUNKS)) as server:
        registry = build_registry(tmp_path, {"anthropic": SECOND_KEY})
        client = ModelCallClient(registry, endpoints_for(server.origin))
        with pytest.raises(AuthenticationError) as caught:
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
        log = server.requests
    assert log == ()
    assert caught.value.failure is ModelCallFailure.AUTHENTICATION
    assert caught.value.http_status is None


def test_an_unconfigured_provider_is_detected_without_decrypting(
    tmp_path: Path,
) -> None:
    backend = RecordingBackend()
    registry = ProviderRegistry(LocalPaths(root=tmp_path), backend, {})
    registry.set_key("anthropic", SECOND_KEY)
    with fallback_server(Route(chunks=OPENAI_CHUNKS)) as server:
        client = ModelCallClient(registry, endpoints_for(server.origin))
        with pytest.raises(AuthenticationError):
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
        log = server.requests
    assert log == ()
    # Status came from `has`, not from a decrypt, and no other provider's
    # credential was touched on the way to the refusal.
    assert "openai" not in backend.reads


def test_a_refused_connection_leaves_no_credential_in_any_frame(
    tmp_path: Path,
) -> None:
    with WireServer({OPENAI_PATH: Route(chunks=OPENAI_CHUNKS)}) as server:
        origin = server.origin
    # The port now refuses connections, so the failure is raised from inside
    # the one frame that ever holds the key -- the only place a traceback
    # renderer could have captured it.
    client = client_for(tmp_path, origin, CallLimits(socket_timeout_seconds=2.0))
    with pytest.raises(TransportError) as caught:
        _ = drain(client.stream(OPENAI_MODEL, REQUEST))
    error = caught.value
    assert error.failure is ModelCallFailure.TRANSPORT
    assert error.turn is not None
    assert error.turn.request_count == 0
    assert CANARY_KEY not in str(error)
    assert CANARY_KEY not in repr(error)
    assert all(CANARY_KEY not in item for item in module_frame_locals(error))


def test_an_authentication_failure_never_retries_unauthenticated(
    tmp_path: Path,
) -> None:
    route = Route(
        status=401,
        body=error_body(type="authentication_error"),
        content_type="application/json",
    )
    with WireServer({OPENAI_PATH: route}) as server:
        client = build_client(tmp_path, server)
        with pytest.raises(AuthenticationError):
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
        log = server.requests
    assert len(log) == 1
    assert "authorization" in log[0].headers


# --------------------------------------------------------------------------
# The credential never leaks.
# --------------------------------------------------------------------------


def safe_repr(value: object) -> str:
    """Render any local for inspection, tolerating a hostile `__repr__`."""
    try:
        return repr(value)
    except Exception:  # noqa: BLE001 - a broken repr must not fail the audit
        return f"<unrepresentable {type(value).__name__}>"


def module_frame_locals(error: BaseException) -> list[str]:
    """Collect the locals of every `modelcall` frame this error can reach.

    Frames belonging to this test file are excluded deliberately: the test's
    own locals hold the canary by construction, and the claim under audit is
    that *the module's* frames do not. `__cause__` and `__context__` are walked
    too, because a chained exception keeps its own frames alive.
    """
    from nipo_local import modelcall  # noqa: PLC0415 - imported for its filename

    rendered: list[str] = []
    seen: set[int] = set()
    pending: list[BaseException | None] = [error]
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        pending.extend([current.__cause__, current.__context__])
        frames = current.__traceback__
        while frames is not None:
            frame = frames.tb_frame
            if frame.f_code.co_filename == modelcall.__file__:
                values = cast("Mapping[str, object]", frame.f_locals)
                rendered.extend(safe_repr(value) for value in values.values())
            frames = frames.tb_next
    return rendered


def test_the_key_reaches_the_header_and_nothing_else(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with WireServer({OPENAI_PATH: Route(chunks=OPENAI_CHUNKS)}) as server:
        client = build_client(tmp_path, server)
        with caplog.at_level(logging.DEBUG):
            text, record = drain(client.stream(OPENAI_MODEL, REQUEST))
        log = server.requests
    assert text == "Hello"
    # Present exactly where it belongs.
    assert log[0].headers["authorization"] == f"Bearer {CANARY_KEY}"
    # Absent everywhere else on the wire.
    assert CANARY_KEY not in log[0].target
    assert CANARY_KEY not in log[0].path
    assert CANARY_KEY not in log[0].query
    assert CANARY_KEY not in log[0].body.decode("utf-8")
    # Absent from every durable or observable surface this module offers.
    assert CANARY_KEY not in repr(record)
    assert CANARY_KEY not in str(record)
    assert CANARY_KEY not in repr(client)
    assert CANARY_KEY not in caplog.text
    assert all(CANARY_KEY not in item.getMessage() for item in caplog.records)


LEAK_ROUTES: Final[list[Route]] = [
    Route(
        status=401,
        body=error_body(type="authentication_error"),
        content_type="application/json",
    ),
    Route(chunks=OPENAI_CHUNKS, cut_after=1),
    Route(chunks=sse(["not json at all"])),
    Route(chunks=OPENAI_CHUNKS[:-1]),
]


@pytest.mark.parametrize("route", LEAK_ROUTES)
def test_the_key_never_reaches_an_error_or_a_traceback(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    route: Route,
) -> None:
    with WireServer({OPENAI_PATH: route}) as server:
        client = build_client(tmp_path, server)
        with caplog.at_level(logging.DEBUG), pytest.raises(ModelCallError) as caught:
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
        log = server.requests
    error = caught.value
    assert CANARY_KEY not in str(error)
    assert CANARY_KEY not in repr(error)
    arguments = cast("tuple[object, ...]", error.args)
    assert all(CANARY_KEY not in safe_repr(item) for item in arguments)
    assert CANARY_KEY not in safe_repr(error.turn)
    assert CANARY_KEY not in caplog.text
    assert all(CANARY_KEY not in item for item in module_frame_locals(error))
    assert all(CANARY_KEY not in entry.target for entry in log)


def test_a_provider_echoing_the_key_back_cannot_republish_it(tmp_path: Path) -> None:
    # A hostile or merely careless endpoint that reflects the credential into
    # its own error body must not get it into anything this module renders.
    route = Route(
        status=401,
        body=error_body(
            type=CANARY_KEY, code=CANARY_KEY, message=f"bad key {CANARY_KEY}"
        ),
        content_type="application/json",
    )
    with WireServer({OPENAI_PATH: route}) as server:
        client = build_client(tmp_path, server)
        with pytest.raises(AuthenticationError) as caught:
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
    error = caught.value
    assert error.provider_code is None
    assert CANARY_KEY not in str(error)
    assert CANARY_KEY not in repr(error)
    assert all(CANARY_KEY not in item for item in module_frame_locals(error))


def test_a_provider_echoing_the_key_mid_stream_cannot_republish_it(
    tmp_path: Path,
) -> None:
    payload = json.dumps({"error": {"type": CANARY_KEY, "message": CANARY_KEY}})
    with WireServer({OPENAI_PATH: Route(chunks=sse([payload]))}) as server:
        client = build_client(tmp_path, server)
        with pytest.raises(UnclassifiedProviderError) as caught:
            _ = drain(client.stream(OPENAI_MODEL, REQUEST))
    error = caught.value
    assert error.provider_code is None
    assert CANARY_KEY not in str(error)
    assert all(CANARY_KEY not in item for item in module_frame_locals(error))


def test_every_default_adapter_puts_the_key_in_a_header_not_a_url() -> None:
    for endpoint in DEFAULT_ENDPOINTS.values():
        adapter = adapter_for(endpoint)
        target = adapter.request_path(endpoint, "some-model-name")
        headers = adapter.headers(CANARY_KEY)
        assert CANARY_KEY not in target
        assert CANARY_KEY not in endpoint.origin
        assert CANARY_KEY not in endpoint.stream_query
        if endpoint.provider_id == "ollama":
            assert all(CANARY_KEY not in value for value in headers.values())
        else:
            assert any(CANARY_KEY in value for value in headers.values())


# --------------------------------------------------------------------------
# Configuration is refused before anything reaches the wire.
# --------------------------------------------------------------------------


def test_plaintext_http_off_loopback_is_refused() -> None:
    with pytest.raises(EndpointConfigurationError):
        _ = ProviderEndpoint(
            "openai",
            Adapter.OPENAI_COMPATIBLE,
            "http://api.openai.com",
            "/v1/chat/completions",
        )


def test_plaintext_http_on_loopback_is_allowed() -> None:
    endpoint = ProviderEndpoint(
        "ollama", Adapter.OLLAMA, "http://127.0.0.1:11434", "/api/chat"
    )
    assert endpoint.address() == ("http", "127.0.0.1", 11434)


def test_an_origin_carrying_a_path_is_refused() -> None:
    with pytest.raises(EndpointConfigurationError):
        _ = ProviderEndpoint(
            "openai", Adapter.OPENAI_COMPATIBLE, "https://api.openai.com/v1", "/x"
        )


BAD_MODEL_NAMES: Final[list[str]] = [
    "openai:../../secret",
    "openai:model?key=leak",
    "openai:model with space",
    "openai:model#frag",
    "openai:evil.example.com\\x",
]


@pytest.mark.parametrize("model_id", BAD_MODEL_NAMES)
def test_an_unsafe_model_name_never_reaches_the_wire(
    tmp_path: Path,
    model_id: str,
) -> None:
    with WireServer({OPENAI_PATH: Route(chunks=OPENAI_CHUNKS)}) as server:
        client = build_client(tmp_path, server)
        with pytest.raises(InvalidRequestError):
            _ = drain(client.stream(model_id, REQUEST))
        log = server.requests
    assert log == ()


BAD_REQUESTS: Final[list[ModelRequest]] = [
    ModelRequest(messages=(), max_output_tokens=16),
    ModelRequest(messages=(Message(role="user", content="hi"),), max_output_tokens=0),
    ModelRequest(messages=(Message(role="root", content="hi"),), max_output_tokens=16),
]


@pytest.mark.parametrize("candidate", BAD_REQUESTS)
def test_an_impossible_request_never_reaches_the_wire(
    tmp_path: Path,
    candidate: ModelRequest,
) -> None:
    with WireServer({OPENAI_PATH: Route(chunks=OPENAI_CHUNKS)}) as server:
        client = build_client(tmp_path, server)
        with pytest.raises(InvalidRequestError):
            _ = drain(client.stream(OPENAI_MODEL, candidate))
        log = server.requests
    assert log == ()


def test_default_endpoints_cover_every_registry_provider() -> None:
    assert set(DEFAULT_ENDPOINTS) == {spec.provider_id for spec in PROVIDERS}
    for provider_id, endpoint in DEFAULT_ENDPOINTS.items():
        assert endpoint.provider_id == provider_id
        assert endpoint.path.startswith("/")
        assert endpoint.stream_query in {"", "alt=sse"}
        scheme, _, _ = endpoint.address()
        assert scheme == ("http" if provider_id == "ollama" else "https")


def test_a_closed_stream_stops_without_a_completion(tmp_path: Path) -> None:
    route = Route(chunks=OPENAI_CHUNKS, gate_after=3, gate_timeout=1.0)
    with WireServer({OPENAI_PATH: route}) as server:
        client = build_client(tmp_path, server)
        events = cast(
            "Generator[ModelEvent, None, None]",
            client.stream(OPENAI_MODEL, REQUEST),
        )
        first = next(events)
        events.close()
        route.gate.set()
        log = server.requests
    assert isinstance(first, TextDelta)
    assert list(events) == []
    assert len(log) == 1
