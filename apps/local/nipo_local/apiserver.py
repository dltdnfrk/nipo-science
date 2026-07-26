"""Loopback-only socket binding and a minimal ASGI HTTP/1.1 server.

SPEC-v0.5 section 2 and LS01 forbid this application from binding any
interface other than loopback, and forbid a configuration value that would
enable remote access. Both are enforced here rather than documented:

* :func:`require_loopback` accepts only the literal token `localhost` and IP
  literals for which :mod:`ipaddress` reports `is_loopback`. A host name is
  never resolved, so no DNS answer can widen the bind, and there is no flag,
  environment variable, or keyword anywhere in this module that reaches a
  non-loopback address.
* :func:`bind_loopback` re-reads `getsockname()` **after** the bind and closes
  the socket if the kernel reports anything but a loopback address. The claim
  is therefore a property of a real socket, not of the argument that produced
  it. IPv6 listeners set `IPV6_V6ONLY`, so binding `::1` can never accidentally
  accept on an IPv4 wildcard.

The repository depends on FastAPI but on no ASGI server, so this module also
carries the smallest HTTP/1.1 server that can drive one honestly. It is
deliberately unambitious: one request per connection, `Connection: close`,
bounded header and *request* body sizes, and no access log -- a local session
credential travels in a request header, and the cheapest way to guarantee it is
never logged is to have no log.

The response body is written as it arrives, not collected
---------------------------------------------------------
An Export Pack the non-functional budget sizes at up to 500 MiB is produced by
`exportrun.stream_pack` in bounded chunks on a worker thread. That was worth
nothing while this server folded every `http.response.body` event into one
`bytearray` and wrote the socket once: the whole pack was held in this process
regardless of how carefully it was read. :class:`_Wire` writes each chunk to
the socket as the application emits it and awaits `drain()` in between, so the
bytes in flight are bounded by the transport's own high-water mark rather than
by the size of the response.

Framing is decided once, at `http.response.start`, from what the application
declared -- never guessed part way through a body:

* **A declared `content-length` is used as the framing.** Every response this
  application produces declares one, including the pack: `Response` sets it,
  and :class:`~nipo_local.api._PackResponse` states the `stat` size it is about
  to send. It is the framing to prefer, because it is the only one that tells a
  browser how long a 500 MiB download will take, and because a client that
  receives fewer bytes than were promised sees a truncated transfer rather than
  a plausible short file. More is never sent than was declared.
* **Otherwise the response is chunked.** Connection-close framing would also
  work here -- this server closes after every response anyway -- but it is
  indistinguishable from a connection that died half way through, which for a
  research artefact is the worst possible failure: a partial pack that looks
  complete. Chunked transfer coding is self-delimiting, so a truncated response
  is missing its terminator and is refused by the client.
* **A response that may not carry content is neither.** `HEAD`, `204`, `304`,
  and `1xx` send headers and stop. A `HEAD` and a `304` still report the length
  the same `GET` would have sent -- for `HEAD` that is the entire point of the
  method -- while a `204` and a `1xx` declare nothing at all, which is what
  RFC 9112 section 6.2 requires of them.

A client that disappears mid-body makes `drain()` raise, which propagates
through `send` into the application exactly as ASGI intends, unwinds the
producer, and leaves this connection to be closed in the `finally` that closes
every connection. Nothing is retried and nothing is buffered on its behalf.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import threading
from contextlib import suppress
from dataclasses import dataclass
from http import HTTPStatus
from typing import TYPE_CHECKING, Final, cast, final
from urllib.parse import unquote

if TYPE_CHECKING:
    from collections.abc import Iterable

    from starlette.types import ASGIApp, Message, Scope

LOOPBACK_HOST: Final = "127.0.0.1"
"""The only host this application ever offers to bind."""

LOCALHOST_TOKEN: Final = "localhost"  # noqa: S105 - a host name, not a secret

IPV6_VERSION: Final = 6
LISTEN_BACKLOG: Final = 16
PRINTABLE_ASCII: Final = range(0x21, 0x7F)
REQUEST_LINE_PARTS: Final = 3

MAX_HEADER_BYTES: Final = 16 * 1024
MAX_BODY_BYTES: Final = 8 * 1024 * 1024
# `HTTPStatus.REQUEST_ENTITY_TOO_LARGE` was renamed in a later Python; the
# numeric status is the stable spelling across the versions this repo supports.
TOO_LARGE: Final = HTTPStatus(413)
READ_TIMEOUT_SECONDS: Final = 15.0
SHUTDOWN_TIMEOUT_SECONDS: Final = 5.0

_HOP_BY_HOP: Final = frozenset({b"content-length", b"transfer-encoding", b"connection"})

_LOWEST_CONTENT_STATUS: Final = 200
"""Below this a response is informational and carries no content at all."""

_NO_CONTENT: Final = 204
"""The one success status RFC 9112 forbids a `content-length` on entirely."""

_NOT_MODIFIED: Final = 304
"""Carries no content, but reports the length the same `GET` would have."""

_NON_LOOPBACK_MESSAGE: Final = "refusing to bind a non-loopback address"
_BOUND_NON_LOOPBACK_MESSAGE: Final = "kernel reported a non-loopback bound address"
_NOT_RUNNING_MESSAGE: Final = "server is not running"


@final
class NonLoopbackBindError(ValueError):
    """Reject a requested listener that is not on the loopback interface."""


def require_loopback(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Return the loopback address one host string denotes, or raise.

    Args:
        host: `localhost` or an IP literal. Host names are never resolved:
            a resolver answer is attacker-influenceable input, and accepting
            one would make the binding claim depend on DNS.

    Returns:
        The parsed loopback address.

    Raises:
        NonLoopbackBindError: The host is a name other than `localhost`, is
            not a valid IP literal, or is a literal that is not loopback --
            which covers every wildcard and every routable address.
    """
    literal = LOOPBACK_HOST if host == LOCALHOST_TOKEN else host
    try:
        address = ipaddress.ip_address(literal)
    except ValueError as error:
        raise NonLoopbackBindError(_NON_LOOPBACK_MESSAGE) from error
    if not address.is_loopback:
        raise NonLoopbackBindError(_NON_LOOPBACK_MESSAGE)
    return address


def bind_loopback(host: str = LOOPBACK_HOST, port: int = 0) -> socket.socket:
    """Bind and listen on loopback, verifying the bound address after the fact.

    Args:
        host: `localhost` or a loopback IP literal.
        port: The TCP port, or 0 for a kernel-assigned ephemeral port.

    Returns:
        A listening socket whose `getsockname()` the kernel confirms is a
        loopback address.

    Raises:
        NonLoopbackBindError: The requested host is not loopback, or the
            kernel bound something that is not. The socket is closed first,
            so a rejected bind leaves no listener behind.
    """
    address = require_loopback(host)
    family = socket.AF_INET6 if address.version == IPV6_VERSION else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind((str(address), port))
        listener.listen(LISTEN_BACKLOG)
        bound = cast("tuple[object, ...]", listener.getsockname())
    except BaseException:
        listener.close()
        raise
    if not _is_loopback_name(bound):
        listener.close()
        raise NonLoopbackBindError(_BOUND_NON_LOOPBACK_MESSAGE)
    return listener


def _is_loopback_name(bound: tuple[object, ...]) -> bool:
    """Report whether a `getsockname()` result is a loopback address."""
    if not bound or not isinstance(bound[0], str):
        return False
    try:
        return ipaddress.ip_address(bound[0]).is_loopback
    except ValueError:
        return False


def loopback_origins(port: int) -> frozenset[str]:
    """Return every browser origin a page served by this listener can carry."""
    return frozenset(
        {
            f"http://{LOOPBACK_HOST}:{port}",
            f"http://{LOCALHOST_TOKEN}:{port}",
            f"http://[::1]:{port}",
        }
    )


def loopback_authorities(port: int) -> frozenset[str]:
    """Return every `Host` header value this listener will answer.

    A loopback server is the classic DNS-rebinding target: an attacker points
    a name they control at `127.0.0.1`, so the page is *same-origin* with the
    server and `Origin` checks alone pass. Pinning the authority closes it.
    """
    return frozenset(
        {
            f"{LOOPBACK_HOST}:{port}",
            f"{LOCALHOST_TOKEN}:{port}",
            f"[::1]:{port}",
        }
    )


@final
@dataclass(frozen=True, slots=True)
class _Head:
    """One parsed request line plus its headers."""

    method: str
    raw_path: bytes
    query: bytes
    headers: tuple[tuple[bytes, bytes], ...]

    def first(self, name: bytes) -> bytes | None:
        """Return the first value of one header, or None."""
        for header, value in self.headers:
            if header == name:
                return value
        return None

    def count(self, name: bytes) -> int:
        """Return how many times one header appears."""
        return sum(1 for header, _ in self.headers if header == name)


def _parse_head(head: bytes) -> _Head | None:
    """Parse a complete request head, refusing anything ambiguous."""
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ")
    if len(parts) != REQUEST_LINE_PARTS or not parts[2].startswith(b"HTTP/1."):
        return None
    target = parts[1]
    if any(byte not in PRINTABLE_ASCII for byte in target):
        return None
    raw_path, _, query = target.partition(b"?")
    headers: list[tuple[bytes, bytes]] = []
    for line in lines[1:]:
        if not line:
            continue
        name, separator, value = line.partition(b":")
        if not separator or name != name.strip():
            return None
        headers.append((name.lower(), value.strip()))
    try:
        method = parts[0].decode("ascii")
    except UnicodeDecodeError:
        return None
    return _Head(method, raw_path, query, tuple(headers))


def _body_length(head: _Head) -> int | None:
    """Return the declared body length, or None when the request is refused."""
    if head.first(b"transfer-encoding") is not None:
        return None
    if head.count(b"content-length") > 1:
        return None
    declared = head.first(b"content-length")
    if declared is None:
        return 0
    if not declared.isdigit():
        return None
    length = int(declared)
    return None if length > MAX_BODY_BYTES else length


def _scope_for(head: _Head, body_length: int, server: tuple[str, int]) -> Scope:
    """Build the ASGI scope for one parsed request."""
    _ = body_length
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": head.method,
        "scheme": "http",
        "path": unquote(head.raw_path.decode("ascii"), errors="replace"),
        "raw_path": head.raw_path,
        "query_string": head.query,
        "root_path": "",
        "headers": list(head.headers),
        "client": (LOOPBACK_HOST, 0),
        "server": server,
        "state": {},
    }


def _head_block(
    status: int,
    headers: Iterable[tuple[bytes, bytes]],
    framing: bytes,
) -> bytes:
    """Serialize one status line and its headers under one framing header.

    Every hop-by-hop header the application offered is dropped and replaced:
    the framing is this server's decision, because this server is what writes
    the socket, and an application that declared a length this connection is
    not going to honour must not be able to say so on the wire. An empty
    `framing` adds no header at all, which is the only conformant answer for a
    `1xx` or a `204`.
    """
    try:
        phrase = HTTPStatus(status).phrase
    except ValueError:
        phrase = "Unknown"
    lines = [f"HTTP/1.1 {status} {phrase}".encode("ascii", "replace")]
    lines.extend(
        b"%s: %s" % (name, value)
        for name, value in headers
        if name.lower() not in _HOP_BY_HOP
    )
    if framing:
        lines.append(framing)
    lines.append(b"connection: close")
    return b"\r\n".join(lines) + b"\r\n\r\n"


def _render(status: int, headers: Iterable[tuple[bytes, bytes]], body: bytes) -> bytes:
    """Serialize one whole response with a server-computed content length.

    Only for the transport's own refusals, whose bodies are a few dozen bytes
    of closed error code. An application response is never rendered this way --
    see :class:`_Wire`.
    """
    return _head_block(status, headers, b"content-length: %d" % len(body)) + body


def _declared_length(headers: Iterable[tuple[bytes, bytes]]) -> int | None:
    """Return the content length an application stated, or None for unstated.

    A value that is not a plain decimal count is treated as unstated rather
    than repaired: this server then frames the response itself, which is safe,
    instead of promising a length it has no reason to believe.
    """
    for name, value in headers:
        if name.lower() == b"content-length":
            text = value.strip()
            return int(text) if text.isdigit() else None
    return None


def _forbids_content(status: int) -> bool:
    """Report whether this status may not even declare a length."""
    return status < _LOWEST_CONTENT_STATUS or status == _NO_CONTENT


def _carries_no_content(method: str, status: int) -> bool:
    """Report whether this exchange may not carry response content at all."""
    return _forbids_content(status) or method == "HEAD" or status == _NOT_MODIFIED


@final
class _Wire:
    """Write one ASGI response to the socket as its events arrive.

    The whole point of this class is that it never holds a body. It decides
    the framing from the first event, writes the head, and from then on every
    `http.response.body` event becomes a socket write followed by a `drain()`.
    `drain()` is what makes this real: without it `write` only appends to an
    unbounded transport buffer, and a 500 MiB pack would be held whole in this
    process again, one layer lower down.
    """

    def __init__(self, writer: asyncio.StreamWriter, method: str) -> None:
        """Bind the wire to one connection and the method that opened it."""
        self._writer = writer
        self._method = method
        self._silent = False
        self._chunked = False
        self._remaining = 0
        self.started = False
        self.ended = False

    async def absorb(self, message: Message) -> None:
        """Put one ASGI response event on the wire."""
        kind = message.get("type")
        if kind == "http.response.start" and not self.started:
            await self._begin(message)
        elif kind == "http.response.body" and self.started and not self.ended:
            await self._continue(message)

    async def _begin(self, message: Message) -> None:
        """Choose this response's framing and write its head."""
        self.started = True
        status = cast("int", message.get("status", HTTPStatus.INTERNAL_SERVER_ERROR))
        headers = list(
            cast("Iterable[tuple[bytes, bytes]]", message.get("headers", []))
        )
        declared = _declared_length(headers)
        if _forbids_content(status):
            # RFC 9112 section 6.2 forbids a `content-length` on a `1xx` or a
            # `204` outright, and there is no body to frame either way.
            self._silent = True
            framing = b""
        elif _carries_no_content(self._method, status):
            # `HEAD` and `304` still report the length the same `GET` would
            # have sent -- for `HEAD` that is the whole answer the method
            # exists to give -- and neither writes a byte of content.
            self._silent = True
            framing = b"" if declared is None else b"content-length: %d" % declared
        elif declared is None:
            self._chunked = True
            framing = b"transfer-encoding: chunked"
        else:
            self._remaining = declared
            framing = b"content-length: %d" % declared
        self._writer.write(_head_block(status, headers, framing))
        await self._writer.drain()

    async def _continue(self, message: Message) -> None:
        """Write one body event, and close the framing when it is the last."""
        chunk = cast("bytes", message.get("body", b""))
        if chunk and not self._silent:
            await self._write(chunk)
        if not cast("bool", message.get("more_body", False)):
            await self.end()

    async def _write(self, chunk: bytes) -> None:
        """Write one body chunk under whichever framing was chosen."""
        if self._chunked:
            self._writer.writelines((b"%x\r\n" % len(chunk), chunk, b"\r\n"))
        else:
            # Never more than was promised. An application that overruns its
            # own `content-length` would otherwise put bytes on the wire that
            # the client has already stopped counting.
            chunk = chunk[: self._remaining]
            if not chunk:
                return
            self._remaining -= len(chunk)
            self._writer.write(chunk)
        await self._writer.drain()

    async def end(self) -> None:
        """Terminate the framing, if this response has one left to terminate."""
        if self.ended:
            return
        self.ended = True
        if self._chunked:
            self._writer.write(b"0\r\n\r\n")
            await self._writer.drain()


def _refusal(status: HTTPStatus, code: str) -> bytes:
    """Serialize a transport-level refusal that never quotes the request."""
    body = b'{"error":"%s"}' % code.encode("ascii")
    return _render(int(status), [(b"content-type", b"application/json")], body)


def _internal_refusal() -> bytes:
    """Serialize the one refusal an application failure is ever answered with."""
    return _refusal(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error")


@final
class LoopbackServer:
    """Serve one ASGI application on an already-bound loopback socket."""

    def __init__(self, app: ASGIApp, listener: socket.socket) -> None:
        """Bind the application to a listening socket this server will own.

        Args:
            app: The ASGI application to drive.
            listener: A socket from :func:`bind_loopback`. Its bound address
                is re-verified here, so a socket obtained any other way still
                cannot make this server listen off loopback.

        Raises:
            NonLoopbackBindError: The socket is not bound to loopback.
        """
        bound = cast("tuple[object, ...]", listener.getsockname())
        if not _is_loopback_name(bound):
            listener.close()
            raise NonLoopbackBindError(_BOUND_NON_LOOPBACK_MESSAGE)
        self._app = app
        self._socket = listener
        self._host = cast("str", bound[0])
        self._port = cast("int", bound[1])
        self._ready = threading.Event()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._closing: asyncio.Event | None = None

    @property
    def host(self) -> str:
        """Return the loopback address the kernel actually bound."""
        return self._host

    @property
    def port(self) -> int:
        """Return the TCP port the kernel actually bound."""
        return self._port

    @property
    def socket(self) -> socket.socket:
        """Return the listening socket, so a caller can assert on it."""
        return self._socket

    @property
    def base_url(self) -> str:
        """Return the only URL a local front end should use."""
        return f"http://{LOOPBACK_HOST}:{self._port}"

    def start(self) -> None:
        """Start serving on a daemon thread and wait until the loop accepts."""
        thread = threading.Thread(target=self._run, name="nipo-local-api", daemon=True)
        self._thread = thread
        thread.start()
        if not self._ready.wait(timeout=SHUTDOWN_TIMEOUT_SECONDS):
            raise RuntimeError(_NOT_RUNNING_MESSAGE)

    def stop(self) -> None:
        """Stop serving and close the listening socket."""
        loop = self._loop
        closing = self._closing
        if loop is not None and closing is not None:
            with suppress(RuntimeError):
                _ = loop.call_soon_threadsafe(closing.set)
        thread = self._thread
        if thread is not None:
            thread.join(timeout=SHUTDOWN_TIMEOUT_SECONDS)
        self._socket.close()
        self._thread = None

    def __enter__(self) -> LoopbackServer:
        """Start the server for a scoped local session."""
        self.start()
        return self

    def __exit__(self, *_details: object) -> None:
        """Stop the server."""
        self.stop()

    def _run(self) -> None:
        """Own one event loop for the lifetime of this server."""
        asyncio.run(self._serve())

    async def _serve(self) -> None:
        """Accept connections until `stop` releases the closing event."""
        self._loop = asyncio.get_running_loop()
        self._closing = asyncio.Event()
        server = await asyncio.start_server(
            self._handle,
            sock=self._socket,
            limit=MAX_HEADER_BYTES,
        )
        async with server:
            self._ready.set()
            _ = await self._closing.wait()

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Answer exactly one request on one connection, then close it."""
        try:
            await self._answer(reader, writer)
            await writer.drain()
        except (OSError, asyncio.IncompleteReadError, TimeoutError):
            pass
        finally:
            writer.close()
            with suppress(OSError, asyncio.IncompleteReadError, TimeoutError):
                await writer.wait_closed()

    async def _answer(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Read one request and write its response to the connection.

        The read is under a timeout and the application is not: a producer
        streaming half a gigabyte off a slow disk is doing exactly what it was
        asked to, and a deadline meant to stop a client that never finishes its
        headers must not also cut a download in half.
        """
        async with asyncio.timeout(READ_TIMEOUT_SECONDS):
            try:
                raw = await reader.readuntil(b"\r\n\r\n")
            except (asyncio.LimitOverrunError, ValueError):
                writer.write(
                    _refusal(
                        HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                        "invalid_request",
                    )
                )
                return
            head = _parse_head(raw[:-4])
            if head is None:
                writer.write(_refusal(HTTPStatus.BAD_REQUEST, "invalid_request"))
                return
            length = _body_length(head)
            if length is None:
                writer.write(_refusal(TOO_LARGE, "payload_too_large"))
                return
            body = await reader.readexactly(length) if length else b""
        await self._invoke(head, body, writer)

    async def _invoke(
        self,
        head: _Head,
        body: bytes,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Drive the ASGI application once, writing what it sends as it sends it."""
        wire = _Wire(writer, head.method)
        pending = [
            cast("Message", {"type": "http.request", "body": body, "more_body": False}),
            cast("Message", {"type": "http.disconnect"}),
        ]

        async def receive() -> Message:
            return pending.pop(0) if pending else {"type": "http.disconnect"}

        async def send(message: Message) -> None:
            await wire.absorb(message)

        scope = _scope_for(head, len(body), (self._host, self._port))
        try:
            await self._app(scope, receive, send)
        except Exception:  # noqa: BLE001 - a traceback must never reach a client
            # Once a head is on the wire its status cannot be taken back, so a
            # producer that fails part way through is answered by *not*
            # terminating the framing. The client then sees a truncated
            # response -- short of a declared length, or missing its chunked
            # terminator -- which is the only honest report available, and is
            # far better than a body that stops early and looks complete.
            if not wire.started:
                writer.write(_internal_refusal())
            return
        if not wire.started:
            writer.write(_internal_refusal())
            return
        await wire.end()
