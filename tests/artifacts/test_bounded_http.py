from __future__ import annotations

import socket
import time
from http.server import BaseHTTPRequestHandler
from threading import Thread
from typing import final, override

import pytest
from services.api.bounded_http import BoundedThreadingHttpServer


@final
class _BodyReadingHandler(BaseHTTPRequestHandler):
    @override
    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def do_POST(self) -> None:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return
        length = int(raw_length)
        _ = self.rfile.read(length)


def _trickle_until_closed(client: socket.socket, payload: bytes) -> float | None:
    started = time.monotonic()
    test_deadline = started + BoundedThreadingHttpServer.request_timeout_seconds + 0.75
    position = 0
    while time.monotonic() < test_deadline:
        try:
            client.sendall(payload[position % len(payload) :][:1])
        except (BrokenPipeError, ConnectionResetError):
            return time.monotonic() - started
        position += 1
        client.settimeout(0.02)
        try:
            received = client.recv(1)
        except TimeoutError:
            pass
        except ConnectionResetError:
            return time.monotonic() - started
        else:
            if not received:
                return time.monotonic() - started
        time.sleep(0.08)
    return None


@pytest.mark.parametrize(
    ("prefix", "trickle"),
    [
        (b"POST ", b"x"),
        (b"POST /slow HTTP/1.1\r\nX-Slow: ", b"x"),
        (
            b"POST /slow HTTP/1.1\r\nContent-Length: 1024\r\n\r\n",
            b"body",
        ),
    ],
    ids=("request-line", "headers", "body"),
)
def test_request_deadline_cannot_be_extended_by_periodic_bytes(
    prefix: bytes,
    trickle: bytes,
) -> None:
    server = BoundedThreadingHttpServer(("127.0.0.1", 0), _BodyReadingHandler)
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.create_connection(("127.0.0.1", server.server_port)) as client:
            client.sendall(prefix)
            closed_after = _trickle_until_closed(client, trickle)
        assert closed_after is not None
        assert closed_after >= server.request_timeout_seconds - 0.5
        assert closed_after <= server.request_timeout_seconds + 0.75
        deadline = time.monotonic() + 1
        while server.active_request_count() != 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.active_request_count() == 0
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        assert not thread.is_alive()
