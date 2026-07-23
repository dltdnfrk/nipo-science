"""Bounded threaded HTTP server shared by local and production processes."""

from __future__ import annotations

import sys
from http.server import ThreadingHTTPServer
from socket import SHUT_RDWR, socket
from threading import BoundedSemaphore, Lock, Timer
from time import monotonic
from typing import TYPE_CHECKING, override

if TYPE_CHECKING:
    from socketserver import BaseRequestHandler

    type RequestSocket = socket | tuple[bytes, socket]

type RequestDeadline = tuple[float, Timer]


class BoundedThreadingHttpServer(ThreadingHTTPServer):
    """Bound concurrent handlers and expire incomplete client requests."""

    request_queue_size: int = 16
    request_timeout_seconds: float = 2.0

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[BaseRequestHandler],
    ) -> None:
        """Initialize one server with a handler-slot bound matching its backlog."""
        self._request_slots: BoundedSemaphore = BoundedSemaphore(
            self.request_queue_size
        )
        self._request_lock: Lock = Lock()
        self._active_requests: set[RequestSocket] = set()
        self._request_deadlines: dict[RequestSocket, RequestDeadline] = {}
        super().__init__(address, handler)

    def active_request_count(self) -> int:
        """Return the current number of allocated handler slots."""
        with self._request_lock:
            return len(self._active_requests)

    @override
    def process_request(
        self, request: RequestSocket, client_address: tuple[str, int]
    ) -> None:
        """Reject excess sockets before allocating another request thread."""
        if not self._request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        expires_at = monotonic() + self.request_timeout_seconds
        deadline_timer = Timer(
            max(0.0, expires_at - monotonic()),
            self._expire_request,
            args=(request,),
        )
        deadline_timer.daemon = True
        with self._request_lock:
            self._active_requests.add(request)
            self._request_deadlines[request] = (expires_at, deadline_timer)
        try:
            deadline_timer.start()
        except RuntimeError:
            with self._request_lock:
                self._active_requests.discard(request)
                _ = self._request_deadlines.pop(request, None)
            self._request_slots.release()
            raise
        try:
            super().process_request(request, client_address)
        except RuntimeError:
            self._release_request(request)
            self._request_slots.release()
            raise

    @override
    def process_request_thread(
        self, request: RequestSocket, client_address: tuple[str, int]
    ) -> None:
        """Release one handler slot after every request-thread outcome."""
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release_request(request)
            self._request_slots.release()

    def _expire_request(self, request: RequestSocket) -> None:
        with self._request_lock:
            deadline = self._request_deadlines.get(request)
        if deadline is None or monotonic() < deadline[0]:
            return
        match request:
            case socket() as connection:
                pass
            case (_, socket() as connection):
                pass
        try:
            connection.shutdown(SHUT_RDWR)
        except OSError:
            return

    def _release_request(self, request: RequestSocket) -> None:
        with self._request_lock:
            self._active_requests.discard(request)
            deadline = self._request_deadlines.pop(request, None)
        if deadline is not None:
            deadline[1].cancel()
            deadline[1].join()

    @override
    def handle_error(
        self, request: RequestSocket, client_address: tuple[str, int]
    ) -> None:
        """Suppress expected socket timeout noise while retaining other errors."""
        error = sys.exception()
        if isinstance(error, OSError):
            return
        super().handle_error(request, client_address)

    @override
    def server_close(self) -> None:
        """Close active sockets before releasing the listening socket."""
        with self._request_lock:
            active = tuple(self._active_requests)
            deadlines = tuple(self._request_deadlines.values())
        for _, timer in deadlines:
            timer.cancel()
        for request in active:
            match request:
                case socket() as connection:
                    pass
                case (_, socket() as connection):
                    pass
            try:
                connection.shutdown(SHUT_RDWR)
            except OSError:
                continue
        for _, timer in deadlines:
            timer.join()
        super().server_close()
