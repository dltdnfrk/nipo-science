from __future__ import annotations

import socket
import tempfile
import time
from pathlib import Path
from threading import Event, Thread

from services.api.provider_uds import (
    PROVIDER_UDS_SERVER_READ_TIMEOUT_SECONDS,
    ProviderUdsClientConfig,
    SecureProviderUnixServer,
    provider_uds_request,
)


def test_server_read_deadline_releases_request_after_trickled_partial_frame() -> None:
    with tempfile.TemporaryDirectory(prefix="swbp-") as directory:
        root = Path(directory).resolve()
        root.chmod(0o700)
        socket_path = root / "provider.sock"
        server = SecureProviderUnixServer(socket_path, lambda source: source)
        server_thread = Thread(target=server.serve_forever, daemon=True)
        trickle_stopped = Event()
        partial_client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        def trickle_partial_frame() -> None:
            while not trickle_stopped.wait(0.05):
                try:
                    partial_client.sendall(b" ")
                except OSError:
                    return

        trickle_thread = Thread(target=trickle_partial_frame, daemon=True)
        try:
            # Given a first accepted client that never completes its JSON frame.
            partial_client.connect(str(socket_path))
            partial_client.sendall(b"{")
            trickle_thread.start()
            server_thread.start()

            # When a complete request arrives behind bytes that defeat an idle timeout.
            started_at = time.monotonic()
            response = provider_uds_request(
                ProviderUdsClientConfig(
                    socket_path,
                    timeout_seconds=PROVIDER_UDS_SERVER_READ_TIMEOUT_SECONDS + 2.0,
                ),
                {"schema_version": 1, "operation": "health"},
            )
            elapsed = time.monotonic() - started_at

            # Then the server's total read deadline releases the valid request.
            assert response == {"schema_version": 1, "operation": "health"}
            assert elapsed < PROVIDER_UDS_SERVER_READ_TIMEOUT_SECONDS + 1.0
        finally:
            trickle_stopped.set()
            partial_client.close()
            if trickle_thread.ident is not None:
                trickle_thread.join(timeout=1)
            if server_thread.is_alive():
                server.shutdown()
            server_thread.join(timeout=5)
            server.server_close()
