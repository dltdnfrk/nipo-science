"""Run the authenticated product fixture for browser journey tests."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from itertools import count
from pathlib import Path
from threading import Event

from services.api.product_app import run_product_server


class _FixtureSessionUnavailableError(LookupError):
    pass


def main() -> None:
    """Serve the product fixture with a process-owned deterministic test session."""
    port = int(os.environ["PRODUCT_UI_PORT"])
    credentials_directory = Path(os.environ["PRODUCT_UI_FIXTURE_CREDENTIALS_DIRECTORY"])
    credentials_path = Path(os.environ["PRODUCT_UI_FIXTURE_CREDENTIALS_FILE"])
    credentials_temp_path = Path(os.environ["PRODUCT_UI_FIXTURE_CREDENTIALS_TEMP_FILE"])
    remove_credentials_directory = (
        os.environ.get("PRODUCT_UI_FIXTURE_REMOVE_CREDENTIALS_DIRECTORY") == "1"
    )
    if (
        credentials_path.parent != credentials_directory
        or credentials_temp_path.parent != credentials_directory
        or credentials_temp_path == credentials_path
    ):
        raise ValueError
    credentials_path.unlink(missing_ok=True)
    credentials_temp_path.unlink(missing_ok=True)
    clock_ticks = count()
    server = run_product_server(
        ("127.0.0.1", port),
        authenticated_fixture=True,
        clock=lambda: datetime(2026, 7, 15, tzinfo=UTC)
        + timedelta(microseconds=next(clock_ticks)),
    )
    try:
        primary_cookie = SimpleCookie()
        primary_cookie.load(server.fixture_session_cookie())
        token = primary_cookie[server.session_cookie_name].value
        foreign_token = server.store.fixture_session_token()
        primary_csrf = server.fixture_csrf_token()
        foreign_csrf = server.store.csrf_token_for(foreign_token)
        if foreign_csrf is None:
            raise _FixtureSessionUnavailableError
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(credentials_temp_path, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as credentials_file:
            json.dump(
                {
                    "primary": {"session": token, "csrf": primary_csrf},
                    "foreign": {"session": foreign_token, "csrf": foreign_csrf},
                },
                credentials_file,
                separators=(",", ":"),
                sort_keys=True,
            )
            credentials_file.flush()
            os.fsync(credentials_file.fileno())
        _ = credentials_temp_path.replace(credentials_path)
        _ = Event().wait()
    finally:
        server.shutdown()
        server.server_close()
        credentials_temp_path.unlink(missing_ok=True)
        credentials_path.unlink(missing_ok=True)
        if remove_credentials_directory:
            credentials_directory.rmdir()


if __name__ == "__main__":
    main()
