"""Run the deterministic Artifact UI fixture for browser acceptance tests."""

from __future__ import annotations

import os

from services.api.artifact_ui_app import ArtifactUiServer


def main() -> None:
    """Serve the fixed local acceptance origin until the runner terminates it."""
    token = os.environ.get("ARTIFACT_UI_PRINCIPAL", "playwright-test-principal")
    port = int(os.environ.get("ARTIFACT_UI_PORT", "18765"))
    server = ArtifactUiServer(("127.0.0.1", port), token)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
