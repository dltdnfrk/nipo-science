"""Standard-library HTTP surface for the G002 dry-lab fixture."""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Final, final, override

from pydantic import TypeAdapter, ValidationError

from science_workbench_science.vertical import DryLabVertical, FixtureFailure

_HTML_PATH = Path(__file__).parents[2] / "apps" / "web" / "g002-fixture.html"
MAX_JSON_BODY_BYTES = 1_000_000
INVALID_JSON_CODE = "invalid-json"
type JsonValue = (
    None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
)
type JsonObject = dict[str, JsonValue]
JSON_OBJECT_ADAPTER: Final[TypeAdapter[JsonObject]] = TypeAdapter(JsonObject)


# The nested handler methods share the fixture's one state-machine boundary.
def make_handler(  # noqa: C901  # Handler methods intentionally remain coupled.
    vertical: DryLabVertical | None = None, html_path: Path = _HTML_PATH
) -> type[BaseHTTPRequestHandler]:
    """Create a handler bound to one fixture state machine."""
    fixture = vertical or DryLabVertical()

    @final
    class FixtureHandler(BaseHTTPRequestHandler):
        server_version: str = "G002Fixture/1"
        sys_version: str = ""

        def do_GET(self) -> None:
            if self.path == "/":
                self._html()
            elif self.path == "/api/fixture/state":
                self._json(HTTPStatus.OK, fixture.read_projection())
            else:
                self._json(HTTPStatus.NOT_FOUND, {"code": "not-found"})

        def do_POST(self) -> None:
            routes = {
                "/api/fixture/upload": self._upload,
                "/api/fixture/plan": self._plan,
                "/api/fixture/approve": self._approve,
                "/api/fixture/execute": self._execute,
                "/api/fixture/review": self._review,
                "/api/fixture/export": self._export,
                "/api/fixture/cleanup": self._cleanup,
            }
            route = routes.get(self.path)
            if route is None:
                self._json(HTTPStatus.NOT_FOUND, {"code": "not-found"})
                return
            try:
                route(self._body())
            except FixtureFailure as error:
                self._json(error.status, {"code": error.code})
            except (TypeError, UnicodeDecodeError, ValidationError):
                self._json(HTTPStatus.BAD_REQUEST, {"code": INVALID_JSON_CODE})

        def _upload(self, body: JsonObject) -> None:
            upload = fixture.upload(
                _string_value(body, "filename"),
                _string_value(body, "csv"),
                request=_string_value(body, "request"),
            )
            self._json(
                HTTPStatus.CREATED,
                {
                    "filename": upload.filename,
                    "sha256": upload.content_sha256,
                    **fixture.read_projection(),
                },
            )

        def _plan(self, body: JsonObject) -> None:
            plan = fixture.create_plan(
                lease_id=_string_value(body, "lease_id", "fresh")
            )
            self._json(
                HTTPStatus.CREATED,
                {"digest": plan.digest, **fixture.read_projection()},
            )

        def _approve(self, body: JsonObject) -> None:
            approval = fixture.approve(_optional_string(body.get("plan_digest")))
            self._json(
                HTTPStatus.ACCEPTED,
                {
                    "token": approval.token,
                    "plan_digest": approval.plan_digest,
                    **fixture.read_projection(),
                },
            )

        def _execute(self, body: JsonObject) -> None:
            result = fixture.execute(
                _optional_string(body.get("token")),
                request=_string_value(body, "request"),
            )
            self._json(
                HTTPStatus.OK,
                {
                    "child_succeeded": result.child_succeeded,
                    **fixture.read_projection(),
                },
            )

        def _review(self, _: JsonObject) -> None:
            review = fixture.review()
            self._json(
                HTTPStatus.CREATED,
                {
                    "verdict": review.verdict,
                    "pinned_hashes": dict(review.pinned_hashes),
                    **fixture.read_projection(),
                },
            )

        def _export(self, _: JsonObject) -> None:
            receipt = fixture.export()
            self._json(
                HTTPStatus.OK,
                {
                    "manifest_sha256": receipt.manifest_sha256,
                    "paths": list(receipt.paths),
                    **fixture.read_projection(),
                },
            )

        def _cleanup(self, _: JsonObject) -> None:
            receipt = fixture.cleanup()
            self._json(
                HTTPStatus.OK,
                {
                    "removed_runtime_data": receipt.removed_runtime_data,
                    "preserved_artifact_hashes": list(
                        receipt.preserved_artifact_hashes
                    ),
                    **fixture.read_projection(),
                },
            )

        def _body(self) -> JsonObject:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > MAX_JSON_BODY_BYTES:
                raise FixtureFailure(INVALID_JSON_CODE)
            decoded = self.rfile.read(length).decode("utf-8")
            return JSON_OBJECT_ADAPTER.validate_json(decoded or "{}")

        def _html(self) -> None:
            try:
                content = html_path.read_bytes()
            except OSError:
                self._json(HTTPStatus.NOT_FOUND, {"code": "fixture-html-missing"})
                return
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            _ = self.wfile.write(content)

        def _json(self, status: HTTPStatus | int, value: object) -> None:
            content = json.dumps(
                value,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            _ = self.wfile.write(content)

        @override
        def log_message(self, format: str, *args: object) -> None:
            """Keep fixture requests from writing request details to stderr."""
            del format, args

    return FixtureHandler


def _string_value(body: JsonObject, key: str, default: str = "") -> str:
    """Read one optional request string without coercing other JSON values."""
    value = body.get(key)
    return value if isinstance(value, str) else default


def _optional_string(value: JsonValue | None) -> str | None:
    """Read a nullable request string without coercing other JSON values."""
    return value if isinstance(value, str) else None

def run_server(
    host: str = "127.0.0.1", port: int = 0
) -> tuple[ThreadingHTTPServer, int]:
    """Start a loopback fixture server and return it with its selected port."""
    server = ThreadingHTTPServer((host, port), make_handler())
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, int(server.server_address[1])
