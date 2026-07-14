from __future__ import annotations

import json
from http.client import HTTPConnection
from typing import Final

import pytest
from pydantic import TypeAdapter
from services.api.dry_lab_fixture import run_server

CSV = "sample,value,calibration\nA,1.25,fixture-cal-1\nB,2.5,fixture-cal-1\n"
type JsonValue = (
    None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
)
type JsonObject = dict[str, JsonValue]

JSON_OBJECT_ADAPTER: Final[TypeAdapter[JsonObject]] = TypeAdapter(JsonObject)


def _json_object(payload: bytes) -> JsonObject:
    return JSON_OBJECT_ADAPTER.validate_json(payload)


def _object_value(value: JsonValue) -> JsonObject:
    assert isinstance(value, dict)
    return value


def _list_value(value: JsonValue) -> list[JsonValue]:
    assert isinstance(value, list)
    return value


def _string_value(value: JsonValue) -> str:
    assert isinstance(value, str)
    return value


def _boolean_value(value: JsonValue) -> bool:
    assert isinstance(value, bool)
    return value


def _request(
    port: int, path: str, body: JsonObject | None = None
) -> tuple[int, JsonObject]:
    connection = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        encoded_body = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"} if body is not None else {}
        connection.request(
            "POST" if body is not None else "GET",
            path,
            body=encoded_body,
            headers=headers,
        )
        response = connection.getresponse()
        try:
            return response.status, _json_object(response.read())
        finally:
            response.close()
    finally:
        connection.close()


def test_loopback_fixture_http_flow_and_ordering() -> None:
    server, port = run_server()
    try:
        status, rejected = _request(port, "/api/fixture/execute", {})
        assert status == 409
        assert rejected == {"code": "invalid-order"}

        status, uploaded = _request(
            port,
            "/api/fixture/upload",
            {"filename": "calibrated.csv", "csv": CSV},
        )
        assert status == 201
        assert _string_value(uploaded["stage"]) == "upload"
        status, plan = _request(port, "/api/fixture/plan", {"lease_id": "fresh"})
        assert status == 201
        status, approval = _request(
            port,
            "/api/fixture/approve",
            {"plan_digest": _string_value(plan["digest"])},
        )
        assert status == 202
        status, executed = _request(
            port,
            "/api/fixture/execute",
            {"token": _string_value(approval["token"])},
        )
        assert status == 200
        assert _boolean_value(executed["child_succeeded"])
        artifacts = _list_value(executed["artifacts"])
        assert len(artifacts) == 5
        assert all(
            len(_string_value(_object_value(item)["sha256"])) == 64
            for item in artifacts
        )
        status, reviewed = _request(port, "/api/fixture/review", {})
        assert status == 201
        assert (
            _string_value(_object_value(reviewed["review"])["verdict"]) == "verified"
        )
        status, exported = _request(port, "/api/fixture/export", {})
        assert status == 200
        assert _list_value(_object_value(exported["export"])["paths"]) == [
            f"artifacts/{_string_value(_object_value(item)['name'])}"
            for item in artifacts
        ]
        status, cleaned = _request(port, "/api/fixture/cleanup", {})
        assert status == 200
        assert _boolean_value(
            _object_value(cleaned["cleanup"])["removed_runtime_data"]
        )
        status, state = _request(port, "/api/fixture/state")
        assert status == 200
        assert _string_value(state["stage"]) == "cleanup"
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("path", ["/", "/api/fixture/state"])
def test_fixture_server_serves_page_and_state(path: str) -> None:
    server, port = run_server()
    try:
        if path == "/":
            connection = HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                connection.request("GET", path)
                response = connection.getresponse()
                try:
                    assert b"run-fixture" in response.read()
                finally:
                    response.close()
            finally:
                connection.close()
        else:
            status, state = _request(port, path)
            assert status == 200
            assert _string_value(state["stage"]) == "new"
    finally:
        server.shutdown()
        server.server_close()
