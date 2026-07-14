"""Deterministic product service coverage for the G003 dry-lab adapter."""

from __future__ import annotations

from services.api.product_dry_lab import JsonObject, ProductDryLabService

_CSV = "sample,value,calibration\na,1.0,cal-1\nb,2.5,cal-1\n"


def _dispatch(
    service: ProductDryLabService,
    session_key: str,
    action: str,
    body: JsonObject,
) -> tuple[int, JsonObject]:
    """Call the service with a JSON-object-shaped test body."""
    response = service.dispatch(session_key, action, body)
    return response.status, response.payload


def test_full_sequence_replay_and_cleanup_preserve_projection() -> None:
    """Run the fixture journey and retain its public receipt after cleanup."""
    service = ProductDryLabService()

    status, upload = _dispatch(
        service,
        "session-one",
        "upload",
        {"filename": "calibrated.csv", "csv": _CSV, "request": ""},
    )
    assert status == 201
    assert upload["stage"] == "upload"

    status, plan = _dispatch(service, "session-one", "plan", {"lease_id": "fresh"})
    assert status == 201
    plan_digest = plan["digest"]
    assert isinstance(plan_digest, str)

    status, approval = _dispatch(
        service, "session-one", "approve", {"plan_digest": plan_digest}
    )
    assert status == 202
    token = approval["token"]
    assert isinstance(token, str)

    status, execution = _dispatch(
        service, "session-one", "execute", {"token": token, "request": ""}
    )
    assert status == 200
    assert execution["stage"] == "execute"
    assert execution["child_succeeded"] is True

    status, replay = _dispatch(
        service, "session-one", "execute", {"token": token, "request": ""}
    )
    assert status == 409
    assert replay == {"code": "approval-replayed"}

    assert _dispatch(service, "session-one", "review", {})[0] == 201
    assert _dispatch(service, "session-one", "export", {})[0] == 200
    status, cleanup = _dispatch(service, "session-one", "cleanup", {})
    assert status == 200
    assert cleanup["stage"] == "cleanup"
    assert cleanup["removed_runtime_data"] is True

    status, state = _dispatch(service, "session-one", "state", {})
    assert status == 200
    assert state["stage"] == "cleanup"
    assert state["artifacts"] == cleanup["artifacts"]
    assert state["cleanup"] == cleanup["cleanup"]


def test_sessions_are_isolated_and_fixture_failures_are_mapped() -> None:
    """Keep each session state private while returning stable fixture errors."""
    service = ProductDryLabService()

    assert _dispatch(
        service,
        "session-one",
        "upload",
        {"filename": "first.csv", "csv": _CSV, "request": ""},
    )[0] == 201
    status, second_state = _dispatch(service, "session-two", "state", {})
    assert status == 200
    assert second_state["stage"] == "new"
    assert second_state["plan_digest"] is None
    assert service.session_count == 2

    status, failure = _dispatch(
        service,
        "session-two",
        "upload",
        {"filename": "second.csv", "csv": _CSV, "request": "network access"},
    )
    assert status == 400
    assert failure == {"code": "egress-requested"}

    status, first_state = _dispatch(service, "session-one", "state", {})
    assert status == 200
    assert first_state["stage"] == "upload"


def test_denial_unknown_action_and_drop_session() -> None:
    """Reject missing authentication and discard state only on explicit logout."""
    service = ProductDryLabService()

    status, denied = _dispatch(service, "", "state", {})
    assert status == 401
    assert denied == {"code": "unauthorized"}
    assert service.session_count == 0

    status, missing = _dispatch(service, "session-one", "missing", {})
    assert status == 404
    assert missing == {"code": "not-found"}
    assert service.session_count == 0

    assert _dispatch(service, "session-one", "state", {})[0] == 200
    assert service.session_count == 1
    service.drop_session("session-one")
    assert service.session_count == 0
    status, state = _dispatch(service, "session-one", "state", {})
    assert status == 200
    assert state["stage"] == "new"
