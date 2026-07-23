"""Deterministic product service coverage for the G003 dry-lab adapter."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast

from services.api.product_artifacts import ProductArtifactService
from services.api.product_dry_lab import (
    JsonObject,
    LocalRunCreate,
    ProductDryLabService,
)

from .fixtures import PRIMARY_SESSION_ID

if TYPE_CHECKING:
    import pytest
    from services.api.product_artifact_types import (
        ArtifactVersion,
        ArtifactVersionDraft,
    )

_CSV = "sample,value,calibration\na,1.0,cal-1\nb,2.5,cal-1\n"
_TRANSIENT_ARTIFACT_STORE_FAILURE = "transient artifact store failure"


def _research_intent() -> JsonObject:
    return {
        "question": "보정된 관측값을 재현 가능하게 정규화할 수 있는가?",
        "rationale": "반복 분석에서 입력 순서가 결과를 바꾸지 않도록 확인한다.",
        "intended_benefit": "검증 가능한 정규화 기준선을 만든다.",
        "success_criteria": ["동일 입력은 동일 체크섬을 만든다."],
        "constraints": ["비임상 연구 데이터만 사용한다."],
        "stop_conditions": ["보정 메타데이터가 없으면 중단한다."],
        "research_mode": "bounded_agentic",
        "data_origin": "observed",
    }


def _dispatch(
    service: ProductDryLabService,
    session_key: str,
    action: str,
    body: JsonObject,
) -> tuple[int, JsonObject]:
    """Call the service with a JSON-object-shaped test body."""
    response = service.dispatch(session_key, action, body)
    return response.status, response.payload


def _create_run(
    service: ProductDryLabService,
    session_key: str,
    filename: str = "calibrated.csv",
    *,
    research_intent: JsonObject | None = None,
) -> tuple[str, str]:
    response = service.create_local_run(
        session_key,
        LocalRunCreate(
            research_session_id=PRIMARY_SESSION_ID,
            prompt="보정값을 정규화하고 재현성을 검증한다.",
            research_intent=research_intent or _research_intent(),
            filename=filename,
            media_type="text/csv",
            content=_CSV,
        ),
    )
    run_id = response.payload["run_id"]
    plan_digest = response.payload["plan_digest"]
    assert response.status == 201
    assert isinstance(run_id, str)
    assert isinstance(plan_digest, str)
    return run_id, plan_digest


def test_full_sequence_replay_and_cleanup_preserve_projection() -> None:
    """Run the fixture journey and retain its public receipt after cleanup."""
    service = ProductDryLabService(ProductArtifactService)

    run_id, plan_digest = _create_run(service, "session-one")

    status, approval = _dispatch(
        service,
        "session-one",
        "approve",
        {"run_id": run_id, "plan_digest": plan_digest},
    )
    assert status == 202
    token = approval["token"]
    assert isinstance(token, str)

    status, execution = _dispatch(
        service,
        "session-one",
        "execute",
        {"run_id": run_id, "token": token, "request": ""},
    )
    assert status == 200
    assert execution["stage"] == "execute"
    assert execution["child_succeeded"] is True

    status, replay = _dispatch(
        service,
        "session-one",
        "execute",
        {"run_id": run_id, "token": token, "request": ""},
    )
    assert status == 409
    assert replay == {"code": "approval-replayed"}

    assert _dispatch(service, "session-one", "review", {"run_id": run_id})[0] == 201
    assert _dispatch(service, "session-one", "export", {"run_id": run_id})[0] == 200
    denied_status, denied_cleanup = _dispatch(
        service, "session-one", "cleanup", {"run_id": run_id}
    )
    assert (denied_status, denied_cleanup) == (
        400,
        {"code": "cleanup-confirmation-required"},
    )
    status, cleanup = _dispatch(
        service,
        "session-one",
        "cleanup",
        {"run_id": run_id, "confirmed": True},
    )
    assert status == 200
    assert cleanup["stage"] == "cleanup"
    assert cleanup["removed_runtime_data"] is True

    resource = service.resource("session-one", "run", run_id)
    assert resource is not None
    assert resource.payload["stage"] == "cleanup"
    assert resource.payload["artifacts"] == cleanup["artifacts"]
    assert resource.payload["cleanup"] == cleanup["cleanup"]


def test_local_run_creation_atomically_binds_intent_and_server_capabilities() -> None:
    run_id = "018f0d7d-6b17-7a91-8b31-2f7331677d01"
    service = ProductDryLabService(
        ProductArtifactService,
        id_factory=lambda: run_id,
        clock=lambda: datetime(2026, 7, 15, 3, 19, tzinfo=UTC),
    )

    response = service.create_local_run(
        "session-local",
        LocalRunCreate(
            research_session_id=PRIMARY_SESSION_ID,
            prompt="보정값을 정규화하고 재현성을 검증한다.",
            research_intent=_research_intent(),
            filename="calibrated.csv",
            media_type="text/csv",
            content=_CSV,
        ),
    )

    assert response.status == 201
    assert response.payload["run_id"] == run_id
    assert response.payload["created_at"] == "2026-07-15T03:19:00Z"
    assert response.payload["stage"] == "plan"
    assert response.payload["research_intent"] == _research_intent() | {
        "synthetic_generator_ref": None,
        "synthetic_validator_ref": None,
    }
    assert response.payload["action_plan"] == {
        "digest": response.payload["plan_digest"],
        "scope_label": "현재 ActionPlan의 격리 실행 1회",
        "approval_status_label": "승인 대기",
        "approval_expires_at": None,
        "approval_ttl_seconds": 600,
    }
    assert response.payload["links"] == [
        {"kind": "run", "href": f"/runs/{run_id}", "label": "실행 보기"},
        {
            "kind": "approval",
            "href": f"/runs/{run_id}/approval",
            "label": "계획 승인 보기",
        },
    ]
    assert [
        action["id"] for action in cast("list[JsonObject]", response.payload["actions"])
    ] == [
        "create-run",
        "approve",
        "reject",
        "cancel",
    ]


def test_reject_and_cancel_terminalize_exact_runs_without_outputs() -> None:
    service = ProductDryLabService(ProductArtifactService)
    rejected_id, _ = _create_run(service, "session-terminal", "rejected.csv")
    cancelled_id, cancelled_digest = _create_run(
        service, "session-terminal", "cancelled.csv"
    )

    rejected_status, rejected = _dispatch(
        service, "session-terminal", "reject", {"run_id": rejected_id}
    )
    approval_status, approval = _dispatch(
        service,
        "session-terminal",
        "approve",
        {"run_id": cancelled_id, "plan_digest": cancelled_digest},
    )
    cancelled_status, cancelled = _dispatch(
        service, "session-terminal", "cancel", {"run_id": cancelled_id}
    )

    assert rejected_status == cancelled_status == 200
    assert approval_status == 202
    assert rejected["stage"] == "reject"
    assert cancelled["stage"] == "cancel"
    assert rejected["artifacts"] == cancelled["artifacts"] == []
    assert rejected["review_id"] is cancelled["review_id"] is None
    assert rejected["export_id"] is cancelled["export_id"] is None
    assert service.artifact_library("session-terminal") == {"artifacts": []}

    token = approval["token"]
    assert isinstance(token, str)
    assert _dispatch(
        service,
        "session-terminal",
        "execute",
        {"run_id": cancelled_id, "token": token, "request": ""},
    ) == (409, {"code": "invalid-order"})
    assert _dispatch(
        service, "session-terminal", "review", {"run_id": cancelled_id}
    ) == (409, {"code": "invalid-order"})


def test_expired_approval_is_visible_and_cannot_execute_or_review() -> None:
    now = [datetime(2026, 7, 16, 2, 0, tzinfo=UTC)]
    service = ProductDryLabService(
        ProductArtifactService,
        clock=lambda: now[0],
    )
    run_id, plan_digest = _create_run(service, "session-expiry")
    approval_status, approval = _dispatch(
        service,
        "session-expiry",
        "approve",
        {"run_id": run_id, "plan_digest": plan_digest},
    )
    assert approval_status == 202
    assert cast("JsonObject", approval["action_plan"])["approval_expires_at"] == (
        "2026-07-16T02:10:00Z"
    )

    now[0] += timedelta(minutes=10)
    expired = service.resource("session-expiry", "run", run_id)

    assert expired is not None
    assert expired.payload["stage"] == "expire"
    assert cast("JsonObject", expired.payload["action_plan"])[
        "approval_status_label"
    ] == "승인 만료"
    assert [
        action["id"]
        for action in cast("list[JsonObject]", expired.payload["actions"])
    ] == ["create-run"]
    token = approval["token"]
    assert isinstance(token, str)
    assert _dispatch(
        service,
        "session-expiry",
        "execute",
        {"run_id": run_id, "token": token, "request": ""},
    ) == (409, {"code": "approval-expired"})
    assert _dispatch(
        service, "session-expiry", "review", {"run_id": run_id}
    ) == (409, {"code": "invalid-order"})


def test_sessions_are_isolated_and_fixture_failures_are_mapped() -> None:
    """Keep each session state private while returning stable fixture errors."""
    service = ProductDryLabService(ProductArtifactService)

    run_id, _ = _create_run(service, "session-one", "first.csv")
    assert service.resource("session-two", "run", run_id) is None
    assert service.workspace_runs("session-two") == ()
    assert service.session_count == 1

    failure = service.create_local_run(
        "session-two",
        LocalRunCreate(
            research_session_id=PRIMARY_SESSION_ID,
            prompt="잘못된 CSV는 원자적으로 거부한다.",
            research_intent=_research_intent(),
            filename="second.csv",
            media_type="text/csv",
            content="not,a,calibrated-csv\n",
        ),
    )
    assert failure.status == 400
    assert failure.payload == {"code": "malformed-csv"}
    assert service.workspace_runs("session-two") == ()

    first = service.resource("session-one", "run", run_id)
    assert first is not None
    assert first.payload["stage"] == "plan"


def test_denial_unknown_action_and_drop_session() -> None:
    """Reject missing authentication and discard state only on explicit logout."""
    service = ProductDryLabService(ProductArtifactService)

    denied = service.create_local_run(
        "",
        LocalRunCreate(
            research_session_id=PRIMARY_SESSION_ID,
            prompt="인증 없는 실행은 거부한다.",
            research_intent=_research_intent(),
            filename="calibrated.csv",
            media_type="text/csv",
            content=_CSV,
        ),
    )
    assert denied.status == 401
    assert denied.payload == {"code": "unauthorized"}
    assert service.session_count == 0

    for removed_action in ("state", "upload", "plan", "missing"):
        status, missing = _dispatch(service, "session-one", removed_action, {})
        assert status == 404
        assert missing == {"code": "not-found"}
    assert service.session_count == 0

    run_id, _ = _create_run(service, "session-one")
    assert service.resource("session-one", "run", run_id) is not None
    assert service.session_count == 1
    service.drop_session("session-one")
    assert service.session_count == 0
    assert service.resource("session-one", "run", run_id) is None


def test_concurrent_local_runs_bind_distinct_authoritative_research_intents() -> None:
    service = ProductDryLabService(ProductArtifactService)
    second_intent = _research_intent() | {
        "question": "서로 다른 연구 질문도 동시에 승인될 수 있는가?"
    }

    def create_run(intent: JsonObject) -> tuple[str, str]:
        return _create_run(
            service,
            "session-race",
            research_intent=intent,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        created = tuple(executor.map(create_run, (_research_intent(), second_intent)))

    assert created[0][0] != created[1][0]
    resources = tuple(
        service.resource("session-race", "run", run_id) for run_id, _ in created
    )
    assert all(resource is not None for resource in resources)
    questions: list[str] = []
    for resource in resources:
        if resource is None:
            continue
        question = cast("JsonObject", resource.payload["research_intent"])["question"]
        assert isinstance(question, str)
        questions.append(question)
    first_question = _research_intent()["question"]
    second_question = second_intent["question"]
    assert isinstance(first_question, str)
    assert isinstance(second_question, str)
    assert set(questions) == {first_question, second_question}


def test_two_runs_in_one_session_retain_exact_independent_resources() -> None:
    service = ProductDryLabService(ProductArtifactService)
    first_run_id, first_digest = _create_run(service, "session-multi", "first.csv")
    second_run_id, second_digest = _create_run(
        service,
        "session-multi",
        "second.csv",
        research_intent=_research_intent()
        | {"question": "두 번째 독립 실행도 정확히 보존되는가?"},
    )

    assert first_run_id != second_run_id
    first = service.resource("session-multi", "run", first_run_id)
    second = service.resource("session-multi", "run", second_run_id)
    assert first is not None
    assert second is not None
    assert first.payload["run_id"] == first_run_id
    assert second.payload["run_id"] == second_run_id
    assert first.payload["plan_digest"] == first_digest
    assert second.payload["plan_digest"] == second_digest
    assert [run["id"] for run in service.workspace_runs("session-multi")] == [
        first_run_id,
        second_run_id,
    ]


def test_workspace_runs_retain_distinct_server_creation_times() -> None:
    run_ids = iter(
        (
            "018f0d7d-6b17-7a91-8b31-2f7331677d11",
            "018f0d7d-6b17-7a91-8b31-2f7331677d12",
        )
    )
    creation_times = iter(
        (
            datetime(2026, 7, 15, 3, 20, tzinfo=UTC),
            datetime(2026, 7, 15, 3, 21, tzinfo=UTC),
        )
    )
    service = ProductDryLabService(
        ProductArtifactService,
        id_factory=run_ids.__next__,
        clock=creation_times.__next__,
    )
    first_run_id, _ = _create_run(service, "session-timestamps", "first.csv")
    second_run_id, _ = _create_run(service, "session-timestamps", "second.csv")

    recent = service.workspace_runs("session-timestamps")
    first_resource = service.resource("session-timestamps", "run", first_run_id)

    assert first_resource is not None
    assert first_resource.payload["created_at"] == "2026-07-15T03:20:00Z"
    assert recent == (
        {
            "id": first_run_id,
            "display_id": "Run 31677d11",
            "name": "드라이랩 연구 실행",
            "created_at": "2026-07-15T03:20:00Z",
            "stage": "plan",
            "stage_label": "계획 승인 대기",
            "links": [
                {
                    "kind": "run",
                    "href": f"/runs/{first_run_id}",
                    "label": "실행 보기",
                },
                {
                    "kind": "approval",
                    "href": f"/runs/{first_run_id}/approval",
                    "label": "계획 승인 보기",
                },
            ],
        },
        {
            "id": second_run_id,
            "display_id": "Run 31677d12",
            "name": "드라이랩 연구 실행",
            "created_at": "2026-07-15T03:21:00Z",
            "stage": "plan",
            "stage_label": "계획 승인 대기",
            "links": [
                {
                    "kind": "run",
                    "href": f"/runs/{second_run_id}",
                    "label": "실행 보기",
                },
                {
                    "kind": "approval",
                    "href": f"/runs/{second_run_id}/approval",
                    "label": "계획 승인 보기",
                },
            ],
        },
    )


def test_concurrent_approvals_target_two_distinct_runs_without_state_bleed() -> None:
    service = ProductDryLabService(ProductArtifactService)
    first_run_id, first_digest = _create_run(service, "session-parallel", "first.csv")
    second_run_id, second_digest = _create_run(
        service,
        "session-parallel",
        "second.csv",
        research_intent=_research_intent()
        | {"question": "두 번째 실행의 상태는 격리되는가?"},
    )

    def approve(item: tuple[str, str]) -> tuple[int, JsonObject]:
        run_id, plan_digest = item
        return _dispatch(
            service,
            "session-parallel",
            "approve",
            {"run_id": run_id, "plan_digest": plan_digest},
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first, second = tuple(
            executor.map(
                approve,
                ((first_run_id, first_digest), (second_run_id, second_digest)),
            )
        )

    assert first[0] == second[0] == 202
    first_resource = service.resource("session-parallel", "run", first_run_id)
    second_resource = service.resource("session-parallel", "run", second_run_id)
    assert first_resource is not None
    assert second_resource is not None
    assert first_resource.payload["stage"] == "approve"
    assert second_resource.payload["stage"] == "approve"
    assert first_resource.payload["plan_digest"] == first_digest
    assert second_resource.payload["plan_digest"] == second_digest


def test_artifact_materialization_failure_is_atomic_and_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: the first Artifact service fails after writing one transient Version.
    original_create_version = ProductArtifactService.create_version
    created = 0

    def fail_after_first_version(
        service: ProductArtifactService,
        draft: ArtifactVersionDraft,
        *,
        base_version_no: int,
    ) -> ArtifactVersion:
        nonlocal created
        if created == 1:
            raise OSError(_TRANSIENT_ARTIFACT_STORE_FAILURE)
        created += 1
        return original_create_version(
            service,
            draft,
            base_version_no=base_version_no,
        )

    monkeypatch.setattr(
        ProductArtifactService, "create_version", fail_after_first_version
    )
    service = ProductDryLabService(ProductArtifactService)
    run_id, plan_digest = _create_run(service, "session-artifact-retry")
    approval_status, approval = _dispatch(
        service,
        "session-artifact-retry",
        "approve",
        {"run_id": run_id, "plan_digest": plan_digest},
    )
    token = approval["token"]
    assert approval_status == 202
    assert isinstance(token, str)

    # When: execution reaches the flaky Artifact materialization boundary.
    failed_status, failed = _dispatch(
        service,
        "session-artifact-retry",
        "execute",
        {"run_id": run_id, "token": token, "request": ""},
    )

    # Then: no execution state leaks, and the same approval remains retryable.
    assert (failed_status, failed) == (500, {"code": "artifact-unavailable"})
    unchanged = service.resource("session-artifact-retry", "run", run_id)
    assert unchanged is not None
    assert unchanged.payload["stage"] == "approve"
    assert unchanged.payload["artifacts"] == []

    monkeypatch.setattr(
        ProductArtifactService,
        "create_version",
        original_create_version,
    )

    retried_status, retried = _dispatch(
        service,
        "session-artifact-retry",
        "execute",
        {"run_id": run_id, "token": token, "request": ""},
    )
    assert retried_status == 200
    assert retried["stage"] == "execute"
    assert len(cast("list[JsonObject]", retried["artifacts"])) == 5
