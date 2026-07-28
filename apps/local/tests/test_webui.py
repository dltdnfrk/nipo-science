"""Tests for the shipped front end and how it is served.

Every literal here is written out rather than imported from `webui`. A test
that asserted `response_csp == DOCUMENT_CSP` would agree with any policy the
module happened to hold, including one that had grown `'unsafe-inline'`.

Nothing is asserted by searching a path for a substring either: `tmp_path`
embeds the test's own function name, which has silently satisfied assertions
in this repository before.
"""

import re
from pathlib import Path

import pytest

from nipo_local.webui import (
    StaticSurface,
    default_web_root,
    inject_token,
)

ANCHOR = re.compile(rb'<meta name="nipo-local-token" content="([^"]*)">')

SHIPPED_ROOT = default_web_root()

DOCUMENT = (
    b"<!doctype html><html><head>"
    b'<meta name="nipo-local-token" content="">'
    b"</head><body></body></html>"
)


def _root(tmp_path: Path, document: bytes = DOCUMENT) -> Path:
    directory = tmp_path / "web"
    directory.mkdir()
    _ = (directory / "index.html").write_bytes(document)
    return directory


def test_the_shipped_document_carries_exactly_one_credential_anchor() -> None:
    payload = (SHIPPED_ROOT / "index.html").read_bytes()

    assert len(ANCHOR.findall(payload)) == 1
    # It ships empty. A credential committed into the repository would be a
    # credential in every checkout.
    assert ANCHOR.findall(payload) == [b""]


def test_the_shipped_front_end_is_a_flat_directory_of_served_suffixes() -> None:
    entries = sorted(item.name for item in SHIPPED_ROOT.iterdir())

    assert entries == ["app.js", "favicon.svg", "index.html", "styles.css"]
    assert all((SHIPPED_ROOT / name).is_file() for name in entries)


def test_the_shipped_script_sets_no_inline_style_attribute() -> None:
    # `style-src 'self'` has no `'unsafe-inline'`, so a style attribute the
    # script sets is refused by the browser and the layout quietly breaks.
    source = (SHIPPED_ROOT / "app.js").read_text(encoding="utf-8")

    assert 'style: "' not in source
    assert 'setAttribute("style"' not in source
    assert ".style." not in source


def test_injecting_a_credential_replaces_only_the_anchor_value() -> None:
    injected = inject_token(DOCUMENT, "abc-123_XYZ")

    assert ANCHOR.findall(injected) == [b"abc-123_XYZ"]
    assert injected.replace(b"abc-123_XYZ", b"") == DOCUMENT


def test_injecting_escapes_a_value_that_could_close_the_attribute() -> None:
    # A `secrets.token_urlsafe` credential contains none of these, which is
    # exactly why the escape must be proven rather than assumed.
    injected = inject_token(DOCUMENT, '"><script>alert(1)</script>')

    assert b"<script>alert(1)</script>" not in injected
    assert b"&lt;script&gt;" in injected
    assert len(ANCHOR.findall(injected)) == 1


def test_injecting_into_a_document_without_an_anchor_is_refused() -> None:
    with pytest.raises(ValueError, match="anchor"):
        _ = inject_token(b"<!doctype html><html></html>", "value")


def test_a_root_without_a_document_is_refused_at_construction(tmp_path: Path) -> None:
    empty = tmp_path / "web"
    empty.mkdir()

    with pytest.raises(FileNotFoundError):
        _ = StaticSurface(empty)


def test_a_missing_root_is_refused_at_construction(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        _ = StaticSurface(tmp_path / "absent")


def test_a_document_without_an_anchor_is_refused_at_construction(
    tmp_path: Path,
) -> None:
    # Serving it would produce a page that silently cannot authenticate, which
    # reads to a researcher as a launcher bug rather than a build one.
    with pytest.raises(ValueError, match="anchor"):
        _ = StaticSurface(_root(tmp_path, b"<!doctype html><html></html>"))


def test_the_served_paths_are_the_document_plus_each_shipped_leaf(
    tmp_path: Path,
) -> None:
    directory = _root(tmp_path)
    _ = (directory / "styles.css").write_bytes(b"body{}")
    _ = (directory / "app.js").write_bytes(b"//")

    surface = StaticSurface(directory)

    assert surface.paths == frozenset({"/", "/index.html", "/styles.css", "/app.js"})


def test_an_unserved_suffix_is_not_reachable(tmp_path: Path) -> None:
    directory = _root(tmp_path)
    _ = (directory / "notes.txt").write_bytes(b"private")
    _ = (directory / "nipo.sqlite3").write_bytes(b"database")

    surface = StaticSurface(directory)

    assert surface.paths == frozenset({"/", "/index.html"})
    assert surface.asset("/notes.txt") is None
    assert surface.asset("/nipo.sqlite3") is None


def test_a_dotfile_is_not_reachable(tmp_path: Path) -> None:
    directory = _root(tmp_path)
    _ = (directory / ".env.js").write_bytes(b"SECRET=1")

    assert StaticSurface(directory).asset("/.env.js") is None


def test_a_symlink_pointing_outside_the_root_is_not_served(tmp_path: Path) -> None:
    # The name is an ordinary leaf and the suffix is served, so only the
    # post-resolution containment check can reject this.
    outside = tmp_path / "outside.js"
    _ = outside.write_bytes(b"secret")
    directory = _root(tmp_path)
    (directory / "leak.js").symlink_to(outside)

    surface = StaticSurface(directory)

    assert surface.asset("/leak.js") is None
    assert surface.paths == frozenset({"/", "/index.html"})


def test_a_subdirectory_is_never_a_served_path(tmp_path: Path) -> None:
    directory = _root(tmp_path)
    nested = directory / "vendor"
    nested.mkdir()
    _ = (nested / "lib.js").write_bytes(b"//")

    surface = StaticSurface(directory)

    assert surface.paths == frozenset({"/", "/index.html"})
    assert surface.asset("/vendor/lib.js") is None
    assert surface.asset("/vendor") is None


def test_both_document_paths_serve_the_same_bytes(tmp_path: Path) -> None:
    surface = StaticSurface(_root(tmp_path))

    root = surface.asset("/")
    named = surface.asset("/index.html")

    assert root is not None
    assert named is not None
    assert root.payload == named.payload
    assert root.is_document is True
    assert named.is_document is True


def test_only_the_document_carries_the_relaxed_policy(tmp_path: Path) -> None:
    directory = _root(tmp_path)
    _ = (directory / "styles.css").write_bytes(b"body{}")

    surface = StaticSurface(directory)

    document = surface.asset("/")
    stylesheet = surface.asset("/styles.css")
    assert document is not None
    assert stylesheet is not None
    assert document.content_security_policy == (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self'; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'"
    )
    assert stylesheet.content_security_policy == ""
    assert stylesheet.is_document is False


def test_the_document_policy_permits_only_self(tmp_path: Path) -> None:
    surface = StaticSurface(_root(tmp_path))
    document = surface.asset("/")
    assert document is not None
    policy = document.content_security_policy

    directives = dict(
        item.strip().split(" ", 1) for item in policy.split(";") if item.strip()
    )
    assert directives == {
        "default-src": "'none'",
        "script-src": "'self'",
        "style-src": "'self'",
        "connect-src": "'self'",
        "img-src": "'self'",
        "base-uri": "'none'",
        "form-action": "'none'",
        "frame-ancestors": "'none'",
    }
    assert "unsafe-inline" not in policy
    assert "unsafe-eval" not in policy
    assert "http" not in policy
    assert "*" not in policy


def test_the_surface_is_a_snapshot_and_a_later_file_is_not_served(
    tmp_path: Path,
) -> None:
    directory = _root(tmp_path)
    surface = StaticSurface(directory)

    _ = (directory / "late.js").write_bytes(b"//")

    assert surface.asset("/late.js") is None
    assert "/late.js" not in surface.paths


def test_a_document_replaced_after_startup_does_not_change_what_is_served(
    tmp_path: Path,
) -> None:
    directory = _root(tmp_path)
    surface = StaticSurface(directory)
    _ = (directory / "index.html").write_bytes(b"<html>replaced</html>")

    document = surface.asset("/")

    assert document is not None
    assert document.payload == DOCUMENT


def test_the_default_root_is_the_shipped_front_end() -> None:
    root = default_web_root()

    assert root.is_dir()
    assert (root / "index.html").is_file()
    assert root.name == "local"
    assert root.parent.name == "web"


def test_served_returns_every_asset_in_path_order(tmp_path: Path) -> None:
    # The route builder iterates this, so it never handles an optional asset:
    # there is no unreachable branch for a missing one.
    directory = _root(tmp_path)
    _ = (directory / "styles.css").write_bytes(b"body{}")
    _ = (directory / "app.js").write_bytes(b"//")

    served = StaticSurface(directory).served()

    assert [item.path for item in served] == [
        "/",
        "/app.js",
        "/index.html",
        "/styles.css",
    ]
    assert {item.path for item in served} == StaticSurface(directory).paths
    assert [item.is_document for item in served] == [True, False, True, False]


def test_the_plan_approval_route_is_registered() -> None:
    # L04 surfaces plan creation under the session path. A missing route leaves
    # the researcher on the not-found screen with no way to author an intent.
    source = (SHIPPED_ROOT / "app.js").read_text(encoding="utf-8")

    assert r"/projects\/([^/]+)\/sessions\/([^/]+)\/plan" in source
    assert "renderPlanApproval" in source
    assert "createActionPlan" in source
    assert "approveActionPlan" in source
    assert "#/projects/${projectId}/sessions/${session.id}/plan" in source


def test_the_plan_approval_screen_has_measurement_load_and_run_cta() -> None:
    # L03 unlocks Run on the approval screen only after a held ProbeInput and
    # an unspent approval. Structure must expose the measurement-load section
    # and the start-run path without inventing inline styles or dropping the
    # in_process disclosure elsewhere in the shell.
    source = (SHIPPED_ROOT / "app.js").read_text(encoding="utf-8")
    styles = (SHIPPED_ROOT / "styles.css").read_text(encoding="utf-8")
    start = source.index("async function renderPlanApproval")
    marker = "-" * 60
    end = source.index(f"// {marker} project gate --", start)
    screen = source[start:end]

    assert '"data-plan-run": "measurement"' in screen
    assert '"data-plan-run": "deferred"' not in screen
    assert "측정 파일 업로드 화면(L03)" not in screen
    assert "승인된 플랜의 실행은 로컬 API로 가능하며" not in screen

    assert "측정 데이터 파일" in screen
    assert "매니페스트" in screen
    assert "측정 파일 불러오기" in screen
    assert '"data-action": "load-measurement"' in screen
    assert '"data-action": "start-run"' in screen
    assert "실행 시작" in screen
    assert "data-measurement-load" in screen
    assert "scientificInput" in screen
    assert "localStorage.setItem" not in screen
    assert "sessionStorage" not in screen
    assert "api.probeInput" in screen or "probeInput:" in source
    assert "inputs/probe" in source
    assert "scientific_input" in screen
    assert "input_sha256" in screen
    assert "LOADER_REASON_TEXT" in source
    assert "science_issue" in source
    assert "manifest_not_found" in source
    assert "metadata_rejected" in source
    assert "image_exceeds_product_pixel_cap" in source

    # Intent edits still invalidate the approval binding (existing L04 contract).
    assert "수정된 의도는 새 승인이 필요합니다" in screen
    assert "needsNewPlan" in screen

    # No inline style attributes in this screen or the stylesheet for it.
    assert "style:" not in screen
    assert "style=" not in screen
    assert ".measurement-receipt" in styles
    assert 'input[type="file"]' in styles

    # Isolation honesty remains part of the shipped shell (not this panel alone).
    assert "in_process" in source
    assert (
        'data-isolation": "in_process"' in source
        or '"data-isolation": "in_process"' in source
    )


def test_the_plan_approval_screen_renders_digest_code_elements() -> None:
    # Digests are server-derived and must be inspectable as <code> blocks, not
    # only as plain text that a reader cannot distinguish from labels.
    source = (SHIPPED_ROOT / "app.js").read_text(encoding="utf-8")

    assert 'el("code", { class: "hash"' in source
    assert "function digestCode(label, value, marker)" in source
    assert '"data-digest": marker' in source
    plan_digest_call = (
        'digestCode("ActionPlan SHA-256", '
        'String(plan.plan_sha256 ?? ""), "plan_sha256")'
    )
    assert plan_digest_call in source
    assert '"research_intent_sha256"' in source
    assert "수정된 의도는 새 승인이 필요합니다" in source
    assert "이미 승인된 플랜입니다" in source
    assert '"data-action": "create-plan"' in source
    assert '"data-action": "approve-plan"' in source
    assert "플랜 작성" in source


def test_guided_first_run_copy_is_present_and_discloses_isolation() -> None:
    # L01 first-run: zero projects must show a guided panel that names the data
    # root, loopback-only bind, and in_process residual without claiming a
    # sandbox or confinement. Projects present must take the list branch.
    source = (SHIPPED_ROOT / "app.js").read_text(encoding="utf-8")
    styles = (SHIPPED_ROOT / "styles.css").read_text(encoding="utf-8")

    assert "function renderFirstRunGuide" in source
    guide_start = source.index("function renderFirstRunGuide")
    guide_end = source.index("async function renderWorkspace", guide_start)
    guide = source[guide_start:guide_end]

    assert "~/.nipo-science" in guide
    assert "루프백" in guide
    assert "in_process" in guide
    assert (
        'data-isolation": "in_process"' in guide
        or '"data-isolation": "in_process"' in guide
    )
    assert "Keychain" in guide
    assert "첫 프로젝트 만들기" in guide
    assert "모델/제공자 설정 열기" in guide
    assert "#/settings/models" in guide
    assert "create-project-heading" in guide or "new-project-name" in guide
    assert "sandbox" not in guide.lower()
    assert "격리" not in guide
    assert "confinement" not in guide.lower()

    workspace_start = source.index("async function renderWorkspace")
    workspace_end = source.index(
        "// -------------------------------------------------------- project detail --",
        workspace_start,
    )
    workspace = source[workspace_start:workspace_end]

    assert "projects.length === 0" in workspace
    assert "renderFirstRunGuide()" in workspace
    assert 'emptyState("아직 프로젝트가 없습니다"' not in workspace
    # Non-empty list takes the object-list branch; the guide is not on that path.
    assert "projects.map((item) => projectRow(item, reload))" in workspace
    assert (
        "renderFirstRunGuide()"
        not in workspace.split("projects.map((item) => projectRow(item, reload))")[1]
    )

    assert ".first-run-guide" in styles


def _turn_panel_slice(source: str) -> str:
    start = source.index("function turnSection")
    end = source.index(
        "// ---------------------------------------------------------------- export --",
        start,
    )
    return source[start:end]


def test_the_run_detail_screen_has_a_turn_panel() -> None:
    # L10 binds a model turn to the Run: a composer-enabled model picker, a
    # prompt, one synchronous send, and the pinned selection plus recorded
    # turns read back from the run detail projection.
    source = (SHIPPED_ROOT / "app.js").read_text(encoding="utf-8")

    assert "function turnSection" in source
    assert "turnSection(projectId, runId, run, picker)" in source
    assert '"data-turn-panel": "run"' in source

    # The picker is fed by the composer endpoint (enabled models only).
    assert "picker = await api.composer()" in source
    assert "createTurn" in source
    assert "/runs/${rid}/turns" in source

    # Pinned selection display from GET run, with the 고정 badge.
    assert "pinned_provider_id" in source
    assert "pinned_model_id" in source
    assert "모델 고정" in source
    assert "고정된 모델" in source

    # Recorded turns read back from the run detail projection.
    assert "run.turns" in source
    assert '"data-turn-history": "run"' in source

    # Prompt, send, and the synchronous response rendering.
    panel = _turn_panel_slice(source)
    assert '"data-turn-form": "composer"' in panel
    assert '"data-action": "send-turn"' in panel
    assert "전송" in panel
    assert "turn-model" in panel
    assert "turn-prompt" in panel
    assert "max_output_tokens" in panel
    assert "TURN_MAX_OUTPUT_TOKENS" in panel
    assert 'role: "user"' in panel
    assert '"data-turn-transcript": "memory"' in panel
    assert '"data-turn-summary": "last"' in panel
    assert "request_count" in panel

    # Once pinned, the picker shows ONLY the pinned selection, disabled.
    assert "if (panel.pinned) return [{ value: panel.pinned" in panel
    assert 'disabled: panel.busy || panel.pinned !== ""' in panel

    # Conversation text stays in screen memory; nothing touches web storage.
    assert "localStorage" not in panel
    assert "sessionStorage" not in panel


def test_the_turn_panel_has_no_automatic_fallback_affordance() -> None:
    # AC-L10: a failed turn is reported, never rerouted. The panel offers no
    # second-model quick-retry marker and never substitutes a default model
    # for the researcher's explicit choice.
    source = (SHIPPED_ROOT / "app.js").read_text(encoding="utf-8")
    panel = _turn_panel_slice(source)

    assert "data-turn-retry" not in source
    assert "retry" not in panel
    assert "fallback" not in panel.lower()
    assert "다른 모델" not in panel
    assert "다른 제공자" not in panel
    assert "default_model" not in panel
    # Model choice stays explicit: an empty first option, no preselection.
    assert 'el("option", { value: "", text: "선택해 주세요" })' in panel


def test_the_turn_failure_copy_covers_every_closed_token() -> None:
    # The wire speaks closed codes only: `turn_failed` carries one of the
    # eleven ModelCallFailure reason tokens, and the three new codes get
    # their own sentences. An unknown token must fall back to a generic
    # sentence, never to raw provider prose.
    source = (SHIPPED_ROOT / "app.js").read_text(encoding="utf-8")

    start = source.index("const TURN_FAILURE_TEXT")
    end = source.index("};", start)
    failure_map = source[start:end]
    for token in (
        "authentication",
        "rate_limit",
        "quota",
        "model_unavailable",
        "provider_unavailable",
        "invalid_request",
        "timeout",
        "transport",
        "malformed_response",
        "response_too_large",
        "unclassified",
    ):
        assert f"{token}:" in failure_map

    assert "turn_failed" in source
    assert "provider_not_configured" in source
    assert "model_selection_locked" in source
    assert "모델 호출이 실패했습니다" in source
    assert "설정에서 키를 등록하세요" in source
    assert "이 실행은 고정된 모델만 사용합니다" in source

    # Failure rendering goes through the map and lands as textContent only;
    # the turn-failure path itself never interpolates a raw reason token.
    assert "describeTurnFailure" in source
    assert "TURN_CODE_TEXT" in source
    assert '"data-turn-failure": "closed"' in source
    describer_start = source.index("function describeTurnFailure")
    describer_end = source.index(
        "}",
        source.index("return TURN_CODE_TEXT", describer_start),
    )
    assert "error.reason}" not in source[describer_start:describer_end]
    assert "text: panel.failure" in _turn_panel_slice(source)


def test_the_turn_panel_adds_no_inline_styles() -> None:
    # `style-src 'self'` refuses every inline style attribute, so the panel
    # must be class-styled end to end.
    source = (SHIPPED_ROOT / "app.js").read_text(encoding="utf-8")
    styles = (SHIPPED_ROOT / "styles.css").read_text(encoding="utf-8")
    panel = _turn_panel_slice(source)

    assert "style:" not in panel
    assert "style=" not in panel
    assert ".style." not in panel
    assert ".turn-transcript" in styles
    assert ".turn-message" in styles
