from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP = (ROOT / "apps/web/product/app.js").read_text(encoding="utf-8")
CSS = (ROOT / "apps/web/product/styles.css").read_text(encoding="utf-8")
INDEX = (ROOT / "apps/web/product/index.html").read_text(encoding="utf-8")
PACKAGE = (ROOT / "package.json").read_text(encoding="utf-8")
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")
PLAYWRIGHT_CONFIG = (ROOT / "playwright.config.ts").read_text(encoding="utf-8")
PLAYWRIGHT_SPEC = (ROOT / "tests/e2e/artifacts.spec.ts").read_text(encoding="utf-8")


def test_artifact_ui_declares_version_diff_lineage_preview_and_associations() -> None:
    required_copy = (
        "버전 비교",
        "변경 바이트",
        "생성 실행",
        "실행 환경 해시",
        "계보 그래프",
        "세션에 연결",
        "세션 연결 해제",
        "격리 미리보기",
    )
    for phrase in required_copy:
        assert phrase in APP
    for source_contract in (
        "request(`/api/v1/artifacts/${artifactId}${suffix}`)",
        'button("세션에 연결", "attach")',
        'button("세션 연결 해제", "detach", "secondary")',
        'method: action === "detach" ? "DELETE" : "POST"',
        'sandbox: ""',
        'referrerpolicy: "no-referrer"',
        'class: "preview-frame"',
        'class: "preview-status"',
        'class: "lineage-graph"',
        'download: ""',
        'return "about:blank"',
        "artifactActionEpoch",
        "requestEpoch !== artifactActionEpoch",
    ):
        assert source_contract in APP
    assert "innerHTML" not in APP
    assert ".preview-frame" in CSS
    assert ".artifact-layout > .stack" in CSS
    assert "order: -1" in CSS
    assert ".artifact-preview-grid { grid-template-columns:" in CSS
    assert ".preview-status" in CSS
    assert ".lineage-graph" in CSS
    assert ".global-nav a:focus-visible" in CSS
    assert 'class="mobile-nav-hint"' in INDEX
    assert "word-break: keep-all" in CSS


def test_artifact_library_version_controls_and_exact_download_allowlist_exist() -> None:
    for contract in (
        '["/artifacts", "아티팩트"]',
        'request("/api/v1/artifacts")',
        '"data-action": "select-version"',
        '"data-version-id": artifact.id',
        'action === "create-version"',
        "/versions/${versionId}",
        "/versions/${selected.id}/attachments",
        "^\\/api\\/v1\\/artifacts\\/",
        "\\/download$",
    ):
        assert contract in APP
    assert "/artifacts/demo" not in APP
    assert '{ session_id: "session-demo" }' not in APP
    assert "selectedAttachmentSessionId()" in APP
    assert "workspaceSessions" in APP


def test_playwright_acceptance_is_pinned_and_runs_from_the_make_target() -> None:
    assert '"@playwright/test": "1.61.1"' in PACKAGE
    assert "node node_modules/@playwright/test/cli.js test" in MAKEFILE
    assert 'trace: "on"' in PLAYWRIGHT_CONFIG
    for scenario in (
        "page.keyboard.press",
        "async function tabTo",
        "previewCookies.every",
        '"content-security-policy"',
        '"x-content-type-options"',
        "createHash",
        "page.screenshot",
    ):
        assert scenario in PLAYWRIGHT_SPEC
    for viewport in ("mobile-375", "tablet-768", "desktop-1280"):
        assert viewport in PLAYWRIGHT_CONFIG
