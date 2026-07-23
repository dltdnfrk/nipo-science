from __future__ import annotations

import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from typing import TypedDict, cast, override

ROOT = Path(__file__).resolve().parents[2]
PRODUCT = ROOT / "apps" / "web" / "product"
HTML = (PRODUCT / "index.html").read_text(encoding="utf-8")
CSS = (PRODUCT / "styles.css").read_text(encoding="utf-8")
JAVASCRIPT = (PRODUCT / "app.js").read_text(encoding="utf-8")
PROVIDER_RUNTIME_CONFIGURATION = (
    ROOT / "services" / "api" / "provider_runtime_configuration.py"
).read_text(encoding="utf-8")
PRODUCT_DRY_LAB = (ROOT / "services" / "api" / "product_dry_lab.py").read_text(
    encoding="utf-8"
)


class _Markup(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.starts: list[tuple[str, dict[str, str | None]]] = []

    @override
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.starts.append((tag, dict(attrs)))


class _NodeEngines(TypedDict):
    node: str


class _PackageManifest(TypedDict):
    engines: _NodeEngines


def test_product_shell_has_semantic_landmarks_and_accessible_bootstrap() -> None:
    parser = _Markup()
    parser.feed(HTML)
    tags = [tag for tag, _ in parser.starts]
    assert "main" in tags
    assert "nav" in tags
    assert "aside" in tags
    assert tags.count("h1") == 1
    assert 'href="#main-content"' in HTML
    assert 'id="main-content"' in HTML
    assert 'aria-live="polite"' in HTML
    assert 'role="alert"' in HTML
    assert (
        '<meta name="viewport" content="width=device-width, initial-scale=1">' in HTML
    )
    assert ":focus-visible" in CSS
    assert "outline: 2px solid var(--signal-300)" in CSS
    assert "prefers-reduced-motion: reduce" in CSS
    assert "overflow-x: hidden" in CSS


def test_spectral_control_room_tokens_and_typography_are_preserved() -> None:
    expected_tokens = {
        "--canvas": "#07090d",
        "--surface-1": "#0f141c",
        "--surface-2": "#151c27",
        "--surface-3": "#1b2431",
        "--text-strong": "#f4f7fb",
        "--text": "#d2dae5",
        "--text-muted": "#91a0b2",
        "--signal-100": "#d7fff3",
        "--signal-300": "#82f2cc",
        "--signal-500": "#39d9ac",
        "--attention": "#f2c66d",
        "--danger": "#ff8a84",
    }
    for name, value in expected_tokens.items():
        assert f"{name}: {value}" in CSS
    assert "font-size: 16px" in CSS
    assert "--font-ui:" in CSS
    assert "--font-mono:" in CSS
    assert "overflow-wrap: anywhere" in CSS
    assert "linear-gradient" in CSS
    assert "radial-gradient" in CSS
    assert ".workspace-hero" in CSS
    assert ".signal-trace" in CSS
    assert ".metric-strip" in CSS
    assert "#6f42c1" not in CSS.lower()


PRODUCT_SOURCE = HTML + JAVASCRIPT


def test_all_routes_and_korean_product_journeys_are_declared() -> None:
    routes = [
        "/workspace",
        "/upload",
        "/artifacts",
        "/settings/providers",
    ]
    for route in routes:
        assert route in PRODUCT_SOURCE
    required_copy = [
        "프로젝트",
        "최근 활동",
        "업로드 검증",
        "검증된 미리보기",
        "원자적으로",
        "거부됩니다",
        "불변 승인",
        "계획 다이제스트",
        "실행 타임라인",
        "아티팩트 버전",
        "체크섬",
        "계보",
        "검토 발견 사항",
        "재실행하지",
        "않습니다",
        "포함된 경로",
        "매니페스트",
        "요청자 소유 연결",
        "자동 대체",
        "없음",
    ]
    for phrase in required_copy:
        assert phrase in JAVASCRIPT
    for server_owned_phrase in ("계획 승인", "승인된 계획 실행", "검토 결과 생성"):
        assert server_owned_phrase in PRODUCT_DRY_LAB
    for server_owned_phrase in (
        "OpenAI Codex",
        "자격 검증 전에는 사용할\\u00a0수\\u00a0없음",
        "GLM 비활성화",
    ):
        assert server_owned_phrase in PROVIDER_RUNTIME_CONFIGURATION


def test_same_origin_data_contract_and_safe_rendering_are_enforced() -> None:
    assert 'request("/api/v1/me")' in JAVASCRIPT
    assert 'request("/api/v1/workspace")' in JAVASCRIPT
    assert 'credentials: "same-origin"' in JAVASCRIPT
    assert "org_id" not in JAVASCRIPT
    assert "innerHTML" not in JAVASCRIPT
    assert "textContent" in JAVASCRIPT
    assert "replaceChildren" in JAVASCRIPT
    assert 'sandbox: "allow-same-origin"' in JAVASCRIPT
    assert "new ResizeObserver(resizePreview)" in JAVASCRIPT
    assert 'headers["X-CSRF-Token"] = csrfToken' in JAVASCRIPT
    assert "csrfToken = identity.csrf_token" in JAVASCRIPT
    assert "unauthorized" not in JAVASCRIPT
    for disallowed in ("api_key", "password", "secret", "bearer "):
        assert disallowed not in (HTML + CSS + JAVASCRIPT).lower()


def test_dynamic_resource_routes_and_dry_lab_actions_are_declared() -> None:
    route_patterns = (
        r"/^\/runs\/[A-Za-z0-9._-]+\/approval$/",
        r"/^\/runs\/[A-Za-z0-9._-]+$/",
        r"/^\/artifacts\/[A-Za-z0-9._-]+$/",
        r"/^\/reviews\/[A-Za-z0-9._-]+$/",
        r"/^\/exports\/[A-Za-z0-9._-]+$/",
    )
    for pattern in route_patterns:
        assert pattern in JAVASCRIPT
    assert "function selectRoute(path)" in JAVASCRIPT
    assert 'return "/artifacts"' in JAVASCRIPT
    assert "refreshNamedResource(path)" in JAVASCRIPT
    assert "/runs/demo" not in JAVASCRIPT
    assert "/reviews/demo" not in JAVASCRIPT
    assert "/exports/demo" not in JAVASCRIPT
    assert "/runs/demo" not in HTML
    assert "/reviews/demo" not in HTML
    assert "/exports/demo" not in HTML
    assert "2147483647" not in JAVASCRIPT
    assert "MAX_TIMER_DELAY_MS" in JAVASCRIPT
    assert (
        "56fe0a7cb28d03fdd54f0f920a6616bb9ac33cbec8046955dc2a841497d27d20"
        not in JAVASCRIPT
    )
    assert 'text("wavelength,intensity' not in JAVASCRIPT
    assert 'accept: ".csv,text/csv"' in JAVASCRIPT
    assert ".tsv" not in JAVASCRIPT
    assert ".xlsx" not in JAVASCRIPT
    assert "CSV, JSON, Markdown, PNG 결과" in JAVASCRIPT
    assert "CSV, PNG, PDF 결과" not in JAVASCRIPT

    assert 'action.href === "/api/v1/runs"' in JAVASCRIPT
    assert "action.href === `/api/v1/runs/${runId}/${action.id}`" in JAVASCRIPT
    assert 'method !== "POST"' in JAVASCRIPT
    assert 'request("/api/v1/dry-lab/state")' not in JAVASCRIPT
    assert "/api/v1/dry-lab/upload" not in JAVASCRIPT
    assert "/api/v1/dry-lab/plan" not in JAVASCRIPT
    assert "/api/v1/dry-lab/" not in JAVASCRIPT
    assert 'method: "POST"' in JAVASCRIPT
    assert '"Content-Type": "application/json"' in JAVASCRIPT
    assert "서버가 작업 완료를 확인했습니다." in JAVASCRIPT
    assert "buttonNode.disabled = true" in JAVASCRIPT
    assert 'function button(label, action, tone = "")' in JAVASCRIPT
    assert 'text: "모드 선택"' in JAVASCRIPT
    assert 'text: "출처 선택"' in JAVASCRIPT
    assert 'id: "dry-lab-file-name"' in JAVASCRIPT


def test_research_intent_is_user_authored_and_sent_with_plan_creation() -> None:
    for field_id in (
        "research-question",
        "research-rationale",
        "research-benefit",
        "research-success-criteria",
        "research-constraints",
        "research-stop-conditions",
        "research-mode",
        "research-data-origin",
        "research-generator-ref",
        "research-validator-ref",
    ):
        assert field_id in JAVASCRIPT
    for phrase in (
        "왜 이 연구인가",
        "성공 기준",
        "중단 조건",
        "실데이터와 합성데이터",
    ):
        assert phrase in JAVASCRIPT
    assert "function researchIntentPayload()" in JAVASCRIPT
    assert "research_intent: researchIntentPayload()" in JAVASCRIPT
    assert 'id: "run-execution-target"' in JAVASCRIPT
    assert "function selectedExecutionTarget()" in JAVASCRIPT
    assert "...selectedExecutionTarget()" in JAVASCRIPT
    assert 'execution_mode: "provider_model"' in JAVASCRIPT
    assert "provider_model POST" not in JAVASCRIPT
    assert JAVASCRIPT.count('value: "", disabled: "", selected: ""') == 2


def test_review_copy_preserves_rejected_server_verdicts() -> None:
    assert 'const verified = reviewState.verdict === "verified";' in JAVASCRIPT
    assert 'status(reviewState.verdict, verified ? "positive" : "danger")' in JAVASCRIPT
    assert 'phrase("실행 결과 또는")' in JAVASCRIPT
    assert "고정된 체크섬의 불일치를 발견했습니다." in JAVASCRIPT


def test_research_intent_ui_preserves_boundary_whitespace_for_server_rejection() -> (
    None
):
    # The client may validate emptiness, but it must not silently rewrite human intent.
    helpers_source = JAVASCRIPT.split("function requiredFieldValue", 1)[1].split(
        "function researchIntentPayload()", 1
    )[0]
    assert ".trim()" not in helpers_source


def test_provider_ui_uses_only_server_registry_state_and_completes_callback() -> None:
    assert "adapterDefaults" not in JAVASCRIPT
    assert "registered.adapter_id === adapter.adapter_id" not in JAVASCRIPT
    assert 'connectable: adapter.adapter_id === "openai_codex"' not in JAVASCRIPT
    assert (
        'adapter.adapter_id === "openai_codex" || adapter.qualified' not in JAVASCRIPT
    )
    assert "connection?.health?.status" not in JAVASCRIPT
    assert "connection?.qualification?.status" not in JAVASCRIPT
    assert "function completeProviderCallback()" in JAVASCRIPT
    assert 'providerRequest("/api/v1/provider-connections/oauth/complete"' in JAVASCRIPT
    assert "new URLSearchParams(location.search)" in JAVASCRIPT
    assert "history.replaceState" in JAVASCRIPT


def test_provider_authorization_policy_is_deployment_injected_and_fail_closed() -> (
    None
):
    assert (
        '<meta name="product-provider-authorization-policy" '
        'content="__PRODUCT_PROVIDER_AUTHORIZATION_POLICY__">' in HTML
    )
    assert "function providerAuthorizationPolicy()" in JAVASCRIPT
    assert "function canonicalProviderAuthorizationEndpoint(raw)" in JAVASCRIPT
    assert "https://provider.example.test/authorize" not in JAVASCRIPT
    assert "PROVIDER_AUTHORIZATION_ENDPOINTS[adapterId]" in JAVASCRIPT


def test_dry_lab_mutations_target_the_server_issued_run() -> None:
    assert "function requiredRunId()" in JAVASCRIPT
    assert "const approvalTokens = new Map();" in JAVASCRIPT
    assert 'const runId = action === "create-run" ? "" : requiredRunId();' in JAVASCRIPT
    assert "payload.run_id =" not in JAVASCRIPT
    assert "payload.token = requiredApprovalToken();" in JAVASCRIPT
    assert "approvalTokens.set(runId, response.token);" in JAVASCRIPT
    assert "localStorage" not in JAVASCRIPT
    assert "sessionStorage" not in JAVASCRIPT
    assert (
        'input: { filename: file.name, media_type: "text/csv", '
        "content: await file.text() }"
    ) in JAVASCRIPT
    assert "dryLabState = validateDryLabResource(response);" in JAVASCRIPT
    assert (
        "dryLabState = response.state || response;\n      await refreshDryLabState();"
        not in JAVASCRIPT
    )


def test_artifact_mobile_alternative_and_responsive_layout_collapse_are_declared() -> None:
    assert 'class: "artifact-table"' in JAVASCRIPT
    assert 'class: "artifact-mobile-list"' in JAVASCRIPT
    assert "@media (max-width: 767px)" in CSS
    assert ".artifact-table { display: none; }" in CSS
    assert ".artifact-mobile-list { display: grid;" in CSS
    assert "@media (max-width: 1023px)" in CSS
    assert ".section-grid.artifact-layout" in CSS
    assert "grid-template-columns: 1fr;" in CSS


def _relative_luminance(color: str) -> float:
    values = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]

    def linearize(value: float) -> float:
        return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4

    red, green, blue = (linearize(value) for value in values)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def test_muted_text_token_meets_aa_on_graphite_surfaces() -> None:
    tokens: dict[str, str] = dict(re.findall(r"(--[\w-]+):\s*(#[0-9a-fA-F]{6})", CSS))
    muted = _relative_luminance(tokens["--text-muted"])
    for surface in ("--canvas", "--surface-1", "--surface-2"):
        background = _relative_luminance(tokens[surface])
        ratio = (max(muted, background) + 0.05) / (min(muted, background) + 0.05)
        assert ratio >= 4.5


def test_product_script_parses_with_the_repository_locked_node() -> None:
    package = cast(
        "_PackageManifest",
        json.loads((ROOT / "package.json").read_text(encoding="utf-8")),
    )
    assert package["engines"]["node"] == "24.17.0"
    node_executable = shutil.which("node")
    assert node_executable is not None
    node_path = Path(node_executable).resolve()
    result = subprocess.run(
        [str(node_path), "--check", str(PRODUCT / "app.js")],
        check=False,
        capture_output=True,
    )
    stderr = result.stderr.decode("utf-8", errors="replace")
    assert result.returncode == 0, stderr


def test_design_contract_precedes_product_routes() -> None:
    design = (ROOT / "DESIGN.md").read_text(encoding="utf-8")
    reference = ROOT / "docs" / "design" / "reference-mineral-notebook.svg"
    _ = ET.parse(reference)  # noqa: S314  # Trusted checked-in design SVG.
    required = (
        "Selected generated reference",
        "Greenfield landscape study",
        "Mineral Notebook",
        "375",
        "768",
        "1280",
        "WCAG 2.2 AA",
        "Korean/CJK",
        "Product screens must not predate",
    )
    for requirement in required:
        assert requirement in design
