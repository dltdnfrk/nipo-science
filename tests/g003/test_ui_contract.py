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
    assert "outline: 3px solid var(--focus)" in CSS
    assert "prefers-reduced-motion: reduce" in CSS
    assert "overflow-x: hidden" in CSS


def test_mineral_notebook_tokens_and_typography_are_preserved() -> None:
    expected_tokens = {
        "--ink-strong": "#23352d",
        "--ink": "#34483d",
        "--ink-muted": "#59665e",
        "--paper": "#fbfaf5",
        "--paper-warm": "#f3f0e7",
        "--paper-accent": "#eef2e8",
        "--rule": "#c9c5b7",
        "--rule-strong": "#8da795",
        "--positive": "#345e48",
        "--attention": "#8a641e",
        "--danger": "#9a3434",
    }
    for name, value in expected_tokens.items():
        assert f"{name}: {value}" in CSS
    assert "font-size: 16px" in CSS
    assert ".meta, .metadata" in CSS
    assert "font-size: 14px" in CSS
    assert "overflow-wrap: anywhere" in CSS
    assert "word-break: break-word" in CSS
    assert re.search(r"\.key-values dd\s*\{[^}]*overflow-wrap: anywhere", CSS)
    assert "linear-gradient" not in CSS
    assert "radial-gradient" not in CSS
    assert "backdrop-filter" not in CSS
    assert not re.search(r"font-size:\s*11px", CSS)
    assert "#6f42c1" not in CSS.lower()


PRODUCT_SOURCE = HTML + JAVASCRIPT


def test_all_routes_and_korean_product_journeys_are_declared() -> None:
    routes = [
        "/workspace",
        "/upload",
        "/runs/demo/approval",
        "/runs/demo",
        "/artifacts",
        "/reviews/demo",
        "/exports/demo",
        "/settings/providers",
    ]
    for route in routes:
        assert route in PRODUCT_SOURCE
    required_copy = [
        "프로젝트",
        "최근 활동",
        "업로드 검증",
        "검증된 미리보기",
        "원자적으로 거부",
        "불변 승인",
        "계획 다이제스트",
        "계획 승인",
        "계획 거절",
        "실행 타임라인",
        "실행 취소",
        "아티팩트 버전",
        "체크섬",
        "계보",
        "검토 발견 사항",
        "재실행하지 않습니다",
        "선택 버전",
        "매니페스트",
        "요청자 소유 연결",
        "자동 대체는 사용하지 않습니다",
        "Codex",
        "자격 검증 전에는 사용할 수 없음",
        "GLM 비활성화",
    ]
    for phrase in required_copy:
        assert phrase in JAVASCRIPT


def test_same_origin_data_contract_and_safe_rendering_are_enforced() -> None:
    assert 'request("/api/v1/me")' in JAVASCRIPT
    assert 'request("/api/v1/workspace")' in JAVASCRIPT
    assert 'credentials: "same-origin"' in JAVASCRIPT
    assert "org_id" not in JAVASCRIPT
    assert "innerHTML" not in JAVASCRIPT
    assert "textContent" in JAVASCRIPT
    assert "replaceChildren" in JAVASCRIPT
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
    assert 'return "/runs/demo/approval"' in JAVASCRIPT
    assert 'return "/artifacts"' in JAVASCRIPT

    endpoints = ("upload", "plan", "approve", "execute", "review", "export", "cleanup")
    for action in endpoints:
        assert f'"/api/v1/dry-lab/{action}"' in JAVASCRIPT
        assert f"{action}:" in JAVASCRIPT
    assert 'request("/api/v1/dry-lab/state")' in JAVASCRIPT
    assert 'method: "POST"' in JAVASCRIPT
    assert '"Content-Type": "application/json"' in JAVASCRIPT
    assert "서버가 작업 완료를 확인했습니다." in JAVASCRIPT
    assert "buttonNode.disabled = true" in JAVASCRIPT
    assert 'function button(label, action, tone = "")' in JAVASCRIPT
    assert 'disabled: ""' not in JAVASCRIPT.split("function providers()", maxsplit=1)[0]


def test_artifact_mobile_alternative_and_900px_layout_collapse_are_declared() -> None:
    assert 'class: "artifact-table"' in JAVASCRIPT
    assert 'class: "artifact-mobile-list"' in JAVASCRIPT
    assert "@media (max-width: 768px)" in CSS
    assert ".artifact-table { display: none; }" in CSS
    assert ".artifact-mobile-list { display: grid;" in CSS
    assert (
        "@media (max-width: 900px) { .section-grid, .artifact-layout > .stack "
        "{ grid-template-columns: 1fr; }"
    ) in CSS


def _relative_luminance(color: str) -> float:
    values = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]

    def linearize(value: float) -> float:
        return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4

    red, green, blue = (linearize(value) for value in values)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def test_muted_text_token_meets_aa_on_warm_and_accent_surfaces() -> None:
    tokens: dict[str, str] = dict(re.findall(r"(--[\w-]+):\s*(#[0-9a-fA-F]{6})", CSS))
    muted = _relative_luminance(tokens["--ink-muted"])
    for surface in ("--paper-warm", "--paper-accent"):
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
