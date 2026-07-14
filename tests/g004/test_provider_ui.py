"""Static contract checks for the provider settings product surface."""

import shutil
import subprocess
from pathlib import Path

SOURCE = (
    Path(__file__).resolve().parents[2] / "apps" / "web" / "product" / "app.js"
)
STYLES = (
    Path(__file__).resolve().parents[2] / "apps" / "web" / "product" / "styles.css"
)


def test_provider_lifecycle_uses_canonical_same_origin_endpoints_and_headers() -> None:
    source = SOURCE.read_text(encoding="utf-8")

    for endpoint in (
        "/api/v1/provider-connections/registry",
        '"/api/v1/provider-connections"',
        "/api/v1/provider-connections/oauth/cancel",
        "/model",
        "/health",
        "/reauth",
    ):
        assert endpoint in source
    assert 'headers["Idempotency-Key"]' in source
    assert 'headers["If-Match"]' in source
    assert 'adapter_id: "openai_codex", flow: "callback", redirect_uri: "/settings/providers"' in source
    assert 'if (method === "POST")' in source


def test_only_openai_has_connect_action_and_glm_has_exact_disabled_reason() -> None:
    source = SOURCE.read_text(encoding="utf-8")

    assert 'id: "provider-connect-openai_codex"' in source
    assert 'adapter.adapter_id === "openai_codex" && !connection' in source
    for adapter_id in (
        "anthropic_claude_code",
        "xai_grok_build",
        "moonshot_kimi_code",
        "zai_glm",
    ):
        assert adapter_id in source
    assert 'adapter.adapter_id === "zai_glm" ? "unsupported_auth"' in source
    assert 'adapter.adapter_id === "openai_codex" || adapter.qualified === true' in source


def test_provider_surface_uses_safe_dom_and_exposes_korean_lifecycle_copy() -> None:
    source = SOURCE.read_text(encoding="utf-8")

    assert "textContent" in source
    assert "innerHTML" not in source
    assert "localStorage" not in source
    assert "sessionStorage" not in source
    assert "api_key" not in source.lower()
    assert "OAuth 구독 연결만 사용합니다" in source
    assert "자동 대체는 하지 않습니다" in source
    assert "민감정보가 제외된 정리 영수증" in source
    assert "provider-authorization-link" in source
    assert "providerAuthorization?.state" in source
    assert "text: providerAuthorization?.state" not in source
    assert "href: authorization" in source


def test_provider_cards_have_responsive_status_styling() -> None:
    styles = STYLES.read_text(encoding="utf-8")

    assert ".provider-grid" in styles
    assert ".provider-card" in styles
    assert ".provider-card:has(.status.positive)" in styles
    assert ".provider-grid { grid-template-columns: 1fr; }" in styles

def test_provider_source_has_node_syntax_contract() -> None:
    node = shutil.which("node")
    if node is None:
        return
    result = subprocess.run(
        [node, "--check", str(SOURCE)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
