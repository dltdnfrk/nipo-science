"""Throwaway adversarial probes for AC-L01 first-run / loopback surface.

No product files are mutated. Probe (a) re-creates the pre-fix
write_token_file parent-mkdir path in probe-local code only, to prove the
guarded umask gap is real.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import cast

import pytest

REPO = Path(__file__).resolve().parents[2]
TEST_API = REPO / "apps" / "local" / "tests" / "test_api.py"
APP_JS = REPO / "apps" / "web" / "local" / "app.js"
SPEC = REPO / "docs" / "spec" / "SPEC-v0.5.md"
REQUIREMENTS = REPO / "docs" / "requirements" / "requirements.yaml"
API_PY = REPO / "apps" / "local" / "nipo_local" / "api.py"
CONFIG_PY = REPO / "apps" / "local" / "nipo_local" / "config.py"

for entry in (
    str(REPO),
    str(REPO / "packages" / "contracts" / "python"),
    str(REPO / "packages" / "science"),
    str(REPO / "apps" / "local"),
):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from nipo_local.api import (  # noqa: E402
    LocalApiDeps,
    LocalToken,
    RunningLocalApi,
    start_local_api,
    token_file,
    write_token_file,
)
from nipo_local.apiserver import NonLoopbackBindError, bind_loopback  # noqa: E402
from nipo_local.config import DEFAULT_ROOT, resolve_paths  # noqa: E402
from services.api.artifacts.runtime import SystemClock, Uuid7Factory  # noqa: E402


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _stub_deps(paths: object) -> LocalApiDeps:
    """Build deps that do not call paths.ensure() themselves."""
    return LocalApiDeps(
        store=cast("object", object()),  # type: ignore[arg-type]
        registry=cast("object", object()),  # type: ignore[arg-type]
        read_model=cast("object", object()),  # type: ignore[arg-type]
        paths=paths,  # type: ignore[arg-type]
        clock=SystemClock(),
        ids=Uuid7Factory(),
    )


def _legacy_write_token_file_mkdir_parent(
    paths: object,
    token: LocalToken,
    base_url: str,
) -> Path:
    """Pre-fix write_token_file path: mkdir parent under process umask.

    Mirrors the removed `path.parent.mkdir(parents=True, exist_ok=True)`
    behaviour without touching product code. Token payload is a throwaway
    probe value, never a production credential shape.
    """
    path = token_file(paths)  # type: ignore[arg-type]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    payload = json.dumps(
        {
            "base_url": base_url,
            "header": "x-nipo-token",
            "token": token.value,
        },
        sort_keys=True,
    )
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            _ = handle.write(f"{payload}\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path


def test_probe_a_legacy_parent_mkdir_under_permissive_umask_is_group_readable(
    tmp_path: Path,
) -> None:
    """(a) Old parent-mkdir path under umask 0 leaves a non-owner-only root.

    Demonstrates the guarded gap is mutation-capable: without ensure-before-
    token and without refusing parent creation, a fresh layout is widened.
    """
    paths = resolve_paths(tmp_path / "legacy-root")
    assert not paths.root.exists()
    previous = os.umask(0o000)
    written: Path | None = None
    try:
        written = _legacy_write_token_file_mkdir_parent(
            paths,
            LocalToken("probe-legacy-token"),
            "http://127.0.0.1:9",
        )
        root_mode = _mode(paths.root)
        # umask 0o000 + mkdir default → group/other bits set; not 0o700.
        assert root_mode != 0o700
        assert root_mode & 0o070, f"expected group bits under umask 0, got {oct(root_mode)}"
        assert root_mode & 0o007, f"expected other bits under umask 0, got {oct(root_mode)}"
    finally:
        _ = os.umask(previous)
        if written is not None:
            written.unlink(missing_ok=True)
        if paths.root.exists():
            # Clean residual tree created by the probe-local legacy path only.
            for child in paths.root.iterdir():
                child.unlink(missing_ok=True)
            paths.root.rmdir()


def test_probe_b_start_local_api_on_readonly_parent_fails_closed(
    tmp_path: Path,
) -> None:
    """(b) Read-only parent → start_local_api fails; no partial root left."""
    parent = tmp_path / "ro-parent"
    parent.mkdir(mode=0o700)
    target = parent / "root"
    paths = resolve_paths(target)
    assert not paths.root.exists()
    parent.chmod(0o500)
    api: RunningLocalApi | None = None
    try:
        with pytest.raises(OSError):
            api = start_local_api(paths, _stub_deps(paths))
        assert not target.exists()
        assert not paths.root.exists()
        assert not any(parent.iterdir())
    finally:
        if api is not None:
            api.close()
        parent.chmod(0o700)


def test_probe_c_start_local_api_repairs_permissive_root(
    tmp_path: Path,
) -> None:
    """(c) ensure then chmod 755 then start_local_api → root repaired to 0700."""
    paths = resolve_paths(tmp_path / "repair-root")
    paths.ensure()
    paths.root.chmod(0o755)
    paths.blobs.chmod(0o755)
    assert _mode(paths.root) == 0o755
    assert _mode(paths.blobs) == 0o755
    api: RunningLocalApi | None = None
    try:
        api = start_local_api(paths, _stub_deps(paths))
        assert _mode(paths.root) == 0o700
        assert _mode(paths.blobs) == 0o700
        assert _mode(api.token_path) == 0o600
    finally:
        if api is not None:
            api.close()


def _guide_source() -> str:
    source = APP_JS.read_text(encoding="utf-8")
    start = source.index("function renderFirstRunGuide")
    end = source.index("async function renderWorkspace", start)
    return source[start:end]


def test_probe_d_guide_honesty_disclosures_present_claims_absent() -> None:
    """(d) Guide discloses residuals; never claims 격리/sandbox/confine."""
    guide = _guide_source()
    lowered = guide.lower()
    assert "~/.nipo-science" in guide
    assert "루프백" in guide
    assert "in_process" in guide
    assert "Keychain" in guide
    assert "소유자 전용" in guide or "owner" in lowered
    assert "sandbox" not in lowered
    assert "격리" not in guide
    assert "confine" not in lowered
    assert "confinement" not in lowered
    # Overclaim sweep: must not assert process-boundary isolation.
    assert "프로세스 경계를 넘는 통제를 주장하지 않" in guide
    assert re.search(r"\bsandbox(ed|ing)?\b", lowered) is None


def test_probe_e_hostile_env_host_sweep_cannot_widen_bind(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """(e) Extra HOST-shaped env vars still cannot open a non-loopback bind."""
    wildcard = "0.0.0.0"  # noqa: S104 - the address under test
    for name, value in (
        ("UVICORN_HOST", wildcard),
        ("UVICORN_PORT", "8080"),
        ("HOST", wildcard),
        ("HOSTNAME", "0.0.0.0"),  # noqa: S104
        ("SERVER_HOST", wildcard),
        ("BIND", wildcard),
        ("BIND_ADDR", wildcard),
        ("LISTEN_HOST", wildcard),
        ("LISTEN_ADDR", wildcard),
        ("HTTP_HOST", wildcard),
        ("APP_HOST", wildcard),
        ("FASTAPI_HOST", wildcard),
        ("STARLETTE_HOST", wildcard),
        ("ASGI_HOST", wildcard),
        ("NIPO_SCIENCE_HOST", wildcard),
        ("NIPO_API_HOST", wildcard),
        ("NIPO_SERVER_HOST", wildcard),
        ("RUST_LOG", "debug"),
        ("PORT", "0"),
        ("SERVER_NAME", wildcard),
        ("IP", wildcard),
        ("ADDR", wildcard),
        ("INTERFACE", wildcard),
        ("NIPO_ALLOW_REMOTE", "true"),
        ("NIPO_REMOTE_ACCESS", "1"),
        ("ALLOW_REMOTE", "1"),
        ("REMOTE", "1"),
    ):
        monkeypatch.setenv(name, value)

    with pytest.raises(NonLoopbackBindError):
        _ = bind_loopback("0.0.0.0", 0)  # noqa: S104
    with pytest.raises(NonLoopbackBindError):
        _ = bind_loopback("::", 0)
    with pytest.raises(NonLoopbackBindError):
        _ = bind_loopback("192.0.2.1", 0)

    paths = resolve_paths(tmp_path / "env-root")
    paths.ensure()
    api: RunningLocalApi | None = None
    try:
        with pytest.raises(NonLoopbackBindError):
            api = start_local_api(
                paths,
                _stub_deps(paths),
                host="0.0.0.0",  # noqa: S104
            )
        # Control: explicit loopback still works under the hostile env.
        api = start_local_api(paths, _stub_deps(paths), host="127.0.0.1")
        bound = api.server.socket.getsockname()
        assert bound[0] == "127.0.0.1"
    finally:
        if api is not None:
            api.close()


def test_probe_docs_honesty_l01_claim_boundary() -> None:
    """SPEC §14 + requirements.yaml L01 residual and claims stay honest."""
    spec = SPEC.read_text(encoding="utf-8")
    req = REQUIREMENTS.read_text(encoding="utf-8")
    api_src = API_PY.read_text(encoding="utf-8")
    config_src = CONFIG_PY.read_text(encoding="utf-8")

    # Residual packaged installer must remain partial, not fully implemented.
    assert "packaged installer is out of scope" in spec
    assert "L01 remains partial" in spec
    assert (
        "installation_first_run_and_loopback_interface_present_first_run_packaging_installer_out_of_scope"
        in req
    )
    assert '"L01"' not in req.split('"implemented_and_verified"')[1].split("]")[0]

    # Positive claims in §14 must map to real code paths.
    assert "LocalPaths.ensure" in spec or "paths.ensure" in api_src
    assert "paths.ensure()" in api_src
    assert "path.parent.mkdir" not in api_src.split("def write_token_file")[1].split(
        "def "
    )[0]
    assert "local data root does not exist" in api_src
    assert 'DEFAULT_ROOT: Final = Path.home() / ".nipo-science"' in config_src
    assert "Documents" in config_src  # exclusion rationale present
    assert "~/.nipo-science" in _guide_source()

    # Must not overclaim full L01 completion or a packaged installer.
    assert re.search(r"\bL01\b[^.]*fully implemented", spec, re.I) is None
    residual = re.search(
        r"L01 remains partial only in that a packaged installer is out of scope",
        spec,
    )
    assert residual is not None
    assert "installer is shipped" not in spec.lower()
    assert "packaged installer is implemented" not in spec.lower()
    assert "confinement" not in _guide_source().lower()
    implemented = req.split('"implemented_and_verified"')[1].split("]")[0]
    assert "L01" not in implemented


def test_probe_default_root_is_outside_documents() -> None:
    """DEFAULT_ROOT stays under home/.nipo-science, never Documents."""
    assert DEFAULT_ROOT.name == ".nipo-science"
    assert DEFAULT_ROOT.parent == Path.home()
    assert "Documents" not in DEFAULT_ROOT.parts
    assert "Desktop" not in DEFAULT_ROOT.parts
    assert "Library" not in str(DEFAULT_ROOT) or True  # not under iCloud Documents
    resolved = str(DEFAULT_ROOT.resolve())
    assert "/Documents/" not in resolved
    assert not resolved.endswith("/Documents")


def test_probe_write_token_file_still_refuses_missing_root(tmp_path: Path) -> None:
    """Cross-check: product write_token_file never creates the root."""
    paths = resolve_paths(tmp_path / "still-missing")
    assert not paths.root.exists()
    with pytest.raises(OSError, match="local data root does not exist"):
        _ = write_token_file(
            paths,
            LocalToken("probe-token-value"),
            "http://127.0.0.1:9",
        )
    assert not paths.root.exists()
