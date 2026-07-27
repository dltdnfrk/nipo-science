from pathlib import Path

import pytest
from tools.platform_policy import saas_quarantine
from tools.platform_policy.saas_quarantine import (
    ALLOWED_REUSE_CLOSURE,
    DELETION_SCHEDULED_MODULES,
    main,
    scan,
)

REPO_ROOT = Path(__file__).parents[2]

_CLOSURE_MODULE_NAMES = (
    "models",
    "runtime",
    "store_contract",
    "memory_recovery",
    "service",
    "watcher",
    "signing",
    "recovery",
    "blob_store",
    "blob_filesystem",
    "file_recovery",
    "file_recovery_storage",
    "store",
)

_SYNTHETIC_ZONE = (
    "services.api.legacy_plane",
    "services.hosted_*",
)


def _write(tmp_path: Path, relative: str, content: str = "") -> None:
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(content, encoding="utf-8")


def _write_minimal_repo(tmp_path: Path) -> None:
    _write(tmp_path, "services/api/artifacts/__init__.py")
    for name in _CLOSURE_MODULE_NAMES:
        _write(tmp_path, f"services/api/artifacts/{name}.py")


def _write_synthetic_zone(tmp_path: Path) -> None:
    _write(tmp_path, "services/api/legacy_plane.py")
    _write(tmp_path, "services/hosted_worker/__init__.py")


@pytest.fixture
def synthetic_zone(monkeypatch: pytest.MonkeyPatch) -> tuple[str, ...]:
    """Reinstate a deletion-scheduled zone to exercise the detection logic."""
    monkeypatch.setattr(
        saas_quarantine, "DELETION_SCHEDULED_MODULES", _SYNTHETIC_ZONE
    )
    return _SYNTHETIC_ZONE


def test_unit_current_repository_satisfies_quarantine() -> None:
    # Given: the real repository tree at Stage 3 (hosted zone fully deleted).

    # When: the quarantine check scans it.
    violations = scan(REPO_ROOT)

    # Then: the closure is intact and the keep side holds no zone import.
    assert violations == ()


def test_unit_deletion_zone_is_empty_after_stage_3() -> None:
    # Given / When: the declared deletion-scheduled inventory.

    # Then: every hosted module retired; nothing is left to schedule.
    assert DELETION_SCHEDULED_MODULES == ()


def test_unit_allowed_closure_includes_indirect_reexport_modules() -> None:
    # Given / When: the declared nipo_local reuse closure.

    # Then: the __init__ re-export closure and signing are pinned by name.
    expected = {
        "services.api.artifacts.blob_store",
        "services.api.artifacts.blob_filesystem",
        "services.api.artifacts.file_recovery",
        "services.api.artifacts.file_recovery_storage",
        "services.api.artifacts.store",
        "services.api.artifacts.signing",
    }
    assert expected <= ALLOWED_REUSE_CLOSURE


def test_unit_minimal_keep_side_repo_passes(tmp_path: Path) -> None:
    # Given: a keep-side tree importing only closure modules.
    _write_minimal_repo(tmp_path)
    _write(
        tmp_path,
        "apps/local/nipo_local/app.py",
        "from services.api.artifacts.models import ArtifactScope\n"
        "from services.api.artifacts import store_contract\n",
    )

    # When / Then: no violation is reported.
    assert scan(tmp_path) == ()


@pytest.mark.usefixtures("synthetic_zone")
def test_unit_saas_zone_internal_imports_are_allowed(tmp_path: Path) -> None:
    # Given: zone modules importing each other inside a scheduled zone.
    _write_minimal_repo(tmp_path)
    _write_synthetic_zone(tmp_path)
    _write(
        tmp_path,
        "services/api/legacy_plane.py",
        "import services.hosted_worker\n",
    )

    # When / Then: intra-zone imports are not flagged (the zone goes wholesale).
    assert scan(tmp_path) == ()


@pytest.mark.usefixtures("synthetic_zone")
@pytest.mark.parametrize(
    "statement",
    [
        "from services.api.legacy_plane import run_server\n",
        "import services.api.legacy_plane\n",
        "from services.api import legacy_plane\n",
        "import services.hosted_worker\n",
    ],
    ids=(
        "from-module",
        "plain-import",
        "package-alias",
        "pattern-match",
    ),
)
def test_security_keep_side_saas_import_is_rejected(
    tmp_path: Path,
    statement: str,
) -> None:
    # Given: nipo_local code importing a deletion-scheduled module.
    _write_minimal_repo(tmp_path)
    _write_synthetic_zone(tmp_path)
    _write(tmp_path, "apps/local/nipo_local/app.py", statement)

    # When: the quarantine check scans the tree.
    violations = scan(tmp_path)

    # Then: the forbidden import is detected and named.
    assert any(
        violation.startswith("saas-quarantine-import:apps/local/nipo_local/app.py")
        for violation in violations
    )


@pytest.mark.usefixtures("synthetic_zone")
def test_security_closure_module_importing_saas_module_is_rejected(
    tmp_path: Path,
) -> None:
    # Given: a closure module reaching into the scheduled zone via relative import.
    _write_minimal_repo(tmp_path)
    _write_synthetic_zone(tmp_path)
    _write(
        tmp_path,
        "services/api/artifacts/service.py",
        "from ..legacy_plane import run_server\n",
    )

    # When: the quarantine check scans the tree.
    violations = scan(tmp_path)

    # Then: the closure drift is detected.
    assert violations == (
        "saas-quarantine-import:services/api/artifacts/service.py:"
        "services.api.legacy_plane",
    )


def test_security_unclassified_services_import_is_rejected(tmp_path: Path) -> None:
    # Given: keep-side code importing a services.api module in neither inventory.
    _write_minimal_repo(tmp_path)
    _write(
        tmp_path,
        "apps/local/nipo_local/app.py",
        "import services.api.unknown_future_module\n",
    )

    # When: the quarantine check scans the tree.
    violations = scan(tmp_path)

    # Then: the inventory gap is reported instead of passing silently.
    assert violations == (
        "saas-quarantine-unclassified:apps/local/nipo_local/app.py:"
        "services.api.unknown_future_module",
    )


def test_unit_missing_closure_module_is_reported(tmp_path: Path) -> None:
    # Given: a keep-side tree with one closure module deleted.
    _write_minimal_repo(tmp_path)
    (tmp_path / "services/api/artifacts/signing.py").unlink()

    # When: the quarantine check scans the tree.
    violations = scan(tmp_path)

    # Then: the accidental closure deletion is reported.
    assert "saas-quarantine-missing-closure:services.api.artifacts.signing" in (
        violations
    )


@pytest.mark.usefixtures("synthetic_zone")
def test_unit_stale_deletion_pattern_is_reported(tmp_path: Path) -> None:
    # Given: a scheduled zone whose modules were deleted without an update.
    _write_minimal_repo(tmp_path)

    # When: the quarantine check scans the tree.
    violations = scan(tmp_path)

    # Then: every stale pattern forces an inventory update in the same commit.
    assert "saas-quarantine-stale-pattern:services.api.legacy_plane" in violations
    assert "saas-quarantine-stale-pattern:services.hosted_*" in violations


def test_unit_cli_reports_violations_and_clean_trees(tmp_path: Path) -> None:
    # Given: a clean minimal repo and a copy with an unclassified import.
    _write_minimal_repo(tmp_path)

    # When / Then: the CLI passes the clean tree.
    assert main([str(tmp_path)]) == 0

    # When: an unclassified services.api import is added.
    _write(
        tmp_path,
        "apps/local/nipo_local/app.py",
        "import services.api.unknown_future_module\n",
    )

    # Then: the CLI fails.
    assert main([str(tmp_path)]) == 1


def test_unit_cli_usage_paths(tmp_path: Path) -> None:
    # Given / When / Then: help, extra arguments, and missing roots.
    assert main(["--help"]) == 0
    assert main([str(tmp_path), "extra"]) == 2
    assert main([str(tmp_path / "missing")]) == 2
