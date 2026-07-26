from pathlib import Path

import pytest
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

_DELETION_FILES = (
    "services/api/product_app.py",
    "services/api/provider_runtime.py",
    "services/api/tool_governance.py",
    "services/api/connector_registry.py",
    "services/api/bounded_http.py",
    "services/api/artifact_ui_app.py",
    "services/api/artifact_production_app.py",
    "services/api/dry_lab_fixture.py",
    "services/api/persistence/__init__.py",
    "services/api/upload/__init__.py",
    "services/api/migrations/__init__.py",
    "services/api/artifacts/composition.py",
    "services/api/artifacts/http.py",
    "services/api/artifacts/scope_resolver.py",
    "services/api/artifacts/postgres_store.py",
    "services/local/__init__.py",
    "services/worker/__init__.py",
)


def _write(tmp_path: Path, relative: str, content: str = "") -> None:
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(content, encoding="utf-8")


def _write_minimal_repo(tmp_path: Path) -> None:
    for relative in _DELETION_FILES:
        _write(tmp_path, relative)
    _write(tmp_path, "services/api/artifacts/__init__.py")
    for name in _CLOSURE_MODULE_NAMES:
        _write(tmp_path, f"services/api/artifacts/{name}.py")


def test_unit_current_repository_satisfies_quarantine() -> None:
    # Given: the real repository tree at Stage 0 (no deletion has landed).

    # When: the quarantine check scans it.
    violations = scan(REPO_ROOT)

    # Then: the keep side holds no SaaS import and the inventory is current.
    assert violations == ()


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


def test_unit_saas_zone_internal_imports_are_allowed(tmp_path: Path) -> None:
    # Given: SaaS zone modules importing each other inside the zone.
    _write_minimal_repo(tmp_path)
    _write(
        tmp_path,
        "services/api/product_app.py",
        "import services.api.provider_runtime\n",
    )

    # When / Then: intra-zone imports are not flagged (the zone goes wholesale).
    assert scan(tmp_path) == ()


@pytest.mark.parametrize(
    "statement",
    [
        "from services.api.product_app import create_app\n",
        "import services.api.provider_runtime\n",
        "from services.api.artifacts import postgres_store\n",
        "import services.local.scanner\n",
        "from services.api.persistence import auth_sessions\n",
    ],
    ids=(
        "from-module",
        "plain-import",
        "package-alias",
        "services-local",
        "persistence",
    ),
)
def test_security_keep_side_saas_import_is_rejected(
    tmp_path: Path,
    statement: str,
) -> None:
    # Given: nipo_local code importing a deletion-scheduled SaaS module.
    _write_minimal_repo(tmp_path)
    _write(tmp_path, "apps/local/nipo_local/app.py", statement)

    # When: the quarantine check scans the tree.
    violations = scan(tmp_path)

    # Then: the forbidden import is detected and named.
    assert any(
        violation.startswith("saas-quarantine-import:apps/local/nipo_local/app.py")
        for violation in violations
    )


def test_security_closure_module_importing_saas_module_is_rejected(
    tmp_path: Path,
) -> None:
    # Given: a closure module reaching into the deletion zone via relative import.
    _write_minimal_repo(tmp_path)
    _write(
        tmp_path,
        "services/api/artifacts/service.py",
        "from .postgres_store import PostgresArtifactStore\n",
    )

    # When: the quarantine check scans the tree.
    violations = scan(tmp_path)

    # Then: the closure drift is detected.
    assert violations == (
        "saas-quarantine-import:services/api/artifacts/service.py:"
        "services.api.artifacts.postgres_store",
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


def test_unit_stale_deletion_pattern_is_reported(tmp_path: Path) -> None:
    # Given: a deletion stage landed without updating the inventory.
    _write_minimal_repo(tmp_path)
    (tmp_path / "services/api/provider_runtime.py").unlink()

    # When: the quarantine check scans the tree.
    violations = scan(tmp_path)

    # Then: the stale pattern forces an inventory update in the same commit.
    assert "saas-quarantine-stale-pattern:services.api.provider_*" in violations
    assert "services.api.provider_*" in DELETION_SCHEDULED_MODULES


def test_unit_cli_reports_violations_and_clean_trees(tmp_path: Path) -> None:
    # Given: a clean minimal repo and a copy with a forbidden import.
    _write_minimal_repo(tmp_path)

    # When / Then: the CLI passes the clean tree.
    assert main([str(tmp_path)]) == 0

    # When: a forbidden import is added.
    _write(
        tmp_path,
        "apps/local/nipo_local/app.py",
        "import services.api.bounded_http\n",
    )

    # Then: the CLI fails.
    assert main([str(tmp_path)]) == 1


def test_unit_cli_usage_paths(tmp_path: Path) -> None:
    # Given / When / Then: help, extra arguments, and missing roots.
    assert main(["--help"]) == 0
    assert main([str(tmp_path), "extra"]) == 2
    assert main([str(tmp_path / "missing")]) == 2
