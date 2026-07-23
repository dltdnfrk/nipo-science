"""Explicit Python static-analysis scope for the G001 release gate."""

from typing import Final

G001_PYTHON_PATHS: Final = (
    "packages/contracts/python",
    "tests/test_openapi_contract.py",
    "services/local",
    "tests/local_stack",
    "tools/platform_policy",
    "tests/platform",
    "tools/boundary_adversarial_cases.py",
    "tools/boundary_ast_rules.py",
    "tools/boundary_node_cases.py",
    "tools/boundary_node_rules.py",
    "tools/boundary_os_cases.py",
    "tools/boundary_path_values.py",
    "tools/boundary_python_sinks.py",
    "tools/boundary_shell_cases.py",
    "tools/boundary_shell_rules.py",
    "tools/boundary_text_rules.py",
    "tools/boundary_write_rules.py",
    "tools/check_boundaries.py",
    "tests/test_boundaries.py",
    "tools/spec_contract.py",
    "tools/spec_runtime.py",
    "tools/verify_spec.py",
    "tools/tests/test_verify_spec.py",
    "tools/architecture_contract.py",
    "tools/architecture_evidence.py",
    "tools/architecture_manifest.py",
    "tools/verify_architecture.py",
    "tests/test_architecture.py",
)

G002_PYTHON_PATHS: Final = (
    "services/api/migrations",
    "services/api/persistence",
    "services/api/tests/persistence",
)

G002_UPLOAD_PYTHON_PATHS: Final = (
    "services/api/upload",
    "tests/upload",
)

G002_ARTIFACT_PYTHON_PATHS: Final = (
    "services/api/artifacts",
    "tests/artifacts",
)

G003_SCIENCE_PYTHON_PATHS: Final = (
    "packages/science",
    "tests/science",
)

G004_ARTIFACT_UI_PYTHON_PATHS: Final = (
    "services/api/artifact_ui_app.py",
    "services/api/artifact_ui_http.py",
    "services/api/product_artifact_fixtures.py",
    "services/api/product_artifact_http.py",
    "services/api/product_artifact_types.py",
    "services/api/product_artifact_validation.py",
    "services/api/product_artifact_views.py",
    "services/api/product_artifacts.py",
    "services/api/product_pdf_validation.py",
    "services/api/product_preview.py",
    "tools/run_artifact_ui_fixture.py",
    "tests/artifact_ui",
)

RELEASE_PYTHON_PATHS: Final = (
    G001_PYTHON_PATHS
    + G002_PYTHON_PATHS
    + G002_UPLOAD_PYTHON_PATHS
    + G002_ARTIFACT_PYTHON_PATHS
    + G003_SCIENCE_PYTHON_PATHS
    + G004_ARTIFACT_UI_PYTHON_PATHS
)
