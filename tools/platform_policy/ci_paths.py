"""Explicit Python static-analysis scope for the G001 release gate."""

from typing import Final

G001_PYTHON_PATHS: Final = (
    "packages/contracts/python",
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

G002_ARTIFACT_PYTHON_PATHS: Final = (
    "services/api/artifacts",
    "tests/artifacts",
)

G003_SCIENCE_PYTHON_PATHS: Final = (
    "packages/science",
    "tests/science",
)

G005_LOCAL_PYTHON_PATHS: Final = (
    "apps/local",
    "tests/e2e/local_workbench_fixture.py",
)


RELEASE_PYTHON_PATHS: Final = (
    G001_PYTHON_PATHS
    + G002_ARTIFACT_PYTHON_PATHS
    + G003_SCIENCE_PYTHON_PATHS
    + G005_LOCAL_PYTHON_PATHS
)
