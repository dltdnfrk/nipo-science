from pathlib import Path

import pytest
from tools.platform_policy.static_check_types import StaticCheckError
from tools.platform_policy.static_checks import check_secrets
from tools.platform_policy.workflow_policy import check_workflow_actions


def test_security_floating_workflow_action_is_rejected(tmp_path: Path) -> None:
    # Given
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    content = "steps:\n  - uses: actions/checkout@v4\n"
    _ = workflow.write_text(content)

    # When / Then
    with pytest.raises(StaticCheckError, match="unpinned-workflow-action"):
        _ = check_workflow_actions(tmp_path)
    assert workflow.read_text() == content


def test_unit_full_sha_workflow_action_is_counted(tmp_path: Path) -> None:
    # Given
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    sha = "34e114876b0b11c390a56381ad16ebd13914f8d5"
    _ = workflow.write_text(f"steps:\n  - uses: actions/checkout@{sha}\n")

    # When
    count = check_workflow_actions(tmp_path)

    # Then
    assert count == 1


def test_security_floating_yaml_workflow_action_is_rejected(tmp_path: Path) -> None:
    # Given
    workflow = tmp_path / ".github/workflows/probe.yaml"
    workflow.parent.mkdir(parents=True)
    _ = workflow.write_text("steps:\n  - uses: actions/checkout@v4\n")

    # When / Then
    with pytest.raises(StaticCheckError, match="unpinned-workflow-action"):
        _ = check_workflow_actions(tmp_path)


def test_unit_nested_yaml_full_sha_action_is_counted_once(tmp_path: Path) -> None:
    # Given
    workflow = tmp_path / ".github/workflows/nested/probe.yaml"
    workflow.parent.mkdir(parents=True)
    sha = "34e114876b0b11c390a56381ad16ebd13914f8d5"
    _ = workflow.write_text(f"steps:\n  - uses: actions/checkout@{sha}\n")

    # When
    count = check_workflow_actions(tmp_path)

    # Then
    assert count == 1


def test_unit_yml_and_yaml_actions_are_not_double_counted(tmp_path: Path) -> None:
    # Given
    workflows = tmp_path / ".github/workflows"
    nested = workflows / "nested"
    nested.mkdir(parents=True)
    sha = "34e114876b0b11c390a56381ad16ebd13914f8d5"
    _ = (workflows / "ci.yml").write_text(f"steps:\n  - uses: actions/checkout@{sha}\n")
    _ = (nested / "probe.yaml").write_text(
        f"steps:\n  - uses: actions/upload-artifact@{sha}\n"
    )

    # When
    count = check_workflow_actions(tmp_path)

    # Then
    assert count == 2


def test_security_ci_runner_without_external_authority_is_rejected(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    sha = "34e114876b0b11c390a56381ad16ebd13914f8d5"
    _ = workflow.write_text(
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  rogue:\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        f"      - uses: actions/checkout@{sha}\n"
        "      - run: make ci-local\n"
    )

    with pytest.raises(StaticCheckError, match="missing-external-ci-authority"):
        _ = check_workflow_actions(tmp_path)


def test_ci_validation_without_authority_owned_publication_is_rejected(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    sha = "34e114876b0b11c390a56381ad16ebd13914f8d5"
    _ = workflow.write_text(
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  validate:\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        f"      - uses: actions/checkout@{sha}\n"
        "        with:\n"
        "          persist-credentials: false\n"
        "      - run: make ci-validate\n"
    )

    with pytest.raises(StaticCheckError, match="missing-external-ci-authority"):
        _ = check_workflow_actions(tmp_path)


def test_inert_authority_strings_do_not_count_as_owned_execution(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    sha = "34e114876b0b11c390a56381ad16ebd13914f8d5"
    _ = workflow.write_text(
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  validate:\n"
        "    steps:\n"
        f"      - uses: actions/checkout@{sha}\n"
        "        with:\n"
        "          persist-credentials: false\n"
        "      - run: make ci-validate\n"
        "  attest:\n"
        "    environment: ci-attestation\n"
        "    permissions:\n"
        "      contents: none\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - env:\n"
        "          CI_AUTHORITY_AUDIENCE: ${{ vars.CI_AUTHORITY_AUDIENCE }}\n"
        "          CI_AUTHORITY_URL: ${{ vars.CI_AUTHORITY_URL }}\n"
        "        run: |\n"
        "          request='{operation:\"execute_and_publish\"}'\n"
        "          header='X-CI-Authority-Protocol: 2'\n"
    )

    with pytest.raises(StaticCheckError, match="missing-external-ci-authority"):
        _ = check_workflow_actions(tmp_path)


@pytest.mark.parametrize(
    ("relative_path", "content", "executable"),
    [
        (
            "infra/leak.sh",
            'export SERVICE_TOKEN="' + "sk-" + "benign_" + ("a" * 20) + '"\n',
            False,
        ),
        (
            ".env.production",
            f"\uff21\uff30\uff29\uff3f\uff2b\uff25\uff39=benign_{'b' * 24}\n",
            False,
        ),
        (
            ".github/workflows/release.yaml",
            "headers:\n  Authorization: Bearer " + "benign." + ("c" * 20),
            False,
        ),
        (
            "deploy",
            "#!/bin/sh\nclient_secret=" + "benign_" + ("d" * 24) + "\n",
            True,
        ),
    ],
    ids=("infra-shell", "root-config", "workflow-header", "executable"),
)
def test_security_secret_material_is_rejected_across_project_files(
    tmp_path: Path,
    relative_path: str,
    content: str,
    executable: bool,
) -> None:
    # Given
    candidate = tmp_path / relative_path
    candidate.parent.mkdir(parents=True, exist_ok=True)
    _ = candidate.write_text(content)
    if executable:
        candidate.chmod(0o700)

    # When / Then
    with pytest.raises(StaticCheckError, match="credential-plaintext"):
        _ = check_secrets(tmp_path)


def test_unit_secret_scan_allows_documented_credential_names(tmp_path: Path) -> None:
    # Given
    document = tmp_path / "docs/security.md"
    document.parent.mkdir(parents=True)
    documented_name = "Configure API_KEY through the secret manager. "
    documented_header = "Authorization: Bearer <token> is the supported header."
    _ = document.write_text(documented_name + documented_header)

    # When
    count = check_secrets(tmp_path)

    # Then
    assert count == 1


def test_unit_secret_scan_allows_long_credential_named_variables(
    tmp_path: Path,
) -> None:
    source = tmp_path / "app.js"
    _ = source.write_text(
        "const providerAuthorization = deriveAuthorization();\n"
        "let authorization = providerAuthorization;\n"
    )

    count = check_secrets(tmp_path)

    assert count == 1


@pytest.mark.parametrize(
    "relative_path",
    [
        "node_modules/package/leak.js",
        ".cache/tool/leak.sh",
        ".tools/runtime/leak",
        ".venv/bin/activate",
        ".ci/evidence/latest/leak.sh",
        "dist/leak.js",
        "__pycache__/leak.py",
    ],
)
def test_unit_secret_scan_excludes_generated_vendor_and_tool_caches(
    tmp_path: Path,
    relative_path: str,
) -> None:
    # Given
    readme = tmp_path / "README.md"
    _ = readme.write_text("Safe project source")
    excluded = tmp_path / relative_path
    excluded.parent.mkdir(parents=True)
    _ = excluded.write_text("token=" + "benign_" + ("e" * 24))

    # When
    count = check_secrets(tmp_path)

    # Then
    assert count == 1
