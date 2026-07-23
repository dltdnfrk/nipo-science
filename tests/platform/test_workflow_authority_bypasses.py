from pathlib import Path

import pytest
from tools.platform_policy.static_check_types import StaticCheckError
from tools.platform_policy.workflow_policy import check_workflow_actions

ROOT = Path(__file__).parents[2]
TEST_ACTION_SHA = "0" * 40


def _write_workflow(tmp_path: Path, content: str) -> None:
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    _ = workflow.write_text(content)


def _canonical_workflow() -> str:
    return (ROOT / ".github/workflows/ci.yml").read_text()


def _assert_rejected(tmp_path: Path, content: str) -> None:
    _write_workflow(tmp_path, content)
    with pytest.raises(StaticCheckError, match="missing-external-ci-authority"):
        _ = check_workflow_actions(tmp_path)


@pytest.mark.parametrize(
    "content",
    [
        "permissions:\n  id-token: write # authority privilege\n",
        "jobs:\n  rogue:\n    environment: ci-attestation # protected\n",
        'permissions:\n  id-token: "wr\\x69te"\n',
        'jobs:\n  rogue:\n    environment: "ci-\\x61ttestation"\n',
    ],
    ids=(
        "inline-permission-comment",
        "inline-environment-comment",
        "escaped-permission",
        "escaped-environment",
    ),
)
def test_security_yaml_scalar_semantics_are_fail_closed(
    tmp_path: Path, content: str
) -> None:
    _assert_rejected(tmp_path, content)


@pytest.mark.parametrize(
    "content",
    [
        "value: &authority ci-attestation\n",
        "value: *authority\n",
        "value: !!str ci-attestation\n",
    ],
    ids=("anchor", "alias", "tag"),
)
def test_security_yaml_node_features_are_fail_closed(
    tmp_path: Path, content: str
) -> None:
    _assert_rejected(tmp_path, content)


@pytest.mark.parametrize(
    "command",
    ["ma$'ke' ci-local", 'm=ma; "${m}ke" ci-local', 'make ci"-"local'],
    ids=("ansi-c-quoted-make", "variable-composed-make", "quote-split-target"),
)
def test_security_dynamic_ci_local_invocation_is_rejected(
    tmp_path: Path, command: str
) -> None:
    content = (
        "jobs:\n  rogue:\n    runs-on: ubuntu-24.04\n"
        f"    steps:\n      - run: {command}\n"
    )
    _assert_rejected(tmp_path, content)


def test_security_authority_workflow_rejects_extra_job(tmp_path: Path) -> None:
    extra_job = (
        "  unrelated:\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        "      - run: echo unrelated\n"
    )
    _assert_rejected(tmp_path, _canonical_workflow() + extra_job)


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        (
            "      - run: make bootstrap\n",
            f"      - uses: actions/setup-python@{TEST_ACTION_SHA}\n"
            "      - run: make bootstrap\n",
        ),
        (
            "      - uses: jdx/mise-action@5228313ee0372e111a38da051671ca30fc5a96db\n",
            "",
        ),
        ("      - run: make bootstrap\n", ""),
        (
            "      - run: make bootstrap\n",
            "      - run: make bootstrap\n        env:\n          EXTRA: true\n",
        ),
        (
            "        run: make ci-validate\n",
            "        run: make ci-validate\n        shell: python\n",
        ),
        (
            "  validate:\n    runs-on:",
            "  validate:\n    name: hidden metadata\n    runs-on:",
        ),
        (
            "      - run: make bootstrap\n",
            "      - name: hidden metadata\n        run: make bootstrap\n",
        ),
        (
            "        shell: bash\n",
            "        shell: bash\n        with:\n          hidden: value\n",
        ),
    ],
    ids=(
        "extra-action",
        "missing-setup",
        "missing-bootstrap",
        "run-env",
        "run-shell",
        "job-name",
        "step-name",
        "attest-with",
    ),
)
def test_security_validate_steps_use_exact_allowlist(
    tmp_path: Path, original: str, replacement: str
) -> None:
    content = _canonical_workflow()
    assert content.count(original) == 1
    _assert_rejected(tmp_path, content.replace(original, replacement))


@pytest.mark.parametrize(
    "job_fields",
    [
        "    environment: CI-ATTESTATION\n    steps:\n      - run: echo inert\n",
        "    environment: ${{ 'ci-attestation' }}\n    steps:\n      - run: echo inert\n",
        '    steps:\n      - run: m=ma; t=ci-; "${m}ke" "${t}local"\n',
        "    steps:\n      - run: python -m tools.platform_policy.ci_runner\n",
        f"    steps:\n      - uses: actions/setup-python@{TEST_ACTION_SHA}\n",
    ],
    ids=(
        "environment-case",
        "environment-expression",
        "fully-dynamic-ci-local",
        "direct-ci-runner",
        "arbitrary-pinned-action",
    ),
)
def test_security_every_executable_workflow_uses_authority_schema(
    tmp_path: Path, job_fields: str
) -> None:
    content = "jobs:\n  rogue:\n    runs-on: ubuntu-24.04\n" + job_fields
    _assert_rejected(tmp_path, content)


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        (
            "on:\n  pull_request:\n  push:\n    branches: [main]\n",
            "on: [pull_request]\n",
        ),
        (
            "    needs: validate\n    runs-on: ubuntu-24.04\n",
            "    needs: validate\n    runs-on: self-hosted\n",
        ),
        ("    timeout-minutes: 20\n", "    timeout-minutes: 21\n"),
        ("    timeout-minutes: 5\n", "    timeout-minutes: 6\n"),
        (
            "\npermissions:\n  contents: read\n",
            "\nconcurrency: authority\npermissions:\n  contents: read\n",
        ),
    ],
    ids=(
        "trigger",
        "attest-runner",
        "validate-timeout",
        "attest-timeout",
        "root-field",
    ),
)
def test_security_workflow_execution_schema_is_exact(
    tmp_path: Path, original: str, replacement: str
) -> None:
    content = _canonical_workflow()
    assert content.count(original) == 1
    _assert_rejected(tmp_path, content.replace(original, replacement))
