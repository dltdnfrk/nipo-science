from pathlib import Path

import pytest
from tools.platform_policy.static_check_types import StaticCheckError
from tools.platform_policy.workflow_policy import (
    AUTHORITY_RUNNER,
    check_workflow_actions,
)

CHECKOUT_SHA = "34e114876b0b11c390a56381ad16ebd13914f8d5"

AUTHORITY_SCRIPT = """set -euo pipefail
test -n "${CI_AUTHORITY_AUDIENCE:-}"
test -n "${CI_AUTHORITY_URL:-}"
case "$CI_AUTHORITY_URL" in https://*) ;; *) exit 2 ;; esac
oidc_response="$(curl --fail --silent --show-error --proto '=https' --tlsv1.3 --max-time 15 \\
  -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \\
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${CI_AUTHORITY_AUDIENCE}")"
oidc_token="$(jq -er 'if keys == ["value"] and (.value | type == "string" and length > 0) then .value else error("invalid OIDC response") end' <<<"$oidc_response")"
printf '::add-mask::%s\\n' "$oidc_token"
request="$(jq -cn \\
  --arg repository "$SOURCE_REPOSITORY" \\
  --arg commit_sha "$SOURCE_SHA" \\
  --arg run_id "$WORKFLOW_RUN_ID" \\
  --arg run_attempt "$WORKFLOW_RUN_ATTEMPT" \\
  '{operation:"execute_and_publish",payload:{repository:$repository,commit_sha:$commit_sha,run_id:$run_id,run_attempt:$run_attempt}}')"
response="$(curl --fail --silent --show-error --proto '=https' --tlsv1.3 --max-time 30 \\
  -H "Authorization: Bearer $oidc_token" \\
  -H 'Content-Type: application/json' \\
  -H 'X-CI-Authority-Protocol: 2' \\
  --data-binary "$request" \\
  "$CI_AUTHORITY_URL")"
jq -e 'keys == ["manifest_sha256","ok"] and .ok == true and (.manifest_sha256 | test("^[0-9a-f]{64}$"))' <<<"$response" >/dev/null"""


def test_authority_runner_image_is_version_pinned() -> None:
    workflow = (Path(__file__).parents[2] / ".github/workflows/ci.yml").read_text()

    assert AUTHORITY_RUNNER == "ubuntu-24.04"
    assert workflow.count("runs-on: ubuntu-24.04") == 2
    assert "ubuntu-latest" not in workflow


def _workflow(authority_script: str) -> str:
    lines = authority_script.splitlines()
    indented_script = "\n".join(f"          {line}" for line in lines)
    return (
        "name: authority-test\n"
        "on:\n"
        "  pull_request:\n"
        "  push:\n"
        "    branches: [main]\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  validate:\n"
        "    runs-on: ubuntu-24.04\n"
        "    timeout-minutes: 30\n"
        "    steps:\n"
        f"      - uses: actions/checkout@{CHECKOUT_SHA}\n"
        "        with:\n"
        "          fetch-depth: 1\n"
        "          persist-credentials: false\n"
        f"      - uses: jdx/mise-action@{CHECKOUT_SHA}\n"
        "      - run: make bootstrap\n"
        "      - name: Run unprivileged CI validation\n"
        "        run: make ci-validate\n"
        "  attest:\n"
        "    if: github.event_name == 'push' && github.ref == 'refs/heads/main'\n"
        "    needs: validate\n"
        "    runs-on: ubuntu-24.04\n"
        "    timeout-minutes: 5\n"
        "    environment: ci-attestation\n"
        "    permissions:\n"
        "      contents: none\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - shell: bash\n"
        "        name: Request authority-owned execution and publication\n"
        "        env:\n"
        "          CI_AUTHORITY_AUDIENCE: ${{ vars.CI_AUTHORITY_AUDIENCE }}\n"
        "          CI_AUTHORITY_URL: ${{ vars.CI_AUTHORITY_URL }}\n"
        "          SOURCE_REPOSITORY: ${{ github.repository }}\n"
        "          SOURCE_SHA: ${{ github.sha }}\n"
        "          WORKFLOW_RUN_ATTEMPT: ${{ github.run_attempt }}\n"
        "          WORKFLOW_RUN_ID: ${{ github.run_id }}\n"
        "        run: |\n"
        f"{indented_script}\n"
    )


def _write_workflow(tmp_path: Path, content: str) -> None:
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    _ = workflow.write_text(content)


def test_security_inert_authority_strings_are_rejected(tmp_path: Path) -> None:
    inert_script = (
        "request='{operation:\"execute_and_publish\"}'\n"
        "header='X-CI-Authority-Protocol: 2'"
    )
    _ = _write_workflow(tmp_path, _workflow(inert_script))

    with pytest.raises(StaticCheckError, match="missing-external-ci-authority"):
        _ = check_workflow_actions(tmp_path)


def test_security_cross_job_authority_string_smuggling_is_rejected(
    tmp_path: Path,
) -> None:
    content = _workflow("request='{operation:\"execute_and_publish\"}'")
    content = content.replace(
        "          CI_AUTHORITY_AUDIENCE: ${{ vars.CI_AUTHORITY_AUDIENCE }}\n",
        "",
    ).replace(
        "        run: |\n          request='{operation:\"execute_and_publish\"}'\n",
        "        run: echo request\n"
        "  smuggle:\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        "      - env:\n"
        "          CI_AUTHORITY_AUDIENCE: ${{ vars.CI_AUTHORITY_AUDIENCE }}\n"
        "        run: |\n"
        "          request='{operation:\"execute_and_publish\"}'\n"
        "          header='X-CI-Authority-Protocol: 2'\n",
    )
    _ = _write_workflow(tmp_path, content)

    with pytest.raises(StaticCheckError, match="missing-external-ci-authority"):
        _ = check_workflow_actions(tmp_path)


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        (
            "github.event_name == 'push' && github.ref == 'refs/heads/main'",
            "github.event_name == 'pull_request'",
        ),
        ("    needs: validate\n", "    needs: smuggle\n"),
        ("  contents: read\njobs:", "  contents: write\njobs:"),
        ("persist-credentials: false", "persist-credentials: true"),
        ("run: make ci-validate", "run: make ci-validate && true"),
        ("environment: ci-attestation", "environment: production"),
        ("      contents: none\n", "      contents: read\n"),
        ("      id-token: write\n", "      id-token: none\n"),
        (
            "    steps:\n      - shell: bash\n",
            f"    steps:\n      - uses: actions/checkout@{CHECKOUT_SHA}\n"
            "      - shell: bash\n",
        ),
        ("https://*) ;; *) exit 2", "http://*) ;; *) exit 2"),
        (
            "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "Authorization: Bearer inert",
        ),
        ("curl --fail", "printf --fail"),
        ('operation:"execute_and_publish"', 'operation:"validate_only"'),
        ("Authorization: Bearer $oidc_token", "Authorization: Bearer inert"),
        ("X-CI-Authority-Protocol: 2", "X-CI-Authority-Protocol: 1"),
        (
            'jq -e \'keys == ["manifest_sha256","ok"]',
            'printf \'keys == ["manifest_sha256","ok"]',
        ),
    ],
    ids=(
        "wrong-event",
        "wrong-needs",
        "privileged-validation",
        "checkout-credentials",
        "inexact-validation-command",
        "wrong-environment",
        "attest-contents-read",
        "attest-without-oidc-permission",
        "attest-checkout",
        "non-https-authority",
        "no-oidc-authorization",
        "no-curl",
        "wrong-operation",
        "no-authority-authorization",
        "wrong-protocol",
        "no-response-check",
    ),
)
def test_security_attestation_structure_and_calls_are_required(
    tmp_path: Path,
    original: str,
    replacement: str,
) -> None:
    _ = _write_workflow(
        tmp_path, _workflow(AUTHORITY_SCRIPT).replace(original, replacement)
    )

    with pytest.raises(StaticCheckError, match="missing-external-ci-authority"):
        _ = check_workflow_actions(tmp_path)


def test_authority_workflow_with_real_oidc_https_call_is_counted(
    tmp_path: Path,
) -> None:
    _ = _write_workflow(tmp_path, _workflow(AUTHORITY_SCRIPT))

    assert check_workflow_actions(tmp_path) == 2


@pytest.mark.parametrize(
    "injected_field",
    [
        "        if: false\n",
        "        continue-on-error: true\n",
        "    continue-on-error: true\n",
    ],
    ids=("step-skip", "step-failure-ignore", "job-failure-ignore"),
)
def test_security_attestation_rejects_execution_control_fields(
    tmp_path: Path,
    injected_field: str,
) -> None:
    anchor = (
        "      - shell: bash\n"
        if injected_field.startswith("        ")
        else "    steps:\n"
    )
    replacement = (
        anchor + injected_field
        if injected_field.startswith("        ")
        else injected_field + anchor
    )
    content = _workflow(AUTHORITY_SCRIPT).replace(anchor, replacement, 1)
    _ = _write_workflow(tmp_path, content)

    with pytest.raises(StaticCheckError, match="missing-external-ci-authority"):
        _ = check_workflow_actions(tmp_path)


@pytest.mark.parametrize(
    "privilege",
    [
        "    environment: ci-attestation\n",
        "    permissions:\n      contents: none\n      id-token: write\n",
    ],
    ids=("protected-environment", "oidc-token"),
)
def test_security_non_attest_job_cannot_claim_authority_privilege(
    tmp_path: Path,
    privilege: str,
) -> None:
    rogue = (
        "  rogue:\n"
        "    runs-on: ubuntu-24.04\n"
        f"{privilege}"
        "    steps:\n"
        "      - run: echo arbitrary\n"
    )
    _ = _write_workflow(tmp_path, _workflow(AUTHORITY_SCRIPT) + rogue)

    with pytest.raises(StaticCheckError, match="missing-external-ci-authority"):
        _ = check_workflow_actions(tmp_path)


def test_security_privileged_job_is_rejected_without_ci_commands(
    tmp_path: Path,
) -> None:
    content = (
        "jobs:\n"
        "  rogue:\n"
        "    runs-on: ubuntu-24.04\n"
        "    environment: ci-attestation\n"
        "    permissions:\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - run: echo arbitrary\n"
    )
    _ = _write_workflow(tmp_path, content)

    with pytest.raises(StaticCheckError, match="missing-external-ci-authority"):
        _ = check_workflow_actions(tmp_path)


def test_security_quoted_uses_key_cannot_hide_floating_action(
    tmp_path: Path,
) -> None:
    content = _workflow(AUTHORITY_SCRIPT).replace(
        "      - name: Run unprivileged CI validation\n",
        '      - "uses": actions/setup-python@v4\n'
        "      - name: Run unprivileged CI validation\n",
    )
    _ = _write_workflow(tmp_path, content)

    with pytest.raises(StaticCheckError):
        _ = check_workflow_actions(tmp_path)
