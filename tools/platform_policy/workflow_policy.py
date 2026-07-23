"""Structural policy for pinned actions and external CI attestation."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

from .ci_remote_authority import (
    AUTHORITY_AUDIENCE_ENV,
    AUTHORITY_URL_ENV,
    OIDC_REQUEST_TOKEN_ENV,
    OIDC_REQUEST_URL_ENV,
    PROTOCOL_VERSION,
)
from .static_check_types import StaticCheckCode, StaticCheckError
from .workflow_yaml import (
    ScalarPairs,
    WorkflowDocument,
    WorkflowJob,
    WorkflowStep,
    WorkflowTrigger,
    action_references,
    parse_workflow,
)

if TYPE_CHECKING:
    from pathlib import Path

ACTION_SHA_PATTERN: Final = re.compile(r"^[^@]+@[0-9a-f]{40}$")
WORKFLOW_SUFFIXES: Final = frozenset({".yaml", ".yml"})
VALIDATE_JOB: Final = "validate"
ATTEST_JOB: Final = "attest"
AUTHORITY_JOBS: Final = frozenset({VALIDATE_JOB, ATTEST_JOB})
AUTHORITY_WORKFLOW_FIELDS: Final = frozenset({"jobs", "name", "on", "permissions"})
VALIDATE_STEP_COUNT: Final = 4
CHECKOUT_ACTION: Final = "actions/checkout@"
SETUP_ACTION: Final = "jdx/mise-action@"
AUTHORITY_TRIGGER: Final = WorkflowTrigger(
    pull_request=True,
    push_branches=("main",),
)
AUTHORITY_RUNNER: Final = "ubuntu-24.04"
VALIDATE_TIMEOUT_MINUTES: Final = 30
ATTEST_TIMEOUT_MINUTES: Final = 5
VALIDATE_JOB_FIELDS: Final = frozenset({"runs-on", "steps", "timeout-minutes"})
ATTEST_JOB_FIELDS: Final = frozenset(
    {
        "environment",
        "if",
        "needs",
        "permissions",
        "runs-on",
        "steps",
        "timeout-minutes",
    }
)
CHECKOUT_STEP_FIELDS: Final = frozenset({"uses", "with"})
SETUP_STEP_FIELDS: Final = frozenset({"uses"})
BOOTSTRAP_STEP_FIELDS: Final = frozenset({"run"})
VALIDATION_STEP_FIELDS: Final = frozenset({"name", "run"})
ATTEST_STEP_FIELDS: Final = frozenset({"env", "name", "run", "shell"})
CHECKOUT_OPTIONS: Final[ScalarPairs] = (
    ("fetch-depth", "1"),
    ("persist-credentials", "false"),
)
MAIN_PUSH_CONDITION: Final = (
    "github.event_name == 'push' && github.ref == 'refs/heads/main'"
)
ATTEST_ENVIRONMENT: Final = "ci-attestation"
VALIDATE_PERMISSIONS: Final[ScalarPairs] = (("contents", "read"),)
ATTEST_PERMISSIONS: Final[ScalarPairs] = (
    ("contents", "none"),
    ("id-token", "write"),
)
ATTEST_ENV: Final[ScalarPairs] = tuple(
    sorted(
        (
            (AUTHORITY_AUDIENCE_ENV, f"${{{{ vars.{AUTHORITY_AUDIENCE_ENV} }}}}"),
            (AUTHORITY_URL_ENV, f"${{{{ vars.{AUTHORITY_URL_ENV} }}}}"),
            ("SOURCE_REPOSITORY", "${{ github.repository }}"),
            ("SOURCE_SHA", "${{ github.sha }}"),
            ("WORKFLOW_RUN_ATTEMPT", "${{ github.run_attempt }}"),
            ("WORKFLOW_RUN_ID", "${{ github.run_id }}"),
        )
    )
)
ATTEST_SCRIPT: Final = "\n".join(
    (
        "set -euo pipefail",
        f'test -n "${{{AUTHORITY_AUDIENCE_ENV}:-}}"',
        f'test -n "${{{AUTHORITY_URL_ENV}:-}}"',
        f'case "${AUTHORITY_URL_ENV}" in https://*) ;; *) exit 2 ;; esac',
        "oidc_response=\"$(curl --fail --silent --show-error --proto '=https' "
        "--tlsv1.3 --max-time 15 \\",
        f'  -H "Authorization: Bearer ${OIDC_REQUEST_TOKEN_ENV}" \\',
        f'  "${{{OIDC_REQUEST_URL_ENV}}}&audience=${{{AUTHORITY_AUDIENCE_ENV}}}")"',
        'oidc_token="$(jq -er \'if keys == ["value"] and (.value | type == '
        '"string" and length > 0) then .value else error("invalid OIDC response") '
        'end\' <<<"$oidc_response")"',
        "printf '::add-mask::%s\\n' \"$oidc_token\"",
        'request="$(jq -cn \\',
        '  --arg repository "$SOURCE_REPOSITORY" \\',
        '  --arg commit_sha "$SOURCE_SHA" \\',
        '  --arg run_id "$WORKFLOW_RUN_ID" \\',
        '  --arg run_attempt "$WORKFLOW_RUN_ATTEMPT" \\',
        '  \'{operation:"execute_and_publish",payload:{repository:$repository,'
        "commit_sha:$commit_sha,run_id:$run_id,run_attempt:$run_attempt}}')\"",
        "response=\"$(curl --fail --silent --show-error --proto '=https' "
        "--tlsv1.3 --max-time 30 \\",
        '  -H "Authorization: Bearer $oidc_token" \\',
        "  -H 'Content-Type: application/json' \\",
        f"  -H 'X-CI-Authority-Protocol: {PROTOCOL_VERSION}' \\",
        '  --data-binary "$request" \\',
        f'  "${AUTHORITY_URL_ENV}")"',
        'jq -e \'keys == ["manifest_sha256","ok"] and .ok == true and '
        '(.manifest_sha256 | test("^[0-9a-f]{64}$"))\' <<<"$response" '
        ">/dev/null",
    )
)


def check_workflow_actions(root: Path) -> int:
    """Require pinned actions and a structurally exact external CI authority flow."""
    count = 0
    for workflow in (root / ".github/workflows").rglob("*"):
        if not workflow.is_file() or workflow.suffix not in WORKFLOW_SUFFIXES:
            continue
        document, root_node = parse_workflow(workflow)
        references = action_references(root_node, workflow)
        count += len(
            tuple(
                reference for reference in references if not reference.startswith("./")
            )
        )
        for reference in references:
            if (
                not reference.startswith("./")
                and ACTION_SHA_PATTERN.fullmatch(reference) is None
            ):
                raise StaticCheckError(
                    StaticCheckCode.UNPINNED_WORKFLOW_ACTION, workflow
                )
        _verify_ci_authority(document, workflow)
    return count


def _verify_ci_authority(document: WorkflowDocument, path: Path) -> None:
    """Require exact authority schema for every GitHub-executable document."""
    if not document.jobs:
        return
    jobs = {job.identifier: job for job in document.jobs}
    if (
        document.field_names != AUTHORITY_WORKFLOW_FIELDS
        or document.trigger != AUTHORITY_TRIGGER
        or document.permissions != VALIDATE_PERMISSIONS
        or jobs.keys() != AUTHORITY_JOBS
    ):
        raise StaticCheckError(StaticCheckCode.MISSING_EXTERNAL_CI_AUTHORITY, path)
    validate = jobs.get(VALIDATE_JOB)
    attest = jobs.get(ATTEST_JOB)
    if validate is None or attest is None or not _valid_validate(validate):
        raise StaticCheckError(StaticCheckCode.MISSING_EXTERNAL_CI_AUTHORITY, path)
    if not _valid_attest(attest):
        raise StaticCheckError(StaticCheckCode.MISSING_EXTERNAL_CI_AUTHORITY, path)


def _valid_validate(job: WorkflowJob) -> bool:
    if len(job.steps) != VALIDATE_STEP_COUNT:
        return False
    checkout, setup, bootstrap, validation = job.steps
    return (
        job.permissions is None
        and job.field_names == VALIDATE_JOB_FIELDS
        and job.condition is None
        and job.needs == ()
        and job.environment is None
        and job.runner == AUTHORITY_RUNNER
        and job.timeout_minutes == VALIDATE_TIMEOUT_MINUTES
        and _valid_action_step(
            checkout, CHECKOUT_STEP_FIELDS, CHECKOUT_ACTION, CHECKOUT_OPTIONS
        )
        and _valid_action_step(setup, SETUP_STEP_FIELDS, SETUP_ACTION, ())
        and _valid_run_step(bootstrap, BOOTSTRAP_STEP_FIELDS, "make bootstrap")
        and _valid_run_step(validation, VALIDATION_STEP_FIELDS, "make ci-validate")
    )


def _valid_attest(job: WorkflowJob) -> bool:
    if (
        job.field_names != ATTEST_JOB_FIELDS
        or job.condition != MAIN_PUSH_CONDITION
        or job.needs != (VALIDATE_JOB,)
        or job.environment != ATTEST_ENVIRONMENT
        or job.permissions != ATTEST_PERMISSIONS
        or job.runner != AUTHORITY_RUNNER
        or job.timeout_minutes != ATTEST_TIMEOUT_MINUTES
        or len(job.steps) != 1
    ):
        return False
    step = job.steps[0]
    return (
        step.field_names == ATTEST_STEP_FIELDS
        and step.uses is None
        and step.shell == "bash"
        and step.environment == ATTEST_ENV
        and (step.run or "").strip() == ATTEST_SCRIPT
    )


def _valid_action_step(
    step: WorkflowStep,
    field_names: frozenset[str],
    action_prefix: str,
    options: ScalarPairs,
) -> bool:
    return (
        step.field_names == field_names
        and (step.uses or "").startswith(action_prefix)
        and step.run is None
        and step.shell is None
        and step.environment == ()
        and step.options == options
    )


def _valid_run_step(
    step: WorkflowStep, field_names: frozenset[str], command: str
) -> bool:
    return (
        step.field_names == field_names
        and step.uses is None
        and (step.run or "").strip() == command
        and step.shell is None
        and step.environment == ()
        and step.options == ()
    )
