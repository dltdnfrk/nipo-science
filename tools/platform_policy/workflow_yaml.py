"""Typed YAML boundary for security-relevant GitHub workflow fields."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Never

from .static_check_types import StaticCheckCode, StaticCheckError
from .workflow_yaml_parser import (
    YamlMapping,
    YamlScalar,
    YamlSequence,
    YamlValue,
    parse_yaml_mapping,
    unquote_scalar,
)

if TYPE_CHECKING:
    from pathlib import Path

type ScalarPairs = tuple[tuple[str, str], ...]
WORKFLOW_FIELDS: Final = frozenset({"jobs", "name", "on", "permissions", "steps"})
JOB_FIELDS: Final = frozenset(
    {
        "environment",
        "if",
        "name",
        "needs",
        "permissions",
        "runs-on",
        "steps",
        "timeout-minutes",
    }
)
STEP_FIELDS: Final = frozenset({"env", "name", "run", "shell", "uses", "with"})
TRIGGER_FIELDS: Final = frozenset({"pull_request", "push"})
PUSH_FIELDS: Final = frozenset({"branches"})


@dataclass(frozen=True, slots=True)
class WorkflowTrigger:
    """Typed trigger subset used by the authority workflow."""

    pull_request: bool
    push_branches: tuple[str, ...] | None


@dataclass(frozen=True, slots=True)
class WorkflowStep:
    """Security-relevant fields from one parsed workflow step."""

    field_names: frozenset[str]
    uses: str | None
    run: str | None
    shell: str | None
    environment: ScalarPairs
    options: ScalarPairs


@dataclass(frozen=True, slots=True)
class WorkflowJob:
    """Security-relevant fields from one parsed workflow job."""

    identifier: str
    field_names: frozenset[str]
    condition: str | None
    needs: tuple[str, ...]
    environment: str | None
    permissions: ScalarPairs | None
    runner: str | None
    timeout_minutes: int | None
    steps: tuple[WorkflowStep, ...]


@dataclass(frozen=True, slots=True)
class WorkflowDocument:
    """Typed subset of a GitHub workflow used by the CI authority policy."""

    field_names: frozenset[str]
    trigger: WorkflowTrigger | None
    permissions: ScalarPairs | None
    jobs: tuple[WorkflowJob, ...]


def parse_workflow(path: Path) -> tuple[WorkflowDocument, YamlMapping]:
    """Parse the supported workflow subset and reject ambiguous YAML."""
    node = parse_yaml_mapping(path.read_text(encoding="utf-8"), path)
    fields = _mapping(node, path)
    if not fields.keys() <= WORKFLOW_FIELDS:
        _fail(path)
    trigger_node = fields.get("on")
    permissions_node = fields.get("permissions")
    jobs_node = fields.get("jobs")
    permissions = (
        _scalar_pairs(permissions_node, path) if permissions_node is not None else None
    )
    jobs = _parse_jobs(jobs_node, path) if jobs_node is not None else ()
    return (
        WorkflowDocument(
            field_names=frozenset(fields),
            trigger=(
                _parse_trigger(trigger_node, path) if trigger_node is not None else None
            ),
            permissions=permissions,
            jobs=jobs,
        ),
        node,
    )


def action_references(node: YamlValue, path: Path) -> tuple[str, ...]:
    """Return structurally active action references from a parsed workflow."""
    match node:
        case YamlScalar():
            return ()
        case YamlSequence(values=children):
            return tuple(
                reference
                for child in children
                for reference in action_references(child, path)
            )
        case YamlMapping():
            fields = _mapping(node, path)
            direct = (_scalar(fields["uses"], path),) if "uses" in fields else ()
            return direct + tuple(
                reference
                for key, child in fields.items()
                if key != "uses"
                for reference in action_references(child, path)
            )


def _parse_jobs(node: YamlValue, path: Path) -> tuple[WorkflowJob, ...]:
    return tuple(
        _parse_job(identifier, value, path)
        for identifier, value in _mapping(node, path).items()
    )


def _parse_job(identifier: str, node: YamlValue, path: Path) -> WorkflowJob:
    fields = _mapping(node, path)
    if not fields.keys() <= JOB_FIELDS:
        _fail(path)
    steps_node = fields.get("steps")
    return WorkflowJob(
        identifier=identifier,
        field_names=frozenset(fields),
        condition=_optional_scalar(fields.get("if"), path),
        needs=_needs(fields.get("needs"), path),
        environment=_optional_scalar(fields.get("environment"), path),
        permissions=(
            _scalar_pairs(fields["permissions"], path)
            if "permissions" in fields
            else None
        ),
        runner=_optional_scalar(fields.get("runs-on"), path),
        timeout_minutes=_optional_integer(fields.get("timeout-minutes"), path),
        steps=_parse_steps(steps_node, path) if steps_node is not None else (),
    )


def _parse_trigger(node: YamlValue, path: Path) -> WorkflowTrigger:
    if isinstance(node, YamlScalar):
        events = _string_list(node, path)
        if not frozenset(events) <= TRIGGER_FIELDS:
            _fail(path)
        return WorkflowTrigger(
            pull_request="pull_request" in events,
            push_branches=() if "push" in events else None,
        )
    fields = _mapping(node, path)
    if not fields.keys() <= TRIGGER_FIELDS:
        _fail(path)
    pull_request = fields.get("pull_request")
    if pull_request is not None and _scalar(pull_request, path):
        _fail(path)
    push = fields.get("push")
    if push is None:
        push_branches = None
    elif isinstance(push, YamlScalar):
        if push.value:
            _fail(path)
        push_branches = ()
    else:
        push_fields = _mapping(push, path)
        if push_fields.keys() != PUSH_FIELDS:
            _fail(path)
        push_branches = _string_list(push_fields["branches"], path)
    return WorkflowTrigger(
        pull_request=pull_request is not None,
        push_branches=push_branches,
    )


def _parse_steps(node: YamlValue, path: Path) -> tuple[WorkflowStep, ...]:
    if not isinstance(node, YamlSequence):
        _fail(path)
    steps: list[WorkflowStep] = []
    for step_node in node.values:
        fields = _mapping(step_node, path)
        if not fields.keys() <= STEP_FIELDS:
            _fail(path)
        steps.append(
            WorkflowStep(
                field_names=frozenset(fields),
                uses=_optional_scalar(fields.get("uses"), path),
                run=_optional_scalar(fields.get("run"), path),
                shell=_optional_scalar(fields.get("shell"), path),
                environment=_optional_scalar_pairs(fields.get("env"), path),
                options=_optional_scalar_pairs(fields.get("with"), path),
            )
        )
    return tuple(steps)


def _mapping(node: YamlValue, path: Path) -> dict[str, YamlValue]:
    if not isinstance(node, YamlMapping):
        _fail(path)
    return dict(node.values)


def _scalar(node: YamlValue, path: Path) -> str:
    if not isinstance(node, YamlScalar):
        _fail(path)
    return node.value


def _optional_scalar(node: YamlValue | None, path: Path) -> str | None:
    return _scalar(node, path) if node is not None else None


def _optional_integer(node: YamlValue | None, path: Path) -> int | None:
    if node is None:
        return None
    value = _scalar(node, path)
    if not value.isdecimal():
        _fail(path)
    return int(value)


def _scalar_pairs(node: YamlValue, path: Path) -> ScalarPairs:
    return tuple(
        sorted(
            (key, _scalar(value, path)) for key, value in _mapping(node, path).items()
        )
    )


def _optional_scalar_pairs(node: YamlValue | None, path: Path) -> ScalarPairs:
    return _scalar_pairs(node, path) if node is not None else ()


def _needs(node: YamlValue | None, path: Path) -> tuple[str, ...]:
    match node:
        case None:
            return ()
        case YamlScalar(value=value):
            if value.startswith("[") and value.endswith("]"):
                return tuple(
                    unquote_scalar(item.strip()) for item in value[1:-1].split(",")
                )
            return (value,)
        case YamlSequence(values=children):
            return tuple(_scalar(item, path) for item in children)
        case YamlMapping():
            return _fail(path)


def _string_list(node: YamlValue, path: Path) -> tuple[str, ...]:
    match node:
        case YamlScalar(value=value):
            if value.startswith("[") and value.endswith("]"):
                inner = value[1:-1].strip()
                if not inner:
                    return ()
                return tuple(unquote_scalar(item.strip()) for item in inner.split(","))
            return (value,)
        case YamlSequence(values=children):
            return tuple(_scalar(item, path) for item in children)
        case YamlMapping():
            return _fail(path)


def _fail(path: Path) -> Never:
    raise StaticCheckError(StaticCheckCode.MISSING_EXTERNAL_CI_AUTHORITY, path)
