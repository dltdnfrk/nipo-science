#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

# ─── How to run ───
# Run: make verify-spec
# ─────────────────

"""Verify the machine-readable requirements and normative SPEC metadata."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Final, Protocol

from tools.spec_contract import (
    DRY_LAB_CHAIN,
    EXPECTED_IDS,
    P0_IDS,
    RV_IDS,
    SKILL_IDS,
    STACK,
    V05_DRY_LAB_CHAIN,
    V05_EXPECTED_IDS,
    V05_P0_IDS,
    V05_STACK,
    ContractParseError,
    VerificationError,
    VerificationReport,
    add_error,
    child_bool,
    child_map,
    child_str,
    child_strs,
    declares_manifest,
    frontmatter_fields,
    frontmatter_version,
    load_root,
)
from tools.spec_runtime import verify_runtime, verify_runtime_v05

EXPECTED_ARGUMENTS: Final = 2


class TextSink(Protocol):
    """Accept text written by the verifier CLI boundary."""

    def write(self, text: str, /) -> int:
        """Write text and return the number of accepted characters."""
        ...


def write_line(sink: TextSink, message: str) -> None:
    """Write one newline-terminated CLI message to a typed sink."""
    _ = sink.write(f"{message}\n")


def verify_contract(manifest_path: Path, spec_path: Path) -> VerificationReport:
    """Verify all normative manifest invariants and SPEC metadata."""
    root = load_root(manifest_path)
    errors: list[str] = []
    spec = child_map(root, "spec")
    version = frontmatter_version(spec_path)
    add_error(version == "0.4" == child_str(spec, "version"), "SPEC version", errors)
    add_error(child_str(spec, "path") == "docs/spec/SPEC-v0.4.md", "SPEC path", errors)
    add_error(child_map(root, "stack") == STACK, "required runtime stack", errors)
    add_error(child_strs(root, "p0_features") == P0_IDS, "P0 F01-F11/F13 IDs", errors)

    verify_runtime(root, errors)

    money = child_map(root, "monetary_semantics")
    empty_money = child_str(money, "state") == "absent" and all(
        money.get(key) == []
        for key in (
            "schema_fields",
            "api_operations",
            "event_fields",
            "error_codes",
            "approval_fields",
            "metrics",
        )
    )
    add_error(empty_money, "zero monetary semantics", errors)
    tools = child_map(root, "tool_governance")
    add_error(
        child_str(tools, "requirement_id") == "F11"
        and child_strs(tools, "scope") == ("tool_grant", "plan_approval"),
        "F11 Tool Grant/Plan Approval only",
        errors,
    )

    review = child_map(root, "review")
    add_error(
        child_str(review, "create_path") == "/reviews"
        and child_str(review, "get_path") == "/reviews/{id}",
        "Review API",
        errors,
    )
    add_error(
        child_strs(review, "create_response") == ("review_id", "run_id", "status")
        and child_str(review, "run_owner") == "system",
        "Review lifecycle",
        errors,
    )
    add_error(
        not child_bool(review, "reviewer_reexecution"),
        "Reviewer non-reexecution",
        errors,
    )
    capabilities = child_map(review, "reviewer_capabilities")
    add_error(
        set(capabilities) == {"runner", "python", "bash", "connector", "artifact_write"}
        and all(value is False for value in capabilities.values()),
        "Reviewer capabilities",
        errors,
    )
    compliance = child_map(root, "compliance")
    add_error(
        child_str(compliance, "legal_hold_authority") == "compliance_operator"
        and child_str(compliance, "owner_legal_hold_access") == "read_only",
        "Compliance Operator authority",
        errors,
    )
    break_glass = child_map(root, "break_glass")
    add_error(
        child_str(break_glass, "authority_role")
        == "internal_security_incident_operator"
        and child_bool(break_glass, "legal_hold_authority_separate")
        and not child_bool(break_glass, "standing_access")
        and child_str(break_glass, "scope") == "least_privilege_resource_and_action"
        and child_bool(break_glass, "reason_required")
        and child_bool(break_glass, "approval_required")
        and child_str(break_glass, "expiry") == "bounded"
        and child_str(break_glass, "revocation") == "immediate"
        and child_str(break_glass, "audit") == "immutable_access_log",
        "bounded break-glass contract",
        errors,
    )
    add_error(
        child_strs(child_map(root, "skills"), "ids") == SKILL_IDS,
        "canonical Skill IDs",
        errors,
    )
    add_error(
        child_strs(child_map(root, "dry_lab"), "ordered_chain") == DRY_LAB_CHAIN,
        "complete dry-lab chain",
        errors,
    )
    sandbox = child_map(root, "sandbox")
    add_error(
        child_str(sandbox, "runtime") == "gvisor"
        and child_str(sandbox, "enforcement_claim") == "outcome_measured"
        and sandbox.get("literal_control_claims") == [],
        "measured gVisor outcomes",
        errors,
    )
    scope = child_map(root, "scope")
    add_error(
        child_str(scope, "product_use") == "research_only_non_clinical"
        and child_str(scope, "clinical_diagnosis") == "forbidden",
        "research-only scope",
        errors,
    )
    requirement_ids = frozenset(child_map(root, "requirements"))
    add_error(
        requirement_ids == EXPECTED_IDS,
        "exact IDs including AC-F13/AC-F13-B/AC-F13-C/AC-F13-D",
        errors,
    )
    if errors:
        raise VerificationError(tuple(errors))
    return VerificationReport(version, len(requirement_ids), len(P0_IDS))


def verify_contract_v05(manifest_path: Path, spec_path: Path) -> VerificationReport:
    """Verify the local-first v0.5 manifest invariants and SPEC metadata."""
    root = load_root(manifest_path)
    errors: list[str] = []
    fields = frontmatter_fields(spec_path)
    spec = child_map(root, "spec")
    version = fields.get("version", "").strip('"')
    add_error(version == "0.5" == child_str(spec, "version"), "SPEC version", errors)
    add_error(child_str(spec, "path") == "docs/spec/SPEC-v0.5.md", "SPEC path", errors)
    add_error(
        child_str(spec, "supersedes") == "docs/spec/SPEC-v0.4.md",
        "SPEC supersession",
        errors,
    )
    add_error(
        declares_manifest(fields, manifest_path),
        "SPEC manifest declaration",
        errors,
    )
    add_error(child_map(root, "stack") == V05_STACK, "required local stack", errors)
    add_error(child_strs(root, "p0_features") == V05_P0_IDS, "P0 L01-L12 IDs", errors)

    verify_runtime_v05(root, errors)

    money = child_map(root, "monetary_semantics")
    empty_money = child_str(money, "state") == "absent" and all(
        money.get(key) == []
        for key in (
            "schema_fields",
            "api_operations",
            "event_fields",
            "error_codes",
            "approval_fields",
            "metrics",
        )
    )
    add_error(empty_money, "zero monetary semantics", errors)
    deployment = child_map(root, "deployment")
    add_error(
        child_str(deployment, "shape") == "single_user_on_device"
        and child_str(deployment, "tenancy") == "absent"
        and child_str(deployment, "accounts") == "absent"
        and child_str(deployment, "roles") == "absent"
        and child_str(deployment, "listener") == "loopback_only"
        and child_str(deployment, "remote_access_toggle") == "absent",
        "single-user loopback-only deployment",
        errors,
    )
    scope = child_map(root, "scope")
    add_error(
        child_str(scope, "product_use") == "research_only_non_clinical"
        and child_str(scope, "clinical_diagnosis") == "forbidden",
        "research-only scope",
        errors,
    )
    review = child_map(root, "review")
    add_error(
        not child_bool(review, "reviewer_reexecution"),
        "Reviewer non-reexecution",
        errors,
    )
    capabilities = child_map(review, "reviewer_capabilities")
    add_error(
        set(capabilities)
        == {
            "runner",
            "python",
            "bash",
            "connector",
            "network",
            "tool_execute",
            "artifact_write",
            "version_update",
        }
        and all(value is False for value in capabilities.values()),
        "Reviewer capabilities",
        errors,
    )
    add_error(child_strs(review, "rules") == RV_IDS, "RV01-RV05 review rules", errors)
    add_error(
        child_strs(child_map(root, "dry_lab"), "ordered_chain") == V05_DRY_LAB_CHAIN,
        "complete local dry-lab chain",
        errors,
    )
    release = child_map(root, "release_gate")
    add_error(
        frozenset(child_strs(release, "required")) == V05_EXPECTED_IDS,
        "release gate requirement IDs",
        errors,
    )
    requirement_ids = frozenset(child_map(root, "requirements"))
    add_error(
        requirement_ids == V05_EXPECTED_IDS,
        "exact v0.5 AC-L/LS/RV/GL/LN IDs",
        errors,
    )
    if errors:
        raise VerificationError(tuple(errors))
    return VerificationReport(version, len(requirement_ids), len(V05_P0_IDS))


def main(arguments: list[str]) -> int:
    """Run the verifier CLI and return a process exit code."""
    if len(arguments) != EXPECTED_ARGUMENTS:
        write_line(sys.stderr, "usage: verify_spec.py REQUIREMENTS_YAML SPEC_MD")
        return 2
    manifest_path = Path(arguments[0])
    spec_path = Path(arguments[1])
    try:
        fields = frontmatter_fields(spec_path)
        if fields.get("version", "").strip('"') == "0.5":
            report = verify_contract_v05(manifest_path, spec_path)
        else:
            report = verify_contract(manifest_path, spec_path)
    except (
        FileNotFoundError,
        json.JSONDecodeError,
        ContractParseError,
        VerificationError,
    ) as error:
        write_line(sys.stderr, f"spec-verification: FAIL: {error}")
        return 1
    summary = (
        f"spec-verification: PASS (v{report.spec_version}; "
        f"{report.requirement_count} IDs; {report.p0_count} P0 features)"
    )
    write_line(sys.stdout, summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
