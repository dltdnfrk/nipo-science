#!/usr/bin/env -S uv run --script
# /// script
# requires-python = "==3.12.13"
# dependencies = []
# ///

# ─── How to run ───
#   uv run tools/verify_architecture.py [ARCHITECTURE_DIR]
#   make verify-architecture
# ─────────────────

"""Verify frozen architecture, abuse, and data-classification contracts."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Final

if __package__:
    import tools.architecture_contract as _contract
    import tools.architecture_manifest as _manifest
else:
    sys.path.insert(0, str(Path(__file__).parents[1]))
    import tools.architecture_contract as _contract
    import tools.architecture_manifest as _manifest

PLACEHOLDER_RE: Final = re.compile(r"\b(?:TODO|TBD|FIXME|PLACEHOLDER)\b", re.IGNORECASE)


def _check_architecture(
    root: Path,
    document: _manifest.JsonObject,
    violations: list[str],
) -> None:
    decisions = _manifest.object_items(document, "decisions", violations)
    decision_ids = {
        value for item in decisions if isinstance((value := item.get("id")), str)
    }
    violations.extend(
        f"missing-decision:{missing}"
        for missing in sorted(_contract.REQUIRED_DECISIONS - decision_ids)
    )
    for decision in decisions:
        adr = decision.get("adr")
        if (
            decision.get("status") != "accepted"
            or not isinstance(adr, str)
            or not (root / adr).is_file()
        ):
            violations.append(f"invalid-decision:{decision.get('id')}")

    for boundary in _manifest.object_items(document, "trust_boundaries", violations):
        valid_endpoints = all(
            isinstance(boundary.get(key), str) and boundary[key]
            for key in ("id", "source", "target")
        )
        if not valid_endpoints:
            violations.append("invalid-boundary")
        if not isinstance(boundary.get("owner"), str) or not boundary["owner"]:
            violations.append(f"unowned-boundary:{boundary.get('id')}")

    _check_capabilities(document, violations)


def _check_capabilities(
    document: _manifest.JsonObject,
    violations: list[str],
) -> None:
    contracts = document.get("contracts")
    if not isinstance(contracts, dict):
        violations.append("architecture-contracts-missing")
    else:
        reviewer = contracts.get("reviewer")
        tool_execution = contracts.get("tool_execution")
        if (
            not isinstance(tool_execution, dict)
            or tool_execution.get("executor") != "application"
        ):
            violations.append("application-not-sole-tool-executor")
        if not isinstance(reviewer, dict):
            violations.append("reviewer-contract-missing")
        else:
            allowed = reviewer.get("allowed_capabilities")
            forbidden_terms = (
                "execute",
                "runner",
                "python",
                "bash",
                "connector",
                "write",
                "save",
            )
            forbidden_allowed = isinstance(allowed, list) and any(
                isinstance(capability, str)
                and any(term in capability for term in forbidden_terms)
                for capability in allowed
            )
            if (
                not isinstance(allowed, list)
                or reviewer.get("reexecution") is not False
                or forbidden_allowed
            ):
                violations.append("reviewer-tool-execution")

    claims = document.get("claims")
    if (
        not isinstance(claims, dict)
        or claims.get("gke_gvisor_enforces_workload_seccomp") is not False
    ):
        violations.append("literal-seccomp-claim")


def _check_threats(
    document: _manifest.JsonObject,
    violations: list[str],
) -> None:
    threats = _manifest.object_items(document, "threats", violations)
    threat_names = {
        value for item in threats if isinstance((value := item.get("name")), str)
    }
    violations.extend(
        f"missing-threat:{missing}"
        for missing in sorted(_contract.REQUIRED_THREATS - threat_names)
    )
    for threat in threats:
        if threat.get("severity") != "High":
            continue
        threat_id = threat.get("id")
        if not isinstance(threat.get("owner"), str) or not threat["owner"]:
            violations.append(f"unowned-high-threat:{threat_id}")
        controls = threat.get("controls")
        if not isinstance(controls, list) or not controls:
            violations.append(f"uncontrolled-high-threat:{threat_id}")
        test = threat.get("executable_test")
        if not isinstance(test, str) or not test.startswith("make "):
            violations.append(f"untested-high-threat:{threat_id}")
        evidence = threat.get("evidence_path")
        if not isinstance(evidence, str) or not evidence.startswith("tools/evidence/"):
            violations.append(f"missing-evidence-path:{threat_id}")
    oauth = next(
        (item for item in threats if item.get("name") == "oauth-token-theft"),
        None,
    )
    controls = oauth.get("controls") if oauth is not None else None
    if (
        not isinstance(controls, list)
        or "refresh-token-never-enters-provider-runtime-process" not in controls
    ):
        violations.append("oauth-refresh-token-exfiltration-mitigation")


def _check_data(document: _manifest.JsonObject, violations: list[str]) -> None:
    levels = document.get("classification_levels")
    allowed: frozenset[str] = (
        frozenset(value for value in levels if isinstance(value, str))
        if isinstance(levels, list)
        else frozenset()
    )
    fields = _manifest.object_items(document, "fields", violations)
    field_ids = {value for item in fields if isinstance((value := item.get("id")), str)}
    violations.extend(
        f"missing-data-field:{missing}"
        for missing in sorted(_contract.REQUIRED_FIELDS - field_ids)
    )
    for field in fields:
        field_id = field.get("id")
        if (
            field.get("sensitive") is True
            and field.get("classification") not in allowed
        ):
            violations.append(f"unclassified-sensitive-field:{field_id}")
        violations.extend(
            f"missing-data-policy:{field_id}:{key}"
            for key in ("retention", "egress", "redaction")
            if not isinstance(field.get(key), str) or not field[key]
        )


def _verify(root: Path) -> tuple[str, ...]:
    violations: list[str] = []
    architecture = _manifest.read_manifest(root / "architecture.json")
    _check_architecture(root, architecture, violations)
    _check_threats(_manifest.read_manifest(root / "threat-model.json"), violations)
    _check_data(
        _manifest.read_manifest(root / "data-classification.json"),
        violations,
    )
    paths = sorted((*root.rglob("*.md"), *root.glob("*.json")))
    violations.extend(
        f"unresolved-placeholder:{path.relative_to(root)}"
        for path in paths
        if PLACEHOLDER_RE.search(path.read_text(encoding="utf-8"))
    )
    return tuple(violations)


def _main(arguments: list[str]) -> int:
    if arguments == ["--help"]:
        _ = sys.stdout.write("usage: verify_architecture.py [ARCHITECTURE_DIR]\n")
        return 0
    if len(arguments) > 1:
        _ = sys.stderr.write("usage: verify_architecture.py [ARCHITECTURE_DIR]\n")
        return 2
    root = Path(arguments[0] if arguments else "docs/architecture").resolve()
    if not root.is_dir():
        _ = sys.stderr.write(
            f"architecture-check: architecture directory missing: {root}\n"
        )
        return 2
    try:
        violations = _verify(root)
    except _manifest.ManifestError as error:
        _ = sys.stderr.write(f"architecture-check: invalid manifest: {error}\n")
        return 2
    if violations:
        for violation in violations:
            _ = sys.stdout.write(f"ARCHITECTURE VIOLATION [{violation}]\n")
        return 1
    counts = "9 decisions, 11 boundaries, 13 High threats, 8 classified fields"
    report = f"architecture-check: PASS ({counts})"
    _ = sys.stdout.write(f"{report}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
