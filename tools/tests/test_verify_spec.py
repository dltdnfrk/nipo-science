"""Mutation tests for the normative SPEC verifier."""

from __future__ import annotations

import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from tools.spec_contract import (
    V05_EXPECTED_IDS,
    ContractParseError,
    VerificationError,
)
from tools.verify_spec import verify_contract, verify_contract_v05

if TYPE_CHECKING:
    from collections.abc import Generator

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs/requirements/requirements.yaml"
SPEC = ROOT / "docs/spec/SPEC-v0.4.md"
MINIMUM_REQUIREMENT_COUNT: Final = 70
MANIFEST_V05 = ROOT / "docs/requirements/requirements-v0.5.yaml"
SPEC_V05 = ROOT / "docs/spec/SPEC-v0.5.md"
V05_REQUIREMENT_COUNT: Final = 64


class VerifySpecTests(unittest.TestCase):
    """Exercise the canonical contract and every protected mutation class."""

    @contextmanager
    def mutated_manifest(self, old: str, new: str) -> Generator[Path]:
        """Yield a temporary manifest containing exactly one text mutation."""
        original = MANIFEST.read_text(encoding="utf-8")
        if old not in original:
            pytest.fail(f"canonical manifest does not contain mutation target: {old}")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements.yaml"
            _ = path.write_text(original.replace(old, new, 1), encoding="utf-8")
            yield path

    def assert_mutation_rejected(self, old: str, new: str, label: str) -> None:
        """Assert that one manifest mutation raises the named verification error."""
        with (
            self.mutated_manifest(old, new) as manifest,
            pytest.raises(VerificationError, match=label),
        ):
            _ = verify_contract(manifest, SPEC)

    def test_accepts_canonical_contract(self) -> None:
        """Accept the unmodified v0.4 contract with its complete ID inventory."""
        report = verify_contract(MANIFEST, SPEC)
        if report.spec_version != "0.4":
            pytest.fail(f"unexpected SPEC version: {report.spec_version}")
        if report.requirement_count <= MINIMUM_REQUIREMENT_COUNT:
            pytest.fail(f"incomplete requirement inventory: {report.requirement_count}")

    def test_rejects_monetary_budget_error_token(self) -> None:
        """Reject a monetary budget error code added to the manifest."""
        self.assert_mutation_rejected(
            '"error_codes": []',
            '"error_codes": ["BUDGET_HARD_CAP"]',
            "monetary semantics",
        )

    def test_rejects_api_key_runtime_auth(self) -> None:
        """Reject API-key authentication in the OAuth-only runtime contract."""
        self.assert_mutation_rejected(
            '"auth_mode": "official_subscription_oauth"',
            '"auth_mode": "api_key"',
            "OAuth-only",
        )

    def test_rejects_literal_seccomp_requirement(self) -> None:
        """Reject literal seccomp in place of measured gVisor outcomes."""
        self.assert_mutation_rejected(
            '"enforcement_claim": "outcome_measured"',
            '"enforcement_claim": "literal_seccomp_required"',
            "gVisor outcomes",
        )

    def test_rejects_missing_required_runtime(self) -> None:
        """Reject omission of the required openai_codex runtime."""
        self.assert_mutation_rejected(
            '"required_runtimes": ["openai_codex"]',
            '"required_runtimes": []',
            "required runtime",
        )

    def test_rejects_missing_exact_acceptance_id(self) -> None:
        """Reject renaming an exact AC-F13 acceptance identifier."""
        self.assert_mutation_rejected('"AC-F13-D": {', '"AC-F13-X": {', "exact IDs")

    def test_rejects_renamed_skill(self) -> None:
        """Reject renaming one of the three canonical Skill identifiers."""
        self.assert_mutation_rejected(
            '"literature-review"',
            '"literature-search"',
            "Skill IDs",
        )

    def test_rejects_review_api_drift(self) -> None:
        """Reject drift from the persisted Review polling API."""
        self.assert_mutation_rejected(
            '"get_path": "/reviews/{id}"',
            '"get_path": "/sessions/{sessionId}/reviews"',
            "Review API",
        )

    def test_rejects_incomplete_dry_lab_chain(self) -> None:
        """Reject omission of provenance from the deterministic dry-lab chain."""
        self.assert_mutation_rejected('"provenance",', "", "dry-lab chain")

    def test_rejects_missing_break_glass_contract(self) -> None:
        """Reject omission of the bounded SEC14 break-glass contract."""
        with (
            self.mutated_manifest(
                '"break_glass": {', '"break_glass_removed": {'
            ) as manifest,
            pytest.raises(ContractParseError, match="break_glass"),
        ):
            _ = verify_contract(manifest, SPEC)


class VerifySpecV05Tests(unittest.TestCase):
    """Exercise the v0.5 local-first contract and its protected mutations."""

    @contextmanager
    def mutated_manifest(self, old: str, new: str) -> Generator[Path]:
        """Yield a temporary v0.5 manifest containing exactly one mutation."""
        original = MANIFEST_V05.read_text(encoding="utf-8")
        if old not in original:
            pytest.fail(f"v0.5 manifest does not contain mutation target: {old}")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "docs" / "requirements" / "requirements-v0.5.yaml"
            path.parent.mkdir(parents=True)
            _ = path.write_text(original.replace(old, new, 1), encoding="utf-8")
            yield path

    def assert_mutation_rejected(self, old: str, new: str, label: str) -> None:
        """Assert that one v0.5 manifest mutation raises the named error."""
        with (
            self.mutated_manifest(old, new) as manifest,
            pytest.raises(VerificationError, match=label),
        ):
            _ = verify_contract_v05(manifest, SPEC_V05)

    def test_accepts_canonical_v05_contract(self) -> None:
        """Accept the unmodified v0.5 contract with its complete ID inventory."""
        report = verify_contract_v05(MANIFEST_V05, SPEC_V05)
        if report.spec_version != "0.5":
            pytest.fail(f"unexpected SPEC version: {report.spec_version}")
        if report.requirement_count != V05_REQUIREMENT_COUNT:
            pytest.fail(
                f"incomplete v0.5 requirement inventory: {report.requirement_count}"
            )

    def test_v05_id_set_is_the_stage3_trusted_source(self) -> None:
        """Pin the v0.5 ID frozenset destined for TRUSTED_REQUIREMENT_IDS."""
        if len(V05_EXPECTED_IDS) != V05_REQUIREMENT_COUNT:
            pytest.fail(f"v0.5 ID set drifted: {len(V05_EXPECTED_IDS)}")
        sentinels = (
            "L01",
            "L12",
            "AC-L01",
            "AC-L12-B",
            "AC-SAFE",
            "AC-DETERMINISM",
            "AC-LOCAL",
            "LS01",
            "LS10",
            "RV01",
            "RV05",
            "GL01",
            "GL08",
            "LN01",
            "LN08",
        )
        for identifier in sentinels:
            if identifier not in V05_EXPECTED_IDS:
                pytest.fail(f"missing v0.5 requirement ID: {identifier}")

    def test_rejects_renamed_v05_acceptance_id(self) -> None:
        """Reject renaming an exact AC-L12-B acceptance identifier."""
        self.assert_mutation_rejected('"AC-L12-B": {', '"AC-L12-X": {', "exact v0.5")

    def test_rejects_monetary_budget_error_token(self) -> None:
        """Reject a monetary budget error code added to the v0.5 manifest."""
        self.assert_mutation_rejected(
            '"error_codes": []',
            '"error_codes": ["BUDGET_HARD_CAP"]',
            "monetary semantics",
        )

    def test_rejects_automatic_provider_fallback(self) -> None:
        """Reject automatic provider fallback in the v0.5 provider contract."""
        self.assert_mutation_rejected(
            '"automatic_fallback": "forbidden"',
            '"automatic_fallback": "allowed"',
            "no automatic fallback",
        )

    def test_rejects_overstated_isolation_claim(self) -> None:
        """Reject an undisclosed sandbox isolation claim in the v0.5 manifest."""
        self.assert_mutation_rejected(
            '"isolation_level": "in_process"',
            '"isolation_level": "sandboxed"',
            "in-process isolation",
        )

    def test_rejects_listener_beyond_loopback(self) -> None:
        """Reject a listener bound beyond loopback in the v0.5 deployment."""
        self.assert_mutation_rejected(
            '"listener": "loopback_only"',
            '"listener": "any_interface"',
            "loopback-only deployment",
        )

    def test_rejects_incomplete_local_dry_lab_chain(self) -> None:
        """Reject omission of in-process Python from the local dry-lab chain."""
        self.assert_mutation_rejected(
            '"in_process_python",', "", "local dry-lab chain"
        )

    def test_rejects_added_reviewer_capability(self) -> None:
        """Reject granting the v0.5 Reviewer an artifact-write capability."""
        self.assert_mutation_rejected(
            '"artifact_write": false',
            '"artifact_write": true',
            "Reviewer capabilities",
        )

    def test_manifest_path_is_location_parameterized(self) -> None:
        """Verify the v0.5 contract from a relocated manifest and SPEC pair."""
        with tempfile.TemporaryDirectory() as directory:
            manifest = (
                Path(directory) / "docs" / "requirements" / "requirements-v0.5.yaml"
            )
            spec = Path(directory) / "docs" / "spec" / "SPEC-v0.5.md"
            manifest.parent.mkdir(parents=True)
            spec.parent.mkdir(parents=True)
            _ = manifest.write_text(
                MANIFEST_V05.read_text(encoding="utf-8"), encoding="utf-8"
            )
            _ = spec.write_text(SPEC_V05.read_text(encoding="utf-8"), encoding="utf-8")
            report = verify_contract_v05(manifest, spec)
        if report.spec_version != "0.5":
            pytest.fail(f"unexpected SPEC version: {report.spec_version}")

    def test_canonical_manifest_transition_needs_no_code_change(self) -> None:
        """Verify a v0.5 manifest re-anchored at canonical requirements.yaml."""
        declaration = "requirements_manifest: docs/requirements/requirements"
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "docs" / "requirements" / "requirements.yaml"
            spec = Path(directory) / "docs" / "spec" / "SPEC-v0.5.md"
            manifest.parent.mkdir(parents=True)
            spec.parent.mkdir(parents=True)
            _ = manifest.write_text(
                MANIFEST_V05.read_text(encoding="utf-8"), encoding="utf-8"
            )
            spec_original = SPEC_V05.read_text(encoding="utf-8")
            declared_v05 = f"{declaration}-v0.5.yaml"
            if declared_v05 not in spec_original:
                pytest.fail(f"SPEC-v0.5 lacks manifest declaration: {declared_v05}")
            spec_text = spec_original.replace(declared_v05, f"{declaration}.yaml", 1)
            _ = spec.write_text(spec_text, encoding="utf-8")
            report = verify_contract_v05(manifest, spec)
        if report.spec_version != "0.5":
            pytest.fail(f"unexpected SPEC version: {report.spec_version}")


if __name__ == "__main__":
    _ = unittest.main()
