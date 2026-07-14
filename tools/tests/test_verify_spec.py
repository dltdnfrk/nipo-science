"""Mutation tests for the normative SPEC verifier."""

from __future__ import annotations

import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from tools.spec_contract import ContractParseError, VerificationError
from tools.verify_spec import verify_contract

if TYPE_CHECKING:
    from collections.abc import Generator

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs/requirements/requirements.yaml"
SPEC = ROOT / "docs/spec/SPEC-v0.4.md"
MINIMUM_REQUIREMENT_COUNT: Final = 70


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


if __name__ == "__main__":
    _ = unittest.main()
