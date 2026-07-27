"""Mutation tests for the normative SPEC verifier."""

from __future__ import annotations

import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from tools.platform_policy.ci_contract import TRUSTED_REQUIREMENT_IDS
from tools.spec_contract import V05_EXPECTED_IDS, VerificationError
from tools.verify_spec import verify_contract_v05

if TYPE_CHECKING:
    from collections.abc import Generator

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs/requirements/requirements.yaml"
SPEC = ROOT / "docs/spec/SPEC-v0.5.md"
V05_REQUIREMENT_COUNT: Final = 64


class VerifySpecV05Tests(unittest.TestCase):
    """Exercise the v0.5 local-first contract and its protected mutations."""

    @contextmanager
    def mutated_manifest(self, old: str, new: str) -> Generator[Path]:
        """Yield a temporary canonical manifest containing exactly one mutation."""
        original = MANIFEST.read_text(encoding="utf-8")
        if old not in original:
            pytest.fail(f"canonical manifest does not contain mutation target: {old}")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "docs" / "requirements" / "requirements.yaml"
            path.parent.mkdir(parents=True)
            _ = path.write_text(original.replace(old, new, 1), encoding="utf-8")
            yield path

    def assert_mutation_rejected(self, old: str, new: str, label: str) -> None:
        """Assert that one manifest mutation raises the named verification error."""
        with (
            self.mutated_manifest(old, new) as manifest,
            pytest.raises(VerificationError, match=label),
        ):
            _ = verify_contract_v05(manifest, SPEC)

    def test_accepts_canonical_contract(self) -> None:
        """Accept the unmodified canonical v0.5 contract in place."""
        report = verify_contract_v05(MANIFEST, SPEC)
        if report.spec_version != "0.5":
            pytest.fail(f"unexpected SPEC version: {report.spec_version}")
        if report.requirement_count != V05_REQUIREMENT_COUNT:
            pytest.fail(
                f"incomplete v0.5 requirement inventory: {report.requirement_count}"
            )

    def test_v05_id_set_matches_the_trusted_requirement_source(self) -> None:
        """Pin the v0.5 ID frozenset mirrored into TRUSTED_REQUIREMENT_IDS."""
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

    def test_trusted_requirement_ids_equal_the_v05_set(self) -> None:
        """Bind the CI trust anchor to exactly the v0.5 requirement inventory."""
        if TRUSTED_REQUIREMENT_IDS != V05_EXPECTED_IDS:
            pytest.fail("TRUSTED_REQUIREMENT_IDS diverged from V05_EXPECTED_IDS")

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
            manifest = Path(directory) / "docs" / "requirements" / "requirements.yaml"
            spec = Path(directory) / "docs" / "spec" / "SPEC-v0.5.md"
            manifest.parent.mkdir(parents=True)
            spec.parent.mkdir(parents=True)
            _ = manifest.write_text(
                MANIFEST.read_text(encoding="utf-8"), encoding="utf-8"
            )
            _ = spec.write_text(SPEC.read_text(encoding="utf-8"), encoding="utf-8")
            report = verify_contract_v05(manifest, spec)
        if report.spec_version != "0.5":
            pytest.fail(f"unexpected SPEC version: {report.spec_version}")

    def test_rejects_undeclared_manifest_location(self) -> None:
        """Reject verification against a manifest the SPEC does not declare."""
        original = MANIFEST.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "docs" / "requirements" / "renamed.yaml"
            manifest.parent.mkdir(parents=True)
            _ = manifest.write_text(original, encoding="utf-8")
            with pytest.raises(VerificationError, match="manifest declaration"):
                _ = verify_contract_v05(manifest, SPEC)


if __name__ == "__main__":
    _ = unittest.main()
