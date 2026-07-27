from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import final, override

PROJECT_ROOT = Path(__file__).parents[1]
CHECKER = PROJECT_ROOT / "tools" / "verify_architecture.py"
SOURCE = PROJECT_ROOT / "docs" / "architecture"


@final
class ArchitectureVerifierTests(unittest.TestCase):
    root: Path = Path()

    @override
    def setUp(self) -> None:
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(directory) / "docs" / "architecture"
        _ = shutil.copytree(SOURCE, self.root)
        _ = shutil.copytree(
            PROJECT_ROOT / "tools" / "evidence",
            Path(directory) / "tools" / "evidence",
        )

    def run_verifier(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECKER), str(self.root)],
            check=False,
            capture_output=True,
            text=True,
        )

    def replace_once(self, relative: str, replacement: tuple[str, str]) -> None:
        path = self.root / relative
        before, after = replacement
        contents = path.read_text(encoding="utf-8")
        assert contents.count(before) == 1
        _ = path.write_text(contents.replace(before, after), encoding="utf-8")

    def assert_rejected(self, expected: str) -> None:
        result = self.run_verifier()
        assert result.returncode != 0
        assert expected in result.stdout + result.stderr

    def test_accepts_complete_architecture_contract(self) -> None:
        # Given: the checked-in architecture contract.

        # When: its manifests and ADRs are verified.
        result = self.run_verifier()

        # Then: the contract is complete.
        assert result.returncode == 0, result.stdout + result.stderr
        assert "architecture-check: PASS" in result.stdout

    def test_contract_test_commands_confine_vitest_discovery(self) -> None:
        # Given: mise stores a trusted-config symlink back to the checkout.
        makefile = (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8")
        vitest_lines = [
            line for line in makefile.splitlines() if "vitest run" in line
        ]
        assert vitest_lines

        # When/Then: every Vitest invocation receives a discovery root.
        for line in vitest_lines:
            assert "vitest run --dir packages/contracts/tests" in line

    def test_rejects_missing_high_threat_evidence(self) -> None:
        # Given: one referenced High-threat evidence artifact is absent.
        evidence = self.root.parents[1] / "tools/evidence/security/T11-export-traversal.json"
        evidence.unlink()

        # When/Then: verification names the dangling reference.
        self.assert_rejected("missing-evidence:T11")

    def test_rejects_missing_high_threat_evidence_checksum(self) -> None:
        # Given: raw evidence exists without its checksum sidecar.
        checksum = self.root.parents[1] / "tools/evidence/security/T11-export-traversal.sha256"
        checksum.unlink()

        # When/Then: verification rejects the unbound artifact.
        self.assert_rejected("missing-evidence-checksum:T11")

    def test_rejects_high_threat_evidence_digest_mismatch(self) -> None:
        # Given: raw evidence changed after its checksum was recorded.
        evidence = self.root.parents[1] / "tools/evidence/security/T11-export-traversal.json"
        with evidence.open("ab") as stream:
            _ = stream.write(b"\n")

        # When/Then: verification detects the mutation.
        self.assert_rejected("evidence-digest-mismatch:T11")

    def test_rejects_high_threat_evidence_path_traversal(self) -> None:
        # Given: a path has the expected prefix but escapes the evidence tree.
        self.replace_once(
            "threat-model.json",
            (
                "tools/evidence/security/T11-export-traversal.json",
                "tools/evidence/../../outside.json",
            ),
        )

        # When/Then: prefix-only path validation is insufficient and rejected.
        self.assert_rejected("invalid-evidence-path:T11")

    def test_rejects_plaintext_provider_key_control_omission(self) -> None:
        # Given: credential theft lacks its plaintext-never-persisted control.
        self.replace_once(
            "threat-model.json",
            ('"plaintext-provider-key-never-persisted", ', ""),
        )

        # When/Then: verification names the missing mitigation.
        self.assert_rejected("plaintext-provider-key-mitigation")

    def test_rejects_unowned_trust_boundary(self) -> None:
        # Given: a trust boundary with no accountable owner.
        self.replace_once(
            "architecture.json",
            ('"owner": "review-platform"', '"owner": ""'),
        )

        # When/Then: verification rejects the unowned boundary.
        self.assert_rejected("unowned-boundary")

    def test_rejects_unclassified_sensitive_field(self) -> None:
        # Given: the provider API key loses its classification.
        self.replace_once(
            "data-classification.json",
            (
                '"classification": "secret", "retention": "until the researcher',
                '"retention": "until the researcher',
            ),
        )

        # When/Then: verification rejects the unclassified sensitive field.
        self.assert_rejected("unclassified-sensitive-field")

    def test_rejects_untested_high_threat(self) -> None:
        # Given: a High threat with no executable test.
        self.replace_once(
            "threat-model.json",
            (
                '"executable_test": "make test-security CASE=export-traversal"',
                '"executable_test": ""',
            ),
        )

        # When/Then: verification rejects the missing test.
        self.assert_rejected("untested-high-threat")

    def test_rejects_unresolved_placeholder(self) -> None:
        # Given: an unresolved marker in an accepted ADR.
        path = self.root / "decisions" / "ADR-0001-isolated-monorepo.md"
        _ = path.write_text(
            path.read_text(encoding="utf-8") + "\nTBD\n",
            encoding="utf-8",
        )

        # When/Then: verification rejects the placeholder.
        self.assert_rejected("unresolved-placeholder")

    def test_rejects_reviewer_tool_execution(self) -> None:
        # Given: Reviewer is granted a Python execution capability.
        self.replace_once(
            "architecture.json",
            (
                '"submit_findings_once"\n',
                '"submit_findings_once",\n        "python.execute"\n',
            ),
        )

        # When/Then: verification rejects Reviewer execution.
        self.assert_rejected("reviewer-tool-execution")

    def test_rejects_overstated_isolation_claim(self) -> None:
        # Given: architecture falsely claims in-process execution confines code.
        self.replace_once(
            "architecture.json",
            (
                '"in_process_execution_provides_confinement": false',
                '"in_process_execution_provides_confinement": true',
            ),
        )

        # When/Then: verification rejects the overstated claim.
        self.assert_rejected("overstated-isolation-claim")


if __name__ == "__main__":
    _ = unittest.main()
