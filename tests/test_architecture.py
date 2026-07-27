from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import final, override

from tools.architecture_manifest import read_manifest

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

    def test_contract_test_command_confines_vitest_discovery(self) -> None:
        # Given: mise stores a trusted-config symlink back to the checkout.
        scripts = read_manifest(PROJECT_ROOT / "package.json").get("scripts")
        assert isinstance(scripts, dict)
        command = scripts.get("contracts:test")
        assert isinstance(command, str)

        # When/Then: Vitest receives a discovery root, not a positional filter.
        assert command.split() == [
            "vitest",
            "run",
            "--dir",
            "packages/contracts/tests",
        ]

    def test_rejects_missing_high_threat_evidence(self) -> None:
        # Given: one referenced High-threat evidence artifact is absent.
        evidence = self.root.parents[1] / "tools/evidence/security/T07-malicious-files-and-archives.json"
        evidence.unlink()

        # When/Then: verification names the dangling reference.
        self.assert_rejected("missing-evidence:T07")

    def test_rejects_missing_high_threat_evidence_checksum(self) -> None:
        # Given: raw evidence exists without its checksum sidecar.
        checksum = self.root.parents[1] / "tools/evidence/security/T07-malicious-files-and-archives.sha256"
        checksum.unlink()

        # When/Then: verification rejects the unbound artifact.
        self.assert_rejected("missing-evidence-checksum:T07")

    def test_rejects_high_threat_evidence_digest_mismatch(self) -> None:
        # Given: raw evidence changed after its checksum was recorded.
        evidence = self.root.parents[1] / "tools/evidence/security/T07-malicious-files-and-archives.json"
        with evidence.open("ab") as stream:
            _ = stream.write(b"\n")

        # When/Then: verification detects the mutation.
        self.assert_rejected("evidence-digest-mismatch:T07")

    def test_rejects_high_threat_evidence_path_traversal(self) -> None:
        # Given: a path has the expected prefix but escapes the evidence tree.
        self.replace_once(
            "threat-model.json",
            (
                "tools/evidence/security/T07-malicious-files-and-archives.json",
                "tools/evidence/../../outside.json",
            ),
        )

        # When/Then: prefix-only path validation is insufficient and rejected.
        self.assert_rejected("invalid-evidence-path:T07")

    def test_rejects_oauth_refresh_token_exfiltration_control_omission(self) -> None:
        # Given: OAuth token theft lacks its refresh-token confinement control.
        self.replace_once(
            "threat-model.json",
            ('        "refresh-token-never-enters-provider-runtime-process",\n', ""),
        )

        # When/Then: verification names the missing mitigation.
        self.assert_rejected("oauth-refresh-token-exfiltration-mitigation")

    def test_rejects_unowned_trust_boundary(self) -> None:
        # Given: a trust boundary with no accountable owner.
        self.replace_once(
            "architecture.json",
            ('"owner": "identity-platform"', '"owner": ""'),
        )

        # When/Then: verification rejects the unowned boundary.
        self.assert_rejected("unowned-boundary")

    def test_rejects_unclassified_sensitive_field(self) -> None:
        # Given: the OAuth refresh token loses its classification.
        self.replace_once(
            "data-classification.json",
            (
                '"classification": "secret", "retention": "until-disconnect',
                '"retention": "until-disconnect',
            ),
        )

        # When/Then: verification rejects the unclassified sensitive field.
        self.assert_rejected("unclassified-sensitive-field")

    def test_rejects_untested_high_threat(self) -> None:
        # Given: a High OAuth threat with no executable test.
        self.replace_once(
            "threat-model.json",
            (
                '"executable_test": "make test-security CASE=malicious-files-and-archives"',
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

    def test_rejects_literal_gvisor_seccomp_claim(self) -> None:
        # Given: architecture falsely claims gVisor enforces workload seccomp.
        self.replace_once(
            "architecture.json",
            (
                '"gke_gvisor_enforces_workload_seccomp": false',
                '"gke_gvisor_enforces_workload_seccomp": true',
            ),
        )

        # When/Then: verification rejects the literal claim.
        self.assert_rejected("literal-seccomp-claim")


if __name__ == "__main__":
    _ = unittest.main()
