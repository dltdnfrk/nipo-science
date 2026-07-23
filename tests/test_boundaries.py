from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.boundary_adversarial_cases import BAD_CASES, SAFE_CASES
from tools.boundary_node_cases import ABS_OUT
from tools.boundary_shell_cases import ABSOLUTE_OUTSIDE

CHECKER = Path(__file__).parents[1] / "tools" / "check_boundaries.py"


class BoundaryCheckerTests(unittest.TestCase):
    def test_absolute_attack_fixtures_are_machine_independent(self) -> None:
        for fixture_path in (ABS_OUT, ABSOLUTE_OUTSIDE):
            with self.subTest(fixture_path=fixture_path):
                self.assertTrue(Path(fixture_path).is_absolute())
                self.assertNotIn("/Users/", fixture_path)

    def run_checker(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECKER), str(root)],
            check=False,
            capture_output=True,
            text=True,
        )

    def assert_named_rejection(self, fixture: tuple[str, str], expected: str) -> None:
        # Given: a synthetic project containing one boundary violation.
        relative_path, contents = fixture
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "science-workbench"
            path = root / relative_path
            _ = path.parent.mkdir(parents=True)
            _ = path.write_text(contents, encoding="utf-8")

            # When: the project boundary is checked through its CLI.
            result = self.run_checker(root)

        # Then: the CLI rejects it and names the violated boundary.
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(expected, result.stdout + result.stderr)

    def test_accepts_files_confined_to_target_when_project_is_clean(self) -> None:
        # Given: a project whose files and references remain under its root.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "science-workbench"
            source = root / "src" / "main.py"
            _ = source.parent.mkdir(parents=True)
            _ = source.write_text("from pathlib import Path\n", encoding="utf-8")

            # When: the project boundary is checked through its CLI.
            result = self.run_checker(root)

        # Then: the CLI accepts the project.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_ignores_generated_cache_when_file_contains_sibling_import(self) -> None:
        # Given: generated cache content that is outside the repository boundary surface.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "science-workbench"
            cached = root / ".cache" / "mise" / "bad.py"
            _ = cached.parent.mkdir(parents=True)
            _ = cached.write_text("from drylab.pipeline import run\n", encoding="utf-8")

            # When: the project boundary is checked through its CLI.
            result = self.run_checker(root)

        # Then: generated cache content is ignored.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_ignores_root_evidence_but_scans_nested_artifact_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "science-workbench"
            evidence = root / "artifacts" / "generated.py"
            source = root / "services" / "api" / "artifacts" / "repository.py"
            evidence.parent.mkdir(parents=True)
            source.parent.mkdir(parents=True)
            _ = evidence.write_text(
                "from drylab.pipeline import run\n",
                encoding="utf-8",
            )
            _ = source.write_text(
                "from drylab.pipeline import run\n",
                encoding="utf-8",
            )

            result = self.run_checker(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("services/api/artifacts/repository.py", result.stdout)
        self.assertNotIn("artifacts/generated.py", result.stdout)

    def test_accepts_unlink_of_tempfile_mkstemp_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "science-workbench"
            source = root / "tools" / "capture.py"
            source.parent.mkdir(parents=True)
            _ = source.write_text(
                "import tempfile\n"
                "from pathlib import Path\n"
                "descriptor, snapshot = tempfile.mkstemp()\n"
                "Path(snapshot).unlink()\n",
                encoding="utf-8",
            )

            result = self.run_checker(root)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rejects_sibling_import_when_source_imports_drylab(self) -> None:
        self.assert_named_rejection(
            ("src/analysis.py", "from drylab.pipeline import run\n"),
            "sibling-import",
        )

    def test_rejects_path_dependency_when_manifest_uses_ontologylab(self) -> None:
        self.assert_named_rejection(
            ("package.json", '{"dependencies":{"ontology":"file:../ontologylab"}}\n'),
            "sibling-path-dependency",
        )

    def test_rejects_workspace_reference_when_workspace_escapes_root(self) -> None:
        self.assert_named_rejection(
            ("pnpm-workspace.yaml", "packages:\n  - ../drylab\n"),
            "workspace-reference",
        )

    def test_rejects_symlink_when_target_escapes_root(self) -> None:
        # Given: a synthetic project with a symlink to a synthetic sibling.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "science-workbench"
            root.mkdir()
            sibling = Path(directory) / "drylab"
            sibling.mkdir()
            (root / "linked-drylab").symlink_to(sibling, target_is_directory=True)

            # When: the project boundary is checked through its CLI.
            result = self.run_checker(root)

        # Then: the CLI rejects it and names the violated boundary.
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("escaping-symlink", result.stdout + result.stderr)

    def test_rejects_build_input_when_docker_copy_escapes_root(self) -> None:
        self.assert_named_rejection(
            ("Dockerfile", "COPY ../shared-data /opt/shared-data\n"),
            "outside-build-input",
        )

    def test_rejects_write_path_when_script_targets_drylab(self) -> None:
        sibling_path = ".." + "/" + "dry" + "lab/result.txt"
        self.assert_named_rejection(
            ("tools/export.sh", f"printf '%s' result > {sibling_path}\n"),
            "sibling-write-path",
        )

    def test_rejects_write_path_when_python_targets_ontologylab(self) -> None:
        sibling_path = ".." + "/" + "ontology" + "lab/out"
        self.assert_named_rejection(
            ("tools/export.py", f"Path('{sibling_path}').write_text('x')\n"),
            "sibling-write-path",
        )

    def test_rejects_dynamic_path_variable_when_write_text_escapes(self) -> None:
        parent = "." + "."
        source = (
            "from pathlib import Path\n"
            f"destination = Path('{parent}') / ('dry' + 'lab') / 'result.txt'\n"
            "destination.write_text('x')\n"
        )
        self.assert_named_rejection(("tools/export.py", source), "outside-write-path")

    def test_rejects_joinpath_resolve_when_write_bytes_escapes(self) -> None:
        parent = "." + "."
        source = (
            "from pathlib import Path\n"
            f"base = Path('{parent}')\n"
            "destination = base.joinpath('shared', 'result.bin').resolve()\n"
            "destination.write_bytes(b'x')\n"
        )
        self.assert_named_rejection(("tools/export.py", source), "outside-write-path")

    def test_rejects_open_when_dynamic_path_variable_escapes(self) -> None:
        parent = "." + "."
        source = (
            "from pathlib import Path\n"
            f"base = Path('{parent}')\n"
            "destination = base / ('ontology' + 'lab') / 'result.txt'\n"
            "with open(destination, 'w') as stream:\n    stream.write('x')\n"
        )
        self.assert_named_rejection(("tools/export.py", source), "outside-write-path")

    def test_rejects_shell_variable_redirect_when_sibling_path_escapes(self) -> None:
        parent = "." + "."
        sibling = "dry" + "lab"
        source = f"DEST={parent}/{sibling}/result.txt\nprintf '%s' result > \"$DEST\"\n"
        self.assert_named_rejection(("tools/export.sh", source), "outside-write-path")

    def test_rejects_shell_variable_redirect_when_generic_path_escapes(self) -> None:
        parent = "." + "."
        source = f'BASE={parent}\nDEST="$BASE/shared/result.txt"\nprintf \'%s\' result>"$DEST"\n'
        self.assert_named_rejection(("tools/export.sh", source), "outside-write-path")

    def test_rejects_parents_index_when_resolved_file_path_escapes(self) -> None:
        for index in ("3", "1 + 1", "~0"):
            with self.subTest(index=index):
                source = (
                    "from pathlib import Path\n"
                    f"destination = Path(__file__).resolve().parents[{index}] / 'out.txt'\n"
                    "destination.write_text('x')\n"
                )
                self.assert_named_rejection(
                    ("tools/export.py", source), "outside-write-path"
                )

    def test_rejects_unresolved_parents_index_that_can_escape(self) -> None:
        source = (
            "from pathlib import Path\n"
            "destination = (Path('artifacts') / name).parents[level] / 'out.txt'\n"
            "destination.write_text('x')\n"
        )
        self.assert_named_rejection(("tools/export.py", source), "outside-write-path")

    def test_rejects_python_move_and_copy_sinks_to_a_sibling(self) -> None:
        for owner, sinks in (
            ("os", ("rename", "replace")),
            ("shutil", ("copy", "copy2", "copyfile", "copytree", "move")),
        ):
            for sink in sinks:
                source = f"import {owner}\nfrom pathlib import Path\n{owner}.{sink}(Path('in'), Path('../drylab/out'))\n"
                with self.subTest(owner=owner, sink=sink):
                    self.assert_named_rejection(
                        ("tools/export.py", source), "outside-write-path"
                    )

    def test_rejects_path_move_sinks_when_destination_is_a_sibling(self) -> None:
        for sink in ("rename", "replace"):
            source = f"from pathlib import Path\nPath('in').{sink}(Path('../ontologylab/out'))\n"
            with self.subTest(sink=sink):
                self.assert_named_rejection(
                    ("tools/export.py", source), "outside-write-path"
                )

    def test_rejects_final_adversarial_bypass_cases(self) -> None:
        for name, relative_path, source in BAD_CASES:
            with self.subTest(name=name):
                self.assert_named_rejection(
                    (relative_path, source), "outside-write-path"
                )

    def test_node_absolute_write_respects_actual_target_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "science-workbench"
            path = root / "tools" / "absolute.js"
            _ = path.parent.mkdir(parents=True)
            outside = root.parent / "drylab" / "out"
            _ = path.write_text(
                f"const fs = require('fs');\nfs.writeFileSync('{outside}', 'x');\n",
                encoding="utf-8",
            )
            result = self.run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            _ = path.write_text(
                f"const fs = require('fs');\nfs.writeFileSync('{root / 'out'}', 'x');\n",
                encoding="utf-8",
            )
            result = self.run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rejects_escaping_write_before_safe_reassignment(self) -> None:
        source = (
            "from pathlib import Path\n"
            "destination = Path('..') / 'ontologylab' / 'out.txt'\n"
            "destination.write_text('x')\n"
            "destination = Path('artifacts') / 'out.txt'\n"
        )
        self.assert_named_rejection(("tools/export.py", source), "outside-write-path")

    def test_accepts_known_in_root_write_destinations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "science-workbench"
            for relative_path, source in SAFE_CASES:
                path = root / relative_path
                _ = path.parent.mkdir(parents=True, exist_ok=True)
                _ = path.write_text(source, encoding="utf-8")
            result = self.run_checker(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    _ = unittest.main()
