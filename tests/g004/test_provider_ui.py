import shutil
import subprocess
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2] / "apps" / "web" / "product" / "app.js"


def test_provider_source_has_node_syntax_contract() -> None:
    node = shutil.which("node")
    assert node is not None, "Node.js is required to validate the provider UI source"
    result = subprocess.run(
        [node, "--check", str(SOURCE)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
