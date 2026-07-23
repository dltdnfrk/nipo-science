"""Run the checked-in CI catalog without publication authority."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Final

from .ci_runner import RUN_PROCESS, ci_commands, redact_raw_output

_CLI_ARG_COUNT: Final = 2
_FAILURE_OUTPUT_TAIL_BYTES: Final = 20_000


def main() -> int:
    """Execute every catalog command while producing no release attestation."""
    root = (
        Path(sys.argv[1]).resolve()
        if len(sys.argv) == _CLI_ARG_COUNT
        else Path.cwd()
    )
    for command in ci_commands(root):
        return_code, captured_output = RUN_PROCESS(command.argv, root)
        if return_code != 0:
            # Surface the (redacted) tail of the failing job's output: a silent
            # summary line made remote failures undiagnosable from CI logs alone.
            tail = redact_raw_output(captured_output)[-_FAILURE_OUTPUT_TAIL_BYTES:]
            _ = sys.stderr.write(tail.decode("utf-8", errors="replace"))
            _ = sys.stderr.write(
                f"\nCI validation failed: {command.job} ({return_code})\n"
            )
            return return_code
        _ = sys.stdout.write(f"CI_VALIDATED_JOB={command.job}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
