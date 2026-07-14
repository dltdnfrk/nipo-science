from __future__ import annotations

import sys
from pathlib import Path

from pydantic import ValidationError

from science_workbench_contracts.openapi_semantics import OpenApiDocument
from science_workbench_contracts.openapi_validator import validate_openapi


def main(arguments: list[str]) -> int:
    if len(arguments) != 1:
        print("usage: validate_openapi.py OPENAPI_JSON", file=sys.stderr)
        return 2

    path = Path(arguments[0])
    try:
        document = OpenApiDocument.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValidationError) as error:
        print(f"openapi-contract: INVALID: {error}", file=sys.stderr)
        return 2

    issues = validate_openapi(document)
    if issues:
        for issue in issues:
            print(f"openapi-contract: FAIL: {issue}", file=sys.stderr)
        return 1

    print(f"openapi-contract: PASS ({len(document.paths)} paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
