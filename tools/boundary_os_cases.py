"""Generated Python os mutation fixtures for boundary-checker tests."""

from __future__ import annotations

DRY_TARGET = ".." + "/dry" + "lab/out"
ONTOLOGY_TARGET = ".." + "/ontology" + "lab/out"


def _source(*parts: str) -> str:
    return "".join(parts)


OS_PATH_SINKS = (
    ("mkdir", ""),
    ("makedirs", ""),
    ("remove", ""),
    ("unlink", ""),
    ("rmdir", ""),
    ("removedirs", ""),
    ("chmod", ", 0o600"),
    ("chown", ", 1, 1"),
    ("truncate", ", 0"),
)
OS_DESTINATION_SINKS = ("rename", "replace", "link", "symlink")
PATH_RECEIVER_SINKS = (
    ("unlink", ""),
    ("rmdir", ""),
    ("chmod", "0o600"),
    ("symlink_to", "'in'"),
    ("hardlink_to", "'in'"),
)
OS_KEYWORD_CALLS = (
    ("mkdir", f"path='{DRY_TARGET}'"),
    ("makedirs", f"name='{DRY_TARGET}'"),
    ("remove", f"path='{DRY_TARGET}'"),
    ("unlink", f"path='{DRY_TARGET}'"),
    ("rmdir", f"path='{DRY_TARGET}'"),
    ("removedirs", f"name='{DRY_TARGET}'"),
    ("chmod", f"path='{DRY_TARGET}', mode=0o600"),
    ("chown", f"path='{DRY_TARGET}', uid=1, gid=1"),
    ("truncate", f"path='{DRY_TARGET}', length=0"),
    *tuple(
        (method, f"src='in', dst='{ONTOLOGY_TARGET}'")
        for method in OS_DESTINATION_SINKS
    ),
)


OS_CASES = (
    tuple(
        (
            f"os module {method}",
            f"tools/os_{method}.py",
            f"import os as operating\noperating.{method}('{DRY_TARGET}'{extra})\n",
        )
        for method, extra in OS_PATH_SINKS
    )
    + tuple(
        (
            f"os direct {method}",
            f"tools/direct_{method}.py",
            f"from os import {method} as mutate\nmutate('{ONTOLOGY_TARGET}'{extra})\n",
        )
        for method, extra in OS_PATH_SINKS
    )
    + tuple(
        (
            f"os module {method}",
            f"tools/os_{method}.py",
            f"import os as operating\noperating.{method}('in', '{DRY_TARGET}')\n",
        )
        for method in OS_DESTINATION_SINKS
    )
    + tuple(
        (
            f"os direct {method}",
            f"tools/direct_{method}.py",
            f"from os import {method} as mutate\nmutate('in', '{ONTOLOGY_TARGET}')\n",
        )
        for method in OS_DESTINATION_SINKS
    )
    + tuple(
        (
            f"os keyword {method}",
            f"tools/keyword_{method}.py",
            f"import os as operating\noperating.{method}({arguments})\n",
        )
        for method, arguments in OS_KEYWORD_CALLS
    )
)


SAFE_OS_CASES = (
    tuple(
        (
            f"tools/safe_os_{method}.py",
            f"import os as operating\noperating.{method}('artifacts/out'{extra})\n",
        )
        for method, extra in OS_PATH_SINKS
    )
    + tuple(
        (
            f"tools/safe_direct_{method}.py",
            f"from os import {method} as mutate\nmutate('artifacts/out'{extra})\n",
        )
        for method, extra in OS_PATH_SINKS
    )
    + tuple(
        (
            f"tools/safe_os_{method}.py",
            _source(
                "import os as operating\n",
                f"operating.{method}('artifacts/in', 'artifacts/out')\n",
            ),
        )
        for method in OS_DESTINATION_SINKS
    )
    + tuple(
        (
            f"tools/safe_direct_{method}.py",
            _source(
                f"from os import {method} as mutate\n",
                "mutate('artifacts/in', 'artifacts/out')\n",
            ),
        )
        for method in OS_DESTINATION_SINKS
    )
)


PATH_CASES = (
    *tuple(
        (
            f"Path {method}",
            f"tools/path_{method}.py",
            f"from pathlib import Path\nPath('{DRY_TARGET}').{method}({argument})\n",
        )
        for method, argument in PATH_RECEIVER_SINKS
    ),
    (
        "Path link_to",
        "tools/path_link_to.py",
        f"from pathlib import Path\nPath('in').link_to(Path('{ONTOLOGY_TARGET}'))\n",
    ),
    (
        "relative_to walk-up",
        "tools/path_relative_walk_up.py",
        _source(
            "from pathlib import Path\n",
            f"candidate = Path('{DRY_TARGET}').resolve()\n",
            "relative = candidate.relative_to(Path.cwd(), walk_up=True)\n",
            "(Path.cwd() / relative).write_text('x')\n",
        ),
    ),
)


SAFE_PATH_CASES = (
    *tuple(
        (
            f"tools/safe_path_{method}.py",
            f"from pathlib import Path\nPath('artifacts/out').{method}({argument})\n",
        )
        for method, argument in PATH_RECEIVER_SINKS
    ),
    (
        "tools/safe_path_link_to.py",
        _source(
            "from pathlib import Path\n",
            "Path('artifacts/in').link_to(Path('artifacts/out'))\n",
        ),
    ),
    (
        "tools/safe_relative_guard.py",
        _source(
            "from pathlib import Path\n",
            "candidate = Path(user_value).resolve()\n",
            "relative = candidate.relative_to(Path.cwd())\n",
            "(Path.cwd() / relative).write_text('x')\n",
        ),
    ),
)
