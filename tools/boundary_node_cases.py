"""Generated Node filesystem mutation fixtures for boundary-checker tests."""

from __future__ import annotations

OUTSIDE = ".." + "/dry" + "lab/out"
ABS_OUT = "/Users/hyunjun/Documents/MUNI/shared/out"
WRITE_FLAGS = "fs.constants.O_WRONLY | fs.constants.O_CREAT"


def _source(*parts: str) -> str:
    return "".join(parts)


PATH_CALLS = (
    ("appendFileSync", ", 'x'"),
    ("appendFile", ", 'x', () => {}"),
    ("rmSync", ""),
    ("rm", ", () => {}"),
    ("rmdirSync", ""),
    ("rmdir", ", () => {}"),
    ("unlinkSync", ""),
    ("unlink", ", () => {}"),
    ("chmodSync", ", 0o600"),
    ("chmod", ", 0o600, () => {}"),
    ("chownSync", ", 1, 1"),
    ("chown", ", 1, 1, () => {}"),
    ("lchownSync", ", 1, 1"),
    ("lchown", ", 1, 1, () => {}"),
    ("lchmodSync", ", 0o600"),
    ("truncateSync", ", 0"),
    ("truncate", ", 0, () => {}"),
    ("ftruncateSync", ", 0"),
    ("ftruncate", ", 0, () => {}"),
    ("utimesSync", ", 0, 0"),
    ("utimes", ", 0, 0, () => {}"),
    ("lutimesSync", ", 0, 0"),
    ("lutimes", ", 0, 0, () => {}"),
    ("mkdtempSync", ""),
    ("mkdtemp", ", () => {}"),
    ("mkdtempDisposableSync", ""),
    ("createWriteStream", ""),
)
DESTINATION_CALLS = (
    ("cpSync", ""),
    ("cp", ", () => {}"),
    ("linkSync", ""),
    ("link", ", () => {}"),
    ("symlinkSync", ""),
    ("symlink", ", () => {}"),
)
PROMISE_PATH_CALLS = tuple(
    (method, extra.replace(", () => {}", ""))
    for method, extra in PATH_CALLS
    if not method.endswith("Sync") and method not in {"createWriteStream", "ftruncate"}
)
PROMISE_DESTINATION_CALLS = tuple(
    (method, extra.replace(", () => {}", ""))
    for method, extra in DESTINATION_CALLS
    if not method.endswith("Sync")
)


MODULE_CASES = tuple(
    (
        f"Node module {method}",
        f"tools/node_{method}.js",
        f"const fs = require('fs');\nfs.{method}('{OUTSIDE}'{extra});\n",
    )
    for method, extra in PATH_CALLS
) + tuple(
    (
        f"Node module {method}",
        f"tools/node_{method}.js",
        f"const fs = require('fs');\nfs.{method}('in', '{OUTSIDE}'{extra});\n",
    )
    for method, extra in DESTINATION_CALLS
)


NAMED_CASES = tuple(
    (
        f"Node named {method}",
        f"tools/named_{method}.ts",
        _source(
            f"import {{ {method} as mutate }} from 'node:fs';\n",
            f"mutate('{OUTSIDE}'{extra});\n",
        ),
    )
    for method, extra in PATH_CALLS
) + tuple(
    (
        f"Node named {method}",
        f"tools/named_{method}.ts",
        _source(
            f"import {{ {method} as mutate }} from 'node:fs';\n",
            f"mutate('in', '{OUTSIDE}'{extra});\n",
        ),
    )
    for method, extra in DESTINATION_CALLS
)


DESTRUCTURED_CASES = tuple(
    (
        f"Node destructured {method}",
        f"tools/destructured_{method}.cjs",
        f"const {{ {method}: mutate }} = require('fs');\nmutate('{OUTSIDE}'{extra});\n",
    )
    for method, extra in PATH_CALLS
) + tuple(
    (
        f"Node destructured {method}",
        f"tools/destructured_{method}.cjs",
        _source(
            f"const {{ {method}: mutate }} = require('fs');\n",
            f"mutate('in', '{OUTSIDE}'{extra});\n",
        ),
    )
    for method, extra in DESTINATION_CALLS
)


PROMISE_CASES = tuple(
    (
        f"Node promise {method}",
        f"tools/promise_{method}.ts",
        _source(
            f"import {{ {method} as mutate }} from 'node:fs/promises';\n",
            f"await mutate('{OUTSIDE}'{extra});\n",
        ),
    )
    for method, extra in PROMISE_PATH_CALLS
) + tuple(
    (
        f"Node promise {method}",
        f"tools/promise_{method}.ts",
        _source(
            f"import {{ {method} as mutate }} from 'node:fs/promises';\n",
            f"await mutate('in', '{OUTSIDE}'{extra});\n",
        ),
    )
    for method, extra in PROMISE_DESTINATION_CALLS
)


OPEN_CASES = (
    (
        "Node openSync write",
        "tools/open.js",
        f"const fs = require('fs');\nfs.openSync('{OUTSIDE}', 'w');\n",
    ),
    (
        "Node open write",
        "tools/open.ts",
        _source(
            "import { open as mutate } from 'node:fs';\n",
            f"mutate('{OUTSIDE}', 'a+', () => {{}});\n",
        ),
    ),
    (
        "Node open destructured",
        "tools/open.cjs",
        f"const {{ openSync: mutate }} = require('fs');\nmutate('{OUTSIDE}', 'x');\n",
    ),
    (
        "Node open promise",
        "tools/open-promise.ts",
        f"import {{ open }} from 'node:fs/promises';\nawait open('{OUTSIDE}', 'w+');\n",
    ),
    (
        "Node same-line module call",
        "tools/same-line.js",
        f"const fs = require('fs'); fs.appendFileSync('{ABS_OUT}', 'x');\n",
    ),
    (
        "Node symbolic open flags",
        "tools/open-symbolic.js",
        f"const fs = require('fs');\nfs.openSync('{ABS_OUT}', {WRITE_FLAGS});\n",
    ),
)


EXTRA_BAD_NODE_CASES = (
    MODULE_CASES + NAMED_CASES + DESTRUCTURED_CASES + PROMISE_CASES + OPEN_CASES
)


EXTRA_SAFE_NODE_CASES = (
    tuple(
        (
            f"tools/safe_node_{method}.js",
            f"const fs = require('fs');\nfs.{method}('artifacts/out'{extra});\n",
        )
        for method, extra in PATH_CALLS
    )
    + tuple(
        (
            f"tools/safe_node_{method}.js",
            _source(
                "const fs = require('fs');\n",
                f"fs.{method}('artifacts/in', 'artifacts/out'{extra});\n",
            ),
        )
        for method, extra in DESTINATION_CALLS
    )
    + (
        (
            "tools/safe_open.js",
            "const fs = require('fs');\nfs.openSync('artifacts/out', 'r');\n",
        ),
        (
            "tools/safe_same_line.js",
            "const fs = require('fs'); fs.appendFileSync('artifacts/out', 'x');\n",
        ),
        (
            "tools/safe_symbolic_open.js",
            "const f=require('fs');\nf.openSync('out',f.constants.O_RDONLY);\n",
        ),
    )
)
