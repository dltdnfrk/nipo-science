"""Adversarial and safe fixtures for boundary-checker regression tests."""

from __future__ import annotations

from tools.boundary_node_cases import EXTRA_BAD_NODE_CASES, EXTRA_SAFE_NODE_CASES
from tools.boundary_os_cases import (
    OS_CASES,
    PATH_CASES,
    SAFE_OS_CASES,
    SAFE_PATH_CASES,
)
from tools.boundary_shell_cases import BAD_SHELL_CASES, SAFE_SHELL_CASES

DRY_TARGET = ".." + "/dry" + "lab/out"
ONTOLOGY_TARGET = ".." + "/ontology" + "lab/out"


def _source(*parts: str) -> str:
    return "".join(parts)


BASE_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "dynamic suffix",
        "tools/dynamic.py",
        _source(
            "from pathlib import Path\n",
            "(Path('artifacts') / dynamic_name).write_text('x')\n",
        ),
    ),
    (
        "open keyword",
        "tools/open_keyword.py",
        "from pathlib import Path\nopen(file=Path('../shared/out'), mode='w')\n",
    ),
    (
        "shutil module alias",
        "tools/copy_alias.py",
        _source(
            "import shutil as files\nfrom pathlib import Path\n",
            f"files.copy(Path('in'), Path('{ONTOLOGY_TARGET}'))\n",
        ),
    ),
    (
        "shutil function alias",
        "tools/copy_function.py",
        _source(
            "from pathlib import Path\nfrom shutil import copy as x\n",
            f"x(Path('in'), Path('{DRY_TARGET}'))\n",
        ),
    ),
    ("shell touch", "tools/touch.sh", f'DEST={DRY_TARGET}\ntouch "$DEST"\n'),
    ("shell copy", "tools/copy.sh", f'DEST={ONTOLOGY_TARGET}\ncp staged "$DEST"\n'),
    ("shell move", "tools/move.sh", f'DEST={DRY_TARGET}\nmv staged "$DEST"\n'),
    ("shell mkdir", "tools/mkdir.sh", f'DEST={ONTOLOGY_TARGET}\nmkdir -p "$DEST"\n'),
    ("shell tee", "tools/tee.sh", f'DEST={DRY_TARGET}\nprintf x | tee "$DEST"\n'),
    (
        "node write sync",
        "tools/write.js",
        _source(
            "const fs = require('node:fs');\n",
            f"const dest = '{DRY_TARGET}';\nfs.writeFileSync(dest, 'x');\n",
        ),
    ),
    (
        "node write alias",
        "tools/write.ts",
        _source(
            "import { writeFile as save } from 'node:fs';\n",
            f"const dest = '{ONTOLOGY_TARGET}';\nsave(dest, 'x', () => {{}});\n",
        ),
    ),
    (
        "node require alias",
        "tools/write.cjs",
        _source(
            "const { writeFileSync: save } = require('fs');\n",
            f"const dest = '{DRY_TARGET}';\nsave(dest, 'x');\n",
        ),
    ),
    (
        "node rename sync",
        "tools/rename.js",
        _source(
            "const fs = require('fs');\n",
            f"const dest = '{DRY_TARGET}';\nfs.renameSync('in', dest);\n",
        ),
    ),
    (
        "node rename async",
        "tools/rename.ts",
        _source(
            "import { rename } from 'node:fs';\n",
            f"const dest = '{ONTOLOGY_TARGET}';\nrename('in', dest, () => {{}});\n",
        ),
    ),
    (
        "node copy sync",
        "tools/copy.js",
        _source(
            "const files = require('node:fs');\n",
            f"const dest = '{DRY_TARGET}';\nfiles.copyFileSync('in', dest);\n",
        ),
    ),
    (
        "node copy alias",
        "tools/copy.ts",
        _source(
            "import { copyFile as copy } from 'fs';\n",
            f"const dest = '{ONTOLOGY_TARGET}';\ncopy('in', dest, () => {{}});\n",
        ),
    ),
    (
        "node mkdir sync",
        "tools/mkdir.js",
        _source(
            "const fs = require('fs');\n",
            f"const dest = '{DRY_TARGET}';\nfs.mkdirSync(dest);\n",
        ),
    ),
    (
        "node mkdir alias",
        "tools/mkdir.ts",
        _source(
            "import { mkdir as make } from 'node:fs';\n",
            f"const dest = '{ONTOLOGY_TARGET}';\nmake(dest, () => {{}});\n",
        ),
    ),
    (
        "node promise named",
        "tools/promise.ts",
        _source(
            "import { writeFile } from 'node:fs/promises';\n",
            f"const dest = '{DRY_TARGET}';\nawait writeFile(dest, 'x');\n",
        ),
    ),
    (
        "node promise module",
        "tools/promise.js",
        _source(
            "const fs = require('fs').promises;\n",
            f"const dest = '{ONTOLOGY_TARGET}';\nfs.mkdir(dest);\n",
        ),
    ),
    (
        "node promise import alias",
        "tools/promise_import.ts",
        _source(
            "import { promises as fs } from 'node:fs';\n",
            f"const dest = '{DRY_TARGET}';\nawait fs.copyFile('in', dest);\n",
        ),
    ),
)


BAD_CASES = BASE_CASES + OS_CASES + PATH_CASES + EXTRA_BAD_NODE_CASES + BAD_SHELL_CASES


BASE_SAFE_CASES: tuple[tuple[str, str], ...] = (
    (
        "tools/safe.py",
        "from pathlib import Path\nPath('artifacts/out').write_text('x')\n",
    ),
    (
        "tools/safe.sh",
        "touch artifacts/out\ncp staged artifacts/out\nmkdir -p artifacts/tree\n",
    ),
    (
        "tools/safe.ts",
        _source(
            "import { copyFile, mkdir } from 'node:fs';\n",
            "copyFile('in', 'artifacts/out', () => {});\n",
            "mkdir('artifacts/tree', () => {});\n",
        ),
    ),
    (
        "tools/safe-promise.ts",
        _source(
            "import { writeFile } from 'node:fs/promises';\n",
            "await writeFile('artifacts/out', 'x');\n",
        ),
    ),
)


SAFE_CASES = (
    BASE_SAFE_CASES
    + SAFE_OS_CASES
    + SAFE_PATH_CASES
    + EXTRA_SAFE_NODE_CASES
    + SAFE_SHELL_CASES
)
