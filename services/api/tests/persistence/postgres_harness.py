from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).parents[4]
POSTGRES_PORT: Final = os.environ.get("SWB_POSTGRES_PORT", "0")
COMPOSE_PROJECT: Final = os.environ.get(
    "TASK8_COMPOSE_PROJECT", f"science-workbench-task8-{os.getpid()}"
)
ALEMBIC_BIN: Final = os.environ.get(
    "TASK8_ALEMBIC_BIN", str(ROOT / ".venv/bin/alembic")
)


def compose(arguments: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (
            "docker",
            "compose",
            "--project-name",
            COMPOSE_PROJECT,
            "-f",
            "compose.yaml",
            *arguments,
        ),
        cwd=ROOT,
        env=os.environ | {"SWB_POSTGRES_PORT": POSTGRES_PORT},
        check=True,
        capture_output=True,
        text=True,
    )


def alembic(arguments: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    database_url = database_url_asyncpg()
    return subprocess.run(
        (ALEMBIC_BIN, "-c", "services/api/alembic.ini", *arguments),
        cwd=ROOT,
        env=os.environ | {"DATABASE_URL": database_url, "PYTHONPATH": str(ROOT)},
        check=True,
        capture_output=True,
        text=True,
    )


def database_url_asyncpg() -> str:
    mapped_port = (
        compose(("port", "postgres", "5432")).stdout.strip().rsplit(":", 1)[-1]
    )
    return os.environ.get(
        "TASK8_DATABASE_URL",
        "postgresql+asyncpg://science_workbench:local-only-postgres@"
        f"127.0.0.1:{mapped_port}/science_workbench",
    )


def psql(sql: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (
            "docker",
            "compose",
            "--project-name",
            COMPOSE_PROJECT,
            "-f",
            "compose.yaml",
            "exec",
            "-T",
            "postgres",
            "psql",
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "science_workbench",
            "-d",
            "science_workbench",
            "-Atqc",
            sql,
        ),
        cwd=ROOT,
        env=os.environ | {"SWB_POSTGRES_PORT": POSTGRES_PORT},
        check=check,
        capture_output=True,
        text=True,
    )
