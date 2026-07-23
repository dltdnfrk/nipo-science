from __future__ import annotations

import os
from logging.config import fileConfig
from typing import TYPE_CHECKING

from alembic import context
from sqlalchemy.ext.asyncio import async_engine_from_config

from services.api.persistence.base import Base

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection


class MissingDatabaseUrlError(Exception):
    def __init__(self) -> None:
        super().__init__(
            "DATABASE_URL must be set explicitly before running migrations"
        )


def database_url() -> str:
    selected = os.environ.get("DATABASE_URL", "").strip()
    if not selected:
        raise MissingDatabaseUrlError
    return selected


def run_migrations_offline() -> None:
    context.configure(
        url=database_url(), target_metadata=Base.metadata, literal_binds=True
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_sync(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=Base.metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    section = context.config.get_section(context.config.config_ini_section) or {}
    section["sqlalchemy.url"] = database_url()
    engine = async_engine_from_config(section, prefix="sqlalchemy.")
    async with engine.connect() as connection:
        await connection.run_sync(run_migrations_sync)
    await engine.dispose()


if context.config.config_file_name is not None:
    fileConfig(context.config.config_file_name)

if context.is_offline_mode():
    run_migrations_offline()
else:
    import anyio

    anyio.run(run_migrations_online)
