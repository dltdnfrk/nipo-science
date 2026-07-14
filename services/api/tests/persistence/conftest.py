from collections.abc import Iterator

import pytest

from services.api.tests.persistence.postgres_harness import alembic, compose


@pytest.fixture(scope="session")
def postgres_database() -> Iterator[None]:
    try:
        _ = compose(
            (
                "up",
                "-d",
                "postgres",
                "--pull",
                "never",
                "--wait",
                "--wait-timeout",
                "120",
            )
        )
        yield
    finally:
        _ = compose(("down", "--volumes", "--remove-orphans"))


@pytest.fixture(scope="session")
def migrated_database(postgres_database: None) -> None:
    _ = postgres_database
    _ = alembic(("upgrade", "head"))
