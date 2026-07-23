from pathlib import Path

from services.api.provider_cleanup_cli import ProviderCleanupProcessConfig


def test_cleanup_process_config_repr_redacts_database_credentials(
    tmp_path: Path,
) -> None:
    sentinel = f"cleanup-{tmp_path.name}-redaction"
    database_url = f"postgresql+asyncpg://cleanup:{sentinel}@localhost/workbench"
    config = ProviderCleanupProcessConfig.from_environment(
        {
            "PROVIDER_CLEANUP_DATABASE_URL": database_url,
            "PROVIDER_CLEANUP_EXPECTED_LOGIN_ROLE": "provider_cleanup_login",
            "PROVIDER_CLEANUP_VAULT_SOCKET": str(tmp_path / "vault.sock"),
        }
    )

    rendered = repr(config)

    assert database_url not in rendered
    assert sentinel not in rendered
