"""Typed local configuration boundary tests."""

import pytest
from pydantic import ValidationError
from services.local.config import LocalConfig


def _valid_env() -> dict[str, str]:
    return {
        "APP_ORIGIN": "http://app.localhost:3000",
        "ARTIFACT_ORIGIN": "http://artifact.localhost:9000",
        "COOKIE_DOMAIN": "",
        "OBJECT_STORE_DRIVER": "s3",
        "OBJECT_STORE_ENDPOINT": "http://minio:9000",
        "MAIL_DRIVER": "mailpit",
        "SMTP_HOST": "mailpit",
        "SMTP_PORT": "1025",
        "CLAMAV_HOST": "clamav",
        "CLAMAV_PORT": "3310",
        "HOST_IP": "127.0.0.1",
        "SERVICE_ROLE": "api",
        "SERVICE_BIND_HOST": "127.0.0.1",
        "SERVICE_PORT": "8000",
    }


def test_config_parses_host_only_local_interfaces() -> None:
    # Given: complete local configuration with separate application/artifact origins.
    raw = _valid_env()

    # When: the environment crosses the typed configuration boundary.
    config = LocalConfig.from_env(raw)

    # Then: local interfaces are typed and the cookie remains host-only.
    assert config.cookie_domain is None
    assert config.object_store_driver.value == "s3"
    assert config.mail_driver.value == "mailpit"
    assert config.app_origin.host != config.artifact_origin.host
    assert str(config.host_ip) == "127.0.0.1"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("OBJECT_STORE_DRIVER", "filesystem"),
        ("MAIL_DRIVER", "console"),
        ("SERVICE_ROLE", "scheduler"),
        ("SMTP_PORT", "0"),
        ("HOST_IP", "192.0.2.1"),
        ("COOKIE_DOMAIN", ".localhost"),
        ("COOKIE_DOMAIN", "example.test"),
    ],
)
def test_config_rejects_unsupported_or_unsafe_values(field: str, value: str) -> None:
    # Given: one unsupported or unsafe boundary value.
    raw = _valid_env() | {field: value}

    # When/Then: parsing fails before the value reaches service logic.
    with pytest.raises(ValidationError):
        _ = LocalConfig.from_env(raw)


def test_config_rejects_shared_application_and_artifact_origin() -> None:
    # Given: artifact delivery is incorrectly placed on the application origin.
    raw = _valid_env() | {"ARTIFACT_ORIGIN": "http://app.localhost:9000"}

    # When/Then: the origin boundary fails closed.
    with pytest.raises(ValidationError):
        _ = LocalConfig.from_env(raw)


def test_config_ignores_container_runtime_environment() -> None:
    # Given: valid app settings mixed with base-image runtime variables.
    raw = _valid_env() | {"PATH": "/usr/local/bin", "HOSTNAME": "container-id"}

    # When: only the owned configuration namespace crosses the boundary.
    config = LocalConfig.from_env(raw)

    # Then: runtime metadata cannot become application configuration.
    assert config.service_role.value == "api"
