"""Docker Compose topology contract tests."""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import NotRequired, TypedDict

from pydantic import TypeAdapter

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_SERVICES = {
    "api",
    "clamav",
    "mailpit",
    "minio",
    "postgres",
    "redis",
    "web",
    "worker",
}


class ComposePort(TypedDict):
    host_ip: str
    published: str


class ComposeService(TypedDict):
    environment: NotRequired[dict[str, str]]
    healthcheck: dict[str, str | int | list[str]]
    ports: NotRequired[list[ComposePort]]


class ComposeConfig(TypedDict):
    services: dict[str, ComposeService]


def _compose_config(environment: dict[str, str] | None = None) -> ComposeConfig:
    docker = shutil.which("docker")
    assert docker is not None
    completed = subprocess.run(
        [docker, "compose", "-f", "compose.yaml", "config", "--format", "json"],
        cwd=ROOT,
        env=os.environ | (environment or {}),
        check=True,
        capture_output=True,
        text=True,
    )
    return TypeAdapter(ComposeConfig).validate_python(json.loads(completed.stdout))


def test_compose_defines_every_local_service_with_healthcheck() -> None:
    # Given: the checked-in hermetic Compose definition.
    config = _compose_config()

    # When: its service topology is inspected.
    services = config["services"]

    # Then: every required service has an explicit health probe.
    assert services.keys() >= EXPECTED_SERVICES
    assert all("healthcheck" in services[name] for name in EXPECTED_SERVICES)


def test_compose_contains_no_provider_or_cloud_credentials() -> None:
    # Given: the fully interpolated default local topology.
    config = _compose_config()

    # When: its deterministic representation is searched.
    serialized = json.dumps(config, sort_keys=True).upper()

    # Then: default startup has no provider or cloud credential surface.
    assert "OPENAI_API_KEY" not in serialized
    assert "ANTHROPIC_API_KEY" not in serialized
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in serialized
    assert "RESEND_API_KEY" not in serialized


def test_compose_uses_resolvable_separate_loopback_origins() -> None:
    # Given: the fully interpolated default local topology.
    config = _compose_config()

    # When: the API service's public origins are inspected.
    environment = config["services"]["api"].get("environment")

    # Then: both origins resolve without host-file changes and remain cookie-isolated.
    assert environment is not None
    assert environment["APP_ORIGIN"] == "http://localhost:53000"
    assert environment["ARTIFACT_ORIGIN"] == "http://127.0.0.1:59000"


def test_anonymous_docker_config_disables_global_credential_helpers(
    tmp_path: Path,
) -> None:
    config_path = ROOT / "infra/local/docker-anonymous/config.json"
    config = TypeAdapter(dict[str, object]).validate_json(config_path.read_text())
    fake_docker = tmp_path / "docker"
    _ = fake_docker.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$DOCKER_CONFIG" "$PATH" "$*"\n'
    )
    fake_docker.chmod(0o700)
    completed = subprocess.run(
        [
            ROOT / "infra/local/pull-anonymous.sh",
            fake_docker,
            "example.invalid/image:test",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    config_dir, helper_path, arguments = completed.stdout.splitlines()

    assert config == {}
    assert config_dir == str(config_path.parent)
    assert helper_path == str(config_path.parent)
    assert arguments == "pull example.invalid/image:test"


def test_host_ports_are_isolated_and_overrideable() -> None:
    overrides = {
        "SWB_POSTGRES_PORT": "45432",
        "SWB_REDIS_PORT": "46379",
        "SWB_MINIO_PORT": "49000",
        "SWB_SMTP_PORT": "41025",
        "SWB_MAILPIT_PORT": "48025",
        "SWB_API_PORT": "48000",
        "SWB_WORKER_PORT": "48001",
        "SWB_WEB_PORT": "43000",
    }
    config = _compose_config(overrides)
    expected = {
        "postgres": ("45432",),
        "redis": ("46379",),
        "minio": ("49000",),
        "mailpit": ("41025", "48025"),
        "api": ("48000",),
        "worker": ("48001",),
        "web": ("43000",),
    }

    actual: dict[str, tuple[str, ...]] = {}
    for service in expected:
        ports = config["services"][service].get("ports")
        assert ports is not None
        assert all(port["host_ip"] == "127.0.0.1" for port in ports)
        actual[service] = tuple(port["published"] for port in ports)
    assert actual == expected
