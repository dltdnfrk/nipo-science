"""Typed configuration boundary for the hermetic local stack."""

from collections.abc import Mapping
from enum import StrEnum
from ipaddress import IPv4Address
from typing import Annotated, ClassVar, Final, Self

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    IPvAnyAddress,
    PositiveInt,
    field_validator,
    model_validator,
)

LOCAL_ENV_KEYS: Final = (
    "APP_ORIGIN",
    "ARTIFACT_ORIGIN",
    "COOKIE_DOMAIN",
    "OBJECT_STORE_DRIVER",
    "OBJECT_STORE_ENDPOINT",
    "MAIL_DRIVER",
    "SMTP_HOST",
    "SMTP_PORT",
    "CLAMAV_HOST",
    "CLAMAV_PORT",
    "HOST_IP",
    "SERVICE_ROLE",
    "SERVICE_BIND_HOST",
    "SERVICE_PORT",
)


class ObjectStoreDriver(StrEnum):
    """Supported object-store interfaces."""

    S3 = "s3"
    GCS = "gcs"


class MailDriver(StrEnum):
    """Supported transactional-mail interfaces."""

    MAILPIT = "mailpit"
    RESEND = "resend"


class ServiceRole(StrEnum):
    """Local deterministic service roles."""

    API = "api"
    WORKER = "worker"


def _host_only(raw: str) -> str | None:
    return raw or None


HostOnlyCookieDomain = Annotated[None, BeforeValidator(_host_only)]


class OriginsMustDifferError(ValueError):
    """Raised when artifacts share the cookie-bearing application origin."""


class LoopbackHostRequiredError(ValueError):
    """Raised when a published local port could bind beyond loopback."""


class LocalConfig(BaseModel):
    """Validated local service configuration without provider credentials."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    app_origin: AnyHttpUrl = Field(alias="APP_ORIGIN")
    artifact_origin: AnyHttpUrl = Field(alias="ARTIFACT_ORIGIN")
    cookie_domain: HostOnlyCookieDomain = Field(alias="COOKIE_DOMAIN")
    object_store_driver: ObjectStoreDriver = Field(alias="OBJECT_STORE_DRIVER")
    object_store_endpoint: AnyHttpUrl = Field(alias="OBJECT_STORE_ENDPOINT")
    mail_driver: MailDriver = Field(alias="MAIL_DRIVER")
    smtp_host: str = Field(alias="SMTP_HOST", min_length=1)
    smtp_port: PositiveInt = Field(alias="SMTP_PORT", le=65535)
    clamav_host: str = Field(alias="CLAMAV_HOST", min_length=1)
    clamav_port: PositiveInt = Field(alias="CLAMAV_PORT", le=65535)
    host_ip: IPv4Address = Field(alias="HOST_IP")
    service_role: ServiceRole = Field(alias="SERVICE_ROLE")
    service_bind_host: IPvAnyAddress = Field(alias="SERVICE_BIND_HOST")
    service_port: PositiveInt = Field(alias="SERVICE_PORT", le=65535)

    @field_validator("host_ip")
    @classmethod
    def enforce_loopback_host(cls, host_ip: IPv4Address) -> IPv4Address:
        """Permit published local services only on IPv4 loopback."""
        if host_ip != IPv4Address("127.0.0.1"):
            raise LoopbackHostRequiredError
        return host_ip

    @model_validator(mode="after")
    def enforce_separate_origins(self) -> Self:
        """Keep artifact responses outside the application cookie origin."""
        if self.app_origin.host == self.artifact_origin.host:
            raise OriginsMustDifferError
        return self

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Self:
        """Parse local service configuration from an environment mapping."""
        owned = {key: env[key] for key in LOCAL_ENV_KEYS if key in env}
        return cls.model_validate(owned)
