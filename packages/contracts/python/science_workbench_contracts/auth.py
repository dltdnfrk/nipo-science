from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from .common import (
    ContractModel,
    NonEmptyText,
    Revision,
    UtcTimestamp,
    Uuid7,
)

Email = Annotated[str, Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")]


class MagicLinkRequest(ContractModel):
    email: Email


class MagicLinkExchange(ContractModel):
    token: NonEmptyText
    state: NonEmptyText


class AuthContext(ContractModel):
    user_id: Uuid7
    org_id: Uuid7
    email: Email
    role: Literal["owner", "member"]
    csrf_token: NonEmptyText
    expires_at: UtcTimestamp


class Organization(ContractModel):
    id: Uuid7
    name: NonEmptyText
    created_at: UtcTimestamp


class ProjectCreate(ContractModel):
    name: NonEmptyText


class Project(ContractModel):
    id: Uuid7
    org_id: Uuid7
    name: NonEmptyText
    revision: Revision
    created_at: UtcTimestamp


class SessionCreate(ContractModel):
    project_id: Uuid7
    title: NonEmptyText


class Session(ContractModel):
    id: Uuid7
    org_id: Uuid7
    project_id: Uuid7
    title: NonEmptyText
    revision: Revision
    created_at: UtcTimestamp


class UploadCreate(ContractModel):
    project_id: Uuid7
    filename: NonEmptyText
    media_type: NonEmptyText


class Upload(ContractModel):
    id: Uuid7
    org_id: Uuid7
    project_id: Uuid7
    filename: NonEmptyText
    status: Literal["pending", "clean", "rejected"]
    created_at: UtcTimestamp
