"""Pydantic-схемы запросов и ответов REST API."""

from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, ConfigDict, Field


class RegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128, description="E-mail пользователя")
    password: str = Field(min_length=6, max_length=256)


class VerifyEmailRequest(BaseModel):
    username: str = Field(description="E-mail")
    code: str = Field(min_length=6, max_length=6, description="Код из письма")


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(min_length=6, max_length=256)


class ResetPasswordRequest(BaseModel):
    username: str = Field(description="E-mail")


class DeleteAccountRequest(BaseModel):
    password: str = Field(description="Подтверждение паролем")


class LoginRequest(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    is_admin: bool = False
    banned: bool = False
    # Дата/время установки бана и дата автоматического снятия (начало след. месяца).
    banned_at: dt.datetime | None = None
    banned_until: dt.datetime | None = None
    email_confirmed: bool = True
    must_change_password: bool = False
    created_at: dt.datetime


class AuthResponse(BaseModel):
    token: str
    token_type: str = "bearer"
    user: UserOut


class MessageResponse(BaseModel):
    ok: bool = True
    message: str = ""


class AccountCreate(BaseModel):
    driver: str = Field(description="Тип хранилища: ftp, ftps, sftp или imap")
    host: str
    port: int = 0
    login: str
    password: str = ""
    path: str = ""
    enabled: bool = True
    label: str = ""


class AccountUpdate(BaseModel):
    label: str | None = None
    host: str | None = None
    port: int | None = None
    login: str | None = None
    password: str | None = None
    path: str | None = None
    enabled: bool | None = None


class AccountOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    driver: str
    label: str
    host: str
    port: int
    login: str
    path: str
    enabled: bool
    created_at: dt.datetime
    nodes_count: int = 0


class FileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    size: int
    checksum: str
    created_at: dt.datetime


class FileNodeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    file_item_id: int
    account_id: int
    remote_id: str
    position: int