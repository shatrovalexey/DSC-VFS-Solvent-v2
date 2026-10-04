"""Dependency Injection: доступ к общим компонентам приложения."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from dsc_vfs_solvent import auth
from dsc_vfs_solvent.db import Database
from dsc_vfs_solvent.keyring import UserKeyError, UserKeyStore
from dsc_vfs_solvent.models import User
from dsc_vfs_solvent.settings import AppSettings
from dsc_vfs_solvent.storage.manager import StorageManager

_bearer = HTTPBearer(auto_error=False)


def get_app_settings() -> AppSettings:
    return AppSettings.load()


SettingsDep = Annotated[AppSettings, Depends(get_app_settings)]


def get_db(settings: SettingsDep) -> Database:
    return app_state.db


def get_user_key_store(settings: SettingsDep) -> UserKeyStore:
    settings.ensure_rsa_keys()
    return UserKeyStore(
        private_key_pem=settings.rsa_private_pem,
        public_key_pem=settings.rsa_public_pem,
    )


def _optional_user_key(
    current_user: CurrentUser,
    store: Annotated[UserKeyStore, Depends(get_user_key_store)],
    x_vfs_key: Annotated[str | None, Header()] = None,
) -> str | None:
    """Ключ пользователя, если он уже есть в кэше или передан в заголовке."""
    key = store.get(current_user.id)
    if key is not None:
        return key
    if x_vfs_key:
        try:
            store.receive(current_user.id, x_vfs_key)
            return store.get(current_user.id)
        except UserKeyError:
            return None
    return None


def get_storage_manager(
    settings: SettingsDep,
    db: Annotated[Database, Depends(get_db)],
    user_key: Annotated[str | None, Depends(_optional_user_key)] = None,
) -> StorageManager:
    return StorageManager(
        db=db, chunk_size=settings.chunk_size, user_key=user_key
    )


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: Annotated[Database, Depends(get_db)],
) -> User:
    """Извлечь текущего пользователя из Bearer-токена."""
    token = credentials.credentials if credentials else None
    try:
        return auth.get_current_user(db, token)
    except auth.AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


CurrentUser = Annotated[User, Depends(get_current_user)]


def get_current_user_key(
    current_user: CurrentUser,
    store: Annotated[UserKeyStore, Depends(get_user_key_store)],
    x_vfs_key: Annotated[str | None, Header()] = None,
) -> str:
    """Вернуть ключ пользователя (из кэша или заголовка X-VFS-Key).

    Заголовок `X-VFS-Key` содержит user_key, зашифрованный открытым
    ключом сервера (RSA-OAEP). Ключ никогда не сохраняется в БД.
    """
    key = store.get(current_user.id)
    if key is not None:
        return key
    if not x_vfs_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Требуется заголовок X-VFS-Key (ключ пользователя)",
        )
    try:
        store.receive(current_user.id, x_vfs_key)
    except UserKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    key = store.get(current_user.id)
    if key is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Не удалось получить ключ пользователя",
        )
    return key


CurrentUserKey = Annotated[str, Depends(get_current_user_key)]


def require_admin_user(current_user: CurrentUser) -> User:
    """Текущий пользователь должен быть администратором."""
    try:
        auth.require_admin(current_user)
    except auth.AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc
    return current_user


AdminUser = Annotated[User, Depends(require_admin_user)]


class _AppState:
    def __init__(self) -> None:
        self.settings: AppSettings | None = None
        self.db: Database | None = None


app_state = _AppState()


def bootstrap(settings: AppSettings) -> None:
    """Инициализировать общее состояние приложения (вызывается при старте)."""
    settings.ensure_dirs()
    settings.ensure_rsa_keys()
    app_state.settings = settings
    app_state.db = Database(settings.database_url())
    app_state.db.create_all()