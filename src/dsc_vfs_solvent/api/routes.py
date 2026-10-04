"""HTTP-эндпоинты REST API.

Многопользовательность: все операции с файлами и аккаунтами выполняются
только от имени аутентифицированного пользователя (CurrentUser).
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from dsc_vfs_solvent import auth, crypto
from dsc_vfs_solvent.api.deps import (
    AdminUser,
    CurrentUser,
    CurrentUserKey,
    SettingsDep,
    get_db,
    get_storage_manager,
    get_user_key_store,
)
from dsc_vfs_solvent.api.schemas import (
    AccountCreate,
    AccountOut,
    AccountUpdate,
    AuthResponse,
    ChangePasswordRequest,
    DeleteAccountRequest,
    FileNodeOut,
    FileOut,
    LoginRequest,
    MessageResponse,
    RegisterRequest,
    ResetPasswordRequest,
    UserOut,
    VerifyEmailRequest,
)
from dsc_vfs_solvent.db import Database
from dsc_vfs_solvent.keyring import UserKeyError, UserKeyStore
from dsc_vfs_solvent.models import Account, FileItem, User
from dsc_vfs_solvent.storage.base import StorageError
from dsc_vfs_solvent.storage.manager import StorageManager

router = APIRouter(prefix="/api", tags=["core"])

_bearer = HTTPBearer(auto_error=False)


# -- Аутентификация -------------------------------------------------------

@router.post("/auth/register", response_model=AuthResponse)
def register(
    payload: RegisterRequest,
    db: Annotated[Database, Depends(get_db)],
    settings: SettingsDep,
    store: Annotated[UserKeyStore, Depends(get_user_key_store)],
    x_vfs_key: Annotated[str | None, Header()] = None,
) -> AuthResponse:
    """Регистрация по e-mail. На почту отправляется код подтверждения.

    Пока e-mail не подтверждён (POST /api/auth/verify), вход невозможен.
    """
    user_key: str | None = None
    if x_vfs_key:
        try:
            user_key = store.decrypt(x_vfs_key)
        except UserKeyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        user = auth.register(db, settings, payload.username, payload.password, user_key=user_key)
        # Токен не выдаём до подтверждения e-mail.
        return AuthResponse(token="", user=UserOut.model_validate(user))
    except auth.AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/auth/verify", response_model=AuthResponse)
def verify_email(
    payload: VerifyEmailRequest,
    db: Annotated[Database, Depends(get_db)],
) -> AuthResponse:
    """Подтвердить e-mail кодом из письма и получить токен."""
    try:
        user = auth.verify_email(db, payload.username, payload.code)
        token = auth.generate_token()
        db.create_token(user.id, auth.hash_token(token))
    except auth.AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AuthResponse(token=token, user=UserOut.model_validate(user))


@router.post("/auth/change-password", response_model=MessageResponse)
def change_password(
    payload: ChangePasswordRequest,
    current_user: CurrentUser,
    db: Annotated[Database, Depends(get_db)],
) -> MessageResponse:
    """Сменить пароль текущего пользователя."""
    try:
        auth.change_password(db, current_user.id, payload.old_password, payload.new_password)
    except auth.AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return MessageResponse(message="Пароль изменён")


@router.post("/auth/forgot-password", response_model=MessageResponse)
def forgot_password(
    payload: ResetPasswordRequest,
    db: Annotated[Database, Depends(get_db)],
    settings: SettingsDep,
) -> MessageResponse:
    """Восстановление пароля: сервер генерирует случайный пароль и шлёт на e-mail."""
    auth.reset_password(db, settings, payload.username)
    return MessageResponse(message="Если e-mail зарегистрирован, новый пароль отправлен")


@router.post("/auth/delete-account", response_model=MessageResponse)
def delete_my_account(
    payload: DeleteAccountRequest,
    current_user: CurrentUser,
    db: Annotated[Database, Depends(get_db)],
    manager: Annotated[StorageManager, Depends(get_storage_manager)],
    store: Annotated[UserKeyStore, Depends(get_user_key_store)],
) -> MessageResponse:
    """Снять регистрацию: уничтожить файлы и удалить аккаунт."""
    try:
        # Подтверждаем паролем.
        user = db.get(User, current_user.id)
        if user is None or not crypto.verify_password(payload.password, user.password_hash):
            raise auth.AuthError("Неверный пароль")
        # Уничтожаем все файлы во внешних хранилищах.
        for item in db.list_files(current_user.id, limit=10_000):
            try:
                manager.purge(item.id, user_id=current_user.id)
            except Exception:
                # Если часть не удалилась во внешнем хранилище — продолжаем.
                pass
        auth.delete_account(db, current_user.id)
        store.drop(current_user.id)
    except auth.AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return MessageResponse(message="Аккаунт удалён, файлы уничтожены")


@router.post("/auth/login", response_model=AuthResponse)
def login(
    payload: LoginRequest,
    db: Annotated[Database, Depends(get_db)],
) -> AuthResponse:
    try:
        user, token = auth.login(db, payload.username, payload.password)
    except auth.AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    return AuthResponse(token=token, user=UserOut.model_validate(user))


@router.post("/auth/logout", response_model=MessageResponse)
def logout(
    current_user: CurrentUser,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: Annotated[Database, Depends(get_db)],
    store: Annotated[UserKeyStore, Depends(get_user_key_store)],
) -> MessageResponse:
    if credentials:
        auth.logout(db, credentials.credentials)
    # При выходе забываем ключ пользователя на сервере.
    store.drop(current_user.id)
    return MessageResponse(message="Выход выполнен")


@router.get("/auth/me", response_model=UserOut)
def me(current_user: CurrentUser) -> User:
    return current_user


@router.get("/auth/public-key", response_model=MessageResponse)
def public_key(
    store: Annotated[UserKeyStore, Depends(get_user_key_store)],
) -> dict:
    """Открытый RSA-ключ сервера для шифрования ключа пользователя."""
    return {"public_key": store.public_key_pem}


@router.post("/auth/key", response_model=MessageResponse)
def submit_key(
    current_user: CurrentUser,
    store: Annotated[UserKeyStore, Depends(get_user_key_store)],
    x_vfs_key: Annotated[str | None, Header()] = None,
) -> MessageResponse:
    """Передать зашифрованный ключ пользователя на сервер.

    Ключ шифруется открытым ключом сервера (RSA-OAEP), передаётся
    в заголовке X-VFS-Key, расшифровывается и кэшируется в памяти.
    """
    if not x_vfs_key:
        raise HTTPException(
            status_code=400,
            detail="Требуется заголовок X-VFS-Key",
        )
    try:
        store.receive(current_user.id, x_vfs_key)
    except UserKeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return MessageResponse(message="Ключ принят")


# -- Администрирование (баны) ---------------------------------------------

@router.get("/admin/users", response_model=list[UserOut])
def admin_list_users(
    _admin: AdminUser,
    db: Annotated[Database, Depends(get_db)],
    q: str | None = Query(default=None, description="Поиск по имени пользователя"),
) -> list[User]:
    """Список пользователей (только администратор), с поиском по имени.

    При просмотре списка автоматически снимаются баны, срок которых наступил
    (первый день месяца, следующего за месяцем установки бана).
    """
    db.expire_bans()
    return db.list_users(query=q)


@router.post("/admin/users/{user_id}/ban", response_model=MessageResponse)
def admin_ban_user(
    user_id: int,
    admin: AdminUser,
    db: Annotated[Database, Depends(get_db)],
    store: Annotated[UserKeyStore, Depends(get_user_key_store)],
) -> MessageResponse:
    """Забанить пользователя (только администратор). Нельзя банить админа."""
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if user.is_admin:
        raise HTTPException(
            status_code=400, detail="Нельзя забанить администратора"
        )
    if user.id == admin.id:
        raise HTTPException(
            status_code=400, detail="Нельзя забанить самого себя"
        )
    db.set_user_banned(user_id, banned=True)
    store.drop(user_id)
    return MessageResponse(message=f"Пользователь {user.username} забанен")


@router.post("/admin/users/{user_id}/unban", response_model=MessageResponse)
def admin_unban_user(
    user_id: int,
    _admin: AdminUser,
    db: Annotated[Database, Depends(get_db)],
) -> MessageResponse:
    """Разбанить пользователя (только администратор)."""
    user = db.set_user_banned(user_id, banned=False)
    if user is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    return MessageResponse(message=f"Пользователь {user.username} разбанен")


# -- Учётные записи хранилищ ----------------------------------------------

@router.get("/accounts", response_model=list[AccountOut])
def list_accounts(
    current_user: CurrentUser,
    db: Annotated[Database, Depends(get_db)],
) -> list[Account]:
    accounts = db.list_accounts(current_user.id)
    for account in accounts:
        account.nodes_count = db.count_nodes_for_account(account.id)
    return accounts


@router.post("/accounts", response_model=AccountOut)
def create_account(
    payload: AccountCreate,
    current_user: CurrentUser,
    user_key: CurrentUserKey,
    db: Annotated[Database, Depends(get_db)],
) -> Account:
    account = Account(
        user_id=current_user.id,
        driver=payload.driver,
        label=payload.label,
        host=payload.host,
        port=payload.port,
        login=payload.login,
        password_cipher=crypto.encrypt_account_password(payload.password, user_key),
        path=payload.path,
        enabled=payload.enabled,
    )
    with db.session() as session:
        session.add(account)
        session.flush()
        account_id = account.id
    result = db.account(account_id, current_user.id)
    if result is None:
        raise HTTPException(status_code=500, detail="Не удалось создать аккаунт")
    result.nodes_count = db.count_nodes_for_account(result.id)
    return result


@router.patch("/accounts/{account_id}", response_model=AccountOut)
def update_account(
    account_id: int,
    payload: AccountUpdate,
    current_user: CurrentUser,
    user_key: CurrentUserKey,
    db: Annotated[Database, Depends(get_db)],
) -> Account:
    with db.session() as session:
        account = session.get(Account, account_id)
        if account is None or account.user_id != current_user.id:
            raise HTTPException(status_code=404, detail="Аккаунт не найден")
        data = payload.model_dump(exclude_unset=True)
        if "password" in data and data["password"] is not None:
            account.password_cipher = crypto.encrypt_account_password(
                data.pop("password"), user_key
            )
        for field, value in data.items():
            setattr(account, field, value)
        session.flush()
        account_id = account.id
    result = db.account(account_id, current_user.id)
    if result is None:
        raise HTTPException(status_code=500, detail="Аккаунт не найден")
    result.nodes_count = db.count_nodes_for_account(result.id)
    return result


@router.delete("/accounts/{account_id}", response_model=MessageResponse)
def delete_account(
    account_id: int,
    current_user: CurrentUser,
    db: Annotated[Database, Depends(get_db)],
    manager: Annotated[StorageManager, Depends(get_storage_manager)],
) -> MessageResponse:
    with db.session() as session:
        account = session.get(Account, account_id)
        if account is None or account.user_id != current_user.id:
            raise HTTPException(status_code=404, detail="Аккаунт не найден")

    nodes_count = db.count_nodes_for_account(account_id)
    if nodes_count:
        try:
            moved = manager.migrate_account(account_id, user_id=current_user.id)
        except StorageError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        message = f"Аккаунт удалён, частей перенесено: {moved}"
    else:
        message = "Аккаунт удалён"

    with db.session() as session:
        account = session.get(Account, account_id)
        if account is not None and account.user_id == current_user.id:
            session.delete(account)
    return MessageResponse(message=message)


# -- Файлы ----------------------------------------------------------------

@router.post("/files", response_model=FileOut)
async def upload_file(
    file: UploadFile = File(...),
    current_user: CurrentUser,
    manager: Annotated[StorageManager, Depends(get_storage_manager)],
    db: Annotated[Database, Depends(get_db)],
) -> FileItem:
    # UploadFile буферизует на диск (SpooledTemporaryFile) — читаем потоково
    # порциями, не загружая файл в память целиком.
    if not file.filename:
        raise HTTPException(status_code=400, detail="Имя файла не указано")
    file_id = manager.store_stream(
        file.file,
        name=file.filename,
        user_id=current_user.id,
    )
    item = db.file_item(file_id, current_user.id)
    if item is None:
        raise HTTPException(status_code=500, detail="Файл не сохранён")
    return item


@router.get("/files", response_model=list[FileOut])
def list_files(
    current_user: CurrentUser,
    db: Annotated[Database, Depends(get_db)],
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[FileItem]:
    return db.list_files(current_user.id, limit=limit, offset=offset)


@router.get("/files/{file_id}", response_model=FileOut)
def get_file(
    file_id: int,
    current_user: CurrentUser,
    db: Annotated[Database, Depends(get_db)],
) -> FileItem:
    item = db.file_item(file_id, current_user.id)
    if item is None:
        raise HTTPException(status_code=404, detail="Файл не найден")
    return item


@router.get("/files/{file_id}/nodes", response_model=list[FileNodeOut])
def get_file_nodes(
    file_id: int,
    current_user: CurrentUser,
    db: Annotated[Database, Depends(get_db)],
) -> list:
    item = db.file_item(file_id, current_user.id)
    if item is None:
        raise HTTPException(status_code=404, detail="Файл не найден")
    return db.file_nodes(file_id, current_user.id)


@router.get("/files/{file_id}/download")
def download_file(
    file_id: int,
    current_user: CurrentUser,
    manager: Annotated[StorageManager, Depends(get_storage_manager)],
    db: Annotated[Database, Depends(get_db)],
) -> StreamingResponse:
    # Сначала узнаём файл и общее количество частей (одна транзакция).
    item, nodes = db.get_file_with_nodes(file_id, current_user.id)
    if item is None:
        raise HTTPException(status_code=404, detail="Файл не найден")
    if not nodes:
        raise HTTPException(status_code=400, detail="У файла нет частей")

    total_chunks = len(nodes)
    filename = Path(item.name).name

    def iterfile():
        # Части скачиваются многопоточно в отдельную временную папку
        # (каждая — в пронумерованный файл), отдаются по порядку
        # и удаляются после отправки.
        yield from manager.fetch_parts_stream(file_id, user_id=current_user.id)

    return StreamingResponse(
        iterfile(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("/files/{file_id}", response_model=MessageResponse)
def delete_file(
    file_id: int,
    current_user: CurrentUser,
    manager: Annotated[StorageManager, Depends(get_storage_manager)],
) -> MessageResponse:
    try:
        manager.purge(file_id, user_id=current_user.id)
    except StorageError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return MessageResponse(message="Файл удалён")