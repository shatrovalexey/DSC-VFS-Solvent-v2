"""Сервис авторизации и многопользовательности.

Реализует регистрацию по e-mail с подтверждением кода из письма, вход по
паролю, выпуск и проверку токенов доступа, смену пароля, восстановление
пароля (сервер генерирует случайный пароль, отправляет его на e-mail и
требует смены при следующем входе) и удаление аккаунта с уничтожением
файлов. Пароли хранятся как HMAC-метки (соль + дайджест), токены — только
в виде SHA-256 хеша. Коды подтверждения e-mail хранятся только в виде
SHA-256 хеша.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets

from dsc_vfs_solvent import crypto
from dsc_vfs_solvent.db import Database
from dsc_vfs_solvent.mailer import send_code
from dsc_vfs_solvent.models import User
from dsc_vfs_solvent.settings import AppSettings


class AuthError(RuntimeError):
    """Ошибка аутентификации или авторизации."""


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def generate_code() -> str:
    """Сгенерировать одноразовый код подтверждения e-mail (6 цифр)."""
    return f"{secrets.randbelow(1_000_000):06d}"


def generate_random_password() -> str:
    """Сгенерировать случайный временный пароль."""
    return secrets.token_urlsafe(12)


def _is_valid_email(email: str) -> bool:
    """Простая проверка адреса электронной почты."""
    email = email.strip()
    if "@" not in email or len(email) > 128:
        return False
    local, _, domain = email.partition("@")
    return bool(local) and "." in domain


def register(
    db: Database,
    settings: AppSettings,
    username: str,
    password: str,
    user_key: str | None = None,
) -> User:
    """Создать нового пользователя (e-mail ещё не подтверждён).

    На e-mail отправляется одноразовый код подтверждения. Пока код не
    подтверждён, вход невозможен.
    """
    username = username.strip().lower()
    if not _is_valid_email(username):
        raise AuthError("Логин должен быть адресом электронной почты")
    if len(password) < 6:
        raise AuthError("Пароль должен содержать не менее 6 символов")
    if db.get_user_by_username(username) is not None:
        raise AuthError("Пользователь с таким e-mail уже существует")
    # Первый пользователь становится администратором.
    is_admin = db.count_users() == 0
    key = user_key or crypto.generate_user_key()
    key_cipher = crypto.wrap_user_key(key, password)
    user = db.create_user(
        username,
        crypto.hash_password(password),
        key_cipher=key_cipher,
        is_admin=is_admin,
        email_confirmed=False,
    )
    code = generate_code()
    db.create_verification_code(
        user.username, hash_token(code), purpose="verify_email"
    )
    send_code(settings, user.username, code, "verify_email")
    return user


def verify_email(db: Database, username: str, code: str) -> User:
    """Подтвердить e-mail одноразовым кодом из письма."""
    user = db.get_user_by_username(username.strip().lower())
    if user is None:
        raise AuthError("Пользователь не найден")
    if user.email_confirmed:
        return user
    if not db.verify_code(
        user.username, hash_token(code.strip()), purpose="verify_email"
    ):
        raise AuthError("Неверный или истёкший код подтверждения")
    with db.session() as session:
        db_user = session.get(User, user.id)
        db_user.email_confirmed = True
    return user


def login(db: Database, username: str, password: str) -> tuple[User, str]:
    """Проверить пароль и выпустить новый токен доступа."""
    user = db.get_user_by_username(username.strip().lower())
    if user is None or not crypto.verify_password(password, user.password_hash):
        raise AuthError("Неверный e-mail или пароль")
    if not user.email_confirmed:
        raise AuthError("E-mail не подтверждён. Введите код из письма")
    if user.banned:
        # Бан действует до конца месяца установки и снимается автоматически
        # в начале следующего месяца.
        if user.banned_until is not None and user.banned_until <= dt.datetime.now(dt.timezone.utc):
            db.set_user_banned(user.id, banned=False)
        else:
            raise AuthError("Пользователь забанен")
    token = generate_token()
    db.create_token(user.id, hash_token(token))
    return user, token


def change_password(
    db: Database, user_id: int, old_password: str, new_password: str
) -> User:
    """Сменить пароль: проверить старый, сохранить новый."""
    user = db.get(User, user_id)
    if user is None:
        raise AuthError("Пользователь не найден")
    if not crypto.verify_password(old_password, user.password_hash):
        raise AuthError("Неверный текущий пароль")
    if len(new_password) < 6:
        raise AuthError("Новый пароль должен содержать не менее 6 символов")
    if not user.key_cipher:
        raise AuthError("У пользователя нет ключа шифрования")
    # Перешифровать ключ пользователя новым паролем (KEK).
    user_key = crypto.unwrap_user_key(user.key_cipher, old_password)
    new_key_cipher = crypto.wrap_user_key(user_key, new_password)
    with db.session() as session:
        db_user = session.get(User, user_id)
        db_user.password_hash = crypto.hash_password(new_password)
        db_user.key_cipher = new_key_cipher
        db_user.must_change_password = False
    return user


def reset_password(db: Database, settings: AppSettings, username: str) -> None:
    """Восстановление пароля: сгенерировать случайный и отправить на e-mail.

    Новый пароль сразу становится действующим, а пользователь обязан сменить
    его при следующем входе (must_change_password=True). Так как старый ключ
    пользователя обёрнут старым паролем, при восстановлении генерируется
    новый ключ — пароли аккаунтов хранилищ нужно будет ввести заново.
    """
    user = db.get_user_by_username(username.strip().lower())
    if user is None:
        # Не раскрываем, существует ли пользователь.
        return
    new_password = generate_random_password()
    new_key_cipher = crypto.wrap_user_key(crypto.generate_user_key(), new_password)
    with db.session() as session:
        db_user = session.get(User, user.id)
        db_user.password_hash = crypto.hash_password(new_password)
        db_user.key_cipher = new_key_cipher
        db_user.must_change_password = True
        db_user.email_confirmed = True
    # Отправляем временный пароль на e-mail (лог-режим печатает в консоль).
    send_code(settings, user.username, new_password, "reset_password")


def delete_account(db: Database, user_id: int) -> None:
    """Снять регистрацию: удалить пользователя со всеми данными.

    Файлы и аккаунты удаляются каскадно; части файлов во внешних хранилищах
    уничтожаются на уровне StorageManager (purge всех файлов) до вызова
    этого метода.
    """
    db.delete_user(user_id)