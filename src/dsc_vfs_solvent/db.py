"""Работа с базой данных через SQLAlchemy 2.0 (PostgreSQL).

Все запросы к данным пользователя фильтруются по user_id — изоляция
между пользователями обеспечивается на уровне доступа к данным.
"""

from __future__ import annotations

import datetime as dt
import time
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, delete, func, select
from sqlalchemy.engine import Engine, URL
from sqlalchemy.exc import DBAPIError, DisconnectionError, InterfaceError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from dsc_vfs_solvent.log import get_logger
from dsc_vfs_solvent.models import (
    Account,
    AuthToken,
    Base,
    FileItem,
    FileNode,
    User,
    VerificationCode,
)

TOKEN_TTL = dt.timedelta(days=30)

log = get_logger(__name__)

# Сколько раз повторяем операцию при потере соединения с БД
# (первая попытка + повторы).
DB_RETRY_ATTEMPTS = 3
# Пауза между повторами (секунды).
DB_RETRY_DELAY = 0.2


def _is_connection_error(exc: BaseException) -> bool:
    """Является ли исключение ошибкой подключения/потери соединения.

    Покрывает: ошибки соединения/переполнения пула (OperationalError,
    InterfaceError), отзыв соединения пулом (DisconnectionError) и любые
    другие ошибки DBAPI, помеченные SQLAlchemy как «соединение невалидно»
    (connection_invalidated=True). Обычные ошибки запросов (например,
    нарушение уникальности) НЕ считаются ошибками подключения.
    """
    if isinstance(exc, (OperationalError, InterfaceError, DisconnectionError)):
        return True
    if isinstance(exc, DBAPIError):
        orig = exc.orig
        if orig is not None and getattr(orig, "connection_invalidated", False):
            return True
    return False


class Database:
    """Обёртка над engine/session SQLAlchemy."""

    def __init__(self, url: str | URL) -> None:
        """Создать engine по SQLAlchemy URL (PostgreSQL).

        Пул соединений настраивается под многопоточный доступ
        (до 16 потоков файловых операций).
        """
        self.url = url
        self.engine: Engine = create_engine(
            url,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
        )
        self.session_factory = sessionmaker(
            bind=self.engine, expire_on_commit=False, autoflush=False
        )

    @staticmethod
    def _is_connection_error(exc: BaseException) -> bool:
        return _is_connection_error(exc)

    def _dispose_pool(self) -> None:
        """Сбросить пул соединений (dispose) — следующее обращение создаст новое."""
        try:
            self.engine.dispose()
        except Exception:  # noqa: BLE001
            pass

    def _retry_connection_errors(self, func, *args, **kwargs):
        """Выполнить func, повторяя при потере соединения с БД.

        При ошибке подключения пул соединений сбрасывается (dispose), что
        заставляет engine создать новое подключение, и операция выполняется
        заново. Используется для всех операций с БД (DRY): и для сессий,
        и для одношаговых вызовов вроде create_all.
        """
        last_error: BaseException | None = None
        for attempt in range(DB_RETRY_ATTEMPTS):
            try:
                return func(*args, **kwargs)
            except BaseException as exc:  # noqa: BLE001
                if not self._is_connection_error(exc):
                    raise
                last_error = exc
                log.warning(
                    "Ошибка подключения к БД (попытка %s/%s): %s",
                    attempt + 1, DB_RETRY_ATTEMPTS, exc,
                )
                self._dispose_pool()
                if attempt + 1 < DB_RETRY_ATTEMPTS:
                    time.sleep(DB_RETRY_DELAY)
        assert last_error is not None
        raise last_error

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Сессия с повторными попытками подключения к СУБД.

        Перед передачей сессии в `with db.session() as s` принудительно
        берётся соединение из пула. Если соединение не удалось установить
        (СУБД недоступна, сервер перезапускается, пул исчерпан), пул
        сбрасывается и попытка повторяется до DB_RETRY_ATTEMPTS раз.
        Благодаря этому все места, использующие `with db.session()`,
        автоматически получают переподключение без дублирования логики (DRY).

        Ошибка подключения, возникшая уже во время выполнения запросов
        внутри блока, пробрасывается вызывающему коду как обычно: повторять
        тело блока невозможно, и при необходимости это делает вызывающий код
        (например, StorageManager уже повторяет операции с частями файлов).
        """
        last_error: BaseException | None = None
        for attempt in range(DB_RETRY_ATTEMPTS):
            session = self.session_factory()
            try:
                # Именно здесь возникает ошибка, если СУБД недоступна:
                # берём соединение из пула до передачи управления блоку.
                session.connection()
            except BaseException as exc:  # noqa: BLE001
                session.close()
                if not self._is_connection_error(exc):
                    raise
                last_error = exc
                log.warning(
                    "Ошибка подключения к БД (попытка %s/%s): %s",
                    attempt + 1, DB_RETRY_ATTEMPTS, exc,
                )
                self._dispose_pool()
                if attempt + 1 < DB_RETRY_ATTEMPTS:
                    time.sleep(DB_RETRY_DELAY)
                continue
            try:
                yield session
                session.commit()
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()
            return
        assert last_error is not None
        raise last_error

    def create_all(self) -> None:
        """Создать все таблицы и индексы одной операцией.

        Используется полное метаданное описание моделей (Base.metadata):
        таблицы и индексы создаются сразу, без последующих ALTER TABLE.
        Для уже существующей базы вызов безопасен (IF NOT EXISTS).
        При потере соединения операция повторяется.
        """
        self._retry_connection_errors(Base.metadata.create_all, self.engine)

    # -- Внутренние хелперы (DRY) -----------------------------------------

    @staticmethod
    def _insert(session: Session, obj) -> int:
        """Добавить объект в сессию, вернуть его первичный ключ."""
        session.add(obj)
        session.flush()
        return obj.id  # type: ignore[no-any-return]

    def _get_owned(self, model: type, item_id: int, user_id: int):
        """Найти объект по id, принадлежащий пользователю."""
        with self.session() as s:
            return s.scalar(
                select(model).where(
                    model.id == item_id,  # type: ignore[attr-defined]
                    model.user_id == user_id,  # type: ignore[attr-defined]
                )
            )

    def _update_user(self, user_id: int, **fields) -> User | None:
        """Обновить поля пользователя и вернуть свежий объект."""
        with self.session() as s:
            user = s.get(User, user_id)
            if user is None:
                return None
            for field, value in fields.items():
                setattr(user, field, value)
            s.flush()
        return self.get(User, user_id)

    # -- Пользователи -----------------------------------------------------

    def get_user_by_username(self, username: str) -> User | None:
        with self.session() as s:
            return s.scalar(select(User).where(User.username == username))

    def create_user(
        self,
        username: str,
        password_hash: str,
        key_cipher: str = "",
        is_admin: bool = False,
        email_confirmed: bool = True,
    ) -> User:
        with self.session() as s:
            user_id = self._insert(
                s,
                User(
                    username=username,
                    password_hash=password_hash,
                    key_cipher=key_cipher,
                    is_admin=is_admin,
                    email_confirmed=email_confirmed,
                ),
            )
        result = self.get(User, user_id)
        if result is None:
            raise RuntimeError("Не удалось создать пользователя")
        return result

    def list_users(self, query: str | None = None) -> list[User]:
        """Список всех пользователей (для администратора), с поиском по имени."""
        with self.session() as s:
            stmt = select(User)
            if query:
                stmt = stmt.where(User.username.ilike(f"%{query}%"))
            return list(s.scalars(stmt.order_by(User.id)))

    def set_user_banned(self, user_id: int, banned: bool) -> User | None:
        """Забанить/разбанить пользователя.

        При бане фиксируется дата/время установки (banned_at), все токены
        доступа отзываются. Разбан сбрасывает banned_at в None.
        """
        with self.session() as s:
            user = s.get(User, user_id)
            if user is None:
                return None
            user.banned = banned
            if banned:
                user.banned_at = dt.datetime.now(dt.timezone.utc)
                # При бане отзываем все токены доступа.
                s.execute(delete(AuthToken).where(AuthToken.user_id == user_id))
            else:
                user.banned_at = None
            s.flush()
        return self.get(User, user_id)

    def expire_bans(self) -> int:
        """Автоматически снять баны, у которых наступил срок (начало месяца).

        Бан снимается в первый день месяца, следующего за месяцем установки,
        даже если до конца месяца оставался 1 день. Возвращает количество
        снятых банов.
        """
        now = dt.datetime.now(dt.timezone.utc)
        with self.session() as s:
            users = list(
                s.scalars(
                    select(User).where(
                        User.banned.is_(True),
                        User.banned_at.is_not(None),
                    )
                )
            )
            expired: list[User] = []
            for user in users:
                if user.banned_until is not None and user.banned_until <= now:
                    expired.append(user)
            for user in expired:
                user.banned = False
                user.banned_at = None
            s.flush()
            return len(expired)

    def delete_user(self, user_id: int) -> None:
        """Полностью удалить пользователя со всеми данными.

        Удаляются: аккаунты, файлы (каскадно FileNode), токены, коды
        подтверждения и сам пользователь.
        """
        with self.session() as s:
            user = s.get(User, user_id)
            if user is None:
                return
            # Каскадные связи (accounts, files, tokens) удаляются через
            # relationship cascade; коды подтверждения удаляем явно.
            s.execute(
                delete(VerificationCode).where(
                    VerificationCode.identifier == user.username
                )
            )
            s.delete(user)

    def set_user_password_hash(
        self, user_id: int, password_hash: str
    ) -> User | None:
        """Обновить проверочную метку пароля пользователя."""
        return self._update_user(user_id, password_hash=password_hash)

    def set_user_key_cipher(self, user_id: int, key_cipher: str) -> User | None:
        """Обновить обёрнутый ключ пользователя."""
        return self._update_user(user_id, key_cipher=key_cipher)

    def count_users(self) -> int:
        """Количество пользователей (для назначения первого администратора)."""
        with self.session() as s:
            return int(s.scalar(select(func.count(User.id))) or 0)

    # -- Токены -----------------------------------------------------------

    def create_token(self, user_id: int, token_hash: str) -> AuthToken:
        with self.session() as s:
            token_id = self._insert(
                s,
                AuthToken(
                    user_id=user_id,
                    token_hash=token_hash,
                    expires_at=dt.datetime.now(dt.timezone.utc) + TOKEN_TTL,
                ),
            )
        result = self.get(AuthToken, token_id)
        if result is None:
            raise RuntimeError("Не удалось создать токен")
        return result

    def get_user_by_token_hash(self, token_hash: str) -> User | None:
        now = dt.datetime.now(dt.timezone.utc)
        with self.session() as s:
            token = s.scalar(
                select(AuthToken).where(
                    AuthToken.token_hash == token_hash,
                    AuthToken.expires_at > now,
                )
            )
            if token is None:
                return None
            return s.get(User, token.user_id)

    def revoke_token(self, token_hash: str) -> None:
        with self.session() as s:
            s.execute(delete(AuthToken).where(AuthToken.token_hash == token_hash))

    # -- Коды подтверждения ----------------------------------------------

    def create_verification_code(
        self, identifier: str, code_hash: str, purpose: str = "verify_email"
    ) -> VerificationCode:
        """Сохранить одноразовый код (подтверждение e-mail или сброс пароля)."""
        with self.session() as s:
            # Гасим старые коды для этого идентификатора и цели.
            s.execute(
                delete(VerificationCode).where(
                    VerificationCode.identifier == identifier,
                    VerificationCode.purpose == purpose,
                )
            )
            code_id = self._insert(
                s,
                VerificationCode(
                    identifier=identifier,
                    code_hash=code_hash,
                    purpose=purpose,
                    expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=30),
                ),
            )
        result = self.get(VerificationCode, code_id)
        if result is None:
            raise RuntimeError("Не удалось сохранить код подтверждения")
        return result

    def verify_code(
        self, identifier: str, code_hash: str, purpose: str
    ) -> bool:
        """Проверить код (хеш) для идентификатора и цели.

        Код одноразовый: при успешной проверке удаляется.
        """
        now = dt.datetime.now(dt.timezone.utc)
        with self.session() as s:
            code = s.scalar(
                select(VerificationCode).where(
                    VerificationCode.identifier == identifier,
                    VerificationCode.purpose == purpose,
                    VerificationCode.expires_at > now,
                )
            )
            if code is None or code.code_hash != code_hash:
                return False
            s.delete(code)
            return True

    # -- Общие хелперы ----------------------------------------------------

    def get(self, model: type, item_id: int):
        """Получить объект по первичному ключу в управляемой сессии."""
        with self.session() as s:
            return s.get(model, item_id)

    def account(self, account_id: int, user_id: int) -> Account | None:
        return self._get_owned(Account, account_id, user_id)

    def list_accounts(self, user_id: int) -> list[Account]:
        with self.session() as s:
            return list(
                s.scalars(
                    select(Account)
                    .where(Account.user_id == user_id)
                    .order_by(Account.id)
                )
            )

    def list_files(
        self, user_id: int, limit: int = 100, offset: int = 0
    ) -> list[FileItem]:
        with self.session() as s:
            stmt = (
                select(FileItem)
                .where(FileItem.user_id == user_id)
                .order_by(FileItem.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            return list(s.scalars(stmt))

    def file_item(self, file_id: int, user_id: int) -> FileItem | None:
        return self._get_owned(FileItem, file_id, user_id)

    def get_file_with_nodes(
        self, file_id: int, user_id: int
    ) -> tuple[FileItem | None, list[FileNode]]:
        """Прочитать файл и все его части в одной транзакции.

        Используется при получении файла (fetch): гарантирует согласованное
        чтение FileItem и FileNode — между двумя отдельными запросами части
        не могут «исчезнуть» или измениться.
        """
        with self.session() as s:
            item = s.scalar(
                select(FileItem).where(
                    FileItem.id == file_id,
                    FileItem.user_id == user_id,
                )
            )
            if item is None:
                return None, []
            stmt = (
                select(FileNode)
                .where(FileNode.file_item_id == file_id)
                .order_by(FileNode.position)
            )
            return item, list(s.scalars(stmt))

    def file_nodes(self, file_item_id: int, user_id: int) -> list[FileNode]:
        """Части файла, принадлежащего пользователю (через владельца FileItem)."""
        _, nodes = self.get_file_with_nodes(file_item_id, user_id)
        return nodes

    def account_nodes(self, account_id: int, user_id: int) -> list[FileNode]:
        """Все части, размещённые в аккаунте пользователя."""
        if self.account(account_id, user_id) is None:
            return []
        with self.session() as s:
            stmt = (
                select(FileNode)
                .where(FileNode.account_id == account_id)
                .order_by(FileNode.file_item_id, FileNode.position)
            )
            return list(s.scalars(stmt))

    def list_accounts_except(self, user_id: int, exclude_account_id: int) -> list[Account]:
        """Аккаунты пользователя, кроме указанного (для переноса частей)."""
        with self.session() as s:
            stmt = (
                select(Account)
                .where(
                    Account.user_id == user_id,
                    Account.id != exclude_account_id,
                )
                .order_by(Account.id)
            )
            return list(s.scalars(stmt))

    def count_nodes_for_account(self, account_id: int) -> int:
        """Количество частей файлов, размещённых в аккаунте."""
        with self.session() as s:
            return int(
                s.scalar(
                    select(func.count(FileNode.id)).where(
                        FileNode.account_id == account_id
                    )
                )
                or 0
            )

    def file_items_with_nodes_in_account(
        self, account_id: int, user_id: int
    ) -> list[FileItem]:
        """Файлы пользователя, у которых есть хотя бы одна часть в аккаунте."""
        with self.session() as s:
            stmt = (
                select(FileItem)
                .join(FileNode, FileNode.file_item_id == FileItem.id)
                .where(
                    FileItem.user_id == user_id,
                    FileNode.account_id == account_id,
                )
                .order_by(FileItem.id)
                .distinct()
            )
            return list(s.scalars(stmt))