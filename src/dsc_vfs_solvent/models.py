"""ORM-модели SQLAlchemy 2.0.

Многопользовательская схема: пользователь владеет аккаунтами хранилищ
и файлами. Данные одного пользователя недоступны другим.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Базовый класс всех ORM-моделей (объявляет метаданные таблиц)."""

    pass


class User(Base):
    """Пользователь системы."""

    __tablename__ = "users"

    # Первичный ключ записи пользователя.
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Логин пользователя — адрес электронной почты (уникален, используется для входа).
    username: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    # Проверочная метка пароля (salt$hmac), сам пароль не хранится.
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    # Ключ пользователя, обёрнутый ключом, производным от пароля (KEK).
    # В открытом виде на сервере не хранится.
    key_cipher: Mapped[str] = mapped_column(String(2048), default="", nullable=False)
    # Флаг администратора — даёт доступ к админ-функциям.
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Флаг блокировки: забаненный пользователь не может входить в систему.
    banned: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Дата/время установки бана. None — пользователь не забанен.
    banned_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    # E-mail подтверждён кодом из письма (регистрация).
    email_confirmed: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    # Требуется сменить пароль при следующем входе (восстановление пароля).
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    # Дата и время создания записи (регистрации пользователя).
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    @property
    def banned_until(self) -> dt.datetime | None:
        """Дата автоматического снятия бана: первый день следующего месяца.

        Бан действует до конца месяца установки и снимается автоматически
        в начале следующего месяца (даже если до конца месяца остался 1 день).
        """
        if self.banned_at is None:
            return None
        banned_at = self.banned_at
        if banned_at.tzinfo is None:
            banned_at = banned_at.replace(tzinfo=dt.timezone.utc)
        if banned_at.month == 12:
            return dt.datetime(banned_at.year + 1, 1, 1, tzinfo=dt.timezone.utc)
        return dt.datetime(banned_at.year, banned_at.month + 1, 1, tzinfo=dt.timezone.utc)

    # Аккаунты хранилищ пользователя (удаляются вместе с пользователем).
    accounts: Mapped[list["Account"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )
    # Файлы пользователя (удаляются вместе с пользователем).
    files: Mapped[list["FileItem"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )
    # Токены доступа пользователя (удаляются вместе с пользователем).
    tokens: Mapped[list["AuthToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class AuthToken(Base):
    """Токен доступа пользователя (хранится только хеш токена)."""

    __tablename__ = "auth_tokens"

    # Первичный ключ записи токена.
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Владелец токена; при удалении пользователя токены удаляются каскадно.
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # SHA-256 хеш токена (сам токен в БД не хранится).
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    # Дата выдачи токена.
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Дата истечения срока действия токена.
    expires_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # Обратная ссылка на пользователя-владельца токена.
    user: Mapped[User] = relationship(back_populates="tokens")


class VerificationCode(Base):
    """Код подтверждения e-mail или восстановления пароля.

    Одноразовый код, хранится только его SHA-256 хеш. Используется при
    регистрации (подтверждение e-mail) и при восстановлении пароля.
    """

    __tablename__ = "verification_codes"

    # Первичный ключ записи кода.
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # e-mail (для подтверждения при регистрации) или username (для смены пароля).
    identifier: Mapped[str] = mapped_column(
        String(128), nullable=False, index=True
    )
    # SHA-256 хеш одноразового кода (сам код в БД не хранится).
    code_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    # Назначение кода: подтверждение e-mail или восстановление пароля.
    purpose: Mapped[str] = mapped_column(
        String(32), default="verify_email", nullable=False
    )
    # Дата создания кода.
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Дата истечения срока действия кода.
    expires_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class Account(Base):
    """Учётная запись внешнего хранилища (FTP/IMAP), принадлежит пользователю."""

    __tablename__ = "accounts"

    # Первичный ключ записи аккаунта.
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Владелец аккаунта; при удалении пользователя аккаунты удаляются каскадно.
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Тип драйвера хранилища: ftp / ftps / sftp / imap.
    driver: Mapped[str] = mapped_column(String(16), nullable=False)
    # Человекочитаемое название аккаунта (отображается в интерфейсе).
    label: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    # Хост (адрес) внешнего хранилища.
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    # Порт подключения (0 — использовать порт по умолчанию для драйвера).
    port: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Логин для подключения к хранилищу.
    login: Mapped[str] = mapped_column(String(255), nullable=False)
    # Пароль шифруется паролем владельца (AES-256-GCM).
    password_cipher: Mapped[str] = mapped_column(String(1024), default="", nullable=False)
    # Путь/папка в хранилище, куда сохраняются части файлов.
    path: Mapped[str] = mapped_column(String(1024), default="", nullable=False)
    # Флаг доступности: отключённые аккаунты не участвуют в хранении.
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Дата и время создания записи аккаунта.
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Обратная ссылка на пользователя-владельца аккаунта.
    owner: Mapped[User] = relationship(back_populates="accounts")
    # Части файлов, размещённые в этом аккаунте.
    nodes: Mapped[list["FileNode"]] = relationship(back_populates="account")


class FileItem(Base):
    """Файл, сохранённый пользователем в децентрализованное хранилище."""

    __tablename__ = "file_items"

    # Первичный ключ записи файла.
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Владелец файла; при удалении пользователя файлы удаляются каскадно.
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Имя файла (как ��охранено пользователем).
    name: Mapped[str] = mapped_column(String(4096), nullable=False, index=True)
    # Размер файла в байтах.
    size: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # SHA-256 контрольная сумма содержимого файла (для проверки целостности).
    checksum: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    # Дата и время загрузки/создания файла.
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Обратная ссылка на пользователя-владельца файла.
    owner: Mapped[User] = relationship(back_populates="files")
    # Части (nodes), из которых состоит файл; удаляются вместе с файлом.
    nodes: Mapped[list["FileNode"]] = relationship(
        back_populates="file_item", cascade="all, delete-orphan"
    )


class FileNode(Base):
    """Часть файла, размещённая в конкретном аккаунте хранилища."""

    __tablename__ = "file_nodes"

    # Первичный ключ записи части.
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Файл, к которому относится часть; при удалении файла части удаляются каскадно.
    file_item_id: Mapped[int] = mapped_column(
        ForeignKey("file_items.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Аккаунт, где физически хранится часть; запрещено удалять аккаунт с частями.
    account_id: Mapped[int] = mapped_column(
        ForeignKey("accounts.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    # Идентификатор части во внешнем хранилище (remote id).
    remote_id: Mapped[str] = mapped_column(String(1024), nullable=False)
    # Пароль шифрования части (AES-256-CFB), уникальный для каждой части.
    password: Mapped[str] = mapped_column(String(512), nullable=False)
    # Порядковый номер части в файле (с нуля).
    position: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Обратная ссылка на файл-владелец части.
    file_item: Mapped[FileItem] = relationship(back_populates="nodes")
    # Обратная ссылка на аккаунт, где хранится часть.
    account: Mapped[Account] = relationship(back_populates="nodes")