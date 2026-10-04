"""Абстрактный интерфейс драйвера хранилища."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Self

from dsc_vfs_solvent.log import get_logger
from dsc_vfs_solvent.models import Account

log = get_logger(__name__)


class StorageError(RuntimeError):
    """Ошибка взаимодействия с внешним хранилищем."""


class StorageDriver(ABC):
    """Базовый класс драйвера внешнего хранилища.

    Драйвер отвечает за низкоуровневые операции с конкретной службой
    (FTP, IMAP и т.д.): сохранение, получение и удаление бинарных частей.

    Соединение устанавливается в `prepare`; при неудаче попытка повторяется
    до `max_attempts` раз. Перед каждой операцией (`store`, `fetch`, `purge`)
    вызывается `_ensure_ready`: если `_is_connected` сообщает, что соединение
    неактуально, драйвер автоматически переподключается через `prepare`.
    """

    def __init__(
        self,
        account: Account,
        password: str,
        chunk_size: int,
        max_attempts: int = 3,
    ) -> None:
        self.account = account
        self.password = password
        self.chunk_size = chunk_size
        self.max_attempts = max(1, max_attempts)

    def prepare(self) -> Self:
        """Установить соединение, повторив попытку до `max_attempts` раз."""
        last_error: Exception | None = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                self._connect()
                return self
            except StorageError as exc:
                last_error = exc
                log.warning(
                    "Не удалось подключиться к %s (попытка %s/%s): %s",
                    self.account.driver, attempt, self.max_attempts, exc,
                )
                # Закрываем частично установленное соединение перед повтором.
                try:
                    self.finish()
                except Exception:  # noqa: BLE001
                    pass
        raise StorageError(
            f"Не удалось подключиться к {self.account.driver}: {last_error}"
        ) from last_error

    @abstractmethod
    def _connect(self) -> None:
        """Установить соединение и подготовить рабочую область."""

    def _is_connected(self) -> bool:
        """Проверить, что соединение живо.

        По умолчанию соединение считается живым; драйверы с долгоживущими
        соединениями (FTP, IMAP и т.д.) переопределяют метод реальной
        проверкой.
        """
        return True

    def _ensure_ready(self) -> None:
        """Проверить соединение и переподключиться при необходимости."""
        if not self._is_connected():
            log.warning(
                "Соединение с %s неактуально, переподключаемся",
                self.account.driver,
            )
            self.prepare()

    def store(self, message: bytes) -> str:
        """Сохранить часть файла, вернуть идентификатор в хранилище."""
        self._ensure_ready()
        return self._store(message)

    @abstractmethod
    def _store(self, message: bytes) -> str:
        """Сохранить часть файла (соединение уже проверено)."""

    def fetch(self, remote_id: str) -> bytes:
        """Получить часть файла по идентификатору."""
        self._ensure_ready()
        return self._fetch(remote_id)

    @abstractmethod
    def _fetch(self, remote_id: str) -> bytes:
        """Получить часть файла (соединение уже проверено)."""

    def purge(self, remote_id: str) -> bool:
        """Удалить часть файла."""
        self._ensure_ready()
        return self._purge(remote_id)

    @abstractmethod
    def _purge(self, remote_id: str) -> bool:
        """Удалить часть файла (соединение уже проверено)."""

    @abstractmethod
    def finish(self) -> None:
        """Закрыть соединение."""