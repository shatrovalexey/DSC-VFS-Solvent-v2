"""Менеджер хранения: потоковая нарезка, шифрование и распределение частей.

Реализует основную бизнес-логику децентрализованного хранения:

1. Файл читается часть за частью (chunk), каждая часть шифруется
   AES-256-CFB со случайным паролем и отправляется в хранилище.
2. При чтении части скачиваются из хранилищ, расшифровываются и
   записываются на место (position * chunk_size) — файл не держится
   в оперативной памяти целиком.
3. Шифрование/отправка и скачивание/расшифровка выполняются
   многопоточно (ThreadPoolExecutor), память ограничена размером
   буфера активных частей.

Все операции выполняются в контексте user_id — пользователь видит только
свои файлы и свои аккаунты (многопользовательность). Пароли аккаунтов
расшифровываются ключом пользователя (user_key).
"""

from __future__ import annotations

import hashlib
import io
import shutil
import tempfile
import threading
from collections.abc import Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, as_completed, wait
from pathlib import Path

from dsc_vfs_solvent import crypto
from dsc_vfs_solvent.db import Database
from dsc_vfs_solvent.log import get_logger
from dsc_vfs_solvent.models import Account, FileItem, FileNode
from dsc_vfs_solvent.storage import (
    FTPDriver,
    FTPSDriver,
    IMAPDriver,
    SFTPDriver,
    StorageDriver,
    StorageError,
)

log = get_logger(__name__)

# Ограничение количества одновременно обрабатываемых частей (буфер в памяти).
# Каждая часть не превышает chunk_size, поэтому пиковое потребление RAM
# ≈ max_pending * chunk_size, а не размер всего файла.
MAX_PENDING = 32


class StorageManager:
    """Высокоуровневые операции: store, fetch, purge, sync, backup, restore."""

    def __init__(
        self,
        db: Database,
        chunk_size: int = 1024 * 1024,
        user_key: str | None = None,
    ) -> None:
        self.db = db
        self.chunk_size = chunk_size
        # Ключ пользователя (hex) для расшифровки паролей аккаунтов.
        self.user_key = user_key

    # -- Переиспользование авторизованных драйверов -------------------------

    class _DriverPool:
        """Пул авторизованных драйверов на одну операцию с файлом.

        Драйвер создаётся и авторизуется один раз на аккаунт и переиспользуется
        всеми потоками; блокировка сериализует доступ к соединению.

        `get(account)` возвращает (драйвер, блокировка) для аккаунта.
        `drop(account_id)` закрывает и выбрасывает сломанный драйвер — при
        следующем `get` он будет создан заново.
        `close()` закрывает все оставшиеся соединения.
        """

        def __init__(self, driver_factory) -> None:
            self._driver_factory = driver_factory
            self._drivers: dict[int, StorageDriver] = {}
            self._locks: dict[int, threading.Lock] = {}
            self._create_lock = threading.Lock()

        def get(self, account: Account) -> tuple[StorageDriver, threading.Lock]:
            with self._create_lock:
                driver = self._drivers.get(account.id)
                if driver is None:
                    driver = self._driver_factory(account).prepare()
                    self._drivers[account.id] = driver
                    self._locks[account.id] = threading.Lock()
            return self._drivers[account.id], self._locks[account.id]

        def drop(self, account_id: int) -> None:
            """Закрыть и удалить драйвер аккаунта после сбоя."""
            with self._create_lock:
                driver = self._drivers.pop(account_id, None)
                self._locks.pop(account_id, None)
            if driver is not None:
                try:
                    driver.finish()
                except Exception:  # noqa: BLE001
                    pass

        def close(self) -> None:
            for driver in self._drivers.values():
                try:
                    driver.finish()
                except Exception:  # noqa: BLE001
                    pass
            self._drivers.clear()
            self._locks.clear()

    def _new_driver_pool(self) -> _DriverPool:
        return self._DriverPool(self._driver)

    # -- Утилиты ----------------------------------------------------------

    def _account_password(self, account: Account) -> str:
        if not account.password_cipher:
            return ""
        if not self.user_key:
            raise StorageError("Отсутствует ключ пользователя для расшифровки пароля аккаунта")
        return crypto.decrypt_account_password(
            account.password_cipher, self.user_key
        )

    def _driver(self, account: Account) -> StorageDriver:
        password = self._account_password(account)
        if account.driver == "ftp":
            driver_cls: type[StorageDriver] = FTPDriver
        elif account.driver == "ftps":
            driver_cls = FTPSDriver
        elif account.driver == "sftp":
            driver_cls = SFTPDriver
        else:
            driver_cls = IMAPDriver
        return driver_cls(account=account, password=password, chunk_size=self.chunk_size)

    def _enabled_accounts(self, user_id: int) -> list[Account]:
        accounts = [
            a for a in self.db.list_accounts(user_id) if a.enabled
        ]
        if not accounts:
            raise StorageError("Нет доступных учётных записей хранилищ")
        return accounts

    def _workers(self, units: int) -> int:
        """Разумное число потоков: не больше 16 и не больше числа частей."""
        return max(1, min(16, units))

    # -- Сохранение (потоковое, многопоточное) -----------------------------

    def store_stream(
        self,
        source,
        name: str,
        user_id: int,
        size: int | None = None,
    ) -> int:
        """Сохранить поток байтов в децентрализованное хранилище.

        `source` — бинарный поток с методом `read(n)` (файл, SpooledTemporaryFile,
        BytesIO). Файл читается частями по `chunk_size`; каждая часть шифруется
        и отправляется в отдельном потоке. В памяти находится не более
        MAX_PENDING частей одновременно.
        """
        accounts = self._enabled_accounts(user_id)
        checksum = hashlib.sha256()
        total = 0

        with self.db.session() as session:
            item = FileItem(user_id=user_id, name=name, size=size or 0, checksum="")
            session.add(item)
            session.flush()
            file_id = item.id

        workers = self._workers(len(accounts) * 2)
        errors: list[BaseException] = []
        position = 0
        pending: dict[Future, int] = {}

        try:
            # Один авторизованный драйвер на аккаунт переиспользуется всеми
            # потоками — не нужно подключаться заново для каждой части.
            pool = self._new_driver_pool()
            try:
                with ThreadPoolExecutor(
                    max_workers=workers, thread_name_prefix="vfs-store"
                ) as pool_executor:
                    while True:
                        if errors:
                            break
                        chunk = source.read(self.chunk_size)
                        if not chunk:
                            break
                        total += len(chunk)
                        checksum.update(chunk)
                        future = pool_executor.submit(
                            self._store_chunk, chunk, accounts, position, file_id, pool
                        )
                        pending[future] = position
                        position += 1

                        # Ограничиваем буфер: ждём завершения хотя бы одной части.
                        if len(pending) >= MAX_PENDING:
                            done, _ = wait(pending, return_when=FIRST_COMPLETED)
                            for fut in done:
                                try:
                                    fut.result()
                                except BaseException as exc:  # noqa: BLE001
                                    errors.append(exc)
                                pending.pop(fut, None)

                    # Дожидаемся оставшихся задач.
                    for fut in as_completed(pending):
                        try:
                            fut.result()
                        except BaseException as exc:  # noqa: BLE001
                            errors.append(exc)
            finally:
                pool.close()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

        if errors:
            self._cleanup_failed_store(file_id, user_id)
            raise StorageError(
                f"Ошибка при сохранении файла: {errors[0]}"
            ) from errors[0]

        with self.db.session() as session:
            db_item = session.get(FileItem, file_id)
            if db_item is None:
                raise StorageError("Файл не сохранён")
            db_item.size = total
            db_item.checksum = checksum.hexdigest()

        log.info(
            "Сохранён файл id=%s user_id=%s размер=%s частей=%s потоков=%s",
            file_id, user_id, total, position, workers,
        )
        return file_id

    def _store_chunk(
        self,
        chunk: bytes,
        accounts: list[Account],
        position: int,
        file_id: int,
        pool,
    ) -> int:
        """Зашифровать и отправить одну часть, записать FileNode в БД.

        Драйвер берётся из пула авторизованных соединений (один на аккаунт)
        и переиспользуется для всех частей файла. Переподключение при
        неактуальном соединении выполняет сам драйвер (StorageDriver);
        при неудаче пробуем следующий доступный аккаунт. Если ни один
        не смог — StorageError.
        """
        first = accounts[position % len(accounts)]
        candidates: list[Account] = [first]
        if len(accounts) > 1:
            candidates.extend(
                a for a in accounts if a.id != first.id
            )
        last_error: BaseException | None = None
        for account in candidates:
            try:
                return self._store_chunk_once(
                    chunk, account, position, file_id, pool
                )
            except BaseException as exc:  # noqa: BLE001
                # Сломанный драйвер закрываем и выбрасываем из пула — при
                # следующем get он будет создан заново.
                pool.drop(account.id)
                last_error = exc
                log.warning(
                    "Не удалось сохранить часть position=%s в аккаунт id=%s: %s",
                    position, account.id, exc,
                )
        raise StorageError(
            f"Не удалось сохранить часть {position} ни в один аккаунт"
        ) from last_error

    def _store_chunk_once(
        self,
        chunk: bytes,
        account: Account,
        position: int,
        file_id: int,
        pool,
    ) -> int:
        """Одн�� попытка: зашифровать и сохранить часть в указанный аккаунт."""
        driver, lock = pool.get(account)
        password = crypto.new_password()
        payload = crypto.encrypt_cfb(chunk, password)
        with lock:
            remote_id = driver.store(payload)

        with self.db.session() as session:
            session.add(
                FileNode(
                    file_item_id=file_id,
                    account_id=account.id,
                    remote_id=remote_id,
                    password=password,
                    position=position,
                )
            )
            session.flush()
        return position

    def _cleanup_failed_store(self, file_id: int, user_id: int) -> None:
        """Best-effort очистка при неудачном сохранении: удалить remote-части и FileItem."""
        try:
            nodes = self.db.file_nodes(file_id, user_id)
            for node in nodes:
                try:
                    account = self.db.account(node.account_id, user_id)
                    if account is None:
                        continue
                    driver = self._driver(account).prepare()
                    try:
                        driver.purge(node.remote_id)
                    finally:
                        driver.finish()
                except Exception:  # noqa: BLE001
                    pass
            with self.db.session() as session:
                item = session.get(FileItem, file_id)
                if item is not None:
                    session.delete(item)
        except Exception:  # noqa: BLE001
            log.warning("Не удалось очистить файл id=%s после ошибки", file_id)

    def store_path(self, path: Path, user_id: int) -> int:
        """Сохранить локальный файл потоково (не загружая целиком в память)."""
        if not path.is_file():
            raise StorageError(f"Файл не найден: {path}")
        with path.open("rb") as f:
            return self.store_stream(
                f, name=str(path), user_id=user_id, size=path.stat().st_size
            )

    def store_bytes(self, data: bytes, name: str, user_id: int) -> int:
        """Сохранить байты (удобно для тестов и небольших данных)."""
        return self.store_stream(
            io.BytesIO(data), name=name, user_id=user_id, size=len(data)
        )

    # -- Чтение (потоковое, многопоточное) ---------------------------------

    def fetch_parts_stream(
        self, file_id: int, user_id: int
    ) -> Iterator[bytes]:
        """Потоково отдать части файла по порядку.

        1. Сначала в одной транзакции узнаётся общее количество частей
           (FileItem + FileNode).
        2. Части скачиваются и расшифровываются многопоточно в отдельную
           временную папку: каждая часть пишется в свой пронумерованный
           временный файл (part-NNNNNNNN).
        3. Генератор ждёт, когда появится файл следующего номера, отдаёт
           его содержимое (как в STDOUT) и удаляет файл.
        4. При первой же ошибке любой из задач генератор немедленно
           останавливается и выбрасывает StorageError; временная папка
           удаляется целиком.

        Каждая часть хранится в памяти только в момент отдачи.
        """
        import time

        item, nodes = self.db.get_file_with_nodes(file_id, user_id)
        if item is None:
            raise StorageError(f"Файл не найден: id={file_id}")

        total_chunks = len(nodes)
        if not nodes:
            raise StorageError(f"У файла нет частей: id={file_id}")

        tmp_dir = Path(tempfile.mkdtemp(prefix=f"vfs-parts-{file_id}-"))
        pool = self._new_driver_pool()
        try:
            workers = self._workers(
                min(len(nodes), len({n.account_id for n in nodes}) * 2)
            )
            # Один авторизованный драйвер на аккаунт переиспользуется всеми
            # потоками — не нужно подключаться заново для каждой части.
            with ThreadPoolExecutor(
                max_workers=workers, thread_name_prefix="vfs-fetch"
            ) as executor:
                futures = [
                    executor.submit(
                        self._fetch_chunk_to_file, node, user_id, tmp_dir, pool
                    )
                    for node in nodes
                ]
                pending = set(futures)
                for position in range(total_chunks):
                    part_path = tmp_dir / f"part-{position:08d}"
                    while not part_path.exists():
                        # Немедленная остановка: если любая задача упала —
                        # прерываем генератор с сообщением об ошибке.
                        done = [f for f in pending if f.done()]
                        for fut in done:
                            exc = fut.exception()
                            if exc is not None:
                                raise StorageError(
                                    f"Ошибка при скачивании файла: {exc}"
                                ) from exc
                        if not pending:
                            raise StorageError(
                                f"Часть {position} не была загружена"
                            )
                        time.sleep(0.05)
                    with part_path.open("rb") as pf:
                        yield pf.read()
                    part_path.unlink(missing_ok=True)
                # Дожидаемся оставшихся задач и проверяем их ошибки.
                for fut in as_completed(pending):
                    exc = fut.exception()
                    if exc is not None:
                        raise StorageError(
                            f"Ошибка при скачивании файла: {exc}"
                        ) from exc
        finally:
            pool.close()
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def fetch_to_file(self, file_id: int, target: Path, user_id: int) -> FileItem:
        """Собрать файл из частей в целевой файл потоково.

        Использует fetch_parts_stream: сначала узнаётся общее количество
        частей, части скачиваются многопоточно в пронумерованные временные
        файлы и дописываются в target по порядку. В конце проверяется
        контрольная сумма.
        """
        item = self.db.file_item(file_id, user_id)
        if item is None:
            raise StorageError(f"Файл не найден: id={file_id}")

        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("wb") as out:
            for chunk in self.fetch_parts_stream(file_id, user_id):
                out.write(chunk)

        if self._file_sha256(target) != item.checksum:
            target.unlink(missing_ok=True)
            raise StorageError("Контрольная сумма не совпадает — данные повреждены")
        return item

    def _fetch_chunk_to_file(
        self, node: FileNode, user_id: int, tmp_dir: Path, pool_get
    ) -> int:
        """Скачать и расшифровать одну часть в пронумерованный временный файл.

        Драйвер берётся из пула авторизованных соединений (один на аккаунт)
        и переиспользуется для всех частей файла. Переподключение при
        неактуальном соединении выполняет сам драйвер (StorageDriver).
        Возвращает position части.
        """
        account = self.db.account(node.account_id, user_id)
        if account is None:
            raise StorageError(f"Аккаунт не найден: id={node.account_id}")
        try:
            self._fetch_chunk_once(node, account, tmp_dir, pool_get)
        except BaseException as exc:  # noqa: BLE001
            # Сломанный драйвер закрываем и выбрасываем из пула — при
            # следующем get он будет создан заново.
            pool_get.drop(account.id)
            raise StorageError(
                f"Не удалось скачать часть {node.position}: {exc}"
            ) from exc
        return node.position

    def _fetch_chunk_once(
        self, node: FileNode, account: Account, tmp_dir: Path, pool_get
    ) -> None:
        """Одна попытка: скачать и расшифровать часть в временный файл."""
        driver, lock = pool_get.get(account)
        with lock:
            payload = driver.fetch(node.remote_id)
        data = crypto.decrypt_cfb(payload, node.password)

        part_path = tmp_dir / f"part-{node.position:08d}"
        with part_path.open("wb") as pf:
            pf.write(data)

    def _file_sha256(self, path: Path) -> str:
        """SHA-256 файла потоковым чтением (память не расходуется)."""
        digest = hashlib.sha256()
        with path.open("rb") as f:
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

    def fetch_bytes(self, file_id: int, user_id: int) -> bytes:
        """Собрать файл целиком в bytes (для тестов и небольших данных)."""
        item, nodes = self.db.get_file_with_nodes(file_id, user_id)
        if item is None:
            raise StorageError(f"Файл не найден: id={file_id}")

        if not nodes:
            raise StorageError(f"У файла нет частей: id={file_id}")

        chunks: list[bytes] = [b""] * (max(n.position for n in nodes) + 1)
        pool = self._new_driver_pool()
        try:
            for node in nodes:
                account = self.db.account(node.account_id, user_id)
                if account is None:
                    raise StorageError(f"Аккаунт не найден: id={node.account_id}")
                driver, lock = pool.get(account)
                with lock:
                    payload = driver.fetch(node.remote_id)
                chunks[node.position] = crypto.decrypt_cfb(payload, node.password)
        finally:
            pool.close()

        data = b"".join(chunks)[: item.size]
        if hashlib.sha256(data).hexdigest() != item.checksum:
            raise StorageError("Контрольная сумма не совпадает — данные повреждены")
        return data

    def fetch_path(self, file_id: int, target: Path, user_id: int) -> None:
        """Собрать файл в указанный путь (потоково, многопоточно)."""
        self.fetch_to_file(file_id, target, user_id)

    # -- Удаление ---------------------------------------------------------

    def purge(self, file_id: int, user_id: int) -> None:
        item = self.db.file_item(file_id, user_id)
        if item is None:
            raise StorageError(f"Файл не найден: id={file_id}")

        nodes = self.db.file_nodes(file_id, user_id)
        connections: dict[int, StorageDriver] = {}
        try:
            for node in nodes:
                account = self.db.account(node.account_id, user_id)
                if account is None:
                    continue
                driver = connections.get(account.id)
                if driver is None:
                    driver = self._driver(account).prepare()
                    connections[account.id] = driver
                driver.purge(node.remote_id)
        finally:
            for driver in connections.values():
                try:
                    driver.finish()
                except Exception:  # noqa: BLE001
                    pass

        with self.db.session() as session:
            item = session.get(FileItem, file_id)
            if item is not None and item.user_id == user_id:
                session.delete(item)
        log.info("Удалён файл id=%s user_id=%s", file_id, user_id)

    # -- Перенос частей ---------------------------------------------------

    def migrate_account(self, account_id: int, user_id: int) -> int:
        """Перенести все части файлов из удаляемого аккаунта в другие.

        Для каждой части данные читаются из старого аккаунта, шифруются
        заново (новый случайный пароль) и сохраняются в ближайший доступный
        аккаунт пользователя. Старая часть удаляется после успешной записи.

        Возвращает количество перенесённых частей.
        """
        account = self.db.account(account_id, user_id)
        if account is None:
            raise StorageError(f"Аккаунт не найден: id={account_id}")

        nodes = self.db.account_nodes(account_id, user_id)
        if not nodes:
            return 0

        targets = [
            a for a in self.db.list_accounts_except(user_id, account_id) if a.enabled
        ]
        if not targets:
            raise StorageError(
                "Нет других доступных аккаунтов для переноса частей файлов"
            )

        source_driver = self._driver(account).prepare()
        target_drivers: dict[int, StorageDriver] = {}
        moved = 0
        try:
            for index, node in enumerate(nodes):
                target = targets[index % len(targets)]
                driver = target_drivers.get(target.id)
                if driver is None:
                    driver = self._driver(target).prepare()
                    target_drivers[target.id] = driver

                payload = source_driver.fetch(node.remote_id)
                password = crypto.new_password()
                new_payload = crypto.encrypt_cfb(
                    crypto.decrypt_cfb(payload, node.password), password
                )
                new_remote_id = driver.store(new_payload)
                try:
                    source_driver.purge(node.remote_id)
                except Exception:  # noqa: BLE001
                    # Старую часть не удалось удалить — оставляем запись в БД
                    # указывающей на неё, чтобы не потерять данные.
                    continue

                with self.db.session() as session:
                    db_node = session.get(FileNode, node.id)
                    if db_node is not None:
                        db_node.account_id = target.id
                        db_node.remote_id = new_remote_id
                        db_node.password = password
                moved += 1
        finally:
            source_driver.finish()
            for driver in target_drivers.values():
                try:
                    driver.finish()
                except Exception:  # noqa: BLE001
                    pass

        if moved < len(nodes):
            raise StorageError(
                f"Перенесено только {moved} из {len(nodes)} частей — "
                "аккаунт не удалён, повторите попытку"
            )
        log.info(
            "Перенесено частей: %s из аккаунта id=%s user_id=%s",
            moved, account_id, user_id,
        )
        return moved