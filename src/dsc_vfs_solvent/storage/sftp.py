"""Драйвер SFTP-хранилища (SSH File Transfer Protocol).

Реализован на paramiko.SFTPClient. Порт по умолчанию — 22.
Части файлов хранятся как отдельные файлы в рабочей директории
(account.path или "/").
"""

from __future__ import annotations

import paramiko

from dsc_vfs_solvent.storage.base import StorageDriver, StorageError


class SFTPDriver(StorageDriver):
    def _connect(self) -> None:
        try:
            self._transport = paramiko.Transport((self.account.host, self.account.port or 22))
            self._transport.connect(username=self.account.login, password=self.password)
            self.connection = paramiko.SFTPClient.from_transport(self._transport)
            target = self.account.path or "/"
            try:
                self.connection.mkdir(target)
            except OSError:
                pass
            try:
                self.connection.chdir(target)
            except OSError as exc:
                raise StorageError(f"SFTP: не удалось перейти в каталог {target!r}: {exc}") from exc
        except (paramiko.SSHException, OSError) as exc:
            raise StorageError(f"SFTP: не удалось подключиться: {exc}") from exc

    def _is_connected(self) -> bool:
        transport = getattr(self, "_transport", None)
        if transport is None or not transport.is_active():
            return False
        try:
            # Любая команда проверит живое ли соединение.
            self.connection.stat(".")
            return True
        except (paramiko.SSHException, OSError):
            return False

    def _do_store(self, message: bytes) -> str:
        try:
            remote_id = self._new_remote_id()
            with self.connection.open(remote_id, "wb") as fh:
                fh.write(message)
            return remote_id
        except (paramiko.SSHException, OSError) as exc:
            raise StorageError(f"SFTP: ошибка сохранения: {exc}") from exc

    def _do_fetch(self, remote_id: str) -> bytes:
        try:
            with self.connection.open(remote_id, "rb") as fh:
                return fh.read()
        except (paramiko.SSHException, OSError) as exc:
            raise StorageError(f"SFTP: ошибка чтения: {exc}") from exc

    def _do_purge(self, remote_id: str) -> bool:
        try:
            self.connection.remove(remote_id)
            return True
        except (paramiko.SSHException, OSError) as exc:
            raise StorageError(f"SFTP: ошибка удаления: {exc}") from exc

    def finish(self) -> None:
        try:
            self.connection.close()
        except (paramiko.SSHException, OSError):
            pass
        try:
            self._transport.close()
        except (paramiko.SSHException, OSError):
            pass

    def _new_remote_id(self) -> str:
        """Сгенерировать уникальное имя файла на сервере."""
        import secrets

        while True:
            candidate = f"dsc_{secrets.token_hex(16)}.blob"
            try:
                self.connection.stat(candidate)
            except OSError:
                return candidate