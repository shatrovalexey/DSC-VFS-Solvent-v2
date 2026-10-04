"""Драйвер FTP-хранилища.

Исправлена работа с бинарными данными: вместо io.StringIO (как в старой
версии) используется io.BytesIO, что корректно для произвольных байтов.
"""

from __future__ import annotations

import ftplib
import io

from dsc_vfs_solvent.storage.base import StorageDriver, StorageError


class FTPDriver(StorageDriver):
    def _connect(self) -> None:
        try:
            self.connection = ftplib.FTP()
            self.connection.connect(
                host=self.account.host,
                port=self.account.port or 21,
                timeout=30,
            )
            self.connection.login(
                user=self.account.login,
                passwd=self.password,
            )
            target = self.account.path or "/"
            try:
                self.connection.mkd(target)
            except ftplib.error_perm:
                pass
            self.connection.cwd(target)
        except (ftplib.all_errors, OSError) as exc:
            raise StorageError(f"FTP: не удалось подключиться: {exc}") from exc

    def _is_connected(self) -> bool:
        """Проверить управляющее соединение командой NOOP."""
        try:
            self.connection.voidcmd("NOOP")
            return True
        except (ftplib.all_errors, OSError):
            return False

    def _store(self, message: bytes) -> str:
        try:
            fh = io.BytesIO(message)
            # STOU — сохранить с уникальным именем; сервер возвращает имя файла.
            response = self.connection.storbinary("STOU", fh, blocksize=self.chunk_size)
            fh.close()
            # Пример ответа: '150 FILE: имя\n226 Transfer complete.'
            return response.split()[-1]
        except (ftplib.all_errors, OSError) as exc:
            raise StorageError(f"FTP: ошибка сохранения: {exc}") from exc

    def _fetch(self, remote_id: str) -> bytes:
        try:
            fh = io.BytesIO()
            self.connection.retrbinary(
                f"RETR {remote_id}", fh.write, blocksize=self.chunk_size
            )
            return fh.getvalue()
        except (ftplib.all_errors, OSError) as exc:
            raise StorageError(f"FTP: ошибка чтения: {exc}") from exc

    def _purge(self, remote_id: str) -> bool:
        try:
            self.connection.delete(remote_id)
            return True
        except (ftplib.all_errors, OSError) as exc:
            raise StorageError(f"FTP: ошибка удаления: {exc}") from exc

    def finish(self) -> None:
        try:
            self.connection.quit()
        except (ftplib.all_errors, OSError):
            pass