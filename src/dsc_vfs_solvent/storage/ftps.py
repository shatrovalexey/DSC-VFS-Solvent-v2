"""Драйвер FTPS-хранилища (explicit TLS поверх FTP).

Использует ftplib.FTP_TLS из стандартной библиотеки: управляющий канал
защищается AUTH TLS, канал данных — PROT P (PBSZ 0).
"""

from __future__ import annotations

import ftplib
import io

from dsc_vfs_solvent.storage.base import StorageDriver, StorageError


class FTPSDriver(StorageDriver):
    def _connect(self) -> None:
        try:
            self.connection = ftplib.FTP_TLS()
            self.connection.connect(
                host=self.account.host,
                port=self.account.port or 21,
                timeout=30,
            )
            self.connection.login(user=self.account.login, passwd=self.password)
            # Защита канала данных: PBSZ 0 + PROT P (выполняется внутри prot_p).
            self.connection.prot_p()
            target = self.account.path or "/"
            try:
                self.connection.mkd(target)
            except ftplib.error_perm:
                pass
            self.connection.cwd(target)
        except (ftplib.all_errors, OSError) as exc:
            raise StorageError(f"FTPS: не удалось подключиться: {exc}") from exc

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
            return response.split()[-1]
        except (ftplib.all_errors, OSError) as exc:
            raise StorageError(f"FTPS: ошибка сохранения: {exc}") from exc

    def _fetch(self, remote_id: str) -> bytes:
        try:
            fh = io.BytesIO()
            self.connection.retrbinary(
                f"RETR {remote_id}", fh.write, blocksize=self.chunk_size
            )
            return fh.getvalue()
        except (ftplib.all_errors, OSError) as exc:
            raise StorageError(f"FTPS: ошибка чтения: {exc}") from exc

    def _purge(self, remote_id: str) -> bool:
        try:
            self.connection.delete(remote_id)
            return True
        except (ftplib.all_errors, OSError) as exc:
            raise StorageError(f"FTPS: ошибка удаления: {exc}") from exc

    def finish(self) -> None:
        try:
            self.connection.quit()
        except (ftplib.all_errors, OSError):
            pass