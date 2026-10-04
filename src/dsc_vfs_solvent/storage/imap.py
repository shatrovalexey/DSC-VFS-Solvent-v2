"""Драйвер IMAP4-хранилища.

Убрана зависимость от Tkinter (tkinter.messagebox), которая была в старом
коде; ошибки теперь пробрасываются через StorageError.
"""

from __future__ import annotations

import binascii
import email
import imaplib

from dsc_vfs_solvent.storage.base import StorageDriver, StorageError


class IMAPDriver(StorageDriver):
    def _connect(self) -> None:
        try:
            self.connection = imaplib.IMAP4_SSL(
                host=self.account.host,
                port=self.account.port or 993,
            )
            self.connection.login(self.account.login, self.password)
            mailbox = self.account.path or "INBOX"
            try:
                self.connection.create(mailbox)
            except imaplib.IMAP4.error:
                pass
            self.connection.select(mailbox)
        except (imaplib.IMAP4.error, OSError) as exc:
            raise StorageError(f"IMAP: не удалось подключиться: {exc}") from exc

    def _is_connected(self) -> bool:
        """Проверить соединение командой NOOP."""
        try:
            status, _ = self.connection.noop()
            return status == "OK"
        except (imaplib.IMAP4.error, OSError):
            return False

    def _store(self, message: bytes) -> str:
        try:
            hex_data = binascii.b2a_hex(message).decode("ascii")
            msg = email.message.Message()
            msg.set_payload(hex_data)
            payload = msg.as_string().encode("utf-8")
            status, data = self.connection.append(
                mailbox=self.account.path or "INBOX",
                message=payload,
                flags=None,
                date_time=None,
            )
            if status != "OK":
                raise StorageError(f"IMAP: append вернул {status!r}")
            response = data[0].split()
            uid = response[2].rstrip(b")").decode("ascii")
            return uid
        except (imaplib.IMAP4.error, OSError) as exc:
            raise StorageError(f"IMAP: ошибка сохранения: {exc}") from exc

    def _fetch(self, remote_id: str) -> bytes:
        try:
            status, data = self.connection.uid("FETCH", remote_id, "(RFC822)")
            if status != "OK":
                raise StorageError(f"IMAP: FETCH вернул {status!r}")
            msg = email.message_from_bytes(data[0][1])
            hex_data = msg.get_payload().rstrip()
            return binascii.a2b_hex(hex_data)
        except (imaplib.IMAP4.error, OSError) as exc:
            raise StorageError(f"IMAP: ошибка чтения: {exc}") from exc

    def _purge(self, remote_id: str) -> bool:
        try:
            self.connection.uid("STORE", remote_id, "+FLAGS", r"(\Deleted)")
            status, _ = self.connection.expunge()
            if status != "OK":
                raise StorageError(f"IMAP: expunge вернул {status!r}")
            return True
        except (imaplib.IMAP4.error, OSError) as exc:
            raise StorageError(f"IMAP: ошибка удаления: {exc}") from exc

    def finish(self) -> None:
        try:
            self.connection.logout()
        except (imaplib.IMAP4.error, OSError):
            pass