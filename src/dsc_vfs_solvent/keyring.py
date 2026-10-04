"""Приём и временное хранение ключей пользователей на сервере.

Ключ пользователя (user_key) используется для расшифровки паролей
FTP/FTPS/SFTP/IMAP-аккаунтов. Ключ передаётся клиентом в заголовке
`X-VFS-Key` в виде RSA-OAEP-шифротекста открытым ключом сервера.

Сервер:
* расшифровывает ключ закрытым RSA-ключом;
* НЕ сохраняет его в БД — держит только в памяти (кэш, TTL 15 минут);
* использует для операций с аккаунтами в рамках текущего пользователя.
"""

from __future__ import annotations

import time

from dsc_vfs_solvent import crypto
from dsc_vfs_solvent.log import get_logger

log = get_logger(__name__)

KEY_TTL_SECONDS = 15 * 60


class UserKeyError(RuntimeError):
    """Ошибка приёма/использования ключа пользователя."""


class UserKeyStore:
    """Кэш ключей пользователей в памяти сервера."""

    def __init__(self, private_key_pem: str, public_key_pem: str) -> None:
        self._private_key_pem = private_key_pem
        self._public_key_pem = public_key_pem
        self._keys: dict[int, tuple[str, float]] = {}

    @property
    def public_key_pem(self) -> str:
        return self._public_key_pem

    def receive(self, user_id: int, wrapped_b64: str) -> None:
        """Принять зашифрованный ключ, расшифровать и закэшировать."""
        user_key = self.decrypt(wrapped_b64)
        if not user_key:
            raise UserKeyError("Пустой ключ пользователя")
        self._keys[user_id] = (user_key, time.monotonic() + KEY_TTL_SECONDS)
        log.info("Ключ пользователя id=%s принят (TTL %s c)", user_id, KEY_TTL_SECONDS)

    def decrypt(self, wrapped_b64: str) -> str:
        """Расшифровать переданный ключ закрытым ключом сервера."""
        try:
            raw = crypto.rsa_decrypt(wrapped_b64, self._private_key_pem)
            return raw.decode("utf-8")
        except Exception as exc:  # noqa: BLE001
            raise UserKeyError("Не удалось расшифровать ключ пользователя") from exc

    def get(self, user_id: int) -> str | None:
        """Вернуть актуальный ключ пользователя или None."""
        entry = self._keys.get(user_id)
        if entry is None:
            return None
        user_key, expires_at = entry
        if time.monotonic() > expires_at:
            self._keys.pop(user_id, None)
            return None
        return user_key

    def drop(self, user_id: int) -> None:
        """Забыть ключ пользователя (например, при выходе)."""
        self._keys.pop(user_id, None)

    def clear(self) -> None:
        self._keys.clear()