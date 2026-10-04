"""Криптографические примитивы.

Замена устаревшего pycrypto на современный pycryptodome:

* AES-256-CFB для шифрования частей файлов (обратная совместимость с v1.x).
* AES-256-GCM для шифрования конфигурации и паролей (аутентифицированное
  шифрование, защита от подмены данных).

ВНИМАНИЕ: пароль пользователя не хранится в открытом виде. Вместо этого
хранится только случайная соль и проверочная метка (HMAC), позволяющая
проверить правильность пароля без его восстановления.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

AES_KEY_SIZE = 32  # AES-256
BLOCK_SIZE = AES.block_size  # 16 байт
SALT_SIZE = 16
ITERATIONS = 200_000


def derive_key(password: str, salt: bytes) -> bytes:
    """Получить ключ AES-256 из пароля через PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        ITERATIONS,
        dklen=AES_KEY_SIZE,
    )


def encrypt_cfb(data: bytes, password: str) -> bytes:
    """Шифрование части файла: IV + AES-256-CFB."""
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    iv = secrets.token_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return salt + iv + cipher.encrypt(data)


def decrypt_cfb(payload: bytes, password: str) -> bytes:
    """Расшифрование части файла."""
    salt = payload[:SALT_SIZE]
    iv = payload[SALT_SIZE : SALT_SIZE + BLOCK_SIZE]
    ciphertext = payload[SALT_SIZE + BLOCK_SIZE :]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.decrypt(ciphertext)


def encrypt_gcm(data: bytes, password: str) -> bytes:
    """Аутентифицированное шифрование (AES-256-GCM): salt|nonce|tag|ciphertext."""
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return salt + nonce + tag + ciphertext


def decrypt_gcm(payload: bytes, password: str) -> bytes:
    """Расшифрование AES-256-GCM с проверкой подлинности."""
    salt = payload[:SALT_SIZE]
    nonce = payload[SALT_SIZE : SALT_SIZE + 12]
    tag = payload[SALT_SIZE + 12 : SALT_SIZE + 12 + 16]
    ciphertext = payload[SALT_SIZE + 12 + 16 :]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def new_password(length: int = 32) -> str:
    """Сгенерировать случайный пароль для части файла (hex)."""
    return secrets.token_hex(length // 2)


def hash_password(password: str) -> str:
    """Проверочная метка пароля: salt$hex_hmac."""
    salt = secrets.token_bytes(SALT_SIZE)
    digest = hmac.new(salt, password.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{salt.hex()}${digest}"


def verify_password(password: str, stored: str) -> bool:
    """Проверить пароль по сохранённой метке."""
    try:
        salt_hex, digest = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
    except (ValueError, AttributeError):
        return False
    expected = hmac.new(salt, password.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, digest)


# -- Ключи пользователей ---------------------------------------------------

def generate_user_key() -> str:
    """Сгенерировать ключ пользователя (256 бит, hex-строка)."""
    return secrets.token_hex(32)


def wrap_user_key(user_key: str, password: str) -> str:
    """Обернуть ключ пользователя ключом, производным от пароля (KEK).

    На сервере хранится только результат этой функции — сам ключ
    пользователя серверу в открытом виде не передаётся.
    """
    payload = encrypt_gcm(user_key.encode("utf-8"), password)
    return base64.b64encode(payload).decode("ascii")


def unwrap_user_key(wrapped: str, password: str) -> str:
    """Развернуть ключ пользователя паролем (клиентская сторона)."""
    payload = base64.b64decode(wrapped.encode("ascii"))
    return decrypt_gcm(payload, password).decode("utf-8")


# -- Пароли аккаунтов хранилищ ----------------------------------------------

def encrypt_account_password(password: str, user_key: str) -> str:
    """Зашифровать пароль FTP/FTPS/SFTP/IMAP ключом пользователя."""
    payload = encrypt_gcm(password.encode("utf-8"), user_key)
    return base64.b64encode(payload).decode("ascii")


def decrypt_account_password(cipher_b64: str, user_key: str) -> str:
    """Расшифровать пароль аккаунта ключом пользователя."""
    payload = base64.b64decode(cipher_b64.encode("ascii"))
    return decrypt_gcm(payload, user_key).decode("utf-8")


# -- RSA-ключи сервера (транспорт ключей пользователя) -----------------------

def generate_rsa_keypair() -> tuple[str, str]:
    """Сгенерировать пару RSA-ключей сервера: (private_pem, public_pem)."""
    key = RSA.generate(2048)
    private_pem = key.export_key().decode("ascii")
    public_pem = key.publickey().export_key().decode("ascii")
    return private_pem, public_pem


def rsa_encrypt(data: bytes, public_key_pem: str) -> str:
    """Зашифровать данные открытым ключом сервера (RSA-OAEP, base64)."""
    key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(key)
    return base64.b64encode(cipher.encrypt(data)).decode("ascii")


def rsa_decrypt(ciphertext_b64: str, private_key_pem: str) -> bytes:
    """Расшифровать данные закрытым ключом сервера (RSA-OAEP)."""
    key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(base64.b64decode(ciphertext_b64.encode("ascii")))