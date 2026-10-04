"""Конфигурация приложения.

Настройки загружаются из файла settings (JSON), переменных окружения.
RSA-пара сервера генерируется автоматически при первом запуске и
используется для передачи ключей пользователей (RSA-OAEP).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import quote_plus

from pydantic import BaseModel, Field

from dsc_vfs_solvent import crypto


class AppSettings(BaseModel):
    """Основные настройки приложения."""

    # Подключение к PostgreSQL (DSN собирается из этих полей).
    db_host: str = "127.0.0.1"
    db_port: int = 5432
    db_user: str = "postgres"
    db_password: str = ""
    db_name: str = "dsc_vfs_solvent"
    data_dir: Path = Path("data")
    chunk_size: int = Field(default=1024 * 1024, ge=64 * 1024)
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    # SMTP для отправки писем (код подтверждения e-mail, восстановление пароля).
    # Если smtp_host пустой — письма пишутся в лог (режим разработки).
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "noreply@ashatrov.ru"
    # RSA-пара сервера для передачи ключей пользователей (генерируется сама).
    rsa_private_pem: str = ""
    rsa_public_pem: str = ""
    log_level: str = "INFO"
    config_file: Path = Path("config/settings.json")

    def database_url(self) -> str:
        """Собрать SQLAlchemy DSN для PostgreSQL из отдельных полей."""
        return (
            f"postgresql+psycopg://{quote_plus(self.db_user)}:"
            f"{quote_plus(self.db_password)}@{self.db_host}:{self.db_port}/{self.db_name}"
        )

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def ensure_rsa_keys(self) -> None:
        """Сгенерировать RSA-пару сервера, если её ещё нет."""
        if self.rsa_private_pem and self.rsa_public_pem:
            return
        private_pem, public_pem = crypto.generate_rsa_keypair()
        self.rsa_private_pem = private_pem
        self.rsa_public_pem = public_pem
        self.save()

    @classmethod
    def load(cls, path: Path | None = None) -> "AppSettings":
        """Загрузить настройки.

        Приоритет: файл конфигурации (config/settings.json или DSC_VFS_CONFIG),
        затем переменные окружения (DB_*, API_*, SMTP_*, LOG_LEVEL), затем
        значения по умолчанию. Переменные окружения удобны для запуска
        в Docker.
        """
        config_file = path or cls._env_path()
        raw: dict = {}
        if config_file.exists():
            raw = json.loads(config_file.read_text(encoding="utf-8"))
            raw = {k: v for k, v in raw.items() if v is not None}
        return cls.model_validate({**raw, **cls._env_values()})

    @staticmethod
    def _env_values() -> dict:
        """Значения настроек из переменных окружения (только заданные)."""
        env_map = {
            "DB_HOST": "db_host",
            "DB_PORT": "db_port",
            "DB_USER": "db_user",
            "DB_PASSWORD": "db_password",
            "DB_NAME": "db_name",
            "API_HOST": "api_host",
            "API_PORT": "api_port",
            "SMTP_HOST": "smtp_host",
            "SMTP_PORT": "smtp_port",
            "SMTP_USER": "smtp_user",
            "SMTP_PASSWORD": "smtp_password",
            "SMTP_FROM": "smtp_from",
            "LOG_LEVEL": "log_level",
        }
        result: dict = {}
        for env_name, field in env_map.items():
            value = os.environ.get(env_name)
            if value is not None and value != "":
                result[field] = value
        return result

    @staticmethod
    def _env_path() -> Path:
        return Path(os.environ.get("DSC_VFS_CONFIG", "config/settings.json"))

    def save(self, path: Path | None = None) -> Path:
        target = path or self.config_file
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            self.model_dump_json(indent=2, exclude_none=True),
            encoding="utf-8",
        )
        return target