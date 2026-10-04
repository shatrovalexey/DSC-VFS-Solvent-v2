#!/usr/bin/env python3
"""Запуск REST API сервера dsc-vfs-solvent.

    python run.py

Скрипт запускает FastAPI-приложение (http://127.0.0.1:8000).
Веб-интерфейс должен быть собран заранее (npm run build); если dist
отсутствует, страница / будет недоступна, но API продолжит работать.
"""

from __future__ import annotations

import sys

import uvicorn

from dsc_vfs_solvent.api.main import app
from dsc_vfs_solvent.settings import AppSettings


def main() -> int:
    settings = AppSettings.load()
    print(f"\nЗапуск сервера: http://{settings.api_host}:{settings.api_port}  (Ctrl+C для остановки)\n")
    uvicorn.run(app, host=settings.api_host, port=settings.api_port)
    return 0


if __name__ == "__main__":
    sys.exit(main())