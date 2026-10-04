"""Централизованное логирование вместо разрозненных print."""

from __future__ import annotations

import logging
import sys

_CONFIGURED = False


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Настроить корневой логгер приложения."""
    global _CONFIGURED
    if not _CONFIGURED:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        root = logging.getLogger()
        root.addHandler(handler)
        root.setLevel(level.upper())
        _CONFIGURED = True
    return logging.getLogger("dsc_vfs_solvent")


def get_logger(name: str = "dsc_vfs_solvent") -> logging.Logger:
    return logging.getLogger(name)