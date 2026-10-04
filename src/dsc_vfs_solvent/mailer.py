"""Отправка e-mail писем.

Поддерживается два режима:
* SMTP — реальная отправка через настроенный сервер (settings.smtp_*).
* Лог-режим — если SMTP не настроен, письмо пишется в лог. Это удобно
  для разработки и тестирования: код подтверждения виден в консоли.

Используется для подтверждения e-mail при регистрации и восстановления
пароля (генерация случайного пароля).
"""

from __future__ import annotations

import smtplib
from email.message import EmailMessage

from dsc_vfs_solvent.log import get_logger
from dsc_vfs_solvent.settings import AppSettings

log = get_logger(__name__)


def send_code(settings: AppSettings, to_email: str, code: str, purpose: str) -> None:
    """Отправить одноразовый код на e-mail.

    purpose: "verify_email" (подтверждение регистрации) или
             "reset_password" (восстановление пароля).
    """
    if purpose == "reset_password":
        subject = "dsc-vfs-solvent: восстановление пароля"
        body = (
            f"Здравствуйте!\n\n"
            f"Вы запросили восстановление пароля для dsc-vfs-solvent.\n"
            f"Ваш новый временный пароль: {code}\n\n"
            f"При следующем входе система попросит сменить его.\n"
            f"Если вы не запрашивали восстановление — проигнорируйте письмо."
        )
    else:
        subject = "dsc-vfs-solvent: подтверждение e-mail"
        body = (
            f"Здравствуйте!\n\n"
            f"Добро пожаловать в dsc-vfs-solvent.\n"
            f"Ваш код подтверждения: {code}\n\n"
            f"Введите его в форме регистрации, чтобы завершить создание аккаунта.\n"
            f"Код действителен 30 минут."
        )

    if not settings.smtp_host:
        # Лог-режим: письмо не отправляется, код печатается в лог.
        log.info(
            "Письмо (лог-режим): to=%s subject=%r код=%s",
            to_email,
            subject,
            code,
        )
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = to_email
    msg.set_content(body)

    try:
        if settings.smtp_port == 465:
            server = smtplib.SMTP_SSL(
                settings.smtp_host, settings.smtp_port, timeout=15
            )
        else:
            server = smtplib.SMTP(
                settings.smtp_host, settings.smtp_port, timeout=15
            )
            server.starttls()
        try:
            if settings.smtp_user:
                server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(msg)
        finally:
            server.quit()
        log.info("Письмо отправлено: to=%s", to_email)
    except Exception as exc:  # noqa: BLE001
        log.error("Не удалось отправить письмо на %s: %s", to_email, exc)
        raise