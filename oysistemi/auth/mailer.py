"""E-posta gönderimi. SMTP yapılandırılmamışsa e-postalar outbox klasörüne yazılır."""
from __future__ import annotations

import secrets
import smtplib
import ssl
from email.message import EmailMessage

from ..config import Settings


def send(settings: Settings, to: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = settings.smtp_from, to, subject
    msg.set_content(body)
    if settings.smtp_host:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as s:
            s.starttls(context=ssl.create_default_context())
            if settings.smtp_user:
                s.login(settings.smtp_user, settings.smtp_password)
            s.send_message(msg)
        return
    if settings.outbox_dir is None:
        raise RuntimeError("no SMTP server and no outbox directory configured")
    settings.outbox_dir.mkdir(parents=True, exist_ok=True)
    (settings.outbox_dir / f"{secrets.token_hex(6)}.eml").write_bytes(bytes(msg))
