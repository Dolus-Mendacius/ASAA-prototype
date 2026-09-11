"""SMTP email delivery (report delivery + UC-5 email alert channel).

Uses only the Python standard library (smtplib + email.message). Configured via
the ASAA_SMTP_* settings in config.py. For the demo, point it at a Mailtrap
sandbox inbox: the mail is captured there (never delivered to real recipients),
so a real send can be shown on screen safely.

Graceful by design: if SMTP is not configured the caller still gets its result
(the report is generated and downloadable); only the send is skipped.
"""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

from .. import config


def is_configured() -> bool:
    """Enough config present to attempt a send. Auth is optional so a local
    debug SMTP server (no login) also works for testing."""
    return bool(config.SMTP_HOST)


def send_email(to: str, subject: str, body: str,
               attachment_path: str | None = None) -> dict:
    if not is_configured():
        return {"sent": False, "reason": "SMTP not configured"}
    if not to:
        return {"sent": False, "reason": "no recipient"}

    msg = EmailMessage()
    msg["From"] = config.SMTP_FROM
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    if attachment_path and Path(attachment_path).exists():
        data = Path(attachment_path).read_bytes()
        msg.add_attachment(data, maintype="application", subtype="pdf",
                           filename=Path(attachment_path).name)

    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=20) as server:
            if config.SMTP_TLS:
                server.starttls(context=ssl.create_default_context())
            if config.SMTP_USER and config.SMTP_PASS:
                server.login(config.SMTP_USER, config.SMTP_PASS)
            server.send_message(msg)
        return {"sent": True, "to": to,
                "attached": bool(attachment_path and Path(attachment_path).exists())}
    except Exception as exc:  # noqa: BLE001 - report the failure, never crash the request
        return {"sent": False, "reason": str(exc)}
