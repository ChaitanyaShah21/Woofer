"""Email dispatching service supporting Brevo HTTP API and SMTP fallback."""
import json
import os
import smtplib
import threading
import urllib.error
import urllib.request
from email.mime.text import MIMEText

from flask import current_app, url_for
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer


def get_serializer(secret_key: str | None = None) -> URLSafeTimedSerializer:
    """Return timed serializer for token signing."""
    key = secret_key or current_app.secret_key or "default-serializer-key"
    return URLSafeTimedSerializer(key)


# Global in-memory outbox for automated testing
outbox: list[dict] = []


def send_async_email(msg: Message, app=None) -> None:
    """Send an email asynchronously using Brevo HTTP API or SMTP."""
    target_app = app or current_app._get_current_object()

    # In testing mode, capture email in outbox without opening network sockets
    if target_app.config.get("TESTING"):
        outbox.append({
            "subject": msg.subject,
            "recipients": msg.recipients,
            "body": msg.body,
        })
        return

    def _send(app_ctx, message):
        with app_ctx:
            sender = (
                target_app.config.get("MAIL_DEFAULT_SENDER")
                or os.getenv("MAIL_USERNAME")
                or "noreply@woofer.local"
            )
            brevo_api_key = target_app.config.get("BREVO_API_KEY")

            # 1. Use Brevo HTTP API (Port 443) - works on Render without SMTP blocks
            if brevo_api_key:
                try:
                    target_app.logger.info("Sending email via Brevo API to %s", message.recipients)
                    url = "https://api.brevo.com/v3/smtp/email"
                    headers = {
                        "accept": "application/json",
                        "api-key": brevo_api_key,
                        "content-type": "application/json",
                    }
                    data = {
                        "sender": {"name": "Woofer", "email": sender},
                        "to": [{"email": r} for r in message.recipients],
                        "subject": message.subject,
                        "textContent": message.body,
                    }
                    req = urllib.request.Request(
                        url,
                        data=json.dumps(data).encode("utf-8"),
                        headers=headers,
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        target_app.logger.info(
                            "Sent email to %s via Brevo API (status %s)",
                            message.recipients,
                            resp.status
                        )
                        return
                except urllib.error.HTTPError as e:
                    err_msg = e.read().decode("utf-8", errors="ignore")
                    target_app.logger.warning("Brevo API HTTPError %s: %s", e.code, err_msg)
                except Exception as e:  # noqa: BLE001
                    target_app.logger.warning("Brevo API failed (%s): %s", type(e).__name__, e)

            # 2. Fallback to SMTP
            server = target_app.config.get("MAIL_SERVER")
            username = target_app.config.get("MAIL_USERNAME")
            password = target_app.config.get("MAIL_PASSWORD")

            if not server or not username or not password:
                target_app.logger.warning("No SMTP fallback configured for %s", message.recipients)
                return

            mime = MIMEText(message.body)
            mime["Subject"] = message.subject
            mime["From"] = sender
            mime["To"] = ", ".join(message.recipients)

            for attempt, (port, use_ssl) in enumerate([(465, True), (587, False)], 1):
                try:
                    target_app.logger.info(
                        "Connecting to %s:%s (SSL=%s) for %s (attempt %s)",
                        server, port, use_ssl, message.recipients, attempt
                    )
                    if use_ssl:
                        smtp = smtplib.SMTP_SSL(server, port, timeout=30)
                    else:
                        smtp = smtplib.SMTP(server, port, timeout=30)
                        smtp.ehlo()
                        smtp.starttls()
                        smtp.ehlo()
                    smtp.login(username, password)
                    smtp.sendmail(sender, message.recipients, mime.as_string())
                    smtp.quit()
                    target_app.logger.info("Sent email to %s via port %s", message.recipients, port)
                    return
                except Exception as e:  # noqa: BLE001
                    target_app.logger.warning(
                        "Attempt %s failed (port %s): %s: %s",
                        attempt, port, type(e).__name__, e
                    )

            target_app.logger.error("All email delivery methods failed for %s", message.recipients)

    thread = threading.Thread(
        target=_send,
        args=(target_app.app_context(), msg),
        daemon=True
    )
    thread.start()


def send_verification_email(user) -> None:
    """Generate email verification link and dispatch email."""
    serializer = get_serializer()
    token = serializer.dumps(user.email, salt="email-confirm")
    link = url_for("auth.confirm_email", token=token, _external=True)
    msg = Message("Verify your Woofer Account", recipients=[user.email])
    msg.body = f"""Hi {user.firstName},

Click to verify your email:
{link}

This link expires in 1 hour."""
    send_async_email(msg)


def send_password_reset_email(user) -> None:
    """Generate password reset link bound to current hash state and dispatch email."""
    serializer = get_serializer()
    # Bind token to email and hash prefix to invalidate old tokens when password changes
    payload = {"email": user.email, "hash_prefix": user.hash[:16]}
    token = serializer.dumps(payload, salt="reset-password")
    link = url_for("auth.reset_password", token=token, _external=True)
    msg = Message("Woofer Password Reset", recipients=[user.email])
    msg.body = f"""Hi {user.firstName},

Click to reset your password:
{link}

This link will expire in 1 hour."""
    send_async_email(msg)
