import logging
import smtplib
from email.message import EmailMessage

from app.core.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    @staticmethod
    def build_verification_email(verification_link: str) -> tuple[str, str, str]:
        subject = f"Confirm your account in {settings.PROJECT_NAME}"
        text_body = (
            "Please confirm your email address to activate your account.\n\n"
            f"Verification link: {verification_link}\n\n"
            "If you did not create this account, you can ignore this email."
        )
        html_body = (
            "<p>Please confirm your email address to activate your account.</p>"
            f"<p><a href=\"{verification_link}\">Confirm account</a></p>"
            "<p>If you did not create this account, you can ignore this email.</p>"
        )
        return subject, text_body, html_body

    @staticmethod
    def build_password_reset_email(new_password: str) -> tuple[str, str, str]:
        subject = f"Your {settings.PROJECT_NAME} password was reset"
        text_body = (
            "Your password has been reset. Use the temporary password below and change it after login.\n\n"
            f"Temporary password: {new_password}\n\n"
            "If you did not request this, contact support immediately."
        )
        html_body = (
            "<p>Your password has been reset. Use the temporary password below and change it after login.</p>"
            f"<p><strong>Temporary password:</strong> {new_password}</p>"
            "<p>If you did not request this, contact support immediately.</p>"
        )
        return subject, text_body, html_body

    @staticmethod
    def send_email(to_email: str, subject: str, text_body: str, html_body: str | None = None) -> None:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
        message["To"] = to_email
        message.set_content(text_body)

        if html_body:
            message.add_alternative(html_body, subtype="html")

        if settings.SMTP_USE_SSL:
            smtp_client = smtplib.SMTP_SSL(
                settings.SMTP_HOST,
                settings.SMTP_PORT,
                timeout=settings.SMTP_TIMEOUT_SECONDS,
            )
        else:
            smtp_client = smtplib.SMTP(
                settings.SMTP_HOST,
                settings.SMTP_PORT,
                timeout=settings.SMTP_TIMEOUT_SECONDS,
            )

        try:
            with smtp_client as server:
                if settings.SMTP_USE_TLS and not settings.SMTP_USE_SSL:
                    server.starttls()

                if settings.SMTP_USER and settings.SMTP_PASSWORD:
                    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)

                server.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            logger.warning("Failed to send email: %s", exc)
