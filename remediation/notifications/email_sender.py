"""
A real SMTP email sender, built entirely on Python's stdlib `smtplib` +
`email.message` - no new pip dependency (matching this repo's existing
"zero new dependency" pattern used everywhere else in the dashboard). Used by the
Notification Settings page's scheduled reports and critical/zero-day/threat-intel team
alerts (see report_scheduler.py and alert_checker.py in this same package).

Deliberately inert unless configured: is_configured() is False (and every send attempt
raises EmailNotConfiguredError, same shape as cli.ClaudeBinaryNotFound elsewhere in this
app) unless SMTP_HOST, SMTP_PORT, and SMTP_FROM_ADDRESS are all set as real environment
variables - this code cannot provision a real mail relay on anyone's behalf, so it stays
dormant until a real operator supplies real SMTP settings. SMTP_USERNAME/SMTP_PASSWORD
are optional (some internal relays allow anonymous relay from a trusted network) and
SMTP_USE_TLS defaults to true (STARTTLS) - set it to "0"/"false" only for a relay that
genuinely doesn't support it.

Like every other connector in this repo, this was built against the standard SMTP
protocol and Python's own stdlib documentation, and has NOT been exercised against a
real mail server - no real SMTP credentials were available while building it. Before
relying on this for real delivery, configure a real relay (an internal relay, or a
provider's SMTP endpoint such as SendGrid/SES/Postmark) and send a real test message via
the Notification Settings page's "Send test email" button first.
"""
import os
import smtplib
from email.message import EmailMessage

from remediation.utils.retry import retry_with_backoff

REQUIRED_ENV_VARS = ("SMTP_HOST", "SMTP_PORT", "SMTP_FROM_ADDRESS")

# Self-healing scope, deliberately narrow: retry a dropped/refused/timed-out connection
# (the genuinely transient failure modes for a real SMTP relay) up to 3 times with
# exponential backoff. Does NOT retry SMTPAuthenticationError, SMTPRecipientsRefused, or
# SMTPSenderRefused - those are OSError subclasses too (smtplib's whole exception
# hierarchy inherits from OSError), but retrying wrong credentials or a rejected
# recipient 3 times wastes 7 seconds arriving at the same permanent failure, so they're
# deliberately excluded rather than caught by a broad OSError net.
_RETRYABLE_EXCEPTIONS = (
    smtplib.SMTPConnectError,
    smtplib.SMTPServerDisconnected,
    ConnectionRefusedError,
    ConnectionResetError,
    TimeoutError,
)


class EmailNotConfiguredError(RuntimeError):
    pass


def is_configured():
    return all(os.environ.get(var) for var in REQUIRED_ENV_VARS)


def from_address():
    return os.environ.get("SMTP_FROM_ADDRESS", "")


def _use_tls():
    return os.environ.get("SMTP_USE_TLS", "1").strip().lower() not in ("0", "false", "no")


def send_email(to_addrs, subject, body_text, body_html=None):
    """Sends one real email via the configured SMTP relay. `to_addrs` is a list of
    recipient addresses (at least one required). Raises EmailNotConfiguredError if SMTP
    isn't configured, or smtplib's own exceptions (e.g. SMTPAuthenticationError,
    SMTPConnectError) on a real delivery failure - callers should catch and surface
    those, not swallow them (same convention as every other real connector in this
    repo)."""
    if not is_configured():
        raise EmailNotConfiguredError(
            "SMTP is not configured on this server - set SMTP_HOST, SMTP_PORT, and "
            "SMTP_FROM_ADDRESS (and optionally SMTP_USERNAME/SMTP_PASSWORD/SMTP_USE_TLS) "
            "as environment variables first.",
        )
    if not to_addrs:
        raise ValueError("to_addrs must contain at least one recipient")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_address()
    msg["To"] = ", ".join(to_addrs)
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    host = os.environ["SMTP_HOST"]
    port = int(os.environ["SMTP_PORT"])
    username = os.environ.get("SMTP_USERNAME")
    password = os.environ.get("SMTP_PASSWORD")

    def _do_send():
        with smtplib.SMTP(host, port, timeout=15) as client:
            if _use_tls():
                client.starttls()
            if username and password:
                client.login(username, password)
            client.send_message(msg)

    retry_with_backoff(_do_send, retryable_exceptions=_RETRYABLE_EXCEPTIONS)
