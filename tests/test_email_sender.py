"""
Tests for remediation/notifications/email_sender.py - is_configured()/send_email()
against real environment-variable state (patched per test, never touching the real
process environment), same "test the honest not-configured path explicitly" discipline
as tests/test_dashboard.py's OIDC-adjacent coverage.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.notifications import email_sender  # noqa: E402

_CONFIGURED_ENV = {"SMTP_HOST": "smtp.example.com", "SMTP_PORT": "587", "SMTP_FROM_ADDRESS": "vulnhunter@example.com"}


class IsConfigured(unittest.TestCase):
    def test_false_when_no_env_vars_set(self):
        with patch.dict("os.environ", {}, clear=True):
            for var in email_sender.REQUIRED_ENV_VARS:
                __import__("os").environ.pop(var, None)
            self.assertFalse(email_sender.is_configured())

    def test_true_when_all_required_vars_set(self):
        with patch.dict("os.environ", _CONFIGURED_ENV):
            self.assertTrue(email_sender.is_configured())

    def test_false_when_missing_one_required_var(self):
        env = dict(_CONFIGURED_ENV)
        del env["SMTP_FROM_ADDRESS"]
        with patch.dict("os.environ", env, clear=True):
            self.assertFalse(email_sender.is_configured())

    def test_username_password_are_not_required(self):
        with patch.dict("os.environ", _CONFIGURED_ENV, clear=True):
            self.assertTrue(email_sender.is_configured())


class FromAddress(unittest.TestCase):
    def test_returns_configured_from_address(self):
        with patch.dict("os.environ", _CONFIGURED_ENV):
            self.assertEqual(email_sender.from_address(), "vulnhunter@example.com")


class SendEmail(unittest.TestCase):
    def test_raises_when_not_configured(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(email_sender.EmailNotConfiguredError):
                email_sender.send_email(["a@example.com"], "subject", "body")

    def test_raises_on_empty_recipients(self):
        with patch.dict("os.environ", _CONFIGURED_ENV):
            with self.assertRaises(ValueError):
                email_sender.send_email([], "subject", "body")

    def test_calls_smtplib_with_expected_message(self):
        """Never opens a real socket - smtplib.SMTP itself is mocked, so this verifies
        the message is built and handed off correctly, not real delivery (this repo has
        no real SMTP credentials to test real delivery against - see the module's own
        docstring)."""
        with patch.dict("os.environ", _CONFIGURED_ENV):
            with patch("smtplib.SMTP") as mock_smtp_cls:
                mock_client = mock_smtp_cls.return_value.__enter__.return_value
                email_sender.send_email(["to@example.com"], "Test Subject", "plain body", "<p>html body</p>")
                mock_client.starttls.assert_called_once()
                mock_client.send_message.assert_called_once()
                sent_msg = mock_client.send_message.call_args[0][0]
                self.assertEqual(sent_msg["Subject"], "Test Subject")
                self.assertEqual(sent_msg["From"], "vulnhunter@example.com")
                self.assertEqual(sent_msg["To"], "to@example.com")

    def test_skips_starttls_when_disabled(self):
        env = dict(_CONFIGURED_ENV, SMTP_USE_TLS="0")
        with patch.dict("os.environ", env):
            with patch("smtplib.SMTP") as mock_smtp_cls:
                mock_client = mock_smtp_cls.return_value.__enter__.return_value
                email_sender.send_email(["to@example.com"], "s", "b")
                mock_client.starttls.assert_not_called()

    def test_logs_in_when_username_and_password_set(self):
        env = dict(_CONFIGURED_ENV, SMTP_USERNAME="user", SMTP_PASSWORD="pass")
        with patch.dict("os.environ", env):
            with patch("smtplib.SMTP") as mock_smtp_cls:
                mock_client = mock_smtp_cls.return_value.__enter__.return_value
                email_sender.send_email(["to@example.com"], "s", "b")
                mock_client.login.assert_called_once_with("user", "pass")

    def test_skips_login_when_no_credentials(self):
        with patch.dict("os.environ", _CONFIGURED_ENV, clear=True):
            with patch("smtplib.SMTP") as mock_smtp_cls:
                mock_client = mock_smtp_cls.return_value.__enter__.return_value
                email_sender.send_email(["to@example.com"], "s", "b")
                mock_client.login.assert_not_called()


if __name__ == "__main__":
    unittest.main()
