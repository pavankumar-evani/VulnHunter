"""
Tests for remediation/utils/retry.py - the self-healing retry-with-backoff helper used
by kev_epss.py's KEV/EPSS fetches and email_sender.py's SMTP send.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.utils.retry import retry_with_backoff  # noqa: E402


class ConnectionLikeError(Exception):
    pass


class AuthLikeError(Exception):
    pass


class RetryWithBackoff(unittest.TestCase):
    def test_succeeds_on_first_try_without_any_sleep(self):
        with patch("remediation.utils.retry.time.sleep") as mock_sleep:
            result = retry_with_backoff(lambda: "ok")
        self.assertEqual(result, "ok")
        mock_sleep.assert_not_called()

    def test_retries_a_retryable_exception_then_succeeds(self):
        attempts = {"count": 0}

        def flaky():
            attempts["count"] += 1
            if attempts["count"] < 3:
                raise ConnectionLikeError("transient")
            return "recovered"

        with patch("remediation.utils.retry.time.sleep") as mock_sleep:
            result = retry_with_backoff(flaky, max_attempts=5, retryable_exceptions=(ConnectionLikeError,))
        self.assertEqual(result, "recovered")
        self.assertEqual(attempts["count"], 3)
        self.assertEqual(mock_sleep.call_count, 2)

    def test_uses_exponential_backoff_delays(self):
        def always_fails():
            raise ConnectionLikeError("still down")

        with patch("remediation.utils.retry.time.sleep") as mock_sleep:
            with self.assertRaises(ConnectionLikeError):
                retry_with_backoff(always_fails, max_attempts=3, base_delay_seconds=1.0,
                                   retryable_exceptions=(ConnectionLikeError,))
        self.assertEqual([call.args[0] for call in mock_sleep.call_args_list], [1.0, 2.0])

    def test_reraises_after_exhausting_max_attempts(self):
        calls = {"count": 0}

        def always_fails():
            calls["count"] += 1
            raise ConnectionLikeError("still down")

        with patch("remediation.utils.retry.time.sleep"):
            with self.assertRaises(ConnectionLikeError):
                retry_with_backoff(always_fails, max_attempts=3, retryable_exceptions=(ConnectionLikeError,))
        self.assertEqual(calls["count"], 3)

    def test_non_retryable_exception_propagates_immediately_with_no_retry(self):
        calls = {"count": 0}

        def bad_credentials():
            calls["count"] += 1
            raise AuthLikeError("wrong password")

        with patch("remediation.utils.retry.time.sleep") as mock_sleep:
            with self.assertRaises(AuthLikeError):
                retry_with_backoff(bad_credentials, max_attempts=5, retryable_exceptions=(ConnectionLikeError,))
        self.assertEqual(calls["count"], 1)
        mock_sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
