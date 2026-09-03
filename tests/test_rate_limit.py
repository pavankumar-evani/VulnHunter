"""
Tests for dashboard/rate_limit.py - the real in-process sliding-window rate limiter.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
sys.path.insert(0, str(REPO_ROOT))

from rate_limit import RateLimiter  # noqa: E402


class RateLimiterTests(unittest.TestCase):
    def test_allows_up_to_the_limit(self):
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        self.assertTrue(limiter.allow("a", now=0))
        self.assertTrue(limiter.allow("a", now=1))
        self.assertTrue(limiter.allow("a", now=2))

    def test_rejects_once_over_the_limit(self):
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        for t in range(3):
            limiter.allow("a", now=t)
        self.assertFalse(limiter.allow("a", now=3))

    def test_different_keys_have_independent_quotas(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        self.assertTrue(limiter.allow("a", now=0))
        self.assertTrue(limiter.allow("b", now=0))
        self.assertFalse(limiter.allow("a", now=0))
        self.assertFalse(limiter.allow("b", now=0))

    def test_old_hits_age_out_of_the_window_and_free_up_quota(self):
        limiter = RateLimiter(max_requests=2, window_seconds=10)
        self.assertTrue(limiter.allow("a", now=0))
        self.assertTrue(limiter.allow("a", now=1))
        self.assertFalse(limiter.allow("a", now=2))  # still within the window of both
        # now=11 is >10s after the hit at t=0, so that one ages out, freeing one slot
        self.assertTrue(limiter.allow("a", now=11))
        self.assertFalse(limiter.allow("a", now=11))  # but the t=1 hit is still counted

    def test_a_rejected_call_is_not_itself_recorded(self):
        """Rejecting a call must not consume a quota slot - otherwise a caller stuck
        at the limit could never recover once the window rolls forward, since each
        retry would re-arm its own rejection."""
        limiter = RateLimiter(max_requests=1, window_seconds=10)
        self.assertTrue(limiter.allow("a", now=0))
        self.assertFalse(limiter.allow("a", now=1))
        self.assertFalse(limiter.allow("a", now=2))
        self.assertTrue(limiter.allow("a", now=11))  # the real t=0 hit has aged out

    def test_retry_after_seconds_reflects_the_real_oldest_hit(self):
        limiter = RateLimiter(max_requests=1, window_seconds=10)
        limiter.allow("a", now=0)
        limiter.allow("a", now=5)  # rejected, not recorded (limit is 1)
        self.assertEqual(limiter.retry_after_seconds("a", now=5), 5)  # 10 - 5

    def test_retry_after_seconds_for_an_unknown_key_is_zero(self):
        limiter = RateLimiter(max_requests=1, window_seconds=10)
        self.assertEqual(limiter.retry_after_seconds("never-called", now=0), 0)


if __name__ == "__main__":
    unittest.main()
