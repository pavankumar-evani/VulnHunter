"""Tiny in-process sliding-window limiter (single node, like dashboard/rate_limit.py; kept here so remediation/ never imports the dashboard)."""
import time
from collections import defaultdict, deque


class SlidingLimiter:
    def __init__(self, max_calls, window_seconds):
        self.max_calls, self.window = int(max_calls), float(window_seconds)
        self._hits = defaultdict(deque)

    def _prune(self, key, now):
        q = self._hits[key]
        while q and q[0] < now - self.window:
            q.popleft()
        return q

    def allow(self, key, now=None):
        now = time.monotonic() if now is None else now
        q = self._prune(key, now)
        if len(q) >= self.max_calls:
            return False
        q.append(now)
        return True

    def blocked(self, key, now=None):
        """True when `key` is at its quota; records nothing (for counting only failures)."""
        now = time.monotonic() if now is None else now
        return len(self._prune(key, now)) >= self.max_calls

    def retry_after(self, key, now=None):
        now = time.monotonic() if now is None else now
        q = self._prune(key, now)
        return max(1, int(q[0] + self.window - now) + 1) if q else 1
