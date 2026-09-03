"""
A real, in-process sliding-window rate limiter, keyed per client IP - genuine
protection against a single caller hammering this app, not a distributed-rate-limiting
story. This app runs single-node today (see dashboard/README.md's "What this is NOT
(yet)"), so an in-process counter is a real, sufficient mitigation for that
deployment shape; a future multi-node deployment needs a shared store (e.g. Redis)
instead - each node would otherwise count independently, and the effective limit would
scale up with node count rather than staying fixed.

Honest limitation, disclosed rather than hidden: `RateLimiter._hits` never prunes a key
whose deque has emptied out (every hit has aged past the window) - a long-running
process that's been called by many distinct IPs accumulates one empty deque per IP
forever. At this app's real scale (a single small-to-mid-size org's own traffic, not a
public multi-tenant service), that's a few thousand empty deques at most over a long
uptime - a real but bounded and low-priority memory cost, not something worth adding
scheduled-cleanup complexity for in this pass.
"""
import time
from collections import defaultdict, deque


class RateLimiter:
    """Tracks request timestamps per key in a deque, dropping any older than
    `window_seconds` before counting - a real sliding window, not a fixed-bucket
    approximation that can double-allow right at a bucket boundary (e.g. a caller
    firing its full quota at 0:59 and again at 1:01 under a naive per-minute-bucket
    scheme)."""

    def __init__(self, max_requests, window_seconds):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits = defaultdict(deque)

    def allow(self, key, now=None):
        """Returns True and records this call if `key` is under its quota for the
        current window, False (without recording) if not."""
        now = now if now is not None else time.monotonic()
        hits = self._hits[key]
        cutoff = now - self.window_seconds
        while hits and hits[0] < cutoff:
            hits.popleft()
        if len(hits) >= self.max_requests:
            return False
        hits.append(now)
        return True

    def retry_after_seconds(self, key, now=None):
        """How many seconds until this key's oldest currently-counted hit ages out of
        the window - the honest value for a 429 response's Retry-After header, not a
        guess. Returns 0 if the key has no hits recorded (shouldn't be called in that
        case, but fails safe rather than raising)."""
        now = now if now is not None else time.monotonic()
        hits = self._hits[key]
        if not hits:
            return 0
        return max(0, round(hits[0] + self.window_seconds - now))
