"""
A small, stdlib-only retry-with-backoff helper for this app's real network calls
(CISA KEV/FIRST.org EPSS fetches in enrichment/kev_epss.py, SMTP delivery in
notifications/email_sender.py) - "self-healing" here means retrying a genuinely
transient failure (a dropped connection, a timeout, a 429/5xx) a bounded number of
times with exponential backoff, not silently swallowing a real, permanent failure (bad
credentials, a 404, a malformed request) that retrying would never fix - callers choose
exactly which exception types are worth retrying via `retryable_exceptions`. Every retry
is printed to stderr so a real transient blip is visible in server logs, not invisible.
"""
import sys
import time


def retry_with_backoff(fn, *, max_attempts=3, base_delay_seconds=1.0, retryable_exceptions=(Exception,)):
    """Calls fn() and returns its result. On a retryable exception, waits
    base_delay_seconds * 2**attempt (1s, 2s, 4s, ... by default) then retries, up to
    max_attempts total attempts. Re-raises the last exception if every attempt fails.
    A non-retryable exception (not in retryable_exceptions) always propagates
    immediately - no wasted retries on a failure that won't change."""
    for attempt in range(max_attempts):
        try:
            return fn()
        except retryable_exceptions as exc:
            if attempt == max_attempts - 1:
                raise
            delay = base_delay_seconds * (2 ** attempt)
            print(
                f"[retry] attempt {attempt + 1}/{max_attempts} failed ({exc!r}) - retrying in {delay:.1f}s",
                file=sys.stderr,
            )
            time.sleep(delay)
