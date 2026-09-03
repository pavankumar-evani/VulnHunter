"""
A minimal, cross-platform advisory lock for the real read-modify-write JSON stores
this app uses (exceptions.json, remediation_approvals.json, activity_log.json, etc.).
Without this, two concurrent requests hitting the same store race on
load-mutate-save: whichever save() call runs last wins and silently drops the other
request's change - for an append-only log (activity_log.py, ai_usage_log.py) that
means an entire audit/usage record vanishes with no error anywhere.

Uses a lock FILE created with the atomic, exclusive `os.O_CREAT | os.O_EXCL` open
flag (fails if the file already exists; succeeds only for whichever caller gets
there first) rather than fcntl/msvcrt, since those are platform-specific
(Unix-only / Windows-only respectively) and this app runs on both. This is the same
dependency-free "lock file" pattern real small tools use for single-machine
coordination - it is explicitly NOT a distributed lock. It coordinates processes on
ONE machine sharing ONE filesystem, which is this app's actual deployment model (see
dashboard/README.md's "What this is NOT (yet)" section - even the stores that have
since moved to a real local SQLite database are still one file on one machine; a real
multi-machine deployment needs a real client-server database with real distributed
transactions instead of this).
"""
import os
import time

DEFAULT_TIMEOUT_SECONDS = 5.0
_POLL_INTERVAL_SECONDS = 0.02


class LockTimeoutError(RuntimeError):
    pass


class FileLock:
    """Context manager: `with FileLock(path):` blocks (polling) until it can create
    `<path>.lock` exclusively, then removes the lock file on exit (success or
    exception). Raises LockTimeoutError if it can't acquire within `timeout` seconds -
    a real, visible failure rather than hanging a request forever."""

    def __init__(self, path, timeout=DEFAULT_TIMEOUT_SECONDS):
        self.lock_path = f"{path}.lock"
        self.timeout = timeout
        self._fd = None

    def acquire(self):
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self._fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                return
            except (FileExistsError, PermissionError):
                # PermissionError (not just FileExistsError) is a real, observed
                # condition on Windows: CreateFile with CREATE_NEW against a path
                # another thread/process is concurrently unlinking can transiently
                # fail this way instead of cleanly raising FileExistsError - a real
                # OS-level race in the underlying filesystem driver (more visible
                # still inside a OneDrive-synced directory, which intercepts file
                # operations). Retrying is correct either way: the path is
                # momentarily unavailable, not permanently inaccessible - a real
                # permissions problem would fail identically on every retry and
                # still surface as LockTimeoutError once the deadline passes.
                self._remove_if_stale()
                if time.monotonic() >= deadline:
                    raise LockTimeoutError(
                        f"Could not acquire lock {self.lock_path!r} within {self.timeout}s - "
                        "another request is holding it, or a stale lock wasn't cleaned up.",
                    )
                time.sleep(_POLL_INTERVAL_SECONDS)

    def _remove_if_stale(self):
        # A lock file older than this lock's own timeout is almost certainly stale -
        # the process that created it crashed or was killed without releasing it.
        # Removing it lets a new caller proceed immediately instead of waiting out
        # the full timeout on a lock nobody will ever release. time.time() (wall
        # clock), not time.monotonic() (used for the acquire-loop deadline above) -
        # os.path.getmtime() is a wall-clock epoch timestamp, and diffing it against
        # a monotonic clock (an arbitrary, unrelated reference point) is meaningless.
        try:
            if time.time() - os.path.getmtime(self.lock_path) > self.timeout:
                os.remove(self.lock_path)
        except OSError:
            pass  # already removed/replaced by someone else - fine, just retry

    def release(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        try:
            os.remove(self.lock_path)
        except OSError:
            pass  # already gone (e.g. a stale-lock takeover happened) - fine

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.release()
        return False
