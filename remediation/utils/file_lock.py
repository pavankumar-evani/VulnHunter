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
coordination - it is explicitly NOT a distributed lock. For several replicas, set
QUANTA_LOCK_BACKEND=db and the same calls take a lease row in the shared database instead
(remediation/coordination/leases.py), which does work across nodes. It coordinates processes on
ONE machine sharing ONE filesystem, which is this app's actual deployment model (see
dashboard/README.md's "What this is NOT (yet)" section - even the stores that have
since moved to a real local SQLite database are still one file on one machine; a real
multi-machine deployment needs a real client-server database with real distributed
transactions instead of this).
"""
import os
import random
import secrets
import socket
import time
from pathlib import Path

# How long a caller waits for a store's lock before giving up with LockTimeoutError. Five seconds was too short under load: twenty writers queued behind
# one another each wait for all the ones ahead, and the ones at the back were failing (and losing their write) while the machine was merely busy.
DEFAULT_TIMEOUT_SECONDS = 30.0
_POLL_INTERVAL_SECONDS = 0.02
# A lock whose recorded owner is a live process on this host is never taken over merely for being slow; this is only the
# backstop against a recycled process id, so it is far longer than any real critical section.
_OWNER_ALIVE_BACKSTOP_SECONDS = 3600.0
_HOSTNAME = socket.gethostname()


def _pid_alive(pid):
    """Is a process with this id running? Never signals it (os.kill(pid, 0) would terminate the process on Windows)."""
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            return bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259   # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class LockTimeoutError(RuntimeError):
    pass


class FileLock:
    """Context manager: `with FileLock(path):` blocks (polling) until it can create
    `<path>.lock` exclusively, then removes the lock file on exit (success or
    exception). Raises LockTimeoutError if it can't acquire within `timeout` seconds -
    a real, visible failure rather than hanging a request forever."""

    def __init__(self, path, timeout=DEFAULT_TIMEOUT_SECONDS, local=False):
        self.lock_path = f"{path}.lock"
        self.timeout = timeout
        self.local = local  # True: always a file lock (used where a database lease would be circular)
        self._fd = None
        self._lease = None
        self._token = None

    def _use_lease(self):
        return not self.local and os.environ.get("QUANTA_LOCK_BACKEND", "file").strip().lower() == "db"

    def _lease_name(self):
        # the same logical lock must get the same name on every replica, whatever the mount path
        repo = Path(__file__).resolve().parents[2]
        p = Path(self.lock_path).resolve()
        try:
            return "lock:" + p.relative_to(repo).as_posix()
        except ValueError:
            return "lock:" + p.name

    def acquire(self):
        if self._use_lease():
            # QUANTA_LOCK_BACKEND=db: a lease row in the shared database, which works across
            # nodes where a lock file on a network volume does not (see remediation/coordination).
            from remediation.coordination import leases
            holder = leases.new_holder_id()
            deadline = time.monotonic() + self.timeout
            while not leases.acquire(self._lease_name(), holder, max(self.timeout * 2, 120.0)):
                if time.monotonic() >= deadline:
                    raise LockTimeoutError(f"Could not acquire lock {self._lease_name()!r} within {self.timeout}s - another replica is holding it.")
                time.sleep(_POLL_INTERVAL_SECONDS * (0.5 + random.random()))   # jitter: waiters that retry in lockstep keep colliding
            self._lease = holder
            return
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self._fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                # who holds it (so a slow holder is not mistaken for a dead one) and a token that is ours alone (so release
                # never deletes a lock that has since passed to someone else)
                self._token = secrets.token_hex(8)
                try:
                    os.write(self._fd, f"{os.getpid()} {_HOSTNAME} {self._token}\n".encode("utf-8"))
                except OSError:
                    pass
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
                time.sleep(_POLL_INTERVAL_SECONDS * (0.5 + random.random()))   # jitter: waiters that retry in lockstep keep colliding

    def _owner(self):
        try:
            with open(self.lock_path, "r", encoding="utf-8") as fh:
                parts = fh.read().split()
            return int(parts[0]), parts[1], (parts[2] if len(parts) > 2 else None)
        except (OSError, ValueError, IndexError):
            return None

    def _remove_if_stale(self):
        # Take over a lock only when its holder is gone. The previous rule (older than this lock's own timeout means abandoned)
        # also took locks from holders that were merely slow, so two writers could be inside the same critical section: a
        # first-use schema creation that outlasted the timeout lost a record and raised "table already exists".
        # A lock records its owner's process id and host. On this host a live owner is never robbed (time.time(), the wall
        # clock, is used for the age because os.path.getmtime() is a wall-clock epoch). A lock with no readable owner (written
        # by an older version, or on another host) keeps the old age rule.
        try:
            age = time.time() - os.path.getmtime(self.lock_path)
            owner = self._owner()
            if owner and owner[1] == _HOSTNAME:
                # Our own process counts as alive: a thread of this process that holds the lock is live, and a thread that
                # leaked one is an in-process bug only the long backstop below recovers from.
                alive = owner[0] == os.getpid() or _pid_alive(owner[0])
                stale = (not alive) or age > _OWNER_ALIVE_BACKSTOP_SECONDS
            else:
                stale = age > self.timeout
            if stale:
                os.remove(self.lock_path)
        except OSError:
            pass  # already removed/replaced by someone else - fine, just retry

    def release(self):
        if self._lease is not None:
            from remediation.coordination import leases
            try:
                leases.release(self._lease_name(), self._lease)
            finally:
                self._lease = None
            return
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
            token, self._token = self._token, None
            owner = self._owner()
            if owner and owner[2] and token and owner[2] != token:
                return   # the lock was taken over and now belongs to someone else: deleting it would let a second writer in
        # On Windows a file another thread has open cannot be deleted (a waiter reading the owner, for one), so retry briefly rather than leave
        # the lock behind for everyone; elsewhere the first attempt succeeds.
        for _ in range(200):
            try:
                os.remove(self.lock_path)
                return
            except FileNotFoundError:
                return   # already gone (e.g. a stale-lock takeover happened) - fine
            except PermissionError:
                time.sleep(0.005)
            except OSError:
                return

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.release()
        return False
