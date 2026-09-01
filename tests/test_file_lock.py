"""
Tests for remediation/utils/file_lock.py - the dependency-free advisory lock used to
make the app's JSON-store read-modify-write functions safe under real concurrency.
"""
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.utils.file_lock import FileLock, LockTimeoutError  # noqa: E402


class FileLockBasics(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tmpdir.name) / "store.json"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_acquire_creates_a_lock_file_and_release_removes_it(self):
        lock = FileLock(self.path)
        lock.acquire()
        self.assertTrue(os.path.exists(lock.lock_path))
        lock.release()
        self.assertFalse(os.path.exists(lock.lock_path))

    def test_context_manager_releases_even_if_the_body_raises(self):
        with self.assertRaises(ValueError):
            with FileLock(self.path):
                raise ValueError("boom")
        self.assertFalse(os.path.exists(f"{self.path}.lock"))

    def test_release_without_acquire_does_not_raise(self):
        FileLock(self.path).release()  # nothing to release - must be a harmless no-op

    def test_a_second_lock_on_a_different_path_does_not_block(self):
        other_path = Path(self.tmpdir.name) / "other.json"
        with FileLock(self.path):
            with FileLock(other_path):
                pass  # must not block - different lock files


class FileLockConcurrency(unittest.TestCase):
    """Real threads, real filesystem, real race - proves the lock actually serializes
    a read-modify-write critical section instead of just existing as an unused API."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tmpdir.name) / "counter.json"
        self.path.write_text("0", encoding="utf-8")

    def tearDown(self):
        self.tmpdir.cleanup()

    def _increment_unlocked(self, errors):
        for _ in range(50):
            try:
                value = int(self.path.read_text(encoding="utf-8"))
                time.sleep(0.0001)  # widen the race window so it's reliably observable
                self.path.write_text(str(value + 1), encoding="utf-8")
            except (OSError, ValueError) as exc:
                # Unsynchronized concurrent access can fail outright, not just lose
                # an update: a real OS-level sharing violation (seen on Windows), or
                # a read catching another thread's write mid-truncate (an empty/
                # partial read that fails int() with ValueError) - both are further
                # proof this needs a lock, not something to hide.
                errors.append(exc)

    def _increment_locked(self):
        for _ in range(50):
            with FileLock(self.path):
                value = int(self.path.read_text(encoding="utf-8"))
                time.sleep(0.0001)
                self.path.write_text(str(value + 1), encoding="utf-8")

    def test_without_the_lock_concurrent_increments_are_unsafe(self):
        errors = []
        threads = [threading.Thread(target=self._increment_unlocked, args=(errors,)) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # 4 threads x 50 increments = 200 if perfectly serialized - the whole point of
        # this test is proving that WITHOUT the lock, concurrent access is unsafe:
        # either the final count is short (a lost update) or real errors were raised
        # (unsynchronized concurrent access faulting outright, seen on Windows).
        final_count = int(self.path.read_text(encoding="utf-8"))
        self.assertTrue(final_count < 200 or errors, f"expected lost updates or errors, got count={final_count}, errors={errors}")

    def test_with_the_lock_concurrent_increments_are_all_preserved(self):
        threads = [threading.Thread(target=self._increment_locked) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(int(self.path.read_text(encoding="utf-8")), 200)


class FileLockTimeoutAndStaleness(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tmpdir.name) / "store.json"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_raises_lock_timeout_error_when_already_held(self):
        holder = FileLock(self.path)
        holder.acquire()
        try:
            with self.assertRaises(LockTimeoutError):
                FileLock(self.path, timeout=0.05).acquire()
        finally:
            holder.release()

    def test_a_stale_lock_older_than_its_own_timeout_is_reclaimed(self):
        # Simulate a crashed holder: create the lock file, then close its descriptor
        # directly (what the OS does automatically when a real process dies, without
        # it ever calling release()) and backdate the file's mtime past the timeout.
        stale = FileLock(self.path, timeout=0.1)
        stale.acquire()
        os.close(stale._fd)
        stale._fd = None
        old_time = time.time() - 10
        os.utime(stale.lock_path, (old_time, old_time))
        # A new caller with the same timeout must reclaim it well within a couple of
        # timeout windows, not hang for real wall-clock time.
        start = time.monotonic()
        with FileLock(self.path, timeout=0.1):
            pass
        self.assertLess(time.monotonic() - start, 1.0)


if __name__ == "__main__":
    unittest.main()
