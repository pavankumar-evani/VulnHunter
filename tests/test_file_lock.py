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

    def _increment_locked(self, errors):
        try:
            for _ in range(50):
                # 30s, not FileLock's 5s default: this test proves the lock preserves
                # every increment under real 4-thread contention, not that acquisition
                # finishes within an arbitrary window (FileLockTimeoutAndStaleness
                # covers timeout behavior separately). Under a CPU-starved full-suite
                # run - or this repo's own OneDrive-synced working directory, which
                # file_lock.py's docstring already flags as intercepting rapid
                # create/delete cycles - legitimate queueing could exceed 5s and trip
                # LockTimeoutError mid-loop, silently killing a worker thread (Python
                # threads swallow unhandled exceptions) and losing the rest of its
                # increments: the real cause of an observed "162 != 200" flake.
                with FileLock(self.path, timeout=30.0):
                    value = int(self.path.read_text(encoding="utf-8"))
                    time.sleep(0.0001)
                    self.path.write_text(str(value + 1), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001 - surface to the main thread below instead of vanishing into stderr
            errors.append(exc)

    def test_without_the_lock_two_threads_reading_the_same_value_lose_an_update(self):
        """Deterministic, not probabilistic: a threading.Barrier forces both threads
        to finish their read BEFORE either writes, guaranteeing (not just hoping for)
        the exact race a real lock prevents - two concurrent callers computing "next
        value" from the same stale read, so whichever writes last silently erases the
        other's update. A `time.sleep()`-based race (the original version of this
        test) only *probably* manifests within N iterations, which is exactly the
        kind of assertion that passes on one machine/OS and flakes on another (a CI
        runner's own scheduler, VM contention, etc.) - real, observed cause of a real
        CI failure on this exact test, not a hypothetical concern."""
        barrier = threading.Barrier(2)

        def worker(amount):
            value = int(self.path.read_text(encoding="utf-8"))
            barrier.wait()  # both threads now guaranteed to have read the SAME value
            self.path.write_text(str(value + amount), encoding="utf-8")

        t1 = threading.Thread(target=worker, args=(1,))
        t2 = threading.Thread(target=worker, args=(2,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        final = int(self.path.read_text(encoding="utf-8"))
        # Without synchronization, one write always clobbers the other - the real
        # result is exactly one of {1, 2}, never their sum (3), which is what two
        # correctly-serialized increments would produce.
        self.assertIn(final, (1, 2))
        self.assertNotEqual(final, 3)

    def test_with_the_lock_concurrent_increments_are_all_preserved(self):
        errors = []
        threads = [
            threading.Thread(target=self._increment_locked, args=(errors,))
            for _ in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
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
