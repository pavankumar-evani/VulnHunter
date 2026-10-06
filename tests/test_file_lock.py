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
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.utils import file_lock  # noqa: E402
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

    def _write_lock(self, text, age_seconds):
        lock = FileLock(self.path, timeout=0.1)
        Path(lock.lock_path).write_text(text, encoding="utf-8")
        old = time.time() - age_seconds
        os.utime(lock.lock_path, (old, old))

    @staticmethod
    def _dead_pid():
        import subprocess
        import sys
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        proc.wait()
        return proc.pid

    def test_a_lock_left_by_a_dead_process_is_reclaimed_at_once(self):
        # what a crashed process leaves behind: a lock file whose recorded owner no longer exists
        self._write_lock(f"{self._dead_pid()} {file_lock._HOSTNAME}\n", age_seconds=0)
        start = time.monotonic()
        with FileLock(self.path, timeout=2.0):
            pass
        self.assertLess(time.monotonic() - start, 1.0)

    def test_a_lock_with_no_owner_information_keeps_the_age_rule(self):
        self._write_lock("", age_seconds=10)       # written by an older version, or on another host
        start = time.monotonic()
        with FileLock(self.path, timeout=0.1):
            pass
        self.assertLess(time.monotonic() - start, 1.0)

    def test_a_lock_from_another_host_keeps_the_age_rule(self):
        self._write_lock("4242 some-other-host\n", age_seconds=10)
        with FileLock(self.path, timeout=0.1):
            pass

    def test_a_slow_but_live_holder_is_never_robbed(self):
        # The defect this guards: a lock older than the waiter's timeout used to be taken, so a holder that was merely slow
        # (creating the schema on a busy disk) ended up with a second writer inside its critical section.
        holder = FileLock(self.path)
        holder.acquire()
        try:
            old = time.time() - 120
            os.utime(holder.lock_path, (old, old))      # far older than the waiter's timeout
            with self.assertRaises(LockTimeoutError):
                FileLock(self.path, timeout=0.2).acquire()
            self.assertTrue(os.path.exists(holder.lock_path))   # still there: it was not stolen
        finally:
            holder.release()

    def test_a_lock_records_its_owner(self):
        with FileLock(self.path) as lock:
            pid, host, token = Path(lock.lock_path).read_text(encoding="utf-8").split()
        self.assertEqual((int(pid), host), (os.getpid(), file_lock._HOSTNAME))
        self.assertTrue(token)

    def test_release_never_deletes_a_lock_that_has_passed_to_someone_else(self):
        # A is slow to release; meanwhile the lock was taken over and re-created for B. A's delayed release must leave B's lock alone,
        # otherwise a third caller could acquire while B still holds it and two writers would be in the critical section.
        a = FileLock(self.path)
        a.acquire()
        Path(a.lock_path).write_text(f"{os.getpid()} {file_lock._HOSTNAME} not-a-token\n", encoding="utf-8")   # B's lock
        a.release()
        self.assertTrue(os.path.exists(a.lock_path))

    def test_twenty_threads_taking_turns_never_overlap(self):
        import threading
        inside = []
        overlaps = []
        guard = threading.Lock()

        def work():
            for _ in range(15):
                with FileLock(self.path, timeout=30):
                    with guard:
                        inside.append(1)
                        if len(inside) > 1:
                            overlaps.append(len(inside))
                    time.sleep(0.001)
                    with guard:
                        inside.pop()

        threads = [threading.Thread(target=work) for _ in range(20)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertEqual(overlaps, [])

    def test_pid_alive_is_true_for_this_process_and_false_for_a_finished_one(self):
        self.assertTrue(file_lock._pid_alive(os.getpid()))
        self.assertFalse(file_lock._pid_alive(self._dead_pid()))
        self.assertFalse(file_lock._pid_alive(0))


class SchemaCreationRaceTests(unittest.TestCase):
    """Several threads touching a brand-new database at once, with table creation slower than the generic lock timeout."""

    def test_slow_concurrent_first_use_creates_the_schema_once_and_loses_nothing(self):
        import threading
        from sqlalchemy import create_engine
        from remediation.utils import db

        with tempfile.TemporaryDirectory() as tmp:
            engine = create_engine(f"sqlite:///{Path(tmp) / 'race.db'}")
            real_create_all = db.metadata.create_all
            calls = []

            def slow_create_all(*args, **kwargs):
                calls.append(1)
                time.sleep(0.6)            # a busy disk makes creating every table slow; every other thread waits meanwhile
                return real_create_all(*args, **kwargs)

            errors = []

            def worker():
                try:
                    db.ensure_schema(engine)
                except Exception as exc:      # noqa: BLE001 - the test is about any failure
                    errors.append(repr(exc))

            with mock.patch.object(db.metadata, "create_all", slow_create_all):
                threads = [threading.Thread(target=worker) for _ in range(6)]
                for th in threads:
                    th.start()
                for th in threads:
                    th.join()
            engine.dispose()
        self.assertEqual(errors, [])
        self.assertGreaterEqual(len(calls), 1)

    def test_schema_creation_waits_longer_than_the_generic_five_seconds(self):
        from sqlalchemy import create_engine
        from remediation.utils import db
        seen = {}
        real = db.FileLock

        def spy(path, timeout=file_lock.DEFAULT_TIMEOUT_SECONDS, local=False):
            seen["timeout"] = timeout
            return real(path, timeout=timeout, local=local)

        with mock.patch.object(db, "FileLock", spy):
            db.ensure_schema(create_engine("sqlite:///:memory:"))
        self.assertGreaterEqual(seen["timeout"], 60)


if __name__ == "__main__":
    unittest.main()
