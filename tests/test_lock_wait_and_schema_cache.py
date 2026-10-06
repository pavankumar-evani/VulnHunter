"""Two changes that keep concurrent writers from failing under load: a longer, jittered wait for a store lock, and the schema checked once per engine."""
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, inspect  # noqa: E402

from remediation.utils import db, file_lock  # noqa: E402
from remediation.utils.file_lock import FileLock, LockTimeoutError  # noqa: E402


class LockWaitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "store.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_the_default_wait_is_long_enough_for_a_queue_of_writers(self):
        self.assertGreaterEqual(file_lock.DEFAULT_TIMEOUT_SECONDS, 30)
        self.assertGreaterEqual(FileLock(self.path).timeout, 30)

    def test_a_waiter_with_the_default_wait_gets_the_lock_when_a_slow_holder_lets_go(self):
        holder = FileLock(self.path)
        holder.acquire()
        threading.Timer(0.6, holder.release).start()
        start = time.monotonic()
        with FileLock(self.path):                       # the default timeout, as the stores use
            waited = time.monotonic() - start
        self.assertGreaterEqual(waited, 0.5)

    def test_a_caller_that_names_a_short_timeout_still_gets_it(self):
        holder = FileLock(self.path)
        holder.acquire()
        try:
            with self.assertRaises(LockTimeoutError):
                FileLock(self.path, timeout=0.1).acquire()
        finally:
            holder.release()

    def test_polling_is_jittered_so_waiters_do_not_retry_in_lockstep(self):
        sleeps = []
        holder = FileLock(self.path)
        holder.acquire()
        real_sleep = time.sleep

        def spy(seconds):
            sleeps.append(seconds)
            real_sleep(min(seconds, 0.005))
        with mock.patch.object(file_lock.time, "sleep", spy):
            with self.assertRaises(LockTimeoutError):
                FileLock(self.path, timeout=0.3).acquire()
        holder.release()
        self.assertGreater(len(set(round(s, 6) for s in sleeps)), 3)
        self.assertTrue(all(0.5 * file_lock._POLL_INTERVAL_SECONDS <= s <= 1.5 * file_lock._POLL_INTERVAL_SECONDS for s in sleeps))


class SchemaCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'a.db'}")

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def test_the_first_call_creates_the_tables_and_later_calls_do_no_work(self):
        calls = []
        real = db.FileLock

        def counting(*a, **k):
            calls.append(1)
            return real(*a, **k)
        with mock.patch.object(db, "FileLock", counting):
            db.ensure_schema(self.engine)
            first = len(calls)
            for _ in range(20):
                db.ensure_schema(self.engine)
        self.assertEqual(first, 1)
        self.assertEqual(len(calls), 1, "later calls must not take the schema lock or re-check any table")
        self.assertIn("exceptions", inspect(self.engine).get_table_names())

    def test_every_new_engine_still_gets_its_own_schema(self):
        db.ensure_schema(self.engine)
        other = create_engine(f"sqlite:///{Path(self.tmp.name) / 'b.db'}")
        try:
            db.ensure_schema(other)
            self.assertIn("exceptions", inspect(other).get_table_names())
        finally:
            other.dispose()

    def test_forgetting_the_schema_makes_the_next_call_check_again(self):
        db.ensure_schema(self.engine)
        with self.engine.begin() as conn:
            conn.exec_driver_sql("DROP TABLE alert_state")
        db.ensure_schema(self.engine)                    # cached: the missing table is not noticed
        self.assertNotIn("alert_state", inspect(self.engine).get_table_names())
        db.forget_schema(self.engine)
        db.ensure_schema(self.engine)
        self.assertIn("alert_state", inspect(self.engine).get_table_names())

    def test_concurrent_first_calls_still_create_the_schema_once_without_error(self):
        errors = []

        def go():
            try:
                db.ensure_schema(self.engine)
            except Exception as exc:    # noqa: BLE001
                errors.append(repr(exc))
        threads = [threading.Thread(target=go) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertIn("exceptions", inspect(self.engine).get_table_names())


if __name__ == "__main__":
    unittest.main()
