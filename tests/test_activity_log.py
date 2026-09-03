"""
Tests for remediation/audit/activity_log.py - the unified, append-only "who did what,
to what, and when" feed every admin mutation in this app also writes to. Every test
uses a fresh in-memory SQLite engine (never the real, shared remediation/vulnhunter.db).
"""
import sys
import threading
import unittest
from pathlib import Path

from sqlalchemy import create_engine

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.audit import activity_log  # noqa: E402


class ActivityLog(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")

    def tearDown(self):
        self.engine.dispose()

    def test_list_from_empty_db_returns_empty_list(self):
        self.assertEqual(activity_log.list_activity(self.engine), [])

    def test_record_then_list_round_trips_a_full_entry(self):
        entry = activity_log.record_activity(
            "admin@example.com", "asset.set_owner", "WIN-DC01", {"owner": "New Name"}, engine=self.engine,
        )
        self.assertEqual(entry["id"], 1)
        self.assertEqual(entry["actor"], "admin@example.com")
        self.assertEqual(activity_log.list_activity(self.engine), [entry])

    def test_missing_actor_records_unknown_not_none(self):
        entry = activity_log.record_activity(None, "login.failure", engine=self.engine)
        self.assertEqual(entry["actor"], "unknown")

    def test_ids_increment_and_list_is_newest_first(self):
        activity_log.record_activity("a@x.com", "action.one", engine=self.engine)
        second = activity_log.record_activity("a@x.com", "action.two", engine=self.engine)
        entries = activity_log.list_activity(self.engine)
        self.assertEqual(entries[0], second)
        self.assertEqual([e["id"] for e in entries], [2, 1])

    def test_list_filters_by_actor_and_action(self):
        activity_log.record_activity("alice@x.com", "asset.set_owner", engine=self.engine)
        activity_log.record_activity("bob@x.com", "asset.set_owner", engine=self.engine)
        activity_log.record_activity("alice@x.com", "exception.revoke", engine=self.engine)
        self.assertEqual(len(activity_log.list_activity(self.engine, actor="alice@x.com")), 2)
        self.assertEqual(len(activity_log.list_activity(self.engine, action="asset.set_owner")), 2)
        self.assertEqual(len(activity_log.list_activity(self.engine, actor="alice@x.com", action="exception.revoke")), 1)

    def test_limit_caps_result_count(self):
        for i in range(5):
            activity_log.record_activity("a@x.com", f"action.{i}", engine=self.engine)
        self.assertEqual(len(activity_log.list_activity(self.engine, limit=2)), 2)

    def test_concurrent_record_activity_calls_never_lose_a_real_entry(self):
        """Real threads, real on-disk SQLite file (not :memory:, which isn't shared
        across connections) - proves a plain INSERT relying on a real DB autoincrement
        id is enough on its own: unlike the old JSON version, record_activity() no
        longer takes a FileLock (see its own docstring for why), so this test is what
        actually backs that design decision, not just the reasoning behind it."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = create_engine(f"sqlite:///{Path(tmpdir) / 'test.db'}")

            def record_one(n):
                activity_log.record_activity(f"user{n}@example.com", "concurrency.test", engine=engine)

            threads = [threading.Thread(target=record_one, args=(n,)) for n in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            entries = activity_log.list_activity(engine)
            self.assertEqual(len(entries), 20)
            self.assertEqual(len({e["id"] for e in entries}), 20)  # every id genuinely unique
            # Windows won't delete a file a pooled connection still has open - dispose
            # releases every connection in the pool before the tmpdir cleanup below.
            engine.dispose()


if __name__ == "__main__":
    unittest.main()
