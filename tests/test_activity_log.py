"""
Tests for remediation/audit/activity_log.py - the unified, append-only "who did what,
to what, and when" feed every admin mutation in this app also writes to. Every test
uses a temporary log file (never the real, shipped activity_log.json).
"""
import sys
import tempfile
import threading
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.audit import activity_log  # noqa: E402


class ActivityLog(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tmpdir.name) / "activity_log.json"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_load_from_missing_file_returns_empty_list(self):
        self.assertEqual(activity_log.list_activity(self.path), [])

    def test_record_then_list_round_trips_a_full_entry(self):
        entry = activity_log.record_activity(
            "admin@example.com", "asset.set_owner", "WIN-DC01", {"owner": "New Name"}, path=self.path,
        )
        self.assertEqual(entry["id"], 1)
        self.assertEqual(entry["actor"], "admin@example.com")
        self.assertEqual(activity_log.list_activity(self.path), [entry])

    def test_missing_actor_records_unknown_not_none(self):
        entry = activity_log.record_activity(None, "login.failure", path=self.path)
        self.assertEqual(entry["actor"], "unknown")

    def test_ids_increment_and_list_is_newest_first(self):
        activity_log.record_activity("a@x.com", "action.one", path=self.path)
        second = activity_log.record_activity("a@x.com", "action.two", path=self.path)
        entries = activity_log.list_activity(self.path)
        self.assertEqual(entries[0], second)
        self.assertEqual([e["id"] for e in entries], [2, 1])

    def test_list_filters_by_actor_and_action(self):
        activity_log.record_activity("alice@x.com", "asset.set_owner", path=self.path)
        activity_log.record_activity("bob@x.com", "asset.set_owner", path=self.path)
        activity_log.record_activity("alice@x.com", "exception.revoke", path=self.path)
        self.assertEqual(len(activity_log.list_activity(self.path, actor="alice@x.com")), 2)
        self.assertEqual(len(activity_log.list_activity(self.path, action="asset.set_owner")), 2)
        self.assertEqual(len(activity_log.list_activity(self.path, actor="alice@x.com", action="exception.revoke")), 1)

    def test_limit_caps_result_count(self):
        for i in range(5):
            activity_log.record_activity("a@x.com", f"action.{i}", path=self.path)
        self.assertEqual(len(activity_log.list_activity(self.path, limit=2)), 2)

    def test_concurrent_record_activity_calls_never_lose_a_real_entry(self):
        """Real threads, real filesystem - proves record_activity()'s file-lock
        actually serializes its read-modify-write cycle. Without it, two real admin
        actions landing at nearly the same moment could both read the same entries
        list, both compute the same next id, and whichever save() ran last would
        silently erase the other's real audit record - an audit log that can lose
        entries under real concurrent use isn't one."""
        def record_one(n):
            activity_log.record_activity(f"user{n}@example.com", "concurrency.test", path=self.path)

        threads = [threading.Thread(target=record_one, args=(n,)) for n in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        entries = activity_log.list_activity(self.path)
        self.assertEqual(len(entries), 20)
        self.assertEqual(len({e["id"] for e in entries}), 20)  # every id genuinely unique


if __name__ == "__main__":
    unittest.main()
