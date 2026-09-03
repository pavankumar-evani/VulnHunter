"""
Tests for remediation/exceptions/store.py - the vulnerability exception (risk-
acceptance/waiver) workflow. Every test uses a fresh in-memory SQLite engine (never the
real, shared remediation/vulnhunter.db) so the suite never mutates real data.
"""
import datetime
import sys
import unittest
from pathlib import Path

from sqlalchemy import create_engine

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.exceptions import store  # noqa: E402


class ExceptionLifecycle(unittest.TestCase):
    """create_exception/revoke_exception also write to the real, shared activity log
    (see remediation/audit/activity_log.py) - passing the same test engine through
    means those writes land in this test's isolated in-memory DB too, not the real one."""

    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")

    def tearDown(self):
        self.engine.dispose()

    def test_load_from_missing_file_returns_empty_list(self):
        self.assertEqual(store.load_exceptions(self.engine), [])

    def test_create_exception_persists_and_returns_a_full_record(self):
        record = store.create_exception(
            "FIND-7", "Compensating control in place", "eng@example.com", "secops@example.com",
            "2026-12-01", engine=self.engine, as_of=datetime.date(2026, 8, 1),
        )
        self.assertEqual(record["id"], "EXC-1")
        self.assertEqual(record["finding_id"], "FIND-7")
        self.assertEqual(record["status"], "active")
        self.assertEqual(record["created_on"], "2026-08-01")
        self.assertEqual(store.load_exceptions(self.engine), [record])

    def test_ids_increment_across_multiple_exceptions(self):
        store.create_exception("FIND-1", "r1", "a@x.com", "b@x.com", "2026-12-01",
                                engine=self.engine, as_of=datetime.date(2026, 8, 1))
        second = store.create_exception("FIND-2", "r2", "a@x.com", "b@x.com", "2026-12-01",
                                          engine=self.engine, as_of=datetime.date(2026, 8, 1))
        self.assertEqual(second["id"], "EXC-2")

    def test_concurrent_create_exception_calls_never_lose_a_real_request(self):
        """Real threads, real filesystem lock - proves create_exception()'s file-lock
        actually serializes its read-modify-write cycle, so two exceptions requested
        at nearly the same real moment don't race on the next EXC-N id and silently
        drop one of them. Uses a shared on-disk (not :memory:) engine because SQLite's
        :memory: databases aren't shared across threads/connections."""
        import tempfile
        import threading

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = create_engine(f"sqlite:///{Path(tmpdir) / 'test.db'}")

            def create_one(n):
                store.create_exception(
                    f"FIND-{n}", "concurrency test", "eng@example.com", "secops@example.com",
                    "2026-12-01", engine=engine, as_of=datetime.date(2026, 8, 1),
                )

            threads = [threading.Thread(target=create_one, args=(n,)) for n in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            exceptions = store.load_exceptions(engine)
            self.assertEqual(len(exceptions), 20)
            self.assertEqual(len({e["id"] for e in exceptions}), 20)  # every id genuinely unique
            # Windows won't delete a file a pooled connection still has open - dispose
            # releases every connection in the pool before the tmpdir cleanup below.
            engine.dispose()

    def test_missing_finding_id_is_rejected(self):
        with self.assertRaises(ValueError):
            store.create_exception("", "reason", "a@x.com", "b@x.com", "2026-12-01", engine=self.engine)

    def test_blank_reason_is_rejected(self):
        with self.assertRaises(ValueError):
            store.create_exception("FIND-1", "   ", "a@x.com", "b@x.com", "2026-12-01", engine=self.engine)

    def test_missing_requester_or_approver_is_rejected(self):
        with self.assertRaises(ValueError):
            store.create_exception("FIND-1", "reason", "", "b@x.com", "2026-12-01", engine=self.engine)
        with self.assertRaises(ValueError):
            store.create_exception("FIND-1", "reason", "a@x.com", "", "2026-12-01", engine=self.engine)

    def test_malformed_expiry_date_is_rejected(self):
        with self.assertRaises(ValueError):
            store.create_exception("FIND-1", "reason", "a@x.com", "b@x.com", "not-a-date", engine=self.engine)

    def test_expiry_date_in_the_past_is_rejected(self):
        with self.assertRaises(ValueError):
            store.create_exception("FIND-1", "reason", "a@x.com", "b@x.com", "2026-01-01",
                                    engine=self.engine, as_of=datetime.date(2026, 8, 1))

    def test_compute_status_active_before_expiry(self):
        record = store.create_exception("FIND-1", "r", "a@x.com", "b@x.com", "2026-12-01",
                                          engine=self.engine, as_of=datetime.date(2026, 8, 1))
        self.assertEqual(store.compute_status(record, as_of=datetime.date(2026, 8, 15)), "active")

    def test_compute_status_expired_after_expiry_without_any_action(self):
        """An exception nobody remembered to revoke still stops counting as active once
        its expires_on date passes - status is derived on read, not stored."""
        record = store.create_exception("FIND-1", "r", "a@x.com", "b@x.com", "2026-08-10",
                                          engine=self.engine, as_of=datetime.date(2026, 8, 1))
        self.assertEqual(store.compute_status(record, as_of=datetime.date(2026, 9, 1)), "expired")

    def test_revoke_marks_revoked_and_stays_revoked_even_before_expiry(self):
        record = store.create_exception("FIND-1", "r", "a@x.com", "b@x.com", "2026-12-01",
                                          engine=self.engine, as_of=datetime.date(2026, 8, 1))
        store.revoke_exception(record["id"], engine=self.engine)
        updated = store.load_exceptions(self.engine)[0]
        self.assertEqual(updated["status"], "revoked")
        self.assertEqual(store.compute_status(updated, as_of=datetime.date(2026, 8, 15)), "revoked")

    def test_revoke_unknown_id_raises_key_error(self):
        with self.assertRaises(KeyError):
            store.revoke_exception("EXC-999", engine=self.engine)

    def test_list_with_status_attaches_computed_status_without_mutating_file(self):
        store.create_exception("FIND-1", "r", "a@x.com", "b@x.com", "2026-08-10",
                                engine=self.engine, as_of=datetime.date(2026, 8, 1))
        listed = store.list_exceptions_with_status(engine=self.engine, as_of=datetime.date(2026, 9, 1))
        self.assertEqual(listed[0]["computed_status"], "expired")
        # The table still says "active" - expiry is never written back.
        raw = store.load_exceptions(self.engine)
        self.assertEqual(raw[0]["status"], "active")

    def test_active_exceptions_by_finding_excludes_expired_and_revoked(self):
        store.create_exception("FIND-1", "active one", "a@x.com", "b@x.com", "2026-12-01",
                                engine=self.engine, as_of=datetime.date(2026, 8, 1))
        store.create_exception("FIND-2", "expired one", "a@x.com", "b@x.com", "2026-08-10",
                                engine=self.engine, as_of=datetime.date(2026, 8, 1))
        revoked = store.create_exception("FIND-3", "revoked one", "a@x.com", "b@x.com", "2026-12-01",
                                          engine=self.engine, as_of=datetime.date(2026, 8, 1))
        store.revoke_exception(revoked["id"], engine=self.engine)

        active = store.active_exceptions_by_finding(engine=self.engine, as_of=datetime.date(2026, 9, 1))
        self.assertEqual(set(active.keys()), {"FIND-1"})
        self.assertNotIn("FIND-2", active)  # expired by as_of
        self.assertNotIn("FIND-3", active)  # explicitly revoked


if __name__ == "__main__":
    unittest.main()
