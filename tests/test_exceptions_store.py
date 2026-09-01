"""
Tests for remediation/exceptions/store.py - the vulnerability exception (risk-
acceptance/waiver) workflow. Every test uses a temporary store file (never the real,
shipped remediation/exceptions/exceptions.json) so the suite never mutates real data.
"""
import datetime
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.audit import activity_log  # noqa: E402
from remediation.exceptions import store  # noqa: E402


class ExceptionLifecycle(unittest.TestCase):
    """create_exception/revoke_exception also write to the real, shared activity log
    (see remediation/audit/activity_log.py) unless redirected - patch its default path
    to a temp file too so this suite never pollutes the real, committed-empty log."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tmpdir.name) / "exceptions.json"
        self.activity_log_path = Path(self.tmpdir.name) / "activity_log.json"
        self.activity_patcher = patch.object(activity_log, "DEFAULT_LOG_PATH", self.activity_log_path)
        self.activity_patcher.start()

    def tearDown(self):
        self.activity_patcher.stop()
        self.tmpdir.cleanup()

    def test_load_from_missing_file_returns_empty_list(self):
        self.assertEqual(store.load_exceptions(self.path), [])

    def test_create_exception_persists_and_returns_a_full_record(self):
        record = store.create_exception(
            "FIND-7", "Compensating control in place", "eng@example.com", "secops@example.com",
            "2026-12-01", path=self.path, as_of=datetime.date(2026, 8, 1),
        )
        self.assertEqual(record["id"], "EXC-1")
        self.assertEqual(record["finding_id"], "FIND-7")
        self.assertEqual(record["status"], "active")
        self.assertEqual(record["created_on"], "2026-08-01")
        self.assertEqual(store.load_exceptions(self.path), [record])

    def test_ids_increment_across_multiple_exceptions(self):
        store.create_exception("FIND-1", "r1", "a@x.com", "b@x.com", "2026-12-01",
                                path=self.path, as_of=datetime.date(2026, 8, 1))
        second = store.create_exception("FIND-2", "r2", "a@x.com", "b@x.com", "2026-12-01",
                                          path=self.path, as_of=datetime.date(2026, 8, 1))
        self.assertEqual(second["id"], "EXC-2")

    def test_missing_finding_id_is_rejected(self):
        with self.assertRaises(ValueError):
            store.create_exception("", "reason", "a@x.com", "b@x.com", "2026-12-01", path=self.path)

    def test_blank_reason_is_rejected(self):
        with self.assertRaises(ValueError):
            store.create_exception("FIND-1", "   ", "a@x.com", "b@x.com", "2026-12-01", path=self.path)

    def test_missing_requester_or_approver_is_rejected(self):
        with self.assertRaises(ValueError):
            store.create_exception("FIND-1", "reason", "", "b@x.com", "2026-12-01", path=self.path)
        with self.assertRaises(ValueError):
            store.create_exception("FIND-1", "reason", "a@x.com", "", "2026-12-01", path=self.path)

    def test_malformed_expiry_date_is_rejected(self):
        with self.assertRaises(ValueError):
            store.create_exception("FIND-1", "reason", "a@x.com", "b@x.com", "not-a-date", path=self.path)

    def test_expiry_date_in_the_past_is_rejected(self):
        with self.assertRaises(ValueError):
            store.create_exception("FIND-1", "reason", "a@x.com", "b@x.com", "2026-01-01",
                                    path=self.path, as_of=datetime.date(2026, 8, 1))

    def test_compute_status_active_before_expiry(self):
        record = store.create_exception("FIND-1", "r", "a@x.com", "b@x.com", "2026-12-01",
                                          path=self.path, as_of=datetime.date(2026, 8, 1))
        self.assertEqual(store.compute_status(record, as_of=datetime.date(2026, 8, 15)), "active")

    def test_compute_status_expired_after_expiry_without_any_action(self):
        """An exception nobody remembered to revoke still stops counting as active once
        its expires_on date passes - status is derived on read, not stored."""
        record = store.create_exception("FIND-1", "r", "a@x.com", "b@x.com", "2026-08-10",
                                          path=self.path, as_of=datetime.date(2026, 8, 1))
        self.assertEqual(store.compute_status(record, as_of=datetime.date(2026, 9, 1)), "expired")

    def test_revoke_marks_revoked_and_stays_revoked_even_before_expiry(self):
        record = store.create_exception("FIND-1", "r", "a@x.com", "b@x.com", "2026-12-01",
                                          path=self.path, as_of=datetime.date(2026, 8, 1))
        store.revoke_exception(record["id"], path=self.path)
        updated = store.load_exceptions(self.path)[0]
        self.assertEqual(updated["status"], "revoked")
        self.assertEqual(store.compute_status(updated, as_of=datetime.date(2026, 8, 15)), "revoked")

    def test_revoke_unknown_id_raises_key_error(self):
        with self.assertRaises(KeyError):
            store.revoke_exception("EXC-999", path=self.path)

    def test_list_with_status_attaches_computed_status_without_mutating_file(self):
        store.create_exception("FIND-1", "r", "a@x.com", "b@x.com", "2026-08-10",
                                path=self.path, as_of=datetime.date(2026, 8, 1))
        listed = store.list_exceptions_with_status(path=self.path, as_of=datetime.date(2026, 9, 1))
        self.assertEqual(listed[0]["computed_status"], "expired")
        # The file on disk still says "active" - expiry is never written back.
        raw = store.load_exceptions(self.path)
        self.assertEqual(raw[0]["status"], "active")

    def test_active_exceptions_by_finding_excludes_expired_and_revoked(self):
        store.create_exception("FIND-1", "active one", "a@x.com", "b@x.com", "2026-12-01",
                                path=self.path, as_of=datetime.date(2026, 8, 1))
        store.create_exception("FIND-2", "expired one", "a@x.com", "b@x.com", "2026-08-10",
                                path=self.path, as_of=datetime.date(2026, 8, 1))
        revoked = store.create_exception("FIND-3", "revoked one", "a@x.com", "b@x.com", "2026-12-01",
                                          path=self.path, as_of=datetime.date(2026, 8, 1))
        store.revoke_exception(revoked["id"], path=self.path)

        active = store.active_exceptions_by_finding(path=self.path, as_of=datetime.date(2026, 9, 1))
        self.assertEqual(set(active.keys()), {"FIND-1"})
        self.assertNotIn("FIND-2", active)  # expired by as_of
        self.assertNotIn("FIND-3", active)  # explicitly revoked


class RealSeedFileIsValid(unittest.TestCase):
    """The shipped remediation/exceptions/exceptions.json should always parse and be
    internally consistent - a regression guard, not a mutation test."""

    def test_shipped_exceptions_file_is_well_formed(self):
        exceptions = store.load_exceptions()
        self.assertIsInstance(exceptions, list)
        for record in exceptions:
            for field in ("id", "finding_id", "reason", "requested_by", "approved_by",
                           "created_on", "expires_on", "status"):
                self.assertIn(field, record)
            datetime.date.fromisoformat(record["expires_on"])  # raises if malformed


if __name__ == "__main__":
    unittest.main()
