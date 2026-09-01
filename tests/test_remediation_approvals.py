"""
Tests for remediation/remediation_approvals/store.py - the human-in-the-loop
approve/reject workflow for normal/emergency change-type findings. Every test uses a
temporary store file (never the real, shipped remediation_approvals.json) so the suite
never mutates real data - same pattern as test_exceptions_store.py.
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
from remediation.remediation_approvals import store  # noqa: E402

WINDOW = {"date": "2026-08-08", "day_of_week": "saturday", "start_time": "23:00", "end_time": "03:00", "timezone": "UTC"}


class ApprovalLifecycle(unittest.TestCase):
    """create_approval_request/approve/reject also write to the real, shared activity
    log (see remediation/audit/activity_log.py) unless redirected - patch its default
    path to a temp file too so this suite never pollutes the real, committed-empty log."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tmpdir.name) / "remediation_approvals.json"
        self.activity_log_path = Path(self.tmpdir.name) / "activity_log.json"
        self.activity_patcher = patch.object(activity_log, "DEFAULT_LOG_PATH", self.activity_log_path)
        self.activity_patcher.start()

    def tearDown(self):
        self.activity_patcher.stop()
        self.tmpdir.cleanup()

    def test_load_from_missing_file_returns_empty_list(self):
        self.assertEqual(store.load_approvals(self.path), [])

    def test_create_request_persists_and_returns_a_full_record(self):
        record = store.create_approval_request(
            "FIND-1", "requester@example.com", WINDOW, path=self.path, as_of=datetime.date(2026, 8, 1),
        )
        self.assertEqual(record["id"], "APR-1")
        self.assertEqual(record["finding_id"], "FIND-1")
        self.assertEqual(record["status"], "pending")
        self.assertEqual(record["created_on"], "2026-08-01")
        self.assertIsNone(record["ad_group_validated"])
        self.assertEqual(store.load_approvals(self.path), [record])

    def test_ids_increment_across_multiple_requests(self):
        store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path, as_of=datetime.date(2026, 8, 1))
        second = store.create_approval_request("FIND-2", "a@x.com", WINDOW, path=self.path, as_of=datetime.date(2026, 8, 1))
        self.assertEqual(second["id"], "APR-2")

    def test_missing_finding_id_is_rejected(self):
        with self.assertRaises(ValueError):
            store.create_approval_request("", "a@x.com", WINDOW, path=self.path)

    def test_blank_requester_is_rejected(self):
        with self.assertRaises(ValueError):
            store.create_approval_request("FIND-1", "   ", WINDOW, path=self.path)

    def test_approve_sets_status_and_ad_validation_result(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path, as_of=datetime.date(2026, 8, 1))
        updated = store.approve(record["id"], "approver@x.com", ad_group_validated=True, path=self.path, as_of=datetime.date(2026, 8, 2))
        self.assertEqual(updated["status"], "approved")
        self.assertEqual(updated["approved_by"], "approver@x.com")
        self.assertEqual(updated["approved_at"], "2026-08-02")
        self.assertTrue(updated["ad_group_validated"])

    def test_approve_with_ad_not_configured_stores_none_not_false(self):
        """None ('AD not configured, we didn't check') must never collapse into False
        ('checked and the user failed the check') - see the store's own docstring."""
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path)
        updated = store.approve(record["id"], "approver@x.com", ad_group_validated=None, path=self.path)
        self.assertIsNone(updated["ad_group_validated"])
        self.assertEqual(updated["status"], "approved")

    def test_approve_blank_approver_is_rejected(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path)
        with self.assertRaises(ValueError):
            store.approve(record["id"], "   ", path=self.path)

    def test_approve_unknown_id_raises_key_error(self):
        with self.assertRaises(KeyError):
            store.approve("APR-999", "approver@x.com", path=self.path)

    def test_reject_sets_status_and_reason(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path, as_of=datetime.date(2026, 8, 1))
        updated = store.reject(record["id"], "approver@x.com", "Downtime window conflicts with a release freeze", path=self.path, as_of=datetime.date(2026, 8, 2))
        self.assertEqual(updated["status"], "rejected")
        self.assertEqual(updated["rejected_by"], "approver@x.com")
        self.assertEqual(updated["rejected_at"], "2026-08-02")
        self.assertEqual(updated["rejection_reason"], "Downtime window conflicts with a release freeze")

    def test_reject_blank_rejecter_is_rejected(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path)
        with self.assertRaises(ValueError):
            store.reject(record["id"], "   ", "reason", path=self.path)

    def test_reject_unknown_id_raises_key_error(self):
        with self.assertRaises(KeyError):
            store.reject("APR-999", "approver@x.com", "reason", path=self.path)

    def test_mark_staging_validated_records_who_and_when(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path)
        updated = store.mark_staging_validated(record["id"], "tester@x.com", path=self.path, as_of=datetime.date(2026, 8, 1))
        self.assertEqual(updated["staging_validated_by"], "tester@x.com")
        self.assertEqual(updated["staging_validated_at"], "2026-08-01")
        self.assertEqual(updated["status"], "pending")  # doesn't change approval status

    def test_mark_staging_validated_blank_validator_is_rejected(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path)
        with self.assertRaises(ValueError):
            store.mark_staging_validated(record["id"], "   ", path=self.path)

    def test_mark_staging_validated_unknown_id_raises_key_error(self):
        with self.assertRaises(KeyError):
            store.mark_staging_validated("APR-999", "tester@x.com", path=self.path)

    def test_mark_staging_validated_works_even_after_approval(self):
        """Not order-enforced (see the function's own docstring) - a real org's staging
        validation might happen at a different point in its process."""
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path)
        store.approve(record["id"], "approver@x.com", path=self.path)
        updated = store.mark_staging_validated(record["id"], "tester@x.com", path=self.path)
        self.assertEqual(updated["status"], "approved")
        self.assertEqual(updated["staging_validated_by"], "tester@x.com")

    def test_create_request_starts_with_no_staging_validation(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path)
        self.assertIsNone(record["staging_validated_by"])
        self.assertIsNone(record["staging_validated_at"])

    def test_mark_remediation_triggered_from_approved(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path)
        store.approve(record["id"], "approver@x.com", path=self.path, as_of=datetime.date(2026, 8, 1))
        updated = store.mark_remediation_triggered(record["id"], actor="admin@x.com", path=self.path, as_of=datetime.date(2026, 8, 2))
        self.assertEqual(updated["status"], "remediation_triggered")
        self.assertEqual(updated["triggered_by"], "admin@x.com")
        self.assertEqual(updated["triggered_at"], "2026-08-02")
        # The original approval decision is preserved, not overwritten.
        self.assertEqual(updated["approved_by"], "approver@x.com")

    def test_mark_remediation_triggered_requires_approved_status_first(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path)
        with self.assertRaises(ValueError):
            store.mark_remediation_triggered(record["id"], actor="admin@x.com", path=self.path)

    def test_mark_remediation_triggered_rejects_a_rejected_approval(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path)
        store.reject(record["id"], "approver@x.com", "reason", path=self.path)
        with self.assertRaises(ValueError):
            store.mark_remediation_triggered(record["id"], actor="admin@x.com", path=self.path)

    def test_mark_remediation_triggered_unknown_id_raises_key_error(self):
        with self.assertRaises(KeyError):
            store.mark_remediation_triggered("APR-999", actor="admin@x.com", path=self.path)

    def test_compute_status_stays_remediation_triggered_even_after_window_passes(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path)
        store.approve(record["id"], "approver@x.com", path=self.path)
        store.mark_remediation_triggered(record["id"], actor="admin@x.com", path=self.path)
        updated = store.load_approvals(self.path)[0]
        self.assertEqual(store.compute_status(updated, as_of=datetime.date(2099, 1, 1)), "remediation_triggered")

    def test_compute_status_pending_before_window(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path)
        self.assertEqual(store.compute_status(record, as_of=datetime.date(2026, 8, 1)), "pending")

    def test_compute_status_expired_after_window_with_no_decision(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path)
        self.assertEqual(store.compute_status(record, as_of=datetime.date(2026, 9, 1)), "expired")

    def test_compute_status_stays_approved_even_after_window_passes(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path)
        store.approve(record["id"], "approver@x.com", path=self.path)
        updated = store.load_approvals(self.path)[0]
        self.assertEqual(store.compute_status(updated, as_of=datetime.date(2026, 9, 1)), "approved")

    def test_list_with_status_attaches_computed_status_without_mutating_file(self):
        store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path)
        listed = store.list_approvals_with_status(path=self.path, as_of=datetime.date(2026, 9, 1))
        self.assertEqual(listed[0]["computed_status"], "expired")
        raw = store.load_approvals(self.path)
        self.assertEqual(raw[0]["status"], "pending")  # expiry is never written back

    def test_approvals_by_finding_keeps_most_recent_per_finding(self):
        store.create_approval_request("FIND-1", "a@x.com", WINDOW, path=self.path, as_of=datetime.date(2026, 8, 1))
        store.create_approval_request("FIND-1", "b@x.com", WINDOW, path=self.path, as_of=datetime.date(2026, 8, 2))
        by_finding = store.approvals_by_finding(path=self.path)
        self.assertEqual(by_finding["FIND-1"]["requested_by"], "b@x.com")


class RealSeedFileIsValid(unittest.TestCase):
    """The shipped remediation_approvals.json should always parse as a well-formed,
    empty-by-default list - no fabricated approval history is ever seeded."""

    def test_shipped_approvals_file_is_well_formed(self):
        approvals = store.load_approvals()
        self.assertIsInstance(approvals, list)
        for record in approvals:
            for field in ("id", "finding_id", "requested_by", "scheduled_window",
                          "created_on", "status", "ad_group_validated"):
                self.assertIn(field, record)


if __name__ == "__main__":
    unittest.main()
