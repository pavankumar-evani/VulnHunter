"""
Tests for remediation/remediation_approvals/store.py - the human-in-the-loop
approve/reject workflow for normal/emergency change-type findings. Every test uses a
fresh in-memory SQLite engine (never the real, shared remediation/vulnhunter.db) so the
suite never mutates real data - same pattern as test_exceptions_store.py.
"""
import datetime
import sys
import unittest
from pathlib import Path

from sqlalchemy import create_engine

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.remediation_approvals import store  # noqa: E402

WINDOW = {"date": "2026-08-08", "day_of_week": "saturday", "start_time": "23:00", "end_time": "03:00", "timezone": "UTC"}


class ApprovalLifecycle(unittest.TestCase):
    """create_approval_request/approve/reject also write to the real, shared activity
    log (see remediation/audit/activity_log.py) - passing the same test engine through
    means those writes land in this test's isolated in-memory DB too, not the real one."""

    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")

    def tearDown(self):
        self.engine.dispose()

    def test_load_from_missing_file_returns_empty_list(self):
        self.assertEqual(store.load_approvals(self.engine), [])

    def test_create_request_persists_and_returns_a_full_record(self):
        record = store.create_approval_request(
            "FIND-1", "requester@example.com", WINDOW, engine=self.engine, as_of=datetime.date(2026, 8, 1),
        )
        self.assertEqual(record["id"], "APR-1")
        self.assertEqual(record["finding_id"], "FIND-1")
        self.assertEqual(record["status"], "pending")
        self.assertEqual(record["created_on"], "2026-08-01")
        self.assertIsNone(record["ad_group_validated"])
        self.assertEqual(store.load_approvals(self.engine), [record])

    def test_ids_increment_across_multiple_requests(self):
        store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine, as_of=datetime.date(2026, 8, 1))
        second = store.create_approval_request("FIND-2", "a@x.com", WINDOW, engine=self.engine, as_of=datetime.date(2026, 8, 1))
        self.assertEqual(second["id"], "APR-2")

    def test_concurrent_create_approval_request_calls_never_lose_a_real_request(self):
        """Real threads, real filesystem lock - proves create_approval_request()'s
        file-lock actually serializes its read-modify-write cycle, so two requests
        filed at nearly the same real moment don't race on the next APR-N id and
        silently drop one of them. Uses a shared on-disk (not :memory:) engine because
        SQLite's :memory: databases aren't shared across threads/connections."""
        import tempfile
        import threading

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = create_engine(f"sqlite:///{Path(tmpdir) / 'test.db'}")

            def create_one(n):
                store.create_approval_request(f"FIND-{n}", "a@x.com", WINDOW, engine=engine, as_of=datetime.date(2026, 8, 1))

            threads = [threading.Thread(target=create_one, args=(n,)) for n in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            approvals = store.load_approvals(engine)
            self.assertEqual(len(approvals), 20)
            self.assertEqual(len({a["id"] for a in approvals}), 20)  # every id genuinely unique
            # Windows won't delete a file a pooled connection still has open - dispose
            # releases every connection in the pool before the tmpdir cleanup below.
            engine.dispose()

    def test_missing_finding_id_is_rejected(self):
        with self.assertRaises(ValueError):
            store.create_approval_request("", "a@x.com", WINDOW, engine=self.engine)

    def test_blank_requester_is_rejected(self):
        with self.assertRaises(ValueError):
            store.create_approval_request("FIND-1", "   ", WINDOW, engine=self.engine)

    def test_approve_sets_status_and_ad_validation_result(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine, as_of=datetime.date(2026, 8, 1))
        updated = store.approve(record["id"], "approver@x.com", ad_group_validated=True, engine=self.engine, as_of=datetime.date(2026, 8, 2))
        self.assertEqual(updated["status"], "approved")
        self.assertEqual(updated["approved_by"], "approver@x.com")
        self.assertEqual(updated["approved_at"], "2026-08-02")
        self.assertTrue(updated["ad_group_validated"])

    def test_approve_with_ad_not_configured_stores_none_not_false(self):
        """None ('AD not configured, we didn't check') must never collapse into False
        ('checked and the user failed the check') - see the store's own docstring."""
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine)
        updated = store.approve(record["id"], "approver@x.com", ad_group_validated=None, engine=self.engine)
        self.assertIsNone(updated["ad_group_validated"])
        self.assertEqual(updated["status"], "approved")

    def test_approve_blank_approver_is_rejected(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine)
        with self.assertRaises(ValueError):
            store.approve(record["id"], "   ", engine=self.engine)

    def test_approve_unknown_id_raises_key_error(self):
        with self.assertRaises(KeyError):
            store.approve("APR-999", "approver@x.com", engine=self.engine)

    def test_reject_sets_status_and_reason(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine, as_of=datetime.date(2026, 8, 1))
        updated = store.reject(record["id"], "approver@x.com", "Downtime window conflicts with a release freeze", engine=self.engine, as_of=datetime.date(2026, 8, 2))
        self.assertEqual(updated["status"], "rejected")
        self.assertEqual(updated["rejected_by"], "approver@x.com")
        self.assertEqual(updated["rejected_at"], "2026-08-02")
        self.assertEqual(updated["rejection_reason"], "Downtime window conflicts with a release freeze")

    def test_reject_blank_rejecter_is_rejected(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine)
        with self.assertRaises(ValueError):
            store.reject(record["id"], "   ", "reason", engine=self.engine)

    def test_reject_unknown_id_raises_key_error(self):
        with self.assertRaises(KeyError):
            store.reject("APR-999", "approver@x.com", "reason", engine=self.engine)

    def test_mark_staging_validated_records_who_and_when(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine)
        updated = store.mark_staging_validated(record["id"], "tester@x.com", engine=self.engine, as_of=datetime.date(2026, 8, 1))
        self.assertEqual(updated["staging_validated_by"], "tester@x.com")
        self.assertEqual(updated["staging_validated_at"], "2026-08-01")
        self.assertEqual(updated["status"], "pending")  # doesn't change approval status

    def test_mark_staging_validated_blank_validator_is_rejected(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine)
        with self.assertRaises(ValueError):
            store.mark_staging_validated(record["id"], "   ", engine=self.engine)

    def test_mark_staging_validated_unknown_id_raises_key_error(self):
        with self.assertRaises(KeyError):
            store.mark_staging_validated("APR-999", "tester@x.com", engine=self.engine)

    def test_mark_staging_validated_works_even_after_approval(self):
        """Not order-enforced (see the function's own docstring) - a real org's staging
        validation might happen at a different point in its process."""
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine)
        store.approve(record["id"], "approver@x.com", engine=self.engine)
        updated = store.mark_staging_validated(record["id"], "tester@x.com", engine=self.engine)
        self.assertEqual(updated["status"], "approved")
        self.assertEqual(updated["staging_validated_by"], "tester@x.com")

    def test_create_request_starts_with_no_staging_validation(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine)
        self.assertIsNone(record["staging_validated_by"])
        self.assertIsNone(record["staging_validated_at"])

    def test_mark_remediation_triggered_from_approved(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine)
        store.approve(record["id"], "approver@x.com", engine=self.engine, as_of=datetime.date(2026, 8, 1))
        updated = store.mark_remediation_triggered(record["id"], actor="admin@x.com", engine=self.engine, as_of=datetime.date(2026, 8, 2))
        self.assertEqual(updated["status"], "remediation_triggered")
        self.assertEqual(updated["triggered_by"], "admin@x.com")
        self.assertEqual(updated["triggered_at"], "2026-08-02")
        # The original approval decision is preserved, not overwritten.
        self.assertEqual(updated["approved_by"], "approver@x.com")

    def test_mark_remediation_triggered_requires_approved_status_first(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine)
        with self.assertRaises(ValueError):
            store.mark_remediation_triggered(record["id"], actor="admin@x.com", engine=self.engine)

    def test_mark_remediation_triggered_rejects_a_rejected_approval(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine)
        store.reject(record["id"], "approver@x.com", "reason", engine=self.engine)
        with self.assertRaises(ValueError):
            store.mark_remediation_triggered(record["id"], actor="admin@x.com", engine=self.engine)

    def test_mark_remediation_triggered_unknown_id_raises_key_error(self):
        with self.assertRaises(KeyError):
            store.mark_remediation_triggered("APR-999", actor="admin@x.com", engine=self.engine)

    def test_compute_status_stays_remediation_triggered_even_after_window_passes(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine)
        store.approve(record["id"], "approver@x.com", engine=self.engine)
        store.mark_remediation_triggered(record["id"], actor="admin@x.com", engine=self.engine)
        updated = store.load_approvals(self.engine)[0]
        self.assertEqual(store.compute_status(updated, as_of=datetime.date(2099, 1, 1)), "remediation_triggered")

    def test_compute_status_pending_before_window(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine)
        self.assertEqual(store.compute_status(record, as_of=datetime.date(2026, 8, 1)), "pending")

    def test_compute_status_expired_after_window_with_no_decision(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine)
        self.assertEqual(store.compute_status(record, as_of=datetime.date(2026, 9, 1)), "expired")

    def test_compute_status_stays_approved_even_after_window_passes(self):
        record = store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine)
        store.approve(record["id"], "approver@x.com", engine=self.engine)
        updated = store.load_approvals(self.engine)[0]
        self.assertEqual(store.compute_status(updated, as_of=datetime.date(2026, 9, 1)), "approved")

    def test_list_with_status_attaches_computed_status_without_mutating_file(self):
        store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine)
        listed = store.list_approvals_with_status(engine=self.engine, as_of=datetime.date(2026, 9, 1))
        self.assertEqual(listed[0]["computed_status"], "expired")
        raw = store.load_approvals(self.engine)
        self.assertEqual(raw[0]["status"], "pending")  # expiry is never written back

    def test_approvals_by_finding_keeps_most_recent_per_finding(self):
        store.create_approval_request("FIND-1", "a@x.com", WINDOW, engine=self.engine, as_of=datetime.date(2026, 8, 1))
        store.create_approval_request("FIND-1", "b@x.com", WINDOW, engine=self.engine, as_of=datetime.date(2026, 8, 2))
        by_finding = store.approvals_by_finding(engine=self.engine)
        self.assertEqual(by_finding["FIND-1"]["requested_by"], "b@x.com")


if __name__ == "__main__":
    unittest.main()
