"""Tests for remediation/verification/closed_loop.py."""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.verification import closed_loop  # noqa: E402


def appr(id_="A-1", fid="FIND-1", status="remediation_triggered", triggered="2026-08-10"):
    return {"id": id_, "finding_id": fid, "status": status, "triggered_at": triggered}


class ClosedLoopTests(unittest.TestCase):
    def test_not_triggered_is_not_assessed(self):
        self.assertEqual(closed_loop.verify_approval(appr(status="approved"), {})["state"], "not-triggered")

    def test_finding_gone_is_verified_with_an_honest_caveat(self):
        v = closed_loop.verify_approval(appr(), {})
        self.assertEqual(v["state"], "verified")
        self.assertIn("scan scope", v["detail"])

    def test_seen_on_or_after_trigger_is_still_present(self):
        for last in ("2026-08-10", "2026-08-20"):
            v = closed_loop.verify_approval(appr(), {"FIND-1": {"id": "FIND-1", "last_seen": last}})
            self.assertEqual(v["state"], "still-present", last)

    def test_seen_only_before_trigger_means_awaiting_rescan(self):
        v = closed_loop.verify_approval(appr(), {"FIND-1": {"id": "FIND-1", "last_seen": "2026-08-02"}})
        self.assertEqual(v["state"], "awaiting-rescan")

    def test_verify_all_summarises(self):
        out = closed_loop.verify_all(
            [appr("A-1", "FIND-1"), appr("A-2", "FIND-2"), appr("A-3", "FIND-3", status="pending")],
            [{"id": "FIND-2", "last_seen": "2026-08-01"}])
        self.assertEqual(out["summary"], {"verified": 1, "still-present": 0, "awaiting-rescan": 1, "not-triggered": 1})

    def test_evidence_pack_is_self_contained(self):
        pack = closed_loop.evidence_pack(appr(), {"id": "FIND-1", "title": "t", "asset": {"name": "h"}}, "# playbook",
                                         {"passed": True, "errors": [], "warnings": []}, {"state": "verified"})
        self.assertEqual(pack["approval"]["finding_id"], "FIND-1")
        self.assertEqual(pack["playbook"]["content"], "# playbook")
        self.assertEqual(pack["verification"]["state"], "verified")
        self.assertIsNone(closed_loop.evidence_pack(appr(), None, None, None, {})["playbook"])


if __name__ == "__main__":
    unittest.main()


class MetricsTests(unittest.TestCase):
    def test_no_data_means_none_not_zero(self):
        m = closed_loop.outcome_metrics([], [])
        self.assertIsNone(m["avg_days_request_to_approval"])
        self.assertIsNone(m["fix_hold_rate"])

    def test_averages_and_hold_rate(self):
        a = [{"id": "1", "created_on": "2026-08-01", "approved_at": "2026-08-03", "triggered_at": "2026-08-05"},
             {"id": "2", "created_on": "2026-08-01", "approved_at": "2026-08-05", "triggered_at": "2026-08-09"},
             {"id": "3", "created_on": "2026-08-01", "approved_at": None, "triggered_at": None}]
        v = [{"approval_id": "1", "state": "verified"}, {"approval_id": "2", "state": "still-present"}]
        m = closed_loop.outcome_metrics(a, v)
        self.assertEqual((m["requests"], m["approved"], m["triggered"]), (3, 2, 2))
        self.assertEqual(m["avg_days_request_to_approval"], 3.0)
        self.assertEqual(m["avg_days_request_to_trigger"], 6.0)
        self.assertEqual((m["assessed_after_rescan"], m["fix_hold_rate"]), (2, 0.5))
