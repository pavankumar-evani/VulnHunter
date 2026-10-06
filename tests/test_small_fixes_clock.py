"""Three small robustness fixes: a queued fix whose finding has no title, and clocks that callers can inject."""
import datetime
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine  # noqa: E402

from remediation.devsecops import controls, factory  # noqa: E402
from remediation.grc import policies  # noqa: E402


class SmallFixTests(unittest.TestCase):
    def test_queue_item_for_a_finding_without_title_or_severity_does_not_crash(self):
        tmp = tempfile.TemporaryDirectory()
        engine = create_engine(f"sqlite:///{Path(tmp.name) / 'f.db'}")
        self.addCleanup(tmp.cleanup)
        self.addCleanup(engine.dispose)
        with mock.patch.object(factory, "_stored", return_value={"F-1": {"finding_id": "F-1", "state": "queued"}}):
            rows = factory.items([{"id": "F-1"}], engine=engine)
        self.assertEqual(rows[0]["title"], None)
        self.assertEqual(rows[0]["shown_state"], "queued")

    def test_gate_evidence_uses_the_injected_clock(self):
        ctl = {"id": "vulnerability-gate", "evidence": {"quanta": "gate-runs"}}
        extras = {"gate_runs": {"app": "2026-10-01T00:00:00Z"}}
        near = datetime.datetime(2026, 10, 2, tzinfo=datetime.timezone.utc)
        far = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
        self.assertEqual(controls.control_status(ctl, "app", [], [], [], extras=extras, now=near)["status"], "evidenced")
        self.assertEqual(controls.control_status(ctl, "app", [], [], [], extras=extras, now=far)["status"], "no-evidence")

    def test_policy_review_overdue_uses_the_injected_date(self):
        tmp = tempfile.TemporaryDirectory()
        engine = create_engine(f"sqlite:///{Path(tmp.name) / 'p.db'}")
        try:
            p = policies.create("Acceptable use", "body", "owner@t.local", "owner@t.local", status="active", review_date="2026-06-01", engine=engine)
            pid = p["id"] if isinstance(p, dict) else p
            self.assertFalse(policies.get(pid, engine=engine, today="2026-01-01")["review_overdue"])
            self.assertTrue(policies.get(pid, engine=engine, today="2026-12-01")["review_overdue"])
        finally:
            engine.dispose()
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
