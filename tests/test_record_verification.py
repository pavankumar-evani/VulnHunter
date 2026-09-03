"""
Tests for remediation/audit/record_verification.py - the /vulnhunt --verify pipeline
step's real activity-log write. Same in-memory-engine pattern as test_activity_log.py.
"""
import sys
import unittest
from pathlib import Path

from sqlalchemy import create_engine

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.audit import activity_log, record_verification  # noqa: E402


class RecordVerification(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")

    def tearDown(self):
        self.engine.dispose()

    def test_resolved_status_round_trips(self):
        entry = record_verification.record_verification(
            "VULN-3", "vulnhunter/auto-fixes-20260901", "resolved", "SQLi pattern no longer present",
            engine=self.engine,
        )
        self.assertEqual(entry["action"], "vulnhunt.verify")
        self.assertEqual(entry["target"], "VULN-3")
        self.assertEqual(entry["details"]["branch"], "vulnhunter/auto-fixes-20260901")
        self.assertEqual(entry["details"]["status"], "resolved")
        logged = activity_log.list_activity(self.engine)
        self.assertEqual(logged, [entry])

    def test_invalid_status_raises_without_writing_anything(self):
        with self.assertRaises(ValueError):
            record_verification.record_verification("VULN-3", "some-branch", "not-a-real-status", engine=self.engine)
        self.assertEqual(activity_log.list_activity(self.engine), [])

    def test_default_actor_identifies_the_pipeline(self):
        entry = record_verification.record_verification("VULN-1", "branch-x", "still-present", engine=self.engine)
        self.assertEqual(entry["actor"], "vulnhunt-verify")


if __name__ == "__main__":
    unittest.main()
