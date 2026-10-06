"""Integrity API: admin only, confirm gate, readyz summary that never fails readiness, CLI."""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard"))

from fastapi.testclient import TestClient  # noqa: E402

import app as dash  # noqa: E402

ADMIN = {"email": "admin@example.test", "name": "A", "role": "admin"}
USER = {"email": "user@example.test", "name": "U", "role": "user"}
REPORT = {"checked_at": "2026-10-06T12:00:00Z", "status": "ok", "counts": {"ok": 1, "info": 0, "warn": 0, "fail": 0}, "checks": [], "fixable": [],
          "manifest": {"state": "no-baseline"}, "code_state": "no-baseline", "host": "h"}


def _clear():
    dash._LOGIN_FAIL_PER_ACCOUNT._hits.clear()
    dash._LOGIN_FAIL_PER_ADDRESS._hits.clear()


class IntegrityApiTests(unittest.TestCase):
    def setUp(self):
        _clear()
        self.client = TestClient(dash.app)

    def tearDown(self):
        _clear()

    def _login(self, who):
        with patch.object(dash.auth_users, "verify_login", return_value=who):
            self.assertEqual(self.client.post("/api/auth/login", json={"email": who["email"], "password": "x"}).status_code, 200)

    def test_anonymous_and_non_admin_are_refused(self):
        self.assertEqual(self.client.get("/api/integrity").status_code, 401)
        self.assertEqual(self.client.post("/api/integrity/heal", json={"confirm": True}).status_code, 401)
        self._login(USER)
        self.assertEqual(self.client.get("/api/integrity").status_code, 403)
        self.assertEqual(self.client.post("/api/integrity/heal", json={"confirm": True}).status_code, 403)

    def test_admin_gets_the_report_with_heal_actions(self):
        self._login(ADMIN)
        with patch.object(dash.integrity_service, "full_report", return_value=dict(REPORT)):
            r = self.client.get("/api/integrity")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["code_state"], "no-baseline")
        self.assertEqual(set(r.json()["heal_actions"]), {"remove_stale_locks", "restore_findings_from_bak", "recreate_missing_tables", "rebuild_file_snapshots"})

    def test_heal_defaults_to_preview(self):
        self._login(ADMIN)
        with patch.object(dash.integrity_heal, "run", return_value={"preview": True, "results": [], "unknown": [], "manual": [], "after": {}}) as run, \
                patch.object(dash.integrity_service, "full_report", return_value=dict(REPORT)):
            r = self.client.post("/api/integrity/heal", json={})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(run.call_args.kwargs["confirm"])

    def test_heal_confirm_is_passed_through_with_the_actor(self):
        self._login(ADMIN)
        with patch.object(dash.integrity_heal, "run", return_value={"preview": False, "results": [], "unknown": [], "manual": [], "after": {}}) as run, \
                patch.object(dash.integrity_service, "full_report", return_value=dict(REPORT)):
            self.client.post("/api/integrity/heal", json={"confirm": True, "actions": ["remove_stale_locks"]})
        self.assertTrue(run.call_args.kwargs["confirm"])
        self.assertEqual(run.call_args.kwargs["actor"], "admin@example.test")
        self.assertEqual(run.call_args.kwargs["actions"], ["remove_stale_locks"])

    def test_unknown_action_is_a_400_and_runs_nothing(self):
        self._login(ADMIN)
        with patch.object(dash.integrity_heal, "run") as run:
            r = self.client.post("/api/integrity/heal", json={"confirm": True, "actions": ["rm_rf"]})
        self.assertEqual(r.status_code, 400)
        run.assert_not_called()

    def test_readyz_reports_integrity_but_warnings_never_fail_readiness(self):
        bad = {"status": "fail", "checked_at": "t", "counts": {}, "code_state": "code-modified", "problems": ["Lock files", "Application code differs from the release baseline"]}
        with patch.object(dash.integrity_service, "last_summary", return_value=bad):
            r = self.client.get("/readyz")
        self.assertIn("integrity", r.json()["checks"])
        self.assertIn("2 issue(s)", r.json()["checks"]["integrity"])
        self.assertEqual(r.json()["status"], "ready")
        with patch.object(dash.integrity_service, "last_summary", return_value=None):
            self.assertEqual(self.client.get("/readyz").json()["checks"]["integrity"], "not checked yet")

    def test_scheduler_hook_respects_the_env_switch(self):
        os.environ["QUANTA_INTEGRITY_CHECKS"] = "false"
        try:
            self.assertIsNone(dash._run_integrity_checks_if_due())
        finally:
            os.environ.pop("QUANTA_INTEGRITY_CHECKS")


class CliTests(unittest.TestCase):
    def test_parser_has_the_commands_and_confirm_needs_heal(self):
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cli"))
        import quanta_admin
        p = quanta_admin.build_parser()
        a = p.parse_args(["check-integrity", "--heal", "--confirm"])
        self.assertTrue(a.heal and a.confirm)
        self.assertFalse(p.parse_args(["check-integrity"]).heal)
        self.assertEqual(p.parse_args(["integrity-manifest", "--out", "x.json"]).out, "x.json")


if __name__ == "__main__":
    unittest.main()
