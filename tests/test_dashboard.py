"""
Tests for the dashboard (data.py parsing logic + app.py routes).

Uses Flask's test client, which calls the WSGI app directly in-process - no real HTTP
server, no network, and no Claude API calls. The one route that can trigger a real API
call (/run, POST with confirm=on) is tested only with confirm omitted (dry-run), matching
the same "never spend real credits in a test" rule as tests/test_cli.py.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
sys.path.insert(0, str(REPO_ROOT / "cli"))

import data as dashboard_data  # noqa: E402
from app import app as flask_app  # noqa: E402


class DataLayerReadsRealArtifacts(unittest.TestCase):
    """These mirror tests/test_pipeline_artifacts.py's expectations - the dashboard's
    parser must agree with the pipeline's own test suite about what the artifacts say."""

    def test_vulnhunt_data_matches_known_totals(self):
        vh = dashboard_data.load_vulnhunt_data()
        self.assertTrue(vh["available"])
        self.assertEqual(vh["total"], 9)
        self.assertEqual(vh["auto_fixable"], 6)

    def test_remediation_findings_match_known_total(self):
        findings = dashboard_data.load_remediation_findings()
        self.assertEqual(len(findings), 11)

    def test_remediation_plan_queue_matches_findings_count(self):
        plan = dashboard_data.load_remediation_plan()
        self.assertTrue(plan["available"])
        self.assertEqual(len(plan["queue"]), 11)

    def test_risk_tier_counts_match_known_split(self):
        plan = dashboard_data.load_remediation_plan()
        self.assertEqual(plan["risk_tier_counts"].get("auto-approvable"), 2)
        self.assertEqual(plan["risk_tier_counts"].get("needs-change-approval"), 5)
        self.assertEqual(plan["risk_tier_counts"].get("manual-only"), 4)

    def test_playbooks_match_known_count(self):
        playbooks = dashboard_data.load_playbooks()
        self.assertEqual(len(playbooks), 7)

    def test_no_mojibake_in_parsed_text(self):
        """Regression guard for the subprocess-encoding bug: git output must be decoded
        as UTF-8, not the platform default, or characters like em-dash corrupt into
        mojibake ('â€”')."""
        vh = dashboard_data.load_vulnhunt_data()
        self.assertNotIn("â€”", vh["title"])
        plan = dashboard_data.load_remediation_plan()
        self.assertNotIn("â€”", plan["title"])


class DashboardRoutesRender(unittest.TestCase):
    def setUp(self):
        flask_app.testing = True
        self.client = flask_app.test_client()

    def test_overview_page_loads(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Security Posture Overview", resp.data)

    def test_vulnhunt_page_lists_all_findings(self):
        resp = self.client.get("/vulnhunt")
        self.assertEqual(resp.status_code, 200)
        for i in range(1, 10):
            self.assertIn(f"VULN-{i}".encode(), resp.data)

    def test_remediate_page_lists_all_findings(self):
        resp = self.client.get("/remediate")
        self.assertEqual(resp.status_code, 200)
        for i in range(1, 12):
            self.assertIn(f"FIND-{i}".encode(), resp.data)

    def test_playbook_detail_page_loads(self):
        resp = self.client.get("/playbooks/FIND-4-sudo-baron-samedit-patch.yml")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Auto-approvable", resp.data)

    def test_unknown_playbook_returns_404(self):
        resp = self.client.get("/playbooks/does-not-exist.yml")
        self.assertEqual(resp.status_code, 404)

    def test_run_page_loads(self):
        resp = self.client.get("/run")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Run a Pipeline", resp.data)

    def test_dry_run_post_never_calls_real_api(self):
        """The critical safety test: submitting the run form WITHOUT the confirm
        checkbox must never spend real API usage, and must say so."""
        resp = self.client.post("/run", data={
            "pipeline": "scan",
            "path": "vulnerable-demo-app",
            "max_budget_usd": "2.00",
            # confirm intentionally omitted -> must stay a dry run
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Dry run only", resp.data)

    def test_api_status_endpoint(self):
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        payload = resp.get_json()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["vulnhunt_findings"], 9)
        self.assertEqual(payload["remediation_findings"], 11)


if __name__ == "__main__":
    unittest.main()
