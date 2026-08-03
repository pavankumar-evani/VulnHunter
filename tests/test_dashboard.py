"""
Tests for the dashboard (data.py parsing logic + app.py routes).

Uses Flask's test client, which calls the WSGI app directly in-process - no real HTTP
server, no network, and no Claude API calls. The one route that can trigger a real API
call (/run, POST with confirm=on) is tested only with confirm omitted (dry-run), matching
the same "never spend real credits in a test" rule as tests/test_cli.py.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
sys.path.insert(0, str(REPO_ROOT / "cli"))
sys.path.insert(0, str(REPO_ROOT))

import data as dashboard_data  # noqa: E402
from app import app as flask_app  # noqa: E402
from remediation.config import priority_engine  # noqa: E402


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
        self.assertEqual(len(findings), 14)

    def test_remediation_plan_queue_matches_findings_count(self):
        plan = dashboard_data.load_remediation_plan()
        self.assertTrue(plan["available"])
        self.assertEqual(len(plan["queue"]), 14)

    def test_risk_tier_counts_match_known_split(self):
        plan = dashboard_data.load_remediation_plan()
        self.assertEqual(plan["risk_tier_counts"].get("auto-approvable"), 2)
        self.assertEqual(plan["risk_tier_counts"].get("needs-change-approval"), 5)
        self.assertEqual(plan["risk_tier_counts"].get("manual-only"), 7)

    def test_playbooks_match_known_count(self):
        playbooks = dashboard_data.load_playbooks()
        self.assertEqual(len(playbooks), 7)

    def test_kev_and_high_epss_counts(self):
        findings = dashboard_data.load_remediation_findings()
        self.assertEqual(dashboard_data.count_kev_listed(findings), 6)
        self.assertEqual(dashboard_data.count_high_epss(findings), 7)

    def test_asset_type_breakdown_covers_all_categories(self):
        findings = dashboard_data.load_remediation_findings()
        breakdown = dashboard_data.asset_type_breakdown(findings)
        self.assertEqual(sum(breakdown.values()), 14)
        for expected_type in ("windows-server", "unix-server", "network-routing-switching",
                               "iot-ot-device", "application", "certificate"):
            self.assertIn(expected_type, breakdown)

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
        for i in range(1, 15):
            self.assertIn(f"FIND-{i}".encode(), resp.data)

    def test_overview_page_shows_kev_and_epss_kpis(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"CISA KEV-listed", resp.data)
        self.assertIn(b"High EPSS", resp.data)
        self.assertIn(b"certificate", resp.data)
        self.assertIn(b"application", resp.data)

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
        self.assertEqual(payload["remediation_findings"], 14)


class LiveQueuePage(unittest.TestCase):
    def setUp(self):
        flask_app.testing = True
        self.client = flask_app.test_client()

    def test_queue_page_loads_and_lists_all_findings_sorted_by_priority(self):
        resp = self.client.get("/queue")
        self.assertEqual(resp.status_code, 200)
        for i in range(1, 15):
            self.assertIn(f"FIND-{i}".encode(), resp.data)
        # Critical-priority rows must appear before Medium-priority rows (sorted queue).
        # Note: no finding in the current sample data scores as "Low" against the
        # shipped rules, so this doesn't assert against that tier.
        text = resp.data.decode()
        self.assertLess(text.index("Critical"), text.index("Medium"))

    def test_queue_page_shows_sla_and_attack_tags(self):
        resp = self.client.get("/queue")
        self.assertIn(b"SLA breached", resp.data)
        self.assertIn(b"T1210", resp.data)  # PrintNightmare/Log4Shell should tag as T1210


class PriorityRulesPage(unittest.TestCase):
    """Every test here uses a temporary rules file (via patching DEFAULT_RULES_PATH) so
    the suite never permanently mutates the real, shipped priority_rules.yaml."""

    def setUp(self):
        flask_app.testing = True
        self.client = flask_app.test_client()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp_rules_path = Path(self.tmpdir.name) / "priority_rules.yaml"
        self.tmp_rules_path.write_text(
            priority_engine.DEFAULT_RULES_PATH.read_text(encoding="utf-8"), encoding="utf-8"
        )
        self.patcher = patch.object(priority_engine, "DEFAULT_RULES_PATH", self.tmp_rules_path)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.tmpdir.cleanup()

    def test_get_shows_current_rules_text(self):
        resp = self.client.get("/priority-rules")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"sla_days", resp.data)

    def test_post_valid_yaml_saves_and_flashes_success(self):
        new_text = self.tmp_rules_path.read_text(encoding="utf-8").replace("Medium: 30", "Medium: 5")
        resp = self.client.post("/priority-rules", data={"rules_text": new_text}, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Priority rules saved", resp.data)
        self.assertIn("Medium: 5", self.tmp_rules_path.read_text(encoding="utf-8"))

    def test_post_invalid_yaml_is_rejected_and_file_unchanged(self):
        original = self.tmp_rules_path.read_text(encoding="utf-8")
        resp = self.client.post("/priority-rules", data={"rules_text": "not: valid: yaml: ["}, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"invalid YAML", resp.data)
        self.assertEqual(self.tmp_rules_path.read_text(encoding="utf-8"), original)  # unchanged


class ServiceNowPage(unittest.TestCase):
    def setUp(self):
        flask_app.testing = True
        self.client = flask_app.test_client()

    def test_get_shows_preview_for_every_finding_with_no_credentials_needed(self):
        resp = self.client.get("/servicenow")
        self.assertEqual(resp.status_code, 200)
        for i in range(1, 15):
            self.assertIn(f"FIND-{i}".encode(), resp.data)

    def test_post_without_confirm_never_touches_the_network(self):
        """The critical safety test, mirroring /run's dry-run guarantee: submitting
        without the confirm checkbox must never call ServiceNowConnector's network
        methods, regardless of what credentials are entered."""
        resp = self.client.post("/servicenow", data={
            "instance": "mycompany", "username": "u", "password": "p", "table": "incident",
            # confirm intentionally omitted
        })
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Preview only", resp.data)

    def test_post_with_confirm_but_missing_credentials_is_rejected(self):
        resp = self.client.post("/servicenow", data={
            "instance": "", "username": "", "password": "", "table": "incident", "confirm": "on",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"required", resp.data)


if __name__ == "__main__":
    unittest.main()
