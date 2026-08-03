"""
Tests for the dashboard: the JSON API (dashboard/app.py's FastAPI routes) and the
data layer (dashboard/data.py). Uses FastAPI's TestClient (Starlette's, in-process
ASGI calls - no real HTTP server, no network, no Claude API calls). The one route
that can trigger a real API call (/api/run, POST with confirm=true) is tested only
with confirm omitted (dry-run), matching the same "never spend real credits in a
test" rule as tests/test_cli.py.

The frontend is a client-rendered single-page app (static/js/*.js, no server-side
templating) - dashboard/app.py serves the same static/index.html shell for every
page route, and the JS router fills in content after fetching from the JSON API.
That means these tests validate the JSON contract precisely rather than grepping
rendered HTML for substrings (there is no rendered HTML to grep server-side - the
DOM is built by JavaScript in a browser). The actual rendering (sidebar nav, tables,
KPI cards, client-side sort, forms) was verified live in a browser during
development - see KNOWLEDGE_TRANSFER.md - not by this Python suite, which cannot
execute JavaScript.
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

from fastapi.testclient import TestClient  # noqa: E402

import data as dashboard_data  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from remediation.config import priority_engine  # noqa: E402

client = TestClient(fastapi_app)


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


class ApiOverview(unittest.TestCase):
    def test_overview_returns_expected_shape_and_counts(self):
        resp = client.get("/api/overview")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["vulnhunt"]["total"], 9)
        self.assertEqual(payload["vulnhunt"]["auto_fixable"], 6)
        self.assertEqual(payload["remediation"]["total"], 14)
        self.assertEqual(payload["playbook_count"], 7)
        self.assertEqual(payload["kev_count"], 6)
        self.assertEqual(payload["high_epss_count"], 7)
        for key in ("breached", "at_risk", "on_track"):
            self.assertIn(key, payload["sla"])
        for asset_type in ("windows-server", "unix-server", "application", "certificate"):
            self.assertIn(asset_type, payload["asset_type_breakdown"])


class ApiVulnhunt(unittest.TestCase):
    def test_lists_all_nine_findings(self):
        resp = client.get("/api/vulnhunt")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertTrue(payload["available"])
        ids = {f["ID"] for f in payload["findings"]}
        self.assertEqual(ids, {f"VULN-{i}" for i in range(1, 10)})


class ApiRemediate(unittest.TestCase):
    def test_lists_all_fourteen_findings_and_playbook_links(self):
        resp = client.get("/api/remediate")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(len(payload["findings"]), 14)
        ids = {row["ID"] for row in payload["plan"]["queue"]}
        self.assertEqual(ids, {f"FIND-{i}" for i in range(1, 15)})
        self.assertEqual(len(payload["playbooks_by_finding"]), 7)


class ApiPlaybookDetail(unittest.TestCase):
    def test_known_playbook_matches_file_contents(self):
        filename = "FIND-4-sudo-baron-samedit-patch.yml"
        path = REPO_ROOT / "remediation" / "output" / filename
        expected_needs_approval = "CHANGE APPROVAL REQUIRED" in path.read_text(encoding="utf-8")

        resp = client.get(f"/api/playbooks/{filename}")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["finding_id"], "FIND-4")
        self.assertEqual(payload["needs_approval"], expected_needs_approval)

    def test_unknown_playbook_returns_404(self):
        resp = client.get("/api/playbooks/does-not-exist.yml")
        self.assertEqual(resp.status_code, 404)


class ApiRunPipeline(unittest.TestCase):
    def test_get_returns_default_budget_and_audit_log_shape(self):
        resp = client.get("/api/run")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertIn("default_budget", payload)
        self.assertIsInstance(payload["audit_log"], list)

    def test_dry_run_post_never_calls_real_api(self):
        """The critical safety test: submitting without confirm must never spend real
        API usage, and must say so."""
        resp = client.post("/api/run", json={
            "pipeline": "scan",
            "path": "vulnerable-demo-app",
            "max_budget_usd": "2.00",
            # confirm intentionally omitted (defaults to False) -> must stay a dry run
        })
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertTrue(payload["dry_run"])
        self.assertIn("Dry run only", payload["message"])

    def test_unknown_pipeline_rejected(self):
        resp = client.post("/api/run", json={"pipeline": "not-a-real-pipeline"})
        self.assertEqual(resp.status_code, 400)


class ApiStatus(unittest.TestCase):
    def test_status_endpoint(self):
        resp = client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["vulnhunt_findings"], 9)
        self.assertEqual(payload["remediation_findings"], 14)


class ApiLiveQueue(unittest.TestCase):
    def test_queue_lists_all_findings_sorted_by_priority(self):
        resp = client.get("/api/queue")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        ids = {f["id"] for f in payload["findings"]}
        self.assertEqual(ids, {f"FIND-{i}" for i in range(1, 15)})

        rank = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
        ranks = [rank[f["priority"]] for f in payload["findings"]]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_queue_shows_sla_and_attack_tags(self):
        resp = client.get("/api/queue")
        payload = resp.json()
        self.assertTrue(any(f["sla"].get("breached") for f in payload["findings"]))
        all_technique_ids = {
            t["technique_id"]
            for f in payload["findings"]
            for t in f.get("attack_techniques", [])
        }
        self.assertIn("T1210", all_technique_ids)  # PrintNightmare/Log4Shell-style RCE


class ApiPriorityRules(unittest.TestCase):
    """Every test here uses a temporary rules file (via patching DEFAULT_RULES_PATH) so
    the suite never permanently mutates the real, shipped priority_rules.yaml."""

    def setUp(self):
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

    def test_get_returns_current_rules_text(self):
        resp = client.get("/api/priority-rules")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("sla_days", resp.json()["rules_text"])

    def test_post_valid_yaml_saves(self):
        new_text = self.tmp_rules_path.read_text(encoding="utf-8").replace("Medium: 30", "Medium: 5")
        resp = client.post("/api/priority-rules", json={"rules_text": new_text})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("saved", resp.json()["message"])
        self.assertIn("Medium: 5", self.tmp_rules_path.read_text(encoding="utf-8"))

    def test_post_invalid_yaml_is_rejected_and_file_unchanged(self):
        original = self.tmp_rules_path.read_text(encoding="utf-8")
        resp = client.post("/api/priority-rules", json={"rules_text": "not: valid: yaml: ["})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("invalid YAML", resp.json()["detail"])
        self.assertEqual(self.tmp_rules_path.read_text(encoding="utf-8"), original)


class ApiServiceNow(unittest.TestCase):
    def test_preview_lists_every_finding_with_no_credentials_needed(self):
        resp = client.get("/api/servicenow/preview")
        self.assertEqual(resp.status_code, 200)
        previews = resp.json()["previews"]
        self.assertEqual({p["finding_id"] for p in previews}, {f"FIND-{i}" for i in range(1, 15)})

    def test_send_without_confirm_never_touches_the_network(self):
        """The critical safety test, mirroring /api/run's dry-run guarantee: submitting
        without confirm must never call ServiceNowConnector's network methods,
        regardless of what credentials are entered."""
        resp = client.post("/api/servicenow/send", json={
            "instance": "mycompany", "username": "u", "password": "p", "table": "incident",
            # confirm intentionally omitted (defaults to False)
        })
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertTrue(payload["preview_only"])
        self.assertIsNone(payload["results"])

    def test_send_with_confirm_but_missing_credentials_is_rejected(self):
        resp = client.post("/api/servicenow/send", json={
            "instance": "", "username": "", "password": "", "table": "incident", "confirm": True,
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("required", resp.json()["detail"])


class HtmlShellRoutesServeTheSpaShell(unittest.TestCase):
    """The frontend is a single static/index.html shell served for every page route;
    static/js/app.js reads window.location.pathname client-side and calls the JSON
    API above to render each page. These tests confirm the shell is served correctly
    (and only the shell - no server-side templating), not what it renders to."""

    SHELL_ROUTES = ["/", "/vulnhunt", "/remediate", "/run", "/queue", "/priority-rules", "/servicenow"]

    def test_every_known_route_serves_the_same_spa_shell(self):
        bodies = set()
        for route in self.SHELL_ROUTES:
            resp = client.get(route)
            self.assertEqual(resp.status_code, 200, route)
            self.assertIn("text/html", resp.headers["content-type"])
            self.assertIn('<script type="module" src="/static/js/app.js">', resp.text)
            bodies.add(resp.text)
        self.assertEqual(len(bodies), 1)  # byte-identical shell for every route

    def test_playbook_detail_route_also_serves_the_shell(self):
        resp = client.get("/playbooks/FIND-4-sudo-baron-samedit-patch.yml")
        self.assertEqual(resp.status_code, 200)
        self.assertIn('id="app"', resp.text)

    def test_unknown_route_still_serves_the_shell(self):
        """A stale bookmark or typo'd URL gets the SPA shell too, so app.js's router can
        render a styled 'Page not found' instead of a bare {"detail":"Not Found"} blob -
        this is the client-side-routing-friendly fallback, registered last in app.py so
        /api/* and /static/* (tested below) still take priority and 404 properly."""
        resp = client.get("/this-route-does-not-exist")
        self.assertEqual(resp.status_code, 200)
        self.assertIn('<script type="module" src="/static/js/app.js">', resp.text)

    def test_unknown_api_route_returns_a_real_404(self):
        resp = client.get("/api/this-does-not-exist")
        self.assertEqual(resp.status_code, 404)

    def test_unknown_static_asset_returns_a_real_404(self):
        resp = client.get("/static/this-does-not-exist.js")
        self.assertEqual(resp.status_code, 404)

    def test_static_assets_are_served(self):
        css = client.get("/static/style.css")
        self.assertEqual(css.status_code, 200)
        js = client.get("/static/js/app.js")
        self.assertEqual(js.status_code, 200)
        self.assertIn("renderRoute", js.text)


if __name__ == "__main__":
    unittest.main()
