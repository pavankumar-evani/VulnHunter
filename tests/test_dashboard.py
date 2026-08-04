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
import datetime
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
sys.path.insert(0, str(REPO_ROOT / "cli"))
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient  # noqa: E402

import data as dashboard_data  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import rbac as rbac_module  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.config import priority_engine  # noqa: E402
from remediation.exceptions import store as exceptions_store  # noqa: E402
from remediation.inventory import asset_inventory  # noqa: E402

client = TestClient(fastapi_app)

# A temporary, module-scoped user store (never the real, shipped users.json) so every
# test in this file that needs to be logged in can log in as a known admin/user without
# depending on the real demo credentials in dashboard/auth/users.json staying fixed.
TEST_ADMIN_EMAIL = "admin@test.local"
TEST_ADMIN_PASSWORD = "admin-test-password-1"
TEST_USER_EMAIL = "user@test.local"
TEST_USER_PASSWORD = "user-test-password-1"

_auth_tmpdir = None
_auth_patcher = None


def setUpModule():
    global _auth_tmpdir, _auth_patcher
    _auth_tmpdir = tempfile.TemporaryDirectory()
    tmp_users_path = Path(_auth_tmpdir.name) / "users.json"
    _auth_patcher = patch.object(auth_users, "DEFAULT_USERS_PATH", tmp_users_path)
    _auth_patcher.start()
    auth_users.create_user(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD, "Test Admin", role="admin")
    auth_users.create_user(TEST_USER_EMAIL, TEST_USER_PASSWORD, "Test User", role="user")


def tearDownModule():
    _auth_patcher.stop()
    _auth_tmpdir.cleanup()


def _login(email, password):
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    if resp.status_code != 200:
        raise AssertionError(f"test login as {email!r} failed: {resp.status_code} {resp.text}")
    return resp


def _logout():
    client.cookies.clear()


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

    def test_confirm_true_but_not_logged_in_is_rejected_before_ever_running_anything(self):
        """Login is required before the real (paid) path even runs cli.run() - not
        just before returning a result. Never logs in here, so if this test somehow
        got past the gate it would attempt a real, paid API call."""
        resp = client.post("/api/run", json={
            "pipeline": "scan", "path": "vulnerable-demo-app", "confirm": True,
        })
        self.assertEqual(resp.status_code, 401)


class ApiStatus(unittest.TestCase):
    def test_status_endpoint(self):
        resp = client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["vulnhunt_findings"], 9)
        self.assertEqual(payload["remediation_findings"], 14)


class ApiAuth(unittest.TestCase):
    def tearDown(self):
        _logout()

    def test_login_with_correct_credentials_sets_a_session_and_returns_the_user(self):
        resp = client.post("/api/auth/login", json={"email": TEST_ADMIN_EMAIL, "password": TEST_ADMIN_PASSWORD})
        self.assertEqual(resp.status_code, 200)
        user = resp.json()["user"]
        self.assertEqual(user["email"], TEST_ADMIN_EMAIL)
        self.assertEqual(user["role"], "admin")
        self.assertNotIn("password_hash", user)
        self.assertIn(rbac_module.SESSION_COOKIE_NAME, resp.cookies)

    def test_login_with_wrong_password_is_rejected(self):
        resp = client.post("/api/auth/login", json={"email": TEST_ADMIN_EMAIL, "password": "not the password"})
        self.assertEqual(resp.status_code, 401)

    def test_login_with_unknown_email_is_rejected(self):
        resp = client.post("/api/auth/login", json={"email": "nobody@test.local", "password": "anything"})
        self.assertEqual(resp.status_code, 401)

    def test_me_without_login_returns_null_user(self):
        resp = client.get("/api/auth/me")
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(resp.json()["user"])

    def test_me_after_login_returns_the_logged_in_user(self):
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        resp = client.get("/api/auth/me")
        self.assertEqual(resp.json()["user"]["email"], TEST_USER_EMAIL)

    def test_logout_clears_the_session(self):
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        logout_resp = client.post("/api/auth/logout")
        self.assertEqual(logout_resp.status_code, 200)
        me_resp = client.get("/api/auth/me")
        self.assertIsNone(me_resp.json()["user"])

    def test_change_password_requires_login(self):
        resp = client.post("/api/auth/change-password", json={"new_password": "brandnewpassword1"})
        self.assertEqual(resp.status_code, 401)

    def test_change_password_then_old_password_no_longer_logs_in(self):
        auth_users.create_user("temp@test.local", "originalpassword1", "Temp User")
        _login("temp@test.local", "originalpassword1")
        resp = client.post("/api/auth/change-password", json={"new_password": "brandnewpassword1"})
        self.assertEqual(resp.status_code, 200)
        _logout()
        self.assertEqual(
            client.post("/api/auth/login", json={"email": "temp@test.local", "password": "originalpassword1"}).status_code,
            401,
        )
        self.assertEqual(
            client.post("/api/auth/login", json={"email": "temp@test.local", "password": "brandnewpassword1"}).status_code,
            200,
        )

    def test_oidc_config_reports_disabled_when_no_env_vars_are_set(self):
        resp = client.get("/api/auth/oidc/config")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["enabled"])
        self.assertIsNone(resp.json()["provider_name"])

    def test_oidc_login_is_unavailable_when_not_configured(self):
        resp = client.get("/api/auth/oidc/login", follow_redirects=False)
        self.assertEqual(resp.status_code, 503)


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
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)  # POST is admin-gated

    def tearDown(self):
        _logout()
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

    def test_post_without_login_is_rejected(self):
        _logout()
        resp = client.post("/api/priority-rules", json={"rules_text": "sla_days: {}"})
        self.assertEqual(resp.status_code, 401)

    def test_post_as_non_admin_is_rejected(self):
        _logout()
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        resp = client.post("/api/priority-rules", json={"rules_text": "sla_days: {}"})
        self.assertEqual(resp.status_code, 403)


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
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/servicenow/send", json={
                "instance": "", "username": "", "password": "", "table": "incident", "confirm": True,
            })
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)
        self.assertIn("required", resp.json()["detail"])

    def test_send_with_confirm_but_not_logged_in_is_rejected(self):
        """The real-send path (confirm=True) requires login even before credential
        validation - preview (confirm=False, tested above) stays open."""
        resp = client.post("/api/servicenow/send", json={
            "instance": "mycompany", "username": "u", "password": "p", "confirm": True,
        })
        self.assertEqual(resp.status_code, 401)


class ApiJira(unittest.TestCase):
    def test_preview_lists_every_finding_with_no_credentials_needed(self):
        resp = client.get("/api/jira/preview")
        self.assertEqual(resp.status_code, 200)
        previews = resp.json()["previews"]
        self.assertEqual({p["finding_id"] for p in previews}, {f"FIND-{i}" for i in range(1, 15)})
        # Uses the documented placeholder project key until a real one is entered.
        self.assertEqual(previews[0]["body"]["fields"]["project"]["key"], "VULN")

    def test_send_without_confirm_never_touches_the_network(self):
        """Mirrors /api/servicenow/send's dry-run guarantee: submitting without confirm
        must never call JiraConnector's network methods, regardless of what
        credentials are entered."""
        resp = client.post("/api/jira/send", json={
            "base_url": "https://mycompany.atlassian.net", "email": "e@example.com",
            "api_token": "t", "project_key": "PROJ",
            # confirm intentionally omitted (defaults to False)
        })
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertTrue(payload["preview_only"])
        self.assertIsNone(payload["results"])
        self.assertEqual(payload["previews"][0]["body"]["fields"]["project"]["key"], "PROJ")

    def test_send_with_confirm_but_missing_credentials_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/jira/send", json={
                "base_url": "", "email": "", "api_token": "", "project_key": "", "confirm": True,
            })
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)
        self.assertIn("required", resp.json()["detail"])

    def test_send_with_confirm_but_not_logged_in_is_rejected(self):
        resp = client.post("/api/jira/send", json={
            "base_url": "https://mycompany.atlassian.net", "email": "e@example.com",
            "api_token": "t", "project_key": "PROJ", "confirm": True,
        })
        self.assertEqual(resp.status_code, 401)


class ApiSplunk(unittest.TestCase):
    def test_preview_lists_every_finding_with_no_credentials_needed(self):
        resp = client.get("/api/splunk/preview")
        self.assertEqual(resp.status_code, 200)
        previews = resp.json()["previews"]
        self.assertEqual({p["finding_id"] for p in previews}, {f"FIND-{i}" for i in range(1, 15)})
        self.assertEqual(previews[0]["body"]["sourcetype"], "vulnhunter:finding")

    def test_send_without_confirm_never_touches_the_network(self):
        """Mirrors /api/servicenow/send's dry-run guarantee: submitting without confirm
        must never call SplunkConnector's network methods, regardless of what
        credentials are entered."""
        resp = client.post("/api/splunk/send", json={
            "hec_url": "https://splunk.example.com:8088/services/collector/event",
            "hec_token": "t",
            # confirm intentionally omitted (defaults to False)
        })
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertTrue(payload["preview_only"])
        self.assertIsNone(payload["results"])

    def test_send_with_confirm_but_missing_credentials_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/splunk/send", json={
                "hec_url": "", "hec_token": "", "confirm": True,
            })
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)
        self.assertIn("required", resp.json()["detail"])

    def test_send_with_confirm_but_not_logged_in_is_rejected(self):
        resp = client.post("/api/splunk/send", json={
            "hec_url": "https://splunk.example.com:8088/services/collector/event",
            "hec_token": "t", "confirm": True,
        })
        self.assertEqual(resp.status_code, 401)


class ApiAiAssist(unittest.TestCase):
    def test_preview_builds_a_real_prompt_with_no_confirm(self):
        resp = client.post("/api/ai-assist", json={"finding_id": "FIND-12", "action": "explain"})
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertTrue(payload["dry_run"])
        self.assertIn("FIND-12", payload["prompt"])
        self.assertIn("Log4Shell", payload["prompt"])

    def test_preview_never_calls_the_real_claude_binary(self):
        """The critical safety test, same pattern as /api/run and /api/servicenow/send:
        without confirm, no subprocess is ever spawned, regardless of action."""
        with patch("app.subprocess.run") as mock_run:
            resp = client.post("/api/ai-assist", json={"finding_id": "FIND-1", "action": "remediate"})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["dry_run"])
        mock_run.assert_not_called()

    def test_works_for_a_code_scan_finding_too(self):
        resp = client.post("/api/ai-assist", json={"finding_id": "VULN-2", "action": "summarize"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("VULN-2", resp.json()["prompt"])

    def test_unknown_finding_returns_404(self):
        resp = client.post("/api/ai-assist", json={"finding_id": "FIND-999", "action": "explain"})
        self.assertEqual(resp.status_code, 404)

    def test_unknown_action_returns_400(self):
        resp = client.post("/api/ai-assist", json={"finding_id": "FIND-1", "action": "delete_everything"})
        self.assertEqual(resp.status_code, 400)

    def test_confirm_true_calls_the_real_binary_exactly_once(self):
        """Only ever exercised with the real subprocess call mocked out - this proves
        the confirm=True path is wired up correctly without ever spending real API
        usage/credits in the test suite."""
        fake_result = MagicMock(returncode=0, stdout="This is a mocked AI response.", stderr="")
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)  # confirm=True is admin-gated
        try:
            with patch("app.cli.find_claude_binary", return_value="/fake/claude"), \
                 patch("app.subprocess.run", return_value=fake_result) as mock_run:
                resp = client.post("/api/ai-assist", json={
                    "finding_id": "FIND-1", "action": "explain", "confirm": True,
                })
        finally:
            _logout()
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertFalse(payload["dry_run"])
        self.assertEqual(payload["response"], "This is a mocked AI response.")
        mock_run.assert_called_once()

    def test_confirm_true_surfaces_a_failed_call_as_502(self):
        fake_result = MagicMock(returncode=1, stdout="", stderr="something went wrong")
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            with patch("app.cli.find_claude_binary", return_value="/fake/claude"), \
                 patch("app.subprocess.run", return_value=fake_result):
                resp = client.post("/api/ai-assist", json={
                    "finding_id": "FIND-1", "action": "explain", "confirm": True,
                })
        finally:
            _logout()
        self.assertEqual(resp.status_code, 502)

    def test_confirm_true_but_not_logged_in_is_rejected(self):
        resp = client.post("/api/ai-assist", json={
            "finding_id": "FIND-1", "action": "explain", "confirm": True,
        })
        self.assertEqual(resp.status_code, 401)


class ApiReports(unittest.TestCase):
    def test_generate_returns_real_computed_kpis(self):
        resp = client.get("/api/reports/generate", params={"period": "weekly"})
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["period"], "weekly")
        self.assertEqual(payload["remediation_total"], 14)
        self.assertEqual(payload["vulnhunt_total"], 9)

    def test_invalid_period_is_rejected(self):
        resp = client.get("/api/reports/generate", params={"period": "fortnightly"})
        self.assertEqual(resp.status_code, 400)

    def test_html_report_is_served_inline_by_default(self):
        resp = client.get("/api/reports/generate.html", params={"period": "daily"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.headers["content-type"])
        self.assertNotIn("content-disposition", resp.headers)
        self.assertIn("Daily Security Report", resp.text)

    def test_html_report_download_sets_content_disposition(self):
        resp = client.get("/api/reports/generate.html", params={"period": "monthly", "download": "true"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("attachment", resp.headers["content-disposition"])
        self.assertIn("vulnhunter-monthly-report.html", resp.headers["content-disposition"])


class ApiExceptions(unittest.TestCase):
    """Every test here uses a temporary store file (via patching DEFAULT_STORE_PATH) so
    the suite never mutates the real, shipped exceptions.json."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmpdir.name) / "exceptions.json"
        self.patcher = patch.object(exceptions_store, "DEFAULT_STORE_PATH", self.tmp_path)
        self.patcher.start()
        # Create requires any logged-in user, revoke requires admin - log in as admin so
        # both work in these tests; the 401/403 tests below explicitly log out/switch.
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)

    def tearDown(self):
        _logout()
        self.patcher.stop()
        self.tmpdir.cleanup()

    def test_list_on_empty_store_returns_empty_list(self):
        resp = client.get("/api/exceptions")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["exceptions"], [])

    def test_create_then_list_shows_the_new_exception_with_computed_status(self):
        create_resp = client.post("/api/exceptions", json={
            "finding_id": "FIND-7", "reason": "Compensating control in place",
            "requested_by": "eng@example.com", "approved_by": "secops@example.com",
            "expires_on": "2099-01-01",
        })
        self.assertEqual(create_resp.status_code, 200)
        self.assertEqual(create_resp.json()["finding_id"], "FIND-7")

        list_resp = client.get("/api/exceptions")
        exceptions = list_resp.json()["exceptions"]
        self.assertEqual(len(exceptions), 1)
        self.assertEqual(exceptions[0]["computed_status"], "active")

    def test_create_with_past_expiry_is_rejected(self):
        resp = client.post("/api/exceptions", json={
            "finding_id": "FIND-7", "reason": "r",
            "requested_by": "a@example.com", "approved_by": "b@example.com",
            "expires_on": "2020-01-01",
        })
        self.assertEqual(resp.status_code, 400)

    def test_create_with_blank_reason_is_rejected(self):
        resp = client.post("/api/exceptions", json={
            "finding_id": "FIND-7", "reason": "   ",
            "requested_by": "a@example.com", "approved_by": "b@example.com",
            "expires_on": "2099-01-01",
        })
        self.assertEqual(resp.status_code, 400)

    def test_revoke_an_existing_exception(self):
        created = client.post("/api/exceptions", json={
            "finding_id": "FIND-7", "reason": "r",
            "requested_by": "a@example.com", "approved_by": "b@example.com",
            "expires_on": "2099-01-01",
        }).json()

        revoke_resp = client.post(f"/api/exceptions/{created['id']}/revoke")
        self.assertEqual(revoke_resp.status_code, 200)
        self.assertEqual(revoke_resp.json()["status"], "revoked")

    def test_revoke_unknown_id_returns_404(self):
        resp = client.post("/api/exceptions/EXC-999/revoke")
        self.assertEqual(resp.status_code, 404)

    def test_queue_reflects_an_active_exception_on_its_finding(self):
        client.post("/api/exceptions", json={
            "finding_id": "FIND-7", "reason": "Isolated OT VLAN",
            "requested_by": "a@example.com", "approved_by": "b@example.com",
            "expires_on": "2099-01-01",
        })
        resp = client.get("/api/queue")
        findings_by_id = {f["id"]: f for f in resp.json()["findings"]}
        self.assertIsNotNone(findings_by_id["FIND-7"]["exception"])
        self.assertEqual(findings_by_id["FIND-7"]["exception"]["reason"], "Isolated OT VLAN")
        # A finding with no exception requested against it must show None, not error.
        self.assertIsNone(findings_by_id["FIND-1"]["exception"])

    def test_create_without_login_is_rejected(self):
        _logout()
        resp = client.post("/api/exceptions", json={
            "finding_id": "FIND-7", "reason": "r",
            "requested_by": "a@example.com", "approved_by": "b@example.com",
            "expires_on": "2099-01-01",
        })
        self.assertEqual(resp.status_code, 401)

    def test_create_as_a_regular_logged_in_user_is_allowed(self):
        """Create only requires login, not admin - unlike revoke below."""
        _logout()
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        resp = client.post("/api/exceptions", json={
            "finding_id": "FIND-7", "reason": "r",
            "requested_by": "a@example.com", "approved_by": "b@example.com",
            "expires_on": "2099-01-01",
        })
        self.assertEqual(resp.status_code, 200)

    def test_revoke_without_login_is_rejected(self):
        created = client.post("/api/exceptions", json={
            "finding_id": "FIND-7", "reason": "r",
            "requested_by": "a@example.com", "approved_by": "b@example.com",
            "expires_on": "2099-01-01",
        }).json()
        _logout()
        resp = client.post(f"/api/exceptions/{created['id']}/revoke")
        self.assertEqual(resp.status_code, 401)

    def test_revoke_as_a_regular_user_is_forbidden(self):
        """Revoke requires admin - a regular logged-in user can create an exception
        (tested above) but not revoke one."""
        created = client.post("/api/exceptions", json={
            "finding_id": "FIND-7", "reason": "r",
            "requested_by": "a@example.com", "approved_by": "b@example.com",
            "expires_on": "2099-01-01",
        }).json()
        _logout()
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        resp = client.post(f"/api/exceptions/{created['id']}/revoke")
        self.assertEqual(resp.status_code, 403)


class ApiAssets(unittest.TestCase):
    """Every test here uses a temporary ownership file so the suite never mutates the
    real, shipped asset_ownership.json."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmpdir.name) / "asset_ownership.json"
        self.patcher = patch.object(asset_inventory, "DEFAULT_OWNERSHIP_PATH", self.tmp_path)
        self.patcher.start()
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)  # owner/facing only require login

    def tearDown(self):
        _logout()
        self.patcher.stop()
        self.tmpdir.cleanup()

    def test_list_assets_aggregates_the_real_findings(self):
        resp = client.get("/api/assets")
        self.assertEqual(resp.status_code, 200)
        assets = resp.json()["assets"]
        by_name = {a["name"]: a for a in assets}
        # WEB-PORTAL01 has two real findings against it (FIND-13, FIND-14).
        self.assertEqual(by_name["WEB-PORTAL01"]["finding_count"], 2)
        self.assertIsNone(by_name["WEB-PORTAL01"]["owner"])

    def test_unowned_assets_have_a_suggestion_key_defaulting_to_none(self):
        # The temp ownership file starts empty in this test class, so there's
        # nothing yet to pattern-match against (see pattern_recognition.py) - every
        # unowned asset's suggestion is None, not a missing key.
        resp = client.get("/api/assets")
        for asset in resp.json()["assets"]:
            self.assertIn("suggestion", asset)
            if not asset["owner"]:
                self.assertIsNone(asset["suggestion"])

    def test_owned_asset_produces_a_pattern_suggestion_for_a_same_type_asset(self):
        client.post("/api/assets/WIN-DC01/owner", json={"owner": "Priya Nair", "team": "Identity"})
        resp = client.get("/api/assets")
        by_name = {a["name"]: a for a in resp.json()["assets"]}
        # WIN-FS02 shares WIN-DC01's asset type (windows-server, the pattern
        # heuristic's weakest signal) - with only one owned asset in the whole
        # known-set it's still enough to produce a suggestion.
        suggestion = by_name["WIN-FS02"]["suggestion"]
        self.assertIsNotNone(suggestion)
        self.assertEqual(suggestion["owner"], "Priya Nair")

    def test_already_owned_asset_never_gets_a_suggestion_for_itself(self):
        client.post("/api/assets/WIN-DC01/owner", json={"owner": "Priya Nair", "team": "Identity"})
        resp = client.get("/api/assets")
        by_name = {a["name"]: a for a in resp.json()["assets"]}
        self.assertIsNone(by_name["WIN-DC01"]["suggestion"])

    def test_set_owner_then_list_shows_the_new_owner(self):
        set_resp = client.post("/api/assets/WEB-PORTAL01/owner", json={
            "owner": "Web Ops", "team": "Platform",
        })
        self.assertEqual(set_resp.status_code, 200)

        resp = client.get("/api/assets")
        by_name = {a["name"]: a for a in resp.json()["assets"]}
        self.assertEqual(by_name["WEB-PORTAL01"]["owner"], "Web Ops")
        self.assertEqual(by_name["WEB-PORTAL01"]["team"], "Platform")

    def test_new_asset_has_unknown_facing_by_default(self):
        resp = client.get("/api/assets")
        by_name = {a["name"]: a for a in resp.json()["assets"]}
        self.assertEqual(by_name["WEB-PORTAL01"]["facing"], "unknown")

    def test_set_facing_then_list_shows_the_new_classification(self):
        set_resp = client.post("/api/assets/WEB-PORTAL01/facing", json={"facing": "external"})
        self.assertEqual(set_resp.status_code, 200)

        resp = client.get("/api/assets")
        by_name = {a["name"]: a for a in resp.json()["assets"]}
        self.assertEqual(by_name["WEB-PORTAL01"]["facing"], "external")

    def test_set_facing_with_invalid_value_is_rejected(self):
        resp = client.post("/api/assets/WEB-PORTAL01/facing", json={"facing": "space-station"})
        self.assertEqual(resp.status_code, 400)

    def test_set_facing_does_not_clobber_an_existing_owner(self):
        client.post("/api/assets/WEB-PORTAL01/owner", json={"owner": "Web Ops", "team": "Platform"})
        client.post("/api/assets/WEB-PORTAL01/facing", json={"facing": "external"})

        resp = client.get("/api/assets")
        by_name = {a["name"]: a for a in resp.json()["assets"]}
        self.assertEqual(by_name["WEB-PORTAL01"]["owner"], "Web Ops")
        self.assertEqual(by_name["WEB-PORTAL01"]["facing"], "external")

    def test_set_owner_without_login_is_rejected(self):
        _logout()
        resp = client.post("/api/assets/WEB-PORTAL01/owner", json={"owner": "Web Ops", "team": "Platform"})
        self.assertEqual(resp.status_code, 401)

    def test_set_facing_without_login_is_rejected(self):
        _logout()
        resp = client.post("/api/assets/WEB-PORTAL01/facing", json={"facing": "external"})
        self.assertEqual(resp.status_code, 401)

    def test_cmdb_import_preview_requires_no_login_and_reconciles_against_real_assets(self):
        csv_text = "Hostname,Owner,Team\nWEB-PORTAL01,Web Ops,Platform\nNEW-SERVER-01,Someone,SomeTeam\n"
        _logout()
        resp = client.post("/api/assets/cmdb-import/preview", json={"csv_text": csv_text})
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["column_mapping"]["asset_name"], "Hostname")
        self.assertEqual(len(payload["matched"]), 1)
        self.assertEqual(payload["matched"][0]["asset_name"], "WEB-PORTAL01")
        self.assertEqual(len(payload["unmatched"]), 1)

    def test_cmdb_import_apply_requires_login(self):
        _logout()
        resp = client.post("/api/assets/cmdb-import/apply", json={"entries": [
            {"asset_name": "WEB-PORTAL01", "owner": "Web Ops", "team": "Platform"},
        ]})
        self.assertEqual(resp.status_code, 401)

    def test_cmdb_import_apply_then_asset_shows_new_owner(self):
        resp = client.post("/api/assets/cmdb-import/apply", json={"entries": [
            {"asset_name": "WEB-PORTAL01", "owner": "Web Ops", "team": "Platform"},
        ]})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["applied"], 1)
        by_name = {a["name"]: a for a in client.get("/api/assets").json()["assets"]}
        self.assertEqual(by_name["WEB-PORTAL01"]["owner"], "Web Ops")


class ApiRiskAttackHeatmap(unittest.TestCase):
    def test_heatmap_covers_the_full_known_taxonomy(self):
        resp = client.get("/api/risk/attack-heatmap")
        self.assertEqual(resp.status_code, 200)
        heatmap = resp.json()["heatmap"]
        self.assertTrue(len(heatmap) >= 10)  # every known (tactic, technique) pair
        self.assertTrue(all("tactic" in row and "count" in row for row in heatmap))

    def test_printnightmare_finding_shows_up_under_its_technique(self):
        """FIND-1/PrintNightmare-style RCE is real sample data - sanity-check it lands
        under Exploitation of Remote Services (T1210), same as test_attack_mapping.py's
        own check against normalized-findings.json."""
        resp = client.get("/api/risk/attack-heatmap")
        heatmap = resp.json()["heatmap"]
        by_technique = {row["technique_id"]: row for row in heatmap}
        self.assertGreater(by_technique["T1210"]["count"], 0)


class ApiAiVulnerabilities(unittest.TestCase):
    def test_returns_the_full_taxonomy_and_heatmap(self):
        resp = client.get("/api/ai-vulnerabilities")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(len(body["vulnerabilities"]) >= 8)
        self.assertTrue(all("summary" in v and "remediation" in v for v in body["vulnerabilities"]))
        self.assertEqual(len(body["heatmap"]), len(body["vulnerabilities"]))

    def test_heatmap_is_all_zero_against_this_repos_real_demo_data(self):
        """Honest scope check: no AI/ML component in this repo's demo app, so no real
        finding should match - see ai_vuln_taxonomy.py's module docstring."""
        resp = client.get("/api/ai-vulnerabilities")
        heatmap = resp.json()["heatmap"]
        self.assertTrue(all(row["count"] == 0 for row in heatmap))


class ApiIngestGeneric(unittest.TestCase):
    """The vendor-agnostic ingestion webhook. Writes to remediation/live-data/ (real,
    gitignored path, same as the live Tenable/Armis connectors) - cleaned up in
    tearDown so no test artifact lingers."""

    LIVE_DATA_PATH = REPO_ROOT / "remediation" / "live-data" / "generic-ingested.json"

    def tearDown(self):
        if self.LIVE_DATA_PATH.exists():
            self.LIVE_DATA_PATH.unlink()

    def test_valid_payload_is_accepted_and_normalized(self):
        resp = client.post("/api/ingest/generic", json={"findings": [{
            "title": "Reflected XSS", "severity": "High",
            "asset_name": "APP-ORDERS01", "asset_type": "application",
        }]})
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["accepted"], 1)
        self.assertEqual(payload["rejected"], [])
        self.assertEqual(payload["findings"][0]["source"], "generic")

    def test_ingested_id_never_collides_with_a_real_finding_id(self):
        """The real pipeline has FIND-1..FIND-14 - a naively-implemented adapter that
        only looked at its own (empty) live-data file would assign FIND-1 again."""
        resp = client.post("/api/ingest/generic", json={"findings": [{
            "title": "t", "severity": "Low", "asset_name": "a", "asset_type": "application",
        }]})
        new_id = resp.json()["findings"][0]["id"]
        real_ids = {f["id"] for f in dashboard_data.load_remediation_findings()}
        self.assertNotIn(new_id, real_ids)

    def test_invalid_payload_is_rejected_with_specific_errors(self):
        resp = client.post("/api/ingest/generic", json={"findings": [{"title": "t"}]})
        self.assertEqual(resp.status_code, 200)  # batch endpoint - per-item errors, not a 4xx
        payload = resp.json()
        self.assertEqual(payload["accepted"], 0)
        self.assertEqual(len(payload["rejected"]), 1)
        self.assertEqual(payload["rejected"][0]["index"], 0)

    def test_mixed_batch_accepts_valid_and_rejects_invalid_independently(self):
        resp = client.post("/api/ingest/generic", json={"findings": [
            {"title": "good", "severity": "High", "asset_name": "a", "asset_type": "application"},
            {"title": "bad", "severity": "Nonsense"},
        ]})
        payload = resp.json()
        self.assertEqual(payload["accepted"], 1)
        self.assertEqual(len(payload["rejected"]), 1)

    def test_accepted_findings_are_written_to_live_data(self):
        client.post("/api/ingest/generic", json={"findings": [{
            "title": "t", "severity": "Low", "asset_name": "a", "asset_type": "application",
        }]})
        self.assertTrue(self.LIVE_DATA_PATH.exists())


class ApiNotifications(unittest.TestCase):
    """build_notifications() is real, system-generated data derived from the live
    queue/exceptions/ingestion state - not person-to-person messages. Exception- and
    ingestion-derived notifications use temporary store files (same patching pattern as
    ApiExceptions/ApiIngestGeneric) so this suite never touches the real shipped files."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp_exc_path = Path(self.tmpdir.name) / "exceptions.json"
        self.exc_patcher = patch.object(exceptions_store, "DEFAULT_STORE_PATH", self.tmp_exc_path)
        self.exc_patcher.start()
        self.ingest_path = Path(self.tmpdir.name) / "generic-ingested.json"
        self.ingest_patcher = patch.object(dashboard_data, "GENERIC_INGESTED_PATH", self.ingest_path)
        self.ingest_patcher.start()

    def tearDown(self):
        self.exc_patcher.stop()
        self.ingest_patcher.stop()
        self.tmpdir.cleanup()

    def test_sla_breached_findings_produce_danger_notifications(self):
        resp = client.get("/api/notifications")
        self.assertEqual(resp.status_code, 200)
        notifications = resp.json()["notifications"]
        sla_ids = {n["id"] for n in notifications if n["category"] == "SLA"}
        # Matches the known real breach count elsewhere in this suite (queue KPI: 6 breached).
        self.assertEqual(len(sla_ids), 6)
        self.assertIn("sla-FIND-1", sla_ids)

    def test_danger_notifications_sort_before_warn_and_info(self):
        notifications = client.get("/api/notifications").json()["notifications"]
        ranks = {"danger": 0, "warn": 1, "info": 2}
        severities = [ranks[n["severity"]] for n in notifications]
        self.assertEqual(severities, sorted(severities))

    def test_exception_expiring_soon_produces_a_warn_notification(self):
        soon = (datetime.date.today() + datetime.timedelta(days=5)).isoformat()
        exceptions_store.create_exception(
            "FIND-7", "Compensating control", "eng@example.com", "secops@example.com", soon,
        )
        notifications = client.get("/api/notifications").json()["notifications"]
        exc_notifs = [n for n in notifications if n["category"] == "Exception"]
        self.assertEqual(len(exc_notifs), 1)
        self.assertEqual(exc_notifs[0]["severity"], "warn")
        self.assertIn("EXC-1", exc_notifs[0]["message"])

    def test_exception_far_from_expiry_produces_no_notification(self):
        far_future = (datetime.date.today() + datetime.timedelta(days=365)).isoformat()
        exceptions_store.create_exception(
            "FIND-7", "Compensating control", "eng@example.com", "secops@example.com", far_future,
        )
        notifications = client.get("/api/notifications").json()["notifications"]
        self.assertEqual([n for n in notifications if n["category"] == "Exception"], [])

    def test_pending_generic_ingested_findings_produce_an_info_notification(self):
        self.ingest_path.parent.mkdir(parents=True, exist_ok=True)
        self.ingest_path.write_text('[{"id": "GEN-1", "title": "t"}]', encoding="utf-8")
        notifications = client.get("/api/notifications").json()["notifications"]
        ingest_notifs = [n for n in notifications if n["category"] == "Ingestion"]
        self.assertEqual(len(ingest_notifs), 1)
        self.assertIn("1 finding(s)", ingest_notifs[0]["message"])
        self.assertIsNone(ingest_notifs[0]["link"])

    def test_no_generic_ingested_file_produces_no_ingestion_notification(self):
        notifications = client.get("/api/notifications").json()["notifications"]
        self.assertEqual([n for n in notifications if n["category"] == "Ingestion"], [])


class HtmlShellRoutesServeTheSpaShell(unittest.TestCase):
    """The frontend is a single static/index.html shell served for every page route;
    static/js/app.js reads window.location.pathname client-side and calls the JSON
    API above to render each page. These tests confirm the shell is served correctly
    (and only the shell - no server-side templating), not what it renders to."""

    SHELL_ROUTES = [
        "/", "/vulnhunt", "/remediate", "/run", "/queue", "/priority-rules", "/servicenow",
        "/jira", "/splunk", "/xdr", "/ai-assist", "/reports", "/support", "/faq",
        "/exceptions", "/assets", "/appsec", "/inbox", "/risk", "/login", "/profile",
    ]

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
