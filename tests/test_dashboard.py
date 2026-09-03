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
import json
import os
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
from sqlalchemy import create_engine, delete, insert  # noqa: E402

import app as dashboard_app_module  # noqa: E402
import data as dashboard_data  # noqa: E402
import rate_limit  # noqa: E402
import vulnhunter as cli  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import rbac as rbac_module  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.audit import activity_log  # noqa: E402
from remediation.audit import ai_usage_log  # noqa: E402
from remediation.config import ai_governance  # noqa: E402
from remediation.config import priority_engine  # noqa: E402
from remediation.config import remediation_policy_engine  # noqa: E402
from remediation.enrichment import exploit_criteria  # noqa: E402
from remediation.exceptions import store as exceptions_store  # noqa: E402
from remediation.inventory import asset_inventory, asset_policy  # noqa: E402
from remediation.connectors import live_data_store  # noqa: E402
from remediation.notifications import email_sender  # noqa: E402
from remediation.remediation_approvals import store as remediation_approvals_store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

client = TestClient(fastapi_app)


def _patch_db_engine(tmpdir_path):
    """Redirects every store module's default DB access (exceptions, remediation
    approvals, activity log, AI usage log - see remediation/utils/db.py) to a fresh
    on-disk SQLite file under `tmpdir_path`. Every migrated store module calls
    `db_module.get_engine()` (dynamically, through the module object) whenever a
    caller doesn't pass its own `engine=`, so patching this one function is the same
    isolation the old per-module DEFAULT_STORE_PATH/DEFAULT_LOG_PATH patches gave,
    just through the one shared choke point that replaced them. Patches nest like any
    other unittest.mock.patch: a class-level override started after a module-level one
    takes precedence for that class's tests and correctly restores the module-level
    one (not the real function) on .stop().

    The returned patcher carries the engine as `.engine` - Windows won't delete a
    tempdir while a pooled connection still has its DB file open, so every caller
    must do `patcher.engine.dispose()` before `patcher.stop()` and the tmpdir cleanup
    that follows (POSIX doesn't enforce this, so the bug is invisible there).

    Also re-seeds the two standard demo accounts (TEST_ADMIN_EMAIL/TEST_USER_EMAIL) -
    auth/users.py shares this same engine now that it's migrated too, so a fresh,
    empty per-test/per-class engine has neither account until something creates them
    here; nearly every test class in this file logs in as one or both, so doing it
    once in this shared helper (rather than in each of those classes' own setUp)
    keeps them from silently disappearing for that class's whole test run."""
    test_engine = create_engine(f"sqlite:///{Path(tmpdir_path) / 'test.db'}")
    patcher = patch.object(db_module, "get_engine", return_value=test_engine)
    patcher.engine = test_engine
    # engine=test_engine passed explicitly - no need for the patch to be active yet,
    # since these two calls target test_engine directly regardless of what
    # db_module.get_engine() currently resolves to.
    auth_users.create_user(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD, "Test Admin", role="admin", engine=test_engine)
    auth_users.create_user(TEST_USER_EMAIL, TEST_USER_PASSWORD, "Test User", role="user", engine=test_engine)
    return patcher

# A temporary, module-scoped user store (never the real, shipped users.json) so every
# test in this file that needs to be logged in can log in as a known admin/user without
# depending on the real demo credentials in dashboard/auth/users.json staying fixed.
TEST_ADMIN_EMAIL = "admin@test.local"
TEST_ADMIN_PASSWORD = "admin-test-password-1"
TEST_USER_EMAIL = "user@test.local"
TEST_USER_PASSWORD = "user-test-password-1"

_auth_tmpdir = None
_db_engine_patcher = None
_ai_governance_patcher = None
_rate_limit_patchers = None


def setUpModule():
    global _auth_tmpdir, _db_engine_patcher, _ai_governance_patcher, _rate_limit_patchers
    _auth_tmpdir = tempfile.TemporaryDirectory()

    # Every mutation route in this file (asset edits, exception revoke, approval
    # decisions, login attempts) also writes to the real, shared activity log and AI
    # usage log (see remediation/audit/) unless redirected, and exceptions/approvals/
    # asset-ownership/user-account routes called with no more specific per-class
    # override (below) would otherwise hit the real, shared remediation/vulnhunter.db
    # too - one module-wide patch here (rather than repeating it in every affected
    # test class) keeps this suite from ever touching real data. _patch_db_engine()
    # already seeds TEST_ADMIN_EMAIL/TEST_USER_EMAIL into the fresh engine itself, so
    # there's no separate create_user() step needed here.
    _db_engine_patcher = _patch_db_engine(_auth_tmpdir.name)
    _db_engine_patcher.start()

    tmp_ai_governance_path = Path(_auth_tmpdir.name) / "ai_governance.yaml"
    _ai_governance_patcher = patch.object(ai_governance, "DEFAULT_PATH", tmp_ai_governance_path)
    _ai_governance_patcher.start()

    # The real rate limiters (dashboard/rate_limit.py) are module-level, process-
    # lifetime singletons - this suite alone makes many thousands of /api/* calls
    # against the SAME TestClient (and so the same client IP) well within their real
    # windows, which would otherwise start returning real 429s partway through an
    # unrelated test. Swapped for effectively-unlimited replacements for the whole
    # module run; RateLimitMiddleware below patches its own, deliberately tiny limits
    # back in just for its own tests, to verify the real 429 behavior actually works.
    _rate_limit_patchers = [
        patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
        patch.object(dashboard_app_module, "_GENERIC_INGEST_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
    ]
    for p in _rate_limit_patchers:
        p.start()


def tearDownModule():
    for p in _rate_limit_patchers:
        p.stop()
    _ai_governance_patcher.stop()
    _db_engine_patcher.engine.dispose()
    _db_engine_patcher.stop()
    _auth_tmpdir.cleanup()


def _login(email, password):
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    if resp.status_code != 200:
        raise AssertionError(f"test login as {email!r} failed: {resp.status_code} {resp.text}")
    return resp


def _logout():
    client.cookies.clear()


class ParseMarkdownTable(unittest.TestCase):
    """Regression coverage for a real Round 13 bug: bulk_plan.py escapes a literal '|'
    inside a finding's title as '\\|' (valid Markdown), but the naive line.split("|")
    parser this used to be didn't account for that - a real NVD CVE description naming
    a "... | LOGIN" WordPress plugin silently dropped that entire row (len(cells) never
    matched the header again), which surfaced as a real 9414-vs-9415 count mismatch
    once the Round 13 cloud CVE expansion happened to include one such title."""

    def test_splits_on_unescaped_pipes_only(self):
        cells = dashboard_data._split_markdown_table_row("| a | b | c |")
        self.assertEqual(cells, ["a", "b", "c"])

    def test_escaped_pipe_inside_a_cell_is_preserved_not_split_on(self):
        cells = dashboard_data._split_markdown_table_row(r"| FIND-1 | Plugin A \| Plugin B | Medium |")
        self.assertEqual(cells, ["FIND-1", "Plugin A | Plugin B", "Medium"])

    def test_a_table_row_with_an_escaped_pipe_is_not_dropped(self):
        markdown = (
            "## Queue\n\n"
            "| ID | Title | Severity |\n"
            "| --- | --- | --- |\n"
            r"| FIND-1 | Contains a \| literal pipe | Medium |" + "\n"
            "| FIND-2 | A normal title | Low |\n"
        )
        header, rows = dashboard_data.parse_markdown_table(markdown, "Queue")
        self.assertEqual(header, ["ID", "Title", "Severity"])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], ["FIND-1", "Contains a | literal pipe", "Medium"])


class DataLayerReadsRealArtifacts(unittest.TestCase):
    """These mirror tests/test_pipeline_artifacts.py's expectations - the dashboard's
    parser must agree with the pipeline's own test suite about what the artifacts say."""

    def test_vulnhunt_data_matches_known_totals(self):
        """9 original findings (app.py/Dockerfile) + 9 more added later from
        ai_assistant.py (AI/ML) and admin_api.py (secrets/API-authorization) = 18 at
        time of writing; 11 of those 18 are auto-fixable (see
        vulnerable-demo-app/SECURITY_REPORT.md's remediation plan)."""
        vh = dashboard_data.load_vulnhunt_data()
        self.assertTrue(vh["available"])
        self.assertEqual(vh["total"], 18)
        self.assertEqual(vh["auto_fixable"], 11)

    def test_remediation_findings_match_known_total(self):
        """Real total at time of writing: 15 hand-curated findings from the original
        pipeline validation + 7,425 real-CVE findings added via bulk NVD sourcing across
        6 infra sub-categories (see remediation/sample-data/generate_bulk_findings.py)
        = 7,440. This is a moving target as more real data is added, so this asserts
        "at least the known floor" rather than an exact snapshot - see
        test_pipeline_artifacts.py for the structural well-formedness checks that
        matter regardless of exact count."""
        findings = dashboard_data.load_remediation_findings()
        self.assertGreaterEqual(len(findings), 7440)

    def test_remediation_plan_queue_matches_findings_count(self):
        plan = dashboard_data.load_remediation_plan()
        self.assertTrue(plan["available"])
        findings = dashboard_data.load_remediation_findings()
        self.assertEqual(len(plan["queue"]), len(findings))

    def test_risk_tier_counts_match_known_split(self):
        plan = dashboard_data.load_remediation_plan()
        counts = plan["risk_tier_counts"]
        # Structural invariants rather than exact counts (which grow as more real
        # findings are added): every tier present, and they sum to the full queue.
        for tier in ("auto-approvable", "needs-change-approval", "manual-only"):
            self.assertIn(tier, counts)
            self.assertGreater(counts[tier], 0)
        self.assertEqual(sum(counts.values()), len(plan["queue"]))

    def test_playbooks_match_known_count(self):
        """Real generated Ansible playbooks - still only for the original 7
        auto/needs-change-approval findings from the hand-curated set (FIND-1, 2, 3, 4,
        5, 10, 11). Generating playbooks for the bulk-sourced auto-approvable findings
        too is a deliberately separate, not-yet-done follow-up (see REMEDIATION_PLAN.md's
        scale note) - /remediate already handles a finding with no playbook gracefully
        ("none" in the Playbook column), this isn't a gap this test should paper over."""
        playbooks = dashboard_data.load_playbooks()
        self.assertEqual(len(playbooks), 7)

    def test_every_real_playbook_has_a_parsed_rollback_plan(self):
        """Every remediation-fixer-windows/-unix agent is instructed to include a
        '# Rollback: ...' comment (ISO/IEC 27002:2022 §8.32) - regression guard that
        _parse_rollback_plan() actually extracts real text from every one of the 7
        real generated playbooks, not just in a synthetic unit test."""
        for playbook in dashboard_data.load_playbooks():
            self.assertIsNotNone(playbook["rollback_plan"], f"{playbook['filename']} has no parsed rollback_plan")
            self.assertTrue(playbook["rollback_plan"].strip())

    def test_parse_rollback_plan_single_line(self):
        text = "# Some header\n# Rollback: revert the change\n---\nreal: yaml\n"
        self.assertEqual(dashboard_data._parse_rollback_plan(text), "revert the change")

    def test_parse_rollback_plan_wraps_across_comment_lines(self):
        text = (
            "# Rollback: re-enable the feature if legacy clients break:\n"
            "#   Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol\n"
            "#\n"
            "---\n"
        )
        result = dashboard_data._parse_rollback_plan(text)
        self.assertIn("re-enable the feature if legacy clients break:", result)
        self.assertIn("Enable-WindowsOptionalFeature", result)

    def test_parse_rollback_plan_stops_at_blank_comment_line(self):
        text = "# Rollback: line one\n# line two\n#\n# unrelated comment after the blank\n"
        result = dashboard_data._parse_rollback_plan(text)
        self.assertNotIn("unrelated", result)

    def test_parse_rollback_plan_missing_returns_none(self):
        text = "# Some header with no rollback line\n---\nreal: yaml\n"
        self.assertIsNone(dashboard_data._parse_rollback_plan(text))

    def test_threat_intel_freshness_reports_a_real_recent_timestamp(self):
        """normalized-findings.json is a real, committed file - its mtime should be a
        real, parseable, recent-ish (not epoch-zero, not future) timestamp."""
        freshness = dashboard_data.load_threat_intel_freshness()
        self.assertTrue(freshness["available"])
        parsed = datetime.datetime.fromisoformat(freshness["last_refreshed"])
        self.assertLessEqual(parsed, datetime.datetime.now(datetime.timezone.utc))
        self.assertGreater(freshness["cve_count"], 0)

    def test_kev_and_high_epss_counts(self):
        """Real, live-verified counts against CISA KEV + FIRST.org EPSS at time of
        writing: 112 KEV-listed, 253 with EPSS >= 50% (see remediation/enrichment/kev_epss.py) -
        grew from 111/251 once the GitHub/GitLab repository (Dependabot-style) category's
        real CVEs were merged in. Asserts a floor, not an exact snapshot - see
        test_remediation_findings_match_known_total."""
        findings = dashboard_data.load_remediation_findings()
        self.assertGreaterEqual(dashboard_data.count_kev_listed(findings), 112)
        self.assertGreaterEqual(dashboard_data.count_high_epss(findings), 253)

    def test_asset_type_breakdown_covers_all_categories(self):
        findings = dashboard_data.load_remediation_findings()
        breakdown = dashboard_data.asset_type_breakdown(findings)
        self.assertEqual(sum(breakdown.values()), len(findings))
        for expected_type in ("windows-server", "unix-server", "network-routing-switching",
                               "network-security-device", "iot-ot-device", "application",
                               "certificate", "cloud-infrastructure", "client-application",
                               "iac-resource", "code-repository", "container-runtime"):
            self.assertIn(expected_type, breakdown)
            self.assertGreater(breakdown[expected_type], 0)

    def test_no_mojibake_in_parsed_text(self):
        """Regression guard for the subprocess-encoding bug: git output must be decoded
        as UTF-8, not the platform default, or characters like em-dash corrupt into
        mojibake ('â€”')."""
        vh = dashboard_data.load_vulnhunt_data()
        self.assertNotIn("â€”", vh["title"])
        plan = dashboard_data.load_remediation_plan()
        self.assertNotIn("â€”", plan["title"])


class ContentEnrichedFindingsCache(unittest.TestCase):
    """The ATT&CK/compensating-controls tagging pass is profiled at ~1.8s across the
    real ~8,000-finding dataset (two regex-heavy passes) - now that Overview/
    Infrastructure/AppSec/Risk all fetch the live queue, that cost was being paid on
    every single page load. These verify the in-process cache (keyed on the findings
    file's mtime + today's date - see _load_content_enriched_findings()'s own
    docstring) actually avoids recomputation, not just that it happens to be fast."""

    def setUp(self):
        dashboard_data._ENRICHED_FINDINGS_CACHE["key"] = None
        dashboard_data._ENRICHED_FINDINGS_CACHE["findings"] = None

    def tearDown(self):
        dashboard_data._ENRICHED_FINDINGS_CACHE["key"] = None
        dashboard_data._ENRICHED_FINDINGS_CACHE["findings"] = None

    def test_second_call_does_not_re_invoke_the_expensive_tag_functions(self):
        with patch.object(dashboard_data, "tag_findings", wraps=dashboard_data.tag_findings) as mock_attack, \
                patch.object(dashboard_data, "tag_compensating_controls",
                              wraps=dashboard_data.tag_compensating_controls) as mock_comp:
            dashboard_data._load_content_enriched_findings()
            dashboard_data._load_content_enriched_findings()
            self.assertEqual(mock_attack.call_count, 1)
            self.assertEqual(mock_comp.call_count, 1)

    def test_cache_invalidates_when_its_key_changes(self):
        """Simulates what a real pipeline re-run (changed mtime) or a day rollover
        (changed date) would trigger, without touching the real file's OS-level mtime."""
        with patch.object(dashboard_data, "tag_findings", wraps=dashboard_data.tag_findings) as mock_attack:
            dashboard_data._load_content_enriched_findings()
            dashboard_data._ENRICHED_FINDINGS_CACHE["key"] = ("a-different-key", "2000-01-01")
            dashboard_data._load_content_enriched_findings()
            self.assertEqual(mock_attack.call_count, 2)

    def test_load_live_queue_still_reflects_exploit_criteria_and_exceptions_live(self):
        """The cache only covers the purely-content-derived tags - exploit-criteria
        matching (reads an admin-editable rules file) and exceptions must still be
        recomputed every call, cache or no cache."""
        findings = dashboard_data.load_live_queue()
        self.assertTrue(all("exploit_criteria_matches" in f for f in findings))
        self.assertTrue(all("exception" in f for f in findings))


class VulnhuntDataCache(unittest.TestCase):
    """load_vulnhunt_data() is profiled at ~0.4s per call (two `git` subprocess
    spawns) - cached for a short in-process TTL since several pages now call it on
    every navigation, not just /vulnhunt itself."""

    def setUp(self):
        dashboard_data._VULNHUNT_DATA_CACHE["data"] = None
        dashboard_data._VULNHUNT_DATA_CACHE["expires_at"] = 0.0

    def tearDown(self):
        dashboard_data._VULNHUNT_DATA_CACHE["data"] = None
        dashboard_data._VULNHUNT_DATA_CACHE["expires_at"] = 0.0

    def test_second_call_within_ttl_does_not_recompute(self):
        with patch.object(dashboard_data, "_compute_vulnhunt_data",
                           wraps=dashboard_data._compute_vulnhunt_data) as mock_compute:
            dashboard_data.load_vulnhunt_data()
            dashboard_data.load_vulnhunt_data()
            self.assertEqual(mock_compute.call_count, 1)

    def test_call_after_ttl_expiry_recomputes(self):
        with patch.object(dashboard_data, "_compute_vulnhunt_data",
                           wraps=dashboard_data._compute_vulnhunt_data) as mock_compute:
            dashboard_data.load_vulnhunt_data()
            dashboard_data._VULNHUNT_DATA_CACHE["expires_at"] = 0.0  # force expiry
            dashboard_data.load_vulnhunt_data()
            self.assertEqual(mock_compute.call_count, 2)


class ApiOverview(unittest.TestCase):
    def test_overview_returns_expected_shape_and_counts(self):
        resp = client.get("/api/overview")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["vulnhunt"]["total"], 18)
        self.assertEqual(payload["vulnhunt"]["auto_fixable"], 11)
        self.assertGreaterEqual(payload["remediation"]["total"], 8096)
        self.assertEqual(payload["playbook_count"], 7)
        self.assertGreaterEqual(payload["kev_count"], 112)
        self.assertGreaterEqual(payload["high_epss_count"], 253)
        for key in ("breached", "at_risk", "on_track"):
            self.assertIn(key, payload["sla"])
        for asset_type in ("windows-server", "unix-server", "application", "certificate"):
            self.assertIn(asset_type, payload["asset_type_breakdown"])

    def test_overview_includes_the_live_priority_rules_summary(self):
        """Overview's SLA/priority definitions panel reads the real, currently
        configured priority_rules.yaml - not a hardcoded snapshot."""
        resp = client.get("/api/overview")
        rules = resp.json()["priority_rules"]
        for tier in ("Critical", "High", "Medium", "Low"):
            self.assertIn(tier, rules["sla_days"])
            self.assertIn(tier, rules["priority_thresholds"])
        self.assertIn("enabled", rules["kev_override"])
        self.assertIn("threshold", rules["epss_escalation"])
        self.assertIn("dc", rules["asset_criticality_keywords"])
        self.assertIn("windows-server", rules["asset_type_weights"])

    def test_overview_includes_the_live_risk_scoring_rules(self):
        """Overview's Risk Scoring methodology panel quotes the real, currently
        configured risk_scoring_rules.yaml - not a hardcoded copy of the weights."""
        resp = client.get("/api/overview")
        rules = resp.json()["risk_scoring_rules"]
        self.assertIn("severity", rules["impact_weights"])
        self.assertIn("criticality", rules["impact_weights"])
        for key in ("kev", "epss", "exploit_criteria", "eol"):
            self.assertIn(key, rules["likelihood_weights"])
        for tier in ("Critical", "High", "Medium", "Low"):
            self.assertIn(tier, rules["risk_tier_thresholds"])

    def test_overview_includes_a_real_computed_exposure_score(self):
        """The Aggregate Exposure Score tile - a real 0-100 int computed from this
        app's own actual scored assets/findings, not a hardcoded placeholder."""
        resp = client.get("/api/overview")
        exposure = resp.json()["exposure_score"]
        self.assertIsInstance(exposure["score"], int)
        self.assertGreaterEqual(exposure["score"], 0)
        self.assertLessEqual(exposure["score"], 100)
        self.assertIn(exposure["band"], ("Critical", "High", "Medium", "Low"))
        self.assertGreater(exposure["total_assets"], 0)
        self.assertGreater(exposure["total_findings"], 0)
        for key in ("avg_risk_score", "kev_prevalence", "avg_epss"):
            self.assertIn(key, exposure["components"])

    def test_overview_includes_the_live_exposure_score_rules(self):
        resp = client.get("/api/overview")
        rules = resp.json()["exposure_score_rules"]
        for key in ("avg_risk_score", "kev_prevalence", "avg_epss"):
            self.assertIn(key, rules["component_weights"])


class ApiThreatIntelRefresh(unittest.TestCase):
    """confirm=True calls remediation/enrichment/kev_epss.py's real enrich_file(),
    which makes real live network calls to CISA/FIRST.org and overwrites the real,
    committed normalized-findings.json - always mocked here, never actually invoked,
    same "never make a real external call from the test suite" convention as every
    other confirm-gated action in this app."""

    def test_freshness_returns_a_real_timestamp_and_recommended_cadence(self):
        resp = client.get("/api/threat-intel/freshness")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertTrue(payload["available"])
        self.assertIn("cisa_kev", payload["recommended_cadence"])
        self.assertIn("first_epss", payload["recommended_cadence"])

    def test_dry_run_refresh_never_calls_the_real_fetch(self):
        with patch("app.kev_epss.enrich_file") as mock_enrich:
            resp = client.post("/api/threat-intel/refresh-now", json={})
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertTrue(payload["dry_run"])
        mock_enrich.assert_not_called()

    def test_confirm_true_but_not_logged_in_is_rejected_before_ever_fetching(self):
        with patch("app.kev_epss.enrich_file") as mock_enrich:
            resp = client.post("/api/threat-intel/refresh-now", json={"confirm": True})
        self.assertEqual(resp.status_code, 401)
        mock_enrich.assert_not_called()

    def test_confirm_true_as_admin_calls_the_real_enrichment_function_once(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            with patch("app.kev_epss.enrich_file") as mock_enrich:
                resp = client.post("/api/threat-intel/refresh-now", json={"confirm": True})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertFalse(payload["dry_run"])
        mock_enrich.assert_called_once()

    def test_confirm_true_as_non_admin_is_forbidden(self):
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        try:
            with patch("app.kev_epss.enrich_file") as mock_enrich:
                resp = client.post("/api/threat-intel/refresh-now", json={"confirm": True})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 403)
        mock_enrich.assert_not_called()

    def test_confirm_true_surfaces_a_real_fetch_failure_as_502(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            with patch("app.kev_epss.enrich_file", side_effect=RuntimeError("network down")):
                resp = client.post("/api/threat-intel/refresh-now", json={"confirm": True})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 502)


class ApiQuantumReadiness(unittest.TestCase):
    def test_returns_real_matched_findings_and_a_consistent_summary(self):
        resp = client.get("/api/quantum-readiness")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertGreater(payload["summary"]["total"], 0)
        self.assertEqual(
            payload["summary"]["total"],
            payload["summary"]["asymmetric_crypto"] + payload["summary"]["legacy_protocol"],
        )
        self.assertEqual(len(payload["findings"]), payload["summary"]["total"])
        for f in payload["findings"]:
            self.assertIn(f["quantum_readiness"]["category"], ("asymmetric-crypto", "legacy-protocol"))

    def test_includes_real_cited_nist_ir_8547_deadlines(self):
        resp = client.get("/api/quantum-readiness")
        ir8547 = resp.json()["nist_ir_8547"]
        self.assertEqual(ir8547["deprecated_by"], 2030)
        self.assertEqual(ir8547["disallowed_by"], 2035)


class ApiVulnhunt(unittest.TestCase):
    def test_lists_all_eighteen_findings(self):
        resp = client.get("/api/vulnhunt")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertTrue(payload["available"])
        ids = {f["ID"] for f in payload["findings"]}
        self.assertEqual(ids, {f"VULN-{i}" for i in range(1, 19)})

    def test_unverified_finding_has_no_verification(self):
        resp = client.get("/api/vulnhunt")
        payload = resp.json()
        vuln1 = next(f for f in payload["findings"] if f["ID"] == "VULN-1")
        self.assertIsNone(vuln1["verification"])

    def test_verified_finding_surfaces_its_latest_outcome(self):
        # record_verification.py logs via activity_log.record_activity() - this test
        # exercises that exact real write, not a mocked stand-in, same as every other
        # real-DB-backed test in this module (see setUpModule()'s module-wide
        # _patch_db_engine()).
        dashboard_data._VULNHUNT_DATA_CACHE["data"] = None  # force a fresh read past the TTL cache
        dashboard_data._VULNHUNT_DATA_CACHE["expires_at"] = 0.0
        activity_log.record_activity(
            "vulnhunt-verify", "vulnhunt.verify", "VULN-2",
            {"branch": "vulnhunter/auto-fixes-test", "status": "resolved", "detail": "confirmed fixed"},
        )
        try:
            resp = client.get("/api/vulnhunt")
            payload = resp.json()
            vuln2 = next(f for f in payload["findings"] if f["ID"] == "VULN-2")
            self.assertEqual(vuln2["verification"]["status"], "resolved")
            self.assertEqual(vuln2["verification"]["detail"], "confirmed fixed")
        finally:
            dashboard_data._VULNHUNT_DATA_CACHE["data"] = None
            dashboard_data._VULNHUNT_DATA_CACHE["expires_at"] = 0.0


class ApiRemediate(unittest.TestCase):
    def test_lists_all_findings_and_playbook_links(self):
        resp = client.get("/api/remediate")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertGreaterEqual(len(payload["findings"]), 7440)
        ids = {row["ID"] for row in payload["plan"]["queue"]}
        # Every real finding ID (FIND-1..FIND-N) must appear in the plan queue - not an
        # exact set (the total grows as more real data is added).
        self.assertEqual(ids, {f"FIND-{i}" for i in range(1, len(payload["findings"]) + 1)})
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

    def test_max_budget_usd_rejects_a_value_above_the_ceiling(self):
        """Unbounded-consumption guardrail regression (OWASP LLM Top 10 2026 #6) - this
        field used to flow straight from an unvalidated form input to a real subprocess
        arg with no type/range check at all."""
        resp = client.post("/api/run", json={"pipeline": "scan", "max_budget_usd": "999999"})
        self.assertEqual(resp.status_code, 422)

    def test_max_budget_usd_rejects_a_non_numeric_value(self):
        resp = client.post("/api/run", json={"pipeline": "scan", "max_budget_usd": "not-a-number"})
        self.assertEqual(resp.status_code, 422)

    def test_max_budget_usd_accepts_a_reasonable_value(self):
        resp = client.post("/api/run", json={"pipeline": "scan", "max_budget_usd": "5.00"})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["dry_run"])

    def test_confirm_true_but_not_logged_in_is_rejected_before_ever_running_anything(self):
        """Login is required before the real (paid) path even runs cli.run() - not
        just before returning a result. Never logs in here, so if this test somehow
        got past the gate it would attempt a real, paid API call."""
        resp = client.post("/api/run", json={
            "pipeline": "scan", "path": "vulnerable-demo-app", "confirm": True,
        })
        self.assertEqual(resp.status_code, 401)

    def test_dry_run_with_finding_id_includes_the_scoped_flag_and_spends_nothing(self):
        """The "Trigger Remediation" button's preview step - proves the exact scoped
        command text is visible before ever calling cli.run() for real. Mocking
        app.cli.run itself (not just the underlying subprocess) is belt-and-suspenders
        here: dry_run=True already makes cli.run() a no-op internally, but this also
        lets us assert on the exact prompt text passed in."""
        with patch("app.cli.run", return_value=0) as mock_run:
            resp = client.post("/api/run", json={
                "pipeline": "remediate", "fix_or_generate": True, "finding_id": "FIND-1",
            })
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertTrue(payload["dry_run"])
        called_prompt = mock_run.call_args[0][0]
        self.assertEqual(called_prompt, "/remediate --generate --finding-id FIND-1")

    def test_unknown_finding_id_dry_run_still_just_previews(self):
        """A finding_id that has no matching approval must never error - the dry-run
        preview only describes the command, it doesn't look up the approval yet."""
        resp = client.post("/api/run", json={
            "pipeline": "remediate", "fix_or_generate": True, "finding_id": "FIND-9999999",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["dry_run"])


class ApiRunTriggersRemediation(unittest.TestCase):
    """/api/run's confirm=True + finding_id path - never calls the real cli.run(), so
    this never spends real API usage/credits. Uses its own isolated
    remediation_approvals.json (same pattern as ApiRemediationApprovals)."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.patcher = _patch_db_engine(self.tmpdir.name)
        self.patcher.start()
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)

    def tearDown(self):
        _logout()
        self.patcher.engine.dispose()
        self.patcher.stop()
        self.tmpdir.cleanup()

    def _create_and_approve(self, finding_id="FIND-1"):
        created = client.post("/api/remediation-approvals", json={"finding_id": finding_id, "requested_by": "eng@example.com"}).json()
        client.post(f"/api/remediation-approvals/{created['id']}/approve", json={"decided_by": "approver@example.com"})
        return created["id"]

    def test_confirm_true_with_finding_id_marks_the_approval_triggered(self):
        approval_id = self._create_and_approve("FIND-1")
        with patch("app.cli.run", return_value=0):
            resp = client.post("/api/run", json={
                "pipeline": "remediate", "fix_or_generate": True,
                "finding_id": "FIND-1", "confirm": True,
            })
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertFalse(payload["dry_run"])
        self.assertIn(f"Approval {approval_id} marked as remediation-triggered", payload["message"])

        approvals = client.get("/api/remediation-approvals").json()["approvals"]
        updated = next(a for a in approvals if a["id"] == approval_id)
        self.assertEqual(updated["status"], "remediation_triggered")
        self.assertEqual(updated["triggered_by"], TEST_ADMIN_EMAIL)

    def test_confirm_true_with_no_matching_approval_still_succeeds(self):
        """A finding with no approval on file at all must not break the run - playbook
        generation is independent of the approval record; only the status-update side
        effect is skipped."""
        with patch("app.cli.run", return_value=0):
            resp = client.post("/api/run", json={
                "pipeline": "remediate", "fix_or_generate": True,
                "finding_id": "FIND-9999999", "confirm": True,
            })
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertFalse(payload["dry_run"])
        self.assertNotIn("marked as remediation-triggered", payload["message"])

    def test_confirm_true_on_a_still_pending_approval_reports_the_status_error_but_still_succeeds(self):
        """mark_remediation_triggered() raises ValueError for a non-"approved" approval
        (see remediation_approvals/store.py) - the run itself still succeeded (exit_code
        0), so the response must say so while being honest that the approval's status
        wasn't updated."""
        created = client.post("/api/remediation-approvals", json={"finding_id": "FIND-1", "requested_by": "eng@example.com"}).json()
        with patch("app.cli.run", return_value=0):
            resp = client.post("/api/run", json={
                "pipeline": "remediate", "fix_or_generate": True,
                "finding_id": "FIND-1", "confirm": True,
            })
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertIn("Approval status not updated", payload["message"])
        approvals = client.get("/api/remediation-approvals").json()["approvals"]
        updated = next(a for a in approvals if a["id"] == created["id"])
        self.assertEqual(updated["status"], "pending")

    def test_confirm_true_but_not_logged_in_is_rejected(self):
        self._create_and_approve("FIND-1")
        _logout()
        resp = client.post("/api/run", json={
            "pipeline": "remediate", "fix_or_generate": True,
            "finding_id": "FIND-1", "confirm": True,
        })
        self.assertEqual(resp.status_code, 401)


class ApiStatus(unittest.TestCase):
    def test_status_endpoint(self):
        resp = client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["vulnhunt_findings"], 18)
        self.assertGreaterEqual(payload["remediation_findings"], 7440)
        self.assertEqual(payload["app_version"], fastapi_app.version)

    def test_status_reports_real_checked_facts_not_hardcoded_ones(self):
        resp = client.get("/api/status")
        payload = resp.json()
        self.assertIsNone(payload["remediation_findings_error"])
        self.assertIn(payload["smtp_configured"], (True, False))
        self.assertIn(payload["session_secret_configured"], (True, False))
        self.assertIn("available", payload["threat_intel"])

    def test_status_degrades_honestly_when_findings_file_is_unreadable(self):
        with patch.object(dashboard_data, "load_remediation_findings", side_effect=RuntimeError("disk gremlins")):
            resp = client.get("/api/status")
        payload = resp.json()
        self.assertEqual(resp.status_code, 200)  # a broken health check must not itself 500
        self.assertEqual(payload["status"], "degraded")
        self.assertEqual(payload["remediation_findings"], 0)
        self.assertIn("disk gremlins", payload["remediation_findings_error"])

    def test_status_reports_real_uptime_and_scheduler_and_data_store_facts(self):
        resp = client.get("/api/status")
        payload = resp.json()
        self.assertGreaterEqual(payload["uptime_seconds"], 0)
        self.assertIn(payload["notification_scheduler_alive"], (True, False))
        for store in ("exceptions", "remediation_approvals", "activity_log", "ai_usage_log"):
            fact = payload["data_stores"][store]
            self.assertIn("exists", fact)
            self.assertIn("record_count", fact)

    def test_data_store_fact_reports_a_missing_file_honestly(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_engine = create_engine(f"sqlite:///{Path(tmpdir) / 'does-not-exist.db'}")
            try:
                with patch.object(db_module, "get_engine", return_value=missing_engine):
                    resp = client.get("/api/status")
            finally:
                missing_engine.dispose()
        fact = resp.json()["data_stores"]["ai_usage_log"]
        self.assertFalse(fact["exists"])
        self.assertIsNone(fact["last_modified"])
        self.assertIsNone(fact["record_count"])

    def test_data_store_fact_reports_a_real_record_count(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            real_engine = create_engine(f"sqlite:///{Path(tmpdir) / 'real.db'}")
            try:
                db_module.ensure_schema(real_engine)
                with real_engine.begin() as conn:
                    conn.execute(insert(db_module.ai_usage_log), [
                        {
                            "actor": "a@x.com", "route": "ai-assist", "model": "m", "usage": "{}",
                            "total_tokens": None, "total_cost_usd": None, "extraction_ok": False,
                            "timestamp": "2026-01-01T00:00:00+00:00",
                        }
                        for _ in range(3)
                    ])
                with patch.object(db_module, "get_engine", return_value=real_engine):
                    resp = client.get("/api/status")
            finally:
                real_engine.dispose()
        fact = resp.json()["data_stores"]["ai_usage_log"]
        self.assertTrue(fact["exists"])
        self.assertEqual(fact["record_count"], 3)
        self.assertIsNotNone(fact["last_modified"])


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
        self.assertEqual(ids, {f"FIND-{i}" for i in range(1, len(payload["findings"]) + 1)})

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

    def test_queue_findings_carry_the_infra_sub_category(self):
        """Real windows-server/unix-server findings should classify as "os" - powers
        the Infrastructure Vulnerabilities hub's OS/Network/Network Security/OT/Cloud
        cards (see infra_classification.py)."""
        resp = client.get("/api/queue")
        payload = resp.json()
        by_id = {f["id"]: f for f in payload["findings"]}
        self.assertEqual(by_id["FIND-1"]["infra_category"], "os")  # WIN-DC01, windows-server
        app_or_cert = [f for f in payload["findings"] if (f.get("asset") or {}).get("type") in ("application", "certificate")]
        self.assertTrue(app_or_cert)
        self.assertTrue(all(f["infra_category"] is None for f in app_or_cert))

    def test_queue_findings_carry_the_new_endpoint_printer_virtualization_categories(self):
        """windows-endpoint/mobile-device (endpoint), printer, and virtualization-host
        are real, populated infra sub-categories now - structural checks (not exact
        counts, which depend on live NVD sourcing), same pattern as the scale-up tests
        elsewhere in this suite."""
        resp = client.get("/api/queue")
        findings = resp.json()["findings"]
        by_type = {}
        for f in findings:
            t = (f.get("asset") or {}).get("type")
            by_type.setdefault(t, []).append(f)
        for asset_type, expected_category in (
            ("windows-endpoint", "endpoint"), ("mobile-device", "endpoint"),
            ("printer", "printer"), ("virtualization-host", "virtualization"),
        ):
            self.assertTrue(by_type.get(asset_type), f"no {asset_type} findings present")
            self.assertTrue(all(f["infra_category"] == expected_category for f in by_type[asset_type]))

    def test_new_endpoint_printer_virtualization_findings_carry_remediation_mechanism(self):
        """Purely informational field naming the real-world patch tool (SCCM/MDM/vendor
        firmware/vendor hypervisor tooling) - present for the 4 new asset types, still
        null for windows-server/unix-server (unaffected, no working automation claim
        changes) since only a real remediation_domain implies working automation."""
        resp = client.get("/api/queue")
        findings = resp.json()["findings"]
        mechanism_by_type = {
            "windows-endpoint": "SCCM / Microsoft Configuration Manager",
            "mobile-device": "MDM (e.g. Microsoft Intune)",
            "printer": "Vendor firmware update (manual or vendor management console)",
            "virtualization-host": "Vendor hypervisor patch tooling (e.g. VMware Update Manager)",
        }
        for asset_type, expected_mechanism in mechanism_by_type.items():
            matches = [f for f in findings if (f.get("asset") or {}).get("type") == asset_type]
            self.assertTrue(matches, f"no {asset_type} findings present")
            self.assertTrue(all(f.get("remediation_mechanism") == expected_mechanism for f in matches))
        windows_server = [f for f in findings if (f.get("asset") or {}).get("type") == "windows-server"]
        self.assertTrue(windows_server)
        self.assertTrue(all(not f.get("remediation_mechanism") for f in windows_server))

    def test_live_queue_cache_reflects_a_real_approval_immediately(self):
        """load_live_queue() is real-time-cached (see data.py's _live_queue_cache_key())
        for performance at real dataset scale - this proves that cache still shows a
        genuine change (a real approval decision) on the very next call, not a stale
        pre-approval snapshot, regardless of the cache being warm."""
        with tempfile.TemporaryDirectory() as tmpdir:
            patcher = _patch_db_engine(tmpdir)
            patcher.start()
            try:
                before = client.get("/api/queue").json()
                find_1_before = next(f for f in before["findings"] if f["id"] == "FIND-1")
                self.assertIsNone(find_1_before["remediation_approval"])

                remediation_approvals_store.create_approval_request(
                    "FIND-1", "tester@example.com", find_1_before["remediation_policy"]["next_window"],
                )
                after = client.get("/api/queue").json()
                find_1_after = next(f for f in after["findings"] if f["id"] == "FIND-1")
                self.assertIsNotNone(find_1_after["remediation_approval"])
                self.assertEqual(find_1_after["remediation_approval"]["requested_by"], "tester@example.com")
            finally:
                patcher.engine.dispose()
                patcher.stop()

    def test_queue_findings_carry_eol_eos_status(self):
        """Real, dated vendor-lifecycle classification (remediation/enrichment/
        eol_lookup.py) - every finding gets an eol_status dict, "unknown" for asset OS
        strings that don't match anything (network/OT firmware mostly), a real
        status/date/vendor/source for ones that do (Windows Server/Windows 10/Ubuntu/
        CentOS)."""
        resp = client.get("/api/queue")
        payload = resp.json()
        by_id = {f["id"]: f for f in payload["findings"]}
        self.assertIn("eol_status", by_id["FIND-1"])  # WIN-DC01, Windows Server 2019
        self.assertIn(by_id["FIND-1"]["eol_status"]["status"], ("eol", "eol-soon", "supported"))
        self.assertTrue(all("eol_status" in f for f in payload["findings"]))

    def test_queue_findings_carry_exploit_criteria_matches(self):
        """Every finding gets an exploit_criteria_matches list (remediation/enrichment/
        exploit_criteria.py) - empty for anything with no cve, real rule matches for
        CVE-bearing findings whose real kev/poc_available/user_interaction_required/
        epss signals satisfy a configured rule."""
        resp = client.get("/api/queue")
        payload = resp.json()
        self.assertTrue(all("exploit_criteria_matches" in f for f in payload["findings"]))
        no_cve = [f for f in payload["findings"] if not f.get("cve")]
        self.assertTrue(no_cve)
        self.assertTrue(all(f["exploit_criteria_matches"] == [] for f in no_cve))


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


class ApiExploitCriteria(unittest.TestCase):
    """Every test here uses a temporary rules file (via patching DEFAULT_RULES_PATH) so
    the suite never permanently mutates the real, shipped exploit_criteria_rules.yaml."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp_rules_path = Path(self.tmpdir.name) / "exploit_criteria_rules.yaml"
        self.tmp_rules_path.write_text(
            exploit_criteria.DEFAULT_RULES_PATH.read_text(encoding="utf-8"), encoding="utf-8"
        )
        self.patcher = patch.object(exploit_criteria, "DEFAULT_RULES_PATH", self.tmp_rules_path)
        self.patcher.start()
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)  # POST is admin-gated

    def tearDown(self):
        _logout()
        self.patcher.stop()
        self.tmpdir.cleanup()

    def test_get_returns_current_rules_text(self):
        resp = client.get("/api/exploit-criteria")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("kev-no-interaction-poc-available", resp.json()["rules_text"])

    def test_post_valid_yaml_saves(self):
        new_text = self.tmp_rules_path.read_text(encoding="utf-8").replace("epss_min: 0.5", "epss_min: 0.7")
        resp = client.post("/api/exploit-criteria", json={"rules_text": new_text})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("saved", resp.json()["message"])
        self.assertIn("epss_min: 0.7", self.tmp_rules_path.read_text(encoding="utf-8"))

    def test_post_invalid_yaml_is_rejected_and_file_unchanged(self):
        original = self.tmp_rules_path.read_text(encoding="utf-8")
        resp = client.post("/api/exploit-criteria", json={"rules_text": "not: valid: yaml: ["})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("invalid YAML", resp.json()["detail"])
        self.assertEqual(self.tmp_rules_path.read_text(encoding="utf-8"), original)

    def test_post_without_login_is_rejected(self):
        _logout()
        resp = client.post("/api/exploit-criteria", json={"rules_text": "rules: []"})
        self.assertEqual(resp.status_code, 401)

    def test_post_as_non_admin_is_rejected(self):
        _logout()
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        resp = client.post("/api/exploit-criteria", json={"rules_text": "rules: []"})
        self.assertEqual(resp.status_code, 403)

    def test_preview_computes_counts_without_saving_and_without_login(self):
        _logout()  # preview is read-only, deliberately ungated - like servicenow preview
        rules_text = (
            "rules:\n"
            "  - id: any-kev\n"
            "    label: Any KEV-listed finding\n"
            "    conditions: {kev_listed: true}\n"
        )
        resp = client.post("/api/exploit-criteria/preview", json={"rules_text": rules_text})
        self.assertEqual(resp.status_code, 200)
        counts = resp.json()["counts"]
        self.assertEqual(len(counts), 1)
        self.assertEqual(counts[0]["id"], "any-kev")
        self.assertGreater(counts[0]["count"], 0)  # real KEV-listed findings exist
        # Saving is untouched by a preview call.
        self.assertNotIn("any-kev", self.tmp_rules_path.read_text(encoding="utf-8"))

    def test_preview_rejects_invalid_yaml(self):
        resp = client.post("/api/exploit-criteria/preview", json={"rules_text": "not: valid: yaml: ["})
        self.assertEqual(resp.status_code, 400)


class ApiRemediationPolicy(unittest.TestCase):
    """Every test here uses a temporary rules file (via patching DEFAULT_RULES_PATH) so
    the suite never permanently mutates the real, shipped remediation_policy.yaml."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp_rules_path = Path(self.tmpdir.name) / "remediation_policy.yaml"
        self.tmp_rules_path.write_text(
            remediation_policy_engine.DEFAULT_RULES_PATH.read_text(encoding="utf-8"), encoding="utf-8"
        )
        self.patcher = patch.object(remediation_policy_engine, "DEFAULT_RULES_PATH", self.tmp_rules_path)
        self.patcher.start()
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)  # POST is admin-gated

    def tearDown(self):
        _logout()
        self.patcher.stop()
        self.tmpdir.cleanup()

    def test_get_returns_current_rules_text(self):
        resp = client.get("/api/remediation-policy")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("policies", resp.json()["rules_text"])

    def test_post_valid_yaml_saves(self):
        new_text = self.tmp_rules_path.read_text(encoding="utf-8").replace('cadence: "weekly"', 'cadence: "monthly"')
        resp = client.post("/api/remediation-policy", json={"rules_text": new_text})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("saved", resp.json()["message"])
        self.assertNotIn('cadence: "weekly"', self.tmp_rules_path.read_text(encoding="utf-8"))

    def test_post_invalid_yaml_is_rejected_and_file_unchanged(self):
        original = self.tmp_rules_path.read_text(encoding="utf-8")
        resp = client.post("/api/remediation-policy", json={"rules_text": "not: valid: yaml: ["})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("invalid YAML", resp.json()["detail"])
        self.assertEqual(self.tmp_rules_path.read_text(encoding="utf-8"), original)

    def test_post_without_login_is_rejected(self):
        _logout()
        resp = client.post("/api/remediation-policy", json={"rules_text": "policies: {}"})
        self.assertEqual(resp.status_code, 401)

    def test_post_as_non_admin_is_rejected(self):
        _logout()
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        resp = client.post("/api/remediation-policy", json={"rules_text": "policies: {}"})
        self.assertEqual(resp.status_code, 403)

    def test_kev_listed_finding_shows_emergency_change_type_on_the_live_queue(self):
        """FIND-1 (PrintNightmare, KEV-listed) must always resolve to change_type
        emergency via the KEV override regardless of its domain's configured default -
        same regression guard as test_remediation_policy_engine.py's own check, exercised
        here through the full /api/queue merge in dashboard/data.py."""
        resp = client.get("/api/queue")
        findings_by_id = {f["id"]: f for f in resp.json()["findings"]}
        policy = findings_by_id["FIND-1"]["remediation_policy"]
        self.assertEqual(policy["change_type"], "emergency")
        self.assertTrue(policy["emergency_override"])
        self.assertIn("next_window", policy)


class ApiServiceNow(unittest.TestCase):
    def test_preview_lists_every_finding_with_no_credentials_needed(self):
        resp = client.get("/api/servicenow/preview")
        self.assertEqual(resp.status_code, 200)
        previews = resp.json()["previews"]
        self.assertEqual({p["finding_id"] for p in previews}, {f"FIND-{i}" for i in range(1, len(previews) + 1)})

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

    def test_send_rejects_an_instance_value_that_could_bypass_the_url_template(self):
        """SSRF guardrail regression: 'instance' is interpolated into a fixed
        f"https://{instance}.service-now.com" template - a value containing a URL
        fragment character would otherwise let an attacker-controlled host survive
        past a naive suffix check. See remediation/connectors/url_safety.py."""
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/servicenow/send", json={
                "instance": "169.254.169.254#", "username": "u", "password": "p",
                "table": "incident", "confirm": True,
            })
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

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
        self.assertEqual({p["finding_id"] for p in previews}, {f"FIND-{i}" for i in range(1, len(previews) + 1)})
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
        self.assertEqual({p["finding_id"] for p in previews}, {f"FIND-{i}" for i in range(1, len(previews) + 1)})
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


class ApiTenable(unittest.TestCase):
    """Route-level safety-boundary tests only (rbac gating, field validation, the
    dry-run guarantee) - same economy-of-testing philosophy as ApiServiceNow/ApiSplunk
    above. The actual fetch/normalize business logic is already thoroughly unit-tested
    against mocked HTTP in tests/test_connectors.py, so it isn't re-proven here."""

    def test_test_connection_requires_login(self):
        resp = client.post("/api/tenable/test-connection", json={"access_key": "k", "secret_key": "s"})
        self.assertEqual(resp.status_code, 401)

    def test_test_connection_with_missing_credentials_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/tenable/test-connection", json={"access_key": "", "secret_key": ""})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)
        self.assertIn("required", resp.json()["detail"])

    def test_fetch_without_confirm_never_touches_the_network(self):
        resp = client.post("/api/tenable/fetch", json={"access_key": "k", "secret_key": "s"})
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertTrue(payload["preview_only"])
        self.assertIsNone(payload["written_to"])

    def test_fetch_with_confirm_but_missing_credentials_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/tenable/fetch", json={"access_key": "", "secret_key": "", "confirm": True})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_fetch_with_confirm_but_not_logged_in_is_rejected(self):
        resp = client.post("/api/tenable/fetch", json={"access_key": "k", "secret_key": "s", "confirm": True})
        self.assertEqual(resp.status_code, 401)


class ApiQualys(unittest.TestCase):
    def test_test_connection_requires_login(self):
        resp = client.post("/api/qualys/test-connection", json={"username": "u", "password": "p", "platform_url": "https://qualysapi.qualys.com"})
        self.assertEqual(resp.status_code, 401)

    def test_test_connection_with_missing_credentials_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/qualys/test-connection", json={"username": "", "password": "", "platform_url": ""})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_test_connection_rejects_a_cloud_metadata_endpoint(self):
        """SSRF guardrail regression - platform_url used to be handed straight to
        requests.Session().get() with zero validation of the destination. See
        remediation/connectors/url_safety.py."""
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/qualys/test-connection", json={
                "username": "u", "password": "p", "platform_url": "http://169.254.169.254/",
            })
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_fetch_without_confirm_never_touches_the_network(self):
        resp = client.post("/api/qualys/fetch", json={"username": "u", "password": "p", "platform_url": "https://qualysapi.qualys.com"})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["preview_only"])

    def test_fetch_with_confirm_but_missing_credentials_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/qualys/fetch", json={"username": "", "password": "", "platform_url": "", "confirm": True})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_fetch_with_confirm_but_not_logged_in_is_rejected(self):
        resp = client.post("/api/qualys/fetch", json={"username": "u", "password": "p", "platform_url": "https://qualysapi.qualys.com", "confirm": True})
        self.assertEqual(resp.status_code, 401)


class ApiPrismaCloud(unittest.TestCase):
    def test_test_connection_requires_login(self):
        resp = client.post("/api/prismacloud/test-connection", json={"access_key_id": "k", "secret_key": "s", "base_url": "https://api.prismacloud.io"})
        self.assertEqual(resp.status_code, 401)

    def test_test_connection_with_missing_credentials_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/prismacloud/test-connection", json={"access_key_id": "", "secret_key": "", "base_url": ""})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_fetch_without_confirm_never_touches_the_network(self):
        resp = client.post("/api/prismacloud/fetch", json={"access_key_id": "k", "secret_key": "s", "base_url": "https://api.prismacloud.io"})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["preview_only"])

    def test_fetch_with_confirm_but_missing_credentials_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/prismacloud/fetch", json={"access_key_id": "", "secret_key": "", "base_url": "", "confirm": True})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_fetch_with_confirm_but_not_logged_in_is_rejected(self):
        resp = client.post("/api/prismacloud/fetch", json={"access_key_id": "k", "secret_key": "s", "base_url": "https://api.prismacloud.io", "confirm": True})
        self.assertEqual(resp.status_code, 401)


class ApiCortexXsiam(unittest.TestCase):
    def test_test_connection_requires_login(self):
        resp = client.post("/api/cortex-xsiam/test-connection", json={"api_key": "k", "api_key_id": "1", "base_url": "https://x.example.com"})
        self.assertEqual(resp.status_code, 401)

    def test_test_connection_with_missing_credentials_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/cortex-xsiam/test-connection", json={"api_key": "", "api_key_id": "", "base_url": ""})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_fetch_without_confirm_never_touches_the_network(self):
        resp = client.post("/api/cortex-xsiam/fetch", json={"api_key": "k", "api_key_id": "1", "base_url": "https://x.example.com"})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["preview_only"])

    def test_fetch_with_confirm_but_missing_credentials_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/cortex-xsiam/fetch", json={"api_key": "", "api_key_id": "", "base_url": "", "confirm": True})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_fetch_with_confirm_but_not_logged_in_is_rejected(self):
        resp = client.post("/api/cortex-xsiam/fetch", json={"api_key": "k", "api_key_id": "1", "base_url": "https://x.example.com", "confirm": True})
        self.assertEqual(resp.status_code, 401)


class ApiInfoblox(unittest.TestCase):
    def test_test_connection_requires_login(self):
        resp = client.post("/api/infoblox/test-connection", json={"grid_master": "gm.example.com", "username": "u", "password": "p"})
        self.assertEqual(resp.status_code, 401)

    def test_test_connection_with_missing_credentials_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/infoblox/test-connection", json={"grid_master": "", "username": "", "password": ""})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_test_connection_rejects_a_cloud_metadata_endpoint(self):
        """SSRF guardrail regression - grid_master had literally zero transform before
        landing in an f-string URL. See remediation/connectors/url_safety.py."""
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/infoblox/test-connection", json={
                "grid_master": "169.254.169.254", "username": "u", "password": "p",
            })
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_fetch_without_confirm_never_touches_the_network(self):
        resp = client.post("/api/infoblox/fetch", json={"grid_master": "gm.example.com", "username": "u", "password": "p"})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["preview_only"])

    def test_fetch_with_confirm_but_missing_credentials_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/infoblox/fetch", json={"grid_master": "", "username": "", "password": "", "confirm": True})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_fetch_with_confirm_but_not_logged_in_is_rejected(self):
        resp = client.post("/api/infoblox/fetch", json={"grid_master": "gm.example.com", "username": "u", "password": "p", "confirm": True})
        self.assertEqual(resp.status_code, 401)


class ApiAxonius(unittest.TestCase):
    def test_test_connection_requires_login(self):
        resp = client.post("/api/axonius/test-connection", json={"base_url": "https://axonius.example.com", "api_key": "k", "api_secret": "s"})
        self.assertEqual(resp.status_code, 401)

    def test_test_connection_with_missing_credentials_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/axonius/test-connection", json={"base_url": "", "api_key": "", "api_secret": ""})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_fetch_without_confirm_never_touches_the_network(self):
        resp = client.post("/api/axonius/fetch", json={"base_url": "https://axonius.example.com", "api_key": "k", "api_secret": "s"})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["preview_only"])

    def test_fetch_with_confirm_but_missing_credentials_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/axonius/fetch", json={"base_url": "", "api_key": "", "api_secret": "", "confirm": True})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_fetch_with_confirm_but_not_logged_in_is_rejected(self):
        resp = client.post("/api/axonius/fetch", json={"base_url": "https://axonius.example.com", "api_key": "k", "api_secret": "s", "confirm": True})
        self.assertEqual(resp.status_code, 401)


class ApiActiveDirectory(unittest.TestCase):
    def test_test_connection_requires_login(self):
        resp = client.post("/api/active-directory/test-connection", json={"server": "dc01.example.com", "base_dn": "DC=example,DC=com"})
        self.assertEqual(resp.status_code, 401)

    def test_test_connection_with_missing_fields_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/active-directory/test-connection", json={"server": "", "base_dn": ""})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_fetch_without_confirm_never_touches_the_network(self):
        resp = client.post("/api/active-directory/fetch", json={"server": "dc01.example.com", "base_dn": "DC=example,DC=com"})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["preview_only"])

    def test_fetch_with_confirm_but_missing_fields_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/active-directory/fetch", json={"server": "", "base_dn": "", "confirm": True})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_fetch_with_confirm_but_not_logged_in_is_rejected(self):
        resp = client.post("/api/active-directory/fetch", json={"server": "dc01.example.com", "base_dn": "DC=example,DC=com", "confirm": True})
        self.assertEqual(resp.status_code, 401)


class ApiOpenVas(unittest.TestCase):
    def test_test_connection_requires_login(self):
        resp = client.post("/api/openvas/test-connection", json={"hostname": "gvm.example.com", "username": "admin", "password": "secret"})
        self.assertEqual(resp.status_code, 401)

    def test_test_connection_with_missing_target_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/openvas/test-connection", json={"hostname": "", "socket_path": "", "username": "admin", "password": "secret"})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_test_connection_rejects_a_cloud_metadata_endpoint(self):
        """SSRF guardrail regression. See remediation/connectors/url_safety.py."""
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/openvas/test-connection", json={
                "hostname": "169.254.169.254", "username": "admin", "password": "secret",
            })
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_test_connection_with_missing_credentials_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/openvas/test-connection", json={"hostname": "gvm.example.com", "username": "", "password": ""})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_scan_start_without_confirm_never_touches_the_network(self):
        resp = client.post("/api/openvas/scan/start", json={"hostname": "gvm.example.com", "username": "admin", "password": "secret", "hosts": "10.0.0.1"})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["preview_only"])
        self.assertIsNone(resp.json()["task_id"])

    def test_scan_start_with_confirm_but_not_logged_in_is_rejected(self):
        resp = client.post("/api/openvas/scan/start", json={"hostname": "gvm.example.com", "username": "admin", "password": "secret", "hosts": "10.0.0.1", "confirm": True})
        self.assertEqual(resp.status_code, 401)

    def test_scan_start_with_confirm_but_no_hosts_is_rejected(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/openvas/scan/start", json={"hostname": "gvm.example.com", "username": "admin", "password": "secret", "hosts": "", "confirm": True})
        finally:
            _logout()
        self.assertEqual(resp.status_code, 400)

    def test_scan_status_requires_login(self):
        resp = client.post("/api/openvas/scan/status", json={"hostname": "gvm.example.com", "username": "admin", "password": "secret", "task_id": "task-1"})
        self.assertEqual(resp.status_code, 401)

    def test_scan_import_without_confirm_never_touches_the_network(self):
        resp = client.post("/api/openvas/scan/import", json={"hostname": "gvm.example.com", "username": "admin", "password": "secret", "task_id": "task-1"})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["preview_only"])

    def test_scan_import_with_confirm_but_not_logged_in_is_rejected(self):
        resp = client.post("/api/openvas/scan/import", json={"hostname": "gvm.example.com", "username": "admin", "password": "secret", "task_id": "task-1", "confirm": True})
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
        # FIND-999 is a genuinely real finding now that bulk sample data pushed the
        # total well past 999 - use an ID far outside any real range instead.
        resp = client.post("/api/ai-assist", json={"finding_id": "FIND-9999999", "action": "explain"})
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

    def test_confirm_true_passes_a_per_call_budget_cap(self):
        """Unbounded-consumption guardrail regression (OWASP LLM Top 10 2026 #6) - this
        subprocess call used to pass no --max-budget-usd at all, relying solely on the
        daily token-limit pre-flight check to bound spend."""
        fake_result = MagicMock(returncode=0, stdout="ok", stderr="")
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            with patch("app.cli.find_claude_binary", return_value="/fake/claude"), \
                 patch("app.subprocess.run", return_value=fake_result) as mock_run:
                client.post("/api/ai-assist", json={
                    "finding_id": "FIND-1", "action": "explain", "confirm": True,
                })
        finally:
            _logout()
        called_command = mock_run.call_args.args[0]
        self.assertIn("--max-budget-usd", called_command)

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

    def test_confirm_true_extracts_result_and_records_real_usage_from_json_response(self):
        fake_stdout = json.dumps({
            "result": "The real JSON-extracted response.",
            "total_cost_usd": 0.0042,
            "usage": {"input_tokens": 300, "output_tokens": 80},
        })
        fake_result = MagicMock(returncode=0, stdout=fake_stdout, stderr="")
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            with patch("app.cli.find_claude_binary", return_value="/fake/claude"), \
                 patch("app.subprocess.run", return_value=fake_result):
                resp = client.post("/api/ai-assist", json={
                    "finding_id": "FIND-1", "action": "explain", "confirm": True,
                })
            self.assertEqual(resp.json()["response"], "The real JSON-extracted response.")
            recorded = ai_usage_log.list_usage(limit=1)[0]
            self.assertEqual(recorded["actor"], TEST_ADMIN_EMAIL)
            self.assertEqual(recorded["route"], "ai-assist")
            self.assertEqual(recorded["total_tokens"], 380)
            self.assertEqual(recorded["total_cost_usd"], 0.0042)
        finally:
            _logout()

    def test_confirm_true_rejected_with_429_once_daily_limit_reached(self):
        fake_result = MagicMock(returncode=0, stdout=json.dumps({
            "result": "won't get here", "usage": {"input_tokens": 10**9, "output_tokens": 0},
        }), stderr="")
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            # Other tests in this class/module also record real usage against the same
            # module-wide patched DB (see setUpModule) - reset it so this test's "first
            # call is under the limit" assumption holds regardless of run order.
            with db_module.get_engine().begin() as conn:
                conn.execute(delete(db_module.ai_usage_log))
            ai_governance.save_governance("sonnet", 100, {})
            # First call: under the limit (0 used so far), goes through and pushes
            # this user's real recorded usage past 100 tokens.
            with patch("app.cli.find_claude_binary", return_value="/fake/claude"), \
                 patch("app.subprocess.run", return_value=fake_result):
                first = client.post("/api/ai-assist", json={
                    "finding_id": "FIND-1", "action": "explain", "confirm": True,
                })
            self.assertEqual(first.status_code, 200)
            # Second call: now over the configured 100-token daily cap - must be
            # rejected BEFORE any subprocess call is made.
            with patch("app.cli.find_claude_binary", return_value="/fake/claude"), \
                 patch("app.subprocess.run", return_value=fake_result) as mock_run:
                second = client.post("/api/ai-assist", json={
                    "finding_id": "FIND-2", "action": "explain", "confirm": True,
                })
            self.assertEqual(second.status_code, 429)
            mock_run.assert_not_called()
        finally:
            ai_governance.save_governance(None, None, {})
            _logout()


class ApiAdminAiGovernance(unittest.TestCase):
    def tearDown(self):
        ai_governance.save_governance(None, None, {})
        _logout()

    def test_get_requires_admin(self):
        resp = client.get("/api/admin/ai-governance")
        self.assertEqual(resp.status_code, 401)
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        resp = client.get("/api/admin/ai-governance")
        self.assertEqual(resp.status_code, 403)

    def test_get_returns_honest_unconfigured_defaults(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        resp = client.get("/api/admin/ai-governance")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertIsNone(payload["default_model"])
        self.assertIsNone(payload["daily_token_limit_per_user"])

    def test_post_saves_and_get_reflects_it(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        resp = client.post("/api/admin/ai-governance", json={
            "default_model": "opus", "daily_token_limit_per_user": 200000, "per_user_overrides": {},
        })
        self.assertEqual(resp.status_code, 200)
        resp = client.get("/api/admin/ai-governance")
        self.assertEqual(resp.json()["default_model"], "opus")
        self.assertEqual(resp.json()["daily_token_limit_per_user"], 200000)

    def test_post_rejects_unknown_model_with_400(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        resp = client.post("/api/admin/ai-governance", json={
            "default_model": "gpt-5", "daily_token_limit_per_user": None, "per_user_overrides": {},
        })
        self.assertEqual(resp.status_code, 400)

    def test_post_requires_admin(self):
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        resp = client.post("/api/admin/ai-governance", json={
            "default_model": "sonnet", "daily_token_limit_per_user": None, "per_user_overrides": {},
        })
        self.assertEqual(resp.status_code, 403)


class ApiAdminAiUsage(unittest.TestCase):
    def tearDown(self):
        _logout()

    def test_get_requires_admin(self):
        resp = client.get("/api/admin/ai-usage")
        self.assertEqual(resp.status_code, 401)

    def test_get_returns_real_recorded_usage_shape(self):
        ai_usage_log.record_usage(
            TEST_ADMIN_EMAIL, "ai-assist", "claude-sonnet-5",
            {"input_tokens": 100, "output_tokens": 20, "cache_creation_input_tokens": None, "cache_read_input_tokens": None},
            0.01, True,
        )
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        resp = client.get("/api/admin/ai-usage")
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertIn(TEST_ADMIN_EMAIL, payload["all_time_by_user"])
        self.assertGreaterEqual(payload["all_time_by_user"][TEST_ADMIN_EMAIL]["total_tokens"], 120)
        self.assertIn("governance", payload)
        self.assertIn("recent_calls", payload)

    def test_budget_reflects_real_recorded_spend_and_the_real_per_call_cap(self):
        ai_usage_log.record_usage(
            TEST_ADMIN_EMAIL, "ai-assist", "claude-sonnet-5",
            {"input_tokens": 100, "output_tokens": 20, "cache_creation_input_tokens": None, "cache_read_input_tokens": None},
            0.05, True,
        )
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        payload = client.get("/api/admin/ai-usage").json()
        budget = payload["budget"]
        self.assertEqual(budget["max_cost_usd_per_call"], float(cli.DEFAULT_MAX_BUDGET_USD))
        # >= (not ==) since this shared usage log can carry other real recorded calls
        # from sibling tests in this module - same convention test_get_returns_real_
        # recorded_usage_shape above already uses for the same reason.
        for window in ("today", "last_7_days", "last_30_days", "all_time"):
            self.assertGreaterEqual(budget[window]["total_cost_usd"], 0.05)


class ApiAdminUsers(unittest.TestCase):
    def tearDown(self):
        _logout()

    def test_list_requires_admin(self):
        resp = client.get("/api/admin/users")
        self.assertEqual(resp.status_code, 401)

    def test_list_returns_real_users_without_a_password_hash(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        users_by_email = {u["email"]: u for u in client.get("/api/admin/users").json()["users"]}
        self.assertIn(TEST_ADMIN_EMAIL, users_by_email)
        self.assertNotIn("password_hash", users_by_email[TEST_ADMIN_EMAIL])
        self.assertIsNone(users_by_email[TEST_USER_EMAIL]["team"])

    def test_create_requires_admin(self):
        resp = client.post("/api/admin/users", json={"email": "rbac-new@test.local", "password": "somepassword1", "name": "New"})
        self.assertEqual(resp.status_code, 401)

    def test_create_then_appears_in_the_list_with_its_real_team(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        resp = client.post("/api/admin/users", json={
            "email": "rbac-new@test.local", "password": "somepassword1", "name": "New Person", "team": "Platform",
        })
        self.assertEqual(resp.status_code, 200)
        users_by_email = {u["email"]: u for u in client.get("/api/admin/users").json()["users"]}
        self.assertEqual(users_by_email["rbac-new@test.local"]["team"], "Platform")

    def test_create_rejects_a_duplicate_email(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        resp = client.post("/api/admin/users", json={"email": TEST_ADMIN_EMAIL, "password": "somepassword1", "name": "Dup"})
        self.assertEqual(resp.status_code, 400)

    def test_set_team_requires_admin(self):
        resp = client.post(f"/api/admin/users/{TEST_USER_EMAIL}/team", json={"team": "Platform"})
        self.assertEqual(resp.status_code, 401)

    def test_set_team_on_unknown_user_is_404(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        resp = client.post("/api/admin/users/nobody@test.local/team", json={"team": "Platform"})
        self.assertEqual(resp.status_code, 404)

    def test_set_role_requires_admin(self):
        resp = client.post(f"/api/admin/users/{TEST_USER_EMAIL}/role", json={"role": "admin"})
        self.assertEqual(resp.status_code, 401)

    def test_set_role_rejects_an_invalid_role(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        resp = client.post(f"/api/admin/users/{TEST_USER_EMAIL}/role", json={"role": "superuser"})
        self.assertEqual(resp.status_code, 400)

    def test_set_role_on_unknown_user_is_404(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        resp = client.post("/api/admin/users/nobody@test.local/role", json={"role": "admin"})
        self.assertEqual(resp.status_code, 404)


class ApiTeamScopedRbac(unittest.TestCase):
    """Real per-team RBAC on finding/asset views. Uses a DEDICATED test account
    (never TEST_USER_EMAIL, which many unrelated tests elsewhere in this module log in
    as expecting full, unfiltered access - giving it a team would silently break all
    of them) so this class's own team assignment can't leak into any other test.
    Exceptions/remediation-approvals tests use their own isolated temp DB, same
    pattern as ApiExceptions/ApiRemediationApprovals, so this class never mutates the
    real, shared remediation/vulnhunter.db.

    Asset ownership and user accounts now live in that same shared DB - each test
    method gets a brand-new, empty one (see setUp, and _patch_db_engine()'s own
    docstring for why it already seeds the two standard demo accounts), so this
    class's own team assignment and test account can't be created once in setUpClass
    the way they used to be: setUpClass's writes would land in setUpModule's
    module-wide DB, not the fresh per-test one any individual test method actually
    runs against. Re-seeding both in setUp (cheap - a handful of single-row writes)
    keeps every test method's DB self-contained while still starting genuinely empty
    of exceptions/approvals, which is the isolation this class actually needs."""

    TEAM_USER_EMAIL = "rbac-team-member@test.local"
    TEAM_USER_PASSWORD = "rbac-team-password-1"
    # Fixed teams, explicitly assigned below to two real assets (WIN-DC01/LNX-DB03,
    # used throughout this test file and confirmed to carry real findings in the
    # sample data) - not discovered from ambient ownership data, since the isolated
    # per-test DB starts with none. Two distinct teams (not just one) so "some other
    # team's finding" comparisons below have a real, different team to find.
    real_team = "RBAC Test Team"
    other_team = "RBAC Other Team"

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_patcher = _patch_db_engine(self.tmpdir.name)
        self.db_patcher.start()
        auth_users.create_user(self.TEAM_USER_EMAIL, self.TEAM_USER_PASSWORD, "Team Member", role="user")
        asset_inventory.set_owner("WIN-DC01", "Test Owner", self.real_team)
        asset_inventory.set_owner("LNX-DB03", "Other Test Owner", self.other_team)
        auth_users.set_team(self.TEAM_USER_EMAIL, self.real_team)

    def tearDown(self):
        _logout()
        self.db_patcher.engine.dispose()
        self.db_patcher.stop()
        self.tmpdir.cleanup()

    def test_admin_sees_the_same_unfiltered_view_as_anonymous(self):
        anonymous_count = len(client.get("/api/assets").json()["assets"])
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        admin_count = len(client.get("/api/assets").json()["assets"])
        self.assertEqual(admin_count, anonymous_count)

    def test_anonymous_access_remains_unfiltered(self):
        unfiltered_count = len(client.get("/api/assets").json()["assets"])
        self.assertGreater(unfiltered_count, 0)

    def test_ai_assist_dry_run_preview_respects_team_scoping(self):
        """Guardrail regression test (OWASP LLM Top 10 2026 #2/#3): the free dry-run
        preview must not let a team-scoped user read another team's finding detail by
        guessing/enumerating a finding_id, even though it never spends real API usage."""
        queue = client.get("/api/queue").json()["findings"]
        other_team_finding = next(f for f in queue if f.get("team") and f["team"] != self.real_team)
        own_team_finding = next(f for f in queue if f.get("team") == self.real_team)

        _login(self.TEAM_USER_EMAIL, self.TEAM_USER_PASSWORD)
        try:
            blocked = client.post("/api/ai-assist", json={"finding_id": other_team_finding["id"], "action": "explain"})
            self.assertEqual(blocked.status_code, 404)

            allowed = client.post("/api/ai-assist", json={"finding_id": own_team_finding["id"], "action": "explain"})
            self.assertEqual(allowed.status_code, 200)
            self.assertTrue(allowed.json()["dry_run"])
        finally:
            _logout()

    def test_ai_assist_dry_run_preview_unfiltered_for_anonymous_and_admin(self):
        """Same baseline every other team-scoped view already guarantees: no session
        or an admin session is never MORE restrictive than a team-scoped one."""
        queue = client.get("/api/queue").json()["findings"]
        other_team_finding = next(f for f in queue if f.get("team") and f["team"] != self.real_team)

        anon = client.post("/api/ai-assist", json={"finding_id": other_team_finding["id"], "action": "explain"})
        self.assertEqual(anon.status_code, 200)

        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            admin = client.post("/api/ai-assist", json={"finding_id": other_team_finding["id"], "action": "explain"})
            self.assertEqual(admin.status_code, 200)
        finally:
            _logout()

    def test_non_admin_with_no_team_sees_everything_unfiltered(self):
        # TEST_USER_EMAIL has no team assigned - opt-in narrowing, not deny-by-default
        # (see _scope_to_team()'s own docstring for why).
        unfiltered_count = len(client.get("/api/assets").json()["assets"])
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        self.assertEqual(len(client.get("/api/assets").json()["assets"]), unfiltered_count)

    def test_non_admin_with_a_team_sees_only_that_teams_assets(self):
        unfiltered = client.get("/api/assets").json()["assets"]
        _login(self.TEAM_USER_EMAIL, self.TEAM_USER_PASSWORD)
        scoped = client.get("/api/assets").json()["assets"]
        self.assertLess(len(scoped), len(unfiltered))
        self.assertTrue(scoped)
        self.assertTrue(all(a["team"] == self.real_team for a in scoped))

    def test_non_admin_with_a_team_sees_only_that_teams_queue_findings(self):
        _login(self.TEAM_USER_EMAIL, self.TEAM_USER_PASSWORD)
        findings = client.get("/api/queue").json()["findings"]
        self.assertTrue(findings)
        self.assertTrue(all(f.get("team") == self.real_team for f in findings))

    def test_scoped_queue_sla_summary_reflects_only_the_scoped_findings(self):
        _login(self.TEAM_USER_EMAIL, self.TEAM_USER_PASSWORD)
        payload = client.get("/api/queue").json()
        expected_total = sum(payload["sla"].values())
        self.assertEqual(expected_total, len(payload["findings"]))

    def test_non_admin_with_a_team_sees_only_that_teams_exceptions(self):
        unfiltered = client.get("/api/queue").json()["findings"]
        own_team_finding = next(f for f in unfiltered if f.get("team") == self.real_team)
        other_team_finding = next(f for f in unfiltered if f.get("team") and f.get("team") != self.real_team)
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        client.post("/api/exceptions", json={
            "finding_id": own_team_finding["id"], "reason": "rbac test - own team",
            "requested_by": "tester@test.local", "approved_by": "manager@test.local",
            "expires_on": "2099-01-01",
        })
        client.post("/api/exceptions", json={
            "finding_id": other_team_finding["id"], "reason": "rbac test - other team",
            "requested_by": "tester@test.local", "approved_by": "manager@test.local",
            "expires_on": "2099-01-01",
        })
        _logout()
        _login(self.TEAM_USER_EMAIL, self.TEAM_USER_PASSWORD)
        exceptions = client.get("/api/exceptions").json()["exceptions"]
        finding_ids = {e["finding_id"] for e in exceptions}
        self.assertIn(own_team_finding["id"], finding_ids)
        self.assertNotIn(other_team_finding["id"], finding_ids)

    def test_non_admin_with_a_team_sees_only_that_teams_remediation_approvals(self):
        unfiltered = client.get("/api/queue").json()["findings"]
        own_team_finding = next(f for f in unfiltered if f.get("team") == self.real_team)
        other_team_finding = next(f for f in unfiltered if f.get("team") and f.get("team") != self.real_team)
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        client.post("/api/remediation-approvals", json={"finding_id": own_team_finding["id"], "requested_by": "eng@example.com"})
        client.post("/api/remediation-approvals", json={"finding_id": other_team_finding["id"], "requested_by": "eng@example.com"})
        _logout()
        _login(self.TEAM_USER_EMAIL, self.TEAM_USER_PASSWORD)
        approvals = client.get("/api/remediation-approvals").json()["approvals"]
        finding_ids = {a["finding_id"] for a in approvals}
        self.assertIn(own_team_finding["id"], finding_ids)
        self.assertNotIn(other_team_finding["id"], finding_ids)


class RequireLoginForReadsMiddleware(unittest.TestCase):
    """VULNHUNTER_REQUIRE_LOGIN_FOR_READS - the opt-in, off-by-default middleware that
    closes the "anonymous reads see everything" gap for a real deployment. Off is the
    default and is exercised by literally every other test in this file that reads
    /api/queue, /api/assets, etc. without a session; this class exercises the ON
    state specifically."""

    def setUp(self):
        self.patcher = patch.dict(os.environ, {"VULNHUNTER_REQUIRE_LOGIN_FOR_READS": "true"})
        self.patcher.start()

    def tearDown(self):
        _logout()
        self.patcher.stop()

    def test_flag_off_is_the_default_and_stays_public(self):
        self.patcher.stop()  # simulate the real default (unset) for this one test
        try:
            resp = client.get("/api/queue")
            self.assertEqual(resp.status_code, 200)
        finally:
            self.patcher.start()

    def test_read_route_without_a_session_is_rejected(self):
        for path in ("/api/queue", "/api/assets", "/api/exceptions", "/api/remediation-approvals", "/api/overview"):
            with self.subTest(path=path):
                self.assertEqual(client.get(path).status_code, 401)

    def test_login_flow_routes_stay_reachable_with_no_session(self):
        self.assertEqual(client.get("/api/auth/me").status_code, 200)
        self.assertEqual(client.get("/api/auth/oidc/config").status_code, 200)
        # A wrong password must still fail with 401 for the RIGHT reason (bad
        # credentials), not because the middleware itself blocked the request before
        # the real login logic ever ran.
        resp = client.post("/api/auth/login", json={"email": TEST_USER_EMAIL, "password": "wrong"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["detail"], "Invalid email or password")

    def test_non_api_paths_stay_reachable_with_no_session(self):
        # The SPA shell and static assets carry no data of their own - the client-side
        # router (not this middleware) is what redirects an unauthenticated browser to
        # /login, and it needs the shell HTML/JS to actually load first.
        self.assertEqual(client.get("/").status_code, 200)
        self.assertEqual(client.get("/queue").status_code, 200)

    def test_read_route_with_a_real_session_returns_real_data(self):
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        resp = client.get("/api/queue")
        self.assertEqual(resp.status_code, 200)
        self.assertGreater(len(resp.json()["findings"]), 0)

    def test_admin_only_route_still_distinguishes_401_from_403(self):
        # Already-gated routes (Depends(rbac.require_admin)) keep their own real
        # status codes - the middleware doesn't flatten everything to a bare 401.
        self.assertEqual(client.get("/api/admin/users").status_code, 401)
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        self.assertEqual(client.get("/api/admin/users").status_code, 403)
        _logout()
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        self.assertEqual(client.get("/api/admin/users").status_code, 200)


class SecurityHeadersMiddleware(unittest.TestCase):
    """The unconditional OWASP secure-headers set is on by default and cannot be
    turned off (unlike the opt-in CSP) - it's the one thing in this file every
    response, authenticated or not, always carries."""

    def test_safe_headers_present_on_every_response(self):
        resp = client.get("/api/status")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("geolocation=()", resp.headers.get("Permissions-Policy", ""))
        self.assertIn("max-age=31536000", resp.headers.get("Strict-Transport-Security", ""))

    def test_csp_absent_by_default(self):
        resp = client.get("/api/status")
        self.assertNotIn("Content-Security-Policy", resp.headers)

    def test_csp_present_when_opted_in(self):
        with patch.dict(os.environ, {"VULNHUNTER_ENABLE_CSP": "true"}):
            resp = client.get("/api/status")
        csp = resp.headers.get("Content-Security-Policy", "")
        self.assertIn("default-src 'self'", csp)
        self.assertIn("style-src 'self' 'unsafe-inline'", csp)


class RateLimitMiddleware(unittest.TestCase):
    """Real per-IP rate limiting on /api/* (see dashboard/rate_limit.py) -
    setUpModule() swaps in effectively-unlimited limiters for every other test in
    this file (which alone makes many thousands of API calls against the same
    TestClient/IP), so these tests patch their own, deliberately tiny limits back in
    to verify the real 429 behavior actually fires past a real threshold. The
    underlying RateLimiter class's own logic (independent per-key quotas, aging out
    of the sliding window, Retry-After accuracy) is unit-tested directly in
    tests/test_rate_limit.py - these are the integration seam only."""

    def setUp(self):
        self.global_patcher = patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(3, 60))
        self.ingest_patcher = patch.object(dashboard_app_module, "_GENERIC_INGEST_RATE_LIMITER", rate_limit.RateLimiter(2, 60))
        self.global_patcher.start()
        self.ingest_patcher.start()

    def tearDown(self):
        self.global_patcher.stop()
        self.ingest_patcher.stop()

    def test_requests_within_the_limit_succeed(self):
        for _ in range(3):
            self.assertEqual(client.get("/api/status").status_code, 200)

    def test_request_past_the_limit_gets_a_429_with_retry_after(self):
        for _ in range(3):
            client.get("/api/status")
        resp = client.get("/api/status")
        self.assertEqual(resp.status_code, 429)
        self.assertIn("Retry-After", resp.headers)

    def test_non_api_routes_are_never_rate_limited(self):
        for _ in range(5):
            client.get("/api/status")  # exhaust the global limit (3)
        resp = client.get("/")  # SPA shell route, not under /api/
        self.assertEqual(resp.status_code, 200)

    def test_generic_ingest_has_its_own_stricter_limit(self):
        payload = {"findings": []}
        for _ in range(2):
            resp = client.post("/api/ingest/generic", json=payload)
            self.assertEqual(resp.status_code, 200)
        resp = client.post("/api/ingest/generic", json=payload)
        self.assertEqual(resp.status_code, 429)


class ApiReports(unittest.TestCase):
    def test_generate_returns_real_computed_kpis(self):
        resp = client.get("/api/reports/generate", params={"period": "weekly"})
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["period"], "weekly")
        self.assertGreaterEqual(payload["remediation_total"], 7440)
        self.assertEqual(payload["vulnhunt_total"], 18)

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
    """Every test here uses an isolated temp DB (via patching db_module.get_engine) so
    the suite never mutates the real, shared remediation/vulnhunter.db."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.patcher = _patch_db_engine(self.tmpdir.name)
        self.patcher.start()
        # Create requires any logged-in user, revoke requires admin - log in as admin so
        # both work in these tests; the 401/403 tests below explicitly log out/switch.
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)

    def tearDown(self):
        _logout()
        self.patcher.engine.dispose()
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


class ApiDirectoryStatus(unittest.TestCase):
    """No AD_SERVER/AD_BASE_DN are set in this test process, so is_configured() is
    always False here - that's the real, honest behavior to test (never fabricate a
    "validated" group check against a directory that was never actually configured)."""

    def test_reports_not_configured_by_default(self):
        resp = client.get("/api/directory/status")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["configured"])

    def test_reports_configured_when_env_vars_set(self):
        with patch.dict("os.environ", {"AD_SERVER": "ldap://dc01.example.com", "AD_BASE_DN": "DC=example,DC=com"}):
            resp = client.get("/api/directory/status")
        self.assertTrue(resp.json()["configured"])


class ApiRemediationApprovals(unittest.TestCase):
    """Every test here uses an isolated temp DB (via patching db_module.get_engine) so
    the suite never mutates the real, shared remediation/vulnhunter.db. AD_SERVER/
    AD_BASE_DN are never set in this test process, so every approve() call here exercises
    the honest "AD not configured" branch - the ldap3-mocked branch is covered directly
    in test_ad_directory.py."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.patcher = _patch_db_engine(self.tmpdir.name)
        self.patcher.start()
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)

    def tearDown(self):
        _logout()
        self.patcher.engine.dispose()
        self.patcher.stop()
        self.tmpdir.cleanup()

    def test_list_on_empty_store_returns_empty_list(self):
        resp = client.get("/api/remediation-approvals")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["approvals"], [])

    def test_create_uses_the_findings_own_resolved_maintenance_window(self):
        resp = client.post("/api/remediation-approvals", json={"finding_id": "FIND-1", "requested_by": "eng@example.com"})
        self.assertEqual(resp.status_code, 200)
        record = resp.json()
        self.assertEqual(record["finding_id"], "FIND-1")
        self.assertEqual(record["status"], "pending")
        queue_policy = client.get("/api/queue").json()
        finding = next(f for f in queue_policy["findings"] if f["id"] == "FIND-1")
        self.assertEqual(record["scheduled_window"], finding["remediation_policy"]["next_window"])

    def test_create_for_unknown_finding_returns_404(self):
        resp = client.post("/api/remediation-approvals", json={"finding_id": "FIND-9999999", "requested_by": "eng@example.com"})
        self.assertEqual(resp.status_code, 404)

    def test_create_without_login_is_rejected(self):
        _logout()
        resp = client.post("/api/remediation-approvals", json={"finding_id": "FIND-1", "requested_by": "eng@example.com"})
        self.assertEqual(resp.status_code, 401)

    def test_approve_without_a_required_approval_group_needs_no_ad_check(self):
        # FIND-8229 (endpoint domain) resolves to requires_approval_group: null in the
        # real shipped remediation_policy.yaml, unlike FIND-1 below (default domain,
        # which does require a group) - see remediation_policy_engine.py's docstring.
        created = client.post("/api/remediation-approvals", json={"finding_id": "FIND-8229", "requested_by": "eng@example.com"}).json()
        resp = client.post(f"/api/remediation-approvals/{created['id']}/approve", json={"decided_by": "approver@example.com"})
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["approval"]["status"], "approved")
        self.assertIsNone(payload["approval"]["ad_group_validated"])

    def test_approve_with_a_required_approval_group_but_ad_not_configured_is_honest(self):
        """FIND-1's resolved policy names requires_approval_group (see
        remediation_policy.yaml's os/default domains) - with no real AD_SERVER/AD_BASE_DN
        set, the response must say so plainly rather than silently skip the check or
        fabricate a passing validation."""
        created = client.post("/api/remediation-approvals", json={"finding_id": "FIND-1", "requested_by": "eng@example.com"}).json()
        resp = client.post(f"/api/remediation-approvals/{created['id']}/approve", json={"decided_by": "approver@example.com"})
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertFalse(payload["ad_configured"])
        self.assertIsNone(payload["approval"]["ad_group_validated"])
        self.assertIn("AD not configured", payload["message"])

    def test_approve_unknown_id_returns_404(self):
        resp = client.post("/api/remediation-approvals/APR-999/approve", json={"decided_by": "approver@example.com"})
        self.assertEqual(resp.status_code, 404)

    def test_approve_without_login_is_rejected(self):
        created = client.post("/api/remediation-approvals", json={"finding_id": "FIND-1", "requested_by": "eng@example.com"}).json()
        _logout()
        resp = client.post(f"/api/remediation-approvals/{created['id']}/approve", json={"decided_by": "approver@example.com"})
        self.assertEqual(resp.status_code, 401)

    def test_approve_as_non_admin_is_forbidden(self):
        created = client.post("/api/remediation-approvals", json={"finding_id": "FIND-1", "requested_by": "eng@example.com"}).json()
        _logout()
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        resp = client.post(f"/api/remediation-approvals/{created['id']}/approve", json={"decided_by": "approver@example.com"})
        self.assertEqual(resp.status_code, 403)

    def test_reject_records_reason(self):
        created = client.post("/api/remediation-approvals", json={"finding_id": "FIND-1", "requested_by": "eng@example.com"}).json()
        resp = client.post(f"/api/remediation-approvals/{created['id']}/reject", json={"decided_by": "approver@example.com", "reason": "Conflicts with a release freeze"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["approval"]["status"], "rejected")
        self.assertEqual(resp.json()["approval"]["rejection_reason"], "Conflicts with a release freeze")

    def test_reject_unknown_id_returns_404(self):
        resp = client.post("/api/remediation-approvals/APR-999/reject", json={"decided_by": "approver@example.com"})
        self.assertEqual(resp.status_code, 404)

    def test_reject_without_login_is_rejected(self):
        created = client.post("/api/remediation-approvals", json={"finding_id": "FIND-1", "requested_by": "eng@example.com"}).json()
        _logout()
        resp = client.post(f"/api/remediation-approvals/{created['id']}/reject", json={"decided_by": "approver@example.com"})
        self.assertEqual(resp.status_code, 401)

    def test_send_communication_preview_needs_no_login_and_returns_the_rendered_text(self):
        created = client.post("/api/remediation-approvals", json={"finding_id": "FIND-1", "requested_by": "eng@example.com"}).json()
        _logout()
        resp = client.post(f"/api/remediation-approvals/{created['id']}/send-communication", json={})
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertTrue(payload["preview_only"])
        self.assertIn("WIN-DC01", payload["body_text"])

    def test_send_communication_unknown_approval_returns_404(self):
        resp = client.post("/api/remediation-approvals/APR-999/send-communication", json={})
        self.assertEqual(resp.status_code, 404)

    def test_send_communication_with_confirm_but_smtp_not_configured_returns_503(self):
        """No real SMTP_HOST is set in this test process - the honest failure, not a
        fabricated 'sent' response, same convention as /api/notification-settings/send-test."""
        created = client.post("/api/remediation-approvals", json={"finding_id": "FIND-1", "requested_by": "eng@example.com"}).json()
        resp = client.post(f"/api/remediation-approvals/{created['id']}/send-communication", json={"recipient": "stakeholder@example.com", "confirm": True})
        self.assertEqual(resp.status_code, 503)

    def test_send_communication_with_confirm_but_not_logged_in_is_rejected(self):
        created = client.post("/api/remediation-approvals", json={"finding_id": "FIND-1", "requested_by": "eng@example.com"}).json()
        _logout()
        resp = client.post(f"/api/remediation-approvals/{created['id']}/send-communication", json={"recipient": "stakeholder@example.com", "confirm": True})
        self.assertEqual(resp.status_code, 401)

    def test_mark_staging_validated_records_who_and_when(self):
        created = client.post("/api/remediation-approvals", json={"finding_id": "FIND-1", "requested_by": "eng@example.com"}).json()
        resp = client.post(f"/api/remediation-approvals/{created['id']}/staging-validated", json={"validated_by": "tester@example.com"})
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["approval"]["staging_validated_by"], "tester@example.com")
        self.assertIsNotNone(payload["approval"]["staging_validated_at"])

    def test_mark_staging_validated_unknown_approval_returns_404(self):
        resp = client.post("/api/remediation-approvals/APR-999/staging-validated", json={"validated_by": "tester@example.com"})
        self.assertEqual(resp.status_code, 404)

    def test_mark_staging_validated_blank_validator_returns_400(self):
        created = client.post("/api/remediation-approvals", json={"finding_id": "FIND-1", "requested_by": "eng@example.com"}).json()
        resp = client.post(f"/api/remediation-approvals/{created['id']}/staging-validated", json={"validated_by": "   "})
        self.assertEqual(resp.status_code, 400)

    def test_mark_staging_validated_requires_login(self):
        created = client.post("/api/remediation-approvals", json={"finding_id": "FIND-1", "requested_by": "eng@example.com"}).json()
        _logout()
        resp = client.post(f"/api/remediation-approvals/{created['id']}/staging-validated", json={"validated_by": "tester@example.com"})
        self.assertEqual(resp.status_code, 401)

    def test_list_approvals_includes_rollback_plan_from_the_real_playbook(self):
        """FIND-1 (PrintNightmare) has a real generated playbook with a genuine
        '# Rollback: ...' comment - the list route must join it in, not just report the
        raw approval record."""
        client.post("/api/remediation-approvals", json={"finding_id": "FIND-1", "requested_by": "eng@example.com"})
        resp = client.get("/api/remediation-approvals")
        approval = next(a for a in resp.json()["approvals"] if a["finding_id"] == "FIND-1")
        self.assertIsNotNone(approval["rollback_plan"])
        self.assertIn("snapshot", approval["rollback_plan"])

    def test_list_approvals_rollback_plan_is_none_without_a_generated_playbook(self):
        """FIND-8229 (used elsewhere in this suite for its null requires_approval_group)
        has no generated playbook - the join must report None honestly, not KeyError or
        a fabricated placeholder."""
        client.post("/api/remediation-approvals", json={"finding_id": "FIND-8229", "requested_by": "eng@example.com"})
        resp = client.get("/api/remediation-approvals")
        approval = next(a for a in resp.json()["approvals"] if a["finding_id"] == "FIND-8229")
        self.assertIsNone(approval["rollback_plan"])


class ApiActivityLog(unittest.TestCase):
    """/api/activity-log reads remediation/audit/activity_log.py's shared feed - this
    class uses its own isolated temp DB (on top of setUpModule's module-wide one) so
    entries written by other test classes running earlier/later in the same process
    can't leak into these assertions."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        # One patch covers both: activity_log and asset_ownership now share the same
        # DB (see remediation/utils/db.py), so redirecting db_module.get_engine once
        # isolates both instead of needing a second DEFAULT_OWNERSHIP_PATH patch.
        self.activity_patcher = _patch_db_engine(self.tmpdir.name)
        self.activity_patcher.start()
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)

    def tearDown(self):
        _logout()
        self.activity_patcher.engine.dispose()
        self.activity_patcher.stop()
        self.tmpdir.cleanup()

    def test_no_asset_edits_by_default(self):
        # setUp's own _login() call already wrote one real "login.success" entry - that
        # is itself correct, intended behavior (see test_login_attempt_is_recorded
        # below), not something to treat as "empty." Filter to the action under test
        # instead of asserting a total count of zero.
        resp = client.get("/api/activity-log?action=asset.set_owner")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["entries"], [])

    def test_login_attempt_is_recorded(self):
        entries = client.get("/api/activity-log?action=login.success").json()["entries"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["actor"], TEST_USER_EMAIL)

    def test_a_real_asset_edit_appears_with_the_real_actor(self):
        client.post("/api/assets/WIN-DC01/owner", json={"owner": "Priya Nair", "team": "Identity"})
        entries = client.get("/api/activity-log?action=asset.set_owner").json()["entries"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["actor"], TEST_USER_EMAIL)
        self.assertEqual(entries[0]["action"], "asset.set_owner")
        self.assertEqual(entries[0]["target"], "WIN-DC01")

    def test_newest_first(self):
        client.post("/api/assets/WIN-DC01/owner", json={"owner": "First", "team": "T"})
        client.post("/api/assets/WIN-DC01/owner", json={"owner": "Second", "team": "T"})
        entries = client.get("/api/activity-log?action=asset.set_owner").json()["entries"]
        self.assertEqual(entries[0]["details"]["owner"], "Second")
        self.assertEqual(entries[1]["details"]["owner"], "First")

    def test_filters_by_action(self):
        client.post("/api/assets/WIN-DC01/owner", json={"owner": "A", "team": "T"})
        client.post("/api/assets/WIN-DC01/facing", json={"facing": "internal"})
        entries = client.get("/api/activity-log?action=asset.set_facing").json()["entries"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["action"], "asset.set_facing")

    def test_limit_caps_result_count(self):
        for i in range(5):
            client.post("/api/assets/WIN-DC01/owner", json={"owner": f"Owner{i}", "team": "T"})
        entries = client.get("/api/activity-log?action=asset.set_owner&limit=2").json()["entries"]
        self.assertEqual(len(entries), 2)


class ApiAssets(unittest.TestCase):
    """Every test here uses an isolated temp DB so the suite never mutates the real,
    shared remediation/vulnhunter.db."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.patcher = _patch_db_engine(self.tmpdir.name)
        self.patcher.start()
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)  # owner/facing only require login

    def tearDown(self):
        _logout()
        self.patcher.engine.dispose()
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

    def test_assets_carry_os_and_eol_eos_status(self):
        """Real, dated vendor-lifecycle classification (remediation/enrichment/
        eol_lookup.py), backfilled the same way ip/mac already are - see
        asset_inventory.py's build_asset_inventory()."""
        resp = client.get("/api/assets")
        assets = resp.json()["assets"]
        by_name = {a["name"]: a for a in assets}
        self.assertIn("os", by_name["WEB-PORTAL01"])
        self.assertIn("eol_status", by_name["WEB-PORTAL01"])
        self.assertTrue(all("eol_status" in a for a in assets))

    def test_assets_carry_risk_scoring_fields(self):
        """Real, NIST-SP-800-30-inspired per-asset Impact/Likelihood/Risk scores
        (remediation/enrichment/risk_scoring.py) - every asset row gets all 4 fields,
        each a valid 0-100 int (or a real tier string)."""
        resp = client.get("/api/assets")
        assets = resp.json()["assets"]
        self.assertTrue(len(assets) > 0)
        for a in assets:
            for key in ("impact_score", "likelihood_score", "risk_score"):
                self.assertIn(key, a)
                self.assertIsInstance(a[key], int)
                self.assertTrue(0 <= a[key] <= 100)
            self.assertIn(a["risk_tier"], ("Critical", "High", "Medium", "Low"))

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

    def test_new_asset_has_unknown_environment_by_default(self):
        resp = client.get("/api/assets")
        by_name = {a["name"]: a for a in resp.json()["assets"]}
        self.assertEqual(by_name["WEB-PORTAL01"]["environment"], "unknown")

    def test_set_environment_then_list_shows_the_new_classification(self):
        set_resp = client.post("/api/assets/WEB-PORTAL01/environment", json={"environment": "dev"})
        self.assertEqual(set_resp.status_code, 200)
        self.assertEqual(set_resp.json()["environment"], "dev")

        resp = client.get("/api/assets")
        by_name = {a["name"]: a for a in resp.json()["assets"]}
        self.assertEqual(by_name["WEB-PORTAL01"]["environment"], "dev")

    def test_set_environment_with_invalid_value_is_rejected(self):
        resp = client.post("/api/assets/WEB-PORTAL01/environment", json={"environment": "space-station"})
        self.assertEqual(resp.status_code, 400)

    def test_set_environment_without_login_is_rejected(self):
        _logout()
        resp = client.post("/api/assets/WEB-PORTAL01/environment", json={"environment": "dev"})
        self.assertEqual(resp.status_code, 401)

    def test_dev_environment_tag_changes_the_findings_resolved_policy_domain(self):
        """An asset tagged environment: dev resolves to the dev policy domain (weekly,
        auto-remediate, no approval group) instead of whatever its infra_category/
        scan_type would otherwise resolve to - see remediation_policy_engine.py's
        _domain_for_finding() docstring."""
        client.post("/api/assets/WEB-PORTAL01/environment", json={"environment": "dev"})
        resp = client.get("/api/queue")
        web_portal_finding = next(f for f in resp.json()["findings"] if (f["asset"] or {}).get("name") == "WEB-PORTAL01")
        self.assertEqual(web_portal_finding["remediation_policy"]["domain"], "dev")

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

    def test_set_network_info_persists_and_is_reflected_on_the_asset(self):
        resp = client.post("/api/assets/WEB-PORTAL01/network-info", json={"ip": "10.20.30.41", "mac": "aa:bb:cc:dd:ee:ff"})
        self.assertEqual(resp.status_code, 200)
        by_name = {a["name"]: a for a in client.get("/api/assets").json()["assets"]}
        self.assertEqual(by_name["WEB-PORTAL01"]["ip"], "10.20.30.41")
        self.assertEqual(by_name["WEB-PORTAL01"]["ip_version"], 4)
        self.assertEqual(by_name["WEB-PORTAL01"]["mac"], "aa:bb:cc:dd:ee:ff")

    def test_set_network_info_rejects_an_invalid_ip_with_a_real_400(self):
        resp = client.post("/api/assets/WEB-PORTAL01/network-info", json={"ip": "not-an-ip"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("not-an-ip", resp.json()["detail"])

    def test_set_network_info_without_login_is_rejected(self):
        _logout()
        resp = client.post("/api/assets/WEB-PORTAL01/network-info", json={"ip": "10.20.30.41"})
        self.assertEqual(resp.status_code, 401)


class ApiSearchAsk(unittest.TestCase):
    """/api/search/ask - the real, deterministic "ask your data" search route (see
    remediation/search/query_engine.py). These assert the route wires real live data
    through correctly; query_engine.py's own tests (tests/test_query_engine.py) cover
    the matching/scoring logic itself in isolation."""

    def test_requires_no_login_same_as_queue_and_assets(self):
        _logout()
        resp = client.post("/api/search/ask", json={"query": "how many critical findings are there"})
        self.assertEqual(resp.status_code, 200)

    def test_finding_id_lookup_against_the_real_live_queue(self):
        resp = client.post("/api/search/ask", json={"query": "FIND-12"})
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(payload["intent"], "finding_lookup")
        self.assertIn("Log4Shell", payload["answer"])

    def test_count_query_against_the_real_live_queue(self):
        resp = client.post("/api/search/ask", json={"query": "how many KEV findings are there"})
        payload = resp.json()
        self.assertEqual(payload["intent"], "count")
        self.assertRegex(payload["answer"], r"^\d+ finding\(s\) match")

    def test_no_match_returns_200_with_an_honest_answer_not_an_error(self):
        resp = client.post("/api/search/ask", json={"query": "xyzzy plugh quux"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["intent"], "no_match")


class ApiAssetPolicy(unittest.TestCase):
    """Every test here uses a temporary rules file (via patching DEFAULT_RULES_PATH)
    plus an isolated temp DB, so the suite never mutates the real, shipped
    asset_policy_rules.yaml or the real, shared remediation/vulnhunter.db."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp_rules_path = Path(self.tmpdir.name) / "asset_policy_rules.yaml"
        self.tmp_rules_path.write_text("rules: []\n", encoding="utf-8")
        self.rules_patcher = patch.object(asset_policy, "DEFAULT_RULES_PATH", self.tmp_rules_path)
        self.rules_patcher.start()
        self.ownership_patcher = _patch_db_engine(self.tmpdir.name)
        self.ownership_patcher.start()
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)

    def tearDown(self):
        _logout()
        self.ownership_patcher.engine.dispose()
        self.ownership_patcher.stop()
        self.rules_patcher.stop()
        self.tmpdir.cleanup()

    def test_get_returns_current_rules_text(self):
        resp = client.get("/api/asset-policy")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("rules: []", resp.json()["rules_text"])

    def test_post_valid_yaml_saves(self):
        new_text = "rules:\n  - name: test\n    match: {name_prefix: WEB}\n    set: {facing: external}\n"
        resp = client.post("/api/asset-policy", json={"rules_text": new_text})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("saved", resp.json()["message"])
        self.assertIn("name: test", self.tmp_rules_path.read_text(encoding="utf-8"))

    def test_post_invalid_yaml_is_rejected(self):
        resp = client.post("/api/asset-policy", json={"rules_text": "not: valid: yaml: ["})
        self.assertEqual(resp.status_code, 400)

    def test_post_without_login_is_rejected(self):
        _logout()
        resp = client.post("/api/asset-policy", json={"rules_text": "rules: []"})
        self.assertEqual(resp.status_code, 401)

    def test_post_as_non_admin_is_rejected(self):
        _logout()
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        resp = client.post("/api/asset-policy", json={"rules_text": "rules: []"})
        self.assertEqual(resp.status_code, 403)

    def test_preview_shows_real_matched_assets_without_writing_anything(self):
        rules_text = "rules:\n  - name: test\n    match: {name_prefix: WEB-PORTAL}\n    set: {facing: external}\n"
        resp = client.post("/api/asset-policy/preview", json={"rules_text": rules_text})
        self.assertEqual(resp.status_code, 200)
        matched = resp.json()["rules"][0]["matched_assets"]
        self.assertIn("WEB-PORTAL01", matched)
        # Preview never writes - the real asset still shows no owner/facing set.
        by_name = {a["name"]: a for a in client.get("/api/assets").json()["assets"]}
        self.assertEqual(by_name["WEB-PORTAL01"]["facing"], "unknown")

    def test_preview_needs_no_login(self):
        _logout()
        resp = client.post("/api/asset-policy/preview", json={"rules_text": "rules: []"})
        self.assertEqual(resp.status_code, 200)

    def test_apply_writes_real_changes_using_the_saved_rules(self):
        # WEB-PORTAL01 exactly (not a prefix match) - this repo's real sample data has
        # grown to include many other WEB-PORTAL-prefixed assets (WEB-PORTAL-0001, etc.
        # from later rounds' cloud/cert-mgmt CVE expansion), so an exact name_regex
        # anchor is what actually isolates a single real asset here.
        client.post("/api/asset-policy", json={
            "rules_text": "rules:\n  - name: test\n    match: {name_regex: '^WEB-PORTAL01$'}\n    set: {facing: external}\n",
        })
        resp = client.post("/api/asset-policy/apply")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["assets_changed"], 1)
        by_name = {a["name"]: a for a in client.get("/api/assets").json()["assets"]}
        self.assertEqual(by_name["WEB-PORTAL01"]["facing"], "external")

    def test_apply_requires_admin(self):
        _logout()
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        resp = client.post("/api/asset-policy/apply")
        self.assertEqual(resp.status_code, 403)


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

    def test_heatmap_has_real_nonzero_counts_from_the_planted_ai_findings(self):
        """vulnerable-demo-app/ai_assistant.py plants 3 genuine AI/ML SAST findings
        (VULN-11 insecure pickle deserialization, VULN-12 prompt injection, VULN-13
        excessive agency) - these tag against this taxonomy for real, unlike the rest
        of this repo's demo data (see ai_vuln_taxonomy.py's module docstring). Asserts
        floors, not exact counts, since keyword-matching against thousands of real bulk
        CVE descriptions can occasionally produce an incidental extra match too."""
        resp = client.get("/api/ai-vulnerabilities")
        heatmap = resp.json()["heatmap"]
        self.assertFalse(all(row["count"] == 0 for row in heatmap))
        by_id = {row["id"]: row["count"] for row in heatmap}
        self.assertGreaterEqual(by_id["prompt-injection"], 1)
        self.assertGreaterEqual(by_id["supply-chain"], 1)
        self.assertGreaterEqual(by_id["excessive-agency"], 1)


class ApiIngestGeneric(unittest.TestCase):
    """The vendor-agnostic ingestion webhook. Writes to the shared SQLite database
    (see remediation/connectors/live_data_store.py) - uses an isolated temp DB so this
    suite never mutates the real, shared remediation/vulnhunter.db."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_patcher = _patch_db_engine(self.tmpdir.name)
        self.db_patcher.start()

    def tearDown(self):
        self.db_patcher.engine.dispose()
        self.db_patcher.stop()
        self.tmpdir.cleanup()

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
        self.assertEqual(live_data_store.count(live_data_store.SOURCE_GENERIC_INGEST), 1)


class ApiNotifications(unittest.TestCase):
    """build_notifications() is real, system-generated data derived from the live
    queue/exceptions/ingestion state - not person-to-person messages. Exception- and
    ingestion-derived notifications use an isolated temp DB (same pattern as
    ApiExceptions/ApiIngestGeneric) so this suite never touches the real, shared
    remediation/vulnhunter.db."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.exc_patcher = _patch_db_engine(self.tmpdir.name)
        self.exc_patcher.start()

    def tearDown(self):
        self.exc_patcher.engine.dispose()
        self.exc_patcher.stop()
        self.tmpdir.cleanup()

    def test_sla_breached_findings_produce_danger_notifications(self):
        resp = client.get("/api/notifications")
        self.assertEqual(resp.status_code, 200)
        notifications = resp.json()["notifications"]
        sla_ids = {n["id"] for n in notifications if n["category"] == "SLA"}
        # dashboard_data.MAX_SLA_BREACH_NOTIFICATIONS caps individual breach
        # notifications at 10, plus one "...and N more" overflow notification once the
        # real breach count (now in the thousands with bulk sample data) exceeds that -
        # so this is a fixed cap, not a count that scales with the dataset.
        self.assertEqual(len(sla_ids), dashboard_data.MAX_SLA_BREACH_NOTIFICATIONS + 1)
        self.assertIn("sla-FIND-1", sla_ids)
        self.assertTrue(any(n_id.startswith("sla-overflow-") for n_id in sla_ids))

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
        live_data_store.append_findings(live_data_store.SOURCE_GENERIC_INGEST, [{"id": "GEN-1", "title": "t"}])
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
        "/adaptors", "/infoblox", "/axonius", "/infrastructure", "/ai-vulnerabilities",
        "/vulnerability-mapping", "/asset-mapping", "/exploit-criteria", "/compensating-controls",
        "/remediation-policy", "/remediation-approvals",
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


class ApiReportSchedule(unittest.TestCase):
    """Same temporary-file-isolation pattern as ApiPriorityRules/ApiExploitCriteria -
    never mutates the real, shipped report_schedule_rules.yaml."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmpdir.name) / "report_schedule_rules.yaml"
        self.tmp_path.write_text(dashboard_data.REPORT_SCHEDULE_RULES_PATH.read_text(encoding="utf-8"), encoding="utf-8")
        self.patcher = patch.object(dashboard_data, "REPORT_SCHEDULE_RULES_PATH", self.tmp_path)
        self.patcher.start()
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)

    def tearDown(self):
        _logout()
        self.patcher.stop()
        self.tmpdir.cleanup()

    def test_get_returns_current_rules_text(self):
        resp = client.get("/api/report-schedule")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("subscriptions", resp.json()["rules_text"])

    def test_post_valid_yaml_saves(self):
        new_text = "subscriptions:\n  - id: test-sub\n    scope: all\n    cadence: weekly\n    recipients: [a@example.com]\n    enabled: false\n"
        resp = client.post("/api/report-schedule", json={"rules_text": new_text})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("test-sub", self.tmp_path.read_text(encoding="utf-8"))

    def test_post_invalid_yaml_is_rejected(self):
        resp = client.post("/api/report-schedule", json={"rules_text": "not: valid: yaml: ["})
        self.assertEqual(resp.status_code, 400)

    def test_post_without_login_is_rejected(self):
        _logout()
        resp = client.post("/api/report-schedule", json={"rules_text": "subscriptions: []"})
        self.assertEqual(resp.status_code, 401)

    def test_post_as_non_admin_is_rejected(self):
        _logout()
        _login(TEST_USER_EMAIL, TEST_USER_PASSWORD)
        resp = client.post("/api/report-schedule", json={"rules_text": "subscriptions: []"})
        self.assertEqual(resp.status_code, 403)


class ApiAlertRules(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmpdir.name) / "alert_rules.yaml"
        self.tmp_path.write_text(dashboard_data.ALERT_RULES_PATH.read_text(encoding="utf-8"), encoding="utf-8")
        self.patcher = patch.object(dashboard_data, "ALERT_RULES_PATH", self.tmp_path)
        self.patcher.start()
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)

    def tearDown(self):
        _logout()
        self.patcher.stop()
        self.tmpdir.cleanup()

    def test_get_returns_current_rules_text(self):
        resp = client.get("/api/alert-rules")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("subscriptions", resp.json()["rules_text"])

    def test_post_valid_yaml_saves(self):
        new_text = "subscriptions:\n  - id: test-alert\n    alert_type: critical\n    scope: all\n    recipients: [a@example.com]\n    enabled: false\n"
        resp = client.post("/api/alert-rules", json={"rules_text": new_text})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("test-alert", self.tmp_path.read_text(encoding="utf-8"))

    def test_post_invalid_yaml_is_rejected(self):
        resp = client.post("/api/alert-rules", json={"rules_text": "not: valid: yaml: ["})
        self.assertEqual(resp.status_code, 400)

    def test_post_without_login_is_rejected(self):
        _logout()
        resp = client.post("/api/alert-rules", json={"rules_text": "subscriptions: []"})
        self.assertEqual(resp.status_code, 401)


class ApiNotificationSettings(unittest.TestCase):
    """Preview/status/send-test/run-checks-now - no SMTP env vars are set in this test
    process, so is_configured() is always False here; that's the real, correct behavior
    to test (never fabricate a "sent" result when nothing was actually configured)."""

    def test_status_reports_unconfigured_by_default(self):
        resp = client.get("/api/notification-settings/status")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["smtp_configured"])
        self.assertIsNone(resp.json()["from_address"])

    def test_status_reports_configured_when_env_vars_set(self):
        with patch.dict("os.environ", {"SMTP_HOST": "smtp.example.com", "SMTP_PORT": "587", "SMTP_FROM_ADDRESS": "vulnhunter@example.com"}):
            resp = client.get("/api/notification-settings/status")
        self.assertTrue(resp.json()["smtp_configured"])
        self.assertEqual(resp.json()["from_address"], "vulnhunter@example.com")

    def test_preview_report_needs_no_login(self):
        resp = client.post("/api/notification-settings/preview", json={"kind": "report", "period": "weekly"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("Weekly Security Report", body["subject"])
        self.assertIn("SLA breached", body["body_text"])

    def test_preview_alert_returns_matched_count(self):
        resp = client.post("/api/notification-settings/preview", json={"kind": "alert", "alert_type": "critical", "scope": "all"})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("Critical Vulnerability Alert", body["subject"])
        self.assertGreater(body["matched_count"], 0)  # real Critical findings exist

    def test_preview_rejects_unknown_kind(self):
        resp = client.post("/api/notification-settings/preview", json={"kind": "carrier-pigeon"})
        self.assertEqual(resp.status_code, 400)

    def test_send_test_without_confirm_is_preview_only_and_needs_no_login(self):
        resp = client.post("/api/notification-settings/send-test", json={
            "kind": "report", "period": "weekly", "recipient": "someone@example.com", "confirm": False,
        })
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["preview_only"])

    def test_send_test_with_confirm_but_no_login_is_rejected(self):
        resp = client.post("/api/notification-settings/send-test", json={
            "kind": "report", "period": "weekly", "recipient": "someone@example.com", "confirm": True,
        })
        self.assertEqual(resp.status_code, 401)

    def test_send_test_with_confirm_and_login_but_no_smtp_returns_503(self):
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/notification-settings/send-test", json={
                "kind": "report", "period": "weekly", "recipient": "someone@example.com", "confirm": True,
            })
        finally:
            _logout()
        self.assertEqual(resp.status_code, 503)

    def test_run_checks_now_needs_admin_login(self):
        resp = client.post("/api/notification-settings/run-checks-now")
        self.assertEqual(resp.status_code, 401)

    def test_run_checks_now_returns_empty_with_no_enabled_subscriptions(self):
        # The real, shipped config files ship with an empty subscriptions list.
        _login(TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
        try:
            resp = client.post("/api/notification-settings/run-checks-now")
        finally:
            _logout()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["report_results"], [])
        self.assertEqual(resp.json()["alert_results"], [])


class ApiMlInsights(unittest.TestCase):
    """Real, live-trained scikit-learn models (remediation/enrichment/ml_insights.py) run
    against the actual shipped demo dataset here - not mocked. dashboard_data's own
    in-process cache (same mtime-keyed convention as _load_content_enriched_findings())
    means only the first test in this class pays the real IsolationForest/KMeans fit
    cost; every later call (in this class or elsewhere in the suite) is fast."""

    def test_anomalies_route_returns_real_flagged_assets_sorted_most_anomalous_first(self):
        resp = client.get("/api/ml-insights/anomalies")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertGreater(body["total_assets"], 0)
        self.assertGreater(len(body["anomalies"]), 0)
        scores = [a["anomaly_score"] for a in body["anomalies"]]
        self.assertEqual(scores, sorted(scores))
        for a in body["anomalies"]:
            self.assertTrue(a["is_anomaly"])
            self.assertIsInstance(a["reasons"], list)
            self.assertGreater(len(a["reasons"]), 0)

    def test_clusters_route_sizes_sum_to_total_findings(self):
        resp = client.get("/api/ml-insights/clusters")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertGreater(len(body["clusters"]), 0)
        self.assertEqual(sum(c["size"] for c in body["clusters"]), body["total_findings"])

    def test_cluster_members_route_returns_only_that_clusters_findings_capped_at_25(self):
        clusters = client.get("/api/ml-insights/clusters").json()["clusters"]
        target = clusters[0]
        resp = client.get(f"/api/ml-insights/clusters/{target['cluster_id']}/members")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["total"], target["size"])
        self.assertLessEqual(len(body["members"]), 25)
        self.assertTrue(all(m["risk_cluster"] == target["cluster_id"] for m in body["members"]))

    def test_similar_findings_surfaces_the_real_log4shell_family(self):
        # FIND-12/619/622/623 are all real CVE-2021-44228/44832/45046 (Log4Shell)
        # family findings in the shipped demo dataset - see
        # remediation/output/normalized-findings.json.
        resp = client.get("/api/ml-insights/similar/FIND-12")
        self.assertEqual(resp.status_code, 200)
        similar_ids = [s["id"] for s in resp.json()["similar"]]
        self.assertIn("FIND-619", similar_ids[:3])

    def test_similar_findings_for_unknown_id_returns_empty_not_an_error(self):
        resp = client.get("/api/ml-insights/similar/FIND-NOPE-DOES-NOT-EXIST")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["similar"], [])


if __name__ == "__main__":
    unittest.main()
