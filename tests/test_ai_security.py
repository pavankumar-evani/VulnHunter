"""
Tests for AI security posture: the OWASP LLM Top 10 rules, gaps, the register, and publishing to the queue.
"""
import datetime
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
from sqlalchemy import create_engine, insert  # noqa: E402

import app as dashboard_app_module  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.aisec import rules, store  # noqa: E402
from remediation.ingest import api_findings  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
TODAY = datetime.date(2026, 10, 15)


def asset(**kw):
    base = {"id": 1, "name": "support-bot", "kind": "application", "owner": "ai-team", "environment": "production", "last_reviewed": "2026-09-01", "data_classes": []}
    base.update(kw)
    return base


def hits(a, **kw):
    return {f["rule"] + ":" + f["severity"] for f in rules.evaluate(a, TODAY, kw.get("approved", []))}


class RuleTests(unittest.TestCase):
    def test_a_clean_record_raises_nothing(self):
        self.assertEqual(hits(asset(untrusted_input=True, input_guardrails=True, can_take_actions=False, rate_limited=True, logging=True)), set())

    def test_prompt_injection_needs_untrusted_input_and_no_defence(self):
        self.assertEqual(hits(asset(untrusted_input=True, input_guardrails=False)), {"LLM01:Medium"})
        self.assertEqual(hits(asset(untrusted_input=True, input_guardrails=False, can_take_actions=True, human_in_loop=True)), {"LLM01:High"})
        self.assertEqual(hits(asset(untrusted_input=True, input_guardrails=False, data_classes=["pii"])), {"LLM01:High"})
        self.assertEqual(hits(asset(untrusted_input=True, input_guardrails=None)), set())  # unknown is not a finding
        self.assertEqual(hits(asset(untrusted_input=False, input_guardrails=False)), set())
        self.assertEqual(hits(asset(kind="dataset", untrusted_input=True, input_guardrails=False)), set())

    def test_sensitive_disclosure_severity_depends_on_exposure(self):
        self.assertEqual(hits(asset(data_classes=["pii", "public"], output_filtering=False)), {"LLM02:High"})
        self.assertEqual(hits(asset(data_classes=["phi"], output_filtering=False, internet_facing=True, auth_required=False, rate_limited=True)), {"LLM02:Critical"})
        self.assertEqual(hits(asset(data_classes=["public"], output_filtering=False)), set())

    def test_supply_chain(self):
        self.assertEqual(hits(asset(kind="model", provenance="unverified", serialization="pickle", plugins_reviewed=False)), {"LLM03:High", "LLM03:Medium"})
        self.assertEqual(hits(asset(kind="model", provenance="verified", serialization="safetensors")), set())
        self.assertEqual(hits(asset(kind="model", provenance="unknown", serialization="unknown")), set())

    def test_poisoning_output_handling_and_misinformation(self):
        self.assertEqual(hits(asset(kind="model", fine_tuned=True, training_data_validated=False)), {"LLM04:Medium"})
        self.assertEqual(hits(asset(kind="dataset", training_data_validated=False)), {"LLM04:Medium"})
        self.assertEqual(hits(asset(downstream_trusts_output=True)), {"LLM05:Medium"})
        self.assertEqual(hits(asset(downstream_trusts_output=True, can_take_actions=True, human_in_loop=True)), {"LLM05:High"})
        self.assertEqual(hits(asset(high_stakes_use=True, human_in_loop=False)), {"LLM09:Medium"})
        self.assertEqual(hits(asset(high_stakes_use=True, human_in_loop=True)), set())

    def test_excessive_agency_scales_with_permissions(self):
        for scope, sev in (("read", "Medium"), (None, "Medium"), ("write", "High"), ("admin", "Critical")):
            self.assertEqual(hits(asset(kind="agent", can_take_actions=True, human_in_loop=False, permissions_scope=scope)), {f"LLM06:{sev}"}, scope)
        self.assertEqual(hits(asset(kind="agent", can_take_actions=True, human_in_loop=True, permissions_scope="admin")), set())

    def test_prompt_secrets_retrieval_and_consumption(self):
        self.assertEqual(hits(asset(secrets_in_prompt=True)), {"LLM07:High"})
        self.assertEqual(hits(asset(uses_rag=True, rag_access_control=False)), {"LLM08:Medium"})
        self.assertEqual(hits(asset(uses_rag=True, rag_access_control=False, data_classes=["proprietary"])), {"LLM08:High"})
        self.assertEqual(hits(asset(kind="vector-db", auth_required=False)), {"LLM08:High"})
        self.assertEqual(hits(asset(internet_facing=True, rate_limited=False)), {"LLM10:Medium"})
        self.assertEqual(hits(asset(internet_facing=False, rate_limited=False)), set())

    def test_mcp_servers(self):
        self.assertEqual(hits(asset(kind="mcp-server", auth_required=False)), {"MCP:High"})
        self.assertEqual(hits(asset(kind="mcp-server", auth_required=False, internet_facing=True)), {"MCP:Critical"})
        self.assertEqual(hits(asset(kind="mcp-server", auth_required=True, internet_facing=True, rate_limited=True)), {"MCP:High"})
        self.assertEqual(hits(asset(kind="mcp-server", auth_required=True, internet_facing=False)), set())

    def test_governance(self):
        self.assertEqual(hits(asset(owner=None)), {"GOV:Medium"})
        self.assertEqual(hits(asset(last_reviewed=None)), {"GOV:Low"})
        self.assertEqual(hits(asset(last_reviewed="2026-01-01")), {"GOV:Low"})
        self.assertEqual(hits(asset(logging=False)), {"GOV:Medium"})
        self.assertEqual(hits(asset(logging=False, environment="development")), set())
        self.assertEqual(hits(asset(vendor_model="gpt-4o"), approved=["claude-sonnet"]), {"GOV:Medium"})
        self.assertEqual(hits(asset(vendor_model="Claude-Sonnet-5"), approved=["claude-sonnet"]), set())
        self.assertEqual(hits(asset(vendor_model="anything"), approved=[]), set())  # no approved list, no check

    def test_gaps_are_the_unanswered_questions_that_matter_for_the_kind(self):
        a = asset(untrusted_input=True, uses_rag=True)
        fields = [f for f, _ in rules.unanswered(a)]
        self.assertIn("input_guardrails", fields)
        self.assertIn("rag_access_control", fields)
        self.assertNotIn("untrusted_input", fields)
        self.assertEqual([f for f, _ in rules.unanswered(asset(kind="dataset"))], ["training_data_validated"])
        self.assertEqual(rules.unanswered(asset(kind="mystery")), [])


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")

    def test_save_validate_update_delete(self):
        a = store.save({"name": "bot", "kind": "agent", "can_take_actions": True, "data_classes": ["pii", "pii"], "last_reviewed": "2026-09-30T10:00:00Z"}, "a", engine=self.e)
        self.assertEqual((a["data_classes"], a["can_take_actions"], a["human_in_loop"], a["last_reviewed"]), (["pii"], True, None, "2026-09-30"))
        u = store.save({"name": "bot", "kind": "agent", "human_in_loop": False}, "b", asset_id=a["id"], engine=self.e)
        self.assertEqual((u["human_in_loop"], u["can_take_actions"], u["updated_by"]), (False, None, "b"))  # a save replaces the record
        for bad in ({"name": " ", "kind": "agent"}, {"name": "x", "kind": "robot"}, {"name": "x"}, {"name": "x", "kind": "agent", "hosting": "moon"}, {"name": "x", "kind": "agent", "data_classes": ["gossip"]},
                    {"name": "x", "kind": "agent", "internet_facing": "yes"}, {"name": "x", "kind": "agent", "last_reviewed": "last week"}, {"name": "bot", "kind": "agent"}):
            with self.assertRaises(ValueError, msg=str(bad)):
                store.save(bad, "a", engine=self.e)
        with self.assertRaises(KeyError):
            store.save({"name": "y", "kind": "agent"}, "a", asset_id=999, engine=self.e)
        self.assertTrue(store.remove(a["id"], self.e))
        self.assertFalse(store.remove(a["id"], self.e))

    def test_discovered_applications_are_copied_in_once_and_blocked_ones_skipped(self):
        db_module.ensure_schema(self.e)
        with self.e.begin() as c:
            for name, dom, status in (("ChatTool", "chat.example", "unreviewed"), ("Blocked AI", "bad.example", "blocked"), ("Known", "known.example", "approved")):
                c.execute(insert(db_module.ai_apps), {"name": name, "domain": dom, "status": status, "owner": "o@t" if name == "Known" else None, "users_seen": 1, "requests_seen": 1,
                                                      "signals": "", "first_seen": "2026-10-01", "last_seen": "2026-10-02", "note": ""})
        store.save({"name": "known", "kind": "application"}, "a", engine=self.e)
        added = store.import_discovered(self.e)
        self.assertEqual(added, ["ChatTool"])
        self.assertEqual(store.import_discovered(self.e), [])
        self.assertEqual(sorted(a["name"] for a in store.list_all(self.e)), ["ChatTool", "known"])

    def test_assessment_ranks_assets_counts_by_rule_and_reports_gaps(self):
        store.save({"name": "risky", "kind": "agent", "owner": "o", "can_take_actions": True, "human_in_loop": False, "permissions_scope": "admin", "last_reviewed": "2026-10-01"}, "a", engine=self.e)
        store.save({"name": "fine", "kind": "application", "owner": "o", "last_reviewed": "2026-10-01"}, "a", engine=self.e)
        a = store.assess(store.list_all(self.e), TODAY, approved=[])
        self.assertEqual([x["name"] for x in a["assets"]], ["risky", "fine"])
        self.assertEqual((a["assets"][0]["worst"], a["by_rule"], a["by_severity"]["Critical"]), ("Critical", {"LLM06": 1}, 1))
        self.assertIsNone(a["assets"][1]["worst"])
        self.assertGreater(a["unanswered_total"], 5)
        self.assertIn("gap, not a pass", a["note"])

    def test_queue_items_are_valid_ingest_records_with_stable_identity(self):
        store.save({"name": "risky", "kind": "agent", "owner": "o", "can_take_actions": True, "human_in_loop": False, "last_reviewed": "2026-10-01"}, "a", engine=self.e)
        items = store.to_queue_items(store.assess(store.list_all(self.e), TODAY, approved=[])["findings"])
        findings, errors = api_findings.normalise_batch(items)
        self.assertEqual((len(findings), errors), (1, []))
        f = findings[0]
        self.assertEqual((f["asset"]["type"], f["severity"], f["scan_type"]), ("ai-ml-system", "Medium", "ai-ml"))  # no permission level recorded, so the middle rating
        self.assertIn("LLM06:2025", f["description"])
        again, _ = api_findings.normalise_batch(items)
        self.assertEqual(f["source_ref"], again[0]["source_ref"])


class AiSecurityApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.merged = []
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
                  patch.object(dashboard_app_module.findings_merge, "merge", side_effect=lambda f, s, reconcile=False: self.merged.append((s, reconcile, len(f))) or {"added": len(f), "updated": 0, "removed": 0}),
                  patch.object(dashboard_app_module, "_enrich_in_background", lambda bg: None)]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", PW, "User", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email):
        self.client.cookies.clear()
        self.client.post("/api/auth/login", json={"email": email, "password": PW})

    def test_admin_only(self):
        self.assertEqual(self.client.get("/api/ai-security/overview").status_code, 401)
        self.login("user@t.local")
        self.assertEqual(self.client.get("/api/ai-security/overview").status_code, 403)
        self.assertEqual(self.client.post("/api/ai-security/assets", json={"name": "x", "kind": "agent"}).status_code, 403)

    def test_register_assess_and_publish(self):
        self.login("admin@t.local")
        r = self.client.post("/api/ai-security/assets", json={"name": "ops-agent", "kind": "agent", "owner": "ops", "can_take_actions": True, "human_in_loop": False, "permissions_scope": "write"})
        self.assertEqual(r.status_code, 200, r.text)
        aid = r.json()["id"]
        self.assertEqual(self.client.post("/api/ai-security/assets", json={"name": "ops-agent", "kind": "agent"}).status_code, 400)
        self.assertEqual(self.client.post("/api/ai-security/assets", json={"name": "z", "kind": "robot"}).status_code, 400)
        ov = self.client.get("/api/ai-security/overview").json()
        self.assertIn("LLM06", ov["assessment"]["by_rule"])
        self.assertIn("kinds", ov["meta"])
        up = self.client.put(f"/api/ai-security/assets/{aid}", json={"name": "ops-agent", "kind": "agent", "owner": "ops", "can_take_actions": True, "human_in_loop": True})
        self.assertEqual(up.status_code, 200)
        self.assertNotIn("LLM06", self.client.get("/api/ai-security/overview").json()["assessment"]["by_rule"])
        self.assertEqual(self.client.put("/api/ai-security/assets/999", json={"name": "q", "kind": "agent"}).status_code, 404)
        pre = self.client.post("/api/ai-security/publish", json={})
        self.assertTrue(pre.json()["preview_only"])
        self.assertEqual(self.merged, [])
        done = self.client.post("/api/ai-security/publish", json={"confirm": True})
        self.assertEqual(done.status_code, 200, done.text)
        self.assertEqual(self.merged[0][:2], ("ai-security", True))  # a complete set, so fixed findings leave the queue
        self.assertEqual(self.client.delete(f"/api/ai-security/assets/{aid}").status_code, 200)
        self.assertEqual(self.client.delete(f"/api/ai-security/assets/{aid}").status_code, 404)

    def test_import_discovered_applications(self):
        self.login("admin@t.local")
        with self.engine.begin() as c:
            db_module.ensure_schema(self.engine)
            c.execute(insert(db_module.ai_apps), {"name": "ChatTool", "domain": "chat.example", "status": "unreviewed", "owner": None, "users_seen": 3, "requests_seen": 9, "signals": "", "first_seen": "2026-10-01",
                                                  "last_seen": "2026-10-02", "note": ""})
        self.assertEqual(self.client.post("/api/ai-security/import-discovered").json()["added"], ["ChatTool"])
        self.assertEqual(self.client.post("/api/ai-security/import-discovered").json()["added"], [])


if __name__ == "__main__":
    unittest.main()
