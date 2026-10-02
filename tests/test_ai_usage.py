"""
Tests for AI usage analytics: event storage and de-duplication, cost that is reported, estimated or honestly unknown, OpenTelemetry
intake, the Anthropic and OpenAI usage connectors, budgets, unusual-day detection, shadow-AI discovery, and the API.
"""
import datetime
import json
import os
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
from remediation.aiusage import analytics, discovery, otlp, pricing, store  # noqa: E402
from remediation.connections import crypto, registry, store as conn_store, sync  # noqa: E402
from remediation.connectors.ai_usage_connector import AnthropicUsageConnector, OpenAIUsageConnector, UsageApiError  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
NOW = datetime.datetime(2026, 10, 15, 12, 0, tzinfo=datetime.timezone.utc)


def ev(**kw):
    d = {"ts": "2026-10-14T10:00:00Z", "model": "m-1", "input_tokens": 100, "output_tokens": 50, "team": "Platform", "application": "chatbot"}
    d.update(kw)
    return d


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")

    def test_records_updates_and_rejects_by_index(self):
        out = store.record([ev(event_key="a"), ev(event_key="b"), {"input_tokens": 1}, ev(input_tokens="x", event_key="c")], "api", self.engine)
        self.assertEqual((out["recorded"], out["rejected"], [e["index"] for e in out["errors"]]), (2, 2, [2, 3]))
        again = store.record([ev(event_key="a", input_tokens=999)], "api", self.engine)
        self.assertEqual((again["recorded"], again["updated"]), (0, 1))
        self.assertEqual(sum(r["input_tokens"] for r in store.fetch(engine=self.engine)), 999 + 100)

    def test_the_same_event_without_a_key_is_not_counted_twice(self):
        store.record([ev()], "api", self.engine)
        store.record([ev()], "api", self.engine)
        self.assertEqual(len(store.fetch(engine=self.engine)), 1)

    def test_source_is_validated_and_batches_are_capped(self):
        with self.assertRaises(store.UsageError):
            store.record([ev()], "nonsense", self.engine)
        with self.assertRaises(store.UsageError):
            store.record([ev()] * (store.MAX_BATCH + 1), "api", self.engine)

    def test_cost_is_reported_estimated_or_unknown_never_zero(self):
        table = {"priced-*": {"input": 3.0, "output": 15.0}}
        with patch.object(pricing, "load", return_value=table):
            store.record([ev(model="priced-1", input_tokens=1_000_000, output_tokens=1_000_000, event_key="p"),
                          ev(model="other", event_key="o"), ev(model="priced-1", cost_usd=1.5, event_key="r")], "api", self.engine)
        by_key = {r["event_key"]: r for r in store.fetch(engine=self.engine)}
        self.assertEqual((by_key["p"]["cost_usd"], by_key["p"]["cost_basis"]), (18.0, "estimated"))
        self.assertEqual((by_key["o"]["cost_usd"], by_key["o"]["cost_basis"]), (None, "unknown"))
        self.assertEqual((by_key["r"]["cost_usd"], by_key["r"]["cost_basis"]), (1.5, "reported"))

    def test_the_shipped_price_table_is_empty_so_nothing_is_invented(self):
        self.assertEqual(pricing.load(), {})
        self.assertIsNone(pricing.estimate({"model": "anything", "input_tokens": 10, "output_tokens": 10}))

    def test_quantas_own_calls_are_included(self):
        with self.engine.begin() as conn:
            db_module.ensure_schema(self.engine)
            conn.execute(insert(db_module.ai_usage_log), {"actor": "a@t", "route": "ai-assist", "model": "claude-x", "usage": json.dumps({"input_tokens": 10, "output_tokens": 5}),
                                                          "total_tokens": 15, "total_cost_usd": 0.01, "extraction_ok": True, "timestamp": "2026-10-14T09:00:00Z"})
        rows = store.fetch(engine=self.engine)
        self.assertEqual((rows[0]["source"], rows[0]["application"], rows[0]["input_tokens"], rows[0]["cost_usd"]), ("quanta", "Quanta: ai-assist", 10, 0.01))


class OtlpTests(unittest.TestCase):
    def doc(self, attrs, resource=None):
        a = [{"key": k, "value": {"stringValue": v} if isinstance(v, str) else {"intValue": v}} for k, v in attrs.items()]
        r = [{"key": k, "value": {"stringValue": v}} for k, v in (resource or {"service.name": "support-bot"}).items()]
        return {"resourceSpans": [{"resource": {"attributes": r}, "scopeSpans": [{"spans": [
            {"traceId": "t1", "spanId": "s1", "startTimeUnixNano": "1760436000000000000", "endTimeUnixNano": "1760436002000000000", "attributes": a}]}]}]}

    def test_genai_spans_become_events(self):
        (e,) = otlp.parse_traces(self.doc({"gen_ai.request.model": "m-1", "gen_ai.usage.input_tokens": 120, "gen_ai.usage.output_tokens": 30,
                                           "gen_ai.provider.name": "anthropic", "enduser.id": "u-7"}))
        self.assertEqual((e["model"], e["input_tokens"], e["output_tokens"], e["application"], e["user_ref"], e["latency_ms"]), ("m-1", 120, 30, "support-bot", "u-7", 2000))
        self.assertEqual(e["event_key"], "t1:s1")

    def test_other_spans_are_ignored_and_bad_documents_refused(self):
        self.assertEqual(otlp.parse_traces(self.doc({"http.method": "GET"})), [])
        with self.assertRaises(ValueError):
            otlp.parse_traces({"nope": 1})


class FakeSession:
    def __init__(self, pages, status=200):
        self.pages, self.status, self.calls = list(pages), status, []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append((url, params, headers))
        outer = self

        class R:
            status_code = outer.status

            def raise_for_status(self):
                if outer.status >= 400:
                    raise RuntimeError(f"HTTP {outer.status}")

            def json(self):
                return outer.pages.pop(0)
        return R()


class ConnectorTests(unittest.TestCase):
    def test_anthropic_maps_buckets_pages_and_authenticates_as_an_admin_key(self):
        p1 = {"data": [{"starting_at": "2026-10-13T00:00:00Z", "ending_at": "2026-10-14T00:00:00Z", "results": [
            {"model": "m-1", "workspace_id": "wrkspc_1", "api_key_id": "key_1", "uncached_input_tokens": 100, "output_tokens": 40,
             "cache_read_input_tokens": 20, "cache_creation": {"ephemeral_5m_input_tokens": 5, "ephemeral_1h_input_tokens": 3}, "service_tier": "standard"},
            {"model": "m-2", "uncached_input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0, "cache_creation": {}}]}], "has_more": True, "next_page": "pg2"}
        p2 = {"data": [{"starting_at": "2026-10-14T00:00:00Z", "results": [{"model": "m-1", "uncached_input_tokens": 7, "output_tokens": 1, "cache_read_input_tokens": 0}]}], "has_more": False}
        s = FakeSession([p1, p2])
        events = AnthropicUsageConnector("sk-ant-admin01-x", days=2, session=s, now=NOW).fetch_events()
        self.assertEqual(len(events), 2)  # the all-zero result is dropped
        e = events[0]
        self.assertEqual((e["input_tokens"], e["output_tokens"], e["cache_read_tokens"], e["cache_write_tokens"], e["application"]), (100, 40, 20, 8, "wrkspc_1"))
        self.assertEqual(s.calls[0][2]["x-api-key"], "sk-ant-admin01-x")
        self.assertEqual(s.calls[0][2]["anthropic-version"], "2023-06-01")
        self.assertEqual(s.calls[1][1]["page"], "pg2")

    def test_a_workspace_key_gets_a_clear_message(self):
        with self.assertRaises(UsageApiError) as cm:
            AnthropicUsageConnector("k", session=FakeSession([{}], status=403), now=NOW).test_connection()
        self.assertIn("Admin API key", str(cm.exception))

    def test_openai_splits_cached_input_and_counts_requests(self):
        page = {"data": [{"start_time": 1760400000, "results": [{"model": "gpt-x", "project_id": "proj_1", "input_tokens": 1000, "input_cached_tokens": 400,
                                                                 "output_tokens": 200, "num_model_requests": 9}]}], "has_more": False}
        (e,) = OpenAIUsageConnector("sk-admin-x", session=FakeSession([page]), now=NOW).fetch_events()
        self.assertEqual((e["input_tokens"], e["cache_read_tokens"], e["output_tokens"], e["request_count"], e["application"]), (600, 400, 200, 9, "proj_1"))

    def test_a_scheduled_connection_records_events_idempotently(self):
        engine = create_engine("sqlite:///:memory:")
        events = [{"ts": "2026-10-14T00:00:00Z", "provider": "anthropic", "model": "m-1", "input_tokens": 10, "output_tokens": 5, "event_key": "k1", "application": "ws"}]
        spec = dict(registry.SPECS["anthropic-usage"], pull=lambda v: {"kind": "ai_usage", "events": events})
        with patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": crypto.generate_key()}), patch.dict(registry.SPECS, {"anthropic-usage": spec}):
            c = conn_store.create("Claude usage", "anthropic-usage", {"admin_key": "sk-ant-admin01-x"}, "admin", engine=engine)
            first = sync.run(c["id"], "admin", engine, enrich=False)
            conn_store.finish_run(c["id"], "ok", "x", 1, engine)
            second = sync.run(c["id"], "admin", engine, enrich=False)
        self.assertTrue(first["ok"], first)
        self.assertIn("1 new", first["message"])
        self.assertIn("1 updated", second["message"])
        self.assertEqual(len(store.fetch(engine=engine)), 1)

    def test_days_is_validated(self):
        with self.assertRaises(ValueError):
            registry.split_values("anthropic-usage", {"admin_key": "k", "days": "abc"})


class AnalyticsTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")

    def test_totals_groupings_and_unknown_cost(self):
        store.record([ev(event_key="1", cost_usd=2.0), ev(event_key="2", team="Data", application="rag", model="m-2", input_tokens=1000),
                      ev(event_key="3", team=None, application=None)], "api", self.engine)
        s = analytics.summary(30, self.engine, NOW)
        self.assertEqual(s["totals"]["requests"], 3)
        self.assertEqual(s["totals"]["cost_usd"], 2.0)
        self.assertEqual(s["totals"]["requests_with_unknown_cost"], 2)
        teams = {t["name"]: t for t in s["by_team"]}
        self.assertEqual(set(teams), {"Platform", "Data", "(unattributed)"})
        self.assertFalse(teams["Data"]["cost_complete"])
        self.assertIn("Only Quanta", analytics.summary(30, create_engine("sqlite:///:memory:"), NOW)["coverage"]["note"])

    def test_cache_hit_rate(self):
        store.record([ev(event_key="1", input_tokens=100, cache_read_tokens=300)], "api", self.engine)
        self.assertEqual(analytics.summary(30, self.engine, NOW)["totals"]["cache_hit_pct"], 75.0)

    def test_a_spike_is_flagged(self):
        events = [ev(event_key=f"d{i}", ts=f"2026-10-{i:02d}T10:00:00Z", input_tokens=200_000, output_tokens=0) for i in range(5, 12)]
        events.append(ev(event_key="spike", ts="2026-10-12T10:00:00Z", input_tokens=2_000_000, output_tokens=0))
        store.record(events, "api", self.engine)
        kinds = {(a["kind"], a["date"]) for a in analytics.summary(30, self.engine, NOW)["anomalies"]}
        self.assertIn(("spike", "2026-10-12"), kinds)

    def test_models_outside_the_approved_list(self):
        store.record([ev(event_key="1", model="approved-1"), ev(event_key="2", model="rogue-9")], "api", self.engine)
        with patch.object(analytics, "policy", return_value={"allowed_models": ["approved-*"]}):
            bad = analytics.summary(30, self.engine, NOW)["outside_allowed_models"]
        self.assertEqual([b["model"] for b in bad], ["rogue-9"])

    def test_budget_states_and_projection(self):
        store.record([ev(event_key="1", ts="2026-10-05T10:00:00Z", cost_usd=60), ev(event_key="2", ts="2026-10-06T10:00:00Z", cost_usd=30, team="Data")], "api", self.engine)
        analytics.add_budget("org", None, "month", 100, None, 80, "a", self.engine)
        analytics.add_budget("team", "Data", "month", 20, None, 80, "a", self.engine)
        analytics.add_budget("team", "Platform", "month", 1000, None, 80, "a", self.engine)
        st = {(b["scope"], b["scope_value"]): b for b in analytics.budget_status(self.engine, NOW)}
        self.assertEqual((st[("org", None)]["state"], st[("org", None)]["used_pct"]), ("alert", 90.0))
        self.assertEqual(st[("team", "Data")]["state"], "exceeded")
        self.assertEqual(st[("team", "Platform")]["state"], "ok")
        self.assertGreater(st[("org", None)]["projected_pct"], 90)

    def test_budget_validation(self):
        for args in (("galaxy", None, "month", 1, None, 80), ("team", "", "month", 1, None, 80), ("org", None, "century", 1, None, 80),
                     ("org", None, "month", None, None, 80), ("org", None, "month", -5, None, 80), ("org", None, "month", 5, None, 0)):
            with self.assertRaises(ValueError):
                analytics.add_budget(*args, "a", self.engine)


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")

    def test_subdomains_match_and_unknown_hosts_are_ignored(self):
        self.assertEqual(discovery.classify("api.openai.com")[0], "OpenAI / ChatGPT")
        self.assertIsNone(discovery.classify("notopenai.com"))
        self.assertIsNone(discovery.classify("example.org"))

    def test_csv_and_free_text_logs(self):
        csv_found = discovery.parse_log("domain,user,count\nchatgpt.com,alice,5\nchatgpt.com,bob,2\nexample.org,carol,9\nclaude.ai,alice,1\n")
        self.assertEqual((csv_found["chatgpt.com"]["requests"], len(csv_found["chatgpt.com"]["users"]), "example.org" in csv_found), (7, 2, False))
        text_found = discovery.parse_log("2026-10-01 GET https://gemini.google.com/app 200\n2026-10-01 GET https://news.example.org/ 200\n")
        self.assertEqual(list(text_found), ["gemini.google.com"])

    def test_recorded_services_start_unreviewed_and_keep_their_status(self):
        out = discovery.record(discovery.parse_log("domain,user,count\nclaude.ai,a,3\n"), "proxy-log", self.engine)
        self.assertEqual(out, {"services": 1, "new": 1})
        (app,) = discovery.list_apps(self.engine)
        self.assertEqual(app["status"], "unreviewed")
        discovery.set_status(app["id"], "sanctioned", "it@acme", "approved for staff", self.engine)
        again = discovery.record(discovery.parse_log("domain,user,count\nclaude.ai,b,4\n"), "dns", self.engine)
        (app,) = discovery.list_apps(self.engine)
        self.assertEqual((again["new"], app["status"], app["requests_seen"], app["signals"]), (0, "sanctioned", 7, ["dns", "proxy-log"]))

    def test_validation(self):
        with self.assertRaises(ValueError):
            discovery.set_status(1, "maybe", engine=self.engine)
        with self.assertRaises(KeyError):
            discovery.set_status(99, "blocked", engine=self.engine)
        with self.assertRaises(ValueError):
            discovery.add_app("x", "not a domain", self.engine)


class AiUsageApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60))]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", PW, "User", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)
        self.login("admin@t.local")
        self.key = self.client.post("/api/api-keys", json={"name": "gw", "scopes": ["ai-usage:write"]}).json()["key"]
        self.other = self.client.post("/api/api-keys", json={"name": "ci", "scopes": ["ingest:write"]}).json()["key"]
        self.client.cookies.clear()

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email):
        self.client.cookies.clear()
        self.client.post("/api/auth/login", json={"email": email, "password": PW})

    def h(self, key=None):
        return {"Authorization": f"Bearer {key or self.key}"}

    def test_a_gateway_pushes_events_with_a_scoped_key(self):
        body = {"source": "gateway", "events": [ev(event_key="e1", ts=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")), {"bad": 1}]}
        self.assertEqual(self.client.post("/api/ingest/ai-usage", json=body).status_code, 401)
        self.assertEqual(self.client.post("/api/ingest/ai-usage", json=body, headers=self.h(self.other)).status_code, 401)
        r = self.client.post("/api/ingest/ai-usage", json=body, headers=self.h())
        self.assertEqual((r.status_code, r.json()["recorded"], r.json()["rejected"]), (200, 1, 1))
        self.login("admin@t.local")
        s = self.client.get("/api/ai-usage/summary").json()
        self.assertEqual((s["totals"]["requests"], s["by_team"][0]["name"]), (1, "Platform"))

    def test_otlp_traces_are_accepted(self):
        doc = OtlpTests().doc({"gen_ai.request.model": "m-1", "gen_ai.usage.input_tokens": 50, "gen_ai.usage.output_tokens": 10})
        r = self.client.post("/api/ingest/otlp/v1/traces", content=json.dumps(doc), headers=self.h())
        self.assertEqual((r.status_code, r.json()["recorded"]), (200, 1), r.text)
        self.assertEqual(self.client.post("/api/ingest/otlp/v1/traces", content="not json", headers=self.h()).status_code, 400)

    def test_the_analytics_are_admin_only(self):
        self.assertEqual(self.client.get("/api/ai-usage/summary").status_code, 401)
        self.login("user@t.local")
        self.assertEqual(self.client.get("/api/ai-usage/summary").status_code, 403)
        self.assertEqual(self.client.get("/api/ai-usage/apps").status_code, 403)

    def test_budgets_and_application_review(self):
        self.login("admin@t.local")
        b = self.client.post("/api/ai-usage/budgets", json={"scope": "org", "period": "month", "limit_usd": 100})
        self.assertEqual(b.status_code, 200, b.text)
        self.assertEqual(self.client.post("/api/ai-usage/budgets", json={"scope": "org", "period": "month"}).status_code, 400)
        self.assertEqual(len(self.client.get("/api/ai-usage/summary").json()["budgets"]), 1)
        self.assertEqual(self.client.delete(f"/api/ai-usage/budgets/{b.json()['id']}").status_code, 200)
        up = self.client.post("/api/ai-usage/discovery?source=proxy", content="domain,user,count\nchatgpt.com,alice,5\n")
        self.assertEqual((up.status_code, up.json()["new"]), (200, 1))
        (app,) = self.client.get("/api/ai-usage/apps").json()["apps"]
        self.assertEqual(self.client.put(f"/api/ai-usage/apps/{app['id']}", json={"status": "blocked"}).status_code, 200)
        self.assertEqual(self.client.put(f"/api/ai-usage/apps/{app['id']}", json={"status": "maybe"}).status_code, 400)
        self.assertEqual(self.client.put("/api/ai-usage/apps/999", json={"status": "blocked"}).status_code, 404)

    def test_the_login_gate_still_protects_everything_except_key_checked_ingest(self):
        with patch.object(dashboard_app_module, "_require_login_for_reads_enabled", return_value=True):
            self.assertEqual(self.client.get("/api/ai-usage/summary").status_code, 401)
            r = self.client.post("/api/ingest/ai-usage", json={"events": [ev(event_key="x")]}, headers=self.h())
            self.assertEqual(r.status_code, 200)


if __name__ == "__main__":
    unittest.main()
