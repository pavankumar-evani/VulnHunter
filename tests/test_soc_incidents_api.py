"""
API tests for SOC incident automation: alerts arriving by API become incidents with nobody creating a case, the documented routes and their shapes, RBAC,
the live Server-Sent Events feed, the analyst roster endpoints, the manual exception, licensing coverage and the optional confirm-gated AI summary.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app as dashboard_app_module  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.licensing import license as licensing  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
T1190 = {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
FINDING = {"id": "FIND-1", "title": "Log4Shell", "cve": "CVE-2021-44228", "severity": "Critical", "asset": {"name": "WEB-1"}, "attack_techniques": [T1190], "kev": {"listed": True}, "epss": {"score": 0.9}}
ALERT = {"external_id": "w1", "title": "Shell spawned by web server", "severity": "High", "asset": "WEB-1", "technique": "T1190", "rule_name": "web-shell", "detail": "outbound to 185.220.101.9"}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
                  patch.object(dashboard_app_module.dashboard_data, "load_live_queue", return_value=[FINDING])]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("plain@t.local", PW, "Plain", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)
        self.login("admin@t.local")
        self.key = self.client.post("/api/api-keys", json={"name": "siem", "scopes": ["soc:write"]}).json()["key"]
        self.h = {"Authorization": f"Bearer {self.key}"}

    def login(self, email):
        self.client.cookies.clear()
        self.client.post("/api/auth/login", json={"email": email, "password": PW})

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def push(self, **kw):
        self.client.cookies.clear()
        r = self.client.post("/api/ingest/alerts", json={"alerts": [{**ALERT, **kw}]}, headers=self.h)
        self.login("admin@t.local")
        return r

    def analyst(self, email, tier=1, **kw):
        r = self.client.put("/api/soc/analysts", json={"email": email, "tier": tier, **kw})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def incidents(self, **q):
        return self.client.get("/api/soc/incidents", params=q).json()["incidents"]


class AutomaticPath(Base):
    def test_an_alert_becomes_a_routed_incident_without_anyone_creating_a_case(self):
        self.analyst("l2@t.local", 2, skills=["endpoint"])
        self.assertEqual(self.push().json()["investigated"], 1)
        inc = self.incidents()
        self.assertEqual(len(inc), 1)
        i = inc[0]
        self.assertEqual((i["status"], i["assignee"], i["tier"], i["source"]), ("new", "l2@t.local", 2, "auto"))
        self.assertTrue(i["routing_reason"])
        self.assertIsNotNone(i["case_id"])
        self.assertEqual(len(self.client.get("/api/soc/cases").json()["cases"]), 1)       # the case is how it is worked, created by the system

    def test_the_detail_shape(self):
        self.analyst("l2@t.local", 2)
        self.push()
        i = self.incidents()[0]
        d = self.client.get(f"/api/soc/incidents/{i['id']}").json()
        for k in ("id", "title", "severity", "base_severity", "priority", "tier", "queue", "status", "assignee", "verdict", "confidence", "summary", "routing_reason", "correlation",
                  "kill_chain", "entities", "assets", "techniques", "cves", "case_id", "sla", "alerts", "timeline", "recommended", "related_incidents", "duplicate_count"):
            self.assertIn(k, d, k)
        self.assertEqual(d["alerts"][0]["role"], "primary")
        self.assertEqual(d["entities"]["hosts"], ["web-1"])
        self.assertEqual(d["kill_chain"][0]["tactic"], "Initial Access")
        self.assertIn("CVE-2021-44228", d["cves"])
        self.assertIn("next_steps", d["recommended"])
        self.assertEqual({"id", "kind", "actor", "body", "data", "created_at", "incident_id"}, set(d["timeline"][0]))
        self.assertEqual(self.client.get("/api/soc/incidents/9999").status_code, 404)

    def test_a_second_alert_is_grouped_and_a_repeat_is_ignored(self):
        self.analyst("l2@t.local", 2)
        self.push()
        self.push(external_id="w2", title="Outbound beacon", technique="T1071", rule_name="beacon")
        self.push()                       # the same external id again
        inc = self.incidents()
        self.assertEqual(len(inc), 1)
        d = self.client.get(f"/api/soc/incidents/{inc[0]['id']}").json()
        self.assertEqual(len(d["alerts"]), 2)
        self.assertEqual({r["reason"] for r in d["alerts"][1]["reasons"]} & {"shared_host"}, {"shared_host"})
        self.assertGreaterEqual(len(d["kill_chain"]), 2)

    def test_filters(self):
        self.analyst("l2@t.local", 2)
        self.push()
        self.push(external_id="w9", asset="LAB-9", title="Odd login", severity="Low", technique="T1110", rule_name="auth", detail="three failed logins")
        self.assertEqual(len(self.incidents(severity="High")), 1)
        self.assertEqual(len(self.incidents(assignee="l2@t.local")), 2)   # an L2 analyst also takes the L1 incident when no L1 exists
        self.assertEqual(len(self.incidents(unassigned="true")), 0)
        self.assertEqual(len(self.incidents(tier=2)), 1)
        self.assertEqual(len(self.incidents(queue="L1")), 1)
        self.assertEqual(len(self.incidents(status="new")), 2)
        self.assertEqual(self.incidents(mine="true"), [])
        self.analyst("admin@t.local", 3)
        self.assertEqual(self.client.get("/api/soc/incidents", params={"mine": "true"}).json()["incidents"], [])

    def test_the_analyst_works_it_through_to_a_verdict(self):
        self.analyst("admin@t.local", 2)
        self.push()
        iid = self.incidents()[0]["id"]
        post = lambda action, **body: self.client.post(f"/api/soc/incidents/{iid}/{action}", json=body)  # noqa: E731
        self.assertEqual(post("accept").json()["status"], "triaging")
        self.assertEqual(post("advance", status="investigating").json()["status"], "investigating")
        self.assertEqual(post("resolve", summary="Contained the shell and rotated credentials.").status_code, 400)      # no verdict
        self.assertEqual(post("resolve", verdict="true-positive", summary="short").status_code, 400)                    # no real summary
        r = post("resolve", verdict="true-positive", summary="Contained the shell and rotated credentials.")
        self.assertEqual((r.status_code, r.json()["status"], r.json()["verdict"]), (200, "resolved", "true-positive"))
        self.assertEqual(post("reopen").status_code, 400)
        self.assertEqual(post("reopen", reason="it is back").json()["status"], "investigating")
        self.assertEqual(post("bogus").status_code, 404)
        self.assertEqual(self.client.post("/api/soc/incidents/9999/accept", json={}).status_code, 404)
        self.assertEqual(post("note", note="called the owner").json()["timeline"][-1]["kind"], "note")
        self.assertEqual(self.client.get("/api/soc/incidents", params={"mine": "true", "open_only": "true"}).json()["counts"], {"investigating": 1})

    def test_merge_split_and_escalate_routes(self):
        self.analyst("admin@t.local", 3)
        self.push()
        self.push(external_id="w2", asset="DB-2", title="Odd query", technique="T1190", rule_name="db-rule", severity="Medium", detail="routine query")
        a, b = sorted(i["id"] for i in self.incidents())
        r = self.client.post(f"/api/soc/incidents/{a}/merge", json={"source_id": b})
        self.assertEqual((r.status_code, len(r.json()["alerts"])), (200, 2))
        self.assertEqual(self.client.post(f"/api/soc/incidents/{a}/merge", json={}).status_code, 400)
        first = r.json()["alerts"][0]["id"]
        s = self.client.post(f"/api/soc/incidents/{a}/split", json={"alert_ids": [r.json()["alerts"][1]["id"]]})
        self.assertEqual(s.status_code, 200)
        self.assertEqual(s.json()["original"]["alerts"][0]["id"], first)
        e = self.client.post(f"/api/soc/incidents/{a}/escalate", json={"summary": "Needs the response team to look at the web server."})
        self.assertEqual(e.json()["tier"], 3)
        self.assertEqual(self.client.post(f"/api/soc/incidents/{a}/escalate", json={"summary": "x"}).status_code, 400)

    def test_manual_creation_is_an_exception_with_a_required_reason(self):
        self.assertEqual(self.client.post("/api/soc/incidents/manual", json={"title": "Phone report", "reason": ""}).status_code, 400)
        r = self.client.post("/api/soc/incidents/manual", json={"title": "Phone report", "reason": "Reported by phone, no alert exists yet", "severity": "Low"})
        self.assertEqual((r.status_code, r.json()["source"]), (200, "manual-exception"))
        self.assertEqual(r.json()["timeline"][0]["data"]["manual"], True)
        # the older case route is untouched
        self.assertEqual(self.client.post("/api/soc/cases", json={"title": "legacy"}).status_code, 200)


class RoutingAndRoster(Base):
    def test_analyst_endpoints(self):
        a = self.analyst("a@t.local", 2, skills=["cloud", "identity"], capacity=5, shift_start="08:00", shift_end="17:00", on_call=True)["analyst"]
        self.assertEqual((a["skills"], a["capacity"], a["on_call"]), (["cloud", "identity"], 5, True))
        row = [x for x in self.client.get("/api/soc/analysts").json()["analysts"] if x["email"] == "a@t.local"][0]
        for k in ("email", "tier", "open_cases", "at_capacity", "skills", "available", "shift_start", "on_call", "capacity", "on_shift", "open_incidents"):
            self.assertIn(k, row, k)
        self.assertEqual(self.client.put("/api/soc/analysts", json={"email": "a@t.local", "skills": ["magic"]}).status_code, 400)
        self.assertEqual(self.client.put("/api/soc/analysts", json={"email": "nobody@t.local", "capacity": 3}).status_code, 404)

    def test_marking_an_analyst_unavailable_reroutes_their_work(self):
        self.analyst("a@t.local", 2)
        self.analyst("b@t.local", 2)
        self.push()
        i = self.incidents()[0]
        other = "b@t.local" if i["assignee"] == "a@t.local" else "a@t.local"
        r = self.client.put("/api/soc/analysts", json={"email": i["assignee"], "available": False}).json()
        self.assertEqual(r["rerouted_incident_ids"], [i["id"]])
        self.assertEqual(self.incidents()[0]["assignee"], other)

    def test_nobody_qualified_is_queued_not_dropped(self):
        self.analyst("l1@t.local", 1)
        self.push()
        i = self.incidents()[0]
        self.assertEqual((i["assignee"], i["queue"]), (None, "L2"))
        self.assertTrue(any("Nobody who qualifies" in r for r in i["routing_reason"]))

    def test_preview_endpoint(self):
        self.analyst("l2@t.local", 2)
        self.push()
        self.push(external_id="w2", title="Second", technique="T1071", rule_name="beacon")
        self.client.cookies.clear()
        self.login("admin@t.local")
        # an alert that is not yet in any incident: store one directly
        from remediation.hunting import store as hunt_store
        new, _ = hunt_store.receive_alert({"external_id": "p1", "title": "Another on WEB-1", "severity": "Medium", "asset": "WEB-1", "technique": "T1055", "rule_name": "inj"}, self.engine)
        before = len(self.incidents())
        r = self.client.get("/api/soc/routing/preview", params={"alert_id": new["id"]})
        self.assertEqual(r.status_code, 200)
        p = r.json()
        self.assertEqual(p["would_join"], self.incidents()[0]["id"])
        self.assertTrue(p["routing"]["reasons"])
        self.assertIn("score", p["correlation"])
        self.assertEqual(len(self.incidents()), before)
        self.assertEqual(self.client.get("/api/soc/routing/preview", params={"alert_id": 9999}).status_code, 404)

    def test_sweep_endpoint(self):
        self.push()
        self.analyst("late@t.local", 2)
        r = self.client.post("/api/soc/incidents/sweep").json()
        self.assertEqual(len(r["retried"]), 1)


class Access(Base):
    ROUTES = [("get", "/api/soc/incidents"), ("get", "/api/soc/incidents/1"), ("post", "/api/soc/incidents/1/accept"), ("post", "/api/soc/incidents/manual"),
              ("get", "/api/soc/routing/preview?alert_id=1"), ("put", "/api/soc/analysts"), ("get", "/api/soc/incidents/stream"), ("post", "/api/soc/incidents/sweep"),
              ("post", "/api/soc/incidents/1/ai-summary")]

    def call(self, method, path):
        return getattr(self.client, method)(path, **({"json": {}} if method in ("post", "put") else {}))

    def test_anonymous_is_refused(self):
        self.client.cookies.clear()
        for m, p in self.ROUTES:
            self.assertEqual(self.call(m, p).status_code, 401, p)

    def test_a_plain_user_is_refused(self):
        self.login("plain@t.local")
        for m, p in self.ROUTES:
            self.assertEqual(self.call(m, p).status_code, 403, p)

    def test_every_incident_route_is_covered_by_the_soc_module_license(self):
        for _, p in self.ROUTES:
            self.assertEqual(licensing.module_for_path(p.split("?")[0]), ("module", ["soc"]))


class Stream(Base):
    def test_sse_headers_events_and_resume(self):
        self.analyst("l2@t.local", 2)
        self.push()
        r = self.client.get("/api/soc/incidents/stream", params={"after": 0, "max_seconds": 1})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.headers["content-type"].startswith("text/event-stream"))
        self.assertEqual(r.headers["cache-control"], "no-cache")
        body = r.text
        self.assertIn("event: incident.created", body)
        self.assertIn("event: incident.assigned", body)
        data = [json.loads(line[6:]) for line in body.splitlines() if line.startswith("data: ")]
        self.assertTrue(all({"id", "type", "incident_id", "kind", "at"} <= set(d) for d in data))
        last = max(d["id"] for d in data)
        again = self.client.get("/api/soc/incidents/stream", params={"max_seconds": 1}, headers={"Last-Event-ID": str(last)})
        self.assertNotIn("event: incident", again.text)                        # nothing newer than the cursor
        self.assertIn("reconnect to continue", again.text)

    def test_the_stream_cannot_write(self):
        self.assertEqual(self.client.post("/api/soc/incidents/stream", json={}).status_code, 405)   # the stream is GET only


class AiSummary(Base):
    def test_preview_only_without_confirm_and_never_includes_alert_text(self):
        self.analyst("l2@t.local", 2)
        self.push()
        iid = self.incidents()[0]["id"]
        with patch.object(dashboard_app_module, "_run_ai_call_and_record_usage", side_effect=AssertionError("must not spend")):
            r = self.client.post(f"/api/soc/incidents/{iid}/ai-summary", json={}).json()
        self.assertTrue(r["dry_run"])
        self.assertNotIn("web server", r["prompt"])
        self.assertNotIn("WEB-1", r["prompt"])

    def test_confirmed_call_is_saved_only_when_asked(self):
        self.analyst("l2@t.local", 2)
        self.push()
        iid = self.incidents()[0]["id"]
        with patch.object(dashboard_app_module, "_enforce_ai_usage_limit", return_value={}), patch.object(dashboard_app_module, "_run_ai_call_and_record_usage", return_value="Look at the web server first."):
            r = self.client.post(f"/api/soc/incidents/{iid}/ai-summary", json={"confirm": True}).json()
            self.assertEqual((r["dry_run"], r["saved"]), (False, False))
            self.assertIsNone(self.client.get(f"/api/soc/incidents/{iid}").json()["summary_ai"])
            self.client.post(f"/api/soc/incidents/{iid}/ai-summary", json={"confirm": True, "save": True})
        d = self.client.get(f"/api/soc/incidents/{iid}").json()
        self.assertEqual(d["summary_ai"], "Look at the web server first.")
        self.assertTrue(d["summary"])       # the deterministic summary is still the record


if __name__ == "__main__":
    unittest.main()
