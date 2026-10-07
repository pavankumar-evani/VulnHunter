"""
API tests for incident investigation reports: the stored-data report, confirm-gated live refresh (reputation, SIEM) with budgets and the look-back ceiling, follow-ups and merging,
ITSM ticket intake through to an investigated incident, the post-back to the ticket (dry run and confirm, with a fake ITSM), RBAC and licensing. No real network: every outside
call is a hand-rolled fake.
"""
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
from remediation.connections import links as conn_links, registry as conn_registry  # noqa: E402
from remediation.hunting import service as hunt_service  # noqa: E402
from remediation.investigation import playbook as qpb  # noqa: E402
from remediation.licensing import license as licensing  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
T1190 = {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
FINDING = {"id": "FIND-1", "title": "Log4Shell", "cve": "CVE-2021-44228", "severity": "Critical", "asset": {"name": "WEB-1"}, "attack_techniques": [T1190], "kev": {"listed": True}, "epss": {"score": 0.9}}
ALERT = {"external_id": "w1", "title": "Shell spawned by web server", "severity": "High", "asset": "WEB-1", "technique": "T1190", "rule_name": "web-shell", "detail": "outbound to 185.220.101.9"}


class FakeSiem:
    def __init__(self, count=3, boom=False):
        self.count, self.boom, self.calls = count, boom, []

    def search(self, query, earliest="-24h", max_rows=25):
        self.calls.append((query, earliest, max_rows))
        if self.boom:
            raise RuntimeError("search timed out")
        return {"count": self.count, "rows": [{"host": "WEB-1", "hosts": "2"}][:max_rows], "truncated": False, "sid": "S"}


class FakeRep:
    def __init__(self):
        self.sent = []

    def lookup(self, v):
        self.sent.append(v)
        return {"result": "seen", "malicious": 30, "suspicious": 1, "harmless": 10, "undetected": 5, "total": 46}


class FakeItsm:
    def __init__(self, fail=False):
        self.sent, self.fail = [], fail

    def add_comment(self, ref, text):
        if self.fail:
            raise RuntimeError("401 from the ITSM")
        self.sent.append((ref, text))
        return {"status": "commented"}


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
        self.other = self.client.post("/api/api-keys", json={"name": "ro", "scopes": ["read:findings"]}).json()["key"]
        self.siem, self.rep = FakeSiem(), FakeRep()

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

    def incident_id(self):
        self.push()
        return self.client.get("/api/soc/incidents").json()["incidents"][0]["id"]

    def connectors(self, siem=True, rep=True):
        def fake(conn_type, cid=None, engine=None):
            if conn_type == "splunk-search":
                return (self.siem, {"name": "splunk"}) if siem else (None, None)
            return (self.rep, {"name": "vt"}) if rep else (None, None)
        return patch.object(hunt_service, "connector", side_effect=fake)


class StoredReport(Base):
    def test_first_open_builds_the_report_from_stored_data_and_it_is_versioned(self):
        iid = self.incident_id()
        r = self.client.get(f"/api/soc/incidents/{iid}/report")
        self.assertEqual(r.status_code, 200, r.text)
        rep = r.json()["report"]
        for k in ("verdict", "summary", "history", "entities", "iocs", "attack", "attack_flow", "timeline", "root_cause", "tool_actions", "recommended_actions", "references", "live_search",
                  "followups", "limits", "evidence", "mode", "version", "look_back_days", "dropped_statements"):
            self.assertIn(k, rep, k)
        self.assertEqual((rep["version"], rep["mode"]["stored_data_only"], rep["mode"]["siem"]), (1, True, "not-connected"))
        self.assertIn(rep["verdict"]["label"], ("true-positive", "false-positive", "action-needed"))
        self.assertTrue(all(c["evidence"] for c in rep["summary"]))
        listed = {e["ref"] for e in rep["evidence"]}
        self.assertTrue(all(set(c["evidence"]) <= listed for c in rep["summary"] + rep["verdict"]["rationale"]))
        self.assertEqual(self.client.get(f"/api/soc/incidents/{iid}/report").json()["report"]["version"], 1)     # opening again does not rebuild
        md = self.client.get(f"/api/soc/incidents/{iid}/report?format=md")
        self.assertIn("text/markdown", md.headers["content-type"])
        self.assertIn("## Why", md.text)
        self.assertEqual(self.client.get(f"/api/soc/incidents/{iid}/report?format=pdf").status_code, 400)
        self.assertEqual(self.client.get("/api/soc/incidents/9999/report").status_code, 404)

    def test_the_known_exploited_host_shows_in_the_summary_and_the_entity_table(self):
        iid = self.incident_id()
        rep = self.client.get(f"/api/soc/incidents/{iid}/report").json()["report"]
        host = next(e for e in rep["entities"] if e["kind"] == "host")
        self.assertEqual((host["kev_findings"], host["owner"]), (1, "unknown"))
        self.assertTrue(any("known-exploited" in c["text"] for c in rep["summary"]))
        self.assertTrue(any(i["value"] == "185.220.101.9" and i["reputation"]["status"] == "not-looked-up" for i in rep["iocs"]))

    def test_refresh_from_stored_data_needs_no_confirmation_and_bumps_the_version(self):
        iid = self.incident_id()
        r = self.client.post(f"/api/soc/incidents/{iid}/report/refresh", json={})
        self.assertEqual((r.status_code, r.json()["preview_only"], r.json()["report"]["version"]), (200, False, 1))
        self.assertEqual(self.client.post(f"/api/soc/incidents/{iid}/report/refresh", json={}).json()["report"]["version"], 2)
        events = self.client.get(f"/api/soc/incidents/{iid}").json()["timeline"]
        self.assertEqual(sum(1 for e in events if e["kind"] == "report"), 2)


class LiveRefresh(Base):
    def test_preview_runs_nothing_and_names_what_would_leave(self):
        iid = self.incident_id()
        with self.connectors():
            r = self.client.post(f"/api/soc/incidents/{iid}/report/refresh", json={"siem": True, "reputation": True})
        j = r.json()
        self.assertEqual((r.status_code, j["preview_only"]), (200, True))
        self.assertEqual(j["indicators_that_would_be_sent"], ["185.220.101.9"])
        self.assertTrue(j["searches_that_would_run"])
        self.assertEqual((self.siem.calls, self.rep.sent), ([], []))
        self.assertEqual(j["budget"]["max_queries"], 6)

    def test_confirm_runs_the_bounded_searches_and_the_lookup_and_records_them(self):
        iid = self.incident_id()
        with self.connectors():
            r = self.client.post(f"/api/soc/incidents/{iid}/report/refresh", json={"siem": True, "reputation": True, "confirm": True})
        self.assertEqual(r.status_code, 200, r.text)
        rep = r.json()["report"]
        self.assertEqual(self.rep.sent, ["185.220.101.9"])
        self.assertTrue(self.siem.calls)
        self.assertLessEqual(len(self.siem.calls), 6)
        self.assertEqual((rep["mode"]["siem"], rep["mode"]["reputation"], rep["live_search"]["stop_reason"]), ("ran", "ran", "completed"))
        self.assertEqual(next(i for i in rep["iocs"] if i["value"] == "185.220.101.9")["verdict"], "malicious")
        self.assertTrue(any(x["kind"] == "reputation lookup" for x in rep["references"]))
        searches = [x for x in rep["references"] if x["kind"] == "search" and x["source"].startswith("SIEM, read-only")]
        self.assertEqual(len(searches), rep["live_search"]["queries_run"])
        self.assertTrue(all(x["query"] and x["at"] for x in searches))
        self.assertEqual(self.client.get(f"/api/soc/incidents/{iid}/report").json()["report"]["version"], rep["version"])

    def test_the_query_budget_stop_is_recorded(self):
        iid = self.incident_id()
        pb = qpb.load()
        pb["budget"]["max_queries"] = 1
        with self.connectors(), patch.object(qpb, "load", return_value=pb):
            rep = self.client.post(f"/api/soc/incidents/{iid}/report/refresh", json={"siem": True, "confirm": True}).json()["report"]
        self.assertEqual((rep["live_search"]["stop_reason"], rep["live_search"]["queries_run"], len(self.siem.calls)), ("stopped: query budget", 1, 1))
        self.assertTrue(rep["live_search"]["not_run"])

    def test_the_look_back_ceiling_needs_a_written_justification(self):
        iid = self.incident_id()
        with self.connectors():
            no = self.client.post(f"/api/soc/incidents/{iid}/report/refresh", json={"siem": True, "confirm": True, "lookback_days": 200})
            self.assertEqual(no.status_code, 400)
            self.assertEqual(self.siem.calls, [])
            too_far = self.client.post(f"/api/soc/incidents/{iid}/report/refresh", json={"siem": True, "confirm": True, "lookback_days": 500, "justification": "x" * 40})
            self.assertEqual(too_far.status_code, 400)
            ok = self.client.post(f"/api/soc/incidents/{iid}/report/refresh", json={"siem": True, "confirm": True, "lookback_days": 200, "justification": "Suspected long-running intrusion; the earliest alert is months old."})
            self.assertEqual(ok.status_code, 200, ok.text)
            default = self.client.post(f"/api/soc/incidents/{iid}/report/refresh", json={"siem": True, "confirm": True})
        self.assertEqual(default.json()["report"]["live_search"]["look_back_cap_days"], 90)
        self.assertEqual(ok.json()["report"]["live_search"]["look_back_cap_days"], 200)
        days = [int(c[1][1:-1]) for c in self.siem.calls]
        self.assertTrue(max(days) <= 30)                                       # each pattern still has its own, smaller limit

    def test_a_failing_siem_is_reported_not_hidden(self):
        iid = self.incident_id()
        self.siem = FakeSiem(boom=True)
        with self.connectors():
            rep = self.client.post(f"/api/soc/incidents/{iid}/report/refresh", json={"siem": True, "confirm": True}).json()["report"]
        self.assertEqual(rep["live_search"]["stop_reason"], "stopped: repeated errors")
        self.assertTrue(all(q["error"] for q in rep["live_search"]["results"]))
        self.assertFalse(any("hits" in c["text"] for c in rep["verdict"]["rationale"]))

    def test_nothing_configured_is_a_clear_400(self):
        iid = self.incident_id()
        with self.connectors(siem=False, rep=False):
            self.assertEqual(self.client.post(f"/api/soc/incidents/{iid}/report/refresh", json={"siem": True}).status_code, 400)
            self.assertEqual(self.client.post(f"/api/soc/incidents/{iid}/report/refresh", json={"reputation": True}).status_code, 400)


class FollowUps(Base):
    def test_ask_record_merge_and_unmerge(self):
        iid = self.incident_id()
        self.push(external_id="w2", title="Beacon", technique="T1071", asset="WEB-2", detail="to 185.220.101.9")
        r = self.client.post(f"/api/soc/incidents/{iid}/follow-up", json={"question": "Has 185.220.101.9 been seen before?"})
        self.assertEqual(r.status_code, 200, r.text)
        fu = r.json()["followup"]
        self.assertTrue(fu["answerable"])
        self.assertFalse(fu["merged"])
        self.assertTrue(fu["evidence"])
        rep = self.client.get(f"/api/soc/incidents/{iid}/report").json()
        self.assertEqual(rep["report"]["followups"], [])
        self.assertEqual([f["id"] for f in rep["open_followups"]], [fu["id"]])
        m = self.client.post(f"/api/soc/incidents/{iid}/report/merge-followups", json={"followup_ids": [fu["id"]]})
        self.assertEqual(m.status_code, 200, m.text)
        self.assertEqual([f["id"] for f in m.json()["report"]["followups"]], [fu["id"]])
        self.assertEqual(m.json()["open_followups"], [])
        u = self.client.post(f"/api/soc/incidents/{iid}/report/merge-followups", json={"followup_ids": [fu["id"]], "merged": False})
        self.assertEqual(u.json()["report"]["followups"], [])
        events = self.client.get(f"/api/soc/incidents/{iid}").json()["timeline"]
        self.assertTrue(any(e["kind"] == "followup" for e in events))
        self.assertEqual(len(self.client.get(f"/api/soc/incidents/{iid}/followups").json()["followups"]), 1)

    def test_a_question_with_no_entity_is_recorded_as_unanswerable_and_cannot_be_merged_into_evidence(self):
        iid = self.incident_id()
        fu = self.client.post(f"/api/soc/incidents/{iid}/follow-up", json={"question": "Is this bad?"}).json()["followup"]
        self.assertFalse(fu["answerable"])
        self.assertIn("Cannot be answered", fu["answer"])
        self.client.post(f"/api/soc/incidents/{iid}/report/merge-followups", json={"followup_ids": [fu["id"]]})
        self.assertEqual(self.client.get(f"/api/soc/incidents/{iid}/report").json()["report"]["followups"], [])

    def test_the_siem_search_in_a_follow_up_needs_confirm_and_the_ceiling(self):
        iid = self.incident_id()
        with self.connectors():
            pre = self.client.post(f"/api/soc/incidents/{iid}/follow-up", json={"question": "history of 185.220.101.9", "siem": True})
            self.assertTrue(pre.json()["preview_only"])
            self.assertEqual(self.siem.calls, [])
            self.assertEqual(self.client.post(f"/api/soc/incidents/{iid}/follow-up", json={"question": "history of 185.220.101.9", "siem": True, "confirm": True, "lookback_days": 400, "justification": "y" * 30}).status_code, 400)
            done = self.client.post(f"/api/soc/incidents/{iid}/follow-up", json={"question": "history of 185.220.101.9", "siem": True, "confirm": True})
        self.assertEqual(done.status_code, 200, done.text)
        self.assertEqual(len(self.siem.calls), 1)
        self.assertIn("SIEM, last 90 days", done.json()["followup"]["answer"])

    def test_errors(self):
        iid = self.incident_id()
        self.assertEqual(self.client.post(f"/api/soc/incidents/{iid}/follow-up", json={"question": "  "}).status_code, 400)
        self.assertEqual(self.client.post(f"/api/soc/incidents/{iid}/follow-up", json={"question": "x 1.2.3.4", "kind": "gossip"}).status_code, 400)
        self.assertEqual(self.client.post("/api/soc/incidents/9999/follow-up", json={"question": "a 1.2.3.4"}).status_code, 404)
        self.assertEqual(self.client.post(f"/api/soc/incidents/{iid}/report/merge-followups", json={"followup_ids": [12345]}).status_code, 400)


class ItsmIntake(Base):
    TICKET = {"system": "servicenow", "ticket_id": "INC0012345", "title": "EDR: shell spawned by web server", "description": "Outbound connection to 185.220.101.9 from the web tier",
              "priority": 2, "asset": "WEB-1", "user": "svc-web", "technique": "T1190", "rule_name": "edr-web-shell"}

    def intake(self, body=None, headers=None):
        self.client.cookies.clear()
        r = self.client.post("/api/ingest/itsm-ticket", json=body or self.TICKET, headers=headers or self.h)
        self.login("admin@t.local")
        return r

    def test_a_ticket_becomes_an_investigated_incident_with_a_report_waiting(self):
        r = self.intake()
        self.assertEqual(r.status_code, 200, r.text)
        j = r.json()
        self.assertEqual((j["created"], j["severity"], j["ticket"]), (True, "High", {"system": "servicenow", "ticket_id": "INC0012345"}))
        self.assertIsNotNone(j["incident_id"])
        self.assertEqual(j["report_version"], 1)
        alert = self.client.get(f"/api/soc/alerts/{j['alert_id']}").json()
        self.assertEqual((alert["source"], alert["external_id"], alert["technique"]), ("itsm:servicenow", "servicenow:INC0012345", "T1190"))
        self.assertIn("185.220.101.9", alert["entities"]["ips"])
        self.assertEqual(self.client.get(f"/api/soc/alerts/{j['alert_id']}/investigation").status_code, 200)       # auto-investigated
        links = conn_links.for_finding(f"alert:{j['alert_id']}", self.engine)
        self.assertEqual((links[0]["system"], links[0]["external_ref"]), ("servicenow", "INC0012345"))
        rep = self.client.get(f"/api/soc/incidents/{j['incident_id']}/report").json()["report"]
        self.assertEqual(rep["version"], 1)                                                                         # built at intake, not on first open
        self.assertIn("svc-web", [e["value"] for e in rep["entities"]])

    def test_a_repeat_of_the_same_ticket_is_ignored(self):
        first = self.intake().json()
        again = self.intake().json()
        self.assertEqual((again["created"], again["alert_id"], again["incident_id"]), (False, first["alert_id"], first["incident_id"]))
        self.assertEqual(len(self.client.get("/api/soc/alerts").json()["alerts"]), 1)

    def test_it_needs_a_key_with_the_soc_scope(self):
        self.assertEqual(self.client.post("/api/ingest/itsm-ticket", json=self.TICKET).status_code, 401)
        self.assertEqual(self.intake(headers={"Authorization": f"Bearer {self.other}"}).status_code, 401)

    def test_bad_tickets_are_400(self):
        self.assertEqual(self.intake({**self.TICKET, "ticket_id": "no spaces allowed"}).status_code, 400)
        self.assertEqual(self.intake({**self.TICKET, "title": " "}).status_code, 400)
        self.assertEqual(self.intake({**self.TICKET, "system": "pigeon"}).status_code, 400)

    def test_a_jira_ticket_with_no_priority_is_medium_and_says_so(self):
        j = self.intake({"system": "jira", "ticket_id": "SEC-77", "title": "Odd login", "description": "bob logged in from 198.51.100.4"}).json()
        self.assertEqual(j["severity"], "Medium")
        self.assertIn("no recognisable severity", self.client.get(f"/api/soc/alerts/{j['alert_id']}").json()["detail"])


class PostToTicket(Base):
    def setUp(self):
        super().setUp()
        self.fake = FakeItsm()
        spec = dict(conn_registry.SPECS["servicenow"])
        spec["make"] = lambda values: self.fake
        self.cm = [patch.object(hunt_service, "find_connection", return_value=({"name": "snow", "type": "servicenow"}, {})), patch.dict(conn_registry.SPECS, {"servicenow": spec}),
                   patch.object(conn_registry, "split_values", return_value=None)]
        self.client.cookies.clear()
        j = self.client.post("/api/ingest/itsm-ticket", json=ItsmIntake.TICKET, headers=self.h).json()
        self.login("admin@t.local")
        self.iid = j["incident_id"]

    def tearDown(self):
        for x in reversed(self.cm):
            try:
                x.stop()
            except RuntimeError:
                pass
        super().tearDown()

    def post(self, **body):
        for x in self.cm:
            x.start()
        try:
            return self.client.post(f"/api/soc/incidents/{self.iid}/report/post-to-ticket", json=body)
        finally:
            for x in reversed(self.cm):
                x.stop()

    def test_dry_run_by_default_then_confirm_then_never_twice(self):
        d = self.post()
        self.assertEqual(d.status_code, 200, d.text)
        self.assertTrue(d.json()["preview_only"])
        self.assertEqual(d.json()["results"][0]["status"], "dry-run")
        self.assertIn("Verdict:", d.json()["comment"])
        self.assertEqual(self.fake.sent, [])
        c = self.post(confirm=True)
        self.assertEqual((c.json()["preview_only"], c.json()["results"][0]["status"]), (False, "posted"))
        self.assertEqual([s[0] for s in self.fake.sent], ["INC0012345"])
        self.assertEqual(self.fake.sent[0][1], c.json()["comment"])
        again = self.post(confirm=True)
        self.assertEqual(again.json()["results"][0]["status"], "already-posted")
        self.assertEqual(len(self.fake.sent), 1)
        timeline = self.client.get(f"/api/soc/incidents/{self.iid}").json()["timeline"]
        self.assertEqual(sum(1 for e in timeline if e["kind"] == "ticket-comment"), 1)

    def test_a_failure_is_reported_and_can_be_retried(self):
        self.fake.fail = True
        r = self.post(confirm=True)
        self.assertEqual(r.json()["results"][0]["status"], "failed")
        self.fake.fail = False
        self.assertEqual(self.post(confirm=True).json()["results"][0]["status"], "posted")

    def test_no_connection_is_said_and_no_linked_ticket_is_a_400(self):
        self.cm[0] = patch.object(hunt_service, "find_connection", return_value=(None, None))
        self.assertEqual(self.post(confirm=True).json()["results"][0]["status"], "no-connection")
        iid = self.incident_id_without_ticket()
        self.assertEqual(self.client.post(f"/api/soc/incidents/{iid}/report/post-to-ticket", json={}).status_code, 400)

    def incident_id_without_ticket(self):
        self.push(external_id="plain1", title="Other thing", asset="DB-7", technique="T1059", detail="x")
        rows = [i for i in self.client.get("/api/soc/incidents").json()["incidents"] if i["id"] != self.iid]
        return rows[0]["id"]


class Access(Base):
    ROUTES = [("get", "/api/soc/incidents/1/report"), ("post", "/api/soc/incidents/1/report/refresh"), ("post", "/api/soc/incidents/1/follow-up"), ("get", "/api/soc/incidents/1/followups"),
              ("post", "/api/soc/incidents/1/report/merge-followups"), ("post", "/api/soc/incidents/1/report/post-to-ticket")]

    def call(self, m, p):
        return getattr(self.client, m)(p, **({"json": {}} if m == "post" else {}))

    def test_anonymous_is_refused(self):
        self.client.cookies.clear()
        for m, p in self.ROUTES:
            self.assertEqual(self.call(m, p).status_code, 401, p)

    def test_a_plain_user_is_refused(self):
        self.login("plain@t.local")
        for m, p in self.ROUTES:
            self.assertEqual(self.call(m, p).status_code, 403, p)

    def test_every_route_is_licensed_with_the_soc_module(self):
        for _, p in self.ROUTES + [("post", "/api/ingest/itsm-ticket")]:
            self.assertEqual(licensing.module_for_path(p), ("module", ["soc"]), p)

    def test_follow_up_is_not_taken_for_an_incident_action(self):
        iid = self.incident_id()
        r = self.client.post(f"/api/soc/incidents/{iid}/follow-up", json={"question": "history of bob"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("followup", r.json())


if __name__ == "__main__":
    unittest.main()
