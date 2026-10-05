"""
Tests for the SOC workflow items: automatic investigation on arrival, follow-up questions merged into the report, the look-back ceiling with its
justification, running all of a hunt's leads under a cap, hunts created from relevant threat-intelligence pushes, the identity map from access governance, and
alert-to-action timing.
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
from remediation.hunting import soc as hunt_soc, store as hunt_store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
T1190 = {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
FINDING = {"id": "FIND-1", "title": "Log4Shell", "cve": "CVE-2021-44228", "severity": "Critical", "asset": {"name": "WEB-1"}, "attack_techniques": [T1190], "kev": {"listed": True}, "epss": {"score": 0.9}}
ALERT = {"external_id": "w1", "title": "Shell spawned by web server", "severity": "High", "asset": "WEB-1", "technique": "T1190", "detail": "outbound to 185.220.101.9"}


class FakeSearch:
    def __init__(self, fail_on=None):
        self.calls, self.fail_on = [], fail_on

    def search(self, query, earliest="-24h", max_rows=25):
        self.calls.append((query, earliest))
        if self.fail_on and self.fail_on in query:
            raise RuntimeError("search timed out")
        return {"count": 2, "rows": [{"host": "WEB-1"}], "truncated": False}


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
        self.client = TestClient(fastapi_app)
        self.client.post("/api/auth/login", json={"email": "admin@t.local", "password": PW})
        self.key = self.client.post("/api/api-keys", json={"name": "siem", "scopes": ["soc:write"]}).json()["key"]
        self.h = {"Authorization": f"Bearer {self.key}"}

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def push(self, **kw):
        self.client.cookies.clear()
        r = self.client.post("/api/ingest/alerts", json={"alerts": [{**ALERT, **kw}]}, headers=self.h)
        self.client.post("/api/auth/login", json={"email": "admin@t.local", "password": PW})
        return r

    def alert_id(self):
        return self.client.get("/api/soc/alerts").json()["alerts"][0]["id"]


class AutoInvestigate(Base):
    def test_a_new_alert_is_investigated_and_gets_a_case(self):
        r = self.push()
        self.assertEqual((r.json()["created"], r.json()["investigated"]), (1, 1))
        aid = self.alert_id()
        inv = self.client.get(f"/api/soc/alerts/{aid}/investigation")
        self.assertEqual(inv.status_code, 200)
        self.assertEqual(inv.json()["investigation"]["report"]["headline"], ALERT["title"])
        cases = self.client.get("/api/soc/cases").json()["cases"]
        self.assertEqual((len(cases), cases[0]["source"], cases[0]["tier"]), (1, "auto", 1))
        self.assertEqual(hunt_store.get_alert(aid, self.engine)["status"], "investigating")

    def test_no_outside_calls_happen(self):
        with patch.object(dashboard_app_module.hunt_service, "connector", side_effect=AssertionError("must not look outside Quanta")):
            self.assertEqual(self.push().json()["investigated"], 1)

    def test_it_can_be_turned_off_and_respects_the_severity_floor(self):
        cfg = {**hunt_soc.config(), "auto_investigate": {"enabled": False}}
        with patch.object(hunt_soc, "config", return_value=cfg):
            self.assertEqual(self.push().json()["investigated"], 0)
        cfg = {**hunt_soc.config(), "auto_investigate": {"enabled": True, "min_severity": "High"}}
        with patch.object(hunt_soc, "config", return_value=cfg):
            self.assertEqual(self.push(external_id="w2", severity="Low").json()["investigated"], 0)
            self.assertEqual(self.push(external_id="w3", severity="High").json()["investigated"], 1)

    def test_a_repeat_is_not_investigated_twice_and_a_batch_is_capped(self):
        self.push()
        self.assertEqual(self.push().json()["investigated"], 0)
        cfg = {**hunt_soc.config(), "auto_investigate": {"enabled": True, "min_severity": "Low", "max_per_request": 2}}
        self.client.cookies.clear()
        with patch.object(hunt_soc, "config", return_value=cfg):
            r = self.client.post("/api/ingest/alerts", json={"alerts": [{**ALERT, "external_id": f"b{i}"} for i in range(5)]}, headers=self.h)
        self.assertEqual((r.json()["created"], r.json()["investigated"]), (5, 2))

    def test_timing_metrics_count_it(self):
        self.push()
        t = self.client.get("/api/soc/metrics?days=7").json()["timing"]
        self.assertEqual(t["alerts_received"], 1)
        self.assertEqual(t["investigated_automatically"], 1)
        self.assertEqual(t["investigated_automatically_share"], 1.0)
        self.assertIsNotNone(t["alert_to_investigation_minutes"])
        self.assertIsNotNone(t["alert_to_case_minutes"])


class FollowUps(Base):
    def test_a_follow_up_is_merged_into_the_stored_report(self):
        self.push()
        aid = self.alert_id()
        r = self.client.post(f"/api/soc/alerts/{aid}/follow-up", json={"kind": "entity-history", "value": "WEB-1"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn("WEB-1", r.json()["question"])
        stored = self.client.get(f"/api/soc/alerts/{aid}/investigation").json()
        self.assertEqual(len(stored["investigation"]["report"]["followups"]), 1)
        self.assertIn("## Follow-ups", stored["report_md"])
        self.client.post(f"/api/soc/alerts/{aid}/follow-up", json={"kind": "similar-alerts", "value": "WEB-1"})
        self.assertEqual(len(self.client.get(f"/api/soc/alerts/{aid}/investigation").json()["investigation"]["report"]["followups"]), 2)

    def test_errors(self):
        with patch.object(hunt_soc, "config", return_value={**hunt_soc.config(), "auto_investigate": {"enabled": False}}):
            self.push()
        aid = self.alert_id()
        self.assertEqual(self.client.post(f"/api/soc/alerts/{aid}/follow-up", json={"kind": "entity-history", "value": "x"}).status_code, 400)  # not investigated
        self.client.post(f"/api/soc/alerts/{aid}/investigate", json={})
        self.assertEqual(self.client.post(f"/api/soc/alerts/{aid}/follow-up", json={"kind": "bogus", "value": "x"}).status_code, 400)
        self.assertEqual(self.client.post(f"/api/soc/alerts/{aid}/follow-up", json={"kind": "entity-history", "value": " "}).status_code, 400)
        self.assertEqual(self.client.post(f"/api/soc/alerts/{aid}/follow-up", json={"kind": "entity-history", "value": "x", "siem": True}).status_code, 400)  # no connection
        self.assertEqual(self.client.post("/api/soc/alerts/999/follow-up", json={"kind": "entity-history", "value": "x"}).status_code, 404)

    def test_the_siem_search_previews_then_needs_confirm(self):
        self.push()
        aid = self.alert_id()
        fake = FakeSearch()
        with patch.object(dashboard_app_module.hunt_service, "connector", return_value=(fake, {"name": "splunk"})):
            pre = self.client.post(f"/api/soc/alerts/{aid}/follow-up", json={"kind": "indicator-sightings", "value": "185.220.101.9", "siem": True}).json()
            self.assertTrue(pre["preview_only"])
            self.assertEqual(fake.calls, [])
            done = self.client.post(f"/api/soc/alerts/{aid}/follow-up", json={"kind": "indicator-sightings", "value": "185.220.101.9", "siem": True, "confirm": True}).json()
        self.assertEqual(len(fake.calls), 1)
        self.assertIn("SIEM", done["answer"])


class LookBack(Base):
    def test_past_the_ceiling_needs_a_written_reason_and_has_a_hard_limit(self):
        self.push()
        aid = self.alert_id()
        url = f"/api/soc/alerts/{aid}/investigate"
        self.assertEqual(self.client.post(url, json={"lookback_days": 30}).status_code, 200)
        self.assertEqual(self.client.post(url, json={"lookback_days": 120}).status_code, 400)
        self.assertEqual(self.client.post(url, json={"lookback_days": 120, "justification": "too short"}).status_code, 400)
        self.assertEqual(self.client.post(url, json={"lookback_days": 400, "justification": "x" * 40}).status_code, 400)
        ok = self.client.post(url, json={"lookback_days": 120, "justification": "Suspected long-running intrusion; the first indicator is 4 months old"})
        self.assertEqual(ok.status_code, 200, ok.text)
        entries = self.client.get("/api/activity-log").json()["entries"]
        ext = [e for e in entries if e["action"] == "soc.lookback.extended"]
        self.assertEqual(len(ext), 1)
        self.assertEqual(ext[0]["details"]["days"], 120)
        self.assertIn("4 months", ext[0]["details"]["justification"])

    def test_the_ceiling_clips_the_siem_searches(self):
        self.push()
        aid = self.alert_id()
        fake = FakeSearch()
        with patch.object(dashboard_app_module.hunt_service, "connector", return_value=(fake, {"name": "splunk"})):
            self.client.post(f"/api/soc/alerts/{aid}/investigate", json={"siem": True, "confirm": True, "lookback_days": 3})
        self.assertTrue(fake.calls)
        for _q, earliest in fake.calls:
            self.assertLessEqual(int(earliest.strip("-d")), 3, earliest)


class RunAll(Base):
    def hunt(self, n=4):
        h = hunt_store.create_hunt({"title": "Hunt", "hypothesis": "h", "queries": [{"name": f"lead {i}", "technique": "T1190", "query": f"search index=web lead{i}"} for i in range(n)]}, "a", self.engine)
        return h["id"]

    def test_preview_then_run_all_records_each_lead(self):
        hid = self.hunt()
        fake = FakeSearch()
        with patch.object(dashboard_app_module.hunt_service, "connector", return_value=(fake, {"name": "splunk"})):
            pre = self.client.post(f"/api/hunting/hunts/{hid}/run-all", json={}).json()
            self.assertEqual((pre["preview_only"], len(pre["leads"])), (True, 4))
            self.assertEqual(fake.calls, [])
            done = self.client.post(f"/api/hunting/hunts/{hid}/run-all", json={"confirm": True}).json()
        self.assertEqual((done["ran"], done["failed"]), (4, 0))
        self.assertEqual(done["hunt"]["summary"]["run"], 4)
        self.assertEqual(done["hunt"]["summary"]["with_hits"], 4)
        with patch.object(dashboard_app_module.hunt_service, "connector", return_value=(FakeSearch(), {"name": "splunk"})):
            again = self.client.post(f"/api/hunting/hunts/{hid}/run-all", json={}).json()
        self.assertEqual(again["leads"], [])  # already run

    def test_the_cap_holds_leads_back(self):
        hid = self.hunt(5)
        cfg = {**hunt_soc.config(), "hunting": {"max_trial_hits_per_run": 2, "auto_create_hunt_at_or_above": "high"}}
        fake = FakeSearch()
        with patch.object(hunt_soc, "config", return_value=cfg), patch.object(dashboard_app_module.hunt_service, "connector", return_value=(fake, {"name": "splunk"})):
            done = self.client.post(f"/api/hunting/hunts/{hid}/run-all", json={"confirm": True}).json()
        self.assertEqual((done["ran"], done["not_run_because_of_the_cap"]), (2, 3))
        self.assertEqual(len(fake.calls), 2)

    def test_one_failing_lead_does_not_stop_the_rest(self):
        hid = self.hunt(3)
        fake = FakeSearch(fail_on="lead1")
        with patch.object(dashboard_app_module.hunt_service, "connector", return_value=(fake, {"name": "splunk"})):
            done = self.client.post(f"/api/hunting/hunts/{hid}/run-all", json={"confirm": True}).json()
        self.assertEqual((done["ran"], done["failed"]), (3, 1))
        self.assertIn("timed out", [r for r in done["results"] if r["error"]][0]["error"])

    def test_lookback_guard_and_missing_connection(self):
        hid = self.hunt(1)
        with patch.object(dashboard_app_module.hunt_service, "connector", return_value=(FakeSearch(), {"name": "splunk"})):
            self.assertEqual(self.client.post(f"/api/hunting/hunts/{hid}/run-all", json={"confirm": True, "earliest": "-180d"}).status_code, 400)
            ok = self.client.post(f"/api/hunting/hunts/{hid}/run-all", json={"confirm": True, "earliest": "-180d", "justification": "Covering the full dwell time of the reported campaign"})
            self.assertEqual(ok.status_code, 200, ok.text)
            self.assertEqual(self.client.post(f"/api/hunting/hunts/{hid}/run-all", json={"earliest": "yesterday"}).status_code, 400)
        self.assertEqual(self.client.post(f"/api/hunting/hunts/{hid}/run-all", json={}).status_code, 400)  # no connection configured
        self.assertEqual(self.client.post("/api/hunting/hunts/999/run-all", json={}).status_code, 404)
        h = self.client.get(f"/api/hunting/hunts/{hid}").json()
        self.assertIn("summary", h)


class IntelAutoHunt(Base):
    def post_intel(self, text, title):
        self.client.cookies.clear()
        key = self.key
        r = self.client.post("/api/ingest/threat-intel", json={"content": text, "title": title}, headers={"Authorization": f"Bearer {key}"})
        self.client.post("/api/auth/login", json={"email": "admin@t.local", "password": PW})
        return r.json()

    def test_a_relevant_report_creates_its_hunt(self):
        r = self.post_intel("Actors exploit CVE-2021-44228 (T1190) against web servers. C2 185.220.101.4", "Campaign A")
        self.assertEqual(r["priority"], "high")
        self.assertIsNotNone(r["hunt_id"])
        hunts = self.client.get("/api/hunting/hunts").json()["hunts"]
        self.assertEqual(len(hunts), 1)
        self.assertEqual(hunts[0]["status"], "proposed")  # created, not run
        again = self.post_intel("Actors exploit CVE-2021-44228 (T1190) against web servers. C2 185.220.101.4", "Campaign A")
        self.assertFalse(again["created"])
        self.assertEqual(len(self.client.get("/api/hunting/hunts").json()["hunts"]), 1)

    def test_a_report_that_matters_less_does_not(self):
        r = self.post_intel("A general advisory about CVE-2019-0001 with nothing in your estate", "Other")
        self.assertIn(r["priority"], ("low", "medium"))
        self.assertIsNone(r["hunt_id"])
        self.assertEqual(self.client.get("/api/hunting/hunts").json()["hunts"], [])

    def test_it_can_be_turned_off(self):
        cfg = {**hunt_soc.config(), "hunting": {"auto_create_hunt_at_or_above": "", "max_trial_hits_per_run": 30}}
        with patch.object(hunt_soc, "config", return_value=cfg):
            r = self.post_intel("Actors exploit CVE-2021-44228 (T1190) against web servers", "Campaign B")
        self.assertIsNone(r["hunt_id"])


class IdentityMap(Base):
    def test_a_privileged_account_is_named_in_the_report(self):
        rows = [{"user": "svc-web", "account": "svc-web", "system": "Active Directory", "privileged": True, "status": "active"},
                {"user": "bob", "account": "bob", "system": "Wiki", "privileged": False, "status": "active"},
                {"user": "old", "account": "old", "system": "Vault", "privileged": True, "status": "disabled"}]
        with patch.object(dashboard_app_module.iam_store, "entitlements", return_value=rows):
            m = dashboard_app_module._identity_map()
            self.assertTrue(m["svc-web"]["privileged"])
            self.assertFalse(m["bob"]["privileged"])
            self.assertNotIn("old", m)
            a, _ = hunt_store.receive_alert({**ALERT, "external_id": "i1", "entities": {"user": "svc-web"}}, self.engine)
            body = self.client.post(f"/api/soc/alerts/{a['id']}/investigate", json={}).json()
        users = [e for e in body["investigation"]["report"]["entities"] if e["kind"] == "user"]
        self.assertIn("privileged access on Active Directory", users[0]["detail"])

    def test_with_no_records_it_says_so(self):
        with patch.object(dashboard_app_module.iam_store, "entitlements", return_value=[]):
            self.assertIsNone(dashboard_app_module._identity_map())
            a, _ = hunt_store.receive_alert({**ALERT, "external_id": "i2", "entities": {"user": "svc-web"}}, self.engine)
            body = self.client.post(f"/api/soc/alerts/{a['id']}/investigate", json={}).json()
        users = [e for e in body["investigation"]["report"]["entities"] if e["kind"] == "user"]
        self.assertIn("access records not loaded", users[0]["detail"])


if __name__ == "__main__":
    unittest.main()
