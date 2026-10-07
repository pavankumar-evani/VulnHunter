"""
Running a hunt's trial hits (POST /api/hunting/hunts/{id}/run-all, the single-lead run, the dry-run plan) against a fake search connection in each language.
The query written for the connection's language, the exact text, the language and the connection name are recorded on each lead and reach the hunt report's
trial-hit table; a lead the language cannot express is recorded as not expressible and nothing is sent; the confirm gate, the cap and the look-back ceiling hold.
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
from remediation.hunting import generate, intel, service as hunt_service, store as hunt_store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
T1190 = {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
T1059 = {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution"}
FINDING = {"id": "FIND-1", "title": "Log4Shell", "cve": "CVE-2021-44228", "severity": "Critical", "asset": {"name": "WEB-1"}, "attack_techniques": [T1190, T1059],
           "kev": {"listed": True}, "epss": {"score": 0.9}}
TYPE_OF = {"splunk-spl": "splunk-search", "kql": "sentinel-search", "eql": "elastic-search", "esql": "elastic-search", "udm": "chronicle-search", "fql": "falcon-search"}


class FakeConn:
    def __init__(self, language, count=2, boom_on=None):
        self.language, self.count, self.boom_on, self.calls = language, count, boom_on, []

    def search(self, query, earliest="-24h", latest="now", max_rows=25, deadline=90):
        self.calls.append((query, earliest))
        if self.boom_on and self.boom_on in query:
            raise RuntimeError("search timed out")
        return {"rows": [{"host": "WEB-1"}], "count": self.count, "truncated": False, "took_ms": 12, "query_language": self.language}


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
        self.hunt = hunt_store.create_hunt(generate.propose([FINDING])[0], "a", self.engine)

    def login(self, email):
        self.client.cookies.clear()
        self.client.post("/api/auth/login", json={"email": email, "password": PW})

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def use(self, conn, name="Corp SIEM"):
        public = {"id": 7, "name": name, "type": TYPE_OF[conn.language], "enabled": True, "config": {"language": conn.language}}
        return [patch.object(hunt_service, "search_connector", return_value=(conn, {"name": name})), patch.object(hunt_service, "find_search_connection", return_value=public)]

    def with_conn(self, conn, fn):
        ps = self.use(conn)
        for x in ps:
            x.start()
        try:
            return fn()
        finally:
            for x in reversed(ps):
                x.stop()

    def run_all(self, **kw):
        return self.client.post(f"/api/hunting/hunts/{self.hunt['id']}/run-all", json={"earliest": "-7d", **kw})


class RunAllPerLanguage(Base):
    def test_each_language_gets_its_own_query_text_recorded_with_language_and_connection(self):
        for lang in ("splunk-spl", "kql", "eql", "esql", "udm"):
            with self.subTest(lang=lang):
                hunt_store.update_hunt(self.hunt["id"], {"queries": [dict(q, result=None) for q in hunt_store.get_hunt(self.hunt["id"], self.engine)["queries"]]}, self.engine)
                conn = FakeConn(lang)
                r = self.with_conn(conn, lambda: self.run_all(confirm=True, only_unrun=False))
                self.assertEqual(r.status_code, 200, r.text)
                body = r.json()
                self.assertGreater(body["ran"], 0)
                sent = {q for q, _ in conn.calls}
                self.assertTrue(sent)
                first = next(x for x in body["results"] if x["state"] in ("hits", "no-hits"))
                self.assertEqual(first["language"], lang)
                self.assertIn(first["query"], sent)
                if lang == "splunk-spl":
                    self.assertTrue(all(q.startswith("search ") for q in sent))
                else:
                    self.assertFalse(any(q.startswith("search ") for q in sent), lang)
                stored = hunt_store.get_hunt(self.hunt["id"], self.engine)["queries"][0]
                self.assertEqual((stored["language_run"], stored["connection"], stored["query_run"] in sent), (lang, "Corp SIEM", True))
        self.assertIn("host", " ".join(q for q, _ in conn.calls).lower())

    def test_a_lead_the_language_cannot_express_is_recorded_not_sent(self):
        conn = FakeConn("fql")
        r = self.with_conn(conn, lambda: self.run_all(confirm=True, only_unrun=False))
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(conn.calls, [])
        self.assertTrue(all(x["state"] == "not-expressible" and x["reason"] for x in body["results"]))
        stored = hunt_store.get_hunt(self.hunt["id"], self.engine)["queries"]
        self.assertTrue(all(q["result"] == "not-expressible" and q["query_run"] is None and q["not_expressible_reason"] for q in stored))

    def test_preview_never_contacts_the_connection_and_lists_the_rendered_queries(self):
        conn = FakeConn("kql")
        r = self.with_conn(conn, lambda: self.run_all())
        body = r.json()
        self.assertTrue(body["preview_only"])
        self.assertEqual((conn.calls, body["language"]), ([], "kql"))
        self.assertTrue(all(p["query"].startswith("union *") for p in body["plan"] if p["state"] == "would-run"))
        self.assertEqual(hunt_store.get_hunt(self.hunt["id"], self.engine)["queries"][0].get("result"), None)

    def test_an_error_on_one_lead_is_recorded_and_the_rest_still_run(self):
        conn = FakeConn("splunk-spl", boom_on="jndi")
        r = self.with_conn(conn, lambda: self.run_all(confirm=True))
        body = r.json()
        self.assertEqual(body["failed"], 1)
        bad = next(x for x in body["results"] if x["state"] == "error")
        self.assertIn("timed out", bad["error"])
        self.assertTrue(any(x["state"] in ("hits", "no-hits") for x in body["results"]))
        rep = self.client.get(f"/api/hunting/hunts/{self.hunt['id']}/report").json()
        by_state = {t["state"] for t in rep["trial_hits"]}
        self.assertIn("error", by_state)
        self.assertTrue(by_state & {"needs-investigation", "no-hit"})

    def test_the_hunt_report_trial_hit_table_is_filled_from_the_real_results(self):
        conn = FakeConn("esql", count=3)
        self.with_conn(conn, lambda: self.run_all(confirm=True))
        rep = self.client.get(f"/api/hunting/hunts/{self.hunt['id']}/report").json()
        ran = [t for t in rep["trial_hits"] if t["status"] != "not-run"]
        self.assertTrue(ran)
        t = ran[0]
        self.assertEqual((t["status"], t["state"], t["hits"], t["language"], t["connection"]), ("needs-investigation", "needs-investigation", 3, "esql", "Corp SIEM"))
        self.assertTrue(t["query_run"].startswith("FROM logs-*"))
        self.assertIn(t["query_run"], conn.calls[0][0] + " " + " ".join(q for q, _ in conn.calls))
        md = self.client.get(f"/api/hunting/hunts/{self.hunt['id']}/report?format=md").text
        self.assertIn("Queries run (exact text, language and connection)", md)
        self.assertIn("esql; Corp SIEM", md)

    def test_no_hit_state(self):
        self.with_conn(FakeConn("kql", count=0), lambda: self.run_all(confirm=True))
        rep = self.client.get(f"/api/hunting/hunts/{self.hunt['id']}/report").json()
        self.assertIn("no-hit", {t["state"] for t in rep["trial_hits"]})

    def test_lookback_ceiling_and_justification_still_apply(self):
        conn = FakeConn("kql")
        r = self.with_conn(conn, lambda: self.client.post(f"/api/hunting/hunts/{self.hunt['id']}/run-all", json={"earliest": "-180d", "confirm": True}))
        self.assertEqual(r.status_code, 400)
        self.assertEqual(conn.calls, [])
        r = self.with_conn(conn, lambda: self.client.post(f"/api/hunting/hunts/{self.hunt['id']}/run-all", json={"earliest": "-180d", "confirm": True,
                                                                                                           "justification": "Responding to a board-level disclosure; need six months."}))
        self.assertEqual(r.status_code, 200, r.text)

    def test_the_cap_limits_leads_per_call(self):
        with patch.object(dashboard_app_module.hunt_soc, "config", return_value={"hunting": {"max_trial_hits_per_run": 1}, "max_lookback_days": 90, "extended_lookback_days": 365}):
            conn = FakeConn("kql")
            body = self.with_conn(conn, lambda: self.run_all(confirm=True)).json()
        self.assertEqual((body["ran"], len(conn.calls)), (1, 1))
        self.assertGreaterEqual(body["not_run_because_of_the_cap"], 1)

    def test_only_an_administrator_may_run_or_plan(self):
        self.login("plain@t.local")
        self.assertIn(self.run_all(confirm=True).status_code, (401, 403))
        self.assertIn(self.client.get(f"/api/hunting/hunts/{self.hunt['id']}/run-plan").status_code, (401, 403))


class DryRunPlan(Base):
    def test_the_plan_names_connection_language_window_and_contacts_nothing(self):
        conn = FakeConn("udm")
        r = self.with_conn(conn, lambda: self.client.get(f"/api/hunting/hunts/{self.hunt['id']}/run-plan?earliest=-30d"))
        self.assertEqual(r.status_code, 200, r.text)
        b = r.json()
        self.assertEqual((b["language"], b["window"], b["contacts_siem"], b["connection"]["name"]), ("udm", "-30d", False, "Corp SIEM"))
        self.assertEqual(conn.calls, [])
        self.assertTrue(any(x["state"] == "would-run" and "principal.hostname" in x["query"] for x in b["leads"]) or any(x["state"] == "not-expressible" for x in b["leads"]))
        self.assertEqual(b["would_run"], sum(1 for x in b["leads"] if x["state"] == "would-run"))

    def test_the_plan_flags_a_window_past_the_ceiling(self):
        b = self.with_conn(FakeConn("kql"), lambda: self.client.get(f"/api/hunting/hunts/{self.hunt['id']}/run-plan?earliest=-180d")).json()
        self.assertTrue(b["needs_justification"])

    def test_without_a_connection_the_plan_says_nothing_could_run(self):
        with patch.object(hunt_service, "find_search_connection", return_value=None):
            b = self.client.get(f"/api/hunting/hunts/{self.hunt['id']}/run-plan").json()
        self.assertIsNone(b["connection"])
        self.assertIn("No read-only search connection", b["message"])

    def test_bad_input(self):
        self.assertEqual(self.client.get(f"/api/hunting/hunts/{self.hunt['id']}/run-plan?earliest=yesterday").status_code, 400)
        self.assertEqual(self.client.get("/api/hunting/hunts/9999/run-plan").status_code, 404)


class SingleLeadAndSelection(Base):
    def test_a_single_lead_preview_and_run_use_the_language(self):
        conn = FakeConn("kql")
        pre = self.with_conn(conn, lambda: self.client.post(f"/api/hunting/hunts/{self.hunt['id']}/queries/0/run", json={"earliest": "-7d"})).json()
        self.assertEqual((pre["preview_only"], pre["language"]), (True, "kql"))
        self.assertTrue(pre["query"].startswith("union *"))
        done = self.with_conn(conn, lambda: self.client.post(f"/api/hunting/hunts/{self.hunt['id']}/queries/0/run", json={"earliest": "-7d", "confirm": True}))
        self.assertEqual(done.status_code, 200, done.text)
        self.assertEqual(done.json()["query"]["language_run"], "kql")

    def test_search_connector_picks_by_id_or_by_order(self):
        with patch.object(hunt_service, "connector", side_effect=lambda t, cid=None, engine=None: (f"conn-{t}", {"name": t}) if t == "elastic-search" else (None, None)), \
                patch.object(hunt_service, "find_connection", side_effect=lambda t, cid=None, engine=None: ({"type": t}, {}) if t == "elastic-search" else (None, None)):
            self.assertEqual(hunt_service.search_connector(engine=self.engine)[0], "conn-elastic-search")
        with patch.object(hunt_service.conn_store, "get_values", return_value=({"type": "reputation"}, {})):
            with self.assertRaises(ValueError):
                hunt_service.search_connector(5, self.engine)

    def test_new_hunt_queries_carry_the_selection_so_any_language_can_be_rendered(self):
        qs = hunt_store.get_hunt(self.hunt["id"], self.engine)["queries"]
        self.assertTrue(all(q.get("selection") and q.get("hosts") == ["WEB-1"] for q in qs))
        ioc = intel.propose_hunt(intel.extract("CVE-2021-44228 beacon to 8.8.4.4 and evil.example.com"), (50, "medium", ["x"], {}), ["WEB-1"])["queries"][-1]
        self.assertEqual(ioc["technique"], "IOC")
        self.assertIn("DestinationIp", ioc["selection"])


if __name__ == "__main__":
    unittest.main()
