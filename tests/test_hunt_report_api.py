"""
API tests for the hunt report: the JSON report and its Markdown and HTML exports, the allow-list routes and their effect on the report, the time-box and metrics routes,
validation, RBAC and licensing.
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
from remediation.hunting import generate, store as hunt_store  # noqa: E402
from remediation.licensing import license as licensing  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
KEV = {"id": "FIND-1", "title": "Log4Shell", "cve": "CVE-2021-44228", "severity": "Critical", "asset": {"name": "WEB-1"}, "kev": {"listed": True}, "epss": {"score": 0.9}, "status": "open",
       "attack_techniques": [{"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"}]}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
                  patch.object(dashboard_app_module.dashboard_data, "load_live_queue", return_value=[KEV])]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("plain@t.local", PW, "Plain", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)
        self.login("admin@t.local")
        prop = generate.propose([KEV])[0]
        self.hunt = hunt_store.create_hunt(prop, "a@t.local", self.engine)
        self.hid = self.hunt["id"]

    def login(self, email):
        self.client.cookies.clear()
        self.client.post("/api/auth/login", json={"email": email, "password": PW})

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def record(self, index=0, **fields):
        h = hunt_store.get_hunt(self.hid, self.engine)
        h["queries"][index].update(fields)
        hunt_store.update_hunt(self.hid, {"queries": h["queries"]}, self.engine)

    def report(self):
        return self.client.get(f"/api/hunting/hunts/{self.hid}/report").json()


class ReportRoutes(Base):
    def test_json_is_the_default_and_every_trial_hit_is_listed(self):
        r = self.client.get(f"/api/hunting/hunts/{self.hid}/report")
        self.assertEqual(r.status_code, 200, r.text)
        j = r.json()
        self.assertEqual((j["hunt_id"], j["verdict"]["label"], j["counts"]["trial_hits"]), (self.hid, "not-run", len(self.hunt["queries"])))
        self.assertTrue(all(t["status"] == "not-run" for t in j["trial_hits"]))
        self.assertTrue(all(t["queries"]["spl"] for t in j["trial_hits"]))
        self.assertEqual(j["timing"]["state"], "open")
        self.assertEqual(self.client.get("/api/hunting/hunts/9999/report").status_code, 404)

    def test_markdown_and_html_exports_by_query_and_by_suffix(self):
        md = self.client.get(f"/api/hunting/hunts/{self.hid}/report?format=md")
        self.assertIn("text/markdown", md.headers["content-type"])
        self.assertIn("# Hunt report:", md.text)
        self.assertEqual(self.client.get(f"/api/hunting/hunts/{self.hid}/report.md").text, md.text)
        html = self.client.get(f"/api/hunting/hunts/{self.hid}/report.html")
        self.assertIn("text/html", html.headers["content-type"])
        self.assertIn("attachment", html.headers["content-disposition"])
        self.assertIn("@media print", html.text)
        self.assertEqual(self.client.get(f"/api/hunting/hunts/{self.hid}/report?format=html").text, html.text)
        self.assertEqual(self.client.get(f"/api/hunting/hunts/{self.hid}/report?format=pdf").status_code, 400)

    def test_results_recorded_on_a_lead_change_the_report(self):
        self.record(0, result="hits", count=3, sample=[{"host": "WEB-1"}, {"host": "WEB-1"}, {"host": "WEB-2"}], ran_at="2026-10-06T10:00:00Z", window="-30d")
        j = self.report()
        self.assertEqual((j["trial_hits"][0]["status"], j["verdict"]["label"], j["look_back"]["days_max"]), ("needs-investigation", "needs-investigation", 30))
        self.record(0, assessment="malicious")
        self.assertEqual(self.report()["verdict"]["label"], "confirmed")

    def test_a_hunt_started_from_a_threat_intel_report_has_a_report_with_its_gist(self):
        text = "Advisory: actor APT41 is exploiting CVE-2021-44228 (T1190, T1059.001). C2 at 45.33.32.4 and http://bad.example.net/x, sha256 " + "b" * 64
        rep = self.client.post("/api/hunting/intel", json={"content": text}).json()
        h = self.client.post(f"/api/hunting/intel/{rep['id']}/hunt")
        self.assertEqual(h.status_code, 200, h.text)
        j = self.client.get(f"/api/hunting/hunts/{h.json()['id']}/report").json()
        self.assertEqual((j["source"], j["verdict"]["label"]), ("intel", "not-run"))
        self.assertTrue(j["gist"])
        self.assertGreaterEqual(j["counts"]["trial_hits"], 1)

    def test_the_old_markdown_link_still_works_with_the_format_parameter(self):
        self.assertEqual(self.client.get(f"/api/hunting/hunts/{self.hid}/report?format=md").status_code, 200)


class AllowListRoutes(Base):
    def setUp(self):
        super().setUp()
        self.record(0, result="hits", count=4, sample=[{"host": "SCAN-1"}, {"host": "SCAN-1"}, {"host": "WEB-2"}, {"host": "WEB-3"}], ran_at="2026-10-06T10:00:00Z", window="-7d")

    def add(self, **kw):
        body = {"lead_index": 0, "field": "host", "value": "SCAN-1", "note": "Nightly vulnerability scanner"}
        return self.client.post(f"/api/hunting/hunts/{self.hid}/allowlist", json={**body, **kw})

    def test_an_entry_changes_the_report_and_is_shown_with_its_reason(self):
        before = self.report()["trial_hits"][0]
        self.assertEqual((before["hits"], before["hits_after_allowlist"]), (4, 4))
        r = self.add()
        self.assertEqual(r.status_code, 200, r.text)
        after = r.json()["report"]["trial_hits"][0]
        self.assertEqual((after["hits"], after["allowlisted_rows"], after["hits_after_allowlist"]), (4, 2, 2))
        j = self.report()
        self.assertEqual((j["allowlist"]["rows_set_aside"], j["allowlist"]["entries"][0]["note"], j["allowlist"]["entries"][0]["created_by"]), (2, "Nightly vulnerability scanner", "admin@t.local"))
        self.assertIn("Nightly vulnerability scanner", self.client.get(f"/api/hunting/hunts/{self.hid}/report.md").text)

    def test_it_applies_to_a_later_hunt_with_the_same_lead(self):
        self.add()
        second = hunt_store.create_hunt({**generate.propose([{**KEV, "cve": "CVE-2022-0001", "id": "FIND-2", "asset": {"name": "WEB-5"}}])[0]}, "a", self.engine)
        h = hunt_store.get_hunt(second["id"], self.engine)
        h["queries"][0].update({"result": "hits", "count": 3, "sample": [{"host": "SCAN-1"}, {"host": "WEB-9"}, {"host": "WEB-9"}], "ran_at": "2026-10-06T11:00:00Z", "window": "-7d"})
        hunt_store.update_hunt(second["id"], {"queries": h["queries"]}, self.engine)
        x = self.client.get(f"/api/hunting/hunts/{second['id']}/report").json()["trial_hits"][0]
        self.assertEqual((x["allowlisted_rows"], x["hits_after_allowlist"]), (1, 2))

    def test_validation(self):
        self.assertEqual(self.add(note="short").status_code, 400)
        self.assertEqual(self.add(field="notafield").status_code, 400)
        self.assertEqual(self.add(value="   ").status_code, 400)
        self.assertEqual(self.add(lead_index=99).status_code, 404)
        self.assertEqual(self.client.post("/api/hunting/hunts/9999/allowlist", json={"lead_index": 0, "field": "host", "value": "x", "note": "long enough note"}).status_code, 404)
        self.assertEqual(self.add().status_code, 200)
        self.assertEqual(self.add().status_code, 400)                    # the same entry twice

    def test_list_and_remove(self):
        eid = self.add().json()["entry"]["id"]
        self.assertEqual(len(self.client.get(f"/api/hunting/hunts/{self.hid}/allowlist").json()["entries"]), 1)
        self.assertIn("host", self.client.get(f"/api/hunting/hunts/{self.hid}/allowlist").json()["fields"])
        self.assertEqual(self.client.delete(f"/api/hunting/hunts/{self.hid}/allowlist/{eid}").status_code, 200)
        self.assertEqual(self.report()["trial_hits"][0]["hits_after_allowlist"], 4)
        self.assertEqual(self.client.delete(f"/api/hunting/hunts/{self.hid}/allowlist/{eid}").status_code, 404)


class TimeBoxRoutes(Base):
    def test_set_the_time_box_and_read_the_metrics(self):
        self.assertEqual(self.report()["timing"]["time_box_hours"], 8)
        r = self.client.post(f"/api/hunting/hunts/{self.hid}/time-box", json={"hours": 24})
        self.assertEqual((r.status_code, r.json()["report"]["timing"]["time_box_hours"], r.json()["report"]["timing"]["time_box_source"]), (200, 24, "hunt"))
        self.assertEqual(self.client.post(f"/api/hunting/hunts/{self.hid}/time-box", json={"hours": 0}).status_code, 400)
        self.assertEqual(self.client.post(f"/api/hunting/hunts/{self.hid}/time-box", json={"hours": 5000}).status_code, 400)
        self.assertEqual(self.client.post("/api/hunting/hunts/9999/time-box", json={"hours": 5}).status_code, 404)
        m = self.client.get("/api/hunting/report-metrics").json()
        self.assertEqual((m["hunts"], m["reports_ready"], m["median_hours"]), (1, 0, None))
        self.assertEqual(len(m["per_hunt"]), 1)

    def test_a_hunt_with_every_lead_run_has_a_time_to_report(self):
        h = hunt_store.get_hunt(self.hid, self.engine)
        for q in h["queries"]:
            q.update({"result": "no-hits", "count": 0, "sample": [], "ran_at": "2999-01-01T00:00:00Z", "window": "-7d"})
        hunt_store.update_hunt(self.hid, {"queries": h["queries"]}, self.engine)
        j = self.report()
        self.assertEqual((j["verdict"]["label"], j["counts"]["not_run"]), ("no-ioc-match", 0))
        self.assertIsNotNone(j["timing"]["time_to_report_hours"])
        self.assertEqual(self.client.get("/api/hunting/report-metrics").json()["reports_ready"], 1)


class Access(Base):
    def routes(self):
        h = self.hid
        return [("get", f"/api/hunting/hunts/{h}/report"), ("get", f"/api/hunting/hunts/{h}/report.md"), ("get", f"/api/hunting/hunts/{h}/report.html"), ("get", f"/api/hunting/hunts/{h}/allowlist"),
                ("post", f"/api/hunting/hunts/{h}/allowlist"), ("delete", f"/api/hunting/hunts/{h}/allowlist/1"), ("post", f"/api/hunting/hunts/{h}/time-box"), ("get", "/api/hunting/report-metrics")]

    def call(self, m, p):
        return getattr(self.client, m)(p, **({"json": {}} if m == "post" else {}))

    def test_anonymous_and_plain_users_are_refused(self):
        self.client.cookies.clear()
        for m, p in self.routes():
            self.assertEqual(self.call(m, p).status_code, 401, p)
        self.login("plain@t.local")
        for m, p in self.routes():
            self.assertEqual(self.call(m, p).status_code, 403, p)

    def test_licensed_with_the_soc_module(self):
        for _, p in self.routes():
            self.assertEqual(licensing.module_for_path(p), ("module", ["soc"]), p)


if __name__ == "__main__":
    unittest.main()
