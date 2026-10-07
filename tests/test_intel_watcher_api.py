"""
API tests for the report watcher: Report sources add/test/poll/disable/remove (admin only, SSRF refusal, poll is confirm-gated), the report's "why this triggered"
and arrival times in the intel listing, the leader tick wiring and its off switch, and the licence prefix covering the new routes.
"""
import os
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
from remediation.connectors import url_safety  # noqa: E402
from remediation.connectors.report_feed_connector import ReportFeedConnector as RealFeedReader  # noqa: E402
from remediation.hunting import hunt_report, intelwatch, service as hunt_service, store as hunt_store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
T1190 = {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
FINDING = {"id": "FIND-1", "title": "Log4Shell", "cve": "CVE-2021-44228", "severity": "Critical", "asset": {"name": "WEB-1"}, "attack_techniques": [T1190], "kev": {"listed": True}, "epss": {"score": 0.9}}
RELEVANT = "Actors exploit CVE-2021-44228 (T1190) against public web servers and beacon to 8.8.4.4."


class FakeFeed:
    calls = 0

    def __init__(self, url, **kw):
        self.url = url

    def fetch(self, etag=None, last_modified=None):
        FakeFeed.calls += 1
        return {"status": "ok", "format": "rss", "items": [{"external_id": "p1", "title": "Log4Shell surge", "url": "https://b/p1", "published_at": "2026-10-06T00:00:00Z", "content": RELEVANT}],
                "etag": None, "last_modified": None}

    def test_connection(self):
        return {"format": "rss", "items": 1, "newest": "Log4Shell surge"}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        real = url_safety.assert_safe_target
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
                  patch.object(dashboard_app_module.dashboard_data, "load_live_queue", return_value=[FINDING]),
                  patch.object(url_safety, "assert_safe_target", side_effect=lambda t: real(t) if any(x in t for x in ("127.0.0.1", "169.254")) else None),
                  patch.object(dashboard_app_module.report_feed_connector, "ReportFeedConnector", FakeFeed)]
        for x in self.p:
            x.start()
        FakeFeed.calls = 0
        auth_users.create_user("admin@t.local", PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("plain@t.local", PW, "Plain", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)
        self.login("admin@t.local")

    def login(self, email):
        self.client.cookies.clear()
        self.client.post("/api/auth/login", json={"email": email, "password": PW})

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def add(self, name="Vendor", url="https://blog.example.com/feed"):
        return self.client.post("/api/hunting/intel/sources", json={"name": name, "kind": "feed", "url": url})


class Sources(Base):
    def test_add_list_disable_remove(self):
        self.assertEqual(self.client.get("/api/hunting/intel/sources").json()["sources"], [])
        r = self.add()
        self.assertEqual(r.status_code, 200, r.text)
        sid = r.json()["id"]
        listing = self.client.get("/api/hunting/intel/sources").json()
        self.assertEqual((len(listing["sources"]), listing["interval_minutes"], listing["watch_enabled"]), (1, 60, True))
        self.assertIn("never runs a search", listing["note"])
        self.assertEqual(self.add().status_code, 400)                                           # a name is unique
        off = self.client.post(f"/api/hunting/intel/sources/{sid}/enabled", json={"enabled": False}).json()
        self.assertFalse(off["enabled"])
        self.assertEqual(self.client.delete(f"/api/hunting/intel/sources/{sid}").json(), {"deleted": True})
        self.assertEqual(self.client.delete(f"/api/hunting/intel/sources/{sid}").status_code, 404)

    def test_validation(self):
        self.assertEqual(self.client.post("/api/hunting/intel/sources", json={"name": "", "kind": "feed", "url": "https://x.example.com/f"}).status_code, 400)
        self.assertEqual(self.client.post("/api/hunting/intel/sources", json={"name": "x", "kind": "carrier-pigeon"}).status_code, 400)
        self.assertEqual(self.client.post("/api/hunting/intel/sources", json={"name": "t", "kind": "taxii", "collection_id": "c"}).status_code, 400)

    def test_only_administrators(self):
        self.login("plain@t.local")
        self.assertIn(self.client.get("/api/hunting/intel/sources").status_code, (401, 403))
        self.assertIn(self.add().status_code, (401, 403))

    def test_test_reads_the_source_and_stores_nothing(self):
        sid = self.add().json()["id"]
        r = self.client.post(f"/api/hunting/intel/sources/{sid}/test")
        self.assertEqual((r.status_code, r.json()["items"]), (200, 1))
        self.assertEqual(hunt_service.list_intel(self.engine), [])


class SsrfAndScheme(Base):
    def test_the_real_feed_reader_refuses_loopback_metadata_and_http(self):
        with patch.object(dashboard_app_module.report_feed_connector, "ReportFeedConnector", RealFeedReader):
            for bad in ("https://127.0.0.1/feed", "https://169.254.169.254/latest", "http://blog.example.com/feed", "gopher://x/"):
                r = self.add(name=f"bad {bad}", url=bad)
                self.assertEqual(r.status_code, 400, bad)
        self.assertEqual(self.client.get("/api/hunting/intel/sources").json()["sources"], [])


class Poll(Base):
    def test_poll_is_confirm_gated_then_stores_the_report_and_creates_the_hunt(self):
        sid = self.add().json()["id"]
        pre = self.client.post(f"/api/hunting/intel/sources/{sid}/poll", json={}).json()
        self.assertTrue(pre["preview_only"])
        self.assertIn("runs no search on your SIEM", pre["message"])
        self.assertEqual((FakeFeed.calls, hunt_service.list_intel(self.engine)), (0, []))
        r = self.client.post(f"/api/hunting/intel/sources/{sid}/poll", json={"confirm": True}).json()
        self.assertEqual((r["status"], r["new"], r["hunts_created"]), ("ok", 1, 1))
        reports = self.client.get("/api/hunting/intel").json()["reports"]
        self.assertEqual(len(reports), 1)
        rep = reports[0]
        self.assertEqual((rep["published_at"], rep["source_id"], rep["url"], rep["why_triggered"]["decision"]), ("2026-10-06T00:00:00Z", sid, "https://b/p1", "created"))
        self.assertTrue(rep["fetched_at"])
        hunt = hunt_store.get_hunt(rep["hunt_id"], self.engine)
        self.assertEqual((hunt["status"], hunt["source"]), ("proposed", "intel"))
        again = self.client.post(f"/api/hunting/intel/sources/{sid}/poll", json={"confirm": True}).json()
        self.assertEqual((again["new"], again["seen"]), (0, 1))
        src = self.client.get("/api/hunting/intel/sources").json()["sources"][0]
        self.assertEqual((src["last_status"], src["total_reports"]), ("ok", 1))

    def test_the_hunt_report_clock_starts_at_the_reports_publication(self):
        sid = self.add().json()["id"]
        self.client.post(f"/api/hunting/intel/sources/{sid}/poll", json={"confirm": True})
        hid = self.client.get("/api/hunting/intel").json()["reports"][0]["hunt_id"]
        rep = self.client.get(f"/api/hunting/hunts/{hid}/report").json()
        self.assertEqual((rep["timing"]["clock_start_source"], rep["timing"]["clock_started_at"]), ("report-published", "2026-10-06T00:00:00Z"))
        self.assertEqual(self.client.get("/api/hunting/hunts/metrics").status_code in (200, 404, 422), True)


class Tick(Base):
    def test_the_leader_tick_polls_due_sources_and_honours_the_switch(self):
        self.add()
        deps = intelwatch.Deps(findings=lambda: [FINDING], make_hunt=lambda rec, actor: dashboard_app_module._hunt_from_intel(rec, actor), hunt_floor=lambda: "high",
                               build_feed=lambda s: FakeFeed(s["url"]), engine=self.engine)
        with patch.object(dashboard_app_module, "_intel_watch_deps", return_value=deps):
            with patch.dict(os.environ, {"QUANTA_INTEL_WATCH": "false"}):
                self.assertIn("off", dashboard_app_module._run_intel_watch_if_due()["skipped"])
            self.assertEqual(FakeFeed.calls, 0)
            out = dashboard_app_module._run_intel_watch_if_due()
        self.assertEqual((len(out["polled"]), out["polled"][0]["new"]), (1, 1))

    def test_a_broken_tick_never_raises(self):
        with patch.object(dashboard_app_module, "_intel_watch_deps", side_effect=RuntimeError("x")):
            self.assertIsNone(dashboard_app_module._run_intel_watch_if_due())

    def test_the_tick_is_wired_into_the_scheduler_loop(self):
        src = (REPO_ROOT / "dashboard" / "app.py").read_text(encoding="utf-8")
        self.assertIn("_run_intel_watch_if_due()", src.split("async def _notification_scheduler_loop")[1].split("DEMO_ACCOUNTS")[0])


class Licensing(unittest.TestCase):
    def test_new_routes_are_under_a_licensed_prefix(self):
        import yaml
        cfg = yaml.safe_load((REPO_ROOT / "remediation" / "config" / "licensing.yaml").read_text(encoding="utf-8"))
        text = yaml.safe_dump(cfg)
        self.assertIn("/api/hunting", text)


if __name__ == "__main__":
    unittest.main()
