"""
Tests for Dark Web Watch: the source catalog, the feed and credential-exposure connectors (against hand-rolled fakes), term matching, hits and alerts,
imports, the scheduler tick and the API. A password must never survive the connector.
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
from remediation.connectors import darkweb_connector as dwc  # noqa: E402
from remediation.darkweb import watch  # noqa: E402
from remediation.hunting import store as hunt_store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

CFG = {"domains": ["acme.example"], "brands": ["Acme Corp", "Zed"], "vendors": ["Globex"], "keywords": [],
       "settings": {"auto_alert": True, "ransomware_severity": "High", "credential_severity": "High", "credential_min_records": 1, "mention_severity": "Medium", "poll_minutes": 60, "lookup_hours": 24}}

LISTED = ["Ahmia", "OnionSearch", "Katana", "Darkdump", "Darkus", "IACA Dark Web Tools", "Onion Search Engine", "Tor66", "TorNode", "Darkweblink", "OnionScan", "Onioff",
          "Docker Onion Nmap", "TorBot", "TorCrawl.py", "VigilantOnion", "OnionIngestor", "Prying Deep", "Darc", "Midnight Sea", "DeepDarkCTI", "Robin", "Recon", "SOCRadar Dark Web",
          "Flare", "BreachForums monitor", "Ransomwatch", "DarkFeed", "IntelligenceX", "DeHashed", "LeakCheck", "Snusbase", "Tor Project", "torsocks", "Nyx", "Tor Browser"]


class Resp:
    def __init__(self, data, status=200):
        self.data, self.status_code = data, status

    def json(self):
        if self.data is None:
            raise ValueError("no json")
        return self.data


class FakeSession:
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        return self.responses.pop(0)


class Catalog(unittest.TestCase):
    def test_every_listed_source_is_in_the_catalog_with_a_mode_and_instructions(self):
        names = {s["name"].lower(): s for s in watch.catalog()}
        for n in LISTED:
            self.assertTrue(any(k.startswith(n.lower()) or n.lower() in k for k in names), n)
        for s in watch.catalog():
            self.assertIn(s["mode"], ("feed", "lookup", "import", "guide"))
            self.assertTrue(s["how"] and s["url"], s["id"])
        self.assertEqual(len({s["id"] for s in watch.catalog()}), len(watch.catalog()))

    def test_active_modes_have_real_connectors(self):
        for s in watch.catalog():
            if s["mode"] == "feed":
                self.assertIn(s["id"], dwc.FEEDS)
            if s["mode"] == "lookup":
                self.assertIn(s["id"], dwc.LOOKUPS)

    def test_lookups_are_connection_types(self):
        from remediation.connections import registry
        for k in dwc.LOOKUPS:
            self.assertEqual(registry.SPECS[k]["kind"], "tool")


class Connectors(unittest.TestCase):
    def test_ransomware_live_parses_victims(self):
        s = FakeSession(Resp([{"victim": "Acme Corp", "group": "lockgroup", "discovered": "2026-10-01", "website": "acme.example", "post_url": "http://x"}, "junk"]))
        v = dwc.RansomwareLive(s).fetch()
        self.assertEqual((v[0]["victim"], v[0]["group"], v[0]["website"]), ("Acme Corp", "lockgroup", "acme.example"))
        self.assertEqual(len(v), 1)

    def test_ransomwatch_posts(self):
        v = dwc.Ransomwatch(FakeSession(Resp([{"post_title": "Globex Ltd", "group_name": "g", "discovered": "2026-10-02"}]))).fetch()
        self.assertEqual(v[0]["victim"], "Globex Ltd")

    def test_dehashed_drops_passwords_and_masks(self):
        entries = [{"email": "alice@acme.example", "password": "hunter2", "hashed_password": "abc", "database_name": "BigBreach"}]
        s = FakeSession(Resp({"entries": entries, "total": 41}))
        r = dwc.DeHashed("k", s).lookup_domain("acme.example")
        self.assertEqual((r["total"], r["records"][0]["identifier"], r["records"][0]["source"]), (41, "a***@acme.example", "BigBreach"))
        self.assertNotIn("hunter2", repr(r))
        self.assertNotIn("abc", repr(r))
        self.assertEqual(s.calls[0][2]["headers"], {"Dehashed-Api-Key": "k"})
        self.assertEqual(s.calls[0][2]["json"]["query"], "domain:acme.example")

    def test_leakcheck_snusbase_intelx(self):
        r = dwc.LeakCheck("k", FakeSession(Resp({"success": True, "found": 2, "result": [{"email": "b@acme.example", "password": "pw", "source": {"name": "X", "breach_date": "2024-01"}}]}))).lookup_domain("acme.example")
        self.assertEqual((r["total"], r["records"][0]["source"], r["records"][0]["date"]), (2, "X", "2024-01"))
        self.assertNotIn("pw", repr(r))
        r = dwc.Snusbase("k", FakeSession(Resp({"size": 3, "results": {"DbA": [{"email": "c@acme.example", "password": "pw2"}]}}))).lookup_domain("acme.example")
        self.assertEqual((r["total"], r["records"][0]["source"]), (3, "DbA"))
        self.assertNotIn("pw2", repr(r))
        s = FakeSession(Resp({"id": "abc", "status": 0}), Resp({"records": [{"name": "dump.txt", "date": "2025-02-02", "bucket": "leaks.public"}], "status": 0}))
        r = dwc.IntelX("k", session=s).lookup_domain("acme.example")
        self.assertEqual((r["total"], r["records"][0]["source"]), (1, "leaks.public"))
        self.assertEqual(s.calls[0][2]["headers"], {"x-key": "k"})

    def test_errors_are_plain(self):
        for code, text in ((401, "rejected"), (429, "rate limiting"), (500, "HTTP 500")):
            with self.assertRaises(dwc.DarkWebError) as cm:
                dwc.DeHashed("k", FakeSession(Resp({}, code))).lookup_domain("a.example")
            self.assertIn(text, str(cm.exception))
        with self.assertRaises(dwc.DarkWebError):
            dwc.DeHashed("k", FakeSession(Resp(None))).lookup_domain("a.example")

    def test_mask(self):
        self.assertEqual(dwc.mask_identifier("Alice@x.org"), "A***@x.org")
        self.assertEqual(dwc.mask_identifier("bob"), "b***")
        self.assertEqual(dwc.mask_identifier(None), "")


class Matching(unittest.TestCase):
    def m(self, text, site=""):
        return watch.match_text(text, site, CFG)

    def test_domain_brand_vendor(self):
        self.assertIn(("domain", "acme.example"), self.m("Some Company", "https://www.acme.example/home"))
        self.assertIn(("brand", "Acme Corp"), self.m("The Acme Corp group"))
        self.assertIn(("vendor", "Globex"), self.m("globex industries"))
        self.assertEqual(self.m("Acmeless Incorporated"), [])

    def test_short_terms_must_be_the_whole_name(self):
        self.assertEqual(self.m("Zed"), [("brand", "Zed")])
        self.assertEqual(self.m("Zedtech Holdings"), [])

    def test_domain_does_not_match_inside_a_longer_host(self):
        self.assertEqual(self.m("see notacme.example.org"), [])
        self.assertTrue(self.m("login at acme.example today"))


class HitsAndAlerts(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")
        p = patch.object(watch, "config", return_value=CFG)
        p.start()
        self.addCleanup(p.stop)

    def victims(self):
        return [{"feed": "ransomware-live", "victim": "Acme Corp", "group": "lockgroup", "discovered": "2026-10-01", "website": "acme.example", "country": "", "post_url": ""},
                {"feed": "ransomware-live", "victim": "Globex Industries", "group": "g2", "discovered": "2026-10-02", "website": "", "country": "", "post_url": ""},
                {"feed": "ransomware-live", "victim": "Unrelated Ltd", "group": "g3", "discovered": "2026-10-02", "website": "", "country": "", "post_url": ""}]

    class Feed:
        def __init__(self, v):
            self.v = v

        def fetch(self):
            return self.v

    def test_feed_run_creates_hits_alerts_and_is_idempotent(self):
        r = watch.run_feed("ransomware-live", self.Feed(self.victims()), self.e)
        self.assertEqual((r["fetched"], r["new"], r["alerts"]), (3, 2, 2))
        hits = {h["term"]: h for h in watch.list_hits(self.e)}
        self.assertEqual(hits["acme.example"]["severity"], "High")
        self.assertEqual(hits["Globex"]["severity"], "Medium")
        self.assertEqual(hits["Globex"]["kind"], "supply-chain-post")
        alert = hunt_store.get_alert(hits["acme.example"]["alert_id"], self.e)
        self.assertEqual((alert["source"], alert["technique"], alert["severity"]), ("darkweb", "T1486", "High"))
        again = watch.run_feed("ransomware-live", self.Feed(self.victims()), self.e)
        self.assertEqual((again["new"], again["known"]), (0, 2))
        self.assertEqual(len(hunt_store.list_alerts(self.e)), 2)

    def test_no_terms_means_no_matching(self):
        with patch.object(watch, "config", return_value={**CFG, "domains": [], "brands": [], "vendors": [], "keywords": []}):
            r = watch.run_feed("ransomware-live", self.Feed(self.victims()), self.e)
        self.assertEqual(r["new"], 0)
        self.assertIn("No watch terms", r["note"])

    def test_credential_lookup_hit_and_growth(self):
        class L:
            def __init__(self, n):
                self.n = n

            def lookup_domain(self, d):
                return {"source": "dehashed", "total": self.n, "records": [{"identifier": "a***@acme.example", "source": "BigBreach", "date": "2024-05"}], "note": ""}
        r = watch.run_lookup("dehashed", L(5), self.e)
        self.assertEqual((r["new"], r["alerts"]), (1, 1))
        h = watch.list_hits(self.e)[0]
        self.assertEqual((h["kind"], h["severity"]), ("credential-exposure", "High"))
        self.assertIn("BigBreach", h["detail"])
        self.assertIn("no password is kept", h["detail"])
        self.assertEqual(watch.run_lookup("dehashed", L(5), self.e)["new"], 0)
        self.assertEqual(watch.run_lookup("dehashed", L(9), self.e)["new"], 1)  # more records is news
        self.assertEqual(watch.run_lookup("dehashed", L(0), self.e)["new"], 0)

    def test_import_keeps_matching_lines_only(self):
        text = "http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion/post Acme Corp database for sale\nunrelated line\n\nanother unrelated\nGlobex VPN access listed"
        r = watch.run_import("torbot", text, self.e)
        self.assertEqual(r["new"], 2)
        self.assertEqual(r["onion_addresses"], 1)
        details = " ".join(h["detail"] for h in watch.list_hits(self.e))
        self.assertIn("onion:", details)
        self.assertNotIn("unrelated", details)
        self.assertEqual(watch.run_import("torbot", text, self.e)["new"], 0)
        with self.assertRaises(KeyError):
            watch.run_import("nope", "x", self.e)

    def test_status_needs_a_note_to_decide(self):
        watch.run_feed("ransomware-live", self.Feed(self.victims()), self.e)
        hid = watch.list_hits(self.e)[0]["id"]
        with self.assertRaises(ValueError):
            watch.set_hit_status(hid, "dismissed", "", self.e)
        self.assertEqual(watch.set_hit_status(hid, "dismissed", "Different company", self.e)["status"], "dismissed")
        with self.assertRaises(KeyError):
            watch.set_hit_status(999, "reviewing", "", self.e)

    def test_sources_state_defaults_and_toggle(self):
        s = {x["id"]: x for x in watch.sources(self.e)}
        self.assertTrue(s["ransomwatch"]["enabled"])
        self.assertFalse(s["dehashed"]["enabled"])  # no connection
        self.assertTrue({x["id"]: x for x in watch.sources(self.e, connected={"dehashed"})}["dehashed"]["connected"])
        watch.set_enabled("ransomwatch", False, self.e)
        self.assertFalse({x["id"]: x for x in watch.sources(self.e)}["ransomwatch"]["enabled"])
        with self.assertRaises(KeyError):
            watch.set_enabled("nope", True, self.e)


class DarkwebApi(unittest.TestCase):
    PW = "test-password-123"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.wp = Path(self.tmp.name) / "watch.yaml"
        self.wp.write_text("domains: []\nbrands: []\nvendors: []\nkeywords: []\nsettings: {}\n", encoding="utf-8")
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine), patch.object(watch, "WATCH_PATH", self.wp),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60))]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", self.PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", self.PW, "User", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)
        self.login("admin@t.local")

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email):
        self.client.cookies.clear()
        self.client.post("/api/auth/login", json={"email": email, "password": self.PW})

    def test_admin_only(self):
        self.login("user@t.local")
        self.assertEqual(self.client.get("/api/darkweb/overview").status_code, 403)
        self.assertEqual(self.client.put("/api/darkweb/watch-terms", json={}).status_code, 403)
        self.assertEqual(self.client.post("/api/darkweb/import", json={"source": "torbot", "text": "x"}).status_code, 403)

    def test_terms_import_and_hits_flow(self):
        self.assertFalse(self.client.get("/api/darkweb/overview").json()["has_terms"])
        self.assertEqual(self.client.post("/api/darkweb/import", json={"source": "torbot", "text": "Acme Corp leak"}).status_code, 400)
        r = self.client.put("/api/darkweb/watch-terms", json={"domains": ["ACME.example", " ", "acme.example"], "brands": ["Acme Corp"], "settings": {"auto_alert": False, "bogus": 1}})
        self.assertEqual(r.json()["terms"]["domains"], ["acme.example"])
        self.assertFalse(r.json()["settings"]["auto_alert"])
        self.assertNotIn("bogus", r.json()["settings"])
        imp = self.client.post("/api/darkweb/import", json={"source": "torbot", "text": "Acme Corp leak"}).json()
        self.assertEqual((imp["new"], imp["alerts"]), (1, 0))
        ov = self.client.get("/api/darkweb/overview").json()
        self.assertEqual(ov["hit_counts"], {"new": 1})
        hid = ov["hits"][0]["id"]
        self.assertEqual(self.client.post(f"/api/darkweb/hits/{hid}/status", json={"status": "dismissed"}).status_code, 400)
        self.assertEqual(self.client.post(f"/api/darkweb/hits/{hid}/status", json={"status": "dismissed", "note": "not us"}).json()["status"], "dismissed")

    def test_lookup_previews_before_sending_and_feed_runs(self):
        self.client.put("/api/darkweb/watch-terms", json={"domains": ["acme.example"]})
        pre = self.client.post("/api/darkweb/sources/dehashed/run", json={}).json()
        self.assertTrue(pre["preview_only"])
        self.assertEqual(pre["domains_that_would_be_sent"], ["acme.example"])
        self.assertEqual(self.client.post("/api/darkweb/sources/dehashed/run", json={"confirm": True}).status_code, 400)  # no connection
        with patch.object(dwc.RansomwareLive, "fetch", return_value=[{"feed": "ransomware-live", "victim": "acme.example Ltd", "group": "g", "discovered": "d", "website": "acme.example", "country": "", "post_url": ""}]):
            r = self.client.post("/api/darkweb/sources/ransomware-live/run", json={}).json()
        self.assertEqual((r["fetched"], r["new"]), (1, 1))
        self.assertEqual(self.client.post("/api/darkweb/sources/torbot/run", json={}).status_code, 400)

    def test_ingest_needs_the_scope(self):
        self.client.put("/api/darkweb/watch-terms", json={"brands": ["Acme Corp"]})
        k = self.client.post("/api/api-keys", json={"name": "crawler", "scopes": ["darkweb:write"]}).json()["key"]
        other = self.client.post("/api/api-keys", json={"name": "ci", "scopes": ["ingest:write"]}).json()["key"]
        self.client.cookies.clear()
        body = {"source": "onionsearch", "text": "Acme Corp mentioned here"}
        self.assertEqual(self.client.post("/api/ingest/darkweb", json=body).status_code, 401)
        self.assertIn(self.client.post("/api/ingest/darkweb", json=body, headers={"Authorization": f"Bearer {other}"}).status_code, (401, 403))
        ok = self.client.post("/api/ingest/darkweb", json=body, headers={"Authorization": f"Bearer {k}"})
        self.assertEqual(ok.json()["new"], 1)
        self.assertEqual(self.client.post("/api/ingest/darkweb", json={"source": "nope", "text": "x"}, headers={"Authorization": f"Bearer {k}"}).status_code, 404)

    def test_scheduler_tick_runs_due_feeds_and_skips_recent(self):
        self.client.put("/api/darkweb/watch-terms", json={"brands": ["Acme Corp"]})
        calls = []

        def fetch(self_):
            calls.append(self_.name)
            return []
        with patch.object(dwc.RansomwareLive, "fetch", fetch), patch.object(dwc.Ransomwatch, "fetch", fetch):
            dashboard_app_module._run_darkweb_if_due()
            first = len(calls)
            dashboard_app_module._run_darkweb_if_due()
        self.assertEqual(first, 2)
        self.assertEqual(len(calls), 2)  # the second tick found both recent


if __name__ == "__main__":
    unittest.main()
