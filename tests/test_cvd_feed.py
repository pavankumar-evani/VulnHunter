"""
Tests for the Anthropic CVD feed: the tolerant parser, the connector (hand-rolled fake session, https only), the store (dedupe, refresh updates),
estate matching (CVE exact, name not a version check) and the routes (auth, confirm gate). No real network.
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
from remediation.connectors import cvd_feed_connector as cvd, url_safety  # noqa: E402
from remediation.cvd import store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PAYLOAD = {"entries": [
    {"id": "abc1", "cve": ["CVE-2026-1111", "GHSA-xxxx-yyyy-zzzz"], "project": "libfoo", "vendor": "Foo Org", "severity": {"claude": "high", "external": "critical"},
     "disclosed_at": "2026-09-30T10:00:00Z", "status": "Disclosed", "bug_class": "Buffer overflow"},
    {"id": "abc2", "project": "Redis", "severity": 7.5, "date": "2026-09-01"},
    {"id": "abc3", "commitment": "deadbeef"},  # only a commitment so far
    {"id": "abc1", "project": "dup"},  # duplicate id in one payload
    "junk", 5,
]}


class Resp:
    def __init__(self, data=None, status=200):
        self.data, self.status_code = data, status

    def json(self):
        if self.data is None:
            raise ValueError("no json")
        return self.data


class FakeSession:
    def __init__(self, resp):
        self.resp, self.calls = resp, []

    def get(self, url, **kw):
        self.calls.append(url)
        return self.resp


class ParseTests(unittest.TestCase):
    def test_good_payload(self):
        recs = cvd.parse(PAYLOAD)
        self.assertEqual([r["id"] for r in recs], ["abc1", "abc2", "abc3"])
        a = recs[0]
        self.assertEqual((a["cves"], a["product"], a["vendor"], a["severity"], a["published"], a["state"]), (["CVE-2026-1111"], "libfoo", "Foo Org", "Critical", "2026-09-30", "disclosed"))
        self.assertEqual(recs[1]["severity"], "High")

    def test_tolerates_missing_fields_and_shapes(self):
        c = cvd.parse(PAYLOAD)[2]
        self.assertEqual((c["cves"], c["product"], c["severity"], c["published"], c["state"], c["url"]), ([], "", "", "", "committed", cvd.PAGE_URL))
        self.assertEqual(cvd.parse(PAYLOAD["entries"])[0]["id"], "abc1")
        self.assertEqual(cvd.parse({"x": {"project": "p"}})[0]["id"], "x")
        self.assertEqual(cvd.parse({"unknown": 1}), [])
        self.assertEqual(cvd.parse(None), [])
        self.assertTrue(cvd.parse([{"cve": "CVE-2026-2222"}])[0]["id"].startswith("anon-"))
        self.assertEqual(cvd.parse([{"title": "no id, cve or project"}]), [])


class ConnectorTests(unittest.TestCase):
    def test_refuses_non_https(self):
        with self.assertRaises(url_safety.UnsafeTargetError):
            cvd.CvdFeedConnector(url="http://red.anthropic.com/2026/cvd/payload.json")

    def test_fetch_and_test_connection(self):
        s = FakeSession(Resp(PAYLOAD))
        c = cvd.CvdFeedConnector(session=s)
        self.assertTrue(c.test_connection())
        self.assertEqual(len(c.fetch()), 3)
        self.assertEqual(s.calls[0], cvd.DEFAULT_URL)

    def test_errors(self):
        with self.assertRaises(cvd.CvdFeedError):
            cvd.CvdFeedConnector(session=FakeSession(Resp({}, 500))).fetch()
        with self.assertRaises(cvd.CvdFeedError):
            cvd.CvdFeedConnector(session=FakeSession(Resp(None))).fetch()


class StoreMatchTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")

    def test_dedupe_and_refresh_updates(self):
        recs = cvd.parse(PAYLOAD)
        self.assertEqual(store.upsert(recs, self.e), {"fetched": 3, "new": 3, "updated": 0})
        self.assertEqual(store.upsert(recs, self.e), {"fetched": 3, "new": 0, "updated": 0})
        recs[2].update(product="newproj", cves=["CVE-2026-3333"], state="disclosed")
        self.assertEqual(store.upsert(recs, self.e), {"fetched": 3, "new": 0, "updated": 1})
        rows = {r["id"]: r for r in store.list_advisories(self.e)}
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows["abc3"]["cves"], ["CVE-2026-3333"])

    def test_matching(self):
        store.upsert(cvd.parse(PAYLOAD), self.e)
        findings = [{"id": "F-1", "cve": "cve-2026-1111", "title": "Something else", "asset": {"name": "h1", "os": "Linux"}},
                    {"id": "F-2", "cve": None, "title": "Redis unauthenticated access", "asset": {"name": "h2", "os": "Linux"}}]
        s = store.summary(store.list_advisories(self.e), findings)
        by = {m["id"]: m for m in s["matches"]}
        self.assertEqual(by["abc1"]["match_basis"], ["cve"])  # vendor/project words absent from the estate, but the CVE is exact
        self.assertEqual(by["abc1"]["finding_ids"], ["F-1"])
        self.assertEqual(by["abc2"]["match_basis"], ["name"])
        self.assertNotIn("abc3", by)  # a bare commitment never matches
        self.assertEqual(s["matches"][0]["id"], "abc1")  # CVE matches first
        self.assertIn("not a version check", s["note"])


class RouteTests(unittest.TestCase):
    PW = "Passw0rd!Test1"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.fake = FakeSession(Resp(PAYLOAD))
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "cvd_connector_factory", lambda: cvd.CvdFeedConnector(session=self.fake)),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60))]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", self.PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", self.PW, "User", role="user", engine=self.engine)
        self.client = TestClient(fastapi_app)

    def tearDown(self):
        self.client.close()
        for x in reversed(self.p):
            x.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def login(self, email):
        self.client.cookies.clear()
        self.client.post("/api/auth/login", json={"email": email, "password": self.PW})

    def test_unauthenticated_and_non_admin_refused(self):
        self.assertEqual(self.client.post("/api/cvd/fetch", json={"confirm": True}).status_code, 401)
        self.assertEqual(self.client.post("/api/cvd/test-connection").status_code, 401)
        self.login("user@t.local")
        self.assertEqual(self.client.post("/api/cvd/fetch", json={"confirm": True}).status_code, 403)
        self.assertEqual(self.client.post("/api/cvd/test-connection").status_code, 403)
        self.assertEqual(self.fake.calls, [])

    def test_confirm_gate_then_fetch_then_list(self):
        self.login("admin@t.local")
        r = self.client.post("/api/cvd/fetch", json={}).json()
        self.assertTrue(r["preview_only"])
        self.assertEqual(self.fake.calls, [])
        r = self.client.post("/api/cvd/fetch", json={"confirm": True}).json()
        self.assertEqual((r["new"], r["fetched"]), (3, 3))
        self.assertTrue(self.client.post("/api/cvd/test-connection").json()["ok"])
        out = self.client.get("/api/cvd/advisories").json()
        self.assertEqual(out["total"], 3)
        self.assertIn("note", out)

    def test_upstream_failure_is_502(self):
        self.fake.resp = Resp({}, 503)
        self.login("admin@t.local")
        self.assertEqual(self.client.post("/api/cvd/fetch", json={"confirm": True}).status_code, 502)


if __name__ == "__main__":
    unittest.main()
