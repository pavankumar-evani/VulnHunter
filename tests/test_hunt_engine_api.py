"""Hunt engine API: auth, shapes, the accept -> hunt -> conclude -> promote flow, licensing."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
sys.path.insert(0, str(REPO_ROOT / "cli"))
sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app as dashboard_app_module  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402
from tests.test_hunt_engine_core import fnd, T1059  # noqa: E402

PW = "test-password-123"


class HuntEngineApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.fake = [fnd(1, host="WEB-1"), fnd(2, host="WEB-2", cve="CVE-2", tech=(T1059,))]
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
                  patch.object(dashboard_app_module.dashboard_data, "load_live_queue", return_value=self.fake)]
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

    def test_auth(self):
        self.assertEqual(self.client.get("/api/hunting/suggestions").status_code, 401)
        self.login("user@t.local")
        self.assertEqual(self.client.get("/api/hunting/suggestions").status_code, 200)   # login is enough to read
        for method, path in (("post", "/api/hunting/suggestions/refresh"), ("post", "/api/hunting/suggestions/hyp-x/accept"), ("post", "/api/hunting/suggestions/hyp-x/dismiss"),
                             ("post", "/api/hunting/suggestions/hyp-x/conclude"), ("post", "/api/hunting/suggestions/hyp-x/promote")):
            self.assertEqual(getattr(self.client, method)(path, json={}).status_code, 403, path)

    def test_full_flow_and_stable_shape(self):
        self.login("admin@t.local")
        r = self.client.post("/api/hunting/suggestions/refresh").json()
        self.assertGreaterEqual(r["new"], 2)
        out = self.client.get("/api/hunting/suggestions").json()
        self.assertEqual(set(out), {"suggestions", "total", "shown", "cap", "capped", "suppressed_hidden", "gaps", "last_refresh", "note"})
        s = next(x for x in out["suggestions"] if x["generator"] == "kev-exposure")
        for k in ("id", "title", "hypothesis", "why_now", "hunt_type", "tactics", "techniques", "scope", "data_sources", "data_readiness", "queries", "expected_malicious", "likely_benign",
                  "scoping", "effort", "expected_value", "priority", "next_step", "soar_playbook", "status", "learned", "gaps"):
            self.assertIn(k, s)
        self.assertEqual(set(s["priority"]), {"score", "breakdown"})
        self.assertEqual(set(s["scope"]["counts"]), {"assets", "identities", "segments"})
        self.assertEqual(set(s["queries"][0]) & {"language", "query", "kql", "sigma", "description"}, {"language", "query", "kql", "sigma", "description"})
        self.assertEqual(len(self.client.get("/api/hunting/suggestions?type=hypothesis-driven").json()["suggestions"]), len([x for x in out["suggestions"] if x["hunt_type"] == "hypothesis-driven"]))
        self.assertEqual(self.client.get("/api/hunting/suggestions?tactic=Initial%20Access").status_code, 200)
        hid = s["id"]
        d = self.client.get(f"/api/hunting/suggestions/{hid}").json()
        self.assertEqual([e["kind"] for e in d["events"]], ["suggested"])
        self.assertEqual(self.client.get("/api/hunting/suggestions/hyp-none").status_code, 404)
        a = self.client.post(f"/api/hunting/suggestions/{hid}/accept", json={}).json()
        self.assertEqual(a["status"], "accepted")
        hunt = self.client.get(f"/api/hunting/hunts/{a['hunt_id']}").json()   # the existing hunt flow keeps working
        self.assertEqual(hunt["status"], "proposed")
        self.assertIn("verdict", hunt)
        self.assertEqual(self.client.post(f"/api/hunting/suggestions/{hid}/accept", json={}).status_code, 409)
        self.assertEqual(self.client.post(f"/api/hunting/suggestions/{hid}/conclude", json={"outcome": "benign", "notes": ""}).status_code, 400)
        c = self.client.post(f"/api/hunting/suggestions/{hid}/conclude", json={"outcome": "true-positive", "notes": "confirmed"}).json()
        self.assertEqual(c["outcome"], "true-positive")
        p = self.client.post(f"/api/hunting/suggestions/{hid}/promote").json()
        self.assertEqual(p["status"], "promoted")
        self.assertEqual(self.client.get("/api/hunting/suggestions?status=promoted").json()["total"], 1)

    def test_dismiss_requires_a_valid_reason(self):
        self.login("admin@t.local")
        self.client.post("/api/hunting/suggestions/refresh")
        hid = self.client.get("/api/hunting/suggestions").json()["suggestions"][0]["id"]
        self.assertEqual(self.client.post(f"/api/hunting/suggestions/{hid}/dismiss", json={"reason": "meh"}).status_code, 400)
        r = self.client.post(f"/api/hunting/suggestions/{hid}/dismiss", json={"reason": "already-covered", "notes": "rule exists"})
        self.assertEqual(r.json()["status"], "dismissed")
        self.assertNotIn(hid, [x["id"] for x in self.client.get("/api/hunting/suggestions").json()["suggestions"]])

    def test_licensing_covers_the_prefix_and_existing_routes_still_work(self):
        cfg = yaml.safe_load((REPO_ROOT / "remediation" / "config" / "licensing.yaml").read_text(encoding="utf-8"))
        self.assertIn("/api/hunting", str(cfg))
        self.login("admin@t.local")
        self.assertEqual(self.client.get("/api/hunting/proposals").status_code, 200)
        self.assertEqual(self.client.get("/api/hunting/hunts").status_code, 200)


if __name__ == "__main__":
    unittest.main()
