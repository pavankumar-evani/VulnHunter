"""
Tests for the capability catalog and its status.
"""
import re
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
from remediation import capabilities  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

PW = "test-password-123"
JS = REPO_ROOT / "dashboard" / "static" / "js"


def routes():
    src = (JS / "app.js").read_text(encoding="utf-8")
    return [re.compile(m.replace("\\/", "/")) for m in re.findall(r"pattern: /(.+?)/,", src)]


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.cat = capabilities.catalog()
        self.items = [i for d in self.cat for g in d["groups"] for i in g["items"]]

    def test_five_areas_numbered_one_to_five(self):
        self.assertEqual([d["number"] for d in self.cat], ["1", "2", "3", "4", "5"])
        self.assertTrue(all(g["number"].startswith(d["number"] + ".") for d in self.cat for g in d["groups"]))
        self.assertEqual([g["number"] for g in self.cat[0]["groups"]], ["1.1", "1.2"])  # vulnerability management, then the DevSecOps library
        self.assertEqual([g["number"] for g in self.cat[2]["groups"]], ["3.1", "3.2"])  # detection and hunting, then AI security

    def test_ids_are_unique_and_every_item_is_described(self):
        ids = [i["id"] for i in self.items]
        self.assertEqual(len(ids), len(set(ids)))
        for i in self.items:
            self.assertTrue(i["title"] and i["summary"] and i["path"].startswith("/"), i["id"])
            self.assertIsInstance(i["needs"], list)

    def test_every_path_opens_a_real_page(self):
        pats = routes()
        for i in self.items:
            base = i["path"].split("?")[0]
            self.assertTrue(any(p.match(base) for p in pats), f"{i['id']} points at {base}, which has no route")

    def test_every_new_page_is_in_the_catalog(self):
        paths = {i["path"].split("?")[0] for i in self.items}
        for page in ("/devsecops", "/cyber-risk", "/hunting", "/soar", "/ai-security", "/firewall", "/access-governance", "/zero-day-watch", "/grc", "/threat-models", "/ai-usage", "/controls"):
            self.assertIn(page, paths)

    def test_the_page_module_each_route_loads_exists(self):
        src = (JS / "app.js").read_text(encoding="utf-8")
        for mod in re.findall(r'import\("\./pages/([A-Za-z0-9_-]+)\.js"\)', src):
            self.assertTrue((JS / "pages" / f"{mod}.js").exists(), mod)


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")

    def flat(self, areas):
        return {i["id"]: i for a in areas for g in a["groups"] for i in g["items"]}

    def test_an_empty_install_is_ready_not_broken(self):
        areas = capabilities.build([], True, self.e)
        items = self.flat(areas)
        self.assertTrue(all(i["state"] == "ready" and i["metric"] is None for i in items.values()))
        self.assertEqual(sum(a["in_use"] for a in areas), 0)
        self.assertTrue(items["firewall"]["needs"])

    def test_what_is_held_is_counted(self):
        db_module.ensure_schema(self.e)
        with self.e.begin() as c:
            for i in range(3):
                c.execute(insert(db_module.fw_rules), {"device": "fw1" if i < 2 else "fw2", "key": f"r{i}", "position": i, "data_json": "{}", "first_seen": "2026-01-01", "fingerprint": "x", "imported_at": "2026-01-01"})
            c.execute(insert(db_module.soc_alerts), {"source": "s", "external_id": "1", "title": "t", "severity": "High", "status": "new", "received_at": "2026-10-01"})
            c.execute(insert(db_module.soc_alerts), {"source": "s", "external_id": "2", "title": "t", "severity": "High", "status": "closed", "received_at": "2026-10-01"})
        findings = [{"kev": {"listed": True}, "attack_techniques": [{"technique_id": "T1190"}]}, {"kev": None}]
        items = self.flat(capabilities.build(findings, True, self.e))
        self.assertEqual(items["firewall"]["metric"], "3 rules from 2 firewalls")
        self.assertEqual(items["triage"]["metric"], "1 open alert")
        self.assertEqual(items["queue"]["metric"], "2 findings, 1 known-exploited")
        self.assertEqual(items["attack-paths"]["state"], "active")
        self.assertEqual(items["iam"]["state"], "ready")

    def test_administrator_pages_are_hidden_from_everyone_else(self):
        admin = self.flat(capabilities.build([], True, self.e))
        user = self.flat(capabilities.build([], False, self.e))
        self.assertIn("soar", admin)
        self.assertNotIn("soar", user)
        self.assertIn("queue", user)
        self.assertIn("firewall", user)  # requests are open to everyone, so the page is
        areas = capabilities.build([], False, self.e)
        self.assertTrue(all(a["capabilities"] == sum(len(g["items"]) for g in a["groups"]) for a in areas))


class CapabilitiesApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)),
                  patch.object(dashboard_app_module.dashboard_data, "load_live_queue", return_value=[])]
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

    def test_login_is_required_and_admin_pages_depend_on_the_role(self):
        self.assertEqual(self.client.get("/api/capabilities").status_code, 401)
        self.login("user@t.local")
        user_ids = {i["id"] for a in self.client.get("/api/capabilities").json()["areas"] for g in a["groups"] for i in g["items"]}
        self.login("admin@t.local")
        r = self.client.get("/api/capabilities")
        self.assertEqual(r.status_code, 200)
        admin_ids = {i["id"] for a in r.json()["areas"] for g in a["groups"] for i in g["items"]}
        self.assertTrue(user_ids < admin_ids)
        self.assertEqual(len(r.json()["areas"]), 5)


if __name__ == "__main__":
    unittest.main()
