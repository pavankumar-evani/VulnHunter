"""API, key-scope, publish, graph and catalog tests for external attack surface management."""
import json
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
from sqlalchemy import create_engine  # noqa: E402

import app as dashboard_app_module  # noqa: E402
import rate_limit  # noqa: E402
from app import app as fastapi_app  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.apikeys import store as apikeys  # noqa: E402
from remediation.asm import store  # noqa: E402
from remediation.graphs import infra  # noqa: E402
from remediation.ingest import merge as findings_merge  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402
from tests.test_asm_core import DNSX, HTTPX, NAABU, NUCLEI, SEEDS, SUBFINDER, at  # noqa: E402


class AsmApi(unittest.TestCase):
    PW = "test-password-123"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        self.qpath = Path(self.tmp.name) / "findings.json"
        self.qpath.write_text("[]", encoding="utf-8")
        self.p = [patch.object(db_module, "get_engine", return_value=self.engine), patch.object(findings_merge, "DEFAULT_PATH", self.qpath),
                  patch.object(dashboard_app_module, "_GLOBAL_API_RATE_LIMITER", rate_limit.RateLimiter(10**9, 60)), patch.object(dashboard_app_module, "_enrich_in_background", lambda b: None)]
        for x in self.p:
            x.start()
        auth_users.create_user("admin@t.local", self.PW, "Admin", role="admin", engine=self.engine)
        auth_users.create_user("user@t.local", self.PW, "User", role="user", engine=self.engine)
        _, self.key = apikeys.create("scanner", ["asm:write"], "admin@t.local", engine=self.engine)
        _, self.other = apikeys.create("ingest-only", ["ingest:write"], "admin@t.local", engine=self.engine)
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

    def auth(self, key=None):
        return {"Authorization": f"Bearer {key or self.key}"}

    def ingest(self, tool, text, key=None, **params):
        self.client.cookies.clear()
        return self.client.post("/api/ingest/asm", params={"tool": tool, **params}, content=text.encode(), headers=self.auth(key))

    # ---- auth
    def test_the_read_and_admin_routes_need_an_administrator(self):
        paths = ["/api/asm/summary", "/api/asm/assets", "/api/asm/changes", "/api/asm/scope", "/api/asm/findings", "/api/asm/how-to-feed"]
        self.login("user@t.local")
        for p in paths:
            self.assertEqual(self.client.get(p).status_code, 403, p)
        self.assertEqual(self.client.put("/api/asm/scope", json={"domains": ["a.example.com"]}).status_code, 403)
        self.assertEqual(self.client.post("/api/asm/import", params={"tool": "subfinder"}, content=b"{}").status_code, 403)
        self.assertEqual(self.client.post("/api/asm/publish", json={"confirm": True}).status_code, 403)
        self.client.cookies.clear()
        for p in paths:
            self.assertIn(self.client.get(p).status_code, (401, 403), p)

    def test_ingest_needs_a_key_with_the_asm_scope(self):
        body = SUBFINDER
        self.client.cookies.clear()
        self.assertEqual(self.client.post("/api/ingest/asm", params={"tool": "subfinder"}, content=body.encode()).status_code, 401)
        self.assertEqual(self.ingest("subfinder", body, key=self.other).status_code, 401)
        self.assertIn("asm:write", apikeys.SCOPES)
        ok = self.ingest("subfinder", body)
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertEqual(ok.json()["new"], 4)

    def test_a_session_cookie_alone_cannot_use_the_ingest_route(self):
        self.login("admin@t.local")
        r = self.client.post("/api/ingest/asm", params={"tool": "subfinder"}, content=SUBFINDER.encode())
        self.assertEqual(r.status_code, 401)

    def test_ingest_cannot_declare_scope_and_unknown_tool_is_a_clear_400(self):
        r = self.ingest("seeds", SEEDS)
        self.assertEqual(r.status_code, 400)
        self.assertIn("administrator", r.json()["detail"])
        r = self.ingest("masscan", "x")
        self.assertEqual(r.status_code, 400)
        self.assertIn("Unknown tool", r.json()["detail"])
        self.assertEqual(self.ingest("subfinder", "").status_code, 400)

    def test_oversize_upload_is_refused(self):
        with patch.object(dashboard_app_module, "MAX_UPLOAD_BYTES", 100):
            r = self.ingest("subfinder", SUBFINDER)
        self.assertEqual(r.status_code, 413)

    # ---- admin flow
    def test_admin_import_scope_assets_changes_summary(self):
        self.login("admin@t.local")
        r = self.client.post("/api/asm/import", params={"tool": "seeds"}, content=SEEDS.encode())
        self.assertEqual(r.status_code, 200, r.text)
        sc = self.client.get("/api/asm/scope").json()
        self.assertEqual((sc["domains"], sc["cidrs"], sc["declared"]), (["example.com"], ["203.0.113.0/24"], True))
        for tool, text in (("subfinder", SUBFINDER), ("dnsx", DNSX), ("httpx", HTTPX), ("naabu", NAABU), ("nuclei", NUCLEI)):
            self.assertEqual(self.client.post("/api/asm/import", params={"tool": tool}, content=text.encode()).status_code, 200)
        a = self.client.get("/api/asm/assets", params={"kind": "service", "in_scope": "true"}).json()
        self.assertTrue(all(x["kind"] == "service" and x["in_scope"] for x in a["assets"]))
        self.assertIn("data_age", a)
        out = self.client.get("/api/asm/assets", params={"in_scope": "false"}).json()
        self.assertTrue(out["total"] >= 2)
        self.assertTrue(all(not x["in_scope"] for x in out["assets"]))
        ch = self.client.get("/api/asm/changes").json()
        self.assertTrue(ch["changes"] and ch["runs"])
        s = self.client.get("/api/asm/summary").json()
        self.assertGreaterEqual(s["exposed_risky_services"], 2)
        self.assertEqual(s["assets"]["by_kind"]["domain"], 1)
        self.assertIn("data_age", s)
        self.assertFalse(s["stale"])

    def test_scope_validation_and_rescoping(self):
        self.client.post("/api/asm/import", params={"tool": "subfinder"}, content=SUBFINDER.encode())
        r = self.client.put("/api/asm/scope", json={"domains": ["example.com"], "cidrs": []})
        self.assertEqual((r.status_code, r.json()["rescoped"]), (200, 1))
        self.assertEqual(self.client.put("/api/asm/scope", json={"domains": ["1.2.3.4"], "cidrs": []}).status_code, 400)
        self.assertEqual(self.client.put("/api/asm/scope", json={"domains": [], "cidrs": ["0.0.0.0/0"]}).status_code, 400)

    def test_cadence_setting_and_stale_view(self):
        self.client.post("/api/asm/import", params={"tool": "subfinder"}, content=SUBFINDER.encode())
        self.assertEqual(self.client.put("/api/asm/settings", json={"expected_cadence_hours": 24}).json()["expected_cadence_hours"], 24)
        self.assertFalse(self.client.get("/api/asm/summary").json()["stale"])
        with patch.object(store, "_now", return_value="2026-10-01T00:00:00Z"):
            self.client.post("/api/asm/import", params={"tool": "subfinder"}, content=SUBFINDER.encode())
        s = self.client.get("/api/asm/summary").json()
        self.assertTrue(s["data_age"]["last_import_at"])
        self.assertEqual(self.client.put("/api/asm/settings", json={"expected_cadence_hours": 0.1}).status_code, 400)

    def test_stale_check_raises_a_soc_alert_through_the_tick(self):
        store.set_cadence_hours(24, self.engine)
        store.import_text("subfinder", SUBFINDER, engine=self.engine, now=at())
        dashboard_app_module._run_asm_stale_if_due()
        from remediation.hunting import store as hunt_store
        alerts = [a for a in hunt_store.list_alerts(self.engine) if a["source"] == "asm"]
        self.assertEqual(len(alerts), 1)
        dashboard_app_module._run_asm_stale_if_due()
        self.assertEqual(len([a for a in hunt_store.list_alerts(self.engine) if a["source"] == "asm"]), 1)

    def test_publish_previews_then_replaces_the_asm_findings_in_the_queue(self):
        self.client.post("/api/asm/import", params={"tool": "seeds"}, content=SEEDS.encode())
        for tool, text in (("httpx", HTTPX), ("naabu", NAABU), ("nuclei", NUCLEI)):
            self.client.post("/api/asm/import", params={"tool": tool}, content=text.encode())
        pre = self.client.post("/api/asm/publish", json={"confirm": False}).json()
        self.assertTrue(pre["preview_only"])
        self.assertEqual(json.loads(self.qpath.read_text()), [])
        done = self.client.post("/api/asm/publish", json={"confirm": True}).json()
        self.assertEqual(done["published"], pre["findings"])
        q = json.loads(self.qpath.read_text())
        self.assertTrue(q and all(f["source"] == "asm" for f in q))
        self.assertIn("CVE-2021-41773", {f.get("cve") for f in q})
        # a later import with nothing left to flag removes them (the complete set is published each time)
        store.clear(self.engine)
        again = self.client.post("/api/asm/publish", json={"confirm": True}).json()
        self.assertEqual((again["published"], again["removed"]), (0, done["published"]))

    def test_key_ingest_can_publish_in_one_step(self):
        self.ingest("naabu", NAABU, publish="true")
        q = json.loads(self.qpath.read_text())
        self.assertTrue(any(f["title"].startswith("SMB") or "RDP" in f["title"] for f in q))

    def test_how_to_feed_has_every_tool_and_the_authorisation_warning(self):
        d = self.client.get("/api/asm/how-to-feed").json()
        self.assertEqual({e["tool"] for e in d["examples"]}, {"subfinder", "dnsx", "httpx", "naabu", "nuclei", "seeds"})
        self.assertIn("does not scan", d["safety"])
        self.assertIn("authorised", d["safety"])
        self.assertIn("example.com", " ".join(e["command"] for e in d["examples"]))


class AsmGraphAndCatalog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'g.db'}")
        db_module.ensure_schema(self.engine)

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def test_the_graph_draws_domain_address_service_technology_and_only_in_scope(self):
        store.import_text("seeds", SEEDS, engine=self.engine, now=at())
        for tool, text in (("httpx", HTTPX), ("naabu", NAABU)):
            store.import_text(tool, text, engine=self.engine, now=at())
        g = infra.build(engine=self.engine, findings=[], topology={"assets": []})
        kinds = {n["kind"] for n in g["nodes"]}
        self.assertTrue({"asm_domain", "asm_ip", "asm_service", "asm_tech", "internet"} <= kinds)
        labels = {n["label"] for n in g["nodes"]}
        self.assertNotIn("198.51.100.5", labels)
        self.assertIn("www.example.com", labels)
        self.assertTrue(any(e["kind"] == "runs" for e in g["edges"]))
        self.assertTrue(any(e["kind"] == "exposes" for e in g["edges"]))

    def test_the_graph_is_bounded(self):
        assets = [{"key": f"service:203.0.113.{i % 250}:{1000 + i}/tcp", "kind": "service", "value": f"203.0.113.{i % 250}:{1000 + i}/tcp", "technologies": ["Nginx:1.2"], "ports": [], "sources": ["naabu"],
                   "last_seen": "2026-10-01T00:00:00Z", "data": {"host": f"203.0.113.{i % 250}", "hosts": [f"h{i}.example.com"], "ips": []}} for i in range(600)]
        g = infra.build(engine=self.engine, findings=[], topology={"assets": []}, asm_assets=assets)
        self.assertLessEqual(len([n for n in g["nodes"] if n["kind"].startswith("asm_")]), infra.MAX_ASM_NODES + 5)

    def test_an_empty_estate_keeps_the_original_empty_note(self):
        g = infra.build(engine=self.engine, findings=[], topology={"assets": []})
        self.assertEqual(g["nodes"], [])
        self.assertEqual(g["note"], infra.NOTE_EMPTY)

    def test_catalog_licensing_and_nav_know_the_page(self):
        import yaml
        root = REPO_ROOT
        cat = yaml.safe_load((root / "remediation/config/capabilities.yaml").read_text(encoding="utf-8"))
        ids = [i["id"] for m in cat for g in m["groups"] for i in g["items"]]
        self.assertIn("attack-surface", ids)
        lic = (root / "remediation/config/licensing.yaml").read_text(encoding="utf-8")
        self.assertIn("/api/asm", lic)
        self.assertIn("/api/ingest/asm", lic)
        nav = (root / "dashboard/static/js/nav.js").read_text(encoding="utf-8")
        self.assertIn('path: "/attack-surface"', nav)

    def test_the_catalog_metric_counts_in_scope_active_assets(self):
        from remediation import capabilities
        store.import_text("subfinder", SUBFINDER, engine=self.engine, now=at())
        m = capabilities.metrics([], self.engine)
        self.assertEqual(m["attack-surface"], "4 external assets imported")


if __name__ == "__main__":
    unittest.main()
