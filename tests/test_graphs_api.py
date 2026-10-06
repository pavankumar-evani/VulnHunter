"""GET /api/graphs/<module>: access control, the shared shape for all eight modules, and the findings-backed infrastructure graph."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_appsec_api import ApiBase  # noqa: E402

MODULES = ("soc", "appsec", "devsecops", "infra", "ai", "remediation", "grc", "admin")
SHAPE = {"module", "title", "description", "directed", "kinds", "nodes", "edges", "truncated", "totals", "note"}


class GraphApiTests(ApiBase):
    def test_an_unknown_module_is_a_404(self):
        self.login("admin@t.local")
        self.assertEqual(self.client.get("/api/graphs/nope").status_code, 404)

    def test_administrator_modules_refuse_anonymous_callers_and_ordinary_users(self):
        for module in ("soc", "appsec", "ai", "grc", "admin"):
            self.client.cookies.clear()
            self.assertEqual(self.client.get(f"/api/graphs/{module}").status_code, 401, module)
            self.login("user@t.local")
            self.assertEqual(self.client.get(f"/api/graphs/{module}").status_code, 403, module)

    def test_an_ordinary_user_can_read_the_graphs_of_the_other_modules(self):
        self.login("user@t.local")
        for module in ("devsecops", "infra", "remediation"):
            self.assertEqual(self.client.get(f"/api/graphs/{module}").status_code, 200, module)

    def test_every_module_returns_the_shared_shape(self):
        self.login("admin@t.local")
        for module in MODULES:
            r = self.client.get(f"/api/graphs/{module}")
            self.assertEqual(r.status_code, 200, (module, r.text[:200]))
            g = r.json()
            self.assertEqual(set(g), SHAPE, module)
            self.assertEqual(g["module"], module)
            ids = {n["id"] for n in g["nodes"]}
            self.assertEqual(len(ids), len(g["nodes"]), f"{module}: duplicate node ids")
            for e in g["edges"]:
                self.assertIn(e["source"], ids, module)
                self.assertIn(e["target"], ids, module)
            for n in g["nodes"]:
                self.assertIn(n["kind"], g["kinds"], module)
            if not g["nodes"]:
                self.assertTrue(g["note"], f"{module}: an empty graph must say what to connect")

    def test_the_same_request_gives_the_same_graph(self):
        self.login("admin@t.local")
        for module in MODULES:
            a = self.client.get(f"/api/graphs/{module}").json()
            b = self.client.get(f"/api/graphs/{module}").json()
            self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True), module)

    def test_the_infrastructure_graph_draws_the_assets_the_findings_name(self):
        self.login("admin@t.local")
        g = self.client.get("/api/graphs/infra").json()
        self.assertTrue(any(n["kind"] == "asset" for n in g["nodes"]), g["note"])

    def test_no_credential_or_token_appears_in_any_graph(self):
        self.login("admin@t.local")
        blob = "".join(self.client.get(f"/api/graphs/{m}").text for m in MODULES).lower()
        for needle in ("password", "secret", "token", "qk_", "authorization"):
            self.assertNotIn(needle, blob.replace('"token', "").replace("tokens", ""), needle)



class GraphLicenceTests(unittest.TestCase):
    def test_each_graph_belongs_to_its_own_module_and_the_admin_one_is_always_included(self):
        from remediation.licensing import license as lic
        for module in ("soc", "appsec", "devsecops", "infra", "ai", "remediation", "grc"):
            self.assertEqual(lic.module_for_path(f"/api/graphs/{module}"), ("module", [module]), module)
        self.assertEqual(lic.module_for_path("/api/graphs/admin")[0], "core")


if __name__ == "__main__":
    unittest.main()
