"""Tests for the AppSec relationship graph: empty state, services, endpoints, data classes, dependencies, threat-model flows, determinism."""
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import create_engine  # noqa: E402

from remediation.apisec import logs, store  # noqa: E402
from remediation.graphs import appsec as appsec_graph  # noqa: E402
from remediation.threatmodel import store as tm_store  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

SPEC = """openapi: 3.0.0
info: {title: Shop API, version: "1.0"}
servers: [{url: "https://shop.corp.test/v1"}]
components:
  securitySchemes: {b: {type: http, scheme: bearer}}
security: [{b: []}]
paths:
  /users/{userId}:
    get:
      parameters: [{name: userId, in: path, required: true}]
      responses: {"200": {description: ok}}
  /orders:
    get: {responses: {"200": {description: ok}}}
  /legacy/report:
    get: {deprecated: true, responses: {"200": {description: ok}}}
"""


def rec(path, **kw):
    r = {"method": "GET", "path": path, "host": "shop.corp.test", "status": 200, "ip": "34.120.5.9", "auth": "bearer", "scheme": "https", "user": "u1"}
    r.update(kw)
    return logs.normalise(r)


MODEL = {"components": [{"id": "web", "name": "Web front", "type": "service", "internet_facing": True},
                        {"id": "db", "name": "Orders DB", "type": "datastore", "handles": ["pii"]}],
         "data_flows": [{"from": "web", "to": "db", "data": ["pii"]}], "trust_zones": []}


class AppsecGraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.e = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        db_module.ensure_schema(self.e)

    def tearDown(self):
        self.e.dispose()
        self.tmp.cleanup()

    def seed(self, model=True):
        store.import_spec(SPEC, None, "upload", "pat.owner@corp.test", engine=self.e)
        store.import_classes("name,priority,detectors\nInternal,3,email", "pat.owner@corp.test", engine=self.e)
        store.ingest_records([
            rec("/v1/users/5", response_fields=["email"]),
            rec("/v1/orders", auth="none", response_fields=["user_email", "ip_address"], source_service="web-front", dest_exposure="internal"),
            rec("/v1/legacy/report"),
            rec("/v1/secret/dump", response_fields=["email"]),
        ], default_service="shop-api", engine=self.e)
        if model:
            tm_store.create("Orders", "", MODEL, "pat.owner@corp.test", self.e)

    def graph(self):
        return appsec_graph.build(self.e)

    def test_empty_state_says_what_to_connect(self):
        g = self.graph()
        self.assertEqual((g["nodes"], g["edges"]), ([], []))
        self.assertIn("OpenAPI", g["note"])

    def test_services_endpoints_and_markers(self):
        self.seed()
        g = self.graph()
        nodes = {n["id"]: n for n in g["nodes"]}
        edges = {(e["source"], e["target"], e["kind"]) for e in g["edges"]}
        self.assertIn(("service:shop-api", "endpoint:shop-api:GET /v1/users/{}", "serves"), edges)
        self.assertEqual(nodes["endpoint:shop-api:GET /v1/secret/dump"]["meta"]["state"], "shadow")
        self.assertEqual(nodes["endpoint:shop-api:GET /v1/secret/dump"]["sev"], "high")
        self.assertIn("open-without-auth", nodes["endpoint:shop-api:GET /v1/orders"]["meta"]["flags"])
        self.assertIn("zombie", nodes["endpoint:shop-api:GET /v1/legacy/report"]["meta"]["flags"])
        self.assertIsNone(nodes["endpoint:shop-api:GET /v1/users/{}"]["sev"])

    def test_shared_data_class_links_two_endpoints_and_unmapped_is_unclassified(self):
        self.seed()
        g = self.graph()
        parents = {e["source"] for e in g["edges"] if e["target"] == "data-class:Internal"}
        self.assertEqual(parents, {"endpoint:shop-api:GET /v1/users/{}", "endpoint:shop-api:GET /v1/orders", "endpoint:shop-api:GET /v1/secret/dump"})
        self.assertIn(("endpoint:shop-api:GET /v1/orders", "data-class:unclassified", "returns"), {(e["source"], e["target"], e["kind"]) for e in g["edges"]})

    def test_service_calls_and_model_flows(self):
        self.seed()
        g = self.graph()
        edges = {(e["source"], e["target"], e["kind"]) for e in g["edges"]}
        self.assertIn(("service:web-front", "service:shop-api", "calls"), edges)
        self.assertTrue(any(e["kind"] == "flows to" and e["label"] == "pii" for e in g["edges"]))
        self.assertEqual(sum(1 for n in g["nodes"] if n["kind"] == "component"), 2)

    def test_model_alone_and_determinism(self):
        tm_store.create("Orders", "", MODEL, "pat.owner@corp.test", self.e)
        g = self.graph()
        self.assertEqual(len(g["nodes"]), 2)
        self.seed(model=False)
        self.assertEqual(self.graph(), self.graph())


if __name__ == "__main__":
    unittest.main()
