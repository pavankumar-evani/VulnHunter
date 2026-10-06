"""Tests for the administration graph: empty state, connections/keys/teams around the core, isolation, no credentials, determinism."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine  # noqa: E402

from remediation.apikeys import store as apikeys  # noqa: E402
from remediation.assignments import store as assignments  # noqa: E402
from remediation.connections import crypto, store  # noqa: E402
from remediation.graphs import admin as admin_graph  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

TENABLE = {"access_key": "AKIA-SENTINEL-ACCESS", "secret_key": "SENTINEL-SECRET-KEY-12345"}
SNOW = {"instance": "corptest", "username": "svc-account", "password": "SENTINEL-PASSWORD-678"}
SPLUNK_SEARCH = {"base_url": "https://splunk.corp.test", "token": "SENTINEL-TOKEN-2"}
ACTOR = "pat.owner@corp.test"


class AdminGraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'a.db'}")
        db_module.ensure_schema(self.engine)
        self.env = patch.dict(os.environ, {"QUANTA_ENCRYPTION_KEY": crypto.generate_key()})
        self.env.start()
        self.guard = patch("remediation.connectors.url_safety.assert_safe_target")
        self.guard.start()

    def tearDown(self):
        self.guard.stop()
        self.env.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def seed(self):
        a = store.create("Corp Tenable", "tenable", TENABLE, ACTOR, engine=self.engine)
        store.finish_run(a["id"], "error", "boom https://x.corp.test/?token=SENTINEL-TOKEN", engine=self.engine)
        c = store.create("Corp Splunk search", "splunk-search", SPLUNK_SEARCH, ACTOR, enabled=False, engine=self.engine)
        _, self.key = apikeys.create("CI scanner", ["ingest:write", "api:write"], ACTOR, engine=self.engine)
        assignments.create_team("Platform", ACTOR, manager_email=ACTOR, engine=self.engine, lock_path=Path(self.tmp.name) / "t.lock")
        return a, c

    def test_empty_state_note(self):
        g = admin_graph.build(self.engine)
        self.assertEqual(g["nodes"], [])
        self.assertIn("/connections", g["note"])

    def test_seeded_graph(self):
        a, c = self.seed()
        g = admin_graph.build(self.engine)
        nodes = {n["id"]: n for n in g["nodes"]}
        edges = {(e["source"], e["target"], e["kind"]) for e in g["edges"]}
        self.assertEqual({f"module:{m}" for m in ("soc", "appsec", "devsecops", "infra", "ai", "remediation", "grc", "admin")},
                         {i for i in nodes if i.startswith("module:")})
        self.assertIn(("core:quanta", "module:grc", "serves"), edges)
        self.assertIn((f"connection:{a['id']}", "core:quanta", "feeds"), edges)
        self.assertIn((f"connection:{a['id']}", "module:infra", "feeds"), edges)
        self.assertEqual(nodes[f"connection:{a['id']}"]["sev"], "high")
        self.assertEqual(nodes[f"connection:{c['id']}"]["sev"], "low")
        self.assertEqual(nodes[f"connection:{c['id']}"]["meta"]["status"], "disabled")
        self.assertIn((f"connection:{c['id']}", "module:soc", "feeds"), edges)
        self.assertIn(("apikey:api:write", "module:appsec", "ingests-into"), edges)
        self.assertIn(("apikey:ingest:write", "module:infra", "ingests-into"), edges)
        self.assertIn(("team:Platform", "core:quanta", "works-in"), edges)

    def test_unfed_module_has_no_connection_edge(self):
        self.seed()
        g = admin_graph.build(self.engine)
        touching = [e for e in g["edges"] if "module:grc" in (e["source"], e["target"])]
        self.assertEqual({e["source"] for e in touching}, {"core:quanta"})

    def test_push_connection_direction(self):
        p = store.create("Corp ServiceNow", "servicenow", SNOW, ACTOR, engine=self.engine)
        g = admin_graph.build(self.engine)
        edges = {(e["source"], e["target"], e["kind"]) for e in g["edges"]}
        self.assertIn(("core:quanta", f"connection:{p['id']}", "sends-to"), edges)

    def test_no_credentials_anywhere(self):
        self.seed()
        store.create("Corp ServiceNow", "servicenow", SNOW, ACTOR, engine=self.engine)
        blob = json.dumps(admin_graph.build(self.engine))
        for needle in ("SENTINEL", "AKIA", "splunk.corp.test", self.key, "boom", "password", "secret_key"):
            self.assertNotIn(needle, blob)

    def test_deterministic(self):
        self.seed()
        self.assertEqual(json.dumps(admin_graph.build(self.engine), sort_keys=True), json.dumps(admin_graph.build(self.engine), sort_keys=True))


if __name__ == "__main__":
    unittest.main()
