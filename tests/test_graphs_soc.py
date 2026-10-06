"""Tests for the SOC relationship graph: empty state, nodes and edges from seeded alerts, cases and hunts, shared entities, determinism."""
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import create_engine  # noqa: E402

from remediation.graphs import soc as soc_graph  # noqa: E402
from remediation.hunting import store  # noqa: E402
from remediation.soc import cases  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402


def alert(ext, host, technique="T1190", severity="High", **kw):
    a = {"external_id": ext, "title": f"Alert {ext}", "severity": severity, "asset": host, "technique": technique,
         "entities": {"host": host, "user": kw.pop("user", None), "ips": kw.pop("ips", []), "domains": kw.pop("domains", [])}}
    a.update(kw)
    return a


class SocGraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.e = create_engine(f"sqlite:///{Path(self.tmp.name) / 't.db'}")
        db_module.ensure_schema(self.e)

    def tearDown(self):
        self.e.dispose()
        self.tmp.cleanup()

    def seed(self):
        a1, _ = store.receive_alert(alert("a1", "web-01.corp.test", user="pat.owner@corp.test", ips=["203.0.113.7"]), self.e)
        a2, _ = store.receive_alert(alert("a2", "web-02.corp.test", severity="Critical", ips=["203.0.113.7"]), self.e)
        c = cases.open_case({"title": "Web campaign", "severity": "High", "techniques": ["T1190"], "alert_ids": [a1["id"], a2["id"]]}, "pat.owner@corp.test", self.e)
        h = store.create_hunt({"title": "Hunt web exploitation", "hypothesis": "Probing", "techniques": ["T1190"], "assets": ["web-01.corp.test"]}, "pat.owner@corp.test", self.e)
        store.create_hunt({"title": "Unrelated", "hypothesis": "None", "techniques": ["T9999"], "assets": ["db-09.corp.test"]}, "pat.owner@corp.test", self.e)
        return a1, a2, c, h

    def test_empty_state_says_what_to_connect(self):
        g = soc_graph.build(self.e)
        self.assertEqual((g["nodes"], g["edges"]), ([], []))
        self.assertIn("/api/ingest/alerts", g["note"])
        self.assertEqual(g["module"], "soc")

    def test_seeded_nodes_and_edges(self):
        a1, a2, c, h = self.seed()
        g = soc_graph.build(self.e)
        ids = {n["id"] for n in g["nodes"]}
        for want in (f"alert:{a1['id']}", f"alert:{a2['id']}", f"case:{c['id']}", f"hunt:{h['id']}", "technique:T1190", "host:web-01.corp.test",
                     "user:pat.owner@corp.test", "ip:203.0.113.7"):
            self.assertIn(want, ids)
        edges = {(e["source"], e["target"], e["kind"]) for e in g["edges"]}
        self.assertIn((f"alert:{a1['id']}", "host:web-01.corp.test", "involves"), edges)
        self.assertIn((f"alert:{a1['id']}", "technique:T1190", "tagged"), edges)
        self.assertIn((f"case:{c['id']}", f"alert:{a1['id']}", "contains"), edges)
        self.assertIn((f"hunt:{h['id']}", "technique:T1190", "hunts"), edges)
        self.assertIn((f"hunt:{h['id']}", "host:web-01.corp.test", "covers"), edges)
        self.assertNotIn("host:db-09.corp.test", ids)
        self.assertEqual(sum(1 for n in g["nodes"] if n["kind"] == "hunt"), 1)  # the unrelated hunt shares nothing
        sev = {n["id"]: n["sev"] for n in g["nodes"]}
        self.assertEqual(sev[f"alert:{a2['id']}"], "critical")

    def test_shared_entity_links_two_alerts(self):
        a1, a2, _c, _h = self.seed()
        g = soc_graph.build(self.e)
        ip = next(n for n in g["nodes"] if n["id"] == "ip:203.0.113.7")
        self.assertEqual(ip["meta"]["alerts"], 2)
        parents = {e["source"] for e in g["edges"] if e["target"] == ip["id"]}
        self.assertEqual(parents, {f"alert:{a1['id']}", f"alert:{a2['id']}"})

    def test_deterministic(self):
        self.seed()
        self.assertEqual(soc_graph.build(self.e), soc_graph.build(self.e))


if __name__ == "__main__":
    unittest.main()
