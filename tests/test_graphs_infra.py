"""Tests for the infrastructure exposure and movement graph (remediation/graphs/infra.py)."""
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import create_engine  # noqa: E402

from remediation.firewall import store as fw_store  # noqa: E402
from remediation.graphs import infra  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

CSV = """Name,Source Zone,Destination Zone,Source Address,Destination Address,Service,Action,Log,Hit Count,Last Hit,Created,Owner,Comment
allow-rdp-in,untrust,dmz,any,web-01.corp.test,tcp/3389,allow,yes,10,2026-10-01,2025-01-01,pat.owner@corp.test,
"""
POLICY = {"risky_ports": {3389: "RDP"}, "internet_zone_words": ["untrust"], "unused_days": 90}
TOPOLOGY = {"assets": [{"match": {"name_prefix": "web-"}, "path_to_internet": [{"hop_type": "waf", "name": "Edge-WAF", "default_action": "allow"},
                                                                              {"hop_type": "firewall", "name": "Perimeter-FW", "default_action": "allow"}]},
                       {"match": {"name": "db-01.corp.test"}, "path_to_internet": [{"hop_type": "firewall", "name": "Perimeter-FW", "default_action": "allow"}]}]}


def finding(i, host, title, sev="High"):
    return {"id": f"FIND-{i}", "title": title, "severity": sev, "asset": {"name": host, "type": "unix-server"}}


FINDINGS = [finding(1, "web-01.corp.test", "SQL injection in login", "Critical"),
            finding(2, "web-01.corp.test", "Outdated library"),
            finding(3, "db-01.corp.test", "Remote code execution in service")]


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'q.db'}")
        db_module.ensure_schema(self.engine)

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def build(self, findings=FINDINGS, topology=None, **kw):
        return infra.build(engine=self.engine, findings=findings, topology=topology or {"assets": []}, firewall_policy=POLICY, **kw)

    def test_empty_state_note(self):
        g = self.build(findings=[])
        self.assertEqual(g["nodes"], [])
        self.assertIn("network_topology.yaml", g["note"])

    def test_findings_only_still_returns_assets_and_says_what_adds_exposure(self):
        g = self.build()
        self.assertEqual({n["id"] for n in g["nodes"]}, {"asset:web-01.corp.test", "asset:db-01.corp.test"})
        self.assertIn("Showing assets with findings only", g["note"])
        web = next(n for n in g["nodes"] if n["id"] == "asset:web-01.corp.test")
        self.assertEqual((web["weight"], web["sev"]), (2, "critical"))

    def test_topology_lane_and_pivot(self):
        g = self.build(topology=TOPOLOGY)
        edges = {(e["source"], e["target"], e["kind"]) for e in g["edges"]}
        self.assertIn(("internet", "hop:Edge-WAF", "reaches"), edges)
        self.assertIn(("hop:Edge-WAF", "hop:Perimeter-FW", "routes_to"), edges)
        self.assertIn(("hop:Perimeter-FW", "asset:web-01.corp.test", "routes_to"), edges)
        self.assertIn(("hop:Perimeter-FW", "asset:db-01.corp.test", "routes_to"), edges)
        pivot = [e for e in g["edges"] if e["kind"] == "pivot"]
        self.assertEqual([(e["source"], e["target"], e["label"]) for e in pivot], [("asset:web-01.corp.test", "asset:db-01.corp.test", "Initial Access")])
        self.assertIsNone(g["note"])

    def test_firewall_rule_and_port_lane(self):
        fw_store.import_rules("fw-edge", CSV, "csv", "pat.owner@corp.test", self.engine)
        g = self.build()
        edges = {(e["source"], e["target"], e["kind"]) for e in g["edges"]}
        self.assertIn(("internet", "rule:fw-edge/allow-rdp-in", "reaches"), edges)
        self.assertIn(("rule:fw-edge/allow-rdp-in", "port:3389", "opens"), edges)
        self.assertIn(("rule:fw-edge/allow-rdp-in", "asset:web-01.corp.test", "routes_to"), edges)

    def test_deterministic(self):
        fw_store.import_rules("fw-edge", CSV, "csv", "pat.owner@corp.test", self.engine)
        self.assertEqual(self.build(topology=TOPOLOGY), self.build(topology=TOPOLOGY))


if __name__ == "__main__":
    unittest.main()
