"""Tests for the GRC relationship graph: empty state, evidence-control-framework-risk edges, shared control hubs, determinism."""
import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine  # noqa: E402

from remediation.graphs import grc as grc_graph  # noqa: E402
from remediation.grc import catalog, evidence, risks  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

TODAY = datetime.date(2026, 10, 15)
OSCAL = {"catalog": {"metadata": {"title": "Corp catalog", "version": "1"}, "groups": [
    {"id": "si", "title": "System Integrity", "controls": [{"id": "si-2", "title": "Flaw Remediation"}]}]}}


def finding(i):
    return {"id": f"FIND-{i}", "severity": "High", "sla": {"breached": True}, "kev": {"listed": True},
            "asset": {"name": "web-01.corp.test"}, "last_seen": "2026-10-14"}


class GrcGraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'g.db'}")
        db_module.ensure_schema(self.engine)

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def seed(self):
        catalog.ensure_builtin(self.engine)
        catalog.import_oscal("corp-cat", OSCAL, engine=self.engine)
        fs = [finding(1), finding(2)]
        evidence.run_all(evidence.Context(fs, self.engine, today=TODAY), only=["kev-remediation", "patch-sla"])
        risks.create({"title": "Unpatched exploited flaws", "inherent_likelihood": 5, "inherent_impact": 4}, "pat.owner@corp.test",
                     source="finding", source_ref="kev-overdue", engine=self.engine)
        risks.create({"title": "Vendor gap noted against RA-5", "inherent_likelihood": 2, "inherent_impact": 2, "owner": "pat.owner@corp.test"},
                     "pat.owner@corp.test", engine=self.engine)
        return fs

    def test_empty_state_says_what_to_load(self):
        g = grc_graph.build(self.engine)
        self.assertEqual(g["nodes"], [])
        self.assertIn("/grc", g["note"])
        self.assertEqual(g["module"], "grc")

    def test_seeded_graph_nodes_and_edges(self):
        fs = self.seed()
        g = grc_graph.build(self.engine, findings=fs, today=TODAY)
        nodes = {n["id"]: n for n in g["nodes"]}
        edges = {(e["source"], e["target"], e["kind"]) for e in g["edges"]}
        self.assertIn("evidence:kev-remediation", nodes)
        self.assertEqual(nodes["evidence:kev-remediation"]["sev"], "high")
        self.assertIn(("evidence:kev-remediation", "control:SI-2", "evidences"), edges)
        self.assertIn(("control:SI-2", "framework:nist-800-53-r5", "part-of"), edges)
        self.assertEqual(nodes["control:SI-2"]["sev"], "high")
        self.assertEqual(nodes["control:SI-2"]["meta"]["status"], "not-satisfied")
        self.assertEqual(len([n for n in g["nodes"] if n["kind"] == "risk"]), 2)
        self.assertIn(("risk:1", "control:SI-2", "mitigated-by"), edges)
        self.assertIn(("risk:2", "control:RA-5", "mitigated-by"), edges)
        self.assertEqual(nodes["findings:kev-overdue"]["meta"]["matching_findings"], 2)
        self.assertEqual(nodes["control:SI-2"]["href"], "/grc")

    def test_control_in_two_frameworks_is_one_hub(self):
        fs = self.seed()
        g = grc_graph.build(self.engine, findings=fs, today=TODAY)
        self.assertEqual(sum(1 for n in g["nodes"] if n["id"] == "control:SI-2"), 1)
        parts = [e for e in g["edges"] if e["source"] == "control:SI-2" and e["kind"] == "part-of"]
        self.assertEqual({e["target"] for e in parts}, {"framework:nist-800-53-r5", "framework:corp-cat"})
        hub = next(n for n in g["nodes"] if n["id"] == "control:SI-2")
        self.assertEqual(hub["meta"]["frameworks"], 2)

    def test_unevidenced_controls_are_left_out(self):
        self.seed()
        g = grc_graph.build(self.engine, findings=[], today=TODAY)
        self.assertNotIn("control:AC-17", {n["id"] for n in g["nodes"]})

    def test_deterministic_and_no_secret_like_text(self):
        fs = self.seed()
        a = grc_graph.build(self.engine, findings=fs, today=TODAY)
        b = grc_graph.build(self.engine, findings=fs, today=TODAY)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        blob = json.dumps(a).lower()
        for needle in ("password", "secret", "token", "qk_"):
            self.assertNotIn(needle, blob)


if __name__ == "__main__":
    unittest.main()
