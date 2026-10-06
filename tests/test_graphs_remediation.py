"""Tests for the "who owns the risk" graph (remediation/graphs/remediation.py)."""
import datetime
import sys
import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
sys.path.insert(0, str(REPO_ROOT))

from auth import users  # noqa: E402
from remediation.assignments import store as assignments  # noqa: E402
from remediation.connections import links  # noqa: E402
from remediation.exceptions import store as exceptions_store  # noqa: E402
from remediation.graphs import remediation as graph  # noqa: E402
from remediation.inventory import asset_inventory  # noqa: E402
from remediation.remediation_approvals import store as approvals  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

TODAY = datetime.date(2026, 10, 1)
WINDOW = {"date": "2026-10-20"}


def finding(fid, asset, severity="High", **kw):
    return {"id": fid, "asset": {"name": asset, "type": "windows-server"}, "severity": severity, "title": "t", **kw}


class RemediationGraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'q.db'}")
        db_module.ensure_schema(self.engine)
        self.lock = str(Path(self.tmp.name) / "x.lock")
        self.findings = [finding("FIND-1", "pay-db01.corp.test", "Critical"), finding("FIND-2", "pay-db01.corp.test", "Low"),
                         finding("FIND-3", "web01.corp.test", "Medium"), finding("FIND-4", "orphan01.corp.test", "Critical")]

    def tearDown(self):
        self.engine.dispose()
        self.tmp.cleanup()

    def build(self, findings="default"):
        return graph.build(self.engine, self.findings if findings == "default" else findings, as_of=TODAY)

    def seed(self):
        e, lk = self.engine, self.lock
        assignments.create_team("Payments", "admin@corp.test", engine=e, lock_path=lk)
        assignments.create_team("Platform", "admin@corp.test", engine=e, lock_path=lk)
        users.create_user("pat.owner@corp.test", "password-123", "Pat Owner", team="Payments", engine=e, lock_path=lk)
        asset_inventory.set_owner("pay-db01.corp.test", "", "Payments", engine=e, lock_path=lk)
        asset_inventory.set_owner("web01.corp.test", "", "Platform", engine=e, lock_path=lk)
        assignments.assign("FIND-1", "admin@corp.test", assignee_email="pat.owner@corp.test", engine=e, lock_path=lk)
        exceptions_store.create_exception("FIND-2", "compensating control", "pat.owner@corp.test", "ciso@corp.test", "2026-12-01", engine=e, as_of=TODAY, lock_path=lk)
        approvals.create_approval_request("FIND-3", "pat.owner@corp.test", WINDOW, engine=e, as_of=TODAY, lock_path=lk)
        links.upsert("FIND-1", "jira", "SEC-12", "open", engine=e)

    def test_no_findings_is_an_empty_graph_with_a_note(self):
        g = self.build(None)
        self.assertEqual((g["nodes"], g["edges"]), ([], []))
        self.assertIn("Ingest scanner findings", g["note"])

    def test_seeded_case_has_expected_nodes_and_edges(self):
        self.seed()
        g = self.build()
        nodes = {n["id"]: n for n in g["nodes"]}
        edges = {(x["source"], x["target"], x["kind"]) for x in g["edges"]}
        self.assertEqual(nodes["asset:pay-db01.corp.test"]["weight"], 2)
        self.assertEqual(nodes["asset:pay-db01.corp.test"]["sev"], "critical")
        self.assertEqual(nodes["asset:pay-db01.corp.test"]["meta"]["open"], 2)
        for expected in [("team:payments", "person:pat.owner@corp.test", "member_of"),
                         ("team:payments", "asset:pay-db01.corp.test", "owns"),
                         ("team:platform", "asset:web01.corp.test", "owns"),
                         ("person:pat.owner@corp.test", "asset:pay-db01.corp.test", "assigned"),
                         ("exception:EXC-1", "asset:pay-db01.corp.test", "waives"),
                         ("approval:APR-1", "asset:web01.corp.test", "approves"),
                         ("ticket:jira:SEC-12", "asset:pay-db01.corp.test", "tracks")]:
            self.assertIn(expected, edges)
        self.assertEqual(nodes["person:pat.owner@corp.test"]["label"], "Pat Owner")

    def test_unowned_asset_is_isolated_and_flagged(self):
        self.seed()
        g = self.build()
        nodes = {n["id"]: n for n in g["nodes"]}
        orphan = "asset:orphan01.corp.test"
        self.assertTrue(nodes[orphan]["meta"]["unowned"])
        self.assertFalse(nodes["asset:web01.corp.test"]["meta"]["unowned"])
        self.assertFalse([e for e in g["edges"] if orphan in (e["source"], e["target"])])
        self.assertIn("1 of 3 assets", g["note"])
        self.assertIn("1 of them", g["note"])

    def test_expired_exception_and_rejected_approval_are_left_out(self):
        self.seed()
        approvals.reject("APR-1", "boss@corp.test", "no", engine=self.engine, as_of=TODAY, lock_path=self.lock)
        g = graph.build(self.engine, self.findings, as_of=datetime.date(2027, 1, 1))
        ids = {n["id"] for n in g["nodes"]}
        self.assertNotIn("exception:EXC-1", ids)
        self.assertNotIn("approval:APR-1", ids)

    def test_deterministic(self):
        self.seed()
        self.assertEqual(self.build(), self.build())


if __name__ == "__main__":
    unittest.main()
