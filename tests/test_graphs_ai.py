"""Tests for the AI dependency graph (remediation/graphs/ai.py)."""
import datetime
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.aisec import rules, store as aisec_store  # noqa: E402
from remediation.aiusage import discovery, store as usage_store  # noqa: E402
from remediation.graphs import ai as graph  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

TODAY = datetime.date(2026, 10, 15)
LINKS = {"support-bot": {"tools": ["ticket-lookup"], "mcp_servers": ["crm-mcp"], "data_sources": ["kb-index"]},
         "sales-agent": {"tools": ["Ticket-Lookup"], "mcp_servers": ["crm-mcp"]}}


class AiGraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'q.db'}")
        db_module.ensure_schema(self.engine)
        self.patch = patch.object(rules, "approved_models", return_value=[])
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def build(self, **kw):
        kw.setdefault("today", TODAY)
        return graph.build(self.engine, kw.pop("findings", None), **kw)

    def seed(self):
        e = self.engine
        aisec_store.save({"name": "support-bot", "kind": "application", "owner": "ai-team@corp.test", "vendor_model": "model-large", "environment": "production"}, "t", engine=e)
        aisec_store.save({"name": "sales-agent", "kind": "agent", "owner": "ai-team@corp.test", "environment": "production"}, "t", engine=e)
        aisec_store.save({"name": "crm-mcp", "kind": "mcp-server", "owner": "ai-team@corp.test", "auth_required": False}, "t", engine=e)
        usage_store.record([{"ts": "2026-10-14T10:00:00Z", "model": "model-large", "provider": "acme-ai", "application": "support-bot"}], "api", engine=e)
        discovery.add_app("Acme AI Chat", "chat.acme-ai.test", engine=e)

    def test_empty_state_note(self):
        g = self.build()
        self.assertEqual((g["nodes"], g["edges"]), ([], []))
        self.assertIn("AI Security", g["note"])

    def test_seeded_nodes_and_edges(self):
        self.seed()
        g = self.build(links=LINKS)
        ids = {n["id"] for n in g["nodes"]}
        edges = {(x["source"], x["target"], x["kind"]) for x in g["edges"]}
        for n in ("system:support-bot", "system:sales-agent", "model:model-large", "provider:acme-ai", "mcp-server:crm-mcp", "tool:ticket-lookup",
                  "data-source:kb-index", "shadow:chat.acme-ai.test"):
            self.assertIn(n, ids)
        self.assertIn(("system:support-bot", "model:model-large", "runs"), edges)
        self.assertIn(("system:support-bot", "provider:acme-ai", "hosted_by"), edges)
        self.assertIn(("system:support-bot", "data-source:kb-index", "reads"), edges)
        self.assertIn(("shadow:chat.acme-ai.test", "provider:acme-ai", "talks_to"), edges)

    def test_shared_tool_links_both_systems(self):
        self.seed()
        g = self.build(links=LINKS)
        edges = {(x["source"], x["target"], x["kind"]) for x in g["edges"]}
        self.assertIn(("system:support-bot", "tool:ticket-lookup", "can_call"), edges)
        self.assertIn(("system:sales-agent", "tool:ticket-lookup", "can_call"), edges)
        nodes = {n["id"]: n for n in g["nodes"]}
        self.assertEqual(nodes["tool:ticket-lookup"]["weight"], 2)
        # the registered MCP server is the same node the systems call, with its own register severity
        self.assertEqual(nodes["mcp-server:crm-mcp"]["weight"], 2)
        self.assertEqual(nodes["mcp-server:crm-mcp"]["sev"], "high")

    def test_no_links_are_invented_and_findings_roll_up(self):
        self.seed()
        findings = [{"id": "F1", "severity": "Critical", "asset": {"name": "Sales-Agent", "type": "ai-ml-system"}},
                    {"id": "F2", "severity": "Low", "asset": {"name": "sales-agent", "type": "windows-server"}}]
        g = self.build(findings=findings)
        edges = {(x["source"], x["kind"]) for x in g["edges"]}
        self.assertNotIn(("system:sales-agent", "can_call"), edges)
        sales = next(n for n in g["nodes"] if n["id"] == "system:sales-agent")
        self.assertEqual(sales["sev"], "critical")
        self.assertEqual(sales["meta"]["queue_findings"], 1)
        self.assertIn("gaps in the record", g["note"])

    def test_deterministic(self):
        self.seed()
        self.assertEqual(self.build(links=LINKS), self.build(links=LINKS))


if __name__ == "__main__":
    unittest.main()
