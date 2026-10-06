"""Tests for the AI supply chain posture framework (remediation/posture/ai_supply_chain.py)."""
import datetime
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.appsec import store as appsec_store  # noqa: E402
from remediation.aisec import rules, store as aisec_store  # noqa: E402
from remediation.aiusage import analytics, discovery, store as usage_store  # noqa: E402
from remediation.posture import ai_supply_chain as aisc, engine as posture_engine  # noqa: E402
from remediation.posture.model import Context  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

NOW = datetime.datetime(2026, 10, 6, tzinfo=datetime.timezone.utc)
ALLOWED = ["model-large", "model-small"]
OWNER = "pat.owner@corp.test"


def bom(*components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [dict(c, **{"bom-ref": c["name"]}) for c in components]}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'q.db'}")
        db_module.ensure_schema(self.engine)
        self.patches = [patch.object(rules, "approved_models", return_value=ALLOWED),
                        patch.object(analytics, "policy", return_value={"allowed_models": ALLOWED})]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def ctx(self, links=None, findings=None):
        c = Context(engine=self.engine, findings=findings, env={}, now=NOW)
        pol = posture_engine.policy()
        c.policy, c.thr = pol, pol["thresholds"]
        if links is not None:
            c.ai_links = links
        return c

    def checks(self, **kw):
        return {c["id"]: c for c in aisc.run(self.ctx(**kw))}

    def reg(self, **kw):
        base = {"environment": "production", "owner": OWNER, "last_reviewed": "2026-10-01"}
        return aisec_store.save({**base, **kw}, "t", engine=self.engine)

    def use(self, app, provider, model="model-large", n=1):
        usage_store.record([{"ts": "2026-10-01T10:00:00Z", "model": model, "provider": provider, "application": app, "request_count": n}], "api", engine=self.engine)


class NoAiTests(Base):
    def test_empty_estate_has_no_pass(self):
        res = self.checks()
        self.assertEqual(len(res), 20)
        for c in res.values():
            self.assertIn(c["status"], ("unknown", "na"), c["id"])
            self.assertIsNone(c["score"])


class CheckTests(Base):
    def test_model_and_provider_recorded(self):
        self.reg(name="support-bot", kind="application", vendor_model="model-large")
        self.reg(name="sales-agent", kind="agent")
        self.use("support-bot", "acme-ai")
        res = self.checks()
        self.assertIn(res["aisc-model-recorded"]["status"], ("partial", "fail"))
        self.assertIn("1 of 2", res["aisc-model-recorded"]["evidence"][0])
        self.assertIn("1 of 2", res["aisc-provider-recorded"]["evidence"][0])

    def test_model_and_provider_recorded_good(self):
        self.reg(name="support-bot", kind="application", vendor_model="model-large")
        self.reg(name="sales-agent", kind="agent", vendor_model="model-small")
        self.use("support-bot", "acme-ai")
        self.use("sales-agent", "other-ai", "model-small")
        res = self.checks()
        self.assertEqual(res["aisc-model-recorded"]["status"], "pass")
        self.assertEqual(res["aisc-provider-recorded"]["status"], "pass")
        self.assertEqual(res["aisc-provider-concentration"]["status"], "pass")  # two providers, each used by half
        self.assertEqual(res["aisc-provider-approved"]["status"], "pass")

    def test_provider_concentration_and_approval_bad(self):
        self.reg(name="support-bot", kind="application", vendor_model="model-large")
        self.reg(name="sales-agent", kind="agent", vendor_model="model-large")
        self.use("support-bot", "acme-ai")
        self.use("sales-agent", "acme-ai", "rogue-model", 3)
        res = self.checks()
        c = res["aisc-provider-concentration"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("2 of 2", c["evidence"][0])
        c = res["aisc-provider-approved"]
        self.assertIn(c["status"], ("partial", "fail"))
        self.assertIn("3 of 4", c["evidence"][0])
        self.assertIn("acme-ai", c["evidence"][0])

    def test_provider_approved_unknown_without_list(self):
        self.reg(name="support-bot", kind="application")
        self.use("support-bot", "acme-ai")
        with patch.object(analytics, "policy", return_value={}):
            self.assertEqual(self.checks()["aisc-provider-approved"]["status"], "unknown")

    def test_tools_recorded(self):
        self.reg(name="support-bot", kind="application", can_take_actions=True)
        self.reg(name="sales-agent", kind="agent", can_take_actions=True)
        c = self.checks()["aisc-tools-recorded"]
        self.assertEqual(c["status"], "unknown")
        self.assertIn("0 have a recorded", c["evidence"][0])
        both = {"support-bot": {"tools": ["ticket-lookup"]}, "sales-agent": {"mcp_servers": ["crm-mcp"]}}
        self.assertEqual(self.checks(links=both)["aisc-tools-recorded"]["status"], "pass")
        c = self.checks(links={"support-bot": {"tools": ["ticket-lookup"]}})["aisc-tools-recorded"]
        self.assertEqual(c["status"], "partial")
        self.assertEqual(c["score"], 0.5)

    def test_tool_concentration(self):
        self.reg(name="support-bot", kind="application")
        self.reg(name="sales-agent", kind="agent")
        c = self.checks()["aisc-tool-concentration"]
        self.assertEqual(c["status"], "unknown")
        shared = {"support-bot": {"tools": ["ticket-lookup"]}, "sales-agent": {"tools": ["ticket-lookup"]}}
        c = self.checks(links=shared)["aisc-tool-concentration"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("2 of 2", c["evidence"][0])
        split = {"support-bot": {"tools": ["ticket-lookup"]}, "sales-agent": {"tools": ["crm-lookup"]}}
        self.assertEqual(self.checks(links=split)["aisc-tool-concentration"]["status"], "pass")

    def test_mcp_governed(self):
        self.reg(name="support-bot", kind="application", can_take_actions=True)
        self.assertEqual(self.checks()["aisc-mcp-governed"]["status"], "unknown")
        self.reg(name="crm-mcp", kind="mcp-server", auth_required=True)
        self.assertEqual(self.checks()["aisc-mcp-governed"]["status"], "pass")
        self.reg(name="files-mcp", kind="mcp-server", auth_required=False, owner=None, last_reviewed=None)
        c = self.checks()["aisc-mcp-governed"]
        self.assertIn(c["status"], ("partial", "fail"))
        self.assertIn("1 of 2", c["evidence"][0])
        self.assertIn("1 without authentication", c["evidence"][1])

    def test_data_sources_owned(self):
        self.reg(name="support-bot", kind="application", uses_rag=True)
        c = self.checks()["aisc-data-sources-owned"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("1 systems retrieve", c["evidence"][0])
        self.reg(name="kb-index", kind="vector-db", data_classes=["proprietary"], auth_required=True)
        self.assertEqual(self.checks()["aisc-data-sources-owned"]["status"], "pass")
        self.reg(name="orphan-set", kind="dataset", owner=None)
        c = self.checks()["aisc-data-sources-owned"]
        self.assertIn(c["status"], ("partial", "fail"))
        self.assertIn("1 of 2", c["evidence"][0])

    def test_vector_store_access_and_retrieval(self):
        self.reg(name="support-bot", kind="application", uses_rag=True, rag_access_control=True)
        self.reg(name="kb-index", kind="vector-db", auth_required=True)
        res = self.checks()
        self.assertEqual(res["aisc-vector-store-access"]["status"], "pass")
        self.assertEqual(res["aisc-retrieval-access-control"]["status"], "pass")
        self.reg(name="open-index", kind="vector-db", auth_required=False)
        self.reg(name="docs-bot", kind="application", uses_rag=True, rag_access_control=False)
        res = self.checks()
        self.assertNotEqual(res["aisc-vector-store-access"]["status"], "pass")
        self.assertIn("1 of 2", res["aisc-vector-store-access"]["evidence"][0])
        self.assertNotEqual(res["aisc-retrieval-access-control"]["status"], "pass")

    def test_model_format_and_provenance(self):
        self.reg(name="m1", kind="model", serialization="safetensors", provenance="verified")
        res = self.checks()
        self.assertEqual((res["aisc-model-format"]["status"], res["aisc-model-provenance"]["status"]), ("pass", "pass"))
        self.reg(name="m2", kind="model", serialization="pickle", provenance="unverified")
        res = self.checks()
        self.assertNotEqual(res["aisc-model-format"]["status"], "pass")
        self.assertIn("1 of 2", res["aisc-model-format"]["evidence"][0])
        self.assertNotEqual(res["aisc-model-provenance"]["status"], "pass")

    def test_shadow_ai(self):
        self.reg(name="support-bot", kind="application")
        self.assertEqual(self.checks()["aisc-shadow-ai"]["status"], "unknown")
        aid = discovery.add_app("Acme Chat", "chat.acme-ai.test", engine=self.engine)
        c = self.checks()["aisc-shadow-ai"]
        self.assertIn(c["status"], ("partial", "fail"))
        self.assertIn("1 of 1", c["evidence"][0])
        discovery.set_status(aid, "blocked", engine=self.engine)
        self.assertEqual(self.checks()["aisc-shadow-ai"]["status"], "pass")

    def test_mlbom(self):
        self.reg(name="support-bot", kind="application")
        self.assertEqual(self.checks()["aisc-mlbom"]["status"], "unknown")  # no SBOM stored
        appsec_store.set_sbom("plain-app", bom({"type": "library", "name": "left-pad", "version": "1.0"}), "ci", "t", engine=self.engine)
        c = self.checks()["aisc-mlbom"]
        self.assertEqual(c["status"], "unknown")
        self.assertIn("1 SBOMs", c["evidence"][0])
        appsec_store.set_sbom("chat-app", bom({"type": "library", "name": "openai", "version": "1.0"}), "ci", "t", engine=self.engine)
        c = self.checks()["aisc-mlbom"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("0 of 1", c["evidence"][0])
        appsec_store.set_sbom("chat-app", bom({"type": "library", "name": "openai", "version": "1.0"}, {"type": "machine-learning-model", "name": "model-large", "version": "1"}),
                              "ci", "t", engine=self.engine)
        c = self.checks()["aisc-mlbom"]
        self.assertEqual(c["status"], "pass")
        self.assertIn("1 of 1", c["evidence"][0])

    def test_not_observable_checks(self):
        self.reg(name="support-bot", kind="application", provenance="verified")
        res = self.checks()
        for cid in ("aisc-model-signing", "aisc-weight-integrity", "aisc-vendor-assurance"):
            self.assertEqual(res[cid]["status"], "unknown", cid)
            self.assertTrue(res[cid]["recommendation"])

    def test_unreadable_graph_is_unknown(self):
        self.reg(name="support-bot", kind="application")
        with patch("remediation.graphs.ai.build", side_effect=RuntimeError("graph down")):
            c = self.checks()["aisc-model-recorded"]
        self.assertEqual(c["status"], "unknown")
        self.assertIn("graph down", c["evidence"][0])


class ShapeTests(Base):
    def seeded(self):
        self.reg(name="support-bot", kind="application", vendor_model="model-large", can_take_actions=True, uses_rag=True, rag_access_control=False)
        self.reg(name="sales-agent", kind="agent", can_take_actions=True, plugins_reviewed=False)
        self.reg(name="crm-mcp", kind="mcp-server", auth_required=False)
        self.reg(name="kb-index", kind="vector-db", auth_required=False)
        self.use("support-bot", "acme-ai")
        self.use("sales-agent", "acme-ai", "rogue-model", 2)
        discovery.add_app("Acme Chat", "chat.acme-ai.test", engine=self.engine)
        appsec_store.set_sbom("chat-app", bom({"type": "library", "name": "openai", "version": "1.0"}), "ci", "t", engine=self.engine)

    def test_shape_unique_ids_and_areas(self):
        self.seeded()
        res = aisc.run(self.ctx(links={"support-bot": {"tools": ["ticket-lookup"]}}))
        keys = {"id", "framework", "area", "title", "status", "score", "weight", "evidence", "detail", "recommendation", "change", "refs", "data_used"}
        ids = [c["id"] for c in res]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual({c["area"] for c in res}, {a for a, _ in aisc.FRAMEWORK["areas"]})
        self.assertEqual(len(res), 20)
        for c in res:
            self.assertEqual(set(c), keys)
            self.assertEqual(c["framework"], "ai-supply-chain")
            self.assertTrue(c["recommendation"], c["id"])
            self.assertTrue(c["evidence"], c["id"])
            if c["status"] in ("partial", "fail"):
                self.assertRegex(" ".join(c["evidence"]), r"\d", c["id"])

    def test_deterministic(self):
        self.seeded()
        self.assertEqual(aisc.run(self.ctx()), aisc.run(self.ctx()))

    def test_changes_name_real_settings(self):
        self.seeded()
        nav = (REPO_ROOT / "dashboard/static/js/nav.js").read_text(encoding="utf-8")
        seen = 0
        for c in aisc.run(self.ctx()):
            ch = c["change"]
            if not ch:
                continue
            seen += 1
            if ch["kind"] in ("yaml", "env"):
                self.assertIn(ch["key"], (REPO_ROOT / ch["where"]).read_text(encoding="utf-8"), c["id"])
            elif ch["kind"] == "page":
                self.assertIn(f'path: "{ch["where"]}"', nav, c["id"])
        self.assertGreater(seen, 8)


if __name__ == "__main__":
    unittest.main()
