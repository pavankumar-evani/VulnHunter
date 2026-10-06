"""Tests for the AI development lifecycle posture framework (remediation/posture/aidlc.py)."""
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
from remediation.aiusage import analytics, discovery, store as usage_store  # noqa: E402
from remediation.posture import aidlc, engine as posture_engine  # noqa: E402
from remediation.posture.model import Context  # noqa: E402
from remediation.utils import db as db_module  # noqa: E402

NOW = datetime.datetime(2026, 10, 6, tzinfo=datetime.timezone.utc)
ALLOWED = ["model-large", "model-small"]
OWNER = "pat.owner@corp.test"
GOOD = {"name": "support-bot", "kind": "application", "owner": OWNER, "environment": "production", "last_reviewed": "2026-10-01", "untrusted_input": True, "input_guardrails": True,
        "can_take_actions": True, "human_in_loop": True, "output_filtering": True, "rate_limited": True, "logging": True, "internet_facing": True, "auth_required": True,
        "downstream_trusts_output": False, "data_classes": ["pii"], "uses_rag": False}
BAD = {"name": "sales-agent", "kind": "agent", "environment": "production", "untrusted_input": True, "input_guardrails": False, "can_take_actions": True, "human_in_loop": False,
       "permissions_scope": "write", "output_filtering": False, "logging": False, "downstream_trusts_output": True, "plugins_reviewed": False, "data_classes": ["pii"], "internet_facing": True,
       "rate_limited": False}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'q.db'}")
        db_module.ensure_schema(self.engine)
        self.patches = [patch.object(rules, "approved_models", return_value=ALLOWED),
                        patch.object(analytics, "policy", return_value={"allowed_models": ALLOWED, "anomaly_factor": 3.0, "anomaly_min_tokens": 100000})]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def ctx(self, findings=None):
        c = Context(engine=self.engine, findings=findings, env={}, now=NOW)
        pol = posture_engine.policy()
        c.policy, c.thr = pol, pol["thresholds"]
        return c

    def run_checks(self, findings=None):
        return {c["id"]: c for c in aidlc.run(self.ctx(findings))}

    def reg(self, **kw):
        return aisec_store.save(kw, "t", engine=self.engine)

    def usage(self, model, n=1):
        usage_store.record([{"ts": "2026-10-01T10:00:00Z", "model": model, "provider": "acme-ai", "application": "support-bot", "request_count": n, "input_tokens": 100, "output_tokens": 50}], "api", engine=self.engine)


class NoAiTests(Base):
    def test_empty_estate_has_no_pass(self):
        res = self.run_checks()
        self.assertTrue(res)
        for c in res.values():
            self.assertIn(c["status"], ("unknown", "na"), c["id"])
            self.assertIsNone(c["score"])


class CheckTests(Base):
    def test_owner(self):
        self.reg(**GOOD)
        self.assertEqual(self.run_checks()["aidlc-owner"]["status"], "pass")
        self.reg(**BAD)
        c = self.run_checks()["aidlc-owner"]
        self.assertIn(c["status"], ("partial", "fail"))
        self.assertIn("1 of 2", c["evidence"][0])
        self.assertIn("sales-agent", c["evidence"][1])

    def test_excessive_agency(self):
        self.reg(**GOOD)
        self.assertEqual(self.run_checks()["aidlc-excessive-agency"]["status"], "pass")
        self.reg(**BAD)
        c = self.run_checks()["aidlc-excessive-agency"]
        self.assertIn(c["status"], ("partial", "fail"))
        self.assertIn("1 of 2", c["evidence"][0])
        self.assertEqual(c["change"]["kind"], "page")

    def test_prompt_injection_and_output_handling(self):
        self.reg(**GOOD)
        res = self.run_checks()
        self.assertEqual(res["aidlc-prompt-injection"]["status"], "pass")
        self.assertEqual(res["aidlc-output-handling"]["status"], "pass")
        self.reg(**BAD)
        res = self.run_checks()
        self.assertIn(res["aidlc-prompt-injection"]["status"], ("partial", "fail"))
        self.assertIn("1 of 2", res["aidlc-prompt-injection"]["evidence"][0])
        self.assertIn(res["aidlc-output-handling"]["status"], ("partial", "fail"))

    def test_unanswered_is_not_a_pass(self):
        self.reg(name="quiet-bot", kind="application", owner=OWNER)
        res = self.run_checks()
        self.assertEqual(res["aidlc-prompt-injection"]["status"], "unknown")
        self.assertEqual(res["aidlc-excessive-agency"]["status"], "unknown")
        self.assertNotEqual(res["aidlc-questions-answered"]["status"], "pass")

    def test_audit_logging_and_rate_limits(self):
        self.reg(**GOOD)
        res = self.run_checks()
        self.assertEqual((res["aidlc-audit-logging"]["status"], res["aidlc-rate-limits"]["status"]), ("pass", "pass"))
        self.reg(**BAD)
        res = self.run_checks()
        self.assertNotEqual(res["aidlc-audit-logging"]["status"], "pass")
        self.assertNotEqual(res["aidlc-rate-limits"]["status"], "pass")

    def test_approved_models(self):
        self.reg(**GOOD)
        self.usage("model-large", 40)
        c = self.run_checks()["aidlc-approved-models"]
        self.assertEqual(c["status"], "pass")
        self.assertIn("40", c["evidence"][0])
        self.usage("rogue-model", 60)
        c = self.run_checks()["aidlc-approved-models"]
        self.assertIn(c["status"], ("partial", "fail"))
        self.assertIn("60 of 100", c["evidence"][0])
        self.assertEqual(c["change"]["key"], "allowed_models")

    def test_approved_models_unknown_without_list(self):
        self.reg(**GOOD)
        self.usage("model-large")
        with patch.object(analytics, "policy", return_value={}):
            self.assertEqual(self.run_checks()["aidlc-approved-models"]["status"], "unknown")

    def test_budgets(self):
        self.reg(**GOOD)
        self.usage("model-large", 5)
        c = self.run_checks()["aidlc-budgets"]
        self.assertEqual(c["status"], "fail")
        self.assertIn("0 budgets", c["evidence"][0])
        analytics.add_budget("org", None, "month", 1000, None, 80, "t", engine=self.engine)
        self.assertEqual(self.run_checks()["aidlc-budgets"]["status"], "pass")

    def test_shadow_ai(self):
        self.reg(**GOOD)
        self.assertEqual(self.run_checks()["aidlc-shadow-ai"]["status"], "unknown")  # nothing uploaded is not a pass
        aid = discovery.add_app("Acme Chat", "chat.acme-ai.test", engine=self.engine)
        c = self.run_checks()["aidlc-shadow-ai"]
        self.assertIn(c["status"], ("partial", "fail"))
        self.assertIn("1 of 1", c["evidence"][0])
        discovery.set_status(aid, "sanctioned", owner=OWNER, engine=self.engine)
        self.assertEqual(self.run_checks()["aidlc-shadow-ai"]["status"], "pass")

    def test_ai_findings_age(self):
        self.reg(**GOOD)
        asset = {"name": "support-bot", "type": "ai-ml-system"}
        fresh = [{"id": "F1", "severity": "High", "first_seen": "2026-10-01", "asset": asset}]
        old = [{"id": "F2", "severity": "Critical", "first_seen": "2026-07-01", "asset": asset}]
        self.assertEqual(self.run_checks()["aidlc-ai-findings-age"]["status"], "unknown")
        self.assertEqual(self.run_checks(fresh)["aidlc-ai-findings-age"]["status"], "pass")
        c = self.run_checks(fresh + old)["aidlc-ai-findings-age"]
        self.assertIn(c["status"], ("partial", "fail"))
        self.assertIn("1 of 2", c["evidence"][0])

    def test_register_severe(self):
        self.reg(**GOOD)
        self.reg(**BAD)
        c = self.run_checks()["aidlc-register-severe"]
        self.assertIn(c["status"], ("partial", "fail"))
        self.assertRegex(c["evidence"][0], r"\d+ Critical or High")

    def test_not_observable_checks(self):
        self.reg(**GOOD)
        res = self.run_checks()
        for cid in ("aidlc-data-provenance-evidence", "aidlc-evaluation-evidence", "aidlc-red-team-evidence"):
            self.assertEqual(res[cid]["status"], "unknown", cid)
            self.assertTrue(res[cid]["recommendation"])

    def test_unreadable_register_is_unknown(self):
        with patch.object(aisec_store, "list_all", side_effect=RuntimeError("db down")):
            res = self.run_checks()
        self.assertEqual(res["aidlc-prompt-injection"]["status"], "na")  # nothing else shows AI, so nothing applies
        findings = [{"id": "F", "severity": "High", "asset": {"name": "x", "type": "ai-ml-system"}}]
        with patch.object(aisec_store, "list_all", side_effect=RuntimeError("db down")):
            res = self.run_checks(findings)
        self.assertEqual(res["aidlc-prompt-injection"]["status"], "unknown")
        self.assertIn("db down", res["aidlc-prompt-injection"]["evidence"][0])


class ShapeTests(Base):
    def seeded(self):
        self.reg(**GOOD)
        self.reg(**BAD)
        self.usage("model-large", 10)
        self.usage("rogue-model", 5)
        discovery.add_app("Acme Chat", "chat.acme-ai.test", engine=self.engine)

    def test_shape_unique_ids_and_areas(self):
        self.seeded()
        res = aidlc.run(self.ctx())
        keys = {"id", "framework", "area", "title", "status", "score", "weight", "evidence", "detail", "recommendation", "change", "refs", "data_used"}
        ids = [c["id"] for c in res]
        self.assertEqual(len(ids), len(set(ids)))
        areas = {a for a, _ in aidlc.FRAMEWORK["areas"]}
        self.assertEqual({c["area"] for c in res}, areas)
        for c in res:
            self.assertEqual(set(c), keys)
            self.assertEqual(c["framework"], "aidlc")
            self.assertTrue(c["recommendation"], c["id"])
            self.assertTrue(c["evidence"], c["id"])
            if c["status"] in ("partial", "fail") and c["id"] not in ("aidlc-owner",):
                self.assertRegex(" ".join(c["evidence"]), r"\d", c["id"])
        self.assertEqual(len(res), 30)

    def test_deterministic(self):
        self.seeded()
        self.assertEqual(aidlc.run(self.ctx()), aidlc.run(self.ctx()))

    def test_changes_name_real_settings(self):
        self.seeded()
        nav = (REPO_ROOT / "dashboard/static/js/nav.js").read_text(encoding="utf-8")
        seen = 0
        for c in aidlc.run(self.ctx()):
            ch = c["change"]
            if not ch:
                continue
            seen += 1
            if ch["kind"] in ("yaml", "env"):
                text = (REPO_ROOT / ch["where"]).read_text(encoding="utf-8")
                self.assertIn(ch["key"], text, c["id"])
            elif ch["kind"] == "page":
                self.assertIn(f'path: "{ch["where"]}"', nav, c["id"])
        self.assertGreater(seen, 10)


if __name__ == "__main__":
    unittest.main()
