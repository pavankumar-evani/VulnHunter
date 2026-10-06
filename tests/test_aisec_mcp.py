"""Tests for the agent, MCP and AI-lifecycle rules, the new register fields, the migration, the posture checks and the graph."""
import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine, insert, select

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.aisec import rules, rules_mcp, store  # noqa: E402
from remediation.aiusage import analytics  # noqa: E402
from remediation.graphs import ai as ai_graph  # noqa: E402
from remediation.posture import ai_supply_chain as aisc, aidlc, engine as posture_engine  # noqa: E402
from remediation.posture.model import Context  # noqa: E402
from remediation.utils import db as db_module, migrations  # noqa: E402

TODAY = datetime.date(2026, 10, 6)
NOW = datetime.datetime(2026, 10, 6, tzinfo=datetime.timezone.utc)
CFG = dict(rules_mcp.DEFAULTS)


def asset(**kw):
    base = {"id": 1, "name": "agent-1", "kind": "agent", "environment": "production"}
    base.update(kw)
    return base


def tool(name="t", **kw):
    return {"name": name, "side_effect": None, "requires_approval": None, "category": None, "server": None, "reads": [], **kw}


def server(name="srv", **kw):
    base = {"name": name, "transport": None, "auth": None, "tool_count": None}
    base.update({k: None for k in rules_mcp.SERVER_TRI})
    base.update(kw)
    return base


def fire(a, **cfg):
    return [f for f in rules_mcp.evaluate(a, TODAY, {**CFG, **cfg})]


def ids(a, **cfg):
    return {f["rule"] for f in fire(a, **cfg)}


def titles(a, rule):
    return [f["title"] for f in fire(a) if f["rule"] == rule]


class McpControlTests(unittest.TestCase):
    def test_nothing_recorded_raises_nothing(self):
        self.assertEqual(fire(asset()), [])

    def test_authentication(self):
        self.assertIn("MCP001", ids(asset(mcp_servers=[server(transport="http", auth="none")])))
        self.assertEqual(fire(asset(mcp_servers=[server(transport="http", auth="none")]))[0]["severity"], "High")
        self.assertNotIn("MCP001", ids(asset(mcp_servers=[server(transport="stdio", auth="none")])))         # local process, not remote
        self.assertNotIn("MCP001", ids(asset(mcp_servers=[server(transport="http", auth="oauth2.1", token_audience_validated=True)])))
        self.assertNotIn("MCP001", ids(asset(mcp_servers=[server(transport="http", auth="mtls")])))
        self.assertNotIn("MCP001", ids(asset(mcp_servers=[server(transport="http", auth=None)])))             # unanswered is a gap, not a finding
        self.assertIn("MCP001", ids(asset(mcp_servers=[server(transport="http", auth="oauth2.1", token_audience_validated=False)])))
        self.assertNotIn("MCP001", ids(asset(mcp_servers=[server(transport="http", auth="oauth2.1", token_audience_validated=None)])))
        keyed = fire(asset(mcp_servers=[server(transport="http", auth="api-key")]))
        self.assertEqual(keyed[0]["severity"], "Medium")

    def test_per_tool_authorization(self):
        self.assertIn("MCP002", ids(asset(mcp_servers=[server(per_tool_authorization=False)])))
        self.assertNotIn("MCP002", ids(asset(mcp_servers=[server(per_tool_authorization=True)])))
        self.assertNotIn("MCP002", ids(asset(mcp_servers=[server(per_tool_authorization=None)])))
        write = asset(mcp_servers=[server(per_tool_authorization=False)], tools=[tool(side_effect="write", requires_approval=True)])
        self.assertEqual([f["severity"] for f in fire(write) if f["rule"] == "MCP002"], ["High"])
        self.assertEqual([f["severity"] for f in fire(asset(mcp_servers=[server(per_tool_authorization=False)])) if f["rule"] == "MCP002"], ["Medium"])

    def test_tool_scoping_count_and_allowlist(self):
        many = asset(mcp_servers=[server(tool_count=11)])
        self.assertIn("MCP003", ids(many))
        self.assertNotIn("MCP003", ids(asset(mcp_servers=[server(tool_count=10)])))
        self.assertNotIn("MCP003", ids(many, max_exposed_tools=20))                                          # threshold comes from the config
        by_tools = asset(mcp_servers=[server()], tools=[tool(f"t{i}") for i in range(12)])
        self.assertIn("MCP003", ids(by_tools))
        danger = asset(mcp_servers=[server(allowlisted_tools=False)], tools=[tool(side_effect="destructive", requires_approval=True)])
        self.assertEqual([f["severity"] for f in fire(danger) if f["rule"] == "MCP003"], ["High"])
        self.assertNotIn("MCP003", ids(asset(mcp_servers=[server(allowlisted_tools=False)], tools=[tool(side_effect="read")])))
        self.assertNotIn("MCP003", ids(asset(mcp_servers=[server(allowlisted_tools=None)], tools=[tool(side_effect="destructive", requires_approval=True)])))

    def test_sandboxing(self):
        shell = asset(mcp_servers=[server(sandboxed=False)], tools=[tool("run_shell", category="shell")])
        self.assertIn("MCP004", ids(shell))
        self.assertIn("MCP004", ids(asset(mcp_servers=[server(transport="stdio", sandboxed=False)])))      # a local process runs with the user's rights
        self.assertIn("MCP004", ids(asset(mcp_servers=[server(sandboxed=True, egress_restricted=False)], tools=[tool("code_interpreter")])))  # by name keyword
        self.assertNotIn("MCP004", ids(asset(mcp_servers=[server(sandboxed=True, egress_restricted=False)], tools=[tool("lookup", category="database")])))
        self.assertNotIn("MCP004", ids(asset(mcp_servers=[server(sandboxed=True, egress_restricted=True)], tools=[tool("run_shell", category="shell")])))
        self.assertNotIn("MCP004", ids(asset(mcp_servers=[server(sandboxed=None)], tools=[tool("run_shell", category="shell")])))
        self.assertNotIn("MCP004", ids(asset(mcp_servers=[server(sandboxed=False, transport="http")], tools=[tool("lookup", category="database")])))

    def test_secrets_handling(self):
        self.assertIn("MCP005", ids(asset(mcp_servers=[server(secrets_mounted=False)])))
        self.assertNotIn("MCP005", ids(asset(mcp_servers=[server(secrets_mounted=True)])))
        self.assertNotIn("MCP005", ids(asset(mcp_servers=[server(secrets_mounted=None)])))

    def test_auditing(self):
        t = [tool(side_effect="write", requires_approval=True)]
        self.assertIn("MCP006", ids(asset(tools=t, audit_log={"immutable": False, "redacts_secrets": True})))
        self.assertEqual([f["severity"] for f in fire(asset(tools=t, audit_log={"immutable": False})) if f["rule"] == "MCP006"], ["High"])
        self.assertIn("MCP007", ids(asset(tools=t, audit_log={"immutable": True, "redacts_secrets": False})))
        self.assertEqual(ids(asset(tools=t, audit_log={"immutable": True, "redacts_secrets": True})), set())
        self.assertEqual(ids(asset(tools=t, audit_log={"immutable": None, "redacts_secrets": None})), set())
        self.assertNotIn("MCP006", ids(asset(audit_log={"immutable": False})))                                # nothing to audit recorded

    def test_human_approval(self):
        for effect in ("write", "external-send", "destructive", "financial"):
            self.assertIn("MCP008", ids(asset(tools=[tool(side_effect=effect, requires_approval=False)])), effect)
        self.assertNotIn("MCP008", ids(asset(tools=[tool(side_effect="read", requires_approval=False)])))
        self.assertNotIn("MCP008", ids(asset(tools=[tool(side_effect="write", requires_approval=True)])))
        self.assertNotIn("MCP008", ids(asset(tools=[tool(side_effect="write", requires_approval=None)])))    # unanswered
        self.assertEqual(fire(asset(tools=[tool(side_effect="write", requires_approval=False)]))[0]["severity"], "High")
        self.assertEqual(fire(asset(tools=[tool(side_effect="financial", requires_approval=False)]))[0]["severity"], "Critical")


class AgentHarnessTests(unittest.TestCase):
    def test_unbounded_loop(self):
        self.assertIn("AGT001", ids(asset(max_steps=0, budget_cap=False)))
        self.assertEqual([f["severity"] for f in fire(asset(max_steps=0, budget_cap=False))], ["High"])
        self.assertEqual([f["severity"] for f in fire(asset(max_steps=0, budget_cap=None))], ["Medium"])
        self.assertNotIn("AGT001", ids(asset(max_steps=0, budget_cap=True)))
        self.assertNotIn("AGT001", ids(asset(max_steps=20, budget_cap=False)))
        self.assertNotIn("AGT001", ids(asset(max_steps=None, budget_cap=None)))                              # unanswered
        self.assertEqual([f["severity"] for f in fire(asset(max_steps=500, budget_cap=True))], ["Low"])
        self.assertNotIn("AGT001", ids(asset(kind="model", max_steps=0, budget_cap=False)))

    def test_persistent_memory(self):
        self.assertIn("AGT002", ids(asset(memory="persistent", memory_provenance=False)))
        self.assertIn("AGT002", ids(asset(memory="persistent", memory_poisoning_controls=False)))
        self.assertNotIn("AGT002", ids(asset(memory="persistent", memory_provenance=True, memory_poisoning_controls=True)))
        self.assertNotIn("AGT002", ids(asset(memory="persistent")))
        self.assertNotIn("AGT002", ids(asset(memory="session", memory_provenance=False)))
        self.assertEqual([f["severity"] for f in fire(asset(memory="persistent", memory_provenance=False, can_take_actions=True))], ["High"])

    def test_untrusted_content_to_side_effect_tool(self):
        """The key rule: content from outside reaches an agent whose side-effect tool needs no approval."""
        t = [tool("send_email", side_effect="external-send", requires_approval=False)]
        for trigger in ({"untrusted_input": True}, {"uses_rag": True}, {"data_sources": [{"name": "inbox", "trusted": False}]}):
            self.assertIn("AGT003", ids(asset(tools=t, **trigger)), trigger)
        f = [x for x in fire(asset(tools=t, untrusted_input=True, data_classes=["pii"])) if x["rule"] == "AGT003"][0]
        self.assertEqual(f["severity"], "Critical")
        self.assertIn("data-theft", f["why"])
        self.assertIn("requires_approval", f["fix"])
        self.assertEqual([x["severity"] for x in fire(asset(tools=[tool(side_effect="write", requires_approval=False)], untrusted_input=True)) if x["rule"] == "AGT003"], ["High"])
        self.assertNotIn("AGT003", ids(asset(tools=[tool(side_effect="external-send", requires_approval=True)], untrusted_input=True)))   # approval closes it
        self.assertNotIn("AGT003", ids(asset(tools=t, untrusted_input=False, uses_rag=False)))                # no untrusted content recorded
        self.assertNotIn("AGT003", ids(asset(tools=t)))
        self.assertNotIn("AGT003", ids(asset(tools=[tool(side_effect="external-send", requires_approval=None)], untrusted_input=True)))   # gap, not a finding
        self.assertNotIn("AGT003", ids(asset(tools=[tool(side_effect="read", requires_approval=False)], untrusted_input=True)))

    def test_observability(self):
        self.assertIn("AGT004", ids(asset(observability={"traces": False})))
        self.assertEqual([f["severity"] for f in fire(asset(observability={"cost": False}))], ["Medium"])
        self.assertEqual([f["severity"] for f in fire(asset(environment="staging", observability={"cost": False}))], ["Low"])
        self.assertNotIn("AGT004", ids(asset(observability={"traces": True, "cost": True, "latency": True, "tool_failures": True})))
        self.assertNotIn("AGT004", ids(asset(observability={"traces": None})))


class LifecycleTests(unittest.TestCase):
    def test_each_rule_positive_and_negative(self):
        self.assertIn("AIDLC001", ids(asset(prompt_versioning=False)))
        self.assertNotIn("AIDLC001", ids(asset(prompt_versioning=True)))
        self.assertNotIn("AIDLC001", ids(asset(prompt_versioning=None)))
        self.assertIn("AIDLC002", ids(asset(eval_suite="none")))
        for ok in ("offline", "online", "both", None):
            self.assertNotIn("AIDLC002", ids(asset(eval_suite=ok)), ok)
        self.assertEqual([f["severity"] for f in fire(asset(eval_suite="none", can_take_actions=True))], ["High"])
        self.assertEqual([f["severity"] for f in fire(asset(eval_suite="none", environment="development"))], ["Medium"])
        self.assertIn("AIDLC003", ids(asset(release={"rollback_path": False})))
        self.assertNotIn("AIDLC003", ids(asset(release={"rollback_path": True})))
        self.assertNotIn("AIDLC003", ids(asset(release={"rollback_path": None})))
        self.assertIn("AIDLC004", ids(asset(release={"canary": False, "shadow": False})))
        self.assertNotIn("AIDLC004", ids(asset(release={"canary": False, "shadow": True})))
        self.assertNotIn("AIDLC004", ids(asset(release={"canary": False, "shadow": None})))                  # one answer missing: not proven big-bang
        self.assertNotIn("AIDLC001", ids(asset(kind="vector-db", prompt_versioning=False)))

    def test_every_finding_explains_and_names_the_fix(self):
        a = asset(tools=[tool("send", side_effect="financial", requires_approval=False), tool("run", category="shell", requires_approval=True)], untrusted_input=True, max_steps=0, budget_cap=False, memory="persistent", memory_provenance=False,
                  prompt_versioning=False, eval_suite="none", release={"rollback_path": False, "canary": False, "shadow": False}, observability={"traces": False},
                  audit_log={"immutable": False, "redacts_secrets": False},
                  mcp_servers=[server(transport="http", auth="none", per_tool_authorization=False, secrets_mounted=False, sandboxed=False)])
        found = fire(a)
        self.assertEqual({f["rule"] for f in found}, {"MCP001", "MCP002", "MCP004", "MCP005", "MCP006", "MCP007", "MCP008", "AGT001", "AGT002", "AGT003", "AGT004", "AIDLC001", "AIDLC002", "AIDLC003", "AIDLC004"})
        for f in found:
            self.assertGreater(len(f["why"]), 40, f["rule"])
            self.assertGreater(len(f["fix"]), 40, f["rule"])
            self.assertTrue(f["owasp"] and f["atlas"].startswith("AML.T"), f["rule"])

    def test_config_file_is_valid_and_has_every_default(self):
        cfg = rules_mcp.config()
        self.assertEqual(set(cfg), set(rules_mcp.DEFAULTS))
        self.assertEqual(cfg["max_exposed_tools"], 10)


class UnansweredTests(unittest.TestCase):
    def test_gaps_listed_only_for_what_is_described(self):
        self.assertEqual(rules_mcp.unanswered(asset()), [])
        gaps = dict(rules_mcp.unanswered(asset(mcp_servers=[server("crm", transport="http")], tools=[tool("send")])))
        self.assertIn("mcp_servers.crm.auth", gaps)
        self.assertIn("mcp_servers.crm.sandboxed", gaps)
        self.assertNotIn("mcp_servers.crm.token_audience_validated", gaps)                                    # only asked of OAuth servers
        self.assertIn("tools.send.requires_approval", gaps)
        self.assertIn("audit_log.immutable", gaps)
        self.assertIn("max_steps", gaps)
        oauth = dict(rules_mcp.unanswered(asset(mcp_servers=[server("crm", transport="http", auth="oauth2.1")])))
        self.assertIn("mcp_servers.crm.token_audience_validated", oauth)

    def test_answered_questions_leave_the_list(self):
        full = server("crm", transport="stdio", auth="none", **{k: True for k in rules_mcp.SERVER_TRI})
        a = asset(mcp_servers=[full], audit_log={"immutable": True, "redacts_secrets": True}, max_steps=10, budget_cap=True)
        self.assertEqual(rules_mcp.unanswered(a), [])

    def test_rules_unanswered_includes_the_new_gaps(self):
        a = asset(mcp_servers=[server("crm")])
        self.assertTrue(any(f.startswith("mcp_servers.crm") for f, _ in rules.unanswered(a)))

    def test_evaluate_includes_the_new_rules(self):
        a = {**asset(tools=[tool(side_effect="write", requires_approval=False)]), "owner": "a@b.test", "last_reviewed": "2026-10-01", "logging": True}
        self.assertIn("MCP008", {f["rule"] for f in rules.evaluate(a, TODAY, [])})


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp.name) / 'q.db'}")
        db_module.ensure_schema(self.engine)
        self.patches = [patch.object(rules, "approved_models", return_value=[]), patch.object(analytics, "policy", return_value={})]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def save(self, **kw):
        kw.setdefault("name", "agent-1")
        kw.setdefault("kind", "agent")
        return store.save(kw, "test", engine=self.engine)


class StoreTests(Base):
    def test_new_fields_round_trip_and_default_to_unknown(self):
        plain = self.save(name="plain")
        self.assertEqual((plain["tools"], plain["mcp_servers"], plain["memory"], plain["audit_log"], plain["max_steps"]), ([], [], None, {"immutable": None, "redacts_secrets": None}, None))
        a = self.save(provider="acme", model_ids=["m1", "m1", "m2"], memory="persistent", max_steps=12, prompt_versioning=True, eval_suite="both",
                      tools=[{"name": "send", "side_effect": "external-send", "requires_approval": False, "server": "crm", "reads": ["kb"]}],
                      mcp_servers=[{"name": "crm", "transport": "http", "auth": "oauth2.1", "token_audience_validated": True}],
                      data_sources=["kb", {"name": "inbox", "trusted": False}], release={"canary": True}, audit_log={"immutable": True})
        got = store.get(a["id"], self.engine)
        self.assertEqual(got["model_ids"], ["m1", "m2"])
        self.assertEqual(got["tools"][0]["server"], "crm")
        self.assertIsNone(got["mcp_servers"][0]["sandboxed"])
        self.assertEqual(got["data_sources"], [{"name": "kb", "trusted": None}, {"name": "inbox", "trusted": False}])
        self.assertEqual(got["release"], {"rollback_path": None, "canary": True, "shadow": None})

    def test_validation(self):
        bad = ({"tools": [{"name": "x", "side_effect": "explode"}]}, {"tools": [{"name": ""}]}, {"tools": [{"name": "a"}, {"name": "A"}]}, {"mcp_servers": [{"name": "s", "transport": "udp"}]},
               {"mcp_servers": [{"name": "s", "auth": "magic"}]}, {"mcp_servers": [{"name": "s", "sandboxed": "yes"}]}, {"memory": "forever"}, {"eval_suite": "sometimes"}, {"max_steps": -1},
               {"max_steps": "ten"}, {"release": {"canary": "maybe"}}, {"audit_log": "x"}, {"tools": "send"}, {"tools": [{"name": f"t{i}"} for i in range(101)]})
        for body in bad:
            with self.assertRaises(ValueError, msg=str(body)[:60]):
                self.save(name="v", **body)

    def test_old_clients_that_send_none_of_the_new_fields_still_work(self):
        a = self.save(name="legacy", kind="application", owner="o@x.test", untrusted_input=True, input_guardrails=False)
        self.assertEqual([f["rule"] for f in store.assess([a], TODAY, [])["findings"] if f["rule"] in ("LLM01",)], ["LLM01"])

    def test_assess_lists_new_gaps_and_findings(self):
        a = self.save(tools=[{"name": "send", "side_effect": "write", "requires_approval": False}], untrusted_input=True)
        res = store.assess([a], TODAY, [])
        self.assertIn("MCP008", res["by_rule"])
        self.assertIn("AGT003", res["by_rule"])
        self.assertTrue(any(u["field"] == "audit_log.immutable" for x in res["assets"] for u in x["unanswered"]))
        items = store.to_queue_items([f for f in res["findings"] if f["rule"] == "AGT003"])
        self.assertIn("LLM01", items[0]["description"])


class MigrationTests(Base):
    def test_backfill_is_expand_only_and_idempotent(self):
        t = db_module.ai_assets
        old = {"name": "old", "kind": "application", "owner": "keep@x.test", "untrusted_input": True, "data_classes": ["pii"]}
        with self.engine.begin() as conn:
            conn.execute(insert(t), {"name": "old", "kind": "application", "data_json": json.dumps(old), "created_at": "x", "updated_at": "x", "updated_by": "t"})
        self.assertEqual(store.backfill_new_fields(self.engine), 1)
        with self.engine.connect() as conn:
            raw = json.loads(conn.execute(select(t.c.data_json)).scalar())
        self.assertEqual({k: raw[k] for k in old}, old)                                                       # nothing existing changed
        self.assertEqual(raw["tools"], [])
        self.assertIsNone(raw["memory"])
        self.assertEqual(store.backfill_new_fields(self.engine), 0)                                           # second run changes nothing
        self.assertEqual(store.get(1, self.engine)["owner"], "keep@x.test")

    def test_backfill_does_not_overwrite_recorded_values(self):
        a = self.save(name="kept", tools=[{"name": "send", "side_effect": "read"}])
        store.backfill_new_fields(self.engine)
        self.assertEqual(store.get(a["id"], self.engine)["tools"][0]["name"], "send")

    def test_registered_migration_runs_once_and_twice(self):
        self.assertIn("ai_asset_agent_mcp_lifecycle_fields", [n for _, n, _ in migrations.MIGRATIONS])
        migrations.apply(self.engine)
        self.assertEqual(migrations.pending(self.engine), [])
        migrations._m007_ai_asset_agent_fields(self.engine)                                                   # re-running by hand is safe
        migrations.apply(self.engine)


class PostureTests(Base):
    def run_fw(self, module):
        ctx = Context(engine=self.engine, findings=[], env={}, now=NOW)
        pol = posture_engine.policy()
        ctx.policy, ctx.thr = pol, pol["thresholds"]
        return {c["id"]: c for c in module.run(ctx)}

    NEW_AIDLC = ("memory-controls", "agent-loop-limits", "prompt-versioning", "eval-suite", "rollback-path", "progressive-rollout", "agent-observability")
    NEW_AISC = ("mcp-auth", "tool-approval", "mcp-isolation", "audit-integrity")

    def test_weights_are_in_range_and_ids_unique(self):
        self.save()
        a, b = self.run_fw(aidlc), self.run_fw(aisc)
        for cid in self.NEW_AIDLC:
            self.assertIn(f"aidlc-{cid}", a)
        for cid in self.NEW_AISC:
            self.assertIn(f"aisc-{cid}", b)
        for c in list(a.values()) + list(b.values()):
            self.assertTrue(1 <= c["weight"] <= 5)

    def test_unknown_when_the_register_has_no_data_never_pass(self):
        self.save(name="bare", environment="production")                                                      # a system, none of the new fields answered
        a, b = self.run_fw(aidlc), self.run_fw(aisc)
        for cid in ("prompt-versioning", "eval-suite", "rollback-path", "progressive-rollout"):
            self.assertEqual(a[f"aidlc-{cid}"]["status"], "unknown", cid)
        for cid in ("agent-loop-limits", "agent-observability"):
            self.assertEqual(a[f"aidlc-{cid}"]["status"], "unknown", cid)
        for cid in self.NEW_AISC:
            self.assertEqual(b[f"aisc-{cid}"]["status"], "unknown", cid)
            self.assertIsNone(b[f"aisc-{cid}"]["score"])

    def test_not_applicable_with_nothing_recorded_at_all(self):
        a, b = self.run_fw(aidlc), self.run_fw(aisc)
        self.assertEqual(a["aidlc-eval-suite"]["status"], "na")
        self.assertEqual(b["aisc-mcp-auth"]["status"], "na")

    def test_checks_pass_and_fail_on_recorded_answers(self):
        self.save(name="good", environment="production", prompt_versioning=True, eval_suite="both", release={"rollback_path": True, "canary": True, "shadow": False},
                  observability={"traces": True, "cost": True, "latency": True, "tool_failures": True}, max_steps=10, memory="persistent", memory_provenance=True, memory_poisoning_controls=True,
                  tools=[{"name": "send", "side_effect": "write", "requires_approval": True}], audit_log={"immutable": True, "redacts_secrets": True},
                  mcp_servers=[{"name": "crm", "transport": "http", "auth": "oauth2.1", "token_audience_validated": True, "sandboxed": True, "egress_restricted": True}])
        a, b = self.run_fw(aidlc), self.run_fw(aisc)
        for cid in self.NEW_AIDLC:
            self.assertEqual(a[f"aidlc-{cid}"]["status"], "pass", cid)
        for cid in self.NEW_AISC:
            self.assertEqual(b[f"aisc-{cid}"]["status"], "pass", cid)
        self.save(name="bad", environment="production", prompt_versioning=False, eval_suite="none", release={"rollback_path": False, "canary": False, "shadow": False},
                  observability={"traces": False}, max_steps=0, budget_cap=False, memory="persistent", memory_provenance=False,
                  tools=[{"name": "pay", "side_effect": "financial", "requires_approval": False}], audit_log={"immutable": False},
                  mcp_servers=[{"name": "open", "transport": "http", "auth": "none", "sandboxed": False}])
        a, b = self.run_fw(aidlc), self.run_fw(aisc)
        for cid in self.NEW_AIDLC:
            self.assertIn(a[f"aidlc-{cid}"]["status"], ("partial", "fail"), cid)
            self.assertLess(a[f"aidlc-{cid}"]["score"] if a[f"aidlc-{cid}"]["score"] is not None else 0.0, 1.0)
        for cid in self.NEW_AISC:
            self.assertIn(b[f"aisc-{cid}"]["status"], ("partial", "fail"), cid)

    def test_mcp_auth_needs_the_audience_answered_before_it_passes(self):
        a = self.save(mcp_servers=[{"name": "crm", "transport": "http", "auth": "oauth2.1"}])
        self.assertEqual(self.run_fw(aisc)["aisc-mcp-auth"]["status"], "unknown")                             # oauth chosen, audience unanswered
        store.save({"name": "agent-1", "kind": "agent", "mcp_servers": [{"name": "crm", "transport": "http", "auth": "oauth2.1", "token_audience_validated": False}]}, "t", asset_id=a["id"], engine=self.engine)
        self.assertEqual(self.run_fw(aisc)["aisc-mcp-auth"]["status"], "fail")

    def test_full_assessment_still_scores(self):
        self.save(eval_suite="both")
        res = posture_engine.assess(engine=self.engine, findings=[], env={}, now=NOW)
        fw = {f["id"]: f for f in res["frameworks"]}
        self.assertTrue({"aidlc", "ai-supply-chain"} <= set(fw))


class GraphTests(Base):
    def test_tools_servers_and_the_untrusted_path(self):
        self.save(name="mail-agent", untrusted_input=True, vendor_model="m1",
                  tools=[{"name": "send_email", "side_effect": "external-send", "requires_approval": False, "server": "mail-mcp", "reads": ["contacts"]},
                         {"name": "search", "side_effect": "read", "requires_approval": True}],
                  mcp_servers=[{"name": "mail-mcp", "transport": "http", "auth": "none"}], data_sources=[{"name": "inbox", "trusted": False}])
        g = ai_graph.build(self.engine, None, today=TODAY)
        nodes = {n["id"]: n for n in g["nodes"]}
        edges = {(e["source"], e["target"], e["kind"]) for e in g["edges"]}
        for nid in ("system:mail-agent", "tool:send_email", "tool:search", "mcp-server:mail-mcp", "data-source:inbox", "data-source:contacts"):
            self.assertIn(nid, nodes)
        self.assertIn(("system:mail-agent", "tool:send_email", "can_call"), edges)
        self.assertIn(("tool:send_email", "mcp-server:mail-mcp", "served_by"), edges)
        self.assertIn(("tool:send_email", "data-source:contacts", "reads"), edges)
        self.assertIn(("system:mail-agent", "data-source:inbox", "reads"), edges)
        self.assertEqual(nodes["tool:send_email"]["sev"], "critical")
        self.assertTrue(nodes["tool:send_email"]["meta"]["untrusted_path"])
        self.assertTrue(nodes["system:mail-agent"]["meta"]["untrusted_path"])
        self.assertIsNone(nodes["tool:search"]["sev"])
        self.assertEqual(nodes["mcp-server:mail-mcp"]["sev"], "high")
        self.assertFalse(nodes["data-source:inbox"]["meta"]["trusted"])

    def test_no_untrusted_content_means_high_not_critical_and_no_path_flag(self):
        self.save(name="a", untrusted_input=False, tools=[{"name": "write_db", "side_effect": "write", "requires_approval": False}])
        n = {x["id"]: x for x in ai_graph.build(self.engine, None, today=TODAY)["nodes"]}
        self.assertEqual(n["tool:write_db"]["sev"], "high")
        self.assertNotIn("untrusted_path", n["tool:write_db"]["meta"])

    def test_unanswered_approval_is_not_flagged(self):
        self.save(name="a", untrusted_input=True, tools=[{"name": "maybe", "side_effect": "write", "requires_approval": None}])
        n = {x["id"]: x for x in ai_graph.build(self.engine, None, today=TODAY)["nodes"]}
        self.assertIsNone(n["tool:maybe"]["sev"])

    def test_deterministic_and_capped(self):
        self.save(name="big", tools=[{"name": f"t{i:03d}", "side_effect": "read"} for i in range(100)])
        for i in range(5):
            self.save(name=f"agent-{i}", tools=[{"name": f"u{i}-{j}", "side_effect": "read"} for j in range(100)])
        g1, g2 = ai_graph.build(self.engine, None, today=TODAY), ai_graph.build(self.engine, None, today=TODAY)
        self.assertEqual(json.dumps(g1, sort_keys=True), json.dumps(g2, sort_keys=True))
        self.assertLessEqual(len(g1["nodes"]), 400)
        self.assertTrue(g1["truncated"])

    def test_caller_links_still_work_with_plain_names(self):
        self.save(name="support-bot", kind="application")
        g = ai_graph.build(self.engine, None, today=TODAY, links={"support-bot": {"tools": ["ticket-lookup"], "mcp_servers": ["crm-mcp"], "data_sources": ["kb"]}})
        ids_ = {n["id"] for n in g["nodes"]}
        self.assertTrue({"tool:ticket-lookup", "mcp-server:crm-mcp", "data-source:kb"} <= ids_)


if __name__ == "__main__":
    unittest.main()
