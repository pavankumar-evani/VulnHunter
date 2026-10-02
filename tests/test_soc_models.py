"""
Tests for the SOC models: detection use-case generation and lifecycle, the playbook recommender, and the guardrails on AI-drafted playbooks.
"""
import datetime
import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

from remediation.hunting import usecase_store, usecases  # noqa: E402
from remediation.soar import ai_draft, recommend  # noqa: E402

TODAY = datetime.date(2026, 10, 15)


def finding(i, tid="T1190"):
    return {"id": f"FIND-{i}", "status": "open", "kev": {"listed": True}, "attack_techniques": [{"technique_id": tid}]}


def alert(i, host, technique, disp="true-positive", minute=0):
    return {"id": i, "asset": host, "technique": technique, "disposition": disp, "occurred_at": f"2026-10-14T10:{minute:02d}:00Z", "received_at": f"2026-10-14T10:{minute:02d}:00Z"}


class UseCases(unittest.TestCase):
    def test_coverage_gap_for_an_unclaimed_technique(self):
        out = usecases.generate_all([finding(1), finding(2)], [], [], [], [], today=TODAY)
        gap = next(c for c in out if c["kind"] == "coverage-gap" and c["techniques"] == ["T1190"])
        self.assertIn("nothing would alert", gap["hypothesis"])
        self.assertEqual(gap["evidence"]["estate_findings"], 2)
        rule = yaml.safe_load(gap["sigma"])
        self.assertEqual(rule["status"], "experimental")
        self.assertIn("attack.t1190", rule["tags"])
        self.assertTrue(gap["test_plan"])

    def test_an_enabled_rule_removes_the_gap_and_a_disabled_one_does_not(self):
        rules = [{"name": "r", "techniques": ["T1190"], "enabled": True}]
        self.assertFalse([c for c in usecases.generate_all([finding(1)], [], [], [], rules, today=TODAY) if c["kind"] == "coverage-gap" and c["techniques"] == ["T1190"]])
        rules[0]["enabled"] = False
        self.assertTrue([c for c in usecases.generate_all([finding(1)], [], [], [], rules, today=TODAY) if c["kind"] == "coverage-gap" and c["techniques"] == ["T1190"]])

    def test_sequences_need_enough_hosts_and_precision(self):
        alerts = []
        for n, host in enumerate(("a", "b", "c")):
            alerts += [alert(n * 2 + 1, host, "T1190", minute=0), alert(n * 2 + 2, host, "T1059", minute=20)]
        out = [c for c in usecases.generate_all([], alerts, [], [], [], today=TODAY) if c["kind"] == "sequence"]
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["techniques"], ["T1190", "T1059"])
        self.assertEqual(out[0]["evidence"]["hosts"], 3)
        self.assertEqual(out[0]["evidence"]["precision"], 1.0)
        self.assertEqual(yaml.safe_load(out[0]["sigma"])["correlation"]["type"], "temporal_ordered")
        # two hosts is not enough
        self.assertFalse([c for c in usecases.generate_all([], alerts[:4], [], [], [], today=TODAY) if c["kind"] == "sequence"])
        # mostly false positives is not a pattern
        fp = [dict(a, disposition="false-positive") for a in alerts]
        self.assertFalse([c for c in usecases.generate_all([], fp, [], [], [], today=TODAY) if c["kind"] == "sequence"])

    def test_ioc_watchlist_from_a_relevant_report(self):
        rep = {"id": 7, "title": "Campaign X", "priority": "high", "relevance": 80, "extracted": {"ips": ["185.220.101.4"], "domains": ["bad.example.test"], "hashes": [], "techniques": ["T1190"]}}
        out = [c for c in usecases.generate_all([], [], [], [rep], [], today=TODAY) if c["kind"] == "ioc-watchlist"]
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["evidence"]["indicators"], {"DestinationIp": 1, "QueryName|endswith": 1})
        low = dict(rep, priority="low")
        self.assertFalse([c for c in usecases.generate_all([], [], [], [low], [], today=TODAY) if c["kind"] == "ioc-watchlist"])

    def test_the_same_inputs_give_the_same_keys(self):
        a = [c["key"] for c in usecases.generate_all([finding(1)], [], [], [], [], today=TODAY)]
        self.assertEqual(a, [c["key"] for c in usecases.generate_all([finding(1)], [], [], [], [], today=TODAY)])


class UseCaseLifecycle(unittest.TestCase):
    def setUp(self):
        self.e = create_engine("sqlite:///:memory:")
        self.cases = usecases.generate_all([finding(1)], [], [], [], [], today=TODAY)

    def test_sync_is_idempotent_and_keeps_decisions(self):
        rows = usecase_store.sync(self.cases, self.e)
        key = rows[0]["key"]
        with self.assertRaises(ValueError):
            usecase_store.set_status(key, "rejected", "", "eng", self.e)
        usecase_store.set_status(key, "accepted", "Build in the SIEM next sprint", "eng", self.e)
        again = usecase_store.sync(self.cases, self.e)
        self.assertEqual(len(again), len(rows))
        self.assertEqual(next(r for r in again if r["key"] == key)["status"], "accepted")

    def test_unknown_status_and_key(self):
        usecase_store.sync(self.cases, self.e)
        with self.assertRaises(ValueError):
            usecase_store.set_status(self.cases[0]["key"], "bogus", "x", "eng", self.e)
        with self.assertRaises(KeyError):
            usecase_store.set_status("nope", "accepted", "x", "eng", self.e)

    def test_ai_suggestion_is_stored_beside_the_case(self):
        usecase_store.sync(self.cases, self.e)
        out = usecase_store.set_ai(self.cases[0]["key"], "Try adding an exclusion for the scanner", self.e)
        self.assertEqual(out["ai_suggestion"], "Try adding an exclusion for the scanner")
        self.assertIn("sigma", out)


def pb(i, name, enabled=True, steps=None, trigger=None):
    return {"id": i, "name": name, "description": "", "enabled": enabled, "trigger": trigger or {"mode": "manual"}, "steps": steps or [{"type": "investigate", "params": {}}]}


def al(i, tech="T1190", rule="Web shell spawn", sev="High", status="closed", disp="true-positive"):
    return {"id": i, "title": "alert", "severity": sev, "technique": tech, "rule_name": rule, "status": status, "disposition": disp, "asset": "WEB-1", "detail": ""}


def past(a, p, status="completed"):
    return {"alert": a, "run": {"status": status}, "playbook": p}


class Recommender(unittest.TestCase):
    def test_history_ranks_the_playbook_that_worked(self):
        a, b = pb(1, "Contain web host"), pb(2, "Notify only")
        hist = [past(al(i), a) for i in range(5)] + [past(al(10 + i), b, "failed") for i in range(5)]
        r = recommend.recommend(al(99, status="new", disp=None), [a, b], hist)
        self.assertEqual(r["basis"], "history")
        self.assertEqual(r["recommendations"][0]["playbook_id"], 1)
        self.assertGreater(r["recommendations"][0]["score"], r["recommendations"][1]["score"])

    def test_more_evidence_beats_one_lucky_run(self):
        a, b = pb(1, "Many"), pb(2, "Once")
        hist = [past(al(i), a) for i in range(10)] + [past(al(50), b)]
        r = recommend.recommend(al(99, status="new", disp=None), [a, b], hist)
        self.assertEqual(r["recommendations"][0]["playbook_id"], 1)

    def test_dissimilar_history_is_ignored(self):
        a = pb(1, "x")
        hist = [past(al(i, tech="T1486", rule="Other", sev="Low"), a) for i in range(5)]
        r = recommend.recommend(al(99, status="new", disp=None), [a], hist)
        self.assertEqual(r["basis"], "none")

    def test_falls_back_to_triggers_without_history(self):
        auto = pb(3, "Auto triage", trigger={"mode": "on-alert", "min_severity": "High"})
        r = recommend.recommend(al(99, status="new", disp=None), [auto, pb(4, "Manual")], [])
        self.assertEqual((r["basis"], r["recommendations"][0]["playbook_id"]), ("trigger", 3))

    def test_disabled_playbooks_are_never_suggested(self):
        a = pb(1, "x", enabled=False)
        self.assertEqual(recommend.recommend(al(99, status="new", disp=None), [a], [past(al(1), a)])["recommendations"], [])


class AiDraftGuardrails(unittest.TestCase):
    def test_a_valid_draft_passes_the_same_validator(self):
        text = '```json\n{"name": "Triage web alert", "description": "d", "steps": [{"type": "investigate", "params": {"reputation": false, "siem": false}}, {"type": "notify", "params": {"channel": "webhook", "text": "Look at {title}"}}]}\n```'
        d = ai_draft.check_draft(text)
        self.assertTrue(d["ok"], d["errors"])
        self.assertEqual([s["type"] for s in d["steps"]], ["investigate", "notify"])

    def test_unknown_step_is_rejected_with_the_validators_message(self):
        d = ai_draft.check_draft(json.dumps({"name": "x", "steps": [{"type": "format-disk", "params": {}}]}))
        self.assertFalse(d["ok"])
        self.assertTrue(d["errors"])

    def test_a_destructive_action_without_approval_is_rejected(self):
        steps = [{"type": "investigate", "params": {}}, {"type": "response-action", "params": {"action": "isolate-host", "target": "{asset}", "reason": "r"}}]
        d = ai_draft.check_draft(json.dumps({"name": "x", "steps": steps}))
        self.assertFalse(d["ok"])

    def test_garbage_is_an_error_not_an_exception(self):
        for text in ("no json here", "{broken", None, '{"name": "x"}'):
            d = ai_draft.check_draft(text)
            self.assertFalse(d["ok"])
            self.assertTrue(d["errors"])

    def test_prompts_carry_no_free_text(self):
        feat = {"category": "web", "technique": "T1190", "rule": "Web shell spawn", "severity": "High"}
        p = ai_draft.playbook_prompt(feat)
        self.assertIn("T1190", p)
        self.assertIn("ONLY a JSON object", p)
        case = {"title": "t", "kind": "coverage-gap", "techniques": ["T1190"], "hypothesis": "h", "evidence": {"estate_findings": 2}, "data_sources": ["web logs"]}
        self.assertIn("no raw logs", ai_draft.usecase_prompt(case))


if __name__ == "__main__":
    unittest.main()
