"""Tests for the typed-decision layer: the schema lock, the confidence gate, the rules that keep auto away from environment changes, the shipped evaluators and the router."""
import copy
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remediation.decisions import gate, registry, router, schema, service  # noqa: E402
from remediation.decisions.schema import Answer, Choice, Score, YesNo  # noqa: E402

POLICY = gate.load_policy()


class FixedEvaluator:
    name, version = "fixed", "t1"

    def __init__(self, value, p, c=None, qname="verdict"):
        self.value, self.p, self.c, self.qname = value, p, c, qname

    def evaluate(self, decision, state):
        q = decision.question(self.qname)
        return {self.qname: Answer(q, self.value, self.p, self.p if self.c is None else self.c, ("fixed",), self.name, self.version)}


class SchemaLock(unittest.TestCase):
    def test_question_kinds_and_fixed_spaces(self):
        c, s, y = Choice("c", ["a", "b"]), Score("s", [1, 2, 3]), YesNo("y")
        self.assertEqual(y.options, ("yes", "no"))
        self.assertEqual(s.rank(3), 2)
        for q, bad in ((c, "z"), (s, 4), (y, "maybe")):
            with self.assertRaises(schema.SchemaViolation):
                q.check(bad)
        with self.assertRaises(schema.SchemaViolation):
            Choice("one", ["only"])
        with self.assertRaises(schema.SchemaViolation):
            Choice("dup", ["a", "a"])

    def test_answer_outside_the_space_is_rejected(self):
        with self.assertRaises(schema.SchemaViolation):
            Answer(YesNo("y"), "maybe", 0.5, 0.5)

    def test_probability_and_confidence_must_be_in_range(self):
        for p, c in ((1.2, 0.5), (0.5, -0.1), (True, 0.5), ("0.5", 0.5)):
            with self.assertRaises(schema.SchemaViolation):
                Answer(YesNo("y"), "yes", p, c)

    def test_distribution_must_sum_to_one_and_stay_in_space(self):
        q = YesNo("y")
        with self.assertRaises(schema.SchemaViolation):
            Answer(q, "yes", 0.8, 0.8, distribution={"yes": 0.8, "no": 0.5})
        with self.assertRaises(schema.SchemaViolation):
            Answer(q, "yes", 0.8, 0.8, distribution={"yes": 0.8, "maybe": 0.2})

    def test_run_rejects_an_evaluator_that_breaks_the_schema(self):
        d = registry.get("soc-alert-triage")
        foreign = Answer(Choice("verdict", ["x", "y"]), "x", 0.9, 0.9)   # an answer to a different question with the same name
        class Foreign:
            name, version = "f", "1"
            def evaluate(self, decision, state): return {"verdict": foreign}
        class Missing:
            name, version = "m", "1"
            def evaluate(self, decision, state): return {}
        class NotADict:
            name, version = "n", "1"
            def evaluate(self, decision, state): return [1]
        for ev in (Foreign(), Missing(), NotADict()):
            with self.assertRaises(schema.SchemaViolation):
                schema.run(d, ev, {})

    def test_unknown_decision(self):
        with self.assertRaises(schema.SchemaViolation):
            registry.get("nope")

    def test_evidence_is_capped(self):
        a = Answer(YesNo("y"), "yes", 0.9, 0.9, evidence=["x" * 1000] * 50)
        self.assertEqual(len(a.evidence), schema.MAX_EVIDENCE)
        self.assertEqual(len(a.evidence[0]), schema.MAX_EVIDENCE_LEN)


class GateThresholds(unittest.TestCase):
    def route(self, name, value, p, state=None, qname="verdict", policy=None):
        d = registry.get(name)
        ans = schema.run(d, FixedEvaluator(value, p, qname=qname), state or {})
        return gate.gate(d, ans, state, policy or POLICY)

    def test_bands_for_an_auto_eligible_decision(self):
        th = POLICY["decisions"]["soc-alert-triage"]["thresholds"]
        self.assertEqual(self.route("soc-alert-triage", "likely-true-positive", th["auto"])["route"], "auto")
        self.assertEqual(self.route("soc-alert-triage", "likely-true-positive", th["auto"] - 0.01)["route"], "review")
        self.assertEqual(self.route("soc-alert-triage", "likely-true-positive", th["review"])["route"], "review")
        self.assertEqual(self.route("soc-alert-triage", "likely-true-positive", th["review"] - 0.01)["route"], "human")

    def test_confidence_below_probability_lowers_the_gate(self):
        d = registry.get("soc-alert-triage")
        ans = schema.run(d, FixedEvaluator("likely-true-positive", 0.99, c=0.3), {})
        self.assertEqual(gate.gate(d, ans, {}, POLICY)["route"], "human")

    def test_most_cautious_answer_decides(self):
        d = registry.get("finding-routing")
        q1, q2 = d.question("fixer_domain"), d.question("owner_known")
        ans = {"fixer_domain": Answer(q1, "unix-server", 0.99, 0.99), "owner_known": Answer(q2, "no", 0.4, 0.4)}
        self.assertEqual(gate.gate(d, ans, {}, POLICY)["route"], "human")

    def test_no_policy_means_human(self):
        d = registry.get("soc-alert-triage")
        ans = schema.run(d, FixedEvaluator("likely-true-positive", 1.0), {})
        self.assertEqual(gate.gate(d, ans, {}, {"decisions": {}})["route"], "human")

    def test_policy_validation(self):
        import tempfile, yaml
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as fh:
            yaml.safe_dump({"decisions": {"x": {"thresholds": {"auto": 0.5, "review": 0.9}}}}, fh)
        with self.assertRaises(gate.PolicyError):
            gate.load_policy(fh.name)


class AutoNeverForEnvironmentChanges(unittest.TestCase):
    def permissive(self, name):
        pol = copy.deepcopy(POLICY)
        pol["decisions"][name].update(reversible=True, local=True, thresholds={"auto": 0.0, "review": 0.0})
        return pol

    def test_the_shipped_policy_declares_it(self):
        self.assertIs(POLICY["decisions"]["change-approval-needed"]["reversible"], False)
        self.assertIs(POLICY["decisions"]["change-approval-needed"]["local"], False)

    def test_change_approval_is_never_auto_even_if_policy_claims_reversible_and_local(self):
        name = "change-approval-needed"
        d = registry.get(name)
        self.assertTrue(d.touches_environment)
        ans = schema.run(d, FixedEvaluator("no", 1.0, qname="needs_approval"), {})
        g = gate.gate(d, ans, {}, self.permissive(name))
        self.assertNotEqual(g["route"], "auto")
        self.assertFalse(g["auto_eligible"])

    def test_not_reversible_or_not_local_is_never_auto(self):
        for flag in ("reversible", "local"):
            pol = self.permissive("finding-routing")
            pol["decisions"]["finding-routing"][flag] = False
            d = registry.get("finding-routing")
            ans = {"fixer_domain": Answer(d.question("fixer_domain"), "unix-server", 1.0, 1.0), "owner_known": Answer(d.question("owner_known"), "yes", 1.0, 1.0)}
            self.assertNotEqual(gate.gate(d, ans, {}, pol)["route"], "auto", flag)

    def test_a_missing_or_truthy_but_not_true_flag_is_not_enough(self):
        pol = self.permissive("soc-alert-triage")
        pol["decisions"]["soc-alert-triage"]["local"] = "yes"
        d = registry.get("soc-alert-triage")
        ans = schema.run(d, FixedEvaluator("likely-true-positive", 1.0), {})
        self.assertNotEqual(gate.gate(d, ans, {}, pol)["route"], "auto")

    def test_every_registered_decision_that_touches_an_environment_is_blocked(self):
        for name, d in registry.DECISIONS.items():
            if d.touches_environment:
                self.assertFalse(gate.auto_allowed(d, self.permissive(name)["decisions"][name]), name)

    def test_an_eligible_decision_can_reach_auto(self):
        d = registry.get("finding-routing")
        f = {"remediation_domain": "unix-server", "asset": {"name": "web1", "type": "unix-server"}}
        r = service.evaluate("finding-routing", {"finding": f, "owners": {"web1": "platform"}})
        self.assertEqual(r["gate"]["route"], "auto")


class CriticalNeverAutoFalsePositive(unittest.TestCase):
    def test_critical_false_positive_goes_to_a_person_even_at_full_confidence(self):
        d = registry.get("soc-alert-triage")
        state = {"severity": "Critical", "signals": {}}
        ans = schema.run(d, FixedEvaluator("likely-false-positive", 1.0), state)
        g = gate.gate(d, ans, state, POLICY)
        self.assertEqual(g["route"], "human")
        self.assertIn("Critical", " ".join(g["reasons"]))

    def test_non_critical_false_positive_is_not_blocked_by_that_guard(self):
        d = registry.get("soc-alert-triage")
        state = {"severity": "Low", "signals": {}}
        ans = schema.run(d, FixedEvaluator("likely-false-positive", 1.0), state)
        self.assertEqual(gate.gate(d, ans, state, POLICY)["route"], "auto")

    def test_the_shipped_evaluator_matches_the_soc_rule(self):
        fp = {"rule_noise_history": True, "clean_indicators": True, "prior_benign_same_host": True}
        crit = service.evaluate("soc-alert-triage", {"signals": fp, "severity": "Critical"})
        self.assertNotEqual(crit["answers"][0]["value"], "likely-false-positive")
        low = service.evaluate("soc-alert-triage", {"signals": fp, "severity": "Low"})
        self.assertEqual(low["answers"][0]["value"], "likely-false-positive")


class ShippedEvaluators(unittest.TestCase):
    def test_soc_uses_the_existing_score_unchanged(self):
        from remediation.hunting import soc
        cfg = soc.config()
        for sig, sev in (({"ioc_malicious": True, "kev_match": True}, "High"), ({}, "Medium"), ({"rule_noise_history": True, "clean_indicators": True}, "Low")):
            verdict, band, _, _ = soc.score(sig, cfg, sev)
            r = service.evaluate("soc-alert-triage", {"signals": sig, "severity": sev})
            self.assertEqual(r["answers"][0]["value"], verdict)
            self.assertEqual(r["answers"][0]["probability"], POLICY["evaluators"]["soc-alert-triage"]["band_probability"][band])

    def test_soc_evidence_names_the_signals_and_distribution_sums_to_one(self):
        r = service.evaluate("soc-alert-triage", {"signals": {"ioc_malicious": True, "kev_match": True}, "severity": "High"})
        a = r["answers"][0]
        self.assertIn("ioc_malicious", a["evidence"][0])
        self.assertAlmostEqual(sum(a["distribution"].values()), 1.0, places=3)
        self.assertEqual(a["evaluator"], "soc-weighted-signals")

    def test_shipped_soc_probabilities_do_not_reach_auto_until_measured(self):
        r = service.evaluate("soc-alert-triage", {"signals": {"ioc_malicious": True, "kev_match": True, "recurrence": True}, "severity": "High"})
        self.assertEqual(r["answers"][0]["value"], "likely-true-positive")
        self.assertEqual(r["gate"]["route"], "review")

    def test_routing(self):
        r = service.evaluate("finding-routing", {"finding": {"asset": {"type": "windows-server", "name": "DC1"}}, "owners": {}})
        by = {a["question"]: a for a in r["answers"]}
        self.assertEqual(by["fixer_domain"]["value"], "windows-server")
        self.assertEqual(by["owner_known"]["value"], "no")
        self.assertEqual(r["gate"]["route"], "human")      # an unowned asset (p 0.5) is below the review threshold
        r = service.evaluate("finding-routing", {"finding": {"asset": {"type": "network-routing-switching"}}})
        self.assertEqual({a["question"]: a["value"] for a in r["answers"]}["fixer_domain"], "none")
        r = service.evaluate("finding-routing", {"finding": {"remediation_domain": "application", "cve": None, "asset": {"type": "application", "name": "a"}}})
        self.assertEqual({a["question"]: a["value"] for a in r["answers"]}["fixer_domain"], "none")

    def test_change_approval_never_auto_whatever_it_answers(self):
        for f in ({"asset": {"type": "windows-server"}, "infra_category": "os"}, {"asset": {"type": "iot-ot-device"}, "infra_category": "ot"}, {}):
            r = service.evaluate("change-approval-needed", {"finding": f})
            self.assertIn(r["answers"][0]["value"], ("yes", "no"))
            self.assertNotEqual(r["gate"]["route"], "auto")

    def test_dry_evaluate_rejects_a_bad_state_cleanly(self):
        with self.assertRaises(schema.SchemaViolation):
            service.evaluate("nope", {})


class Router(unittest.TestCase):
    def answers(self, evidence=("e",)):
        return {"y": Answer(YesNo("y"), "yes", 0.9, 0.9, evidence)}

    def test_decide_never_needs_a_model(self):
        self.assertFalse(router.needs_generated_text(self.answers(), "auto", "decide")["needs_model"])

    def test_explain_uses_evidence_when_there_is_some(self):
        self.assertFalse(router.needs_generated_text(self.answers(), "review", "explain")["needs_model"])
        self.assertTrue(router.needs_generated_text(self.answers(()), "review", "explain")["needs_model"])

    def test_draft_needs_a_model_and_is_deterministic(self):
        a = router.needs_generated_text(self.answers(), "human", "draft")
        self.assertTrue(a["needs_model"])
        self.assertEqual(a, router.needs_generated_text(self.answers(), "human", "draft"))

    def test_bad_purpose(self):
        with self.assertRaises(ValueError):
            router.needs_generated_text(self.answers(), "auto", "chat")


if __name__ == "__main__":
    unittest.main()
