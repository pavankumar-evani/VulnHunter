"""
The registered decisions and the shipped evaluators.

Three decisions, each wired to code that already exists (nothing is re-implemented):
  soc-alert-triage        the verdict on an alert, from remediation/hunting/soc.py's weighted signals (`soc.score`);
  finding-routing         which fixer domain a finding goes to (the same domains as ingest/api_findings.FIXER_DOMAINS) and whether its asset has a recorded owner;
  change-approval-needed  whether a remediation needs a human change approval, from remediation/config/remediation_policy_engine.policy_for_finding.

The shipped evaluators are deterministic and explainable: the evidence of an answer names the signals or rules that produced it. They never call a model.
`touches_environment` is a fact about the decision, fixed here in code; the policy file cannot override it.
"""
from dataclasses import dataclass, field
from typing import Callable

from remediation.decisions import gate as gate_mod
from remediation.decisions import schema
from remediation.decisions.schema import Answer, Choice, YesNo

FIXER_DOMAINS = ("windows-server", "unix-server", "iot-ot-device", "application")
VERDICTS = ("likely-true-positive", "likely-false-positive", "escalate-l2")


@dataclass(frozen=True)
class Decision:
    name: str
    title: str
    questions: tuple
    touches_environment: bool                 # fixed in code: True means this decision can never be routed auto
    guards: Callable = field(default=lambda state, answers: [], compare=False)   # (state, answers) -> reasons that force a human

    def question(self, name):
        return next(q for q in self.questions if q.name == name)


def _soc_guard(state, answers):
    a = answers.get("verdict")
    if a is not None and a.value == "likely-false-positive" and (state or {}).get("severity") == "Critical":
        return ["A Critical alert is never closed as a false positive without a person."]
    return []


DECISIONS = {d.name: d for d in (
    Decision("soc-alert-triage", "Alert triage verdict", (Choice("verdict", VERDICTS, "What should happen to this alert?"),), False, _soc_guard),
    Decision("finding-routing", "Finding routing", (Choice("fixer_domain", FIXER_DOMAINS + ("none",), "Which fixer domain handles this finding?"),
                                                     YesNo("owner_known", "Does the asset have a recorded owner?")), False),
    Decision("change-approval-needed", "Needs human change approval", (YesNo("needs_approval", "Does this remediation need a human change approval?"),), True),
)}


def get(name):
    if name not in DECISIONS:
        raise schema.SchemaViolation(f"unknown decision '{name}' (known: {', '.join(sorted(DECISIONS))})")
    return DECISIONS[name]


def _spread(options, value, p):
    rest = [o for o in options if o != value]
    return {value: p, **{o: (1 - p) / len(rest) for o in rest}}


class _Base:
    version = "1"

    def __init__(self, policy=None):
        self.policy = policy or gate_mod.load_policy()

    def _cfg(self, decision_name):
        return (self.policy.get("evaluators") or {}).get(decision_name) or {}

    def _answer(self, q, value, p, evidence, confidence=None):
        return Answer(q, value, p, p if confidence is None else confidence, tuple(evidence), self.name, self.version, _spread(q.options, value, p))


class SocTriageEvaluator(_Base):
    """state: {"signals": {signal: bool}, "severity": "High", optional "cfg": soc_triage config}. Uses soc.score unchanged, so the verdict is the existing one."""
    name = "soc-weighted-signals"

    def evaluate(self, decision, state):
        from remediation.hunting import soc
        cfg = state.get("cfg") or soc.config()
        signals = {k: bool(v) for k, v in (state.get("signals") or {}).items()}
        severity = state.get("severity")
        verdict, band, tp, fp = soc.score(signals, cfg, severity)
        probs = self._cfg(decision.name).get("band_probability") or {"high": 0.9, "medium": 0.7, "low": 0.5}
        fired = sorted(k for k, v in signals.items() if v)
        evidence = [f"Signals that fired: {', '.join(fired) if fired else 'none'}.", f"True-positive score {tp}, false-positive score {fp}; the verdict's own confidence label is {band}."]
        if severity == "Critical":
            evidence.append("The alert is Critical, so it is never called a likely false positive.")
        return {"verdict": self._answer(decision.question("verdict"), verdict, float(probs[band]), evidence)}


class RoutingEvaluator(_Base):
    """state: {"finding": normalized finding, "owners": {asset name lower: team}}."""
    name = "routing-rules"

    def evaluate(self, decision, state):
        c = self._cfg(decision.name)
        f = state.get("finding") or {}
        asset = f.get("asset") or {}
        explicit, atype = f.get("remediation_domain"), asset.get("type")
        if explicit in FIXER_DOMAINS:
            domain, p, why = explicit, c.get("explicit_domain", 0.95), f"The finding is already routed to {explicit}."
        elif atype in FIXER_DOMAINS:
            domain, p, why = atype, c.get("derived_domain", 0.85), f"The asset type is {atype}, which has a fixer."
        elif atype:
            domain, p, why = "none", c.get("no_fixer", 0.9), f"There is no automated fixer for asset type {atype}."
        else:
            domain, p, why = "none", c.get("unknown_type", 0.6), "The finding names no asset type, so no fixer could be chosen."
        evidence = [why]
        if domain == "application" and not f.get("cve"):
            domain, p = "none", c.get("no_fixer", 0.9)
            evidence.append("An application finding needs a CVE for the dependency-upgrade fixer, and this one has none.")
        name = (asset.get("name") or "").lower()
        owner = (state.get("owners") or {}).get(name) if name else None
        op = c.get("owner_known", 0.9) if owner else c.get("owner_unknown", 0.5)
        return {"fixer_domain": self._answer(decision.question("fixer_domain"), domain, float(p), evidence),
                "owner_known": self._answer(decision.question("owner_known"), "yes" if owner else "no", float(op),
                                            ["An owner is recorded for the asset." if owner else "No owner is recorded for the asset (or the asset has no name)."])}


class ApprovalEvaluator(_Base):
    """state: {"finding": ..., "environment": "prod"|..., optional "rules": remediation policy}. Uses the remediation policy engine unchanged."""
    name = "remediation-policy"

    def evaluate(self, decision, state):
        from remediation.config import remediation_policy_engine as rpe
        c = self._cfg(decision.name)
        rules = state.get("rules") or rpe.load_rules()
        pol = rpe.policy_for_finding(state.get("finding") or {}, rules=rules, environment=state.get("environment"))
        standard_auto = pol.get("change_type") == "standard" and bool(pol.get("auto_remediate"))
        evidence = [f"Policy domain {pol['domain']}: change type {pol.get('change_type')}, auto-remediate {bool(pol.get('auto_remediate'))}."]
        if pol.get("emergency_override"):
            p = c.get("emergency", 0.98)
            evidence.append("A KEV-listed finding makes this an emergency change, which is still approved, never skipped.")
        elif pol["domain"] == "default":
            p = c.get("default_policy", 0.7)
            evidence.append("No specific policy domain matched, so the default policy applied.")
        else:
            p = c.get("policy_matched", 0.9)
        return {"needs_approval": self._answer(decision.question("needs_approval"), "no" if standard_auto else "yes", float(p), evidence)}


EVALUATORS = {"soc-alert-triage": SocTriageEvaluator, "finding-routing": RoutingEvaluator, "change-approval-needed": ApprovalEvaluator}


def default_evaluator(name, policy=None):
    return EVALUATORS[get(name).name](policy)
