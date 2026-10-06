"""
The confidence gate: auto / review / human.

Rule that no configuration can change: a decision may be routed "auto" only when its policy declares it reversible AND local, AND the decision, as
registered in code, does not touch a customer environment. Anything else tops out at "review" however high the confidence. A decision's own guards can
also force "human" (for example a Critical alert is never auto-closed as a false positive).
"""
from pathlib import Path

import yaml

POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "decision_policy.yaml"
ROUTES = ("auto", "review", "human")


class PolicyError(ValueError):
    pass


def load_policy(path=None):
    with open(path or POLICY_PATH, encoding="utf-8") as fh:
        pol = yaml.safe_load(fh) or {}
    for name, d in (pol.get("decisions") or {}).items():
        t = d.get("thresholds") or {}
        try:
            auto, review = float(t["auto"]), float(t["review"])
        except (KeyError, TypeError, ValueError):
            raise PolicyError(f"{name}: thresholds need numeric auto and review") from None
        if not (0 <= review <= auto <= 1):
            raise PolicyError(f"{name}: need 0 <= review <= auto <= 1")
    return pol


def auto_allowed(decision, dpol):
    """True only when the policy declares the decision reversible and local and the code says it does not touch a customer environment."""
    return bool(dpol.get("reversible") is True and dpol.get("local") is True and not decision.touches_environment)


def gate(decision, answers, state=None, policy=None):
    """Returns {route, confidence, auto_eligible, thresholds, reasons[]}. The route is the most cautious one over all of the decision's answers."""
    policy = policy or load_policy()
    dpol = (policy.get("decisions") or {}).get(decision.name)
    if dpol is None:
        return {"route": "human", "confidence": None, "auto_eligible": False, "thresholds": None, "reasons": [f"No gate policy for '{decision.name}', so a person decides."]}
    eligible = auto_allowed(decision, dpol)
    t = dpol["thresholds"]
    conf = min(a.gate_confidence for a in answers.values())
    reasons, route = [], "human"
    if conf >= float(t["review"]):
        route = "review"
    if conf >= float(t["auto"]):
        if eligible:
            route = "auto"
        else:
            reasons.append("Auto is not allowed for this decision (it is not both reversible and local, or it touches a customer environment), so a person confirms it.")
    for why in decision.guards(state or {}, answers):
        route = "human"
        reasons.append(why)
    if not reasons:
        reasons.append({"auto": "Confidence is at or above the auto threshold.", "review": "Confidence is enough to suggest, not to act.",
                        "human": "Confidence is below the review threshold."}[route])
    return {"route": route, "confidence": round(conf, 4), "auto_eligible": eligible, "thresholds": {"auto": float(t["auto"]), "review": float(t["review"])}, "reasons": reasons}
