"""
Configurable priority + SLA engine.

Loads remediation/config/priority_rules.yaml and computes, for any normalized finding
(see remediation/schema/normalized-finding-schema.md), a priority tier, a numeric score,
and an SLA due date/breach status. This is deliberately separate from
remediation-planner's own priority logic: the planner is a Claude Code subagent that
produces a point-in-time REMEDIATION_PLAN.md snapshot; this module is what the dashboard
uses to re-score findings live whenever an admin edits the rules file, without needing to
re-run the whole pipeline. See remediation/config/README.md for that distinction.
"""
import datetime
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_RULES_PATH = Path(__file__).resolve().parent / "priority_rules.yaml"

PRIORITY_ORDER = ["Low", "Medium", "High", "Critical"]


def load_rules(path=DEFAULT_RULES_PATH):
    path = Path(path)
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def _priority_from_score(score, thresholds):
    """thresholds maps tier -> minimum score for that tier; pick the highest tier whose
    threshold the score meets, walking from Critical down to Low."""
    for tier in reversed(PRIORITY_ORDER):
        if score >= thresholds.get(tier, 0):
            return tier
    return "Low"


def _max_priority(a, b):
    return a if PRIORITY_ORDER.index(a) >= PRIORITY_ORDER.index(b) else b


def asset_criticality_score(asset, rules):
    """Returns {keyword_score, matched_keyword, type_score} for an asset's criticality
    contribution to a finding's priority - extracted out of compute_priority() so
    remediation/enrichment/risk_scoring.py's asset-level Impact score can reuse the
    exact same asset-name-keyword/asset-type weighting instead of a second, potentially
    drifting copy of this logic."""
    asset_name = (asset.get("name") or "").lower()
    keyword_score = rules["asset_criticality_keywords"].get("default", 0)
    matched_keyword = None
    for keyword, points in rules["asset_criticality_keywords"].items():
        if keyword == "default":
            continue
        if keyword in asset_name:
            keyword_score = points
            matched_keyword = keyword
            break
    asset_type = asset.get("type", "")
    type_score = rules["asset_type_weights"].get(asset_type, 0)
    return {"keyword_score": keyword_score, "matched_keyword": matched_keyword, "type_score": type_score}


def compute_priority(finding, rules):
    """Returns {priority, score, reasons: [str]} for one finding."""
    reasons = []
    severity = finding.get("severity", "Low")
    score = rules["severity_weights"].get(severity, 0)
    reasons.append(f"severity {severity} (+{rules['severity_weights'].get(severity, 0)})")

    asset = finding.get("asset", {})
    crit = asset_criticality_score(asset, rules)
    score += crit["keyword_score"]
    if crit["matched_keyword"]:
        reasons.append(f"asset name matches '{crit['matched_keyword']}' (+{crit['keyword_score']})")

    score += crit["type_score"]
    if crit["type_score"]:
        reasons.append(f"asset type {asset.get('type', '')} (+{crit['type_score']})")

    priority = _priority_from_score(score, rules["priority_thresholds"])

    kev = finding.get("kev")
    kev_rule = rules.get("kev_override", {})
    if kev_rule.get("enabled") and kev and kev.get("listed"):
        forced = kev_rule["forces_priority"]
        if forced != priority:
            reasons.append(f"CISA KEV-listed → forced to {forced}")
        priority = _max_priority(priority, forced)

    epss = finding.get("epss")
    epss_rule = rules.get("epss_escalation", {})
    if epss_rule.get("enabled") and epss and epss.get("score", 0) >= epss_rule.get("threshold", 1.0):
        forced = epss_rule["forces_priority_at_least"]
        if PRIORITY_ORDER.index(forced) > PRIORITY_ORDER.index(priority):
            reasons.append(
                f"EPSS {epss['score']:.1%} ≥ {epss_rule['threshold']:.0%} threshold → elevated to {forced}"
            )
        priority = _max_priority(priority, forced)

    return {"priority": priority, "score": score, "reasons": reasons}


def compute_sla(finding, priority, rules, as_of=None, asset_risk_tier=None):
    """Returns {due_date, days_remaining, breached, risk_tier_multiplier} based on
    first_seen + the SLA window for this finding's priority tier, tightened or loosened
    by its asset's risk_tier (remediation/enrichment/risk_scoring.py) via
    `sla_risk_tier_multiplier` in priority_rules.yaml - CIS Controls v8 §7.2 calls for
    factoring real asset criticality into remediation timelines, not just a finding's
    own severity, so the same Critical-severity finding gets a tighter window on a
    Critical-risk-tier asset than on a Low-risk-tier one. `asset_risk_tier=None` (the
    asset has no computed risk_tier, or a caller doesn't have one to pass) falls back to
    a neutral 1.0 multiplier - unchanged behavior for any caller that doesn't supply it."""
    as_of = as_of or datetime.date.today()
    sla_days = rules["sla_days"].get(priority, 90)
    multiplier = rules.get("sla_risk_tier_multiplier", {}).get(asset_risk_tier, 1.0)
    sla_days = max(1, round(sla_days * multiplier))

    first_seen_str = finding.get("first_seen")
    if not first_seen_str:
        return {"due_date": None, "days_remaining": None, "breached": None, "risk_tier_multiplier": multiplier}

    first_seen = datetime.date.fromisoformat(first_seen_str)
    due_date = first_seen + datetime.timedelta(days=sla_days)
    days_remaining = (due_date - as_of).days

    return {
        "due_date": due_date.isoformat(),
        "days_remaining": days_remaining,
        "breached": days_remaining < 0,
        "risk_tier_multiplier": multiplier,
    }


def score_findings(findings, rules=None, as_of=None, risk_tier_by_asset=None):
    """Convenience: compute priority + SLA for a whole findings list, returning a new
    list of dicts (doesn't mutate the input) sorted by priority (highest first).
    `risk_tier_by_asset` (optional {asset_name: risk_tier}) feeds compute_sla()'s
    asset-criticality multiplier - omit it (or pass {}) to get the pre-existing,
    severity-tier-only SLA behavior."""
    rules = rules or load_rules()
    risk_tier_by_asset = risk_tier_by_asset or {}
    scored = []
    for f in findings:
        priority_result = compute_priority(f, rules)
        asset_name = (f.get("asset") or {}).get("name")
        asset_risk_tier = risk_tier_by_asset.get(asset_name)
        sla_result = compute_sla(f, priority_result["priority"], rules, as_of=as_of, asset_risk_tier=asset_risk_tier)
        scored.append({**f, **priority_result, "sla": sla_result})
    scored.sort(key=lambda f: PRIORITY_ORDER.index(f["priority"]), reverse=True)
    return scored
