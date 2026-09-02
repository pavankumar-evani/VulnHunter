"""
Per-asset Blast Radius scoring: "if this specific asset is compromised, how far does
the damage spread and how much does it cost" - a different question from
risk_scoring.py's Impact/Likelihood/Risk, which is anchored to a specific finding's
severity. Blast radius asks the same question regardless of which finding got an
attacker in the door, then gets cross-referenced against real exploitability
(kev_count/likelihood_score, already computed by risk_scoring.py) to surface the
"high blast radius AND actively exploitable" cases that matter most.

Grounded directly against a real 4-dimension profiling framework (Identity & Privilege,
Network Topology & Reachability, Business Criticality & Data Sensitivity, Attack
Surface & Vulnerability Context) - honestly mapped against what data this app actually
has, not what the framework describes in general:

- Identity & Privilege (who has credentials/logged in here): NOT AVAILABLE. Would need
  real Active Directory logon-session data and group-membership-to-endpoint mapping -
  active_directory_connector.py only pulls computer inventory (name/OS/enabled), never
  session or group data, and no connector in this app collects EDR credential/LSASS
  telemetry. The only real proxy this app has is asset_criticality_keywords' "dc"/
  "auth" keywords (an asset NAMED like a domain controller/auth server) - a
  naming-convention heuristic, not real credential data. Folded into the criticality
  component below with that caveat, not presented as identity data.
- Network Topology & Reachability (where can it go): NOT AVAILABLE beyond two coarse,
  already-real signals: the manually-set internal/external "facing" classification
  (asset_inventory.py - never derived from an actual network scan or firewall rules),
  and asset_type_weights' virtualization-host weight (a hypervisor compromise cascades
  to every VM it hosts - see priority_rules.yaml's own comment on that weight, a real,
  already-modeled blast-radius difference). Real VLAN/segmentation/dual-homed/session
  data would need a genuinely new data source no connector here collects.
- Business Criticality & Data Sensitivity (what does it hold): REAL, already computed -
  reuses priority_engine.asset_criticality_score()'s own keyword+type weighting, the
  exact same signal risk_scoring.py's Impact score already uses.
- Attack Surface & Vulnerability Context (how easily breached): REAL, already computed
  elsewhere - this module deliberately does NOT recompute it. An asset's own
  likelihood_score (risk_scoring.py: KEV + EPSS + exploit-criteria matches, weighted)
  and kev_count (asset_inventory.py) are reused as-is as the exploitability axis to
  cross-reference blast radius against, matching the source framework's own point that
  blast radius (what's at stake) and exploitability (how likely) are two different
  questions combined for a "true risk profile" - not the same number.
"""
from pathlib import Path

import yaml

from remediation.config import priority_engine

DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "config" / "blast_radius_rules.yaml"

# Mirrors risk_scoring.py's own tier convention (Low..Critical), reused here for the
# same reason: one shared vocabulary for "how big a number is this" across the app.
_TIER_ORDER = ["Low", "Medium", "High", "Critical"]


def load_rules(path=DEFAULT_RULES_PATH):
    path = Path(path)
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def _criticality_component(asset_row, priority_rules):
    """0-100, identical logic/normalization to risk_scoring.py's own
    _criticality_component() - deliberately not re-derived differently, so an asset's
    business-criticality contribution to Blast Radius always agrees with its
    contribution to Impact elsewhere in the app."""
    crit = priority_engine.asset_criticality_score(
        {"name": asset_row.get("name"), "type": asset_row.get("type")}, priority_rules)
    keyword_weights = [v for k, v in priority_rules["asset_criticality_keywords"].items() if k != "default"]
    max_keyword = max(keyword_weights) if keyword_weights else 0
    max_type = max(priority_rules["asset_type_weights"].values()) if priority_rules["asset_type_weights"] else 0
    max_total = max_keyword + max_type
    matched_keyword = crit["matched_keyword"]
    score = 0 if max_total <= 0 else (crit["keyword_score"] + crit["type_score"]) / max_total * 100
    return score, matched_keyword


def _network_reachability_proxy(asset_row, rules):
    """0-100 - see module docstring for why this is a coarse proxy, not real topology
    data. `facing` unset/unknown gets the SAME points as internal (never assume
    elevated reachability without real evidence either way)."""
    facing = (asset_row.get("facing") or "unknown").lower()
    points = rules["facing_points"].get(facing, rules["facing_points"]["unknown"])
    return points, facing


def _tier_from_score(score, thresholds):
    for tier in reversed(_TIER_ORDER):
        if score >= thresholds.get(tier, 0):
            return tier
    return "Low"


def score_blast_radius(asset_rows, rules=None, priority_rules=None):
    """Returns a new list (doesn't mutate `asset_rows`) with `blast_radius_score`
    (0-100 int), `blast_radius_tier`, and `blast_radius_factors` (the real inputs that
    produced the score, for the page to explain itself - matched_keyword/asset_type/
    facing) added to every row. Expects `asset_rows` shaped like
    risk_scoring.score_assets()'s own output (so kev_count/likelihood_score are already
    present for cross_reference_immediate_risks() below) - this module doesn't
    recompute those."""
    rules = rules if rules is not None else load_rules()
    priority_rules = priority_rules if priority_rules is not None else priority_engine.load_rules()

    scored = []
    for row in asset_rows:
        criticality, matched_keyword = _criticality_component(row, priority_rules)
        network_proxy, facing = _network_reachability_proxy(row, rules)
        weights = rules["component_weights"]
        total_weight = (weights["criticality"] + weights["network_reachability_proxy"]) or 1
        blast_radius = (criticality * weights["criticality"] + network_proxy * weights["network_reachability_proxy"]) / total_weight
        tier = _tier_from_score(blast_radius, rules["blast_radius_tier_thresholds"])

        scored.append({
            **row,
            "blast_radius_score": round(blast_radius),
            "blast_radius_tier": tier,
            "blast_radius_factors": {
                "criticality_component": round(criticality),
                "matched_criticality_keyword": matched_keyword,
                "asset_type": row.get("type"),
                "network_reachability_component": round(network_proxy),
                "facing": facing,
            },
        })
    return scored


def cross_reference_immediate_risks(scored_assets, rules=None):
    """The user-facing point of combining blast radius with exploitability: assets that
    are BOTH high blast-radius AND actively/plausibly exploitable right now - "a device
    with a critical RCE flaw and [high blast radius] represents an immediate,
    catastrophic risk," minus the identity-specific claim this app can't back with real
    data (see module docstring). Deliberately reuses likelihood_score/kev_count as-is
    rather than recomputing exploitability - this function only combines, never scores.
    Returns the subset of `scored_assets` that qualifies, sorted highest blast radius
    first."""
    rules = rules if rules is not None else load_rules()
    threshold = rules["immediate_risk_blast_radius_threshold"]
    matches = [
        a for a in scored_assets
        if a.get("blast_radius_score", 0) >= threshold
        and (a.get("kev_count", 0) > 0 or a.get("likelihood_score", 0) >= rules["immediate_risk_likelihood_threshold"])
    ]
    return sorted(matches, key=lambda a: a["blast_radius_score"], reverse=True)


# Static, honest disclosure of what each of the source framework's 4 profiling
# dimensions actually is in this app today - rendered directly on the dashboard page
# rather than left to a footnote, same "disclose inline, not just in a footnote"
# convention as every other heuristic taxonomy in this app.
PROFILING_COVERAGE = [
    {
        "dimension": "Identity & Privilege Profiling",
        "question": "Who has credentials or a logged-in session on this endpoint?",
        "status": "not_available",
        "detail": "No connector in this app collects real logon-session or group-membership-to-endpoint data. "
                   "The Active Directory connector pulls computer inventory (name/OS/enabled) only. The only proxy "
                   "folded into Business Criticality below is an asset NAME matching \"dc\"/\"auth\" - a naming "
                   "convention heuristic, not real credential data.",
    },
    {
        "dimension": "Network Topology & Reachability",
        "question": "Where can an attacker go from here?",
        "status": "partial",
        "detail": "No VLAN/segmentation/firewall-rule/session data exists in this app. The two real signals used "
                   "below are the manually-set Internal/External-facing classification (never derived from an "
                   "actual network scan) and a virtualization-host asset-type weight (a compromised hypervisor "
                   "exposes every VM it hosts).",
    },
    {
        "dimension": "Business Criticality & Data Sensitivity",
        "question": "What does this endpoint hold or enable?",
        "status": "available",
        "detail": "Real, already-computed asset-name-keyword and asset-type weighting from "
                   "remediation/config/priority_rules.yaml - the same signal this app's Impact score already uses.",
    },
    {
        "dimension": "Attack Surface & Vulnerability Context",
        "question": "How easily can it be breached right now?",
        "status": "available",
        "detail": "Real, already-computed CISA KEV listing, FIRST.org EPSS, and exploit-criteria matches - shown "
                   "here as a separate cross-reference axis, not folded into the Blast Radius score itself.",
    },
]
