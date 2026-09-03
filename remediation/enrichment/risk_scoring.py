"""
Per-ASSET risk scoring: Impact score, Likelihood score, and an overall Risk score for
every asset, built entirely from real, already-computed data elsewhere in this pipeline
- no new external data source, no fabricated sub-metric.

IMPORTANT - read before treating this as a certified assessment. The user's own request
asked for something "like standard NIST RMF." NIST SP 800-37 ("RMF" proper) is a 7-step
*process* (Categorize/Select/Implement/Assess/Authorize/Monitor) - it has no scoring
formula of its own to borrow. The document that actually defines a semi-quantitative
risk-scoring model is **NIST SP 800-30 Rev. 1**, whose real core idea is:
    Risk = Likelihood x Impact
(mapped, in the real document, to discrete qualitative levels via a lookup table - not a
literal continuous product). This module is an honest, disclosed SIMPLIFICATION of that
idea using a continuous 0-100 scale for each factor, not a literal reproduction of
SP 800-30's own tables and not a certified RMF/800-30 output. Treat every score here as
"NIST SP 800-30-inspired," the same "illustrative, verify yourself" caveat this project
already applies to its other heuristic taxonomies (MITRE mapping, compensating-controls
suggestions, owner-pattern-matching).

Every input is real and already computed elsewhere:
- Severity/CVSS and asset criticality (asset-name-keyword + asset-type weights, reused
  from remediation/config/priority_engine.py's asset_criticality_score() - NOT
  redeclared here, so there's exactly one place that defines "how critical is this
  asset") feed the Impact score.
- CISA KEV listing, FIRST.org EPSS, /exploit-criteria rule matches, and EOL/EOS status
  (remediation/enrichment/eol_lookup.py) feed the Likelihood score.

Known overlap, disclosed rather than hidden: an admin's own exploit_criteria_rules.yaml
conditions can themselves reference kev_listed/epss_min, so the KEV/EPSS/exploit-criteria
Likelihood components aren't fully statistically independent of each other. This is the
same kind of overlap priority_engine.py's own KEV-override and EPSS-escalation already
have with the weighted score they sit on top of - not a bug, just worth knowing.

A fifth Likelihood component, "control_coverage", is added ONLY for an asset that has at
least one finding with real coverage data in remediation/config/security_controls.yaml
(see remediation/enrichment/control_coverage.py) - an asset with no such data gets exactly
the same 4-component score this module always computed, not a diluted one from a
zero-valued fifth weight. See _likelihood_components()/score_assets() below for how that
conditional inclusion is implemented.

Note on what this is NOT: CVSS is stored in this pipeline only as a single rolled-up
scalar (finding["cvss"]) - there is no Impact/Exploitability sub-score split (the
Confidentiality/Integrity/Availability impact metrics, or the Attack Vector/Complexity/
Privileges/User-Interaction exploitability metrics) ingested or stored anywhere. This
module's "Impact score" does NOT claim to derive from CVSS's own real Impact sub-metric -
that data doesn't exist in this pipeline. It's built from the CVSS Base Score scalar plus
asset criticality instead.
"""
from pathlib import Path

import yaml

from remediation.config import priority_engine
from remediation.enrichment import control_coverage

DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "config" / "risk_scoring_rules.yaml"

_TIER_ORDER = ["Low", "Medium", "High", "Critical"]


def load_rules(path=DEFAULT_RULES_PATH):
    path = Path(path)
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def _weighted(components, weights):
    """Weighted average of `components` (dict of name -> 0-100 value) by `weights`
    (dict of the same names -> weight) - divides by the actual weight sum rather than
    assuming the configured weights already total 1.0, so a retuned config that doesn't
    sum to exactly 1.0 still produces a score that stays within [0, 100]."""
    total_weight = sum(weights.values()) or 1
    return sum(components[key] * weights[key] for key in weights) / total_weight


def _severity_component(asset_findings, asset_row, severity_weights):
    """0-100: the worst CVSS among this asset's own findings, scaled directly
    (cvss/10*100). Falls back to the asset's highest_severity (already computed by
    asset_inventory.build_asset_inventory()) scaled against severity_weights when no
    finding on this asset has a numeric CVSS at all (e.g. a purely hand-authored,
    no-CVE category like IaC/DAST/AI-ML)."""
    cvss_values = [f.get("cvss") for f in asset_findings if isinstance(f.get("cvss"), (int, float))]
    if cvss_values:
        return max(cvss_values) / 10 * 100
    highest_severity = asset_row.get("highest_severity")
    if not highest_severity:
        return 0
    max_weight = max(severity_weights.values()) if severity_weights else 0
    if not max_weight:
        return 0
    return severity_weights.get(highest_severity, 0) / max_weight * 100


def _criticality_component(asset_row, priority_rules):
    """0-100: reuses priority_engine.asset_criticality_score()'s own asset-name-keyword
    + asset-type weighting (from priority_rules.yaml) - the same criticality signal a
    finding on this asset already gets in its own priority score, normalized against
    the maximum possible combined score so it's comparable across a rules file an admin
    might retune."""
    crit = priority_engine.asset_criticality_score(
        {"name": asset_row.get("name"), "type": asset_row.get("type")}, priority_rules)
    keyword_weights = [v for k, v in priority_rules["asset_criticality_keywords"].items() if k != "default"]
    max_keyword = max(keyword_weights) if keyword_weights else 0
    max_type = max(priority_rules["asset_type_weights"].values()) if priority_rules["asset_type_weights"] else 0
    max_total = max_keyword + max_type
    if max_total <= 0:
        return 0
    return (crit["keyword_score"] + crit["type_score"]) / max_total * 100


def _control_coverage_component(asset_findings, security_controls):
    """Returns 0-100 (the MAX residual_risk_pct among this asset's findings that
    actually have coverage data on file), or None if no finding on this asset has any
    security_controls.yaml entry - the None case means "don't add this component at
    all" (see score_assets()), never a guessed 0 or 100.

    `security_controls` MUST be the already-loaded dict, not None - control_coverage.
    load_controls() re-opens and re-parses the YAML file with no caching, and this
    function is called once per asset while scoring every asset in the pipeline, so
    resolving it fresh here would mean one disk read per asset (thousands, at this
    pipeline's real data scale) instead of the single read score_assets() already does
    up front. See score_assets() for where that one real load happens."""
    residuals = [
        coverage["residual_risk_pct"]
        for f in asset_findings
        for coverage in [control_coverage.assess_coverage(f, controls=security_controls)]
        if coverage["has_data"]
    ]
    return max(residuals) if residuals else None


def _likelihood_components(asset_row, asset_findings, rules, security_controls):
    """Returns the raw 0-100 Likelihood sub-components for one asset - always the 4 base
    ones (kev/epss/exploit_criteria/eol), plus "control_coverage" only when at least one
    finding on this asset has real coverage data (see _control_coverage_component)."""
    kev_component = 100 if asset_row.get("kev_count", 0) > 0 else 0

    epss_values = [
        f["epss"]["score"] for f in asset_findings
        if f.get("epss") and isinstance(f["epss"].get("score"), (int, float))
    ]
    epss_component = (max(epss_values) * 100) if epss_values else 0

    cap = rules.get("exploit_criteria_match_cap", 3) or 1
    matching_count = sum(1 for f in asset_findings if f.get("exploit_criteria_matches"))
    exploit_criteria_component = min(matching_count, cap) / cap * 100

    eol_status = (asset_row.get("eol_status") or {}).get("status", "unknown")
    eol_component = rules["eol_likelihood_points"].get(eol_status, 0)

    components = {
        "kev": kev_component,
        "epss": epss_component,
        "exploit_criteria": exploit_criteria_component,
        "eol": eol_component,
    }
    coverage_component = _control_coverage_component(asset_findings, security_controls)
    if coverage_component is not None:
        components["control_coverage"] = coverage_component
    return components


def _tier_from_score(score, thresholds):
    """Picks the highest tier whose threshold the score meets, walking Critical down
    to Low - same convention as priority_engine.py's own _priority_from_score()."""
    for tier in reversed(_TIER_ORDER):
        if score >= thresholds.get(tier, 0):
            return tier
    return "Low"


def score_assets(asset_rows, findings, rules=None, priority_rules=None, security_controls=None):
    """Returns a new list (doesn't mutate `asset_rows`) with `impact_score`,
    `likelihood_score`, `risk_score` (all 0-100 ints), and `risk_tier` added to every
    row. `findings` should already have `exploit_criteria_matches` tagged (see
    remediation/enrichment/exploit_criteria.py's tag_exploit_criteria()) for the
    Likelihood score's exploit-criteria component to reflect anything - a finding
    missing that field is treated the same as one with no matches (honest, not a bug).

    security_controls.yaml is loaded exactly ONCE here (like rules/priority_rules
    already are) and threaded through to every asset's _control_coverage_component()
    call - not reloaded per-asset, which at this pipeline's real data scale (thousands
    of assets) would mean thousands of avoidable disk reads for one static file."""
    rules = rules if rules is not None else load_rules()
    priority_rules = priority_rules if priority_rules is not None else priority_engine.load_rules()
    security_controls = security_controls if security_controls is not None else control_coverage.load_controls()

    findings_by_asset = {}
    for f in findings:
        name = (f.get("asset") or {}).get("name")
        if not name:
            continue
        findings_by_asset.setdefault(name, []).append(f)

    scored = []
    for row in asset_rows:
        asset_findings = findings_by_asset.get(row["name"], [])

        impact = _weighted(
            {
                "severity": _severity_component(asset_findings, row, priority_rules["severity_weights"]),
                "criticality": _criticality_component(row, priority_rules),
            },
            rules["impact_weights"],
        )
        likelihood_components = _likelihood_components(row, asset_findings, rules, security_controls)
        # Only the weights for components actually present this time - an asset with no
        # control_coverage component gets exactly today's 4-way weighted average, not one
        # diluted by a 5th weight sitting at an implicit zero (see module docstring).
        likelihood_weights = {k: v for k, v in rules["likelihood_weights"].items() if k in likelihood_components}
        likelihood = _weighted(likelihood_components, likelihood_weights)
        risk = impact * likelihood / 100
        tier = _tier_from_score(risk, rules["risk_tier_thresholds"])

        scored.append({
            **row,
            "impact_score": round(impact),
            "likelihood_score": round(likelihood),
            "risk_score": round(risk),
            "risk_tier": tier,
        })
    return scored
