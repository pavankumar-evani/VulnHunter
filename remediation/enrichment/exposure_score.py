"""
Aggregate Exposure Score - a single, fleet-wide 0-100 number rolling up three real,
already-computed signals this app has for every finding/asset:

  - the mean per-asset Risk Score (remediation/enrichment/risk_scoring.py's own
    NIST SP 800-30-inspired Impact x Likelihood score)
  - what fraction of all findings are CISA KEV-listed (confirmed actively exploited)
  - the mean FIRST.org EPSS score across findings that have one

WHAT THIS IS NOT: a reproduction of Tenable's Cyber Exposure Score (CES) or any other
named, proprietary scoring product. Tenable does not publish CES's formula, so there is
nothing published to match - claiming equivalence to an undisclosed formula would be
fabrication. It is also not SSVC (FIRST/CISA's Stakeholder-Specific Vulnerability
Categorization) - SSVC is a per-vulnerability decision tree (what action to take on THIS
finding), not a fleet-wide aggregate score.

WHAT THIS IS: an originally-authored, fully disclosed rollup, in the same spirit as
OWASP's Risk Rating Methodology's Likelihood x Impact framing (each per-asset Risk Score
already IS that shape) combined with a real, portfolio-level EPSS/KEV aggregation -
FIRST.org's own EPSS FAQ (https://www.first.org/epss/faq) explicitly endorses
aggregating EPSS scores across a set of vulnerabilities for prioritization purposes,
while deliberately publishing no single fixed aggregation formula for anyone to
reproduce. Where these real sources are silent on exact mechanics, the weights below are
an original, disclosed choice (remediation/config/exposure_score_rules.yaml) - never
claimed as an industry-standard formula. See the "How this score is calculated" panel on
the Overview page for the same disclosure in place, and docs/COMPLIANCE_MAPPING.md.
"""
from pathlib import Path

import yaml

DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "config" / "exposure_score_rules.yaml"


def load_rules(path=DEFAULT_RULES_PATH):
    path = Path(path)
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def _band_for_score(score, bands):
    """bands maps a label -> minimum score for that label; pick the highest band whose
    threshold the score meets, same convention as priority_engine's tier lookup."""
    ordered = sorted(bands.items(), key=lambda kv: kv[1], reverse=True)
    for label, threshold in ordered:
        if score >= threshold:
            return label
    return ordered[-1][0] if ordered else "Low"


def compute_exposure_score(scored_assets, findings, rules=None):
    """`scored_assets` must already carry `risk_score` (see
    remediation/enrichment/risk_scoring.py's score_assets()) - this function doesn't
    compute per-asset risk itself, it only rolls those real numbers up. `findings` is
    the same real, normalized finding list used everywhere else in this app.

    Returns a real breakdown (not just the final number) so the dashboard can show
    exactly what moved the score, per the same "no black box" convention as
    priority_engine's own `reasons` list."""
    rules = rules if rules is not None else load_rules()
    weights = rules["component_weights"]

    total_assets = len(scored_assets)
    avg_risk_score = (
        sum(a.get("risk_score", 0) for a in scored_assets) / total_assets if total_assets else 0.0
    )

    total_findings = len(findings)
    kev_count = sum(1 for f in findings if (f.get("kev") or {}).get("listed"))
    kev_prevalence = (kev_count / total_findings * 100) if total_findings else 0.0

    epss_scores = [f["epss"]["score"] for f in findings if f.get("epss") and f["epss"].get("score") is not None]
    avg_epss = (sum(epss_scores) / len(epss_scores) * 100) if epss_scores else 0.0

    score = (
        avg_risk_score * weights["avg_risk_score"]
        + kev_prevalence * weights["kev_prevalence"]
        + avg_epss * weights["avg_epss"]
    )
    score = max(0, min(100, round(score)))

    tier_counts = {}
    for a in scored_assets:
        tier = a.get("risk_tier") or "unknown"
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

    return {
        "score": score,
        "band": _band_for_score(score, rules.get("score_bands", {})),
        "components": {
            "avg_risk_score": round(avg_risk_score, 1),
            "kev_prevalence": round(kev_prevalence, 1),
            "avg_epss": round(avg_epss, 1),
        },
        "total_assets": total_assets,
        "total_findings": total_findings,
        "kev_count": kev_count,
        "risk_tier_counts": tier_counts,
    }
