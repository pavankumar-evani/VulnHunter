"""
Real compensating-control coverage assessment.

Correlates one finding against its asset's hand-maintained firewall-rule and EDR-policy
state (remediation/config/security_controls.yaml) to compute how much existing coverage
already reduces exposure, what additional controls would help, and a residual-risk
percentage after applying them - the same shape of answer
remediation/enrichment/compensating_controls.py's generic suggestion text stops short of
giving, because that module has no real control-state data to reason over. This module is
additive, not a replacement: an asset with no security_controls.yaml entry gets an honest
"no data" result, and compensating_controls.py's generic suggestions still show everywhere
they already do.

IMPORTANT - what this is not: security_controls.yaml is a hand-maintained dataset, not a
live query against a real firewall/EDR management API or console (see that file's own
header for why). The coverage math below is this module's own disclosed, deterministic
scoring convention - not a formula any vendor or standard defines - same "illustrative,
verify yourself" caveat risk_scoring.py and attack_mapping.py already carry.

Formula (every constant fixed here, so retuning it means editing these, not guessing at an
opaque number):
    firewall_component (0.0 / 0.5 / 1.0):
        1.0 - at least one rule whose source looks internet/DMZ-facing denies traffic to
              this asset (the untrusted-facing path is blocked at the network layer)
        0.5 - at least one such rule exists but none of them deny (a path exists and is
              tracked, just not blocking)
        0.0 - no firewall_rules at all for this asset
    edr_component (0.0 / 0.5 / 1.0):
        1.0 - EDR mode is "block" and signature_coverage matches this finding
        0.5 - EDR mode is "detect" and signature_coverage matches this finding
        0.0 - no match, or no edr entry at all
    existing_coverage_pct = round(100 * (FIREWALL_WEIGHT * firewall_component
                                          + EDR_WEIGHT * edr_component))
    recommended_controls   - concrete text for whichever component is below 1.0
    incremental_coverage_pct - round(100 * (FIREWALL_WEIGHT * (1.0 - firewall_component)
                                             + EDR_WEIGHT * (1.0 - edr_component)))
                               i.e. exactly what applying every recommendation would add,
                               so existing + incremental always sums to 100 when both
                               components are addressed.
    residual_risk_pct      = 100 - existing_coverage_pct

Deliberately NOT done here: filtering by the finding's own port. The normalized Finding
schema doesn't carry a port field today, so the firewall_component is an asset-level
network-exposure signal ("is this asset's untrusted-facing path blocked at all"), not a
per-finding, per-port one. Say so plainly rather than pretending to a precision this
pipeline's data doesn't support.
"""
import re
from pathlib import Path

import yaml

DEFAULT_CONTROLS_PATH = Path(__file__).resolve().parent.parent / "config" / "security_controls.yaml"

FIREWALL_WEIGHT = 0.6
EDR_WEIGHT = 0.4

_UNTRUSTED_SOURCE_RE = re.compile(r"internet|dmz", re.IGNORECASE)


def load_controls(path=None):
    path = Path(path) if path is not None else DEFAULT_CONTROLS_PATH
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {"assets": []}


def _entry_matches(match, asset_name):
    if "name" in match:
        return asset_name == match["name"]
    if "name_prefix" in match:
        return asset_name.startswith(match["name_prefix"])
    if "name_regex" in match:
        return bool(re.search(match["name_regex"], asset_name))
    return False


def find_asset_controls(asset_name, controls=None):
    """Returns the first matching entry (dict with optional firewall_rules/edr keys), or
    None if security_controls.yaml has no entry covering this asset - an honest "no data"
    result, never a guessed full- or zero-coverage default."""
    controls = controls if controls is not None else load_controls()
    for entry in controls.get("assets", []):
        if _entry_matches(entry.get("match", {}), asset_name):
            return entry
    return None


def _firewall_component(firewall_rules):
    if not firewall_rules:
        return 0.0, "No firewall rules are on file for this asset — add its real rules to security_controls.yaml, or confirm network exposure manually."
    untrusted_rules = [r for r in firewall_rules if _UNTRUSTED_SOURCE_RE.search(str(r.get("source", "")))]
    if not untrusted_rules:
        return 0.5, None
    denying = [r for r in untrusted_rules if str(r.get("action", "")).lower() == "deny"]
    if denying:
        return 1.0, None
    allowing = untrusted_rules[0]
    return 0.0, (
        f"Tighten the firewall rule allowing {allowing.get('source', 'an untrusted source')} to reach "
        f"{allowing.get('dest', 'this asset')} — change it to deny, or restrict it to only the specific "
        f"ports this asset actually needs exposed."
    )


def _finding_text(finding):
    return f"{finding.get('cve') or ''} {finding.get('title', '')} {finding.get('description', '')}".lower()


def _edr_component(edr, finding):
    if not edr:
        return 0.0, "No EDR policy data is on file for this asset — add one to security_controls.yaml, or confirm EDR coverage manually."
    coverage = [str(c).lower() for c in (edr.get("signature_coverage") or [])]
    text = _finding_text(finding)
    matched = any(c in text for c in coverage)
    mode = (edr.get("mode") or "none").lower()
    if matched and mode == "block":
        return 1.0, None
    if matched and mode == "detect":
        return 0.5, "Escalate the existing EDR detection rule for this finding from detect-only to block mode."
    if mode in ("detect", "block"):
        return 0.0, "Add an EDR detection/blocking rule (e.g. an Attack Surface Reduction rule) covering this finding's technique — none is currently configured for it."
    return 0.0, "Enable EDR coverage for this asset — none is currently configured."


def assess_coverage(finding, controls=None):
    """Returns {has_data, existing_coverage_pct, recommended_controls, incremental_coverage_pct,
    residual_risk_pct} for one finding. `has_data` is False (all percentages None) when
    security_controls.yaml has no entry for the finding's asset at all - distinct from a
    real 0% coverage, which means an entry exists but covers nothing."""
    asset_name = (finding.get("asset") or {}).get("name")
    entry = find_asset_controls(asset_name, controls) if asset_name else None
    if entry is None:
        return {
            "has_data": False,
            "existing_coverage_pct": None,
            "recommended_controls": [],
            "incremental_coverage_pct": None,
            "residual_risk_pct": None,
        }

    fw_score, fw_recommendation = _firewall_component(entry.get("firewall_rules") or [])
    edr_score, edr_recommendation = _edr_component(entry.get("edr") or {}, finding)

    existing_pct = round(100 * (FIREWALL_WEIGHT * fw_score + EDR_WEIGHT * edr_score))
    incremental_pct = round(100 * (FIREWALL_WEIGHT * (1.0 - fw_score) + EDR_WEIGHT * (1.0 - edr_score)))
    recommended = [r for r in (fw_recommendation, edr_recommendation) if r]

    return {
        "has_data": True,
        "existing_coverage_pct": existing_pct,
        "recommended_controls": recommended,
        "incremental_coverage_pct": incremental_pct if recommended else 0,
        "residual_risk_pct": 100 - existing_pct,
    }
