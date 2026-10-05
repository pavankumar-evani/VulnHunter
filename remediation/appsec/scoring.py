"""
Ranks application findings: open-source dependency findings and first-party code findings on one scale, with every factor visible.

The method and its weights live in remediation/config/appsec_scoring.yaml and are a disclosed choice, not a standard. The score is
100 x (sum of weight x signal) x reachability modifier x dependency modifier, where each signal is between 0 and 1:
CVSS, EPSS, known exploitation (CISA KEV), the application's business criticality, the affected package's criticality, the application's attack surface
(exposure x environment), and the finding's stage in an entry-pivot-impact chain. A recorded network path that is denied lowers the score; it never removes it.

Where a signal is missing the result says so (`assumptions`): a CVSS score absent from the scanner is replaced by a value derived from severity and
marked as assumed, never silently invented.
"""
import re
from pathlib import Path

import yaml

PATH = Path(__file__).resolve().parent.parent / "config" / "appsec_scoring.yaml"
LABELS = {"cvss": "CVSS base score", "epss": "Exploit probability (EPSS)", "known_exploited": "Known exploited (CISA KEV)", "asset_criticality": "Application criticality",
          "package_criticality": "Package or code sensitivity", "attack_surface": "Attack surface", "attack_chain": "Attack-chain position"}
_SENSITIVE = (("critical", re.compile(r"auth|login|passw|crypt|secret|token|payment|card|credential", re.I)),
              ("high", re.compile(r"session|admin|account|user|api|controller|handler|upload|route", re.I)))


def load_rules(path=None):
    with open(path or PATH, encoding="utf-8") as fh:
        rules = yaml.safe_load(fh) or {}
    total = sum(rules["weights"].values())
    if abs(total - 1.0) > 0.001:
        raise ValueError(f"appsec_scoring.yaml: the weights add up to {total:.3f}, not 1.0")
    return rules


def file_sensitivity(location):
    path = location if isinstance(location, str) else (location or {}).get("file") or ""
    for level, rx in _SENSITIVE:
        if rx.search(path or ""):
            return level
    return "unknown"


def tier(score, rules):
    for name, floor in sorted(rules["tiers"].items(), key=lambda kv: -kv[1]):
        if score >= floor:
            return name
    return "P4"


def exposure(app, reach):
    """('internet' | 'internal' | 'unknown', why)."""
    facing = (app or {}).get("internet_facing")
    verdict = (reach or {}).get("verdict", "unknown")
    if facing is True:
        return "internet", "the application is recorded as internet facing"
    if verdict in ("allowed", "denied") and facing is None:
        return "internet", f"a path from the internet is recorded ({verdict})"
    if facing is False:
        return "internal", "the application is recorded as not internet facing"
    return "unknown", "exposure is not recorded for this application"


def score_finding(f, ctx, rules):
    """ctx: {app, reach, chain_role, package_level, depth}. depth is 'direct' | 'transitive' | 'unknown' | None (a code finding)."""
    w = rules["weights"]
    app = ctx.get("app") or {}
    assumptions = []
    cvss, cvss_assumed = f.get("cvss"), False
    if not isinstance(cvss, (int, float)):
        cvss_assumed = True
        cvss = rules["severity_cvss_fallback"].get(f.get("severity"), 5.0)
        assumptions.append(f"No CVSS score from the scanner; {cvss} assumed from the {f.get('severity', 'unknown')} severity.")
    epss = (f.get("epss") or {}).get("score")
    if epss is None:
        epss = 0.0
        if f.get("cve"):
            assumptions.append("No EPSS score is recorded for this CVE; counted as 0.")
    crit = (app.get("business_criticality") or "unknown").lower()
    if crit == "unknown":
        assumptions.append("The application's business criticality is not recorded; a middle value is used.")
    pkg_level = ctx.get("package_level") or "unknown"
    expo, expo_why = exposure(app, ctx.get("reach"))
    env = (app.get("environment") or "unknown").lower()
    if env == "unknown":
        assumptions.append("The application's environment is not recorded.")
    if expo == "unknown":
        assumptions.append("Exposure is not recorded: set 'internet facing' on the application or add its network path.")
    surface = rules["attack_surface"]["exposure"][expo] * rules["attack_surface"]["environment"].get(env, rules["attack_surface"]["environment"]["unknown"])
    role = ctx.get("chain_role") or "none"
    signals = {"cvss": min(float(cvss), 10.0) / 10.0, "epss": min(max(float(epss), 0.0), 1.0), "known_exploited": 1.0 if (f.get("kev") or {}).get("listed") else 0.0,
               "asset_criticality": rules["asset_criticality"].get(crit, rules["asset_criticality"]["unknown"]),
               "package_criticality": rules["package_criticality"].get(pkg_level, rules["package_criticality"]["unknown"]),
               "attack_surface": surface, "attack_chain": rules["attack_chain"].get(role, 0.0)}
    notes = {"cvss": f"{cvss}" + (" (assumed)" if cvss_assumed else ""), "epss": f"{epss:.3f}", "known_exploited": "listed" if signals["known_exploited"] else "not listed",
             "asset_criticality": crit, "package_criticality": pkg_level, "attack_surface": f"{expo}, {env}: {expo_why}", "attack_chain": role}
    verdict = (ctx.get("reach") or {}).get("verdict", "unknown")
    depth = ctx.get("depth") or "unknown"
    mods = [{"name": "Network path", "value": rules["modifiers"]["reachability"].get(verdict, 1.0), "note": f"path to the internet is {verdict}"}]
    if ctx.get("depth") is not None:
        mods.append({"name": "Dependency depth", "value": rules["modifiers"]["dependency"].get(depth, 1.0), "note": f"{depth} dependency"})
    mult = 1.0
    for m in mods:
        mult *= m["value"]
    raw = sum(w[k] * signals[k] for k in w)
    score = round(min(100.0, 100.0 * raw * mult), 1)
    breakdown = sorted(({"factor": LABELS[k], "signal": round(signals[k], 3), "weight": w[k], "points": round(100.0 * w[k] * signals[k], 1), "note": notes[k]} for k in w),
                       key=lambda r: -r["points"])
    return {"score": score, "tier": tier(score, rules), "breakdown": breakdown, "modifiers": mods, "assumptions": assumptions}
