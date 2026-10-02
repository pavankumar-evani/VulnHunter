"""
Compensating controls specific to the client's own environment.

The question for a finding that cannot be fixed yet is "what should be in place so the flaw is hard to use, and what is
already?". This answers it in three steps, each of which can be checked:

1. Which attack techniques does the flaw enable? From the finding's ATT&CK tags (attack_mapping.py) and, for code and web
   findings, its CWE ids.
2. Which mitigations does MITRE publish for those techniques? (attack_mitigations.yaml, read from attack.mitre.org.) Each is
   expressed as a control class you can check for.
3. Which of those does THIS asset have, according to the controls inventory (remediation/controls/store.py)? Each mitigation is
   reported as one of:
     verified  a connector observed the control on the asset
     claimed   a person recorded it, or it comes from the older security_controls.yaml
     absent    the asset has recorded controls but not this one: a gap to close
     unknown   nothing is recorded for the asset at all, so Quanta cannot say; the advice is general until it is

Coverage is a simple, disclosed measure: of the applicable compensating mitigations, a verified one counts 1, a claimed one 0.5.
It is indicative, not a risk calculation. Patching and scanning are shown separately because they are the fix, not a
compensating control. A technique MITRE lists no mitigations for (Weaken Encryption) yields none, and the result says so.
"""
from pathlib import Path

import yaml

from remediation.controls import store
from remediation.enrichment import attack_mapping

PATH = Path(__file__).resolve().parent / "attack_mitigations.yaml"
NON_COMPENSATING = {"patching", "vuln-scanning"}
CLAIMED_WEIGHT = 0.5
_CACHE = {"mtime": None, "data": None}


def load(path=None):
    path = Path(path or PATH)
    mtime = path.stat().st_mtime
    if _CACHE["data"] is None or _CACHE["mtime"] != (str(path), mtime):
        _CACHE["data"], _CACHE["mtime"] = yaml.safe_load(path.read_text(encoding="utf-8")), (str(path), mtime)
    return _CACHE["data"]


def techniques_for(finding, data=None):
    """[{technique_id, technique_name}] from ATT&CK tags and CWE ids, de-duplicated."""
    data = data or load()
    found = {}
    for t in finding.get("attack_techniques") or attack_mapping.map_finding_to_attack(finding, all_matches=True):
        found[t["technique_id"]] = t.get("technique_name")
    from remediation.guidance.engine import finding_cwes
    for cwe in finding_cwes(finding):
        tid = (data.get("cwe_to_technique") or {}).get(cwe)
        if tid:
            found.setdefault(tid, None)
    names = {tid: tname for _p, tid, tname, _tac in attack_mapping._PATTERNS if tid}
    return [{"technique_id": tid, "technique_name": name or names.get(tid)} for tid, name in found.items()]


def candidates(finding, data=None):
    """The mitigations that apply, each with the techniques it covers; most-covering first."""
    data = data or load()
    techniques = techniques_for(finding, data)
    by_id = {}
    for tech in techniques:
        for mid in (data["techniques"].get(tech["technique_id"]) or []):
            m = data["mitigations"].get(mid)
            if not m:
                continue
            entry = by_id.setdefault(mid, {"id": mid, "name": m["name"], "control_class": m["class"], "action": m["action"], "nist": m.get("nist", []),
                                           "techniques": [], "compensating": m["class"] not in NON_COMPENSATING})
            entry["techniques"].append(tech["technique_id"])
    ordered = sorted(by_id.values(), key=lambda e: (-len(e["techniques"]), e["id"]))
    return techniques, ordered


def assess(finding, inventory=None, data=None):
    """The full client-specific assessment for one finding."""
    data = data or load()
    techniques, mitigations = candidates(finding, data)
    asset = (finding.get("asset") or {}).get("name")
    entries = inventory if inventory is not None else (store.for_asset(asset) if asset else [])
    by_class = {}
    for e in entries:
        by_class.setdefault(e["control_class"], []).append(e)
    classes = data["control_classes"]
    out = []
    for m in mitigations:
        have = by_class.get(m["control_class"], [])
        if not entries:
            status = "unknown"
        elif any(h["state"] == "verified" for h in have):
            status = "verified"
        elif have:
            status = "claimed"
        else:
            status = "absent"
        out.append({**m, "class_label": classes.get(m["control_class"], m["control_class"]), "status": status,
                    "evidence": [{"name": h["name"], "state": h["state"], "source": h["source"]} for h in have]})
    comp = [m for m in out if m["compensating"]]
    fix = [m for m in out if not m["compensating"]]
    result = {"techniques": techniques, "has_inventory": bool(entries), "compensating": comp, "the_fix_itself": fix,
              "gaps": [m for m in comp if m["status"] == "absent"] if entries else [],
              "coverage_pct": None, "note": None}
    if not techniques:
        result["note"] = "This finding does not map to an ATT&CK technique Quanta recognises, so no technique-based controls are suggested; the general advice applies."
    elif not comp:
        result["note"] = ("MITRE lists no compensating mitigations for the technique this flaw enables, because it abuses a system feature; "
                          "the fix itself is the control.")
    if entries and comp:
        score = sum(1.0 if m["status"] == "verified" else CLAIMED_WEIGHT if m["status"] == "claimed" else 0 for m in comp)
        result["coverage_pct"] = round(100 * score / len(comp))
        result["residual_pct"] = 100 - result["coverage_pct"]
    elif comp and not entries:
        result["note"] = ("Nothing is recorded in the controls inventory for this asset, so Quanta cannot say which of these are in place. "
                          "Record its controls on the Controls page (or have a connector push them) to get a gap analysis.")
    result["disclaimer"] = ("Mitigations are the ones MITRE ATT&CK publishes for the technique; the coverage figure is indicative "
                            "(verified = 1, claimed = 0.5), not a measurement of risk. A compensating control reduces risk, it does not close the finding.")
    return result
