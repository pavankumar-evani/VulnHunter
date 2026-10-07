"""
The ATT&CK matrix view: one cell per technique, joined from data Quanta already holds, so the Threat Hunting page can show where detection, hunting and exposure meet.

Pure function of its inputs (rules, findings, alerts, hunts, suggestions); the route gathers them once and passes them down. Nothing is guessed:
a technique that attack_tactics.yaml does not place under a tactic goes in an "Unmapped" column, and "covered" means an ENABLED detection rule claims the technique
(a name claim, not proof the rule fires).

State of a cell, strongest first:
  covered  an enabled detection rule claims the technique
  hunted   no rule, but a hunt (any status) tests it
  gap      no rule and no hunt, but open findings or stored alerts involve it
  quiet    known technique, nothing observed
"""
from pathlib import Path

import yaml

TACTICS_PATH = Path(__file__).with_name("attack_tactics.yaml")
TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
                "Collection", "Command and Control", "Exfiltration", "Impact"]
UNMAPPED = "Unmapped"


def _parent(tid):
    return str(tid or "").split(".")[0].strip().upper()


def tactic_catalogue(path=None):
    try:
        with open(path or TACTICS_PATH, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
    except OSError:
        return {}
    return {str(k).upper(): {"name": v.get("name", ""), "tactics": list(v.get("tactics") or [])} for k, v in raw.items() if isinstance(v, dict)}


def _hunt_techniques(h):
    out = set()
    for t in h.get("techniques") or []:
        out.add(_parent(t.get("technique_id") if isinstance(t, dict) else t))
    for q in h.get("queries") or []:
        if isinstance(q, dict) and q.get("technique"):
            out.add(_parent(q["technique"]))
    out.discard("")
    return out


def build(rules=None, findings=None, alerts=None, hunts=None, suggestions=None, library=None, catalogue=None):
    cat = catalogue if catalogue is not None else tactic_catalogue()
    cells = {}

    def cell(tid, name=None, tactics=None):
        tid = _parent(tid)
        if not tid:
            return None
        c = cells.get(tid)
        if c is None:
            known = cat.get(tid, {})
            c = cells[tid] = {"technique_id": tid, "name": name or known.get("name") or tid, "tactics": tactics or known.get("tactics") or [], "rules": [], "rules_disabled": [],
                              "findings": 0, "alerts": 0, "hunts": [], "suggestions": [], "in_library": False}
        else:
            if name and c["name"] == tid:
                c["name"] = name
            if tactics and not c["tactics"]:
                c["tactics"] = list(tactics)
        return c

    for tid in cat:
        cell(tid)
    for tid in (library or {}):
        c = cell(tid)
        if c:
            c["in_library"] = True
    for r in rules or []:
        for t in r.get("techniques") or []:
            c = cell(t)
            if c:
                (c["rules"] if r.get("enabled", True) else c["rules_disabled"]).append(r.get("name"))
    for f in findings or []:
        if f.get("status") in ("resolved", "closed") or (f.get("exception") or {}).get("active"):
            continue
        for t in f.get("attack_techniques") or []:
            c = cell(t.get("technique_id"), t.get("technique_name"))
            if c:
                c["findings"] += 1
    for a in alerts or []:
        c = cell(a.get("technique"))
        if c:
            c["alerts"] += 1
    for h in hunts or []:
        for tid in _hunt_techniques(h):
            c = cell(tid)
            if c and h.get("id") not in c["hunts"]:
                c["hunts"].append(h.get("id"))
    for s in suggestions or []:
        for t in s.get("techniques") or []:
            c = cell(t.get("technique_id"), t.get("technique_name"), t.get("tactics"))
            if c and s.get("id") not in c["suggestions"]:
                c["suggestions"].append(s.get("id"))

    out = []
    for c in cells.values():
        c["rules"] = sorted(set(x for x in c["rules"] if x))
        c["rules_disabled"] = sorted(set(x for x in c["rules_disabled"] if x))
        c["exposure"] = c["findings"] + c["alerts"]
        c["state"] = "covered" if c["rules"] else "hunted" if c["hunts"] else "gap" if c["exposure"] else "quiet"
        c["tactic"] = c["tactics"][0] if c["tactics"] else UNMAPPED
        out.append(c)
    out.sort(key=lambda c: (-c["exposure"], c["technique_id"]))
    present = {c["tactic"] for c in out}
    columns = [t for t in TACTIC_ORDER if t in present] + sorted(t for t in present if t not in TACTIC_ORDER and t != UNMAPPED) + ([UNMAPPED] if UNMAPPED in present else [])
    observed = [c for c in out if c["exposure"]]
    return {"tactics": columns, "techniques": out,
            "totals": {"techniques": len(out), "observed": len(observed), "covered": sum(1 for c in out if c["state"] == "covered"),
                       "observed_covered": sum(1 for c in observed if c["state"] == "covered"), "observed_hunted": sum(1 for c in observed if c["state"] == "hunted"),
                       "observed_gap": sum(1 for c in observed if c["state"] == "gap"), "rules_recorded": bool(rules)},
            "note": "A cell is covered when an enabled detection rule claims the technique: a name match, not proof the rule fires. Techniques outside Quanta's tactic table appear under Unmapped, never under a guessed tactic."}
