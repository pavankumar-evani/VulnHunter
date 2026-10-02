"""
Alert triage with exposure context, runbooks, and hunt metrics.

An alert from a SIEM says something happened on a host. Quanta adds what the SIEM cannot know: the host's open vulnerabilities, whether any is on
the KEV list, who owns it, and whether a vulnerability on it matches the technique the alert reports. That raises or lowers the order in which a
queue should be worked; it never changes the alert's own severity or decides that it is real.

Priority = severity base (Critical 100, High 70, Medium 40, Low 15, Informational 5) + 30 for a KEV-listed open finding on the host + 20 when a
finding on the host is tagged with the alert's ATT&CK technique + 10 for a high-EPSS finding + 10 when the host has no owner (nobody will notice
otherwise). The reasons are listed so an analyst can see why the order is what it is.
"""
from pathlib import Path

import yaml

BASE = {"Critical": 100, "High": 70, "Medium": 40, "Low": 15, "Informational": 5}
RUNBOOKS_PATH = Path(__file__).with_name("runbooks.yaml")


def runbooks():
    with open(RUNBOOKS_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or []


def runbook_for(alert, books=None):
    books = books if books is not None else runbooks()
    tech, title = (alert.get("technique") or "").upper(), (alert.get("title") or "").lower()
    for b in books:
        if tech and tech in b.get("techniques", []):
            return b
    for b in books:
        if any(k in title for k in b.get("keywords", [])):
            return b
    return next((b for b in books if b["id"] == "rb-generic"), None)


def _host_findings(asset, findings):
    a = (asset or "").lower()
    if not a:
        return []
    return [f for f in findings if (f.get("asset") or {}).get("name", "").lower() == a or (f.get("asset") or {}).get("ip") == asset]


def enrich(alert, findings, owners=None, books=None):
    owners = owners or {}
    fs = [f for f in _host_findings(alert.get("asset"), findings) if f.get("status") not in ("resolved", "closed")]
    kev = [f for f in fs if (f.get("kev") or {}).get("listed")]
    hi_epss = [f for f in fs if ((f.get("epss") or {}).get("score") or 0) >= 0.5]
    tech = (alert.get("technique") or "").upper()
    related = [f for f in fs if tech and any(t.get("technique_id") == tech for t in f.get("attack_techniques") or [])]
    owner = owners.get((alert.get("asset") or "").lower())
    score, reasons = BASE.get(alert.get("severity"), 40), [f"{alert.get('severity')} alert"]
    if kev:
        score += 30
        reasons.append(f"{len(kev)} known-exploited vulnerabilit{'ies' if len(kev) != 1 else 'y'} open on the host")
    if related:
        score += 20
        reasons.append(f"a vulnerability on the host matches technique {tech}")
    if hi_epss:
        score += 10
        reasons.append("a vulnerability with high exploitation probability is open")
    if alert.get("asset") and not owner:
        score += 10
        reasons.append("the host has no recorded owner")
    if not alert.get("asset"):
        reasons.append("the alert names no host, so no vulnerability context could be added")
    elif not fs:
        reasons.append("Quanta has no open findings for this host")
    order = ["Critical", "High", "Medium", "Low", "Informational"]
    top = sorted(fs, key=lambda f: (order.index(f["severity"]) if f.get("severity") in order else 9, -(((f.get("epss") or {}).get("score")) or 0)))[:8]
    return {"priority": score, "reasons": reasons, "owner": owner, "open_findings": len(fs), "kev_findings": len(kev),
            "findings": [{"id": f["id"], "title": f.get("title"), "severity": f.get("severity"), "cve": f.get("cve"), "kev": bool((f.get("kev") or {}).get("listed")),
                          "related_to_alert": f in related} for f in top],
            "runbook": runbook_for(alert, books)}


def metrics(hunts, alerts, findings, lib=None):
    """Hunt and triage numbers. Technique coverage counts how many of the techniques that appear in the estate's open findings have been hunted."""
    lib = lib or {}
    closed = [h for h in hunts if h["status"] == "closed"]
    hunted = {t["technique_id"] for h in hunts if h["status"] in ("active", "closed") for t in h["techniques"]}
    estate = {}
    for f in findings:
        for t in f.get("attack_techniques") or []:
            estate[t["technique_id"]] = t["technique_name"]
    queries = [q for h in hunts for q in h["queries"]]
    closed_alerts = [a for a in alerts if a["status"] == "closed"]
    return {
        "hunts": {"total": len(hunts), "proposed": sum(h["status"] == "proposed" for h in hunts), "active": sum(h["status"] == "active" for h in hunts),
                  "closed": len(closed), "confirmed": sum(h["outcome"] == "confirmed" for h in closed),
                  "not_found": sum(h["outcome"] == "not-found" for h in closed), "needs_data": sum(h["outcome"] == "needs-data" for h in closed),
                  "detections_created": sum(h["detection_created"] for h in hunts)},
        "queries": {"total": len(queries), "run": sum(q.get("result") in ("hits", "no-hits", "error") for q in queries)},
        "coverage": {"estate_techniques": len(estate), "hunted": len(set(estate) & hunted),
                     "pct": round(100 * len(set(estate) & hunted) / len(estate)) if estate else None,
                     "not_hunted": [{"technique_id": k, "technique_name": estate[k], "library": k in lib} for k in sorted(set(estate) - hunted)]},
        "alerts": {"total": len(alerts), "open": sum(a["status"] != "closed" for a in alerts), "closed": len(closed_alerts),
                   "true_positive": sum(a["disposition"] == "true-positive" for a in closed_alerts),
                   "false_positive": sum(a["disposition"] in ("false-positive", "benign") for a in closed_alerts)},
    }
