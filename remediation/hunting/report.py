"""
The investigation report an analyst opens instead of a bare alert.

Every section answers a question an analyst would otherwise answer by hand, and says where its answer comes from:

  Verdict and why         the recommendation and the signals behind it (soc.py)
  Incident summary        what the alert is, on what, how long, and what else Quanta knows about the host
  Historical correlation  how many earlier alerts involve each host, user and address, how they were closed, and what the SIEM history search found
  Associated entities     the host and its owner, the user and whether they hold privileged access (from access governance), the addresses, domains and hashes
  ATT&CK mapping          the technique and tactic, and what to check next for that technique
  Attack flow             the alerts on this host or for this user in time order, by tactic: where this one sits in a sequence
  Indicators              each public indicator with its reputation, if looked up
  Blast radius            where else the same indicators appear in alerts Quanta holds and in the SIEM, and what is exposed on those hosts
  What your tools did     the action the EDR or firewall reports it took (blocked, quarantined, allowed) and whether that needs checking
  Recommended actions     what to do next, from the verdict, the signals and the runbook, with the playbooks that could carry it out
  References              the searches that were run (with counts), the detection rule, the runbook
  Follow-ups              questions asked after the first report, answered from the same data and merged in

All of it is assembled from data Quanta holds or the searches a person confirmed; nothing is written by a model and nothing is guessed. A section with
nothing to say says so ("no earlier alert involves ..."), because an empty result is itself information.
"""
import datetime
import ipaddress
import re
from pathlib import Path

import yaml

from remediation.enrichment import client_controls
from remediation.hunting import detection, generate

TACTICS_PATH = Path(__file__).with_name("attack_tactics.yaml")
TACTIC_ORDER = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
                "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"]
BLOCKED = ("block", "quarantin", "denied", "deny", "contain", "kill", "prevent", "isolat", "remediated", "dropped", "reset")
ALLOWED = ("allow", "permit", "observed", "detect only", "detected", "monitor", "passed", "not blocked")


def tactics():
    with open(TACTICS_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def technique_info(tid):
    if not tid:
        return None
    parent = str(tid).upper().split(".")[0]
    t = tactics().get(parent)
    return {"id": str(tid).upper(), "parent": parent, "name": t["name"] if t else None, "tactics": t["tactics"] if t else [], "tactic": t["tactics"][0] if t else None}


def _dt(ts):
    try:
        return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        return None


def _vals(alert):
    e = alert.get("entities") or {}
    out = []
    if alert.get("asset") or e.get("host"):
        out.append(("host", alert.get("asset") or e.get("host")))
    if e.get("user"):
        out.append(("user", e["user"]))
    for kind, key in (("address", "ips"), ("domain", "domains"), ("hash", "hashes"), ("url", "urls")):
        out += [(kind, v) for v in e.get(key) or []]
    return out


def _has(alert, kind, value):
    v = value.lower()
    return any(k == kind and str(x).lower() == v for k, x in _vals(alert))


# ---------------------------------------------------------------- sections
def entity_history(alert, alerts):
    others = [a for a in alerts if a["id"] != alert["id"]]
    rec = [d for d in (_dt(a.get("received_at")) for a in alerts) if d]
    since = min(rec).strftime("%Y-%m-%d") if rec else None
    rows = []
    for kind, value in _vals(alert)[:12]:
        match = [a for a in others if _has(a, kind, value)]
        tp = sum(1 for a in match if a.get("disposition") == "true-positive")
        noise = sum(1 for a in match if a.get("disposition") in ("benign", "false-positive"))
        first = min((a["received_at"] for a in match), default=None)
        open_ = sum(1 for a in match if a["status"] != "closed")
        if match:
            text = (f"{len(match)} earlier alert(s) involve {kind} {value}, the first on {first[:10]}; {tp} closed as true positive, {noise} as benign or false positive, {open_} still open.")
        else:
            text = f"No earlier alert involves {kind} {value}" + (f" (Quanta holds alerts since {since})." if since else ".")
        rows.append({"kind": kind, "value": value, "alerts": len(match), "true_positive": tp, "noise": noise, "open": open_, "first_seen": first, "text": text})
    return rows


def associated_entities(alert, host_ctx, identity=None):
    e = alert.get("entities") or {}
    rows = []
    host = alert.get("asset") or e.get("host")
    if host:
        bits = [f"owner {host_ctx['owner']}" if host_ctx.get("owner") else "no owner recorded", f"{host_ctx['open_findings']} open vulnerabilities"]
        if host_ctx.get("kev_findings"):
            bits.append(f"{host_ctx['kev_findings']} known-exploited")
        rows.append({"kind": "host", "value": host, "detail": ", ".join(bits)})
    if e.get("user"):
        who = (identity or {}).get(str(e["user"]).lower())
        if who is None:
            detail = "not in the access records Quanta holds" if identity is not None else "access records not loaded"
        elif who["privileged"]:
            detail = "holds privileged access on " + ", ".join(sorted(who["systems"])[:4])
        else:
            detail = "no privileged access recorded"
        rows.append({"kind": "user", "value": e["user"], "detail": detail})
    for ip in e.get("ips") or []:
        try:
            a = ipaddress.ip_address(ip)
            detail = "internal address" if (a.is_private or a.is_loopback or a.is_link_local) else "public address"
        except ValueError:
            detail = "address"
        rows.append({"kind": "address", "value": ip, "detail": detail})
    rows += [{"kind": "domain", "value": d, "detail": ""} for d in e.get("domains") or []]
    rows += [{"kind": "hash", "value": h, "detail": ""} for h in e.get("hashes") or []]
    rows += [{"kind": "url", "value": u, "detail": ""} for u in e.get("urls") or []]
    return rows[:30]


def technique_guidance(tid):
    info = technique_info(tid)
    if not info:
        return None
    lib = generate.library().get(info["parent"]) or {}
    cc = client_controls.load()
    ids = (cc.get("techniques") or {}).get(info["parent"]) or []
    mits = [{"name": cc["mitigations"][m]["name"], "action": cc["mitigations"][m]["action"]} for m in ids[:4] if m in (cc.get("mitigations") or {})]
    return {**info, "what_to_check": lib.get("notes"), "title": lib.get("hunt"), "data_sources": lib.get("data_sources") or [], "mitigations": mits}


def attack_flow(alert, alerts):
    host, user = (alert.get("asset") or "").lower(), ((alert.get("entities") or {}).get("user") or "").lower()
    related = [a for a in alerts if a["id"] == alert["id"] or (host and (a.get("asset") or "").lower() == host) or (user and ((a.get("entities") or {}).get("user") or "").lower() == user)]
    steps = []
    for a in related:
        info = technique_info(a.get("technique"))
        steps.append({"at": a.get("occurred_at") or a["received_at"], "alert_id": a["id"], "title": a["title"], "severity": a["severity"], "technique": info["id"] if info else None,
                      "technique_name": info["name"] if info else None, "tactic": info["tactic"] if info else None, "current": a["id"] == alert["id"]})
    steps.sort(key=lambda s: s["at"] or "")
    stages = []
    for s in steps:
        if s["tactic"] and s["tactic"] not in stages:
            stages.append(s["tactic"])
    stages.sort(key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99)
    return {"steps": steps[:30], "stages": stages}


def tool_action(alert):
    t = (alert.get("action_taken") or "").strip()
    if not t:
        return {"text": None, "state": "unknown", "advice": "The alert does not say what your tools did. Check the EDR or firewall for the outcome."}
    low = t.lower()
    if any(w in low for w in BLOCKED):
        return {"text": t, "state": "blocked", "advice": "Your tool reports it stopped this. Confirm in the tool that it was blocked and not only logged."}
    if any(w in low for w in ALLOWED):
        return {"text": t, "state": "allowed", "advice": "Your tool reports it did NOT stop this. Treat the activity as having happened."}
    return {"text": t, "state": "other", "advice": "Check in the tool what this outcome means."}


def blast_radius(alert, alerts, host_findings_by_host, siem_evidence):
    """Where the alert's indicators appear elsewhere: in other alerts Quanta holds, and in the SIEM searches that counted hosts."""
    e = alert.get("entities") or {}
    inds = [("address", v) for v in e.get("ips") or []] + [("domain", v) for v in e.get("domains") or []] + [("hash", v) for v in e.get("hashes") or []] + [("url", v) for v in e.get("urls") or []]
    rows, hosts_all = [], set()
    for kind, v in inds[:20]:
        hosts = sorted({(a.get("asset") or "").lower() for a in alerts if a["id"] != alert["id"] and a.get("asset") and _has(a, kind, v)})
        hosts_all.update(hosts)
        rows.append({"kind": kind, "value": v, "other_hosts": hosts[:20], "other_hosts_count": len(hosts)})
    siem = [{"name": q["name"], "count": q.get("count"), "hosts": (q.get("rows") or [{}])[0].get("hosts")} for q in siem_evidence if q.get("error") is None and "else" in q["name"].lower()]
    exposed = []
    for h in sorted(hosts_all)[:10]:
        f = host_findings_by_host.get(h) or {}
        if f.get("kev"):
            exposed.append(f"{h}: {f['kev']} known-exploited vulnerability(ies) open")
    wide = any(str(s.get("hosts") or "").isdigit() and int(str(s["hosts"])) > 1 for s in siem)
    scope = "more than one host" if hosts_all or wide else "single host"
    return {"indicators": rows, "siem": siem, "hosts_total": len(hosts_all), "scope": scope, "exposed": exposed,
            "text": ("The indicators appear in no other alert Quanta holds." if not hosts_all else f"The same indicators appear in alerts on {len(hosts_all)} other host(s): " + ", ".join(sorted(hosts_all)[:8]) + ".")}


def recommended_actions(alert, inv, tool, blast, rule_stats, playbooks=()):
    v, sig = inv["verdict"], inv["signals"]
    acts = []
    if v == "likely-false-positive":
        acts.append(("Document as a false positive", "Close with the reasons above so the next analyst can see why."))
        acts.append(("No immediate action", "Nothing here needs containment."))
        if rule_stats and rule_stats.get("rule_noise_rate") and rule_stats["rule_noise_rate"] >= 0.5:
            acts.append(("Tune the rule", f"{alert.get('rule_name')} is closed benign or false positive {round(100 * rule_stats['rule_noise_rate'])}% of the time; see Detection engineering."))
        acts.append(("Watch for recurrence", "Reopen if the same host, user or address alerts again within a week."))
    elif v == "likely-true-positive":
        if inv.get("runbook"):
            acts += [(f"Step {i}", s) for i, s in enumerate(inv["runbook"]["steps"][:4], 1)]
        if blast["hosts_total"]:
            acts.append(("Check the other hosts", f"The indicators were seen on {blast['hosts_total']} other host(s): decide whether to isolate them."))
        if tool["state"] == "allowed":
            acts.append(("Contain now", "Your tools allowed the activity; do not wait for the full investigation."))
    else:
        acts.append(("Hand to level 2", "The evidence is thin or mixed; a person should decide."))
        if not inv["siem_evidence"]:
            acts.append(("Search the SIEM", "Run the investigation with the SIEM search to see what else the host and user did."))
        if inv.get("lookup_note"):
            acts.append(("Look up the indicators", "Run the investigation with the reputation lookup."))
    if tool["state"] == "blocked":
        acts.append(("Verify the block", tool["advice"]))
    if inv["host"]["kev_findings"]:
        acts.append(("Fix the exposure", f"{inv['host']['kev_findings']} known-exploited vulnerability(ies) are open on the host."))
    pbs = [p["name"] for p in playbooks][:3]
    if pbs and v != "likely-false-positive":
        acts.append(("Playbooks you could run", ", ".join(pbs) + ". Run as a dry run first; anything that changes your environment needs a second person."))
    return [{"action": a, "why": w} for a, w in acts]


def references(alert, inv):
    refs = [{"kind": "search", "name": q["name"], "detail": f"{q['count']} event(s) over {q.get('window', 'the look-back')}" if q.get("error") is None else f"failed: {q['error']}", "query": q["query"]} for q in inv["siem_evidence"]]
    if alert.get("rule_name"):
        refs.append({"kind": "detection rule", "name": alert["rule_name"], "detail": "", "query": None})
    if inv.get("runbook"):
        refs.append({"kind": "runbook", "name": inv["runbook"]["title"], "detail": inv["runbook"]["id"], "query": None})
    return refs


def widen_note(inv, max_days):
    """If a history search found activity across the whole window, say a wider look needs a justification rather than looking wider by itself."""
    hits = [q for q in inv["siem_evidence"] if q.get("error") is None and (q.get("count") or 0) >= 25 and (q.get("lookback_days") or 0) >= max_days]
    return (f"{hits[0]['name']} found {hits[0]['count']} events across the whole {max_days}-day window. If this looks widespread, ask for a wider look-back with a written reason; "
            "Quanta does not widen it on its own.") if hits else None


# ---------------------------------------------------------------- assembly
def build(alert, alerts, inv, findings=(), identity=None, playbooks=(), max_lookback_days=90):
    host_ctx = inv["host"]
    by_host = {}
    for f in findings:
        if (f.get("kev") or {}).get("listed") and f.get("status") not in ("resolved", "closed"):
            h = ((f.get("asset") or {}).get("name") or "").lower()
            by_host.setdefault(h, {"kev": 0})["kev"] += 1
    tool = tool_action(alert)
    hist = entity_history(alert, alerts)
    blast = blast_radius(alert, alerts, by_host, inv["siem_evidence"])
    info = technique_info(alert.get("technique"))
    n_host = sum(1 for a in alerts if a["id"] != alert["id"] and (a.get("asset") or "").lower() == (alert.get("asset") or "").lower() and alert.get("asset"))
    gist = (f"{alert['title']}" + (f" on {alert['asset']}" if alert.get("asset") else "") + (f" ({info['id']} {info['name'] or ''}".rstrip() + ")" if info else "") + ". "
            f"{n_host} other alert(s) on this host" + (f"; {host_ctx['kev_findings']} known-exploited vulnerability(ies) open there" if host_ctx["kev_findings"] else "") + ".")
    return {"headline": alert["title"], "gist": gist, "verdict": inv["verdict"], "confidence": inv["confidence"], "reasons": inv["reasons"], "history": hist, "entities": associated_entities(alert, host_ctx, identity),
            "attack": technique_guidance(alert.get("technique")), "flow": attack_flow(alert, alerts), "blast_radius": blast, "tool_action": tool,
            "actions": recommended_actions(alert, inv, tool, blast, inv["history"], playbooks), "references": references(alert, inv), "widen_note": widen_note(inv, max_lookback_days),
            "followups": []}


def _table(rows, cols):
    return ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)] + ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]


def to_markdown(alert, inv):
    r = inv["report"]
    L = [f"# Investigation: {r['headline']}", "", f"**Recommended verdict: {r['verdict']}** (confidence {r['confidence']}). A person validates this; Quanta has not closed or changed the alert.", "", r["gist"], "",
         "## Why", *[f"- {x}" for x in r["reasons"]], "", "## Incident summary",
         f"- Source: {alert['source']} / {alert['external_id']}   Severity: {alert['severity']}   Rule: {alert.get('rule_name') or 'not given'}",
         f"- Raised: {alert.get('occurred_at') or alert['received_at']}   Category: {inv['category']}", f"- Detail: {alert.get('detail') or 'none given'}", "", "## Historical correlation"]
    L += [f"- {h['text']}" for h in r["history"]] or ["- The alert names no host, user or address to correlate."]
    for q in inv["siem_evidence"]:
        if "else" in q["name"].lower() or "earlier" in q["name"].lower():
            L.append(f"- SIEM, {q['name'].lower()}: " + (f"{q['count']} event(s)" if q.get("error") is None else f"search failed ({q['error']})"))
    L += ["", "## Associated entities"] + (_table([(e["kind"], e["value"], e["detail"]) for e in r["entities"]], ["Kind", "Value", "Detail"]) if r["entities"] else ["None named in the alert."])
    L += ["", "## ATT&CK mapping"]
    a = r["attack"]
    if a:
        L.append(f"- {a['id']} {a['name'] or ''}" + (f" ({', '.join(a['tactics'])})" if a["tactics"] else " (tactic not in Quanta's table)"))
        if a["what_to_check"]:
            L.append(f"- What to check next: {a['what_to_check']}")
        if a["data_sources"]:
            L.append("- Look in: " + "; ".join(a["data_sources"]))
        L += [f"- Mitigation: {m['name']}: {m['action']}" for m in a["mitigations"][:3]]
    else:
        L.append("The alert carries no ATT&CK technique.")
    L += ["", "## Attack flow", "Alerts on this host or for this user, in time order." + (" Stages: " + " -> ".join(r["flow"]["stages"]) + "." if r["flow"]["stages"] else "")]
    L += _table([(s["at"], ("-> " if s["current"] else "") + s["title"], s["tactic"] or "-", s["technique"] or "-") for s in r["flow"]["steps"]], ["When", "Alert", "Tactic", "Technique"])
    L += ["", "## Indicators"]
    if inv["indicators"]:
        L += _table([(x["value"], x["type"], x.get("result") or "not looked up", (str(x["malicious"]) + (" of " + str(x["total"]) if x.get("total") else "")) if x.get("malicious") is not None else "-") for x in inv["indicators"]], ["Indicator", "Type", "Result", "Flagged by"])
    else:
        L.append("None in the alert.")
    if inv["lookup_note"]:
        L.append(f"\n{inv['lookup_note']}")
    b = r["blast_radius"]
    L += ["", "## Blast radius", b["text"], f"Scope: {b['scope']}."] + [f"- {x}" for x in b["exposed"]]
    for q in b["siem"]:
        L.append(f"- SIEM, {q['name'].lower()}: {q['count']} event(s)" + (f" on {q['hosts']} host(s)" if q.get("hosts") else ""))
    t = r["tool_action"]
    L += ["", "## What your tools did", (f"Reported outcome: {t['text']}. " if t["text"] else "") + t["advice"]]
    L += ["", "## Recommended actions"] + [f"- **{x['action']}**: {x['why']}" for x in r["actions"]]
    if r["widen_note"]:
        L += ["", r["widen_note"]]
    L += ["", "## References"] + [f"- {x['kind']}: {x['name']}" + (f" ({x['detail']})" if x["detail"] else "") for x in r["references"]]
    if inv["siem_evidence"]:
        L += ["", "Searches run (read-only):"] + [f"    {q['query']}" for q in inv["siem_evidence"]]
    L += ["", "## Timeline", *[f"- {t['at']}  {t['event']}" for t in inv["timeline"]]]
    if r["followups"]:
        L += ["", "## Follow-ups"] + [f"- Q: {f['question']}\n  A: {f['answer']}" for f in r["followups"]]
    return "\n".join(L) + "\n"


def to_html(alert, inv):
    return detection.to_html(to_markdown(alert, inv), f"Investigation: {alert['title']}")
