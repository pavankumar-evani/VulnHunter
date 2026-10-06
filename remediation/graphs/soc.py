"""SOC relationship graph: who and what is connected through alerts.

Alerts, the hosts / users / addresses / domains named on them, the ATT&CK techniques they carry, the SOC cases that contain them and the hunts
that look at the same techniques or hosts. An entity shared by several alerts is the point: that is how one campaign shows up. Everything comes
from the stores (hunting alerts and hunts, SOC cases); nothing is inferred and no node is invented.
"""
from sqlalchemy import select

from remediation.graphs.schema import GraphBuilder, empty
from remediation.hunting import store as hunting_store
from remediation.soc import cases as soc_cases
from remediation.utils import db as db_module

TITLE = "Alert relationships"
DESCRIPTION = "Alerts, the entities and techniques they share, the cases that contain them and the hunts that look at the same things."
_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "info", "info": "info"}


def _sev(s):
    return _SEV.get(str(s or "").strip().lower())


def _entities(alert):
    """[(kind, value)] named on an alert: its entities plus its asset field, de-duplicated, in a stable order."""
    ent = alert.get("entities") or {}
    out = []
    host = ent.get("host") or alert.get("asset")
    if host:
        out.append(("host", str(host).strip().lower()))
    if ent.get("user"):
        out.append(("user", str(ent["user"]).strip().lower()))
    for ip in ent.get("ips") or []:
        out.append(("ip", str(ip).strip().lower()))
    for d in ent.get("domains") or []:
        out.append(("domain", str(d).strip().lower()))
    seen, uniq = set(), []
    for k, v in out:
        if v and (k, v) not in seen:
            seen.add((k, v))
            uniq.append((k, v))
    return uniq


def _case_alert_links(engine):
    t = db_module.soc_case_alerts
    with engine.connect() as conn:
        return [(r[0], r[1]) for r in conn.execute(select(t.c.case_id, t.c.alert_id).order_by(t.c.case_id, t.c.alert_id)).all()]


def build(engine=None, findings=None, **context):
    alerts = hunting_store.list_alerts(engine)
    cases = soc_cases.list_cases(engine)
    hunts = hunting_store.list_hunts(engine)
    if not (alerts or cases):
        return empty("soc", TITLE, DESCRIPTION,
                     "No alerts or cases are recorded yet. Send alerts from your SIEM or XDR to /api/ingest/alerts (or /api/ingest/alerts/ocsf), "
                     "or open a case on the SOC Operations page, and the connections between them will appear here.")
    engine = engine or db_module.get_engine()
    g = GraphBuilder("soc", TITLE, DESCRIPTION)
    g.kind("alert", "Alert")
    g.kind("case", "SOC case")
    g.kind("hunt", "Hunt")
    g.kind("technique", "ATT&CK technique")
    g.kind("host", "Host")
    g.kind("user", "User")
    g.kind("ip", "IP address")
    g.kind("domain", "Domain")
    entity_alerts = {}
    alert_ids = set()
    for a in alerts:
        aid = f"alert:{a['id']}"
        alert_ids.add(a["id"])
        g.node(aid, a["title"][:60], "alert", sev=_sev(a["severity"]), href="/hunting?tab=alerts",
               meta={"severity": a["severity"], "status": a["status"], "source": a["source"], "rule": a.get("rule_name")})
        for kind, val in _entities(a):
            nid = f"{kind}:{val}"
            entity_alerts.setdefault(nid, set()).add(a["id"])
            g.node(nid, val, kind, weight=0, sev=_sev(a["severity"]), href="/assets" if kind == "host" else None)
            g.edge(aid, nid, "involves")
        tech = (a.get("technique") or "").strip().upper()
        if tech:
            g.node(f"technique:{tech}", tech, "technique", href="/hunting?tab=proposals")
            g.edge(aid, f"technique:{tech}", "tagged")
    for nid, ids in entity_alerts.items():
        g.node(nid, nid, nid.split(":", 1)[0], weight=len(ids), meta={"alerts": len(ids)})
    case_ids = set()
    for c in cases:
        cid = f"case:{c['id']}"
        case_ids.add(c["id"])
        g.node(cid, c["title"][:60], "case", sev=_sev(c["severity"]), href="/soc",
               meta={"priority": c["priority"], "status": c["status"], "tier": c["tier"], "severity": c["severity"]})
        for t in c.get("techniques") or []:
            t = str(t).strip().upper()
            if t:
                g.node(f"technique:{t}", t, "technique", href="/hunting?tab=proposals")
                g.edge(cid, f"technique:{t}", "tagged")
    for case_id, alert_id in _case_alert_links(engine):
        if case_id in case_ids and alert_id in alert_ids:
            g.edge(f"case:{case_id}", f"alert:{alert_id}", "contains")
    present = set(entity_alerts) | {f"technique:{(a.get('technique') or '').strip().upper()}" for a in alerts if a.get("technique")}
    present |= {f"technique:{str(t).strip().upper()}" for c in cases for t in c.get("techniques") or [] if str(t).strip()}
    for h in hunts:
        hid = f"hunt:{h['id']}"
        links = []
        for t in h.get("techniques") or []:
            nid = f"technique:{str(t).strip().upper()}"
            if nid in present:
                links.append((nid, "hunts"))
        for asset in h.get("assets") or []:
            nid = f"host:{str(asset).strip().lower()}"
            if nid in present:
                links.append((nid, "covers"))
        if not links:
            continue
        g.node(hid, h["title"][:60], "hunt", href="/hunting?tab=proposals", meta={"status": h["status"], "outcome": h["outcome"]})
        for target, kind in links:
            g.edge(hid, target, kind)
    return g.build(note="Entities and techniques linked to more than one alert are where a campaign shows up; hunts appear only where they share a technique or host with an alert.")
