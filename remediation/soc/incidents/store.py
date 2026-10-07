"""Storage and plumbing for incidents: policy, rows, events, the timeline, listing. The rules live in correlate.py, routing.py and service.py."""
import datetime
import json
from pathlib import Path

import yaml
from sqlalchemy import insert, select, update

from remediation.utils import db as db_module

POLICY_PATH = Path(__file__).resolve().parents[2] / "config" / "soc_routing.yaml"
OPEN = ("new", "triaging", "investigating", "contained")
STATUSES = OPEN + ("resolved", "auto_closed", "merged")
VERDICTS = ("true-positive", "false-positive", "benign", "duplicate", "insufficient-data", "accepted-risk")
SEVERITIES = ("Informational", "Low", "Medium", "High", "Critical")      # ascending
PRIORITY_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
JSON_FIELDS = ("routing_reason", "correlation", "kill_chain", "entities", "assets", "techniques", "cves")
DEFAULTS = {"routing_reason": [], "correlation": [], "kill_chain": [], "entities": {}, "assets": [], "techniques": [], "cves": []}


def policy():
    with open(POLICY_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def enabled():
    return bool((policy().get("incidents") or {}).get("enabled"))


def now_dt():
    return datetime.datetime.now(datetime.timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse(s):
    try:
        return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc) if s else None
    except (TypeError, ValueError):
        return None


def engine_for(engine=None):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def sev_index(s):
    return SEVERITIES.index(s) if s in SEVERITIES else 0


def row_to_incident(r):
    d = dict(r)
    for k in JSON_FIELDS:
        raw = d.pop(f"{k}_json", None)
        d[k] = json.loads(raw) if raw else json.loads(json.dumps(DEFAULTS[k]))
    return d


def event(conn, incident_id, kind, actor, body="", data=None, now=None):
    return conn.execute(insert(db_module.soc_incident_events), {"incident_id": int(incident_id), "kind": kind, "actor": actor, "body": (body or "")[:4000],
                                                               "data_json": json.dumps(data) if data else None, "created_at": iso(now or now_dt())}).inserted_primary_key[0]


def add_event(incident_id, kind, actor, body="", data=None, engine=None, now=None):
    engine = engine_for(engine)
    with engine.begin() as conn:
        return event(conn, incident_id, kind, actor, body, data, now)


def raw_incident(incident_id, engine=None):
    engine, t = engine_for(engine), db_module.soc_incidents
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(incident_id))).mappings().first()
    return row_to_incident(r) if r else None


def write(incident_id, values, engine=None, now=None):
    """Updates incident columns. JSON fields are given by their plain name and encoded here."""
    engine, t = engine_for(engine), db_module.soc_incidents
    v = {}
    for k, x in values.items():
        if k in JSON_FIELDS:
            v[f"{k}_json"] = json.dumps(x)
        else:
            v[k] = x
    v["updated_at"] = iso(now or now_dt())
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.id == int(incident_id)).values(**v))


def alert_rows(incident_id, engine=None):
    """The alerts of an incident with the link's role, reasons and the facts captured when each arrived."""
    engine = engine_for(engine)
    ia, a = db_module.soc_incident_alerts, db_module.soc_alerts
    with engine.connect() as conn:
        rows = conn.execute(select(a, ia.c.role, ia.c.reasons_json, ia.c.facts_json, ia.c.linked_at).join(ia, ia.c.alert_id == a.c.id)
                            .where(ia.c.incident_id == int(incident_id)).order_by(a.c.id)).mappings().all()
    out = []
    for r in rows:
        d = dict(r)
        d["reasons"] = json.loads(d.pop("reasons_json") or "[]")
        d["facts"] = json.loads(d.pop("facts_json") or "{}")
        try:
            d["entities"] = json.loads(d.pop("entities_json") or "null") or {}
        except ValueError:
            d["entities"] = {}
        out.append(d)
    return out


def events(incident_id, engine=None):
    engine, t = engine_for(engine), db_module.soc_incident_events
    with engine.connect() as conn:
        rows = conn.execute(select(t).where(t.c.incident_id == int(incident_id)).order_by(t.c.id)).mappings().all()
    return [{**{k: v for k, v in dict(r).items() if k != "data_json"}, "data": json.loads(r["data_json"]) if r["data_json"] else None} for r in rows]


def case_sla(case_id, engine=None, now=None):
    from remediation.soc import cases
    if not case_id:
        return None
    c = cases.get_case(case_id, engine, now, detail=False)
    return None if not c else {"case_id": c["id"], "status": c["status"], "tier": c["tier"], "priority": c["priority"], "impact": c["impact"], "sla": c["sla"],
                              "auto_escalated_tiers": c["auto_escalated_tiers"]}


def get_incident(incident_id, engine=None, now=None, detail=True):
    inc = raw_incident(incident_id, engine)
    if not inc:
        return None
    inc["case"] = case_sla(inc["case_id"], engine, now)
    inc["sla"] = (inc["case"] or {}).get("sla")
    if detail:
        rows = alert_rows(inc["id"], engine)
        inc["alerts"] = [{"id": r["id"], "title": r["title"], "severity": r["severity"], "asset": r["asset"], "technique": r["technique"], "rule_name": r["rule_name"],
                          "status": r["status"], "disposition": r["disposition"], "received_at": r["received_at"], "role": r["role"], "reasons": r["reasons"],
                          "verdict": r["facts"].get("verdict"), "verdict_confidence": r["facts"].get("verdict_confidence"), "tactic": r["facts"].get("tactic")} for r in rows]
        inc["duplicate_count"] = sum(1 for r in rows if r["role"] == "duplicate")
        inc["timeline"] = events(inc["id"], engine)
    return inc


def list_incidents(engine=None, assignee=None, queue=None, status=None, severity=None, tier=None, mine=None, open_only=False, unassigned=False, now=None):
    engine, t = engine_for(engine), db_module.soc_incidents
    q = select(t)
    if assignee:
        q = q.where(t.c.assignee == assignee.lower())
    if mine:
        q = q.where(t.c.assignee == mine.lower())
    if queue:
        q = q.where(t.c.queue == queue)
    if status:
        q = q.where(t.c.status == status)
    if severity:
        q = q.where(t.c.severity == severity)
    if tier:
        q = q.where(t.c.tier == int(tier))
    if open_only:
        q = q.where(t.c.status.in_(OPEN))
    if unassigned:
        q = q.where(t.c.assignee.is_(None))
    with engine.connect() as conn:
        rows = [row_to_incident(r) for r in conn.execute(q).mappings().all()]
    if any(i["case_id"] for i in rows):
        from remediation.soc import cases
        by_case = {c["id"]: c for c in cases.list_cases(engine, now=now)}
        for inc in rows:
            c = by_case.get(inc["case_id"])
            inc["sla"] = c["sla"] if c else None
    for inc in rows:
        inc.setdefault("sla", None)
    rows.sort(key=lambda i: (i["status"] not in OPEN, PRIORITY_RANK.get(i["priority"], 9), i["created_at"], i["id"]))
    return rows


def link_alert(conn, incident_id, alert_id, role, reasons, facts, now):
    conn.execute(insert(db_module.soc_incident_alerts), {"incident_id": int(incident_id), "alert_id": int(alert_id), "role": role, "reasons_json": json.dumps(reasons),
                                                         "facts_json": json.dumps(facts), "linked_at": iso(now)})


def incident_for_alert(alert_id, engine=None):
    engine, t = engine_for(engine), db_module.soc_incident_alerts
    with engine.connect() as conn:
        r = conn.execute(select(t.c.incident_id).where(t.c.alert_id == int(alert_id))).first()
    return r[0] if r else None
