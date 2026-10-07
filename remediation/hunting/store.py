"""
Hunt workspace and SOC alert store.

A hunt moves proposed -> active -> closed. Closing needs an outcome (confirmed, not-found, needs-data), because "we looked and found nothing" is a
result that has to be recorded or the hunt looks unfinished. Each query keeps the result the analyst reported next to it. An alert is received from a
SIEM or XDR (unique per source + external id, so a re-send updates nothing twice), worked by an assignee and closed with a disposition.
"""
import datetime
import json

from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError

from remediation.hunting import ocsf
from remediation.utils import db as db_module

HUNT_STATUSES = ("proposed", "active", "closed")
OUTCOMES = ("confirmed", "not-found", "needs-data")
ALERT_STATUSES = ("new", "investigating", "closed")
DISPOSITIONS = ("true-positive", "benign", "false-positive", "needs-data")
SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
QUERY_RESULTS = ("hits", "no-hits", "not-run", "error", "not-expressible")
ASSESSMENTS = ("benign", "suspicious", "malicious")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def _hunt(r):
    d = dict(r)
    for k in ("techniques", "assets", "data_sources", "queries"):
        d[k] = json.loads(d.pop(f"{k}_json") or "[]")
    d["detection_created"] = bool(d["detection_created"])
    return d


def create_hunt(h, actor, engine=None):
    title, hyp = (h.get("title") or "").strip(), (h.get("hypothesis") or "").strip()
    if not title or len(title) > 200:
        raise ValueError("A title of 1 to 200 characters is required")
    if not hyp:
        raise ValueError("State the hypothesis: what you expect to find and why")
    engine, t, now = _engine(engine), db_module.hunts, _now()
    row = {"title": title, "hypothesis": hyp, "source": h.get("source") or "manual", "source_ref": h.get("source_ref"), "status": "proposed",
           "outcome": None, "techniques_json": json.dumps(h.get("techniques") or []), "assets_json": json.dumps(h.get("assets") or []),
           "data_sources_json": json.dumps(h.get("data_sources") or []), "queries_json": json.dumps(h.get("queries") or []),
           "notes": h.get("notes") or "", "follow_ups": "", "detection_created": 0, "owner": h.get("owner"), "created_by": actor,
           "created_at": now, "updated_at": now, "closed_at": None}
    try:
        with engine.begin() as conn:
            hid = conn.execute(insert(t), row).inserted_primary_key[0]
    except IntegrityError:
        raise ValueError("A hunt for this already exists") from None
    return get_hunt(hid, engine)


def get_hunt(hunt_id, engine=None):
    engine, t = _engine(engine), db_module.hunts
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(hunt_id))).mappings().first()
    return _hunt(r) if r else None


def list_hunts(engine=None):
    engine, t = _engine(engine), db_module.hunts
    with engine.connect() as conn:
        rows = conn.execute(select(t).order_by(t.c.id.desc())).mappings().all()
    return [_hunt(r) for r in rows]


def update_hunt(hunt_id, fields, engine=None):
    cur = get_hunt(hunt_id, engine)
    if not cur:
        raise KeyError("No such hunt")
    values = {"updated_at": _now()}
    for k in ("title", "hypothesis", "notes", "follow_ups", "owner"):
        if k in fields and fields[k] is not None:
            if k in ("title", "hypothesis") and not str(fields[k]).strip():
                raise ValueError(f"{k} cannot be empty")
            values[k] = fields[k]
    if fields.get("detection_created") is not None:
        values["detection_created"] = 1 if fields["detection_created"] else 0
    if fields.get("queries") is not None:
        qs = fields["queries"]
        for q in qs:
            if q.get("result") not in (None, *QUERY_RESULTS):
                raise ValueError(f"A query result must be one of {', '.join(QUERY_RESULTS)}")
            if q.get("assessment") not in (None, *ASSESSMENTS):
                raise ValueError(f"A lead assessment must be one of {', '.join(ASSESSMENTS)}")
        values["queries_json"] = json.dumps(qs)
    status, outcome = fields.get("status", cur["status"]), fields.get("outcome", cur["outcome"])
    if status not in HUNT_STATUSES:
        raise ValueError(f"status must be one of {', '.join(HUNT_STATUSES)}")
    if outcome not in (None, *OUTCOMES):
        raise ValueError(f"outcome must be one of {', '.join(OUTCOMES)}")
    if status == "closed":
        if not outcome:
            raise ValueError("Record an outcome (confirmed, not-found or needs-data) before closing a hunt")
        if cur["status"] != "closed":
            values["closed_at"] = _now()
    else:
        values["closed_at"] = None
        outcome = None if status != "closed" and "outcome" not in fields else outcome
    values["status"], values["outcome"] = status, outcome
    engine, t = _engine(engine), db_module.hunts
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.id == int(hunt_id)).values(**values))
    return get_hunt(hunt_id, engine)


def existing_refs(engine=None):
    return {h["source_ref"] for h in list_hunts(engine) if h["source"] == "generated" and h["source_ref"]}


# ---- alerts ----

def _clean_severity(s):
    s = (s or "").strip().title() or "Medium"
    if s in ("Info", "Informational"):
        s = "Informational"
    if s not in SEVERITIES:
        raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}")
    return s


def _alert(r):
    d = dict(r)
    try:
        d["entities"] = json.loads(d.pop("entities_json") or "null") or ocsf.empty_entities()
    except ValueError:
        d["entities"] = ocsf.empty_entities()
    return d


def receive_alert(a, engine=None):
    """Stores one alert. Returns (alert, created); a repeat of (source, external_id) returns the existing one untouched."""
    ext, title = str(a.get("external_id") or "").strip(), (a.get("title") or "").strip()
    if not ext or not title:
        raise ValueError("An alert needs an external_id and a title")
    source = (a.get("source") or "api").strip()[:60]
    engine, t = _engine(engine), db_module.soc_alerts
    row = {"source": source, "external_id": ext[:200], "title": title[:300], "severity": _clean_severity(a.get("severity")), "asset": (a.get("asset") or None),
           "technique": (a.get("technique") or None), "detail": (a.get("detail") or "")[:4000], "status": "new", "disposition": None, "assignee": None,
           "notes": "", "occurred_at": a.get("occurred_at"), "received_at": _now(), "closed_at": None,
           "rule_name": (a.get("rule_name") or None) and str(a["rule_name"])[:200], "action_taken": (str(a.get("action_taken") or "").strip()[:120] or None)}
    ent = a.get("entities") if isinstance(a.get("entities"), dict) else None
    if ent is None:
        ent = ocsf.scan_text(f"{title} {a.get('detail') or ''}")
        ent["host"] = a.get("asset")
    else:
        ent = {**ocsf.empty_entities(), **ent}
    row["entities_json"] = json.dumps(ent)
    try:
        with engine.begin() as conn:
            aid = conn.execute(insert(t), row).inserted_primary_key[0]
        return get_alert(aid, engine), True
    except IntegrityError:
        with engine.connect() as conn:
            r = conn.execute(select(t).where(t.c.source == source, t.c.external_id == ext[:200])).mappings().first()
        return _alert(r), False


def get_alert(alert_id, engine=None):
    engine, t = _engine(engine), db_module.soc_alerts
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(alert_id))).mappings().first()
    return _alert(r) if r else None


def list_alerts(engine=None, status=None):
    engine, t = _engine(engine), db_module.soc_alerts
    q = select(t).order_by(t.c.id.desc())
    if status:
        q = q.where(t.c.status == status)
    with engine.connect() as conn:
        return [_alert(r) for r in conn.execute(q).mappings().all()]


def update_alert(alert_id, fields, engine=None):
    cur = get_alert(alert_id, engine)
    if not cur:
        raise KeyError("No such alert")
    values = {}
    for k in ("assignee", "notes"):
        if fields.get(k) is not None:
            values[k] = fields[k]
    status, disp = fields.get("status", cur["status"]), fields.get("disposition", cur["disposition"])
    if status not in ALERT_STATUSES:
        raise ValueError(f"status must be one of {', '.join(ALERT_STATUSES)}")
    if disp not in (None, *DISPOSITIONS):
        raise ValueError(f"disposition must be one of {', '.join(DISPOSITIONS)}")
    if status == "closed":
        if not disp:
            raise ValueError("Record a disposition (true-positive, benign, false-positive or needs-data) before closing an alert")
        if cur["status"] != "closed":
            values["closed_at"] = _now()
    else:
        values["closed_at"] = None
        if "disposition" not in fields:
            disp = None
    values["status"], values["disposition"] = status, disp
    engine, t = _engine(engine), db_module.soc_alerts
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.id == int(alert_id)).values(**values))
    return get_alert(alert_id, engine)
