"""
The database-backed glue for hunting and triage: running a hunt lead in the SIEM, keeping threat-intel reports, and keeping investigations.

Connections are the ones an administrator stored on the Connections page (credentials encrypted there). A search or a reputation lookup only
ever happens because a person asked for it on a specific hunt or alert; nothing here runs on a schedule.
"""
import datetime
import json

from sqlalchemy import insert, select, update

from remediation.connections import registry, store as conn_store
from remediation.hunting import store as hunt_store
from remediation.utils import db as db_module


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def find_connection(conn_type, connection_id=None, engine=None):
    """The stored connection to use: the one asked for, else the first enabled one of that type. Returns (public, values) or (None, None)."""
    if connection_id:
        public, values = conn_store.get_values(int(connection_id), engine)
        return (public, values) if public and public["type"] == conn_type else (None, None)
    for c in conn_store.list_connections(engine):
        if c["type"] == conn_type and c["enabled"]:
            return conn_store.get_values(c["id"], engine)
    return None, None


def connector(conn_type, connection_id=None, engine=None):
    public, values = find_connection(conn_type, connection_id, engine)
    if not public:
        return None, None
    registry.split_values(conn_type, values)  # the SSRF guard again at use time
    return registry.SPECS[conn_type]["build"](values), public


def run_hunt_query(hunt_id, index, connector_obj, earliest="-24h", max_rows=25, engine=None):
    """Runs lead `index` of a hunt and records the count, a short sample and when it ran. Raises KeyError/IndexError for a bad id; a search
    error is recorded on the lead (result 'error') and re-raised."""
    hunt = hunt_store.get_hunt(hunt_id, engine)
    if not hunt:
        raise KeyError("No such hunt")
    if index < 0 or index >= len(hunt["queries"]):
        raise IndexError("No such query")
    q = hunt["queries"][index]
    try:
        r = connector_obj.search(q["query"], earliest=earliest, max_rows=max_rows)
        q.update({"result": "hits" if r["count"] else "no-hits", "count": r["count"], "sample": r["rows"], "truncated": r["truncated"], "error": None})
    except Exception as exc:  # noqa: BLE001 - recorded on the lead, then re-raised
        q.update({"result": "error", "count": None, "sample": [], "error": str(exc)[:300]})
        q["ran_at"], q["window"] = _now(), earliest
        hunt_store.update_hunt(hunt_id, {"queries": hunt["queries"]}, engine)
        raise
    q["ran_at"], q["window"] = _now(), earliest
    if hunt["status"] == "proposed":
        hunt_store.update_hunt(hunt_id, {"queries": hunt["queries"], "status": "active"}, engine)
    else:
        hunt_store.update_hunt(hunt_id, {"queries": hunt["queries"]}, engine)
    return q


# ---------------------------------------------------------------- threat intel reports
def save_intel(title, source, content_hash, extracted, score, priority, reasons, actor, engine=None):
    engine, t = _engine(engine), db_module.threat_intel_reports
    with engine.begin() as conn:
        existing = conn.execute(select(t.c.id).where(t.c.content_hash == content_hash)).first()
        if existing:
            return existing[0], False
        rid = conn.execute(insert(t), {"title": title[:200], "source": (source or None), "content_hash": content_hash, "extracted_json": json.dumps(extracted),
                                       "relevance": score, "priority": priority, "reasons_json": json.dumps(reasons), "hunt_id": None, "received_by": actor,
                                       "received_at": _now()}).inserted_primary_key[0]
    return rid, True


def _intel(r):
    d = dict(r)
    d["extracted"] = json.loads(d.pop("extracted_json"))
    d["reasons"] = json.loads(d.pop("reasons_json"))
    return d


def get_intel(report_id, engine=None):
    engine, t = _engine(engine), db_module.threat_intel_reports
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(report_id))).mappings().first()
    return _intel(r) if r else None


def list_intel(engine=None):
    engine, t = _engine(engine), db_module.threat_intel_reports
    with engine.connect() as conn:
        rows = conn.execute(select(t).order_by(t.c.relevance.desc(), t.c.id.desc())).mappings().all()
    return [_intel(r) for r in rows]


def link_intel_hunt(report_id, hunt_id, engine=None):
    engine, t = _engine(engine), db_module.threat_intel_reports
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.id == int(report_id)).values(hunt_id=hunt_id))


# ---------------------------------------------------------------- investigations
def save_investigation(inv, md, actor, engine=None):
    engine, t = _engine(engine), db_module.soc_investigations
    with engine.begin() as conn:
        iid = conn.execute(insert(t), {"alert_id": inv["alert_id"], "verdict": inv["verdict"], "confidence": inv["confidence"], "reasons_json": json.dumps(inv["reasons"]),
                                       "evidence_json": json.dumps(inv), "report_md": md, "created_by": actor, "created_at": _now()}).inserted_primary_key[0]
    return iid


def _inv(r):
    d = dict(r)
    d["reasons"] = json.loads(d.pop("reasons_json"))
    d["investigation"] = json.loads(d.pop("evidence_json"))
    return d


def latest_investigation(alert_id, engine=None):
    engine, t = _engine(engine), db_module.soc_investigations
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.alert_id == int(alert_id)).order_by(t.c.id.desc()).limit(1)).mappings().first()
    return _inv(r) if r else None
