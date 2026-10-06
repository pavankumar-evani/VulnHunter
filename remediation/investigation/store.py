"""Storage for investigation reports, analyst follow-ups, hunt allow-list entries and hunt time-boxes. No rules here; see incident_report.py, followup.py, hunt_report.py."""
import datetime
import json

from sqlalchemy import delete, insert, select, update

from remediation.utils import db as db_module


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


# ---------------------------------------------------------------- reports
def save_report(incident_id, report, actor, live=False, engine=None):
    engine, t = _engine(engine), db_module.investigation_reports
    with engine.begin() as conn:
        last = conn.execute(select(t.c.version).where(t.c.incident_id == int(incident_id)).order_by(t.c.version.desc()).limit(1)).first()
        version = (last[0] + 1) if last else 1
        report = {**report, "version": version}
        conn.execute(insert(t), {"incident_id": int(incident_id), "version": version, "report_json": json.dumps(report), "live": 1 if live else 0,
                                 "generated_by": actor, "generated_at": _now()})
    return report


def latest_report(incident_id, engine=None):
    engine, t = _engine(engine), db_module.investigation_reports
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.incident_id == int(incident_id)).order_by(t.c.version.desc()).limit(1)).mappings().first()
    return json.loads(r["report_json"]) if r else None


def report_versions(incident_id, engine=None):
    engine, t = _engine(engine), db_module.investigation_reports
    with engine.connect() as conn:
        rows = conn.execute(select(t.c.version, t.c.live, t.c.generated_by, t.c.generated_at).where(t.c.incident_id == int(incident_id)).order_by(t.c.version)).mappings().all()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------- follow-ups
def _fu(r):
    d = dict(r)
    d["data"] = json.loads(d.pop("data_json") or "null")
    d["evidence"] = json.loads(d.pop("evidence_json") or "[]")
    d["answerable"] = bool(d["answerable"])
    d["merged"] = bool(d["merged"])
    return d


def add_followup(incident_id, kind, value, question, answer, data, evidence, answerable, actor, engine=None):
    engine, t = _engine(engine), db_module.incident_followups
    with engine.begin() as conn:
        fid = conn.execute(insert(t), {"incident_id": int(incident_id), "kind": kind, "value": value, "question": question[:500], "answer": answer[:4000],
                                       "data_json": json.dumps(data) if data is not None else None, "evidence_json": json.dumps(evidence or []),
                                       "answerable": 1 if answerable else 0, "merged": 0, "asked_by": actor, "asked_at": _now()}).inserted_primary_key[0]
    return get_followup(fid, engine)


def get_followup(fid, engine=None):
    engine, t = _engine(engine), db_module.incident_followups
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(fid))).mappings().first()
    return _fu(r) if r else None


def list_followups(incident_id, engine=None):
    engine, t = _engine(engine), db_module.incident_followups
    with engine.connect() as conn:
        rows = conn.execute(select(t).where(t.c.incident_id == int(incident_id)).order_by(t.c.id)).mappings().all()
    return [_fu(r) for r in rows]


def set_merged(incident_id, ids, merged, actor, engine=None):
    """Marks follow-ups of this incident merged (or not). Returns the ids that changed; an id of another incident is ignored."""
    engine, t = _engine(engine), db_module.incident_followups
    own = {f["id"] for f in list_followups(incident_id, engine)}
    chosen = [int(i) for i in ids if int(i) in own]
    if chosen:
        with engine.begin() as conn:
            conn.execute(update(t).where(t.c.id.in_(chosen)).values(merged=1 if merged else 0, merged_by=actor if merged else None, merged_at=_now() if merged else None))
    return chosen


# ---------------------------------------------------------------- hunt allow-list
def lead_key(q):
    return f"{(q.get('technique') or '').upper()}|{(q.get('name') or '').strip()}"


def add_allow(lead, hunt_id, field, value, note, actor, engine=None):
    engine, t = _engine(engine), db_module.hunt_allowlist
    key = lead_key(lead)
    with engine.begin() as conn:
        dup = conn.execute(select(t.c.id).where(t.c.lead_key == key, t.c.field == field, t.c.value == value)).first()
        if dup:
            raise ValueError("This value is already on the allow-list for this lead")
        eid = conn.execute(insert(t), {"lead_key": key, "hunt_id": hunt_id, "field": field, "value": value, "note": note, "created_by": actor, "created_at": _now()}).inserted_primary_key[0]
    return get_allow(eid, engine)


def get_allow(eid, engine=None):
    engine, t = _engine(engine), db_module.hunt_allowlist
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(eid))).mappings().first()
    return dict(r) if r else None


def list_allow(engine=None, lead_keys=None):
    engine, t = _engine(engine), db_module.hunt_allowlist
    q = select(t).order_by(t.c.id)
    if lead_keys is not None:
        q = q.where(t.c.lead_key.in_(list(lead_keys)))
    with engine.connect() as conn:
        return [dict(r) for r in conn.execute(q).mappings().all()]


def remove_allow(eid, engine=None):
    engine, t = _engine(engine), db_module.hunt_allowlist
    with engine.begin() as conn:
        return conn.execute(delete(t).where(t.c.id == int(eid))).rowcount > 0


# ---------------------------------------------------------------- hunt report time-box
def set_time_box(hunt_id, hours, actor, engine=None):
    engine, t = _engine(engine), db_module.hunt_report_meta
    with engine.begin() as conn:
        if conn.execute(select(t.c.hunt_id).where(t.c.hunt_id == int(hunt_id))).first():
            conn.execute(update(t).where(t.c.hunt_id == int(hunt_id)).values(time_box_hours=hours, updated_by=actor, updated_at=_now()))
        else:
            conn.execute(insert(t), {"hunt_id": int(hunt_id), "time_box_hours": hours, "updated_by": actor, "updated_at": _now()})


def time_boxes(engine=None):
    engine, t = _engine(engine), db_module.hunt_report_meta
    with engine.connect() as conn:
        return {r[0]: r[1] for r in conn.execute(select(t.c.hunt_id, t.c.time_box_hours))}


# ---------------------------------------------------------------- alert/incident plumbing
def alert_incident_map(engine=None):
    """{alert_id: incident_id} for every alert linked to an incident (a duplicate included)."""
    engine, t = _engine(engine), db_module.soc_incident_alerts
    with engine.connect() as conn:
        return {r[0]: r[1] for r in conn.execute(select(t.c.alert_id, t.c.incident_id))}
