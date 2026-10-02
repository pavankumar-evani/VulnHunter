"""Storage for threat models and the reviews of their threats. Threats themselves are computed on read from the model (see engine.py), so a
changed model never leaves stale threats behind; only the decisions a person made (accepted, mitigated, not applicable) are stored."""
import datetime
import json

from sqlalchemy import delete, insert, select, update

from remediation.threatmodel import engine as tm_engine
from remediation.utils import db as db_module


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def _row(r):
    d = dict(r)
    d["model"] = json.loads(d.pop("model_json") or "{}")
    return d


def create(name, description, model, actor, engine=None):
    name = (name or "").strip()
    if not name or len(name) > 120:
        raise ValueError("A name of 1 to 120 characters is required")
    model = tm_engine.normalise_model(model or {"components": [], "data_flows": [], "trust_zones": []})
    engine, t, stamp = _engine(engine), db_module.threat_models, _now()
    with engine.begin() as conn:
        mid = conn.execute(insert(t), {"name": name, "description": (description or "")[:1000], "model_json": json.dumps(model), "created_by": actor,
                                       "created_at": stamp, "updated_at": stamp, "updated_by": actor}).inserted_primary_key[0]
    return get(mid, engine)


def get(model_id, engine=None):
    engine, t = _engine(engine), db_module.threat_models
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(model_id))).mappings().first()
    return _row(r) if r else None


def list_models(engine=None):
    engine, t = _engine(engine), db_module.threat_models
    with engine.connect() as conn:
        rows = [_row(r) for r in conn.execute(select(t).order_by(t.c.name)).mappings().all()]
    for r in rows:
        r["components"], r["flows"] = len(r["model"].get("components", [])), len(r["model"].get("data_flows", []))
        del r["model"]
    return rows


def update_model(model_id, actor, name=None, description=None, model=None, engine=None):
    engine, t = _engine(engine), db_module.threat_models
    values = {"updated_at": _now(), "updated_by": actor}
    if name is not None:
        if not name.strip() or len(name) > 120:
            raise ValueError("A name of 1 to 120 characters is required")
        values["name"] = name.strip()
    if description is not None:
        values["description"] = description[:1000]
    if model is not None:
        values["model_json"] = json.dumps(tm_engine.normalise_model(model))
    with engine.begin() as conn:
        if conn.execute(update(t).where(t.c.id == int(model_id)).values(**values)).rowcount != 1:
            raise KeyError("No such threat model")
    return get(model_id, engine)


def delete_model(model_id, engine=None):
    engine = _engine(engine)
    with engine.begin() as conn:
        conn.execute(delete(db_module.threat_reviews).where(db_module.threat_reviews.c.model_id == int(model_id)))
        return conn.execute(delete(db_module.threat_models).where(db_module.threat_models.c.id == int(model_id))).rowcount == 1


def set_review(model_id, key, status, note, actor, engine=None):
    if status not in tm_engine.REVIEW_STATUSES:
        raise ValueError(f"status must be one of {', '.join(tm_engine.REVIEW_STATUSES)}")
    if status in ("accepted", "not-applicable") and not (note or "").strip():
        raise ValueError("Say why in the note when accepting a threat or marking it not applicable")
    engine, t, stamp = _engine(engine), db_module.threat_reviews, _now()
    with engine.begin() as conn:
        if not conn.execute(select(db_module.threat_models.c.id).where(db_module.threat_models.c.id == int(model_id))).first():
            raise KeyError("No such threat model")
        existing = conn.execute(select(t.c.threat_key).where(t.c.model_id == int(model_id), t.c.threat_key == key)).first()
        if existing:
            conn.execute(update(t).where(t.c.model_id == int(model_id), t.c.threat_key == key).values(status=status, note=note, reviewer=actor, updated_at=stamp))
        else:
            conn.execute(insert(t), {"model_id": int(model_id), "threat_key": key, "status": status, "note": note, "reviewer": actor, "updated_at": stamp})


def reviews(model_id, engine=None):
    engine, t = _engine(engine), db_module.threat_reviews
    with engine.connect() as conn:
        rows = conn.execute(select(t).where(t.c.model_id == int(model_id))).mappings().all()
    return {r["threat_key"]: {"status": r["status"], "note": r["note"], "reviewer": r["reviewer"], "updated_at": r["updated_at"]} for r in rows}


def analyse(model_id, findings=None, engine=None, controls_for=None):
    rec = get(model_id, engine)
    if not rec:
        raise KeyError("No such threat model")
    result = tm_engine.analyse(rec["model"], findings, controls_for=controls_for, reviews=reviews(model_id, engine))
    return {"id": rec["id"], "name": rec["name"], "description": rec["description"], "updated_at": rec["updated_at"], "updated_by": rec["updated_by"], **result}
