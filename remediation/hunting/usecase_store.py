"""
Lifecycle store for generated detection use cases. The generator (usecases.py) is deterministic, so a case keeps the same key every time its evidence is
the same; syncing inserts new keys and refreshes the evidence of cases still proposed, but never touches a decision an engineer has recorded.

proposed -> accepted -> implemented, or rejected / deferred. Every decision needs a note, so the reason survives the person who made it.
"""
import datetime
import json

from sqlalchemy import insert, select, update

from remediation.utils import db as db_module

STATUSES = ("proposed", "accepted", "implemented", "rejected", "deferred")
DECIDED = ("accepted", "implemented", "rejected", "deferred")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def _row(r):
    d = dict(r)
    d.update(json.loads(d.pop("data_json")))
    return d


def sync(cases, engine=None):
    engine, t, now = _engine(engine), db_module.detection_usecases, _now()
    with engine.begin() as conn:
        have = {r["key"]: r["status"] for r in conn.execute(select(t.c.key, t.c.status)).mappings()}
        for c in cases:
            data = json.dumps({k: v for k, v in c.items() if k != "key"})
            if c["key"] not in have:
                conn.execute(insert(t), {"key": c["key"], "kind": c["kind"], "title": c["title"], "status": "proposed", "note": None, "ai_suggestion": None,
                                         "data_json": data, "decided_by": None, "created_at": now, "updated_at": now})
            elif have[c["key"]] == "proposed":
                conn.execute(update(t).where(t.c.key == c["key"]).values(title=c["title"], data_json=data, updated_at=now))
    return list_all(engine)


def list_all(engine=None, status=None):
    engine, t = _engine(engine), db_module.detection_usecases
    q = select(t).order_by(t.c.id)
    if status:
        q = q.where(t.c.status == status)
    with engine.connect() as conn:
        rows = [_row(r) for r in conn.execute(q).mappings()]
    rows.sort(key=lambda r: -r.get("score", 0))
    return rows


def get(key, engine=None):
    engine, t = _engine(engine), db_module.detection_usecases
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.key == key)).mappings().first()
    return _row(r) if r else None


def set_status(key, status, note, actor, engine=None):
    if status not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)}")
    if status in DECIDED and not (note or "").strip():
        raise ValueError("Write a note with the decision so the reason is kept")
    if not get(key, engine):
        raise KeyError("No such use case")
    engine, t = _engine(engine), db_module.detection_usecases
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.key == key).values(status=status, note=(note or "").strip() or None, decided_by=actor if status != "proposed" else None, updated_at=_now()))
    return get(key, engine)


def set_ai(key, text, engine=None):
    if not get(key, engine):
        raise KeyError("No such use case")
    engine, t = _engine(engine), db_module.detection_usecases
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.key == key).values(ai_suggestion=text[:6000], updated_at=_now()))
    return get(key, engine)
