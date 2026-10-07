"""
Storage for the knowledge base: report versions (`hunt_knowledge_reports`), AI-drafted items (`hunt_knowledge_drafts`, drafts only, always labelled) and the planning list
for suggested controls and rules (`hunt_planned_items`, never "implemented").
"""
import datetime
import json

from sqlalchemy import delete, insert, select, update

from remediation.utils import db as db_module

DRAFT_LABEL = "AI-drafted, unvalidated"
DRAFT_KINDS = ("hypothesis-refine", "query-draft", "result-summary")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


# ---------------------------------------------------------------- reports
def _report(r, full=True):
    d = {"id": r["id"], "subject": {"kind": r["subject_kind"], "id": r["subject_id"]}, "version": r["version"], "title": r["title"], "lookback_days": r["lookback_days"],
         "created_by": r["created_by"], "created_at": r["created_at"]}
    if full:
        d["report"] = json.loads(r["data_json"])
    return d


def save_report(kind, sid, title, lookback_days, report, actor, keep=10, engine=None):
    engine, t = _engine(engine), db_module.hunt_knowledge_reports
    with engine.begin() as conn:
        last = conn.execute(select(t.c.version).where(t.c.subject_kind == kind, t.c.subject_id == sid).order_by(t.c.version.desc()).limit(1)).scalar()
        version = (last or 0) + 1
        rid = conn.execute(insert(t), {"subject_kind": kind, "subject_id": sid, "version": version, "title": title[:200], "lookback_days": int(lookback_days), "created_by": actor,
                                       "created_at": _now(), "data_json": json.dumps({**report, "version": version})}).inserted_primary_key[0]
        old = [r[0] for r in conn.execute(select(t.c.id).where(t.c.subject_kind == kind, t.c.subject_id == sid).order_by(t.c.version.desc()).offset(max(1, int(keep))))]
        if old:
            conn.execute(delete(t).where(t.c.id.in_(old)))
    return get_report(rid, engine)


def get_report(rid, engine=None):
    engine, t = _engine(engine), db_module.hunt_knowledge_reports
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(rid))).mappings().first()
    return _report(r) if r else None


def list_reports(kind=None, sid=None, limit=50, engine=None):
    engine, t = _engine(engine), db_module.hunt_knowledge_reports
    q = select(t).order_by(t.c.id.desc()).limit(limit)
    if kind:
        q = q.where(t.c.subject_kind == kind)
    if sid:
        q = q.where(t.c.subject_id == sid)
    with engine.connect() as conn:
        return [_report(r, full=False) for r in conn.execute(q).mappings()]


# ---------------------------------------------------------------- AI drafts
def _draft(r):
    return {"id": r["id"], "kind": r["kind"], "subject": {"kind": r["subject_kind"], "id": r["subject_id"]}, "language": r["language"], "label": r["label"], "status": r["status"],
            "content": json.loads(r["content_json"]), "validation": json.loads(r["validation_json"]), "model": r["model"], "created_by": r["created_by"], "created_at": r["created_at"],
            "counts_as": "a model call in AI usage", "never": "applied, run or counted as coverage"}


def save_draft(kind, subject_kind, subject_id, content, validation, actor, language=None, model=None, engine=None):
    if kind not in DRAFT_KINDS:
        raise ValueError(f"kind must be one of {', '.join(DRAFT_KINDS)}")
    engine, t = _engine(engine), db_module.hunt_knowledge_drafts
    with engine.begin() as conn:
        did = conn.execute(insert(t), {"kind": kind, "subject_kind": subject_kind, "subject_id": subject_id, "language": language, "label": DRAFT_LABEL, "status": "draft",
                                       "content_json": json.dumps(content), "validation_json": json.dumps(validation), "model": model, "created_by": actor, "created_at": _now()}).inserted_primary_key[0]
    return get_draft(did, engine)


def get_draft(did, engine=None):
    engine, t = _engine(engine), db_module.hunt_knowledge_drafts
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(did))).mappings().first()
    return _draft(r) if r else None


def list_drafts(subject_kind=None, subject_id=None, limit=50, engine=None):
    engine, t = _engine(engine), db_module.hunt_knowledge_drafts
    q = select(t).order_by(t.c.id.desc()).limit(limit)
    if subject_kind:
        q = q.where(t.c.subject_kind == subject_kind)
    if subject_id:
        q = q.where(t.c.subject_id == subject_id)
    with engine.connect() as conn:
        return [_draft(r) for r in conn.execute(q).mappings()]


def count_drafts(subject_kind, subject_id, engine=None):
    return len(list_drafts(subject_kind, subject_id, limit=1000, engine=engine))


def discard_draft(did, engine=None):
    engine, t = _engine(engine), db_module.hunt_knowledge_drafts
    with engine.begin() as conn:
        n = conn.execute(update(t).where(t.c.id == int(did)).values(status="discarded")).rowcount
    if not n:
        raise KeyError("No such draft")
    return get_draft(did, engine)


# ---------------------------------------------------------------- planning list
def _planned(r):
    return {"key": r["key"], "kind": r["kind"], "title": r["title"], "status": r["status"], "ref": json.loads(r["ref_json"]), "note": r["note"], "created_by": r["created_by"],
            "created_at": r["created_at"], "is_implemented": False,
            "meaning": "Planned only. It enters the controls inventory when a person records it there as claimed or verified, and counts as detection coverage only when an enabled rule is evidenced."}


def plan(key, kind, title, ref, note, actor, engine=None):
    engine, t = _engine(engine), db_module.hunt_planned_items
    with engine.begin() as conn:
        have = conn.execute(select(t.c.status).where(t.c.key == key)).scalar()
        if have is None:
            conn.execute(insert(t), {"key": key, "kind": kind, "title": title[:200], "status": "planned", "ref_json": json.dumps(ref), "note": (note or "").strip() or None,
                                     "created_by": actor, "created_at": _now()})
        elif have == "discarded":
            conn.execute(update(t).where(t.c.key == key).values(status="planned", note=(note or "").strip() or None))
    return get_planned(key, engine)


def get_planned(key, engine=None):
    engine, t = _engine(engine), db_module.hunt_planned_items
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.key == key)).mappings().first()
    return _planned(r) if r else None


def list_planned(kind=None, engine=None):
    engine, t = _engine(engine), db_module.hunt_planned_items
    q = select(t).order_by(t.c.created_at.desc())
    if kind:
        q = q.where(t.c.kind == kind)
    with engine.connect() as conn:
        return [_planned(r) for r in conn.execute(q).mappings()]


def discard_planned(key, engine=None):
    engine, t = _engine(engine), db_module.hunt_planned_items
    with engine.begin() as conn:
        n = conn.execute(update(t).where(t.c.key == key).values(status="discarded")).rowcount
    if not n:
        raise KeyError("No such planned item")
    return get_planned(key, engine)
