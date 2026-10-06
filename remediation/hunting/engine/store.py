"""
Storage for hunt hypotheses (table `hunt_hypotheses`) and their event history (`hunt_hypothesis_events`).

Identity: a hypothesis id is a hash of its generator and subject, so a refresh updates the row it already has. What a refresh may and may not change:
  suggested      body, score and evidence are refreshed; a hypothesis the generators no longer produce is marked not current (kept for history, hidden)
  accepted..     never overwritten: a person is working on it
  concluded/promoted  never re-suggested
  dismissed      stays dismissed, unless the evidence MATERIALLY changed (`material_new_refs` new items, or any new strong item), in which case it returns as suggested
                 with a `reopened` event that keeps the earlier dismissal reason in the history
Outcome statistics per pattern are computed from the rows themselves, so there is no second copy to drift.
"""
import datetime
import json

from sqlalchemy import insert, select, update

from remediation.hunting.engine import model as m
from remediation.utils import db as db_module


def _now(now=None):
    return (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def _row(r):
    d = json.loads(r["data_json"])
    d.update({"id": r["id"], "generator": r["generator"], "hunt_type": r["hunt_type"], "pattern_key": r["pattern_key"], "status": r["status"], "outcome": r["outcome"], "outcome_notes": r["outcome_notes"], "dismissal_reason": r["dismissal_reason"],
              "hunt_id": r["hunt_id"], "promoted_key": r["promoted_key"], "current": bool(r["current"]), "decided_by": r["decided_by"],
              "created_at": r["created_at"], "updated_at": r["updated_at"]})
    d["priority"] = {**d.get("priority", {}), "score": r["score"]}
    return d


def add_event(conn, hid, kind, actor=None, body=None, data=None, now=None):
    conn.execute(insert(db_module.hunt_hypothesis_events), {"hypothesis_id": hid, "kind": kind, "actor": actor, "body": body, "data_json": json.dumps(data) if data is not None else None, "created_at": _now(now)})


def all_rows(engine=None):
    engine, t = _engine(engine), db_module.hunt_hypotheses
    with engine.connect() as conn:
        return [_row(r) for r in conn.execute(select(t).order_by(t.c.score.desc(), t.c.id)).mappings()]


def get(hid, engine=None):
    engine, t = _engine(engine), db_module.hunt_hypotheses
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == hid)).mappings().first()
    return _row(r) if r else None


def events(hid, engine=None):
    engine, t = _engine(engine), db_module.hunt_hypothesis_events
    with engine.connect() as conn:
        rows = conn.execute(select(t).where(t.c.hypothesis_id == hid).order_by(t.c.id)).mappings().all()
    return [{"kind": r["kind"], "actor": r["actor"], "body": r["body"], "data": json.loads(r["data_json"]) if r["data_json"] else None, "at": r["created_at"]} for r in rows]


def last_refresh(engine=None):
    engine, t = _engine(engine), db_module.hunt_hypothesis_events
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.hypothesis_id == "_engine", t.c.kind == "refresh").order_by(t.c.id.desc()).limit(1)).mappings().first()
    return {"at": r["created_at"], **(json.loads(r["data_json"]) if r["data_json"] else {})} if r else None


def pattern_stats(engine=None):
    """{pattern_key: {concluded, true_positive, benign, inconclusive, dismissed}} from the rows."""
    out = {}
    for h in all_rows(engine):
        s = out.setdefault(h["pattern_key"], {"concluded": 0, "true_positive": 0, "benign": 0, "inconclusive": 0, "dismissed": 0})
        if h["status"] in ("concluded", "promoted") and h["outcome"]:
            s["concluded"] += 1
            s[{"true-positive": "true_positive", "benign": "benign", "inconclusive-needs-data": "inconclusive"}[h["outcome"]]] += 1
        elif h["status"] == "dismissed":
            s["dismissed"] += 1
    return out


def material_change(old_refs, new_refs, strong_refs, cfg):
    fresh = set(new_refs) - set(old_refs)
    return len(fresh) >= int(cfg.get("material_new_refs") or 3) or bool(fresh & set(strong_refs))


def apply_refresh(items, cfg, actor="system", now=None, engine=None):
    """Writes a refresh. `items` are finalised hypotheses. Returns counts."""
    engine, t = _engine(engine), db_module.hunt_hypotheses
    stamp = _now(now)
    counts = {"new": 0, "updated": 0, "reopened": 0, "expired": 0, "kept_dismissed": 0}
    seen = set()
    with engine.begin() as conn:
        have = {r["id"]: r for r in conn.execute(select(t)).mappings()}
        for h in items:
            seen.add(h["id"])
            row = have.get(h["id"])
            refs = json.dumps(h["evidence_refs"])
            if row is None:
                conn.execute(insert(t), {"id": h["id"], "generator": h["generator"], "hunt_type": h["hunt_type"], "pattern_key": h["pattern_key"], "title": h["title"], "status": "suggested",
                                         "outcome": None, "outcome_notes": None, "dismissal_reason": None, "score": h["priority"]["score"], "current": 1, "hunt_id": None, "promoted_key": None,
                                         "evidence_refs_json": refs, "data_json": json.dumps(h), "decided_by": None, "created_at": stamp, "updated_at": stamp})
                add_event(conn, h["id"], "suggested", actor, h["title"], {"score": h["priority"]["score"]}, now)
                counts["new"] += 1
            elif row["status"] == "suggested":
                conn.execute(update(t).where(t.c.id == h["id"]).values(title=h["title"], score=h["priority"]["score"], current=1, evidence_refs_json=refs, data_json=json.dumps(h), updated_at=stamp))
                counts["updated"] += 1
            elif row["status"] == "dismissed":
                strong = [f"{e['kind']}:{e['ref']}" for e in h["why_now"] if e.get("strong")]
                if material_change(json.loads(row["evidence_refs_json"]), h["evidence_refs"], strong, cfg):
                    conn.execute(update(t).where(t.c.id == h["id"]).values(status="suggested", title=h["title"], score=h["priority"]["score"], current=1, evidence_refs_json=refs,
                                                                          data_json=json.dumps(h), updated_at=stamp, dismissal_reason=None, decided_by=None))
                    add_event(conn, h["id"], "reopened", actor, "The evidence changed materially since it was dismissed", {"was": row["dismissal_reason"], "new_refs": sorted(set(h["evidence_refs"]) - set(json.loads(row["evidence_refs_json"])))}, now)
                    counts["reopened"] += 1
                else:
                    counts["kept_dismissed"] += 1
        for hid, row in have.items():
            if hid not in seen and row["status"] == "suggested" and row["current"]:
                conn.execute(update(t).where(t.c.id == hid).values(current=0, updated_at=stamp))
                counts["expired"] += 1
    return counts


def set_state(hid, status, actor, kind=None, body=None, data=None, engine=None, now=None, **cols):
    """Moves a hypothesis to `status` if the lifecycle allows it. Extra columns (outcome, hunt_id, ...) are written in the same transaction."""
    engine, t = _engine(engine), db_module.hunt_hypotheses
    with engine.begin() as conn:
        r = conn.execute(select(t).where(t.c.id == hid)).mappings().first()
        if not r:
            raise KeyError("No such suggestion")
        if status != r["status"] and status not in m.TRANSITIONS[r["status"]]:
            raise TransitionError(f"A suggestion that is {r['status']} cannot become {status}")
        conn.execute(update(t).where(t.c.id == hid).values(status=status, decided_by=actor if actor != "system" else r["decided_by"], updated_at=_now(now), **cols))
        add_event(conn, hid, kind or status, actor, body, data, now)
    return get(hid, engine)


class TransitionError(ValueError):
    """The lifecycle does not allow this move (the API answers 409)."""
