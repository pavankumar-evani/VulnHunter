"""
Entitlements, the HR roster, and access certification campaigns.

An import replaces everything previously loaded from the same source name, so loading the identity provider's full export again keeps the picture
current. A campaign takes a snapshot of the matching active entitlements and asks each one's reviewer (the manager on record, else whoever the
administrator assigns) to certify or revoke it. A revoke decision is a person's instruction, recorded here and listed for the identity team to carry out:
Quanta does not change any account.
"""
import datetime
import json

from sqlalchemy import delete, insert, select, update

from remediation.iam import model
from remediation.utils import db as db_module

DECISIONS = ("certify", "revoke")


def _now(now=None):
    return (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def import_entitlements(source, text, fmt, actor, engine=None, now=None):
    source = (source or "").strip()
    if not source or len(source) > 80:
        raise model.IamFormatError("Name the source (for example the identity provider or application)")
    ents = model.parse(text, fmt)
    if len(ents) > 200000:
        raise model.IamFormatError("More than 200,000 rows in one import")
    engine, t = _engine(engine), db_module.iam_entitlements
    stamp = _now(now)
    seen, rows = set(), []
    for e in ents:
        k = (e["account"], e["system"].lower(), e["entitlement"].lower())
        if k in seen:
            continue
        seen.add(k)
        rows.append({**e, "source": source, "imported_at": stamp})
    with engine.begin() as conn:
        removed = conn.execute(delete(t).where(t.c.source == source)).rowcount
        conn.execute(insert(t), rows)
    return {"source": source, "rows": len(rows), "replaced": removed}


def import_roster(text, engine=None):
    rows = model.parse_roster(text)
    engine, t = _engine(engine), db_module.iam_roster
    with engine.begin() as conn:
        conn.execute(delete(t))
        conn.execute(insert(t), rows)
    return {"people": len(rows)}


def entitlements(engine=None):
    engine, t = _engine(engine), db_module.iam_entitlements
    with engine.connect() as conn:
        rows = [dict(r) for r in conn.execute(select(t).order_by(t.c.user, t.c.system)).mappings().all()]
    for r in rows:
        r["privileged"] = bool(r["privileged"])
    return rows


def roster(engine=None):
    engine, t = _engine(engine), db_module.iam_roster
    with engine.connect() as conn:
        return [dict(r) for r in conn.execute(select(t)).mappings().all()]


def clear(engine=None):
    engine = _engine(engine)
    with engine.begin() as conn:
        for t in (db_module.iam_entitlements, db_module.iam_roster):
            conn.execute(delete(t))


# ---------------------------------------------------------------- certification campaigns
def create_campaign(name, scope, due_date, actor, engine=None, now=None):
    name = (name or "").strip()
    if not name or len(name) > 160:
        raise ValueError("A name of 1 to 160 characters is required")
    try:
        datetime.date.fromisoformat(str(due_date))
    except ValueError:
        raise ValueError("The due date must look like 2026-12-31") from None
    scope = scope or {}
    engine, tc, ti = _engine(engine), db_module.iam_campaigns, db_module.iam_review_items
    ros = {r["user"]: r for r in roster(engine)}
    systems = {s.lower() for s in scope.get("systems") or []}
    chosen = [e for e in entitlements(engine) if e["status"] == "active" and (not scope.get("privileged_only") or e["privileged"]) and (not systems or e["system"].lower() in systems)]
    if not chosen:
        raise ValueError("No active entitlements match that scope")
    stamp = _now(now)
    with engine.begin() as conn:
        cid = conn.execute(insert(tc), {"name": name, "scope_json": json.dumps({"privileged_only": bool(scope.get("privileged_only")), "systems": sorted(systems)}), "due_date": str(due_date),
                                        "status": "open", "created_by": actor, "created_at": stamp}).inserted_primary_key[0]
        conn.execute(insert(ti), [{"campaign_id": cid, "reviewer": e["manager"] or (ros.get(e["user"]) or {}).get("manager") or "unassigned", "decision": None, "decided_by": None, "decided_at": None, "note": None,
                                   "snapshot_json": json.dumps({k: e[k] for k in ("user", "account", "system", "entitlement", "privileged", "last_login", "department")})} for e in chosen])
    return get_campaign(cid, engine)


def _campaign(r, items):
    d = dict(r)
    d["scope"] = json.loads(d.pop("scope_json"))
    done = [i for i in items if i["decision"]]
    d.update({"total": len(items), "decided": len(done), "certified": sum(1 for i in done if i["decision"] == "certify"), "revoke": sum(1 for i in done if i["decision"] == "revoke"),
              "pct": round(100 * len(done) / len(items)) if items else 0, "unassigned": sum(1 for i in items if i["reviewer"] == "unassigned")})
    return d


def _items(cid, engine, reviewer=None):
    t = db_module.iam_review_items
    q = select(t).where(t.c.campaign_id == int(cid)).order_by(t.c.reviewer, t.c.id)
    if reviewer:
        q = q.where(t.c.reviewer == reviewer)
    with engine.connect() as conn:
        rows = [dict(r) for r in conn.execute(q).mappings().all()]
    for r in rows:
        r["entitlement"] = json.loads(r.pop("snapshot_json"))
    return rows


def get_campaign(cid, engine=None):
    engine, t = _engine(engine), db_module.iam_campaigns
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(cid))).mappings().first()
    return _campaign(r, _items(cid, engine)) if r else None


def list_campaigns(engine=None):
    engine, t = _engine(engine), db_module.iam_campaigns
    with engine.connect() as conn:
        rows = conn.execute(select(t).order_by(t.c.id.desc())).mappings().all()
    return [_campaign(r, _items(r["id"], engine)) for r in rows]


def items_for(cid, reviewer=None, engine=None):
    return _items(cid, _engine(engine), reviewer)


def decide(item_id, decision, actor, note="", is_admin=False, engine=None, now=None):
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {', '.join(DECISIONS)}")
    engine, t, tc = _engine(engine), db_module.iam_review_items, db_module.iam_campaigns
    with engine.connect() as conn:
        it = conn.execute(select(t).where(t.c.id == int(item_id))).mappings().first()
        camp = conn.execute(select(tc).where(tc.c.id == it["campaign_id"])).mappings().first() if it else None
    if not it:
        raise KeyError("No such review item")
    if camp["status"] != "open":
        raise ValueError("This campaign is closed")
    if not is_admin and it["reviewer"] != actor.lower():
        raise PermissionError("This item is assigned to someone else")
    if it["reviewer"] == json.loads(it["snapshot_json"])["user"] and not is_admin:
        raise PermissionError("Nobody reviews their own access")
    if decision == "revoke" and not (note or "").strip():
        raise ValueError("Say why the access should be removed")
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.id == int(item_id)).values(decision=decision, decided_by=actor, decided_at=_now(now), note=(note or "")[:500]))
    return {"ok": True}


def reassign(item_id, reviewer, engine=None):
    engine, t, tc = _engine(engine), db_module.iam_review_items, db_module.iam_campaigns
    if not (reviewer or "").strip():
        raise ValueError("Name the reviewer")
    with engine.connect() as conn:
        row = conn.execute(select(tc.c.status).select_from(t.join(tc, tc.c.id == t.c.campaign_id)).where(t.c.id == int(item_id))).first()
    if row and row[0] != "open":
        raise ValueError("This campaign is closed")
    with engine.begin() as conn:
        if not conn.execute(update(t).where(t.c.id == int(item_id), t.c.decision.is_(None)).values(reviewer=reviewer.strip().lower())).rowcount:
            raise KeyError("No such undecided review item")


def close_campaign(cid, engine=None):
    engine, t = _engine(engine), db_module.iam_campaigns
    with engine.begin() as conn:
        if not conn.execute(update(t).where(t.c.id == int(cid), t.c.status == "open").values(status="closed")).rowcount:
            raise KeyError("No such open campaign")
    return get_campaign(cid, engine)


def revocations(cid, engine=None):
    """What the identity team should now remove: the revoke decisions of a campaign."""
    return [{"item_id": i["id"], "decided_by": i["decided_by"], "note": i["note"], **i["entitlement"]} for i in items_for(cid, engine=engine) if i["decision"] == "revoke"]
