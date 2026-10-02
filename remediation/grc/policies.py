"""Policies with versions and acknowledgements. Changing a policy's text makes a new version, which people must acknowledge again; changing only its
owner or review date does not. Acknowledgement coverage is measured against the user accounts that exist."""
import datetime

from sqlalchemy import insert, select, update

from remediation.utils import db as db_module

STATUSES = ("draft", "active", "retired")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def _date(v):
    if v in (None, ""):
        return None
    try:
        return datetime.date.fromisoformat(str(v)[:10]).isoformat()
    except ValueError:
        raise ValueError("review_date must be a date like 2026-12-31") from None


def create(title, body, owner, actor, status="draft", review_date=None, engine=None):
    if not (title or "").strip() or len(title) > 200:
        raise ValueError("A title of 1 to 200 characters is required")
    if not (body or "").strip():
        raise ValueError("The policy text is required")
    if status not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)}")
    engine, t = _engine(engine), db_module.grc_policies
    with engine.begin() as conn:
        pid = conn.execute(insert(t), {"title": title.strip(), "version": 1, "owner": owner, "status": status, "body": body, "review_date": _date(review_date),
                                       "updated_at": _now(), "updated_by": actor}).inserted_primary_key[0]
    return get(pid, engine)


def get(policy_id, engine=None, users=None):
    engine, t = _engine(engine), db_module.grc_policies
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(policy_id))).mappings().first()
        if not r:
            return None
        acks = [dict(a) for a in conn.execute(select(db_module.grc_policy_acks).where(
            db_module.grc_policy_acks.c.policy_id == int(policy_id), db_module.grc_policy_acks.c.version == r["version"])).mappings().all()]
    out = dict(r)
    out["acknowledged_by"] = sorted(a["user_email"] for a in acks)
    out["review_overdue"] = bool(out["review_date"] and out["review_date"] < datetime.date.today().isoformat() and out["status"] == "active")
    if users is not None:
        emails = {u["email"] for u in users}
        out["ack_pct"] = round(100 * len(emails & set(out["acknowledged_by"])) / len(emails)) if emails else None
        out["not_yet_acknowledged"] = sorted(emails - set(out["acknowledged_by"])) if out["status"] == "active" else []
    return out


def list_policies(engine=None, users=None):
    engine, t = _engine(engine), db_module.grc_policies
    with engine.connect() as conn:
        ids = [r[0] for r in conn.execute(select(t.c.id).order_by(t.c.title))]
    return [get(i, engine, users) for i in ids]


def update_policy(policy_id, actor, title=None, body=None, owner=None, status=None, review_date=None, engine=None):
    cur = get(policy_id, engine)
    if not cur:
        raise KeyError("No such policy")
    values = {"updated_at": _now(), "updated_by": actor}
    if title is not None:
        if not title.strip():
            raise ValueError("A title is required")
        values["title"] = title.strip()
    if owner is not None:
        values["owner"] = owner
    if status is not None:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        values["status"] = status
    if review_date is not None:
        values["review_date"] = _date(review_date)
    if body is not None and body != cur["body"]:
        if not body.strip():
            raise ValueError("The policy text is required")
        values["body"] = body
        values["version"] = cur["version"] + 1
    engine, t = _engine(engine), db_module.grc_policies
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.id == int(policy_id)).values(**values))
    return get(policy_id, engine)


def acknowledge(policy_id, user_email, engine=None):
    cur = get(policy_id, engine)
    if not cur:
        raise KeyError("No such policy")
    if cur["status"] != "active":
        raise ValueError("Only an active policy can be acknowledged")
    engine, t = _engine(engine), db_module.grc_policy_acks
    with engine.begin() as conn:
        if not conn.execute(select(t.c.user_email).where(t.c.policy_id == int(policy_id), t.c.version == cur["version"], t.c.user_email == user_email)).first():
            conn.execute(insert(t), {"policy_id": int(policy_id), "version": cur["version"], "user_email": user_email, "acked_at": _now()})
    return get(policy_id, engine)
