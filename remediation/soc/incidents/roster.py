"""
The analyst roster for routing: tier, specialties, availability, shift, on-call and capacity, kept on the existing soc_analysts rows.

Availability is explicit: an analyst is routable only when active, marked available, and either inside their shift (UTC, "HH:MM"; no shift set means always) or
on call for an urgent priority. Nothing here reads a calendar or an HR system; people (or an API call from the rota tool) set it.
"""
import json
import re

from sqlalchemy import func, insert, select, update

from remediation.soc.incidents import store
from remediation.utils import db as db_module

HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def _minutes(hhmm):
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def on_shift(a, now):
    """True when no shift is set, or `now` (UTC) falls inside it. A shift whose end is before its start runs over midnight."""
    s, e = a.get("shift_start"), a.get("shift_end")
    if not s or not e:
        return True
    cur = now.hour * 60 + now.minute
    s, e = _minutes(s), _minutes(e)
    return s <= cur < e if s <= e else (cur >= s or cur < e)


def _row(r, pol):
    cap = r["capacity"] if r["capacity"] else pol["analysts"]["default_capacity"]
    return {"email": r["email"], "tier": r["tier"], "skills": json.loads(r["skills_json"]) if r["skills_json"] else [], "available": r["available"] != 0,
            "shift_start": r["shift_start"], "shift_end": r["shift_end"], "on_call": bool(r["on_call"]), "capacity": cap, "capacity_set": bool(r["capacity"])}


def list_roster(engine=None, now=None, include_inactive=False):
    engine, t = store.engine_for(engine), db_module.soc_analysts
    pol, now = store.policy(), now or store.now_dt()
    q = select(t).order_by(t.c.tier, t.c.email)
    if not include_inactive:
        q = q.where(t.c.active == 1)
    with engine.connect() as conn:
        rows = [_row(r, pol) for r in conn.execute(q).mappings().all()]
        it = db_module.soc_incidents
        load = dict(conn.execute(select(it.c.assignee, func.count())
                                 .where(it.c.status.in_(store.OPEN), it.c.assignee.isnot(None)).group_by(it.c.assignee)).all())
    for a in rows:
        a["on_shift"] = on_shift(a, now)
        a["open_incidents"] = load.get(a["email"], 0)
        a["at_capacity"] = a["open_incidents"] >= a["capacity"]
    return rows


def get(email, engine=None, now=None):
    return next((a for a in list_roster(engine, now) if a["email"] == (email or "").strip().lower()), None)


def update_analyst(email, fields, engine=None):
    """Sets any of tier, skills, available, shift_start, shift_end, on_call, capacity (only the keys given). Creates the analyst when tier is given for a new email."""
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        raise ValueError("An analyst needs an email address")
    pol = store.policy()
    engine, t = store.engine_for(engine), db_module.soc_analysts
    v = {}
    if fields.get("tier") is not None:
        if int(fields["tier"]) not in (1, 2, 3):
            raise ValueError("tier must be 1, 2 or 3")
        v["tier"] = int(fields["tier"])
    if fields.get("skills") is not None:
        skills = sorted({str(s).strip().lower() for s in fields["skills"] if str(s).strip()})
        bad = [s for s in skills if s not in pol["analysts"]["known_specialties"]]
        if bad:
            raise ValueError(f"Unknown specialty: {', '.join(bad)}. Known: {', '.join(pol['analysts']['known_specialties'])}")
        v["skills_json"] = json.dumps(skills)
    for k in ("shift_start", "shift_end"):
        if k in fields:
            if fields[k] in (None, ""):
                v[k] = None
            elif HHMM.match(str(fields[k])):
                v[k] = str(fields[k])
            else:
                raise ValueError(f"{k} must be HH:MM (UTC) or empty")
    if fields.get("available") is not None:
        v["available"] = 1 if fields["available"] else 0
    if fields.get("on_call") is not None:
        v["on_call"] = 1 if fields["on_call"] else 0
    if "capacity" in fields:
        if fields["capacity"] in (None, 0):
            v["capacity"] = None
        else:
            if not 1 <= int(fields["capacity"]) <= 200:
                raise ValueError("capacity must be between 1 and 200")
            v["capacity"] = int(fields["capacity"])
    with engine.begin() as conn:
        cur = conn.execute(select(t.c.id, t.c.tier).where(t.c.email == email)).first()
        if cur is None:
            if "tier" not in v:
                raise KeyError("No such analyst; give a tier to add one")
            conn.execute(insert(t), {"email": email, "tier": v["tier"], "active": 1, "created_at": store.iso(store.now_dt()), **{k: x for k, x in v.items() if k != "tier"}})
        elif v:
            conn.execute(update(t).where(t.c.id == cur[0]).values(active=1, **v))
    return get(email, engine)
