"""
Security operations cases: ITIL-style incident handling for SOC alerts.

A case groups one or more alerts into a piece of work with an owner, a tier (L1, L2 or L3 queue), a priority and service-level clocks. The rules (tiers, the
impact x urgency matrix, targets, escalation, what must be written) live in remediation/config/soc_ops.yaml and are read on every call.

Priority. impact (single / multiple / widespread, from how many hosts the case touches, or set by hand) times urgency (from the alert severity) gives a score;
the first threshold met gives P1 to P4. Nothing here is learned or guessed: it is the ITIL matrix with the weights in the file.

Service-level clocks, in minutes, derived on read from timestamps (nothing to keep in sync):
  ack      created -> acknowledged (assigning or starting work acknowledges)
  pickup   after an escalation, tier_since -> the higher tier taking the case (only when the case was escalated)
  resolve  created -> resolved
A clock is met, running, at-risk (past the at_risk fraction of its target) or breached; a case waiting on someone outside ('pending') pauses nothing but is shown so.

Escalation. Functional: an analyst escalates to the next tier and must write a hand-off note (no note, no escalation). Hierarchical: sweep() moves an open case up one tier
when it has sat in its tier longer than the resolve target, once per tier, with an event that says why. A person is never silently overruled: an auto-escalation
is an event in the case history like any other.

Every case carries a summary note. The deterministic summary (summarise()) is built from the facts on the case: who, what, which techniques and hosts, what was done,
what is outstanding. It is rewritten on escalate, resolve and close from the note the analyst wrote, and an optional AI summary can be added on request, never silently.
"""
import datetime
import json
from pathlib import Path

import yaml
from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.exc import IntegrityError

from remediation.utils import db as db_module

POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "soc_ops.yaml"
STATUSES = ("new", "in_progress", "pending", "escalated", "resolved", "closed")
OPEN = ("new", "in_progress", "pending", "escalated")
SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
IMPACTS = ("single", "multiple", "widespread")


def policy():
    with open(POLICY_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _now_dt():
    return datetime.datetime.now(datetime.timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(s):
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc) if s else None


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


# ---------------------------------------------------------------- priority
def impact_for(assets, entities=None, pol=None, raised=False):
    pol = pol or policy()
    n = len({str(a).lower() for a in (assets or []) if a})
    n = max(n, 1 if (entities or {}).get("user") else 0)
    if n >= pol["impact_widespread_hosts"]:
        level = 2
    elif n >= pol["impact_multiple_hosts"]:
        level = 1
    else:
        level = 0
    if raised:
        level = min(2, level + 1)
    return IMPACTS[level]


def priority_for(impact, severity, pol=None):
    pol = pol or policy()
    score = pol["impact_weights"][impact] * pol["urgency_weights"].get(severity, 1)
    for row in pol["priority_thresholds"]:
        if score >= row["min_score"]:
            return row["priority"], score
    return "P4", score


# ---------------------------------------------------------------- rows
def _case(r):
    d = dict(r)
    for k in ("techniques", "entities", "assets", "auto_escalated_tiers"):
        d[k] = json.loads(d.pop(f"{k}_json") or ("{}" if k == "entities" else "[]"))
    d["queue"] = (policy()["tiers"].get(d["tier"]) or {}).get("queue", f"L{d['tier']}")
    return d


def _event(conn, case_id, kind, actor, body="", data=None, now=None):
    conn.execute(insert(db_module.soc_case_events), {"case_id": case_id, "kind": kind, "actor": actor, "body": body or "",
                                                      "data_json": json.dumps(data) if data else None, "created_at": _iso(now or _now_dt())})


def get_case(case_id, engine=None, now=None, detail=True):
    engine, t = _engine(engine), db_module.soc_cases
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(case_id))).mappings().first()
        if not r:
            return None
        c = _case(r)
        if detail:
            ev = conn.execute(select(db_module.soc_case_events).where(db_module.soc_case_events.c.case_id == c["id"]).order_by(db_module.soc_case_events.c.id)).mappings().all()
            c["events"] = [{**dict(e), "data": json.loads(e["data_json"]) if e["data_json"] else None} for e in ev]
            for e in c["events"]:
                e.pop("data_json", None)
            c["alert_ids"] = [x[0] for x in conn.execute(select(db_module.soc_case_alerts.c.alert_id).where(db_module.soc_case_alerts.c.case_id == c["id"]).order_by(db_module.soc_case_alerts.c.id))]
    c["sla"] = sla(c, now=now)
    return c


def list_cases(engine=None, tier=None, status=None, assignee=None, priority=None, open_only=False, now=None):
    engine, t = _engine(engine), db_module.soc_cases
    q = select(t).order_by(t.c.id.desc())
    if tier:
        q = q.where(t.c.tier == int(tier))
    if status:
        q = q.where(t.c.status == status)
    if assignee:
        q = q.where(t.c.assignee == assignee)
    if priority:
        q = q.where(t.c.priority == priority)
    if open_only:
        q = q.where(t.c.status.in_(OPEN))
    with engine.connect() as conn:
        rows = [_case(r) for r in conn.execute(q).mappings().all()]
    for c in rows:
        c["sla"] = sla(c, now=now)
    rank = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    rows.sort(key=lambda c: (rank.get(c["priority"], 9), c["created_at"]))
    return rows


# ---------------------------------------------------------------- service levels
def _clock(start, end, target_min, now, paused=False):
    if not start:
        return None
    done = end is not None
    elapsed = ((end if done else now) - start).total_seconds() / 60
    if done:
        state = "met" if elapsed <= target_min else "breached"
    elif elapsed > target_min:
        state = "breached"
    elif elapsed >= target_min * policy().get("at_risk_threshold", 0.8):
        state = "at_risk"
    else:
        state = "running"
    return {"target_minutes": target_min, "elapsed_minutes": round(elapsed, 1), "remaining_minutes": round(target_min - elapsed, 1), "state": state, "done": done}


def sla(c, now=None):
    pol = policy()
    now = now or _now_dt()
    tg = pol["targets"].get(c["priority"]) or pol["targets"]["P4"]
    out = {"ack": _clock(_parse(c["created_at"]), _parse(c["acknowledged_at"]), tg["ack_minutes"], now),
           "resolve": _clock(_parse(c["created_at"]), _parse(c["resolved_at"]), tg["resolve_minutes"], now),
           "pickup": None}
    if c["escalation_count"] and c["tier"] > 1:
        out["pickup"] = _clock(_parse(c["tier_since"]), _parse(c["picked_up_at"]), tg["pickup_minutes"], now)
    if c["status"] == "closed" or c["status"] == "resolved":
        out["resolve"]["done"] = True
    states = [x["state"] for x in out.values() if x and not (x["done"] and x["state"] == "met")]
    out["worst"] = "breached" if "breached" in states else "at_risk" if "at_risk" in states else "ok"
    return out


# ---------------------------------------------------------------- summary
def summarise(c, alerts=()):
    """The deterministic summary: built only from what is on the case."""
    techs = ", ".join(f"{t['id']} {t.get('name') or ''}".strip() if isinstance(t, dict) else str(t) for t in c.get("techniques") or []) or "none identified"
    assets = ", ".join(c.get("assets") or []) or "none recorded"
    ents = c.get("entities") or {}
    parts = [f"{c['priority']} {c['severity']} case in the {c.get('queue', 'L' + str(c['tier']))} queue ({c['impact']} impact): {c['title']}.",
             f"Techniques: {techs}. Hosts: {assets}."]
    if ents.get("user"):
        parts.append(f"Account involved: {ents['user']}.")
    if alerts:
        parts.append(f"{len(alerts)} alert(s) linked.")
    if c.get("recommendation"):
        parts.append(f"The system recommended: {c['recommendation']}.")
    parts.append(f"Status {c['status']}" + (f", owned by {c['assignee']}" if c.get("assignee") else ", not yet owned") + f"; escalated {c['escalation_count']} time(s), reopened {c['reopen_count']} time(s).")
    if c.get("resolution"):
        parts.append(f"Resolved as {c['resolution']}.")
    return " ".join(parts)


# ---------------------------------------------------------------- analysts
def add_analyst(email, tier, engine=None):
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        raise ValueError("An analyst needs an email address")
    if int(tier) not in (1, 2, 3):
        raise ValueError("tier must be 1, 2 or 3")
    engine, t = _engine(engine), db_module.soc_analysts
    with engine.begin() as conn:
        cur = conn.execute(select(t.c.id).where(t.c.email == email)).first()
        if cur:
            conn.execute(update(t).where(t.c.id == cur[0]).values(tier=int(tier), active=1))
        else:
            conn.execute(insert(t), {"email": email, "tier": int(tier), "active": 1, "created_at": _iso(_now_dt())})
    return list_analysts(engine)


def remove_analyst(email, engine=None):
    engine, t = _engine(engine), db_module.soc_analysts
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.email == (email or "").strip().lower()).values(active=0))
    return list_analysts(engine)


def list_analysts(engine=None):
    engine, t = _engine(engine), db_module.soc_analysts
    with engine.connect() as conn:
        rows = conn.execute(select(t).where(t.c.active == 1).order_by(t.c.tier, t.c.email)).mappings().all()
        load = dict(conn.execute(select(db_module.soc_cases.c.assignee, func.count()).where(db_module.soc_cases.c.status.in_(OPEN), db_module.soc_cases.c.assignee.isnot(None))
                                 .group_by(db_module.soc_cases.c.assignee)).all())
    cap = policy().get("max_open_per_analyst", 15)
    return [{"email": r["email"], "tier": r["tier"], "open_cases": load.get(r["email"], 0), "at_capacity": load.get(r["email"], 0) >= cap} for r in rows]


def suggest_assignee(tier, engine=None):
    """The least-loaded active analyst of this tier who is under the cap, or None."""
    pool = [a for a in list_analysts(engine) if a["tier"] == int(tier) and not a["at_capacity"]]
    pool.sort(key=lambda a: (a["open_cases"], a["email"]))
    return pool[0]["email"] if pool else None


def _analyst_tier(conn, email):
    r = conn.execute(select(db_module.soc_analysts.c.tier).where(db_module.soc_analysts.c.email == (email or "").lower(), db_module.soc_analysts.c.active == 1)).first()
    return r[0] if r else None


# ---------------------------------------------------------------- lifecycle
def open_case(f, actor, engine=None, now=None):
    pol, now = policy(), now or _now_dt()
    title = (f.get("title") or "").strip()
    if not title or len(title) > 300:
        raise ValueError("A title of 1 to 300 characters is required")
    sev = f.get("severity") or "Medium"
    if sev not in SEVERITIES:
        raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}")
    assets = [str(a) for a in (f.get("assets") or []) if a]
    ents = f.get("entities") or {}
    impact = f.get("impact") or impact_for(assets, ents, pol, raised=bool(f.get("raise_impact")))
    if impact not in IMPACTS:
        raise ValueError(f"impact must be one of {', '.join(IMPACTS)}")
    prio, _ = priority_for(impact, sev, pol)
    tier = int(f.get("tier") or 1)
    if tier not in (1, 2, 3):
        raise ValueError("tier must be 1, 2 or 3")
    engine, t = _engine(engine), db_module.soc_cases
    ts = _iso(now)
    row = {"title": title, "severity": sev, "impact": impact, "priority": prio, "tier": tier, "status": "new", "assignee": None, "resolution": None,
           "summary": (f.get("summary") or "").strip() or None, "techniques_json": json.dumps(f.get("techniques") or []), "entities_json": json.dumps(ents),
           "assets_json": json.dumps(assets), "recommendation": f.get("recommendation"), "source": f.get("source") or "manual", "reopen_count": 0, "escalation_count": 0,
           "auto_escalated_tiers_json": "[]", "created_by": actor, "created_at": ts, "acknowledged_at": None, "tier_since": ts, "picked_up_at": None,
           "resolved_at": None, "closed_at": None, "updated_at": ts}
    with engine.begin() as conn:
        cid = conn.execute(insert(t), row).inserted_primary_key[0]
        _event(conn, cid, "opened", actor, f"Opened as {prio} in the L{tier} queue", {"priority": prio, "impact": impact}, now)
        for aid in f.get("alert_ids") or []:
            try:
                conn.execute(insert(db_module.soc_case_alerts), {"case_id": cid, "alert_id": int(aid), "linked_at": ts})
                conn.execute(update(db_module.soc_alerts).where(db_module.soc_alerts.c.id == int(aid), db_module.soc_alerts.c.status == "new").values(status="investigating"))
            except IntegrityError:
                pass
    if f.get("assignee"):
        assign(cid, f["assignee"], actor, engine, now)
    return get_case(cid, engine, now)


def _require(c, allowed=OPEN):
    if not c:
        raise KeyError("No such case")
    if c["status"] not in allowed:
        raise ValueError(f"The case is {c['status']}; this action needs it to be {' or '.join(allowed)}")


def _write(case_id, values, kind, actor, body, data, engine, now):
    values["updated_at"] = _iso(now)
    with engine.begin() as conn:
        conn.execute(update(db_module.soc_cases).where(db_module.soc_cases.c.id == int(case_id)).values(**values))
        _event(conn, case_id, kind, actor, body, data, now)
    return get_case(case_id, engine, now)


def add_note(case_id, text, actor, engine=None, now=None, kind="note"):
    text = (text or "").strip()
    if not text:
        raise ValueError("A note cannot be empty")
    engine, now = _engine(engine), now or _now_dt()
    c = get_case(case_id, engine, now, detail=False)
    if not c:
        raise KeyError("No such case")
    with engine.begin() as conn:
        _event(conn, int(case_id), kind, actor, text[:4000], None, now)
        conn.execute(update(db_module.soc_cases).where(db_module.soc_cases.c.id == int(case_id)).values(updated_at=_iso(now)))
    return get_case(case_id, engine, now)


def assign(case_id, assignee, actor, engine=None, now=None):
    engine, now = _engine(engine), now or _now_dt()
    c = get_case(case_id, engine, now, detail=False)
    _require(c)
    assignee = (assignee or "").strip().lower()
    if not assignee:
        raise ValueError("Name an assignee")
    with engine.connect() as conn:
        tier = _analyst_tier(conn, assignee)
    if tier is not None and tier < c["tier"]:
        raise ValueError(f"{assignee} works the L{tier} queue; this case is in L{c['tier']}. Escalate it or pick a higher-tier analyst")
    ts = _iso(now)
    vals = {"assignee": assignee, "status": "in_progress" if c["status"] in ("new", "escalated") else c["status"]}
    if not c["acknowledged_at"]:
        vals["acknowledged_at"] = ts
    if c["escalation_count"] and not c["picked_up_at"] and (tier is None or tier >= c["tier"]):
        vals["picked_up_at"] = ts
    return _write(case_id, vals, "assigned", actor, f"Assigned to {assignee}", {"assignee": assignee}, engine, now)


def acknowledge(case_id, actor, engine=None, now=None):
    engine, now = _engine(engine), now or _now_dt()
    c = get_case(case_id, engine, now, detail=False)
    _require(c)
    if c["acknowledged_at"]:
        return get_case(case_id, engine, now)
    return _write(case_id, {"acknowledged_at": _iso(now), "status": "in_progress" if c["status"] == "new" else c["status"]}, "acknowledged", actor, "Acknowledged", None, engine, now)


def set_pending(case_id, reason, actor, engine=None, now=None):
    engine, now = _engine(engine), now or _now_dt()
    _require(get_case(case_id, engine, now, detail=False), ("new", "in_progress", "pending"))
    return _write(case_id, {"status": "pending"}, "note", actor, f"Waiting: {(reason or 'on another party').strip()}", None, engine, now)


def _need_summary(action, text, pol):
    if action in pol["escalation"]["require_summary_on"]:
        if len((text or "").strip()) < pol["escalation"]["min_summary_chars"]:
            raise ValueError(f"Write a summary of at least {pol['escalation']['min_summary_chars']} characters before you {action}: what you found, what you did, what is left")


def escalate(case_id, summary, actor, engine=None, now=None, to_tier=None, auto=False):
    pol, engine, now = policy(), _engine(engine), now or _now_dt()
    c = get_case(case_id, engine, now, detail=False)
    _require(c)
    if not auto:
        _need_summary("escalate", summary, pol)
    target = int(to_tier or c["tier"] + 1)
    if target <= c["tier"] or target > pol["escalation"]["max_tier"]:
        raise ValueError(f"A case in L{c['tier']} can be escalated to a tier above it, up to L{pol['escalation']['max_tier']}")
    ts = _iso(now)
    done = c["auto_escalated_tiers"] + ([c["tier"]] if auto else [])
    vals = {"tier": target, "status": "escalated", "assignee": None, "tier_since": ts, "picked_up_at": None, "escalation_count": c["escalation_count"] + 1,
            "summary": (summary or "").strip(), "auto_escalated_tiers_json": json.dumps(done)}
    body = (summary or "").strip()
    return _write(case_id, vals, "auto_escalated" if auto else "escalated", actor, body, {"from_tier": c["tier"], "to_tier": target}, engine, now)


def resolve(case_id, resolution, summary, actor, engine=None, now=None):
    pol, engine, now = policy(), _engine(engine), now or _now_dt()
    c = get_case(case_id, engine, now, detail=False)
    _require(c)
    _need_summary("resolve", summary, pol)
    allowed = pol["tiers"][c["tier"]]["may_resolve_as"]
    if resolution not in pol["resolution_codes"]:
        raise ValueError(f"resolution must be one of {', '.join(pol['resolution_codes'])}")
    if resolution not in allowed:
        raise ValueError(f"A case in L{c['tier']} cannot be resolved as {resolution}; escalate it")
    ts = _iso(now)
    vals = {"status": "resolved", "resolution": resolution, "resolved_at": ts, "summary": summary.strip()}
    if not c["acknowledged_at"]:
        vals["acknowledged_at"] = ts
    out = _write(case_id, vals, "resolved", actor, summary.strip(), {"resolution": resolution}, engine, now)
    _close_alerts(case_id, resolution, engine)
    return out


_DISPOSITION = {"true-positive": "true-positive", "false-positive": "false-positive", "benign": "benign", "duplicate": "false-positive",
                "insufficient-data": "needs-data", "accepted-risk": "benign"}


def _close_alerts(case_id, resolution, engine):
    t = db_module.soc_alerts
    with engine.begin() as conn:
        ids = [x[0] for x in conn.execute(select(db_module.soc_case_alerts.c.alert_id).where(db_module.soc_case_alerts.c.case_id == int(case_id)))]
        if ids:
            conn.execute(update(t).where(t.c.id.in_(ids), t.c.status != "closed").values(status="closed", disposition=_DISPOSITION[resolution], closed_at=_iso(_now_dt())))


def close(case_id, summary, actor, engine=None, now=None):
    pol, engine, now = policy(), _engine(engine), now or _now_dt()
    c = get_case(case_id, engine, now, detail=False)
    _require(c, ("resolved",))
    _need_summary("close", summary or c["summary"], pol)
    vals = {"status": "closed", "closed_at": _iso(now)}
    if summary and summary.strip():
        vals["summary"] = summary.strip()
    return _write(case_id, vals, "closed", actor, (summary or "").strip() or "Closed", None, engine, now)


def reopen(case_id, reason, actor, engine=None, now=None):
    engine, now = _engine(engine), now or _now_dt()
    c = get_case(case_id, engine, now, detail=False)
    _require(c, ("resolved", "closed"))
    if not (reason or "").strip():
        raise ValueError("Say why the case is being reopened")
    vals = {"status": "in_progress" if c["assignee"] else "new", "resolution": None, "resolved_at": None, "closed_at": None, "reopen_count": c["reopen_count"] + 1}
    out = _write(case_id, vals, "reopened", actor, reason.strip(), None, engine, now)
    with engine.begin() as conn:
        ids = [x[0] for x in conn.execute(select(db_module.soc_case_alerts.c.alert_id).where(db_module.soc_case_alerts.c.case_id == int(case_id)))]
        if ids:
            conn.execute(update(db_module.soc_alerts).where(db_module.soc_alerts.c.id.in_(ids)).values(status="investigating", disposition=None, closed_at=None))
    return out


def set_impact(case_id, impact, actor, engine=None, now=None):
    if impact not in IMPACTS:
        raise ValueError(f"impact must be one of {', '.join(IMPACTS)}")
    engine, now = _engine(engine), now or _now_dt()
    c = get_case(case_id, engine, now, detail=False)
    _require(c)
    prio, _ = priority_for(impact, c["severity"])
    return _write(case_id, {"impact": impact, "priority": prio}, "priority", actor, f"Impact set to {impact}; priority {prio}", {"priority": prio}, engine, now)


def link_alert(case_id, alert_id, actor, engine=None, now=None):
    engine, now = _engine(engine), now or _now_dt()
    _require(get_case(case_id, engine, now, detail=False))
    try:
        with engine.begin() as conn:
            conn.execute(insert(db_module.soc_case_alerts), {"case_id": int(case_id), "alert_id": int(alert_id), "linked_at": _iso(now)})
            _event(conn, int(case_id), "alert_linked", actor, f"Alert {alert_id} linked", None, now)
    except IntegrityError:
        raise ValueError("That alert is already linked to this case") from None
    return get_case(case_id, engine, now)


def set_techniques(case_id, techniques, actor, engine=None, now=None):
    engine, now = _engine(engine), now or _now_dt()
    _require(get_case(case_id, engine, now, detail=False))
    return _write(case_id, {"techniques_json": json.dumps(techniques)}, "evidence", actor, "Techniques updated: " + ", ".join(t["id"] if isinstance(t, dict) else str(t) for t in techniques), None, engine, now)


# ---------------------------------------------------------------- hierarchical escalation
def sweep(engine=None, now=None):
    """Moves open cases up a tier when they have sat in their tier past the resolve target. Returns the case ids moved."""
    pol, engine, now = policy(), _engine(engine), now or _now_dt()
    if not pol["escalation"].get("auto_escalate_on_resolve_breach"):
        return []
    moved = []
    for c in list_cases(engine, open_only=True, now=now):
        target = pol["targets"][c["priority"]]["resolve_minutes"]
        if c["tier"] >= pol["escalation"]["max_tier"] or c["tier"] in c["auto_escalated_tiers"]:
            continue
        if (now - _parse(c["tier_since"])).total_seconds() / 60 > target:
            escalate(c["id"], f"Automatic escalation: the case has been in L{c['tier']} for over {target} minutes, the {c['priority']} resolve target, without being resolved. "
                              f"Status was {c['status']}, owner {c['assignee'] or 'none'}.", "system", engine, now, auto=True)
            moved.append(c["id"])
    return moved


# ---------------------------------------------------------------- automatic cases
def auto_case(alert, investigation, engine=None, now=None):
    """Opens a case from an alert's investigation when the policy allows; None when it does not (or when the alert already has a case)."""
    pol, engine, now = policy()["auto_case"], _engine(engine), now or _now_dt()
    if not pol.get("enabled") or investigation["verdict"] not in pol["verdicts"]:
        return None
    if SEVERITIES.index(alert["severity"]) > SEVERITIES.index(pol["min_severity"]):
        return None
    with engine.connect() as conn:
        if conn.execute(select(db_module.soc_case_alerts.c.id).where(db_module.soc_case_alerts.c.alert_id == alert["id"])).first():
            return None
        recent = conn.execute(select(func.count()).select_from(db_module.soc_cases).where(db_module.soc_cases.c.source == "auto",
                                                                                          db_module.soc_cases.c.created_at >= _iso(now - datetime.timedelta(hours=1)))).scalar()
    if recent >= pol["max_per_hour"]:
        return None
    ents = alert.get("entities") or {}
    techs = [{"id": alert["technique"]}] if alert.get("technique") else []
    return open_case({"title": alert["title"], "severity": alert["severity"], "assets": [alert["asset"]] if alert.get("asset") else [], "entities": ents,
                      "techniques": techs, "alert_ids": [alert["id"]], "recommendation": investigation["verdict"], "source": "auto",
                      "summary": f"Opened automatically from alert {alert['id']}: the first-look investigation said {investigation['verdict']} ({investigation.get('confidence', '')} confidence)."},
                     "system", engine, now)
