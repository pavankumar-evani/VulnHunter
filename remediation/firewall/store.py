"""
Firewall rules held in Quanta, their recertification, and change requests.

Importing a device's rules replaces that device's rule list. A rule keeps its first-seen date and its recertification across imports as long as
what it matches and does has not changed; change the source, destination, service or action and it is a new rule that needs certifying again.

Recertification: every enabled allow rule must be re-confirmed by its owner every `recertify_every_days` (keep, modify or remove). A rule with no
certification is due that long after Quanta first saw it. The decision is a person's statement recorded here; a "remove" or "modify" is still
carried out on the firewall by whoever manages it. Quanta never changes a firewall.

Change requests: a request is checked when it is submitted (already allowed? blocked? how risky? may it be approved without review?), then
approved or rejected by an administrator, then marked implemented once it is done on the firewall. The time each step took is kept so cycle time is a
measurement, not an estimate.
"""
import datetime
import hashlib
import json
import statistics

from sqlalchemy import delete, insert, select, update

from remediation.firewall import analysis, model
from remediation.utils import db as db_module

REQ_STATUSES = ("submitted", "approved", "rejected", "implemented", "withdrawn")
DECISIONS = ("keep", "modify", "remove")


def _now(now=None):
    return (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def _fingerprint(rule):
    basis = json.dumps([rule["action"], rule["src_zones"], rule["dst_zones"], rule["sources"], rule["destinations"], rule["services"]], sort_keys=True)
    return hashlib.sha256(basis.encode()).hexdigest()[:20]


# ---------------------------------------------------------------- rules
def import_rules(device, text, fmt, actor, engine=None, now=None):
    device = (device or "").strip()
    if not device or len(device) > 120:
        raise model.RuleFormatError("Name the firewall (1 to 120 characters)")
    rules, detected = model.detect_and_parse(text, device, fmt)
    if len(rules) > 50000:
        raise model.RuleFormatError("More than 50,000 rules in one import")
    engine, t = _engine(engine), db_module.fw_rules
    stamp = _now(now)
    with engine.begin() as conn:
        old = {r["key"]: dict(r) for r in conn.execute(select(t).where(t.c.device == device)).mappings().all()}
        conn.execute(delete(t).where(t.c.device == device))
        seen, rows = set(), []
        for r in rules:
            key = r["key"]
            if key in seen:  # a device that reuses a name: keep the first, number the rest
                key = f"{key}#{r['position']}"
                r["key"] = key
            seen.add(key)
            fp = _fingerprint(r)
            prev = old.get(key)
            same = bool(prev and prev["fingerprint"] == fp)
            rows.append({"device": device, "key": key, "position": r["position"], "data_json": json.dumps(r), "first_seen": prev["first_seen"] if same else stamp[:10], "fingerprint": fp,
                         "certified_at": prev["certified_at"] if same else None, "certified_by": prev["certified_by"] if same else None, "decision": prev["decision"] if same else None,
                         "decision_note": prev["decision_note"] if same else None, "imported_at": stamp})
        conn.execute(insert(t), rows)
    added = len(seen - set(old))
    return {"device": device, "format": detected, "rules": len(rules), "added": added, "removed": len(set(old) - seen), "enabled": sum(r["enabled"] for r in rules)}


def _rule_row(r):
    d = json.loads(r["data_json"])
    d.update({"first_seen": r["first_seen"], "certified_at": r["certified_at"], "certified_by": r["certified_by"], "decision": r["decision"], "decision_note": r["decision_note"]})
    return d


def rules(device=None, engine=None):
    engine, t = _engine(engine), db_module.fw_rules
    q = select(t).order_by(t.c.device, t.c.position)
    if device:
        q = q.where(t.c.device == device)
    with engine.connect() as conn:
        return [_rule_row(r) for r in conn.execute(q).mappings().all()]


def devices(engine=None):
    return sorted({r["device"] for r in rules(engine=engine)})


def delete_device(device, engine=None):
    engine, t = _engine(engine), db_module.fw_rules
    with engine.begin() as conn:
        return conn.execute(delete(t).where(t.c.device == device)).rowcount


# ---------------------------------------------------------------- recertification
def certify(device, key, decision, note, actor, engine=None, now=None):
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {', '.join(DECISIONS)}")
    if decision in ("modify", "remove") and not (note or "").strip():
        raise ValueError("Say what should change, or why it should go")
    engine, t = _engine(engine), db_module.fw_rules
    with engine.begin() as conn:
        n = conn.execute(update(t).where(t.c.device == device, t.c.key == key).values(certified_at=_now(now), certified_by=actor, decision=decision, decision_note=(note or "")[:500])).rowcount
    if not n:
        raise KeyError("No such rule")


def recert_status(all_rules, pol=None, today=None):
    pol = pol or analysis.policy()
    today = today or datetime.date.today()
    every, grace = pol.get("recertify_every_days", 365), pol.get("recertify_grace_days", 30)
    out, counts = [], {"current": 0, "due-soon": 0, "overdue": 0, "removal-requested": 0, "change-requested": 0}
    for r in all_rules:
        if not (r["enabled"] and r["action"] == "allow"):
            continue
        base = (r["certified_at"] or r["first_seen"] or today.isoformat())[:10]
        due = datetime.date.fromisoformat(base) + datetime.timedelta(days=every)
        if r["decision"] == "remove":
            state = "removal-requested"
        elif r["decision"] == "modify":
            state = "change-requested"
        elif today > due + datetime.timedelta(days=grace):
            state = "overdue"
        elif today > due - datetime.timedelta(days=30):
            state = "due-soon"
        else:
            state = "current"
        counts[state] += 1
        out.append({"device": r["device"], "key": r["key"], "rule": r["name"], "owner": r["owner"], "state": state, "due": due.isoformat(), "certified_at": r["certified_at"],
                    "certified_by": r["certified_by"], "decision": r["decision"], "decision_note": r["decision_note"]})
    order = {"overdue": 0, "removal-requested": 1, "change-requested": 2, "due-soon": 3, "current": 4}
    out.sort(key=lambda x: (order[x["state"]], x["due"]))
    return {"rules": out, "counts": counts, "interval_days": every}


# ---------------------------------------------------------------- change requests
def _req(r):
    d = dict(r)
    d["request"] = json.loads(d.pop("request_json"))
    d["check"] = json.loads(d.pop("check_json"))
    return d


def submit_request(requester, sources, destinations, services, days, justification, all_rules, pol=None, topology=None, engine=None, now=None, src_zone=None, dst_zone=None):
    if not (justification or "").strip():
        raise ValueError("Say why the access is needed")
    for label, v in (("source", sources), ("destination", destinations), ("service", services)):
        if not v or not [x for x in v if str(x).strip()]:
            raise ValueError(f"Give at least one {label}")
    if days is not None and (not isinstance(days, int) or days < 1 or days > 3650):
        raise ValueError("days must be a whole number from 1 to 3650, or left empty for no end date")
    req = {"sources": [str(x).strip() for x in sources][:50], "destinations": [str(x).strip() for x in destinations][:50], "services": [str(x).strip() for x in services][:50], "days": days,
           "src_zone": (src_zone or "").strip()[:60] or None, "dst_zone": (dst_zone or "").strip()[:60] or None}
    check = analysis.check_request(req, all_rules, pol, topology)
    engine, t = _engine(engine), db_module.fw_requests
    status = "submitted"
    row = {"requester": requester, "request_json": json.dumps(req), "justification": justification.strip()[:1000], "status": status, "check_json": json.dumps(check), "created_at": _now(now),
           "decided_by": None, "decided_at": None, "decision_note": None, "implemented_at": None}
    with engine.begin() as conn:
        rid = conn.execute(insert(t), row).inserted_primary_key[0]
    return get_request(rid, engine)


def get_request(rid, engine=None):
    engine, t = _engine(engine), db_module.fw_requests
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(rid))).mappings().first()
    return _req(r) if r else None


def list_requests(engine=None, status=None):
    engine, t = _engine(engine), db_module.fw_requests
    q = select(t).order_by(t.c.id.desc())
    if status:
        q = q.where(t.c.status == status)
    with engine.connect() as conn:
        return [_req(r) for r in conn.execute(q).mappings().all()]


def decide_request(rid, status, actor, note="", engine=None, now=None):
    cur = get_request(rid, engine)
    if not cur:
        raise KeyError("No such request")
    allowed = {"submitted": ("approved", "rejected", "withdrawn"), "approved": ("implemented", "rejected")}
    if status not in allowed.get(cur["status"], ()):
        raise ValueError(f"A {cur['status']} request cannot become {status}")
    if status == "rejected" and not (note or "").strip():
        raise ValueError("Say why it was rejected")
    if status == "approved" and cur["check"]["verdict"] == "blocked-by-rule" and not (note or "").strip():
        raise ValueError("A deny rule blocks this traffic; say how the approval accounts for that")
    engine, t = _engine(engine), db_module.fw_requests
    vals = {"status": status}
    if status == "implemented":
        vals["implemented_at"] = _now(now)
    else:
        vals.update({"decided_by": actor, "decided_at": _now(now), "decision_note": (note or "")[:500]})
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.id == int(rid)).values(**vals))
    return get_request(rid, engine)


def request_metrics(reqs):
    def hours(a, b):
        try:
            f = "%Y-%m-%dT%H:%M:%SZ"
            return (datetime.datetime.strptime(b, f) - datetime.datetime.strptime(a, f)).total_seconds() / 3600
        except (TypeError, ValueError):
            return None
    decide = [hours(r["created_at"], r["decided_at"]) for r in reqs if r["decided_at"] and r["status"] in ("approved", "implemented")]
    impl = [hours(r["created_at"], r["implemented_at"]) for r in reqs if r["implemented_at"]]
    med = lambda xs: round(statistics.median([x for x in xs if x is not None]), 1) if [x for x in xs if x is not None] else None  # noqa: E731
    return {"total": len(reqs), "by_status": {s: sum(1 for r in reqs if r["status"] == s) for s in REQ_STATUSES}, "median_hours_to_decision": med(decide), "median_hours_to_implemented": med(impl),
            "already_allowed": sum(1 for r in reqs if r["check"]["verdict"] == "already-allowed"), "auto_approvable": sum(1 for r in reqs if r["check"]["auto_approvable"])}
