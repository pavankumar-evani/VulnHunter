"""
Incident automation: the orchestration. An investigated alert is grouped into an incident (or starts one), the incident's derived fields are recomputed from its
alerts, it is routed, and every step is an event on its timeline. People act on incidents through accept, advance, reassign, escalate, resolve, reopen, merge,
split and undo_auto_close; none of them requires anyone to create a case first.

Safety rules kept here, not in configuration:
  * An alert is auto-closed only when the decision layer's gate says "auto" for its false-positive verdict (so the decision is declared reversible and local and
    confidence is at or above the auto threshold), policy allows it, its severity is not in never_for_severities (Critical is always listed in the shipped file)
    and no known-exploited vulnerability is on its host. An alert that correlates into a live incident is never auto-closed. It stays reviewable, with undo.
  * Resolving needs a verdict and a written summary; the analyst's verdict is what judges the decision layer's recommendation (calibration).
  * Routing never assigns someone who does not qualify; with nobody qualified the incident waits in its tier's queue and the lead is told.
  * Nothing here changes a customer environment.
"""
import datetime
import fnmatch
import json
from collections import Counter

from sqlalchemy import delete, insert, select, update

from remediation.decisions import calibration as decision_calibration, service as decision_service
from remediation.hunting import report as hunt_report
from remediation.soc import cases as soc_cases
from remediation.soc.incidents import correlate, roster, routing, store, summary
from remediation.utils import db as db_module

SYSTEM = "system"
ADVANCE = {"new": ("triaging", "investigating", "contained"), "triaging": ("investigating", "contained"), "investigating": ("triaging", "contained"),
           "contained": ("investigating",)}


class Context:
    """Data loaded once per request: asset type and criticality by host name (from the live findings queue) and owners."""

    def __init__(self, findings=(), owners=None):
        self.owners = owners or {}
        self.assets = {}
        for f in findings or []:
            a = f.get("asset") or {}
            n = (a.get("name") or "").lower()
            if n:
                cur = self.assets.setdefault(n, {"type": None, "criticality": None})
                cur["type"] = cur["type"] or a.get("type")
                cur["criticality"] = cur["criticality"] or (a.get("criticality") or "").lower() or None


def _engine(engine):
    return store.engine_for(engine)


# ---------------------------------------------------------------- facts captured when an alert arrives
def build_facts(alert, inv, ev, ctx):
    ti = hunt_report.technique_info(alert.get("technique")) or {}
    host = inv.get("host") or {}
    fnds = host.get("findings") or []
    name = (alert.get("asset") or "").lower()
    info = (ctx.assets.get(name) if ctx else None) or {}
    gate = (ev or {}).get("gate") or {}
    return {"verdict": inv.get("verdict"), "verdict_band": inv.get("confidence"), "verdict_confidence": gate.get("confidence"), "route": gate.get("route"),
            "gate_reasons": gate.get("reasons") or [], "category": inv.get("category"), "tactic": ti.get("tactic"), "technique": ti.get("id"), "technique_name": ti.get("name"),
            "cves": sorted({f["cve"] for f in fnds if f.get("cve") and (f.get("kev") or f.get("related_to_alert"))}),
            "kev_cves": sorted({f["cve"] for f in fnds if f.get("cve") and f.get("kev")}), "open_findings": host.get("open_findings"), "kev_findings": host.get("kev_findings"),
            "owner": host.get("owner"), "reasons": (inv.get("reasons") or [])[:4], "runbook": {"id": (inv.get("runbook") or {}).get("id"), "name": (inv.get("runbook") or {}).get("name")},
            "asset_type": info.get("type"), "asset_criticality": info.get("criticality"), "signals": sorted(k for k, v in (inv.get("signals") or {}).items() if v)}


def evaluate(alert, inv):
    """The decision layer's reading of this investigation (dry: nothing is logged here). None if it cannot be evaluated."""
    try:
        return decision_service.public(decision_service.evaluate("soc-alert-triage", {"signals": inv["signals"], "severity": alert.get("severity")}))
    except Exception:  # noqa: BLE001 - a failed evaluation means no auto-close, never a lost alert
        return None


# ---------------------------------------------------------------- candidates for correlation
def _candidates(engine, now, pol):
    it, ia, a = db_module.soc_incidents, db_module.soc_incident_alerts, db_module.soc_alerts
    since = store.iso(now - datetime.timedelta(minutes=pol["correlation"]["window_minutes"]))
    with engine.connect() as conn:
        incs = conn.execute(select(it.c.id, it.c.status, it.c.last_alert_at, it.c.created_at).where(it.c.status.in_(store.OPEN + ("auto_closed",)))).mappings().all()
        incs = [i for i in incs if (i["last_alert_at"] or i["created_at"]) >= since]
        if not incs:
            return []
        ids = [i["id"] for i in incs]
        rows = conn.execute(select(a, ia.c.incident_id, ia.c.facts_json, ia.c.role).join(ia, ia.c.alert_id == a.c.id).where(ia.c.incident_id.in_(ids)).order_by(a.c.id)).mappings().all()
    by = {i["id"]: {"id": i["id"], "status": i["status"], "last_alert_at": i["last_alert_at"] or i["created_at"], "alerts": []} for i in incs}
    for r in rows:
        d = dict(r)
        d["facts"] = json.loads(d.pop("facts_json") or "{}")
        try:
            d["entities"] = json.loads(d.pop("entities_json") or "null") or {}
        except ValueError:
            d["entities"] = {}
        by[d.pop("incident_id")]["alerts"].append(d)
    return list(by.values())


# ---------------------------------------------------------------- recompute
def _crown(assets, pol):
    pats = [p.lower() for p in pol.get("crown_jewels") or []]
    return any(fnmatch.fnmatch(a.lower(), p) for a in assets for p in pats)


def recompute(incident_id, engine=None, now=None, actor=SYSTEM):
    """Rebuilds every derived field of an incident from its alerts. Returns (incident, severity_rose: bool, raise_reason)."""
    engine, now, pol = _engine(engine), now or store.now_dt(), store.policy()
    inc = store.raw_incident(incident_id, engine)
    rows = store.alert_rows(incident_id, engine)
    if not rows:
        return inc, False, None
    real = [r for r in rows if r["role"] != "duplicate"] or rows
    ents = {"hosts": [], "users": [], "indicators": []}
    for r in rows:
        k = correlate.keys(r)
        for n in ents:
            for v in sorted(k[n]):
                if v not in ents[n]:
                    ents[n].append(v)
    assets, seen = [], set()
    for r in rows:
        if r.get("asset") and r["asset"].lower() not in seen:
            seen.add(r["asset"].lower())
            assets.append(r["asset"])
    techs, tseen = [], set()
    for r in real:
        f = r["facts"]
        t = f.get("technique") or r.get("technique")
        if t and t not in tseen:
            tseen.add(t)
            techs.append({"id": t, "name": f.get("technique_name"), "tactic": f.get("tactic")})
    cves = sorted({c for r in rows for c in r["facts"].get("cves", [])})
    chain = correlate.kill_chain([{"id": r["id"], "technique": r.get("technique"), "received_at": r["received_at"], "facts": r["facts"]} for r in real], pol)
    sev, base, why = correlate.roll_up_severity([r["severity"] for r in real], chain, pol)
    confs = []
    for r in real:
        f = r["facts"]
        c, v = f.get("verdict_confidence"), f.get("verdict")
        if c is None or not v:
            continue
        confs.append(c if v == "likely-true-positive" else (1 - c) if v == "likely-false-positive" else 0.5)
    cfg = pol["confidence"]
    conf = None if not confs else round(min(1.0, max(confs) + min(cfg["max_bonus"], cfg["corroboration_bonus"] * (len(confs) - 1))), 4)
    impact = soc_cases.impact_for(assets, {"user": ents["users"][0] if ents["users"] else None}, raised=any((r["facts"].get("kev_findings") or 0) > 0 for r in real))
    prio, _ = soc_cases.priority_for(impact, sev)
    title = real[0]["title"] + (f" (+{len(real) - 1} related alert(s))" if len(real) > 1 else "")
    last = max(r["received_at"] for r in rows)
    draft = {**inc, "severity": sev, "base_severity": base, "kill_chain": chain, "entities": ents, "confidence": conf, "cves": cves}
    text = summary.build(draft, [{**r, "facts": r["facts"]} for r in rows])
    store.write(incident_id, {"title": title[:300], "severity": sev, "base_severity": base, "priority": prio, "confidence": conf, "summary": text, "kill_chain": chain, "entities": ents,
                              "assets": assets, "techniques": techs, "cves": cves, "last_alert_at": last}, engine, now)
    if inc["case_id"]:
        with engine.begin() as conn:
            conn.execute(update(db_module.soc_cases).where(db_module.soc_cases.c.id == inc["case_id"]).values(
                severity=sev, impact=impact, priority=prio, assets_json=json.dumps(assets), entities_json=json.dumps({"user": ents["users"][0] if ents["users"] else None, "hosts": ents["hosts"]}),
                techniques_json=json.dumps([{"id": t["id"], "name": t["name"]} for t in techs]), updated_at=store.iso(now)))
    out = store.raw_incident(incident_id, engine)
    return out, store.sev_index(sev) > store.sev_index(inc["severity"]), why


def _refresh_summary(incident_id, engine, now):
    """Rewrites the deterministic summary from the stored fields (it names the tier, so it is rebuilt after routing)."""
    inc = store.raw_incident(incident_id, engine)
    rows = store.alert_rows(incident_id, engine)
    if rows:
        store.write(incident_id, {"summary": summary.build(inc, rows)}, engine, now)


def _view(inc, rows, pol):
    """The facts routing needs, from the stored alert facts (no outside data)."""
    real = [r for r in rows if r["role"] != "duplicate"] or rows
    facts = [r["facts"] for r in real]
    assets = [a.lower() for a in inc["assets"]]
    tier, tier_reasons = routing.required_tier({
        "severity": inc["severity"], "confidence": inc["confidence"], "hosts": inc["entities"].get("hosts") or [],
        "kev": any((f.get("kev_findings") or 0) > 0 for f in facts), "crown_jewel": _crown(assets, pol),
        "critical_asset": any((f.get("asset_criticality") or "") in ("critical", "high") for f in facts),
        "late_stage_progression": any(s["late_stage"] for s in inc["kill_chain"]) and len(inc["kill_chain"]) >= 2}, pol)
    cat = Counter(f.get("category") for f in facts if f.get("category") and f["category"] != "other").most_common(1)
    spec, why = routing.needed_specialty(cat[0][0] if cat else None, [f.get("asset_type") for f in facts if f.get("asset_type")], pol)
    return {"tier": tier, "tier_reasons": tier_reasons, "priority": inc["priority"], "specialty": spec, "specialty_why": why, "severity": inc["severity"]}


def _slas(engine, now):
    return {c["id"]: c["sla"]["worst"] for c in soc_cases.list_cases(engine, open_only=True, now=now)}


def _related(inc, others, now, pol):
    hrs = pol["routing"]["continuity_hours"]
    since = store.iso(now - datetime.timedelta(hours=hrs))
    mine = {*(inc["entities"].get("hosts") or []), *(inc["entities"].get("users") or [])}
    out = []
    for o in others:
        if o["id"] == inc["id"] or not o["assignee"] or o["status"] in ("merged", "auto_closed"):
            continue
        if o["status"] not in store.OPEN and (o["updated_at"] or "") < since:
            continue
        if mine & {*(o["entities"].get("hosts") or []), *(o["entities"].get("users") or [])}:
            out.append({"assignee": o["assignee"], "incident_id": o["id"], "at": o["updated_at"]})
    return out


def _load_incidents(engine, now, pol):
    it = db_module.soc_incidents
    since = store.iso(now - datetime.timedelta(hours=pol["routing"]["continuity_hours"]))
    with engine.connect() as conn:
        rows = conn.execute(select(it).where((it.c.status.in_(store.OPEN)) | ((it.c.status == "resolved") & (it.c.updated_at >= since)))).mappings().all()
    return [store.row_to_incident(r) for r in rows]


def _set_case(case_id, engine, now, **vals):
    if not case_id:
        return
    vals["updated_at"] = store.iso(now)
    with engine.begin() as conn:
        conn.execute(update(db_module.soc_cases).where(db_module.soc_cases.c.id == case_id).values(**vals))


def route(incident_id, engine=None, now=None, actor=SYSTEM, why=None, keep_current=True, exclude=(), force_tier=None):
    """Works out the tier and the assignee (or queue) for an open incident and applies it. Returns the routing result."""
    engine, now, pol = _engine(engine), now or store.now_dt(), store.policy()
    inc = store.raw_incident(incident_id, engine)
    if not inc or inc["status"] not in store.OPEN:
        raise ValueError("Only an open incident can be routed")
    rows = store.alert_rows(incident_id, engine)
    view = _view(inc, rows, pol)
    if force_tier:
        view["tier"] = max(view["tier"], force_tier)
        view["tier_reasons"].append(f"Tier {force_tier} after escalation.")
    prev_tier = inc["tier"]
    # the tier never goes down on its own: an escalation or a kill-chain rise is kept
    view["tier"] = max(view["tier"], prev_tier if inc["routing_reason"] else 1)
    ros, others = roster.list_roster(engine, now), _load_incidents(engine, now, pol)
    current = inc["assignee"] if keep_current else None
    kept = False
    if current:
        ok, why_not = routing.still_eligible(current, view, ros, others, now, pol)
        kept = ok and current not in exclude
    res = routing.choose(view, ros, others, _related(inc, others, now, pol), now, pol, _slas(engine, now), exclude=exclude, current=current if kept else None)
    if kept and res["assignee"] != current:
        # stability: the owner still qualifies, so a better-ranked colleague does not take it from them
        res = {**res, "assignee": current, "reasons": res["reasons"][:1] + [f"Kept with {current}, who still qualifies; a re-route does not move work that is going well."], "unrouted": False}
    reasons = ([why] if why else []) + view["tier_reasons"] + res["reasons"]
    prev = inc["assignee"]
    ts = store.iso(now)
    changed = (prev != res["assignee"]) or (prev_tier != view["tier"]) or not inc["routing_reason"]
    store.write(incident_id, {"tier": view["tier"], "queue": res["queue"], "assignee": res["assignee"], "routing_reason": reasons,
                              "assigned_at": ts if res["assignee"] and res["assignee"] != prev else inc["assigned_at"]}, engine, now)
    _set_case(inc["case_id"], engine, now, tier=view["tier"], assignee=res["assignee"])
    _refresh_summary(incident_id, engine, now)
    with engine.begin() as conn:
        if changed or why:
            kind = "unrouted" if res["unrouted"] else ("reassigned" if prev and prev != res["assignee"] else "routed")
            store.event(conn, incident_id, kind, actor, reasons[-1] if res["unrouted"] else f"{'Routed' if kind == 'routed' else 'Re-routed'} to {res['assignee'] or res['queue']}",
                        {"from": prev, "to": res["assignee"], "queue": res["queue"], "tier": view["tier"], "reasons": reasons, "candidates": res["candidates"][:8]}, now)
    if res["unrouted"] and not any("Nobody who qualifies" in r for r in inc["routing_reason"]):
        _alert_lead(inc, res, engine, now)
    return {**res, "reasons": reasons}


def _alert_lead(inc, res, engine, now):
    """Nobody qualified: record it where the lead will see it (activity log, the live stream) and mail the lead when one is configured."""
    try:
        from remediation.audit import activity_log
        activity_log.record_activity(SYSTEM, "soc.incident.unrouted", str(inc["id"]), {"tier": res["tier"], "queue": res["queue"], "severity": inc["severity"]}, engine=engine)
    except Exception:  # noqa: BLE001
        pass
    lead = store.policy()["routing"].get("lead_email")
    if lead:
        try:
            from remediation.notifications import email_sender
            if email_sender.is_configured():
                email_sender.send_email([lead], f"Quanta: incident {inc['id']} has no analyst available", "\n".join(res["reasons"]))
        except Exception:  # noqa: BLE001
            pass


def preview(alert, engine=None, now=None, inv=None, ctx=None):
    """What would happen to this alert: which incident it would join (or that it would start one) and who it would be routed to. Writes nothing."""
    engine, now, pol = _engine(engine), now or store.now_dt(), store.policy()
    ctx = ctx or Context()
    existing = store.incident_for_alert(alert["id"], engine)
    if existing:
        inc = store.get_incident(existing, engine, now)
        return {"alert_id": alert["id"], "already_in_incident": existing, "incident_id": existing, "would_join": existing, "routing": {"assignee": inc["assignee"], "queue": inc["queue"],
                "tier": inc["tier"], "reasons": inc["routing_reason"]}, "correlation": inc["correlation"]}
    facts = _preview_facts(alert, inv, ctx)
    cand = _candidates(engine, now, pol)
    target, sc, reasons, dup = correlate.best_incident(alert | {"received_at": alert.get("received_at") or store.iso(now)}, facts, cand, pol)
    view_inc = {"severity": alert["severity"], "confidence": None, "entities": {"hosts": sorted(correlate.keys(alert)["hosts"])}, "assets": [alert["asset"]] if alert.get("asset") else [],
                "kill_chain": [], "priority": soc_cases.priority_for("single", alert["severity"])[0]}
    rows = [{"role": "primary", "facts": facts}]
    if target:
        t = store.raw_incident(target["id"], engine)
        view_inc = {**t, "severity": max([t["severity"], alert["severity"]], key=store.sev_index)}
        rows = store.alert_rows(t["id"], engine) + rows
    v = _view(view_inc, rows, pol)
    ros, others = roster.list_roster(engine, now), _load_incidents(engine, now, pol)
    res = routing.choose(v, ros, others, _related({**view_inc, "id": -1}, others, now, pol), now, pol, _slas(engine, now), current=view_inc.get("assignee") if target else None)
    return {"alert_id": alert["id"], "already_in_incident": None, "would_join": target["id"] if target else None, "would_be_duplicate_of_alert": dup,
            "correlation": {"score": sc, "reasons": reasons, "join_threshold": pol["correlation"]["join_threshold"]},
            "routing": {"assignee": res["assignee"], "queue": res["queue"], "tier": res["tier"], "reasons": v["tier_reasons"] + res["reasons"], "candidates": res["candidates"][:10], "unrouted": res["unrouted"]},
            "note": "A preview. Nothing was created, grouped or assigned."}


def _preview_facts(alert, inv, ctx):
    ti = hunt_report.technique_info(alert.get("technique")) or {}
    name = (alert.get("asset") or "").lower()
    info = ctx.assets.get(name) or {}
    f = {"tactic": ti.get("tactic"), "technique": ti.get("id"), "cves": [], "kev_cves": [], "kev_findings": 0, "category": None, "asset_type": info.get("type"), "asset_criticality": info.get("criticality")}
    if inv:
        f.update(build_facts(alert, inv, evaluate(alert, inv), ctx))
    return f


# ---------------------------------------------------------------- ingest
def _auto_close_ok(alert, facts, ev, pol):
    ac = pol["auto_close"]
    if not ac.get("enabled") or not ev or facts.get("verdict") != "likely-false-positive":
        return False, "not a likely false positive, or auto-close is off"
    if alert["severity"] in ac["never_for_severities"]:
        return False, f"{alert['severity']} alerts are never auto-closed"
    if ac.get("also_never_when_kev_on_host") and (facts.get("kev_findings") or 0) > 0:
        return False, "a known-exploited vulnerability is open on the host"
    g = ev["gate"]
    if g["route"] != "auto":
        return False, f"the decision layer routed it '{g['route']}', not 'auto' ({g['reasons'][0] if g['reasons'] else ''})"
    return True, f"The decision layer routed this verdict 'auto' at {round(100 * g['confidence'])}% confidence (thresholds auto {g['thresholds']['auto']}, review {g['thresholds']['review']}); reversible and local."


def _new_incident(engine, alert, facts, now, source="auto", status="new"):
    t = db_module.soc_incidents
    ts = store.iso(now)
    with engine.begin() as conn:
        iid = conn.execute(insert(t), {"title": alert["title"][:300], "severity": alert["severity"], "base_severity": alert["severity"],
                                       "priority": soc_cases.priority_for("single", alert["severity"])[0], "tier": 1, "queue": None, "status": status, "assignee": None,
                                       "source": source, "escalation_count": 0, "created_at": ts, "updated_at": ts, "last_alert_at": alert.get("received_at") or ts,
                                       "routing_reason_json": "[]", "correlation_json": "[]", "kill_chain_json": "[]", "entities_json": "{}", "assets_json": "[]",
                                       "techniques_json": "[]", "cves_json": "[]"}).inserted_primary_key[0]
    return iid


def _ensure_case(incident_id, engine, now, source="auto", actor=SYSTEM):
    inc = store.raw_incident(incident_id, engine)
    if inc["case_id"]:
        return inc["case_id"]
    rows = store.alert_rows(incident_id, engine)
    top = rows[0]["facts"] if rows else {}
    c = soc_cases.open_case({"title": inc["title"], "severity": inc["severity"], "assets": inc["assets"], "entities": {"user": (inc["entities"].get("users") or [None])[0]},
                             "techniques": [{"id": t["id"], "name": t["name"]} for t in inc["techniques"]], "alert_ids": [r["id"] for r in rows],
                             "recommendation": top.get("verdict"), "source": source, "tier": max(1, inc["tier"]), "summary": inc["summary"]}, actor, engine, now)
    store.write(incident_id, {"case_id": c["id"]}, engine, now)
    return c["id"]


def ingest(alert, inv, ctx=None, engine=None, now=None):
    """Takes one investigated alert into the incident layer. Returns the incident, or None when the layer is off. Idempotent per alert."""
    pol = store.policy()
    if not (pol.get("incidents") or {}).get("enabled"):
        return None
    engine, now, ctx = _engine(engine), now or store.now_dt(), ctx or Context()
    existing = store.incident_for_alert(alert["id"], engine)
    if existing:
        return store.get_incident(existing, engine, now)
    ev = evaluate(alert, inv)
    facts = build_facts(alert, inv, ev, ctx)
    a = {**alert, "received_at": alert.get("received_at") or store.iso(now)}
    cand = _candidates(engine, now, pol)
    live = [c for c in cand if c["status"] in store.OPEN]
    target, sc, reasons, dup = correlate.best_incident(a, facts, live, pol)
    ok, close_why = _auto_close_ok(a, facts, ev, pol)
    # an auto-closed alert may still be a duplicate of an earlier auto-closed one: grouped there, not as a new line in the lane
    if not target and ok:
        for c in cand:
            if c["status"] == "auto_closed" and correlate.is_duplicate(a, c["alerts"], pol):
                return _join_auto_closed(c["id"], a, facts, ev, close_why, engine, now)
    if target:
        return _join(target["id"], a, facts, sc, reasons, dup, engine, now)
    if ok:
        return _auto_close(a, facts, ev, close_why, engine, now)
    iid = _new_incident(engine, a, facts, now)
    with engine.begin() as conn:
        store.link_alert(conn, iid, a["id"], "primary", [{"reason": "first_alert", "weight": 0, "detail": "This alert started the incident."}], facts, now)
        conn.execute(update(db_module.soc_alerts).where(db_module.soc_alerts.c.id == a["id"], db_module.soc_alerts.c.status == "new").values(status="investigating"))
        store.event(conn, iid, "created", SYSTEM, f"Incident created from alert {a['id']}: {a['title']}", {"alert_id": a["id"]}, now)
        store.event(conn, iid, "investigation", SYSTEM, f"First-look verdict {facts['verdict']} ({facts.get('verdict_band')} confidence)",
                    {"alert_id": a["id"], "verdict": facts["verdict"], "reasons": facts["reasons"], "gate": (ev or {}).get("gate"), "auto_close_considered": close_why}, now)
    recompute(iid, engine, now)
    _ensure_case(iid, engine, now)
    route(iid, engine, now, SYSTEM, keep_current=False)
    return store.get_incident(iid, engine, now)


def _join(iid, alert, facts, sc, reasons, dup, engine, now):
    role = "duplicate" if dup else "correlated"
    with engine.begin() as conn:
        store.link_alert(conn, iid, alert["id"], role, reasons, facts, now)
        conn.execute(update(db_module.soc_alerts).where(db_module.soc_alerts.c.id == alert["id"], db_module.soc_alerts.c.status == "new").values(status="investigating"))
        body = (f"Alert {alert['id']} merged as a duplicate of alert {dup}: same rule, same host" if dup else f"Alert {alert['id']} added: " + " ".join(r["detail"] for r in reasons))
        store.event(conn, iid, "alert_added", SYSTEM, body, {"alert_id": alert["id"], "role": role, "score": sc, "reasons": reasons, "duplicate_of": dup}, now)
        store.event(conn, iid, "investigation", SYSTEM, f"First-look verdict {facts['verdict']} for alert {alert['id']}", {"alert_id": alert["id"], "verdict": facts["verdict"], "reasons": facts["reasons"]}, now)
    inc = store.raw_incident(iid, engine)
    store.write(iid, {"correlation": inc["correlation"] + [{"alert_id": alert["id"], "role": role, "score": sc, "reasons": reasons}]}, engine, now)
    if inc["case_id"]:
        try:
            soc_cases.link_alert(inc["case_id"], alert["id"], SYSTEM, engine, now)
        except (ValueError, KeyError):
            pass
    out, rose, why = recompute(iid, engine, now)
    if rose:
        store.add_event(iid, "severity_raised", SYSTEM, f"Severity raised to {out['severity']}: {why}" if why else f"Severity is now {out['severity']}", {"to": out["severity"], "reason": why}, engine, now)
    if out["status"] in store.OPEN and (rose or not out["assignee"] or not dup):
        route(iid, engine, now, SYSTEM, why=f"Re-evaluated after alert {alert['id']} joined" + (f"; severity is now {out['severity']}" if rose else ""), keep_current=True)
    return store.get_incident(iid, engine, now)


def _close_alert(conn, alert_id, now):
    conn.execute(update(db_module.soc_alerts).where(db_module.soc_alerts.c.id == alert_id).values(status="closed", disposition="false-positive", action_taken="auto-closed", closed_at=store.iso(now)))


def _auto_close(alert, facts, ev, why, engine, now):
    iid = _new_incident(engine, alert, facts, now, status="auto_closed")
    with engine.begin() as conn:
        store.link_alert(conn, iid, alert["id"], "primary", [{"reason": "first_alert", "weight": 0, "detail": "This alert started the incident."}], facts, now)
        _close_alert(conn, alert["id"], now)
        store.event(conn, iid, "created", SYSTEM, f"Incident created from alert {alert['id']}: {alert['title']}", {"alert_id": alert["id"]}, now)
        store.event(conn, iid, "auto_closed", SYSTEM, "Auto-closed as a likely false positive. " + why, {"alert_id": alert["id"], "gate": ev["gate"], "undo": f"POST /api/soc/incidents/{iid}/undo-auto-close"}, now)
    recompute(iid, engine, now)
    store.write(iid, {"verdict": "false-positive", "routing_reason": ["Auto-closed, not routed: " + why, "It stays in the auto-closed lane for review; undo returns it to the queue."], "queue": None}, engine, now)
    return store.get_incident(iid, engine, now)


def _join_auto_closed(iid, alert, facts, ev, why, engine, now):
    with engine.begin() as conn:
        store.link_alert(conn, iid, alert["id"], "duplicate", [{"reason": "same_rule_same_host", "weight": 0, "detail": "Same rule on the same host as an auto-closed alert."}], facts, now)
        _close_alert(conn, alert["id"], now)
        store.event(conn, iid, "auto_closed", SYSTEM, f"Alert {alert['id']} auto-closed and grouped as a duplicate. " + why, {"alert_id": alert["id"], "gate": ev["gate"]}, now)
    recompute(iid, engine, now)
    return store.get_incident(iid, engine, now)


# ---------------------------------------------------------------- analyst actions
def _need(inc, allowed=store.OPEN):
    if not inc:
        raise KeyError("No such incident")
    if inc["status"] not in allowed:
        raise ValueError(f"The incident is {inc['status']}; this action needs it to be {' or '.join(allowed)}")


def accept(incident_id, actor, engine=None, now=None):
    """The analyst takes it: the owner (or anyone, when it is waiting in a queue) accepts, which moves it to triaging and acknowledges the service-level clock."""
    engine, now = _engine(engine), now or store.now_dt()
    inc = store.raw_incident(incident_id, engine)
    _need(inc)
    me = actor.lower()
    if inc["assignee"] and inc["assignee"] != me:
        raise ValueError(f"The incident is routed to {inc['assignee']}. Ask for it to be reassigned instead of taking it")
    taken = not inc["assignee"]
    vals = {"assignee": me, "assigned_at": store.iso(now)} if taken else {}
    if inc["status"] == "new":
        vals["status"] = "triaging"
    if vals:
        store.write(incident_id, vals, engine, now)
    if taken:
        _set_case(inc["case_id"], engine, now, assignee=me)
    if inc["case_id"]:
        case = soc_cases.get_case(inc["case_id"], engine, now, detail=False)
        if case and case["escalation_count"] and not case["picked_up_at"]:
            _set_case(inc["case_id"], engine, now, picked_up_at=store.iso(now))      # the higher tier has taken it: stops the pick-up clock
        try:
            soc_cases.acknowledge(inc["case_id"], me, engine, now)
        except (ValueError, KeyError):
            pass
    store.add_event(incident_id, "accepted", me, f"Accepted by {me}" + (" (taken from the queue)" if taken else ""), {"taken_from_queue": taken}, engine, now)
    return store.get_incident(incident_id, engine, now)


def advance(incident_id, status, actor, engine=None, now=None, note=None):
    engine, now = _engine(engine), now or store.now_dt()
    inc = store.raw_incident(incident_id, engine)
    _need(inc)
    if status not in ADVANCE.get(inc["status"], ()):
        raise ValueError(f"An incident that is {inc['status']} can move to: {', '.join(ADVANCE.get(inc['status'], ()))} (or be resolved with a verdict)")
    store.write(incident_id, {"status": status}, engine, now)
    store.add_event(incident_id, "status", actor, note or f"{inc['status']} to {status}", {"from": inc["status"], "to": status}, engine, now)
    return store.get_incident(incident_id, engine, now)


def reassign(incident_id, assignee, actor, reason=None, engine=None, now=None):
    engine, now = _engine(engine), now or store.now_dt()
    inc = store.raw_incident(incident_id, engine)
    _need(inc)
    to = (assignee or "").strip().lower()
    r = roster.get(to, engine, now)
    if not r:
        raise ValueError(f"{to or 'That person'} is not an active analyst on the roster")
    if r["tier"] < inc["tier"]:
        raise ValueError(f"{to} works the L{r['tier']} queue; this incident needs L{inc['tier']}. Escalate it or pick a higher-tier analyst")
    store.write(incident_id, {"assignee": to, "assigned_at": store.iso(now), "routing_reason": [f"Reassigned by {actor} to {to}" + (f": {reason}" if reason else "") + "."] + inc["routing_reason"][:6]}, engine, now)
    _set_case(inc["case_id"], engine, now, assignee=to)
    warn = [] if r["available"] and r["on_shift"] else ["The analyst is marked unavailable or outside their shift; the move was made anyway."]
    store.add_event(incident_id, "reassigned", actor, f"Reassigned from {inc['assignee'] or 'the queue'} to {to}" + (f": {reason}" if reason else ""), {"from": inc["assignee"], "to": to, "reason": reason, "warnings": warn}, engine, now)
    return store.get_incident(incident_id, engine, now)


def escalate(incident_id, summary_text, actor, to_tier=None, engine=None, now=None, auto=False):
    engine, now, pol = _engine(engine), now or store.now_dt(), store.policy()
    inc = store.raw_incident(incident_id, engine)
    _need(inc)
    if inc["tier"] >= pol["escalation"]["max_tier"] and not to_tier:
        raise ValueError("The incident is already at the highest tier")
    cid = _ensure_case(incident_id, engine, now)
    c = soc_cases.escalate(cid, summary_text, actor, engine, now, to_tier=to_tier, auto=auto)
    store.write(incident_id, {"tier": c["tier"], "status": "new", "assignee": None, "escalation_count": inc["escalation_count"] + 1}, engine, now)
    store.add_event(incident_id, "auto_escalated" if auto else "escalated", actor, summary_text, {"from_tier": inc["tier"], "to_tier": c["tier"], "auto": auto}, engine, now)
    route(incident_id, engine, now, actor, why=f"{'Automatically escalated' if auto else 'Escalated by ' + actor} to tier {c['tier']}.", keep_current=False, force_tier=c["tier"])
    return store.get_incident(incident_id, engine, now)


def resolve(incident_id, verdict, summary_text, actor, engine=None, now=None):
    """Needs a verdict and a written summary. The verdict judges the decision layer's recommendation for each alert (calibration)."""
    engine, now = _engine(engine), now or store.now_dt()
    inc = store.raw_incident(incident_id, engine)
    _need(inc)
    if verdict not in store.VERDICTS:
        raise ValueError(f"A verdict is required: one of {', '.join(store.VERDICTS)}")
    cid = _ensure_case(incident_id, engine, now)
    soc_cases.resolve(cid, verdict, summary_text, actor, engine, now)
    store.write(incident_id, {"status": "resolved", "verdict": verdict, "resolved_at": store.iso(now)}, engine, now)
    judged = 0
    for r in store.alert_rows(incident_id, engine):
        judged += decision_service.judge_soc_disposition(r["id"], verdict if verdict in ("true-positive", "false-positive", "benign") else "", engine)
    store.add_event(incident_id, "resolved", actor, summary_text.strip(), {"verdict": verdict, "calibration_rows_judged": judged}, engine, now)
    return store.get_incident(incident_id, engine, now)


def reopen(incident_id, reason, actor, engine=None, now=None):
    engine, now = _engine(engine), now or store.now_dt()
    inc = store.raw_incident(incident_id, engine)
    _need(inc, ("resolved",))
    if not (reason or "").strip():
        raise ValueError("Say why the incident is being reopened")
    if inc["case_id"]:
        soc_cases.reopen(inc["case_id"], reason, actor, engine, now)
    store.write(incident_id, {"status": "investigating" if inc["assignee"] else "new", "verdict": None, "resolved_at": None}, engine, now)
    with engine.begin() as conn:
        ids = [r[0] for r in conn.execute(select(db_module.soc_incident_alerts.c.alert_id).where(db_module.soc_incident_alerts.c.incident_id == int(incident_id)))]
        if ids:
            conn.execute(update(db_module.soc_alerts).where(db_module.soc_alerts.c.id.in_(ids)).values(status="investigating", disposition=None, closed_at=None))
    store.add_event(incident_id, "reopened", actor, reason.strip(), None, engine, now)
    route(incident_id, engine, now, actor, why=f"Reopened by {actor}.", keep_current=True)
    return store.get_incident(incident_id, engine, now)


def undo_auto_close(incident_id, actor, reason=None, engine=None, now=None):
    engine, now = _engine(engine), now or store.now_dt()
    inc = store.raw_incident(incident_id, engine)
    _need(inc, ("auto_closed",))
    rows = store.alert_rows(incident_id, engine)
    with engine.begin() as conn:
        ids = [r["id"] for r in rows]
        conn.execute(update(db_module.soc_alerts).where(db_module.soc_alerts.c.id.in_(ids)).values(status="investigating", disposition=None, closed_at=None, action_taken=None))
    judged = 0
    for r in rows:
        judged += decision_calibration.record_outcome_for_ref("soc-alert-triage", f"alert:{r['id']}", "overridden", question="verdict", outcome_value="escalate-l2", engine=engine)
    store.write(incident_id, {"status": "new", "verdict": None}, engine, now)
    store.add_event(incident_id, "auto_close_undone", actor, f"Auto-close undone by {actor}" + (f": {reason}" if reason else ""), {"calibration_rows_judged": judged, "reason": reason}, engine, now)
    recompute(incident_id, engine, now)
    _ensure_case(incident_id, engine, now)
    route(incident_id, engine, now, actor, why=f"Auto-close undone by {actor}; the system's false-positive verdict was overridden.", keep_current=False)
    return store.get_incident(incident_id, engine, now)


def merge(target_id, source_id, actor, engine=None, now=None):
    """Moves every alert of `source` into `target` and closes the source as merged. The decision is a person's."""
    engine, now = _engine(engine), now or store.now_dt()
    if int(target_id) == int(source_id):
        raise ValueError("Pick two different incidents")
    tgt, src = store.raw_incident(target_id, engine), store.raw_incident(source_id, engine)
    _need(tgt)
    _need(src)
    ia = db_module.soc_incident_alerts
    with engine.begin() as conn:
        ids = [r[0] for r in conn.execute(select(ia.c.alert_id).where(ia.c.incident_id == int(source_id)))]
        conn.execute(update(ia).where(ia.c.incident_id == int(source_id)).values(incident_id=int(target_id), role="correlated"))
        if src["case_id"] and tgt["case_id"]:
            conn.execute(update(db_module.soc_case_alerts).where(db_module.soc_case_alerts.c.case_id == src["case_id"]).values(case_id=tgt["case_id"]))
        store.event(conn, target_id, "merged_in", actor, f"Incident {source_id} merged in ({len(ids)} alert(s))", {"source": int(source_id), "alert_ids": ids}, now)
        store.event(conn, source_id, "merged", actor, f"Merged into incident {target_id}", {"into": int(target_id)}, now)
    store.write(source_id, {"status": "merged", "merged_into": int(target_id), "assignee": None}, engine, now)
    if src["case_id"]:
        _set_case(src["case_id"], engine, now, status="closed", resolution="duplicate", closed_at=store.iso(now), resolved_at=store.iso(now), assignee=None)
        soc_cases.add_note(src["case_id"], f"Merged into incident {target_id} by {actor}.", actor, engine, now)
    out, rose, why = recompute(target_id, engine, now)
    if rose:
        store.add_event(target_id, "severity_raised", SYSTEM, f"Severity raised to {out['severity']}: {why}", {"to": out["severity"], "reason": why}, engine, now)
    route(target_id, engine, now, actor, why=f"Re-evaluated after incident {source_id} was merged in.", keep_current=True)
    return store.get_incident(target_id, engine, now)


def split(incident_id, alert_ids, actor, engine=None, now=None):
    """Moves the given alerts into a new incident (routed on its own). At least one alert must stay."""
    engine, now = _engine(engine), now or store.now_dt()
    inc = store.raw_incident(incident_id, engine)
    _need(inc)
    rows = store.alert_rows(incident_id, engine)
    have = {r["id"] for r in rows}
    ids = sorted({int(i) for i in alert_ids or []})
    if not ids or not set(ids) <= have:
        raise ValueError("Name alerts that belong to this incident")
    if set(ids) == have:
        raise ValueError("At least one alert must stay in the original incident")
    first = next(r for r in rows if r["id"] in ids)
    new_id = _new_incident(engine, first, first["facts"], now)
    ia = db_module.soc_incident_alerts
    with engine.begin() as conn:
        conn.execute(update(ia).where(ia.c.alert_id.in_(ids)).values(incident_id=new_id, role="correlated"))
        conn.execute(update(ia).where(ia.c.alert_id == ids[0]).values(role="primary"))
        if inc["case_id"]:
            conn.execute(delete(db_module.soc_case_alerts).where(db_module.soc_case_alerts.c.case_id == inc["case_id"], db_module.soc_case_alerts.c.alert_id.in_(ids)))
        store.event(conn, new_id, "created", actor, f"Split from incident {incident_id} ({len(ids)} alert(s))", {"split_from": int(incident_id), "alert_ids": ids}, now)
        store.event(conn, incident_id, "split", actor, f"{len(ids)} alert(s) split into incident {new_id}", {"into": new_id, "alert_ids": ids}, now)
    recompute(new_id, engine, now)
    _ensure_case(new_id, engine, now, actor=actor)
    route(new_id, engine, now, actor, why=f"Split from incident {incident_id} by {actor}.", keep_current=False)
    recompute(incident_id, engine, now)
    route(incident_id, engine, now, actor, why=f"Re-evaluated after alerts were split off to incident {new_id}.", keep_current=True)
    return {"original": store.get_incident(incident_id, engine, now), "new": store.get_incident(new_id, engine, now)}


def create_manual(fields, actor, reason, engine=None, now=None):
    """The exception path: a person opens an incident by hand. A reason is required and recorded; the incident is routed like any other."""
    engine, now = _engine(engine), now or store.now_dt()
    if len((reason or "").strip()) < 10:
        raise ValueError("Manual creation is an exception: give a reason of at least 10 characters")
    title = (fields.get("title") or "").strip()
    if not title or len(title) > 300:
        raise ValueError("A title of 1 to 300 characters is required")
    sev = fields.get("severity") or "Medium"
    if sev not in store.SEVERITIES:
        raise ValueError(f"severity must be one of {', '.join(store.SEVERITIES)}")
    for aid in fields.get("alert_ids") or []:
        if store.incident_for_alert(aid, engine):
            raise ValueError(f"Alert {aid} is already in incident {store.incident_for_alert(aid, engine)}; merge or split instead")
    t, ts = db_module.soc_incidents, store.iso(now)
    assets = [str(a) for a in fields.get("assets") or [] if a]
    impact = soc_cases.impact_for(assets, {})
    with engine.begin() as conn:
        iid = conn.execute(insert(t), {"title": title, "severity": sev, "base_severity": sev, "priority": soc_cases.priority_for(impact, sev)[0], "tier": 1, "status": "new", "source": "manual-exception",
                                       "escalation_count": 0, "created_at": ts, "updated_at": ts, "last_alert_at": ts, "routing_reason_json": "[]", "correlation_json": "[]",
                                       "kill_chain_json": "[]", "entities_json": json.dumps({"hosts": [a.lower() for a in assets], "users": [], "indicators": []}),
                                       "assets_json": json.dumps(assets), "techniques_json": "[]", "cves_json": "[]", "summary": (fields.get("summary") or "").strip() or None}).inserted_primary_key[0]
        store.event(conn, iid, "created", actor, f"Created by hand (exception): {reason.strip()}", {"manual": True, "reason": reason.strip()}, now)
        for aid in fields.get("alert_ids") or []:
            store.link_alert(conn, iid, aid, "primary" if aid == fields["alert_ids"][0] else "correlated", [{"reason": "manual", "weight": 0, "detail": f"Added by {actor}."}], {}, now)
    if fields.get("alert_ids"):
        recompute(iid, engine, now)
    cid = soc_cases.open_case({"title": title, "severity": sev, "assets": assets, "alert_ids": fields.get("alert_ids") or [], "source": "manual", "summary": fields.get("summary")}, actor, engine, now)["id"]
    store.write(iid, {"case_id": cid}, engine, now)
    route(iid, engine, now, actor, why=f"Created by hand by {actor}; routed by the same rules as any incident.", keep_current=False)
    try:
        from remediation.audit import activity_log
        activity_log.record_activity(actor, "soc.incident.manual_create", str(iid), {"reason": reason.strip()[:300]}, engine=engine)
    except Exception:  # noqa: BLE001
        pass
    return store.get_incident(iid, engine, now)


# ---------------------------------------------------------------- recommended next actions
def recommended_actions(incident_id, playbooks=(), past=(), engine=None):
    """The runbook(s) the first-look investigations attached plus the playbooks soar.recommend ranks for the incident's lead alert. Starts nothing."""
    from remediation.soar import recommend
    engine = _engine(engine)
    rows = store.alert_rows(incident_id, engine)
    out = {"runbooks": [], "playbooks": [], "playbook_basis": "none", "next_steps": []}
    seen = set()
    for r in rows:
        rb = r["facts"].get("runbook") or {}
        if rb.get("id") and rb["id"] not in seen:
            seen.add(rb["id"])
            out["runbooks"].append(rb)
    lead = next((r for r in rows if r["role"] != "duplicate"), None)
    if lead is not None and playbooks:
        rec = recommend.recommend(lead, list(playbooks), list(past))
        out["playbooks"], out["playbook_basis"] = rec["recommendations"], rec["basis"]
    inc = store.raw_incident(incident_id, engine)
    steps = []
    if inc["status"] == "new":
        steps.append("Accept the incident to start the clock and begin triage.")
    if (inc["cves"]):
        steps.append("Confirm the host's known-exploited vulnerabilities are patched or isolated: " + ", ".join(inc["cves"][:5]) + ".")
    if len(inc["kill_chain"]) >= 2:
        steps.append("Scope the later stages first: " + inc["kill_chain"][-1]["tactic"] + " is the furthest the alerts show.")
    if inc["status"] in store.OPEN:
        steps.append("Resolve with a verdict (true positive, false positive or benign) and a short summary when done; that verdict also tunes the automatic decisions.")
    out["next_steps"] = steps
    return out


# ---------------------------------------------------------------- the periodic sweep
def sweep(engine=None, now=None):
    """Hourly (leader tick). 1) sync tiers the case sweep escalated, 2) escalate incidents whose clock is at the escalating state, 3) re-route incidents whose owner no
    longer qualifies, 4) retry the ones waiting in a queue. Returns what it did. Work that is going well is not moved."""
    engine, now, pol = _engine(engine), now or store.now_dt(), store.policy()
    if not (pol.get("incidents") or {}).get("enabled"):
        return {"enabled": False}
    soc_cases.sweep(engine, now)
    done = {"synced": [], "escalated": [], "rerouted": [], "retried": []}
    states = set(pol["escalation"]["on_sla"])
    by_case = {c["id"]: c for c in soc_cases.list_cases(engine, open_only=True, now=now)}
    for inc in store.list_incidents(engine, open_only=True, now=now):
        c = by_case.get(inc["case_id"])
        if c and c["tier"] != inc["tier"]:
            store.write(inc["id"], {"tier": c["tier"], "assignee": None, "status": "new", "escalation_count": inc["escalation_count"] + 1}, engine, now)
            store.add_event(inc["id"], "auto_escalated", SYSTEM, f"The case moved to L{c['tier']} (resolve target passed)", {"from_tier": inc["tier"], "to_tier": c["tier"]}, engine, now)
            route(inc["id"], engine, now, SYSTEM, why=f"Escalated to tier {c['tier']} when the case's resolve target passed.", keep_current=False, force_tier=c["tier"])
            done["synced"].append(inc["id"])
            continue
        trigger = None
        if c:
            sla = c["sla"]
            if c["escalation_count"]:       # already escalated: the clock that matters is the higher tier taking it
                if sla.get("pickup") and not sla["pickup"]["done"] and sla["pickup"]["state"] in states:
                    trigger = f"the L{inc['tier']} queue has not picked it up in time (the {sla['pickup']['state']} pick-up clock)"
            elif sla["ack"] and not sla["ack"]["done"] and sla["ack"]["state"] in states:
                trigger = f"it has not been accepted in time (the {sla['ack']['state']} acknowledgement clock)"
            elif sla["resolve"]["state"] in states and not sla["resolve"]["done"]:
                trigger = f"the resolve clock is {sla['resolve']['state']}"
        if trigger and inc["tier"] < pol["escalation"]["max_tier"] and inc["tier"] not in c["auto_escalated_tiers"]:
            escalate(inc["id"], f"Automatic escalation: {trigger}; priority {inc['priority']}, tier L{inc['tier']}.", SYSTEM, engine=engine, now=now, auto=True)
            done["escalated"].append(inc["id"])
            continue
        rows = store.alert_rows(inc["id"], engine)
        view = _view(inc, rows, pol)
        if inc["assignee"]:
            ok, why_not = routing.still_eligible(inc["assignee"], view, roster.list_roster(engine, now), _load_incidents(engine, now, pol), now, pol)
            if not ok:
                route(inc["id"], engine, now, SYSTEM, why=f"{inc['assignee']} no longer qualifies ({why_not}); re-routed.", keep_current=False, exclude=(inc["assignee"],))
                done["rerouted"].append(inc["id"])
        else:
            before = store.raw_incident(inc["id"], engine)["assignee"]
            res = route(inc["id"], engine, now, SYSTEM, keep_current=False)
            if res["assignee"] and not before:
                done["retried"].append(inc["id"])
    return done


def rebalance_analyst(email, engine=None, now=None):
    """After an analyst is marked unavailable (or their shift/tier changes): re-route their open incidents that no longer qualify. Returns the incident ids moved."""
    engine, now = _engine(engine), now or store.now_dt()
    moved = []
    pol = store.policy()
    for inc in store.list_incidents(engine, open_only=True, assignee=email, now=now):
        rows = store.alert_rows(inc["id"], engine)
        ok, why_not = routing.still_eligible(email, _view(inc, rows, pol), roster.list_roster(engine, now), _load_incidents(engine, now, pol), now, pol)
        if not ok:
            route(inc["id"], engine, now, SYSTEM, why=f"{email} no longer qualifies ({why_not}); re-routed.", keep_current=False, exclude=(email,))
            moved.append(inc["id"])
    return moved


def related_incidents(incident_id, engine=None, limit=10):
    """Other incidents that share a host, account, indicator or vulnerability with this one (not grouped, because the rules did not join them), newest first."""
    engine = _engine(engine)
    inc = store.raw_incident(incident_id, engine)
    if not inc:
        raise KeyError("No such incident")
    mine = {"host": set(inc["entities"].get("hosts") or []), "account": set(inc["entities"].get("users") or []), "indicator": set(inc["entities"].get("indicators") or []),
            "vulnerability": set(inc["cves"] or [])}
    out = []
    for o in store.list_incidents(engine):
        if o["id"] == inc["id"] or o["status"] == "merged":
            continue
        theirs = {"host": set(o["entities"].get("hosts") or []), "account": set(o["entities"].get("users") or []), "indicator": set(o["entities"].get("indicators") or []),
                  "vulnerability": set(o["cves"] or [])}
        shared = {k: sorted(mine[k] & theirs[k]) for k in mine if mine[k] & theirs[k]}
        if shared:
            out.append({"id": o["id"], "title": o["title"], "severity": o["severity"], "status": o["status"], "assignee": o["assignee"], "shared": shared, "created_at": o["created_at"]})
    out.sort(key=lambda r: r["created_at"], reverse=True)
    return out[:limit]
