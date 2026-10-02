"""
Runs a SOAR playbook against an alert, step by step, keeping a log a person can read.

A run is stored after every step, so it survives a restart and a person can see exactly what happened. It ends completed, failed (a step
raised; later steps do not run), rejected (an approver said no) or cancelled, or it waits at a request-approval step.

Safety, in the order a reviewer would ask:
  - A dry run never contacts anything outside Quanta and changes nothing: external steps log what they WOULD do. An approval step passes in a
    dry run so the rest of the playbook can be seen, and the log says so.
  - A real run needs the providers for what it uses (reputation, SIEM, notify, response endpoint); a missing one fails that step with a
    message rather than skipping it silently.
  - A response action that changes your environment refuses to go unless an approval was recorded in THIS run, whatever the conditions did.
  - The approver must be a different person from whoever started the run when the policy says so (it does by default).
  - A playbook can mark an alert investigating or assign it; it can never close one.
Nothing runs on a schedule. An on-alert playbook starts when a matching alert arrives, within the hourly cap in the policy.
"""
import datetime
import json
import re

from sqlalchemy import insert, select, update

from remediation.hunting import soc, store as hunt_store
from remediation.soar import playbooks
from remediation.utils import db as db_module

STATUSES = ("running", "waiting-approval", "completed", "failed", "rejected", "cancelled")


class StepError(RuntimeError):
    pass


class Providers:
    """What a real run can reach. Any may be None; a step that needs a missing one fails with a clear message."""
    def __init__(self, lookup=None, siem_run=None, notify_webhook=None, send_email=None, response=None, findings=None, owners=None, save_investigation=None):
        self.lookup, self.siem_run, self.notify_webhook, self.send_email, self.response = lookup, siem_run, notify_webhook, send_email, response
        self.findings, self.owners, self.save_investigation = findings or [], owners or {}, save_investigation


def _now(now=None):
    return (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


# ---------------------------------------------------------------- small helpers
def _get(ctx, path):
    cur = ctx
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def condition_true(when, ctx):
    if not when:
        return True
    v, op, want = _get(ctx, when["path"]), when["op"], when.get("value")
    if op == "eq":
        return v == want
    if op == "ne":
        return v != want
    if op == "in":
        return v in (want if isinstance(want, list) else [want])
    if op == "gte":
        if v in playbooks.SEVERITY_ORDER and want in playbooks.SEVERITY_ORDER:
            return playbooks.SEVERITY_ORDER.index(v) >= playbooks.SEVERITY_ORDER.index(want)
        try:
            return float(v) >= float(want)
        except (TypeError, ValueError):
            return False
    if op == "truthy":
        return bool(v)
    return not bool(v)


def variables(alert, ctx):
    ent = alert.get("entities") or {}
    inv = ctx.get("investigation") or {}
    return {"title": alert["title"], "severity": alert["severity"], "asset": alert.get("asset") or "", "user": ent.get("user") or "", "first_ip": (ent.get("ips") or [""])[0],
            "first_domain": (ent.get("domains") or [""])[0], "first_hash": (ent.get("hashes") or [""])[0], "rule": alert.get("rule_name") or "", "technique": alert.get("technique") or "",
            "alert_id": str(alert["id"]), "verdict": inv.get("verdict", "not investigated"), "confidence": inv.get("confidence", "")}


def fmt(text, alert, ctx):
    v = variables(alert, ctx)
    return re.sub(r"\{([a-z_]+)\}", lambda m: str(v.get(m.group(1), m.group(0))), str(text))


# ---------------------------------------------------------------- persistence
def _run(r):
    d = dict(r)
    d["context"] = json.loads(d.pop("context_json"))
    d["log"] = json.loads(d.pop("log_json"))
    d["dry_run"] = bool(d["dry_run"])
    return d


def get_run(run_id, engine=None):
    engine, t = _engine(engine), db_module.soar_runs
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(run_id))).mappings().first()
    return _run(r) if r else None


def list_runs(engine=None, alert_id=None, status=None, limit=100):
    engine, t = _engine(engine), db_module.soar_runs
    q = select(t).order_by(t.c.id.desc()).limit(limit)
    if alert_id is not None:
        q = q.where(t.c.alert_id == int(alert_id))
    if status:
        q = q.where(t.c.status == status)
    with engine.connect() as conn:
        return [_run(r) for r in conn.execute(q).mappings().all()]


def _save(run_id, engine, **vals):
    t = db_module.soar_runs
    for k in ("context", "log"):
        if k in vals:
            vals[f"{k}_json"] = json.dumps(vals.pop(k), default=str)
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.id == int(run_id)).values(**vals))


def _log(log, i, step, status, detail, now=None):
    log.append({"step": i + 1, "type": step["type"], "status": status, "detail": detail, "at": _now(now)})


# ---------------------------------------------------------------- steps
def _investigate(alert, ctx, providers, dry_run, use_reputation, use_siem, save):
    if (use_reputation and not providers.lookup and not dry_run) or (use_siem and not providers.siem_run and not dry_run):
        missing = "reputation" if use_reputation and not providers.lookup else "Splunk search"
        raise StepError(f"No {missing} connection is configured for this run")
    inv = soc.investigate(alert, hunt_store.list_alerts(), providers.findings, providers.owners,
                          lookup=providers.lookup if use_reputation and not dry_run else None, siem_run=providers.siem_run if use_siem and not dry_run else None)
    ctx["investigation"] = inv
    if save and providers.save_investigation and not dry_run:
        providers.save_investigation(inv, soc.render_markdown(alert, inv))
    note = (" (reputation and SIEM lookups skipped in a dry run)" if dry_run and (use_reputation or use_siem) else "")
    return f"Verdict {inv['verdict']} ({inv['confidence']} confidence){note}"


def _step(i, st, alert, ctx, run, providers, pol, engine):
    t, p, dry = st["type"], st["params"], run["dry_run"]
    if t == "investigate":
        return _investigate(alert, ctx, providers, dry, p["reputation"], p["siem"], True)
    if t == "enrich-indicators":
        return _investigate(alert, ctx, providers, dry, True, False, True)
    if t == "add-note":
        text = fmt(p["text"], alert, ctx)
        if dry:
            return f"Would add the note: {text}"
        cur = hunt_store.get_alert(alert["id"], engine)
        hunt_store.update_alert(alert["id"], {"notes": ((cur["notes"] + "\n") if cur["notes"] else "") + f"[playbook {run['playbook_name']}] {text}"}, engine)
        return f"Added the note: {text}"
    if t == "update-alert":
        if dry:
            return f"Would set {p}"
        cur = hunt_store.get_alert(alert["id"], engine)
        fields = {}
        if p.get("status") and cur["status"] == "new":
            fields["status"] = p["status"]
        if p.get("assignee"):
            fields["assignee"] = p["assignee"]
        if fields:
            hunt_store.update_alert(alert["id"], fields, engine)
        return f"Set {fields or 'nothing (already past new)'}"
    if t == "notify":
        text = fmt(p["text"], alert, ctx)
        if dry:
            return f"Would send by {p['channel']}: {text}"
        if p["channel"] == "webhook":
            if not providers.notify_webhook:
                raise StepError("No notification webhook connection is configured")
            providers.notify_webhook.send(text)
        else:
            if not providers.send_email:
                raise StepError("Email is not configured on this Quanta")
            providers.send_email(p["to"], f"Quanta: {alert['title']}", text)
        return f"Sent by {p['channel']}"
    if t == "response-action":
        action, target = p["action"], fmt(p["target"], alert, ctx)
        approved = ctx.get("approvals") or []
        if playbooks.is_destructive(action) and not approved:
            raise StepError(f"'{action}' needs an approval recorded in this run, and there is none")
        if dry:
            return f"Would ask your endpoint to {action} {target}"
        if not providers.response:
            raise StepError("No response webhook connection is configured")
        providers.response.send(action, target, {"alert_id": alert["id"], "run_id": run["id"], "playbook": run["playbook_name"], "requested_by": run["started_by"],
                                                "approved_by": approved[-1]["by"] if approved else None, "reason": fmt(p.get("reason") or "", alert, ctx)})
        return f"Asked your endpoint to {action} {target}"
    raise StepError(f"Unknown step type {t}")


def _advance(run_id, pb, providers, engine, now=None):
    pol = playbooks.policy()
    run = get_run(run_id, engine)
    alert = hunt_store.get_alert(run["alert_id"], engine)
    ctx, log, i = run["context"], run["log"], run["next_step"]
    steps = pb["steps"]
    while i < len(steps):
        st = steps[i]
        if not condition_true(st.get("when"), {**ctx, "alert": alert}):
            _log(log, i, st, "skipped", "The condition was not met", now)
            i += 1
            continue
        if st["type"] == "request-approval":
            msg = fmt(st["params"]["message"], alert, ctx)
            if run["dry_run"]:
                ctx.setdefault("approvals", []).append({"step": i + 1, "by": "(dry run)", "at": _now(now), "simulated": True})
                _log(log, i, st, "dry-run", f"Would wait for approval: {msg}. Continuing as if approved so you can see the rest.", now)
                i += 1
                continue
            ctx["pending"] = {"step": i + 1, "message": msg}
            _log(log, i, st, "waiting", f"Waiting for a second person to approve: {msg}", now)
            _save(run_id, engine, status="waiting-approval", next_step=i + 1, context=ctx, log=log)
            return get_run(run_id, engine)
        try:
            detail = _step(i, st, alert, ctx, run, providers, pol, engine)
            _log(log, i, st, "dry-run" if run["dry_run"] and st["type"] in ("notify", "response-action", "add-note", "update-alert") else "ok", detail, now)
        except Exception as exc:  # noqa: BLE001 - a failing step ends the run, with the reason on record
            _log(log, i, st, "failed", str(exc)[:300], now)
            _save(run_id, engine, status="failed", finished_at=_now(now), next_step=i, context=ctx, log=log)
            return get_run(run_id, engine)
        alert = hunt_store.get_alert(run["alert_id"], engine) or alert
        i += 1
        _save(run_id, engine, next_step=i, context=ctx, log=log)
    _save(run_id, engine, status="completed", finished_at=_now(now), next_step=i, context=ctx, log=log)
    return get_run(run_id, engine)


# ---------------------------------------------------------------- public API
def start(pb, alert, actor, dry_run=True, providers=None, engine=None, now=None):
    engine, t = _engine(engine), db_module.soar_runs
    ctx = {"approvals": [], "pending": None, "investigation": None}
    with engine.begin() as conn:
        rid = conn.execute(insert(t), {"playbook_id": pb["id"], "playbook_name": pb["name"], "alert_id": alert["id"], "status": "running", "dry_run": 1 if dry_run else 0,
                                       "started_by": actor, "started_at": _now(now), "finished_at": None, "next_step": 0, "context_json": json.dumps(ctx), "log_json": "[]"}).inserted_primary_key[0]
    return _advance(rid, pb, providers or Providers(), engine, now)


def approve(run_id, approver, providers=None, engine=None, now=None):
    engine = _engine(engine)
    run = get_run(run_id, engine)
    if not run:
        raise KeyError("No such run")
    if run["status"] != "waiting-approval":
        raise ValueError("This run is not waiting for approval")
    if playbooks.policy().get("require_second_person", True) and approver == run["started_by"]:
        raise PermissionError("A different person must approve a run than the one who started it")
    pb = playbooks.get(run["playbook_id"], engine)
    if not pb:
        raise ValueError("The playbook no longer exists")
    ctx, log = run["context"], run["log"]
    ctx.setdefault("approvals", []).append({"step": (ctx.get("pending") or {}).get("step"), "by": approver, "at": _now(now)})
    ctx["pending"] = None
    log.append({"step": run["next_step"], "type": "request-approval", "status": "approved", "detail": f"Approved by {approver}", "at": _now(now)})
    _save(run_id, engine, status="running", context=ctx, log=log)
    return _advance(run_id, pb, providers or Providers(), engine, now)


def reject(run_id, approver, reason="", engine=None, now=None):
    engine = _engine(engine)
    run = get_run(run_id, engine)
    if not run:
        raise KeyError("No such run")
    if run["status"] != "waiting-approval":
        raise ValueError("This run is not waiting for approval")
    log = run["log"]
    log.append({"step": run["next_step"], "type": "request-approval", "status": "rejected", "detail": f"Rejected by {approver}" + (f": {reason[:200]}" if reason else ""), "at": _now(now)})
    _save(run_id, engine, status="rejected", finished_at=_now(now), log=log)
    return get_run(run_id, engine)


def cancel(run_id, actor, engine=None, now=None):
    engine = _engine(engine)
    run = get_run(run_id, engine)
    if not run:
        raise KeyError("No such run")
    if run["status"] not in ("waiting-approval", "running"):
        raise ValueError("This run has already finished")
    log = run["log"]
    log.append({"step": run["next_step"], "type": "run", "status": "cancelled", "detail": f"Cancelled by {actor}", "at": _now(now)})
    _save(run_id, engine, status="cancelled", finished_at=_now(now), log=log)
    return get_run(run_id, engine)


def auto_run(alert, providers_factory, engine=None, now=None):
    """Starts every enabled on-alert playbook that matches a new alert, within the hourly cap. Returns the runs started."""
    engine = _engine(engine)
    pol = playbooks.policy()
    cap = pol.get("auto_runs_per_hour", 20)
    now_dt = now or datetime.datetime.now(datetime.timezone.utc)
    since = (now_dt - datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    t = db_module.soar_runs
    with engine.connect() as conn:
        recent = len(conn.execute(select(t.c.id).where(t.c.started_by == "automation", t.c.started_at >= since)).all())
    started = []
    for pb in playbooks.list_all(engine):
        if not playbooks.matches_trigger(pb, alert):
            continue
        if recent + len(started) >= cap:
            break
        started.append(start(pb, alert, "automation", dry_run=False, providers=providers_factory(), engine=engine, now=now))
    return started
