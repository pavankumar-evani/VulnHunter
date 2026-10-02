"""
Automated control evidence: tests that read Quanta's own data and say whether a control appears to be operating.

Each test returns a result (pass, fail, warn or na), the number it measured, the threshold it was held to, and a sentence of detail. Results
are stored with a timestamp so there is a history, and mapped to framework controls (remediation/config/grc_tests.yaml) so a control's page
shows the latest evidence for it. Two rules keep this honest: a test with too little data returns `na`, never `pass`; and a result is evidence
that Quanta observed something, not an audit conclusion, so the report and the OSCAL export both say "observed by Quanta".
"""
import datetime
from pathlib import Path

import yaml
from sqlalchemy import insert, select

from remediation.utils import db as db_module

CONFIG = Path(__file__).resolve().parent.parent / "config" / "grc_tests.yaml"


def config():
    return yaml.safe_load(CONFIG.read_text(encoding="utf-8")) or {}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def _res(result, metric=None, threshold=None, detail=""):
    return {"result": result, "metric": metric, "threshold": threshold, "detail": detail}


def _pct(n, d):
    return round(100.0 * n / d, 1) if d else None


class Context:
    """The data the tests read, loaded once: pass real data in production, fakes in tests."""

    def __init__(self, findings, engine=None, today=None, thresholds=None):
        self.findings, self.engine = findings, _engine(engine)
        self.today = today or datetime.date.today()
        self.t = thresholds or config()["thresholds"]


def t_patch_sla(c):
    hi = [f for f in c.findings if f.get("severity") in ("Critical", "High") and f.get("sla")]
    if not hi:
        return _res("na", detail="No Critical or High findings with an SLA to measure.")
    ok = sum(1 for f in hi if not f["sla"].get("breached"))
    pct = _pct(ok, len(hi))
    th = c.t["patch_sla_min_pct"]
    return _res("pass" if pct >= th else "fail", pct, th, f"{ok} of {len(hi)} Critical and High findings are inside their SLA ({pct}%).")


def t_kev(c):
    kev = [f for f in c.findings if (f.get("kev") or {}).get("listed")]
    if not c.findings:
        return _res("na", detail="No findings loaded.")
    late = [f for f in kev if (f.get("sla") or {}).get("breached")]
    return _res("pass" if not late else "fail", len(late), 0, f"{len(late)} of {len(kev)} known-exploited findings are past their SLA." + (f" Oldest: {late[0]['id']}." if late else ""))


def t_scan_freshness(c):
    dates = [str(f.get("last_seen"))[:10] for f in c.findings if f.get("last_seen")]
    if not dates:
        return _res("na", detail="No findings carry a last-seen date.")
    age = (c.today - datetime.date.fromisoformat(max(dates))).days
    th = c.t["scan_max_age_days"]
    return _res("pass" if age <= th else "fail", age, th, f"The newest scan data is {age} day(s) old (last seen {max(dates)}).")


def t_exceptions(c):
    from remediation.exceptions import store as ex
    items = ex.list_exceptions_with_status(c.engine, as_of=c.today)
    active = [e for e in items if e.get("status") == "active"]
    bad = [e for e in active if not (e.get("reason") or "").strip() or not e.get("approved_by") or not e.get("expires_on")]
    th = c.t["max_active_exceptions"]
    if bad:
        return _res("fail", len(bad), 0, f"{len(bad)} active exception(s) lack a reason, an approver or an expiry date.")
    return _res("warn" if len(active) > th else "pass", len(active), th, f"{len(active)} active risk exception(s); each has a reason, an approver and an expiry.")


def t_ownership(c):
    hi = [f for f in c.findings if f.get("severity") in ("Critical", "High")]
    if not hi:
        return _res("na", detail="No Critical or High findings.")
    from remediation.assignments import store as asg
    owned = {a["finding_id"] for a in asg.load_assignments(c.engine) if a.get("assignee_email") or a.get("assigned_team")}
    n = sum(1 for f in hi if f["id"] in owned)
    pct, th = _pct(n, len(hi)), c.t["ownership_min_pct"]
    return _res("pass" if pct >= th else "fail", pct, th, f"{n} of {len(hi)} Critical and High findings have an owner or team ({pct}%).")


def t_audit(c):
    from remediation.audit.activity_log import list_activity
    recent = [a for a in list_activity(engine=c.engine) if str(a.get("timestamp", ""))[:10] >= (c.today - datetime.timedelta(days=c.t["audit_window_days"])).isoformat()]
    th = c.t["audit_window_days"]
    return _res("pass" if recent else "fail", len(recent), 1, f"{len(recent)} audit-log event(s) in the last {th} days." if recent else f"No audit-log events in the last {th} days.")


def t_privileged(c):
    from auth import users
    admins = [u for u in users.list_users(c.engine) if u.get("role") == "admin"]
    th = c.t["max_admin_accounts"]
    if not admins:
        return _res("na", detail="No administrator accounts found.")
    return _res("pass" if len(admins) <= th else "warn", len(admins), th, f"{len(admins)} administrator account(s) (limit {th}). Review who holds them.")


def t_verification(c):
    from remediation.remediation_approvals import store as appr
    from remediation.verification import closed_loop
    triggered = [a for a in appr.list_approvals_with_status(c.engine) if a.get("status") == "remediation_triggered"]
    if not triggered:
        return _res("na", detail="No remediations have been triggered yet, so there is nothing to verify.")
    s = closed_loop.verify_all(triggered, c.findings)["summary"]
    decided = s["verified"] + s["still-present"]
    if not decided:
        return _res("na", detail=f"{s['awaiting-rescan']} triggered remediation(s) are awaiting a rescan.")
    pct = _pct(s["verified"], decided)
    return _res("pass" if s["still-present"] == 0 else "warn", pct, 100, f"{s['verified']} fix(es) verified by the next scan, {s['still-present']} still present, {s['awaiting-rescan']} awaiting a rescan.")


def t_controls(c):
    from fnmatch import fnmatchcase
    from remediation.controls import store as cs
    counts = {}
    for f in c.findings:
        n = (f.get("asset") or {}).get("name")
        if n:
            counts[n] = counts.get(n, 0) + 1
    top = sorted(counts, key=lambda n: -counts[n])[:200]
    if not top:
        return _res("na", detail="No assets in the findings.")
    patterns = [e["asset_name"].lower() for e in cs.list_controls(engine=c.engine)]
    covered = sum(1 for n in top if any(fnmatchcase(n.lower(), p) for p in patterns))
    pct, th = _pct(covered, len(top)), c.t["controls_min_pct"]
    return _res("pass" if pct >= th else "fail", pct, th, f"{covered} of the {len(top)} most-affected assets have at least one recorded security control ({pct}%).")


def t_risk_register(c):
    from remediation.grc import risks
    live = [r for r in risks.list_risks(c.engine) if r["status"] != "closed"]
    if not live:
        return _res("fail", 0, 1, "The risk register is empty.")
    stale = [r for r in live if r["review_overdue"] or not r["owner"]]
    return _res("pass" if not stale else "warn", len(live), 1, f"{len(live)} open risk(s); {len(stale)} overdue for review or without an owner.")


def t_ai_apps(c):
    from remediation.aiusage import discovery
    apps = discovery.list_apps(c.engine)
    if not apps:
        return _res("na", detail="No AI applications have been discovered; upload a proxy or DNS export on the AI Usage page.")
    open_ = [a for a in apps if a["status"] == "unreviewed"]
    return _res("pass" if not open_ else "fail", len(open_), 0, f"{len(open_)} of {len(apps)} AI application(s) found are still unreviewed.")


def t_ai_usage(c):
    from remediation.aiusage import store
    rows = store.fetch(since=(c.today - datetime.timedelta(days=30)).isoformat() + "T00:00:00Z", engine=c.engine)
    external = [r for r in rows if r["source"] != "quanta"]
    if not external:
        return _res("na", detail="Only Quanta's own AI calls are recorded; connect a provider, gateway or OpenTelemetry source.")
    unattributed = sum(1 for r in external if not r.get("team") and not r.get("application"))
    return _res("pass" if not unattributed else "warn", len(external), 1, f"{len(external)} AI usage record(s) in 30 days; {unattributed} without a team or application.")


def t_ai_budgets(c):
    from remediation.aiusage import analytics
    b = analytics.budget_status(c.engine)
    if not b:
        return _res("fail", 0, 1, "No AI budgets are defined.")
    over = [x for x in b if x["state"] == "exceeded"]
    return _res("pass" if not over else "warn", len(b), 1, f"{len(b)} AI budget(s); {len(over)} exceeded.")


def t_ai_models(c):
    from remediation.aiusage import analytics
    s = analytics.summary(30, c.engine)
    allowed = analytics.policy().get("allowed_models")
    if not allowed:
        return _res("na", detail="No approved-model list is set in ai_usage_policy.yaml.")
    bad = s["outside_allowed_models"] or []
    return _res("pass" if not bad else "fail", len(bad), 0, f"{len(bad)} model(s) in use outside the approved list." if bad else "All models in use are on the approved list.")


TESTS = {
    "patch-sla": ("Critical and High findings inside their SLA", t_patch_sla), "kev-remediation": ("Known-exploited findings past their deadline", t_kev),
    "scan-freshness": ("Scan data is current", t_scan_freshness), "exceptions-hygiene": ("Risk exceptions are justified and expire", t_exceptions),
    "ownership": ("Critical and High findings have an owner", t_ownership), "audit-trail": ("Audit log is active", t_audit),
    "privileged-access": ("Administrator accounts are limited", t_privileged), "fix-verification": ("Remediations are verified by the next scan", t_verification),
    "controls-coverage": ("Assets have recorded security controls", t_controls), "risk-register": ("Risk register is maintained", t_risk_register),
    "ai-apps-reviewed": ("AI applications have been reviewed", t_ai_apps), "ai-usage-recorded": ("AI usage is recorded and attributed", t_ai_usage),
    "ai-budgets": ("AI spend has budgets", t_ai_budgets), "ai-approved-models": ("Only approved AI models are used", t_ai_models),
}


def run_all(ctx, only=None):
    """Runs every test (or `only`) and stores the results. Returns [{test_id, title, result, metric, threshold, detail, collected_at}]."""
    out, stamp, t = [], _now(), db_module.grc_evidence
    for tid, (title, fn) in TESTS.items():
        if only and tid not in only:
            continue
        try:
            r = fn(ctx)
        except Exception as exc:  # noqa: BLE001 - one broken test must not stop the rest
            r = _res("error", detail=f"{type(exc).__name__}: {exc}"[:300])
        out.append({"test_id": tid, "title": title, "collected_at": stamp, **r})
    with ctx.engine.begin() as conn:
        for r in out:
            conn.execute(insert(t), {"test_id": r["test_id"], "result": r["result"], "metric": r["metric"], "threshold": r["threshold"], "detail": r["detail"], "collected_at": stamp})
    return out


def latest(engine=None):
    """The most recent result of each test: {test_id: row}."""
    engine, t = _engine(engine), db_module.grc_evidence
    with engine.connect() as conn:
        rows = conn.execute(select(t).order_by(t.c.id)).mappings().all()
    out = {}
    for r in rows:
        out[r["test_id"]] = dict(r, title=TESTS.get(r["test_id"], (r["test_id"],))[0])
    return out


def history(test_id, limit=30, engine=None):
    engine, t = _engine(engine), db_module.grc_evidence
    with engine.connect() as conn:
        rows = conn.execute(select(t).where(t.c.test_id == test_id).order_by(t.c.id.desc()).limit(limit)).mappings().all()
    return [dict(r) for r in rows]
