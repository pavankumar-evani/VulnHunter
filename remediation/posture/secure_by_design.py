"""Secure by Design: a self-assessment of THIS Quanta deployment against CISA's Secure by Design principles (take ownership of customer security
outcomes, radical transparency and accountability, lead from the top) plus the concrete hardening the product offers.

The `hardening` checks read this deployment's own settings (ctx.env) and are always observable. Everything else reads what Quanta has recorded and is
`unknown` when nothing is recorded. No secret value is ever put in evidence: only presence and length.
"""
import datetime
from pathlib import Path

import yaml

from remediation.posture.model import check

FRAMEWORK = {
    "id": "secure-by-design",
    "title": "Secure by Design (this deployment)",
    "summary": "How well this Quanta deployment follows CISA's Secure by Design principles and uses the hardening the product offers.",
    "areas": [("ownership", "Ownership of security outcomes"), ("transparency", "Transparency and accountability"),
              ("leadership", "Leadership"), ("hardening", "Hardening of this deployment")],
    "refs": [{"label": "CISA Secure by Design", "url": "https://www.cisa.gov/resources-tools/resources/secure-by-design"}],
}
FW = FRAMEWORK["id"]
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
REPORT_SCHEDULE_PATH = REPO_ROOT / "remediation" / "config" / "report_schedule_rules.yaml"
DEMO_ACCOUNTS = ("admin@quanta.local", "analyst@quanta.local")
DEMO_PASSWORD = "ChangeMe123!"   # published in dashboard/README.md; used only to test whether it still works
REF = FRAMEWORK["refs"]
MIN_SECRET_LENGTH = 32


def _c(id, area, title, status, **kw):
    kw.setdefault("refs", REF)
    return check(f"sbd-{id}", FW, area, title, status, **kw)


def _share(ctx, share):
    """pass / partial / fail for a share in place, using the shared coverage thresholds. Returns (status, score)."""
    if share >= ctx.thr.get("coverage_good", 0.9):
        return "pass", None
    if share >= ctx.thr.get("coverage_partial", 0.5):
        return "partial", share
    return "fail", None


def _env_change(key, value, effect, where):
    return {"kind": "env", "where": where, "key": key, "value": value, "effect": effect}


def _secret_len(ctx, name):
    """(length, source) of a secret given directly or as NAME_FILE. Never returns the value."""
    v = (ctx.env.get(name) or "").strip()
    if v:
        return len(v), "environment"
    path = (ctx.env.get(name + "_FILE") or "").strip()
    if path:
        try:
            return len(Path(path).read_text(encoding="utf-8").strip()), "file"
        except OSError:
            return 0, "unreadable file"
    return None, None


def _file_check(rel):
    p = REPO_ROOT / rel
    try:
        return p.stat().st_size if p.is_file() else None
    except OSError:
        return None


def _users(ctx):
    def load():
        try:
            from auth import users
        except ImportError:
            from dashboard.auth import users
        return users, users.load_users(ctx.engine)
    return ctx.get("sbd-users", load)


def _date(value):
    try:
        return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


# ------------------------------------------------------------------------------------------------------------------------ ownership
def _own_policy(ctx):
    size = _file_check("SECURITY.md")
    if size:
        return _c("own-security-policy", "ownership", "A way to report security issues is published", "pass", weight=3,
                  evidence=[f"SECURITY.md is present ({size} bytes)"], detail="A published reporting route is the first step of owning customers' security outcomes.",
                  data_used=["SECURITY.md"])
    return _c("own-security-policy", "ownership", "A way to report security issues is published", "fail", weight=3,
              evidence=["SECURITY.md was not found (0 bytes) at the repository root"], detail="Without it, researchers and customers have no stated route to report a flaw.",
              recommendation="Add a SECURITY.md with a contact, what to include and how long a reply takes.",
              change={"kind": "process", "where": "SECURITY.md", "key": "SECURITY.md", "value": "contact + disclosure process", "effect": "Gives reporters a stated route."},
              data_used=["SECURITY.md"])


def _own_support(ctx):
    def load():
        from remediation.support import analytics, store
        tickets = store.list_tickets(limit=500, engine=ctx.engine)
        return len(tickets), analytics.compute(tickets, as_of=ctx.now) if tickets else None
    r = ctx.get("sbd-support", load)
    kw = dict(weight=3, data_used=["support tickets"], detail="Customers' reports are only owned if they are answered inside a stated time.",
              change={"kind": "page", "where": "/support", "key": None, "value": None, "effect": "Triage tickets and keep the SLA clocks green."})
    if not r or not r[0] or r[1]["sla_compliance_pct"] is None:
        n = r[0] if r else 0
        return _c("own-support-sla", "ownership", "Support tickets are answered within their SLA", "unknown",
                  evidence=[f"{n} support tickets with a finished SLA clock recorded"], recommendation="Use the Support desk so response and resolution times can be measured.", **kw)
    pct, t = r[1]["sla_compliance_pct"], r[1]["totals"]
    ev = [f"{pct}% of finished SLA clocks were met across {r[0]} tickets", f"{t['breached_open']} open tickets have breached an SLA"]
    status, score = _share(ctx, pct / 100)
    return _c("own-support-sla", "ownership", "Support tickets are answered within their SLA", status, score=score, evidence=ev,
              recommendation="" if status == "pass" else "Work the breached tickets and review the routing and targets.", **kw)


def _own_exceptions(ctx):
    def load():
        from remediation.exceptions import store
        return store.list_exceptions_with_status(engine=ctx.engine, as_of=ctx.now.date())
    rows = ctx.get("sbd-exceptions", load)
    kw = dict(weight=2, data_used=["risk exceptions"], detail="An exception is only owned while someone approved it and it still has an end date in the future.",
              change={"kind": "page", "where": "/exceptions", "key": None, "value": None, "effect": "Revoke or renew expired exceptions."})
    live = [e for e in (rows or []) if e["computed_status"] in ("active", "expired")]
    if not live:
        return _c("own-exceptions", "ownership", "Risk exceptions have owners and have not lapsed", "unknown",
                  evidence=[f"{len(rows or [])} exceptions recorded, 0 not revoked"], recommendation="Record waivers as exceptions with a requester, an approver and an expiry.", **kw)
    owned = [e for e in live if e.get("requested_by") and e.get("approved_by")]
    expired = [e for e in live if e["computed_status"] == "expired"]
    share = (len(owned) - len([e for e in owned if e in expired])) / len(live)
    ev = [f"{len(owned)} of {len(live)} exceptions name a requester and an approver", f"{len(expired)} exceptions have expired and were not revoked"]
    status, score = _share(ctx, share)
    return _c("own-exceptions", "ownership", "Risk exceptions have owners and have not lapsed", status, score=score, evidence=ev,
              recommendation="" if status == "pass" else "Revoke or renew the expired exceptions.", **kw)


# ------------------------------------------------------------------------------------------------------------------------ transparency
def _trans_docs(ctx):
    want = ["PRODUCTION_GUIDE.md", "SCALING_LIMITS.md", "INTEGRATION_API.md", "SUPPORT.md"]
    have = [d for d in want if _file_check(f"docs/{d}")]
    ev = [f"{len(have)} of {len(want)} limits and operations documents present in docs/"]
    status, score = _share(ctx, len(have) / len(want))
    return _c("trans-honest-docs", "transparency", "Limits and operating guidance are documented", status, score=score, weight=2, evidence=ev,
              detail="Radical transparency means saying what the product cannot do and how to run it safely.", data_used=["docs/"],
              recommendation="" if status == "pass" else "Restore the missing documents: " + ", ".join(sorted(set(want) - set(have))),
              change=None if status == "pass" else {"kind": "process", "where": "docs/", "key": "docs/", "value": "limits + operations guides", "effect": "Publishes honest limits."})


def _trans_changelog(ctx):
    p = REPO_ROOT / "CHANGELOG.md"
    try:
        n = sum(1 for line in p.read_text(encoding="utf-8").splitlines() if line.startswith("## ")) if p.is_file() else 0
    except OSError:
        n = 0
    if n:
        return _c("trans-release-notes", "transparency", "Release notes are published", "pass", weight=2, evidence=[f"CHANGELOG.md has {n} release sections"],
                  detail="Customers can only judge a change if it is described.", data_used=["CHANGELOG.md"])
    return _c("trans-release-notes", "transparency", "Release notes are published", "fail", weight=2, evidence=["CHANGELOG.md has 0 release sections or is missing"],
              recommendation="Keep a CHANGELOG.md with one section per release.", data_used=["CHANGELOG.md"],
              change={"kind": "process", "where": "CHANGELOG.md", "key": "CHANGELOG.md", "value": "one section per release", "effect": "Records what changed."})


def _trans_sbom(ctx):
    return _c("trans-own-sbom", "transparency", "An SBOM of Quanta itself is published", "unknown", weight=2,
              evidence=["0 SBOMs of Quanta itself are recorded here"], detail="Quanta cannot see how it was built from inside the running deployment.",
              recommendation="Generate a CycloneDX SBOM of this release in CI and upload it (Applications page) so it can be checked.",
              change={"kind": "page", "where": "/applications", "key": None, "value": None, "effect": "Stores an SBOM for the Quanta application."}, data_used=["application SBOMs"])


def _trans_deps(ctx):
    return _c("trans-own-dependencies", "transparency", "Vulnerabilities in Quanta's own dependencies are tracked", "unknown", weight=2,
              evidence=["0 findings about Quanta's own dependencies are observable here"], detail="Not observable from inside the deployment.",
              recommendation="Scan Quanta's own requirements in CI and ingest the result as findings.", data_used=["findings"],
              change={"kind": "process", "where": "ci", "key": "dependency scan", "value": "SARIF or SBOM upload", "effect": "Makes the dependency risk visible."})


# ------------------------------------------------------------------------------------------------------------------------ leadership
def _lead_risks(ctx):
    def load():
        from remediation.grc import risks
        return risks.list_risks(ctx.engine, include_closed=False)
    rows = ctx.get("sbd-risks", load)
    kw = dict(weight=3, data_used=["risk register"], detail="Leaders own risk when each open risk has a named owner and a review that is not overdue.",
              change={"kind": "page", "where": "/grc", "key": None, "value": None, "effect": "Assign owners and review dates in the risk register."})
    if not rows:
        return _c("lead-risk-register", "leadership", "The risk register is owned and reviewed", "unknown",
                  evidence=[f"{len(rows or [])} open risks recorded"], recommendation="Record the organisation's risks with an owner and a review date.", **kw)
    today = ctx.now.date().isoformat()
    good = [r for r in rows if r.get("owner") and not (r.get("review_date") and r["review_date"] < today)]
    ev = [f"{len(good)} of {len(rows)} open risks have an owner and a current review"]
    status, score = _share(ctx, len(good) / len(rows))
    return _c("lead-risk-register", "leadership", "The risk register is owned and reviewed", status, score=score, evidence=ev,
              recommendation="" if status == "pass" else "Give every open risk an owner and review the overdue ones.", **kw)


def _lead_policies(ctx):
    def load():
        from remediation.grc import policies
        us = _users(ctx)
        users = [{"email": e} for e in us[1]] if us else []
        return [p for p in policies.list_policies(ctx.engine, users) if p["status"] == "active"], len(users)
    r = ctx.get("sbd-policies", load)
    kw = dict(weight=2, data_used=["policies", "user accounts"], detail="A policy leaders issue only counts when the people it covers have acknowledged it.",
              change={"kind": "page", "where": "/grc", "key": None, "value": None, "effect": "Ask people to acknowledge the active policies."})
    if not r or not r[0] or not r[1]:
        return _c("lead-policy-acks", "leadership", "Active policies are acknowledged", "unknown",
                  evidence=[f"{len(r[0]) if r else 0} active policies and {r[1] if r else 0} user accounts recorded"], recommendation="Publish a policy and have people acknowledge it.", **kw)
    pcts = [p["ack_pct"] or 0 for p in r[0]]
    avg = sum(pcts) / len(pcts)
    ev = [f"{len(r[0])} active policies, average {round(avg)}% acknowledged by {r[1]} accounts"]
    status, score = _share(ctx, avg / 100)
    return _c("lead-policy-acks", "leadership", "Active policies are acknowledged", status, score=score, evidence=ev,
              recommendation="" if status == "pass" else "Chase the people who have not acknowledged the current version.", **kw)


def _lead_reports(ctx):
    def load():
        data = yaml.safe_load(Path(REPORT_SCHEDULE_PATH).read_text(encoding="utf-8")) or {}
        return data.get("subscriptions") or []
    subs = ctx.get("sbd-report-schedule", load)
    kw = dict(weight=2, data_used=["report_schedule_rules.yaml"], detail="Scheduled reports put the numbers in front of leaders without anyone asking.",
              change={"kind": "yaml", "where": "remediation/config/report_schedule_rules.yaml", "key": "subscriptions", "value": "one enabled entry per team",
                      "effect": "Sends a periodic report to the recipients."})
    if subs is None:
        return _c("lead-exec-reports", "leadership", "Reports are scheduled to leaders", "unknown", evidence=["the report schedule could not be read"],
                  recommendation="Fix the report schedule file.", **kw)
    on = [s for s in subs if s.get("enabled") and s.get("recipients")]
    if on:
        return _c("lead-exec-reports", "leadership", "Reports are scheduled to leaders", "pass", evidence=[f"{len(on)} of {len(subs)} report subscriptions are enabled"], **kw)
    return _c("lead-exec-reports", "leadership", "Reports are scheduled to leaders", "fail", evidence=[f"{len(on)} of {len(subs)} report subscriptions are enabled"],
              recommendation="Add an enabled subscription for the leaders of each team.", **kw)


# ------------------------------------------------------------------------------------------------------------------------ hardening
def _h(id, title, status, weight, evidence, rec="", change=None, score=None, detail="", data_used=("environment",)):
    return _c(f"hard-{id}", "hardening", title, status, weight=weight, evidence=evidence, recommendation=rec, change=change, score=score,
              detail=detail, data_used=list(data_used))


def _hard_production(ctx):
    on = ctx.flag("QUANTA_PRODUCTION")
    return _h("production", "Production mode is on", "pass" if on else "fail", 5, [f"QUANTA_PRODUCTION is {'on' if on else 'off or not set'}"],
              "" if on else "Set QUANTA_PRODUCTION=true: it requires a session secret, refuses demo passwords and closes anonymous reads.",
              _env_change("QUANTA_PRODUCTION", "true", "Applies the safe defaults and refuses unsafe start-ups.", "dashboard/app.py"),
              detail="Production mode makes the safe choice the default.")


def _hard_session(ctx):
    n, src = _secret_len(ctx, "QUANTA_SESSION_SECRET")
    ch = _env_change("QUANTA_SESSION_SECRET", "a random value of at least 32 characters", "Sessions survive restarts and cookies cannot be forged.", "dashboard/auth/rbac.py")
    if n is None:
        return _h("session-secret", "A strong session secret is set", "fail", 5, ["QUANTA_SESSION_SECRET is not set (0 characters)"], "Set a stable random secret.", ch)
    ok = n >= MIN_SECRET_LENGTH
    return _h("session-secret", "A strong session secret is set", "pass" if ok else "fail", 5, [f"session secret from {src} is {n} characters (minimum {MIN_SECRET_LENGTH})"],
              "" if ok else "Use at least 32 random characters.", ch)


def _hard_encryption(ctx):
    n, src = _secret_len(ctx, "QUANTA_ENCRYPTION_KEY")
    ch = _env_change("QUANTA_ENCRYPTION_KEY", "a key from `quanta_admin gen-key`", "Connector credentials are encrypted at rest.", "dashboard/app.py")
    if n:
        return _h("encryption-key", "The credential encryption key is set", "pass", 5, [f"encryption key from {src} is set ({n} characters)"], change=ch)
    return _h("encryption-key", "The credential encryption key is set", "fail", 5, ["QUANTA_ENCRYPTION_KEY is not set (0 characters)"], "Generate a key and keep it outside the database.", ch)


def _hard_tls(ctx):
    off = ctx.flag("QUANTA_DISABLE_TLS")
    return _h("tls", "TLS is not disabled", "fail" if off else "pass", 4, [f"QUANTA_DISABLE_TLS is {'true' if off else 'not set'}"],
              "Only disable TLS behind a proxy that terminates it." if off else "",
              _env_change("QUANTA_DISABLE_TLS", "false", "Serves HTTPS.", "dashboard/app.py"))


def _csp_on(ctx):
    raw = (ctx.env.get("QUANTA_ENABLE_CSP") or "").strip().lower()
    if raw in ("0", "false", "no"):
        return False
    if raw in ("1", "true", "yes"):
        return True
    return ctx.flag("QUANTA_PRODUCTION")


def _hard_csp(ctx):
    on = _csp_on(ctx)
    return _h("csp", "Content-Security-Policy is on", "pass" if on else "fail", 3, [f"Content-Security-Policy is {'on' if on else 'off'}"],
              "" if on else "Set QUANTA_ENABLE_CSP=true.", _env_change("QUANTA_ENABLE_CSP", "true", "Adds a same-origin Content-Security-Policy header.", "dashboard/app.py"))


def _hard_reads(ctx):
    closed = ctx.flag("QUANTA_REQUIRE_LOGIN_FOR_READS") or (ctx.flag("QUANTA_PRODUCTION") and not ctx.flag("QUANTA_ALLOW_PUBLIC_READS"))
    return _h("login-for-reads", "Anonymous reads are closed", "pass" if closed else "fail", 5,
              [f"anonymous reads are {'closed' if closed else 'open'} (QUANTA_ALLOW_PUBLIC_READS is {'set' if ctx.flag('QUANTA_ALLOW_PUBLIC_READS') else 'not set'})"],
              "" if closed else "Require login for reads.", _env_change("QUANTA_REQUIRE_LOGIN_FOR_READS", "true", "Every /api read needs a session.", "dashboard/app.py"))


def _hard_demo(ctx):
    us = _users(ctx)
    ch = {"kind": "process", "where": "cli/quanta_admin.py", "key": "reset-password", "value": "delete or reset the demo accounts", "effect": "Removes the published password."}
    if not us or not us[1]:
        return _h("demo-accounts", "Demo accounts do not use the published password", "unknown", 5, ["0 user accounts recorded"], "Create an administrator.", data_used=["user accounts"])

    def load():
        return [e for e in DEMO_ACCOUNTS if e in us[1] and us[0].verify_login(e, DEMO_PASSWORD, engine=ctx.engine)]
    bad = ctx.get("sbd-demo", load)
    if bad is None:
        return _h("demo-accounts", "Demo accounts do not use the published password", "unknown", 5, ["the accounts could not be tested"], data_used=["user accounts"])
    if bad:
        return _h("demo-accounts", "Demo accounts do not use the published password", "fail", 5, [f"{len(bad)} of {len(DEMO_ACCOUNTS)} demo accounts still accept the published password"],
                  "Delete the demo accounts or reset their passwords.", ch, data_used=["user accounts"])
    return _h("demo-accounts", "Demo accounts do not use the published password", "pass", 5, [f"0 of {len(DEMO_ACCOUNTS)} demo accounts accept the published password"], data_used=["user accounts"])


def _hard_api_keys(ctx):
    rows = ctx.get("sbd-keys", lambda: __import__("remediation.apikeys.store", fromlist=["x"]).list_keys(ctx.engine))
    ch = {"kind": "page", "where": "/connections", "key": None, "value": None, "effect": "Revoke old keys and issue new ones with an expiry."}
    if not rows:
        return _h("api-keys", "API keys expire and are used", "unknown", 3, ["0 API keys recorded"], data_used=["API keys"])
    now = ctx.now
    active = [k for k in rows if not k["revoked_at"] and not (k["expires_at"] and _aware(_date(k["expires_at"])) <= now)]
    if not active:
        return _h("api-keys", "API keys expire and are used", "na", 3, [f"0 of {len(rows)} API keys are active"], data_used=["API keys"])
    stale = ctx.thr.get("stale_days", 90)

    def idle(k):
        last = _aware(_date(k["last_used_at"] or k["created_at"]))
        return last is not None and (now - last).days > stale
    good = [k for k in active if k["expires_at"] and not idle(k)]
    ev = [f"{len(good)} of {len(active)} active API keys have an expiry and were used in the last {stale} days",
          f"{sum(1 for k in active if not k['expires_at'])} active keys never expire"]
    status, score = _share(ctx, len(good) / len(active))
    return _h("api-keys", "API keys expire and are used", status, 3, ev, "" if status == "pass" else "Revoke idle keys and issue new ones with an expiry.", ch, score, data_used=["API keys"])


def _hard_licence(ctx):
    mode = (ctx.env.get("QUANTA_LICENSE_MODE") or "").strip().lower()
    ch = _env_change("QUANTA_LICENSE_MODE", "warn", "Reads and reports the licence.", "remediation/licensing/license.py")
    if mode in ("warn", "enforce"):
        return _h("licence-mode", "Licence checking is active", "pass", 1, [f"QUANTA_LICENSE_MODE is {mode}"], change=ch)
    return _h("licence-mode", "Licence checking is active", "partial", 1, ["QUANTA_LICENSE_MODE is off or not set: module licences are not checked"],
              "Use warn or enforce if modules are licensed.", ch, 0.5)


def _hard_rate(ctx):
    problems = []
    for name, default in (("QUANTA_RATE_LIMIT_MAX", 300), ("QUANTA_INGEST_RATE_LIMIT_MAX", 20)):
        raw = (ctx.env.get(name) or "").strip()
        try:
            v = int(raw) if raw else default
        except ValueError:
            v = -1
        if v <= 0 or v >= 100000:
            problems.append(f"{name}={v}")
    ch = _env_change("QUANTA_RATE_LIMIT_MAX", "300", "Caps requests per window.", "dashboard/app.py")
    if problems:
        return _h("rate-limits", "Rate limits are not disabled", "fail", 3, [f"{len(problems)} rate limits are effectively off: " + ", ".join(problems)], "Restore the defaults.", ch)
    return _h("rate-limits", "Rate limits are not disabled", "pass", 3, ["2 of 2 rate limits are in effect"], change=ch)


def _hard_gitops(ctx):
    off = (ctx.env.get("QUANTA_GITOPS_SYNC") or "true").strip().lower() in ("0", "false", "no")
    return _h("gitops-sync", "Fix pull requests are followed automatically", "fail" if off else "pass", 1, [f"QUANTA_GITOPS_SYNC is {'off' if off else 'on'}"],
              "Turn it back on." if off else "", _env_change("QUANTA_GITOPS_SYNC", "true", "Hourly sync of open fix pull requests.", "dashboard/app.py"))


def _hard_oidc(ctx):
    names = ("OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_REDIRECT_URI")
    n = sum(1 for v in names if (ctx.env.get(v) or "").strip())
    ch = _env_change("OIDC_ISSUER", "https://idp.corp.test", "Enables single sign-on.", "dashboard/auth/oidc.py")
    ev = [f"{n} of {len(names)} OIDC settings are set"]
    if n == len(names):
        return _h("oidc", "Single sign-on is configured", "pass", 2, ev, change=ch)
    if n:
        return _h("oidc", "Single sign-on is configured", "partial", 2, ev, "Set the remaining OIDC settings.", ch, n / len(names))
    return _h("oidc", "Single sign-on is configured", "fail", 2, ev, "Configure an identity provider instead of local passwords.", ch)


def _hard_admins(ctx):
    us = _users(ctx)
    ch = {"kind": "page", "where": "/admin/people", "key": None, "value": None, "effect": "Adjust who is an administrator."}
    if not us or not us[1]:
        return _h("admin-count", "The number of administrators is sensible", "unknown", 3, ["0 user accounts recorded"], data_used=["user accounts"])
    n = sum(1 for u in us[1].values() if u.get("role") == "admin")
    mx = ctx.thr.get("max_admins", 5)
    ev = [f"{n} administrators of {len(us[1])} accounts (sensible range 2 to {mx})"]
    if 2 <= n <= mx:
        return _h("admin-count", "The number of administrators is sensible", "pass", 3, ev, change=ch, data_used=["user accounts"])
    if n == 0:
        return _h("admin-count", "The number of administrators is sensible", "fail", 3, ev, "Create an administrator.", ch, data_used=["user accounts"])
    return _h("admin-count", "The number of administrators is sensible", "partial", 3, ev,
              "Add a second administrator." if n == 1 else "Reduce the number of administrators.", ch, 0.5 if n == 1 else mx / n, data_used=["user accounts"])


def _hard_audit(ctx):
    def load():
        from remediation.audit import activity_log
        return activity_log.list_activity(ctx.engine, limit=500)
    rows = ctx.get("sbd-audit", load)
    if not rows:
        return _h("audit-activity", "Recent activity is audited", "unknown", 3, ["0 audit entries recorded"], data_used=["activity log"])
    stale = ctx.thr.get("stale_days", 90)
    recent = [r for r in rows if _aware(_date(r["timestamp"])) and (ctx.now - _aware(_date(r["timestamp"]))).days <= stale]
    ev = [f"{len(recent)} of {len(rows)} audit entries fall in the last {stale} days"]
    if recent:
        return _h("audit-activity", "Recent activity is audited", "pass", 3, ev, data_used=["activity log"])
    return _h("audit-activity", "Recent activity is audited", "fail", 3, ev, "Check that audit logging is working.", data_used=["activity log"])


def _hard_database(ctx):
    url = (ctx.env.get("QUANTA_DATABASE_URL") or "").strip()
    scheme = url.split(":", 1)[0].split("+")[0] if url else "sqlite"
    ch = _env_change("QUANTA_DATABASE_URL", "postgresql+psycopg2://...", "Runs on PostgreSQL.", "remediation/utils/db.py")
    if scheme.startswith("postgres"):
        return _h("database", "A server database backs this deployment", "pass", 2, [f"database backend is {scheme}"], change=ch)
    return _h("database", "A server database backs this deployment", "partial", 2, [f"database backend is {scheme} (single host)"],
              "Use PostgreSQL for anything beyond a single host.", ch, 0.5)


def _hard_webhook(ctx):
    def load():
        from sqlalchemy import func, select
        from remediation.utils import db as db_module
        engine = ctx.engine or db_module.get_engine()
        db_module.ensure_schema(engine)
        with engine.connect() as conn:
            return conn.execute(select(func.count()).select_from(db_module.fix_proposals)).scalar() or 0
    n = ctx.get("sbd-proposals", load)
    ch = _env_change("QUANTA_GIT_WEBHOOK_SECRET", "a random value", "Accepts signed Git webhooks.", "dashboard/appsec_api.py")
    if n is None:
        return _h("webhook-secret", "Webhook secrets are set where receivers are used", "unknown", 2, ["fix pull requests could not be read"], data_used=["fix proposals"])
    if not n:
        return _h("webhook-secret", "Webhook secrets are set where receivers are used", "na", 2, ["0 fix pull requests recorded: the webhook is not in use"], data_used=["fix proposals"])
    ln, _ = _secret_len(ctx, "QUANTA_GIT_WEBHOOK_SECRET")
    if ln:
        return _h("webhook-secret", "Webhook secrets are set where receivers are used", "pass", 2, [f"{n} fix pull requests recorded; webhook secret is set ({ln} characters)"], change=ch, data_used=["fix proposals"])
    return _h("webhook-secret", "Webhook secrets are set where receivers are used", "fail", 2, [f"{n} fix pull requests recorded but no webhook secret is set (0 characters)"],
              "Set a secret so the Git host can push status.", ch, data_used=["fix proposals"])


def _hard_admin_password(ctx):
    present = bool((ctx.env.get("QUANTA_ADMIN_PASSWORD") or "").strip())
    return _h("admin-password-env", "The bootstrap admin password is not left in the environment", "fail" if present else "pass", 3,
              [f"QUANTA_ADMIN_PASSWORD is {'present' if present else 'not present'} in the environment"],
              "Remove it after the first start." if present else "",
              {"kind": "env", "where": "cli/quanta_admin.py", "key": "QUANTA_ADMIN_PASSWORD", "value": "(unset)", "effect": "Removes the bootstrap password from the environment."})


def run(ctx):
    return [
        _own_policy(ctx), _own_support(ctx), _own_exceptions(ctx),
        _trans_docs(ctx), _trans_changelog(ctx), _trans_sbom(ctx), _trans_deps(ctx),
        _lead_risks(ctx), _lead_policies(ctx), _lead_reports(ctx),
        _hard_production(ctx), _hard_session(ctx), _hard_encryption(ctx), _hard_tls(ctx), _hard_csp(ctx), _hard_reads(ctx), _hard_demo(ctx),
        _hard_api_keys(ctx), _hard_licence(ctx), _hard_rate(ctx), _hard_gitops(ctx), _hard_oidc(ctx), _hard_admins(ctx), _hard_audit(ctx),
        _hard_database(ctx), _hard_webhook(ctx), _hard_admin_password(ctx),
    ]
