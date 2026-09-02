"""
Cadence-based scheduling for VulnHunter's scheduled report subscriptions
(remediation/config/report_schedule_rules.yaml). Pure, testable date-math functions
(is_due/due_subscriptions) plus a thin orchestrator (check_and_send_due_reports) tying
them to the real report generator (dashboard/reports.py) and the real SMTP sender
(email_sender.py).

Runs on an in-process timer inside the dashboard server (see dashboard/app.py's startup
hook) - this only checks/sends while that server process stays alive; a restart resets
the timer but never double-sends for the same period (schedule_state.json, not the
timer, is what prevents that). For guaranteed delivery independent of server uptime,
point a real external cron/Task Scheduler at POST /api/notification-settings/run-checks-now
instead of relying on the in-process timer.

last-sent tracking lives in its own small JSON file (schedule_state.json), deliberately
SEPARATE from report_schedule_rules.yaml - that file is meant to stay a clean,
comment-rich, human-edited config; round-tripping it through a YAML dump on every
scheduler write would silently strip an admin's own comments/formatting.
"""
import datetime
from pathlib import Path

from sqlalchemy import select

from remediation.utils import db as db_module
from remediation.utils.file_lock import FileLock

CADENCE_DAYS = {
    "weekly": 7,
    "monthly": 30,
    "quarterly": 91,
    "half-yearly": 182,
    "yearly": 365,
}

# Same reasoning as alert_checker.py's LOCK_PATH/LOCK_TIMEOUT_SECONDS: the real
# critical section is check_and_send_due_reports() as a whole (it sends real email),
# not just the load/save calls, and a generous timeout since a real send can be slow.
LOCK_PATH = Path(__file__).resolve().parent / ".report_scheduler.lock"
LOCK_TIMEOUT_SECONDS = 60.0


def load_state(engine=None):
    """Returns {subscription_id: last_sent_at_iso} - same external shape the old
    schedule_state.json produced, now read from the schedule_state table."""
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    with engine.connect() as conn:
        rows = conn.execute(select(db_module.schedule_state)).all()
    return {subscription_id: last_sent_at for subscription_id, last_sent_at in rows}


def save_state(state, engine=None):
    """Upserts every (subscription_id, last_sent_at) pair in `state` - a per-row
    delete-then-insert rather than alert_state's blunt delete-everything-then-reinsert,
    so this is safe to call with either the full state dict (today's real call pattern,
    check_and_send_due_reports passes back what load_state returned) or a partial one -
    unlike a bulk replace, it never drops a subscription's record just because that
    subscription wasn't included in this particular call."""
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    with engine.begin() as conn:
        for subscription_id, last_sent_at in state.items():
            conn.execute(db_module.schedule_state.delete().where(
                db_module.schedule_state.c.subscription_id == subscription_id))
            conn.execute(db_module.schedule_state.insert().values(
                subscription_id=subscription_id, last_sent_at=last_sent_at))


def is_due(subscription, last_sent_at, now=None):
    """A subscription that's never sent (last_sent_at is None) is due immediately.
    Otherwise due once at least CADENCE_DAYS[cadence] real days have elapsed since
    last_sent_at - a simple, honest rolling-window check, not a calendar-aware one
    (e.g. "every 1st of the month"), since this pipeline has no calendar-scheduling
    primitive to build that from without a new dependency."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    cadence = subscription.get("cadence")
    if cadence not in CADENCE_DAYS:
        return False
    if not last_sent_at:
        return True
    last = datetime.datetime.fromisoformat(last_sent_at)
    if last.tzinfo is None:
        last = last.replace(tzinfo=datetime.timezone.utc)
    return (now - last).days >= CADENCE_DAYS[cadence]


def due_subscriptions(rules, state, now=None):
    return [
        s for s in rules.get("subscriptions", [])
        if s.get("enabled") and is_due(s, state.get(s.get("id")), now)
    ]


def check_and_send_due_reports(dashboard_data, reports_module, email_sender, now=None,
                                engine=None, lock_path=None, lock_timeout=None):
    """Real orchestrator: finds due, enabled subscriptions, builds each real scoped
    report, and sends via email_sender if SMTP is configured. If SMTP isn't configured,
    the subscription is honestly reported as skipped (not silently dropped, not
    fabricated as sent) and its state is left untouched so it's retried on the next
    check. A single subscription's send failure is caught and reported per-subscription
    rather than aborting the whole batch.

    Holds a real lock across this ENTIRE function, same reasoning as
    alert_checker.check_and_send_alerts(): the in-process scheduler timer and the "run
    checks now" button can call this concurrently, and the whole
    read-decide-send-persist sequence has to be exclusive, not just the final write."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    with FileLock(lock_path or LOCK_PATH, timeout=lock_timeout or LOCK_TIMEOUT_SECONDS):
        rules = dashboard_data.load_report_schedule_rules()
        state = load_state(engine)
        due = due_subscriptions(rules, state, now)
        results = []
        if not due:
            return results

        smtp_ready = email_sender.is_configured()
        for sub in due:
            if not smtp_ready:
                results.append({"id": sub["id"], "status": "skipped", "reason": "SMTP not configured"})
                continue
            try:
                report = reports_module.generate_report_data(
                    sub["cadence"], dashboard_data, scope=sub.get("scope", "all"), team=sub.get("team"),
                )
                email_sender.send_email(
                    sub["recipients"],
                    reports_module.report_title(report),
                    reports_module.render_report_text(report),
                    reports_module.render_report_html(report),
                )
                state[sub["id"]] = now.isoformat(timespec="seconds")
                results.append({"id": sub["id"], "status": "sent", "recipients": sub["recipients"]})
            except Exception as exc:  # noqa: BLE001 - one bad subscription must not block the rest
                results.append({"id": sub["id"], "status": "error", "reason": str(exc)})

        save_state(state, engine)
        return results
