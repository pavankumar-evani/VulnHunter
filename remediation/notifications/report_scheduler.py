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
import json
from pathlib import Path

CADENCE_DAYS = {
    "weekly": 7,
    "monthly": 30,
    "quarterly": 91,
    "half-yearly": 182,
    "yearly": 365,
}

STATE_PATH = Path(__file__).resolve().parent / "schedule_state.json"


def load_state(path=None):
    path = path or STATE_PATH
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(state, path=None):
    path = path or STATE_PATH
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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


def check_and_send_due_reports(dashboard_data, reports_module, email_sender, now=None, state_path=None):
    """Real orchestrator: finds due, enabled subscriptions, builds each real scoped
    report, and sends via email_sender if SMTP is configured. If SMTP isn't configured,
    the subscription is honestly reported as skipped (not silently dropped, not
    fabricated as sent) and its state is left untouched so it's retried on the next
    check. A single subscription's send failure is caught and reported per-subscription
    rather than aborting the whole batch."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    rules = dashboard_data.load_report_schedule_rules()
    state = load_state(state_path)
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

    save_state(state, state_path)
    return results
