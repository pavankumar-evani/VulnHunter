"""
Team alert checking for VulnHunter's dashboard (remediation/config/alert_rules.yaml) -
critical-severity, zero-day-style, and threat-intel (MITRE ATT&CK threat-actor-group
correlated) findings, emailed to a subscribed team once per finding per subscription
(tracked in alert_state.json), not once per poll.

Same in-process-timer caveat as report_scheduler.py: this only runs while the dashboard
server stays alive. POST /api/notification-settings/run-checks-now is the real,
cron-callable alternative for guaranteed-uptime delivery.
"""
import html
from pathlib import Path

from sqlalchemy import delete, insert, select

from remediation.enrichment import threat_actor_groups
from remediation.inventory import asset_inventory
from remediation.utils import db as db_module
from remediation.utils.file_lock import FileLock

# check_and_send_alerts() is the real critical section - not load_state()/save_state()
# individually - since it reads state, decides what's new, sends real email (slow I/O),
# then persists. A generous timeout (not FileLock's tiny 5s default) because a real
# batch of emails can legitimately take longer than that to send.
LOCK_PATH = Path(__file__).resolve().parent / ".alert_checker.lock"
LOCK_TIMEOUT_SECONDS = 60.0


def load_state(engine=None):
    """Returns {subscription_id: [finding_id, ...]} - same external shape the old
    alert_state.json produced, now read from the alert_state table."""
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    state = {}
    with engine.connect() as conn:
        for subscription_id, finding_id in conn.execute(select(db_module.alert_state)):
            state.setdefault(subscription_id, []).append(finding_id)
    return state


def save_state(state, engine=None):
    """Replaces the entire table's contents with `state` - same "rewrite everything"
    semantics the old JSON file had, now atomic (a single DB transaction) instead of a
    non-atomic full-file rewrite."""
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    rows = [
        {"subscription_id": sub_id, "finding_id": fid}
        for sub_id, fids in state.items() for fid in fids
    ]
    with engine.begin() as conn:
        conn.execute(delete(db_module.alert_state))
        if rows:
            conn.execute(insert(db_module.alert_state), rows)


def _is_critical(f):
    return f.get("severity") == "Critical"


def _is_zero_day(f):
    """Same definition already used on the /threat-intel dashboard - CISA KEV-listed
    (confirmed actively exploited) AND matching at least one configured Exploit Criteria
    rule (remediation/config/exploit_criteria_rules.yaml) - not a separate definition
    invented here."""
    return bool(f.get("kev") and f["kev"].get("listed")) and bool(f.get("exploit_criteria_matches"))


def _is_threat_intel_match(f):
    """A finding whose tagged MITRE ATT&CK technique(s) correlate to at least one real,
    MITRE-documented threat-actor group (remediation/enrichment/threat_actor_groups.py) -
    the same correlation /threat-intel already shows per group, checked here per
    finding."""
    for t in f.get("attack_techniques") or []:
        tid = t.get("technique_id")
        if tid and threat_actor_groups.groups_for_technique(tid):
            return True
    return False


ALERT_TYPES = ("critical", "zero_day", "threat_intel")
_MATCHERS = {"critical": _is_critical, "zero_day": _is_zero_day, "threat_intel": _is_threat_intel_match}


def matching_findings(subscription, findings, ownership):
    matcher = _MATCHERS.get(subscription.get("alert_type"))
    if not matcher:
        return []
    scope = subscription.get("scope", "all")
    team = subscription.get("team")
    result = []
    for f in findings:
        if scope != "all" and f.get("scan_type") != scope:
            continue
        if team and (ownership.get((f.get("asset") or {}).get("name")) or {}).get("team") != team:
            continue
        if matcher(f):
            result.append(f)
    return result


def new_matching_findings(subscription, findings, ownership, state):
    """Only findings not already recorded as alerted-on for this subscription."""
    already = set(state.get(subscription.get("id"), []))
    matched = matching_findings(subscription, findings, ownership)
    return [f for f in matched if f.get("id") not in already]


_ALERT_LABELS = {
    "critical": "Critical Vulnerability Alert",
    "zero_day": "Zero-Day Alert",
    "threat_intel": "Threat Intel Alert",
}


def build_subject(subscription):
    label = _ALERT_LABELS.get(subscription.get("alert_type"), "Alert")
    bits = [f"VulnHunter {label}"]
    if subscription.get("scope", "all") != "all":
        bits.append(subscription["scope"])
    if subscription.get("team"):
        bits.append(subscription["team"])
    return " - ".join(bits)


def build_alert_body_text(subscription, findings):
    lines = [build_subject(subscription), "", f"{len(findings)} new finding(s) matched this alert:"]
    for f in findings:
        asset = (f.get("asset") or {}).get("name", "?")
        lines.append(f"  - {f.get('id')}: {f.get('title')} ({asset}) - CVE {f.get('cve') or 'N/A'}")
    return "\n".join(lines)


def build_alert_body_html(subscription, findings):
    rows = "".join(
        f"<tr><td>{html.escape(f.get('id') or '')}</td><td>{html.escape(f.get('title') or '')}</td>"
        f"<td>{html.escape((f.get('asset') or {}).get('name') or '')}</td>"
        f"<td>{html.escape(f.get('cve') or 'N/A')}</td></tr>"
        for f in findings
    )
    return f"""<!doctype html>
<html><body style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif">
<h2>{html.escape(build_subject(subscription))}</h2>
<p>{len(findings)} new finding(s) matched this alert:</p>
<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse">
<thead><tr><th>ID</th><th>Title</th><th>Asset</th><th>CVE</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</body></html>"""


def check_and_send_alerts(dashboard_data, email_sender, engine=None, lock_path=None, lock_timeout=None):
    """Real orchestrator: for every enabled subscription, finds findings that newly
    match its alert type/scope/team since the last check and emails them - if SMTP
    isn't configured, honestly reports the subscription as skipped (state untouched, so
    it's retried once SMTP is configured) rather than fabricating a send. A single
    subscription's send failure is caught per-subscription, not fatal to the batch.

    Holds a real lock across this ENTIRE function - not just the load/save calls -
    because the in-process scheduler timer and the "run checks now" button can call
    this concurrently, and the whole read-decide-send-persist sequence (not just the
    final write) has to be exclusive to avoid sending the same alert twice. This is the
    confirmed race this locking closes."""
    with FileLock(lock_path or LOCK_PATH, timeout=lock_timeout or LOCK_TIMEOUT_SECONDS):
        rules = dashboard_data.load_alert_rules()
        findings = dashboard_data.load_live_queue()
        ownership = asset_inventory.load_ownership()
        state = load_state(engine)
        results = []

        smtp_ready = email_sender.is_configured()
        for sub in rules.get("subscriptions", []):
            if not sub.get("enabled"):
                continue
            new_findings = new_matching_findings(sub, findings, ownership, state)
            if not new_findings:
                continue
            if not smtp_ready:
                results.append({
                    "id": sub["id"], "status": "skipped",
                    "reason": "SMTP not configured", "new_count": len(new_findings),
                })
                continue
            try:
                email_sender.send_email(
                    sub["recipients"], build_subject(sub),
                    build_alert_body_text(sub, new_findings), build_alert_body_html(sub, new_findings),
                )
                state.setdefault(sub["id"], [])
                state[sub["id"]].extend(f["id"] for f in new_findings)
                results.append({"id": sub["id"], "status": "sent", "new_count": len(new_findings)})
            except Exception as exc:  # noqa: BLE001 - one bad subscription must not block the rest
                results.append({"id": sub["id"], "status": "error", "reason": str(exc)})

        save_state(state, engine)
        return results
