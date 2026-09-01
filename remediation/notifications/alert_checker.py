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
import json
from pathlib import Path

from remediation.enrichment import threat_actor_groups
from remediation.inventory import asset_inventory

STATE_PATH = Path(__file__).resolve().parent / "alert_state.json"


def load_state(path=None):
    path = path or STATE_PATH
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(state, path=None):
    path = path or STATE_PATH
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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


def check_and_send_alerts(dashboard_data, email_sender, state_path=None):
    """Real orchestrator: for every enabled subscription, finds findings that newly
    match its alert type/scope/team since the last check and emails them - if SMTP
    isn't configured, honestly reports the subscription as skipped (state untouched, so
    it's retried once SMTP is configured) rather than fabricating a send. A single
    subscription's send failure is caught per-subscription, not fatal to the batch."""
    rules = dashboard_data.load_alert_rules()
    findings = dashboard_data.load_live_queue()
    ownership = asset_inventory.load_ownership()
    state = load_state(state_path)
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

    save_state(state, state_path)
    return results
