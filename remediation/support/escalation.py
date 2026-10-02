"""
SLA escalation for support tickets.

A ticket whose running clock reaches "at risk" or "breached" raises one alert per level,
exactly once (tracked in the activity log as `support.sla_alert.<level>`, which is also the
audit trail). Who is told:
  at_risk  -> the assignee, else the team's manager
  breached -> the assignee, the team's manager, and every administrator
Alerts are always recorded in-app. Email goes out only when an SMTP relay is configured;
without one the alert is still recorded and visible, never silently dropped.
"""
from sqlalchemy import func, select

from remediation.audit.activity_log import record_activity
from remediation.utils import db as db_module

ACTION_PREFIX = "support.sla_alert."


def level_for(ticket):
    sla = ticket.get("sla") or {}
    if ticket["status"] not in ("open", "in_progress", "waiting_on_requester"):
        return None
    if sla.get("breached"):
        return "breached"
    if sla.get("at_risk"):
        return "at_risk"
    return None


def recipients(ticket, level, team_record, users):
    """Ordered, de-duplicated list of email addresses to alert for this ticket and level."""
    out = []
    if ticket.get("assignee_email"):
        out.append(ticket["assignee_email"])
    manager = (team_record or {}).get("manager_email")
    if manager and (level == "breached" or not out):
        out.append(manager)
    if level == "breached":
        out += [u["email"] for u in users if u.get("role") == "admin"]
    seen, result = set(), []
    for e in out:
        e = (e or "").strip().lower()
        if e and "@" in e and e not in seen:
            seen.add(e)
            result.append(e)
    return result


def already_alerted(ref, level, engine):
    al = db_module.activity_log
    with engine.connect() as conn:
        n = conn.execute(select(func.count()).select_from(al).where(al.c.action == ACTION_PREFIX + level, al.c.target == ref)).scalar()
    return bool(n)


def pending_alerts(tickets, teams_by_name, users, engine=None):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    pending = []
    for t in tickets:
        level = level_for(t)
        if not level or already_alerted(t["ref"], level, engine):
            continue
        team = teams_by_name.get((t.get("team") or "").lower())
        pending.append({"ref": t["ref"], "level": level, "priority": t.get("priority"), "team": t.get("team"),
                        "subject": t["subject"], "recipients": recipients(t, level, team, users)})
    return pending


def run(tickets, teams_by_name, users, email_sender, send=True, engine=None):
    """Raises every pending alert. Returns the list, each with `emailed` True/False.
    With send=False nothing is emailed or recorded (a preview)."""
    engine = engine or db_module.get_engine()
    alerts = pending_alerts(tickets, teams_by_name, users, engine)
    can_email = bool(send and email_sender is not None and email_sender.is_configured())
    for a in alerts:
        emailed = False
        if can_email and a["recipients"]:
            word = "BREACHED" if a["level"] == "breached" else "at risk"
            try:
                email_sender.send_email(
                    a["recipients"], f"[Quanta support] {a['ref']} SLA {word}: {a['subject']}",
                    f"Ticket {a['ref']} ({a['priority']}, team {a['team'] or 'unrouted'}) is {word} against its SLA.\n\n"
                    f"Subject: {a['subject']}\nOpen it in Quanta > Support.")
                emailed = True
            except Exception:  # noqa: BLE001 - a bad relay must not stop the other alerts
                emailed = False
        a["emailed"] = emailed
        if send:
            record_activity("system", ACTION_PREFIX + a["level"], a["ref"],
                            {"recipients": a["recipients"], "emailed": emailed, "priority": a["priority"], "team": a["team"]}, engine=engine)
    return alerts


def escalation_view(ticket, team_record, users):
    """What the ticket detail shows: the current level and who it would escalate to."""
    level = level_for(ticket)
    if not level:
        return None
    return {"level": level, "notify": recipients(ticket, level, team_record, users)}
