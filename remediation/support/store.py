"""
In-app support tickets: the helpdesk behind the Support page.

Why a database table and not an external tracker: a support request routinely describes
the customer's own environment (hostnames, findings, error output), so it belongs in the
customer's own database, under the same RBAC and audit trail as everything else - not in
a public issue tracker. Same shape as the finding-assignment layer (remediation/
assignments/store.py): tables in the shared SQLite DB, every change appended to the
activity log, one admin-triaged queue.

Workflow: open -> in_progress -> waiting_on_requester -> resolved -> closed. A requester
sees only their own tickets and the non-internal comments; an admin sees every ticket and
may add internal notes, assign, change severity/status, and record a resolution.
Escalation to the vendor is a separate, opt-in step (see dashboard/app.py's support
routes) - nothing leaves the deployment by default.
"""
import datetime

from sqlalchemy import insert, select, update

from remediation.audit.activity_log import record_activity
from remediation.support import routing, sla
from remediation.utils import db as db_module

KINDS = ("bug", "feature", "question", "access", "other")
IMPACTS = sla.IMPACTS
SEVERITIES = ("low", "normal", "high", "urgent")
STATUSES = ("open", "in_progress", "waiting_on_requester", "resolved", "closed")
OPEN_STATUSES = ("open", "in_progress", "waiting_on_requester")
MAX_SUBJECT, MAX_BODY = 200, 8000


def _now(now=None):
    return (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def ref(ticket_id):
    return f"TKT-{int(ticket_id)}"


def parse_ref(value):
    value = str(value).strip().upper()
    if value.startswith("TKT-"):
        value = value[4:]
    if not value.isdigit():
        raise ValueError("Ticket reference must look like TKT-12")
    return int(value)


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def _text(value, label, limit, required=True):
    value = (value or "").strip()
    if required and not value:
        raise ValueError(f"{label} is required")
    if len(value) > limit:
        raise ValueError(f"{label} must be at most {limit} characters")
    return value


def _view(row, policy=None):
    r = dict(row)
    r["ref"] = ref(r["id"])
    r["sla"] = sla.evaluate(r, policy=policy)
    r["reopen_count"] = r.get("reopen_count") or 0
    return r


def create_ticket(requester_email, kind, subject, description, severity="normal", impact="individual",
                  finding_id=None, team_names=(), engine=None, now=None):
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}")
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}")
    if impact not in IMPACTS:
        raise ValueError(f"impact must be one of {', '.join(IMPACTS)}")
    subject = _text(subject, "Subject", MAX_SUBJECT)
    description = _text(description, "Description", MAX_BODY)
    finding_id = _text(finding_id, "Finding", 64, required=False) or None
    engine = _engine(engine)
    stamp = _now(now)
    policy = sla.load_policy()
    priority = sla.priority_for(impact, severity, policy)
    routed = routing.route(kind, subject, description, priority, list(team_names))
    response_due, resolution_due = sla.due_times(stamp, priority, policy)
    row = {"kind": kind, "severity": severity, "subject": subject, "description": description,
           "status": "open", "requester_email": requester_email.lower(), "assignee_email": routed["assignee"],
           "resolution": None, "created_at": stamp, "updated_at": stamp, "resolved_at": None,
           "team": routed["team"], "impact": impact, "priority": priority, "finding_id": finding_id,
           "first_response_at": None, "response_due_at": response_due, "resolution_due_at": resolution_due,
           "paused_at": None, "reopen_count": 0}
    with engine.begin() as conn:
        new_id = conn.execute(insert(db_module.support_tickets), row).inserted_primary_key[0]
    record_activity(requester_email, "support.ticket.create", ref(new_id),
                    {"kind": kind, "severity": severity, "priority": priority, "team": routed["team"],
                     "rule": routed["rule"], "finding_id": finding_id, "subject": subject}, engine=engine)
    return _view({**row, "id": new_id}, policy)


def get_ticket(ticket_id, engine=None):
    engine = _engine(engine)
    t = db_module.support_tickets
    with engine.connect() as conn:
        row = conn.execute(select(t).where(t.c.id == int(ticket_id))).mappings().first()
    return _view(row) if row else None


def list_tickets(requester_email=None, status=None, assignee_email=None, kind=None, team=None, finding_id=None,
                 teams=None, breached=None, limit=500, engine=None):
    """`teams` (a collection of team names) restricts to tickets routed to any of them, used
    for a team agent's queue. `breached=True` keeps only tickets with a breached running clock."""
    engine = _engine(engine)
    t = db_module.support_tickets
    stmt = select(t).order_by(t.c.id.desc()).limit(limit)
    if requester_email:
        stmt = stmt.where(t.c.requester_email == requester_email.lower())
    if status == "open_all":
        stmt = stmt.where(t.c.status.in_(OPEN_STATUSES))
    elif status:
        stmt = stmt.where(t.c.status == status)
    if assignee_email:
        stmt = stmt.where(t.c.assignee_email == assignee_email.lower())
    if kind:
        stmt = stmt.where(t.c.kind == kind)
    if team:
        stmt = stmt.where(t.c.team == team)
    if teams is not None:
        stmt = stmt.where(t.c.team.in_(list(teams)))
    if finding_id:
        stmt = stmt.where(t.c.finding_id == finding_id)
    policy = sla.load_policy()
    with engine.connect() as conn:
        rows = [_view(r, policy) for r in conn.execute(stmt).mappings().all()]
    if breached is not None:
        rows = [r for r in rows if r["sla"]["breached"] == breached]
    return rows


def list_comments(ticket_id, include_internal=False, engine=None):
    engine = _engine(engine)
    c = db_module.support_ticket_comments
    stmt = select(c).where(c.c.ticket_id == int(ticket_id)).order_by(c.c.id)
    if not include_internal:
        stmt = stmt.where(c.c.internal == 0)
    with engine.connect() as conn:
        return [{**dict(r), "internal": bool(r["internal"])} for r in conn.execute(stmt).mappings().all()]


def add_comment(ticket_id, author_email, body, internal=False, engine=None, now=None):
    body = _text(body, "Comment", MAX_BODY)
    engine = _engine(engine)
    ticket = get_ticket(ticket_id, engine)
    if not ticket:
        raise KeyError(f"No ticket {ref(ticket_id)}")
    stamp = _now(now)
    author = author_email.lower()
    row = {"ticket_id": int(ticket_id), "author_email": author, "body": body,
           "internal": 1 if internal else 0, "created_at": stamp}
    changes = {"updated_at": stamp}
    from_requester = author == ticket["requester_email"]
    # the first public reply from anyone but the requester stops the response clock
    if not internal and not from_requester and not ticket["first_response_at"]:
        changes["first_response_at"] = stamp
    # a requester replying to a ticket waiting on them resumes it and un-pauses the clock
    if not internal and from_requester and ticket["status"] == "waiting_on_requester":
        changes.update(status="in_progress", paused_at=None,
                       resolution_due_at=sla.shifted_due(ticket["resolution_due_at"], ticket["paused_at"],
                                                         sla.parse(stamp)))
    with engine.begin() as conn:
        new_id = conn.execute(insert(db_module.support_ticket_comments), row).inserted_primary_key[0]
        conn.execute(update(db_module.support_tickets).where(db_module.support_tickets.c.id == int(ticket_id)).values(**changes))
    record_activity(author_email, "support.ticket.comment", ref(ticket_id), {"internal": bool(internal)}, engine=engine)
    return {**row, "id": new_id, "internal": bool(internal)}


def update_ticket(ticket_id, actor, status=None, severity=None, impact=None, assignee_email=None, team=None,
                  resolution=None, clear_assignee=False, engine=None, now=None):
    """Triage. Only the fields passed are changed. Priority and due times are recomputed
    when severity or impact change; pausing/resuming and reopening are handled here."""
    engine = _engine(engine)
    ticket = get_ticket(ticket_id, engine)
    if not ticket:
        raise KeyError(f"No ticket {ref(ticket_id)}")
    stamp = _now(now)
    changes = {}
    if status is not None:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        changes["status"] = status
        was_done = ticket["status"] in ("resolved", "closed")
        if status in ("resolved", "closed") and not ticket["resolved_at"]:
            changes["resolved_at"] = stamp
        if status in OPEN_STATUSES:
            changes["resolved_at"] = None
            if was_done:
                changes["reopen_count"] = (ticket["reopen_count"] or 0) + 1
        if status == "waiting_on_requester" and not ticket["paused_at"]:
            changes["paused_at"] = stamp
        elif status != "waiting_on_requester" and ticket["paused_at"]:
            changes["paused_at"] = None
            changes["resolution_due_at"] = sla.shifted_due(ticket["resolution_due_at"], ticket["paused_at"], sla.parse(stamp))
        # acknowledging an untouched ticket counts as the first response
        if ticket["status"] == "open" and status not in ("open", "waiting_on_requester") and not ticket["first_response_at"]:
            changes["first_response_at"] = stamp
    if severity is not None:
        if severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}")
        changes["severity"] = severity
    if impact is not None:
        if impact not in IMPACTS:
            raise ValueError(f"impact must be one of {', '.join(IMPACTS)}")
        changes["impact"] = impact
    if "severity" in changes or "impact" in changes:
        pr = sla.priority_for(changes.get("impact", ticket["impact"]), changes.get("severity", ticket["severity"]))
        if pr != ticket["priority"]:
            changes["priority"] = pr
            changes["response_due_at"], changes["resolution_due_at"] = sla.due_times(ticket["created_at"], pr)
    if team is not None:
        changes["team"] = team.strip() or None
    if clear_assignee:
        changes["assignee_email"] = None
    elif assignee_email is not None:
        changes["assignee_email"] = assignee_email.strip().lower() or None
    if resolution is not None:
        changes["resolution"] = _text(resolution, "Resolution", MAX_BODY, required=False) or None
    if not changes:
        return ticket
    changes["updated_at"] = stamp
    tbl = db_module.support_tickets
    with engine.begin() as conn:
        conn.execute(update(tbl).where(tbl.c.id == int(ticket_id)).values(**changes))
    record_activity(actor, "support.ticket.update", ref(ticket_id),
                    {k: v for k, v in changes.items() if k != "updated_at"}, engine=engine)
    return get_ticket(ticket_id, engine)


def summary(tickets=None, engine=None):
    """Counts for the queue header."""
    tickets = tickets if tickets is not None else list_tickets(engine=engine, limit=5000)
    by_status = {s: 0 for s in STATUSES}
    for t in tickets:
        by_status[t["status"]] += 1
    open_t = [t for t in tickets if t["status"] in OPEN_STATUSES]
    return {"total": len(tickets), "by_status": by_status, "open": len(open_t),
            "unassigned_open": sum(1 for t in open_t if not t["assignee_email"]),
            "unrouted_open": sum(1 for t in open_t if not t["team"]),
            "urgent_open": sum(1 for t in open_t if t["severity"] == "urgent"),
            "breached_open": sum(1 for t in open_t if t["sla"]["breached"]),
            "at_risk_open": sum(1 for t in open_t if t["sla"]["at_risk"] and not t["sla"]["breached"])}


def rate_ticket(ticket_id, rater_email, score, comment=None, engine=None, now=None):
    """The requester's satisfaction rating (1-5) on a resolved or closed ticket. Once only."""
    engine = _engine(engine)
    ticket = get_ticket(ticket_id, engine)
    if not ticket:
        raise KeyError(f"No ticket {ref(ticket_id)}")
    if ticket["requester_email"] != rater_email.lower():
        raise PermissionError("Only the requester can rate a ticket")
    if ticket["status"] not in ("resolved", "closed"):
        raise ValueError("A ticket can be rated once it is resolved")
    if ticket.get("csat_score"):
        raise ValueError("This ticket has already been rated")
    if not isinstance(score, int) or isinstance(score, bool) or not 1 <= score <= 5:
        raise ValueError("score must be a whole number from 1 to 5")
    comment = _text(comment, "Comment", 1000, required=False) or None
    tbl = db_module.support_tickets
    with engine.begin() as conn:
        conn.execute(update(tbl).where(tbl.c.id == int(ticket_id)).values(csat_score=score, csat_comment=comment, csat_at=_now(now)))
    record_activity(rater_email, "support.ticket.csat", ref(ticket_id), {"score": score}, engine=engine)
    return get_ticket(ticket_id, engine)
