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
from remediation.utils import db as db_module

KINDS = ("bug", "feature", "question", "access", "other")
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


def _view(row):
    r = dict(row)
    r["ref"] = ref(r["id"])
    return r


def create_ticket(requester_email, kind, subject, description, severity="normal", engine=None, now=None):
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}")
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}")
    subject = _text(subject, "Subject", MAX_SUBJECT)
    description = _text(description, "Description", MAX_BODY)
    engine = _engine(engine)
    stamp = _now(now)
    row = {"kind": kind, "severity": severity, "subject": subject, "description": description,
           "status": "open", "requester_email": requester_email.lower(), "assignee_email": None,
           "resolution": None, "created_at": stamp, "updated_at": stamp, "resolved_at": None}
    with engine.begin() as conn:
        new_id = conn.execute(insert(db_module.support_tickets), row).inserted_primary_key[0]
    record_activity(requester_email, "support.ticket.create", ref(new_id),
                    {"kind": kind, "severity": severity, "subject": subject}, engine=engine)
    return _view({**row, "id": new_id})


def get_ticket(ticket_id, engine=None):
    engine = _engine(engine)
    t = db_module.support_tickets
    with engine.connect() as conn:
        row = conn.execute(select(t).where(t.c.id == int(ticket_id))).mappings().first()
    return _view(row) if row else None


def list_tickets(requester_email=None, status=None, assignee_email=None, kind=None, limit=500, engine=None):
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
    with engine.connect() as conn:
        return [_view(r) for r in conn.execute(stmt).mappings().all()]


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
    row = {"ticket_id": int(ticket_id), "author_email": author_email.lower(), "body": body,
           "internal": 1 if internal else 0, "created_at": stamp}
    with engine.begin() as conn:
        new_id = conn.execute(insert(db_module.support_ticket_comments), row).inserted_primary_key[0]
        # a requester replying to a ticket waiting on them puts it back in the queue
        if (not internal and ticket["status"] == "waiting_on_requester"
                and author_email.lower() == ticket["requester_email"]):
            conn.execute(update(db_module.support_tickets).where(db_module.support_tickets.c.id == int(ticket_id))
                         .values(status="in_progress", updated_at=stamp))
        else:
            conn.execute(update(db_module.support_tickets).where(db_module.support_tickets.c.id == int(ticket_id))
                         .values(updated_at=stamp))
    record_activity(author_email, "support.ticket.comment", ref(ticket_id), {"internal": bool(internal)}, engine=engine)
    return {**row, "id": new_id, "internal": bool(internal)}


def update_ticket(ticket_id, actor, status=None, severity=None, assignee_email=None, resolution=None,
                  clear_assignee=False, engine=None, now=None):
    """Admin triage. Only the fields passed are changed."""
    engine = _engine(engine)
    ticket = get_ticket(ticket_id, engine)
    if not ticket:
        raise KeyError(f"No ticket {ref(ticket_id)}")
    changes = {}
    if status is not None:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        changes["status"] = status
        if status in ("resolved", "closed") and not ticket["resolved_at"]:
            changes["resolved_at"] = _now(now)
        if status in OPEN_STATUSES:
            changes["resolved_at"] = None
    if severity is not None:
        if severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}")
        changes["severity"] = severity
    if clear_assignee:
        changes["assignee_email"] = None
    elif assignee_email is not None:
        changes["assignee_email"] = assignee_email.strip().lower() or None
    if resolution is not None:
        changes["resolution"] = _text(resolution, "Resolution", MAX_BODY, required=False) or None
    if not changes:
        return ticket
    changes["updated_at"] = _now(now)
    t = db_module.support_tickets
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.id == int(ticket_id)).values(**changes))
    record_activity(actor, "support.ticket.update", ref(ticket_id),
                    {k: v for k, v in changes.items() if k != "updated_at"}, engine=engine)
    return get_ticket(ticket_id, engine)


def summary(engine=None):
    """Counts for the admin queue header."""
    tickets = list_tickets(engine=engine, limit=5000)
    by_status = {s: 0 for s in STATUSES}
    for t in tickets:
        by_status[t["status"]] += 1
    return {"total": len(tickets), "by_status": by_status,
            "open": sum(by_status[s] for s in OPEN_STATUSES),
            "unassigned_open": sum(1 for t in tickets if t["status"] in OPEN_STATUSES and not t["assignee_email"]),
            "urgent_open": sum(1 for t in tickets if t["status"] in OPEN_STATUSES and t["severity"] == "urgent")}
