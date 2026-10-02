"""
Links between Quanta findings and tickets in an external system (ServiceNow, Jira, ...),
and the mapping of the external system's states onto Quanta's work statuses.

A link is created when Quanta pushes a finding (a stored push connection), or when the
external system reports in over the inbound API. Its `state` is the external system's own
state normalised to open / in_progress / blocked / resolved, so a finding shows "INC0012345,
in progress" without anyone copying a status by hand. When the external ticket is resolved,
the finding's assignment (if it has one) is marked resolved too: the owner's report, never a
silent close, because the next scan decides whether the vulnerability is really gone.
"""
import datetime

from sqlalchemy import insert, select, update

from remediation.audit.activity_log import record_activity
from remediation.utils import db as db_module

STATES = ("open", "in_progress", "blocked", "resolved")


def _now(now=None):
    return (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


# ServiceNow incident states: 1 New, 2 In Progress, 3 On Hold, 4/5 awaiting, 6 Resolved, 7 Closed, 8 Canceled.
_SNOW = {"1": "open", "2": "in_progress", "3": "blocked", "4": "blocked", "5": "blocked", "6": "resolved", "7": "resolved", "8": "resolved"}
# Jira status categories (stable across custom workflows): new, indeterminate, done.
_JIRA_CATEGORY = {"new": "open", "to do": "open", "indeterminate": "in_progress", "in progress": "in_progress", "done": "resolved"}
_WORDS = {"open": "open", "new": "open", "in_progress": "in_progress", "in progress": "in_progress", "active": "in_progress",
          "blocked": "blocked", "on hold": "blocked", "waiting": "blocked", "resolved": "resolved", "closed": "resolved", "done": "resolved"}


def map_state(system, state):
    """The Quanta status for an external state value, or None if it is not recognised."""
    s = str(state if state is not None else "").strip().lower()
    if not s:
        return None
    if s in STATES:
        return s
    if system == "servicenow" and s in _SNOW:
        return _SNOW[s]
    if system == "jira" and s in _JIRA_CATEGORY:
        return _JIRA_CATEGORY[s]
    return _WORDS.get(s)


def upsert(finding_id, system, external_ref, state, connection_id=None, external_id=None, error=None, engine=None, now=None):
    """Creates or updates the link for (connection, finding, system). Returns the link."""
    engine = _engine(engine)
    t = db_module.ticket_links
    stamp = _now(now)
    with engine.begin() as conn:
        q = select(t).where(t.c.finding_id == finding_id, t.c.system == system)
        q = q.where(t.c.connection_id == connection_id) if connection_id is not None else q.where(t.c.connection_id.is_(None))
        row = conn.execute(q).mappings().first()
        if row:
            changes = {"updated_at": stamp, "last_error": error}
            if external_ref:
                changes["external_ref"] = external_ref
            if external_id:
                changes["external_id"] = external_id
            if state:
                changes["state"] = state
            conn.execute(update(t).where(t.c.id == row["id"]).values(**changes))
            link_id = row["id"]
        else:
            link_id = conn.execute(insert(t), {"connection_id": connection_id, "finding_id": finding_id, "system": system,
                                               "external_id": external_id, "external_ref": external_ref, "state": state,
                                               "last_error": error, "created_at": stamp, "updated_at": stamp}).inserted_primary_key[0]
    return get(link_id, engine)


def get(link_id, engine=None):
    engine = _engine(engine)
    t = db_module.ticket_links
    with engine.connect() as conn:
        row = conn.execute(select(t).where(t.c.id == int(link_id))).mappings().first()
    return dict(row) if row else None


def for_finding(finding_id, engine=None):
    engine = _engine(engine)
    t = db_module.ticket_links
    with engine.connect() as conn:
        return [dict(r) for r in conn.execute(select(t).where(t.c.finding_id == finding_id).order_by(t.c.id)).mappings().all()]


def pushed_ids(connection_id, engine=None):
    """Finding ids already pushed (successfully) through this connection."""
    engine = _engine(engine)
    t = db_module.ticket_links
    with engine.connect() as conn:
        return {r[0] for r in conn.execute(select(t.c.finding_id).where(t.c.connection_id == connection_id, t.c.external_ref.is_not(None)))}


def open_links(connection_id, engine=None):
    engine = _engine(engine)
    t = db_module.ticket_links
    with engine.connect() as conn:
        return [dict(r) for r in conn.execute(select(t).where(
            t.c.connection_id == connection_id, t.c.external_ref.is_not(None), (t.c.state.is_(None)) | (t.c.state != "resolved"))).mappings().all()]


def apply_to_assignment(finding_id, status, actor, engine=None):
    """Mirrors an external state onto the finding's assignment, if it has one. Returns True if
    an assignment was updated."""
    from remediation.assignments import store as assignments_store
    engine = _engine(engine)
    current = next((a for a in assignments_store.load_assignments(engine) if a["finding_id"] == finding_id), None)
    if not current or current["status"] == status:
        return False
    assignments_store.set_status(finding_id, status, actor, notes="Synced from the external ticket", engine=engine)
    return True


def report_state(finding_id, system, state, actor, external_ref=None, engine=None):
    """Records an external ticket's state for a finding (inbound webhook or poll) and mirrors it
    to the assignment. Returns {status, link, assignment_updated}."""
    engine = _engine(engine)
    status = map_state(system, state)
    if not status:
        raise ValueError(f"Unrecognised {system} state {state!r}")
    existing = [l for l in for_finding(finding_id, engine) if l["system"] == system]
    link = upsert(finding_id, system, external_ref or (existing[0]["external_ref"] if existing else None), status,
                  connection_id=existing[0]["connection_id"] if existing else None, engine=engine)
    updated = apply_to_assignment(finding_id, status, actor, engine)
    record_activity(actor, "ticket.state", finding_id, {"system": system, "state": status, "ref": link.get("external_ref"),
                                                          "assignment_updated": updated}, engine=engine)
    return {"status": status, "link": link, "assignment_updated": updated}
