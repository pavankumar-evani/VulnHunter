"""
Vulnerability exception (risk-acceptance / waiver) management.

A finding that can't be remediated on schedule - a compensating control is in place, a
vendor patch doesn't exist yet, the asset is being decommissioned - needs a documented,
time-boxed exception rather than either silently missing its SLA forever or being
deleted from the queue. This module is the store + lifecycle logic for that: request,
approve (both captured as separate fields so "who asked" and "who signed off" aren't
conflated), auto-expire, and revoke.

Persistence is the shared local SQLite database (see remediation/utils/db.py) -
previously a flat JSON file, migrated for real ACID write safety. A production version
would still need a real approval workflow with actual auth (see KNOWLEDGE_TRANSFER.md's
Tier 3 gaps); this is the honest MVP version of that workflow's shape.

Deliberate scope limit: an active exception is surfaced to the dashboard (queue rows
show it), but it does NOT currently suppress or pause SLA-breach computation in
remediation/config/priority_engine.py - a finding with an active exception can still show
as "SLA breached" today. A full implementation would feed exception status back into the
priority engine so an accepted risk stops counting against SLA; that's a real follow-up,
not done here to avoid entangling two engines that are already deliberately kept separate
(see priority_engine.py's own module docstring on why).
"""
import datetime
from pathlib import Path

from sqlalchemy import delete, insert, select

from remediation.audit.activity_log import record_activity
from remediation.utils import db as db_module
from remediation.utils.file_lock import FileLock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
# Real, on-disk lock file this module's read-modify-write functions still take (see
# their own comments) - the DB migration changed the STORAGE backend, not the need for
# mutual exclusion across the compute-next-id-then-insert critical section.
LOCK_PATH = Path(__file__).resolve().parent / ".exceptions.lock"

STATUSES = ("active", "expired", "revoked")


def load_exceptions(engine=None):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    with engine.connect() as conn:
        rows = conn.execute(select(db_module.exceptions)).mappings().all()
    return [dict(r) for r in rows]


def save_exceptions(exceptions, engine=None):
    """Replaces the entire table's contents with `exceptions` - same "rewrite
    everything" semantics the old JSON file had, now atomic (one transaction) instead
    of a non-atomic full-file rewrite."""
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    with engine.begin() as conn:
        conn.execute(delete(db_module.exceptions))
        if exceptions:
            conn.execute(insert(db_module.exceptions), exceptions)


def _next_id(exceptions):
    existing = [int(e["id"].split("-")[1]) for e in exceptions if e.get("id", "").startswith("EXC-")]
    return f"EXC-{max(existing, default=0) + 1}"


def compute_status(exception, as_of=None):
    """An exception's stored status is only ever "active" or "revoked" (revocation is
    an explicit human action); "expired" is derived here from expires_on vs as_of
    rather than stored, so a forgotten exception can't silently stay "active" forever
    just because nobody revoked it."""
    if exception.get("status") == "revoked":
        return "revoked"
    as_of = as_of or datetime.date.today()
    expires_on = datetime.date.fromisoformat(exception["expires_on"])
    return "expired" if expires_on < as_of else "active"


def list_exceptions_with_status(engine=None, as_of=None):
    """Returns every exception with its live-computed status attached (doesn't mutate
    the stored table - expiry is computed on read, never written back)."""
    exceptions = load_exceptions(engine)
    return [{**e, "computed_status": compute_status(e, as_of=as_of)} for e in exceptions]


def active_exceptions_by_finding(engine=None, as_of=None):
    """Returns {finding_id: exception} for every currently-active (not expired, not
    revoked) exception - at most one per finding_id (the most recently created one wins
    if somehow more than one exists for the same finding)."""
    result = {}
    for e in list_exceptions_with_status(engine=engine, as_of=as_of):
        if e["computed_status"] == "active":
            result[e["finding_id"]] = e
    return result


def create_exception(finding_id, reason, requested_by, approved_by, expires_on,
                      engine=None, as_of=None, lock_path=None):
    """Validates expires_on is a real ISO date in the future (relative to as_of, which
    defaults to today) and that the required text fields are non-empty, then appends
    and persists a new exception record. Raises ValueError on any validation failure -
    the caller (the API route) is responsible for turning that into a 400."""
    if not finding_id:
        raise ValueError("finding_id is required")
    if not reason or not reason.strip():
        raise ValueError("reason is required")
    if not requested_by or not requested_by.strip():
        raise ValueError("requested_by is required")
    if not approved_by or not approved_by.strip():
        raise ValueError("approved_by is required")

    try:
        expires_date = datetime.date.fromisoformat(expires_on)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"expires_on must be an ISO date (YYYY-MM-DD), got {expires_on!r}") from exc

    as_of = as_of or datetime.date.today()
    if expires_date <= as_of:
        raise ValueError("expires_on must be a future date")

    # Locked for the full read-modify-write cycle: two exceptions requested at
    # nearly the same real moment would otherwise both compute the same next
    # EXC-N id from the same stale `exceptions` read, and whichever save() ran last
    # would silently drop the other's real exception record. The DB migration changed
    # the storage backend, not this need - a bare INSERT could race on the same
    # computed id and raise a PRIMARY KEY conflict instead of silently losing data,
    # which is better but still not the graceful, always-succeeds behavior callers
    # (the API route) already expect.
    with FileLock(lock_path or LOCK_PATH):
        exceptions = load_exceptions(engine)
        record = {
            "id": _next_id(exceptions),
            "finding_id": finding_id,
            "reason": reason.strip(),
            "requested_by": requested_by.strip(),
            "approved_by": approved_by.strip(),
            "created_on": as_of.isoformat(),
            "expires_on": expires_on,
            "status": "active",
            "revoked_by": None,
            "revoked_at": None,
        }
        exceptions.append(record)
        save_exceptions(exceptions, engine)
    record_activity(requested_by.strip(), "exception.create", record["id"],
                     {"finding_id": finding_id, "approved_by": record["approved_by"], "expires_on": expires_on},
                     engine=engine)
    return record


def revoke_exception(exception_id, revoked_by=None, engine=None, as_of=None, lock_path=None):
    """Marks an exception revoked (a permanent, explicit action distinct from
    expiring). Records who revoked it and when - previously this only flipped the
    status with no who/when trace at all. Raises KeyError if no exception with that ID
    exists."""
    as_of = as_of or datetime.datetime.now(datetime.timezone.utc)
    with FileLock(lock_path or LOCK_PATH):
        exceptions = load_exceptions(engine)
        found = next((e for e in exceptions if e["id"] == exception_id), None)
        if not found:
            raise KeyError(f"No exception with id {exception_id!r}")
        found["status"] = "revoked"
        found["revoked_by"] = revoked_by or "unknown"
        found["revoked_at"] = as_of.isoformat()
        save_exceptions(exceptions, engine)
    record_activity(revoked_by, "exception.revoke", exception_id, {"finding_id": found.get("finding_id")},
                     engine=engine, as_of=as_of)
    return found
