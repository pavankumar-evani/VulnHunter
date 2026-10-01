"""
Finding assignment and team ownership - the ITSM-style "who owns this and what state is
it in" layer. Before this module the product knew who owned an *asset* (a free-text
owner/team on asset_ownership) but a *finding* could not be handed to a person or a
team, tracked through a work-state, or reported on by owner.

Two record types, both in the shared local SQLite database (remediation/utils/db.py):

* teams - first-class assignment groups with an accountable manager. A user's or an
  asset's `team` is still just a string naming one; list_teams() also surfaces teams
  that exist only as such strings, so deployments that predate this table need no
  migration.
* finding_assignments - sparse (one row per explicitly assigned finding): who it's
  assigned to, which team, and the assignee's own work-state. Every change is also
  appended to the audit log (action "finding.*"), which is where assignment *history*
  lives - this table only ever holds current state.

Deliberate scope: assignment records ownership and progress. It does not move or
close the underlying finding - whether a vulnerability is still present is decided by
the next scan, never by an owner setting status to "resolved".
"""
import datetime
import json
from pathlib import Path

from sqlalchemy import delete, insert, select, update

from remediation.audit.activity_log import list_activity, record_activity
from remediation.utils import db as db_module
from remediation.utils.file_lock import FileLock

LOCK_PATH = Path(__file__).resolve().parent / ".assignments.lock"

STATUSES = ("open", "in_progress", "blocked", "resolved")
MAX_TEAM_NAME = 60
MAX_NOTES = 2000


def _now(now=None):
    return (now or datetime.datetime.now(datetime.timezone.utc)).isoformat()


def _clean(value):
    value = (value or "").strip()
    return value or None


# --------------------------------------------------------------------------- teams

def _validate_team_name(name):
    name = _clean(name)
    if not name:
        raise ValueError("Team name is required")
    if len(name) > MAX_TEAM_NAME:
        raise ValueError(f"Team name must be {MAX_TEAM_NAME} characters or fewer")
    return name


def load_teams(engine=None):
    """Explicitly created teams only (see list_teams() for the merged view)."""
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    with engine.connect() as conn:
        rows = conn.execute(select(db_module.teams).order_by(db_module.teams.c.name)).mappings().all()
    return [dict(r) for r in rows]


def list_teams(known_team_names=(), engine=None):
    """Every team, explicit or implied. `known_team_names` is whatever team strings
    already exist elsewhere (users' and assets' `team` values) - a team that only
    exists as such a string is returned with `explicit: False` so the UI can offer to
    formalize it. Case-insensitive de-duplication; the explicit record wins."""
    result = {}
    for t in load_teams(engine):
        result[t["name"].lower()] = {**t, "explicit": True}
    for name in known_team_names:
        name = _clean(name)
        if name and name.lower() not in result:
            result[name.lower()] = {
                "name": name, "description": None, "manager_email": None,
                "created_by": None, "created_at": None, "explicit": False,
            }
    return sorted(result.values(), key=lambda t: t["name"].lower())


def create_team(name, actor, description=None, manager_email=None, engine=None, now=None, lock_path=None):
    name = _validate_team_name(name)
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    with FileLock(lock_path or LOCK_PATH):
        if any(t["name"].lower() == name.lower() for t in load_teams(engine)):
            raise ValueError(f"A team named {name!r} already exists")
        row = {
            "name": name, "description": _clean(description),
            "manager_email": (_clean(manager_email) or "").lower() or None,
            "created_by": actor, "created_at": _now(now),
        }
        with engine.begin() as conn:
            conn.execute(insert(db_module.teams), row)
    record_activity(actor, "team.create", name, {"manager_email": row["manager_email"]}, engine=engine)
    return {**row, "explicit": True}


def update_team(name, actor, description=None, manager_email=None, engine=None, lock_path=None):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    with FileLock(lock_path or LOCK_PATH):
        existing = next((t for t in load_teams(engine) if t["name"].lower() == (name or "").lower()), None)
        if not existing:
            raise KeyError(f"No team named {name!r}")
        changes = {
            "description": _clean(description),
            "manager_email": (_clean(manager_email) or "").lower() or None,
        }
        with engine.begin() as conn:
            conn.execute(update(db_module.teams).where(db_module.teams.c.name == existing["name"]).values(**changes))
    record_activity(actor, "team.update", existing["name"], changes, engine=engine)
    return {**existing, **changes, "explicit": True}


def delete_team(name, actor, in_use_count=0, engine=None, lock_path=None):
    """Removes an explicit team record. `in_use_count` is how many users/assignments
    still reference it, supplied by the caller (this module doesn't own users) - a team
    in use is refused rather than orphaning those references."""
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    with FileLock(lock_path or LOCK_PATH):
        existing = next((t for t in load_teams(engine) if t["name"].lower() == (name or "").lower()), None)
        if not existing:
            raise KeyError(f"No team named {name!r}")
        if in_use_count:
            raise ValueError(
                f"Team {existing['name']!r} still has {in_use_count} member(s) or open assignment(s) - "
                "move them first."
            )
        with engine.begin() as conn:
            conn.execute(delete(db_module.teams).where(db_module.teams.c.name == existing["name"]))
    record_activity(actor, "team.delete", existing["name"], {}, engine=engine)
    return existing


# ------------------------------------------------------------------- assignments

def load_assignments(engine=None):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    with engine.connect() as conn:
        rows = conn.execute(select(db_module.finding_assignments)).mappings().all()
    return [dict(r) for r in rows]


def assignments_by_finding(engine=None):
    return {a["finding_id"]: a for a in load_assignments(engine)}


def get_assignment(finding_id, engine=None):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    with engine.connect() as conn:
        row = conn.execute(
            select(db_module.finding_assignments).where(db_module.finding_assignments.c.finding_id == finding_id)
        ).mappings().first()
    return dict(row) if row is not None else None


def _upsert(conn, record):
    exists = conn.execute(
        select(db_module.finding_assignments.c.finding_id)
        .where(db_module.finding_assignments.c.finding_id == record["finding_id"])
    ).first()
    if exists:
        conn.execute(
            update(db_module.finding_assignments)
            .where(db_module.finding_assignments.c.finding_id == record["finding_id"])
            .values(**{k: v for k, v in record.items() if k != "finding_id"})
        )
    else:
        conn.execute(insert(db_module.finding_assignments), record)


def assign(finding_id, actor, assignee_email=None, team=None, notes=None, engine=None, now=None, lock_path=None):
    """Assigns (or re-assigns) one finding to a person, a team, or both. Re-assigning
    keeps the existing work-state unless the assignee changed, in which case it resets
    to "open" - a new owner hasn't started yet. Returns the stored record."""
    if not finding_id:
        raise ValueError("finding_id is required")
    assignee_email = (_clean(assignee_email) or "").lower() or None
    team = _clean(team)
    if not assignee_email and not team:
        raise ValueError("Assign to a person, a team, or both - at least one is required")
    notes = _clean(notes)
    if notes and len(notes) > MAX_NOTES:
        raise ValueError(f"Notes must be {MAX_NOTES} characters or fewer")

    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    stamp = _now(now)
    with FileLock(lock_path or LOCK_PATH):
        previous = get_assignment(finding_id, engine)
        keep_status = previous and previous["assignee_email"] == assignee_email
        record = {
            "finding_id": finding_id,
            "assignee_email": assignee_email,
            "assigned_team": team,
            "status": previous["status"] if keep_status else "open",
            "notes": notes if notes is not None else (previous or {}).get("notes"),
            "assigned_by": actor,
            "assigned_at": previous["assigned_at"] if previous else stamp,
            "updated_at": stamp,
        }
        with engine.begin() as conn:
            _upsert(conn, record)
    record_activity(actor, "finding.assign", finding_id, {
        "assignee": assignee_email, "team": team,
        "previous_assignee": (previous or {}).get("assignee_email"),
        "previous_team": (previous or {}).get("assigned_team"),
        "notes": notes,
    }, engine=engine)
    return record


def _apply_many(items, actor, action, engine, now, lock_path, per_item_audit=True):
    """items: [(finding_id, assignee_email|None, team|None, notes|None)]. One lock, one
    transaction, one batched audit insert for the whole set - per-finding assign() would
    take a lock file and open a transaction thousands of times for a large queue, which
    is slow on any disk and slower still on a synced one. Each finding gets its own audit
    row, except for a rule-driven batch (per_item_audit=False), which writes ONE summary row
    instead - thousands of identical machine-generated rows would bury the real human
    activity in the log; the assignment record itself still carries who/when/why."""
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    stamp = _now(now)
    fa, al = db_module.finding_assignments, db_module.activity_log
    with FileLock(lock_path or LOCK_PATH):
        existing = {a["finding_id"]: a for a in load_assignments(engine)}
        inserts, updates, audit = [], [], []
        for fid, assignee, team, notes in items:
            prev = existing.get(fid)
            keep_status = prev and prev["assignee_email"] == assignee
            rec = {
                "finding_id": fid, "assignee_email": assignee, "assigned_team": team,
                "status": prev["status"] if keep_status else "open",
                "notes": notes if notes is not None else (prev or {}).get("notes"),
                "assigned_by": actor,
                "assigned_at": prev["assigned_at"] if prev else stamp,
                "updated_at": stamp,
            }
            (updates if prev else inserts).append(rec)
            if per_item_audit:
                audit.append({
                    "actor": actor or "unknown", "action": action, "target": fid, "timestamp": stamp,
                    "details": json.dumps({
                        "assignee": assignee, "team": team,
                        "previous_assignee": (prev or {}).get("assignee_email"),
                        "previous_team": (prev or {}).get("assigned_team"), "notes": notes,
                    }),
                })
        with engine.begin() as conn:
            if inserts:
                conn.execute(insert(fa), inserts)
            for rec in updates:
                conn.execute(update(fa).where(fa.c.finding_id == rec["finding_id"])
                             .values(**{k: v for k, v in rec.items() if k != "finding_id"}))
            if audit:
                conn.execute(insert(al), audit)
            if not per_item_audit and items:
                by_team = {}
                for _fid, _assignee, team, _notes in items:
                    by_team[team or "(none)"] = by_team.get(team or "(none)", 0) + 1
                conn.execute(insert(al), {
                    "actor": actor or "unknown", "action": action, "target": "batch", "timestamp": stamp,
                    "details": json.dumps({"count": len(items), "by_team": by_team}),
                })
    return len(items)


def bulk_assign(finding_ids, actor, assignee_email=None, team=None, notes=None, engine=None, now=None, lock_path=None):
    """Assigns many findings in one transaction. Returns the number assigned.
    Validation (a person, a team, or both) matches assign() and is checked up front,
    so a bad request changes nothing."""
    assignee_email = (_clean(assignee_email) or "").lower() or None
    team = _clean(team)
    if not assignee_email and not team:
        raise ValueError("Assign to a person, a team, or both - at least one is required")
    ids = [fid for fid in dict.fromkeys(finding_ids or []) if fid]
    return _apply_many([(fid, assignee_email, team, _clean(notes)) for fid in ids],
                       actor, "finding.assign", engine, now, lock_path)


def set_status(finding_id, status, actor, notes=None, engine=None, now=None, lock_path=None):
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    with FileLock(lock_path or LOCK_PATH):
        previous = get_assignment(finding_id, engine)
        if not previous:
            raise KeyError(f"Finding {finding_id!r} is not assigned - assign it first")
        changes = {"status": status, "updated_at": _now(now)}
        if _clean(notes):
            changes["notes"] = _clean(notes)[:MAX_NOTES]
        with engine.begin() as conn:
            conn.execute(
                update(db_module.finding_assignments)
                .where(db_module.finding_assignments.c.finding_id == finding_id).values(**changes)
            )
    record_activity(actor, "finding.status", finding_id,
                    {"from": previous["status"], "to": status, "notes": _clean(notes)}, engine=engine)
    return {**previous, **changes}


def unassign(finding_id, actor, engine=None, lock_path=None):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    with FileLock(lock_path or LOCK_PATH):
        previous = get_assignment(finding_id, engine)
        if not previous:
            raise KeyError(f"Finding {finding_id!r} is not assigned")
        with engine.begin() as conn:
            conn.execute(
                delete(db_module.finding_assignments)
                .where(db_module.finding_assignments.c.finding_id == finding_id)
            )
    record_activity(actor, "finding.unassign", finding_id, {
        "previous_assignee": previous["assignee_email"], "previous_team": previous["assigned_team"],
    }, engine=engine)
    return previous


def assignment_history(finding_id, engine=None, limit=50):
    """Newest-first audit trail of every assignment action on one finding. Queried by
    target in SQL, not by loading the whole activity log - the log can hold thousands of
    rows and this runs every time a finding's detail opens."""
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    al = db_module.activity_log
    stmt = (select(al).where(al.c.target == finding_id, al.c.action.like("finding.%"))
            .order_by(al.c.id.desc()).limit(limit))
    with engine.connect() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [{**r, "details": json.loads(r["details"]) if r["details"] else {}} for r in rows]


def auto_assign_from_assets(findings, actor, engine=None, now=None, lock_path=None, dry_run=True):
    """The ITSM "assignment rule": route every not-yet-assigned finding to the team that
    owns its asset. `findings` must already carry a `team` (the asset owner's team - see
    dashboard/app.py's _annotate_finding_teams). Only fills gaps: a finding that already
    has an assignment is never touched, and a finding whose asset has no team is skipped
    (nothing honest to route it to). Returns {"would_assign"/"assigned", "skipped_no_team",
    "already_assigned"}; with dry_run=True (default) nothing is written."""
    existing = assignments_by_finding(engine)
    todo, skipped_no_team, already = [], 0, 0
    for f in findings:
        if f["id"] in existing:
            already += 1
        elif not f.get("team"):
            skipped_no_team += 1
        else:
            todo.append((f["id"], f["team"]))
    if not dry_run and todo:
        _apply_many([(fid, None, team, "Auto-routed to the asset owner's team") for fid, team in todo],
                    actor, "finding.auto_assign", engine, now, lock_path, per_item_audit=False)
    key = "would_assign" if dry_run else "assigned"
    return {key: len(todo), "skipped_no_team": skipped_no_team, "already_assigned": already, "dry_run": dry_run}
