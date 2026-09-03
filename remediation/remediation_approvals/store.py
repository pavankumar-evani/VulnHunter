"""
Remediation approval workflow - the real, human-in-the-loop approve/reject action this
app was missing for "normal"/"emergency" change-type findings (see
remediation/config/remediation_policy_engine.py). `risk_tier == needs-change-approval`
and `change_type == normal/emergency` were previously just labels in
REMEDIATION_PLAN.md/generated playbook comments - nothing recorded who actually clicked
approve, or when, or whether they were verified to be in the required AD group. This is
that missing piece.

Deliberately NOT the same thing as remediation/exceptions/store.py: an exception means
"accept the risk instead of fixing this"; an approval here means "yes, go ahead and mark
this remediation's generated playbook ready for a human/change-management process to
run" - a decision about HOW to proceed with the fix, not whether to skip it.

Persistence is the shared local SQLite database (see remediation/utils/db.py) -
previously a flat JSON file, migrated for real ACID write safety. Starts empty (no
seeded fake approval history, since fabricating past approvals would misrepresent
what's actually happened in this demo dataset).
"""
import datetime
import json
from pathlib import Path

from sqlalchemy import delete, insert, select

from remediation.audit.activity_log import record_activity
from remediation.utils import db as db_module
from remediation.utils.file_lock import FileLock

# Real, on-disk lock file this module's read-modify-write functions still take (see
# exceptions/store.py's own migration comment for why the DB migration didn't remove
# the need for it).
LOCK_PATH = Path(__file__).resolve().parent / ".remediation_approvals.lock"

STATUSES = ("pending", "approved", "rejected", "expired", "remediation_triggered")

# scheduled_window is a real nested dict ({"date": ..., ...}) - stored as JSON-encoded
# text in the DB (db_module.remediation_approvals's own column comment), so every
# row needs it encoded on the way in and decoded on the way out.
_JSON_FIELD = "scheduled_window"


def _row_to_record(row):
    record = dict(row)
    record[_JSON_FIELD] = json.loads(record[_JSON_FIELD]) if record.get(_JSON_FIELD) else {}
    return record


def _record_to_row(record):
    row = dict(record)
    row[_JSON_FIELD] = json.dumps(row.get(_JSON_FIELD) or {})
    return row


def load_approvals(engine=None):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    with engine.connect() as conn:
        rows = conn.execute(select(db_module.remediation_approvals)).mappings().all()
    return [_row_to_record(r) for r in rows]


def save_approvals(approvals, engine=None):
    """Replaces the entire table's contents with `approvals` - same "rewrite
    everything" semantics the old JSON file had, now atomic (one transaction)."""
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    with engine.begin() as conn:
        conn.execute(delete(db_module.remediation_approvals))
        if approvals:
            conn.execute(insert(db_module.remediation_approvals), [_record_to_row(a) for a in approvals])


def _next_id(approvals):
    existing = [int(a["id"].split("-")[1]) for a in approvals if a.get("id", "").startswith("APR-")]
    return f"APR-{max(existing, default=0) + 1}"


def compute_status(approval, as_of=None):
    """An approval's stored status is only ever "pending"/"approved"/"rejected"/
    "remediation_triggered" (approve/reject/trigger are all explicit human actions);
    "expired" is derived here - a pending request whose scheduled maintenance window
    has already passed with no decision - same "derive on read, never silently stay
    pending forever" pattern as exceptions/store.py's compute_status()."""
    status = approval.get("status", "pending")
    if status in ("approved", "rejected", "remediation_triggered"):
        return status
    as_of = as_of or datetime.date.today()
    window_date_str = (approval.get("scheduled_window") or {}).get("date")
    if window_date_str:
        try:
            if datetime.date.fromisoformat(window_date_str) < as_of:
                return "expired"
        except (TypeError, ValueError):
            pass
    return "pending"


def list_approvals_with_status(engine=None, as_of=None):
    """Returns every approval request with its live-computed status attached (doesn't
    mutate the stored table)."""
    approvals = load_approvals(engine)
    return [{**a, "computed_status": compute_status(a, as_of=as_of)} for a in approvals]


def approvals_by_finding(engine=None, as_of=None):
    """Returns {finding_id: approval} - the most recently created request wins per
    finding_id if more than one somehow exists."""
    result = {}
    for a in list_approvals_with_status(engine=engine, as_of=as_of):
        result[a["finding_id"]] = a
    return result


def create_approval_request(finding_id, requested_by, scheduled_window, engine=None, as_of=None, lock_path=None):
    if not finding_id:
        raise ValueError("finding_id is required")
    if not requested_by or not requested_by.strip():
        raise ValueError("requested_by is required")

    as_of = as_of or datetime.date.today()
    # Locked for the full read-modify-write cycle: two approval requests filed at
    # nearly the same real moment would otherwise both compute the same next APR-N
    # id from the same stale `approvals` read, and whichever save() ran last would
    # silently drop the other's real request. See exceptions/store.py's own migration
    # comment for why the DB migration didn't remove this need.
    with FileLock(lock_path or LOCK_PATH):
        approvals = load_approvals(engine)
        record = {
            # Every column from db_module.remediation_approvals is present from the
            # start (None for anything not yet decided) - save_approvals() bulk-inserts
            # the whole list in one INSERT, which needs every row to carry the same set
            # of keys; a field only added later by mark_remediation_triggered() etc.
            # would otherwise be missing from every OLDER record in that same INSERT.
            "id": _next_id(approvals),
            "finding_id": finding_id,
            "requested_by": requested_by.strip(),
            "scheduled_window": scheduled_window or {},
            "created_on": as_of.isoformat(),
            "status": "pending",
            "approved_by": None,
            "approved_at": None,
            "ad_group_validated": None,
            "rejected_by": None,
            "rejected_at": None,
            "rejection_reason": None,
            "staging_validated_by": None,
            "staging_validated_at": None,
            "triggered_by": None,
            "triggered_at": None,
        }
        approvals.append(record)
        save_approvals(approvals, engine)
    record_activity(requested_by.strip(), "approval.request", record["id"], {"finding_id": finding_id}, engine=engine)
    return record


def mark_staging_validated(approval_id, validated_by, engine=None, as_of=None, lock_path=None):
    """Records that this change was validated in a staging/test environment before
    production approval - ISO/IEC 27002:2022 §8.32 ("Change management") calls for
    testing changes before they're applied, alongside the change-approval step this
    workflow already has. Metadata only: there's no real staging environment behind
    this - it records who attests the validation happened and when, the same honest
    "who/when, not a live integration" pattern as ad_group_validated above. Settable at
    any status (most naturally before Approve, but not enforced - a real org's staging
    validation might happen at a different point in its own process, and refusing to
    record it after the fact would just be a demo restriction pretending to be a
    control, not a real one)."""
    if not validated_by or not validated_by.strip():
        raise ValueError("validated_by is required")
    with FileLock(lock_path or LOCK_PATH):
        approvals = load_approvals(engine)
        found = next((a for a in approvals if a["id"] == approval_id), None)
        if not found:
            raise KeyError(f"No approval request with id {approval_id!r}")
        found["staging_validated_by"] = validated_by.strip()
        found["staging_validated_at"] = (as_of or datetime.date.today()).isoformat()
        save_approvals(approvals, engine)
    record_activity(validated_by.strip(), "approval.staging_validated", approval_id,
                     {"finding_id": found.get("finding_id")}, engine=engine)
    return found


def mark_remediation_triggered(approval_id, actor=None, engine=None, as_of=None, lock_path=None):
    """Marks an already-approved finding's real playbook as generated on demand (the
    dashboard's "Trigger Remediation" button, backed by /api/run scoped to one finding -
    see cli/vulnhunter.py's remediate_prompt(finding_id=...)). Only ever moves an
    approval FROM "approved" - a pending or rejected approval can't be triggered, and
    raises ValueError rather than silently overwriting a decision that hasn't
    happened yet. This never means the playbook was executed against real
    infrastructure - only that it was generated and is ready for a human/
    change-management process to run, same as every other playbook in this app."""
    with FileLock(lock_path or LOCK_PATH):
        approvals = load_approvals(engine)
        found = next((a for a in approvals if a["id"] == approval_id), None)
        if not found:
            raise KeyError(f"No approval request with id {approval_id!r}")
        if found.get("status") != "approved":
            raise ValueError(
                f"Approval {approval_id!r} must be 'approved' before remediation can be "
                f"triggered (currently {found.get('status')!r})."
            )
        found["status"] = "remediation_triggered"
        found["triggered_by"] = actor or "unknown"
        found["triggered_at"] = (as_of or datetime.date.today()).isoformat()
        save_approvals(approvals, engine)
    record_activity(actor, "approval.trigger_remediation", approval_id,
                     {"finding_id": found.get("finding_id")}, engine=engine)
    return found


def approve(approval_id, approved_by, ad_group_validated=None, engine=None, as_of=None, lock_path=None):
    """`ad_group_validated` is True/False when AD was configured and the check actually
    ran, or None when AD isn't configured - callers must not collapse None into False,
    since that would misrepresent "we didn't check" as "we checked and it failed"."""
    if not approved_by or not approved_by.strip():
        raise ValueError("approved_by is required")
    with FileLock(lock_path or LOCK_PATH):
        approvals = load_approvals(engine)
        found = next((a for a in approvals if a["id"] == approval_id), None)
        if not found:
            raise KeyError(f"No approval request with id {approval_id!r}")
        found["status"] = "approved"
        found["approved_by"] = approved_by.strip()
        found["approved_at"] = (as_of or datetime.date.today()).isoformat()
        found["ad_group_validated"] = ad_group_validated
        save_approvals(approvals, engine)
    record_activity(approved_by.strip(), "approval.approve", approval_id,
                     {"finding_id": found.get("finding_id")}, engine=engine)
    return found


def reject(approval_id, rejected_by, reason, engine=None, as_of=None, lock_path=None):
    if not rejected_by or not rejected_by.strip():
        raise ValueError("rejected_by is required")
    with FileLock(lock_path or LOCK_PATH):
        approvals = load_approvals(engine)
        found = next((a for a in approvals if a["id"] == approval_id), None)
        if not found:
            raise KeyError(f"No approval request with id {approval_id!r}")
        found["status"] = "rejected"
        found["rejected_by"] = rejected_by.strip()
        found["rejected_at"] = (as_of or datetime.date.today()).isoformat()
        found["rejection_reason"] = (reason or "").strip() or None
        save_approvals(approvals, engine)
    record_activity(rejected_by.strip(), "approval.reject", approval_id,
                     {"finding_id": found.get("finding_id"), "reason": found["rejection_reason"]}, engine=engine)
    return found
