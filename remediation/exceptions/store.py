"""
Vulnerability exception (risk-acceptance / waiver) management.

A finding that can't be remediated on schedule - a compensating control is in place, a
vendor patch doesn't exist yet, the asset is being decommissioned - needs a documented,
time-boxed exception rather than either silently missing its SLA forever or being
deleted from the queue. This module is the store + lifecycle logic for that: request,
approve (both captured as separate fields so "who asked" and "who signed off" aren't
conflated), auto-expire, and revoke.

Persistence is a single local JSON file (remediation/exceptions/exceptions.json),
committed to the repo and seeded with one realistic example - the same
"real, editable config" pattern as remediation/config/priority_rules.yaml, not a
database. A production version would need real persistence + an approval workflow with
actual auth (see KNOWLEDGE_TRANSFER.md's Tier 3 gaps); this is the honest MVP version of
that workflow's shape.

Deliberate scope limit: an active exception is surfaced to the dashboard (queue rows
show it), but it does NOT currently suppress or pause SLA-breach computation in
remediation/config/priority_engine.py - a finding with an active exception can still show
as "SLA breached" today. A full implementation would feed exception status back into the
priority engine so an accepted risk stops counting against SLA; that's a real follow-up,
not done here to avoid entangling two engines that are already deliberately kept separate
(see priority_engine.py's own module docstring on why).
"""
import datetime
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_STORE_PATH = Path(__file__).resolve().parent / "exceptions.json"

STATUSES = ("active", "expired", "revoked")


def load_exceptions(path=None):
    # Resolved inside the body (not as a bound default parameter) so that patching
    # DEFAULT_STORE_PATH in tests (patch.object(store, "DEFAULT_STORE_PATH", tmp_path))
    # actually takes effect for every caller that omits `path` - a bound default is
    # captured once at function-definition time and is immune to patching afterwards.
    path = Path(path) if path is not None else DEFAULT_STORE_PATH
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def save_exceptions(exceptions, path=None):
    path = Path(path) if path is not None else DEFAULT_STORE_PATH
    path.write_text(json.dumps(exceptions, indent=2) + "\n", encoding="utf-8")


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


def list_exceptions_with_status(path=None, as_of=None):
    """Returns every exception with its live-computed status attached (doesn't mutate
    the stored file - expiry is computed on read, never written back)."""
    exceptions = load_exceptions(path)
    return [{**e, "computed_status": compute_status(e, as_of=as_of)} for e in exceptions]


def active_exceptions_by_finding(path=None, as_of=None):
    """Returns {finding_id: exception} for every currently-active (not expired, not
    revoked) exception - at most one per finding_id (the most recently created one wins
    if somehow more than one exists for the same finding)."""
    result = {}
    for e in list_exceptions_with_status(path=path, as_of=as_of):
        if e["computed_status"] == "active":
            result[e["finding_id"]] = e
    return result


def create_exception(finding_id, reason, requested_by, approved_by, expires_on,
                      path=None, as_of=None):
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

    exceptions = load_exceptions(path)
    record = {
        "id": _next_id(exceptions),
        "finding_id": finding_id,
        "reason": reason.strip(),
        "requested_by": requested_by.strip(),
        "approved_by": approved_by.strip(),
        "created_on": as_of.isoformat(),
        "expires_on": expires_on,
        "status": "active",
    }
    exceptions.append(record)
    save_exceptions(exceptions, path)
    return record


def revoke_exception(exception_id, path=None):
    """Marks an exception revoked (a permanent, explicit action distinct from
    expiring). Raises KeyError if no exception with that ID exists."""
    exceptions = load_exceptions(path)
    for e in exceptions:
        if e["id"] == exception_id:
            e["status"] = "revoked"
            save_exceptions(exceptions, path)
            return e
    raise KeyError(f"No exception with id {exception_id!r}")
