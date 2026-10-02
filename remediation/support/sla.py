"""
Support ticket priority and SLA, ITIL-style.

Priority is impact x urgency (see remediation/config/support_sla.yaml). Each priority has
a response target and a resolution target. The resolution clock pauses while a ticket waits
on the requester. State is always derived on read from timestamps, never stored, so editing
the policy re-evaluates every open ticket on the next request.

States for each clock: met / missed (finished), ok / at_risk / breached (running),
paused (waiting on requester), n/a.
"""
import datetime
from pathlib import Path

import yaml

POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "support_sla.yaml"
IMPACTS = ("individual", "team", "organization")

_DEFAULT = {
    "impact_weights": {"individual": 1, "team": 2, "organization": 3},
    "urgency_weights": {"low": 1, "normal": 2, "high": 3, "urgent": 4},
    "priority_thresholds": [{"priority": "P1", "min_score": 9}, {"priority": "P2", "min_score": 6},
                            {"priority": "P3", "min_score": 3}, {"priority": "P4", "min_score": 0}],
    "targets": {"P1": {"response_minutes": 30, "resolution_minutes": 240},
                "P2": {"response_minutes": 60, "resolution_minutes": 480},
                "P3": {"response_minutes": 240, "resolution_minutes": 4320},
                "P4": {"response_minutes": 480, "resolution_minutes": 7200}},
    "at_risk_threshold": 0.8,
}
FMT = "%Y-%m-%dT%H:%M:%SZ"


def load_policy(path=POLICY_PATH):
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        data = {}
    return {**_DEFAULT, **{k: v for k, v in data.items() if v}}


def parse(value):
    if not value:
        return None
    return datetime.datetime.strptime(value, FMT).replace(tzinfo=datetime.timezone.utc)


def fmt(dt):
    return dt.strftime(FMT) if dt else None


def priority_for(impact, urgency, policy=None):
    policy = policy or load_policy()
    score = policy["impact_weights"].get(impact or "individual", 1) * policy["urgency_weights"].get(urgency or "normal", 2)
    for rule in policy["priority_thresholds"]:
        if score >= rule["min_score"]:
            return rule["priority"]
    return policy["priority_thresholds"][-1]["priority"]


def due_times(created_at, priority, policy=None):
    policy = policy or load_policy()
    t = policy["targets"].get(priority) or policy["targets"]["P4"]
    created = parse(created_at) if isinstance(created_at, str) else created_at
    return (fmt(created + datetime.timedelta(minutes=t["response_minutes"])),
            fmt(created + datetime.timedelta(minutes=t["resolution_minutes"])))


def _clock(start, due, end, now, at_risk, paused=False):
    """One clock. `end` is when it stopped (response given / ticket resolved) or None."""
    if not due:
        return {"state": "n/a", "due_at": None, "minutes_remaining": None, "percent_elapsed": None}
    allowed = (due - start).total_seconds() or 1
    if end is not None:
        return {"state": "met" if end <= due else "missed", "due_at": fmt(due), "minutes_remaining": None,
                "percent_elapsed": round((end - start).total_seconds() / allowed * 100)}
    elapsed = (now - start).total_seconds()
    state = "paused" if paused else "breached" if now > due else "at_risk" if elapsed / allowed >= at_risk else "ok"
    return {"state": state, "due_at": fmt(due), "minutes_remaining": round((due - now).total_seconds() / 60),
            "percent_elapsed": round(elapsed / allowed * 100)}


def evaluate(ticket, now=None, policy=None):
    """Derived SLA view of one ticket row. Safe on tickets created before the ITSM columns
    existed (no priority/due times -> every clock is n/a)."""
    policy = policy or load_policy()
    now = now or datetime.datetime.now(datetime.timezone.utc)
    created = parse(ticket.get("created_at"))
    if not created or not ticket.get("priority"):
        return {"priority": ticket.get("priority"), "response": _clock(None, None, None, now, 1),
                "resolution": _clock(None, None, None, now, 1), "breached": False, "at_risk": False}
    at_risk = policy.get("at_risk_threshold", 0.8)
    paused = bool(ticket.get("paused_at"))
    finished = ticket.get("status") in ("resolved", "closed")
    response = _clock(created, parse(ticket.get("response_due_at")), parse(ticket.get("first_response_at")), now, at_risk)
    resolution = _clock(created, parse(ticket.get("resolution_due_at")), parse(ticket.get("resolved_at")) if finished else None,
                        now, at_risk, paused=paused and not finished)
    running = [c["state"] for c in (response, resolution)]
    return {"priority": ticket["priority"], "response": response, "resolution": resolution,
            "breached": "breached" in running, "at_risk": "at_risk" in running}


def shifted_due(due_at, paused_at, now):
    """Resolution due moves out by however long the ticket sat waiting on the requester."""
    due, paused = parse(due_at), parse(paused_at)
    if not due or not paused:
        return due_at
    return fmt(due + (now - paused))
