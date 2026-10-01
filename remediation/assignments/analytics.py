"""
Ownership analytics - who (and which team) is carrying how much of the vulnerability
backlog, how much of it is breaching SLA, and how much has no owner at all.

Pure functions over data the caller has already loaded (scored queue findings, the
assignment records, user accounts, teams): no I/O, no globals, so it is trivially
testable and the dashboard can scope its inputs (e.g. to one team) before calling it.

Every number here is a direct count over real findings and real assignment records -
nothing is estimated or sampled. Definitions the UI repeats verbatim:

  ownership state  assigned  - an individual is the assignee
                   team_only - no individual, but a team owns it (assigned to the
                               team, or inherited from the asset owner's team)
                   unowned   - neither
  open             any finding whose assignment status isn't "resolved"
                   ("resolved" = owner reports it fixed, pending the next scan)
  effective team   the assignment's team if set, else the asset owner's team
"""
import datetime

AGE_BUCKETS = (("0-7 days", 0, 7), ("8-30 days", 8, 30), ("31-90 days", 31, 90), ("90+ days", 91, None))
PRIORITIES = ("Critical", "High", "Medium", "Low")


def _age_days(first_seen, as_of):
    try:
        return max((as_of - datetime.date.fromisoformat(str(first_seen)[:10])).days, 0)
    except (TypeError, ValueError):
        return None


def _bucket(age):
    if age is None:
        return None
    for label, lo, hi in AGE_BUCKETS:
        if age >= lo and (hi is None or age <= hi):
            return label
    return None


def effective_team(finding, assignment):
    return (assignment or {}).get("assigned_team") or finding.get("team") or None


def ownership_state(finding, assignment):
    if (assignment or {}).get("assignee_email"):
        return "assigned"
    return "team_only" if effective_team(finding, assignment) else "unowned"


def _blank_bucket():
    return {"total": 0, "critical": 0, "high": 0, "breached": 0, "at_risk": 0,
            "assigned": 0, "team_only": 0, "unowned": 0,
            "open": 0, "in_progress": 0, "blocked": 0, "resolved": 0}


def _tally(bucket, finding, assignment, state):
    bucket["total"] += 1
    status = (assignment or {}).get("status")
    if status == "resolved":
        bucket["resolved"] += 1
        return                       # a resolved item no longer counts toward the live workload
    bucket[state] += 1
    bucket["open"] += 1
    if status in ("in_progress", "blocked"):
        bucket[status] += 1
    prio = finding.get("priority")
    if prio == "Critical":
        bucket["critical"] += 1
    elif prio == "High":
        bucket["high"] += 1
    sla = finding.get("sla") or {}
    if sla.get("breached"):
        bucket["breached"] += 1
    elif sla.get("days_remaining") is not None and sla["days_remaining"] <= 3:
        bucket["at_risk"] += 1


def ownership_analytics(findings, assignments, users=(), teams=(), as_of=None):
    """findings: scored queue findings (need id, priority, sla, first_seen, and `team` =
    the asset owner's team). assignments: finding_assignments rows (list). users:
    [{email, name, role, team}]. teams: [{name, manager_email, ...}]. as_of: date used
    for ageing (default today)."""
    as_of = as_of or datetime.date.today()
    by_finding = {a["finding_id"]: a for a in assignments}
    user_by_email = {u["email"].lower(): u for u in users}

    totals = _blank_bucket()
    by_team, by_user = {}, {}
    status_counts = {s: 0 for s in ("open", "in_progress", "blocked", "resolved")}
    ageing = {label: {"assigned": 0, "team_only": 0, "unowned": 0} for label, _, _ in AGE_BUCKETS}
    unowned_urgent = []

    for t in teams:
        by_team[t["name"]] = {**_blank_bucket(), "name": t["name"], "manager_email": t.get("manager_email"),
                               "members": 0, "explicit": t.get("explicit", True)}
    for u in users:
        by_user[u["email"].lower()] = {**_blank_bucket(), "email": u["email"].lower(), "name": u.get("name"),
                                        "team": u.get("team"), "role": u.get("role"), "oldest_open_days": None}
        if u.get("team") and u["team"] in by_team:
            by_team[u["team"]]["members"] += 1

    for f in findings:
        a = by_finding.get(f["id"])
        state = ownership_state(f, a)
        _tally(totals, f, a, state)
        status = (a or {}).get("status", "open")
        status_counts[status if status in status_counts else "open"] += 1

        team = effective_team(f, a) or "(no team)"
        tb = by_team.setdefault(team, {**_blank_bucket(), "name": team, "manager_email": None,
                                        "members": 0, "explicit": False})
        _tally(tb, f, a, state)

        email = ((a or {}).get("assignee_email") or "").lower()
        if email:
            ub = by_user.setdefault(email, {**_blank_bucket(), "email": email, "name": None,
                                            "team": None, "role": None, "oldest_open_days": None})
            _tally(ub, f, a, "assigned")
            if status != "resolved":
                age = _age_days(f.get("first_seen"), as_of)
                if age is not None and (ub["oldest_open_days"] is None or age > ub["oldest_open_days"]):
                    ub["oldest_open_days"] = age

        if status != "resolved":
            bucket = _bucket(_age_days(f.get("first_seen"), as_of))
            if bucket:
                ageing[bucket][state] += 1
            if state == "unowned" and f.get("priority") in ("Critical", "High"):
                unowned_urgent.append(f)

    for email, ub in by_user.items():
        if not ub.get("name") and email in user_by_email:
            ub["name"] = user_by_email[email].get("name")

    unowned_urgent.sort(key=lambda f: (
        0 if (f.get("sla") or {}).get("breached") else 1,
        PRIORITIES.index(f["priority"]) if f.get("priority") in PRIORITIES else 9,
        -(f.get("score") or 0),
    ))
    owned_open = totals["assigned"] + totals["team_only"]
    return {
        "as_of": as_of.isoformat(),
        "totals": {
            **totals,
            "assigned_pct": round(100 * totals["assigned"] / totals["open"], 1) if totals["open"] else 0.0,
            "owned_pct": round(100 * owned_open / totals["open"], 1) if totals["open"] else 0.0,
        },
        "status_counts": status_counts,
        "ageing": [{"bucket": label, **ageing[label]} for label, _, _ in AGE_BUCKETS],
        "by_team": sorted(by_team.values(), key=lambda b: (-b["open"], b["name"].lower())),
        "by_user": sorted(by_user.values(), key=lambda b: (-b["open"], b["email"])),
        "unowned_urgent": [
            {"id": f["id"], "title": f.get("title"), "priority": f.get("priority"),
             "asset": (f.get("asset") or {}).get("name"), "breached": bool((f.get("sla") or {}).get("breached")),
             "due_date": (f.get("sla") or {}).get("due_date")}
            for f in unowned_urgent[:15]
        ],
        "unowned_urgent_total": len(unowned_urgent),
    }
