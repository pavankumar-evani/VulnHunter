"""
Support desk analytics: the figures an ITSM owner is measured on, computed from the
ticket table. Every value is None (not 0) when there is nothing behind it.

Metrics follow common service-desk practice: first-response time, mean time to resolve
(MTTR), SLA compliance (share of finished clocks that met their target), backlog and its
ageing, reopen rate, workload by team and by assignee, and a created-vs-resolved trend.
"""
import datetime

from remediation.support import sla

OPEN = ("open", "in_progress", "waiting_on_requester")
AGE_BUCKETS = (("0-1 days", 0, 1), ("2-7 days", 2, 7), ("8-30 days", 8, 30), ("31+ days", 31, 10**6))


def _hours(a, b):
    a, b = sla.parse(a), sla.parse(b)
    return (b - a).total_seconds() / 3600 if a and b else None


def _avg(values, digits=1):
    values = [v for v in values if v is not None]
    return round(sum(values) / len(values), digits) if values else None


def _pct(num, den):
    return round(num / den * 100) if den else None


def _group(tickets, key):
    out = {}
    for t in tickets:
        out.setdefault(key(t) or "(unassigned)", []).append(t)
    return out


def _team_row(name, rows, as_of):
    open_t = [t for t in rows if t["status"] in OPEN]
    done = [t for t in rows if t.get("resolved_at")]
    return {
        "name": name, "total": len(rows), "open": len(open_t),
        "breached": sum(1 for t in open_t if t["sla"]["breached"]),
        "at_risk": sum(1 for t in open_t if t["sla"]["at_risk"] and not t["sla"]["breached"]),
        "avg_resolution_hours": _avg([_hours(t["created_at"], t["resolved_at"]) for t in done]),
        "sla_compliance_pct": _pct(sum(1 for t in done if t["sla"]["resolution"]["state"] == "met"), len(done)),
    }


def compute(tickets, as_of=None, days=14):
    as_of = as_of or datetime.datetime.now(datetime.timezone.utc)
    open_t = [t for t in tickets if t["status"] in OPEN]
    done = [t for t in tickets if t.get("resolved_at")]
    responded = [t for t in tickets if t.get("first_response_at")]

    finished_clocks = [t["sla"]["resolution"]["state"] for t in done] + [t["sla"]["response"]["state"] for t in responded]
    met = sum(1 for s in finished_clocks if s == "met")

    ageing = []
    for label, lo, hi in AGE_BUCKETS:
        n = 0
        for t in open_t:
            age = (as_of - sla.parse(t["created_at"])).days
            if lo <= age <= hi:
                n += 1
        ageing.append({"bucket": label, "count": n})

    by_priority = {}
    for p in ("P1", "P2", "P3", "P4"):
        rows = [t for t in tickets if t.get("priority") == p]
        d = [t for t in rows if t.get("resolved_at")]
        by_priority[p] = {"total": len(rows), "open": sum(1 for t in rows if t["status"] in OPEN),
                          "mttr_hours": _avg([_hours(t["created_at"], t["resolved_at"]) for t in d]),
                          "first_response_minutes": _avg([(_hours(t["created_at"], t["first_response_at"]) or 0) * 60
                                                          for t in rows if t.get("first_response_at")], 0)}

    trend = []
    for i in range(days - 1, -1, -1):
        day = (as_of - datetime.timedelta(days=i)).date()
        trend.append({"date": day.isoformat(),
                      "created": sum(1 for t in tickets if (sla.parse(t["created_at"]).date() == day)),
                      "resolved": sum(1 for t in done if sla.parse(t["resolved_at"]).date() == day)})

    return {
        "totals": {"tickets": len(tickets), "open": len(open_t), "resolved": len(done),
                   "breached_open": sum(1 for t in open_t if t["sla"]["breached"]),
                   "at_risk_open": sum(1 for t in open_t if t["sla"]["at_risk"] and not t["sla"]["breached"]),
                   "unrouted_open": sum(1 for t in open_t if not t.get("team")),
                   "linked_to_findings": sum(1 for t in tickets if t.get("finding_id"))},
        "first_response_avg_minutes": _avg([(_hours(t["created_at"], t["first_response_at"]) or 0) * 60 for t in responded], 0),
        "mttr_hours": _avg([_hours(t["created_at"], t["resolved_at"]) for t in done]),
        "sla_compliance_pct": _pct(met, len(finished_clocks)),
        "reopen_rate_pct": _pct(sum(1 for t in done if t.get("reopen_count")), len(done)) if done else None,
        "ageing": ageing,
        "by_priority": by_priority,
        "by_team": sorted((_team_row(n, r, as_of) for n, r in _group(tickets, lambda t: t.get("team")).items()),
                          key=lambda r: (-r["open"], r["name"])),
        "by_assignee": sorted((_team_row(n, r, as_of) for n, r in _group(open_t, lambda t: t.get("assignee_email")).items()),
                              key=lambda r: (-r["open"], r["name"])),
        "by_kind": {k: sum(1 for t in tickets if t["kind"] == k) for k in sorted({t["kind"] for t in tickets})},
        "trend": trend,
    }
