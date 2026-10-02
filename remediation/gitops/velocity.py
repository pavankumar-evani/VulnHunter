"""
Remediation velocity: how quickly fixes move from a finding to a verified closure, measured from the proposals' own timestamps.

Every figure is computed from recorded times: created, approved, opened, merged, and the first time a scan showed the findings gone. A stage with no data
reports no number rather than zero. "Verified" means the findings are no longer reported, which is evidence the fix held (it is also what you would see if
the application left scan scope).
"""
import datetime
import statistics


def _dt(v):
    if not v:
        return None
    try:
        return datetime.datetime.strptime(v[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        try:
            return datetime.datetime.strptime(v[:10], "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            return None


def _hours(a, b):
    a, b = _dt(a), _dt(b)
    return (b - a).total_seconds() / 3600.0 if a and b and b >= a else None


def _stats(values):
    v = sorted(x for x in values if x is not None)
    if not v:
        return {"n": 0, "median_hours": None, "p90_hours": None}
    return {"n": len(v), "median_hours": round(statistics.median(v), 1), "p90_hours": round(v[min(len(v) - 1, int(round(0.9 * (len(v) - 1))))], 1)}


def compute(proposals, findings, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    by_id = {f["id"]: f for f in findings}
    by_status = {}
    for p in proposals:
        by_status[p["status"]] = by_status.get(p["status"], 0) + 1
    open_prs = [p for p in proposals if p["status"] in ("pr-opened", "in-review")]
    ages = [(now - _dt(p["opened_at"])).total_seconds() / 3600.0 for p in open_prs if _dt(p["opened_at"])]
    detect_to_pr = []
    for p in proposals:
        if p["opened_at"]:
            firsts = [_dt(by_id[f]["first_seen"]) for f in p["finding_ids"] if f in by_id and by_id[f].get("first_seen")]
            if firsts:
                detect_to_pr.append(((_dt(p["opened_at"]) - min(firsts)).total_seconds() / 3600.0) if _dt(p["opened_at"]) >= min(firsts) else None)
    weeks = {}
    for p in proposals:
        d = _dt(p["merged_at"])
        if d:
            y, w, _ = d.isocalendar()
            weeks[f"{y}-W{w:02d}"] = weeks.get(f"{y}-W{w:02d}", 0) + 1
    start = now - datetime.timedelta(weeks=11)
    series = []
    for i in range(12):
        y, w, _ = (start + datetime.timedelta(weeks=i)).isocalendar()
        series.append({"week": f"{y}-W{w:02d}", "merged": weeks.get(f"{y}-W{w:02d}", 0)})
    merged = [p for p in proposals if p["status"] == "merged"]
    apps = {}
    for p in proposals:
        a = apps.setdefault(p["application"], {"application": p["application"], "proposals": 0, "opened": 0, "merged": 0, "verified": 0, "still_present": 0})
        a["proposals"] += 1
        a["opened"] += 1 if p["opened_at"] else 0
        a["merged"] += 1 if p["status"] == "merged" else 0
        a["verified"] += 1 if p["verified_state"] == "verified" else 0
        a["still_present"] += 1 if p["verified_state"] == "still-present" else 0
    return {
        "proposals": len(proposals), "by_status": by_status,
        "open_pull_requests": {"count": len(open_prs), "oldest_hours": round(max(ages), 1) if ages else None, "median_age_hours": round(statistics.median(ages), 1) if ages else None,
                               "waiting_for_review": sum(1 for p in open_prs if p["review_state"] in (None, "none")), "changes_requested": sum(1 for p in open_prs if p["review_state"] == "changes-requested"),
                               "failing_checks": sum(1 for p in open_prs if p["checks_state"] == "failing")},
        "stages": {"created_to_approved": _stats([_hours(p["created_at"], p["approved_at"]) for p in proposals]), "approved_to_opened": _stats([_hours(p["approved_at"], p["opened_at"]) for p in proposals]),
                   "opened_to_merged": _stats([_hours(p["opened_at"], p["merged_at"]) for p in proposals]), "merged_to_verified": _stats([_hours(p["merged_at"], p["verified_at"]) for p in proposals]),
                   "detected_to_pull_request": _stats(detect_to_pr), "created_to_verified": _stats([_hours(p["created_at"], p["verified_at"]) for p in proposals])},
        "outcomes": {"merged": len(merged), "verified": sum(1 for p in merged if p["verified_state"] == "verified"), "still_present": sum(1 for p in merged if p["verified_state"] == "still-present"),
                     "awaiting_rescan": sum(1 for p in merged if p["verified_state"] in (None, "awaiting-rescan")),
                     "closed_unmerged": by_status.get("closed", 0), "failed": by_status.get("failed", 0)},
        "merged_per_week": series, "by_application": sorted(apps.values(), key=lambda a: -a["proposals"]),
        "note": "Times come from the moments Quanta recorded. Verified means the findings are no longer reported; it is evidence, not proof.",
    }
