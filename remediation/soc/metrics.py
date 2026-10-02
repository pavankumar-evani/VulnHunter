"""
Security operations metrics, computed from the cases and alerts already stored. Nothing is estimated and nothing is kept separately: every figure is a count or an average
over timestamps on the case, so it cannot drift from the case history.

  MTTA  mean minutes from case created to acknowledged (cases acknowledged in the window)
  MTTR  mean minutes from case created to resolved (cases resolved in the window); the median and 90th percentile are shown too because a mean hides a long tail
  SLA   per clock (ack, pickup, resolve) the share of finished clocks that were met, plus how many open cases are currently at risk or breached
  Backlog   open cases by queue and by priority, and the age of the oldest
  Escalation rate  cases that moved up a tier at least once / cases opened; auto-escalation share; reopen rate = reopened / resolved
  Resolution mix   how resolved cases were classified; false-positive rate = (false-positive + benign + duplicate) / resolved
  Recommendation accuracy   when the system recommended likely-true-positive, how often the analyst resolved true-positive; likely-false-positive vs
                            false-positive, benign or duplicate; escalate-l2 vs a case that actually reached L2 or above. Only cases with both a recommendation and a resolution count.
  Automation rate   cases opened automatically / all cases
  Analyst workload  per analyst: open, resolved in the window, mean time to resolve
  Daily series      opened and resolved per day over the window
"""
import datetime
import statistics

from remediation.soc import cases as cases_module

FP_CODES = ("false-positive", "benign", "duplicate")


def _mean(xs):
    return round(sum(xs) / len(xs), 1) if xs else None


def _pct(xs, p):
    if not xs:
        return None
    s = sorted(xs)
    return round(s[min(len(s) - 1, int(round(p * (len(s) - 1))))], 1)


def _ratio(a, b):
    return round(a / b, 3) if b else None


def _mins(c, a, b):
    x, y = cases_module._parse(c.get(a)), cases_module._parse(c.get(b))
    return (y - x).total_seconds() / 60 if x and y else None


def compute(engine=None, days=30, now=None):
    now = now or cases_module._now_dt()
    since = now - datetime.timedelta(days=days)
    allc = cases_module.list_cases(engine, now=now)
    opened = [c for c in allc if cases_module._parse(c["created_at"]) >= since]
    resolved = [c for c in allc if c["resolved_at"] and cases_module._parse(c["resolved_at"]) >= since]
    acked = [c for c in allc if c["acknowledged_at"] and cases_module._parse(c["acknowledged_at"]) >= since]
    open_cases = [c for c in allc if c["status"] in cases_module.OPEN]

    ttr = [m for m in (_mins(c, "created_at", "resolved_at") for c in resolved) if m is not None]
    tta = [m for m in (_mins(c, "created_at", "acknowledged_at") for c in acked) if m is not None]

    sla_out = {}
    for clock in ("ack", "pickup", "resolve"):
        fin = [c["sla"][clock] for c in allc if c["sla"].get(clock) and c["sla"][clock]["done"]]
        met = sum(1 for x in fin if x["state"] == "met")
        live = [c["sla"][clock]["state"] for c in open_cases if c["sla"].get(clock) and not c["sla"][clock]["done"]]
        sla_out[clock] = {"finished": len(fin), "met": met, "compliance": _ratio(met, len(fin)), "open_at_risk": live.count("at_risk"), "open_breached": live.count("breached")}

    by_queue, by_prio = {}, {}
    for c in open_cases:
        by_queue[c["queue"]] = by_queue.get(c["queue"], 0) + 1
        by_prio[c["priority"]] = by_prio.get(c["priority"], 0) + 1
    oldest = max(((now - cases_module._parse(c["created_at"])).total_seconds() / 3600 for c in open_cases), default=None)
    unowned = sum(1 for c in open_cases if not c["assignee"])

    mix = {}
    for c in resolved:
        mix[c["resolution"]] = mix.get(c["resolution"], 0) + 1
    fp = sum(mix.get(k, 0) for k in FP_CODES)

    acc = {"likely-true-positive": [0, 0], "likely-false-positive": [0, 0], "escalate-l2": [0, 0]}
    for c in allc:
        rec = c.get("recommendation")
        if rec not in acc or not c["resolution"]:
            continue
        acc[rec][1] += 1
        if rec == "likely-true-positive" and c["resolution"] == "true-positive":
            acc[rec][0] += 1
        elif rec == "likely-false-positive" and c["resolution"] in FP_CODES:
            acc[rec][0] += 1
        elif rec == "escalate-l2" and (c["tier"] >= 2 or c["escalation_count"] > 0):
            acc[rec][0] += 1
    accuracy = {k: {"agreed": v[0], "judged": v[1], "rate": _ratio(v[0], v[1])} for k, v in acc.items()}
    judged = sum(v[1] for v in acc.values())

    people = {}
    for c in allc:
        if not c["assignee"]:
            continue
        p = people.setdefault(c["assignee"], {"analyst": c["assignee"], "open": 0, "resolved": 0, "_t": []})
        if c["status"] in cases_module.OPEN:
            p["open"] += 1
        if c in resolved:
            p["resolved"] += 1
            m = _mins(c, "created_at", "resolved_at")
            if m is not None:
                p["_t"].append(m)
    workload = sorted(({"analyst": p["analyst"], "open": p["open"], "resolved": p["resolved"], "mean_minutes_to_resolve": _mean(p["_t"])} for p in people.values()),
                      key=lambda x: -x["open"])

    series = {}
    for i in range(days):
        series[(since + datetime.timedelta(days=i + 1)).strftime("%Y-%m-%d")] = {"opened": 0, "resolved": 0}
    for c in opened:
        d = c["created_at"][:10]
        if d in series:
            series[d]["opened"] += 1
    for c in resolved:
        d = c["resolved_at"][:10]
        if d in series:
            series[d]["resolved"] += 1

    return {
        "window_days": days, "generated_at": cases_module._iso(now),
        "totals": {"opened": len(opened), "resolved": len(resolved), "open_now": len(open_cases), "unowned_open": unowned},
        "mtta_minutes": _mean(tta), "mttr_minutes": _mean(ttr), "mttr_median_minutes": round(statistics.median(ttr), 1) if ttr else None, "mttr_p90_minutes": _pct(ttr, 0.9),
        "sla": sla_out,
        "backlog": {"by_queue": by_queue, "by_priority": by_prio, "oldest_open_hours": round(oldest, 1) if oldest is not None else None},
        "escalation": {"rate": _ratio(sum(1 for c in opened if c["escalation_count"]), len(opened)),
                       "auto_share": _ratio(sum(1 for c in opened if c["auto_escalated_tiers"]), sum(1 for c in opened if c["escalation_count"])),
                       "reopen_rate": _ratio(sum(1 for c in resolved if c["reopen_count"]), len(resolved))},
        "resolution_mix": mix, "false_positive_rate": _ratio(fp, len(resolved)),
        "recommendation_accuracy": accuracy, "recommendation_judged": judged,
        "automation_rate": _ratio(sum(1 for c in opened if c["source"] == "auto"), len(opened)),
        "analyst_workload": workload,
        "daily": [{"date": d, **v} for d, v in sorted(series.items())],
    }
