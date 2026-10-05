"""
Endpoint metrics: calls, latency, errors, bytes, distinct callers and security events per endpoint per day, with a trend.

Imported or derived, never invented. The error RATE is not stored: it is errors divided by calls, computed here, exactly as the source of the numbers defines it
(an error is a response with status 400 or above; an exception is 500 or above). Latency is reported as an average and a maximum because the records carry
individual timings that were summed on the way in, not a distribution: a percentile would be a guess. Distinct callers are counted from the caller rows, so a caller
seen in two uploads is counted once. A trend compares the latest window with the one before and says nothing when either window has too few calls.
"""
import datetime

from remediation.apisec import config


def rate(errors, calls):
    return round(errors / calls, 4) if calls else None


def _sum(rows):
    calls = sum(r["calls"] for r in rows)
    n = sum(r["latency_n"] for r in rows)
    mx = [r["latency_max_ms"] for r in rows if r["latency_max_ms"] is not None]
    errors = sum(r["errors"] for r in rows)
    return {"calls": calls, "errors": errors, "exceptions": sum(r["exceptions"] for r in rows), "error_rate": rate(errors, calls),
            "avg_latency_ms": round(sum(r["latency_sum_ms"] for r in rows) / n, 1) if n else None, "max_latency_ms": max(mx) if mx else None,
            "bytes_in": sum(r["bytes_in"] for r in rows), "bytes_out": sum(r["bytes_out"] for r in rows), "security_events": sum(r["security_events"] for r in rows)}


def series(rows):
    """Daily points for one endpoint, oldest first."""
    return [{"day": r["day"], **_sum([r])} for r in sorted(rows, key=lambda r: r["day"])]


def _window(rows, start, end):
    s, e = start.isoformat(), end.isoformat()
    return [r for r in rows if s <= r["day"] <= e]


def trend(rows, today=None, cfg=None):
    """Latest window against the one before it: [{metric, previous, recent, change, note}] for the metrics that moved more than the thresholds."""
    th = (cfg or config.load())["thresholds"]
    today = today or datetime.date.today()
    w = th["trend_window_days"]
    recent = _sum(_window(rows, today - datetime.timedelta(days=w - 1), today))
    prev = _sum(_window(rows, today - datetime.timedelta(days=2 * w - 1), today - datetime.timedelta(days=w)))
    base = {"window_days": w, "recent": recent, "previous": prev, "flags": []}
    if recent["calls"] < th["trend_min_calls"] or prev["calls"] < th["trend_min_calls"]:
        base["note"] = f"Too few calls to compare (needs {th['trend_min_calls']} in each {w}-day window)."
        return base
    chg = (recent["calls"] - prev["calls"]) / prev["calls"] * 100
    if abs(chg) >= th["trend_calls_change_pct"]:
        base["flags"].append({"metric": "calls", "previous": prev["calls"], "recent": recent["calls"], "change": f"{chg:+.0f}%"})
    if recent["error_rate"] is not None and prev["error_rate"] is not None and recent["error_rate"] - prev["error_rate"] >= th["trend_error_rate_delta"]:
        base["flags"].append({"metric": "error rate", "previous": prev["error_rate"], "recent": recent["error_rate"], "change": f"{(recent['error_rate'] - prev['error_rate']) * 100:+.1f} points"})
    if recent["avg_latency_ms"] and prev["avg_latency_ms"]:
        lc = (recent["avg_latency_ms"] - prev["avg_latency_ms"]) / prev["avg_latency_ms"] * 100
        if lc >= th["trend_latency_change_pct"]:
            base["flags"].append({"metric": "average latency", "previous": prev["avg_latency_ms"], "recent": recent["avg_latency_ms"], "change": f"{lc:+.0f}%"})
    if recent["security_events"] > prev["security_events"] and recent["security_events"] >= 5:
        base["flags"].append({"metric": "security events", "previous": prev["security_events"], "recent": recent["security_events"], "change": f"{recent['security_events'] - prev['security_events']:+d}"})
    return base


def overview(endpoints, metric_rows, actor_rows, days=30, today=None, cfg=None):
    """Per-endpoint summary over the last `days`, plus the whole-estate total and the endpoints whose trend moved."""
    today = today or datetime.date.today()
    since = (today - datetime.timedelta(days=days - 1)).isoformat()
    by_ep, actors = {}, {}
    for r in metric_rows:
        by_ep.setdefault(r["endpoint_id"], []).append(r)
    for a in actor_rows:
        if a["day"] >= since:
            actors.setdefault(a["endpoint_id"], set()).add(a["actor"])
    out, moved = [], []
    for ep in endpoints:
        rows = by_ep.get(ep["id"], [])
        recent = [r for r in rows if r["day"] >= since]
        if not recent:
            continue
        s = _sum(recent)
        t = trend(rows, today, cfg)
        item = {"endpoint_id": ep["id"], "service": ep["service"], "method": ep["method"], "template": ep["template"], **s, "distinct_actors": len(actors.get(ep["id"], ())), "flags": t["flags"]}
        out.append(item)
        if t["flags"]:
            moved.append(item)
    out.sort(key=lambda x: -x["calls"])
    allrows = [r for rows in by_ep.values() for r in rows if r["day"] >= since]
    return {"days": days, "total": _sum(allrows) if allrows else None, "endpoints": out, "moved": moved,
            "definition": "Error rate = errors / calls, where an error is a response with status 400 or above. Latency is an average and a maximum of the timings in the records; Quanta does not compute percentiles."}
