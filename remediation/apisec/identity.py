"""
Identity correlated with what each caller reached: the evidence an investigator needs for scraping or data exfiltration.

For one caller (an identity from the records, or an address when the records carried none) this lists every endpoint they used, how much, how many distinct objects
they touched, how many bytes came back, and which of YOUR data classes those endpoints return. Indicators fire on explicit thresholds from api_security.yaml:
  volume        calls to one endpoint in a day at or above scraping_calls_per_actor_day
  exfiltration  bytes returned to the caller in a day at or above exfil_bytes_per_actor_day
  enumeration   distinct object ids on one endpoint in a day at or above bola_distinct_objects_per_actor_day
  probing       at least half of 50 or more calls failed (a caller guessing at ids or paths)
  sensitive     the caller reached endpoints that return data in your sensitive classes (priority at or below severity.sensitive_priority_max)
An indicator is a reason to look, not a verdict. A draft protection policy can be proposed from the indicators; it is never saved or sent on its own.
"""
import datetime

from remediation.apisec import config


def _day_totals(rows):
    d = {}
    for r in rows:
        x = d.setdefault(r["day"], {"calls": 0, "bytes_out": 0})
        x["calls"] += r["calls"]
        x["bytes_out"] += r["bytes_out"]
    return d


def listing(actor_rows, views_by_id, cfg=None, since=None):
    """Callers ranked by volume, with their indicator types, for the investigation list."""
    th = (cfg or config.load())["thresholds"]
    by = {}
    for r in actor_rows:
        if since and r["day"] < since:
            continue
        by.setdefault(r["actor"], []).append(r)
    out = []
    for actor, rows in by.items():
        flags = indicators(actor, rows, views_by_id, th, cfg)
        out.append({"actor": actor, "calls": sum(r["calls"] for r in rows), "bytes_out": sum(r["bytes_out"] for r in rows), "endpoints": len({r["endpoint_id"] for r in rows}),
                    "days": len({r["day"] for r in rows}), "indicators": sorted({f["type"] for f in flags})})
    out.sort(key=lambda x: (-len(x["indicators"]), -x["calls"]))
    return out[:500]


def indicators(actor, rows, views_by_id, th, cfg=None):
    cfg = cfg or config.load()
    out = []
    for r in rows:
        v = views_by_id.get(r["endpoint_id"])
        name = f"{v['method']} {v['template']}" if v else f"endpoint {r['endpoint_id']}"
        if r["calls"] >= th["scraping_calls_per_actor_day"]:
            out.append({"type": "volume", "detail": f"{r['calls']:,} calls to {name} on {r['day']} (limit {th['scraping_calls_per_actor_day']:,}).", "endpoint_id": r["endpoint_id"], "day": r["day"]})
        if r["distinct_objects"] >= th["bola_distinct_objects_per_actor_day"]:
            out.append({"type": "enumeration", "detail": f"{r['distinct_objects']:,} distinct object ids on {name} on {r['day']} (limit {th['bola_distinct_objects_per_actor_day']}).", "endpoint_id": r["endpoint_id"], "day": r["day"]})
        if r["calls"] >= 50 and r["errors"] / r["calls"] >= 0.5:
            out.append({"type": "probing", "detail": f"{r['errors']:,} of {r['calls']:,} calls to {name} on {r['day']} failed.", "endpoint_id": r["endpoint_id"], "day": r["day"]})
    for day, t in sorted(_day_totals(rows).items()):
        if t["bytes_out"] >= th["exfil_bytes_per_actor_day"]:
            out.append({"type": "exfiltration", "detail": f"{t['bytes_out']:,} bytes returned on {day} across all endpoints (limit {th['exfil_bytes_per_actor_day']:,}).", "endpoint_id": None, "day": day})
    smax = cfg["severity"]["sensitive_priority_max"]
    sens = sorted({(v["method"] + " " + v["template"]) for r in rows for v in [views_by_id.get(r["endpoint_id"])] if v and v["data"]["top_priority"] is not None and v["data"]["top_priority"] <= smax})
    if sens:
        out.append({"type": "sensitive", "detail": "Reached endpoints that return your sensitive data classes: " + ", ".join(sens[:6]) + (" ..." if len(sens) > 6 else ""), "endpoint_id": None, "day": None})
    return out


def investigate(actor, actor_rows, views_by_id, cfg=None):
    cfg = cfg or config.load()
    th = cfg["thresholds"]
    rows = [r for r in actor_rows if r["actor"] == actor]
    if not rows:
        return None
    per = {}
    for r in rows:
        p = per.setdefault(r["endpoint_id"], {"endpoint_id": r["endpoint_id"], "calls": 0, "errors": 0, "bytes_out": 0, "max_objects": 0, "days": set(), "ips": set()})
        p["calls"] += r["calls"]
        p["errors"] += r["errors"]
        p["bytes_out"] += r["bytes_out"]
        p["max_objects"] = max(p["max_objects"], r["distinct_objects"])
        p["days"].add(r["day"])
        p["ips"].update(r.get("ips") or [])
    endpoints, classes = [], {}
    for p in per.values():
        v = views_by_id.get(p["endpoint_id"]) or {}
        d = (v.get("data") or {"classes": []})
        for c in d["classes"]:
            classes[c["name"]] = c["priority"]
        endpoints.append({"endpoint_id": p["endpoint_id"], "service": v.get("service"), "method": v.get("method"), "template": v.get("template"), "exposure": v.get("exposure"),
                          "calls": p["calls"], "errors": p["errors"], "bytes_out": p["bytes_out"], "max_distinct_objects": p["max_objects"], "days": len(p["days"]),
                          "data_classes": [c["name"] for c in d["classes"]]})
    endpoints.sort(key=lambda e: -e["calls"])
    ind = indicators(actor, rows, views_by_id, th, cfg)
    ips = sorted({ip for p in per.values() for ip in p["ips"]})[:20]
    days = sorted({r["day"] for r in rows})
    return {"actor": actor, "first_day": days[0], "last_day": days[-1], "days": len(days), "calls": sum(r["calls"] for r in rows), "bytes_out": sum(r["bytes_out"] for r in rows),
            "addresses": ips, "endpoints": endpoints, "data_classes": [{"name": n, "priority": pr} for n, pr in sorted(classes.items(), key=lambda x: (x[1], x[0]))],
            "indicators": ind, "suggested_policies": suggest(actor, endpoints, ind, ips, classes), "note": "Indicators are reasons to look, not verdicts. Drafts are never saved or sent on their own."}


def suggest(actor, endpoints, ind, ips, classes):
    """Draft policies (monitor mode) from the indicators. They are starting points to review, tune from the metrics, and then save."""
    out = []
    types = {i["type"] for i in ind}
    vol = [e for e in endpoints if any(i["type"] in ("volume", "enumeration") and i["endpoint_id"] == e["endpoint_id"] for i in ind)]
    if vol:
        out.append({"name": f"Rate limit for {vol[0]['method']} {vol[0]['template']}", "kind": "rate-limit", "mode": "monitor", "description": f"Drafted from activity by {actor}: tune the limit from the endpoint's metrics.",
                    "scope": {"endpoints": sorted({f"{e['method']} {e['template']}" for e in vol})[:20]}, "params": {"limit": 300, "window_seconds": 300, "by": "ip"}})
    if "exfiltration" in types or "sensitive" in types:
        top = min(classes, key=lambda n: classes[n]) if classes else None
        d = {"name": f"Data-loss limit{(' for ' + top) if top else ''}", "kind": "data-loss", "mode": "monitor", "description": "Drafted from caller activity. Needs an enforcement point that sees responses.",
             "scope": {}, "params": {"by": "actor", "window_seconds": 86400, "max_bytes": 52428800}}
        if top:
            d["params"]["data_class"] = top
        out.append(d)
    if ips and actor.startswith("ip:"):
        out.append({"name": f"Block {ips[0]}", "kind": "malicious-source", "mode": "monitor", "description": f"Drafted from activity by {actor}.", "scope": {}, "params": {"cidrs": ips[:5], "reason": "Investigated: see Quanta caller activity"}})
    return out
