"""
The query playbook runner: a short, fixed, bounded set of read-only searches for an investigation.

plan() decides, once and up front, which searches to run from remediation/config/query_playbook.yaml, the alerts' entities and ATT&CK techniques. It never
looks at a search's result to plan another one, so an investigation cannot recurse into a rabbit hole. run() then runs the plan through `run_fn(query,
earliest, max_rows) -> {count, rows}` and stops at the first budget reached: query count, rows returned, wall-clock time, or repeated errors. The stop
reason is always recorded ("stopped: query budget"), and so is everything that was planned but not run.

Every look-back is capped at `cap_days`, which the caller has already validated (the default ceiling, or a longer one backed by a written justification).
Nothing here talks to a SIEM itself; the caller supplies run_fn from a confirmed, read-only search connection.
"""
import time
from pathlib import Path

import yaml

from remediation.hunting import soc as hunt_soc

PATH = Path(__file__).resolve().parent.parent / "config" / "query_playbook.yaml"


def load(path=None):
    with open(path or PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def budget(cfg):
    b = dict(cfg.get("budget") or {})
    return {"max_queries": int(b.get("max_queries", 6)), "max_rows": int(b.get("max_rows", 100)), "rows_per_query": int(b.get("rows_per_query", 10)),
            "time_budget_seconds": float(b.get("time_budget_seconds", 60)), "max_consecutive_errors": int(b.get("max_consecutive_errors", 2))}


def _tech(alert):
    return (alert.get("technique") or "").upper().split(".")[0]


def plan(alerts, cfg, cap_days, language="splunk-spl"):
    """-> (planned, skipped). planned: [{id, name, purpose, query, days, technique, alert_id}] in priority order (technique-specific patterns first); not truncated."""
    planned, skipped, seen = [], [], set()
    key = hunt_soc.LANG_KEY.get(language, language)
    no_template = set()
    patterns = cfg.get("patterns") or []
    ordered = sorted(patterns, key=lambda p: 0 if (p.get("for") or {}).get("techniques") else 1)
    for pat in ordered:
        want = [t.upper() for t in (pat.get("for") or {}).get("techniques") or []]
        for a in alerts:
            if want and _tech(a) not in want:
                continue
            values = hunt_soc.playbook_values(a)
            missing = [n for n in pat.get("needs") or [] if not values.get(n)]
            if missing:
                continue
            if not pat.get(key):
                if pat["id"] not in no_template:
                    no_template.add(pat["id"])
                    skipped.append({"id": pat["id"], "alert_id": a["id"], "reason": f"no {language} template for this search yet; not translated by guesswork"})
                continue
            query = hunt_soc._fill(pat[key], values)
            if query is None:
                skipped.append({"id": pat["id"], "alert_id": a["id"], "reason": "a value is not plain host, user or address text, so it was not put in a query"})
                continue
            if query in seen:
                continue
            seen.add(query)
            planned.append({"id": pat["id"], "name": pat["name"], "purpose": pat.get("purpose"), "query": query, "days": max(1, min(int(pat.get("lookback_days", 7)), int(cap_days))),
                            "technique": _tech(a) or None, "alert_id": a["id"]})
    return planned, skipped


def run(planned, run_fn, bud, clock=time.monotonic, now_fn=None):
    """-> {results, stop_reason, queries_run, rows_seen, elapsed_seconds, not_run}. `now_fn()` gives the ISO time recorded on each search."""
    now_fn = now_fn or (lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    start = clock()
    results, rows_seen, errors_in_a_row, stop = [], 0, 0, None
    for q in planned:
        if len(results) >= bud["max_queries"]:
            stop = "stopped: query budget"
            break
        if rows_seen >= bud["max_rows"]:
            stop = "stopped: row budget"
            break
        if clock() - start >= bud["time_budget_seconds"]:
            stop = "stopped: time budget"
            break
        if errors_in_a_row >= bud["max_consecutive_errors"]:
            stop = "stopped: repeated errors"
            break
        room = max(1, min(bud["rows_per_query"], bud["max_rows"] - rows_seen))
        base = {"id": q["id"], "name": q["name"], "purpose": q.get("purpose"), "query": q["query"], "lookback_days": q["days"], "technique": q.get("technique"),
                "alert_id": q.get("alert_id"), "ran_at": now_fn()}
        try:
            r = run_fn(q["query"], f"-{q['days']}d", room)
            rows = list(r.get("rows") or [])[:room]
            rows_seen += len(rows)
            errors_in_a_row = 0
            results.append({**base, "count": r.get("count"), "rows": rows, "error": None})
        except Exception as exc:  # noqa: BLE001 - a failed search is evidence of nothing; it is recorded and counted toward the error stop
            errors_in_a_row += 1
            results.append({**base, "count": None, "rows": [], "error": str(exc)[:200]})
    not_run = [{"id": q["id"], "name": q["name"], "query": q["query"]} for q in planned[len(results):]]
    return {"results": results, "stop_reason": stop or "completed", "queries_run": len(results), "rows_seen": rows_seen,
            "elapsed_seconds": round(clock() - start, 3), "not_run": not_run}
