"""
AI usage analytics: what the organization spends on AI, who and what drives it, and what looks wrong.

Everything is computed from the events (remediation/aiusage/store.py), so it is only as complete as the sources feeding it; `coverage`
says which sources have reported and Quanta says so rather than implying a complete picture. Cost is shown only where it is known:
reported by the source, or estimated from a price the client entered. Events with no known cost are counted separately, never as zero.
"""
import datetime
import fnmatch
import statistics
from pathlib import Path

import yaml
from sqlalchemy import delete, insert, select

from remediation.aiusage import store
from remediation.utils import db as db_module

POLICY = Path(__file__).resolve().parent.parent / "config" / "ai_usage_policy.yaml"
PERIODS = ("day", "week", "month")
SCOPES = ("org", "team", "application")


def policy():
    try:
        return yaml.safe_load(POLICY.read_text(encoding="utf-8")) or {}
    except OSError:
        return {}


def _tokens(r):
    return r["input_tokens"] + r["output_tokens"] + r["cache_read_tokens"] + r["cache_write_tokens"]


def _group(rows, key, label_none="(unattributed)"):
    out = {}
    for r in rows:
        k = r.get(key) or label_none
        g = out.setdefault(k, {"name": k, "requests": 0, "tokens": 0, "cost_usd": 0.0, "cost_known_requests": 0})
        g["requests"] += r["request_count"]
        g["tokens"] += _tokens(r)
        if r["cost_usd"] is not None:
            g["cost_usd"] += r["cost_usd"]
            g["cost_known_requests"] += r["request_count"]
    for g in out.values():
        g["cost_usd"] = round(g["cost_usd"], 4)
        g["cost_complete"] = g["cost_known_requests"] == g["requests"]
    return sorted(out.values(), key=lambda g: (-g["tokens"], g["name"]))


def _day(ts):
    return ts[:10]


def daily(rows):
    out = {}
    for r in rows:
        d = out.setdefault(_day(r["ts"]), {"date": _day(r["ts"]), "tokens": 0, "requests": 0, "cost_usd": 0.0})
        d["tokens"] += _tokens(r)
        d["requests"] += r["request_count"]
        d["cost_usd"] += r["cost_usd"] or 0.0
    return [dict(v, cost_usd=round(v["cost_usd"], 4)) for _k, v in sorted(out.items())]


def anomalies(series, rows, pol=None):
    pol = pol or policy()
    factor, floor = float(pol.get("anomaly_factor", 3.0)), int(pol.get("anomaly_min_tokens", 100000))
    out = []
    for i, d in enumerate(series):
        prior = [x["tokens"] for x in series[max(0, i - 14):i]]
        if len(prior) >= 3:
            med = statistics.median(prior)
            if d["tokens"] >= floor and d["tokens"] > factor * max(med, 1):
                out.append({"kind": "spike", "date": d["date"], "detail": f"{d['tokens']:,} tokens, {d['tokens'] / max(med, 1):.1f}x the median of the previous {len(prior)} days ({int(med):,})."})
    seen_before, first = set(), {}
    for r in sorted(rows, key=lambda x: x["ts"]):
        first.setdefault(r["model"], r["ts"])
    if series:
        last = series[-1]["date"]
        for model, ts in first.items():
            if _day(ts) >= (datetime.date.fromisoformat(last) - datetime.timedelta(days=2)).isoformat() and len(series) > 3:
                out.append({"kind": "new-model", "date": _day(ts), "detail": f"Model {model} appeared for the first time."})
    return out


def _outside_allowed(rows, pol):
    allowed = pol.get("allowed_models") or []
    if not allowed:
        return None
    bad = {}
    for r in rows:
        if not any(fnmatch.fnmatchcase(r["model"], a) for a in allowed):
            b = bad.setdefault(r["model"], {"model": r["model"], "requests": 0, "tokens": 0})
            b["requests"] += r["request_count"]
            b["tokens"] += _tokens(r)
    return sorted(bad.values(), key=lambda b: -b["tokens"])


def summary(days=30, engine=None, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    since = (now - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = store.fetch(since=since, engine=engine)
    total_tokens = sum(_tokens(r) for r in rows)
    reqs = sum(r["request_count"] for r in rows)
    known = [r for r in rows if r["cost_usd"] is not None]
    inp = sum(r["input_tokens"] for r in rows)
    cache_read = sum(r["cache_read_tokens"] for r in rows)
    series = daily(rows)
    pol = policy()
    sources = sorted({r["source"] for r in rows})
    return {
        "days": days,
        "totals": {"requests": reqs, "tokens": total_tokens, "input_tokens": inp, "output_tokens": sum(r["output_tokens"] for r in rows),
                   "cache_read_tokens": cache_read, "cost_usd": round(sum(r["cost_usd"] for r in known), 4),
                   "requests_with_unknown_cost": sum(r["request_count"] for r in rows if r["cost_usd"] is None),
                   "cache_hit_pct": round(100 * cache_read / (inp + cache_read), 1) if (inp + cache_read) else None},
        "daily": series, "by_team": _group(rows, "team"), "by_application": _group(rows, "application"), "by_model": _group(rows, "model"),
        "by_provider": _group(rows, "provider", "(unknown)"), "by_source": _group(rows, "source"),
        "top_users": _group(rows, "user_ref", "(no user recorded)")[:10],
        "anomalies": anomalies(series, rows, pol), "outside_allowed_models": _outside_allowed(rows, pol),
        "budgets": budget_status(engine, now),
        "coverage": {"sources_reporting": sources,
                     "note": ("Only Quanta's own AI calls are counted so far." if sources == ["quanta"] or not sources else
                              "Totals cover the sources listed; AI used through anything not connected is not counted. Check Applications found for unreviewed use.")},
    }


# ---------------------------------------------------------------- budgets
def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def add_budget(scope, scope_value, period, limit_usd, limit_tokens, alert_pct, actor, engine=None):
    if scope not in SCOPES:
        raise ValueError(f"scope must be one of {', '.join(SCOPES)}")
    if scope != "org" and not (scope_value or "").strip():
        raise ValueError("scope_value (the team or application name) is required")
    if period not in PERIODS:
        raise ValueError(f"period must be one of {', '.join(PERIODS)}")
    if limit_usd in (None, "") and limit_tokens in (None, ""):
        raise ValueError("Give a limit in US dollars, in tokens, or both")
    try:
        usd = float(limit_usd) if limit_usd not in (None, "") else None
        tok = int(limit_tokens) if limit_tokens not in (None, "") else None
        pct = int(alert_pct)
    except (TypeError, ValueError):
        raise ValueError("limits must be numbers") from None
    if (usd is not None and usd <= 0) or (tok is not None and tok <= 0) or not 1 <= pct <= 100:
        raise ValueError("limits must be positive and alert_pct between 1 and 100")
    engine = _engine(engine)
    with engine.begin() as conn:
        return conn.execute(insert(db_module.ai_budgets), {
            "scope": scope, "scope_value": (scope_value or "").strip() or None, "period": period, "limit_usd": usd, "limit_tokens": tok,
            "alert_pct": pct, "created_by": actor, "created_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}).inserted_primary_key[0]


def delete_budget(budget_id, engine=None):
    engine = _engine(engine)
    with engine.begin() as conn:
        return conn.execute(delete(db_module.ai_budgets).where(db_module.ai_budgets.c.id == int(budget_id))).rowcount == 1


def _period_bounds(period, now):
    if period == "day":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return start, start + datetime.timedelta(days=1)
    if period == "week":
        start = (now - datetime.timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        return start, start + datetime.timedelta(days=7)
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    nxt = (start.replace(year=start.year + 1, month=1) if start.month == 12 else start.replace(month=start.month + 1))
    return start, nxt


def budget_status(engine=None, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    engine = _engine(engine)
    with engine.connect() as conn:
        budgets = [dict(r) for r in conn.execute(select(db_module.ai_budgets).order_by(db_module.ai_budgets.c.id)).mappings().all()]
    out = []
    for b in budgets:
        start, end = _period_bounds(b["period"], now)
        rows = store.fetch(since=start.strftime("%Y-%m-%dT%H:%M:%SZ"), until=end.strftime("%Y-%m-%dT%H:%M:%SZ"), engine=engine)
        if b["scope"] == "team":
            rows = [r for r in rows if (r.get("team") or "") == b["scope_value"]]
        elif b["scope"] == "application":
            rows = [r for r in rows if (r.get("application") or "") == b["scope_value"]]
        used_usd = sum(r["cost_usd"] or 0 for r in rows)
        used_tokens = sum(_tokens(r) for r in rows)
        pcts = []
        if b["limit_usd"]:
            pcts.append(100 * used_usd / b["limit_usd"])
        if b["limit_tokens"]:
            pcts.append(100 * used_tokens / b["limit_tokens"])
        pct = max(pcts) if pcts else 0
        elapsed = max((now - start).total_seconds(), 1)
        projected = pct * (end - start).total_seconds() / elapsed
        state = "exceeded" if pct >= 100 else "alert" if pct >= b["alert_pct"] else "ok"
        out.append({**b, "period_start": start.strftime("%Y-%m-%d"), "period_end": end.strftime("%Y-%m-%d"), "used_usd": round(used_usd, 4), "used_tokens": used_tokens,
                    "used_pct": round(pct, 1), "projected_pct": round(projected, 1), "state": state,
                    "unknown_cost_requests": sum(r["request_count"] for r in rows if r["cost_usd"] is None) if b["limit_usd"] else 0})
    return out
