"""
AI usage events: one record per call, or per bucket of calls, from any source that can report them.

This is what makes AI usage visible across the organization rather than only what Quanta itself calls. Events arrive from:
  * "provider-api"  a stored connection to a provider's usage API (Anthropic Usage & Cost Admin API, OpenAI organization usage);
                    these are hourly or daily BUCKETS, so one event stands for `request_count` requests;
  * "otel"          an application instrumented with the OpenTelemetry GenAI conventions, sending OTLP/HTTP JSON traces;
  * "gateway"/"api" a gateway, proxy or any script posting events to /api/ingest/ai-usage;
  * "quanta"        Quanta's own Claude calls (read from ai_usage_log at query time, not copied).

Privacy by design: an event holds counts, model, time and attribution (team, application, a user reference). It never holds a
prompt or a response. `user_ref` is whatever the sender provides; send a pseudonymous id (a hash) if you do not want people
identifiable in the report.

Identity: (source, event_key) is unique, so re-sending the same bucket or request updates it rather than doubling the totals.
"""
import datetime
from remediation.utils.digest import dedup_sha1

from sqlalchemy import insert, select, update

from remediation.utils import db as db_module

MAX_BATCH = 5000
SOURCES = ("provider-api", "otel", "gateway", "api")


class UsageError(ValueError):
    pass


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def _int(v, field):
    if v in (None, ""):
        return 0
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise UsageError(f"{field} must be a whole number") from None
    if n < 0:
        raise UsageError(f"{field} cannot be negative")
    return n


def _ts(v):
    if not v:
        return _now()
    s = str(v)
    try:
        d = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise UsageError(f"ts {v!r} is not an ISO 8601 time") from None
    if d.tzinfo is None:
        d = d.replace(tzinfo=datetime.timezone.utc)
    return d.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalise(ev, source):
    """One incoming event dict -> a row dict. Raises UsageError naming the problem."""
    if not isinstance(ev, dict):
        raise UsageError("each event must be an object")
    model = str(ev.get("model") or "").strip()[:120]
    if not model:
        raise UsageError("model is required")
    row = {
        "ts": _ts(ev.get("ts") or ev.get("timestamp")), "source": source,
        "provider": str(ev.get("provider") or "").strip().lower()[:60] or None, "model": model,
        "team": str(ev.get("team") or "").strip()[:80] or None, "application": str(ev.get("application") or ev.get("app") or "").strip()[:120] or None,
        "user_ref": str(ev.get("user_ref") or ev.get("user") or "").strip()[:120] or None,
        "input_tokens": _int(ev.get("input_tokens"), "input_tokens"), "output_tokens": _int(ev.get("output_tokens"), "output_tokens"),
        "cache_read_tokens": _int(ev.get("cache_read_tokens"), "cache_read_tokens"),
        "cache_write_tokens": _int(ev.get("cache_write_tokens"), "cache_write_tokens"),
        "request_count": max(1, _int(ev.get("request_count") or 1, "request_count")),
        "latency_ms": _int(ev.get("latency_ms"), "latency_ms") if ev.get("latency_ms") not in (None, "") else None,
        "cost_usd": None, "cost_basis": "unknown",
    }
    if ev.get("cost_usd") not in (None, ""):
        try:
            row["cost_usd"] = round(float(ev["cost_usd"]), 6)
        except (TypeError, ValueError):
            raise UsageError("cost_usd must be a number") from None
        if row["cost_usd"] < 0:
            raise UsageError("cost_usd cannot be negative")
        row["cost_basis"] = "reported"
    key = ev.get("event_key") or ev.get("request_id")
    row["event_key"] = str(key)[:200] if key else dedup_sha1("|".join(str(row[k]) for k in (
        "ts", "model", "team", "application", "user_ref", "input_tokens", "output_tokens", "cache_read_tokens")).encode()).hexdigest()
    return row


def record(events, source, engine=None, source_mode=None):
    """Stores events, updating any already seen. Returns {recorded, updated, rejected, errors[:50]}. Estimated cost is filled from the
    price table when the sender gave none and a price exists for the model.

    `source_mode` is the provenance of this batch: "simulation" marks demonstration data (column `source_mode`; None is live). It is not part of
    the unique key. A simulated batch never changes a live event that has the same key (counted as `kept_live`); a live batch that meets a
    simulated event replaces it with the real one."""
    from remediation.aiusage import pricing
    if source not in SOURCES:
        raise UsageError(f"source must be one of {', '.join(SOURCES)}")
    if len(events) > MAX_BATCH:
        raise UsageError(f"At most {MAX_BATCH} events per request")
    engine, t = _engine(engine), db_module.ai_usage_events
    table, recorded, updated, kept_live, errors = pricing.load(), 0, 0, 0, []
    mode = source_mode if source_mode == "simulation" else None
    with engine.begin() as conn:
        for i, ev in enumerate(events):
            try:
                row = normalise(ev, source)
            except UsageError as exc:
                errors.append({"index": i, "error": str(exc)})
                continue
            if row["cost_usd"] is None:
                est = pricing.estimate(row, table)
                if est is not None:
                    row["cost_usd"], row["cost_basis"] = est, "estimated"
            row["source_mode"] = mode
            existing = conn.execute(select(t.c.id, t.c.source_mode).where(t.c.source == source, t.c.event_key == row["event_key"])).first()
            if existing:
                if mode == "simulation" and existing.source_mode != "simulation":
                    kept_live += 1
                    continue
                conn.execute(update(t).where(t.c.id == existing.id).values(**row))
                updated += 1
            else:
                conn.execute(insert(t), {**row, "received_at": _now()})
                recorded += 1
    out = {"recorded": recorded, "updated": updated, "rejected": len(errors), "errors": errors[:50]}
    if kept_live:
        out["kept_live"] = kept_live
    return out


def remove_simulated(engine=None):
    """Deletes every simulated usage event (live events are never touched). Returns how many were removed."""
    from sqlalchemy import delete
    engine, t = _engine(engine), db_module.ai_usage_events
    with engine.begin() as conn:
        return conn.execute(delete(t).where(t.c.source_mode == "simulation")).rowcount


def count_simulated(engine=None):
    from sqlalchemy import func
    engine, t = _engine(engine), db_module.ai_usage_events
    with engine.connect() as conn:
        return conn.execute(select(func.count()).select_from(t).where(t.c.source_mode == "simulation")).scalar() or 0


def fetch(since=None, until=None, engine=None):
    """Raw event rows in [since, until) (ISO strings), plus Quanta's own calls from ai_usage_log mapped to the same shape."""
    engine, t = _engine(engine), db_module.ai_usage_events
    q = select(t)
    if since:
        q = q.where(t.c.ts >= since)
    if until:
        q = q.where(t.c.ts < until)
    with engine.connect() as conn:
        rows = [dict(r) for r in conn.execute(q.order_by(t.c.ts)).mappings().all()]
    rows += _quanta_own(since, until, engine)
    return rows


def _quanta_own(since, until, engine):
    import json
    log = db_module.ai_usage_log
    with engine.connect() as conn:
        raw = [dict(r) for r in conn.execute(select(log)).mappings().all()]
    out = []
    for r in raw:
        ts = str(r.get("timestamp") or "")
        if not ts or (since and ts < since) or (until and ts >= until):
            continue
        try:
            u = json.loads(r.get("usage") or "{}") or {}
        except ValueError:
            u = {}

        def tok(*names):
            for n in names:
                if isinstance(u.get(n), (int, float)):
                    return int(u[n])
            return 0
        out.append({
            "id": f"q{r.get('id')}", "ts": ts, "source": "quanta", "provider": "anthropic", "model": r.get("model") or "unknown",
            "team": None, "application": f"Quanta: {r.get('route') or 'ai'}", "user_ref": r.get("actor"),
            "input_tokens": tok("input_tokens", "inputTokens"), "output_tokens": tok("output_tokens", "outputTokens"),
            "cache_read_tokens": tok("cache_read_input_tokens", "cacheReadInputTokens"),
            "cache_write_tokens": tok("cache_creation_input_tokens", "cacheCreationInputTokens"),
            "request_count": 1, "latency_ms": None, "cost_usd": r.get("total_cost_usd"),
            "cost_basis": "reported" if r.get("total_cost_usd") is not None else "unknown",
        })
    return out
