"""
The live feed for the incident UI: Server-Sent Events built from the incident event table, so any replica can serve it and a reconnecting browser resumes from
its Last-Event-ID without missing anything. Read-only: the stream carries ids and short labels, never anything a client could send back.

Event types: incident.created, incident.assigned (routed, re-routed, reassigned, unrouted), incident.updated (everything else). The payload says which incident
changed; the client refetches it from GET /api/soc/incidents/{id}. A comment line is sent as a heartbeat so proxies keep the connection open.
"""
import json
import time

from sqlalchemy import func, select

from remediation.soc.incidents import store
from remediation.utils import db as db_module

ASSIGNED = ("routed", "reassigned", "unrouted", "accepted")


def type_for(kind):
    if kind == "created":
        return "incident.created"
    if kind in ASSIGNED:
        return "incident.assigned"
    return "incident.updated"


def latest_id(engine=None):
    engine, t = store.engine_for(engine), db_module.soc_incident_events
    with engine.connect() as conn:
        return conn.execute(select(func.max(t.c.id))).scalar() or 0


def since(after_id, engine=None, limit=200):
    engine, t = store.engine_for(engine), db_module.soc_incident_events
    with engine.connect() as conn:
        rows = conn.execute(select(t).where(t.c.id > int(after_id)).order_by(t.c.id).limit(limit)).mappings().all()
    return [{"id": r["id"], "type": type_for(r["kind"]), "incident_id": r["incident_id"], "kind": r["kind"], "actor": r["actor"], "at": r["created_at"],
             "label": (r["body"] or "")[:160]} for r in rows]


def format_event(ev):
    return f"id: {ev['id']}\nevent: {ev['type']}\ndata: {json.dumps(ev)}\n\n"


def generate(engine=None, after_id=None, max_seconds=None, poll_seconds=None, heartbeat_seconds=None, sleep=time.sleep, clock=time.monotonic):
    """Yields SSE text. With no Last-Event-ID the stream starts at 'now' (the client loads the current state through the list route)."""
    cfg = store.policy().get("stream") or {}
    max_seconds = cfg.get("max_seconds", 3600) if max_seconds is None else max_seconds
    poll = cfg.get("poll_seconds", 2) if poll_seconds is None else poll_seconds
    beat = cfg.get("heartbeat_seconds", 15) if heartbeat_seconds is None else heartbeat_seconds
    cursor = latest_id(engine) if after_id is None else int(after_id)
    start = last_beat = clock()
    yield f": connected, resuming after event {cursor}\nretry: {int(poll * 1000 * 2)}\n\n"
    while True:
        for ev in since(cursor, engine):
            cursor = ev["id"]
            yield format_event(ev)
        now = clock()
        if now - start >= max_seconds:
            yield ": closing, reconnect to continue\n\n"
            return
        if now - last_beat >= beat:
            last_beat = now
            yield ": heartbeat\n\n"
        sleep(poll)
