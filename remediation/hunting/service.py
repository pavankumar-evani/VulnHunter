"""
The database-backed glue for hunting and triage: running a hunt lead in the SIEM, keeping threat-intel reports, and keeping investigations.

Connections are the ones an administrator stored on the Connections page (credentials encrypted there). A search or a reputation lookup only
ever happens because a person asked for it on a specific hunt or alert; nothing here runs on a schedule.
"""
import datetime
import json

from sqlalchemy import insert, select, update

from remediation.connections import registry, store as conn_store
from remediation.hunting import store as hunt_store, translate
from remediation.utils import db as db_module


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def find_connection(conn_type, connection_id=None, engine=None):
    """The stored connection to use: the one asked for, else the first enabled one of that type. Returns (public, values) or (None, None)."""
    if connection_id:
        public, values = conn_store.get_values(int(connection_id), engine)
        return (public, values) if public and public["type"] == conn_type else (None, None)
    for c in conn_store.list_connections(engine):
        if c["type"] == conn_type and c["enabled"]:
            return conn_store.get_values(c["id"], engine)
    return None, None


def connector(conn_type, connection_id=None, engine=None):
    public, values = find_connection(conn_type, connection_id, engine)
    if not public:
        return None, None
    registry.split_values(conn_type, values)  # the SSRF guard again at use time
    return registry.SPECS[conn_type]["build"](values), public


def search_connector(connection_id=None, engine=None):
    """The read-only search connection to use, whatever the product: the one named by `connection_id` (any of registry.SEARCH_TYPES), else the first enabled one
    in registry.SEARCH_TYPES order (Splunk first). Returns (connector, public) or (None, None). Raises ValueError for an id that is not a search connection."""
    if connection_id:
        public = conn_store.get_values(int(connection_id), engine)[0]
        if public and public["type"] not in registry.SEARCH_TYPES:
            raise ValueError(f"Connection {connection_id} is a {public['type']} connection, not a search connection")
        return connector(public["type"] if public else "splunk-search", connection_id, engine)
    for t in registry.SEARCH_TYPES:
        if t != "splunk-search" and not find_connection(t, None, engine)[0]:
            continue
        c, p = connector(t, None, engine)
        if c:
            return c, p
    return None, None


LANGUAGE_OF_TYPE = {"splunk-search": "splunk-spl", "sentinel-search": "kql", "chronicle-search": "udm", "falcon-search": "fql", "elastic-search": "esql"}


def connection_language(public):
    """The query language of a stored search connection, read from its type and settings; builds nothing and contacts nothing (used by the dry-run plan)."""
    if public["type"] == "elastic-search":
        return (public.get("config") or {}).get("language") or "esql"
    return LANGUAGE_OF_TYPE.get(public["type"], "splunk-spl")


def find_search_connection(connection_id=None, engine=None):
    """The stored (public view only) search connection that search_connector() would pick, without building a connector. Returns public or None."""
    if connection_id:
        public = conn_store.get_values(int(connection_id), engine)[0]
        if public and public["type"] not in registry.SEARCH_TYPES:
            raise ValueError(f"Connection {connection_id} is a {public['type']} connection, not a search connection")
        return public
    for t in registry.SEARCH_TYPES:
        public = find_connection(t, None, engine)[0]
        if public:
            return public
    return None


def language_of(connector_obj):
    return getattr(connector_obj, "language", None) or "splunk-spl"


def prepare_lead(q, language):
    """-> (query text, language) for a hunt lead on a connection that speaks `language`. Raises translate.NotExpressible, with a reason, when it cannot be written
    there (never a silent drop): a lead is rendered from its stored Sigma-style selection; a hand-written lead only runs where it was written."""
    if q.get("language") == language and q.get("query"):
        return q["query"], language
    if q.get("selection"):
        return translate.render(language, q["selection"], q.get("hosts") or None, q.get("index") if language == "splunk-spl" else None), language
    if language == "kql" and q.get("kql"):
        return q["kql"], language
    if language == "splunk-spl" and q.get("query"):
        return q["query"], language
    raise translate.NotExpressible(f"this lead was written in {q.get('language') or 'another language'} and carries no selection to render in {language}")


def plan_hunt(hunt, language, earliest="-24h", cap=30, only_unrun=True):
    """The dry-run view of run-all: what would run, in which language, over what window. Never touches a connection."""
    rows, todo = [], 0
    for i, q in enumerate(hunt["queries"]):
        row = {"index": i, "name": q.get("name"), "technique": q.get("technique"), "language": language, "window": earliest, "query": None, "state": "would-run", "reason": None}
        if not q.get("query") and not q.get("selection"):
            row.update(state="skipped", reason="the lead has no query")
        elif only_unrun and q.get("result") in ("hits", "no-hits"):
            row.update(state="skipped", reason="already run; send only_unrun false to run it again")
        else:
            try:
                row["query"] = prepare_lead(q, language)[0]
            except translate.NotExpressible as exc:
                row.update(state="not-expressible", reason=str(exc)[:200])
            else:
                todo += 1
                if todo > cap:
                    row.update(state="over-cap", reason=f"past the {cap}-search cap for one run")
        rows.append(row)
    return {"leads": rows, "would_run": sum(1 for r in rows if r["state"] == "would-run"), "language": language, "window": earliest, "cap": cap}


def run_hunt_query(hunt_id, index, connector_obj, earliest="-24h", max_rows=25, engine=None, connection_name=None):
    """Runs lead `index` of a hunt and records the count, a short sample, when it ran, and the exact query text, language and connection used. Raises KeyError/IndexError
    for a bad id. A search error is recorded on the lead (result 'error') and re-raised. A lead the connection's language cannot express is recorded as
    'not-expressible' with the reason and nothing is sent."""
    hunt = hunt_store.get_hunt(hunt_id, engine)
    if not hunt:
        raise KeyError("No such hunt")
    if index < 0 or index >= len(hunt["queries"]):
        raise IndexError("No such query")
    q = hunt["queries"][index]
    language = language_of(connector_obj)
    q["ran_at"], q["window"], q["language_run"], q["connection"] = _now(), earliest, language, connection_name
    try:
        text, _ = prepare_lead(q, language)
    except translate.NotExpressible as exc:
        q.update({"result": "not-expressible", "count": None, "sample": [], "error": None, "query_run": None, "not_expressible_reason": str(exc)[:300]})
        hunt_store.update_hunt(hunt_id, {"queries": hunt["queries"]}, engine)
        return q
    q["query_run"], q["not_expressible_reason"] = text, None
    try:
        r = connector_obj.search(text, earliest=earliest, max_rows=max_rows)
        q.update({"result": "hits" if r["count"] else "no-hits", "count": r["count"], "sample": r["rows"], "truncated": r["truncated"], "error": None, "took_ms": r.get("took_ms")})
    except Exception as exc:  # noqa: BLE001 - recorded on the lead, then re-raised
        q.update({"result": "error", "count": None, "sample": [], "error": str(exc)[:300]})
        hunt_store.update_hunt(hunt_id, {"queries": hunt["queries"]}, engine)
        raise
    if hunt["status"] == "proposed":
        hunt_store.update_hunt(hunt_id, {"queries": hunt["queries"], "status": "active"}, engine)
    else:
        hunt_store.update_hunt(hunt_id, {"queries": hunt["queries"]}, engine)
    return q


# ---------------------------------------------------------------- threat intel reports
def save_intel(title, source, content_hash, extracted, score, priority, reasons, actor, engine=None, published_at=None, source_id=None, external_id=None, url=None, trigger=None):
    """Stores a report once (by content hash). `published_at` is when the source published it, when known; `fetched_at` is always now: the hunt report's time-to-report
    clock starts at the earlier-known of the two (see with_clock_start). Returns (id, created)."""
    engine, t = _engine(engine), db_module.threat_intel_reports
    now = _now()
    with engine.begin() as conn:
        existing = conn.execute(select(t.c.id).where(t.c.content_hash == content_hash)).first()
        if existing:
            return existing[0], False
        rid = conn.execute(insert(t), {"title": title[:200], "source": (source or None), "content_hash": content_hash, "extracted_json": json.dumps(extracted),
                                       "relevance": score, "priority": priority, "reasons_json": json.dumps(reasons), "hunt_id": None, "received_by": actor,
                                       "received_at": now, "fetched_at": now, "published_at": published_at, "source_id": source_id, "external_id": (external_id or None) and external_id[:300],
                                       "url": (url or None) and url[:500], "trigger_json": json.dumps(trigger) if trigger else None}).inserted_primary_key[0]
    return rid, True


def set_intel_trigger(report_id, trigger, engine=None):
    engine, t = _engine(engine), db_module.threat_intel_reports
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.id == int(report_id)).values(trigger_json=json.dumps(trigger)))


def intel_seen(source_id, external_id, engine=None):
    engine, t = _engine(engine), db_module.threat_intel_reports
    with engine.connect() as conn:
        return conn.execute(select(t.c.id).where(t.c.source_id == int(source_id), t.c.external_id == external_id)).first() is not None


def _intel(r):
    d = dict(r)
    d["extracted"] = json.loads(d.pop("extracted_json"))
    d["reasons"] = json.loads(d.pop("reasons_json"))
    d["trigger"] = json.loads(d.pop("trigger_json")) if d.get("trigger_json") else None
    d.pop("trigger_json", None)
    return d


def clock_start_for(hunt, engine=None):
    """-> (iso time, source) the hunt's time-to-report clock starts at: the arrival of the threat-intel report that caused the hunt (the source's published_at when
    known, else when Quanta fetched or received it), or (None, None) for any other hunt. Covers a hunt made straight from a report and a hunt accepted from an
    engine suggestion whose evidence names a report."""
    ids = []
    if hunt.get("source") == "intel" and str(hunt.get("source_ref") or "").startswith("intel-"):
        ids.append(str(hunt["source_ref"])[6:])
    elif hunt.get("source") == "hypothesis" and hunt.get("source_ref"):
        try:
            from remediation.hunting.engine import store as engine_store
            hyp = engine_store.get(hunt["source_ref"], engine)
            ids += [e["ref"] for e in (hyp or {}).get("why_now") or [] if e.get("kind") == "intel"]
        except Exception:  # noqa: BLE001 - a missing engine record just means the clock starts at hunt creation
            pass
    best = None
    for i in ids:
        try:
            rec = get_intel(int(i), engine)
        except (ValueError, TypeError):
            rec = None
        if not rec:
            continue
        if rec.get("published_at"):
            cand = (rec["published_at"], "report-published")
        else:
            cand = (rec.get("fetched_at") or rec["received_at"], "report-fetched")
        if best is None or cand[0] < best[0]:
            best = cand
    return best or (None, None)


def with_clock_start(hunt, engine=None):
    """A copy of the hunt carrying clock_start / clock_start_source when it came from a threat-intel report (read by hunt_report.timing)."""
    start, src = clock_start_for(hunt, engine)
    return {**hunt, "clock_start": start, "clock_start_source": src} if start else hunt


# ---------------------------------------------------------------- report sources (the watcher)
def _src(r):
    d = dict(r)
    d["enabled"] = bool(d["enabled"])
    return d


def list_sources(engine=None):
    engine, t = _engine(engine), db_module.intel_sources
    with engine.connect() as conn:
        return [_src(r) for r in conn.execute(select(t).order_by(t.c.id)).mappings().all()]


def get_source(source_id, engine=None):
    engine, t = _engine(engine), db_module.intel_sources
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(source_id))).mappings().first()
    return _src(r) if r else None


def add_source(name, kind, url, actor, connection_id=None, collection_id=None, engine=None):
    engine, t = _engine(engine), db_module.intel_sources
    with engine.begin() as conn:
        if conn.execute(select(t.c.id).where(t.c.name == name)).first():
            raise ValueError(f"A report source named {name!r} already exists")
        sid = conn.execute(insert(t), {"name": name, "kind": kind, "url": url, "connection_id": connection_id, "collection_id": collection_id, "enabled": 1,
                                       "total_reports": 0, "created_by": actor, "created_at": _now()}).inserted_primary_key[0]
    return get_source(sid, engine)


def update_source(source_id, values, engine=None):
    engine, t = _engine(engine), db_module.intel_sources
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.id == int(source_id)).values(**values))


def delete_source(source_id, engine=None):
    from sqlalchemy import delete
    engine, t = _engine(engine), db_module.intel_sources
    with engine.begin() as conn:
        conn.execute(delete(t).where(t.c.id == int(source_id)))


def get_intel(report_id, engine=None):
    engine, t = _engine(engine), db_module.threat_intel_reports
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(report_id))).mappings().first()
    return _intel(r) if r else None


def list_intel(engine=None):
    engine, t = _engine(engine), db_module.threat_intel_reports
    with engine.connect() as conn:
        rows = conn.execute(select(t).order_by(t.c.relevance.desc(), t.c.id.desc())).mappings().all()
    return [_intel(r) for r in rows]


def link_intel_hunt(report_id, hunt_id, engine=None):
    engine, t = _engine(engine), db_module.threat_intel_reports
    with engine.begin() as conn:
        conn.execute(update(t).where(t.c.id == int(report_id)).values(hunt_id=hunt_id))


# ---------------------------------------------------------------- investigations
def save_investigation(inv, md, actor, engine=None):
    engine, t = _engine(engine), db_module.soc_investigations
    with engine.begin() as conn:
        iid = conn.execute(insert(t), {"alert_id": inv["alert_id"], "verdict": inv["verdict"], "confidence": inv["confidence"], "reasons_json": json.dumps(inv["reasons"]),
                                       "evidence_json": json.dumps(inv), "report_md": md, "created_by": actor, "created_at": _now()}).inserted_primary_key[0]
    return iid


def _inv(r):
    d = dict(r)
    d["reasons"] = json.loads(d.pop("reasons_json"))
    d["investigation"] = json.loads(d.pop("evidence_json"))
    return d


def latest_investigation(alert_id, engine=None):
    engine, t = _engine(engine), db_module.soc_investigations
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.alert_id == int(alert_id)).order_by(t.c.id.desc()).limit(1)).mappings().first()
    return _inv(r) if r else None
