"""
The API inventory: specifications, endpoints, daily traffic aggregates, caller activity, service dependencies and your data-classification framework.

Everything is built from records Quanta is given (a spec upload or fetch, an access-log export, pushed records, CI results). Nothing here observes a network.
An endpoint is (service, method, path key); it is `documented` when an uploaded spec of its service describes it and `observed` when traffic reached it. Traffic is
aggregated in memory per upload and merged into the database with a handful of statements, never one write per record.
"""
import datetime
import hashlib
import ipaddress
import json
import re

from sqlalchemy import delete, insert, select, update

from remediation.apisec import classify, config, logs, openapi, paths
from remediation.utils import db as db_module

EXPOSURES = ("external", "partner", "internal", "unknown")
STATUSES = ("active", "decommissioning", "accepted-risk")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def _j(v, default=None):
    try:
        return json.loads(v) if v else default
    except ValueError:
        return default


def slug(text, fallback="service"):
    s = re.sub(r"[^a-z0-9]+", "-", str(text or "").lower()).strip("-")[:80]
    return s or fallback


def _is_public(ip):
    try:
        return ipaddress.ip_address(ip.strip("[]")).is_global
    except ValueError:
        return None


def _actor_key(rec):
    if rec.get("actor"):
        if config.load()["thresholds"].get("actor_handling") == "hash":
            return "h:" + hashlib.sha256(rec["actor"].encode()).hexdigest()[:16]
        return rec["actor"]
    return f"ip:{rec['client_ip']}" if rec.get("client_ip") else "anonymous"


# ---------------------------------------------------------------- specifications
def list_specs(engine=None):
    engine, t = _engine(engine), db_module.api_specs
    with engine.connect() as conn:
        rows = conn.execute(select(t).order_by(t.c.service)).mappings().all()
    return [{**{k: r[k] for k in ("id", "service", "title", "version", "source", "source_ref", "sha256", "endpoints", "uploaded_by", "uploaded_at")}, "hosts": _j(r["hosts_json"], []),
             "meta": _j(r["meta_json"], {})} for r in rows]


def get_spec_content(service, engine=None):
    engine, t = _engine(engine), db_module.api_specs
    with engine.connect() as conn:
        r = conn.execute(select(t.c.content).where(t.c.service == service)).first()
    return r[0] if r else None


def delete_spec(service, engine=None):
    engine = _engine(engine)
    with engine.begin() as conn:
        n = conn.execute(delete(db_module.api_specs).where(db_module.api_specs.c.service == service)).rowcount
        conn.execute(update(db_module.api_endpoints).where(db_module.api_endpoints.c.service == service).values(in_spec=False, spec_json=None))
    return bool(n)


def host_map(engine=None):
    engine = _engine(engine)
    out = {}
    with engine.connect() as conn:
        for r in conn.execute(select(db_module.api_specs.c.service, db_module.api_specs.c.hosts_json)).all():
            for h in _j(r[1], []):
                out[h.lower()] = r[0]
    return out


def _spec_keys(conn):
    out = {}
    for r in conn.execute(select(db_module.api_endpoints.c.service, db_module.api_endpoints.c.path_key, db_module.api_endpoints.c.method).where(db_module.api_endpoints.c.in_spec == True)).all():  # noqa: E712
        out.setdefault(r[0], set()).add(r[1])
    return out


def _empty_observed():
    return {"auth_counts": {}, "unauth_success": 0, "plain_http": 0, "external_calls": 0, "internal_calls": 0, "query_params": [], "request_fields": [], "response_fields": [],
            "detected": {}, "jwt": {"seen": 0, "algs": {}, "no_exp": 0, "max_lifetime_hours": None, "key_url_header": 0, "no_aud": 0, "none_accepted": 0}, "status_counts": {}, "rules": {}, "sources": [],
            "max_response_bytes": 0}


def _merge_observed(a, b):
    out = json.loads(json.dumps(a or _empty_observed()))
    for k in ("auth_counts", "detected", "status_counts", "rules"):
        for key, n in (b.get(k) or {}).items():
            out.setdefault(k, {})[key] = out.get(k, {}).get(key, 0) + n
    for k in ("unauth_success", "plain_http", "external_calls", "internal_calls"):
        out[k] = out.get(k, 0) + b.get(k, 0)
    for k, cap in (("query_params", 40), ("request_fields", 200), ("response_fields", 200), ("sources", 10)):
        out[k] = sorted(set(out.get(k) or []) | set(b.get(k) or []))[:cap]
    j, bj = out.setdefault("jwt", _empty_observed()["jwt"]), b.get("jwt") or {}
    j["seen"] += bj.get("seen", 0)
    j["no_exp"] += bj.get("no_exp", 0)
    j["key_url_header"] += bj.get("key_url_header", 0)
    j["no_aud"] += bj.get("no_aud", 0)
    j["none_accepted"] = j.get("none_accepted", 0) + bj.get("none_accepted", 0)
    for alg, n in (bj.get("algs") or {}).items():
        j["algs"][alg] = j["algs"].get(alg, 0) + n
    if bj.get("max_lifetime_hours") is not None:
        j["max_lifetime_hours"] = max(j["max_lifetime_hours"] or 0, bj["max_lifetime_hours"])
    out["max_response_bytes"] = max(out.get("max_response_bytes", 0), b.get("max_response_bytes", 0))
    return out


def _merge_endpoint(conn, src_id, dst_id):
    ep, mt, ah = db_module.api_endpoints, db_module.api_metrics, db_module.api_actor_hits
    s = conn.execute(select(ep).where(ep.c.id == src_id)).mappings().first()
    d = conn.execute(select(ep).where(ep.c.id == dst_id)).mappings().first()
    merged = _merge_observed(_j(d["observed_json"], {}), _j(s["observed_json"], {}))
    firsts = [x for x in (d["first_seen"], s["first_seen"]) if x]
    lasts = [x for x in (d["last_seen"], s["last_seen"]) if x]
    conn.execute(update(ep).where(ep.c.id == dst_id).values(observed_json=json.dumps(merged), observed=bool(d["observed"] or s["observed"]), calls_total=d["calls_total"] + s["calls_total"],
                                                              first_seen=min(firsts) if firsts else None, last_seen=max(lasts) if lasts else None,
                                                              owner=d["owner"] or s["owner"], updated_at=_now()))
    for r in conn.execute(select(mt).where(mt.c.endpoint_id == src_id)).mappings().all():
        ex = conn.execute(select(mt).where(mt.c.endpoint_id == dst_id, mt.c.day == r["day"])).mappings().first()
        if ex:
            conn.execute(update(mt).where(mt.c.endpoint_id == dst_id, mt.c.day == r["day"]).values(
                calls=ex["calls"] + r["calls"], errors=ex["errors"] + r["errors"], exceptions=ex["exceptions"] + r["exceptions"], latency_sum_ms=ex["latency_sum_ms"] + r["latency_sum_ms"],
                latency_n=ex["latency_n"] + r["latency_n"], latency_max_ms=max(x for x in (ex["latency_max_ms"], r["latency_max_ms"]) if x is not None) if (ex["latency_max_ms"] is not None or r["latency_max_ms"] is not None) else None,
                bytes_in=ex["bytes_in"] + r["bytes_in"], bytes_out=ex["bytes_out"] + r["bytes_out"], security_events=ex["security_events"] + r["security_events"]))
        else:
            conn.execute(insert(mt), {**dict(r), "endpoint_id": dst_id})
    for r in conn.execute(select(ah).where(ah.c.endpoint_id == src_id)).mappings().all():
        ex = conn.execute(select(ah).where(ah.c.endpoint_id == dst_id, ah.c.day == r["day"], ah.c.actor == r["actor"])).mappings().first()
        if ex:
            conn.execute(update(ah).where(ah.c.endpoint_id == dst_id, ah.c.day == r["day"], ah.c.actor == r["actor"]).values(
                calls=ex["calls"] + r["calls"], errors=ex["errors"] + r["errors"], bytes_out=ex["bytes_out"] + r["bytes_out"], distinct_objects=max(ex["distinct_objects"], r["distinct_objects"])))
        else:
            conn.execute(insert(ah), {**dict(r), "endpoint_id": dst_id})
    conn.execute(delete(mt).where(mt.c.endpoint_id == src_id))
    conn.execute(delete(ah).where(ah.c.endpoint_id == src_id))
    conn.execute(delete(ep).where(ep.c.id == src_id))


def import_spec(text, service, source, actor, source_ref=None, engine=None):
    """Stores a specification (replacing that service's previous one) and marks the endpoints it documents. Returns a summary with the drift against observed traffic."""
    parsed = openapi.parse(text)
    service = slug(service or parsed["title"] or (parsed["hosts"][0] if parsed["hosts"] else "service"))
    engine = _engine(engine)
    sha = hashlib.sha256(text.encode("utf-8") if isinstance(text, str) else text).hexdigest()
    sp, ep = db_module.api_specs, db_module.api_endpoints
    now = _now()
    vals = {"title": parsed["title"], "version": parsed["version"], "source": source, "source_ref": (source_ref or "")[:300] or None, "sha256": sha, "hosts_json": json.dumps(parsed["hosts"]),
            "meta_json": json.dumps({k: parsed[k] for k in ("servers", "base_paths", "plain_http_servers", "security_schemes", "openapi")}), "endpoints": len(parsed["endpoints"]),
            "content": text if isinstance(text, str) else text.decode("utf-8", "replace"), "uploaded_by": actor, "uploaded_at": now}
    added = updated = 0
    with engine.begin() as conn:
        if conn.execute(update(sp).where(sp.c.service == service).values(**vals)).rowcount == 0:
            conn.execute(insert(sp), {"service": service, **vals})
        # traffic that was recorded under one of the spec's own host names now belongs to this service
        existing = {(r["method"], r["path_key"]): r for r in conn.execute(select(ep).where(ep.c.service == service)).mappings().all()}
        for host in parsed["hosts"]:
            for r in conn.execute(select(ep).where(ep.c.service == host.lower())).mappings().all():
                dst = existing.get((r["method"], r["path_key"]))
                if dst:
                    _merge_endpoint(conn, r["id"], dst["id"])
                else:
                    conn.execute(update(ep).where(ep.c.id == r["id"]).values(service=service))
                    existing[(r["method"], r["path_key"])] = {**dict(r), "service": service}
        keys_now = set()
        for e in parsed["endpoints"]:
            spec_json = json.dumps({k: e[k] for k in ("summary", "deprecated", "auth_state", "auth", "params", "request_fields", "response_fields", "tags", "exposure_hint")})
            keys_now.add((e["method"], e["key"]))
            row = existing.get((e["method"], e["key"]))
            if row:
                conn.execute(update(ep).where(ep.c.id == row["id"]).values(in_spec=True, spec_json=spec_json, template=e["path"], updated_at=now))
                updated += 1
            else:
                conn.execute(insert(ep), {"service": service, "method": e["method"], "path_key": e["key"], "template": e["path"], "in_spec": True, "observed": False, "spec_json": spec_json,
                                          "observed_json": json.dumps(_empty_observed()), "status": "active", "created_at": now, "updated_at": now, "calls_total": 0})
                added += 1
        removed = 0
        for (m, k), row in existing.items():
            if (m, k) not in keys_now and row["in_spec"]:
                conn.execute(update(ep).where(ep.c.id == row["id"]).values(in_spec=False, spec_json=None, updated_at=now))
                removed += 1
    return {"service": service, "title": parsed["title"], "version": parsed["version"], "operations": len(parsed["endpoints"]), "added": added, "updated": updated, "removed_from_spec": removed,
            "hosts": parsed["hosts"], "plain_http_servers": parsed["plain_http_servers"], "security_schemes": parsed["security_schemes"]}


# ---------------------------------------------------------------- traffic
def ingest_records(records, default_service=None, source="import", engine=None, today=None):
    """Merges normalised request records (from logs.parse or a push) into the inventory. Returns counts."""
    engine = _engine(engine)
    cfg = config.load()["thresholds"]
    today = today or datetime.datetime.now(datetime.timezone.utc).date()
    ep, mt, ah, dp = db_module.api_endpoints, db_module.api_metrics, db_module.api_actor_hits, db_module.api_dependencies
    hmap = host_map(engine)
    with engine.connect() as conn:
        speckeys = _spec_keys(conn)
    agg, deps = {}, {}
    per_day_actors = {}
    for r in records:
        host = r.get("host")
        svc = hmap.get(host) if host else None
        if not svc:
            svc = slug(default_service) if default_service else (host or "unspecified")
        key, ids = paths.resolve(r["path"], speckeys.get(svc, ()))
        gk = (svc, r["method"], key)
        a = agg.get(gk)
        if a is None:
            a = agg[gk] = {"template": paths.template_of(r["path"]) if key == paths.key_of(r["path"]) else key, "obs": _empty_observed(), "days": {}, "actors": {}, "first": None, "last": None, "calls": 0}
        o = a["obs"]
        day = (r["ts"].astimezone(datetime.timezone.utc).date() if r.get("ts") else today).isoformat()
        d = a["days"].setdefault(day, {"calls": 0, "errors": 0, "exceptions": 0, "lat_sum": 0.0, "lat_n": 0, "lat_max": None, "bin": 0, "bout": 0, "events": 0})
        d["calls"] += 1
        a["calls"] += 1
        st = r.get("status")
        if st is not None:
            o["status_counts"][f"{st // 100}xx"] = o["status_counts"].get(f"{st // 100}xx", 0) + 1
            if st >= 400:
                d["errors"] += 1
            if st >= 500:
                d["exceptions"] += 1
        if r.get("latency_ms") is not None:
            d["lat_sum"] += r["latency_ms"]
            d["lat_n"] += 1
            d["lat_max"] = r["latency_ms"] if d["lat_max"] is None else max(d["lat_max"], r["latency_ms"])
        d["bin"] += r.get("bytes_in") or 0
        d["bout"] += r.get("bytes_out") or 0
        o["max_response_bytes"] = max(o["max_response_bytes"], r.get("bytes_out") or 0)
        if r.get("security_event"):
            d["events"] += 1
            if r.get("rule"):
                o["rules"][r["rule"]] = o["rules"].get(r["rule"], 0) + 1
        auth = r.get("auth")
        if auth:
            o["auth_counts"][auth] = o["auth_counts"].get(auth, 0) + 1
            if auth == "none" and st is not None and st < 400:
                o["unauth_success"] += 1
        if r.get("scheme") == "http":
            o["plain_http"] += 1
        pub = _is_public(r["client_ip"]) if r.get("client_ip") else None
        if pub is True:
            o["external_calls"] += 1
        elif pub is False:
            o["internal_calls"] += 1
        for k in ("query_params", "request_fields", "response_fields"):
            o[k] = sorted(set(o[k]) | set(r.get(k) or []))[: {"query_params": 40}.get(k, 200)]
        for det, n in (r.get("detected") or {}).items():
            o["detected"][det] = o["detected"].get(det, 0) + n
        j = r.get("jwt")
        if j:
            oj = o["jwt"]
            oj["seen"] += 1
            oj["algs"][j["alg"] or "unknown"] = oj["algs"].get(j["alg"] or "unknown", 0) + 1
            oj["no_exp"] += 0 if j["has_exp"] else 1
            oj["key_url_header"] += 1 if j["key_url_header"] else 0
            oj["no_aud"] += 0 if j["has_aud"] else 1
            if j["alg"] == "none" and st is not None and st < 400:
                oj["none_accepted"] += 1
            if j["lifetime_hours"] is not None:
                oj["max_lifetime_hours"] = max(oj["max_lifetime_hours"] or 0, j["lifetime_hours"])
        if source not in o["sources"]:
            o["sources"].append(source)
        a["first"] = day if a["first"] is None or day < a["first"] else a["first"]
        a["last"] = day if a["last"] is None or day > a["last"] else a["last"]
        who = _actor_key(r)
        ak = (day, who)
        if len(per_day_actors.setdefault((gk, day), set())) >= cfg["max_distinct_actors_per_endpoint_day"] and who not in per_day_actors[(gk, day)]:
            who, ak = "other", (day, "other")
        per_day_actors[(gk, day)].add(who)
        h = a["actors"].setdefault(ak, {"calls": 0, "errors": 0, "bout": 0, "objs": set(), "ips": set()})
        h["calls"] += 1
        h["errors"] += 1 if st is not None and st >= 400 else 0
        h["bout"] += r.get("bytes_out") or 0
        if ids and len(h["objs"]) < cfg["max_objects_tracked_per_actor_day"]:
            h["objs"].add("/".join(ids))
        if r.get("client_ip") and len(h["ips"]) < 20:
            h["ips"].add(r["client_ip"])
        if r.get("source_service"):
            dk = (slug(r["source_service"]), svc)
            dd = deps.setdefault(dk, {"calls": 0, "exp": r.get("dest_exposure"), "day": day})
            dd["calls"] += 1
    now = _now()
    new_eps = 0
    with engine.begin() as conn:
        ids_by_key = {}
        for r in conn.execute(select(ep.c.id, ep.c.service, ep.c.method, ep.c.path_key, ep.c.observed_json, ep.c.first_seen, ep.c.last_seen, ep.c.calls_total, ep.c.observed)).mappings().all():
            ids_by_key[(r["service"], r["method"], r["path_key"])] = r
        for gk, a in agg.items():
            row = ids_by_key.get(gk)
            if row is None:
                eid = conn.execute(insert(ep), {"service": gk[0], "method": gk[1], "path_key": gk[2], "template": a["template"], "in_spec": False, "observed": True, "spec_json": None,
                                                "observed_json": json.dumps(a["obs"]), "status": "active", "first_seen": a["first"], "last_seen": a["last"], "calls_total": a["calls"],
                                                "created_at": now, "updated_at": now}).inserted_primary_key[0]
                new_eps += 1
            else:
                eid = row["id"]
                merged = _merge_observed(_j(row["observed_json"], {}), a["obs"])
                conn.execute(update(ep).where(ep.c.id == eid).values(
                    observed=True, observed_json=json.dumps(merged), calls_total=row["calls_total"] + a["calls"],
                    first_seen=min(x for x in (row["first_seen"], a["first"]) if x), last_seen=max(x for x in (row["last_seen"], a["last"]) if x), updated_at=now))
            ex_m = {r["day"]: r for r in conn.execute(select(mt).where(mt.c.endpoint_id == eid, mt.c.day.in_(list(a["days"])))).mappings().all()}
            for day, d in a["days"].items():
                cur = ex_m.get(day)
                if cur:
                    lm = [x for x in (cur["latency_max_ms"], d["lat_max"]) if x is not None]
                    conn.execute(update(mt).where(mt.c.endpoint_id == eid, mt.c.day == day).values(
                        calls=cur["calls"] + d["calls"], errors=cur["errors"] + d["errors"], exceptions=cur["exceptions"] + d["exceptions"], latency_sum_ms=cur["latency_sum_ms"] + d["lat_sum"],
                        latency_n=cur["latency_n"] + d["lat_n"], latency_max_ms=max(lm) if lm else None, bytes_in=cur["bytes_in"] + d["bin"], bytes_out=cur["bytes_out"] + d["bout"],
                        security_events=cur["security_events"] + d["events"]))
                else:
                    conn.execute(insert(mt), {"endpoint_id": eid, "day": day, "calls": d["calls"], "errors": d["errors"], "exceptions": d["exceptions"], "latency_sum_ms": d["lat_sum"],
                                              "latency_n": d["lat_n"], "latency_max_ms": d["lat_max"], "bytes_in": d["bin"], "bytes_out": d["bout"], "security_events": d["events"]})
            ex_a = {(r["day"], r["actor"]): r for r in conn.execute(select(ah).where(ah.c.endpoint_id == eid, ah.c.day.in_(list(a["days"])))).mappings().all()}
            for (day, who), h in a["actors"].items():
                cur = ex_a.get((day, who))
                if cur:
                    ips = sorted(set(_j(cur["ips_json"], [])) | h["ips"])[:20]
                    conn.execute(update(ah).where(ah.c.endpoint_id == eid, ah.c.day == day, ah.c.actor == who).values(
                        calls=cur["calls"] + h["calls"], errors=cur["errors"] + h["errors"], bytes_out=cur["bytes_out"] + h["bout"], distinct_objects=max(cur["distinct_objects"], len(h["objs"])), ips_json=json.dumps(ips)))
                else:
                    conn.execute(insert(ah), {"endpoint_id": eid, "day": day, "actor": who, "calls": h["calls"], "errors": h["errors"], "bytes_out": h["bout"], "distinct_objects": len(h["objs"]),
                                              "ips_json": json.dumps(sorted(h["ips"]))})
        for (src, dst), d in deps.items():
            cur = conn.execute(select(dp).where(dp.c.source_service == src, dp.c.dest_service == dst)).mappings().first()
            if cur:
                conn.execute(update(dp).where(dp.c.source_service == src, dp.c.dest_service == dst).values(calls=cur["calls"] + d["calls"], last_seen=max(cur["last_seen"] or "", d["day"]),
                                                                                                           dest_exposure=d["exp"] or cur["dest_exposure"]))
            else:
                conn.execute(insert(dp), {"source_service": src, "dest_service": dst, "dest_exposure": d["exp"], "calls": d["calls"], "first_seen": d["day"], "last_seen": d["day"]})
    return {"records": len(records), "endpoints": len(agg), "new_endpoints": new_eps, "services": sorted({k[0] for k in agg}), "dependencies": len(deps)}


# ---------------------------------------------------------------- reading
def _ep_dict(r):
    out = {k: r[k] for k in ("id", "service", "method", "path_key", "template", "owner", "exposure_override", "status", "notes", "first_seen", "last_seen", "calls_total", "created_at", "updated_at")}
    out["in_spec"], out["observed"] = bool(r["in_spec"]), bool(r["observed"])
    out["spec"] = _j(r["spec_json"], None)
    out["obs"] = _j(r["observed_json"], _empty_observed())
    return out


def list_endpoints(engine=None):
    engine, t = _engine(engine), db_module.api_endpoints
    with engine.connect() as conn:
        return [_ep_dict(r) for r in conn.execute(select(t).order_by(t.c.service, t.c.template, t.c.method)).mappings().all()]


def get_endpoint(eid, engine=None):
    engine, t = _engine(engine), db_module.api_endpoints
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(eid))).mappings().first()
    return _ep_dict(r) if r else None


def update_endpoint(eid, owner=None, exposure=None, status=None, notes=None, engine=None, fields=()):
    """Sets only the fields named in `fields`."""
    engine, t = _engine(engine), db_module.api_endpoints
    vals = {}
    if "owner" in fields:
        vals["owner"] = (owner or "").strip()[:200] or None
    if "exposure" in fields:
        if exposure not in (None, "") and exposure not in EXPOSURES:
            raise ValueError(f"exposure must be one of {', '.join(EXPOSURES)}")
        vals["exposure_override"] = exposure or None
    if "status" in fields:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        vals["status"] = status
    if "notes" in fields:
        vals["notes"] = (notes or "")[:1000] or None
    if not vals:
        raise ValueError("Nothing to change")
    vals["updated_at"] = _now()
    with engine.begin() as conn:
        if not conn.execute(update(t).where(t.c.id == int(eid)).values(**vals)).rowcount:
            raise KeyError("No such endpoint")
    return get_endpoint(eid, engine)


def metrics_rows(engine=None, endpoint_id=None, since=None):
    engine, t = _engine(engine), db_module.api_metrics
    q = select(t)
    if endpoint_id is not None:
        q = q.where(t.c.endpoint_id == int(endpoint_id))
    if since:
        q = q.where(t.c.day >= since)
    with engine.connect() as conn:
        return [dict(r) for r in conn.execute(q.order_by(t.c.endpoint_id, t.c.day)).mappings().all()]


def actor_rows(engine=None, endpoint_id=None, actor=None, since=None):
    engine, t = _engine(engine), db_module.api_actor_hits
    q = select(t)
    if endpoint_id is not None:
        q = q.where(t.c.endpoint_id == int(endpoint_id))
    if actor:
        q = q.where(t.c.actor == actor)
    if since:
        q = q.where(t.c.day >= since)
    with engine.connect() as conn:
        return [{**dict(r), "ips": _j(r["ips_json"], [])} for r in conn.execute(q).mappings().all()]


def dependencies(engine=None):
    engine, t = _engine(engine), db_module.api_dependencies
    with engine.connect() as conn:
        return [dict(r) for r in conn.execute(select(t).order_by(t.c.calls.desc())).mappings().all()]


# ---------------------------------------------------------------- your classification framework
def list_classes(engine=None):
    engine, t = _engine(engine), db_module.api_data_classes
    with engine.connect() as conn:
        rows = conn.execute(select(t).order_by(t.c.priority, t.c.name)).mappings().all()
    return [{"id": r["id"], "name": r["name"], "priority": r["priority"], "description": r["description"], "detectors": _j(r["detectors_json"], []),
             "field_patterns": _j(r["patterns_json"], []), "imported_by": r["imported_by"], "imported_at": r["imported_at"]} for r in rows]


def import_classes(text, actor, fmt=None, replace=True, engine=None):
    classes = classify.parse_framework(text, fmt)
    engine, t = _engine(engine), db_module.api_data_classes
    now = _now()
    with engine.begin() as conn:
        if replace:
            conn.execute(delete(t))
        have = {r[0] for r in conn.execute(select(t.c.name)).all()}
        for c in classes:
            vals = {"priority": c["priority"], "description": c["description"], "detectors_json": json.dumps(c["detectors"]), "patterns_json": json.dumps(c["field_patterns"]),
                    "imported_by": actor, "imported_at": now}
            if c["name"] in have:
                conn.execute(update(t).where(t.c.name == c["name"]).values(**vals))
            else:
                conn.execute(insert(t), {"name": c["name"], **vals})
    return list_classes(engine)


def clear_classes(engine=None):
    engine = _engine(engine)
    with engine.begin() as conn:
        return conn.execute(delete(db_module.api_data_classes)).rowcount


def drift(service, engine=None):
    """How a service's uploaded specification and its observed traffic differ: endpoints in traffic that no spec documents (shadow), and documented ones never seen."""
    engine = _engine(engine)
    eps = [e for e in list_endpoints(engine) if e["service"] == service]
    with engine.connect() as conn:
        has_spec = conn.execute(select(db_module.api_specs.c.id).where(db_module.api_specs.c.service == service)).first() is not None
    row = lambda e: {"id": e["id"], "method": e["method"], "template": e["template"], "calls": e["calls_total"], "first_seen": e["first_seen"], "last_seen": e["last_seen"]}  # noqa: E731
    return {"service": service, "has_spec": has_spec, "documented": sum(1 for e in eps if e["in_spec"]), "observed": sum(1 for e in eps if e["observed"]),
            "shadow": [row(e) for e in eps if e["observed"] and not e["in_spec"]] if has_spec else [],
            "documented_never_seen": [row(e) for e in eps if e["in_spec"] and not e["observed"]],
            "note": None if has_spec else "No specification has been uploaded for this service, so nothing can be called shadow yet."}
