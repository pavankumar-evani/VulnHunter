"""
The AI asset register: what AI systems exist, what each can do, how it is exposed and defended, and the findings the rules raise from that.

Applications Quanta found by watching traffic (the shadow-AI list on the AI Usage page) can be copied in as assets with everything marked unknown, so
the register starts from what is really in use. Findings can be published to the main queue (source ai-security, asset type ai-ml-system); each
publish is the complete current set, so a finding disappears from the queue once the record shows it fixed.
"""
import datetime
import json

from sqlalchemy import delete, insert, select, update

from remediation.aisec import rules, rules_mcp
from remediation.utils import db as db_module

TEXT_FIELDS = ("owner", "vendor_model")
CHOICES = {"kind": rules.KINDS, "environment": rules.ENVIRONMENTS, "hosting": rules.HOSTING, "permissions_scope": rules.SCOPES, "provenance": rules.PROVENANCE, "serialization": rules.SERIALIZATION}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def clean(data):
    name = (data.get("name") or "").strip()
    if not name or len(name) > 160:
        raise ValueError("A name of 1 to 160 characters is required")
    out = {"name": name}
    for f, allowed in CHOICES.items():
        v = data.get(f)
        if v in (None, ""):
            if f == "kind":
                raise ValueError(f"kind must be one of {', '.join(allowed)}")
            out[f] = None
        elif v not in allowed:
            raise ValueError(f"{f} must be one of {', '.join(allowed)}")
        else:
            out[f] = v
    for f in TEXT_FIELDS:
        out[f] = (str(data.get(f) or "").strip()[:200]) or None
    classes = data.get("data_classes") or []
    if not isinstance(classes, list) or any(c not in rules.DATA_CLASSES for c in classes):
        raise ValueError(f"data_classes must be a list drawn from {', '.join(rules.DATA_CLASSES)}")
    out["data_classes"] = sorted(set(classes))
    for f in rules.TRI:
        v = data.get(f)
        if v not in (None, True, False):
            raise ValueError(f"{f} must be true, false or unknown")
        out[f] = v
    lr = data.get("last_reviewed")
    if lr:
        try:
            out["last_reviewed"] = datetime.date.fromisoformat(str(lr)[:10]).isoformat()
        except ValueError:
            raise ValueError("last_reviewed must be a date like 2026-09-30") from None
    else:
        out["last_reviewed"] = None
    out["notes"] = (str(data.get("notes") or "")[:1000]) or None
    out.update(_clean_agent_fields(data))
    return out


def _tri(v, label):
    if v not in (None, True, False):
        raise ValueError(f"{label} must be true, false or unknown")
    return v


def _choice(v, allowed, label):
    if v in (None, ""):
        return None
    if v not in allowed:
        raise ValueError(f"{label} must be one of {', '.join(allowed)}")
    return v


def _text(v, n=120):
    return (str(v or "").strip()[:n]) or None


def _list_of(v, label, cap):
    if v in (None, ""):
        return []
    if not isinstance(v, list) or len(v) > cap:
        raise ValueError(f"{label} must be a list of at most {cap} entries")
    return v


def _unique(items, label):
    names = [i["name"].lower() for i in items]
    if len(set(names)) != len(names):
        raise ValueError(f"{label} names must be unique")
    return items


def empty_agent_fields():
    """The agent, MCP and lifecycle fields of a record with nothing stated. Also what the expand-only migration backfills."""
    return {"provider": None, "model_ids": [], "tools": [], "mcp_servers": [], "data_sources": [], "memory": None, "memory_provenance": None, "memory_poisoning_controls": None,
            "max_steps": None, "budget_cap": None, "prompt_versioning": None, "eval_suite": None, "release": {k: None for k in rules_mcp.RELEASE_TRI},
            "observability": {k: None for k in rules_mcp.OBS_TRI}, "audit_log": {k: None for k in rules_mcp.AUDIT_TRI}}


def _clean_agent_fields(data):
    """Validates the agent, MCP and lifecycle fields. A missing field is unknown (None, [] or all-None), never a default 'no'."""
    out = empty_agent_fields()
    out["provider"] = _text(data.get("provider"), 120)
    ids = _list_of(data.get("model_ids"), "model_ids", 20)
    out["model_ids"] = [x for x in dict.fromkeys(_text(i, 120) for i in ids) if x]
    tools = []
    for t in _list_of(data.get("tools"), "tools", 100):
        if not isinstance(t, dict) or not _text(t.get("name"), 80):
            raise ValueError("each tool needs a name")
        tools.append({"name": _text(t["name"], 80), "scope": _text(t.get("scope"), 120), "side_effect": _choice(t.get("side_effect"), rules_mcp.SIDE_EFFECTS, "tool side_effect"),
                      "requires_approval": _tri(t.get("requires_approval"), "tool requires_approval"), "category": _choice(t.get("category"), rules_mcp.CATEGORIES, "tool category"),
                      "server": _text(t.get("server"), 80),
                      "reads": [x for x in dict.fromkeys(_text(i, 120) for i in _list_of(t.get("reads"), "tool reads", 20)) if x]})
    out["tools"] = _unique(tools, "tool")
    servers = []
    for s in _list_of(data.get("mcp_servers"), "mcp_servers", 30):
        if not isinstance(s, dict) or not _text(s.get("name"), 80):
            raise ValueError("each MCP server needs a name")
        n = s.get("tool_count")
        if n in (None, ""):
            n = None
        elif isinstance(n, bool) or not isinstance(n, int) or not 0 <= n <= 10000:
            raise ValueError("tool_count must be a whole number from 0 to 10000")
        rec = {"name": _text(s["name"], 80), "transport": _choice(s.get("transport"), rules_mcp.TRANSPORTS, "MCP transport"), "auth": _choice(s.get("auth"), rules_mcp.AUTH, "MCP auth"), "tool_count": n}
        for f in rules_mcp.SERVER_TRI:
            rec[f] = _tri(s.get(f), f"MCP {f}")
        servers.append(rec)
    out["mcp_servers"] = _unique(servers, "MCP server")
    sources = []
    for d in _list_of(data.get("data_sources"), "data_sources", 100):
        d = {"name": d} if isinstance(d, str) else d
        if not isinstance(d, dict) or not _text(d.get("name"), 120):
            raise ValueError("each data source needs a name")
        sources.append({"name": _text(d["name"], 120), "trusted": _tri(d.get("trusted"), "data source trusted")})
    out["data_sources"] = _unique(sources, "data source")
    out["memory"] = _choice(data.get("memory"), rules_mcp.MEMORY, "memory")
    out["eval_suite"] = _choice(data.get("eval_suite"), rules_mcp.EVAL_SUITES, "eval_suite")
    for f in ("memory_provenance", "memory_poisoning_controls", "budget_cap", "prompt_versioning"):
        out[f] = _tri(data.get(f), f)
    ms = data.get("max_steps")
    if ms not in (None, ""):
        if isinstance(ms, bool) or not isinstance(ms, int) or not 0 <= ms <= 100000:
            raise ValueError("max_steps must be a whole number from 0 (no limit) to 100000")
        out["max_steps"] = ms
    for field, keys in (("release", rules_mcp.RELEASE_TRI), ("observability", rules_mcp.OBS_TRI), ("audit_log", rules_mcp.AUDIT_TRI)):
        block = data.get(field) or {}
        if not isinstance(block, dict):
            raise ValueError(f"{field} must be an object")
        out[field] = {k: _tri(block.get(k), f"{field}.{k}") for k in keys}
    return out


def backfill_new_fields(engine=None):
    """Expand-only migration: adds the agent/MCP/lifecycle keys to stored records that lack them, leaving every existing value alone. Safe to run again; returns how many changed."""
    engine, t = engine or db_module.get_engine(), db_module.ai_assets   # no ensure_schema: this runs from inside it (migrations), which would recurse
    changed = 0
    with engine.begin() as conn:
        for r in conn.execute(select(t.c.id, t.c.data_json)).mappings().all():
            d = json.loads(r["data_json"])
            fresh = {k: v for k, v in empty_agent_fields().items() if k not in d}
            if fresh:
                conn.execute(update(t).where(t.c.id == r["id"]).values(data_json=json.dumps({**d, **fresh})))
                changed += 1
    return changed


def _row(r):
    d = json.loads(r["data_json"])
    for k, v in empty_agent_fields().items():
        d.setdefault(k, v)
    d.update({"id": r["id"], "created_at": r["created_at"], "updated_at": r["updated_at"], "updated_by": r["updated_by"]})
    return d


def save(data, actor, asset_id=None, engine=None):
    c = clean(data)
    engine, t = _engine(engine), db_module.ai_assets
    vals = {"name": c["name"], "kind": c["kind"], "data_json": json.dumps(c), "updated_at": _now(), "updated_by": actor}
    with engine.begin() as conn:
        dup = conn.execute(select(t.c.id).where(t.c.name == c["name"])).first()
        if dup and dup[0] != asset_id:
            raise ValueError("An AI asset with that name already exists")
        if asset_id:
            if not conn.execute(update(t).where(t.c.id == int(asset_id)).values(**vals)).rowcount:
                raise KeyError("No such asset")
            aid = int(asset_id)
        else:
            aid = conn.execute(insert(t), {**vals, "created_at": _now()}).inserted_primary_key[0]
    return get(aid, engine)


def get(aid, engine=None):
    engine, t = _engine(engine), db_module.ai_assets
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(aid))).mappings().first()
    return _row(r) if r else None


def list_all(engine=None):
    engine, t = _engine(engine), db_module.ai_assets
    with engine.connect() as conn:
        return [_row(r) for r in conn.execute(select(t).order_by(t.c.name)).mappings().all()]


def remove(aid, engine=None):
    engine, t = _engine(engine), db_module.ai_assets
    with engine.begin() as conn:
        return bool(conn.execute(delete(t).where(t.c.id == int(aid))).rowcount)


def import_discovered(engine=None, actor="import"):
    """Copies applications from the shadow-AI list that are not in the register yet. Everything beyond the name and owner is left unknown."""
    engine = _engine(engine)
    apps = db_module.ai_apps
    with engine.connect() as conn:
        found = conn.execute(select(apps.c.name, apps.c.owner, apps.c.domain, apps.c.status)).mappings().all()
    have = {a["name"].lower() for a in list_all(engine)}
    added = []
    for f in found:
        if f["name"].lower() in have or f["status"] == "blocked":
            continue
        save({"name": f["name"], "kind": "application", "owner": f["owner"], "notes": f"Found in traffic ({f['domain']}); status {f['status']}."}, actor, engine=engine)
        added.append(f["name"])
    return added


def assess(assets, today=None, approved=None):
    findings, per_asset, gaps = [], [], 0
    for a in assets:
        f = rules.evaluate(a, today, approved)
        u = rules.unanswered(a)
        findings += f
        gaps += len(u)
        per_asset.append({"id": a["id"], "name": a["name"], "kind": a["kind"], "owner": a.get("owner"), "environment": a.get("environment"), "findings": len(f), "score": rules.score(f),
                          "worst": max((x["severity"] for x in f), key=lambda s: rules.SEV_WEIGHT[s], default=None), "unanswered": [{"field": k, "question": q} for k, q in u]})
    findings.sort(key=lambda x: (-rules.SEV_WEIGHT[x["severity"]], x["asset"], x["rule"]))
    per_asset.sort(key=lambda x: (-x["score"], x["name"]))
    by_rule = {}
    for f in findings:
        by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1
    return {"findings": findings, "assets": per_asset, "by_rule": by_rule, "by_severity": {s: sum(1 for f in findings if f["severity"] == s) for s in rules.SEV_WEIGHT},
            "unanswered_total": gaps,
            "note": "Rules fire on an explicit 'no'. A question left unanswered is a gap, not a pass: it is listed so the record can be completed."}


def to_queue_items(findings):
    """The findings in the shape the ingest API takes, for publishing to the main queue."""
    items = []
    for f in findings:
        items.append({"title": f"{f['title']} ({f['asset']})", "severity": f["severity"], "asset": {"name": f["asset"], "type": "ai-ml-system"}, "source_ref": f"{f['rule']}:{f['asset_id']}:{f['title'][:40]}",
                      "description": f"{f['owasp']}. {f['why']}", "recommended_fix": f["fix"], "scan_type": "ai-ml"})
    return items
