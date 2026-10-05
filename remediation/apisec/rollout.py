"""
Operationalisation: the onboarding checklist, the two rollout orders, the maturity journey and who does what, from remediation/config/api_security.yaml.

Each checklist item either names something Quanta can see (a spec uploaded, traffic imported, a policy sent, CI results received) and is shown done or not from the
data, or is a step a person must state (architecture agreed, gate made blocking). Stated steps are ticked by an administrator with a note. Nothing is marked done on
the strength of intention.
"""
import datetime
import os

from sqlalchemy import func, select

from remediation.apisec import config
from remediation.utils import db as db_module


def _n(conn, table, *where):
    q = select(func.count()).select_from(table)
    for w in where:
        q = q.where(w)
    return conn.execute(q).scalar() or 0


def gather(engine, unclassified=0, owners_missing=0, smtp_configured=False):
    """The facts the checks need, read once."""
    t = db_module
    db_module.ensure_schema(engine)
    with engine.connect() as c:
        keys = [r[0] for r in c.execute(select(t.api_keys.c.scopes).where(t.api_keys.c.revoked_at.is_(None))).all()]
        conns = [r[0] for r in c.execute(select(t.connections.c.type)).all()]
        facts = {
            "api_key": any("api:write" in str(k) for k in keys),
            "spec": _n(c, t.api_specs) > 0,
            "traffic": _n(c, t.api_metrics) > 0,
            "classification": _n(c, t.api_data_classes) > 0,
            "published": _n(c, t.activity_log, t.activity_log.c.action == "api-security.publish") > 0,
            "ci": _n(c, t.scan_runs, t.scan_runs.c.scan_type == config.load()["ci"]["scan_type"]) > 0,
            "policy_connection": "api-policy-endpoint" in conns,
            "policy_pushed": _n(c, t.api_policy_pushes, t.api_policy_pushes.c.status.in_(["sent", "applied"])) > 0,
            "policy_block": _n(c, t.api_policy_pushes, t.api_policy_pushes.c.mode == "block", t.api_policy_pushes.c.status.in_(["sent", "applied"])) > 0,
            "alerts": ("notify-webhook" in conns) or (smtp_configured and bool(os.environ.get("QUANTA_ALERT_EMAIL", "").strip())),
            "findings": _n(c, t.api_endpoints) > 0,
        }
        manual = {r["item_id"]: dict(r) for r in c.execute(select(t.api_rollout_state)).mappings().all()}
    facts["owners"] = facts["traffic"] and owners_missing == 0
    facts["mapped"] = facts["classification"] and unclassified == 0
    facts["always"] = True
    return facts, manual


def build(facts, manual, track=None):
    cfg = config.load()["rollout"]
    items, by_phase = [], {}
    for it in cfg["checklist"]:
        m = manual.get(it["id"])
        if it.get("check"):
            done, basis = bool(facts.get(it["check"])), "observed"
        else:
            done, basis = bool(m and m["done"]), "stated"
        row = {**it, "done": done, "basis": basis, "note": (m or {}).get("note"), "set_by": (m or {}).get("set_by"), "set_at": (m or {}).get("set_at")}
        items.append(row)
        by_phase.setdefault(it["phase"], []).append(row)
    tracks = cfg["tracks"]
    chosen = next((t for t in tracks if t["id"] == track), tracks[0])
    phases = [{"phase": p, "items": by_phase.get(p, []), "done": sum(1 for i in by_phase.get(p, []) if i["done"]), "total": len(by_phase.get(p, []))} for p in chosen["order"] if p in by_phase]
    maturity = []
    reached = True
    for m in cfg["maturity"]:
        ok = bool(facts.get(m["check"])) if m.get("check") else False
        maturity.append({"id": m["id"], "title": m["title"], "reached": ok, "observed": bool(m.get("check"))})
    return {"track": chosen["id"], "tracks": [{"id": t["id"], "title": t["title"], "note": t["note"]} for t in tracks], "phases": phases, "items": items,
            "done": sum(1 for i in items if i["done"]), "total": len(items), "maturity": maturity, "roles": cfg["roles"],
            "sso_note": "Quanta has an administrator role and an ordinary-user role, narrowed by team. Single sign-on code exists (OIDC, authorization code with PKCE) but has never been run against a live identity provider; until it is configured, accounts are local. Developers see their team's API findings in the main queue after you publish."}


def set_item(item_id, done, note, actor, engine):
    from sqlalchemy import insert, update
    valid = {i["id"] for i in config.load()["rollout"]["checklist"] if not i.get("check")}
    if item_id not in valid:
        raise KeyError("That step is observed from data and cannot be ticked by hand")
    db_module.ensure_schema(engine)
    t = db_module.api_rollout_state
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    vals = {"done": bool(done), "note": (note or "")[:500] or None, "set_by": actor, "set_at": stamp}
    with engine.begin() as conn:
        if conn.execute(update(t).where(t.c.item_id == item_id).values(**vals)).rowcount == 0:
            conn.execute(insert(t), {"item_id": item_id, **vals})
