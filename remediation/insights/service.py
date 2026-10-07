"""
Insights service: refresh (run the detectors, correlate, persist), list/get with role and team filtering, person-driven state changes, learning weights
and the admin-editable settings. A refresh is idempotent: an insight keeps its stable id, so a person's snooze/dismiss/acted decision survives it, and
nothing is ever created twice. It is cheap (no network, no model) and safe to run hourly on the leader tick.
"""
import copy
import datetime
import json
import os
import tempfile
from pathlib import Path

import yaml
from sqlalchemy import insert, select, update

from remediation.insights import detectors, loader, scoring
from remediation.insights.model import ROLES, STATES, now_utc
from remediation.utils import db as db_module

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "insights.yaml"
HEADER = "# Insights engine settings (edited from the Insights settings API; see docs/INSIGHTS.md). Deterministic rules only; nothing here calls a model.\n"


def enabled():
    return os.environ.get("QUANTA_INSIGHTS", "true").strip().lower() not in ("0", "false", "no")


def _ts(dt=None):
    return (dt or now_utc()).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


# ---------------------------------------------------------------- settings
def load_config(path=None):
    with open(path or CONFIG_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


class SettingsError(ValueError):
    pass


def _merge_checked(base, patch, path=""):
    """Deep-merges `patch` into a copy of `base`, rejecting unknown keys and wrong types (a number must stay a number, a flag a flag)."""
    out = copy.deepcopy(base)
    for k, v in patch.items():
        here = f"{path}{k}"
        if k not in base:
            raise SettingsError(f"unknown setting {here}")
        cur = base[k]
        if isinstance(cur, dict):
            if not isinstance(v, dict):
                raise SettingsError(f"{here} must be an object")
            if k == "detectors":
                for dn in v:
                    if dn not in cur:
                        raise SettingsError(f"unknown detector {dn}")
            if k == "action_prefixes":
                pass
            out[k] = _merge_checked(cur, v, here + ".")
        elif isinstance(cur, bool):
            if not isinstance(v, bool):
                raise SettingsError(f"{here} must be true or false")
            out[k] = v
        elif isinstance(cur, (int, float)):
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
                raise SettingsError(f"{here} must be a non-negative number")
            out[k] = v
        elif isinstance(cur, list):
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise SettingsError(f"{here} must be a list of strings")
            out[k] = v
        else:
            out[k] = v
    return out


def update_config(patch, path=None):
    path = Path(path or CONFIG_PATH)
    cfg = _merge_checked(load_config(path), patch)
    lc = cfg["learning"]
    if not (0 < lc["min_weight"] <= 1 <= lc["max_weight"]):
        raise SettingsError("learning weights need 0 < min_weight <= 1 <= max_weight")
    if not (1 <= cfg["max_per_role"] <= 50):
        raise SettingsError("max_per_role must be between 1 and 50")
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(HEADER + yaml.safe_dump(cfg, sort_keys=False))
    os.replace(tmp, path)
    return cfg


# ---------------------------------------------------------------- baselines and bookkeeping
def _get_baseline(engine, key):
    with engine.connect() as conn:
        row = conn.execute(select(db_module.insight_baselines).where(db_module.insight_baselines.c.key == key)).mappings().first()
    return json.loads(row["value"]) if row else None


def _set_baseline(engine, key, value, now):
    t = db_module.insight_baselines
    with engine.begin() as conn:
        if conn.execute(select(t.c.key).where(t.c.key == key)).first():
            conn.execute(update(t).where(t.c.key == key).values(value=json.dumps(value), updated_at=_ts(now)))
        else:
            conn.execute(insert(t).values(key=key, value=json.dumps(value), updated_at=_ts(now)))


# ---------------------------------------------------------------- refresh
def refresh(engine=None, findings=None, assets=None, now=None, snapshot=None, config=None):
    """Runs every enabled detector, adds the correlation insights, persists them and records the new baselines. Returns a summary with the gap notes
    ("this detector had no data") and any detector errors. `snapshot` lets a test (or a caller with its own data) skip the loader."""
    engine, cfg = _engine(engine), config or load_config()
    now = now or now_utc()
    snap = snapshot if snapshot is not None else loader.load(engine, findings=findings, assets=assets, now=now)
    snap.setdefault("now", now)
    prev = _get_baseline(engine, "state") or {}
    snap["baseline"] = {"assets": prev.get("assets"), "controls": prev.get("controls")} if prev else {"assets": None, "controls": None}
    found, gaps, errors = detectors.run_all(snap, cfg)
    found = found + scoring.correlate(found, cfg)
    t, ts, new = db_module.insights, _ts(now), 0
    with engine.begin() as conn:
        existing = {r["id"] for r in conn.execute(select(t.c.id)).mappings().all()}
        for ins in found:
            payload = json.dumps(ins)
            if ins["id"] in existing:
                conn.execute(update(t).where(t.c.id == ins["id"]).values(payload=payload, last_seen=ts, kind=ins["kind"], module=ins["module"]))
            else:
                conn.execute(insert(t).values(id=ins["id"], detector=ins["detector"], kind=ins["kind"], module=ins["module"], state="open", payload=payload, first_seen=ts, last_seen=ts))
                new += 1
    base = detectors.capture_baselines(snap)
    merged = {**prev, **base}
    _set_baseline(engine, "state", merged, now)
    summary = {"refreshed_at": ts, "produced": len(found), "new": new, "gaps": gaps, "errors": errors}
    _set_baseline(engine, "last_refresh", summary, now)
    return summary


def last_refresh(engine=None):
    return _get_baseline(_engine(engine), "last_refresh")


# ---------------------------------------------------------------- reading
def _decorate(row, now):
    ins = json.loads(row["payload"])
    state, until = row["state"], row["snooze_until"]
    if state == "snoozed" and until and until <= _ts(now):
        state = "open"
    ins.update({"state": state, "state_reason": row["state_reason"], "state_by": row["state_by"], "state_at": row["state_at"],
                "snooze_until": until, "first_seen": row["first_seen"], "last_seen": row["last_seen"]})
    return ins


def learning_counts(engine=None):
    t = db_module.insights
    out = {}
    with _engine(engine).connect() as conn:
        for r in conn.execute(select(t.c.detector, t.c.state)).mappings().all():
            if r["state"] in ("acted", "dismissed"):
                out.setdefault(r["detector"], {"acted": 0, "dismissed": 0})[r["state"]] += 1
    return out


def weights(engine=None, config=None):
    return scoring.learned_weights(learning_counts(engine), config or load_config())


def default_role(user):
    return "admin" if user and user.get("role") == "admin" else "analyst"


def _visible_to(ins, user):
    if user and user.get("role") == "admin":
        return True
    if ins.get("admin_only"):
        return False
    team = user.get("team") if user else None
    return not (team and ins.get("teams") and team not in ins["teams"])


def list_insights(user, engine=None, role=None, limit=None, include_closed=False, now=None, config=None):
    """Ranked insights this person may see, for a role lens (default: admin->admin, else analyst). Dismissed/acted/snoozed ones are hidden unless
    `include_closed`. The cap per role applies after ranking."""
    engine, cfg, now = _engine(engine), config or load_config(), now or now_utc()
    role = role if role in ROLES else default_role(user)
    horizon = _ts(now - datetime.timedelta(days=cfg.get("resolve_after_days", 3)))
    with engine.connect() as conn:
        rows = conn.execute(select(db_module.insights).where(db_module.insights.c.last_seen >= horizon)).mappings().all()
    items = [_decorate(r, now) for r in rows]
    items = [i for i in items if _visible_to(i, user) and (include_closed or i["state"] == "open")]
    cap = min(int(limit or 10 ** 6), int(cfg.get("max_per_role", 10)))
    return scoring.rank_for_role(items, role, weights(engine, cfg), cap)


def get_insight(insight_id, user, engine=None, role=None, now=None, config=None):
    engine, cfg, now = _engine(engine), config or load_config(), now or now_utc()
    with engine.connect() as conn:
        row = conn.execute(select(db_module.insights).where(db_module.insights.c.id == insight_id)).mappings().first()
    if row is None:
        return None
    ins = _decorate(row, now)
    if not _visible_to(ins, user):
        return None
    return scoring.score(ins, role if role in ROLES else default_role(user), weights(engine, cfg))


# ---------------------------------------------------------------- person decisions
def set_state(insight_id, state, user, reason=None, snooze_days=None, engine=None, now=None, config=None):
    """snooze | dismiss | acted | reopen. Only a person calls this; the engine never changes a state itself. Dismissing needs a reason (it feeds learning)."""
    engine, cfg, now = _engine(engine), config or load_config(), now or now_utc()
    if state not in STATES:
        raise ValueError(f"state must be one of {STATES}")
    if state == "dismissed" and not (reason or "").strip():
        raise ValueError("A reason is required to dismiss an insight")
    if get_insight(insight_id, user, engine=engine, now=now, config=cfg) is None:
        raise KeyError(insight_id)
    until = None
    if state == "snoozed":
        days = int(snooze_days or cfg.get("snooze_days", 7))
        if not 1 <= days <= 90:
            raise ValueError("snooze_days must be between 1 and 90")
        until = _ts(now + datetime.timedelta(days=days))
    with engine.begin() as conn:
        conn.execute(update(db_module.insights).where(db_module.insights.c.id == insight_id).values(
            state=state, state_reason=(reason or None), state_by=(user or {}).get("email"), state_at=_ts(now), snooze_until=until))
    return get_insight(insight_id, user, engine=engine, now=now, config=cfg)


# ---------------------------------------------------------------- admin view
def settings_view(engine=None):
    cfg = load_config()
    counts = learning_counts(engine)
    w = scoring.learned_weights(counts, cfg)
    return {"config": cfg, "enabled": enabled(), "last_refresh": last_refresh(engine),
            "detectors": [{"name": d.name, "kind": d.kind, "module": d.module, "needs": list(d.needs), "description": d.doc,
                           "enabled": (cfg.get("detectors", {}).get(d.name) or {}).get("enabled", True),
                           "acted": counts.get(d.name, {}).get("acted", 0), "dismissed": counts.get(d.name, {}).get("dismissed", 0),
                           "weight": w.get(d.name, 1.0)} for d in detectors.DETECTORS]}


def run_tick(findings_fn, assets_fn, engine=None):
    """The leader tick: hourly at most, off with QUANTA_INSIGHTS=false, never raises. The two callables supply the scored queue and assets lazily."""
    if not enabled():
        return None
    try:
        engine = _engine(engine)
        last = _get_baseline(engine, "last_refresh")
        if last and last.get("refreshed_at", "") > _ts(now_utc() - datetime.timedelta(minutes=55)):
            return None
        return refresh(engine, findings=findings_fn(), assets=assets_fn())
    except Exception:  # noqa: BLE001
        return None
