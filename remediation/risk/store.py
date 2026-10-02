"""
Risk scenarios, the signals shown beside them, the portfolio total against appetite, and the cyber health score.
"""
import datetime
import fnmatch
import json
from pathlib import Path

import yaml
from sqlalchemy import delete, insert, select, update

from remediation.risk import quant
from remediation.utils import db as db_module

POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "risk_policy.yaml"
CATEGORIES = ("ransomware", "data-breach", "outage", "fraud", "insider", "supply-chain", "other")
STATUSES = ("draft", "active", "retired")


def policy(path=None):
    with open(path or POLICY_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine(engine):
    engine = engine or db_module.get_engine()
    db_module.ensure_schema(engine)
    return engine


def _row(r):
    d = dict(r)
    d["options"] = json.loads(d.pop("options_json") or "[]")
    return d


def _clean_options(opts):
    out = []
    for o in (opts or [])[:10]:
        name = str(o.get("name") or "").strip()[:80]
        if not name:
            continue
        try:
            cost, fc, lc = float(o.get("annual_cost", 0)), float(o.get("frequency_reduction", 0)), float(o.get("loss_reduction", 0))
        except (TypeError, ValueError):
            raise quant.ScenarioError("A treatment option needs numbers for its cost and reductions") from None
        if cost < 0 or not (0 <= fc <= 1) or not (0 <= lc <= 1):
            raise quant.ScenarioError("A treatment option's cost cannot be negative and its reductions must be between 0 and 1 (for example 0.4 for 40%)")
        out.append({"name": name, "annual_cost": cost, "frequency_reduction": fc, "loss_reduction": lc})
    return out


def save(data, actor, scenario_id=None, engine=None):
    name = (data.get("name") or "").strip()
    if not name or len(name) > 160:
        raise quant.ScenarioError("A name of 1 to 160 characters is required")
    quant.validate(data)
    cat = data.get("category") or "other"
    status = data.get("status") or "active"
    if cat not in CATEGORIES:
        raise quant.ScenarioError(f"category must be one of {', '.join(CATEGORIES)}")
    if status not in STATUSES:
        raise quant.ScenarioError(f"status must be one of {', '.join(STATUSES)}")
    vals = {"name": name, "description": (data.get("description") or "")[:1000], "asset_scope": (data.get("asset_scope") or "")[:500], "category": cat,
            "tef_min": float(data["tef_min"]), "tef_likely": float(data["tef_likely"]), "tef_max": float(data["tef_max"]),
            "loss_min": float(data["loss_min"]), "loss_likely": float(data["loss_likely"]), "loss_max": float(data["loss_max"]),
            "options_json": json.dumps(_clean_options(data.get("options"))), "status": status, "owner": data.get("owner") or None, "risk_id": data.get("risk_id"),
            "updated_at": _now(), "updated_by": actor}
    engine, t = _engine(engine), db_module.risk_scenarios
    with engine.begin() as conn:
        if scenario_id:
            if not conn.execute(update(t).where(t.c.id == int(scenario_id)).values(**vals)).rowcount:
                raise KeyError("No such scenario")
            sid = int(scenario_id)
        else:
            sid = conn.execute(insert(t), {**vals, "created_by": actor, "created_at": _now()}).inserted_primary_key[0]
    return get(sid, engine)


def get(sid, engine=None):
    engine, t = _engine(engine), db_module.risk_scenarios
    with engine.connect() as conn:
        r = conn.execute(select(t).where(t.c.id == int(sid))).mappings().first()
    return _row(r) if r else None


def list_all(engine=None):
    engine, t = _engine(engine), db_module.risk_scenarios
    with engine.connect() as conn:
        return [_row(r) for r in conn.execute(select(t).order_by(t.c.name)).mappings().all()]


def remove(sid, engine=None):
    engine, t = _engine(engine), db_module.risk_scenarios
    with engine.begin() as conn:
        return bool(conn.execute(delete(t).where(t.c.id == int(sid))).rowcount)


def signals(scenario, findings, controls=None):
    """What the live data says about the scenario's assets, to read alongside the numbers. Never changes them."""
    pats = [p.strip() for p in (scenario.get("asset_scope") or "").replace(";", ",").split(",") if p.strip()]
    if not pats:
        return None
    hit = [f for f in findings if any(fnmatch.fnmatch((f.get("asset") or {}).get("name", "").lower(), p.lower()) for p in pats)
           and f.get("status") not in ("resolved", "closed")]
    assets = {(f.get("asset") or {}).get("name") for f in hit}
    kev = [f for f in hit if (f.get("kev") or {}).get("listed")]
    breached = [f for f in hit if (f.get("sla") or {}).get("breached")]
    return {"assets_with_findings": len(assets), "open_findings": len(hit), "known_exploited": len(kev), "past_sla": len(breached),
            "critical": sum(1 for f in hit if f.get("severity") == "Critical"),
            "reading": ("Known-exploited vulnerabilities are open on these assets, so a frequency at the low end deserves a second look." if kev
                        else "No known-exploited vulnerability is open on these assets." if hit else "No open findings match this scope.")}


def portfolio(scenarios, findings, pol=None, engine=None):
    """Simulates every active scenario. The total ALE is the sum of the scenarios' ALEs (scenarios are treated as independent)."""
    pol = pol or policy()
    trials = pol.get("trials", 10000)
    rows = []
    for s in scenarios:
        if s["status"] != "active":
            continue
        r = quant.simulate(s, trials, seed=s["id"], tolerance=pol.get("scenario_tolerance"))
        rows.append({"id": s["id"], "name": s["name"], "category": s["category"], "owner": s["owner"], "asset_scope": s["asset_scope"], **r, "signals": signals(s, findings),
                     "over_tolerance": bool(pol.get("scenario_tolerance") and s["tef_likely"] * s["loss_likely"] > pol["scenario_tolerance"] and r["ale"] > pol["scenario_tolerance"])})
    rows.sort(key=lambda x: -x["ale"])
    total = sum(r["ale"] for r in rows)
    app = pol.get("appetite_annual_loss")
    return {"scenarios": rows, "total_ale": total, "appetite": app, "within_appetite": (total <= app) if app else None,
            "currency": pol.get("currency", "USD"), "trials": trials,
            "note": "Numbers come from the estimates you entered. The total adds the scenarios' averages and assumes they are independent."}


def health(evidence_latest, detection_assessment, pol=None):
    """The cyber health score from the control tests' latest results and the detection assessment. Returns domains, the score and what was not measured."""
    pol = pol or policy()
    val = {"pass": 1.0, "warn": 0.5, "fail": 0.0}
    domains, missing, num, den = [], [], 0.0, 0.0
    for key, d in (pol.get("health_domains") or {}).items():
        score, used = None, []
        if d.get("from") == "detection":
            if detection_assessment:
                judged = [r for r in detection_assessment["rules"] if r["metrics"]["tier"] != "low_volume"]
                if judged:
                    good = sum(1 for r in judged if r["metrics"]["tier"] in ("high_fidelity", "healthy"))
                    score, used = 100 * good / len(judged), [f"{good} of {len(judged)} judged rules are healthy"]
        else:
            res = [(t, evidence_latest.get(t)) for t in d.get("tests", [])]
            usable = [(t, r) for t, r in res if r and r["result"] in val]
            if usable:
                score = 100 * sum(val[r["result"]] for _, r in usable) / len(usable)
                used = [f"{t}: {r['result']}" for t, r in usable]
        if score is None:
            missing.append(d.get("label", key))
            domains.append({"key": key, "label": d.get("label", key), "weight": d.get("weight", 1), "score": None, "basis": []})
            continue
        domains.append({"key": key, "label": d.get("label", key), "weight": d.get("weight", 1), "score": round(score), "basis": used})
        num += score * d.get("weight", 1)
        den += d.get("weight", 1)
    return {"score": round(num / den) if den else None, "domains": domains, "not_measured": missing,
            "how": "Each domain is the average of its control tests (pass 1, warn 0.5, fail 0; tests with too little data are left out). The score is the weighted average of the domains that were measured. "
                   "A domain with no usable result is listed as not measured and does not raise or lower the score."}
