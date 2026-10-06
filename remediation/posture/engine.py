"""Runs every framework's checks against one Context and turns them into scores, maturity stages and a ranked action list."""
from pathlib import Path

import yaml

from remediation.posture import load_frameworks
from remediation.posture.model import Context

POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "posture_policy.yaml"
_DEFAULT_POLICY = {"min_observable_share": 0.30, "top_actions": 12,
                   "maturity": [{"stage": "Traditional", "below": 35}, {"stage": "Initial", "below": 60}, {"stage": "Advanced", "below": 85}, {"stage": "Optimal", "below": 101}],
                   "thresholds": {"stale_days": 90, "kev_open_days": 14, "critical_open_days": 30, "min_sbom_age_days": 90, "coverage_good": 0.9, "coverage_partial": 0.5, "max_admins": 5}}


def policy():
    try:
        loaded = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        loaded = {}
    merged = {**_DEFAULT_POLICY, **{k: v for k, v in loaded.items() if v is not None}}
    merged["thresholds"] = {**_DEFAULT_POLICY["thresholds"], **(loaded.get("thresholds") or {})}
    return merged


def stage_for(score, pol):
    for step in pol["maturity"]:
        if score < step["below"]:
            return step["stage"]
    return pol["maturity"][-1]["stage"]


def _framework_result(mod, checks, pol):
    meta = mod.FRAMEWORK
    scored = [c for c in checks if c["score"] is not None]
    total_w = sum(c["weight"] for c in checks if c["status"] != "na")
    seen_w = sum(c["weight"] for c in scored)
    share = (seen_w / total_w) if total_w else 0.0
    score = round(100 * sum(c["weight"] * c["score"] for c in scored) / seen_w, 1) if seen_w and share >= pol["min_observable_share"] else None
    areas = []
    for area_id, area_title in meta.get("areas", []):
        mine = [c for c in checks if c["area"] == area_id]
        sc = [c for c in mine if c["score"] is not None]
        w = sum(c["weight"] for c in sc)
        areas.append({"id": area_id, "title": area_title, "checks": len(mine), "observable": len(sc),
                      "score": round(100 * sum(c["weight"] * c["score"] for c in sc) / w, 1) if w else None})
    counts = {s: sum(1 for c in checks if c["status"] == s) for s in ("pass", "partial", "fail", "unknown", "na")}
    return {"id": meta["id"], "title": meta["title"], "summary": meta.get("summary", ""), "refs": meta.get("refs", []), "score": score,
            "stage": stage_for(score, pol) if score is not None else None, "observable_share": round(share, 3), "counts": counts, "areas": areas, "checks": checks,
            "note": None if score is not None else "Not enough is recorded to score this honestly. The checks below say what to connect."}


def assess(engine=None, findings=None, env=None, now=None):
    """The whole review. Deterministic for the same recorded data, environment and `now`."""
    pol = policy()
    ctx = Context(engine=engine, findings=findings, env=env, now=now)
    ctx.policy = pol
    ctx.thr = pol["thresholds"]
    mods, problems = load_frameworks()
    frameworks = []
    for mod in mods:
        try:
            checks = list(mod.run(ctx))
        except Exception as exc:  # noqa: BLE001 - one framework failing must not hide the others
            problems[mod.FRAMEWORK["id"]] = f"checks failed: {type(exc).__name__}: {exc}"[:200]
            continue
        for c in checks:
            c["framework"] = mod.FRAMEWORK["id"]
        frameworks.append(_framework_result(mod, checks, pol))
    ids = [c["id"] for f in frameworks for c in f["checks"]]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        problems["duplicate-check-ids"] = ", ".join(dupes)

    # actions: every partial or failed check, ranked by weight x the gap that remains, one per distinct change
    actions, seen_change = [], set()
    for f in frameworks:
        for c in f["checks"]:
            if c["status"] not in ("fail", "partial"):
                continue
            gap = 1.0 - (c["score"] or 0.0)
            key = (c["change"]["kind"], c["change"].get("where"), c["change"].get("key")) if c["change"] else ("check", c["id"])
            actions.append({"impact": round(c["weight"] * gap, 3), "framework": f["id"], "framework_title": f["title"], "area": c["area"], "check_id": c["id"],
                            "title": c["title"], "status": c["status"], "evidence": c["evidence"], "recommendation": c["recommendation"], "change": c["change"], "_key": key})
    actions.sort(key=lambda a: (-a["impact"], a["framework"], a["check_id"]))
    unique = []
    for a in actions:
        if a["_key"] in seen_change:
            continue
        seen_change.add(a["_key"])
        unique.append({k: v for k, v in a.items() if k != "_key"})
    unobservable = [{"framework": f["id"], "check_id": c["id"], "title": c["title"], "data_used": c["data_used"], "recommendation": c["recommendation"]}
                    for f in frameworks for c in f["checks"] if c["status"] == "unknown"]
    scored = [f["score"] for f in frameworks if f["score"] is not None]
    overall = round(sum(scored) / len(scored), 1) if scored else None
    return {"frameworks": frameworks, "overall": {"score": overall, "stage": stage_for(overall, pol) if overall is not None else None, "scored_frameworks": len(scored), "frameworks": len(frameworks)},
            "actions": unique[: pol["top_actions"]], "all_actions": len(unique), "not_observable": unobservable, "unavailable_sources": dict(ctx.unavailable),
            "problems": problems, "policy": {"min_observable_share": pol["min_observable_share"], "maturity": pol["maturity"], "thresholds": pol["thresholds"]}}
