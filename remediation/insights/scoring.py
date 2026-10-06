"""
Prioritisation: score = impact x confidence x urgency x role relevance x learned weight, every factor visible. Plus near-duplicate folding, compound
(cross-module) insights built from shared entities, and a per-role cap.

Correlation is deterministic: two insights are connected when they name the same entity key (asset:NAME, app:NAME, cve:ID). The keys are the same
identities the relationship graphs (remediation/graphs) are built from; this module reads the insights' own entities rather than rebuilding a graph, and
there is no ontology layer in the repository to consult.
"""
import collections

from remediation.insights.model import make

DEFAULT_RELEVANCE = 0.3     # a role the detector did not rate still sees the insight, ranked low


def learned_weights(counts, cfg):
    """counts: {detector: {"acted": n, "dismissed": n}} -> {detector: weight}. Weight is 1.0 until `min_actions` actions exist, then
    1 + strength * (acted - dismissed) / total, clamped to [min_weight, max_weight]. Snoozes are not counted: they say "not now", not "not useful"."""
    lc = cfg.get("learning") or {}
    lo, hi, strength, min_a = lc.get("min_weight", 0.6), lc.get("max_weight", 1.4), lc.get("strength", 0.4), lc.get("min_actions", 5)
    out = {}
    for det, c in (counts or {}).items():
        acted, dismissed = c.get("acted", 0), c.get("dismissed", 0)
        total = acted + dismissed
        w = 1.0 if total < min_a else 1 + strength * (acted - dismissed) / total
        out[det] = round(max(lo, min(hi, w)), 3)
    return out


def score(ins, role, weights):
    """Attaches `score` (0-100) and `breakdown` for the given role lens. Returns the same dict."""
    impact, conf, urg = ins["impact"]["value"], ins["confidence"]["value"], ins["urgency"]
    rel = ins["roles"].get(role, DEFAULT_RELEVANCE)
    w = weights.get(ins["detector"], 1.0)
    raw = impact * conf * urg * rel * w
    ins["score"] = round(min(1.0, raw) * 100, 1)
    ins["breakdown"] = {"impact": impact, "confidence": conf, "urgency": urg, "role_relevance": rel, "learned_weight": w, "role": role,
                        "formula": "impact x confidence x urgency x role relevance x learned weight"}
    return ins


def fold_duplicates(items):
    """Near-duplicates: same kind, module and primary entity (or the same title). The highest-scored one is kept and records the ids it absorbed."""
    best = {}
    for ins in items:
        primary = ins["entities"][0] if ins["entities"] else ins["title"]
        k = (ins["kind"], ins["module"], primary)
        if k not in best:
            best[k] = ins
            continue
        keep, other = (ins, best[k]) if ins.get("score", 0) > best[k].get("score", 0) else (best[k], ins)
        keep.setdefault("folded", []).extend([other["id"]] + other.get("folded", []))
        best[k] = keep
    return list(best.values())


def correlate(insights, cfg):
    """Compound insights: an entity named by at least `min_insights` insights (from at least two detectors) becomes one correlation insight whose
    impact is the strongest member plus a step per extra member and whose confidence is the members' mean. Members are linked, never removed."""
    need = (cfg.get("correlation") or {}).get("min_insights", 3)
    by = collections.defaultdict(list)
    for ins in insights:
        for e in ins["entities"]:
            if not e.startswith("cve:"):
                by[e].append(ins)
    out = []
    for e, members in by.items():
        if len(members) < need or len({m["detector"] for m in members}) < 2:
            continue
        kind, name = e.split(":", 1)
        impact = min(1.0, max(m["impact"]["value"] for m in members) + 0.1 * (len(members) - 1))
        conf = sum(m["confidence"]["value"] for m in members) / len(members)
        urg = max(m["urgency"] for m in members)
        roles = {r: max(m["roles"].get(r, 0) for m in members) for r in ("admin", "analyst", "appsec", "exec")}
        mods = sorted({m["module"] for m in members})
        c = make("correlation", e, "correlation", "core", f"{name} shows up in {len(members)} separate insights",
                 f"{kind} '{name}' is named by {len(members)} insights across {', '.join(mods)}: " + "; ".join(m["title"] for m in members[:4]) + ".",
                 "Independent signals pointing at the same thing are far less likely to be coincidence, and one fix may address several of them.",
                 evidence=[{"label": m["title"], "type": "insight", "ref": m["id"], "page": ""} for m in members[:6]], impact=impact,
                 impact_text=f"{len(members)} related signals", confidence=conf, confidence_reason=f"Mean confidence of the {len(members)} member insights; matched on the exact entity key {e}.",
                 action_label="Review them together", action_page=members[0]["action"]["page"], action_role=members[0]["action"]["role"], roles=roles, entities=[e],
                 teams=sorted({t for m in members for t in m["teams"]}), admin_only=all(m["admin_only"] for m in members), urgency=urg)
        c["members"] = [m["id"] for m in members]
        out.append(c)
    return out


def rank_for_role(insights, role, weights, cap, now_state=None):
    """Scores for `role`, folds duplicates, sorts best-first and applies the cap. `now_state` is {id: state} for already-dismissed/snoozed filtering is done by the service."""
    scored = [score(dict(i), role, weights) for i in insights]
    scored = fold_duplicates(sorted(scored, key=lambda i: -i["score"]))
    scored.sort(key=lambda i: (-i["score"], i["id"]))
    return scored[:cap]
