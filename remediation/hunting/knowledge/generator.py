"""
The knowledge generator for the hunt engine: threat groups and malware families that are relevant to THIS estate, expanded into their ATT&CK techniques from the catalog,
and turned into hypotheses for the techniques nothing covers and nobody hunted recently.

Relevance comes only from records Quanta holds:
  * a stored threat-intelligence report names the group (by name or alias) or the family;
  * the group is documented by MITRE as targeting the `industry` set in hunt_engine.yaml (the curated cross-reference in enrichment/threat_actor_groups.py);
  * the group's techniques are already tagged on your open findings or alerts (shown as overlap, never as attribution).
A group nothing points at is not suggested just because the catalog holds it.

For each relevant group the hypothesis tests the techniques that are (a) not claimed by an enabled detection rule and (b) not hunted in the last `recent_hunt_days`, up to
`max_techniques`, preferring techniques that have ready-made leads from the scenario packs, then those tagged in your estate. When no rules are recorded, coverage is unknown
and every technique counts as uncovered, the hypothesis says so, and the engine's score treats coverage as a third (never as covered).

Data readiness names the data classes the hypothesis needs (from the scenarios and the catalog's data components) and what Quanta can tell about each: connected, held,
alerts seen, or cannot tell. A pure function of the Context, like every generator.
"""
import datetime

from remediation.enrichment import threat_actor_groups
from remediation.hunting import usecases
from remediation.hunting.engine import model as m
from remediation.hunting.knowledge import catalog as cat, config as kcfg, data_needs, readiness, scenarios

CAP_EVIDENCE = 8
m.LINKS.setdefault("catalog", "/hunting?tab=library")   # evidence that names an entry of the ATT&CK/ATLAS catalog (a group or a malware family)


def _parent(t):
    return cat.parent_id(t)


def _estate_techniques(ctx):
    seen = {}
    for f in ctx.open_findings():
        for t in f.get("attack_techniques") or []:
            if t.get("technique_id"):
                seen.setdefault(_parent(t["technique_id"]), []).append(("finding", f))
    for a in ctx.alerts or []:
        if a.get("technique") and a.get("status") != "closed":
            seen.setdefault(_parent(a["technique"]), []).append(("alert", a))
    return seen


def _recent_hunted(ctx, days):
    out = set()
    for h in ctx.hunts or []:
        d = ctx.days_since(h.get("created_at") or h.get("updated_at"))
        if d is None or d <= days:
            for t in h.get("techniques") or []:
                if t.get("technique_id"):
                    out.add(_parent(t["technique_id"]))
    return out


def scenarios_for(tids, scn=None):
    """Scenarios whose techniques overlap `tids` (sub-technique ids match their parent), best overlap first."""
    scn = scn if scn is not None else scenarios.load()
    want = {str(t).upper() for t in tids}
    wparents = {_parent(t) for t in want}
    scored = []
    for s in scn:
        n = len({t.upper() for t in s["techniques"]} & want) * 2 + len({_parent(t) for t in s["techniques"]} & wparents)
        if n:
            scored.append((-n, s["id"], s))
    return [s for _, _, s in sorted(scored, key=lambda x: (x[0], x[1]))]


def pick_techniques(c, tids, covered, hunted, estate, scn, cap):
    """Uncovered, not recently hunted techniques of `tids`, ranked: has a scenario lead, tagged in the estate, a new tactic, then id. Returns (picked, skipped_counts)."""
    lead_techs = {_parent(t) for s in scn for ld in s["leads"] for t in [ld["technique"]]}
    skip = {"covered": 0, "recent": 0, "unknown_id": 0}
    cand = []
    for t in dict.fromkeys(str(x).upper() for x in tids):
        r = c.resolve(t)
        if not r:
            skip["unknown_id"] += 1
            continue
        p = _parent(r)
        if p in covered:
            skip["covered"] += 1
            continue
        if p in hunted:
            skip["recent"] += 1
            continue
        cand.append(r)
    ranked, tactics = [], set()
    pool = sorted(cand, key=lambda t: (_parent(t) not in lead_techs, _parent(t) not in estate, t))
    # a first pass takes one technique per tactic, so a hypothesis spans the intrusion rather than clustering on one stage
    for t in pool:
        tac = (c.technique(t, detail=False).get("tactics") or ["?"])[0]
        if tac not in tactics and len(ranked) < cap:
            ranked.append(t)
            tactics.add(tac)
    for t in pool:
        if t not in ranked and len(ranked) < cap:
            ranked.append(t)
    return ranked, skip


def _intel_mentions(ctx, c):
    """{group id: [reports]} and {software id: [reports]} for stored reports that name them (actors by alias; families by name in the title)."""
    groups, software = {}, {}
    for r in ctx.intel or []:
        x = r.get("extracted") or {}
        for a in x.get("actors") or []:
            rid = c.resolve_actor(a)
            if rid and rid.upper() in c.groups:
                groups.setdefault(rid.upper(), []).append(r)
        title = str(r.get("title") or "").lower()
        for sid, s in c.software.items():
            names = [s["name"], *s.get("aliases", [])]
            if any(len(n) >= 5 and n.lower() in title for n in names):
                software.setdefault(sid, []).append(r)
    return groups, software


def _industry_groups(ctx, c):
    out = {}
    if not ctx.industry:
        return out
    for g in threat_actor_groups.THREAT_ACTOR_GROUPS:
        if ctx.industry in g["target_industries"] and g.get("status") == "active" and g["id"].upper() in c.groups:
            out[g["id"].upper()] = g
    return out


def _sig_for(ctx, reports, estate_hits, tids):
    rel = max([float(r.get("relevance") or 0) for r in reports] or [0])
    fresh = min([d for d in (ctx.days_since(r.get("received_at")) for r in reports) if d is not None] or [None]) if reports else None
    kev = any(((f.get("kev") or {}).get("listed")) for kind, f in estate_hits if kind == "finding")
    return {"intel_relevance": rel, "freshness_days": fresh, "kev": kev, "blast": len({(f.get("asset") or {}).get("name") for kind, f in estate_hits if kind == "finding"} - {None}),
            "anomaly": False}


def _evidence_for(reports, estate_hits, subject_ev):
    why = [subject_ev]
    for r in reports[:3]:
        why.append(m.ev("intel", r["id"], r["title"], "; ".join(r.get("reasons") or [])[:250], strong=r.get("priority") == "high"))
    seen = set()
    for kind, rec in estate_hits:
        if kind == "finding" and rec["id"] not in seen and len(why) < CAP_EVIDENCE:
            seen.add(rec["id"])
            why.append(m.ev("finding", rec["id"], f"{rec['id']} on {(rec.get('asset') or {}).get('name')}", rec.get("title") or rec.get("cve") or "", strong=bool((rec.get("kev") or {}).get("listed"))))
        elif kind == "alert" and f"a{rec['id']}" not in seen and len(why) < CAP_EVIDENCE:
            seen.add(f"a{rec['id']}")
            why.append(m.ev("alert", rec["id"], rec["title"], f"{rec.get('severity')}, technique {rec.get('technique')}"))
    return why


def _build_one(ctx, c, kind, rec, relevance_notes, reports, tids_all, covered, hunted, estate, scn_all, sig, gcfg, rules_known):
    picked, skip = pick_techniques(c, tids_all, covered, hunted, estate, scn_all, int(gcfg["max_techniques"]))
    if not picked:
        return None, skip
    matched = scenarios_for(picked, scn_all)[:4]
    names = [c.technique(t, detail=False)["name"] for t in picked]
    who = f"{rec['name']}" + (f" (also known as {', '.join(rec.get('aliases', [])[:2])})" if rec.get("aliases") else "") if kind == "group" else f"{rec['name']} ({rec['type']})"
    behaviours = [s["title"] if (s["title"].split(" ")[0].isupper() or s["title"][1:2].isupper()) else s["title"][0].lower() + s["title"][1:] for s in matched[:3]]
    expect = (f"behaviour such as {'; '.join(behaviours)}, and activity matching {', '.join(names[:4])}" if behaviours else f"activity matching {', '.join(names[:5])}")
    hits = [h for t in picked for h in estate.get(_parent(t), [])]
    assets = sorted({(f.get("asset") or {}).get("name") for k, f in hits if k == "finding"} - {None}) + sorted({a["asset"] for k, a in hits if k == "alert" and a.get("asset")})
    subject_ev = m.ev("catalog", rec["id"], f"{rec['name']}: {relevance_notes}", f"MITRE {rec['id']}; {len(rec.get('techniques', []))} documented techniques; {len(picked)} tested here"[:290])
    why = _evidence_for(reports, hits, subject_ev)
    needed = []
    for s in matched:
        for d in s["data_sources"]:
            if d not in needed:
                needed.append(d)
    for t in picked:
        for d in data_needs.classes_for_technique(c, t):
            if d not in needed:
                needed.append(d)
    sigl = readiness.signals(ctx.connections, ctx.alerts, ctx.entitlements, (getattr(ctx, "data_signals", None) or {}).get("asm_assets"))
    rd = readiness.assess(needed[:6], sigl)
    extra, seen = [], set()
    for s in matched:
        for q in scenarios.engine_queries(s, assets[:50]):
            if cat.related(q["technique"], picked) and (q["name"] not in seen):
                seen.add(q["name"])
                extra.append(q)
    extra = extra[:8]
    sev = [s["severity"] for s in matched]
    malicious = []
    benign = []
    for s in matched[:3]:
        malicious += s["malicious"][:2]
        benign += s["benign"][:2]
    h = m.build("knowledge-" + kind, "intel-driven", f"{kind}:{rec['id']}", picked[0], f"Is {rec['name']} tradecraft present?" if kind == "group" else f"Is {rec['name']} present?", who, expect,
                f"{len(assets)} host(s) tagged with those techniques" if assets else "the systems those techniques would touch", why, picked, assets=assets, signals=dict(sig),
                malicious=malicious or [f"Behaviour for {', '.join(names[:3])} on in-scope hosts"], benign=benign or ["Common administrative activity: many techniques are shared by normal operations and by many groups"],
                scoping=f"Last 30 days, hosts carrying the matching findings first. This tests {len(picked)} technique(s) {rec['name']} is documented to use; it is a cross-reference to MITRE's catalogue, not attribution.",
                next_step="Review the data readiness, run the leads you can in your own tool, and record each result." + ("" if rules_known else " No detection rules are recorded, so coverage of these techniques could not be judged."),
                soar={"suggested": "Open a case and enrich indicators", "note": "Containment needs a named approver."},
                source_note=f"Group and technique data from MITRE ATT&CK {c.meta.get('enterprise', {}).get('version', '')}; overlap with your estate is a cross-reference, not attribution.")
    h["signals"] = {k: v for k, v in h["signals"].items() if v is not None}
    h["extra_queries"] = extra
    h["data_readiness_override"] = readiness.to_engine_shape(rd)
    h["knowledge"] = {"origin": "intel-knowledge", "subject": {"kind": kind, "id": rec["id"], "name": rec["name"]}, "scenarios": [s["id"] for s in matched], "techniques_tested": picked,
                      "skipped": skip, "data_classes": needed[:6], "readiness": rd, "severity_hint": max(sev, key=["low", "medium", "high", "critical"].index) if sev else None,
                      "catalog": {"version": c.meta.get("enterprise", {}).get("version"), "retrieved": (c.manifest or {}).get("retrieved")},
                      "report_hint": {"subject": {"kind": kind, "id": rec["id"]}}}
    return h, skip


def gen_knowledge(ctx, lib):
    kc = kcfg.load()
    c = cat.get()
    if not kc["enabled"]:
        return [], []
    if not c.available:
        return [], ["The ATT&CK/ATLAS catalog is not loaded (run scripts/build_hunt_knowledge.py), so no group or malware-family hypotheses were generated."]
    gcfg = kc["generator"]
    gaps = []
    covered = usecases.covered_techniques(ctx.rules) if ctx.rules else set()
    rules_known = bool(ctx.rules)
    if not rules_known:
        gaps.append("No detection rules are recorded, so which techniques are already covered could not be judged; every technique counts as uncovered and coverage is scored as unknown.")
    hunted = _recent_hunted(ctx, int(gcfg["recent_hunt_days"]))
    estate = _estate_techniques(ctx)
    scn_all = scenarios.load()
    g_intel, s_intel = _intel_mentions(ctx, c)
    g_ind = _industry_groups(ctx, c) if gcfg["use_industry"] else {}
    if not ctx.industry:
        gaps.append("No industry is set in remediation/config/hunt_engine.yaml, so groups are suggested only from stored intelligence reports and your own tagged findings, not from your sector.")
    if not ctx.intel:
        gaps.append("No threat-intelligence reports are imported, so groups and families named in current reporting could not be matched.")
    out = []
    # ---- groups
    cands = {}
    for gid, reps in g_intel.items():
        cands.setdefault(gid, {"notes": [], "reports": []})["notes"].append(f"named in {len(reps)} stored report(s)")
        cands[gid]["reports"] += reps
    for gid, g in g_ind.items():
        cands.setdefault(gid, {"notes": [], "reports": []})["notes"].append(f"documented by MITRE as targeting {ctx.industry}")
    ranked = []
    for gid, info in cands.items():
        g = c.groups[gid]
        overlap = sorted({_parent(t) for t in g.get("techniques", [])} & set(estate))
        if gcfg["min_estate_overlap"] and not info["reports"] and len(overlap) < int(gcfg["min_estate_overlap"]):
            continue
        if overlap:
            info["notes"].append(f"{len(overlap)} of its techniques are tagged in your estate")
        ranked.append((-(len(info["reports"]) * 3 + (2 if gid in g_ind else 0) + len(overlap)), gid))
    for _, gid in sorted(ranked)[: int(gcfg["max_groups"])]:
        info, g = cands[gid], c.groups[gid]
        hits = [h for t in g.get("techniques", []) for h in estate.get(_parent(t), [])]
        h, skip = _build_one(ctx, c, "group", g, "; ".join(info["notes"]), info["reports"], g.get("techniques", []), covered, hunted, estate, scn_all, _sig_for(ctx, info["reports"], hits, g.get("techniques", [])), gcfg, rules_known)
        if h:
            out.append(h)
        else:
            gaps.append(f"{g['name']} is relevant ({'; '.join(info['notes'])}) but every one of its catalogued techniques is covered by an enabled rule or was hunted in the last {gcfg['recent_hunt_days']} days.")
    # ---- software (malware families and tools)
    scands = {}
    for sid, reps in s_intel.items():
        scands.setdefault(sid, {"notes": [], "reports": []})["notes"].append(f"named in {len(reps)} stored report(s)")
        scands[sid]["reports"] += reps
    shared = {}
    for _, gid in ranked:
        for sid in c.groups[gid].get("software", []):
            s = c.software.get(sid.upper())
            if s and s["type"] == "malware":
                shared.setdefault(sid.upper(), set()).add(gid)
    for sid, gs in shared.items():
        if len(gs) >= 2:
            scands.setdefault(sid, {"notes": [], "reports": []})["notes"].append(f"used by {len(gs)} groups relevant to you")
    for sid in sorted(scands, key=lambda k: (-len(scands[k]["reports"]), -len(shared.get(k, ())), k))[: int(gcfg["max_software"])]:
        s, info = c.software[sid], scands[sid]
        hits = [h for t in s.get("techniques", []) for h in estate.get(_parent(t), [])]
        h, skip = _build_one(ctx, c, "software", s, "; ".join(info["notes"]), info["reports"], s.get("techniques", []), covered, hunted, estate, scn_all, _sig_for(ctx, info["reports"], hits, s.get("techniques", [])), gcfg, rules_known)
        if h:
            out.append(h)
    if not out and not gaps:
        gaps.append("Nothing in your reports, sector or tagged findings points at a threat group or malware family, so none was suggested from the catalog.")
    return out, gaps
