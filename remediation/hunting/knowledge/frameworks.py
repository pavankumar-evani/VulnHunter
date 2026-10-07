"""
Analytic framework views for a hypothesis or a hunt report: the Diamond Model, the Lockheed Martin Cyber Kill Chain, the MITRE tactic position, the Unified Kill Chain,
the PEAK phase with the concrete next action, and the hunt maturity level. Returned as structured JSON for the UI.

Rule for all of it: a field is filled from the catalog, a stored intelligence report, or the hunt's own scope, and says where it came from. Where nothing supports an
answer it is "unknown" (or "cannot-tell"); nothing is invented, and technique overlap with a threat group is shown as a CANDIDATE, never as attribution.
"""
from remediation.hunting.knowledge import catalog as cat

KILL_CHAIN = [("reconnaissance", "Reconnaissance"), ("weaponization", "Weaponization"), ("delivery", "Delivery"), ("exploitation", "Exploitation"), ("installation", "Installation"),
              ("command-and-control", "Command and control"), ("actions-on-objectives", "Actions on objectives")]
# An indicative mapping of tactics to Lockheed Martin phases (the model predates the tactic list, so several tactics have no exact home).
TACTIC_TO_KILL_CHAIN = {
    "reconnaissance": "reconnaissance", "resource-development": "weaponization", "ai-attack-staging": "weaponization", "initial-access": "delivery", "ai-model-access": "delivery",
    "execution": "exploitation", "privilege-escalation": "exploitation", "persistence": "installation", "defense-evasion": "installation", "stealth": "installation",
    "defense-impairment": "installation", "evasion": "installation", "command-and-control": "command-and-control", "credential-access": "actions-on-objectives",
    "discovery": "actions-on-objectives", "lateral-movement": "actions-on-objectives", "collection": "actions-on-objectives", "exfiltration": "actions-on-objectives",
    "impact": "actions-on-objectives", "inhibit-response-function": "actions-on-objectives", "impair-process-control": "actions-on-objectives"}
UNIFIED = [("reconnaissance", "Reconnaissance", "in"), ("weaponization", "Weaponization", "in"), ("delivery", "Delivery", "in"), ("social-engineering", "Social engineering", "in"),
           ("exploitation", "Exploitation", "in"), ("persistence", "Persistence", "in"), ("defense-evasion", "Defence evasion", "in"), ("command-and-control", "Command and control", "in"),
           ("pivoting", "Pivoting", "through"), ("discovery", "Discovery", "through"), ("privilege-escalation", "Privilege escalation", "through"), ("execution", "Execution", "through"),
           ("credential-access", "Credential access", "through"), ("lateral-movement", "Lateral movement", "through"), ("collection", "Collection", "out"),
           ("exfiltration", "Exfiltration", "out"), ("impact", "Impact", "out"), ("objectives", "Objectives", "out")]
TACTIC_TO_UNIFIED = {"reconnaissance": "reconnaissance", "resource-development": "weaponization", "ai-attack-staging": "weaponization", "initial-access": "delivery", "ai-model-access": "delivery",
                     "execution": "execution", "persistence": "persistence", "privilege-escalation": "privilege-escalation", "defense-evasion": "defense-evasion", "stealth": "defense-evasion",
                     "defense-impairment": "defense-evasion", "evasion": "defense-evasion", "credential-access": "credential-access", "discovery": "discovery",
                     "lateral-movement": "lateral-movement", "collection": "collection", "command-and-control": "command-and-control", "exfiltration": "exfiltration", "impact": "impact",
                     "inhibit-response-function": "impact", "impair-process-control": "impact"}
DIRECTION = {"reconnaissance": "adversary-to-infrastructure", "resource-development": "adversary-to-infrastructure", "initial-access": "infrastructure-to-victim",
             "command-and-control": "bidirectional", "exfiltration": "victim-to-infrastructure"}
HMM = {0: ("Initial", "Relies on automated alerting; little routine data collection."), 1: ("Minimal", "Searches driven by threat intelligence on centrally collected data."),
       2: ("Procedural", "Follows hunt procedures published by others, adapting them to your data."),
       3: ("Innovative", "Creates new hunt procedures from your own data and hypotheses."), 4: ("Leading", "Automates successful hunts into detections.")}
HUNT_TYPE_LABEL = {"intel-driven": "Intelligence-driven", "hypothesis-driven": "Hypothesis-driven", "baseline-anomaly": "Baseline / anomaly", "model-assisted": "Model-assisted"}


def _slug(x):
    return str(x or "").strip().lower().replace(" ", "-").replace("/", "-")


def tactic_slugs(tid, c=None):
    """The tactics of a technique as slugs ('stealth', 'initial-access', ...). ATLAS tactic ids are turned into their names."""
    c = c or cat.get()
    t = c.technique(tid, detail=False)
    if not t:
        return []
    if t["framework"] == "atlas":
        return [_slug(c.tactic_name.get(("atlas", x), x)) for x in t.get("tactics", [])]
    return [_slug(x) for x in t.get("tactics", [])]


def _techs(ids, c):
    out = []
    for i in dict.fromkeys(str(x).upper() for x in ids or []):
        r = c.resolve(i)
        t = c.technique(r, detail=False) if r else None
        out.append({"id": r or i, "given_as": i if r and r != i else None, "name": t["name"] if t else None, "known": bool(t), "framework": t["framework"] if t else None,
                    "tactics": tactic_slugs(r, c) if r else []})
    return out


# ---------------------------------------------------------------- kill chain, tactic position, unified kill chain
def kill_chain_view(technique_ids, c=None):
    c = c or cat.get()
    techs = _techs(technique_ids, c)
    phases = {k: [] for k, _ in KILL_CHAIN}
    unmapped = []
    for t in techs:
        hit = {TACTIC_TO_KILL_CHAIN[s] for s in t["tactics"] if s in TACTIC_TO_KILL_CHAIN}
        if not hit:
            unmapped.append(t["id"])
        for ph in hit:
            phases[ph].append(t["id"])
    covered = [k for k, _ in KILL_CHAIN if phases[k]]
    return {"model": "Lockheed Martin Cyber Kill Chain", "mapping": "indicative: the model predates the ATT&CK tactic list",
            "phases": [{"id": k, "label": lbl, "techniques": phases[k], "covered": bool(phases[k])} for k, lbl in KILL_CHAIN], "covered": covered,
            "earliest": covered[0] if covered else None, "latest": covered[-1] if covered else None, "unmapped_techniques": unmapped,
            "reading": ("Unknown: no technique with a known tactic" if not covered else
                        (f"Evidence for this hypothesis would fall in the {dict(KILL_CHAIN)[covered[0]]} phase." if covered[0] == covered[-1] else
                         f"Evidence for this hypothesis would fall between {dict(KILL_CHAIN)[covered[0]]} and {dict(KILL_CHAIN)[covered[-1]]}; breaking it at the earliest of these stops the later ones."))}


def attack_position_view(technique_ids, c=None):
    """Where the techniques sit across the tactics of their framework, in the framework's own order."""
    c = c or cat.get()
    techs = _techs(technique_ids, c)
    out = []
    for fw in dict.fromkeys(t["framework"] for t in techs if t["framework"]):
        order = [(_slug(t.get("shortname") or t["name"]), t["name"]) for t in c.tactics.get(fw, [])]
        if fw == "atlas":
            order = [(_slug(t["name"]), t["name"]) for t in c.tactics["atlas"]]
        cols = [{"tactic": slug, "name": name, "techniques": [t["id"] for t in techs if t["framework"] == fw and slug in t["tactics"]]} for slug, name in order]
        hit = [i for i, col in enumerate(cols) if col["techniques"]]
        out.append({"framework": fw, "label": cat.LABEL[fw], "tactics": cols, "first": cols[hit[0]]["name"] if hit else None, "last": cols[hit[-1]]["name"] if hit else None,
                    "position": {"first_index": hit[0] + 1, "last_index": hit[-1] + 1, "of": len(cols)} if hit else None})
    return out


def unified_view(technique_ids, c=None):
    c = c or cat.get()
    techs = _techs(technique_ids, c)
    ph = {k: [] for k, _, _ in UNIFIED}
    for t in techs:
        for s in t["tactics"]:
            k = TACTIC_TO_UNIFIED.get(s)
            if k:
                ph[k].append(t["id"])
    return {"model": "Unified Kill Chain", "mapping": "indicative: derived from each technique's tactics; the social-engineering, pivoting and objectives phases have no ATT&CK tactic and stay empty",
            "phases": [{"id": k, "label": lbl, "stage": stage, "techniques": sorted(set(ph[k])), "covered": bool(ph[k])} for k, lbl, stage in UNIFIED]}


# ---------------------------------------------------------------- diamond
def _direction(tactics):
    d = {DIRECTION[t] for t in tactics if t in DIRECTION}
    if len(d) == 1:
        return {"value": d.pop(), "basis": "derived from the tactic"}
    return {"value": "unknown", "basis": "the tactics span more than one direction" if d else "no tactic implies a direction"}


def diamond(s, c=None):
    """`s` is the subject: {techniques, scope, intel, groups, software, scenario, outcome, lookback_days, industry, evidence_dates}. See `views()`."""
    c = c or cat.get()
    techs = _techs(s.get("techniques"), c)
    tactics = sorted({t for x in techs for t in x["tactics"]})
    # adversary
    adv_items, status, notes = [], "unknown", []
    for r in s.get("intel") or []:
        for a in (r.get("extracted") or {}).get("actors") or []:
            adv_items.append({"value": a, "detail": "named in a stored intelligence report", "source": f"intel report: {r.get('title')}"})
            status = "named-by-intel"
    for g in s.get("groups") or []:
        adv_items.append({"value": g["name"], "detail": f"MITRE {g['id']}; aliases: {', '.join(g.get('aliases', [])[:4]) or 'none listed'}", "source": f"catalog {g['id']}"})
        status = status if status == "named-by-intel" else "hypothesised"
    for sw in s.get("software") or []:
        notes.append(f"Hunting for {sw['name']} ({sw['id']}); the operator behind it is not known.")
    if status == "hypothesised":
        notes.append("This hunt tests whether this group's behaviour is present. It is a hypothesis about tradecraft, not an attribution.")
    cand = []
    if not adv_items and techs:
        want = {t["id"].upper() for t in techs if t["known"]}
        for gid, g in c.groups.items():
            used = want & {x.upper() for x in g.get("techniques", [])}
            if used and len(want) >= 2 and len(used) / len(want) >= 0.6:
                cand.append({"id": gid, "name": g["name"], "overlap": f"{len(used)} of {len(want)} techniques", "ratio": round(len(used) / len(want), 2)})
        cand.sort(key=lambda x: (-x["ratio"], x["id"]))
        if cand:
            notes.append("Groups below use these techniques. Many groups share common techniques: this is a place to start reading, not attribution.")
    adversary = {"status": status, "items": adv_items, "candidates": cand[:5], "note": " ".join(notes) or "No report or selection names an adversary, so none is shown."}
    # capability
    cap_items = [{"value": f"{t['name']} ({t['id']})", "detail": ", ".join(t["tactics"]) or "tactic unknown", "source": "catalog"} for t in techs if t["known"]]
    for sw in (s.get("software") or [])[:8]:
        cap_items.append({"value": f"{sw['name']} ({sw['id']})", "detail": sw.get("type", "software"), "source": f"catalog {sw['id']}"})
    if not s.get("software") and techs:
        tops = {}
        for t in techs:
            for sid in c.software_by_tech.get(t["id"].upper(), []):
                tops[sid] = tops.get(sid, 0) + 1
        for sid, n in sorted(tops.items(), key=lambda kv: (-kv[1], kv[0]))[:4]:
            if n >= 2 or len(techs) == 1:
                cap_items.append({"value": f"{c.software[sid]['name']} ({sid})", "detail": f"{c.software[sid]['type']} known to use {n} of these techniques", "source": "catalog join (known to use, not observed here)"})
    cap_hints = list(((s.get("scenario") or {}).get("diamond") or {}).get("capability") or [])
    capability = {"status": "known" if cap_items else "unknown", "items": cap_items, "hints": cap_hints, "note": "Techniques come from the catalog; software is listed as known to use them, not as seen in your estate."}
    # infrastructure
    inf_items = []
    for r in s.get("intel") or []:
        x = r.get("extracted") or {}
        for kind in ("ips", "domains", "hashes", "urls"):
            for v in (x.get(kind) or [])[:10]:
                inf_items.append({"value": v, "detail": kind[:-1], "source": f"intel report: {r.get('title')}"})
    inf_hints = list(((s.get("scenario") or {}).get("diamond") or {}).get("infrastructure") or [])
    infrastructure = {"status": "indicators-known" if inf_items else "unknown", "items": inf_items[:40], "hints": inf_hints,
                      "note": "Indicators come only from stored intelligence reports. The hints say what to look for; they are not observations."}
    # victim
    sc = s.get("scope") or {}
    vic_items = [{"value": a, "detail": "asset", "source": "hunt scope"} for a in (sc.get("assets") or [])[:30]] + [{"value": i, "detail": "identity", "source": "hunt scope"} for i in (sc.get("identities") or [])[:30]]
    vic_items += [{"value": seg, "detail": "segment", "source": "hunt scope"} for seg in (sc.get("segments") or [])[:10]]
    victim = {"status": "scoped" if vic_items else "unknown", "items": vic_items, "hints": list(((s.get("scenario") or {}).get("diamond") or {}).get("victim") or []),
              "industry": s.get("industry"), "note": "Scope comes from the records that raised the hypothesis; with none, the whole estate is in scope and the victim is unknown."}
    # meta-features
    dates = [d for d in s.get("evidence_dates") or [] if d]
    meta = {"timestamp": {"lookback_days": s.get("lookback_days"), "first_evidence": min(dates) if dates else "unknown", "last_evidence": max(dates) if dates else "unknown"},
            "phase": {"kill_chain": kill_chain_view(s.get("techniques"), c)["covered"], "tactics": tactics},
            "result": {"value": "activity-confirmed" if s.get("outcome") == "true-positive" else "unknown",
                       "basis": "a person concluded the hunt as a true positive" if s.get("outcome") == "true-positive" else "no conclusion has been recorded; benign or inconclusive outcomes do not show the adversary failed"},
            "direction": _direction(tactics),
            "methodology": {"value": (s.get("scenario") or {}).get("category") or ("technique-based" if techs else "unknown"), "techniques": [t["name"] for t in techs if t["known"]]},
            "resources": {"value": "unknown", "basis": "the effort or funding behind an adversary is not observable from this data"},
            "technology": sorted({p for t in techs if t["known"] for p in (c.technique(t["id"], detail=False).get("platforms") or [])})}
    return {"model": "Diamond Model of Intrusion Analysis", "vertices": {"adversary": adversary, "capability": capability, "infrastructure": infrastructure, "victim": victim},
            "meta": meta, "unknown_vertices": [k for k, v in (("adversary", adversary), ("capability", capability), ("infrastructure", infrastructure), ("victim", victim)) if v["status"] == "unknown"],
            "note": "Vertices that nothing supports stay 'unknown'. Pivot from any known vertex to fill an unknown one; do not assume it."}


# ---------------------------------------------------------------- PEAK and maturity
def peak(s):
    st = s.get("status") or "report"
    readiness = (s.get("readiness") or {}).get("status")
    has_q = bool(s.get("has_queries"))
    prep = [("Hypothesis stated", bool(s.get("hypothesis"))), ("Techniques identified", bool(s.get("techniques"))),
            ("Data sources named", bool(s.get("data_sources"))), ("Data readiness assessed", readiness is not None), ("Scope defined", bool((s.get("scope") or {}).get("counts", {}) and any((s.get("scope") or {}).get("counts", {}).values())) or bool(s.get("scope_defined"))),
            ("Benign explanations listed", bool(s.get("has_benign"))), ("Leads ready in at least one language", has_q)]
    if st in ("suggested", "report", None):
        phase = "prepare"
        todo = [n for n, done in prep if not done]
        if readiness in ("cannot-tell", "partial"):
            nxt = "Confirm the log sources the leads need are collected where you will run them (the data readiness section lists them), then accept the hunt."
        elif todo:
            nxt = "Finish preparation: " + "; ".join(todo[:3]) + "."
        else:
            nxt = "Accept the hunt to create it, then run the leads in your own tool (or confirm a Splunk search) and record each result."
    elif st in ("accepted", "running", "evidence-recorded"):
        phase = "execute"
        nxt = "Run the remaining leads, record each result (hits, no hits), pivot on any hit, then conclude." if st != "evidence-recorded" else "Pivot on the recorded hits or conclude the hunt with notes."
    else:
        phase = "act"
        nxt = ("Promote to a detection use case (a proposed draft, not counted as coverage until enabled and evidenced)." if st == "concluded" else
               "Track the detection's health under Detection engineering; feed the lesson back (the learning loop already has the outcome)." if st == "promoted" else "Reopen only if the evidence changes.")
    return {"model": "PEAK (Prepare, Execute, Act)", "current": phase, "next_action": nxt,
            "prepare": [{"item": n, "done": d} for n, d in prep],
            "execute": [{"item": "Run each lead and record the result", "done": st in ("evidence-recorded", "concluded", "promoted")}, {"item": "Pivot on hits and widen scope if needed", "done": st in ("concluded", "promoted")}],
            "act": [{"item": "Conclude with notes", "done": st in ("concluded", "promoted")}, {"item": "Promote the finding to a detection", "done": st == "promoted"},
                    {"item": "Outcome feeds the learning loop", "done": st in ("concluded", "promoted", "dismissed")}]}


def maturity(s):
    gen = s.get("generator") or ""
    origin = s.get("origin") or ("scenario" if s.get("scenario") else "technique")
    if s.get("status") == "promoted":
        lvl, why = 4, "The hunt's finding was promoted to a detection use case."
    elif origin in ("tenant-data", "model-assisted") or gen in ("coverage-gap", "lessons-learned", "model-assisted", "low-and-slow", "alert-burst", "exposed-asset", "identity-misuse"):
        lvl, why = 3, "The hypothesis was derived from your own data, not from a published procedure."
    elif origin in ("scenario", "library", "intel-knowledge"):
        lvl, why = 2, "The hunt follows a published procedure (a scenario or catalog technique) adapted to your data."
    else:
        lvl, why = 1, "The hunt starts from intelligence or a technique id with leads to adapt."
    limit = None
    if (s.get("readiness") or {}).get("status") == "cannot-tell":
        limit = "Quanta cannot tell whether the data these leads need is collected, so the hunt may not be able to run at this level yet."
    name, desc = HMM[lvl]
    return {"model": "Hunting Maturity Model (HMM)", "level": lvl, "label": f"HMM{lvl} {name}", "description": desc, "why": why, "limiting_factor": limit,
            "hunt_type": s.get("hunt_type"), "hunt_type_label": HUNT_TYPE_LABEL.get(s.get("hunt_type"), s.get("hunt_type")),
            "note": "Describes this hunt, not your team's overall maturity."}


def views(s, c=None):
    """All framework views for one subject dict. Keys of `s` (all optional): techniques, scope, intel, groups, software, scenario, outcome, status, lookback_days, industry,
    evidence_dates, readiness, data_sources, hypothesis, has_queries, has_benign, generator, hunt_type, origin."""
    c = c or cat.get()
    return {"diamond": diamond(s, c), "kill_chain": kill_chain_view(s.get("techniques"), c), "attack": attack_position_view(s.get("techniques"), c),
            "unified_kill_chain": unified_view(s.get("techniques"), c), "peak": peak(s), "maturity": maturity(s)}
