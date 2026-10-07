"""
On-demand hunt report packages.

`build(subject, lookback_days, scope, ctx)` assembles, from the catalog, the scenario packs, stored intelligence and the hunt library, everything a person needs to run a hunt on
a technique, a group, a piece of malware, a tactic, an ATLAS technique or a scenario: the hypothesis, the framework views, relevant intelligence with its source, the lead
queries per configured language, data readiness, expected evidence, what a hit means, recommended containment (recommendations for a person), detection and control
recommendations and an execution plan. NOTHING is run: no query is sent anywhere and no customer system is touched. Running stays the existing confirm-gated hunt path;
`create_hunt` turns a report into a hunt through the existing accept flow.
"""
import datetime
import re

from remediation.hunting import detection, usecases
from remediation.hunting.engine import model as m, render as engine_render
from remediation.hunting.knowledge import catalog as cat, config as kcfg, content, data_needs, frameworks, generator, readiness, scenarios

KINDS = ("technique", "group", "software", "scenario", "tactic", "atlas-technique")
MAX_ID = 80


class SubjectError(ValueError):
    """The subject is unknown or malformed (the API answers 400 or 404)."""


def _parent(t):
    return cat.parent_id(t)


def _clean_list(xs, cap=50):
    out = []
    for x in xs or []:
        s = str(x).strip()
        if s and len(s) <= 120 and re.fullmatch(r"[\w.@:/*?\[\]\- ]+", s) and s not in out:
            out.append(s)
    return out[:cap]


def normalise_scope(scope):
    sc = scope or {}
    a, i, s = _clean_list(sc.get("assets")), _clean_list(sc.get("identities")), _clean_list(sc.get("segments"), 20)
    return {"assets": a, "identities": i, "segments": s, "counts": {"assets": len(a), "identities": len(i), "segments": len(s)}}


# ---------------------------------------------------------------- subject resolution
def resolve_subject(kind, sid, c=None):
    """-> {kind, id, name, url, description, techniques, groups, software, scenario, aliases}. Raises SubjectError."""
    c = c or cat.get()
    if kind not in KINDS:
        raise SubjectError(f"kind must be one of {', '.join(KINDS)}")
    sid = str(sid or "").strip()
    if not sid or len(sid) > MAX_ID:
        raise SubjectError("id is required")
    if not c.available:
        raise SubjectError("The catalog is not loaded. Run scripts/build_hunt_knowledge.py first.")
    base = {"kind": kind, "groups": [], "software": [], "scenario": None, "aliases": []}
    if kind in ("technique", "atlas-technique"):
        r = c.resolve(sid)
        t = c.technique(r) if r else None
        if not t:
            raise SubjectError(f"No technique {sid} in the catalog")
        if (kind == "atlas-technique") != (t["framework"] == "atlas"):
            raise SubjectError(f"{t['id']} is a {'ATLAS' if t['framework'] == 'atlas' else 'ATT&CK'} technique; use kind '{'atlas-technique' if t['framework'] == 'atlas' else 'technique'}'")
        techs = [t["id"]] + [x["id"] for x in t["subtechniques"][:6]]
        return {**base, "id": t["id"], "name": t["name"], "url": t["url"], "description": t.get("description", ""), "techniques": techs, "given_as": sid.upper() if sid.upper() != t["id"] else None,
                "framework": t["framework"]}
    if kind == "group":
        g = c.group(sid)
        if not g:
            raise SubjectError(f"No group {sid} in the catalog")
        return {**base, "id": g["id"], "name": g["name"], "url": g["url"], "description": g["description"], "aliases": g.get("aliases", []), "techniques": list(g.get("techniques", [])),
                "groups": [{"id": g["id"], "name": g["name"], "aliases": g.get("aliases", [])}], "software": [{"id": s["id"], "name": s["name"], "type": s["type"]} for s in g["software_details"] if s["name"]][:10]}
    if kind == "software":
        s = c.software_item(sid)
        if not s:
            raise SubjectError(f"No software {sid} in the catalog")
        return {**base, "id": s["id"], "name": s["name"], "url": s["url"], "description": s["description"], "aliases": s.get("aliases", []), "techniques": list(s.get("techniques", [])),
                "software": [{"id": s["id"], "name": s["name"], "type": s["type"]}], "groups": [{"id": g["id"], "name": g["name"], "aliases": []} for g in s["groups"][:10]]}
    if kind == "scenario":
        s = scenarios.get(sid)
        if not s:
            raise SubjectError(f"No scenario {sid}")
        return {**base, "id": s["id"], "name": s["title"], "url": None, "description": s["hypothesis"].replace("{scope}", "the systems in scope"), "techniques": list(s["techniques"]), "scenario": s}
    # tactic
    slug = sid.lower().replace(" ", "-")
    hit = [(fw, t) for fw in ("enterprise", "atlas", "mobile", "ics") for t in c.tactics.get(fw, [])
           if slug in {str(t.get("shortname") or "").lower(), t["id"].lower(), t["name"].lower().replace(" ", "-")}]
    if not hit:
        raise SubjectError(f"No tactic {sid} in the catalog")
    fw, t = hit[0]
    key = t.get("shortname") or t["id"]
    techs = sorted(x["id"] for x in c.techniques.values() if x["framework"] == fw and key in x.get("tactics", []) and not x.get("parent"))
    return {**base, "id": t["id"] if fw == "atlas" else key, "name": f"{t['name']} ({cat.LABEL[fw]})", "url": None, "description": t.get("description", ""), "techniques": techs, "framework": fw}


# ---------------------------------------------------------------- pieces
def _estate(ctx):
    est = generator._estate_techniques(ctx)
    return est


def _technique_rows(c, tids, ctx, covered, hunted, estate, rules_known, lead_parents):
    rows = []
    for tid in tids:
        t = c.technique(tid)
        if not t:
            continue
        p = _parent(t["id"])
        hits = estate.get(p, [])
        rows.append({"id": t["id"], "name": t["name"], "framework": t["framework"], "tactics": t["tactic_names"], "platforms": t.get("platforms", []), "description": t.get("description", ""),
                     "detection_guidance": t.get("detection", []), "data_sources": t.get("data_sources", []), "data_classes": data_needs.classes_for_technique(c, t["id"]),
                     "mitigations": [x["id"] for x in t.get("mitigation_details", [])], "url": t["url"],
                     "covered": (p in covered) if rules_known and t["framework"] != "atlas" else None, "recently_hunted": p in hunted,
                     "in_estate": {"findings": sum(1 for k, _ in hits if k == "finding"), "alerts": sum(1 for k, _ in hits if k == "alert")}, "has_ready_lead": p in lead_parents,
                     "groups": len(t["groups"]), "software": len(t["software"])})
    return rows


def _intel_for(ctx, c, subj, tids):
    want = {_parent(t) for t in tids}
    names = {subj["name"].lower(), *[a.lower() for a in subj.get("aliases", [])]}
    out = []
    for r in ctx.intel or []:
        x = r.get("extracted") or {}
        why = []
        for a in x.get("actors") or []:
            rid = c.resolve_actor(a)
            if rid and any(g["id"].upper() == rid.upper() for g in subj["groups"]):
                why.append(f"names {a}")
        if subj["kind"] in ("group", "software") and any(len(n) >= 5 and n in str(r.get("title") or "").lower() for n in names):
            why.append("its title mentions the subject")
        shared = sorted({_parent(t) for t in x.get("techniques") or []} & want)
        if shared:
            why.append("names technique(s) " + ", ".join(shared[:5]))
        if why:
            out.append({"id": r["id"], "title": r["title"], "priority": r.get("priority"), "relevance": r.get("relevance"), "received_at": r.get("received_at"), "why_relevant": why,
                        "indicators": {k: (x.get(k) or [])[:10] for k in ("ips", "domains", "hashes", "urls") if x.get(k)}, "cves": (x.get("cves") or [])[:10],
                        "source": f"stored intelligence report #{r['id']} ({r.get('source') or 'imported'})", "link": "/hunting?tab=intel"})
    out.sort(key=lambda r: ({"high": 0, "medium": 1, "low": 2}.get(r.get("priority"), 3), -(r.get("relevance") or 0)))
    return out[:10]


def _library_leads(tid, lib):
    entry = lib.get(_parent(tid))
    if not entry:
        return []
    out = []
    for d in entry.get("detections", []):
        out.append({"name": d["name"], "technique": tid, "selection": dict(d["selection"]), "logsource": usecases.LOGSOURCE.get(_parent(tid), {"category": "process_creation"}),
                    "notes": f"{entry.get('hunt', '')}. {entry.get('notes') or ''}".strip(), "_from": "hunt library"})
    return out


def _leads(subj, matched, tids, hosts, kc, lib):
    seen, out = set(), []
    for s in matched:
        for lead in s["leads"]:
            if subj["kind"] != "scenario" and not cat.related(lead["technique"], tids):
                continue
            r = scenarios.render_lead(lead, s, hosts, hyp_text=scenarios.hypothesis_text(s))
            key = (s["id"], lead["name"])
            if key not in seen:
                seen.add(key)
                out.append({**r, "scenario": s["id"], "origin": "scenario pack"})
    have = {_parent(l["technique"]) for l in out}
    for tid in tids:
        if _parent(tid) in have:
            continue
        for lead in _library_leads(tid, lib):
            r = scenarios.render_lead(lead, None, hosts, hyp_text="")
            out.append({**r, "scenario": None, "origin": "hunt library"})
            have.add(_parent(tid))
    out.sort(key=lambda l: (0 if l.get("selection") else 1, l["technique"]))
    cap = int(kc["report"]["max_leads"])
    langs = [lng for lng in kc["languages"] if lng in scenarios.LANGUAGES]
    for l in out:
        l["languages"] = {k: v for k, v in l["languages"].items() if k in langs}
    return out[:cap], [t for t in tids if _parent(t) not in have]


def _short(text, n):
    text = " ".join(str(text or "").split())
    return text if len(text) <= n else text[:n].rsplit(" ", 1)[0].rstrip(",;:") + "..."


def _hypothesis(subj, scope, matched, tech_rows):
    """{statement, who, expect, where, scope_text, basis, template?, detection_guidance?}. The statement has the engine's form: If <who> is active in our environment, we would expect to see <expect> on <where>."""
    if scope["assets"]:
        where = ", ".join(scope["assets"][:3]) + (f" and {scope['counts']['assets'] - 3} other host(s)" if scope["counts"]["assets"] > 3 else "")
    else:
        where = "the systems in scope"

    def make(who, expect, basis, **extra):
        return {"statement": f"If {who} is active in our environment, we would expect to see {expect} on {where}.", "who": who, "expect": expect, "where": where, "scope_text": where, "basis": basis, **extra}

    names = [t["name"] for t in tech_rows[:4]]
    beh = [s["title"] for s in matched[:3]]
    if subj["kind"] == "scenario":
        s = subj["scenario"]
        return {"statement": scenarios.hypothesis_text(s, where), "who": None, "expect": None, "where": where, "scope_text": where, "template": s["hypothesis"], "basis": "hand-authored scenario pack"}
    if subj["kind"] in ("group", "software"):
        who = f"{subj['name']}" + (f" (also known as {', '.join(subj['aliases'][:2])})" if subj["aliases"] else "")
        expect = f"behaviour such as {'; '.join(beh)}, and activity matching {', '.join(names)}" if beh else f"activity matching {', '.join(names)}"
        return make(who, expect, "MITRE's catalogue of the techniques it is documented to use; a hypothesis about tradecraft, not an attribution")
    if subj["kind"] == "tactic":
        return make(f"an adversary working at the {subj['name']} stage", f"activity matching {', '.join(names)}", "the techniques MITRE lists under this tactic")
    t = tech_rows[0] if tech_rows else {"name": subj["name"], "detection_guidance": []}
    det = (t.get("detection_guidance") or [""])[0]
    return make(f"an adversary using {t['name']} ({subj['id']})", f"evidence of {t['name']}, as MITRE's detection guidance describes it,", "MITRE's technique description and detection guidance",
                detection_guidance=_short(det, 220) if det else None)


def _expected(matched):
    mal, ben, tun = [], [], []
    for s in matched:
        mal += s["malicious"]
        ben += s["benign"]
        tun += s["tuning"]
    uniq = lambda xs: list(dict.fromkeys(xs))[:10]  # noqa: E731
    return {"malicious": uniq(mal), "likely_benign": uniq(ben), "tuning": uniq(tun)}


def _hit_meaning(matched, tech_rows):
    out = []
    for s in matched[:5]:
        out.append({"scenario": s["id"], "severity": s["severity"], "priority": s["priority"],
                    "meaning": f"A confirmed hit on '{s['title']}' means {s['malicious'][0][0].lower() + s['malicious'][0][1:]}. Rule out first: {s['benign'][0][0].lower() + s['benign'][0][1:]}."})
    if not out and tech_rows:
        t = tech_rows[0]
        out.append({"scenario": None, "severity": None, "priority": None,
                    "meaning": f"A confirmed hit means {t['name']} behaviour is present. No scenario pack covers it, so there is no curated list of benign look-alikes: ask the owner of the host or account before concluding."})
    return out


def _containment(matched):
    pbs = scenarios.playbooks()
    seen, plays, steps = set(), [], []
    for s in matched:
        pid = s["playbook"]
        if pid in seen or pid not in pbs:
            continue
        seen.add(pid)
        plays.append({"id": pid, **pbs[pid]})
        steps += [x["step"] for x in pbs[pid]["steps"]]
    steps += [r for s in matched[:3] for r in s["response"]]
    return {"playbooks": plays, "recommendations_for_a_person": list(dict.fromkeys(steps))[:12],
            "note": "Recommendations for a person to decide and carry out. Quanta contains nothing and changes nothing; steps marked as needing approval change a customer system."}


def _execution_plan(readiness_status, leads, lookback, has_siem_run):
    first = leads[0]["name"] if leads else "the first lead"
    return [{"order": 1, "phase": "prepare", "who": "hunt lead", "step": "Read the data readiness section and confirm each needed log source is collected where you will run the query. Where it is not, record that the hunt cannot answer, rather than concluding 'nothing found'."},
            {"order": 2, "phase": "prepare", "who": "hunt lead", "step": f"Fix the scope and time box: look back {lookback} days, in-scope hosts or identities first, widening only if something is found."},
            {"order": 3, "phase": "execute", "who": "analyst", "step": f"Run '{first}' and the other leads in your SIEM or EDR in the language you use" + (", or confirm a read-only Splunk search from the hunt record." if has_siem_run else ".") + " Record each result as hits or no hits."},
            {"order": 4, "phase": "execute", "who": "analyst", "step": "For every hit, pivot on the Diamond Model: which vertex is known (host, account, address, tool), and what does it tell you about the others? Rule out the listed benign explanations."},
            {"order": 5, "phase": "act", "who": "analyst", "step": "Conclude the hunt with notes: true positive, benign or inconclusive (needs data). A true positive starts the response in the containment section."},
            {"order": 6, "phase": "act", "who": "detection engineer", "step": "Promote what worked into a detection use case (it will be proposed, not counted as coverage until implemented and evidenced), and add the missing controls to the plan."}]


# ---------------------------------------------------------------- build
def build(kind, sid, ctx, lookback_days=None, scope=None, planned=None, c=None, now=None):
    c = c or cat.get()
    kc = kcfg.load()
    subj = resolve_subject(kind, sid, c)
    try:
        lb = int(lookback_days) if lookback_days is not None else int(kc["report"]["default_lookback_days"])
    except (TypeError, ValueError) as exc:
        raise SubjectError("lookback_days must be a whole number") from exc
    if lb < 1 or lb > int(kc["report"]["max_lookback_days"]):
        raise SubjectError(f"lookback_days must be between 1 and {kc['report']['max_lookback_days']}")
    sc = normalise_scope(scope)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    all_tids = [t for t in dict.fromkeys(x.upper() for x in subj["techniques"]) if c.resolve(t)]
    covered = usecases.covered_techniques(ctx.rules) if ctx.rules else set()
    rules_known = bool(ctx.rules)
    hunted = generator._recent_hunted(ctx, int(kc["generator"]["recent_hunt_days"]))
    estate = generator._estate_techniques(ctx)
    scn_all = scenarios.load()
    lead_parents = {_parent(ld["technique"]) for s in scn_all for ld in s["leads"]}
    # a large subject (a group, a tactic) is cut to the techniques most worth hunting; the rest are listed, not dropped silently
    if subj["kind"] in ("group", "software", "tactic") and len(all_tids) > 12:
        picked, skip = generator.pick_techniques(c, all_tids, set(), set(), estate, scn_all, 12)
        omitted = [t for t in all_tids if t not in picked]
    else:
        picked, omitted, skip = all_tids, [], {}
    matched = [subj["scenario"]] if subj["kind"] == "scenario" else generator.scenarios_for(picked, scn_all)[:6]
    tech_rows = _technique_rows(c, picked, ctx, covered, hunted, estate, rules_known, lead_parents)
    needed = []
    for s in matched:
        for d in s["data_sources"]:
            if d not in needed:
                needed.append(d)
    for t in picked:
        for d in data_needs.classes_for_technique(c, t):
            if d not in needed:
                needed.append(d)
    sig = readiness.signals(ctx.connections, ctx.alerts, ctx.entitlements, (getattr(ctx, "data_signals", None) or {}).get("asm_assets"))
    rd = readiness.assess(needed[:8], sig)
    lib = engine_render.library()
    leads, no_lead = _leads(subj, matched, picked, sc["assets"], kc, lib)
    hyp = _hypothesis(subj, sc, matched, tech_rows)
    intel = _intel_for(ctx, c, subj, picked)
    hunt_type = "intel-driven" if kind in ("group", "software") else "hypothesis-driven"
    fsubj = {"techniques": picked, "scope": sc, "intel": [r for r in (ctx.intel or []) if r["id"] in {i["id"] for i in intel}], "groups": subj["groups"] if kind in ("group", "software") else [],
             "software": subj["software"] if kind == "software" else [], "scenario": matched[0] if matched else None, "outcome": None, "status": "report", "lookback_days": lb, "industry": ctx.industry,
             "evidence_dates": [i["received_at"] for i in intel], "readiness": rd, "data_sources": needed, "hypothesis": hyp["statement"], "has_queries": bool(leads),
             "has_benign": any(s["benign"] for s in matched), "hunt_type": hunt_type, "origin": "scenario" if matched or kind == "scenario" else "technique", "generator": f"knowledge-{kind}"}
    exp = _expected(matched)
    uc = [content.use_case_for(s, c) for s in matched[:4]]
    ctrl = content.controls_for(picked, c, {p["key"]: p for p in planned or []})[:14]
    rules = [{"scenario": s["id"], "name": r["name"], "technique": r["technique"], "sigma_status": r["languages"]["sigma"]["status"], "sigma": r["languages"]["sigma"].get("query"),
              "key": r["key"], "index": r["index"]} for s in matched[:4] for r in content.rules_for(s)][:12]
    cov = [content.coverage(s, rules_known, covered, {u["key"]: u["status"] for u in ctx.usecases or []}) | {"scenario": s["id"]} for s in matched[:6]]
    limits = ["Nothing was run: no query was sent to any system and no customer data was read to build this report.",
              "Catalog data is MITRE's public data as of " + str((c.manifest or {}).get("retrieved") or "unknown date") + "; text is trimmed, follow the links for full detail.",
              "Query field names are Sigma's: map them to your data model. KQL and EQL here are small renderings of the same selection, not tuned production queries.",
              "Data readiness is inferred from connections, alerts and data Quanta holds; it never proves a log source is or is not collected."]
    if not rules_known:
        limits.append("No detection rules are recorded in Quanta, so which techniques are already covered could not be judged.")
    if no_lead:
        limits.append("No ready-made lead exists for " + ", ".join(no_lead[:8]) + ("..." if len(no_lead) > 8 else "") + "; MITRE's detection guidance is listed for each technique instead.")
    if omitted:
        limits.append(f"{len(omitted)} further technique(s) of this subject were not expanded to keep the report usable: " + ", ".join(omitted[:12]) + ("..." if len(omitted) > 12 else ""))
    rep = {"subject": {k: subj[k] for k in ("kind", "id", "name", "url", "description")} | {"aliases": subj.get("aliases", []), "given_as": subj.get("given_as")}, "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
           "lookback_days": lb, "scope": sc, "title": f"Hunt report: {subj['name']}", "catalog": {"attack_version": c.meta.get("enterprise", {}).get("version"), "atlas_version": c.meta.get("atlas", {}).get("version"),
                                                                                           "retrieved": (c.manifest or {}).get("retrieved")},
           "hypothesis": hyp, "techniques": tech_rows, "scenarios": [scenarios.summary(s, c) for s in matched], "intel": intel, "frameworks": frameworks.views(fsubj, c), "data_readiness": rd,
           "leads": leads, "languages": [lng for lng in kc["languages"] if lng in scenarios.LANGUAGES], "expected_evidence": exp, "what_a_hit_means": _hit_meaning(matched, tech_rows),
           "containment": _containment(matched), "recommendations": {"detections": rules, "controls": ctrl, "use_cases": [{"key": u["key"], "title": u["title"], "score": u["score"], "techniques": u["techniques"]} for u in uc],
                                                                       "coverage": cov, "note": "Suggestions only. A use case is proposed, a rule is imported disabled and a control is planned; none counts as coverage or as implemented."},
           "execution_plan": _execution_plan(rd["status"], leads, lb, rd["can_run_in_quanta"]), "limits": limits, "ran_anything": False,
           "actions": {"create_hunt": "POST /api/hunting/knowledge/reports/{id}/create-hunt", "promote": "POST /api/hunting/knowledge/promote", "ai_draft": "POST /api/hunting/knowledge/ai-draft"}}
    return rep


# ---------------------------------------------------------------- hunt creation (through the existing accept flow)
def create_hunt(report, ctx, actor, engine=None):
    """Turns a stored report into a hunt through the engine's own accept flow: a suggestion is recorded (suggested), then accepted, which creates an ordinary `proposed` hunt.
    Nothing runs. Returns {"suggestion": hypothesis, "hunt_id": n}."""
    from remediation.hunting.engine import service as engine_service
    subj = report["subject"]
    tids = [t["id"] for t in report["techniques"]]
    sc = report["scope"]
    why = [m.ev("catalog", subj["id"], f"{subj['name']} (hunt report v{report.get('version', 1)})", "an on-demand hunt report", strong=False)]
    why += [m.ev("intel", i["id"], i["title"], "; ".join(i["why_relevant"])[:250]) for i in report["intel"][:4]]
    raw = m.build("knowledge-report", "intel-driven" if subj["kind"] in ("group", "software") else "hypothesis-driven", f"{subj['kind']}:{subj['id']}", tids[0] if tids else subj["id"], report["title"][:190],
                  (report["hypothesis"].get("who") or "an adversary"), (report["hypothesis"].get("expect") or report["hypothesis"]["statement"].split("we would expect to see ", 1)[-1]), report["hypothesis"]["scope_text"], why, tids, assets=sc["assets"],
                  identities=sc["identities"], segments=sc["segments"], signals={}, malicious=report["expected_evidence"]["malicious"], benign=report["expected_evidence"]["likely_benign"],
                  scoping=f"Look back {report['lookback_days']} days; {report['hypothesis']['scope_text']}.", next_step=report["execution_plan"][2]["step"])
    raw["hypothesis"] = report["hypothesis"]["statement"]
    raw["extra_queries"] = [{"technique": l["technique"], "name": l["name"], "domain": "knowledge", "source": "SIEM", "language": "splunk-spl", "query": l["languages"]["splunk-spl"]["query"],
                             "kql": l["languages"].get("kql", {}).get("query", ""), "sigma": l["languages"].get("sigma", {}).get("query", ""), "eql": l["languages"].get("eql", {}).get("query", ""),
                             "description": (l.get("notes") or "")[:300], "result": None, "notes": "", "scenario": l.get("scenario")}
                            for l in report["leads"] if l["languages"].get("splunk-spl", {}).get("status") == "provided"]
    raw["data_readiness_override"] = readiness.to_engine_shape(report["data_readiness"])
    raw["knowledge"] = {"origin": "report", "subject": subj, "scenarios": [s["id"] for s in report["scenarios"]], "report_version": report.get("version"), "readiness": report["data_readiness"]}
    h = engine_service.finalise(raw, ctx)
    _insert_one(h, actor, engine)
    accepted = engine_service.accept(h["id"], actor, engine=engine)
    return {"suggestion": accepted, "hunt_id": accepted["hunt_id"]}


def _insert_one(h, actor, engine=None):
    """Records one finalised hypothesis as `suggested` without touching any other suggestion (a refresh would expire the ones the generators did not produce)."""
    import json
    from sqlalchemy import insert, select, update
    from remediation.hunting.engine import store as es
    from remediation.utils import db as db_module
    engine, t = es._engine(engine), db_module.hunt_hypotheses
    stamp = es._now()
    refs = json.dumps(h["evidence_refs"])
    with engine.begin() as conn:
        row = conn.execute(select(t.c.status).where(t.c.id == h["id"])).scalar()
        if row is None:
            conn.execute(insert(t), {"id": h["id"], "generator": h["generator"], "hunt_type": h["hunt_type"], "pattern_key": h["pattern_key"], "title": h["title"], "status": "suggested", "outcome": None,
                                     "outcome_notes": None, "dismissal_reason": None, "score": h["priority"]["score"], "current": 1, "hunt_id": None, "promoted_key": None, "evidence_refs_json": refs,
                                     "data_json": json.dumps(h), "decided_by": None, "created_at": stamp, "updated_at": stamp})
            es.add_event(conn, h["id"], "suggested", actor, h["title"], {"score": h["priority"]["score"], "from": "hunt report"})
        elif row == "suggested":
            conn.execute(update(t).where(t.c.id == h["id"]).values(title=h["title"], score=h["priority"]["score"], current=1, evidence_refs_json=refs, data_json=json.dumps(h), updated_at=stamp))
    return h


# ---------------------------------------------------------------- rendering
def to_markdown(r):
    L = [f"# {r['title']}", "", f"Generated {r['generated_at']} | look-back {r['lookback_days']} days | catalog: ATT&CK {r['catalog']['attack_version']}, ATLAS {r['catalog']['atlas_version']} (retrieved {r['catalog']['retrieved']})", "",
         "> Built without running anything on a customer system. " + r["limits"][1], "", "## Hypothesis", "", r["hypothesis"]["statement"], "", f"Basis: {r['hypothesis']['basis']}.", ""]
    L += ["## Subject", "", f"**{r['subject']['name']}** ({r['subject']['kind']} {r['subject']['id']})", "", r["subject"].get("description") or "", ""]
    L += ["## Relevant intelligence", ""] + ([f"- **{i['title']}** (priority {i['priority']}): {'; '.join(i['why_relevant'])}. Source: {i['source']}." for i in r["intel"]] or ["No stored report names this subject or its techniques."]) + [""]
    L += ["## Techniques", ""] + [f"- **{t['id']} {t['name']}** ({', '.join(t['tactics'])}): {t['description']}" + (f" Covered by an enabled rule: {'yes' if t['covered'] else 'no'}." if t["covered"] is not None else "") for t in r["techniques"]] + [""]
    fw = r["frameworks"]
    d = fw["diamond"]
    L += ["## Analytic frameworks", "", "### Diamond Model", ""]
    for k, v in d["vertices"].items():
        L.append(f"- **{k.title()}** ({v['status']}): " + ("; ".join(i["value"] for i in v["items"][:6]) or "unknown") + (f". Hints: {'; '.join(v['hints'][:2])}" if v.get("hints") else ""))
    L += ["", f"- Meta: phase {', '.join(d['meta']['phase']['kill_chain']) or 'unknown'}; direction {d['meta']['direction']['value']}; result {d['meta']['result']['value']}", ""]
    L += [f"### Kill chain", "", fw["kill_chain"]["reading"], "", f"### PEAK", "", f"Phase: {fw['peak']['current']}. Next: {fw['peak']['next_action']}", "", f"### Maturity", "", f"{fw['maturity']['label']}: {fw['maturity']['why']}", ""]
    rd = r["data_readiness"]
    L += ["## Data readiness", "", f"Overall: **{rd['status']}**", ""] + [f"- {n['label']}: {n['status']}. {n['what_to_check']}" for n in rd["needs"]] + [""]
    L += ["## Leads", ""]
    for l in r["leads"]:
        L += [f"### {l['name']} ({l['technique']})", "", l.get("notes") or ""]
        for lang, v in l["languages"].items():
            L += [f"**{lang}**", "", "```", v.get("query") or f"{v['status']}: {v.get('reason', '')}", "```", ""]
    L += ["## Expected evidence", "", "Malicious:"] + [f"- {x}" for x in r["expected_evidence"]["malicious"]] + ["", "Likely benign:"] + [f"- {x}" for x in r["expected_evidence"]["likely_benign"]] + ["", "Tuning:"] + [f"- {x}" for x in r["expected_evidence"]["tuning"]] + [""]
    L += ["## What a hit means", ""] + [f"- {h['meaning']}" for h in r["what_a_hit_means"]] + [""]
    L += ["## Recommended containment (for a person to decide)", ""] + [f"- {s}" for s in r["containment"]["recommendations_for_a_person"]] + [""]
    rec = r["recommendations"]
    L += ["## Detection and control recommendations", "", "Rules (drafts):"] + [f"- {x['name']} ({x['technique']}): Sigma {x['sigma_status']}" for x in rec["detections"]] + ["", "Controls:"] + [f"- {x['id']} {x['name']}" + (f" ({x['class_label']})" if x["class_label"] else "") + f": {x['action']}" for x in rec["controls"]] + ["", rec["note"], ""]
    L += ["## Execution plan", ""] + [f"{p['order']}. [{p['phase']}] {p['step']} ({p['who']})" for p in r["execution_plan"]] + ["", "## Limits", ""] + [f"- {x}" for x in r["limits"]]
    return "\n".join(L) + "\n"


def to_html(r):
    return detection.to_html(to_markdown(r), r["title"])
