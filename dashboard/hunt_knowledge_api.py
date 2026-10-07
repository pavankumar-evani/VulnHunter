"""
Routes for the hunting knowledge base: the ATT&CK / ATLAS catalog and matrices with your overlays, groups and malware families, the scenario packs, the out-of-the-box library,
on-demand hunt reports (JSON, Markdown, HTML), framework views for a hypothesis, promotion of suggestions, and the confirm-gated model-assisted drafts.

Reads need a login; everything that writes or spends needs an administrator. Built by `build_router()` so this module needs nothing from app.py except what is handed in
(the live findings loader and the two functions that enforce the AI usage cap and make the real model call). Nothing here runs a query on a customer system, and a model is
never called unless the request carries `confirm: true`. Reference with payload examples: docs/HUNT_KNOWLEDGE.md.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from auth import rbac
from remediation.audit import activity_log
from remediation.hunting import store as hunt_store
from remediation.hunting.engine import context as ctx_mod, service as engine_service, store as engine_store
from remediation.hunting.knowledge import ai as kai, catalog as cat, config as kcfg, content, data_needs, frameworks, generator, readiness, report as kreport, scenarios, store as kstore


class ReportBody(BaseModel):
    subject: dict
    lookback_days: int | None = None
    scope: dict | None = None


class PromoteBody(BaseModel):
    kind: str
    scenario_id: str | None = None
    lead_index: int | None = None
    control_id: str | None = None
    scenario_ids: list[str] | None = None
    techniques: list[str] | None = None
    note: str | None = None


class AiDraftBody(BaseModel):
    kind: str
    subject: dict
    intel_text: str | None = None
    hypothesis: str | None = None
    language: str | None = None
    schema_hint: str | None = None
    results_text: str | None = None
    hunt_id: int | None = None
    techniques: list[str] | None = None
    confirm: bool = False


def _err(exc):
    msg = str(exc)
    return HTTPException(status_code=404 if msg.startswith("No ") else 400, detail=msg)


def build_router(*, load_findings, enforce_ai_limit, run_ai_call):
    router = APIRouter()
    admin, login = rbac.require_admin, rbac.require_login

    def _ctx():
        return ctx_mod.load(load_findings())

    def _planned_by_key():
        return {p["key"]: p for p in kstore.list_planned()}

    def _state(ctx):
        return {"rules": ctx.rules, "usecases": ctx.usecases, "planned": _planned_by_key(),
                "signals": readiness.signals(ctx.connections, ctx.alerts, ctx.entitlements, (getattr(ctx, "data_signals", None) or {}).get("asm_assets"))}

    # ------------------------------------------------------------ status and search
    @router.get("/api/hunting/knowledge/status")
    def api_knowledge_status(user: dict = Depends(login)):  # noqa: ARG001
        c = cat.get()
        scn = scenarios.load()
        kc = kcfg.load()
        return {"catalog": {"available": c.available, "frameworks": c.frameworks(), "groups": len(c.groups), "software": len(c.software), "mitigations": len(c.mitigations),
                            "case_studies": len(c.case_studies), "manifest": c.manifest,
                            "note": "Generated from MITRE's public data by scripts/build_hunt_knowledge.py; re-run it to refresh." if c.available else
                                    "The catalog files are missing. Run scripts/build_hunt_knowledge.py to create them."},
                "scenarios": {"count": len(scn), "categories": sorted({s["category"] for s in scn}), "problems": scenarios.problems()},
                "languages": kc["languages"], "ai": {"enabled": kc["ai"]["enabled"], "needs_confirm": True, "note": "Optional. The deterministic path needs no model."}, "generator_enabled": kc["enabled"]}

    @router.get("/api/hunting/knowledge/search")
    def api_knowledge_search(q: str = Query("", max_length=100), kinds: str = "technique,group,software,case-study", limit: int = Query(25, ge=1, le=100), user: dict = Depends(login)):  # noqa: ARG001
        return {"query": q, "results": cat.get().search(q, tuple(k for k in kinds.split(",") if k), limit)}

    # ------------------------------------------------------------ matrix
    @router.get("/api/hunting/knowledge/matrix")
    def api_knowledge_matrix(framework: str = "enterprise", overlays: bool = True, user: dict = Depends(login)):  # noqa: ARG001
        c = cat.get()
        if framework not in cat.FRAMEWORKS:
            raise HTTPException(status_code=400, detail=f"framework must be one of {', '.join(cat.FRAMEWORKS)}")
        mx = c.matrix(framework)
        if not mx:
            raise HTTPException(status_code=404, detail="That framework is not in the catalog")
        out = {"matrix": mx, "overlay": {}, "summary": None}
        if not overlays:
            return out
        ctx = _ctx()
        rules_known = bool(ctx.rules)
        from remediation.hunting import usecases
        covered = usecases.covered_techniques(ctx.rules) if rules_known else set()
        estate = generator._estate_techniques(ctx)
        hunts, sugg, scn_n = {}, {}, {}
        for h in ctx.hunts or []:
            for t in h.get("techniques") or []:
                r = c.resolve(t.get("technique_id") or "")
                if r:
                    hunts.setdefault(cat.parent_id(r), []).append(h["id"])
        for s in engine_store.all_rows():
            if s["status"] in ("suggested", "accepted", "running", "evidence-recorded") and s.get("current"):
                for t in s.get("techniques") or []:
                    r = c.resolve(t.get("technique_id") or "")
                    if r:
                        sugg.setdefault(cat.parent_id(r), []).append(s["id"])
        for sc in scenarios.load():
            for t in sc["techniques"]:
                scn_n.setdefault(cat.parent_id(t), set()).add(sc["id"])
        ov = {}
        attack = framework != "atlas"
        for col in mx["tactics"]:
            for t in col["techniques"]:
                for item in [t, *t["subtechniques"]]:
                    tid, p = item["id"].upper(), cat.parent_id(item["id"])
                    exact = [e for e in estate.get(p, [])]
                    ov[tid] = {"covered": (p in covered) if (rules_known and attack) else None, "findings": sum(1 for k, _ in exact if k == "finding"), "alerts": sum(1 for k, _ in exact if k == "alert"),
                               "hunts": sorted(set(hunts.get(p, [])))[:10], "suggestions": sorted(set(sugg.get(p, [])))[:10], "scenarios": sorted(scn_n.get(tid, scn_n.get(p, set())))[:10]}
        tops = [t for col in mx["tactics"] for t in col["techniques"]]
        uniq = {t["id"] for t in tops}
        unmatched = sorted({p for p in estate if not c.resolve(p)})
        out["overlay"] = ov
        out["summary"] = {"techniques": len(uniq), "with_scenarios": sum(1 for t in uniq if ov[t.upper()]["scenarios"]), "covered": sum(1 for t in uniq if ov[t.upper()]["covered"] is True) if rules_known and attack else None,
                          "uncovered": sum(1 for t in uniq if ov[t.upper()]["covered"] is False) if rules_known and attack else None, "hunted": sum(1 for t in uniq if ov[t.upper()]["hunts"]),
                          "with_findings": sum(1 for t in uniq if ov[t.upper()]["findings"]), "coverage_known": rules_known and attack, "unmatched_tags": unmatched,
                          "note": ("Coverage counts enabled detection rules that name the technique." if rules_known else "No detection rules are recorded, so coverage cannot be judged (shown as null, never as covered)."
                                   if attack else "Quanta cannot match ATLAS techniques to detection-rule tags, so no coverage is shown.")}
        return out

    # ------------------------------------------------------------ technique, group, software
    @router.get("/api/hunting/knowledge/techniques/{tid}")
    def api_knowledge_technique(tid: str, user: dict = Depends(login)):  # noqa: ARG001
        c = cat.get()
        r = c.resolve(tid)
        t = c.technique(r) if r else None
        if not t:
            raise HTTPException(status_code=404, detail=f"No technique {tid} in the catalog")
        ctx = _ctx()
        from remediation.hunting import usecases
        covered = usecases.covered_techniques(ctx.rules) if ctx.rules else set()
        estate = generator._estate_techniques(ctx)
        p = cat.parent_id(t["id"])
        scn = generator.scenarios_for([t["id"]])
        classes = data_needs.classes_for_technique(c, t["id"])
        st = _state(ctx)
        return {"technique": t, "renamed_from": tid.upper() if r != tid.upper() else None, "scenarios": [scenarios.summary(s, c) for s in scn[:8]], "data_classes": classes,
                "readiness": readiness.assess(classes, st["signals"]), "controls": content.controls_for([t["id"]], c, st["planned"]),
                "your_estate": {"covered": (p in covered) if (ctx.rules and t["framework"] != "atlas") else None, "coverage_known": bool(ctx.rules),
                                "findings": [f["id"] for k, f in estate.get(p, []) if k == "finding"][:10], "alerts": [f["id"] for k, f in estate.get(p, []) if k == "alert"][:10]},
                "frameworks": {"kill_chain": frameworks.kill_chain_view([t["id"]], c), "attack": frameworks.attack_position_view([t["id"]], c), "unified_kill_chain": frameworks.unified_view([t["id"]], c)},
                "report": {"subject": {"kind": "atlas-technique" if t["framework"] == "atlas" else "technique", "id": t["id"]}}}

    @router.get("/api/hunting/knowledge/groups")
    def api_knowledge_groups(q: str = Query("", max_length=100), limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0), user: dict = Depends(login)):  # noqa: ARG001
        c = cat.get()
        rows = [g for g in c.groups.values() if not q or q.lower() in (g["name"] + " " + " ".join(g.get("aliases", []))).lower() or q.upper() == g["id"]]
        rows.sort(key=lambda g: g["name"].lower())
        return {"total": len(rows), "groups": [{"id": g["id"], "name": g["name"], "aliases": g.get("aliases", []), "techniques": len(g.get("techniques", [])), "software": len(g.get("software", [])),
                                                "description": g.get("description", "")} for g in rows[offset: offset + limit]]}

    @router.get("/api/hunting/knowledge/groups/{gid}")
    def api_knowledge_group(gid: str, user: dict = Depends(login)):  # noqa: ARG001
        c = cat.get()
        g = c.group(gid)
        if not g:
            raise HTTPException(status_code=404, detail=f"No group {gid} in the catalog")
        ctx = _ctx()
        mentions, _ = generator._intel_mentions(ctx, c)
        estate = generator._estate_techniques(ctx)
        ind = generator._industry_groups(ctx, c)
        parents = {t.split(".")[0].upper() for t in g.get("techniques", [])}
        return {"group": g, "scenarios": [scenarios.summary(s, c) for s in generator.scenarios_for(g.get("techniques", []))[:8]],
                "relevance_to_you": {"named_in_reports": [{"id": r["id"], "title": r["title"]} for r in mentions.get(g["id"].upper(), [])], "industry_match": g["id"].upper() in ind, "industry": ctx.industry,
                                     "techniques_tagged_in_your_estate": sorted(parents & set(estate)), "note": "A cross-reference to what you hold, not attribution."},
                "report": {"subject": {"kind": "group", "id": g["id"]}}}

    @router.get("/api/hunting/knowledge/software")
    def api_knowledge_software(q: str = Query("", max_length=100), type: str | None = None, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0), user: dict = Depends(login)):  # noqa: ARG001
        c = cat.get()
        rows = [s for s in c.software.values() if (not type or s["type"] == type) and (not q or q.lower() in (s["name"] + " " + " ".join(s.get("aliases", []))).lower() or q.upper() == s["id"])]
        rows.sort(key=lambda s: s["name"].lower())
        return {"total": len(rows), "software": [{"id": s["id"], "name": s["name"], "type": s["type"], "aliases": s.get("aliases", []), "platforms": s.get("platforms", []), "techniques": len(s.get("techniques", [])),
                                                  "description": s.get("description", "")} for s in rows[offset: offset + limit]]}

    @router.get("/api/hunting/knowledge/software/{sid}")
    def api_knowledge_software_item(sid: str, user: dict = Depends(login)):  # noqa: ARG001
        c = cat.get()
        s = c.software_item(sid)
        if not s:
            raise HTTPException(status_code=404, detail=f"No software {sid} in the catalog")
        return {"software": s, "scenarios": [scenarios.summary(x, c) for x in generator.scenarios_for(s.get("techniques", []))[:8]], "report": {"subject": {"kind": "software", "id": s["id"]}}}

    # ------------------------------------------------------------ scenarios and library
    @router.get("/api/hunting/knowledge/scenarios")
    def api_knowledge_scenarios(category: str | None = None, technique: str | None = None, q: str | None = None, user: dict = Depends(login)):  # noqa: ARG001
        c = cat.get()
        rows = scenarios.load()
        if category:
            rows = [s for s in rows if s["category"] == category]
        if technique:
            rows = generator.scenarios_for([technique], rows)
        if q:
            rows = [s for s in rows if q.lower() in (s["title"] + " " + s["hypothesis"]).lower()]
        return {"total": len(rows), "categories": scenarios.CATEGORIES, "scenarios": [scenarios.summary(s, c) for s in rows]}

    @router.get("/api/hunting/knowledge/scenarios/{sid}")
    def api_knowledge_scenario(sid: str, user: dict = Depends(login)):  # noqa: ARG001
        s = scenarios.get(sid)
        if not s:
            raise HTTPException(status_code=404, detail=f"No scenario {sid}")
        c = cat.get()
        ctx = _ctx()
        rd = readiness.assess(s["data_sources"], _state(ctx)["signals"])
        return {"scenario": {**{k: s[k] for k in ("id", "title", "category", "pack", "severity", "priority", "kill_chain", "diamond", "data_sources", "malicious", "benign", "tuning", "response", "playbook")},
                             "hypothesis": s["hypothesis"], "hypothesis_text": scenarios.hypothesis_text(s), "techniques": [c.technique(t, detail=False) and {"id": t, "name": c.technique(t, detail=False)["name"]} for t in s["techniques"]]},
                "leads": [scenarios.render_lead(ld, s, hyp_text=scenarios.hypothesis_text(s)) for ld in s["leads"]], "readiness": rd, "frameworks": _framework_views_for_scenario(s, ctx, c),
                "content": content.scenario_content(s, c, _planned_by_key())}

    def _framework_views_for_scenario(s, ctx, c):
        subj = {"techniques": s["techniques"], "scenario": s, "scope": {}, "intel": [], "groups": [], "software": [], "industry": ctx.industry, "status": "report", "hypothesis": s["hypothesis"],
                "data_sources": s["data_sources"], "has_queries": True, "has_benign": True, "origin": "scenario", "readiness": readiness.assess(s["data_sources"], _state(ctx)["signals"]), "hunt_type": "hypothesis-driven"}
        return frameworks.views(subj, c)

    @router.get("/api/hunting/knowledge/library")
    def api_knowledge_library(category: str | None = None, tactic: str | None = None, platform: str | None = None, data_source: str | None = None, status: str | None = None,
                              framework: str | None = None, scenario: str | None = None, q: str | None = Query(None, max_length=100), user: dict = Depends(login)):  # noqa: ARG001
        ctx = _ctx()
        return content.library(_state(ctx), filters={k: v for k, v in {"category": category, "tactic": tactic, "platform": platform, "data_source": data_source, "status": status, "framework": framework,
                                                                       "scenario": scenario, "q": q}.items() if v})

    @router.get("/api/hunting/knowledge/planned")
    def api_knowledge_planned(kind: str | None = None, user: dict = Depends(login)):  # noqa: ARG001
        return {"planned": kstore.list_planned(kind), "note": "A planning list. Nothing here is in the controls inventory or counted as coverage."}

    @router.post("/api/hunting/knowledge/planned/{key}/discard")
    def api_knowledge_planned_discard(key: str, user: dict = Depends(admin)):
        try:
            return kstore.discard_planned(key)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="No such planned item") from exc

    @router.post("/api/hunting/knowledge/promote")
    def api_knowledge_promote(body: PromoteBody, user: dict = Depends(admin)):
        try:
            r = content.promote(body.kind, body.model_dump(), user["email"])
        except content.PromoteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        activity_log.record_activity(user["email"], "hunt.knowledge.promote", body.kind, {k: v for k, v in r.items() if k in ("key", "rule_id", "status", "name")})
        return r

    # ------------------------------------------------------------ reports
    @router.post("/api/hunting/knowledge/report")
    def api_knowledge_report(body: ReportBody, user: dict = Depends(admin)):
        sub = body.subject or {}
        ctx = _ctx()
        try:
            rep = kreport.build(sub.get("kind"), sub.get("id"), ctx, body.lookback_days, body.scope, planned=kstore.list_planned())
        except kreport.SubjectError as exc:
            raise _err(exc) from exc
        saved = kstore.save_report(rep["subject"]["kind"], rep["subject"]["id"], rep["title"], rep["lookback_days"], rep, user["email"], keep=int(kcfg.load()["report"]["keep_versions"]))
        activity_log.record_activity(user["email"], "hunt.knowledge.report", f"{rep['subject']['kind']}:{rep['subject']['id']}", {"version": saved["version"], "leads": len(rep["leads"])})
        return {"id": saved["id"], "version": saved["version"], "subject": saved["subject"], "created_at": saved["created_at"], "report": saved["report"],
                "urls": {"json": f"/api/hunting/knowledge/reports/{saved['id']}", "markdown": f"/api/hunting/knowledge/reports/{saved['id']}?format=markdown", "html": f"/api/hunting/knowledge/reports/{saved['id']}?format=html"}}

    @router.get("/api/hunting/knowledge/reports")
    def api_knowledge_reports(kind: str | None = None, id: str | None = None, limit: int = Query(50, ge=1, le=200), user: dict = Depends(login)):  # noqa: ARG001
        return {"reports": kstore.list_reports(kind, id, limit)}

    @router.get("/api/hunting/knowledge/reports/{rid}")
    def api_knowledge_report_get(rid: int, format: str = "json", user: dict = Depends(login)):  # noqa: ARG001
        r = kstore.get_report(rid)
        if not r:
            raise HTTPException(status_code=404, detail="No such report")
        if format == "markdown":
            return PlainTextResponse(kreport.to_markdown(r["report"]), media_type="text/markdown; charset=utf-8")
        if format == "html":
            return HTMLResponse(kreport.to_html(r["report"]))
        if format != "json":
            raise HTTPException(status_code=400, detail="format must be json, markdown or html")
        return r

    @router.post("/api/hunting/knowledge/reports/{rid}/create-hunt")
    def api_knowledge_report_create_hunt(rid: int, user: dict = Depends(admin)):
        r = kstore.get_report(rid)
        if not r:
            raise HTTPException(status_code=404, detail="No such report")
        try:
            out = kreport.create_hunt(r["report"], _ctx(), user["email"])
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=409 if isinstance(exc, engine_service.TransitionError) else 400, detail=str(exc)) from exc
        activity_log.record_activity(user["email"], "hunt.knowledge.create_hunt", str(rid), {"hunt_id": out["hunt_id"]})
        return {**out, "note": "A proposed hunt was created through the normal accept flow. Nothing ran: running a lead stays the existing confirm-gated action on the hunt."}

    # ------------------------------------------------------------ framework views for a hypothesis
    def _hypothesis_views(hid):
        h = engine_service.detail(hid)
        if not h:
            raise HTTPException(status_code=404, detail="No such suggestion")
        c = cat.get()
        ctx = _ctx()
        intel_ids = {e["ref"] for e in h["why_now"] if e["kind"] == "intel"}
        know = h.get("knowledge") or {}
        subj_ref = know.get("subject") or {}
        groups, software = [], []
        if subj_ref.get("kind") == "group" and c.group(subj_ref["id"]):
            g = c.group(subj_ref["id"])
            groups = [{"id": g["id"], "name": g["name"], "aliases": g.get("aliases", [])}]
        if subj_ref.get("kind") == "software" and c.software_item(subj_ref["id"]):
            s = c.software_item(subj_ref["id"])
            software = [{"id": s["id"], "name": s["name"], "type": s["type"]}]
        scn = scenarios.get((know.get("scenarios") or [None])[0] or "")
        origin = know.get("origin") or ("tenant-data" if h["generator"] in ("coverage-gap", "lessons-learned", "model-assisted", "low-and-slow", "alert-burst", "exposed-asset", "identity-misuse") else "technique")
        evidence_dates = [r.get("received_at") for r in (ctx.intel or []) if str(r["id"]) in intel_ids]
        sd = {"techniques": [t["technique_id"] for t in h["techniques"]], "scope": h["scope"], "intel": [r for r in (ctx.intel or []) if str(r["id"]) in intel_ids], "groups": groups, "software": software,
              "scenario": scn, "outcome": h.get("outcome"), "status": h["status"], "lookback_days": 30, "industry": ctx.industry, "evidence_dates": evidence_dates,
              "readiness": know.get("readiness") or {"status": h["data_readiness"]["status"]}, "data_sources": [d["name"] for d in h["data_sources"]], "hypothesis": h["hypothesis"],
              "has_queries": bool(h["queries"]), "has_benign": bool(h["likely_benign"]), "generator": h["generator"], "hunt_type": h["hunt_type"], "origin": origin}
        return {"hypothesis_id": hid, "status": h["status"], "title": h["title"], "frameworks": frameworks.views(sd, c)}

    @router.get("/api/hunting/knowledge/hypotheses/{hid}/frameworks")
    def api_knowledge_hypothesis_frameworks(hid: str, user: dict = Depends(login)):  # noqa: ARG001
        return _hypothesis_views(hid)

    @router.post("/api/hunting/knowledge/hypotheses/{hid}/frameworks")
    def api_knowledge_hypothesis_frameworks_post(hid: str, user: dict = Depends(login)):  # noqa: ARG001
        return _hypothesis_views(hid)

    # ------------------------------------------------------------ the model-assisted agent (confirm-gated)
    @router.post("/api/hunting/knowledge/ai-draft")
    def api_knowledge_ai_draft(body: AiDraftBody, user: dict = Depends(admin)):
        kc = kcfg.load()
        if not kc["ai"]["enabled"]:
            raise HTTPException(status_code=403, detail="Model-assisted drafts are switched off in remediation/config/hunt_knowledge.yaml (ai.enabled). The deterministic reports and library are unaffected.")
        c = cat.get()
        sub = body.subject or {}
        try:
            subj = kreport.resolve_subject(sub.get("kind"), sub.get("id"), c)
        except kreport.SubjectError as exc:
            raise _err(exc) from exc
        data = body.model_dump()
        if body.kind == "result-summary" and body.hunt_id and not body.results_text:
            hunt = hunt_store.get_hunt(body.hunt_id)
            if not hunt:
                raise HTTPException(status_code=404, detail="No such hunt")
            lines = [f"Hunt: {hunt['title']}", f"Hypothesis: {hunt['hypothesis']}"] + [f"- {q['name']} ({q['technique']}): {q.get('result') or 'not run'}" + (f"; notes: {q['notes']}" if q.get("notes") else "") for q in hunt["queries"]]
            data["results_text"], data["results_origin"] = "\n".join(lines), f"taken from hunt #{hunt['id']} (titles, results and notes)"
        try:
            prompt, sent = kai.build_prompt(body.kind, subj, data, c, kc)
        except kai.DraftError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not body.confirm:
            return {"dry_run": True, "prompt": prompt, "sent": sent, "label": kai.LABEL, "checks": ["technique ids must exist in the catalog", "queries must pass the read-only gate (siem_search_connector.check_query for SPL)",
                                                                                                  "the result is stored as a draft only and counts as a model call in AI usage"],
                    "message": "Preview only. Nothing was sent. The prompt above is exactly what would be sent; secret-shaped strings were replaced. Send confirm: true to ask the model; this spends API usage."}
        if kstore.count_drafts(subj["kind"], subj["id"]) >= int(kc["ai"]["max_drafts_per_subject"]):
            raise HTTPException(status_code=409, detail="This subject already has the maximum number of drafts; discard some first.")
        governance = enforce_ai_limit(user["email"])
        text = run_ai_call(prompt, "hunt-knowledge-" + body.kind, user["email"], governance)
        content_, validation = kai.validate(body.kind, text, data, c)
        draft = kstore.save_draft(body.kind, subj["kind"], subj["id"], content_, validation, user["email"], language=body.language if body.kind == "query-draft" else None, model=governance.get("default_model"))
        activity_log.record_activity(user["email"], "hunt.knowledge.ai_draft", f"{subj['kind']}:{subj['id']}", {"kind": body.kind, "ok": validation["ok"]})
        return {"dry_run": False, "draft": draft, "note": "A draft, labelled AI-drafted and unvalidated. It has not been saved to any hunt, rule or report, and nothing has run."}

    @router.get("/api/hunting/knowledge/ai-drafts")
    def api_knowledge_ai_drafts(subject_kind: str | None = None, subject_id: str | None = None, user: dict = Depends(admin)):  # noqa: ARG001
        return {"drafts": kstore.list_drafts(subject_kind, subject_id)}

    @router.post("/api/hunting/knowledge/ai-drafts/{did}/discard")
    def api_knowledge_ai_draft_discard(did: int, user: dict = Depends(admin)):  # noqa: ARG001
        try:
            return kstore.discard_draft(did)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="No such draft") from exc

    return router
