"""The AI supply chain: the models, tools, data and providers each AI system depends on, and the assurance around them.

Reads what Quanta records: the AI register (remediation/aisec), the AI dependency graph (remediation/graphs/ai.py, which joins the register to AI usage
events and unreviewed applications), AI usage by provider and model (remediation/aiusage), the approved-model list in remediation/config/ai_usage_policy.yaml and
stored SBOMs (remediation/appsec). The register stores a system's model but not the tools or data it reaches, so those links appear only when recorded; absent
links are gaps, never a pass. Model provenance, signing and weight integrity cannot be observed and are `unknown`.
"""
import datetime
import fnmatch

from remediation.posture import model

FRAMEWORK = {
    "id": "ai-supply-chain",
    "title": "AI supply chain",
    "summary": "Which models, providers, tools and data each AI system depends on, whether those dependencies are recorded, owned, reviewed and approved, and whether an AI bill of "
               "materials exists, from the AI register, AI usage and stored SBOMs. Quanta cannot verify model signatures or weight integrity, so those are listed as not observable.",
    "areas": [("models", "Models"), ("tools", "Tools"), ("data", "Data"), ("providers", "Providers"), ("assurance", "Assurance")],
    "refs": [{"label": "CycloneDX machine learning bill of materials (ML-BOM)", "url": "https://cyclonedx.org/capabilities/mlbom/"},
             {"label": "MITRE ATLAS: adversary tactics and techniques against AI systems", "url": "https://atlas.mitre.org/"}],
}
FW = FRAMEWORK["id"]
REFS = FRAMEWORK["refs"]
SYSTEM_KINDS = ("application", "agent", "gateway")
PAGE_REGISTER = {"kind": "page", "where": "/ai-security"}
PAGE_USAGE = {"kind": "page", "where": "/ai-usage"}
PAGE_APPS = {"kind": "page", "where": "/applications"}
POLICY_FILE = "remediation/config/ai_usage_policy.yaml"
# package names that mean an application uses a model or an AI framework (matched on the component name, lower case)
AI_LIBRARIES = frozenset({"openai", "anthropic", "langchain", "langchain-core", "llama-index", "llama_index", "transformers", "torch", "tensorflow", "onnxruntime",
                          "sentence-transformers", "huggingface-hub", "mcp", "chromadb"})


def _chk(cid, area, title, status, **kw):
    kw.setdefault("refs", REFS)
    return model.check(f"aisc-{cid}", FW, area, title, status, **kw)


def _page(base, key, value, effect):
    return {**base, "key": key, "value": value, "effect": effect}


def _age_days(d, now):
    try:
        return (now.date() - datetime.date.fromisoformat(str(d)[:10])).days
    except ValueError:
        return None


def _cov(share, thr):
    if share >= thr["coverage_good"]:
        return "pass", None
    if share >= thr["coverage_partial"]:
        return "partial", share
    return "fail", None


def _share_check(cid, area, title, share, ev, thr, weight=3, **kw):
    """pass at full coverage, otherwise partial/fail by the shared thresholds."""
    st, sc = ("pass", None) if share >= 1 else _cov(share, thr)
    return _chk(cid, area, title, st, score=sc, weight=weight, evidence=ev, **kw)


def _load(ctx):
    from remediation.aisec import store as aisec_store
    from remediation.aiusage import analytics, discovery
    from remediation.aiusage import store as usage_store
    from remediation.appsec import store as appsec_store
    from remediation.graphs import ai as ai_graph
    since = (ctx.now - datetime.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    d = {"assets": ctx.get("ai.assets", lambda: aisec_store.list_all(ctx.engine)),
         "usage": ctx.get("ai.usage30", lambda: usage_store.fetch(since=since, engine=ctx.engine)),
         "apps": ctx.get("ai.apps", lambda: discovery.list_apps(ctx.engine)),
         "policy": ctx.get("ai.policy", analytics.policy) or {},
         "graph": ctx.get("aisc.graph", lambda: ai_graph.build(engine=ctx.engine, findings=ctx.findings, today=ctx.now.date(), links=getattr(ctx, "ai_links", None)))}

    def sboms():
        out = {}
        for name in sorted(appsec_store.sbom_summaries(ctx.engine)):
            rec = appsec_store.get_sbom(name, ctx.engine)
            out[name] = (rec["graph"].get("components") or []) if rec else []
        return out
    d["sboms"] = ctx.get("aisc.sboms", sboms)
    ai_findings = [f for f in ctx.findings if isinstance(f.get("asset"), dict) and f["asset"].get("type") == "ai-ml-system"]
    d["has_ai"] = bool(d["assets"] or d["apps"] or d["usage"] or ai_findings)
    return d


def _na(cid, area, title, weight):
    return _chk(cid, area, title, "na", weight=weight, evidence=["No AI systems, AI findings, AI usage or AI applications are recorded, so this does not apply yet."],
                recommendation="Register AI systems on AI Security when you have them.", data_used=["AI register", "AI usage"])


def _unreadable(ctx, key, cid, area, title, weight):
    return _chk(cid, area, title, "unknown", weight=weight, evidence=[f"Could not read {key}: {ctx.unavailable.get(key, 'not available')}"],
                recommendation="Check that the database is reachable, then re-run the review.", data_used=[key])


def _tri_check(cid, area, title, pool, answered, bad, what, rec, weight, change, bad_means, thr, data_used=("AI register",)):
    n, a, b = len(pool), len(answered), len(bad)
    names = ", ".join(sorted(x["name"] for x in bad)[:5])
    if not n:
        return _chk(cid, area, title, "unknown", weight=weight, evidence=[f"No registered system of this kind ({what})."], recommendation=rec, change=change, data_used=list(data_used))
    if not a:
        return _chk(cid, area, title, "unknown", weight=weight, evidence=[f"0 of {n} registered records have answered this ({what})."], recommendation=rec, change=change, data_used=list(data_used))
    if b:
        score = 1 - b / a
        return _chk(cid, area, title, "partial" if score >= thr["coverage_partial"] else "fail", score=score, weight=weight,
                    evidence=[f"{b} of {a} answering records are {bad_means}: {names}.", f"{n - a} of {n} have not answered."], recommendation=rec, change=change, data_used=list(data_used))
    if a < n:
        return _chk(cid, area, title, "partial", score=a / n, weight=weight, evidence=[f"{a} of {n} answered and none is {bad_means}; {n - a} have not answered."], recommendation=rec, change=change, data_used=list(data_used))
    return _chk(cid, area, title, "pass", weight=weight, evidence=[f"All {n} answered and none is {bad_means}."], recommendation=rec, data_used=list(data_used))


def _edges(graph, kinds):
    """{target node id: set of system node ids} for edges of the given kinds that start at an AI system."""
    out = {}
    for e in graph["edges"]:
        if e["kind"] in kinds and e["source"].startswith("system:"):
            out.setdefault(e["target"], set()).add(e["source"])
    return out


def _systems(graph):
    return {n["id"] for n in graph["nodes"] if n["kind"] == "system"}


def run(ctx):
    d = _load(ctx)
    thr = ctx.thr
    assets, graph = d["assets"], d["graph"]
    systems = [a for a in (assets or []) if a.get("kind") in SYSTEM_KINDS]
    out = []

    def guard(cid, area, title, fn, weight=3, need=("ai.assets",)):
        if not d["has_ai"]:
            return _na(cid, area, title, weight)
        for key in need:
            val = {"ai.assets": assets, "aisc.graph": graph, "aisc.sboms": d["sboms"], "ai.usage30": d["usage"], "ai.apps": d["apps"]}[key]
            if val is None:
                return _unreadable(ctx, key, cid, area, title, weight)
        return fn()

    def concentration(cid, area, title, kinds, label, weight):
        def fn():
            sysids = _systems(graph)
            targets = _edges(graph, kinds)
            if len(sysids) < 2:
                return _chk(cid, area, title, "na", weight=weight, evidence=[f"{len(sysids)} AI system(s) in the dependency graph; concentration needs at least two."], recommendation="Revisit when more systems are registered.", data_used=["AI dependency graph"])
            if not targets:
                return _chk(cid, area, title, "unknown", weight=weight, evidence=[f"No {label} is recorded for any of {len(sysids)} systems, so sharing cannot be seen."],
                            recommendation=f"Record which {label} each system uses (the AI dependency graph shows them once recorded).", change=_page(PAGE_REGISTER, "register", "record each dependency", "Lets shared dependencies show."), data_used=["AI dependency graph"])
            top_id, top_set = sorted(targets.items(), key=lambda kv: (-len(kv[1]), kv[0]))[0]
            share = len(top_set) / len(sysids)
            ev = [f"{top_id.split(':', 1)[1]} is used by {len(top_set)} of {len(sysids)} AI systems ({round(100 * share)}%)."]
            rec = f"Plan for the failure or compromise of that {label}: a fallback, a pinned version and an owner."
            ch = _page(PAGE_REGISTER, "register", "record a fallback in notes", "Keeps the single point of failure visible.")
            if share <= thr["coverage_partial"]:
                return _chk(cid, area, title, "pass", weight=weight, evidence=ev, recommendation="Keep dependencies spread.", data_used=["AI dependency graph"])
            if share >= thr["coverage_good"]:
                return _chk(cid, area, title, "fail", weight=weight, evidence=ev, detail="One shared dependency is a single point of failure and a single route into every system.", recommendation=rec, change=ch, data_used=["AI dependency graph"])
            return _chk(cid, area, title, "partial", score=(thr["coverage_good"] - share) / (thr["coverage_good"] - thr["coverage_partial"]), weight=weight, evidence=ev, recommendation=rec, change=ch, data_used=["AI dependency graph"])
        return guard(cid, area, title, fn, weight, need=("aisc.graph",))

    # ---- models
    def rec_model():
        if not systems:
            return _chk("model-recorded", "models", "Each AI system's model is recorded", "unknown", weight=4, evidence=["No application, agent or gateway is registered."], recommendation="Register each AI system and its model.",
                        change=_page(PAGE_REGISTER, "vendor_model", "the model name", "Records which model runs."), data_used=["AI register"])
        linked = {e["source"] for e in graph["edges"] if e["kind"] == "runs"}
        n = sum(1 for s in _systems(graph) if s in linked)
        return _share_check("model-recorded", "models", "Each AI system's model is recorded", n / len(systems), [f"{n} of {len(systems)} registered AI systems have a model recorded or seen in usage."], thr, 4,
                            detail="You cannot assess or patch a model you have not listed.", recommendation="Record vendor_model for each system.", change=_page(PAGE_REGISTER, "vendor_model", "the model name", "Records which model runs."), data_used=["AI register", "AI usage"])
    out.append(guard("model-recorded", "models", "Each AI system's model is recorded", rec_model, 4, need=("ai.assets", "aisc.graph")))

    def mprov():
        pool = [a for a in assets if a.get("kind") in ("model",) + SYSTEM_KINDS]
        ans = [a for a in pool if a.get("provenance") in ("verified", "unverified")]
        return _tri_check("model-provenance", "models", "Models come from a source that was checked", pool, ans, [a for a in ans if a["provenance"] == "unverified"], "models and the systems that embed one",
                          "Pull models from a registry you control, pin hashes and record the source.", 4, _page(PAGE_REGISTER, "provenance", "verified", "Records that the origin was checked."), "of unverified origin", thr)
    out.append(guard("model-provenance", "models", "Models come from a source that was checked", mprov, 4))

    def mfmt():
        pool = [a for a in assets if a.get("kind") == "model"]
        ans = [a for a in pool if a.get("serialization") not in (None, "unknown")]
        return _tri_check("model-format", "models", "Model files use a format that cannot run code", pool, ans, [a for a in ans if a["serialization"] == "pickle"], "registered models",
                          "Convert pickle models to safetensors and load only from trusted sources.", 3, _page(PAGE_REGISTER, "serialization", "safetensors", "Records a non-executable format."), "stored as pickle", thr)
    out.append(guard("model-format", "models", "Model files use a format that cannot run code", mfmt))

    out.append(_na("model-signing", "models", "Models are signed and their signatures verified", 3) if not d["has_ai"] else
               _chk("model-signing", "models", "Models are signed and their signatures verified", "unknown", weight=3,
                    evidence=[f"Quanta cannot check signatures; {len([a for a in assets or [] if a.get('provenance') == 'verified'])} of {len(assets or [])} registered records say their origin was verified."],
                    recommendation="Sign models you publish, verify signatures and hashes on every pull, and record the result in the register.", change=_page(PAGE_REGISTER, "provenance", "verified", "Records the check you made."), data_used=["AI register"]))
    out.append(concentration("model-concentration", "models", "AI systems do not all depend on one model", ("runs",), "model", 2))

    # ---- tools
    def tools_rec():
        acting = [a for a in systems if a.get("can_take_actions") is True]
        unsure = [a for a in systems if a.get("can_take_actions") is None]
        ch = _page(PAGE_REGISTER, "register", "record each system's MCP servers and tools", "Lets the dependency graph show what each system can call.")
        if not acting:
            if unsure or not systems:
                return _chk("tools-recorded", "tools", "The tools and MCP servers each system can call are recorded", "unknown", weight=4,
                            evidence=[f"{len(unsure)} of {len(systems)} systems have not said whether they can act."], recommendation="Record what each system can do and call.", change=ch, data_used=["AI register"])
            return _chk("tools-recorded", "tools", "The tools and MCP servers each system can call are recorded", "na", weight=4, evidence=[f"All {len(systems)} systems say they cannot take actions."], recommendation="Revisit when tools are added.", data_used=["AI register"])
        linked_ids = {s for srcs in _edges(graph, ("can_call",)).values() for s in srcs}
        n = sum(1 for a in acting if f"system:{' '.join(a['name'].lower().split())}" in linked_ids)
        if not n:
            return _chk("tools-recorded", "tools", "The tools and MCP servers each system can call are recorded", "unknown", weight=4,
                        evidence=[f"{len(acting)} systems can take actions; 0 have a recorded tool or MCP server link."], detail="The register stores a system's model, not the tools it calls, so nothing can be said until they are recorded.",
                        recommendation="Record each acting system's tools and MCP servers.", change=ch, data_used=["AI dependency graph"])
        return _share_check("tools-recorded", "tools", "The tools and MCP servers each system can call are recorded", n / len(acting), [f"{n} of {len(acting)} systems that can act have their tools recorded."], thr, 4,
                            recommendation="Record the tools of the rest.", change=ch, data_used=["AI dependency graph"])
    out.append(guard("tools-recorded", "tools", "The tools and MCP servers each system can call are recorded", tools_rec, 4, need=("ai.assets", "aisc.graph")))

    def mcp():
        pool = [a for a in assets if a.get("kind") == "mcp-server"]
        ch = _page(PAGE_REGISTER, "auth_required", True, "Records that the server needs authentication.")
        if not pool:
            acting = sum(1 for a in systems if a.get("can_take_actions") is True)
            return _chk("mcp-governed", "tools", "Registered MCP servers have an owner, authentication and a current review", "unknown", weight=4,
                        evidence=[f"No MCP server is registered; {acting} of {len(systems)} systems can take actions and may use one."], recommendation="Register every MCP server and tool server in use.", change=_page(PAGE_REGISTER, "kind", "mcp-server", "Brings the server under the OWASP and MCP rules."), data_used=["AI register"])
        noauth = [a for a in pool if a.get("auth_required") is False]
        owner = [a for a in pool if not a.get("owner")]
        stale = [a for a in pool if (_age_days(a.get("last_reviewed"), ctx.now) is None or _age_days(a.get("last_reviewed"), ctx.now) > thr["stale_days"])]
        ok = [a for a in pool if a.get("auth_required") is True and a.get("owner") and a not in stale]
        return _share_check("mcp-governed", "tools", "Registered MCP servers have an owner, authentication and a current review", len(ok) / len(pool),
                            [f"{len(ok)} of {len(pool)} MCP servers have an owner, require authentication and were reviewed in {thr['stale_days']} days.",
                             f"{len(noauth)} without authentication, {len(owner)} without an owner, {len(stale)} not recently reviewed."], thr, 4,
                            detail="Any client that can reach an unauthenticated MCP server can call its tools.", recommendation="Require authentication, name an owner and review each server.", change=ch, data_used=["AI register"])
    out.append(guard("mcp-governed", "tools", "Registered MCP servers have an owner, authentication and a current review", mcp, 4))

    def treview():
        pool = [a for a in assets if a.get("kind") in ("plugin", "agent")]
        ans = [a for a in pool if a.get("plugins_reviewed") is not None]
        return _tri_check("tools-reviewed", "tools", "Plugins and tools were reviewed before use", pool, ans, [a for a in ans if a["plugins_reviewed"] is False], "agents and plugins",
                          "Review each plugin's code, permissions and publisher before enabling it.", 3, _page(PAGE_REGISTER, "plugins_reviewed", True, "Records the review."), "not reviewed", thr)
    out.append(guard("tools-reviewed", "tools", "Plugins and tools were reviewed before use", treview))
    out.append(concentration("tool-concentration", "tools", "AI systems do not all depend on one tool or MCP server", ("can_call",), "tool or MCP server", 2))

    # ---- data
    def dsrc():
        pool = [a for a in assets if a.get("kind") in ("vector-db", "dataset")]
        rag = [a for a in systems if a.get("uses_rag") is True]
        ch = _page(PAGE_REGISTER, "data_classes", "the classes the store holds", "Records what the store holds and who owns it.")
        if not pool:
            if rag:
                return _chk("data-sources-owned", "data", "Data sources have an owner and a recorded data classification", "fail", weight=4,
                            evidence=[f"{len(rag)} systems retrieve from a document or vector store, and 0 vector stores or datasets are registered."], detail="Data an AI system reads is part of its supply chain.",
                            recommendation="Register each vector store and dataset with an owner and its data classes.", change=ch, data_used=["AI register"])
            return _chk("data-sources-owned", "data", "Data sources have an owner and a recorded data classification", "unknown", weight=4, evidence=["No vector store or dataset is registered."],
                        recommendation="Register each vector store and dataset.", change=ch, data_used=["AI register"])
        ok = [a for a in pool if a.get("owner") and a.get("data_classes")]
        return _share_check("data-sources-owned", "data", "Data sources have an owner and a recorded data classification", len(ok) / len(pool),
                            [f"{len(ok)} of {len(pool)} vector stores and datasets have an owner and data classes recorded."], thr, 4, recommendation="Add the owner and data classes to the rest.", change=ch, data_used=["AI register"])
    out.append(guard("data-sources-owned", "data", "Data sources have an owner and a recorded data classification", dsrc, 4))

    def vauth():
        pool = [a for a in assets if a.get("kind") == "vector-db"]
        ans = [a for a in pool if a.get("auth_required") is not None]
        return _tri_check("vector-store-access", "data", "Vector stores require authentication", pool, ans, [a for a in ans if a["auth_required"] is False], "registered vector stores",
                          "Require authentication and restrict the network path; embeddings can be read back into text.", 4, _page(PAGE_REGISTER, "auth_required", True, "Records that authentication is required."), "open without authentication", thr)
    out.append(guard("vector-store-access", "data", "Vector stores require authentication", vauth, 4))

    def rac():
        pool = [a for a in systems if a.get("uses_rag") is True]
        ans = [a for a in pool if a.get("rag_access_control") is not None]
        return _tri_check("retrieval-access-control", "data", "Retrieval respects each user's access to documents", pool, ans, [a for a in ans if a["rag_access_control"] is False], "systems that retrieve from a store",
                          "Enforce per-document permissions at retrieval time and separate tenants' indexes.", 4, _page(PAGE_REGISTER, "rag_access_control", True, "Records that retrieval honors permissions."), "ignoring document permissions", thr)
    out.append(guard("retrieval-access-control", "data", "Retrieval respects each user's access to documents", rac, 4))

    def dsval():
        pool = [a for a in assets if a.get("kind") == "dataset"]
        ans = [a for a in pool if a.get("training_data_validated") is not None]
        return _tri_check("dataset-validated", "data", "Datasets are validated before use", pool, ans, [a for a in ans if a["training_data_validated"] is False], "registered datasets",
                          "Track lineage, validate and sample what goes in.", 3, _page(PAGE_REGISTER, "training_data_validated", True, "Records the validation."), "not validated", thr)
    out.append(guard("dataset-validated", "data", "Datasets are validated before use", dsval, 3))

    # ---- providers
    def prov_rec():
        if not systems:
            return _chk("provider-recorded", "providers", "Each AI system's provider is recorded", "unknown", weight=3, evidence=["No application, agent or gateway is registered."], recommendation="Register each AI system.", change=_page(PAGE_REGISTER, "register", "add each system", "Lets providers be linked."), data_used=["AI register"])
        linked = {e["source"] for e in graph["edges"] if e["kind"] == "hosted_by"}
        n = sum(1 for s in _systems(graph) if s in linked)
        ch = _page(PAGE_USAGE, "usage source", "connect a provider or gateway, naming the application", "Ties each system to the provider it calls.")
        if not n:
            if d["usage"]:
                return _chk("provider-recorded", "providers", "Each AI system's provider is recorded", "fail", weight=3, evidence=[f"{len(d['usage'])} AI usage events in 30 days, none attributed to any of {len(systems)} registered systems."],
                            recommendation="Send the application name with each usage event so usage ties to a registered system.", change=ch, data_used=["AI usage", "AI register"])
            return _chk("provider-recorded", "providers", "Each AI system's provider is recorded", "unknown", weight=3, evidence=[f"No AI usage is recorded, so no provider can be tied to any of {len(systems)} systems."],
                        recommendation="Connect an AI usage source.", change=ch, data_used=["AI usage"])
        return _share_check("provider-recorded", "providers", "Each AI system's provider is recorded", n / len(systems), [f"{n} of {len(systems)} registered systems have a provider seen in usage."], thr, 3,
                            recommendation="Attribute usage to the remaining systems.", change=ch, data_used=["AI usage", "AI register"])
    out.append(guard("provider-recorded", "providers", "Each AI system's provider is recorded", prov_rec, 3, need=("ai.assets", "aisc.graph")))

    def prov_ok():
        allowed = d["policy"].get("allowed_models") or []
        ch = {"kind": "yaml", "where": POLICY_FILE, "key": "allowed_models", "value": ["<your approved model names>"], "effect": "Flags AI usage on any other model."}
        rows = d["usage"]
        if not allowed:
            return _chk("provider-approved", "providers", "AI is used only through approved models and providers", "unknown", weight=4, evidence=["No approved-model list is recorded, so nothing can be called outside it."],
                        recommendation="List the approved models; usage on others will be flagged per provider.", change=ch, data_used=["ai_usage_policy.yaml"])
        if not rows:
            return _chk("provider-approved", "providers", "AI is used only through approved models and providers", "unknown", weight=4, evidence=[f"An approved list of {len(allowed)} entries is set, but no AI usage was recorded in 30 days."],
                        recommendation="Connect an AI usage source.", change=_page(PAGE_USAGE, "usage source", "connect a provider or gateway", "Records which models and providers are called."), data_used=["AI usage"])
        bad, total = {}, 0
        for r in rows:
            total += r["request_count"]
            if not any(fnmatch.fnmatchcase(r["model"], a) for a in allowed):
                bad[r.get("provider") or "(provider not stated)"] = bad.get(r.get("provider") or "(provider not stated)", 0) + r["request_count"]
        nb = sum(bad.values())
        if not nb:
            return _chk("provider-approved", "providers", "AI is used only through approved models and providers", "pass", weight=4, evidence=[f"All {total} AI requests in 30 days used approved models."], recommendation="Keep the list current.", data_used=["AI usage"])
        share = 1 - nb / total
        return _chk("provider-approved", "providers", "AI is used only through approved models and providers", "partial" if share >= thr["coverage_partial"] else "fail", score=share, weight=4,
                    evidence=[f"{nb} of {total} AI requests used models outside the approved list, via: " + ", ".join(f"{p} ({n})" for p, n in sorted(bad.items(), key=lambda kv: (-kv[1], kv[0]))[:5]) + "."],
                    recommendation="Move that usage to an approved model or review the provider and add the model.", change=ch, data_used=["AI usage", "ai_usage_policy.yaml"])
    out.append(guard("provider-approved", "providers", "AI is used only through approved models and providers", prov_ok, 4, need=("ai.usage30",)))
    out.append(concentration("provider-concentration", "providers", "AI systems do not all depend on one provider", ("hosted_by",), "provider", 3))

    def shadow():
        apps = d["apps"]
        ch = {"kind": "page", "where": "/ai-usage", "key": "Applications found", "value": "upload a proxy or DNS export, then mark each service sanctioned or blocked", "effect": "Finds and reviews AI services people use."}
        if not apps:
            return _chk("shadow-ai", "providers", "AI services in use have been reviewed", "unknown", weight=4, evidence=["No AI applications are recorded. That means no proxy or DNS export was uploaded, not that none are in use."],
                        recommendation="Upload a proxy or DNS export on AI Usage.", change=ch, data_used=["AI applications found"])
        open_ = [a for a in apps if a["status"] == "unreviewed"]
        share = 1 - len(open_) / len(apps)
        if not open_:
            return _chk("shadow-ai", "providers", "AI services in use have been reviewed", "pass", weight=4, evidence=[f"All {len(apps)} AI applications found have been reviewed."], recommendation="Re-upload exports regularly.", data_used=["AI applications found"])
        return _chk("shadow-ai", "providers", "AI services in use have been reviewed", "partial" if share >= thr["coverage_partial"] else "fail", score=share, weight=4,
                    evidence=[f"{len(open_)} of {len(apps)} AI applications found in traffic are unreviewed: {', '.join(a['name'] for a in open_[:5])}."], recommendation="Mark each sanctioned or blocked, and register the sanctioned ones.", change=ch, data_used=["AI applications found"])
    out.append(guard("shadow-ai", "providers", "AI services in use have been reviewed", shadow, 4, need=("ai.apps",)))

    # ---- assurance
    def mlbom():
        boms = d["sboms"]
        ch = _page(PAGE_APPS, "SBOM", "upload or generate one that lists the model components", "Records the models an application contains.")
        if not boms:
            return _chk("mlbom", "assurance", "Applications that use models have an AI bill of materials", "unknown", weight=4, evidence=["No SBOM is stored for any application, so no AI component can be seen."],
                        recommendation="Store an SBOM for each application that uses a model, listing the model as a machine-learning-model component.", change=ch, data_used=["application SBOMs"])
        libs, models_ = {}, {}
        for app, comps in boms.items():
            lib = [c for c in comps if str(c.get("name") or "").lower() in AI_LIBRARIES]
            ml = [c for c in comps if c.get("type") == "machine-learning-model"]
            if lib or ml:
                libs[app], models_[app] = lib, ml
        if not libs:
            return _chk("mlbom", "assurance", "Applications that use models have an AI bill of materials", "unknown", weight=4,
                        evidence=[f"{len(boms)} SBOMs are stored; none lists an AI library or a machine-learning-model component, and registered systems cannot be tied to an SBOM."],
                        recommendation="Make sure the SBOM of each AI application is stored and includes its models.", change=ch, data_used=["application SBOMs"])
        have = [a for a in libs if models_[a]]
        return _share_check("mlbom", "assurance", "Applications that use models have an AI bill of materials", len(have) / len(libs),
                            [f"{len(have)} of {len(libs)} applications with AI components list a machine-learning-model component ({len(boms)} SBOMs stored)."], thr, 4,
                            detail="An SBOM that names the AI library but not the model hides what the application actually runs.", recommendation="Add the models to the SBOM as machine-learning-model components (CycloneDX ML-BOM).", change=ch, data_used=["application SBOMs"])
    out.append(guard("mlbom", "assurance", "Applications that use models have an AI bill of materials", mlbom, 4, need=("aisc.sboms",)))

    for cid, title, ev, rec in (("weight-integrity", "Model weights are protected against tampering", "Quanta cannot read model weights or their hashes.", "Store weights in a controlled registry, record a hash for each release and verify it at load time."),
                                ("vendor-assurance", "AI providers have been assessed for security", "Quanta holds no record of provider security assessments, certifications or contract terms.", "Record each provider's assessment (date, scope, result) in the register notes or your vendor system.")):
        out.append(_na(cid, "assurance", title, 3) if not d["has_ai"] else
                   _chk(cid, "assurance", title, "unknown", weight=3, evidence=[ev + f" {len(assets or [])} system(s) and {len(d['apps'] or [])} unreviewed or reviewed AI application(s) are recorded."], recommendation=rec,
                        change=_page(PAGE_REGISTER, "notes", "evidence reference", "Keeps the evidence next to the system."), data_used=["AI register"]))
    return out
