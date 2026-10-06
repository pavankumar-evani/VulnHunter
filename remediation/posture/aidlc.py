"""The AI development lifecycle: NIST SP 800-218A (the SSDF community profile for generative AI) and the OWASP Top 10 for LLM applications (2025).

Reads only what Quanta already records: the AI register (remediation/aisec), AI findings in the queue (asset type ai-ml-system), AI usage events, budgets and
unreviewed AI applications (remediation/aiusage) and the approved-model list in remediation/config/ai_usage_policy.yaml. A register question left unanswered is a gap,
never a pass. What Quanta cannot see (training-data provenance, evaluation results, red-team results, model weights, prompts) is `unknown`, with a note to record it.
"""
import datetime
import fnmatch

from remediation.posture import model

FRAMEWORK = {
    "id": "aidlc",
    "title": "AI development lifecycle",
    "summary": "How AI systems are governed, fed, built, deployed and operated, against NIST SP 800-218A and the OWASP Top 10 for LLM applications, from what the AI register, "
               "the queue and AI usage records show. Quanta cannot inspect models, training data, evaluation results or prompts, so those are listed as not observable.",
    "areas": [("govern", "Govern"), ("data", "Data"), ("model", "Model"), ("deploy", "Deploy"), ("operate", "Operate")],
    "refs": [{"label": "NIST SP 800-218A: SSDF community profile for generative AI", "url": "https://csrc.nist.gov/pubs/sp/800/218/a/final"},
             {"label": "OWASP Top 10 for LLM applications (2025)", "url": "https://genai.owasp.org/llm-top-10/"}],
}
FW = FRAMEWORK["id"]
REFS = FRAMEWORK["refs"]
APP_KINDS = ("application", "agent", "gateway")
PAGE_REGISTER = {"kind": "page", "where": "/ai-security"}
PAGE_USAGE = {"kind": "page", "where": "/ai-usage"}
POLICY_FILE = "remediation/config/ai_usage_policy.yaml"


def _chk(cid, area, title, status, **kw):
    kw.setdefault("refs", REFS)
    return model.check(f"aidlc-{cid}", FW, area, title, status, **kw)


def _page(base, key, value, effect):
    return {**base, "key": key, "value": value, "effect": effect}


# ----------------------------------------------------------------------------------------------------------------------------- loading
def _load(ctx):
    from remediation.aisec import rules
    from remediation.aisec import store as aisec_store
    from remediation.aiusage import analytics, discovery
    assets = ctx.get("ai.assets", lambda: aisec_store.list_all(ctx.engine))
    assessed = ctx.get("ai.assessed", lambda: aisec_store.assess(assets or [], ctx.now.date(), rules.approved_models())) if assets is not None else None
    summary = ctx.get("ai.summary", lambda: analytics.summary(30, ctx.engine, ctx.now))
    apps = ctx.get("ai.apps", lambda: discovery.list_apps(ctx.engine))
    policy = ctx.get("ai.policy", analytics.policy) or {}
    ai_findings = [f for f in ctx.findings if isinstance(f.get("asset"), dict) and f["asset"].get("type") == "ai-ml-system"]
    requests = ((summary or {}).get("totals") or {}).get("requests", 0)
    has_ai = bool(assets or ai_findings or apps or requests)
    return {"assets": assets, "assessed": assessed, "summary": summary, "apps": apps, "policy": policy, "ai_findings": ai_findings, "has_ai": has_ai, "requests": requests}


def _cov(share, thr):
    """(status, score) for a share-in-place: pass at coverage_good, partial between the two thresholds, fail below coverage_partial."""
    if share >= thr["coverage_good"]:
        return "pass", None
    if share >= thr["coverage_partial"]:
        return "partial", share
    return "fail", None


def _no_ai(cid, area, title, weight=3):
    return _chk(cid, area, title, "na", weight=weight, evidence=["No AI systems, AI findings, AI usage or AI applications are recorded, so this does not apply yet."],
                recommendation="Register AI systems on AI Security when you have them.", data_used=["AI register", "AI usage", "AI findings"])


def _unreadable(ctx, cid, area, title, source, weight=3):
    return _chk(cid, area, title, "unknown", weight=weight, evidence=[f"Could not read {source}: {ctx.unavailable.get(source, 'not available')}"],
                recommendation="Check that the database is reachable, then re-run the review.", data_used=[source])


def _tri(assets, field, bad, kinds=None, only=None):
    """(considered, answered, bad_assets): `only` narrows to assets for which a predicate holds first."""
    pool = [a for a in assets if (kinds is None or a.get("kind") in kinds) and (only is None or only(a))]
    answered = [a for a in pool if a.get(field) is not None]
    return pool, answered, [a for a in answered if a.get(field) is bad]


def _tri_check(cid, area, title, pool, answered, bad, what, rec, weight=3, change=None, bad_means="", data_used=("AI register",), thr=None):
    """The shared rule for a yes/no register question. Only an explicit bad answer fails; an unanswered question is a gap."""
    n, a, b = len(pool), len(answered), len(bad)
    names = ", ".join(sorted(x["name"] for x in bad)[:5])
    if not n:
        return _chk(cid, area, title, "na", weight=weight, evidence=[f"No registered system this applies to ({what})."], recommendation=rec, data_used=list(data_used))
    if not a:
        return _chk(cid, area, title, "unknown", weight=weight, evidence=[f"0 of {n} systems have answered this question ({what})."], recommendation=rec, change=change, data_used=list(data_used))
    if b:
        score = 1 - b / a
        ev = [f"{b} of {a} answering systems are {bad_means}: {names}.", f"{n - a} of {n} systems have not answered."]
        return _chk(cid, area, title, "partial" if score >= (thr or {"coverage_partial": 0.5})["coverage_partial"] else "fail", score=score, weight=weight, evidence=ev,
                    detail=what, recommendation=rec, change=change, data_used=list(data_used))
    if a < n:
        return _chk(cid, area, title, "partial", score=a / n, weight=weight, evidence=[f"{a} of {n} systems answered and none is {bad_means}; {n - a} have not answered."],
                    detail=what, recommendation=rec, change=change, data_used=list(data_used))
    return _chk(cid, area, title, "pass", weight=weight, evidence=[f"All {n} systems answered and none is {bad_means}."], detail=what, recommendation=rec, data_used=list(data_used))


def derived(assets, fn, kinds=None, only=None):
    """(pool, answered, bad) for a question whose answer is computed from a record (a nested field, or several fields together).

    fn(asset) returns True (in place), False (explicitly not) or None (not answered). Copies carry the answer in `_v` so the shared yes/no rule applies unchanged.
    """
    pool = [{**a, "_v": fn(a)} for a in assets if (kinds is None or a.get("kind") in kinds) and (only is None or only(a))]
    return pool, [a for a in pool if a["_v"] is not None], [a for a in pool if a["_v"] is False]


def all_of(*vals):
    """True when every answer is True, False when any is False, otherwise unknown: one explicit 'no' counts, a blank never counts as a 'yes'."""
    if any(v is False for v in vals):
        return False
    return True if all(v is True for v in vals) else None


def _age_days(first_seen, now):
    try:
        return (now.date() - datetime.date.fromisoformat(str(first_seen)[:10])).days
    except ValueError:
        return None


# ----------------------------------------------------------------------------------------------------------------------------- the checks
def run(ctx):
    d = _load(ctx)
    thr = ctx.thr
    out = []
    assets, assessed, summary = d["assets"], d["assessed"], d["summary"]

    def guard(cid, area, title, fn, weight=3, needs_assets=True):
        if not d["has_ai"]:
            return _no_ai(cid, area, title, weight)
        if needs_assets and assets is None:
            return _unreadable(ctx, cid, area, title, "ai.assets", weight)
        return fn()

    # ---- govern
    def owner():
        if not assets:
            return _chk("owner", "govern", "Every registered AI system has an accountable owner", "unknown", weight=4,
                        evidence=["No AI system is registered" + (f", although {d['requests']} AI requests and {len(d['apps'] or [])} AI applications were seen" if d["requests"] or d["apps"] else "") + "."],
                        recommendation="Register each AI system with an owner.", change=_page(PAGE_REGISTER, "owner", "a named accountable person or team", "Makes a person accountable for each AI system."), data_used=["AI register"])
        owned = [a for a in assets if a.get("owner")]
        share = len(owned) / len(assets)
        ev = [f"{len(owned)} of {len(assets)} registered AI systems have an owner."] + ([f"No owner: {', '.join(sorted(a['name'] for a in assets if not a.get('owner'))[:5])}."] if share < 1 else [])
        st, sc = ("pass", None) if share == 1 else _cov(share, thr)
        return _chk("owner", "govern", "Every registered AI system has an accountable owner", st, score=sc if st == "partial" else None, weight=4, evidence=ev,
                    detail="NIST SP 800-218A asks for defined roles for AI; an unowned system is nobody's to review or retire.", recommendation="Name an owner for each system on AI Security.",
                    change=_page(PAGE_REGISTER, "owner", "a named accountable person or team", "Makes a person accountable for each AI system."), data_used=["AI register"])
    out.append(guard("owner", "govern", "Every registered AI system has an accountable owner", owner, 4, needs_assets=False))

    def answered():
        if not assets:
            return _chk("questions-answered", "govern", "The AI risk questions are answered for each system", "unknown", evidence=["No AI system is registered."],
                        recommendation="Register each AI system and answer its risk questions.", change=_page(PAGE_REGISTER, "risk questions", "answer each one", "Lets the OWASP LLM rules decide."), data_used=["AI register"])
        gaps = assessed["unanswered_total"]
        given = sum(1 for a in assets for f in ("untrusted_input", "internet_facing", "auth_required", "can_take_actions", "human_in_loop", "high_stakes_use", "downstream_trusts_output",
                                                  "input_guardrails", "output_filtering", "rate_limited", "logging", "secrets_in_prompt", "plugins_reviewed", "training_data_validated",
                                                  "fine_tuned", "uses_rag", "rag_access_control") if a.get(f) is not None)
        total = given + gaps
        if not total:
            return _chk("questions-answered", "govern", "The AI risk questions are answered for each system", "unknown", evidence=[f"{len(assets)} systems registered, no question asked or answered."],
                        recommendation="Answer the risk questions on AI Security.", change=_page(PAGE_REGISTER, "risk questions", "answer each one", "Lets the OWASP LLM rules decide."), data_used=["AI register"])
        share = given / total
        st, sc = ("pass", None) if gaps == 0 else _cov(share, thr)
        return _chk("questions-answered", "govern", "The AI risk questions are answered for each system", st, score=sc, evidence=[f"{given} of {total} risk questions answered ({gaps} unanswered) across {len(assets)} systems."],
                    detail="A rule fires only on an explicit no, so an unanswered question hides a possible finding.", recommendation="Answer the open questions listed per system on AI Security.",
                    change=_page(PAGE_REGISTER, "risk questions", "answer each one", "Lets the OWASP LLM rules decide."), data_used=["AI register"])
    out.append(guard("questions-answered", "govern", "The AI risk questions are answered for each system", answered, needs_assets=False))

    def review():
        if not assets:
            return _chk("review-current", "govern", "AI systems have been reviewed recently", "unknown", weight=2, evidence=["No AI system is registered."], recommendation="Register and review each AI system.",
                        change=_page(PAGE_REGISTER, "last_reviewed", "today's date after a review", "Records that a person reviewed it."), data_used=["AI register"])
        cur = [a for a in assets if (_age_days(a.get("last_reviewed"), ctx.now) is not None and _age_days(a.get("last_reviewed"), ctx.now) <= thr["stale_days"])]
        share = len(cur) / len(assets)
        st, sc = ("pass", None) if share == 1 else _cov(share, thr)
        return _chk("review-current", "govern", "AI systems have been reviewed recently", st, score=sc, weight=2,
                    evidence=[f"{len(cur)} of {len(assets)} systems were reviewed in the last {thr['stale_days']} days."], detail="Capabilities and exposure drift; an old review no longer counts.",
                    recommendation="Review each system and record the date.", change=_page(PAGE_REGISTER, "last_reviewed", "today's date after a review", "Records that a person reviewed it."), data_used=["AI register"])
    out.append(guard("review-current", "govern", "AI systems have been reviewed recently", review, 2, needs_assets=False))

    def approved():
        allowed = d["policy"].get("allowed_models") or []
        ch = {"kind": "yaml", "where": POLICY_FILE, "key": "allowed_models", "value": ["<your approved model names>"], "effect": "Flags AI usage on any other model."}
        if not allowed:
            return _chk("approved-models", "govern", "AI usage stays on approved models", "unknown", weight=4, evidence=["No approved-model list is recorded in ai_usage_policy.yaml, so nothing can be called outside it."],
                        recommendation="List the models your organization approves.", change=ch, data_used=["ai_usage_policy.yaml"])
        if not d["requests"]:
            return _chk("approved-models", "govern", "AI usage stays on approved models", "unknown", weight=4, evidence=[f"An approved list of {len(allowed)} entries is set, but no AI usage was recorded in 30 days."],
                        recommendation="Connect an AI usage source so usage can be compared with the list.", change=_page(PAGE_USAGE, "usage source", "connect a provider or gateway", "Records which models are called."), data_used=["AI usage"])
        outside = summary.get("outside_allowed_models") or []
        bad = sum(m["requests"] for m in outside)
        share = 1 - bad / d["requests"]
        if not outside:
            return _chk("approved-models", "govern", "AI usage stays on approved models", "pass", weight=4, evidence=[f"All {d['requests']} AI requests in 30 days used approved models."], data_used=["AI usage"], recommendation="Keep the list current.")
        return _chk("approved-models", "govern", "AI usage stays on approved models", "partial" if share >= thr["coverage_partial"] else "fail", score=share, weight=4,
                    evidence=[f"{bad} of {d['requests']} AI requests ({round(100 * (1 - share), 1)}%) used {len(outside)} model(s) outside the approved list: {', '.join(m['model'] for m in outside[:5])}."],
                    detail="Unapproved models have had no security or data-handling review.", recommendation="Move that usage to an approved model, or review the model and add it to the list.", change=ch, data_used=["AI usage", "ai_usage_policy.yaml"])
    out.append(guard("approved-models", "govern", "AI usage stays on approved models", approved, 4, needs_assets=False))

    def shadow():
        apps = d["apps"]
        ch = {"kind": "page", "where": "/ai-usage", "key": "Applications found", "value": "upload a proxy or DNS export, then mark each service sanctioned or blocked", "effect": "Finds and reviews AI services people use."}
        if not apps:
            return _chk("shadow-ai", "govern", "AI applications found in traffic have been reviewed", "unknown", weight=3,
                        evidence=["No AI applications are recorded. That means no proxy or DNS export was uploaded, not that none are in use."], recommendation="Upload a proxy or DNS export on AI Usage.", change=ch, data_used=["AI applications found"])
        open_ = [a for a in apps if a["status"] == "unreviewed"]
        share = 1 - len(open_) / len(apps)
        if not open_:
            return _chk("shadow-ai", "govern", "AI applications found in traffic have been reviewed", "pass", weight=3, evidence=[f"All {len(apps)} AI applications found have been reviewed."], data_used=["AI applications found"], recommendation="Re-upload exports regularly.")
        return _chk("shadow-ai", "govern", "AI applications found in traffic have been reviewed", "partial" if share >= thr["coverage_partial"] else "fail", score=share, weight=3,
                    evidence=[f"{len(open_)} of {len(apps)} AI applications found in traffic are unreviewed: {', '.join(a['name'] for a in open_[:5])}."], detail="Unreviewed AI use is where data leaves without a decision.",
                    recommendation="Mark each service sanctioned or blocked, and register the sanctioned ones.", change=ch, data_used=["AI applications found"])
    out.append(guard("shadow-ai", "govern", "AI applications found in traffic have been reviewed", shadow, needs_assets=False))

    # ---- data
    def filt():
        pool, ans, bad = _tri(assets, "output_filtering", False, only=lambda a: set(a.get("data_classes") or []) & {"pii", "phi", "pci", "secrets", "proprietary"})
        return _tri_check("output-filtering", "data", "Systems handling sensitive data filter what the model returns (LLM02)", pool, ans, bad, "systems that handle sensitive data classes",
                          "Filter outputs for the data classes involved and answer the question on AI Security.", 4, _page(PAGE_REGISTER, "output_filtering", True, "Records that output filtering is in place."), "returning sensitive data unfiltered", thr=thr)
    out.append(guard("output-filtering", "data", "Systems handling sensitive data filter what the model returns (LLM02)", filt, 4))

    def trainval():
        pool = [a for a in assets if a.get("fine_tuned") is True or a.get("kind") == "dataset"]
        ans = [a for a in pool if a.get("training_data_validated") is not None]
        return _tri_check("training-data-validated", "data", "Training and fine-tuning data is validated (LLM04)", pool, ans, [a for a in ans if a["training_data_validated"] is False],
                          "fine-tuned systems and datasets", "Validate and sample training data, then record it on AI Security.", 3, _page(PAGE_REGISTER, "training_data_validated", True, "Records the validation."), "unvalidated", thr=thr)
    out.append(guard("training-data-validated", "data", "Training and fine-tuning data is validated (LLM04)", trainval))

    def rag():
        pool, ans, bad = _tri(assets, "rag_access_control", False, only=lambda a: a.get("uses_rag") is True)
        return _tri_check("rag-access-control", "data", "Retrieval respects each user's access to documents (LLM08)", pool, ans, bad, "systems that retrieve from a document or vector store",
                          "Enforce per-document permissions at retrieval time.", 4, _page(PAGE_REGISTER, "rag_access_control", True, "Records that retrieval honors permissions."), "ignoring document permissions", thr=thr)
    out.append(guard("rag-access-control", "data", "Retrieval respects each user's access to documents (LLM08)", rag, 4))

    def prov_ev():
        n = len([a for a in assets if a.get("fine_tuned") is True or a.get("kind") == "dataset"]) if assets else 0
        return _chk("data-provenance-evidence", "data", "Training-data provenance is evidenced", "unknown", weight=3,
                    evidence=[f"Quanta cannot inspect training data or its lineage. {n} registered system(s) are fine-tuned or datasets."],
                    recommendation="Record where each dataset came from, who approved it and its licence, in the register notes or your data catalogue.",
                    change=_page(PAGE_REGISTER, "notes", "source, approver and licence of each dataset", "Keeps the lineage next to the system."), data_used=["AI register"])
    out.append(_no_ai("data-provenance-evidence", "data", "Training-data provenance is evidenced") if not d["has_ai"] else prov_ev())

    # ---- model
    def mprov():
        pool = [a for a in assets if a.get("kind") in ("model", "application", "agent")]
        ans = [a for a in pool if a.get("provenance") in ("verified", "unverified")]
        return _tri_check("model-provenance", "model", "Models come from a verified source (LLM03)", pool, ans, [a for a in ans if a["provenance"] == "unverified"], "models and the systems that embed one",
                          "Pull models from a registry you control and record the source.", 4, _page(PAGE_REGISTER, "provenance", "verified", "Records that the origin was checked."), "of unverified origin", thr=thr)
    out.append(guard("model-provenance", "model", "Models come from a verified source (LLM03)", mprov, 4))

    def mser():
        pool = [a for a in assets if a.get("kind") == "model"]
        ans = [a for a in pool if a.get("serialization") not in (None, "unknown")]
        return _tri_check("model-format", "model", "Models are stored in a format that cannot run code (LLM03)", pool, ans, [a for a in ans if a["serialization"] == "pickle"], "registered models",
                          "Convert pickle models to safetensors.", 3, _page(PAGE_REGISTER, "serialization", "safetensors", "Records a non-executable format."), "stored as pickle", thr=thr)
    out.append(guard("model-format", "model", "Models are stored in a format that cannot run code (LLM03)", mser))

    for cid, title, what, rec in (("evaluation-evidence", "Models are evaluated before release", "evaluation results", "Record the evaluation (what was tested, when, the result) against each system in the register notes."),
                                  ("red-team-evidence", "AI systems are red-teamed or adversarially tested", "red-team and adversarial test results", "Record each red-team exercise and its date in the register notes.")):
        out.append(_no_ai(cid, "model", title, 3) if not d["has_ai"] else _chk(cid, "model", title, "unknown", weight=3, evidence=[f"Quanta cannot see {what}; {len(assets or [])} system(s) are registered."],
                                                                              recommendation=rec, change=_page(PAGE_REGISTER, "notes", "evidence reference", "Keeps the evidence next to the system."), data_used=["AI register"]))

    # ---- deploy
    def pi():
        pool, ans, bad = _tri(assets, "input_guardrails", False, APP_KINDS, only=lambda a: a.get("untrusted_input") is True)
        c = _tri_check("prompt-injection", "deploy", "Systems that take untrusted input have injection defences (LLM01)", pool, ans, bad, "application, agent and gateway systems that process untrusted input",
                       "Separate instructions from data, filter input and never let model output authorise an action alone.", 5, _page(PAGE_REGISTER, "input_guardrails", True, "Records the defence."), "without an injection defence", thr=thr)
        if c["status"] == "na" and any(a.get("kind") in APP_KINDS and a.get("untrusted_input") is None for a in assets):
            return _chk("prompt-injection", "deploy", c["title"], "unknown", weight=5, evidence=["No application, agent or gateway system has said whether it takes untrusted input."], recommendation="Answer the untrusted-input question on AI Security.",
                        change=_page(PAGE_REGISTER, "untrusted_input", "true or false", "Lets the injection rule decide."), data_used=["AI register"])
        return c
    out.append(guard("prompt-injection", "deploy", "Systems that take untrusted input have injection defences (LLM01)", pi, 5))

    def oh():
        pool = [a for a in assets if a.get("kind") in APP_KINDS]
        ans = [a for a in pool if a.get("downstream_trusts_output") is not None]
        return _tri_check("output-handling", "deploy", "Model output is validated before other systems use it (LLM05)", pool, ans, [a for a in ans if a["downstream_trusts_output"] is True], "application, agent and gateway systems",
                          "Validate and encode output for where it goes; never execute it directly.", 4, _page(PAGE_REGISTER, "downstream_trusts_output", False, "Records that output is validated."), "passing output on unvalidated", thr=thr)
    out.append(guard("output-handling", "deploy", "Model output is validated before other systems use it (LLM05)", oh, 4))

    def agency():
        pool = [a for a in assets if a.get("kind") in ("application", "agent", "mcp-server", "gateway")]
        acting = [a for a in pool if a.get("can_take_actions") is True]
        unsure = [a for a in pool if a.get("can_take_actions") is None]
        if not pool:
            return _chk("excessive-agency", "deploy", "Systems that can act need a person's approval (LLM06)", "unknown", weight=5, evidence=["No registered system has recorded whether it can take actions."],
                        recommendation="Record what each agent and tool can do.", change=_page(PAGE_REGISTER, "can_take_actions", "true or false", "Lets the agency rule decide."), data_used=["AI register"])
        if len(unsure) == len(pool):
            return _chk("excessive-agency", "deploy", "Systems that can act need a person's approval (LLM06)", "unknown", weight=5, evidence=[f"0 of {len(pool)} systems have answered whether they can act."],
                        recommendation="Answer the can-take-actions question on AI Security.", change=_page(PAGE_REGISTER, "can_take_actions", "true or false", "Lets the agency rule decide."), data_used=["AI register"])
        unapproved = [a for a in acting if a.get("human_in_loop") is not True]
        if acting:
            share = 1 - len(unapproved) / len(acting)
            if not unapproved and not unsure:
                return _chk("excessive-agency", "deploy", "Systems that can act need a person's approval (LLM06)", "pass", weight=5, evidence=[f"All {len(acting)} systems that can act have a person approving consequential actions."], data_used=["AI register"], recommendation="Keep permissions narrow.")
            ev = [f"{len(unapproved)} of {len(acting)} systems that can act lack recorded human approval: {', '.join(sorted(a['name'] for a in unapproved)[:5])}."] + ([f"{len(unsure)} systems have not said whether they can act."] if unsure else [])
            return _chk("excessive-agency", "deploy", "Systems that can act need a person's approval (LLM06)", "partial" if share >= thr["coverage_partial"] and share > 0 else "fail", score=share, weight=5, evidence=ev,
                        detail="A model that can act and is steered wrongly acts wrongly at machine speed.", recommendation="Require approval for consequential or irreversible actions and give it the narrowest permissions.",
                        change=_page(PAGE_REGISTER, "human_in_loop", True, "Records that a person approves."), data_used=["AI register"])
        if not unsure:
            return _chk("excessive-agency", "deploy", "Systems that can act need a person's approval (LLM06)", "pass", weight=5, evidence=[f"All {len(pool)} systems say they cannot take actions."], data_used=["AI register"], recommendation="Re-check when tools are added.")
        return _chk("excessive-agency", "deploy", "Systems that can act need a person's approval (LLM06)", "partial", score=(len(pool) - len(unsure)) / len(pool), weight=5,
                    evidence=[f"No system says it can act; {len(unsure)} of {len(pool)} have not answered."], recommendation="Answer the can-take-actions question for the rest.", change=_page(PAGE_REGISTER, "can_take_actions", "true or false", "Lets the agency rule decide."), data_used=["AI register"])
    out.append(guard("excessive-agency", "deploy", "Systems that can act need a person's approval (LLM06)", agency, 5))

    def sev():
        sevs = assessed["by_severity"]
        hi = sevs.get("Critical", 0) + sevs.get("High", 0)
        gaps = assessed["unanswered_total"]
        if not assets:
            return _chk("register-severe", "deploy", "No Critical or High AI risks in the register", "unknown", weight=5, evidence=["No AI system is registered."], recommendation="Register AI systems.", change=_page(PAGE_REGISTER, "register", "add each system", "Lets the OWASP rules run."), data_used=["AI register"])
        if hi:
            share = 1 - len({f["asset_id"] for f in assessed["findings"] if f["severity"] in ("Critical", "High")}) / len(assets)
            rules_hit = sorted({f["rule"] for f in assessed["findings"] if f["severity"] in ("Critical", "High")})
            return _chk("register-severe", "deploy", "No Critical or High AI risks in the register", "partial" if share >= thr["coverage_partial"] and share > 0 else "fail", score=share, weight=5,
                        evidence=[f"{hi} Critical or High finding(s) across {len(assets)} systems ({sevs.get('Critical', 0)} Critical, {sevs.get('High', 0)} High); rules {', '.join(rules_hit)}."],
                        recommendation="Work the listed findings, worst first.", change=_page(PAGE_REGISTER, "findings", "publish to the queue", "Puts the findings in the remediation queue with owners."), data_used=["AI register"])
        if gaps:
            tot = gaps + sum(1 for a in assets for f in ("untrusted_input", "can_take_actions", "human_in_loop", "input_guardrails", "output_filtering", "logging") if a.get(f) is not None)
            return _chk("register-severe", "deploy", "No Critical or High AI risks in the register", "partial", score=max(0.0, 1 - gaps / tot), weight=5, evidence=[f"No Critical or High findings, but {gaps} question(s) are unanswered, so the rules cannot see everything."],
                        recommendation="Answer the open questions.", change=_page(PAGE_REGISTER, "risk questions", "answer each one", "Lets the OWASP LLM rules decide."), data_used=["AI register"])
        return _chk("register-severe", "deploy", "No Critical or High AI risks in the register", "pass", weight=5, evidence=[f"0 Critical or High findings across {len(assets)} systems; no open questions."], recommendation="Keep the register current.", data_used=["AI register"])
    out.append(guard("register-severe", "deploy", "No Critical or High AI risks in the register", sev, 5))

    def plug():
        pool = [a for a in assets if a.get("kind") in ("agent", "plugin")]
        ans = [a for a in pool if a.get("plugins_reviewed") is not None]
        return _tri_check("plugins-reviewed", "deploy", "Plugins and tools were reviewed before use (LLM03)", pool, ans, [a for a in ans if a["plugins_reviewed"] is False], "agents and plugins",
                          "Review each plugin's code, permissions and publisher.", 3, _page(PAGE_REGISTER, "plugins_reviewed", True, "Records the review."), "not reviewed", thr=thr)
    out.append(guard("plugins-reviewed", "deploy", "Plugins and tools were reviewed before use (LLM03)", plug))

    # ---- operate
    def fage():
        fs = [f for f in d["ai_findings"] if str(f.get("severity")).lower() in ("critical", "high")]
        ch = {"kind": "page", "where": "/ai-security", "key": "Publish findings", "value": "publish", "effect": "Puts register findings in the queue where they are tracked and aged."}
        if not d["ai_findings"]:
            return _chk("ai-findings-age", "operate", "Critical and High AI findings are not left open", "unknown", weight=4,
                        evidence=["No findings for AI systems are in the queue" + (f"; the register has {len(assessed['findings'])} unpublished" if assessed and assessed["findings"] else "") + "."],
                        recommendation="Publish the register's findings to the queue so they are tracked.", change=ch, data_used=["findings", "AI register"])
        old, undated = [], 0
        for f in fs:
            a = _age_days(f.get("first_seen"), ctx.now)
            if a is None:
                undated += 1
            elif a > thr["critical_open_days"]:
                old.append((f, a))
        if not fs:
            return _chk("ai-findings-age", "operate", "Critical and High AI findings are not left open", "pass", weight=4, evidence=[f"{len(d['ai_findings'])} AI finding(s) in the queue, none Critical or High."], data_used=["findings"], recommendation="Keep working the rest.")
        if not old:
            return _chk("ai-findings-age", "operate", "Critical and High AI findings are not left open", "pass", weight=4,
                        evidence=[f"{len(fs)} Critical or High AI finding(s), none open longer than {thr['critical_open_days']} days" + (f" ({undated} without a first-seen date)." if undated else ".")], data_used=["findings"], recommendation="Close them.")
        share = 1 - len(old) / len(fs)
        return _chk("ai-findings-age", "operate", "Critical and High AI findings are not left open", "partial" if 0 < share and share >= thr["coverage_partial"] else "fail", score=share, weight=4,
                    evidence=[f"{len(old)} of {len(fs)} Critical or High AI findings are older than {thr['critical_open_days']} days; oldest {max(a for _, a in old)} days."],
                    recommendation="Fix or formally accept these, starting with the oldest.", change=ch, data_used=["findings"])
    out.append(guard("ai-findings-age", "operate", "Critical and High AI findings are not left open", fage, 4, needs_assets=False))

    def logs():
        pool, ans, bad = _tri(assets, "logging", False, only=lambda a: a.get("environment") == "production")
        return _tri_check("audit-logging", "operate", "Production AI systems keep an audit log", pool, ans, bad, "systems in production", "Log prompts, tool calls and decisions, mindful of personal data retention.", 4,
                          _page(PAGE_REGISTER, "logging", True, "Records that audit logging is on."), "running without audit logging", thr=thr)
    out.append(guard("audit-logging", "operate", "Production AI systems keep an audit log", logs, 4))

    def rate():
        pool, ans, bad = _tri(assets, "rate_limited", False, only=lambda a: a.get("internet_facing") is True)
        return _tri_check("rate-limits", "operate", "Internet-facing AI systems are rate limited (LLM10)", pool, ans, bad, "internet-facing systems", "Rate limit per identity, cap tokens per request and set spend alerts.", 3,
                          _page(PAGE_REGISTER, "rate_limited", True, "Records the limit."), "exposed without a rate limit", thr=thr)
    out.append(guard("rate-limits", "operate", "Internet-facing AI systems are rate limited (LLM10)", rate, 3))

    def budgets():
        b = (summary or {}).get("budgets") or []
        ch = _page(PAGE_USAGE, "Budgets", "add a monthly budget per team or application", "Alerts before spend or tokens run past a limit.")
        if not b:
            if not d["requests"]:
                return _chk("budgets", "operate", "AI spend and tokens have budgets", "unknown", weight=3, evidence=["No budget is set and no AI usage was recorded, so there is nothing to budget yet."],
                            recommendation="Connect an AI usage source and add budgets.", change=ch, data_used=["AI usage", "AI budgets"])
            return _chk("budgets", "operate", "AI spend and tokens have budgets", "fail", weight=3, evidence=[f"{d['requests']} AI requests in 30 days and 0 budgets."], detail="Unbounded use means unbounded cost and extraction risk (LLM10).",
                        recommendation="Add a budget at least for the organization.", change=ch, data_used=["AI usage", "AI budgets"])
        over = [x for x in b if x["state"] == "exceeded"]
        if not over:
            return _chk("budgets", "operate", "AI spend and tokens have budgets", "pass", weight=3, evidence=[f"{len(b)} budget(s) set, none exceeded."], data_used=["AI budgets"], recommendation="Review limits each quarter.")
        return _chk("budgets", "operate", "AI spend and tokens have budgets", "partial", score=1 - len(over) / len(b), weight=3, evidence=[f"{len(over)} of {len(b)} budgets are exceeded."], recommendation="Investigate the overspend or raise the limit on purpose.",
                    change=ch, data_used=["AI budgets"])
    out.append(guard("budgets", "operate", "AI spend and tokens have budgets", budgets, needs_assets=False))

    def unusual():
        an = (summary or {}).get("anomalies") or []
        ch = {"kind": "yaml", "where": POLICY_FILE, "key": "anomaly_factor", "value": 3.0, "effect": "Sets how far above normal a day must be to be flagged."}
        if not d["requests"]:
            return _chk("unusual-usage", "operate", "AI usage has no unexplained spikes", "unknown", weight=2, evidence=["No AI usage was recorded in 30 days."], recommendation="Connect an AI usage source.",
                        change=_page(PAGE_USAGE, "usage source", "connect a provider or gateway", "Records usage so spikes show."), data_used=["AI usage"])
        if not an:
            return _chk("unusual-usage", "operate", "AI usage has no unexplained spikes", "pass", weight=2, evidence=[f"{d['requests']} AI requests in 30 days, no unusual day or new model."], data_used=["AI usage"], recommendation="Keep the source connected.")
        return _chk("unusual-usage", "operate", "AI usage has no unexplained spikes", "partial", score=max(0.0, 1 - len(an) / max(len(summary["daily"]), 1)), weight=2,
                    evidence=[f"{len(an)} unusual event(s) in 30 days across {len(summary['daily'])} days: {an[0]['detail']}"], recommendation="Find out what drove each one.", change=ch, data_used=["AI usage"])
    out.append(guard("unusual-usage", "operate", "AI usage has no unexplained spikes", unusual, 2, needs_assets=False))

    # ---- agents, memory and release (read from the register's agent and lifecycle fields; blank is a gap)
    ch_reg = lambda key, value, effect: _page(PAGE_REGISTER, key, value, effect)  # noqa: E731
    acting = lambda a: a.get("kind") == "agent" or a.get("can_take_actions") is True  # noqa: E731

    def memory():
        pool, ans, bad = derived(assets, lambda a: all_of(a.get("memory_provenance"), a.get("memory_poisoning_controls")), only=lambda a: a.get("memory") == "persistent")
        return _tri_check("memory-controls", "data", "Persistent agent memory records its source and has poisoning controls (LLM04)", pool, ans, bad, "systems with persistent memory",
                          "Record where each memory entry came from, never store instructions from untrusted content, and review or expire entries.", 3,
                          ch_reg("memory_poisoning_controls", True, "Records that memory is validated and reviewable."), "missing provenance or poisoning controls", thr=thr)
    out.append(guard("memory-controls", "data", "Persistent agent memory records its source and has poisoning controls (LLM04)", memory, 3))

    def loops():
        def v(a):
            ms, cap = a.get("max_steps"), a.get("budget_cap")
            if cap is True or (isinstance(ms, int) and ms > 0):
                return True
            return False if (ms == 0 and cap is False) else None
        pool, ans, bad = derived(assets, v, kinds=APP_KINDS, only=acting)
        return _tri_check("agent-loop-limits", "deploy", "Agent loops have a step limit or a budget (LLM10)", pool, ans, bad, "agents and systems that can act",
                          "Set a maximum number of steps per run and a token or cost cap per run.", 3, ch_reg("max_steps", 20, "Bounds one run."), "unbounded", thr=thr)
    out.append(guard("agent-loop-limits", "deploy", "Agent loops have a step limit or a budget (LLM10)", loops, 3))

    def pv():
        pool, ans, bad = derived(assets, lambda a: a.get("prompt_versioning"), kinds=APP_KINDS)
        return _tri_check("prompt-versioning", "deploy", "System prompts are versioned and reviewed (NIST 800-218A)", pool, ans, bad, "applications, agents and gateways",
                          "Keep prompts in version control and record the prompt version of each release.", 3, ch_reg("prompt_versioning", True, "Records that prompts are versioned."), "not versioned", thr=thr)
    out.append(guard("prompt-versioning", "deploy", "System prompts are versioned and reviewed (NIST 800-218A)", pv, 3))

    def ev():
        pool, ans, bad = derived(assets, lambda a: None if a.get("eval_suite") is None else a["eval_suite"] != "none", kinds=APP_KINDS)
        return _tri_check("eval-suite", "deploy", "Systems have an evaluation suite that runs on change (NIST 800-218A)", pool, ans, bad, "applications, agents and gateways",
                          "Build an offline evaluation suite that includes injection and tool-misuse cases, and run it on every prompt, model or tool change.", 4,
                          ch_reg("eval_suite", "offline", "Records that an evaluation suite exists."), "without an evaluation suite", thr=thr)
    out.append(guard("eval-suite", "deploy", "Systems have an evaluation suite that runs on change (NIST 800-218A)", ev, 4))

    def rb():
        pool, ans, bad = derived(assets, lambda a: (a.get("release") or {}).get("rollback_path"), kinds=APP_KINDS, only=lambda a: a.get("environment") == "production")
        return _tri_check("rollback-path", "operate", "Production AI releases can be rolled back", pool, ans, bad, "production applications, agents and gateways",
                          "Keep the previous prompt, model id and tool configuration deployable and rehearse the switch back.", 4,
                          ch_reg("release.rollback_path", True, "Records a tested rollback path."), "without a rollback path", thr=thr)
    out.append(guard("rollback-path", "operate", "Production AI releases can be rolled back", rb, 4))

    def pr():
        def v(a):
            r = a.get("release") or {}
            if r.get("canary") is True or r.get("shadow") is True:
                return True
            return False if (r.get("canary") is False and r.get("shadow") is False) else None
        pool, ans, bad = derived(assets, v, kinds=APP_KINDS, only=lambda a: a.get("environment") == "production")
        return _tri_check("progressive-rollout", "operate", "Production AI changes are released progressively (canary or shadow)", pool, ans, bad, "production applications, agents and gateways",
                          "Release to a small share of traffic or run in shadow first, and widen after evaluations and traces look right.", 2,
                          ch_reg("release.canary", True, "Records progressive release."), "released all at once", thr=thr)
    out.append(guard("progressive-rollout", "operate", "Production AI changes are released progressively (canary or shadow)", pr, 2))

    def obs():
        pool, ans, bad = derived(assets, lambda a: all_of(*[(a.get("observability") or {}).get(k) for k in ("traces", "cost", "latency", "tool_failures")]), kinds=APP_KINDS, only=acting)
        return _tri_check("agent-observability", "operate", "Agents are traced, with cost, latency and tool failures tracked", pool, ans, bad, "agents and systems that can act",
                          "Trace each run step by step and track cost, latency and tool failures per run, with alerts.", 3,
                          ch_reg("observability.traces", True, "Records run tracing."), "missing at least one of tracing, cost, latency or tool-failure tracking", thr=thr)
    out.append(guard("agent-observability", "operate", "Agents are traced, with cost, latency and tool failures tracked", obs, 3))
    return out
