"""Threat modelling posture: do the applications that matter have a threat model, is it complete enough to be useful, are its threats being decided,
and is it kept current? Reads the recorded threat models (remediation/threatmodel), applications (remediation/appsec) and the API inventory
(remediation/apisec). With nothing recorded every check is `unknown`, never a pass."""
import datetime
import fnmatch

from remediation.posture.model import check

FRAMEWORK = {
    "id": "threat-modelling",
    "title": "Threat modelling",
    "summary": "Whether important applications and APIs have a threat model, whether it is complete, whether its threats are decided and whether it is current.",
    "areas": [("coverage", "Coverage"), ("quality", "Quality of the models"), ("treatment", "Treatment of threats"), ("currency", "Currency")],
    "refs": [{"label": "OWASP Threat Modeling Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html"},
             {"label": "OWASP ASVS", "url": "https://owasp.org/www-project-application-security-verification-standard/"}],
}
FW = FRAMEWORK["id"]
CHANGE_PAGE = {"kind": "page", "where": "/threat-models", "key": None, "value": None, "effect": "Create or update the threat model here."}
HIGH = ("Critical", "High")


def _c(id, area, title, status, **kw):
    kw.setdefault("refs", FRAMEWORK["refs"])
    return check(f"tm-{id}", FW, area, title, status, **kw)


def _share(ctx, share):
    if share >= ctx.thr.get("coverage_good", 0.9):
        return "pass", None
    if share >= ctx.thr.get("coverage_partial", 0.5):
        return "partial", share
    return "fail", None


def _unknown(id, area, title, why, rec, used, weight=3):
    return _c(id, area, title, "unknown", weight=weight, evidence=[why], recommendation=rec, change=CHANGE_PAGE, data_used=used,
              detail="Nothing recorded can answer this yet.")


def _norm(s):
    return (s or "").strip().lower()


def _load_models(ctx):
    def load():
        from remediation.controls import store as controls_store
        from remediation.threatmodel import store

        def controls_for(names):
            return [c for n in names for c in controls_store.for_asset(n, ctx.engine)]
        out = []
        for m in store.list_models(ctx.engine):
            rec = store.get(m["id"], ctx.engine)
            an = store.analyse(m["id"], findings=ctx.findings, engine=ctx.engine, controls_for=controls_for)
            last = max([rec["updated_at"]] + [r["updated_at"] for r in store.reviews(m["id"], ctx.engine).values()])
            out.append({"rec": rec, "an": an, "last": last})
        return out
    return ctx.get("tm-models", load)


def _names(entry):
    model = entry["an"]["model"]
    names = {_norm(entry["rec"]["name"])}
    pats = []
    for c in model["components"]:
        names |= {_norm(c.get("name")), _norm(c.get("id"))}
        pats += [_norm(p) for p in c.get("assets") or []]
    return names - {""}, pats


def _covers(entry, name):
    n = _norm(name)
    names, pats = _names(entry)
    return n in names or any(fnmatch.fnmatchcase(n, p) for p in pats)


def _apps(ctx):
    def load():
        from remediation.appsec import store
        return store.list_applications(ctx.engine)
    return ctx.get("tm-apps", load)


def _services(ctx):
    def load():
        from remediation.apisec import store
        return sorted({e["service"] for e in store.list_endpoints(ctx.engine)})
    return ctx.get("tm-services", load)


def _day(value):
    return datetime.date.fromisoformat(str(value)[:10]) if value else None


# ------------------------------------------------------------------------------------------------------------------------ coverage
def _coverage_apps(ctx, id, title, pick, label, weight):
    apps, models = _apps(ctx), _load_models(ctx)
    used = ["applications", "threat models"]
    chosen = [a for a in (apps or []) if pick(a)]
    if not chosen:
        return _unknown(id, "coverage", title, f"0 {label} recorded in the applications register",
                        f"Record applications with their exposure or criticality so {label} can be matched to models.", used, weight)
    have = [a for a in chosen if any(_covers(m, a["name"]) for m in models or [])]
    share = len(have) / len(chosen)
    status, score = _share(ctx, share)
    missing = [a["name"] for a in chosen if a not in have][:5]
    return _c(id, "coverage", title, status, score=score, weight=weight, data_used=used, change=CHANGE_PAGE,
              evidence=[f"{len(have)} of {len(chosen)} {label} have a threat model" + (f"; without one: {', '.join(missing)}" if missing else "")],
              detail="A system that has never been modelled has threats nobody has looked for.",
              recommendation="" if status == "pass" else f"Create a threat model for each of the {len(chosen) - len(have)} {label} without one.")


def _coverage_internet(ctx):
    return _coverage_apps(ctx, "cov-internet-facing", "Internet-facing applications have a threat model", lambda a: a.get("internet_facing") is True, "internet-facing applications", 5)


def _coverage_critical(ctx):
    return _coverage_apps(ctx, "cov-critical-apps", "Business-critical applications have a threat model",
                          lambda a: _norm(a.get("business_criticality")) in ("critical", "high"), "critical or high criticality applications", 4)


def _coverage_api(ctx):
    services, models = _services(ctx), _load_models(ctx)
    if not services:
        return _unknown("cov-api-services", "coverage", "API services have a threat model", "0 API services recorded in the API inventory",
                        "Import an OpenAPI specification or gateway logs on the API Security page.", ["API inventory", "threat models"], 3)
    have = [s for s in services if any(_covers(m, s) for m in models or [])]
    status, score = _share(ctx, len(have) / len(services))
    return _c("cov-api-services", "coverage", "API services have a threat model", status, score=score, weight=3, data_used=["API inventory", "threat models"], change=CHANGE_PAGE,
              evidence=[f"{len(have)} of {len(services)} API services have a threat model"], detail="APIs are the attack surface most often exposed.",
              recommendation="" if status == "pass" else "Model the API services that are not covered.")


# ------------------------------------------------------------------------------------------------------------------------ quality
def _quality_structure(ctx):
    models = _load_models(ctx)
    if not models:
        return _unknown("qual-zones-flows", "quality", "Models record trust zones and data flows", "0 threat models recorded", "Create a threat model.", ["threat models"], 4)
    good = [m for m in models if m["an"]["model"]["components"] and m["an"]["model"]["trust_zones"] and m["an"]["model"]["data_flows"]]
    status, score = _share(ctx, len(good) / len(models))
    thin = [m["rec"]["name"] for m in models if m not in good][:5]
    return _c("qual-zones-flows", "quality", "Models record trust zones and data flows", status, score=score, weight=4, data_used=["threat models"], change=CHANGE_PAGE,
              evidence=[f"{len(good)} of {len(models)} models have components, trust zones and data flows" + (f"; thin: {', '.join(thin)}" if thin else "")],
              detail="Threats arise where data crosses a trust boundary; a model with only components cannot show them.",
              recommendation="" if status == "pass" else "Add trust zones and data flows to the thin models.")


def _quality_assets(ctx):
    models = _load_models(ctx)
    comps = [c for m in models or [] for c in m["an"]["model"]["components"]]
    if not comps:
        return _unknown("qual-assets-linked", "quality", "Components are linked to real assets", "0 model components recorded", "Create a threat model.", ["threat models"], 3)
    linked = [c for c in comps if c.get("assets")]
    status, score = _share(ctx, len(linked) / len(comps))
    return _c("qual-assets-linked", "quality", "Components are linked to real assets", status, score=score, weight=3, data_used=["threat models"], change=CHANGE_PAGE,
              evidence=[f"{len(linked)} of {len(comps)} components name the assets they run on"],
              detail="Only linked components can be joined to live findings and recorded controls.",
              recommendation="" if status == "pass" else "Add asset names or patterns to the unlinked components.")


def _quality_controls(ctx):
    models = _load_models(ctx)
    threats = [t for m in models or [] for t in m["an"]["threats"]]
    if not threats:
        return _unknown("qual-controls-known", "quality", "Threats can be compared with recorded controls", "0 threats computed from the recorded models",
                        "Create a threat model with components and flows.", ["threat models", "controls inventory"], 2)
    known = [t for t in threats if t["controls_known"]]
    status, score = _share(ctx, len(known) / len(threats))
    return _c("qual-controls-known", "quality", "Threats can be compared with recorded controls", status, score=score, weight=2, data_used=["threat models", "controls inventory"],
              evidence=[f"{len(known)} of {len(threats)} threats have controls recorded for their assets"], detail="Without recorded controls residual risk equals inherent risk.",
              recommendation="" if status == "pass" else "Record the controls for the assets in the models.",
              change={"kind": "page", "where": "/controls", "key": None, "value": None, "effect": "Record verified controls."})


# ------------------------------------------------------------------------------------------------------------------------ treatment
def _threats(ctx):
    models = _load_models(ctx)
    return [(m, t) for m in models or [] for t in m["an"]["threats"]]


def _treat_rate(ctx):
    ts = _threats(ctx)
    if not ts:
        return _unknown("treat-decision-rate", "treatment", "Threats have been decided", "0 threats computed from the recorded models",
                        "Create a threat model with components and flows.", ["threat models"], 3)
    decided = [t for _, t in ts if t["review"]["status"] != "open"]
    status, score = _share(ctx, len(decided) / len(ts))
    return _c("treat-decision-rate", "treatment", "Threats have been decided", status, score=score, weight=3, data_used=["threat models"], change=CHANGE_PAGE,
              evidence=[f"{len(decided)} of {len(ts)} threats have a decision (accepted, mitigated or not applicable)"], detail="An undecided threat is a risk nobody has owned.",
              recommendation="" if status == "pass" else "Review the open threats, starting with the highest rated.")


def _treat_undecided_high(ctx):
    ts = _threats(ctx)
    if not ts:
        return _unknown("treat-undecided-high", "treatment", "No High or Critical threat is undecided", "0 threats computed from the recorded models",
                        "Create a threat model with components and flows.", ["threat models"], 4)
    bad = [(m, t) for m, t in ts if t["rating"] in HIGH and t["review"]["status"] == "open"]
    total = sum(1 for _, t in ts if t["rating"] in HIGH)
    ev = [f"{len(bad)} of {total} High or Critical threats are still undecided"] + [f"{m['rec']['name']}: {t['key']} ({t['rating']})" for m, t in bad[:3]]
    return _c("treat-undecided-high", "treatment", "No High or Critical threat is undecided", "fail" if bad else "pass", weight=4, data_used=["threat models"], change=CHANGE_PAGE,
              evidence=ev, detail="The threats that matter most should be the first to be decided.", recommendation="Decide each one: mitigate it, or accept it with a written reason." if bad else "")


def _treat_residual(ctx):
    ts = _threats(ctx)
    if not ts:
        return _unknown("treat-high-residual", "treatment", "High residual threats have a decision", "0 threats computed from the recorded models",
                        "Create a threat model with components and flows.", ["threat models", "controls inventory"], 4)
    bad = [(m, t) for m, t in ts if t["residual_rating"] in HIGH and t["review"]["status"] == "open"]
    total = sum(1 for _, t in ts if t["residual_rating"] in HIGH)
    ev = [f"{len(bad)} of {total} threats with High or Critical residual risk have no decision"] + [f"{m['rec']['name']}: {t['key']} residual {t['residual_score']}" for m, t in bad[:3]]
    return _c("treat-high-residual", "treatment", "High residual threats have a decision", "fail" if bad else "pass", weight=4, data_used=["threat models", "controls inventory"], change=CHANGE_PAGE,
              evidence=ev, detail="Residual risk is what remains after the recorded controls.", recommendation="Add the missing controls or record a decision." if bad else "")


def _treat_findings(ctx):
    ts = _threats(ctx)
    if not ts:
        return _unknown("treat-live-findings", "treatment", "No unmitigated threat is backed by live findings", "0 threats computed from the recorded models",
                        "Create a threat model with components and flows.", ["threat models", "findings"], 4)
    patterned = any(c.get("assets") for m in _load_models(ctx) for c in m["an"]["model"]["components"])
    if not ctx.findings or not patterned:
        return _unknown("treat-live-findings", "treatment", "No unmitigated threat is backed by live findings",
                        f"{len(ctx.findings)} findings loaded and {'some' if patterned else '0'} components linked to assets: threats cannot be joined to findings",
                        "Load findings and link model components to assets.", ["threat models", "findings"], 4)
    bad = [(m, t) for m, t in ts if t["findings_total"] and t["review"]["status"] not in ("mitigated", "not-applicable")]
    kev = sum(1 for _, t in bad if t["findings"] and any(f["kev"] for f in t["findings"]))
    nf = sum(t["findings_total"] for _, t in bad)
    ev = [f"{len(bad)} unmitigated threats are backed by {nf} open findings ({kev} known-exploited)"] + [f"{m['rec']['name']}: {t['key']} ({t['findings_total']} findings)" for m, t in bad[:3]]
    return _c("treat-live-findings", "treatment", "No unmitigated threat is backed by live findings", "fail" if bad else "pass", weight=4, data_used=["threat models", "findings"],
              change=CHANGE_PAGE, evidence=ev, detail="A finding that matches a threat shows the threat is not only theoretical.",
              recommendation="Fix the findings or record the threat as mitigated once they are closed." if bad else "")


# ------------------------------------------------------------------------------------------------------------------------ currency
def _cur_stale(ctx):
    models = _load_models(ctx)
    if not models:
        return _unknown("cur-reviewed", "currency", "Models have been reviewed recently", "0 threat models recorded", "Create a threat model.", ["threat models"], 3)
    days = ctx.thr.get("stale_days", 90)
    today = ctx.now.date()
    fresh = [m for m in models if (today - _day(m["last"])).days <= days]
    status, score = _share(ctx, len(fresh) / len(models))
    old = [m["rec"]["name"] for m in models if m not in fresh][:5]
    return _c("cur-reviewed", "currency", "Models have been reviewed recently", status, score=score, weight=3, data_used=["threat models"], change=CHANGE_PAGE,
              evidence=[f"{len(fresh)} of {len(models)} models changed or reviewed in the last {days} days" + (f"; stale: {', '.join(old)}" if old else "")],
              detail="Systems change; a model that does not is probably out of date.", recommendation="" if status == "pass" else "Review the stale models.")


def _cur_reassess(ctx):
    models = _load_models(ctx)
    patterned = any(c.get("assets") for m in models or [] for c in m["an"]["model"]["components"])
    if not models or not ctx.findings or not patterned:
        return _unknown("cur-reassessed-after-critical", "currency", "Models are re-assessed after a Critical finding appears",
                        f"{len(models or [])} models, {len(ctx.findings)} findings loaded: nothing to compare", "Load findings and link model components to assets.",
                        ["threat models", "findings"], 3)
    by_id = {f.get("id"): f for f in ctx.findings}
    affected, stale = [], []
    for m in models:
        seen = [_day(by_id[f["id"]].get("first_seen")) for t in m["an"]["threats"] for f in t["findings"]
                if f["id"] in by_id and str(f.get("severity")).lower() == "critical" and by_id[f["id"]].get("first_seen")]
        if not seen:
            continue
        affected.append(m)
        if max(seen) > _day(m["last"]):
            stale.append(m)
    if not affected:
        return _c("cur-reassessed-after-critical", "currency", "Models are re-assessed after a Critical finding appears", "pass", weight=3, data_used=["threat models", "findings"],
                  evidence=[f"0 of {len(models)} models are linked to a dated Critical finding"], change=CHANGE_PAGE)
    share = (len(affected) - len(stale)) / len(affected)
    status, score = _share(ctx, share)
    return _c("cur-reassessed-after-critical", "currency", "Models are re-assessed after a Critical finding appears", status, score=score, weight=3, data_used=["threat models", "findings"],
              change=CHANGE_PAGE, evidence=[f"{len(stale)} of {len(affected)} models linked to a Critical finding were not re-assessed after it first appeared"] + [m["rec"]["name"] for m in stale[:3]],
              detail="A new Critical finding on a modelled component can change its threats.", recommendation="" if status == "pass" else "Re-assess the listed models.")


def run(ctx):
    return [_coverage_internet(ctx), _coverage_critical(ctx), _coverage_api(ctx),
            _quality_structure(ctx), _quality_assets(ctx), _quality_controls(ctx),
            _treat_rate(ctx), _treat_undecided_high(ctx), _treat_residual(ctx), _treat_findings(ctx),
            _cur_stale(ctx), _cur_reassess(ctx)]
