"""Open source dependency risk: how exposed the estate is to vulnerable libraries, how many are being exploited, and how fast they are fixed.

Everything comes from what Quanta holds: dependency findings (scanner output, with KEV and EPSS added by enrichment), stored SBOMs and fix proposals. Quanta
ships no advisory database, so a library with no scanner finding is simply not in the data. End-of-life and abandoned components are not observable and
are reported `unknown`. With no dependency findings and no sign a dependency scan ever ran, every finding-based check is `unknown`, never a pass.
"""
import datetime

from remediation.appsec import graph as sbom_graph
from remediation.appsec import store as appsec_store
from remediation.devsecops import controls as dso
from remediation.gitops import proposals as gitops_proposals
from remediation.posture.model import check

FRAMEWORK = {
    "id": "open-source", "title": "Open source dependencies",
    "summary": "How exposed the estate is to vulnerable open source libraries, whether the ones being exploited are dealt with, and how well fixes are found and shipped.",
    "areas": [("exposure", "Exposure"), ("exploitation", "Exploitation"), ("remediation", "Remediation"), ("hygiene", "Inventory hygiene")],
    "refs": [],
}
FID = "open-source"
EPSS_HIGH = 0.5
SEV_ORDER = ("Critical", "High", "Medium", "Low")
DATA_FINDINGS = ["dependency findings (scan type sca)", "scan runs", "stored SBOMs"]


# ---------------------------------------------------------------- helpers
def _age_days(stamp, now):
    if not stamp:
        return None
    s = str(stamp)
    for fmt, n in (("%Y-%m-%dT%H:%M:%S", 19), ("%Y-%m-%d", 10)):
        try:
            return (now - datetime.datetime.strptime(s[:n], fmt).replace(tzinfo=datetime.timezone.utc)).total_seconds() / 86400.0
        except ValueError:
            continue
    return None


def _coverage(share, thr):
    if share >= thr["coverage_good"]:
        return "pass", None
    if share >= thr["coverage_partial"]:
        return "partial", share
    return "fail", None


def _norm(name):
    return (name or "").strip().lower()


def _unknown(cid, area, title, why, rec, data_used, weight=3, change=None):
    if not any(ch.isdigit() for ch in why):
        why += " Usable records found: 0."
    return check(cid, FID, area, title, "unknown", weight=weight, evidence=[why], recommendation=rec, change=change, data_used=data_used)


def _built(cid, area, title, share, thr, evidence, rec, change, data_used, weight=3, detail=""):
    status, score = _coverage(share, thr)
    return check(cid, FID, area, title, status, score=score, weight=weight, evidence=evidence, detail=detail, recommendation=rec if status != "pass" else "",
                 change=change if status != "pass" else None, data_used=data_used)


def _simple(cid, area, title, status, evidence, rec, change, data_used, weight, score=None, detail=""):
    keep = status != "pass"
    return check(cid, FID, area, title, status, score=score, weight=weight, evidence=evidence, detail=detail, recommendation=rec if keep else "", change=change if keep else None, data_used=data_used)


APPS_PAGE = {"kind": "page", "where": "/applications", "key": "Applications & SBOM", "value": "open the application", "effect": "Shows the findings ranked, with the one upgrade that closes the most."}
QUEUE_PAGE = {"kind": "page", "where": "/queue", "key": "Remediation Queue", "value": "filter to dependency findings", "effect": "Lists the open dependency findings by priority."}
FIX_PAGE = {"kind": "page", "where": "/fix-prs", "key": "Fix Pull Requests", "value": "propose and open the upgrade", "effect": "Turns an upgrade into a reviewable pull request with the evidence in it."}


# ---------------------------------------------------------------- data
def _dep(ctx):
    return [f for f in ctx.findings if f.get("status") not in ("resolved", "closed") and ((f.get("dependency") or {}).get("package") or f.get("scan_type") == "sca")]


def _evidence_of_scanning(ctx):
    """True when a dependency scan or an SBOM is recorded, so zero findings means 'looked and found none'. None when that could not be read."""
    runs = ctx.get("os.runs", lambda: dso.scan_runs(ctx.engine))
    sb = ctx.get("os.sbom_summaries", lambda: appsec_store.sbom_summaries(ctx.engine))
    if runs is None or sb is None:
        return None
    return any(r["scan_type"] == "sca" for r in runs) or bool(sb)


def _apps_of(findings):
    out = {}
    for f in findings:
        out.setdefault(_norm((f.get("asset") or {}).get("name")), []).append(f)
    out.pop("", None)
    return out


def _graphs(ctx):
    """{app key: (structure, {finding id: component ref}, [unmatched ids])} for applications with both dependency findings and a stored SBOM."""
    def load():
        out = {}
        by_app = _apps_of([f for f in _dep(ctx) if (f.get("dependency") or {}).get("package")])
        for key, fs in by_app.items():
            sb = appsec_store.get_sbom(key, ctx.engine)
            if not sb:
                continue
            st = sbom_graph.structure(sb["graph"])
            hits, unmatched = sbom_graph.match_findings(st, fs)
            out[key] = (st, {fid: ref for ref, ids in hits.items() for fid in ids}, unmatched)
        return out
    return ctx.get("os.graphs", load)


def _packages(ctx):
    """{(package, ecosystem): {"apps": set, "findings": [..], "direct": True/False/None}}."""
    graphs = _graphs(ctx) or {}
    pk = {}
    for f in _dep(ctx):
        dep = f.get("dependency") or {}
        if not dep.get("package"):
            continue
        key = (_norm(dep["package"]), _norm(dep.get("ecosystem")))
        entry = pk.setdefault(key, {"name": dep["package"], "apps": set(), "findings": [], "flags": []})
        app = _norm((f.get("asset") or {}).get("name"))
        entry["apps"].add(app)
        entry["findings"].append(f)
        direct = None
        g = graphs.get(app)
        if g and f["id"] in g[1]:
            direct = sbom_graph.is_direct(g[0], g[1][f["id"]])
        if direct is None:
            direct = dep.get("direct") if isinstance(dep.get("direct"), bool) else None
        entry["flags"].append(direct)
    for e in pk.values():
        e["direct"] = True if any(x is True for x in e["flags"]) else (False if e["flags"] and all(x is False for x in e["flags"]) else None)
    return pk


def _gate_unknown(ctx, cid, area, title, rec, weight, change=None):
    """Returns a check when finding-based checks cannot be answered, else None."""
    seen = _evidence_of_scanning(ctx)
    if seen is None:
        return _unknown(cid, area, title, "Scan runs or SBOMs could not be read.", rec, DATA_FINDINGS, weight, change)
    if not _dep(ctx) and not seen:
        return _unknown(cid, area, title, "No dependency finding, dependency scan or SBOM is recorded (0 findings), so nothing is known about the libraries in use.", rec, DATA_FINDINGS, weight, change)
    return None


# ---------------------------------------------------------------- exposure
def _severity(ctx):
    cid, area, title = "os-exp-severity", "exposure", "No Critical or High vulnerable dependencies are open"
    rec = "Upgrade the vulnerable libraries, Critical first. The Applications page groups findings into the one upgrade that closes each package."
    early = _gate_unknown(ctx, cid, area, title, rec, 5, APPS_PAGE)
    if early:
        return early
    dep = _dep(ctx)
    n = {s: sum(1 for f in dep if f.get("severity") == s) for s in SEV_ORDER}
    evidence = [f"{len(dep)} open dependency findings: {n['Critical']} Critical, {n['High']} High, {n['Medium']} Medium, {n['Low']} Low"]
    if n["Critical"]:
        return _simple(cid, area, title, "fail", evidence, rec, APPS_PAGE, DATA_FINDINGS, 5)
    if n["High"]:
        return _simple(cid, area, title, "partial", evidence, rec, APPS_PAGE, DATA_FINDINGS, 5, score=0.5)
    return _simple(cid, area, title, "pass", evidence, rec, APPS_PAGE, DATA_FINDINGS, 5)


def _direct_transitive(ctx):
    cid, area, title = "os-exp-direct-transitive", "exposure", "Vulnerable packages can be fixed directly"
    rec = "For a transitive package, upgrade the direct dependency that pulls it in, or override the transitive version. The application's graph names the parent."
    early = _gate_unknown(ctx, cid, area, title, rec, 1, APPS_PAGE)
    if early:
        return early
    pk = _packages(ctx)
    known = [e for e in pk.values() if e["direct"] is not None]
    if not known:
        return _unknown(cid, area, title, f"{len(pk)} vulnerable packages are recorded but none can be classed direct or transitive (no SBOM graph, no dependency.direct).", rec, DATA_FINDINGS, 1, APPS_PAGE)
    direct = [e for e in known if e["direct"]]
    evidence = [f"{len(direct)} of {len(known)} vulnerable packages are direct dependencies, {len(known) - len(direct)} are transitive", f"{len(pk) - len(known)} could not be classed"]
    if len(direct) == len(known):
        return _simple(cid, area, title, "pass", evidence, rec, APPS_PAGE, DATA_FINDINGS, 1)
    return _simple(cid, area, title, "partial", evidence, rec, APPS_PAGE, DATA_FINDINGS, 1, score=len(direct) / len(known),
                   detail="A transitive package cannot be upgraded by editing your own manifest alone.")


def _concentration(ctx):
    cid, area, title = "os-exp-concentration", "exposure", "Vulnerable packages are not shared across applications"
    rec = "Fix a shared vulnerable package once, in a shared base or library, then roll the upgrade out to each application that uses it."
    early = _gate_unknown(ctx, cid, area, title, rec, 2, FIX_PAGE)
    if early:
        return early
    pk = _packages(ctx)
    if not pk:
        return _unknown(cid, area, title, "No finding names a package (0 packages), so sharing cannot be measured.", rec, DATA_FINDINGS, 2, FIX_PAGE)
    shared = sorted(e["name"] for e in pk.values() if len(e["apps"]) >= 2)
    evidence = [f"{len(shared)} of {len(pk)} vulnerable packages are used by two or more applications"]
    if shared:
        evidence.append("Shared: " + ", ".join(shared[:5]))
        return _simple(cid, area, title, "partial", evidence, rec, FIX_PAGE, DATA_FINDINGS, 2, score=1 - len(shared) / len(pk),
                       detail="One vulnerable package in several applications multiplies the exposure, and one upgrade fixes it everywhere.")
    return _simple(cid, area, title, "pass", evidence, rec, FIX_PAGE, DATA_FINDINGS, 2)


# ---------------------------------------------------------------- exploitation
def _kev(ctx):
    limit = ctx.thr["kev_open_days"]
    cid, area, title = "os-expl-kev", "exploitation", f"No known-exploited dependency stays open beyond {limit} days"
    rec = "Treat a vulnerable library on the CISA KEV list as an incident: upgrade it or put a compensating control in place within days, not weeks."
    early = _gate_unknown(ctx, cid, area, title, rec, 5, QUEUE_PAGE)
    if early:
        return early
    dep = _dep(ctx)
    kev = [f for f in dep if (f.get("kev") or {}).get("listed")]
    over, unaged = [], []
    for f in kev:
        a = _age_days(f.get("first_seen"), ctx.now)
        if a is None:
            unaged.append(f)
        elif a > limit:
            over.append(f)
    evidence = [f"{len(kev)} of {len(dep)} open dependency findings are on the CISA KEV list", f"{len(over)} older than {limit} days"]
    if unaged:
        evidence.append(f"{len(unaged)} have no first-seen date, so their age cannot be shown")
    if over:
        evidence.append("Overdue: " + ", ".join(sorted(f["id"] for f in over)[:6]))
        return _simple(cid, area, title, "fail", evidence, rec, QUEUE_PAGE, DATA_FINDINGS, 5)
    if kev:
        return _simple(cid, area, title, "partial", evidence, rec, QUEUE_PAGE, DATA_FINDINGS, 5, score=0.5)
    return _simple(cid, area, title, "pass", evidence, rec, QUEUE_PAGE, DATA_FINDINGS, 5)


def _epss(ctx):
    cid, area, title = "os-expl-epss", "exploitation", f"Few open dependency findings are likely to be exploited (EPSS {EPSS_HIGH} or more)"
    rec = "Fix the findings with a high chance of exploitation first; EPSS orders them better than severity alone."
    early = _gate_unknown(ctx, cid, area, title, rec, 3, QUEUE_PAGE)
    if early:
        return early
    scored = [f for f in _dep(ctx) if isinstance(f.get("epss"), dict) and f["epss"].get("score") is not None]
    if not scored:
        return _unknown(cid, area, title, f"{len(_dep(ctx))} open dependency findings but none carries an EPSS score (enrichment has not run or had no network).", rec, DATA_FINDINGS, 3, QUEUE_PAGE)
    high = [f for f in scored if f["epss"]["score"] >= EPSS_HIGH]
    evidence = [f"{len(high)} of {len(scored)} findings with an EPSS score are at {EPSS_HIGH} or above"]
    if high:
        evidence.append("Highest: " + ", ".join(sorted(f["id"] for f in high)[:6]))
    return _built(cid, area, title, 1 - len(high) / len(scored), ctx.thr, evidence, rec, QUEUE_PAGE, DATA_FINDINGS, 3)


def _disclosure_feed(ctx):
    return _unknown("os-disclosure-feed", "exploitation", "A coordinated vulnerability disclosure feed is connected",
                    "No disclosure feed is connected (0 feeds), so Quanta learns of a vulnerability only from your scanners and CISA KEV.",
                    "Connect the Anthropic coordinated disclosure feed once it is available. Until then, rely on your scanners and the CISA KEV list.", ["connected disclosure feeds"], 1)


# ---------------------------------------------------------------- remediation
def _fix_available(ctx):
    cid, area, title = "os-rem-fix-available", "remediation", "Open dependency findings have a fixed version"
    rec = "Where no fixed version exists, watch the advisory, replace the package, or record an exception with a compensating control."
    early = _gate_unknown(ctx, cid, area, title, rec, 3, QUEUE_PAGE)
    if early:
        return early
    dep = _dep(ctx)
    if not dep:
        return _simple(cid, area, title, "pass", ["0 open dependency findings"], rec, QUEUE_PAGE, DATA_FINDINGS, 3)
    fixed = [f for f in dep if (f.get("dependency") or {}).get("fixed_version")]
    evidence = [f"{len(fixed)} of {len(dep)} open dependency findings name a fixed version"]
    return _built(cid, area, title, len(fixed) / len(dep), ctx.thr, evidence, rec, QUEUE_PAGE, DATA_FINDINGS, 3)


def _overdue(ctx):
    limit = ctx.thr["critical_open_days"]
    cid, area, title = "os-rem-overdue", "remediation", f"Critical and High findings with a fix are not open beyond {limit} days"
    rec = "Upgrade the packages that already have a fix. These are the cheapest risk reduction available."
    early = _gate_unknown(ctx, cid, area, title, rec, 4, FIX_PAGE)
    if early:
        return early
    fixable = [f for f in _dep(ctx) if f.get("severity") in ("Critical", "High") and (f.get("dependency") or {}).get("fixed_version")]
    if not fixable:
        return _simple(cid, area, title, "pass", ["0 open Critical or High dependency findings have a fixed version waiting"], rec, FIX_PAGE, DATA_FINDINGS, 4)
    late = [f for f in fixable if (_age_days(f.get("first_seen"), ctx.now) is None) or _age_days(f.get("first_seen"), ctx.now) > limit]
    evidence = [f"{len(late)} of {len(fixable)} fixable Critical or High findings are older than {limit} days (a missing first-seen date counts as overdue)"]
    if late:
        evidence.append("Overdue: " + ", ".join(sorted(f["id"] for f in late)[:6]))
    return _built(cid, area, title, 1 - len(late) / len(fixable), ctx.thr, evidence, rec, FIX_PAGE, DATA_FINDINGS, 4)


def _multi_upgrade(ctx):
    cid, area, title = "os-rem-multi-upgrade", "remediation", "Upgrades that close several findings are proposed"
    rec = "Propose these first: one upgrade closes every finding in the package, so each proposal removes the most findings."
    early = _gate_unknown(ctx, cid, area, title, rec, 2, FIX_PAGE)
    if early:
        return early
    props = ctx.get("os.proposals", lambda: gitops_proposals.list_proposals(engine=ctx.engine))
    if props is None:
        return _unknown(cid, area, title, "Fix proposals could not be read.", rec, DATA_FINDINGS, 2, FIX_PAGE)
    groups = {}
    for f in _dep(ctx):
        dep = f.get("dependency") or {}
        if dep.get("package") and dep.get("fixed_version"):
            groups.setdefault((_norm((f.get("asset") or {}).get("name")), _norm(dep["package"]), _norm(dep.get("ecosystem"))), []).append(f)
    multi = {k: fs for k, fs in groups.items() if len(fs) >= 2}
    if not multi:
        return check(cid, FID, area, title, "na", weight=2, evidence=[f"0 of {len(groups)} fixable packages have more than one open finding"], data_used=DATA_FINDINGS)
    covered_ids = {fid for p in props if p["status"] not in ("discarded", "closed") for fid in p["finding_ids"]}
    done = [k for k, fs in multi.items() if all(f["id"] in covered_ids for f in fs)]
    top = sorted(multi.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:3]
    evidence = [f"{len(done)} of {len(multi)} multi-finding upgrades are in a fix proposal", "Biggest: " + ", ".join(f"{fs[0]['dependency']['package']} closes {len(fs)} findings" for _k, fs in top)]
    return _built(cid, area, title, len(done) / len(multi), ctx.thr, evidence, rec, FIX_PAGE, DATA_FINDINGS, 2)


# ---------------------------------------------------------------- hygiene
def _sbom_present(ctx):
    cid, area, title = "os-hyg-sbom-present", "hygiene", "Applications with dependency findings have a stored SBOM"
    rec = "Upload or generate an SBOM for each application so its findings are matched to components and the dependency path is known."
    early = _gate_unknown(ctx, cid, area, title, rec, 3, APPS_PAGE)
    if early:
        return early
    by_app = _apps_of([f for f in _dep(ctx) if (f.get("dependency") or {}).get("package")])
    if not by_app:
        return _unknown(cid, area, title, "No finding names a package or an application (0 applications).", rec, DATA_FINDINGS, 3, APPS_PAGE)
    sb = {_norm(k) for k in (ctx.get("os.sbom_summaries", lambda: appsec_store.sbom_summaries(ctx.engine)) or {})}
    have = [a for a in by_app if a in sb]
    evidence = [f"{len(have)} of {len(by_app)} applications with dependency findings have a stored SBOM"]
    if len(have) < len(by_app):
        evidence.append("No SBOM: " + ", ".join(sorted(a for a in by_app if a not in sb)[:5]))
    return _built(cid, area, title, len(have) / len(by_app), ctx.thr, evidence, rec, APPS_PAGE, DATA_FINDINGS, 3)


def _sbom_match(ctx):
    cid, area, title = "os-hyg-sbom-match", "hygiene", "Scanner findings match components in the SBOM"
    rec = "Regenerate the SBOM from the same build the scanner looked at; a finding that matches no component means the two disagree about what is installed."
    early = _gate_unknown(ctx, cid, area, title, rec, 2, APPS_PAGE)
    if early:
        return early
    graphs = _graphs(ctx)
    if not graphs:
        return _unknown(cid, area, title, "No application has both dependency findings and a stored SBOM (0 applications), so matches cannot be checked.", rec, DATA_FINDINGS, 2, APPS_PAGE)
    total = sum(len(g[1]) + len(g[2]) for g in graphs.values())
    unmatched = sum(len(g[2]) for g in graphs.values())
    if not total:
        return _unknown(cid, area, title, "0 findings name a package in an application that has an SBOM.", rec, DATA_FINDINGS, 2, APPS_PAGE)
    evidence = [f"{total - unmatched} of {total} dependency findings match a component in their application's SBOM", f"{len(graphs)} applications compared"]
    return _built(cid, area, title, (total - unmatched) / total, ctx.thr, evidence, rec, APPS_PAGE, DATA_FINDINGS, 2)


def _eol(ctx):
    return _unknown("os-hyg-eol", "hygiene", "No dependency is end-of-life or abandoned",
                    "Quanta ships no lifecycle or maintenance data, so end-of-life and abandoned packages are not observable (0 components assessed).",
                    "Check your components against the project's own release status, endoflife.date and the OpenSSF Scorecard, and record what you find as a finding or an exception.",
                    ["stored SBOMs"], 2)


def run(ctx):
    return [
        _severity(ctx), _direct_transitive(ctx), _concentration(ctx),
        _kev(ctx), _epss(ctx), _disclosure_feed(ctx),
        _fix_available(ctx), _overdue(ctx), _multi_upgrade(ctx),
        _sbom_match(ctx), _eol(ctx), _sbom_present(ctx),
    ]
