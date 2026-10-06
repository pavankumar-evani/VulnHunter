"""Software supply chain, read against SLSA and the OpenSSF Scorecard's themes.

Quanta can see what it was given: the applications and SBOMs it stores, the pipeline checks it ran over CI files, the release gate's decisions and the
fix pull requests it proposed. It cannot see inside a build, a signature or a provenance statement, so those checks are `unknown` with the next step,
never a pass. Nothing is a pass when nothing is recorded.
"""
import datetime
import json

from sqlalchemy import select

from remediation.appsec import store as appsec_store
from remediation.devsecops import controls as dso
from remediation.devsecops import gates
from remediation.gitops import policy as gitops_policy
from remediation.gitops import proposals as gitops_proposals
from remediation.posture.model import check
from remediation.utils import db as db_module

FRAMEWORK = {
    "id": "supply-chain", "title": "Software supply chain (SLSA)",
    "summary": "Do you know what your applications are made of, are the pipelines that build them hardened, and do fixes for vulnerable components actually ship and hold?",
    "areas": [("inventory", "Inventory (SBOMs)"), ("integrity", "Build and pipeline integrity"), ("provenance", "Provenance and signing"), ("delivery", "Fix delivery")],
    "refs": [{"label": "SLSA v1.1 build levels", "url": "https://slsa.dev/spec/v1.1/levels"}, {"label": "OpenSSF Scorecard", "url": "https://scorecard.dev/"}],
}
REFS = FRAMEWORK["refs"]
FID = "supply-chain"
OPEN_PR = ("pr-opened", "in-review")
DANGEROUS = ("GHA002", "GHA003", "GHA009", "JK001")


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


def _is_open(f):
    return f.get("status") not in ("resolved", "closed")


def _norm(name):
    return (name or "").strip().lower()


def _unknown(cid, area, title, why, rec, data_used, weight=3, change=None, refs=REFS):
    if not any(ch.isdigit() for ch in why):
        why += " Usable records found: 0."
    return check(cid, FID, area, title, "unknown", weight=weight, evidence=[why], recommendation=rec, change=change, refs=refs, data_used=data_used)


def _built(cid, area, title, share, thr, evidence, rec, change, data_used, weight=3, detail=""):
    status, score = _coverage(share, thr)
    return check(cid, FID, area, title, status, score=score, weight=weight, evidence=evidence, detail=detail, recommendation=rec if status != "pass" else "",
                 change=change if status != "pass" else None, refs=REFS, data_used=data_used)


# ---------------------------------------------------------------- loaders
def _apps(ctx):
    return ctx.get("sc.apps", lambda: appsec_store.list_applications(ctx.engine))


def _sboms(ctx):
    """{normalised application name: {format, components, uploaded_at, kind}} where kind is full, declared-only or flat."""
    def load():
        engine = ctx.engine or db_module.get_engine()
        db_module.ensure_schema(engine)
        t = db_module.app_sboms
        with engine.connect() as conn:
            rows = conn.execute(select(t.c.application, t.c.format, t.c.component_count, t.c.uploaded_at, t.c.notes_json, t.c.graph_json)).mappings().all()
        out = {}
        for r in rows:
            graph = json.loads(r["graph_json"] or "{}")
            notes = json.loads(r["notes_json"] or "[]")
            edges = graph.get("edges") or []
            children = {b for _a, b in edges}
            deep = any(a in children for a, _b in edges)
            declared_only = any("Only declared dependencies" in str(n) for n in notes)
            kind = "full" if deep and not declared_only else ("declared-only" if edges or declared_only else "flat")
            out[_norm(r["application"])] = {"name": r["application"], "format": r["format"], "components": r["component_count"], "uploaded_at": r["uploaded_at"], "kind": kind}
        return out
    return ctx.get("sc.sboms", load)


def _runs(ctx):
    return ctx.get("sc.runs", lambda: dso.scan_runs(ctx.engine))


def _states(ctx):
    return ctx.get("sc.states", lambda: dso.states(ctx.engine))


def _proposals(ctx):
    return ctx.get("sc.proposals", lambda: gitops_proposals.list_proposals(engine=ctx.engine))


def _dep_findings(ctx):
    return [f for f in ctx.findings if _is_open(f) and ((f.get("dependency") or {}).get("package") or f.get("scan_type") == "sca")]


# ---------------------------------------------------------------- inventory
def _sbom_coverage(ctx):
    cid, area, title = "sc-inv-sbom-coverage", "inventory", "Applications have a stored SBOM"
    data = ["applications", "stored SBOMs"]
    rec = "Upload an SBOM for each application from CI (POST /api/ingest/sbom) or generate one from its lock file on the Applications page."
    change = {"kind": "page", "where": "/applications", "key": "Applications & SBOM", "value": "generate or upload the SBOM", "effect": "Stores the SBOM so findings can be matched to components and the dependency graph drawn."}
    apps, sb = _apps(ctx), _sboms(ctx)
    if apps is None or sb is None:
        return _unknown(cid, area, title, "Applications or SBOMs could not be read.", rec, data, 4)
    if not apps:
        return _unknown(cid, area, title, "No application is registered (0 applications), so SBOM coverage cannot be measured.", rec, data, 4, change)
    have = [a for a in apps if _norm(a["name"]) in sb]
    missing = [a["name"] for a in apps if _norm(a["name"]) not in sb]
    evidence = [f"{len(have)} of {len(apps)} applications have a stored SBOM"]
    if missing:
        evidence.append("No SBOM: " + ", ".join(missing[:5]) + (f" and {len(missing) - 5} more" if len(missing) > 5 else ""))
    return _built(cid, area, title, len(have) / len(apps), ctx.thr, evidence, rec, change, data, 4, detail="Without an SBOM, a vulnerable library cannot be traced to the applications that ship it.")


def _sbom_fresh(ctx):
    limit = ctx.thr["min_sbom_age_days"]
    cid, area, title = "sc-inv-sbom-fresh", "inventory", f"SBOMs are no older than {limit} days"
    data = ["applications", "stored SBOMs"]
    rec = "Regenerate the SBOM on every build or release so it describes what is deployed now."
    change = {"kind": "process", "where": "CI pipeline", "key": "POST /api/ingest/sbom", "value": "on every release", "effect": "Replaces the stored SBOM with the current one."}
    apps, sb = _apps(ctx), _sboms(ctx)
    if apps is None or sb is None:
        return _unknown(cid, area, title, "Applications or SBOMs could not be read.", rec, data, 3)
    if not apps:
        return _unknown(cid, area, title, "No application is registered (0 applications).", rec, data, 3, change)
    fresh, stale = 0, []
    for a in apps:
        s = sb.get(_norm(a["name"]))
        age = _age_days(s["uploaded_at"], ctx.now) if s else None
        if age is not None and age <= limit:
            fresh += 1
        elif s:
            stale.append(f"{a['name']} ({int(age) if age is not None else '?'} days)")
    evidence = [f"{fresh} of {len(apps)} applications have an SBOM stored in the last {limit} days"]
    if stale:
        evidence.append("Stale: " + ", ".join(stale[:5]))
    return _built(cid, area, title, fresh / len(apps), ctx.thr, evidence, rec, change, data, 3)


def _unregistered(ctx):
    cid, area, title = "sc-inv-registered", "inventory", "Applications with dependency findings are registered"
    data = ["findings with a dependency", "applications"]
    rec = "Register each application that has dependency findings so it can carry an owner, a repository and an SBOM."
    change = {"kind": "page", "where": "/applications", "key": "Applications & SBOM", "value": "register the application", "effect": "Gives the application an owner and lets Quanta attach an SBOM."}
    apps = _apps(ctx)
    dep = _dep_findings(ctx)
    if apps is None:
        return _unknown(cid, area, title, "Applications could not be read.", rec, data, 2)
    if not dep:
        return _unknown(cid, area, title, "No open dependency finding is recorded (0 findings).", rec, data, 2, change)
    names = {_norm((f.get("asset") or {}).get("name")) for f in dep} - {""}
    known = {_norm(a["name"]) for a in apps}
    loose = sorted(n for n in names if n not in known)
    evidence = [f"{len(names) - len(loose)} of {len(names)} applications with dependency findings are registered"]
    if loose:
        evidence.append("Not registered: " + ", ".join(loose[:5]))
    return _built(cid, area, title, (len(names) - len(loose)) / len(names), ctx.thr, evidence, rec, change, data, 2)


# ---------------------------------------------------------------- integrity
def _transitive(ctx):
    cid, area, title = "sc-int-transitive", "integrity", "SBOMs include transitive dependencies"
    data = ["stored SBOMs (graph and generation notes)"]
    rec = "Generate the SBOM from a lock file or your SCA tool's export. A manifest-only SBOM lists declared dependencies and misses what they pull in."
    change = {"kind": "page", "where": "/applications", "key": "Applications & SBOM", "value": "upload a lock file", "effect": "A lock file gives the full tree, so findings in transitive packages are found and traced."}
    sb = _sboms(ctx)
    if sb is None:
        return _unknown(cid, area, title, "SBOMs could not be read.", rec, data, 3)
    if not sb:
        return _unknown(cid, area, title, "No SBOM is stored (0 SBOMs).", rec, data, 3, change)
    full = [s for s in sb.values() if s["kind"] == "full"]
    decl = [s for s in sb.values() if s["kind"] == "declared-only"]
    flat = [s for s in sb.values() if s["kind"] == "flat"]
    evidence = [f"{len(full)} of {len(sb)} SBOMs include transitive dependencies", f"{len(decl)} list declared dependencies only, {len(flat)} are flat component lists"]
    if full:
        return _built(cid, area, title, len(full) / len(sb), ctx.thr, evidence, rec, change, data, 3)
    return check(cid, FID, area, title, "partial" if decl else "fail", score=0.5 if decl else None, weight=3, evidence=evidence, recommendation=rec, change=change, refs=REFS, data_used=data,
                 detail="A manifest-only SBOM is partial: it shows the direct choices, not the packages those pull in.")


def _ci_check(ctx, cid, title, rules, weight, rec, change, any_is_fail=False, detail=""):
    area, data = "integrity", ["pipeline-check findings (scan type cicd)", "scan runs"]
    runs = _runs(ctx)
    if runs is None:
        return _unknown(cid, area, title, "Scan runs could not be read.", rec, data, weight)
    findings = [f for f in ctx.findings if _is_open(f) and f.get("rule_id") in rules]
    scanned = {_norm(r["asset"]) for r in runs if r["scan_type"] == "cicd"} | {_norm((f.get("asset") or {}).get("name")) for f in ctx.findings if f.get("scan_type") == "cicd"}
    scanned.discard("")
    if not scanned:
        return _unknown(cid, area, title, "No pipeline has been checked (0 repositories), so CI files are not observed.", rec, data, weight, change)
    bad = {_norm((f.get("asset") or {}).get("name")) for f in findings}
    evidence = [f"{len(bad)} of {len(scanned)} checked repositories have an open {'/'.join(sorted(rules))} finding" if findings else f"0 of {len(scanned)} checked repositories have an open {'/'.join(sorted(rules))} finding"]
    if findings:
        evidence.append("Findings: " + ", ".join(sorted(f["id"] for f in findings)[:6]))
    if any_is_fail and findings:
        return check(cid, FID, area, title, "fail", weight=weight, evidence=evidence, detail=detail, recommendation=rec, change=change, refs=REFS, data_used=data)
    return _built(cid, area, title, 1 - len(bad) / len(scanned), ctx.thr, evidence, rec, change, data, weight, detail=detail)


# ---------------------------------------------------------------- provenance
def _stated(ctx, control_ids):
    st = _states(ctx) or []
    return len({_norm(s["asset"]) for s in st if s["control_id"] in control_ids and s["state"] == "implemented"})


def _slsa_unknown(ctx, cid, title, what):
    stated = _stated(ctx, ("artifact-provenance", "signed-commits"))
    why = f"Quanta cannot see {what}. " + (f"{stated} repositories are recorded as implementing it (stated by a person, not observed)." if stated else "No one has recorded a state for it (0 repositories).")
    return _unknown(cid, "provenance", title, why,
                    f"Check {what} with your build system, and adopt SLSA: build on a hosted, isolated service, generate provenance and verify it before deploy. Record the state on the Control Library page.",
                    ["Control Library recorded states"], 3, {"kind": "page", "where": "/devsecops", "key": "Control Library", "value": "record the state", "effect": "Shows the stated state beside what Quanta can observe, never as evidence."})


def _gate_sbom(ctx):
    cid, area, title = "sc-prov-gate-sbom", "provenance", "The production release gate requires a current SBOM"
    data = ["pipeline_gates.yaml", "applications"]
    rec = "Set the SBOM rule to block in production so an application without a current SBOM cannot be released."
    apps = _apps(ctx)
    if not apps and not _proposals(ctx):
        return _unknown(cid, area, title, "No application is registered (0 applications), so the gate's setting is not assessed.", rec, data, 3)
    pol = ctx.get("sc.gate_policy", lambda: gates.load())
    if pol is None:
        return _unknown(cid, area, title, "The release gate policy could not be read.", rec, data, 3)
    mode = ((pol.get("environments") or {}).get("production") or {}).get("sbom")
    if mode is None:
        return _unknown(cid, area, title, "The gate policy has no production setting for the SBOM rule (0 settings).", rec, data, 3)
    change = {"kind": "yaml", "where": "remediation/config/pipeline_gates.yaml (environments: production)", "key": "sbom", "value": "block", "effect": "A missing or stale SBOM makes the production gate decision fail."}
    evidence = [f"In production the SBOM rule is '{mode}' (1 of 3 modes: block, warn, off)"]
    if mode == "block":
        return check(cid, FID, area, title, "pass", weight=3, evidence=evidence, refs=REFS, data_used=data)
    if mode == "warn":
        return check(cid, FID, area, title, "partial", score=0.5, weight=3, evidence=evidence, recommendation=rec, change=change, refs=REFS, data_used=data)
    return check(cid, FID, area, title, "fail", weight=3, evidence=evidence, recommendation=rec, change=change, refs=REFS, data_used=data)


# ---------------------------------------------------------------- delivery
def _live_proposals(ctx):
    props = _proposals(ctx)
    return None if props is None else [p for p in props if p["status"] != "discarded"]


def _throughput(ctx):
    cid, area, title = "sc-del-fix-throughput", "delivery", "Opened fix pull requests get merged"
    data = ["fix pull requests"]
    rec = "Review and merge the open fix pull requests, or close the ones that will not be taken so the backlog is honest."
    change = {"kind": "page", "where": "/fix-prs", "key": "Fix Pull Requests", "value": "work the open proposals", "effect": "Shows where each pull request is waiting."}
    props = _live_proposals(ctx)
    if props is None:
        return _unknown(cid, area, title, "Fix proposals could not be read.", rec, data, 3)
    opened = [p for p in props if p["opened_at"] or p["status"] == "merged"]
    if not opened:
        return _unknown(cid, area, title, "No fix pull request has been opened (0 pull requests).", rec, data, 3, change)
    merged = [p for p in opened if p["status"] == "merged"]
    closed = [p for p in opened if p["status"] in ("closed", "failed")]
    evidence = [f"{len(merged)} of {len(opened)} opened pull requests are merged", f"{len(closed)} closed or failed, {len(opened) - len(merged) - len(closed)} still open"]
    return _built(cid, area, title, len(merged) / len(opened), ctx.thr, evidence, rec, change, data, 3)


def _verified(ctx):
    cid, area, title = "sc-del-verified", "delivery", "Merged fixes are confirmed gone by a later scan"
    data = ["fix pull requests (verification state)", "findings"]
    rec = "For a merged fix that is still reported, check the merged change and the scanner's view of the version in use, then rescan."
    change = {"kind": "page", "where": "/fix-prs", "key": "Fix Pull Requests", "value": "check still-present fixes", "effect": "Lists merged proposals whose findings a later scan still reports."}
    props = _live_proposals(ctx)
    if props is None:
        return _unknown(cid, area, title, "Fix proposals could not be read.", rec, data, 3)
    merged = [p for p in props if p["status"] == "merged"]
    if not merged:
        return _unknown(cid, area, title, "No fix pull request has been merged (0 merged).", rec, data, 3, change)
    by_id = {f["id"]: f for f in ctx.findings}
    ver = still = wait = 0
    for p in merged:
        state = gitops_proposals.verify_one(p, by_id)["state"]
        ver += state == "verified"
        still += state == "still-present"
        wait += state == "awaiting-rescan"
    evidence = [f"{ver} verified, {still} still reported, {wait} awaiting a rescan of {len(merged)} merged"]
    if ver + still == 0:
        return _unknown(cid, area, title, f"{wait} merged fixes are awaiting a rescan, so none can be confirmed or refuted yet.", rec, data, 3, change)
    return _built(cid, area, title, ver / (ver + still), ctx.thr, evidence, rec, change, data, 3, detail="Verified means the findings are no longer reported: evidence the fix held, not proof.")


def _unproposed(ctx):
    cid, area, title = "sc-del-unproposed", "delivery", "Dependency findings with a fix available have a fix proposal"
    data = ["findings with a dependency and fixed version", "fix pull requests"]
    rec = "Propose the upgrades from the Applications page: one proposal closes every finding in the same package."
    change = {"kind": "page", "where": "/applications", "key": "Applications & SBOM", "value": "propose the upgrade", "effect": "Creates a fix proposal for the package upgrade, to approve and open as a pull request."}
    props = _proposals(ctx)
    if props is None:
        return _unknown(cid, area, title, "Fix proposals could not be read.", rec, data, 4)
    dep = _dep_findings(ctx)
    if not dep:
        return _unknown(cid, area, title, "No open dependency finding is recorded (0 findings).", rec, data, 4, change)
    fixable = [f for f in dep if (f.get("dependency") or {}).get("fixed_version")]
    if not fixable:
        return check(cid, FID, area, title, "na", weight=4, evidence=[f"0 of {len(dep)} open dependency findings name a fixed version"], refs=REFS, data_used=data)
    covered_ids = {fid for p in props if p["status"] not in ("discarded", "closed") for fid in p["finding_ids"]}
    open_ = [f for f in fixable if f["id"] not in covered_ids]
    evidence = [f"{len(fixable) - len(open_)} of {len(fixable)} fixable dependency findings are in a fix proposal"]
    if open_:
        evidence.append("Not proposed: " + ", ".join(sorted(f["id"] for f in open_)[:6]))
    return _built(cid, area, title, (len(fixable) - len(open_)) / len(fixable), ctx.thr, evidence, rec, change, data, 4)


def _backlog(ctx):
    limit = ctx.thr["kev_open_days"]
    cid, area, title = "sc-del-pr-backlog", "delivery", f"Open fix pull requests are not older than {limit} days"
    data = ["fix pull requests"]
    rec = "Ask the owners to review the stale pull requests or close them; an unreviewed fix protects nothing."
    change = {"kind": "page", "where": "/fix-prs", "key": "Fix Pull Requests", "value": "chase the oldest", "effect": "Shows each open pull request's age and review state."}
    props = _live_proposals(ctx)
    if props is None:
        return _unknown(cid, area, title, "Fix proposals could not be read.", rec, data, 2)
    open_ = [p for p in props if p["status"] in OPEN_PR]
    if not open_:
        return _unknown(cid, area, title, "No fix pull request is open (0 open).", rec, data, 2, change)
    old = [p for p in open_ if (_age_days(p["opened_at"], ctx.now) or 0) > limit]
    evidence = [f"{len(old)} of {len(open_)} open pull requests are older than {limit} days"]
    return _built(cid, area, title, 1 - len(old) / len(open_), ctx.thr, evidence, rec, change, data, 2)


def _sync(ctx):
    cid, area, title = "sc-del-pr-sync", "delivery", "Open fix pull requests are followed automatically"
    data = ["QUANTA_GITOPS_SYNC", "applications and proposals"]
    rec = "Leave the hourly pull request follow-up on (it is on unless QUANTA_GITOPS_SYNC is set to false), so merged fixes are re-checked against the latest scan."
    change = {"kind": "env", "where": "QUANTA_GITOPS_SYNC", "key": "QUANTA_GITOPS_SYNC", "value": "true", "effect": "Quanta follows open pull requests hourly and re-checks merged ones against the latest scan."}
    props, apps = _proposals(ctx), _apps(ctx)
    if not props and not apps:
        return _unknown(cid, area, title, "No application or fix proposal is recorded (0 records).", rec, data, 2)
    on = ctx.flag("QUANTA_GITOPS_SYNC", True)
    evidence = [f"Hourly follow-up is {'on' if on else 'off'} (QUANTA_GITOPS_SYNC); {len(props or [])} proposals recorded"]
    if on:
        return check(cid, FID, area, title, "pass", weight=2, evidence=evidence, refs=REFS, data_used=data)
    return check(cid, FID, area, title, "fail", weight=2, evidence=evidence, recommendation=rec, change=change, refs=REFS, data_used=data)


def _approver(ctx):
    cid, area, title = "sc-del-distinct-approver", "delivery", "A fix is approved by someone other than its creator"
    data = ["gitops_policy.yaml", "fix pull requests"]
    rec = "Require a distinct approver, so the administrator who creates a fix proposal is not the one who approves it."
    change = {"kind": "yaml", "where": "remediation/config/gitops_policy.yaml (approval)", "key": "require_distinct_approver", "value": "true", "effect": "Quanta refuses an approval from the person who created the proposal."}
    props = _proposals(ctx)
    if not props:
        return _unknown(cid, area, title, "No fix proposal is recorded (0 proposals).", rec, data, 2)
    pol = ctx.get("sc.gitops_policy", lambda: gitops_policy.load())
    if pol is None:
        return _unknown(cid, area, title, "The pull request policy could not be read.", rec, data, 2)
    distinct = bool((pol.get("approval") or {}).get("require_distinct_approver"))
    approved = [p for p in props if p.get("approved_by")]
    selfs = [p for p in approved if p["approved_by"] == p["created_by"]]
    evidence = [f"require_distinct_approver is {'true' if distinct else 'false'}; {len(selfs)} of {len(approved)} approved proposals were approved by their creator"]
    if distinct and not selfs:
        return check(cid, FID, area, title, "pass", weight=2, evidence=evidence, refs=REFS, data_used=data)
    if selfs:
        return check(cid, FID, area, title, "fail", weight=2, evidence=evidence, recommendation=rec, change=change, refs=REFS, data_used=data)
    return check(cid, FID, area, title, "partial", score=0.5, weight=2, evidence=evidence, recommendation=rec, change=change, refs=REFS, data_used=data)


def run(ctx):
    token_change = {"kind": "page", "where": "/devsecops", "key": "Control Library", "value": "least-privilege-ci-token", "effect": "Shows which repositories fail the token-permission control and the snippet that fixes it."}
    pin_change = {"kind": "page", "where": "/devsecops", "key": "Control Library", "value": "pin-pipeline-dependencies", "effect": "Shows which repositories use unpinned actions or images and how to pin them."}
    danger_change = {"kind": "page", "where": "/devsecops", "key": "Control Library", "value": "untrusted-input", "effect": "Shows which repositories run untrusted input in a privileged workflow."}
    return [
        _sbom_coverage(ctx),
        _sbom_fresh(ctx),
        _unregistered(ctx),
        _transitive(ctx),
        _ci_check(ctx, "sc-int-pinned-actions", "Third-party actions and images are pinned", ("GHA001", "GL001"), 4,
                  "Pin every third-party action to a full commit SHA and every container image to a tag or digest, and let a dependency bot propose updates.", pin_change,
                  detail="A mutable tag lets whoever controls the action change what runs in your build."),
        _ci_check(ctx, "sc-int-token-permissions", "Workflow tokens have restricted permissions", ("GHA004",), 3,
                  "Set `permissions: contents: read` at the top of each workflow and grant more per job only where needed.", token_change),
        _ci_check(ctx, "sc-int-dangerous-workflow", "No workflow runs untrusted input with privilege", DANGEROUS, 4,
                  "Do not check out and run pull request code under pull_request_target, and pass event fields through environment variables, never inline in a run script.", danger_change,
                  any_is_fail=True, detail="A poisoned pipeline lets an outsider run code with your build's secrets."),
        _slsa_unknown(ctx, "sc-prov-build-level", "Builds meet an SLSA build level", "how your builds run (hosted, isolated, scripted) and so which SLSA build level they meet"),
        _slsa_unknown(ctx, "sc-prov-signed-releases", "Releases are signed and carry provenance", "whether release artifacts are signed or carry provenance"),
        _gate_sbom(ctx),
        _throughput(ctx),
        _verified(ctx),
        _unproposed(ctx),
        _backlog(ctx),
        _sync(ctx),
        _approver(ctx),
    ]
