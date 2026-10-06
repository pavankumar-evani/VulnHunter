"""Secure software development lifecycle, read against NIST SSDF (SP 800-218).

Every check reads what Quanta already holds about delivery: the DevSecOps control library and each repository's status against it, scan uploads by type,
pipeline-check findings, release-gate decisions, the code fix queue and fix pull requests. Nothing here looks inside a pipeline. What Quanta was never told
is `unknown`, not a pass: an estate with no repositories gives no passes at all.
"""
import datetime

from remediation.devsecops import controls as dso
from remediation.devsecops import factory, gates
from remediation.gitops import proposals, velocity
from remediation.posture.model import check
from remediation.threatmodel import store as tm_store

FRAMEWORK = {
    "id": "sdlc", "title": "Secure software development lifecycle (NIST SSDF)",
    "summary": "How well the delivery pipeline is secured and observed, from the evidence Quanta holds: scans that ran, controls evidenced, release-gate decisions and how fast code findings are fixed.",
    "areas": [("prepare", "Prepare the organisation (PO)"), ("protect", "Protect the software (PS)"), ("produce", "Produce well-secured software (PW)"), ("respond", "Respond to vulnerabilities (RV)")],
    "refs": [{"label": "NIST SSDF (SP 800-218)", "url": "https://csrc.nist.gov/projects/ssdf"}],
}
REFS = FRAMEWORK["refs"]
CODE_TYPES = ("sast", "sca", "secrets", "iac", "container")
GATE_RULES = ("open_severity", "known_exploited", "fixable_overdue", "required_scans", "sbom", "secrets")


# ---------------------------------------------------------------- helpers
def _age_days(stamp, now):
    if not stamp:
        return None
    s = str(stamp)
    for fmt, n in (("%Y-%m-%dT%H:%M:%S", 19), ("%Y-%m-%d", 10)):
        try:
            d = datetime.datetime.strptime(s[:n], fmt).replace(tzinfo=datetime.timezone.utc)
            return (now - d).total_seconds() / 86400.0
        except ValueError:
            continue
    return None


def _coverage(share, thr):
    """(status, score) for a share of the estate that is in place."""
    if share >= thr["coverage_good"]:
        return "pass", None
    if share >= thr["coverage_partial"]:
        return "partial", share
    return "fail", None


def _pct(n, d):
    return f"{n} of {d}"


def _is_open(f):
    return f.get("status") not in ("resolved", "closed")


def _unknown(cid, area, title, why, rec, data_used, weight=3, change=None):
    if not any(ch.isdigit() for ch in why):
        why += " Usable records found: 0."
    return check(cid, "sdlc", area, title, "unknown", weight=weight, evidence=[why], recommendation=rec, change=change, refs=REFS, data_used=data_used)


def _built(cid, area, title, share, thr, evidence, rec, change, data_used, weight=3, detail=""):
    status, score = _coverage(share, thr)
    return check(cid, "sdlc", area, title, status, score=score, weight=weight, evidence=evidence, detail=detail, recommendation=rec if status != "pass" else "",
                 change=change if status != "pass" else None, refs=REFS, data_used=data_used)


# ---------------------------------------------------------------- loaders (each recorded as unavailable on failure)
def _runs(ctx):
    return ctx.get("sdlc.runs", lambda: dso.scan_runs(ctx.engine))


def _repos(ctx):
    def load():
        runs, rec = dso.scan_runs(ctx.engine), dso.states(ctx.engine)
        return dso.assets(runs, rec, ctx.findings)
    return ctx.get("sdlc.repos", load)


def _reports(ctx):
    """[{asset, cells: [(control id, stage, status, recorded_state)]}]: the library's status for every repository."""
    def load():
        runs, rec = dso.scan_runs(ctx.engine), dso.states(ctx.engine)
        tms = len(tm_store.list_models(ctx.engine))
        from remediation.appsec import store as appsec_store
        extras = {"sboms": {k.strip().lower(): v for k, v in appsec_store.sbom_summaries(ctx.engine).items()}, "gate_runs": gates.last_by_application(ctx.engine)}
        lib = dso.full_library(ctx.engine)
        out = []
        for name in dso.assets(runs, rec, ctx.findings):
            rp = dso.repo_report(name, lib, runs, rec, ctx.findings, tms, extras)
            out.append({"asset": name, "cells": [(r["id"], r["stage"], r["status"], (r["recorded"] or {}).get("state")) for r in rp["controls"]]})
        return out
    return ctx.get("sdlc.reports", load)


def _threat_models(ctx):
    return ctx.get("sdlc.tms", lambda: len(tm_store.list_models(ctx.engine)))


def _applications(ctx):
    from remediation.appsec import store as appsec_store
    return ctx.get("sdlc.apps", lambda: appsec_store.list_applications(ctx.engine))


def _gate_last(ctx):
    return ctx.get("sdlc.gate_last", lambda: gates.last_by_application(ctx.engine))


def _gate_history(ctx):
    return ctx.get("sdlc.gate_history", lambda: gates.history(limit=2000, engine=ctx.engine))


def _gate_policy(ctx):
    return ctx.get("sdlc.gate_policy", lambda: gates.load())


def _estate(ctx):
    """True when anything about delivery is recorded; a settings-only check must not look good on an empty estate."""
    return bool(_repos(ctx) or _applications(ctx) or _gate_last(ctx))


# ---------------------------------------------------------------- control library by stage
def _stage_check(ctx, cid, area, stage, title, weight):
    data = ["DevSecOps control library", "scan runs", "pipeline-check findings", "recorded control states"]
    rec_text = "Upload the scans the controls need (SARIF from your pipeline) and record the state of the controls Quanta cannot see."
    change = {"kind": "page", "where": "/devsecops", "key": "Control Library", "value": stage, "effect": f"Shows which {stage}-stage controls each repository is missing and how to add them."}
    reports = _reports(ctx)
    if reports is None:
        return _unknown(cid, area, title, "The control library status could not be read.", rec_text, data, weight)
    if not reports:
        return _unknown(cid, area, title, "No repository is recorded (no scan upload, recorded control state or repository finding).", rec_text, data, weight)
    ev = fail = obs = stated = hidden = 0
    for rp in reports:
        for _cid, st, status, recorded in rp["cells"]:
            if st != stage:
                continue
            if status == "not-observable":
                hidden += 1
                stated += 1 if recorded == "implemented" else 0
                continue
            obs += 1
            ev += status == "evidenced"
            fail += status == "failing"
            stated += 1 if (status == "no-evidence" and recorded == "implemented") else 0
    if obs == 0:
        return _unknown(cid, area, title, f"All {hidden} {stage}-stage control checks across {len(reports)} repositories are not observable by Quanta"
                        + (f" ({stated} are stated as implemented, which is not evidence)." if stated else "."), rec_text, data, weight, change)
    share = ev / obs
    evidence = [f"{_pct(ev, obs)} observable {stage}-stage control checks are evidenced across {len(reports)} repositories", f"{fail} failing, {obs - ev - fail} with no evidence, {hidden} not observable"]
    if stated:
        evidence.append(f"{stated} more are stated as implemented by a person (stated, not observed)")
    return _built(cid, area, title, share, ctx.thr, evidence, rec_text, change, data, weight,
                  detail=f"Evidenced means a scan or pipeline check was seen; the {stage} stage covers what happens before code is {'released' if stage in ('release', 'operate') else 'built and shipped'}.")


# ---------------------------------------------------------------- scan recency
def _scan_recent(ctx, cid, area, scan_type, label, weight):
    title = f"Repositories have a {label} scan within {ctx.thr['stale_days']} days"
    data = ["scan runs", "repository list"]
    rec = f"Upload a {label} scan (SARIF) from every repository's pipeline on each change, so a clean result is recorded too."
    change = {"kind": "process", "where": "CI pipeline", "key": "POST /api/ingest/findings", "value": scan_type, "effect": "Records that the scan ran, even when it finds nothing."}
    repos, runs = _repos(ctx), _runs(ctx)
    if repos is None or runs is None:
        return _unknown(cid, area, title, "Scan runs could not be read.", rec, data, weight)
    if not repos:
        return _unknown(cid, area, title, "No repository is recorded, so there is nothing to measure.", rec, data, weight)
    fresh, behind = 0, []
    for name in repos:
        ages = [_age_days(r["received_at"], ctx.now) for r in runs if r["scan_type"] == scan_type and (r["asset"] or "").strip().lower() == name.strip().lower()]
        ages = [a for a in ages if a is not None]
        if ages and min(ages) <= ctx.thr["stale_days"]:
            fresh += 1
        else:
            behind.append(name)
    evidence = [f"{_pct(fresh, len(repos))} repositories have a {label} scan in the last {ctx.thr['stale_days']} days"]
    if behind:
        evidence.append("No recent scan: " + ", ".join(behind[:5]) + (f" and {len(behind) - 5} more" if len(behind) > 5 else ""))
    return _built(cid, area, title, fresh / len(repos), ctx.thr, evidence, rec, change, data, weight)


# ---------------------------------------------------------------- checks
def _gate_policy_check(ctx):
    cid, area, title = "sdlc-po-gate-policy", "prepare", "The production release gate blocks on its rules"
    data = ["pipeline_gates.yaml", "repository and gate records"]
    rec = "Set the production release gate's rules to block so a build that breaks policy cannot ship."
    if not _estate(ctx):
        return _unknown(cid, area, title, "No repository, application or gate evaluation is recorded, so the gate's setting is not assessed.", rec, data, 3)
    pol = _gate_policy(ctx)
    if pol is None:
        return _unknown(cid, area, title, "The release gate policy file could not be read.", rec, data, 3)
    modes = (pol.get("environments") or {}).get("production")
    if modes is None:
        return _unknown(cid, area, title, "The gate policy has no production environment.", rec, data, 3)
    rules = [r for r in GATE_RULES if r in (pol.get("rules") or {})]
    if not rules:
        return _unknown(cid, area, title, "The gate policy lists none of the expected rules.", rec, data, 3)
    val = {"block": 1.0, "warn": 0.5}
    share = sum(val.get(modes.get(r, "off"), 0.0) for r in rules) / len(rules)
    nb = [r for r in rules if modes.get(r, "off") != "block"]
    evidence = [f"{_pct(sum(1 for r in rules if modes.get(r) == 'block'), len(rules))} gate rules block in production", "Not blocking: " + (", ".join(f"{r} ({modes.get(r, 'off')})" for r in nb) or "none")]
    change = {"kind": "yaml", "where": "remediation/config/pipeline_gates.yaml (environments: production)", "key": nb[0] if nb else "known_exploited", "value": "block",
              "effect": "A failing rule makes the production gate decision fail, so the CI job stops the release."}
    return _built(cid, area, title, share, ctx.thr, evidence, rec, change, data, 3, detail="A gate set to warn or off records a problem but lets the release through.")


def _secure_design_check(ctx):
    cid, area, title = "sdlc-po-threat-models", "prepare", "Designs have a recorded threat model"
    data = ["threat models", "repository list"]
    rec = "Model each system's components, data flows and trust zones on the Threat Models page, starting with the internet-facing ones."
    change = {"kind": "page", "where": "/threat-models", "key": "Threat Models", "value": "one model per system", "effect": "Raises STRIDE threats from the model and joins them to live findings."}
    repos, tms = _repos(ctx), _threat_models(ctx)
    if repos is None or tms is None:
        return _unknown(cid, area, title, "Repositories or threat models could not be read.", rec, data, 2)
    if not repos:
        return _unknown(cid, area, title, "No repository is recorded. The secure design assistant's use is not recorded either, so it cannot be counted.", rec, data, 2)
    share = min(1.0, tms / len(repos))
    evidence = [f"{tms} threat model(s) for {len(repos)} repositories"]
    return _built(cid, area, title, share, ctx.thr, evidence, rec, change, data, 2, detail="A model is counted per repository; Quanta cannot tell which system a model describes beyond its count.")


def _pipeline_findings_check(ctx):
    cid, area, title = "sdlc-ps-pipeline-findings", "protect", "Pipeline checks find no open serious issues"
    data = ["pipeline-check findings (scan type cicd)", "scan runs"]
    rec = "Run the pipeline scanner (quanta-admin scan-pipelines) over every repository and fix the open findings, starting with the highest severity."
    change = {"kind": "page", "where": "/devsecops", "key": "Control Library", "value": "pipeline controls", "effect": "Lists the failing pipeline controls per repository."}
    runs = _runs(ctx)
    if runs is None:
        return _unknown(cid, area, title, "Scan runs could not be read.", rec, data, 4)
    cicd = [f for f in ctx.findings if f.get("scan_type") == "cicd" and _is_open(f)]
    checked = {(r["asset"] or "").strip().lower() for r in runs if r["scan_type"] == "cicd"}
    if not cicd and not checked:
        return _unknown(cid, area, title, "No pipeline has been checked and no pipeline finding is recorded.", rec, data, 4, change)
    serious = [f for f in cicd if f.get("severity") in ("Critical", "High")]
    evidence = [f"{len(cicd)} open pipeline finding(s), {len(serious)} Critical or High", f"{len(checked)} repositories have a recorded pipeline check"]
    if serious:
        evidence.append("Serious: " + ", ".join(sorted({f"{f.get('rule_id') or f['id']} ({f['severity']})" for f in serious})[:6]))
        return check(cid, "sdlc", area, title, "fail", weight=4, evidence=evidence, recommendation=rec, change=change, refs=REFS, data_used=data,
                     detail="A Critical or High pipeline finding is a way in to the build itself.")
    if cicd:
        return check(cid, "sdlc", area, title, "partial", score=0.5, weight=4, evidence=evidence, recommendation=rec, change=change, refs=REFS, data_used=data)
    return check(cid, "sdlc", area, title, "pass", weight=4, evidence=evidence, refs=REFS, data_used=data)


def _gate_used_check(ctx):
    cid, area, title = "sdlc-pw-gate-used", "produce", f"Applications are evaluated by the release gate within {ctx.thr['stale_days']} days"
    data = ["applications", "gate runs"]
    rec = "Add the release-gate step to each application's pipeline (the Pipeline Gates page gives the snippet) so every release is evaluated."
    change = {"kind": "page", "where": "/pipeline-gates", "key": "Pipeline Gates", "value": "add the CI step", "effect": "Gives the CI step that calls GET /api/gate/evaluate before a release."}
    apps, last = _applications(ctx), _gate_last(ctx)
    if apps is None or last is None:
        return _unknown(cid, area, title, "Applications or gate runs could not be read.", rec, data, 4)
    if not apps:
        return _unknown(cid, area, title, "No application is registered, so gate coverage cannot be measured.", rec, data, 4)
    used, missing = 0, []
    for a in apps:
        age = _age_days(last.get(a["name"].strip().lower()), ctx.now)
        if age is not None and age <= ctx.thr["stale_days"]:
            used += 1
        else:
            missing.append(a["name"])
    evidence = [f"{_pct(used, len(apps))} applications were gate-evaluated in the last {ctx.thr['stale_days']} days"]
    if missing:
        evidence.append("Not evaluated: " + ", ".join(missing[:5]))
    return _built(cid, area, title, used / len(apps), ctx.thr, evidence, rec, change, data, 4)


def _gate_latest_check(ctx):
    cid, area, title = "sdlc-pw-gate-latest", "produce", "The latest production gate decision is not a failure"
    data = ["gate runs"]
    rec = "Fix what the failing gate names (its rules list the findings) and re-evaluate before the release."
    change = {"kind": "page", "where": "/pipeline-gates", "key": "Pipeline Gates", "value": "re-evaluate", "effect": "Shows each rule's reasons for the last decision."}
    hist = _gate_history(ctx)
    if hist is None:
        return _unknown(cid, area, title, "Gate history could not be read.", rec, data, 2)
    latest = {}
    for h in hist:  # newest first
        if h["environment"] == "production":
            latest.setdefault(h["application"].strip().lower(), h)
    if not latest:
        return _unknown(cid, area, title, "No production gate evaluation is recorded.", rec, data, 2)
    failed = sorted(k for k, h in latest.items() if h["decision"] == "fail")
    evidence = [f"{_pct(len(failed), len(latest))} applications' latest production decision is fail"]
    if failed:
        evidence.append("Failing: " + ", ".join(failed[:5]))
    return _built(cid, area, title, 1 - len(failed) / len(latest), ctx.thr, evidence, rec, change, data, 2,
                  detail="A failing latest decision means a known blocker is open; it says nothing about whether the pipeline obeyed it.")


def _gate_override_check(ctx):
    return _unknown("sdlc-pw-gate-override", "produce", "A failing gate is never overridden", "Quanta records the gate's decision, not whether the pipeline stopped when it said fail, so overrides are not observable.",
                    "Make the gate step a required status check on the protected branch, and review manual releases against failing decisions.", ["gate runs"], 3,
                    {"kind": "process", "where": "CI/CD platform", "key": "required status check", "value": "release gate", "effect": "A failing decision blocks the merge or deploy rather than only reporting."})


def _critical_code_check(ctx):
    cid, area, title = "sdlc-rv-critical-code-open", "respond", f"No Critical code finding stays open beyond {ctx.thr['critical_open_days']} days"
    data = ["code-level findings (sast, sca, secrets, iac, container)", "scan runs"]
    rec = "Queue the open Critical code findings in the code fix queue, assign an owner and fix them first."
    change = {"kind": "page", "where": "/devsecops?tab=queue", "key": "Code Fix Queue", "value": "queue Critical findings", "effect": "Produces a fix brief per finding and tracks it until a later scan stops reporting it."}
    runs = _runs(ctx)
    if runs is None:
        return _unknown(cid, area, title, "Scan runs could not be read.", rec, data, 5)
    code = [f for f in ctx.findings if f.get("scan_type") in CODE_TYPES and _is_open(f)]
    if not code and not runs:
        return _unknown(cid, area, title, "No code finding and no scan upload is recorded.", rec, data, 5)
    crit = [f for f in code if f.get("severity") == "Critical"]
    over, unaged = [], []
    for f in crit:
        a = _age_days(f.get("first_seen"), ctx.now)
        if a is None:
            unaged.append(f)
        elif a > ctx.thr["critical_open_days"]:
            over.append(f)
    evidence = [f"{len(crit)} open Critical of {len(code)} open code findings", f"{len(over)} older than {ctx.thr['critical_open_days']} days"]
    if unaged:
        evidence.append(f"{len(unaged)} have no first-seen date, so their age cannot be shown")
    if over:
        evidence.append("Overdue: " + ", ".join(sorted(f["id"] for f in over)[:6]))
        return check(cid, "sdlc", area, title, "fail", weight=5, evidence=evidence, recommendation=rec, change=change, refs=REFS, data_used=data)
    if crit:
        return check(cid, "sdlc", area, title, "partial", score=0.5, weight=5, evidence=evidence, recommendation=rec, change=change, refs=REFS, data_used=data)
    return check(cid, "sdlc", area, title, "pass", weight=5, evidence=evidence, refs=REFS, data_used=data)


def _queue_age_check(ctx):
    cid, area, title = "sdlc-rv-fix-queue-age", "respond", f"Queued code fixes are not older than {ctx.thr['critical_open_days']} days"
    data = ["code fix queue (remediation_factory)"]
    rec = "Review the oldest queued fixes, assign each an owner and a date, or record a won't-fix decision."
    change = {"kind": "page", "where": "/devsecops?tab=queue", "key": "Code Fix Queue", "value": "work the oldest first", "effect": "Shows each item's state and age."}
    items = ctx.get("sdlc.queue", lambda: factory.items(ctx.findings, ctx.engine))
    if items is None:
        return _unknown(cid, area, title, "The fix queue could not be read.", rec, data, 3)
    live = [i for i in items if i["shown_state"] in ("queued", "in-progress", "pr-opened", "merged-still-reported")]
    if not live:
        return _unknown(cid, area, title, "No code finding is waiting in the fix queue, so its age cannot be shown.", rec, data, 3)
    aged = [i for i in live if (_age_days(i["queued_at"], ctx.now) or 0) > ctx.thr["critical_open_days"]]
    evidence = [f"{_pct(len(aged), len(live))} open queue items are older than {ctx.thr['critical_open_days']} days"]
    if aged:
        evidence.append("Oldest: " + ", ".join(i["finding_id"] for i in sorted(aged, key=lambda i: i["queued_at"])[:5]))
    return _built(cid, area, title, 1 - len(aged) / len(live), ctx.thr, evidence, rec, change, data, 3)


def _fix_speed_check(ctx):
    cid, area, title = "sdlc-rv-fix-speed", "respond", "Findings reach a fix pull request quickly"
    limit_h = ctx.thr["critical_open_days"] * 24
    data = ["fix pull requests", "findings first-seen dates"]
    rec = "Approve and open fix pull requests as soon as a fixable finding appears; the Fix Pull Requests page shows the stage that is slowest."
    change = {"kind": "page", "where": "/fix-prs", "key": "Fix Pull Requests", "value": "open the proposals", "effect": "Shows where fixes wait, from detection to merge."}
    props = ctx.get("sdlc.proposals", lambda: proposals.list_proposals(engine=ctx.engine))
    if props is None:
        return _unknown(cid, area, title, "Fix proposals could not be read.", rec, data, 3)
    v = velocity.compute(props, ctx.findings, ctx.now)
    st = v["stages"]["detected_to_pull_request"]
    if not st["n"]:
        return _unknown(cid, area, title, "No fix pull request has been opened for a finding with a first-seen date, so the time to fix cannot be shown.", rec, data, 3)
    med = st["median_hours"]
    evidence = [f"Median {med} hours from detection to pull request over {st['n']} pull request(s) (limit {limit_h} hours)", f"p90 {st['p90_hours']} hours"]
    if med <= limit_h:
        return check(cid, "sdlc", area, title, "pass", weight=3, evidence=evidence, refs=REFS, data_used=data)
    if med <= 3 * limit_h:
        return check(cid, "sdlc", area, title, "partial", score=round(limit_h / med, 4), weight=3, evidence=evidence, recommendation=rec, change=change, refs=REFS, data_used=data)
    return check(cid, "sdlc", area, title, "fail", weight=3, evidence=evidence, recommendation=rec, change=change, refs=REFS, data_used=data)


def run(ctx):
    return [
        _stage_check(ctx, "sdlc-po-design-controls", "prepare", "design", "Design-stage controls are evidenced", 3),
        _secure_design_check(ctx),
        _gate_policy_check(ctx),
        _stage_check(ctx, "sdlc-ps-code-controls", "protect", "code", "Code-stage controls are evidenced", 3),
        _stage_check(ctx, "sdlc-ps-build-controls", "protect", "build", "Build-stage controls are evidenced", 3),
        _scan_recent(ctx, "sdlc-ps-secrets-scanning", "protect", "secrets", "secrets", 4),
        _pipeline_findings_check(ctx),
        _scan_recent(ctx, "sdlc-pw-sast-recent", "produce", "sast", "static analysis (SAST)", 4),
        _scan_recent(ctx, "sdlc-pw-sca-recent", "produce", "sca", "dependency (SCA)", 3),
        _stage_check(ctx, "sdlc-pw-test-controls", "produce", "test", "Test-stage controls are evidenced", 2),
        _stage_check(ctx, "sdlc-pw-release-controls", "produce", "release", "Release-stage controls are evidenced", 3),
        _gate_used_check(ctx),
        _gate_latest_check(ctx),
        _gate_override_check(ctx),
        _stage_check(ctx, "sdlc-rv-operate-controls", "respond", "operate", "Operate-stage controls are evidenced", 2),
        _critical_code_check(ctx),
        _queue_age_check(ctx),
        _fix_speed_check(ctx),
    ]

