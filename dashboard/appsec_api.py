"""
Routes for application security: applications and their SBOMs, the dependency graph, ranked work, fix pull requests, the release gate, the secure design
assistant and the organisation's own DevSecOps controls.

Built by `build_router()` so this module needs nothing from app.py except what is handed in (the API-key dependency, team scoping, the upload reader).
Reads need a login; every change needs an administrator; the two CI-facing routes (SBOM upload, release gate) and the pull-request status callback
check an API key themselves. The only route that can change a customer's repository is `POST /api/gitops/proposals/{id}/open`, which is a dry run
unless `confirm` is true.
"""
import datetime
import json
import re
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

import data as dashboard_data
from auth import rbac
from remediation.appsec import analysis, manifest_gen, sbom_parse, scoring, store as app_store
from remediation.appsec import graph as app_graph
from remediation.audit import activity_log
from remediation.connectors import git_host_connector, osv_connector
from remediation.devsecops import controls as dso_controls
from remediation.devsecops import design as dso_design
from remediation.devsecops import gates as dso_gates
from remediation.enrichment import network_reachability as network_reach
from remediation.gitops import policy as gitops_policy
from remediation.gitops import proposals, service as gitops_service, velocity
from remediation.ingest import merge as findings_merge
from remediation.utils import db as db_module

REPO_ROOT = Path(__file__).resolve().parent.parent
CODE_FIX_DIR = REPO_ROOT / "remediation" / "output" / "code-fixes"
UPGRADE_PLAN_DIR = REPO_ROOT / "remediation" / "output" / "upgrade-plans"
_FINDING_ID = re.compile(r"^FIND-\d+$")


def osv_connector_factory():
    return osv_connector.OsvConnector()


class AppBody(BaseModel):
    environment: str | None = None
    platform: str | None = None
    os: str | None = None
    owner: str | None = None
    team: str | None = None
    business_criticality: str | None = None
    internet_facing: bool | None = None
    data_classification: str | None = None
    repo_provider: str | None = None
    repo: str | None = None
    default_branch: str | None = None
    manifest_paths: list[str] | str | None = None
    connection_id: int | None = None
    notes: str | None = None


class GenerateBody(BaseModel):
    files: dict[str, str]
    version: str | None = None


class ConfirmBody(BaseModel):
    confirm: bool = False


class DepProposalBody(BaseModel):
    application: str
    item_id: str
    manifests: dict[str, str] | None = None
    fetch: bool = False
    lockfiles: list[str] | None = None
    group: str | None = None


class CodeProposalBody(BaseModel):
    application: str
    finding_id: str
    patches: dict[str, str] | None = None
    originals: dict[str, str] | None = None
    fetch: bool = False
    from_output: bool = False
    explanation: str | None = None
    validation: dict | None = None


class DiscardBody(BaseModel):
    reason: str = ""


class InboundPrBody(BaseModel):
    proposal: str
    state: str
    merged_at: str | None = None


class GateBody(BaseModel):
    application: str
    environment: str | None = None


class AssessBody(BaseModel):
    answers: dict[str, str]
    name: str = "the system"


class CustomControlBody(BaseModel):
    stage: str
    title: str
    why: str
    how: str
    keywords: list[str] = []
    evidence: dict | None = None


def _slug(text, limit=30):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:limit].strip("-") or "app"


def build_router(require_api_key, scope_findings, read_upload, enrich_in_background):
    r = APIRouter()

    def live():
        return dashboard_data.load_live_queue()

    def bad(exc, code=400):
        return HTTPException(status_code=code, detail=str(exc.args[0]) if isinstance(exc, KeyError) else str(exc))

    def topology():
        try:
            return network_reach.load_topology()
        except Exception:  # noqa: BLE001 - optional context
            return None

    def analyse(name, findings, view="focus"):
        try:
            return analysis.analyse(name, findings, topology=topology(), view=view)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="No such application") from exc
        except ValueError as exc:
            raise bad(exc) from exc

    # ---------------------------------------------------------------- applications
    @r.get("/api/applications")
    def api_applications(user: dict = Depends(rbac.require_login)):
        rows = scope_findings(live(), user)
        ov = analysis.overview(rows)
        if user.get("role") != "admin" and user.get("team"):
            seen = {(f.get("asset") or {}).get("name", "").lower() for f in rows}
            ov["applications"] = [a for a in ov["applications"] if a.get("team") == user["team"] or a["name"].lower() in seen]
        return {**ov, "environments": list(app_store.ENVIRONMENTS), "criticality": list(app_store.CRITICALITY), "providers": list(app_store.PROVIDERS)}

    @r.put("/api/applications/{name:path}/context")
    def api_application_put(name: str, body: AppBody, user: dict = Depends(rbac.require_admin)):
        try:
            app = app_store.upsert_application(name, body.model_dump(exclude_unset=True), user["email"])
        except ValueError as exc:
            raise bad(exc) from exc
        activity_log.record_activity(user["email"], "application.update", name, {"fields": sorted(body.model_dump(exclude_unset=True))})
        return app

    @r.delete("/api/applications/{name:path}/context")
    def api_application_delete(name: str, user: dict = Depends(rbac.require_admin)):
        if not app_store.delete_application(name):
            raise HTTPException(status_code=404, detail="No such application")
        activity_log.record_activity(user["email"], "application.delete", name, {})
        return {"ok": True}

    @r.get("/api/applications/{name:path}/analysis")
    def api_application_analysis(name: str, view: str = "focus", user: dict = Depends(rbac.require_login)):
        if view not in ("focus", "all"):
            raise HTTPException(status_code=400, detail="view must be focus or all")
        out = analyse(name, scope_findings(live(), user), view)
        out["proposals"] = [proposals.public(p, with_files=False) for p in proposals.list_proposals(out["application"])]
        return out

    @r.post("/api/applications/{name:path}/sbom/generate")
    def api_sbom_generate(name: str, body: GenerateBody, user: dict = Depends(rbac.require_admin)):
        try:
            doc, notes = manifest_gen.generate(name, body.files, body.version)
            out = app_store.set_sbom(name, doc, "generated from " + ", ".join(sorted(body.files))[:100], user["email"], notes=notes)
        except (ValueError, sbom_parse.SbomError) as exc:
            raise bad(exc) from exc
        activity_log.record_activity(user["email"], "application.sbom.generate", name, {"components": out["components"]})
        return out

    @r.post("/api/applications/{name:path}/sbom")
    async def api_sbom_upload(name: str, request: Request, source: str = "upload", user: dict = Depends(rbac.require_admin)):
        try:
            out = app_store.set_sbom(name, await read_upload(request), source, user["email"])
        except (ValueError, sbom_parse.SbomError) as exc:
            raise bad(exc) from exc
        activity_log.record_activity(user["email"], "application.sbom.upload", name, {"components": out["components"], "format": out["format"]})
        return out

    @r.post("/api/ingest/sbom")
    async def api_ingest_sbom(request: Request, application: str, source: str = "ci", key: dict = Depends(require_api_key("ingest:write"))):
        """For a CI job: upload the build's CycloneDX or SPDX JSON as the request body. Creates the application if it is new and replaces its SBOM."""
        try:
            out = app_store.set_sbom(application, await read_upload(request), source, f"apikey:{key['name']}")
        except (ValueError, sbom_parse.SbomError) as exc:
            raise bad(exc) from exc
        activity_log.record_activity(f"apikey:{key['name']}", "ingest.sbom", application, {"components": out["components"], "format": out["format"]})
        return out

    @r.post("/api/applications/{name:path}/osv-check")
    def api_osv_check(name: str, body: ConfirmBody, background: BackgroundTasks, user: dict = Depends(rbac.require_admin)):
        """Ask the public OSV database which advisories affect the packages in this application's SBOM. Sends package URLs and versions only; asks first."""
        sb = app_store.get_sbom(name)
        if not sb:
            raise HTTPException(status_code=404, detail="Store an SBOM for this application first")
        app = app_store.get_application(name)
        st = app_graph.structure(sb["graph"])
        comps = []
        for ref, c in st["comps"].items():
            if c.get("version") and c.get("ecosystem"):
                purl = manifest_gen._purl(c["ecosystem"], c["name"], c["version"], c.get("group"))
                comps.append({**c, "purl": purl, "direct": app_graph.is_direct(st, ref)})
        if not comps:
            raise HTTPException(status_code=400, detail="No component has both a version and an ecosystem, so there is nothing to look up")
        if len(comps) > osv_connector.MAX_COMPONENTS:
            raise HTTPException(status_code=400, detail=f"Too many components for one check ({len(comps)}; the limit is {osv_connector.MAX_COMPONENTS})")
        if not body.confirm:
            return {"preview_only": True, "components": len(comps), "service": "api.osv.dev",
                    "sends": "Package URLs and versions only (for example pkg:maven/org.example/lib@1.2.3). No application name, repository or finding is sent.",
                    "example": [c["purl"] for c in comps[:3]], "message": "Nothing has been sent. Send confirm: true to look these components up in OSV."}
        today = datetime.date.today().isoformat()
        try:
            conn = osv_connector_factory()
            ids = conn.query(comps)
            unique = sorted({i for row in ids for i in row})
            if len(unique) > osv_connector.MAX_ADVISORIES:
                raise HTTPException(status_code=400, detail=f"{len(unique)} advisories apply, more than the {osv_connector.MAX_ADVISORIES} one check will fetch. Upgrade the worst packages first and check again.")
            advisories = {i: conn.advisory(i) for i in unique}
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"OSV could not be reached or answered badly ({type(exc).__name__}: {str(exc)[:150]})") from exc
        pairs = [(c, advisories[i]) for c, row in zip(comps, ids) for i in row if i in advisories]
        findings = osv_connector.to_findings(app["name"], comps, pairs, today)
        source = "osv-" + _slug(app["name"], 30)
        out = findings_merge.merge(findings, source, reconcile=True)
        activity_log.record_activity(user["email"], "application.osv-check", app["name"], {"components": len(comps), "advisories": len(unique), **out})
        if out.get("added") or out.get("updated"):
            enrich_in_background(background)
        return {"preview_only": False, "components": len(comps), "advisories": len(unique), "findings": len(findings), **out, "source": source,
                "note": "Severity comes from the advisory's label; OSV gives a CVSS vector rather than a score, so the ranking marks CVSS as assumed. Known-exploited and EPSS data are added by Quanta's own CVE enrichment."}

    # ---------------------------------------------------------------- pull requests
    def policy_for(repo=None):
        return gitops_policy.for_repo(gitops_policy.load(), repo)

    @r.get("/api/gitops/policy")
    def api_gitops_policy(user: dict = Depends(rbac.require_login)):  # noqa: ARG001
        pol = gitops_policy.load()
        return {"policy": {k: pol[k] for k in ("branch", "commit", "pull_request", "approval", "files", "code_fix", "process")}, "overrides": len(pol.get("overrides") or []),
                "never": ["merge a pull request", "write to a default or protected branch", "force-push", "delete a branch", "run a package manager or the project's tests", "open a pull request without an administrator's confirmation"]}

    @r.get("/api/gitops/proposals")
    def api_proposals(application: str | None = None, status: str | None = None, user: dict = Depends(rbac.require_login)):  # noqa: ARG001
        return {"proposals": [proposals.public(p, with_files=False) for p in proposals.list_proposals(application, status)], "statuses": list(proposals.STATUSES)}

    @r.get("/api/gitops/proposals/{proposal_id}")
    def api_proposal(proposal_id: int, user: dict = Depends(rbac.require_login)):  # noqa: ARG001
        p = proposals.get(proposal_id)
        if not p:
            raise HTTPException(status_code=404, detail="No such proposal")
        out = proposals.public(p)
        out["plan"] = proposals.plan(p, policy_for(p["repo"]))
        out["verification"] = proposals.verify_one(p, {f["id"]: f for f in live()})
        return out

    def _plan_notes(finding_ids):
        for fid in finding_ids:
            path = UPGRADE_PLAN_DIR / f"{fid}.json"
            if _FINDING_ID.match(fid) and path.is_file() and path.stat().st_size < 100_000:
                try:
                    d = json.loads(path.read_text(encoding="utf-8"))
                    return {"business_logic": "; ".join(d.get("test_focus") or []) or None, "risks": d.get("breaking_changes") or []}
                except ValueError:
                    return None
        return None

    @r.post("/api/gitops/proposals/dependency")
    def api_proposal_dependency(body: DepProposalBody, user: dict = Depends(rbac.require_admin)):
        app = app_store.get_application(body.application)
        if not app:
            raise HTTPException(status_code=404, detail="No such application")
        a = analyse(app["name"], live())
        item = next((i for i in a["work_items"] if i["id"] == body.item_id and i["kind"] == "dependency-upgrade"), None)
        if not item:
            raise HTTPException(status_code=404, detail="That upgrade is not in the application's ranked work (it may already be fixed)")
        manifests, locks, problems = dict(body.manifests or {}), list(body.lockfiles or []), []
        if not manifests:
            if not body.fetch:
                raise HTTPException(status_code=400, detail="Give the dependency files, or set fetch to read them from the repository")
            conn, _ = gitops_service.connector_for_application(app)
            if conn is None:
                raise HTTPException(status_code=400, detail=f"No {app.get('repo_provider') or 'Git'} connection is configured for this application")
            try:
                manifests, locks, problems = gitops_service.fetch_manifests(conn, app, item.get("ecosystem"))
            except (ValueError, git_host_connector.GitHostError) as exc:
                raise bad(exc) from exc
            if not manifests:
                raise HTTPException(status_code=400, detail="No dependency file could be read: " + "; ".join(problems))
        short = (item["package"] or "").lower().rsplit(":", 1)[-1]
        node = next((n for n in a["nodes"] if (n.get("name") or "").lower() == short and n.get("group")), None)
        group = body.group or (node or {}).get("group")
        compact = [f for f in a["findings"] if f["id"] in item["finding_ids"]]
        try:
            p = proposals.create_dependency(app, item, compact, a["reachability"], manifests, user["email"], lockfiles=locks, group=group, validation=_plan_notes(item["finding_ids"]))
        except ValueError as exc:
            raise bad(exc) from exc
        activity_log.record_activity(user["email"], "gitops.proposal.create", str(p["id"]), {"kind": "dependency-upgrade", "package": item["package"], "to": item["target_version"]})
        return {**proposals.public(p), "read_problems": problems}

    @r.post("/api/gitops/proposals/code")
    def api_proposal_code(body: CodeProposalBody, user: dict = Depends(rbac.require_admin)):
        app = app_store.get_application(body.application)
        if not app:
            raise HTTPException(status_code=404, detail="No such application")
        if not _FINDING_ID.match(body.finding_id):
            raise HTTPException(status_code=400, detail="finding_id must look like FIND-123")
        a = analyse(app["name"], live())
        finding = next((f for f in live() if f["id"] == body.finding_id), None)
        compact = next((f for f in a["findings"] if f["id"] == body.finding_id and not f.get("package")), None)
        if not finding or not compact:
            raise HTTPException(status_code=404, detail="That is not an open first-party code finding for this application")
        patches, explanation, validation = body.patches, body.explanation, body.validation
        if body.from_output:
            path = CODE_FIX_DIR / f"{body.finding_id}.json"
            if not path.is_file() or path.stat().st_size > 1_000_000:
                raise HTTPException(status_code=404, detail=f"No fix was written for {body.finding_id} (expected {path.relative_to(REPO_ROOT).as_posix()})")
            try:
                spec = json.loads(path.read_text(encoding="utf-8"))
                patches = {f["path"]: f["patch"] for f in spec["files"]}
                explanation, validation = spec.get("explanation"), spec.get("validation")
            except (ValueError, KeyError, TypeError) as exc:
                raise HTTPException(status_code=400, detail=f"The fix file is not in the expected format: {exc}") from exc
        if not patches:
            raise HTTPException(status_code=400, detail="Give the patches (path to unified diff), or set from_output")
        originals = dict(body.originals or {})
        if body.fetch or not all(p in originals for p in patches):
            conn, _ = gitops_service.connector_for_application(app)
            if conn is None:
                raise HTTPException(status_code=400, detail="Give the current content of each file, or configure a Git connection so Quanta can read it")
            try:
                originals.update(gitops_service.fetch_files(conn, app, [p for p in patches if p not in originals]))
            except (ValueError, git_host_connector.GitHostError) as exc:
                raise bad(exc) from exc
        try:
            p = proposals.create_code(app, finding, compact, a["reachability"], originals, patches, explanation, validation, user["email"])
        except ValueError as exc:
            raise bad(exc) from exc
        activity_log.record_activity(user["email"], "gitops.proposal.create", str(p["id"]), {"kind": "code-fix", "finding": body.finding_id})
        return proposals.public(p)

    @r.post("/api/gitops/proposals/{proposal_id}/approve")
    def api_proposal_approve(proposal_id: int, user: dict = Depends(rbac.require_admin)):
        try:
            p = proposals.approve(proposal_id, user["email"])
        except KeyError as exc:
            raise bad(exc, 404) from exc
        except ValueError as exc:
            raise bad(exc, 409) from exc
        activity_log.record_activity(user["email"], "gitops.proposal.approve", str(proposal_id), {})
        return proposals.public(p)

    @r.post("/api/gitops/proposals/{proposal_id}/discard")
    def api_proposal_discard(proposal_id: int, body: DiscardBody, user: dict = Depends(rbac.require_admin)):
        try:
            p = proposals.discard(proposal_id, user["email"], body.reason)
        except KeyError as exc:
            raise bad(exc, 404) from exc
        except ValueError as exc:
            raise bad(exc, 409) from exc
        activity_log.record_activity(user["email"], "gitops.proposal.discard", str(proposal_id), {})
        return proposals.public(p)

    @r.post("/api/gitops/proposals/{proposal_id}/open")
    def api_proposal_open(proposal_id: int, body: ConfirmBody, user: dict = Depends(rbac.require_admin)):
        """The one route that can change a customer's repository. A dry run unless `confirm` is true: it creates a new branch of Quanta's making, commits the files shown
        in the diff to it and opens a pull request. It never merges and never writes to a default or protected branch."""
        p = proposals.get(proposal_id)
        if not p:
            raise HTTPException(status_code=404, detail="No such proposal")
        conn, public = None, None
        try:
            if body.confirm:
                conn, public = gitops_service.connector(p.get("provider"), p.get("connection_id"))
            elif p.get("provider"):
                public = gitops_service.find_connection(p["provider"], p.get("connection_id"))[0]  # only to name it in the preview; nothing is built or contacted
        except ValueError as exc:
            raise bad(exc) from exc
        try:
            out = proposals.open_pr(proposal_id, user["email"], confirm=body.confirm, connector=conn, connection_name=(public or {}).get("name"), findings=live() if body.confirm else None)
        except KeyError as exc:
            raise bad(exc, 404) from exc
        except ValueError as exc:
            raise bad(exc, 409) from exc
        if body.confirm:
            activity_log.record_activity(user["email"], "gitops.proposal.open", str(proposal_id), {"repo": p["repo"], "pr": out.get("pr_url")})
        return out

    @r.post("/api/gitops/sync")
    def api_gitops_sync(user: dict = Depends(rbac.require_admin)):
        """Ask the Git host for the state of every open pull request, then re-check merged ones against the latest scan."""
        cache = {}
        report = proposals.sync(lambda p: gitops_service.connector_for_proposal(p, cache=cache))
        verified = proposals.verify_all(live())
        activity_log.record_activity(user["email"], "gitops.sync", None, {"checked": len(report), "verified": len(verified)})
        return {"synced": report, "verification": verified}

    @r.post("/api/gitops/verify")
    def api_gitops_verify(user: dict = Depends(rbac.require_login)):  # noqa: ARG001
        return {"verification": proposals.verify_all(live())}

    @r.post("/api/inbound/pr-status")
    def api_inbound_pr(body: InboundPrBody, key: dict = Depends(require_api_key("tickets:update"))):
        """For a Git host webhook or a CI job to report that a Quanta pull request was merged or closed. `proposal` is the proposal number or the pull request URL."""
        try:
            p = proposals.record_external(body.proposal, body.state, body.merged_at, f"apikey:{key['name']}")
        except KeyError as exc:
            raise bad(exc, 404) from exc
        except ValueError as exc:
            raise bad(exc) from exc
        return {"id": p["id"], "status": p["status"], "merged_at": p["merged_at"]}

    @r.get("/api/gitops/velocity")
    def api_velocity(user: dict = Depends(rbac.require_login)):  # noqa: ARG001
        return velocity.compute(proposals.list_proposals(), live())

    # ---------------------------------------------------------------- release gate
    def _gate(application, environment, findings, actor):
        app = app_store.get_application(application)
        name = app["name"] if app else application
        env = environment or (app or {}).get("environment")
        mine = analysis.app_findings(name, findings)
        runs = [x for x in dso_controls.scan_runs() if app_store.norm(x["asset"]) == app_store.norm(name)]
        sb = app_store.sbom_summaries().get(name)
        res = dso_gates.evaluate(name, env or "", mine, runs, sb)
        res["application_known"] = app is not None
        dso_gates.record(res, actor)
        return res

    @r.get("/api/gate/evaluate")
    def api_gate_ci(application: str, environment: str | None = None, key: dict = Depends(require_api_key("read:findings"))):
        """For a CI job. Answers pass, warn or fail with the reasons; the job decides what to do with it (see the Pipeline gates page for the step to paste)."""
        if not application.strip() or len(application) > 120:
            raise HTTPException(status_code=400, detail="Name the application")
        return _gate(application.strip(), environment, live(), f"apikey:{key['name']}")

    @r.post("/api/pipeline-gates/evaluate")
    def api_gate_page(body: GateBody, user: dict = Depends(rbac.require_login)):
        return _gate(body.application.strip(), body.environment, scope_findings(live(), user), user["email"])

    @r.get("/api/pipeline-gates")
    def api_gate_info(request: Request, application: str | None = None, user: dict = Depends(rbac.require_login)):  # noqa: ARG001
        pol = dso_gates.load()
        base = str(request.base_url).rstrip("/")
        return {"policy": {k: pol[k] for k in ("default_environment", "rules", "environments")}, "version": pol["_version"], "history": dso_gates.history(application, 50),
                "snippets": dso_gates.snippets(base, application or "your-application", pol["default_environment"]),
                "applications": [a["name"] for a in app_store.list_applications()]}

    # ---------------------------------------------------------------- secure design assistant
    @r.get("/api/secure-design/questions")
    def api_design_questions(user: dict = Depends(rbac.require_login)):  # noqa: ARG001
        return {"questions": dso_design.questions()}

    @r.post("/api/secure-design/assess")
    def api_design_assess(body: AssessBody, format: str = "json", user: dict = Depends(rbac.require_login)):  # noqa: ARG001
        try:
            res = dso_design.assess(body.answers, dso_controls.full_library())
        except ValueError as exc:
            raise bad(exc) from exc
        if format == "markdown":
            return PlainTextResponse(dso_design.to_markdown(body.name[:100], res), media_type="text/markdown")
        return res

    # ---------------------------------------------------------------- the organisation's own controls
    @r.put("/api/devsecops/custom-controls/{control_id}")
    def api_custom_control_put(control_id: str, body: CustomControlBody, user: dict = Depends(rbac.require_admin)):
        try:
            c = dso_controls.save_custom_control(control_id, body.model_dump(), user["email"])
        except ValueError as exc:
            raise bad(exc) from exc
        activity_log.record_activity(user["email"], "devsecops.custom-control.save", control_id, {})
        return c

    @r.delete("/api/devsecops/custom-controls/{control_id}")
    def api_custom_control_delete(control_id: str, user: dict = Depends(rbac.require_admin)):
        if not dso_controls.delete_custom_control(control_id):
            raise HTTPException(status_code=404, detail="No such custom control")
        activity_log.record_activity(user["email"], "devsecops.custom-control.delete", control_id, {})
        return {"ok": True}

    return r
