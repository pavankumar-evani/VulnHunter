"""
VulnHunter Dashboard - a FastAPI JSON API plus a hand-rolled vanilla-JS single-page
frontend (static/index.html + static/js/*.js) reading the real generated artifacts
from both pipelines. No Node/npm/build step - see dashboard/README.md for why, and
what a production version would add on top of this.

Run with: python dashboard/app.py
Then open http://127.0.0.1:5050
"""
import json
import secrets
import subprocess
import sys
from pathlib import Path

import uvicorn
import yaml
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "cli"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ai_assist  # noqa: E402
import data as dashboard_data  # noqa: E402
import reports  # noqa: E402
import vulnhunter as cli  # noqa: E402
from auth import oidc, rbac, sessions  # noqa: E402
from auth import users as auth_users  # noqa: E402
from remediation.connectors.generic_connector import (  # noqa: E402
    normalize_generic_finding, validate_generic_payload,
)
from remediation.connectors.jira_connector import (  # noqa: E402
    DEFAULT_ISSUE_TYPE as JIRA_DEFAULT_ISSUE_TYPE, JiraConnector, build_issue_body,
)
from remediation.connectors.servicenow_connector import (  # noqa: E402
    ServiceNowConnector, build_incident_body,
)
from remediation.connectors.splunk_connector import (  # noqa: E402
    DEFAULT_SOURCETYPE as SPLUNK_DEFAULT_SOURCETYPE, SplunkConnector, build_hec_event,
)
from remediation.enrichment.ai_vuln_taxonomy import (  # noqa: E402
    AI_VULNERABILITIES, build_ai_atlas_heatmap, tag_findings as tag_ai_vulnerabilities,
)
from remediation.enrichment.attack_mapping import build_attack_heatmap  # noqa: E402
from remediation.exceptions import store as exceptions_store  # noqa: E402
from remediation.inventory import asset_inventory, cmdb_import, pattern_recognition  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="VulnHunter Dashboard API", version="1.0.0")


# ---------------------------------------------------------------------------
# JSON API - the frontend's only source of data. Every function below stays a
# thin adapter over dashboard_data / cli / the ServiceNow connector; none of
# them contain business logic of their own (same rule the old Flask routes
# followed).
# ---------------------------------------------------------------------------

@app.get("/api/overview")
def api_overview():
    findings = dashboard_data.load_remediation_findings()
    vh = dashboard_data.load_vulnhunt_data()
    plan = dashboard_data.load_remediation_plan()
    playbooks = dashboard_data.load_playbooks()
    eligible = [f for f in findings if f.get("remediation_domain")]
    manual_only = [f for f in findings if not f.get("remediation_domain")]
    live_queue = dashboard_data.load_live_queue()

    return {
        "sla": dashboard_data.sla_summary(live_queue),
        "kev_count": dashboard_data.count_kev_listed(findings),
        "high_epss_count": dashboard_data.count_high_epss(findings),
        "vulnhunt": {"total": vh.get("total", 0), "auto_fixable": vh.get("auto_fixable", 0)},
        "remediation": {
            "total": len(findings),
            "eligible": len(eligible),
            "manual_only": len(manual_only),
        },
        "playbook_count": len(playbooks),
        "plan": {
            "available": plan.get("available", False),
            "risk_tier_counts": plan.get("risk_tier_counts", {}),
        },
        "asset_type_breakdown": dashboard_data.asset_type_breakdown(findings),
        "priority_rules": dashboard_data.sla_and_priority_definitions(),
    }


@app.get("/api/vulnhunt")
def api_vulnhunt():
    return dashboard_data.load_vulnhunt_data()


@app.get("/api/remediate")
def api_remediate():
    findings = dashboard_data.load_remediation_findings()
    plan = dashboard_data.load_remediation_plan()
    playbooks = dashboard_data.load_playbooks()
    playbooks_by_finding = {p["finding_id"]: p["filename"] for p in playbooks if p["finding_id"]}
    return {"findings": findings, "plan": plan, "playbooks_by_finding": playbooks_by_finding}


@app.get("/api/playbooks/{filename}")
def api_playbook_detail(filename: str):
    playbooks = {p["filename"]: p for p in dashboard_data.load_playbooks()}
    playbook = playbooks.get(filename)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return playbook


@app.get("/api/queue")
def api_queue():
    scored = dashboard_data.load_live_queue()
    return {"findings": scored, "sla": dashboard_data.sla_summary(scored)}


@app.get("/api/notifications")
def api_notifications():
    scored = dashboard_data.load_live_queue()
    return {"notifications": dashboard_data.build_notifications(scored)}


@app.get("/api/priority-rules")
def api_get_priority_rules():
    return {"rules_text": dashboard_data.load_priority_rules_text()}


class PriorityRulesBody(BaseModel):
    rules_text: str


@app.post("/api/priority-rules")
def api_save_priority_rules(body: PriorityRulesBody, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    try:
        dashboard_data.save_priority_rules_text(body.rules_text)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Not saved - invalid YAML: {exc}") from exc
    return {
        "message": "Priority rules saved. The live queue and SLA dashboard now reflect "
                    "these weights.",
    }


@app.get("/api/servicenow/preview")
def api_servicenow_preview():
    findings = dashboard_data.load_remediation_findings()
    return {"previews": [{"finding_id": f["id"], "body": build_incident_body(f)} for f in findings]}


class ServiceNowSendBody(BaseModel):
    instance: str = ""
    username: str = ""
    password: str = ""
    table: str = "incident"
    confirm: bool = False


@app.post("/api/servicenow/send")
def api_servicenow_send(body: ServiceNowSendBody, request: Request):
    findings = dashboard_data.load_remediation_findings()
    previews = [{"finding_id": f["id"], "body": build_incident_body(f)} for f in findings]

    if not body.confirm:
        return {
            "preview_only": True,
            "message": "Preview only (nothing was sent to ServiceNow). Check confirm and "
                       "provide real credentials to actually create incidents.",
            "previews": previews,
            "results": None,
        }

    # Only the real-send path (confirm=True) requires login - preview is exactly as
    # open as the read-only /api/queue data it's built from, so it stays ungated.
    rbac.require_admin(request)

    if not body.instance or not body.username or not body.password:
        raise HTTPException(
            status_code=400,
            detail="Instance, username, and password are all required to actually push to ServiceNow.",
        )

    conn = ServiceNowConnector(body.instance, body.username, body.password, table=body.table)
    try:
        results = conn.create_incidents_for_findings(findings)
    except Exception as exc:  # noqa: BLE001 - surface any connection failure to the caller
        raise HTTPException(status_code=502, detail=f"ServiceNow request failed: {exc}") from exc

    return {
        "preview_only": False,
        "message": f"Attempted {len(results)} incident(s) against "
                   f"{body.instance}.service-now.com/{body.table}.",
        "previews": previews,
        "results": results,
    }


# A placeholder project key used only so /api/jira/preview can show a real, well-formed
# issue body with zero credentials required - build_issue_body() has no default project
# key of its own since a real send always needs the caller's actual one.
_JIRA_PREVIEW_PROJECT_KEY = "VULN"


@app.get("/api/jira/preview")
def api_jira_preview():
    findings = dashboard_data.load_remediation_findings()
    return {
        "previews": [
            {"finding_id": f["id"], "body": build_issue_body(f, _JIRA_PREVIEW_PROJECT_KEY)}
            for f in findings
        ],
    }


class JiraSendBody(BaseModel):
    base_url: str = ""
    email: str = ""
    api_token: str = ""
    project_key: str = ""
    issue_type: str = JIRA_DEFAULT_ISSUE_TYPE
    confirm: bool = False


@app.post("/api/jira/send")
def api_jira_send(body: JiraSendBody, request: Request):
    findings = dashboard_data.load_remediation_findings()
    preview_key = body.project_key or _JIRA_PREVIEW_PROJECT_KEY
    previews = [
        {"finding_id": f["id"], "body": build_issue_body(f, preview_key, body.issue_type)}
        for f in findings
    ]

    if not body.confirm:
        return {
            "preview_only": True,
            "message": "Preview only (nothing was sent to Jira). Check confirm and provide "
                       "a real site URL, email, API token, and project key to actually create issues.",
            "previews": previews,
            "results": None,
        }

    rbac.require_admin(request)

    if not body.base_url or not body.email or not body.api_token or not body.project_key:
        raise HTTPException(
            status_code=400,
            detail="Site URL, email, API token, and project key are all required to actually push to Jira.",
        )

    conn = JiraConnector(body.base_url, body.email, body.api_token, body.project_key)
    try:
        results = conn.create_issues_for_findings(findings)
    except Exception as exc:  # noqa: BLE001 - surface any connection failure to the caller
        raise HTTPException(status_code=502, detail=f"Jira request failed: {exc}") from exc

    return {
        "preview_only": False,
        "message": f"Attempted {len(results)} issue(s) against {body.base_url} ({body.project_key}).",
        "previews": previews,
        "results": results,
    }


@app.get("/api/splunk/preview")
def api_splunk_preview():
    findings = dashboard_data.load_remediation_findings()
    return {
        "previews": [
            {"finding_id": f["id"], "body": build_hec_event(f)}
            for f in findings
        ],
    }


class SplunkSendBody(BaseModel):
    hec_url: str = ""
    hec_token: str = ""
    sourcetype: str = SPLUNK_DEFAULT_SOURCETYPE
    index: str = ""
    confirm: bool = False


@app.post("/api/splunk/send")
def api_splunk_send(body: SplunkSendBody, request: Request):
    findings = dashboard_data.load_remediation_findings()
    index = body.index or None
    previews = [
        {"finding_id": f["id"], "body": build_hec_event(f, sourcetype=body.sourcetype, index=index)}
        for f in findings
    ]

    if not body.confirm:
        return {
            "preview_only": True,
            "message": "Preview only (nothing was sent to Splunk). Check confirm and provide "
                       "a real HEC URL and token to actually send events.",
            "previews": previews,
            "results": None,
        }

    rbac.require_admin(request)

    if not body.hec_url or not body.hec_token:
        raise HTTPException(
            status_code=400,
            detail="HEC URL and token are both required to actually send events to Splunk.",
        )

    conn = SplunkConnector(body.hec_url, body.hec_token)
    try:
        results = conn.send_events_for_findings(findings, sourcetype=body.sourcetype, index=index)
    except Exception as exc:  # noqa: BLE001 - surface any connection failure to the caller
        raise HTTPException(status_code=502, detail=f"Splunk HEC request failed: {exc}") from exc

    return {
        "preview_only": False,
        "message": f"Attempted {len(results)} event(s) against {body.hec_url}.",
        "previews": previews,
        "results": results,
    }


@app.get("/api/run")
def api_run_get():
    return {
        "audit_log": dashboard_data.load_cli_audit_log_summaries(),
        "default_budget": cli.DEFAULT_MAX_BUDGET_USD,
    }


class RunBody(BaseModel):
    pipeline: str
    fix_or_generate: bool = False
    path: str = "vulnerable-demo-app"
    max_budget_usd: str = cli.DEFAULT_MAX_BUDGET_USD
    confirm: bool = False


@app.post("/api/run")
def api_run_post(body: RunBody, request: Request):
    if body.pipeline == "scan":
        prompt = cli.scan_prompt(body.path, fix=body.fix_or_generate)
        pipeline_name = "vulnhunt"
    elif body.pipeline == "remediate":
        prompt = cli.remediate_prompt(generate=body.fix_or_generate)
        pipeline_name = "remediate"
    else:
        raise HTTPException(status_code=400, detail="Unknown pipeline selected.")

    dry_run = not body.confirm
    if not dry_run:
        rbac.require_admin(request)
    exit_code = cli.run(prompt, pipeline_name, dry_run=dry_run, max_budget_usd=body.max_budget_usd)

    if dry_run:
        message = ("Dry run only (nothing was executed, no API usage spent). "
                    "Set confirm to actually run it.")
    elif exit_code == 0:
        message = f"{pipeline_name} run completed. Reload the relevant page to see updated results."
    else:
        message = f"{pipeline_name} run failed (exit code {exit_code}). Check the audit log for details."

    return {"dry_run": dry_run, "exit_code": exit_code, "message": message}


def _find_any_finding(finding_id):
    """Looks up a finding by ID across both pipelines' output - the remediation
    findings (FIND-N) and the code-scan findings (VULN-N), reshaped into a common
    minimal shape so ai_assist.build_ai_assist_prompt() can treat either uniformly."""
    for f in dashboard_data.load_remediation_findings():
        if f.get("id") == finding_id:
            return f
    vh = dashboard_data.load_vulnhunt_data()
    for f in vh.get("findings", []):
        if f.get("ID") == finding_id:
            return {
                "id": f.get("ID"),
                "title": f.get("Title"),
                "severity": f.get("Severity"),
                "cve": None,
                "asset": {"name": f.get("File"), "type": "source-code"},
                "description": f"{f.get('CWE', '')} finding in {f.get('File', '')}".strip(),
            }
    return None


class AiAssistBody(BaseModel):
    finding_id: str
    action: str = "explain"
    confirm: bool = False


@app.post("/api/ai-assist")
def api_ai_assist(body: AiAssistBody, request: Request):
    """Same dry-run-preview-by-default / explicit-confirm-to-spend pattern as /api/run
    and /api/servicenow/send: without confirm, this only builds and returns the prompt
    text, at zero cost. With confirm, it calls the real `claude` CLI (same binary
    discovery as cli/vulnhunter.py) and spends real API usage/credits."""
    finding = _find_any_finding(body.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding {body.finding_id} not found")
    if body.action not in ai_assist.ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"action must be one of {ai_assist.ACTIONS}, got {body.action!r}",
        )

    prompt = ai_assist.build_ai_assist_prompt(finding, body.action)

    if not body.confirm:
        return {
            "dry_run": True,
            "prompt": prompt,
            "message": "Preview only (no API call made). Set confirm to actually ask "
                       "the AI - this spends real API usage/credits.",
        }

    rbac.require_admin(request)

    try:
        claude_bin = cli.find_claude_binary()
    except cli.ClaudeBinaryNotFound as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    command = [claude_bin, "-p", prompt, "--output-format", "text"]
    result = subprocess.run(  # noqa: S603 - fixed binary + a prompt string, no shell
        command, cwd=cli.REPO_ROOT, capture_output=True, text=True, encoding="utf-8",
    )
    if result.returncode != 0:
        raise HTTPException(
            status_code=502,
            detail=f"AI assist call failed: {result.stderr.strip()[:500]}",
        )

    return {"dry_run": False, "prompt": prompt, "response": result.stdout.strip()}


@app.get("/api/reports/generate")
def api_generate_report(period: str = "weekly"):
    try:
        return reports.generate_report_data(period, dashboard_data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/reports/generate.html", response_class=HTMLResponse)
def api_generate_report_html(period: str = "weekly", download: bool = False):
    try:
        data = reports.generate_report_data(period, dashboard_data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    html_body = reports.render_report_html(data)
    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="vulnhunter-{period}-report.html"'
    return HTMLResponse(content=html_body, headers=headers)


@app.get("/api/exceptions")
def api_list_exceptions():
    return {"exceptions": exceptions_store.list_exceptions_with_status()}


class ExceptionCreateBody(BaseModel):
    finding_id: str
    reason: str
    requested_by: str
    approved_by: str
    expires_on: str


@app.post("/api/exceptions")
def api_create_exception(body: ExceptionCreateBody, user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    try:
        record = exceptions_store.create_exception(
            body.finding_id, body.reason, body.requested_by, body.approved_by, body.expires_on,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return record


@app.post("/api/exceptions/{exception_id}/revoke")
def api_revoke_exception(exception_id: str, user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
    try:
        return exceptions_store.revoke_exception(exception_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/assets")
def api_list_assets():
    findings = dashboard_data.load_remediation_findings()
    rows = asset_inventory.build_asset_inventory(findings)
    # A pattern-matching (not ML - see pattern_recognition.py's module docstring)
    # suggested owner/team for assets that don't have one yet, so the "Edit owner"
    # form isn't always starting from a blank slate. `known` only ever includes
    # already-owned assets - never used to suggest an owner for itself.
    known = [r for r in rows if r.get("owner")]
    for row in rows:
        row["suggestion"] = None if row.get("owner") else pattern_recognition.suggest_owner_team(row, known)
    return {"assets": rows}


class AssetOwnerBody(BaseModel):
    owner: str = ""
    team: str = ""


@app.post("/api/assets/{asset_name}/owner")
def api_set_asset_owner(asset_name: str, body: AssetOwnerBody, user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    return asset_inventory.set_owner(asset_name, body.owner, body.team)


class AssetFacingBody(BaseModel):
    facing: str


@app.post("/api/assets/{asset_name}/facing")
def api_set_asset_facing(asset_name: str, body: AssetFacingBody, user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    try:
        return asset_inventory.set_facing(asset_name, body.facing)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class CmdbImportPreviewBody(BaseModel):
    csv_text: str
    column_mapping: dict | None = None


@app.post("/api/assets/cmdb-import/preview")
def api_cmdb_import_preview(body: CmdbImportPreviewBody):
    """Read-only - parses and reconciles the uploaded CSV against the real,
    finding-derived asset list but writes nothing. See cmdb_import.py's module
    docstring for why this is CSV, not a fabricated .xlsx binary parser."""
    headers, rows = cmdb_import.parse_csv_text(body.csv_text)
    mapping = body.column_mapping or cmdb_import.suggest_column_mapping(headers)
    known_names = [a["name"] for a in asset_inventory.build_asset_inventory(dashboard_data.load_remediation_findings())]
    reconciled = cmdb_import.reconcile_rows(rows, mapping, known_names)
    return {"headers": headers, "column_mapping": mapping, **reconciled}


class CmdbImportApplyBody(BaseModel):
    entries: list[dict]


@app.post("/api/assets/cmdb-import/apply")
def api_cmdb_import_apply(body: CmdbImportApplyBody, user: dict = Depends(rbac.require_login)):  # noqa: ARG001
    return cmdb_import.apply_import(body.entries)


@app.get("/api/risk/attack-heatmap")
def api_risk_attack_heatmap():
    queue = dashboard_data.load_live_queue()
    return {"heatmap": build_attack_heatmap(queue)}


@app.get("/api/ai-vulnerabilities")
def api_ai_vulnerabilities():
    """Real findings tagged against the AI/ML vulnerability taxonomy (illustrative
    MITRE ATLAS cross-reference - see ai_vuln_taxonomy.py's module docstring), plus
    the full taxonomy reference (summary/remediation per category) regardless of
    whether any finding matched it. Honest expectation: this repo's demo data has no
    AI/ML component, so `heatmap` will show all zero counts - not faked."""
    findings = tag_ai_vulnerabilities(dashboard_data.load_remediation_findings())
    return {"vulnerabilities": AI_VULNERABILITIES, "heatmap": build_ai_atlas_heatmap(findings)}


class GenericIngestBody(BaseModel):
    findings: list[dict]


@app.post("/api/ingest/generic")
def api_ingest_generic(body: GenericIngestBody):
    """The vendor-agnostic 'bring your own XDR/EDR/SIEM' webhook receiver - see
    remediation/connectors/generic_connector.py's module docstring for why this is a
    generic validated-payload adapter rather than N bespoke vendor connectors.
    Deliberately does NOT merge into remediation/output/normalized-findings.json or
    the live queue - consistent with how live Tenable/Armis connector output also
    isn't auto-merged (see KNOWLEDGE_TRANSFER.md); it writes to
    remediation/live-data/, gitignored, same as those.

    Deliberately NOT gated behind session login, unlike the mutation routes below -
    this is a machine-to-machine webhook receiver a SIEM/XDR would call directly, not
    something a logged-in browser session submits. A real deployment should protect it
    with a webhook-specific API key or HMAC request signature instead of cookie auth -
    that's a real follow-up, not implemented here. Being unauthenticated also means
    there's no cap on how often it's called or how large remediation/live-data/
    generic-ingested.json can grow (each call re-reads and rewrites the whole file) -
    a real deployment needs request throttling/a size cap alongside the auth mentioned
    above, not implemented here either."""
    live_data_dir = dashboard_data.REPO_ROOT / "remediation" / "live-data"
    live_data_path = live_data_dir / "generic-ingested.json"

    existing = []
    if live_data_path.exists():
        existing = json.loads(live_data_path.read_text(encoding="utf-8"))

    # IDs continue from the real pipeline's FIND-N sequence (not just this file's own),
    # even though this data isn't merged into the queue - so a ingested finding's ID
    # never collides with a real one if this ever does get merged later.
    real_findings = dashboard_data.load_remediation_findings()

    accepted = []
    rejected = []
    for i, payload in enumerate(body.findings):
        errors = validate_generic_payload(payload)
        if errors:
            rejected.append({"index": i, "errors": errors})
            continue
        finding = normalize_generic_finding(payload, real_findings + existing + accepted)
        accepted.append(finding)

    if accepted:
        live_data_dir.mkdir(parents=True, exist_ok=True)
        live_data_path.write_text(
            json.dumps(existing + accepted, indent=2) + "\n", encoding="utf-8",
        )

    return {"accepted": len(accepted), "rejected": rejected, "findings": accepted}


# ---------------------------------------------------------------------------
# Auth - local login MVP + OIDC-ready SSO. See dashboard/auth/__init__.py for the full
# design (PBKDF2 password hashing, signed-cookie sessions, the OIDC client) and the
# scope decision on which routes above actually require login (Depends(rbac.require_*)
# or an inline rbac.require_*(request) call on the confirm=True branch only).
# ---------------------------------------------------------------------------

class LoginBody(BaseModel):
    email: str
    password: str


@app.post("/api/auth/login")
def api_auth_login(body: LoginBody, response: Response):
    user = auth_users.verify_login(body.email, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    cookie_value = sessions.create_session_cookie(user, rbac.SESSION_SECRET)
    response.set_cookie(
        rbac.SESSION_COOKIE_NAME, cookie_value, httponly=True, samesite="lax",
        max_age=sessions.DEFAULT_MAX_AGE_SECONDS,
    )
    return {"user": user}


@app.post("/api/auth/logout")
def api_auth_logout(response: Response):
    response.delete_cookie(rbac.SESSION_COOKIE_NAME)
    return {"message": "Logged out."}


@app.get("/api/auth/me")
def api_auth_me(request: Request):
    return {"user": rbac.get_current_user(request)}


class ChangePasswordBody(BaseModel):
    new_password: str


@app.post("/api/auth/change-password")
def api_auth_change_password(body: ChangePasswordBody, user: dict = Depends(rbac.require_login)):
    try:
        auth_users.set_password(user["email"], body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "Password changed."}


@app.get("/api/auth/oidc/config")
def api_auth_oidc_config():
    """Tells the login page whether to show a "Sign in with SSO" button at all - see
    oidc.py's module docstring for why this stays disabled until a real provider's
    credentials are configured via environment variables."""
    configured = oidc.is_configured()
    return {"enabled": configured, "provider_name": oidc.provider_name() if configured else None}


# state -> PKCE code_verifier, in-memory only. Fine for a single-process dev server;
# a real multi-worker deployment needs this in a shared store (Redis, a DB row) instead,
# and should expire abandoned entries - neither done here, this is the MVP version.
_oidc_pending_logins = {}


@app.get("/api/auth/oidc/login")
def api_auth_oidc_login():
    if not oidc.is_configured():
        raise HTTPException(status_code=503, detail="OIDC is not configured on this server.")
    state = secrets.token_urlsafe(24)
    verifier, challenge = oidc.generate_pkce_pair()
    _oidc_pending_logins[state] = verifier
    return RedirectResponse(oidc.build_authorize_url(state, challenge))


@app.get("/api/auth/oidc/callback")
def api_auth_oidc_callback(code: str, state: str):
    if not oidc.is_configured():
        raise HTTPException(status_code=503, detail="OIDC is not configured on this server.")
    verifier = _oidc_pending_logins.pop(state, None)
    if not verifier:
        raise HTTPException(
            status_code=400,
            detail="Unknown or expired OIDC login attempt - please try signing in again.",
        )
    try:
        token_response = oidc.exchange_code_for_token(code, verifier)
        userinfo = oidc.fetch_userinfo(token_response["access_token"])
    except Exception as exc:  # noqa: BLE001 - surface any provider/network failure
        raise HTTPException(status_code=502, detail=f"OIDC login failed: {exc}") from exc

    email = (userinfo.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(status_code=502, detail="OIDC provider did not return an email claim.")
    # Every OIDC-authenticated user lands as role "user", never "admin" - there's no
    # reliable, provider-agnostic way to know someone's real org role from a generic
    # userinfo claim set. A real deployment would map the IdP's own group/role claims
    # (which vary per provider) onto VulnHunter's admin/user roles; that mapping isn't
    # implemented here.
    user = {"email": email, "name": userinfo.get("name", email), "role": "user"}
    cookie_value = sessions.create_session_cookie(user, rbac.SESSION_SECRET)
    redirect = RedirectResponse("/")
    redirect.set_cookie(
        rbac.SESSION_COOKIE_NAME, cookie_value, httponly=True, samesite="lax",
        max_age=sessions.DEFAULT_MAX_AGE_SECONDS,
    )
    return redirect


@app.get("/api/status")
def api_status():
    """A trivial machine-readable health/status endpoint."""
    vh = dashboard_data.load_vulnhunt_data()
    findings = dashboard_data.load_remediation_findings()
    return {
        "status": "ok",
        "vulnhunt_available": vh.get("available", False),
        "vulnhunt_findings": vh.get("total", 0),
        "remediation_findings": len(findings),
        "remediation_playbooks": len(dashboard_data.load_playbooks()),
    }


# ---------------------------------------------------------------------------
# HTML shell - a single static/index.html served for every page route. All of
# these routes return byte-identical HTML; static/js/app.js reads
# window.location.pathname client-side and renders the right page by calling
# the JSON API above. This is what lets the frontend be a real SPA (client
# routing, no full-page reloads between pages) without any Node/npm/webpack -
# see "Why FastAPI + vanilla JS" in dashboard/README.md.
# ---------------------------------------------------------------------------

def _serve_shell():
    return FileResponse(STATIC_DIR / "index.html")


for _route in (
    "/", "/vulnhunt", "/remediate", "/run", "/queue", "/priority-rules", "/servicenow",
    "/jira", "/splunk", "/xdr", "/infoblox", "/axonius", "/ai-assist", "/reports", "/support", "/faq",
    "/exceptions", "/assets", "/appsec", "/infrastructure", "/inbox", "/risk", "/ai-vulnerabilities", "/login", "/profile",
    "/adaptors",
):
    app.api_route(_route, methods=["GET", "HEAD"], include_in_schema=False)(_serve_shell)


@app.api_route("/playbooks/{filename}", methods=["GET", "HEAD"], include_in_schema=False)
def playbook_page(filename: str):  # noqa: ARG001 - filename is read client-side from the URL
    return _serve_shell()


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.api_route("/{full_path:path}", methods=["GET", "HEAD"], include_in_schema=False)
def spa_fallback(full_path: str):
    """Anything not matched above (a stale bookmark, a typo'd URL) still gets the SPA
    shell - static/js/app.js's router renders a styled "Page not found" instead of a
    bare {"detail":"Not Found"} JSON blob. Registered last, so /static/* (StaticFiles'
    own 404) already wins by mount precedence; /api/* is excluded explicitly below so an
    unknown API path still gets a real JSON 404, not HTML."""
    if full_path == "api" or full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="Not Found")
    return _serve_shell()


if __name__ == "__main__":
    import os

    # Local dev HTTPS is opt-in via SSL_KEYFILE/SSL_CERTFILE env vars pointing at a
    # self-signed cert - see dashboard/README.md for the one-line openssl command to
    # generate one. Real deployments should terminate TLS at a reverse proxy
    # (nginx/Caddy) instead of running uvicorn's own TLS directly - also documented
    # there, along with why a self-signed cert is dev-only, never production.
    ssl_keyfile = os.environ.get("SSL_KEYFILE")
    ssl_certfile = os.environ.get("SSL_CERTFILE")
    uvicorn.run(
        app, host="127.0.0.1", port=5050,
        ssl_keyfile=ssl_keyfile, ssl_certfile=ssl_certfile,
    )
