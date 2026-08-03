"""
VulnHunter Dashboard - a FastAPI JSON API plus a hand-rolled vanilla-JS single-page
frontend (static/index.html + static/js/*.js) reading the real generated artifacts
from both pipelines. No Node/npm/build step - see dashboard/README.md for why, and
what a production version would add on top of this.

Run with: python dashboard/app.py
Then open http://127.0.0.1:5050
"""
import subprocess
import sys
from pathlib import Path

import uvicorn
import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "cli"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ai_assist  # noqa: E402
import data as dashboard_data  # noqa: E402
import reports  # noqa: E402
import vulnhunter as cli  # noqa: E402
from remediation.connectors.servicenow_connector import (  # noqa: E402
    ServiceNowConnector, build_incident_body,
)

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


@app.get("/api/priority-rules")
def api_get_priority_rules():
    return {"rules_text": dashboard_data.load_priority_rules_text()}


class PriorityRulesBody(BaseModel):
    rules_text: str


@app.post("/api/priority-rules")
def api_save_priority_rules(body: PriorityRulesBody):
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
def api_servicenow_send(body: ServiceNowSendBody):
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
def api_run_post(body: RunBody):
    if body.pipeline == "scan":
        prompt = cli.scan_prompt(body.path, fix=body.fix_or_generate)
        pipeline_name = "vulnhunt"
    elif body.pipeline == "remediate":
        prompt = cli.remediate_prompt(generate=body.fix_or_generate)
        pipeline_name = "remediate"
    else:
        raise HTTPException(status_code=400, detail="Unknown pipeline selected.")

    dry_run = not body.confirm
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
def api_ai_assist(body: AiAssistBody):
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
    "/ai-assist", "/reports", "/support", "/faq",
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
    uvicorn.run(app, host="127.0.0.1", port=5050)
