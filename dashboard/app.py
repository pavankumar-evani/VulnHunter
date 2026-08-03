"""
VulnHunter Dashboard - MVP web UI reading the real generated artifacts from both
pipelines. Server-rendered (Flask + Jinja2), not a React SPA - see dashboard/README.md
for why, and what a production version would add on top of this.

Run with: python dashboard/app.py
Then open http://127.0.0.1:5050
"""
import sys
from pathlib import Path

from flask import Flask, render_template, abort, request, redirect, url_for, flash

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "cli"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import data as dashboard_data  # noqa: E402
import vulnhunter as cli  # noqa: E402
import yaml  # noqa: E402
from remediation.connectors.servicenow_connector import (  # noqa: E402
    ServiceNowConnector, build_incident_body,
)

app = Flask(__name__)
app.secret_key = "vulnhunter-dashboard-dev-only-not-for-production"


@app.route("/")
def overview():
    vh = dashboard_data.load_vulnhunt_data()
    findings = dashboard_data.load_remediation_findings()
    plan = dashboard_data.load_remediation_plan()
    playbooks = dashboard_data.load_playbooks()

    eligible = [f for f in findings if f.get("remediation_domain")]
    manual_only = [f for f in findings if not f.get("remediation_domain")]

    live_queue = dashboard_data.load_live_queue()
    sla = dashboard_data.sla_summary(live_queue)

    return render_template(
        "overview.html",
        vh=vh,
        remediation_total=len(findings),
        remediation_eligible=len(eligible),
        remediation_manual_only=len(manual_only),
        playbook_count=len(playbooks),
        plan=plan,
        kev_count=dashboard_data.count_kev_listed(findings),
        high_epss_count=dashboard_data.count_high_epss(findings),
        asset_type_breakdown=dashboard_data.asset_type_breakdown(findings),
        sla=sla,
    )


@app.route("/vulnhunt")
def vulnhunt_view():
    vh = dashboard_data.load_vulnhunt_data()
    return render_template("vulnhunt.html", vh=vh)


@app.route("/remediate")
def remediate_view():
    findings = dashboard_data.load_remediation_findings()
    plan = dashboard_data.load_remediation_plan()
    playbooks = dashboard_data.load_playbooks()
    playbooks_by_finding = {p["finding_id"]: p for p in playbooks if p["finding_id"]}
    return render_template(
        "remediate.html",
        findings=findings,
        plan=plan,
        playbooks=playbooks,
        playbooks_by_finding=playbooks_by_finding,
    )


@app.route("/playbooks/<filename>")
def playbook_detail(filename):
    playbooks = {p["filename"]: p for p in dashboard_data.load_playbooks()}
    playbook = playbooks.get(filename)
    if not playbook:
        abort(404)
    return render_template("playbook_detail.html", playbook=playbook)


@app.route("/run", methods=["GET", "POST"])
def run_pipeline():
    if request.method == "GET":
        audit_log = dashboard_data.load_cli_audit_log_summaries()
        return render_template("run.html", audit_log=audit_log,
                                default_budget=cli.DEFAULT_MAX_BUDGET_USD)

    pipeline = request.form.get("pipeline")
    fix_or_generate = request.form.get("fix_or_generate") == "on"
    confirmed = request.form.get("confirm") == "on"
    target_path = request.form.get("path", "vulnerable-demo-app").strip()
    max_budget = request.form.get("max_budget_usd", cli.DEFAULT_MAX_BUDGET_USD)

    if pipeline == "scan":
        prompt = cli.scan_prompt(target_path, fix=fix_or_generate)
        pipeline_name = "vulnhunt"
    elif pipeline == "remediate":
        prompt = cli.remediate_prompt(generate=fix_or_generate)
        pipeline_name = "remediate"
    else:
        flash("Unknown pipeline selected.", "error")
        return redirect(url_for("run_pipeline"))

    dry_run = not confirmed
    exit_code = cli.run(prompt, pipeline_name, dry_run=dry_run, max_budget_usd=max_budget)

    if dry_run:
        flash(
            f"Dry run only (nothing was executed, no API usage spent). "
            f"Check the 'I understand this spends real API usage' box to actually run it.",
            "info",
        )
    elif exit_code == 0:
        flash(f"{pipeline_name} run completed. Reload the relevant page to see updated results.", "success")
    else:
        flash(f"{pipeline_name} run failed (exit code {exit_code}). Check the audit log for details.", "error")

    return redirect(url_for("run_pipeline"))


@app.route("/queue")
def queue_view():
    """The LIVE remediation queue - re-scored on every request using whatever
    priority_rules.yaml currently says, with MITRE ATT&CK tags. Distinct from
    /remediate, which shows the static REMEDIATION_PLAN.md snapshot from the last
    agent run."""
    scored = dashboard_data.load_live_queue()
    sla = dashboard_data.sla_summary(scored)
    return render_template("queue.html", findings=scored, sla=sla)


@app.route("/priority-rules", methods=["GET", "POST"])
def priority_rules_view():
    if request.method == "GET":
        return render_template("priority_rules.html", rules_text=dashboard_data.load_priority_rules_text())

    rules_text = request.form.get("rules_text", "")
    try:
        dashboard_data.save_priority_rules_text(rules_text)
        flash("Priority rules saved. The live queue and SLA dashboard now reflect these weights.", "success")
    except yaml.YAMLError as exc:
        flash(f"Not saved - invalid YAML: {exc}", "error")
    return redirect(url_for("priority_rules_view"))


@app.route("/servicenow", methods=["GET", "POST"])
def servicenow_view():
    findings = dashboard_data.load_remediation_findings()

    if request.method == "GET":
        previews = [{"finding_id": f["id"], "body": build_incident_body(f)} for f in findings]
        return render_template("servicenow.html", previews=previews, results=None)

    instance = request.form.get("instance", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    table = request.form.get("table", "incident").strip() or "incident"
    confirmed = request.form.get("confirm") == "on"

    previews = [{"finding_id": f["id"], "body": build_incident_body(f)} for f in findings]

    if not confirmed:
        flash("Preview only (nothing was sent to ServiceNow). Check the confirm box "
              "and provide real credentials to actually create incidents.", "info")
        return render_template("servicenow.html", previews=previews, results=None)

    if not instance or not username or not password:
        flash("Instance, username, and password are all required to actually push to ServiceNow.", "error")
        return render_template("servicenow.html", previews=previews, results=None)

    conn = ServiceNowConnector(instance, username, password, table=table)
    try:
        results = conn.create_incidents_for_findings(findings)
        flash(f"Attempted {len(results)} incident(s) against {instance}.service-now.com/{table}.", "success")
    except Exception as exc:  # noqa: BLE001 - surface any connection failure to the user, not a 500 page
        flash(f"ServiceNow request failed: {exc}", "error")
        results = None

    return render_template("servicenow.html", previews=previews, results=results)


@app.route("/api/status")
def api_status():
    """A trivial machine-readable health/status endpoint - the seed of a real API layer."""
    vh = dashboard_data.load_vulnhunt_data()
    findings = dashboard_data.load_remediation_findings()
    return {
        "status": "ok",
        "vulnhunt_available": vh.get("available", False),
        "vulnhunt_findings": vh.get("total", 0),
        "remediation_findings": len(findings),
        "remediation_playbooks": len(dashboard_data.load_playbooks()),
    }


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=True)
