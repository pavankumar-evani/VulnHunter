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

import data as dashboard_data  # noqa: E402
import vulnhunter as cli  # noqa: E402

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
