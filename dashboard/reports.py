"""
On-demand report generation for the dashboard's /reports page and /api/reports/*
endpoints. Real data, real computation - nothing here fabricates a number.

Honest limitation: the `period` parameter (daily/weekly/monthly/quarterly/half-yearly/
yearly) labels the report's intended cadence, but this MVP has no persistence layer
(see KNOWLEDGE_TRANSFER.md's roadmap) - there is no history of past runs to aggregate.
Every period therefore summarizes the same real, current-moment snapshot rather than
actual historical data for that window. A production version would query a real
findings-history database for the requested date range; today, `period` is exactly the
parameter a real scheduler (cron/CI) would pass once that exists. Documented here
rather than faked with invented trend numbers.
"""
import datetime
import html

from remediation.inventory import asset_inventory

VALID_PERIODS = ("daily", "weekly", "monthly", "quarterly", "half-yearly", "yearly")

# Matches this app's existing scan_type taxonomy (remediation/enrichment/
# scan_type_mapping.py) - "all" is the whole landscape, anything else scopes a report to
# that one sub-domain. "sast" is deliberately excluded, same reason scan_type_mapping.py
# excludes it from QUEUE_SCAN_TYPES: /queue (and therefore this report) never tags a
# finding "sast" - those live only in the separate /vulnhunt data path, which a scoped
# (sub-domain/team) report can't meaningfully include (see the scope_note below).
VALID_SCOPES = ("all", "infra-vm", "sca", "cert-mgmt", "dast", "iac", "secrets", "runtime", "ai-ml")


def _scope_findings(findings, scope, team):
    result = findings
    if scope != "all":
        result = [f for f in result if f.get("scan_type") == scope]
    if team:
        # Loaded lazily, only when a team filter is actually requested - keeps
        # scope="all"/team=None (the common case, and every stub-based unit test) fully
        # isolated from the real asset_ownership.json file on disk.
        ownership = asset_inventory.load_ownership()
        result = [
            f for f in result
            if (ownership.get((f.get("asset") or {}).get("name")) or {}).get("team") == team
        ]
    return result


def generate_report_data(period, data_module, scope="all", team=None):
    """Pure(ish) function over dashboard_data's read-only loaders - no writes, no
    network. `data_module` is injected (rather than imported here) so tests can pass a
    fake/stub module without touching real artifacts on disk.

    `scope` (one of VALID_SCOPES) and `team` (a team name from
    remediation/inventory/asset_ownership.json, or None) narrow the report to one
    security sub-domain and/or one team's owned assets - "sub-domain, team-wise"
    reporting. Landscape-wide (scope="all", team=None) reproduces the original
    unscoped report exactly. A scoped report necessarily excludes SAST/Code Scan
    findings (no scan_type/team association in that data path - see VALID_SCOPES) and
    the static REMEDIATION_PLAN.md risk-tier snapshot/playbook count (both are
    whole-pipeline artifacts, not filterable by sub-domain or team) - disclosed via
    `scope_note` rather than silently zeroed."""
    if period not in VALID_PERIODS:
        raise ValueError(f"period must be one of {VALID_PERIODS}, got {period!r}")
    if scope not in VALID_SCOPES:
        raise ValueError(f"scope must be one of {VALID_SCOPES}, got {scope!r}")

    live_queue = data_module.load_live_queue()
    scoped = _scope_findings(live_queue, scope, team)
    is_landscape_wide = scope == "all" and not team

    sla = data_module.sla_summary(scoped)
    top_priority = [
        {
            "id": f.get("id"),
            "title": f.get("title"),
            "priority": f.get("priority"),
            "asset": (f.get("asset") or {}).get("name"),
        }
        for f in scoped[:5]
    ]

    vh = data_module.load_vulnhunt_data() if is_landscape_wide else {"total": 0, "auto_fixable": 0}
    plan = data_module.load_remediation_plan() if is_landscape_wide else {}
    playbooks = data_module.load_playbooks() if is_landscape_wide else []

    scope_note = None
    if not is_landscape_wide:
        scope_note = (
            "Scoped to " + (scope if scope != "all" else "all sub-domains")
            + (f", team \"{team}\"" if team else "")
            + " - excludes SAST/Code Scan findings (no team/sub-domain association in "
              "that data path) and the static REMEDIATION_PLAN.md risk-tier snapshot/"
              "playbook count (whole-pipeline artifacts, not filterable this way)."
        )

    return {
        "period": period,
        "scope": scope,
        "team": team,
        "scope_note": scope_note,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "sla": sla,
        "kev_count": data_module.count_kev_listed(scoped),
        "high_epss_count": data_module.count_high_epss(scoped),
        "vulnhunt_total": vh.get("total", 0),
        "vulnhunt_auto_fixable": vh.get("auto_fixable", 0),
        "remediation_total": len(scoped),
        "playbook_count": len(playbooks),
        "risk_tier_counts": plan.get("risk_tier_counts", {}),
        "asset_type_breakdown": data_module.asset_type_breakdown(scoped),
        "top_priority_findings": top_priority,
    }


def _row(label, value):
    return f'<tr><td class="label">{html.escape(str(label))}</td><td class="value">{html.escape(str(value))}</td></tr>'


def report_title(report):
    period_title = report["period"].replace("-", " ").title()
    scope_bit = "" if report.get("scope", "all") == "all" else f" - {report['scope']}"
    team_bit = f" - {report['team']}" if report.get("team") else ""
    return f"VulnHunter {period_title} Security Report{scope_bit}{team_bit}"


def render_report_html(report):
    """Renders a self-contained HTML document (inline CSS only) so it's a sensible
    standalone download, independent of dashboard/static/style.css."""
    risk_rows = "".join(_row(tier, count) for tier, count in report["risk_tier_counts"].items())
    asset_rows = "".join(_row(atype, count) for atype, count in report["asset_type_breakdown"].items())
    top_rows = "".join(
        f'<tr><td>{html.escape(f["id"] or "")}</td><td>{html.escape(f["priority"] or "")}</td>'
        f'<td>{html.escape(f["asset"] or "")}</td><td>{html.escape(f["title"] or "")}</td></tr>'
        for f in report["top_priority_findings"]
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(report_title(report))}</title>
<style>
  html {{ background: #ffffff; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
          max-width: 820px; margin: 40px auto; padding: 0 20px; color: #14171a;
          background: #ffffff; }}
  h1 {{ margin-bottom: 4px; }}
  .meta {{ color: #6b7280; font-size: 0.9rem; margin-bottom: 28px; }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
               gap: 12px; margin-bottom: 28px; }}
  .kpi {{ border: 1px solid #e2e4e8; border-radius: 8px; padding: 14px; }}
  .kpi .n {{ font-size: 1.6rem; font-weight: 700; }}
  .kpi .l {{ color: #6b7280; font-size: 0.82rem; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 28px; font-size: 0.9rem; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #e2e4e8; }}
  th {{ background: #fafbfc; color: #6b7280; font-weight: 600; }}
  td.label {{ color: #6b7280; }}
  .caveat {{ background: #fef3c7; color: #92400e; border-radius: 8px; padding: 12px 16px;
             font-size: 0.85rem; margin-bottom: 28px; }}
</style>
</head>
<body>
  <h1>{html.escape(report_title(report))}</h1>
  <p class="meta">Generated {html.escape(report["generated_at"])} UTC</p>

  <div class="caveat">
    This MVP has no persistence layer yet, so every report period currently summarizes
    the same real, current-moment snapshot rather than aggregating actual historical
    data for that window - see KNOWLEDGE_TRANSFER.md's roadmap. All figures below are
    real, live-computed values, not placeholders.
  </div>

  {f'<div class="caveat">{html.escape(report["scope_note"])}</div>' if report.get("scope_note") else ""}

  <div class="kpi-grid">
    <div class="kpi"><div class="n">{report["sla"]["breached"]}</div><div class="l">SLA breached</div></div>
    <div class="kpi"><div class="n">{report["sla"]["at_risk"]}</div><div class="l">SLA at risk</div></div>
    <div class="kpi"><div class="n">{report["sla"]["on_track"]}</div><div class="l">SLA on track</div></div>
    <div class="kpi"><div class="n">{report["kev_count"]}</div><div class="l">CISA KEV-listed</div></div>
    <div class="kpi"><div class="n">{report["high_epss_count"]}</div><div class="l">High EPSS</div></div>
    <div class="kpi"><div class="n">{report["remediation_total"]}</div><div class="l">Infra findings</div></div>
    <div class="kpi"><div class="n">{report["vulnhunt_total"]}</div><div class="l">Code vulnerabilities</div></div>
    <div class="kpi"><div class="n">{report["playbook_count"]}</div><div class="l">Playbooks generated</div></div>
  </div>

  <h2>Top priority findings</h2>
  <table>
    <thead><tr><th>ID</th><th>Priority</th><th>Asset</th><th>Title</th></tr></thead>
    <tbody>{top_rows}</tbody>
  </table>

  <h2>Risk tier breakdown</h2>
  <table><tbody>{risk_rows}</tbody></table>

  <h2>Coverage by asset class</h2>
  <table><tbody>{asset_rows}</tbody></table>
</body>
</html>"""


def render_report_text(report):
    """Plain-text rendering of the same report - used as the email body's text/plain
    alternative (email_sender.send_email always needs a text part; body_html is the
    richer optional one)."""
    lines = [
        report_title(report),
        f"Generated {report['generated_at']} UTC",
        "",
    ]
    if report.get("scope_note"):
        lines += [report["scope_note"], ""]
    lines += [
        f"SLA breached: {report['sla']['breached']}",
        f"SLA at risk: {report['sla']['at_risk']}",
        f"SLA on track: {report['sla']['on_track']}",
        f"CISA KEV-listed: {report['kev_count']}",
        f"High EPSS: {report['high_epss_count']}",
        f"Findings in scope: {report['remediation_total']}",
        f"Code vulnerabilities (landscape-wide only): {report['vulnhunt_total']}",
        f"Playbooks generated (landscape-wide only): {report['playbook_count']}",
        "",
        "Top priority findings:",
    ]
    for f in report["top_priority_findings"]:
        lines.append(f"  - [{f['priority']}] {f['id']}: {f['title']} ({f['asset']})")
    if not report["top_priority_findings"]:
        lines.append("  (none)")
    lines += ["", "Risk tier breakdown:"]
    for tier, count in report["risk_tier_counts"].items():
        lines.append(f"  - {tier}: {count}")
    lines += ["", "Coverage by asset class:"]
    for atype, count in report["asset_type_breakdown"].items():
        lines.append(f"  - {atype}: {count}")
    return "\n".join(lines)
