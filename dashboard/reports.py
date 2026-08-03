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

VALID_PERIODS = ("daily", "weekly", "monthly", "quarterly", "half-yearly", "yearly")


def generate_report_data(period, data_module):
    """Pure(ish) function over dashboard_data's read-only loaders - no writes, no
    network. `data_module` is injected (rather than imported here) so tests can pass a
    fake/stub module without touching real artifacts on disk."""
    if period not in VALID_PERIODS:
        raise ValueError(f"period must be one of {VALID_PERIODS}, got {period!r}")

    findings = data_module.load_remediation_findings()
    vh = data_module.load_vulnhunt_data()
    plan = data_module.load_remediation_plan()
    playbooks = data_module.load_playbooks()
    live_queue = data_module.load_live_queue()
    sla = data_module.sla_summary(live_queue)

    top_priority = [
        {
            "id": f.get("id"),
            "title": f.get("title"),
            "priority": f.get("priority"),
            "asset": (f.get("asset") or {}).get("name"),
        }
        for f in live_queue[:5]
    ]

    return {
        "period": period,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "sla": sla,
        "kev_count": data_module.count_kev_listed(findings),
        "high_epss_count": data_module.count_high_epss(findings),
        "vulnhunt_total": vh.get("total", 0),
        "vulnhunt_auto_fixable": vh.get("auto_fixable", 0),
        "remediation_total": len(findings),
        "playbook_count": len(playbooks),
        "risk_tier_counts": plan.get("risk_tier_counts", {}),
        "asset_type_breakdown": data_module.asset_type_breakdown(findings),
        "top_priority_findings": top_priority,
    }


def _row(label, value):
    return f'<tr><td class="label">{html.escape(str(label))}</td><td class="value">{html.escape(str(value))}</td></tr>'


def render_report_html(report):
    """Renders a self-contained HTML document (inline CSS only) so it's a sensible
    standalone download, independent of dashboard/static/style.css."""
    period_title = report["period"].replace("-", " ").title()

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
<title>VulnHunter {html.escape(period_title)} Security Report</title>
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
  <h1>VulnHunter {html.escape(period_title)} Security Report</h1>
  <p class="meta">Generated {html.escape(report["generated_at"])} UTC</p>

  <div class="caveat">
    This MVP has no persistence layer yet, so every report period currently summarizes
    the same real, current-moment snapshot rather than aggregating actual historical
    data for that window - see KNOWLEDGE_TRANSFER.md's roadmap. All figures below are
    real, live-computed values, not placeholders.
  </div>

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
