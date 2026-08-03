import { api } from "../api.js";
import { escapeHtml, timeAgo } from "../dom.js";

export const title = "Security Posture Overview";

const REFRESH_MS = 20000;

function kpi(value, label, cls = "") {
  return `<div class="kpi-card ${cls}"><div class="kpi-value">${value}</div><div class="kpi-label">${label}</div></div>`;
}

function renderBody(data) {
  const riskRows = Object.entries(data.plan.risk_tier_counts || {}).map(([tier, count]) => `
    <tr>
      <td><span class="badge badge-${tier.replaceAll("-", "_")}">${escapeHtml(tier)}</span></td>
      <td>${count}</td>
    </tr>`).join("");

  const assetRows = Object.entries(data.asset_type_breakdown).map(([type, count]) => `
    <tr><td>${escapeHtml(type)}</td><td>${count}</td></tr>`).join("");

  return `
    <p class="subtitle">Real results from the last validated run of both pipelines — not simulated.</p>

    <div class="kpi-grid">
      ${kpi(data.sla.breached, "SLA breached", "kpi-danger")}
      ${kpi(data.sla.at_risk, "SLA at risk (≤3 days)", "kpi-warn")}
      ${kpi(data.sla.on_track, "SLA on track", "kpi-good")}
      ${kpi(data.kev_count, "CISA KEV-listed (actively exploited)", "kpi-danger")}
      ${kpi(data.high_epss_count, "High EPSS (≥50% exploit probability)", "kpi-warn")}
    </div>

    <div class="kpi-grid">
      ${kpi(data.vulnhunt.total || 0, "Code vulnerabilities found")}
      ${kpi(data.vulnhunt.auto_fixable || 0, "Auto-fixed on a branch", "kpi-good")}
      ${kpi(data.remediation.total, "Infra findings normalized")}
      ${kpi(data.remediation.eligible, "Auto-remediable today", "kpi-good")}
      ${kpi(data.remediation.manual_only, "Manual-only (no fixer yet)", "kpi-warn")}
      ${kpi(data.playbook_count, "Playbooks generated")}
    </div>

    <div class="callout">
      Priority in the <a href="/queue" data-link>live remediation queue</a> is
      threat-intel-aware, not just severity-based: a finding confirmed in
      <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener">CISA's KEV catalog</a>
      is escalated to top priority regardless of asset type, and EPSS (exploit-probability
      scoring from FIRST.org) catches high-risk CVEs KEV hasn't confirmed yet. SLA windows,
      asset-criticality weights, and these overrides are all editable on the
      <a href="/priority-rules" data-link>Priority Rules</a> page.
    </div>

    ${data.plan.available ? `
      <h2>Risk tier breakdown (remediation queue)</h2>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>Risk Tier</th><th>Count</th></tr></thead>
          <tbody>${riskRows}</tbody>
        </table>
      </div>` : ""}

    <h2>Coverage by asset class</h2>
    <p class="subtitle">Not just code — infra, OS, network, IoT/OT, application, and certificate-level findings.</p>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Asset Type</th><th>Findings</th></tr></thead>
        <tbody>${assetRows}</tbody>
      </table>
    </div>

    <div class="callout">
      Every playbook shown here is a reviewable artifact — nothing in this dashboard executes
      against real infrastructure automatically. See the safety model in
      <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/KNOWLEDGE_TRANSFER.md#43-the-safety-model-the-single-most-important-design-decision" target="_blank" rel="noopener">KNOWLEDGE_TRANSFER.md §4.3</a>.
    </div>`;
}

export async function render(container) {
  const topbarExtra = document.getElementById("topbar-extra");
  let lastFetched = null;

  function renderLiveBadge() {
    if (!topbarExtra) return;
    topbarExtra.innerHTML = `<span class="live-badge" data-tooltip="Auto-refreshes every ${REFRESH_MS / 1000}s">` +
      `<span class="live-dot"></span> Live · updated ${lastFetched ? timeAgo(lastFetched) : "just now"}</span>`;
  }

  async function load() {
    const data = await api.overview();
    lastFetched = new Date();
    container.innerHTML = renderBody(data);
    renderLiveBadge();
  }

  await load();
  const tickTimer = setInterval(renderLiveBadge, 1000);
  const refreshTimer = setInterval(() => { load().catch((err) => console.error(err)); }, REFRESH_MS);

  return () => {
    clearInterval(tickTimer);
    clearInterval(refreshTimer);
  };
}
