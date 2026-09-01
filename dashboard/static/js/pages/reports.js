import { api } from "../api.js";
import { escapeHtml } from "../dom.js";

export const title = "Reports";

const PERIODS = ["daily", "weekly", "monthly", "quarterly", "half-yearly", "yearly"];

function label(period) {
  return period.split("-").map((w) => w[0].toUpperCase() + w.slice(1)).join("-");
}

function kpi(value, l) {
  return `<div class="kpi-card"><div class="kpi-value">${value}</div><div class="kpi-label">${l}</div></div>`;
}

function renderSummary(data) {
  const topRows = data.top_priority_findings.map((f) => `
    <tr>
      <td>${escapeHtml(f.id)}</td>
      <td><span class="badge badge-priority-${(f.priority || "").toLowerCase()}">${escapeHtml(f.priority)}</span></td>
      <td>${escapeHtml(f.asset)}</td>
      <td class="wrap-cell">${escapeHtml(f.title)}</td>
    </tr>`).join("");

  return `
    <p class="subtitle">Generated ${escapeHtml(data.generated_at)} UTC</p>
    <div class="callout callout-warn">
      This MVP has no persistence layer yet, so every period summarizes the same real,
      current-moment snapshot rather than actual historical data for that window - see
      KNOWLEDGE_TRANSFER.md's roadmap. Every number below is real and live-computed, not
      a placeholder.
    </div>
    <div class="kpi-grid">
      ${kpi(data.sla.breached, "SLA breached")}
      ${kpi(data.sla.at_risk, "SLA at risk")}
      ${kpi(data.sla.on_track, "SLA on track")}
      ${kpi(data.kev_count, "CISA KEV-listed")}
      ${kpi(data.high_epss_count, "High EPSS")}
      ${kpi(data.remediation_total, "Infra findings")}
      ${kpi(data.vulnhunt_total, "Code vulnerabilities")}
      ${kpi(data.playbook_count, "Playbooks generated")}
    </div>
    <h2>Top priority findings</h2>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>ID</th><th>Priority</th><th>Asset</th><th>Title</th></tr></thead>
        <tbody>${topRows}</tbody>
      </table>
    </div>
    <p>
      <a href="/api/reports/generate.html?period=${encodeURIComponent(data.period)}&download=true"
         target="_blank" rel="noopener">⬇ Download this report as HTML</a>
    </p>`;
}

export async function render(container) {
  container.innerHTML = `
    <p class="subtitle">Generate a shareable snapshot report - real KPI/SLA/coverage
    data pulled live from this repo's actual artifacts, not sample text.</p>
    <form class="run-form" id="report-form" style="max-width:320px">
      <label>Period
        <select name="period">
          ${PERIODS.map((p) => `<option value="${p}">${label(p)}</option>`).join("")}
        </select>
      </label>
      <button type="submit">Generate</button>
    </form>
    <div id="report-output"></div>`;

  const form = container.querySelector("#report-form");
  const output = container.querySelector("#report-output");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    output.innerHTML = `<div class="empty-state">Generating…</div>`;
    const data = await api.reportGenerate(form.period.value);
    output.innerHTML = renderSummary(data);
  });

  form.requestSubmit();
}
