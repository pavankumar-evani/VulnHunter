import { api } from "../api.js";
import { escapeHtml, flash, kpiLink } from "../dom.js";

export const title = "Reports";

const PERIODS = ["daily", "weekly", "monthly", "quarterly", "half-yearly", "yearly"];

function label(period) {
  return period.split("-").map((w) => w[0].toUpperCase() + w.slice(1)).join("-");
}

function renderSummary(data) {
  const topRows = data.top_priority_findings.map((f) => `
    <tr>
      <td><a href="/queue?highlight=${encodeURIComponent(f.id)}" data-link>${escapeHtml(f.id)}</a></td>
      <td><span class="badge badge-priority-${(f.priority || "").toLowerCase()}">${escapeHtml(f.priority)}</span></td>
      <td>${escapeHtml(f.asset)}</td>
      <td class="wrap-cell"><a href="/queue?highlight=${encodeURIComponent(f.id)}" data-link>${escapeHtml(f.title)}</a></td>
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
      ${kpiLink("/queue?slaStatus=breached", data.sla.breached, "SLA breached")}
      ${kpiLink("/queue?slaStatus=at_risk", data.sla.at_risk, "SLA at risk")}
      ${kpiLink("/queue?slaStatus=on_track", data.sla.on_track, "SLA on track")}
      ${kpiLink("/queue?kevOnly=true", data.kev_count, "CISA KEV-listed")}
      ${kpiLink("/queue?highEpssOnly=true", data.high_epss_count, "High EPSS")}
      ${kpiLink("/queue", data.remediation_total, "Infra findings")}
      ${kpiLink("/vulnhunt", data.vulnhunt_total, "Code vulnerabilities")}
      ${kpiLink("/remediate", data.playbook_count, "Playbooks generated")}
    </div>
    <h2>Top priority findings</h2>
    <p class="filter-count" style="margin:-4px 0 8px">Click a row to jump to it on the Remediation Queue.</p>
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

function scheduleSectionHtml(status, schedule) {
  const statusLine = status.smtp_configured
    ? `✅ SMTP is configured (sending from <code>${escapeHtml(status.from_address)}</code>) - schedules below will actually deliver once enabled.`
    : `⚠️ SMTP is NOT configured on this server - schedules below can be saved but won't
       actually send until an admin sets <code>SMTP_HOST</code>/<code>SMTP_PORT</code>/
       <code>SMTP_FROM_ADDRESS</code>. See <a href="/notification-settings" data-link>Notification Settings</a>.`;
  return `
    <h2 style="margin-top:28px">Schedule automatic email reports</h2>
    <div class="callout ${status.smtp_configured ? "" : "callout-warn"}">${statusLine}</div>
    <p class="filter-count" style="margin:-4px 0 8px">
      One subscription per sub-domain/team/cadence combination - edit the YAML directly,
      see the comments in the file for the exact schema. For per-team critical/zero-day/
      threat-intel email <em>alerts</em> (a different, complementary feature), see
      <a href="/notification-settings" data-link>Notification Settings →</a>.
    </p>
    <form class="config-form" id="report-schedule-form">
      <textarea name="rules_text" spellcheck="false" rows="12">${escapeHtml(schedule.rules_text)}</textarea>
      <button type="submit">Save Report Schedule</button>
    </form>`;
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [status, schedule] = await Promise.all([api.notificationStatus(), api.getReportSchedule()]);

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
    <div id="report-output"></div>

    ${scheduleSectionHtml(status, schedule)}`;

  const form = container.querySelector("#report-form");
  const output = container.querySelector("#report-output");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    output.innerHTML = `<div class="empty-state">Generating…</div>`;
    const data = await api.reportGenerate(form.period.value);
    output.innerHTML = renderSummary(data);
  });

  form.requestSubmit();

  container.querySelector("#report-schedule-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const result = await api.saveReportSchedule(event.target.rules_text.value);
      flash(result.message, "success");
    } catch (err) {
      flash(err.message, "error");
    }
  });
}
