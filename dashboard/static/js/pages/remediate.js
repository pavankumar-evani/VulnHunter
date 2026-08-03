import { api } from "../api.js";
import { escapeHtml } from "../dom.js";

export const title = "/remediate — Remediation Plan (snapshot)";

const INTRO = `
  <div class="callout">
    This is the static plan from the last <code>/remediate</code> agent run. For a live,
    re-scored view using the current priority rules and SLA windows, see the
    <a href="/queue" data-link>Remediation Queue</a> page instead.
  </div>`;

export async function render(container) {
  const data = await api.remediate();
  const plan = data.plan;

  if (!plan.available) {
    container.innerHTML = `${INTRO}
      <p class="empty-state">
        No remediation plan found yet. Run <code>/remediate</code> in Claude Code, or use the
        <a href="/run" data-link>Run Pipeline</a> page.
      </p>`;
    return;
  }

  const rows = plan.queue.map((row) => {
    const playbookFile = data.playbooks_by_finding[row.ID];
    return `
      <tr>
        <td>${escapeHtml(row.ID)}</td>
        <td>${escapeHtml(row.Asset)}</td>
        <td>${escapeHtml(row.Title)}</td>
        <td><code>${escapeHtml(row.CVE)}</code></td>
        <td><span class="badge badge-${(row.Severity || "").toLowerCase()}">${escapeHtml(row.Severity)}</span></td>
        <td>${escapeHtml(row["Action Type"])}</td>
        <td>${escapeHtml(row["Automation Target"])}</td>
        <td><span class="badge badge-${(row["Risk Tier"] || "").replaceAll("-", "_")}">${escapeHtml(row["Risk Tier"])}</span></td>
        <td>${row.KEV === "Yes"
          ? `<span class="badge badge-critical">KEV</span>`
          : `<span class="muted">${escapeHtml(row.KEV)}</span>`}</td>
        <td>${escapeHtml(row.EPSS)}</td>
        <td>${playbookFile
          ? `<a href="/playbooks/${encodeURIComponent(playbookFile)}" data-link>View</a>`
          : `<span class="muted">none</span>`}</td>
      </tr>`;
  }).join("");

  container.innerHTML = `${INTRO}
    <p class="subtitle">${escapeHtml(plan.title)}</p>
    <div class="table-scroll">
      <table class="data-table">
        <thead>
          <tr>
            <th>ID</th><th>Asset</th><th>Title</th><th>CVE</th><th>Severity</th>
            <th>Action Type</th><th>Automation Target</th><th>Risk Tier</th>
            <th>KEV</th><th>EPSS</th><th>Playbook</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}
