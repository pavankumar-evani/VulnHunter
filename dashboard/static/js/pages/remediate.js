import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { exportButtonsHtml, wireExportButtons } from "../export.js";
import { paginate, paginationHtml, wirePagination } from "../pagination.js";

export const title = "/remediate — Remediation Plan (snapshot)";

const EXPORT_COLUMNS = [
  { label: "ID", value: (r) => r.ID },
  { label: "Asset", value: (r) => r.Asset },
  { label: "Title", value: (r) => r.Title },
  { label: "CVE", value: (r) => r.CVE },
  { label: "Severity", value: (r) => r.Severity },
  { label: "Action Type", value: (r) => r["Action Type"] },
  { label: "Automation Target", value: (r) => r["Automation Target"] },
  { label: "Risk Tier", value: (r) => r["Risk Tier"] },
  { label: "KEV", value: (r) => r.KEV },
  { label: "EPSS", value: (r) => r.EPSS },
];

const INTRO = `
  <div class="callout">
    This is the static plan from the last <code>/remediate</code> agent run. For a live,
    re-scored view using the current priority rules and SLA windows, see the
    <a href="/queue" data-link>Remediation Queue</a> page instead.
  </div>`;

function rowHtml(row, playbookFile) {
  return `
    <tr>
      <td>${escapeHtml(row.ID)}</td>
      <td>${escapeHtml(row.Asset)}</td>
      <td class="wrap-cell">${escapeHtml(row.Title)}</td>
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
}

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

  const riskTiers = [...new Set(plan.queue.map((r) => r["Risk Tier"]).filter(Boolean))].sort();
  const targets = [...new Set(plan.queue.map((r) => r["Automation Target"]).filter(Boolean))].sort();
  const filters = { riskTier: "all", target: "all" };

  container.innerHTML = `${INTRO}
    <p class="subtitle">${escapeHtml(plan.title)}</p>

    <div class="filter-bar">
      <label>Risk tier
        <select id="f-risk-tier">
          <option value="all">All</option>
          ${riskTiers.map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join("")}
        </select>
      </label>
      <label>Automation target
        <select id="f-target">
          <option value="all">All</option>
          ${targets.map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join("")}
        </select>
      </label>
      <span class="filter-count" id="plan-count"></span>
    </div>

    ${exportButtonsHtml("plan")}

    <div class="table-scroll">
      <table class="data-table">
        <thead>
          <tr>
            <th>ID</th><th>Asset</th><th>Title</th><th>CVE</th><th>Severity</th>
            <th>Action Type</th><th>Automation Target</th><th>Risk Tier</th>
            <th>KEV</th><th>EPSS</th><th>Playbook</th>
          </tr>
        </thead>
        <tbody id="plan-body"></tbody>
      </table>
    </div>
    <div id="plan-pagination"></div>`;

  const tbody = container.querySelector("#plan-body");
  const countEl = container.querySelector("#plan-count");
  let currentFiltered = plan.queue;
  let page = 1;

  function renderRows() {
    const filtered = plan.queue.filter((row) =>
      (filters.riskTier === "all" || row["Risk Tier"] === filters.riskTier) &&
      (filters.target === "all" || row["Automation Target"] === filters.target));
    currentFiltered = filtered;
    const paged = paginate(filtered, page);
    page = paged.page;
    tbody.innerHTML = paged.rows.length
      ? paged.rows.map((row) => rowHtml(row, data.playbooks_by_finding[row.ID])).join("")
      : `<tr><td colspan="11" class="empty-state">No findings match the current filters.</td></tr>`;
    countEl.textContent = `${filtered.length} of ${plan.queue.length} finding(s)`;
    container.querySelector("#plan-pagination").innerHTML = paginationHtml(paged.page, paged.totalPages);
  }
  wirePagination(container, (p) => { page = p; renderRows(); });

  wireExportButtons(container, "plan", {
    getRows: () => currentFiltered,
    columns: EXPORT_COLUMNS,
    filenameBase: "vulnhunter-remediation-plan",
  });

  container.querySelector("#f-risk-tier").addEventListener("change", (e) => { filters.riskTier = e.target.value; page = 1; renderRows(); });
  container.querySelector("#f-target").addEventListener("change", (e) => { filters.target = e.target.value; page = 1; renderRows(); });
  renderRows();
}
