// Shared "live findings list" table - same columns/behavior as the Live Remediation
// Queue's table (priority, clickable ID -> detail modal, asset, category, CVE, KEV,
// EPSS, last seen, SLA, ATT&CK, Ask AI), reused by the Security Domains hub pages
// (Infrastructure, AppSec) so every findings list in the app looks and behaves the
// same, per the "sub-domain dashboards need to look consistent" ask - rather than
// each hub page inventing its own table. Queue.js keeps its own copy of this rendering
// (it additionally needs live sort/filter/tenant-switching); this module is for pages
// that just need to show one already-filtered, static slice of normalized findings.
import { escapeHtml } from "./dom.js";
import { icon } from "./icons.js";
import { exportButtonsHtml, wireExportButtons } from "./export.js";
import { paginate, paginationHtml, wirePagination } from "./pagination.js";
import { openFindingDetail } from "./findingDetail.js";

const EXPORT_COLUMNS = [
  { label: "Priority", value: (f) => f.priority },
  { label: "ID", value: (f) => f.id },
  { label: "Asset", value: (f) => f.asset && f.asset.name },
  { label: "Asset Type", value: (f) => f.asset && f.asset.type },
  { label: "Category", value: (f) => f.scan_type_label || f.scan_type },
  { label: "Title", value: (f) => f.title },
  { label: "CVE", value: (f) => f.cve },
  { label: "KEV", value: (f) => (f.kev && f.kev.listed ? "Yes" : "No") },
  { label: "EPSS", value: (f) => (f.epss ? f.epss.score : "") },
  { label: "Last Seen", value: (f) => f.last_seen },
  { label: "SLA Due", value: (f) => f.sla && f.sla.due_date },
  { label: "SLA Breached", value: (f) => !!(f.sla && f.sla.breached) },
  { label: "ATT&CK Techniques", value: (f) => (f.attack_techniques || []).map((t) => t.technique_id).join("; ") },
];

function rowHtml(f) {
  const kev = f.kev && f.kev.listed
    ? `<span class="badge badge-critical">KEV</span>`
    : `<span class="muted">—</span>`;
  const epss = f.epss ? `${(f.epss.score * 100).toFixed(1)}%` : "—";

  let slaCell = `<span class="muted">—</span>`;
  if (f.sla && f.sla.due_date) {
    if (f.sla.breached) {
      slaCell = `<span class="sla-breached">${escapeHtml(f.sla.due_date)} (breached)</span>`;
    } else if (f.sla.days_remaining <= 3) {
      slaCell = `<span class="sla-warn">${escapeHtml(f.sla.due_date)} (${f.sla.days_remaining}d)</span>`;
    } else {
      slaCell = `<span class="sla-ok">${escapeHtml(f.sla.due_date)} (${f.sla.days_remaining}d)</span>`;
    }
  }

  const attackTags = (f.attack_techniques && f.attack_techniques.length)
    ? f.attack_techniques.map((t) => `<span class="attack-tag" title="${escapeHtml(t.tactic)}">${escapeHtml(t.technique_id)}</span>`).join("")
    : `<span class="muted">—</span>`;

  return `
    <tr>
      <td><span class="badge badge-priority-${(f.priority || "").toLowerCase()}">${escapeHtml(f.priority)}</span></td>
      <td><button type="button" class="link-button finding-id-link" data-finding-id="${escapeHtml(f.id)}">${escapeHtml(f.id)}</button></td>
      <td>${escapeHtml(f.asset && f.asset.name)}</td>
      <td class="asset-type-cell">${escapeHtml(f.asset && f.asset.type)}</td>
      <td>${escapeHtml(f.title)}</td>
      <td><code>${escapeHtml(f.cve || "—")}</code></td>
      <td>${kev}</td>
      <td>${epss}</td>
      <td>${escapeHtml(f.last_seen || "—")}</td>
      <td>${slaCell}</td>
      <td>${attackTags}</td>
      <td><a href="/ai-assist?finding_id=${encodeURIComponent(f.id)}" data-link class="ai-assist-link">${icon("ai", 14)} Ask AI</a></td>
    </tr>`;
}

// Markup for the table itself - insert wherever the caller's page template wants it,
// then call wireFindingsTable() once the container's innerHTML includes this.
export function findingsTableHtml(exportGroupId) {
  return `
    ${exportButtonsHtml(exportGroupId)}
    <div class="table-scroll">
      <table class="data-table">
        <thead>
          <tr>
            <th>Priority</th><th>ID</th><th>Asset</th><th>Asset Type</th><th>Title</th><th>CVE</th>
            <th>KEV</th><th>EPSS</th><th>Last Seen</th><th>SLA Due</th><th>ATT&amp;CK</th><th>AI</th>
          </tr>
        </thead>
        <tbody class="findings-table-body"></tbody>
      </table>
    </div>
    <div class="findings-table-pagination"></div>`;
}

// Call exactly once per render() - wires pagination, the clickable-ID detail modal,
// and export against the given (already-filtered, static) findings array. Not for
// pages that need live sort/filter/tenant-switching - see queue.js for that.
export function wireFindingsTable(container, findings, { exportGroupId, filenameBase }) {
  let page = 1;

  function renderRows() {
    const paged = paginate(findings, page);
    page = paged.page;
    const tbody = container.querySelector(".findings-table-body");
    if (!tbody) return;
    tbody.innerHTML = paged.rows.length
      ? paged.rows.map(rowHtml).join("")
      : `<tr><td colspan="12" class="empty-state">No findings in this category yet.</td></tr>`;
    const paginationEl = container.querySelector(".findings-table-pagination");
    if (paginationEl) paginationEl.innerHTML = paginationHtml(paged.page, paged.totalPages);
  }

  wirePagination(container, (p) => { page = p; renderRows(); });
  container.addEventListener("click", (e) => {
    const btn = e.target.closest(".finding-id-link");
    if (!btn) return;
    const finding = findings.find((f) => f.id === btn.dataset.findingId);
    if (finding) openFindingDetail(finding);
  });
  wireExportButtons(container, exportGroupId, {
    getRows: () => findings,
    columns: EXPORT_COLUMNS,
    filenameBase,
  });

  renderRows();
}
