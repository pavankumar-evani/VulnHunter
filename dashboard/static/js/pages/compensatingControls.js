// "Compensating Controls" watchlist: findings that can't be (or currently aren't)
// remediated directly - Critical findings on an EOL/EOS asset, actively-exploited
// (CISA KEV-listed) findings with no public POC yet available (matches at least one
// configured /exploit-criteria rule), or findings already covered by an approved
// exception - with each one's already-computed compensating_controls listed inline,
// not hidden behind a click like the per-finding view on /exceptions. Not a separate
// data source: built entirely from the same /api/queue the Remediation Queue already
// shows (which already carries eol_status, kev, exploit_criteria_matches,
// compensating_controls, and the finding's active exception, if any).
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { openFindingDetail } from "../findingDetail.js";
import { buildOwnerTeamMaps } from "../assetLookup.js";
import { exportButtonsHtml, wireExportButtons } from "../export.js";
import { columnPickerHtml, loadVisibleColumns, applyColumnVisibility, wireColumnPicker } from "../columnPicker.js";
import { paginate, paginationHtml, wirePagination, DEFAULT_PAGE_SIZE } from "../pagination.js";
import { groupLabelFor } from "../domainGrouping.js";
import { threatIntelCellHtml, threatIntelExportValue } from "../threatIntelTagging.js";

export const title = "Compensating Controls";

const FLAG_BADGE_CLASS = { eol: "badge-critical", "zero-day": "badge-critical" };

function flagsFor(f) {
  const flags = [];
  if (f.severity === "Critical" && f.eol_status && ["eol", "eol-soon"].includes(f.eol_status.status)) {
    flags.push({ code: "eol", label: f.eol_status.status === "eol" ? "Critical + EOL" : "Critical + EOL soon" });
  }
  const criteriaMatches = f.exploit_criteria_matches || [];
  if (f.kev && f.kev.listed && criteriaMatches.length) {
    flags.push({
      code: "zero-day",
      label: "Actively exploited — matches exploit criteria",
      detail: criteriaMatches.map((m) => m.label).join("; "),
    });
  }
  if (f.exception) {
    // f.exception is merged from active_exceptions_by_finding() (dashboard/data.py's
    // load_live_queue()), which only ever returns currently-active exceptions - an
    // expired or revoked one drops out of this field entirely (correctly reverting
    // the finding to "Request exception" below), so there's no separate status to
    // branch on here. id/reason/expires_on already reach the browser via /api/queue -
    // no backend change needed to link straight to the record.
    flags.push({
      code: "exception",
      label: `Exception approved (${f.exception.id})`,
      badgeClass: "badge-auto_approvable",
      exceptionId: f.exception.id,
    });
  }
  return flags;
}

function flagChipsHtml(flags) {
  return flags.map((fl) => {
    const badgeClass = fl.badgeClass || FLAG_BADGE_CLASS[fl.code];
    const tooltip = fl.detail ? ` data-tooltip="${escapeHtml(fl.detail)}"` : "";
    // A flag tied to a real exception record links straight to it on /exceptions,
    // mirroring queue.js's own ?highlight=<finding-id> deep-link pattern.
    return fl.exceptionId
      ? `<a class="badge ${badgeClass}"${tooltip} href="/exceptions?highlight=${encodeURIComponent(fl.exceptionId)}" data-link>${escapeHtml(fl.label)}</a>`
      : `<span class="badge ${badgeClass}"${tooltip}>${escapeHtml(fl.label)}</span>`;
  }).join(" ");
}

function controlsListHtml(controls) {
  if (!controls || !controls.length) return `<span class="muted">—</span>`;
  return `<ul style="margin:0; padding-left:18px">${controls.map((c) => `<li style="margin-bottom:2px">${escapeHtml(c)}</li>`).join("")}</ul>`;
}

function autoReason(f, flags) {
  const parts = [`Flagged on the Compensating Controls watchlist: ${flags.map((fl) => fl.label).join(", ")}.`];
  if (f.compensating_controls && f.compensating_controls.length) {
    parts.push(`Suggested compensating control: ${f.compensating_controls[0]}`);
  }
  return parts.join(" ");
}

function rowHtml(row) {
  const { f, flags } = row;
  // No redundant text here when an exception already exists - the "Why flagged" chip
  // already shows and links to it (see flagsFor()/flagChipsHtml() above).
  const exceptionAction = f.exception
    ? ""
    : `<a href="/exceptions?finding_id=${encodeURIComponent(f.id)}&reason=${encodeURIComponent(autoReason(f, flags))}" data-link>Request exception</a>`;

  return `
    <tr>
      <td data-col="priority"><span class="badge badge-priority-${(f.priority || "").toLowerCase()}">${escapeHtml(f.priority)}</span></td>
      <td data-col="id"><button type="button" class="link-button finding-id-link" data-finding-id="${escapeHtml(f.id)}">${escapeHtml(f.id)}</button></td>
      <td data-col="cve_title">${escapeHtml(f.cve || f.title)}</td>
      <td data-col="severity"><span class="badge badge-${(f.severity || "").toLowerCase()}">${escapeHtml(f.severity)}</span></td>
      <td data-col="threat_intel">${threatIntelCellHtml(f)}</td>
      <td data-col="why_flagged">${flagChipsHtml(flags)}</td>
      <td data-col="controls">${controlsListHtml(f.compensating_controls)}</td>
      <td data-col="owner">${escapeHtml(f.owner || "Unowned")}</td>
      <td data-col="team">${escapeHtml(f.team || "—")}</td>
      <td data-col="actions">
        <a href="/queue?highlight=${encodeURIComponent(f.id)}" data-link>View in queue</a>
        ${f.cve ? ` · <a href="/queue?cve=${encodeURIComponent(f.cve)}" data-link>All assets w/ this CVE</a>` : ""}
        ${exceptionAction ? `<br>${exceptionAction}` : ""}
      </td>
    </tr>`;
}

// Order matches the header row/rowHtml() below - see columnPicker.js. Threat Intel and
// Team start hidden - the remaining 8 already cover what this watchlist is for
// (what's flagged, why, and what to do about it).
const CC_COLUMNS = [
  { id: "priority", label: "Priority" },
  { id: "id", label: "ID" },
  { id: "cve_title", label: "CVE/Title" },
  { id: "severity", label: "Severity" },
  { id: "threat_intel", label: "Threat Intel", defaultVisible: false },
  { id: "why_flagged", label: "Why flagged" },
  { id: "controls", label: "Compensating controls" },
  { id: "owner", label: "Owner" },
  { id: "team", label: "Team", defaultVisible: false },
  { id: "actions", label: "Actions" },
];

const EXPORT_COLUMNS = [
  { label: "Priority", value: (r) => r.f.priority },
  { label: "ID", value: (r) => r.f.id },
  { label: "CVE/Title", value: (r) => r.f.cve || r.f.title },
  { label: "Severity", value: (r) => r.f.severity },
  { label: "Threat Intel", value: (r) => threatIntelExportValue(r.f) },
  { label: "Why Flagged", value: (r) => r.flags.map((fl) => fl.label).join("; ") },
  { label: "Compensating Controls", value: (r) => (r.f.compensating_controls || []).join("; ") },
  { label: "Owner", value: (r) => r.f.owner },
  { label: "Team", value: (r) => r.f.team },
];

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [queue, assetsData] = await Promise.all([api.queue(), api.assetsList()]);
  const { ownerByAssetName, teamByAssetName } = buildOwnerTeamMaps(assetsData.assets);

  const rows = queue.findings
    .map((f) => ({
      f: {
        ...f,
        owner: ownerByAssetName.get(f.asset && f.asset.name),
        team: teamByAssetName.get(f.asset && f.asset.name),
      },
      flags: flagsFor(f),
    }))
    .filter((row) => row.flags.length > 0)
    .map((row) => ({ ...row, groupLabel: groupLabelFor(row.f) }));
  // Sort by group so every group's rows stay contiguous across pages - Array.sort is
  // stable, so rows within the same group keep their original relative order.
  rows.sort((a, b) => a.groupLabel.localeCompare(b.groupLabel));

  const groupLabels = [...new Set(rows.map((r) => r.groupLabel))].sort();

  const eolCount = rows.filter((r) => r.flags.some((fl) => fl.code === "eol")).length;
  const zeroDayCount = rows.filter((r) => r.flags.some((fl) => fl.code === "zero-day")).length;
  const exceptionCount = rows.filter((r) => r.flags.some((fl) => fl.code === "exception")).length;

  let page = 1;
  let groupFilter = "all";
  let visibleColumns = loadVisibleColumns("compensating-controls", CC_COLUMNS);

  function renderRows() {
    const filtered = groupFilter === "all" ? rows : rows.filter((r) => r.groupLabel === groupFilter);
    const paged = paginate(filtered, page);
    page = paged.page;
    const tbody = container.querySelector("#cc-body");
    if (!paged.rows.length) {
      tbody.innerHTML = `<tr><td colspan="${CC_COLUMNS.length}" class="empty-state">Nothing currently flagged.</td></tr>`;
    } else {
      // A divider row before every group change - including the very first row on a
      // page, so a page that starts mid-group still shows which group it's in.
      let lastGroupKey = null;
      const parts = [];
      for (const row of paged.rows) {
        if (row.groupLabel !== lastGroupKey) {
          const groupCount = filtered.filter((r) => r.groupLabel === row.groupLabel).length;
          parts.push(`<tr class="table-section-row"><td colspan="${CC_COLUMNS.length}">${escapeHtml(row.groupLabel)} (${groupCount})</td></tr>`);
          lastGroupKey = row.groupLabel;
        }
        parts.push(rowHtml(row));
      }
      tbody.innerHTML = parts.join("");
    }
    applyColumnVisibility(container.querySelector("#cc-table"), visibleColumns);
    const paginationEl = container.querySelector("#cc-pagination");
    if (paginationEl) paginationEl.innerHTML = paginationHtml(paged.page, paged.totalPages);
    const countEl = container.querySelector("#cc-count");
    if (countEl) countEl.textContent = `${filtered.length} of ${rows.length} finding(s) flagged`;
  }

  container.innerHTML = `
    <p class="subtitle">
      Findings that can't be remediated right now - a Critical finding on an End-of-Life/
      End-of-Support asset, an actively-exploited (CISA KEV) finding matching a configured
      <a href="/exploit-criteria" data-link>exploit criteria</a> rule, or one already
      covered by an approved exception - together with the compensating controls already
      suggested for each. Not a separate data source: built from the same
      <code>/api/queue</code> the Remediation Queue already shows.
    </p>

    <div class="kpi-grid">
      <div class="kpi-card kpi-danger"><div class="kpi-value">${eolCount}</div><div class="kpi-label">Critical + EOL/EOS</div></div>
      <div class="kpi-card kpi-danger"><div class="kpi-value">${zeroDayCount}</div><div class="kpi-label">Actively exploited, matches exploit criteria</div></div>
      <div class="kpi-card kpi-warn"><div class="kpi-value">${exceptionCount}</div><div class="kpi-label">Exception-covered</div></div>
      <div class="kpi-card"><div class="kpi-value">${rows.length}</div><div class="kpi-label">Total flagged</div></div>
    </div>

    <div class="filter-bar">
      <label>Group
        <select id="cc-f-group">
          <option value="all">All (${rows.length})</option>
          ${groupLabels.map((label) => `<option value="${escapeHtml(label)}">${escapeHtml(label)}</option>`).join("")}
        </select>
      </label>
      <span class="filter-count" id="cc-count"></span>
    </div>
    <div class="table-toolbar">
      ${exportButtonsHtml("compensating-controls")}
      ${columnPickerHtml("compensating-controls", CC_COLUMNS, visibleColumns)}
    </div>
    <div class="table-scroll">
      <table class="data-table" id="cc-table">
        <thead>
          <tr>
            <th data-col="priority">Priority</th><th data-col="id">ID</th><th data-col="cve_title">CVE/Title</th><th data-col="severity">Severity</th><th data-col="threat_intel">Threat Intel</th>
            <th data-col="why_flagged">Why flagged</th><th data-col="controls">Compensating controls</th><th data-col="owner">Owner</th><th data-col="team">Team</th><th data-col="actions">Actions</th>
          </tr>
        </thead>
        <tbody id="cc-body"></tbody>
      </table>
    </div>
    <div id="cc-pagination"></div>`;

  renderRows();

  container.querySelector("#cc-f-group").addEventListener("change", (e) => {
    groupFilter = e.target.value;
    page = 1;
    renderRows();
  });

  wirePagination(container, (p) => { page = p; renderRows(); });

  wireExportButtons(container, "compensating-controls", {
    getRows: () => rows,
    columns: EXPORT_COLUMNS,
    filenameBase: "vulnhunter-compensating-controls",
  });
  wireColumnPicker(container, "compensating-controls", (visible) => {
    visibleColumns = visible;
    applyColumnVisibility(container.querySelector("#cc-table"), visibleColumns);
  });

  container.addEventListener("click", (e) => {
    const btn = e.target.closest(".finding-id-link");
    if (!btn) return;
    const row = rows.find((r) => r.f.id === btn.dataset.findingId);
    if (row) openFindingDetail(row.f);
  });
}
