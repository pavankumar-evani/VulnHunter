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
import { columnPickerHtml, loadVisibleColumns, applyColumnVisibility, wireColumnPicker } from "./columnPicker.js";
import { paginate, paginationHtml, wirePagination } from "./pagination.js";
import { openFindingDetail } from "./findingDetail.js";
import { threatIntelCellHtml, threatIntelExportValue } from "./threatIntelTagging.js";
import { ENVIRONMENT_LABELS, environmentCellHtml } from "./assetLookup.js";

const EXPORT_COLUMNS = [
  { label: "Priority", value: (f) => f.priority },
  { label: "ID", value: (f) => f.id },
  { label: "Asset", value: (f) => f.asset && f.asset.name },
  { label: "Asset Type", value: (f) => f.asset && f.asset.type },
  { label: "Cloud Provider", value: (f) => f.cloud_provider || "" },
  { label: "Environment", value: (f) => ENVIRONMENT_LABELS[f.environment || "unknown"] || f.environment },
  { label: "Owner", value: (f) => f.owner },
  { label: "Team", value: (f) => f.team },
  { label: "Category", value: (f) => f.scan_type_label || f.scan_type },
  { label: "Remediation Mechanism", value: (f) => f.remediation_mechanism || "" },
  { label: "Title", value: (f) => f.title },
  { label: "CVE", value: (f) => f.cve },
  { label: "KEV", value: (f) => (f.kev && f.kev.listed ? "Yes" : "No") },
  { label: "EPSS", value: (f) => (f.epss ? f.epss.score : "") },
  { label: "Threat Intel", value: threatIntelExportValue },
  { label: "Last Seen", value: (f) => f.last_seen },
  { label: "SLA Due", value: (f) => f.sla && f.sla.due_date },
  { label: "SLA Breached", value: (f) => !!(f.sla && f.sla.breached) },
  { label: "ATT&CK Techniques", value: (f) => (f.attack_techniques || []).map((t) => t.technique_id).join("; ") },
];

// Order matches the header row/rowHtml() below - each id is also the data-col value on
// that column's <th> and every row's matching <td>. Same compact-by-default reasoning
// as queue.js's QUEUE_COLUMNS; kept per-exportGroupId (Infrastructure hub vs AppSec hub
// each remember their own choice, via columnPicker.js's localStorage key).
const FINDINGS_TABLE_COLUMNS = [
  { id: "priority", label: "Priority" },
  { id: "id", label: "ID" },
  { id: "asset", label: "Asset" },
  { id: "asset_type", label: "Asset Type", defaultVisible: false },
  { id: "cloud_provider", label: "Cloud Provider", defaultVisible: false },
  { id: "environment", label: "Environment", defaultVisible: false },
  { id: "owner", label: "Owner", defaultVisible: false },
  { id: "team", label: "Team", defaultVisible: false },
  { id: "remediation_mechanism", label: "Remediation Mechanism", defaultVisible: false },
  { id: "title", label: "Title" },
  { id: "cve", label: "CVE" },
  { id: "kev", label: "KEV" },
  { id: "epss", label: "EPSS" },
  { id: "threat_intel", label: "Threat Intel", defaultVisible: false },
  { id: "last_seen", label: "Last Seen", defaultVisible: false },
  { id: "sla", label: "SLA Due" },
  { id: "attack", label: "ATT&CK", defaultVisible: false },
  { id: "ai", label: "AI" },
];

function distinctSorted(values) {
  return [...new Set(values.filter((v) => v !== undefined && v !== null && v !== ""))].sort();
}

// Column filter controls (Priority/Asset Type/Owner/Team/Asset/ID, plus an optional
// caller-supplied Category dropdown) for pages using findingsTableHtml/wireFindingsTable
// below - meant to sit inside the same `.filter-bar` div as that page's own
// dateRangeHtml() controls (see appsec.js), not a separate row, so a page's whole set
// of filters reads as one compact bar rather than the date range alone stretching
// across it. Dropdown options are derived once from the full incoming `findings` (not
// re-derived as filters narrow the visible set) so a dropdown's own option list never
// shrinks out from under a user mid-selection - same precedent as queue.js's filter bar.
export function findingsFilterBarHtml(idPrefix, findings, { ownerByAssetName, teamByAssetName, categoryLabel, categoryOptions } = {}) {
  const owners = ownerByAssetName || new Map();
  const teams = teamByAssetName || new Map();
  const assetTypes = distinctSorted(findings.map((f) => f.asset && f.asset.type));
  const ownerValues = distinctSorted(findings.map((f) => owners.get(f.asset && f.asset.name) || "Unowned"));
  const teamValues = distinctSorted(findings.map((f) => teams.get(f.asset && f.asset.name)));
  // Real, already-loaded values only (no fabricated suggestions) - native browser
  // autocomplete via <datalist>, same "predictions as you type" convenience as the
  // global search bar, for the two free-text filters that don't have a dropdown.
  const assetNames = distinctSorted(findings.map((f) => f.asset && f.asset.name));
  const findingIds = distinctSorted(findings.map((f) => f.id));

  return `
    <label>Priority
      <select id="${idPrefix}-f-priority">
        <option value="all">All</option>
        <option value="Critical">Critical</option>
        <option value="High">High</option>
        <option value="Medium">Medium</option>
        <option value="Low">Low</option>
      </select>
    </label>
    <label>Asset type
      <select id="${idPrefix}-f-asset-type"><option value="all">All</option>${assetTypes.map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join("")}</select>
    </label>
    ${categoryOptions ? `
    <label>${escapeHtml(categoryLabel || "Category")}
      <select id="${idPrefix}-f-category"><option value="all">All</option>${categoryOptions.map((o) => `<option value="${escapeHtml(o.value)}">${escapeHtml(o.label)}</option>`).join("")}</select>
    </label>` : ""}
    <label>Owner
      <select id="${idPrefix}-f-owner"><option value="all">All</option>${ownerValues.map((o) => `<option value="${escapeHtml(o)}">${escapeHtml(o)}</option>`).join("")}</select>
    </label>
    <label>Team
      <select id="${idPrefix}-f-team"><option value="all">All</option>${teamValues.map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join("")}</select>
    </label>
    <label>Asset
      <input type="search" id="${idPrefix}-f-asset" list="${idPrefix}-asset-options" placeholder="Search asset…">
      <datalist id="${idPrefix}-asset-options">${assetNames.map((n) => `<option value="${escapeHtml(n)}">`).join("")}</datalist>
    </label>
    <label>ID
      <input type="search" id="${idPrefix}-f-id" list="${idPrefix}-id-options" placeholder="Search ID…">
      <datalist id="${idPrefix}-id-options">${findingIds.map((n) => `<option value="${escapeHtml(n)}">`).join("")}</datalist>
    </label>`;
}

const DEFAULT_FINDINGS_FILTERS = { priority: "all", assetType: "all", category: "all", owner: "all", team: "all", asset: "", id: "" };

export function applyFindingsFilters(findings, filters, { ownerByAssetName, teamByAssetName, categoryField } = {}) {
  if (!filters) return findings;
  const owners = ownerByAssetName || new Map();
  const teams = teamByAssetName || new Map();
  const catField = categoryField || "scan_type";
  return findings.filter((f) => {
    if (filters.priority !== "all" && f.priority !== filters.priority) return false;
    if (filters.assetType !== "all" && (f.asset && f.asset.type) !== filters.assetType) return false;
    if (filters.category !== "all" && f[catField] !== filters.category) return false;
    if (filters.owner !== "all" && (owners.get(f.asset && f.asset.name) || "Unowned") !== filters.owner) return false;
    if (filters.team !== "all" && (teams.get(f.asset && f.asset.name) || "") !== filters.team) return false;
    if (filters.asset && !((f.asset && f.asset.name) || "").toLowerCase().includes(filters.asset.toLowerCase())) return false;
    if (filters.id && !(f.id || "").toLowerCase().includes(filters.id.toLowerCase())) return false;
    return true;
  });
}

// Wires the controls rendered by findingsFilterBarHtml() above. `onChange(filters)`
// fires on every change with the full current filter-state object (starting from
// DEFAULT_FINDINGS_FILTERS) - mirrors dateRange.js's wireDateRange() callback shape so
// a page composes the two the same way (see appsec.js).
export function wireFindingsFilterBar(container, idPrefix, onChange) {
  const state = { ...DEFAULT_FINDINGS_FILTERS };
  const bind = (id, key, event, read) => {
    const el = container.querySelector(`#${idPrefix}-${id}`);
    if (!el) return;
    el.addEventListener(event, () => { state[key] = read(el); onChange({ ...state }); });
  };
  bind("f-priority", "priority", "change", (el) => el.value);
  bind("f-asset-type", "assetType", "change", (el) => el.value);
  bind("f-category", "category", "change", (el) => el.value);
  bind("f-owner", "owner", "change", (el) => el.value);
  bind("f-team", "team", "change", (el) => el.value);
  bind("f-asset", "asset", "input", (el) => el.value);
  bind("f-id", "id", "input", (el) => el.value);
}

// Purely informational (remediation/schema/normalized-finding-schema.md's own field
// notes): names the REAL-WORLD tool that would normally patch this asset class (SCCM,
// MDM, vendor firmware/hypervisor tooling) - not a working integration, so this is
// never a link/action, just a labeled fact for whichever team owns that tool.
function remediationMechanismCellHtml(f) {
  if (!f.remediation_mechanism) return `<span class="muted">—</span>`;
  return `<span data-tooltip="Real-world tool, not a working integration in this app - see the FAQ">${escapeHtml(f.remediation_mechanism)}</span>`;
}

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
      <td data-col="priority"><span class="badge badge-priority-${(f.priority || "").toLowerCase()}">${escapeHtml(f.priority)}</span></td>
      <td data-col="id"><button type="button" class="link-button finding-id-link" data-finding-id="${escapeHtml(f.id)}">${escapeHtml(f.id)}</button></td>
      <td data-col="asset">${escapeHtml(f.asset && f.asset.name)}</td>
      <td data-col="asset_type" class="asset-type-cell">${escapeHtml(f.asset && f.asset.type)}</td>
      <td data-col="cloud_provider" class="asset-type-cell">${f.cloud_provider ? escapeHtml(f.cloud_provider) : `<span class="muted">—</span>`}</td>
      <td data-col="environment">${environmentCellHtml(f.environment, escapeHtml)}</td>
      <td data-col="owner">${escapeHtml(f.owner || "Unowned")}</td>
      <td data-col="team">${escapeHtml(f.team || "—")}</td>
      <td data-col="remediation_mechanism">${remediationMechanismCellHtml(f)}</td>
      <td data-col="title">${escapeHtml(f.title)}</td>
      <td data-col="cve"><code>${escapeHtml(f.cve || "—")}</code></td>
      <td data-col="kev">${kev}</td>
      <td data-col="epss">${epss}</td>
      <td data-col="threat_intel">${threatIntelCellHtml(f)}</td>
      <td data-col="last_seen">${escapeHtml(f.last_seen || "—")}</td>
      <td data-col="sla">${slaCell}</td>
      <td data-col="attack">${attackTags}</td>
      <td data-col="ai"><a href="/ai-assist?finding_id=${encodeURIComponent(f.id)}" data-link class="ai-assist-link">${icon("ai", 14)} Ask AI</a></td>
    </tr>`;
}

// Markup for the table itself - insert wherever the caller's page template wants it,
// then call wireFindingsTable() once the container's innerHTML includes this.
export function findingsTableHtml(exportGroupId) {
  const visible = loadVisibleColumns(exportGroupId, FINDINGS_TABLE_COLUMNS);
  return `
    <div class="table-toolbar">
      ${exportButtonsHtml(exportGroupId)}
      ${columnPickerHtml(exportGroupId, FINDINGS_TABLE_COLUMNS, visible)}
    </div>
    <div class="table-scroll">
      <table class="data-table" id="${exportGroupId}-findings-table">
        <thead>
          <tr>
            <th data-col="priority">Priority</th><th data-col="id">ID</th><th data-col="asset">Asset</th><th data-col="asset_type">Asset Type</th><th data-col="cloud_provider">Cloud Provider</th><th data-col="environment">Environment</th><th data-col="owner">Owner</th><th data-col="team">Team</th><th data-col="remediation_mechanism">Remediation Mechanism</th><th data-col="title">Title</th><th data-col="cve">CVE</th>
            <th data-col="kev">KEV</th><th data-col="epss">EPSS</th><th data-col="threat_intel">Threat Intel</th><th data-col="last_seen">Last Seen</th><th data-col="sla">SLA Due</th><th data-col="attack">ATT&amp;CK</th><th data-col="ai">AI</th>
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
// `ownerByAssetName`/`teamByAssetName`/`environmentByAssetName` (see assetLookup.js's
// buildOwnerTeamMaps) are optional - pages that haven't fetched /api/assets can omit
// them and every row just shows "Unowned"/"—"/"Unknown", same as an asset with no
// owner/environment set at all.
export function wireFindingsTable(container, findings, { exportGroupId, filenameBase, ownerByAssetName, teamByAssetName, environmentByAssetName }) {
  let page = 1;
  let visibleColumns = loadVisibleColumns(exportGroupId, FINDINGS_TABLE_COLUMNS);
  const owners = ownerByAssetName || new Map();
  const teams = teamByAssetName || new Map();
  const environments = environmentByAssetName || new Map();
  findings = findings.map((f) => ({
    ...f,
    owner: owners.get(f.asset && f.asset.name),
    team: teams.get(f.asset && f.asset.name),
    environment: environments.get(f.asset && f.asset.name),
  }));

  function renderRows() {
    const paged = paginate(findings, page);
    page = paged.page;
    const tbody = container.querySelector(".findings-table-body");
    if (!tbody) return;
    tbody.innerHTML = paged.rows.length
      ? paged.rows.map(rowHtml).join("")
      : `<tr><td colspan="${FINDINGS_TABLE_COLUMNS.length}" class="empty-state">No findings in this category yet.</td></tr>`;
    applyColumnVisibility(container.querySelector(`#${exportGroupId}-findings-table`), visibleColumns);
    const paginationEl = container.querySelector(".findings-table-pagination");
    if (paginationEl) paginationEl.innerHTML = paginationHtml(paged.page, paged.totalPages);
  }

  wirePagination(container, (p) => { page = p; renderRows(); });
  wireColumnPicker(container, exportGroupId, (visible) => {
    visibleColumns = visible;
    applyColumnVisibility(container.querySelector(`#${exportGroupId}-findings-table`), visibleColumns);
  });
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
