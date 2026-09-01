import { api } from "../api.js";
import { escapeHtml, timeAgo } from "../dom.js";
import { icon } from "../icons.js";
import { filterByTenant, tenantBannerHtml } from "../tenant.js";
import { QUEUE_SCAN_TYPES, SCAN_TYPE_LABELS } from "../scanTypes.js";
import { INFRA_CATEGORIES, INFRA_CATEGORY_LABELS } from "../infraTypes.js";
import { exportButtonsHtml, wireExportButtons } from "../export.js";
import { columnPickerHtml, loadVisibleColumns, applyColumnVisibility, wireColumnPicker } from "../columnPicker.js";
import { paginate, paginationHtml, wirePagination, DEFAULT_PAGE_SIZE } from "../pagination.js";
import { openFindingDetail } from "../findingDetail.js";
import { buildOwnerTeamMaps, environmentCellHtml, ENVIRONMENT_LABELS } from "../assetLookup.js";
import { dateRangeHtml, wireDateRange, filterByDateRange, computeRange, dateRangeDisclaimerHtml } from "../dateRange.js";
import { threatIntelCellHtml, threatIntelExportValue } from "../threatIntelTagging.js";
import { setInsightsContent, insightSectionHtml, insightAlertHtml } from "../insightsPanel.js";

// These 5 categories are each fixed to one effective asset type/category the moment the
// URL selects them (cert-mgmt->certificate, iac->iac-resource, runtime->container-runtime,
// dast/secrets->application or code-repository split only by CVE presence) - showing
// Asset type/Category/Infra sub-category selects on these views is pure redundancy, since
// there's nothing else for them to filter to. Only `sca` (application OR code-repository)
// and the `infra-vm` default (6 asset types) genuinely need those controls.
const SINGLE_ASSET_TYPE_CATEGORIES = new Set(["cert-mgmt", "iac", "runtime", "dast", "secrets", "ai-ml"]);

const EXPORT_COLUMNS = [
  { label: "Priority", value: (f) => f.priority },
  { label: "ID", value: (f) => f.id },
  { label: "Asset", value: (f) => f.asset && f.asset.name },
  { label: "Asset Type", value: (f) => f.asset && f.asset.type },
  { label: "Cloud Provider", value: (f) => f.cloud_provider || "" },
  { label: "Environment", value: (f) => ENVIRONMENT_LABELS[f.environment || "unknown"] || f.environment },
  { label: "Owner", value: (f) => f.owner },
  { label: "Team", value: (f) => f.team },
  { label: "Remediation Mechanism", value: (f) => f.remediation_mechanism || "" },
  { label: "Category", value: (f) => f.scan_type_label || f.scan_type },
  { label: "Title", value: (f) => f.title },
  { label: "CVE", value: (f) => f.cve },
  { label: "KEV", value: (f) => (f.kev && f.kev.listed ? "Yes" : "No") },
  { label: "EPSS", value: (f) => (f.epss ? f.epss.score : "") },
  { label: "Threat Intel", value: threatIntelExportValue },
  { label: "Last Seen", value: (f) => f.last_seen },
  { label: "SLA Due", value: (f) => f.sla && f.sla.due_date },
  { label: "SLA Breached", value: (f) => !!(f.sla && f.sla.breached) },
  { label: "ATT&CK Techniques", value: (f) => (f.attack_techniques || []).map((t) => t.technique_id).join("; ") },
  { label: "Exception", value: (f) => (f.exception ? f.exception.reason : "") },
  { label: "Change Type", value: (f) => (f.remediation_policy || {}).change_type || "" },
  { label: "Cadence", value: (f) => (f.remediation_policy || {}).cadence || "" },
  { label: "Cadence Overridden", value: (f) => !!((f.remediation_policy || {}).schedule_override) },
  { label: "Next Maintenance Window", value: (f) => windowText((f.remediation_policy || {}).next_window) },
  { label: "Auto-Remediate", value: (f) => ((f.remediation_policy || {}).auto_remediate ? "Yes" : "No") },
];

// Order matches EXPORT_COLUMNS/the header row/rowHtml() below - each id is also the
// data-col value on that column's <th> and every row's matching <td> (see
// columnPicker.js's applyColumnVisibility()). Defaults keep the columns most people
// need to triage/act on a finding at a glance; everything else is a click away instead
// of always-on - see the FAQ/screenshot this addresses ("too many columns").
const QUEUE_COLUMNS = [
  { id: "priority", label: "Priority" },
  { id: "id", label: "ID" },
  { id: "asset", label: "Asset" },
  { id: "asset_type", label: "Asset Type", defaultVisible: false },
  { id: "cloud_provider", label: "Cloud Provider", defaultVisible: false },
  { id: "environment", label: "Environment", defaultVisible: false },
  { id: "owner", label: "Owner", defaultVisible: false },
  { id: "team", label: "Team", defaultVisible: false },
  { id: "remediation_mechanism", label: "Remediation Mechanism", defaultVisible: false },
  { id: "category", label: "Category" },
  { id: "title", label: "Title" },
  { id: "cve", label: "CVE" },
  { id: "kev", label: "KEV" },
  { id: "epss", label: "EPSS" },
  { id: "threat_intel", label: "Threat Intel", defaultVisible: false },
  { id: "last_seen", label: "Last Seen", defaultVisible: false },
  { id: "sla", label: "SLA Due" },
  { id: "attack", label: "ATT&CK", defaultVisible: false },
  { id: "change_type", label: "Change Type" },
  { id: "cadence", label: "Cadence" },
  { id: "next_window", label: "Next Maintenance Window", defaultVisible: false },
  { id: "auto_remediate", label: "Auto-Remediate", defaultVisible: false },
  { id: "ai", label: "AI" },
];

export const title = "Live Remediation Queue";

const REFRESH_MS = 20000;
const PRIORITY_RANK = { Critical: 3, High: 2, Medium: 1, Low: 0 };
// Same change-type -> badge-color convention as remediationApprovals.js.
const CHANGE_TYPE_CLASS = { emergency: "badge-critical", normal: "badge-medium", standard: "badge-auto_approvable" };

function windowText(w) {
  if (!w || !w.date) return "—";
  return `${w.date} (${w.day_of_week}) ${w.start_time}-${w.end_time} ${w.timezone}`;
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
  if (f.exception) {
    // Links straight to the specific exception record on /exceptions, same
    // ?highlight=<id> deep-link pattern this page's own applyHighlight() supports for
    // finding IDs (see below) - closes the loop from "here's why this can't be
    // remediated" back to the actual approval record.
    slaCell += `<br><a class="exception-tag" data-tooltip="${escapeHtml(f.exception.reason)}" ` +
      `href="/exceptions?highlight=${encodeURIComponent(f.exception.id)}" data-link>` +
      `Risk-accepted until ${escapeHtml(f.exception.expires_on)}</a>`;
  }

  const attackTags = (f.attack_techniques && f.attack_techniques.length)
    ? f.attack_techniques.map((t) => `<span class="attack-tag" title="${escapeHtml(t.tactic)}">${escapeHtml(t.technique_id)}</span>`).join("")
    : `<span class="muted">—</span>`;

  const category = f.scan_type
    ? `<span class="category-tag" data-tooltip="${escapeHtml(f.scan_type_label || "")}">${escapeHtml(f.scan_type)}</span>`
    : `<span class="muted">—</span>`;

  // Purely informational (see normalized-finding-schema.md's field notes): the
  // real-world tool that would normally patch this asset class (SCCM, MDM, vendor
  // firmware/hypervisor tooling) - not a working integration, never a link/action.
  const remediationMechanism = f.remediation_mechanism
    ? `<span data-tooltip="Real-world tool, not a working integration in this app - see the FAQ">${escapeHtml(f.remediation_mechanism)}</span>`
    : `<span class="muted">—</span>`;

  // Sourced from the finding's already-resolved remediation_policy (see
  // remediation/config/remediation_policy_engine.py) - computed server-side in
  // dashboard/data.py's load_live_queue(), same "recomputed live" convention as
  // priority/SLA. See /remediation-policy for the config driving this per domain.
  const policy = f.remediation_policy || {};
  const changeTypeCell = policy.change_type
    ? `<span class="badge ${CHANGE_TYPE_CLASS[policy.change_type] || ""}">${escapeHtml(policy.change_type)}</span>`
    : `<span class="muted">—</span>`;
  // schedule_override (remediation/config/remediation_policy_engine.py's
  // policy_for_finding()) is true when this asset has its own remediation_schedule
  // override (see /asset-policy) - shown distinctly from the domain's own default
  // cadence so an admin can tell at a glance which findings are on a custom schedule.
  const cadenceCell = policy.cadence
    ? `${escapeHtml(policy.cadence)}${policy.schedule_override ? ` <span class="badge badge-medium" data-tooltip="Asset-level override - see /asset-policy">override</span>` : ""}`
    : `<span class="muted">—</span>`;

  return `
    <tr data-finding-id="${escapeHtml(f.id)}">
      <td data-col="priority"><span class="badge badge-priority-${(f.priority || "").toLowerCase()}">${escapeHtml(f.priority)}</span></td>
      <td data-col="id"><button type="button" class="link-button finding-id-link" data-finding-id="${escapeHtml(f.id)}">${escapeHtml(f.id)}</button></td>
      <td data-col="asset">${escapeHtml(f.asset && f.asset.name)}</td>
      <td data-col="asset_type" class="asset-type-cell">${escapeHtml(f.asset && f.asset.type)}</td>
      <td data-col="cloud_provider" class="asset-type-cell">${f.cloud_provider ? escapeHtml(f.cloud_provider) : `<span class="muted">—</span>`}</td>
      <td data-col="environment">${environmentCellHtml(f.environment, escapeHtml)}</td>
      <td data-col="owner">${escapeHtml(f.owner || "Unowned")}</td>
      <td data-col="team">${escapeHtml(f.team || "—")}</td>
      <td data-col="remediation_mechanism">${remediationMechanism}</td>
      <td data-col="category">${category}</td>
      <td data-col="title">${escapeHtml(f.title)}</td>
      <td data-col="cve"><code>${escapeHtml(f.cve || "—")}</code></td>
      <td data-col="kev">${kev}</td>
      <td data-col="epss">${epss}</td>
      <td data-col="threat_intel">${threatIntelCellHtml(f)}</td>
      <td data-col="last_seen">${escapeHtml(f.last_seen || "—")}</td>
      <td data-col="sla">${slaCell}</td>
      <td data-col="attack">${attackTags}</td>
      <td data-col="change_type">${changeTypeCell}</td>
      <td data-col="cadence">${cadenceCell}</td>
      <td data-col="next_window">${windowText(policy.next_window)}</td>
      <td data-col="auto_remediate">${policy.auto_remediate ? "Yes" : "No"}</td>
      <td data-col="ai"><a href="/ai-assist?finding_id=${encodeURIComponent(f.id)}" data-link class="ai-assist-link">${icon("ai", 14)} Ask AI</a></td>
    </tr>`;
}

function sortFindings(findings, key, dir) {
  const factor = dir === "asc" ? 1 : -1;
  return [...findings].sort((a, b) => {
    let av;
    let bv;
    if (key === "priority") {
      av = PRIORITY_RANK[a.priority] ?? -1;
      bv = PRIORITY_RANK[b.priority] ?? -1;
    } else if (key === "sla") {
      av = a.sla && a.sla.days_remaining !== null && a.sla.days_remaining !== undefined ? a.sla.days_remaining : Infinity;
      bv = b.sla && b.sla.days_remaining !== null && b.sla.days_remaining !== undefined ? b.sla.days_remaining : Infinity;
    } else {
      av = a[key];
      bv = b[key];
    }
    if (av < bv) return -1 * factor;
    if (av > bv) return 1 * factor;
    return 0;
  });
}

function applyFilters(findings, filters) {
  let result = findings.filter((f) => {
    if (filters.priority !== "all" && f.priority !== filters.priority) return false;
    if (filters.assetType !== "all" && (f.asset && f.asset.type) !== filters.assetType) return false;
    if (filters.environment !== "all" && (f.environment || "unknown") !== filters.environment) return false;
    if (filters.category !== "all" && f.scan_type !== filters.category) return false;
    if (filters.infraType !== "all" && f.infra_category !== filters.infraType) return false;
    if (filters.kevOnly && !(f.kev && f.kev.listed)) return false;
    if (filters.cve && f.cve !== filters.cve) return false;
    if (filters.title && f.title !== filters.title) return false;
    if (filters.assetName && (f.asset && f.asset.name) !== filters.assetName) return false;
    return true;
  });
  if (filters.dateRange && filters.dateRange.preset) {
    const range = computeRange(filters.dateRange.preset, filters.dateRange.customFrom, filters.dateRange.customTo);
    result = filterByDateRange(result, range, "first_seen");
  }
  return result;
}

// Mirrors dashboard_data.sla_summary()'s logic in JS so the KPI cards always match
// whatever slice of findings the table is currently showing (tenant + filters), not
// just the unfiltered server-side total.
function computeSlaSummary(findings) {
  let breached = 0;
  let atRisk = 0;
  let onTrack = 0;
  for (const f of findings) {
    const sla = f.sla || {};
    if (sla.breached) breached += 1;
    else if (sla.days_remaining !== null && sla.days_remaining !== undefined && sla.days_remaining <= 3) atRisk += 1;
    else onTrack += 1;
  }
  return { breached, at_risk: atRisk, on_track: onTrack };
}

export async function render(container) {
  const topbarExtra = document.getElementById("topbar-extra");
  let allFindings = [];
  let lastFetched = null;
  let sort = { key: "priority", dir: "desc" };
  let page = 1;
  let visibleColumns = loadVisibleColumns("queue", QUEUE_COLUMNS);
  // A nav deep-link (e.g. /queue?category=infra-vm from the Security Domains menu) can
  // preselect the category filter on load - falls back to "all" the same as before.
  const initialCategory = new URLSearchParams(window.location.search).get("category") || "all";
  // A card on the Infrastructure Vulnerabilities hub (/infrastructure) deep-links here
  // with &infraType=os|network|network-security|ot|cloud on top of category=infra-vm.
  const initialInfraType = new URLSearchParams(window.location.search).get("infraType") || "all";
  // Drill-down deep-links from the Vulnerability/Asset Mapping dashboards
  // (/vulnerability-mapping, /asset-mapping) - see applyFilters()'s cve/assetName
  // predicate above.
  const initialCve = new URLSearchParams(window.location.search).get("cve") || null;
  const initialTitle = new URLSearchParams(window.location.search).get("title") || null;
  const initialAssetName = new URLSearchParams(window.location.search).get("asset") || null;
  let filters = {
    priority: "all", assetType: "all", environment: "all", category: initialCategory, infraType: initialInfraType,
    kevOnly: false, cve: initialCve, title: initialTitle, assetName: initialAssetName,
    dateRange: { preset: "", customFrom: "", customTo: "" },
  };
  // A global-search result (search.js) deep-links here with ?highlight=<id> - the
  // matching row gets scrolled into view and visually marked once on load.
  const highlightId = new URLSearchParams(window.location.search).get("highlight");
  let hasScrolledToHighlight = false;

  function renderLiveBadge() {
    if (!topbarExtra) return;
    topbarExtra.innerHTML = `<span class="live-badge" data-tooltip="Auto-refreshes every ${REFRESH_MS / 1000}s">` +
      `<span class="live-dot"></span> Live · updated ${lastFetched ? timeAgo(lastFetched) : "just now"}</span>`;
  }

  function currentSlice() {
    const tenantFiltered = filterByTenant(allFindings);
    return applyFilters(tenantFiltered, filters);
  }

  function renderRows() {
    const sliced = currentSlice();
    const sorted = sortFindings(sliced, sort.key, sort.dir);

    // A highlighted deep-link (?highlight=<id>) may land on a page other than the
    // current one - jump to its page once, same one-time-only rule as the scroll itself.
    if (highlightId && !hasScrolledToHighlight) {
      const idx = sorted.findIndex((f) => f.id === highlightId);
      if (idx !== -1) page = Math.floor(idx / DEFAULT_PAGE_SIZE) + 1;
    }

    const paged = paginate(sorted, page);
    page = paged.page;
    const tbody = container.querySelector("#queue-body");
    if (!tbody) return;
    tbody.innerHTML = paged.rows.length
      ? paged.rows.map(rowHtml).join("")
      : `<tr><td colspan="${QUEUE_COLUMNS.length}" class="empty-state">No findings match the current filters.</td></tr>`;
    applyColumnVisibility(container.querySelector("#queue-table"), visibleColumns);
    container.querySelectorAll("th.sortable").forEach((th) => {
      const indicator = th.querySelector(".sort-indicator");
      indicator.textContent = th.dataset.sort === sort.key ? (sort.dir === "asc" ? "▲" : "▼") : "";
    });
    const countEl = container.querySelector("#queue-count");
    if (countEl) countEl.textContent = `${sorted.length} of ${allFindings.length} finding(s)`;
    const paginationEl = container.querySelector("#queue-pagination");
    if (paginationEl) paginationEl.innerHTML = paginationHtml(paged.page, paged.totalPages);

    // KPI cards always reflect the current tenant/filter slice, not the unfiltered total.
    const sla = computeSlaSummary(sliced);
    const breachedEl = container.querySelector("#kpi-breached");
    const atRiskEl = container.querySelector("#kpi-at-risk");
    const onTrackEl = container.querySelector("#kpi-on-track");
    if (breachedEl) breachedEl.textContent = sla.breached;
    if (atRiskEl) atRiskEl.textContent = sla.at_risk;
    if (onTrackEl) onTrackEl.textContent = sla.on_track;

    if (highlightId) applyHighlight(sliced);
  }

  // Scrolls to and marks the finding a global-search result linked to (?highlight=<id>).
  // Only auto-scrolls once, so the periodic 20s refresh doesn't keep jerking the page
  // back to it. If the finding exists but the current tenant/filter selection hides it,
  // says so instead of silently showing nothing.
  function applyHighlight(sliced) {
    const noteEl = container.querySelector("#highlight-note");
    const row = container.querySelector(`[data-finding-id="${CSS.escape(highlightId)}"]`);
    if (row) {
      row.classList.add("row-highlight");
      if (!hasScrolledToHighlight) {
        row.scrollIntoView({ behavior: "smooth", block: "center" });
        hasScrolledToHighlight = true;
      }
      if (noteEl) noteEl.innerHTML = "";
      return;
    }
    if (!noteEl) return;
    const existsAtAll = allFindings.some((f) => f.id === highlightId);
    noteEl.innerHTML = existsAtAll
      ? `<div class="callout callout-warn">Finding <code>${escapeHtml(highlightId)}</code> exists but is hidden by ` +
        `the current tenant/filter selection above - clear filters to see it.</div>`
      : `<div class="callout callout-warn">Finding <code>${escapeHtml(highlightId)}</code> was not found.</div>`;
  }

  function assetTypeOptions() {
    const types = [...new Set(allFindings.map((f) => f.asset && f.asset.type).filter(Boolean))].sort();
    return types.map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join("");
  }

  function infraTypeOptions() {
    // Always lists every known sub-category (see infraTypes.js) - same "show the full
    // known taxonomy" reasoning as categoryOptions() below.
    return INFRA_CATEGORIES.map((value) =>
      `<option value="${value}" ${value === filters.infraType ? "selected" : ""}>${escapeHtml(INFRA_CATEGORY_LABELS[value])}</option>`).join("");
  }

  function categoryOptions() {
    // Always list every real queue category (not just ones present in today's data) so a
    // deep link like /queue?category=dast shows a matching, selected dropdown option even
    // when there's currently no sample finding of that type - see scanTypes.js.
    const seen = new Map(QUEUE_SCAN_TYPES.map((t) => [t, SCAN_TYPE_LABELS[t]]));
    for (const f of allFindings) {
      if (f.scan_type && !seen.has(f.scan_type)) seen.set(f.scan_type, f.scan_type_label || f.scan_type);
    }
    return [...seen.entries()].sort().map(([value, label]) =>
      `<option value="${value}" ${value === filters.category ? "selected" : ""}>${escapeHtml(label)}</option>`).join("");
  }

  function wireControls() {
    container.querySelectorAll("th.sortable").forEach((th) => {
      th.addEventListener("click", () => {
        const key = th.dataset.sort;
        sort = sort.key === key ? { key, dir: sort.dir === "asc" ? "desc" : "asc" } : { key, dir: "desc" };
        page = 1;
        renderRows();
      });
    });
    container.querySelector("#f-priority").addEventListener("change", (e) => { filters.priority = e.target.value; page = 1; renderRows(); });
    container.querySelector("#f-environment").addEventListener("change", (e) => { filters.environment = e.target.value; page = 1; renderRows(); });
    // Asset type/Category/Infra sub-category are omitted entirely (not just disabled)
    // on the single-asset-type deep-links - see SINGLE_ASSET_TYPE_CATEGORIES above.
    const assetTypeEl = container.querySelector("#f-asset-type");
    if (assetTypeEl) assetTypeEl.addEventListener("change", (e) => { filters.assetType = e.target.value; page = 1; renderRows(); });
    const categoryEl = container.querySelector("#f-category");
    if (categoryEl) categoryEl.addEventListener("change", (e) => { filters.category = e.target.value; page = 1; renderRows(); });
    const infraTypeEl = container.querySelector("#f-infra-type");
    if (infraTypeEl) infraTypeEl.addEventListener("change", (e) => { filters.infraType = e.target.value; page = 1; renderRows(); });
    container.querySelector("#f-kev-only").addEventListener("change", (e) => { filters.kevOnly = e.target.checked; page = 1; renderRows(); });
    wireDateRange(container, "f-daterange", (dateRange) => { filters.dateRange = dateRange; page = 1; renderRows(); });
  }

  function renderShell() {
    const hideAssetCategoryFilters = SINGLE_ASSET_TYPE_CATEGORIES.has(filters.category);
    container.innerHTML = `
      <p class="subtitle">
        Re-scored on every page load from <a href="/priority-rules" data-link>the
        current priority rules</a> — edit the weights there and reload this page to see it change.
      </p>

      ${tenantBannerHtml()}

      <div id="highlight-note"></div>

      <div class="kpi-grid">
        <div class="kpi-card kpi-danger"><div class="kpi-value" id="kpi-breached">0</div><div class="kpi-label">SLA breached</div></div>
        <div class="kpi-card kpi-warn"><div class="kpi-value" id="kpi-at-risk">0</div><div class="kpi-label">Due within 3 days</div></div>
        <div class="kpi-card kpi-good"><div class="kpi-value" id="kpi-on-track">0</div><div class="kpi-label">On track</div></div>
      </div>
      <p class="filter-count" style="margin:-8px 0 8px">KPIs above reflect the current tenant/filter selection below.</p>

      <div class="filter-bar">
        <label>Priority
          <select id="f-priority">
            <option value="all">All</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </label>
        <label>Environment
          <select id="f-environment">
            <option value="all">All</option>
            ${Object.entries(ENVIRONMENT_LABELS).map(([value, label]) =>
              `<option value="${value}" ${filters.environment === value ? "selected" : ""}>${escapeHtml(label)}</option>`).join("")}
          </select>
        </label>
        ${hideAssetCategoryFilters ? "" : `
        <label>Asset type
          <select id="f-asset-type"><option value="all">All</option>${assetTypeOptions()}</select>
        </label>
        <label>Category
          <select id="f-category"><option value="all" ${filters.category === "all" ? "selected" : ""}>All</option>${categoryOptions()}</select>
        </label>
        <label>Infra sub-category
          <select id="f-infra-type"><option value="all" ${filters.infraType === "all" ? "selected" : ""}>All</option>${infraTypeOptions()}</select>
        </label>`}
        <label class="checkbox-label"><input type="checkbox" id="f-kev-only"> CISA KEV-listed only</label>
        ${dateRangeHtml("f-daterange", filters.dateRange)}
        <span class="filter-count" id="queue-count"></span>
      </div>
      ${dateRangeDisclaimerHtml()}

      <div class="table-toolbar">
        ${exportButtonsHtml("queue")}
        ${columnPickerHtml("queue", QUEUE_COLUMNS, visibleColumns)}
      </div>

      <div class="table-scroll">
        <table class="data-table" id="queue-table">
          <thead>
            <tr>
              <th class="sortable" data-col="priority" data-sort="priority">Priority <span class="sort-indicator"></span></th>
              <th data-col="id">ID</th><th data-col="asset">Asset</th><th data-col="asset_type">Asset Type</th><th data-col="cloud_provider">Cloud Provider</th><th data-col="environment">Environment</th><th data-col="owner">Owner</th><th data-col="team">Team</th><th data-col="remediation_mechanism">Remediation Mechanism</th><th data-col="category">Category</th><th data-col="title">Title</th><th data-col="cve">CVE</th>
              <th data-col="kev">KEV</th><th data-col="epss">EPSS</th><th data-col="threat_intel">Threat Intel</th><th data-col="last_seen">Last Seen</th>
              <th class="sortable" data-col="sla" data-sort="sla">SLA Due <span class="sort-indicator"></span></th>
              <th data-col="attack">ATT&amp;CK</th>
              <th data-col="change_type">Change Type</th><th data-col="cadence">Cadence</th><th data-col="next_window">Next Maintenance Window</th><th data-col="auto_remediate">Auto-Remediate</th>
              <th data-col="ai">AI</th>
            </tr>
          </thead>
          <tbody id="queue-body"></tbody>
        </table>
      </div>
      <div id="queue-pagination"></div>

      <div class="callout">
        Priority reasoning for each finding (why it landed where it did) is in the plan detail
        at <a href="/remediate" data-link>/remediate</a>. MITRE ATT&amp;CK tags are a
        keyword heuristic, not authoritative technique attribution — see
        <code>remediation/enrichment/attack_mapping.py</code>'s docstring. "Category" is a
        methodology taxonomy (Infrastructure VM / SCA / Cert-Mgmt / DAST) inferred from
        asset type (and, for application findings, whether a CVE is present) — see
        <code>remediation/enrichment/scan_type_mapping.py</code>'s docstring for what it
        does and doesn't claim. Change Type/Cadence/Next Maintenance Window/Auto-Remediate
        come from <a href="/remediation-policy" data-link>the configurable Remediation
        Policy</a> — a "override" badge on Cadence means this specific asset has its own
        schedule set on <a href="/asset-policy" data-link>Asset Policy</a>, taking
        precedence over its domain's default. See
        <a href="/remediation-approvals" data-link>Remediation Approvals</a> for normal/emergency
        findings awaiting a human decision.
      </div>`;
    wireControls();
    wireExportButtons(container, "queue", {
      getRows: () => sortFindings(currentSlice(), sort.key, sort.dir),
      columns: EXPORT_COLUMNS,
      filenameBase: "vulnhunter-remediation-queue",
    });
    wireColumnPicker(container, "queue", (visible) => {
      visibleColumns = visible;
      applyColumnVisibility(container.querySelector("#queue-table"), visibleColumns);
    });
    renderRows();
  }

  async function load() {
    const [data, assetsData] = await Promise.all([api.queue(), api.assetsList()]);
    const { ownerByAssetName, teamByAssetName, environmentByAssetName } = buildOwnerTeamMaps(assetsData.assets);
    allFindings = data.findings.map((f) => ({
      ...f,
      owner: ownerByAssetName.get(f.asset && f.asset.name),
      team: teamByAssetName.get(f.asset && f.asset.name),
      environment: environmentByAssetName.get(f.asset && f.asset.name),
    }));
    lastFetched = new Date();
    renderShell();
    renderLiveBadge();

    const kevCount = allFindings.filter((f) => f.kev && f.kev.listed).length;
    const breachedCount = allFindings.filter((f) => f.sla && f.sla.breached).length;
    const teamAssignedCount = allFindings.filter((f) => f.team).length;
    const teamAssignedPct = allFindings.length ? Math.round((teamAssignedCount / allFindings.length) * 100) : 0;

    const alerts = [];
    if (breachedCount > 0) {
      alerts.push(insightAlertHtml(`<strong>${breachedCount}</strong> finding(s) are past their SLA window.`, "danger"));
    }
    if (kevCount > 0) {
      alerts.push(insightAlertHtml(`<strong>${kevCount}</strong> finding(s) are CISA KEV-listed - confirmed actively exploited.`, "warn"));
    }
    if (teamAssignedPct < 50 && allFindings.length) {
      alerts.push(insightAlertHtml(
        `Only <strong>${teamAssignedPct}%</strong> of findings have a team assigned - see <a href="/assets" data-link>Asset Inventory</a> to import ownership.`,
        "info",
      ));
    }

    // Trimmed to just the one most load-bearing section (real, page-specific alerts
    // computed from live data) - the panel now starts collapsed by default (see
    // insightsPanel.js), so what little it shows on open should earn the click. Tips/
    // term definitions are still available via the FAQ and this page's own callouts.
    setInsightsContent(insightSectionHtml("On this page", alerts.join("")));
  }

  const onTenantChanged = () => { page = 1; renderRows(); };
  window.addEventListener("tenant-changed", onTenantChanged);

  // Delegated on the outer container (survives renderShell()'s innerHTML replacement) -
  // wired exactly once per render() call, same rule as wirePagination below.
  container.addEventListener("click", (e) => {
    const btn = e.target.closest(".finding-id-link");
    if (!btn) return;
    const finding = allFindings.find((f) => f.id === btn.dataset.findingId);
    if (finding) openFindingDetail(finding);
  });
  wirePagination(container, (p) => { page = p; renderRows(); });

  await load();
  const tickTimer = setInterval(renderLiveBadge, 1000);
  const refreshTimer = setInterval(() => { load().catch((err) => console.error(err)); }, REFRESH_MS);

  return () => {
    clearInterval(tickTimer);
    clearInterval(refreshTimer);
    window.removeEventListener("tenant-changed", onTenantChanged);
  };
}
