import { api } from "../api.js";
import { escapeHtml, timeAgo } from "../dom.js";
import { icon } from "../icons.js";
import { getTenant, filterByTenant } from "../tenant.js";
import { QUEUE_SCAN_TYPES, SCAN_TYPE_LABELS } from "../scanTypes.js";
import { exportButtonsHtml, wireExportButtons } from "../export.js";

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
  { label: "SLA Due", value: (f) => f.sla && f.sla.due_date },
  { label: "SLA Breached", value: (f) => !!(f.sla && f.sla.breached) },
  { label: "ATT&CK Techniques", value: (f) => (f.attack_techniques || []).map((t) => t.technique_id).join("; ") },
  { label: "Exception", value: (f) => (f.exception ? f.exception.reason : "") },
];

export const title = "Live Remediation Queue";

const REFRESH_MS = 20000;
const PRIORITY_RANK = { Critical: 3, High: 2, Medium: 1, Low: 0 };

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
    slaCell += `<br><span class="exception-tag" data-tooltip="${escapeHtml(f.exception.reason)}">` +
      `Risk-accepted until ${escapeHtml(f.exception.expires_on)}</span>`;
  }

  const attackTags = (f.attack_techniques && f.attack_techniques.length)
    ? f.attack_techniques.map((t) => `<span class="attack-tag" title="${escapeHtml(t.tactic)}">${escapeHtml(t.technique_id)}</span>`).join("")
    : `<span class="muted">—</span>`;

  const category = f.scan_type
    ? `<span class="category-tag" data-tooltip="${escapeHtml(f.scan_type_label || "")}">${escapeHtml(f.scan_type)}</span>`
    : `<span class="muted">—</span>`;

  return `
    <tr data-finding-id="${escapeHtml(f.id)}">
      <td><span class="badge badge-priority-${(f.priority || "").toLowerCase()}">${escapeHtml(f.priority)}</span></td>
      <td>${escapeHtml(f.id)}</td>
      <td>${escapeHtml(f.asset && f.asset.name)}</td>
      <td class="asset-type-cell">${escapeHtml(f.asset && f.asset.type)}</td>
      <td>${category}</td>
      <td>${escapeHtml(f.title)}</td>
      <td><code>${escapeHtml(f.cve || "—")}</code></td>
      <td>${kev}</td>
      <td>${epss}</td>
      <td>${slaCell}</td>
      <td>${attackTags}</td>
      <td><a href="/ai-assist?finding_id=${encodeURIComponent(f.id)}" data-link class="ai-assist-link">${icon("ai", 14)} Ask AI</a></td>
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
  return findings.filter((f) => {
    if (filters.priority !== "all" && f.priority !== filters.priority) return false;
    if (filters.assetType !== "all" && (f.asset && f.asset.type) !== filters.assetType) return false;
    if (filters.category !== "all" && f.scan_type !== filters.category) return false;
    if (filters.kevOnly && !(f.kev && f.kev.listed)) return false;
    return true;
  });
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
  // A nav deep-link (e.g. /queue?category=infra-vm from the Security Domains menu) can
  // preselect the category filter on load - falls back to "all" the same as before.
  const initialCategory = new URLSearchParams(window.location.search).get("category") || "all";
  let filters = { priority: "all", assetType: "all", category: initialCategory, kevOnly: false };
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
    const tbody = container.querySelector("#queue-body");
    if (!tbody) return;
    tbody.innerHTML = sorted.length
      ? sorted.map(rowHtml).join("")
      : `<tr><td colspan="12" class="empty-state">No findings match the current filters.</td></tr>`;
    container.querySelectorAll("th.sortable").forEach((th) => {
      const indicator = th.querySelector(".sort-indicator");
      indicator.textContent = th.dataset.sort === sort.key ? (sort.dir === "asc" ? "▲" : "▼") : "";
    });
    const countEl = container.querySelector("#queue-count");
    if (countEl) countEl.textContent = `${sorted.length} of ${allFindings.length} finding(s)`;

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
    return types.map((t) => `<option value="${t}">${t}</option>`).join("");
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
        renderRows();
      });
    });
    container.querySelector("#f-priority").addEventListener("change", (e) => { filters.priority = e.target.value; renderRows(); });
    container.querySelector("#f-asset-type").addEventListener("change", (e) => { filters.assetType = e.target.value; renderRows(); });
    container.querySelector("#f-category").addEventListener("change", (e) => { filters.category = e.target.value; renderRows(); });
    container.querySelector("#f-kev-only").addEventListener("change", (e) => { filters.kevOnly = e.target.checked; renderRows(); });
  }

  function renderShell() {
    const tenant = getTenant();
    container.innerHTML = `
      <p class="subtitle">
        Re-scored on every page load from <a href="/priority-rules" data-link>the
        current priority rules</a> — edit the weights there and reload this page to see it change.
      </p>

      ${tenant.id !== "all" ? `
        <div class="callout callout-warn">
          Viewing as <strong>${escapeHtml(tenant.label)}</strong> - illustrative MSSP demo
          view (partitions the same real findings by asset category). Not real
          per-tenant data isolation - see the <a href="/faq" data-link>FAQ</a>.
        </div>` : ""}

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
        <label>Asset type
          <select id="f-asset-type"><option value="all">All</option>${assetTypeOptions()}</select>
        </label>
        <label>Category
          <select id="f-category"><option value="all" ${filters.category === "all" ? "selected" : ""}>All</option>${categoryOptions()}</select>
        </label>
        <label class="checkbox-label"><input type="checkbox" id="f-kev-only"> CISA KEV-listed only</label>
        <span class="filter-count" id="queue-count"></span>
      </div>

      ${exportButtonsHtml("queue")}

      <div class="table-scroll">
        <table class="data-table">
          <thead>
            <tr>
              <th class="sortable" data-sort="priority">Priority <span class="sort-indicator"></span></th>
              <th>ID</th><th>Asset</th><th>Asset Type</th><th>Category</th><th>Title</th><th>CVE</th>
              <th>KEV</th><th>EPSS</th>
              <th class="sortable" data-sort="sla">SLA Due <span class="sort-indicator"></span></th>
              <th>ATT&amp;CK</th><th>AI</th>
            </tr>
          </thead>
          <tbody id="queue-body"></tbody>
        </table>
      </div>

      <div class="callout">
        Priority reasoning for each finding (why it landed where it did) is in the plan detail
        at <a href="/remediate" data-link>/remediate</a>. MITRE ATT&amp;CK tags are a
        keyword heuristic, not authoritative technique attribution — see
        <code>remediation/enrichment/attack_mapping.py</code>'s docstring. "Category" is a
        methodology taxonomy (Infrastructure VM / SCA / Cert-Mgmt) inferred from asset
        type — see <code>remediation/enrichment/scan_type_mapping.py</code>'s docstring
        for what it does and doesn't claim (and why DAST has no sample data yet).
      </div>`;
    wireControls();
    wireExportButtons(container, "queue", {
      getRows: () => sortFindings(currentSlice(), sort.key, sort.dir),
      columns: EXPORT_COLUMNS,
      filenameBase: "vulnhunter-remediation-queue",
    });
    renderRows();
  }

  async function load() {
    const data = await api.queue();
    allFindings = data.findings;
    lastFetched = new Date();
    renderShell();
    renderLiveBadge();
  }

  const onTenantChanged = () => renderRows();
  window.addEventListener("tenant-changed", onTenantChanged);

  await load();
  const tickTimer = setInterval(renderLiveBadge, 1000);
  const refreshTimer = setInterval(() => { load().catch((err) => console.error(err)); }, REFRESH_MS);

  return () => {
    clearInterval(tickTimer);
    clearInterval(refreshTimer);
    window.removeEventListener("tenant-changed", onTenantChanged);
  };
}
