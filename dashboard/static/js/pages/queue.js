import { api } from "../api.js";
import { escapeHtml, timeAgo } from "../dom.js";
import { icon } from "../icons.js";
import { getTenant, filterByTenant } from "../tenant.js";

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

  const attackTags = (f.attack_techniques && f.attack_techniques.length)
    ? f.attack_techniques.map((t) => `<span class="attack-tag" title="${escapeHtml(t.tactic)}">${escapeHtml(t.technique_id)}</span>`).join("")
    : `<span class="muted">—</span>`;

  return `
    <tr>
      <td><span class="badge badge-priority-${(f.priority || "").toLowerCase()}">${escapeHtml(f.priority)}</span></td>
      <td>${escapeHtml(f.id)}</td>
      <td>${escapeHtml(f.asset && f.asset.name)}</td>
      <td class="asset-type-cell">${escapeHtml(f.asset && f.asset.type)}</td>
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
  let filters = { priority: "all", assetType: "all", kevOnly: false };

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
      : `<tr><td colspan="11" class="empty-state">No findings match the current filters.</td></tr>`;
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
  }

  function assetTypeOptions() {
    const types = [...new Set(allFindings.map((f) => f.asset && f.asset.type).filter(Boolean))].sort();
    return types.map((t) => `<option value="${t}">${t}</option>`).join("");
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
        <label class="checkbox-label"><input type="checkbox" id="f-kev-only"> CISA KEV-listed only</label>
        <span class="filter-count" id="queue-count"></span>
      </div>

      <div class="table-scroll">
        <table class="data-table">
          <thead>
            <tr>
              <th class="sortable" data-sort="priority">Priority <span class="sort-indicator"></span></th>
              <th>ID</th><th>Asset</th><th>Asset Type</th><th>Title</th><th>CVE</th>
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
        <code>remediation/enrichment/attack_mapping.py</code>'s docstring.
      </div>`;
    wireControls();
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
