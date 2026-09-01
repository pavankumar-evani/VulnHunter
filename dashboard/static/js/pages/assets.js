import { api } from "../api.js";
import { escapeHtml, flash, openModal, closeModal } from "../dom.js";
import { exportButtonsHtml, wireExportButtons } from "../export.js";
import { columnPickerHtml, loadVisibleColumns, applyColumnVisibility, wireColumnPicker } from "../columnPicker.js";
import { paginate, paginationHtml, wirePagination } from "../pagination.js";

export const title = "Asset Inventory";

const PAGE_SIZE = 20;

// Order matches the header row/assetRow() below - see columnPicker.js. This table is
// more modest than Queue/Findings (12 columns, not 22+), so most stay visible by
// default - only the two least immediately-actionable-at-a-glance columns start hidden.
const ASSET_COLUMNS = [
  { id: "asset", label: "Asset" },
  { id: "type", label: "Type" },
  { id: "ip", label: "IP Address" },
  { id: "mac", label: "MAC Address", defaultVisible: false },
  { id: "findings", label: "Findings" },
  { id: "severity", label: "Highest Severity" },
  { id: "kev", label: "KEV Exposure", defaultVisible: false },
  { id: "risk", label: "Risk Score" },
  { id: "environment", label: "Environment" },
  { id: "schedule", label: "Remediation Schedule" },
  { id: "owner", label: "Owner" },
  { id: "team", label: "Team" },
  { id: "eol", label: "EOL/EOS", defaultVisible: false },
  { id: "edit", label: "Edit" },
];

const EXPORT_COLUMNS = [
  { label: "Asset", value: (a) => a.name },
  { label: "Type", value: (a) => a.type },
  { label: "IP Address", value: (a) => a.ip },
  { label: "IP Version", value: (a) => (a.ip_version ? `IPv${a.ip_version}` : "") },
  { label: "MAC Address", value: (a) => a.mac },
  { label: "OS", value: (a) => a.os },
  { label: "Findings", value: (a) => a.finding_count },
  { label: "Critical Findings", value: (a) => a.critical_count },
  { label: "Highest Severity", value: (a) => a.highest_severity },
  { label: "KEV Exposure", value: (a) => a.kev_count },
  { label: "Impact Score", value: (a) => a.impact_score },
  { label: "Likelihood Score", value: (a) => a.likelihood_score },
  { label: "Risk Score", value: (a) => a.risk_score },
  { label: "Risk Tier", value: (a) => a.risk_tier },
  { label: "Facing", value: (a) => a.facing },
  { label: "Environment", value: (a) => a.environment },
  { label: "Remediation Schedule Override", value: (a) => (a.remediation_schedule && a.remediation_schedule.cadence) || "" },
  { label: "Owner", value: (a) => a.owner },
  { label: "Team", value: (a) => a.team },
  { label: "EOL/EOS Status", value: (a) => a.eol_status && a.eol_status.status },
  { label: "EOL/EOS Date", value: (a) => a.eol_status && a.eol_status.eol_date },
];

// Same badge-class convention as priority/severity everywhere else in this app -
// risk_tier reuses the Critical/High/Medium/Low scale, not a separate one.
function riskTierBadgeHtml(a) {
  if (typeof a.risk_score !== "number") return `<span class="muted">—</span>`;
  return `<span class="badge badge-${(a.risk_tier || "").toLowerCase()}" data-tooltip="Impact ${a.impact_score} × Likelihood ${a.likelihood_score} (NIST SP 800-30-inspired, not a certified assessment - see the FAQ)">${a.risk_score}</span>`;
}

// Real, dated vendor-lifecycle lookup (remediation/enrichment/eol_lookup.py) - never a
// guessed date. "unknown" means this asset's OS string didn't match anything in that
// small reference table, not that it's confirmed still supported.
const EOL_BADGE_CLASS = { eol: "badge-critical", "eol-soon": "badge-medium", supported: "badge-auto_approvable" };
const EOL_LABEL = { eol: "EOL", "eol-soon": "EOL soon", supported: "Supported" };

function eolCellHtml(a) {
  const eol = a.eol_status;
  if (!eol || eol.status === "unknown") return `<span class="muted">Unknown</span>`;
  const tooltip = `${eol.vendor} lifecycle - ${eol.eol_date} (${eol.source})`;
  return `<span class="badge ${EOL_BADGE_CLASS[eol.status]}" data-tooltip="${escapeHtml(tooltip)}">${EOL_LABEL[eol.status]}</span>`;
}

// Pattern-matched (NOT machine learning - see pattern_recognition.py's module
// docstring) owner/team suggestion for an unowned asset, based on hostname naming
// convention, IP subnet, and asset-type matches against assets that already have an
// owner. Never applied automatically - a one-click "Use" button on top of the
// existing manual "Edit" flow, same non-authoritative posture as the ATT&CK tags and
// compensating-control suggestions elsewhere in this app.
function ownerCellHtml(a) {
  if (a.owner) return escapeHtml(a.owner);
  if (!a.suggestion) return `<span class="muted">Unassigned</span>`;
  const pct = Math.round(a.suggestion.confidence * 100);
  return `
    <span class="muted">Unassigned</span>
    <div class="asset-suggestion" data-tooltip="${escapeHtml(a.suggestion.reasons.join("; "))}">
      Suggested: ${escapeHtml(a.suggestion.owner)} (${pct}% pattern match)
      <button type="button" class="link-button" data-apply-suggestion="${escapeHtml(a.name)}">Use</button>
    </div>`;
}

// Same manually-set, never-guessed convention as Risk's own facing classification -
// drives the remediation policy engine's "dev" domain override (see
// remediation/config/remediation_policy.yaml).
const ENVIRONMENT_LABELS = { prod: "Production", staging: "Staging", dev: "Dev", unknown: "Unknown" };
const ENVIRONMENT_BADGE_CLASS = { prod: "badge-critical", staging: "badge-medium", dev: "badge-auto_approvable", unknown: "badge-outline" };

function environmentCellHtml(a) {
  const env = a.environment || "unknown";
  return `<span class="badge ${ENVIRONMENT_BADGE_CLASS[env] || "badge-outline"}">${escapeHtml(ENVIRONMENT_LABELS[env] || env)}</span>`;
}

// Same string-enum convention remediation_policy.yaml's own per-domain `cadence`
// field already uses - an asset-level override (set here or in bulk via
// /asset-policy) is directly interchangeable with a domain's default, shown on
// /queue's own Cadence column with an "override" badge when this is set.
const CADENCE_LABELS = {
  weekly: "Weekly", monthly: "Monthly", quarterly: "Quarterly",
  "half-yearly": "Half-yearly", yearly: "Yearly", "on-demand": "On-demand",
};

function scheduleCellHtml(a) {
  const cadence = a.remediation_schedule && a.remediation_schedule.cadence;
  if (!cadence) return `<span class="muted">Domain default</span>`;
  return `<span class="badge badge-medium" data-tooltip="Overrides this asset's remediation-domain default cadence - see /asset-policy">${escapeHtml(CADENCE_LABELS[cadence] || cadence)}</span>`;
}

// IP/MAC come from whatever a scan finding reported, or a human-set override (see
// asset_inventory.set_network_info) which always wins - see build_asset_inventory()'s
// merge. ip_version (4/6/None) is computed server-side (pattern_recognition.ip_version,
// via the real stdlib `ipaddress` module) so this page never re-implements IP parsing.
function networkCellHtml(a) {
  if (!a.ip) return `<span class="muted">Unknown</span>`;
  const versionBadge = a.ip_version ? `<span class="badge badge-outline" style="margin-left:6px">IPv${a.ip_version}</span>` : "";
  return `${escapeHtml(a.ip)}${versionBadge}`;
}

function macCellHtml(a) {
  return a.mac ? `<code>${escapeHtml(a.mac)}</code>` : `<span class="muted">Unknown</span>`;
}

function assetRow(a) {
  const kev = a.kev_count > 0
    ? `<span class="badge badge-critical">${a.kev_count} KEV</span>`
    : `<span class="muted">—</span>`;
  const severity = a.highest_severity
    ? `<span class="badge badge-${a.highest_severity.toLowerCase()}">${escapeHtml(a.highest_severity)}</span>`
    : `<span class="muted">—</span>`;
  return `
    <tr data-asset-name="${escapeHtml(a.name)}">
      <td data-col="asset">${escapeHtml(a.name)}</td>
      <td data-col="type" class="asset-type-cell">${escapeHtml(a.type)}</td>
      <td data-col="ip">${networkCellHtml(a)}</td>
      <td data-col="mac">${macCellHtml(a)}</td>
      <td data-col="findings">${a.finding_count}</td>
      <td data-col="severity">${severity}</td>
      <td data-col="kev">${kev}</td>
      <td data-col="risk">${riskTierBadgeHtml(a)}</td>
      <td data-col="environment">${environmentCellHtml(a)}</td>
      <td data-col="schedule">${scheduleCellHtml(a)}</td>
      <td data-col="owner">${ownerCellHtml(a)}</td>
      <td data-col="team">${a.team ? escapeHtml(a.team) : `<span class="muted">—</span>`}</td>
      <td data-col="eol">${eolCellHtml(a)}</td>
      <td data-col="edit"><button type="button" class="link-button" data-edit-owner="${escapeHtml(a.name)}">Edit</button></td>
    </tr>`;
}

function columnSelect(fieldName, label, headers, selected) {
  return `
    <label>${label}
      <select name="${fieldName}">
        <option value="">(none)</option>
        ${headers.map((h) => `<option value="${escapeHtml(h)}" ${h === selected ? "selected" : ""}>${escapeHtml(h)}</option>`).join("")}
      </select>
    </label>`;
}

function reconciledRow(entry, groupLabel) {
  return `
    <tr data-reconciled-row>
      <td><span class="badge ${groupLabel === "Matched" ? "badge-auto_approvable" : "badge-manual_only"}">${groupLabel}</span></td>
      <td>${escapeHtml(entry.asset_name)}</td>
      <td><input type="text" class="reconciled-owner" value="${escapeHtml(entry.owner)}"></td>
      <td><input type="text" class="reconciled-team" value="${escapeHtml(entry.team)}"></td>
    </tr>`;
}

// Reads ?risk_tier=Critical,High and/or ?owner=unassigned from the URL (the deep-link
// Overview's own risk-scoring tiles/charts use via wireChartLinks()) and filters the
// real assets list client-side - not a new data source, just a pre-applied view over
// the same /api/assets response this page always shows. No dropdown UI yet (a bigger,
// separate feature); "Clear filter" always returns to the full unfiltered list.
function filtersFromUrl() {
  const params = new URLSearchParams(window.location.search);
  const riskTierParam = params.get("risk_tier");
  return {
    riskTiers: riskTierParam ? riskTierParam.split(",").map((t) => t.trim()).filter(Boolean) : null,
    ownerFilter: params.get("owner"), // "unassigned" is the only real value used today
  };
}

function applyUrlFilters(assets, filters) {
  return assets.filter((a) => {
    if (filters.riskTiers && !filters.riskTiers.includes(a.risk_tier)) return false;
    if (filters.ownerFilter === "unassigned" && a.owner) return false;
    return true;
  });
}

function activeFilterBannerHtml(filters, shownCount, totalCount) {
  if (!filters.riskTiers && !filters.ownerFilter) return "";
  const parts = [];
  if (filters.riskTiers) parts.push(`risk tier: ${filters.riskTiers.join(" or ")}`);
  if (filters.ownerFilter === "unassigned") parts.push("no owner assigned");
  return `
    <div class="callout callout-warn" style="margin-bottom:12px">
      Showing ${shownCount} of ${totalCount} asset(s) - filtered by ${escapeHtml(parts.join(", "))}
      (from a link elsewhere in the app).
      <a href="/assets" data-link>Clear filter</a>
    </div>`;
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const { assets: allAssets } = await api.assetsList();
  const filters = filtersFromUrl();
  const assets = applyUrlFilters(allAssets, filters);
  const visibleColumns = loadVisibleColumns("assets", ASSET_COLUMNS);
  let page = 1;
  // A global-search asset match (search.js) or any other link elsewhere in this app
  // deep-links here with ?highlight=<asset-name> - jump to that asset's real page (same
  // one-time scroll-and-mark pattern queue.js uses for findings) if it's not on page 1.
  const highlightName = new URLSearchParams(window.location.search).get("highlight");
  if (highlightName) {
    const idx = assets.findIndex((a) => a.name === highlightName);
    if (idx !== -1) page = Math.floor(idx / PAGE_SIZE) + 1;
  }
  let hasScrolledToHighlight = false;

  container.innerHTML = `
    <p class="subtitle">
      Every asset with at least one finding against it, aggregated from
      <code>remediation/output/normalized-findings.json</code> - not a separate CMDB, a
      real live query over the same data the Queue and Overview pages already read.
    </p>

    ${activeFilterBannerHtml(filters, assets.length, allAssets.length)}

    <details class="cmdb-import">
      <summary>Import owner/team from a CMDB export (CSV)</summary>
      <p class="filter-count" style="margin:8px 0">
        Upload a CSV export of your asset details - column names are guessed (keyword
        heuristic, adjust below if wrong), then reconciled against the real asset list
        above. "Excel" here means CSV, which Excel exports/opens natively - see the FAQ.
      </p>
      <form class="run-form" id="cmdb-upload-form">
        <label>CSV file<input type="file" name="file" accept=".csv,text/csv" required></label>
        <button type="submit">Preview Import</button>
      </form>
      <div id="cmdb-preview"></div>
    </details>

    <div class="table-toolbar">
      ${exportButtonsHtml("assets")}
      ${columnPickerHtml("assets", ASSET_COLUMNS, visibleColumns)}
    </div>

    <p class="filter-count" id="assets-count" style="margin:-4px 0 8px"></p>
    <div class="table-scroll">
      <table class="data-table" id="assets-table">
        <thead>
          <tr>
            <th data-col="asset">Asset</th><th data-col="type">Type</th><th data-col="ip">IP Address</th><th data-col="mac">MAC Address</th><th data-col="findings">Findings</th><th data-col="severity">Highest Severity</th>
            <th data-col="kev">KEV Exposure</th><th data-col="risk">Risk Score</th><th data-col="environment">Environment</th><th data-col="schedule">Remediation Schedule</th><th data-col="owner">Owner</th><th data-col="team">Team</th><th data-col="eol">EOL/EOS</th><th data-col="edit"></th>
          </tr>
        </thead>
        <tbody id="assets-body"></tbody>
      </table>
    </div>
    <div id="assets-pagination"></div>

    <div class="callout">
      Ownership is stored locally in
      <code>remediation/inventory/asset_ownership.json</code> - a real, editable file
      (same pattern as <code>priority_rules.yaml</code>), not a sync from a real
      CMDB/asset-management system. See the module docstring for what a production
      version would need instead. Unassigned assets may show a <strong>pattern-matched
      suggestion</strong> (hostname naming convention, IP subnet, or asset type shared
      with an already-owned asset) - a transparent heuristic, not machine learning
      (the dataset here is far too small to train anything real on), never applied
      automatically. Hover a suggestion to see exactly why it was made.
      <strong>EOL/EOS</strong> status comes from a small, real table of publicly
      documented vendor lifecycle dates
      (<code>remediation/enrichment/eol_lookup.py</code>), matched against the asset's
      OS string - "Unknown" means no confident match, never a guessed date.
      <strong>Risk Score</strong> (hover a badge for its Impact/Likelihood breakdown) is
      a NIST SP 800-30-inspired Impact × Likelihood score computed from this asset's
      real severity/CVSS, asset criticality, CISA KEV listing, EPSS, exploit-criteria
      matches, and EOL/EOS status (<code>remediation/enrichment/risk_scoring.py</code>,
      configurable in <code>remediation/config/risk_scoring_rules.yaml</code>) - an
      illustrative, disclosed simplification, not a certified RMF/800-30 assessment.
    </div>`;

  let visibleColumnsState = visibleColumns;

  function renderRows() {
    const paged = paginate(assets, page, PAGE_SIZE);
    page = paged.page;
    const tbody = container.querySelector("#assets-body");
    tbody.innerHTML = paged.rows.length
      ? paged.rows.map(assetRow).join("")
      : `<tr><td colspan="${ASSET_COLUMNS.length}" class="empty-state">No assets match the current filter.</td></tr>`;
    applyColumnVisibility(container.querySelector("#assets-table"), visibleColumnsState);
    const paginationEl = container.querySelector("#assets-pagination");
    if (paginationEl) paginationEl.innerHTML = paginationHtml(paged.page, paged.totalPages);
    const countEl = container.querySelector("#assets-count");
    if (countEl) countEl.textContent = `${assets.length} asset(s)`;

    // A global-search asset match (search.js) or any other link elsewhere in this app
    // deep-links here with ?highlight=<asset-name> - same one-time scroll-and-mark
    // pattern queue.js/exceptions.js already use for findings; page was already jumped
    // to this asset's real page above, before the first render.
    if (highlightName && !hasScrolledToHighlight) {
      const row = container.querySelector(`[data-asset-name="${CSS.escape(highlightName)}"]`);
      if (row) {
        row.classList.add("row-highlight");
        row.scrollIntoView({ behavior: "smooth", block: "center" });
        hasScrolledToHighlight = true;
      }
    }
  }

  wireExportButtons(container, "assets", {
    getRows: () => assets,
    columns: EXPORT_COLUMNS,
    filenameBase: "vulnhunter-asset-inventory",
  });
  wireColumnPicker(container, "assets", (visible) => {
    visibleColumnsState = visible;
    applyColumnVisibility(container.querySelector("#assets-table"), visibleColumnsState);
  });
  wirePagination(container, (p) => { page = p; renderRows(); });
  renderRows();

  // Delegated on the outer container (survives renderRows()'s tbody replacement on
  // every page change) - same "wire once, works for rows created later" pattern
  // queue.js's finding-id-link listener already uses. Both actions below can call
  // render(container) again on success (a full re-fetch+re-render), which would
  // otherwise stack a duplicate copy of this same listener on the persistent #app node
  // every time - apply-suggestion fires api.assetSetOwner directly with no modal gate
  // in between, so a stacked duplicate would mean a real duplicate API call per click,
  // not just harmless DOM churn. Stashing the handler on the container and removing any
  // previous copy first keeps exactly one attached.
  if (container._assetsClickHandler) {
    container.removeEventListener("click", container._assetsClickHandler);
  }
  const onAssetsClick = (e) => {
    const suggestBtn = e.target.closest("[data-apply-suggestion]");
    if (suggestBtn) {
      const name = suggestBtn.dataset.applySuggestion;
      const asset = assets.find((a) => a.name === name);
      if (!asset || !asset.suggestion) return;
      api.assetSetOwner(name, { owner: asset.suggestion.owner, team: asset.suggestion.team })
        .then(() => {
          flash(`Applied suggested owner for ${name}.`, "success");
          render(container);
        })
        .catch((err) => flash(err.message, "error"));
      return;
    }
    const editBtn = e.target.closest("[data-edit-owner]");
    if (editBtn) openEditModal(editBtn.dataset.editOwner);
  };
  container._assetsClickHandler = onAssetsClick;
  container.addEventListener("click", onAssetsClick);

  function openEditModal(name) {
    const asset = assets.find((a) => a.name === name);
    const body = openModal(`
        <h2>Edit owner - ${escapeHtml(name)}</h2>
        <form class="run-form" id="owner-form">
          <label>Owner
            <input type="text" name="owner" value="${escapeHtml(asset.owner || "")}">
          </label>
          <label>Team
            <input type="text" name="team" value="${escapeHtml(asset.team || "")}">
          </label>
          <label>IP address (IPv4 or IPv6)
            <input type="text" name="ip" placeholder="e.g. 10.20.30.41 or 2001:db8::1" value="${escapeHtml(asset.ip || "")}">
          </label>
          <label>MAC address
            <input type="text" name="mac" placeholder="e.g. aa:bb:cc:dd:ee:ff" value="${escapeHtml(asset.mac || "")}">
          </label>
          <p class="filter-count" style="margin:-4px 0 8px">
            Overrides whatever a scan finding reported for this asset (or fills it in
            if none did) - clear either field to fall back to the scan-reported value.
          </p>
          <label>Environment
            <select name="environment">
              ${Object.keys(ENVIRONMENT_LABELS).map((v) =>
                `<option value="${v}" ${v === (asset.environment || "unknown") ? "selected" : ""}>${ENVIRONMENT_LABELS[v]}</option>`).join("")}
            </select>
          </label>
          <p class="filter-count" style="margin:-4px 0 8px">
            Environment drives the remediation policy engine's auto-remediate-without-
            approval treatment for non-production assets - see Remediation Policy.
          </p>
          <label>Remediation schedule override
            <select name="cadence">
              <option value="">(none - use domain default)</option>
              ${Object.keys(CADENCE_LABELS).map((v) =>
                `<option value="${v}" ${v === ((asset.remediation_schedule || {}).cadence || "") ? "selected" : ""}>${CADENCE_LABELS[v]}</option>`).join("")}
            </select>
          </label>
          <p class="filter-count" style="margin:-4px 0 8px">
            Overrides this asset's remediation-domain default cadence (see
            <a href="/remediation-policy" data-link>Remediation Policy</a>) - shown with an
            "override" badge on /queue. To bulk-set this across many assets at once, see
            <a href="/asset-policy" data-link>Asset Policy</a>.
          </p>
          <button type="submit">Save</button>
        </form>`);
    body.querySelector("#owner-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        await api.assetSetOwner(name, {
          owner: event.target.owner.value,
          team: event.target.team.value,
        });
        await api.assetSetNetworkInfo(name, {
          ip: event.target.ip.value,
          mac: event.target.mac.value,
        });
        await api.assetSetEnvironment(name, event.target.environment.value);
        const cadence = event.target.cadence.value || null;
        await api.setAssetRemediationSchedule(name, cadence, null);
        closeModal();
        flash(`Updated owner/environment/schedule for ${name}.`, "success");
        render(container);
      } catch (err) {
        flash(err.message, "error");
      }
    });
  }

  let lastCsvText = "";

  function renderPreview(data) {
    const previewEl = container.querySelector("#cmdb-preview");
    const rows = [...data.matched, ...data.unmatched];
    previewEl.innerHTML = `
      <form class="run-form" id="cmdb-mapping-form">
        <p><strong>Column mapping</strong> (re-preview after adjusting)</p>
        ${columnSelect("asset_name", "Asset name column", data.headers, data.column_mapping.asset_name)}
        ${columnSelect("owner", "Owner column", data.headers, data.column_mapping.owner)}
        ${columnSelect("team", "Team column", data.headers, data.column_mapping.team)}
        <button type="submit">Re-preview with this mapping</button>
      </form>

      <p class="filter-count" style="margin:10px 0">
        <strong>${data.matched.length}</strong> matched (already have findings - owner/team
        applies immediately), <strong>${data.unmatched.length}</strong> not yet seen
        (owner/team stored, applies once a finding against them exists),
        <strong>${data.invalid.length}</strong> invalid (no asset name found).
      </p>

      ${rows.length ? `
        <div class="table-scroll">
          <table class="data-table">
            <thead><tr><th>Status</th><th>Asset</th><th>Owner</th><th>Team</th></tr></thead>
            <tbody id="cmdb-reconciled-body">
              ${data.matched.map((e) => reconciledRow(e, "Matched")).join("")}
              ${data.unmatched.map((e) => reconciledRow(e, "Not yet seen")).join("")}
            </tbody>
          </table>
        </div>
        <button type="button" class="secondary-button" id="cmdb-apply" style="margin-top:10px">
          Apply Import (${rows.length} asset(s))
        </button>` : ""}`;

    previewEl.querySelector("#cmdb-mapping-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.target;
      const mapping = {
        asset_name: form.asset_name.value || null,
        owner: form.owner.value || null,
        team: form.team.value || null,
      };
      try {
        const result = await api.cmdbImportPreview(lastCsvText, mapping);
        renderPreview(result);
      } catch (err) {
        flash(err.message, "error");
      }
    });

    const applyBtn = previewEl.querySelector("#cmdb-apply");
    if (applyBtn) {
      applyBtn.addEventListener("click", async () => {
        const entries = [...previewEl.querySelectorAll("[data-reconciled-row]")].map((row) => ({
          asset_name: row.children[1].textContent,
          owner: row.querySelector(".reconciled-owner").value,
          team: row.querySelector(".reconciled-team").value,
        }));
        try {
          const result = await api.cmdbImportApply(entries);
          flash(`Applied owner/team for ${result.applied} asset(s).`, "success");
          render(container);
        } catch (err) {
          flash(err.message, "error");
        }
      });
    }
  }

  container.querySelector("#cmdb-upload-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const fileInput = event.target.file;
    const file = fileInput.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async () => {
      lastCsvText = reader.result;
      try {
        const result = await api.cmdbImportPreview(lastCsvText);
        renderPreview(result);
      } catch (err) {
        flash(err.message, "error");
      }
    };
    reader.readAsText(file);
  });

}
