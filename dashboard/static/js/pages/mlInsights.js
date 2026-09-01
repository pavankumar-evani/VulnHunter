// ML Insights: real, unsupervised machine learning (scikit-learn), genuinely fit at
// request time against this app's own real finding/asset data - see
// remediation/enrichment/ml_insights.py's module docstring for exactly what this is and
// (just as importantly) what it deliberately is NOT. Unlike every other "smart-looking"
// feature in this app (owner suggestions, ATT&CK tagging, compensating-control
// suggestions), the models here are real IsolationForest/KMeans/TF-IDF fits, not keyword
// heuristics - and unlike those heuristics, this page says so plainly.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { openFindingDetail } from "../findingDetail.js";
import { exportButtonsHtml, wireExportButtons } from "../export.js";
import { columnPickerHtml, loadVisibleColumns, applyColumnVisibility, wireColumnPicker } from "../columnPicker.js";
import { paginate, paginationHtml, wirePagination } from "../pagination.js";
import { environmentCellHtml } from "../assetLookup.js";
import { groupLabelFor } from "../domainGrouping.js";

export const title = "ML Insights";

// Order matches the header row/anomalyRowHtml() below - see columnPicker.js. Critical
// count and Team start hidden - Risk Score/Anomaly Score/Why flagged are this table's
// whole point and stay visible.
const ANOMALY_COLUMNS = [
  { id: "asset", label: "Asset" },
  { id: "type", label: "Type" },
  { id: "environment", label: "Environment" },
  { id: "findings", label: "Findings" },
  { id: "critical", label: "Critical", defaultVisible: false },
  { id: "kev", label: "KEV" },
  { id: "risk", label: "Risk Score" },
  { id: "anomaly_score", label: "Anomaly Score" },
  { id: "why_flagged", label: "Why flagged" },
  { id: "owner", label: "Owner" },
  { id: "team", label: "Team", defaultVisible: false },
];

const ANOMALY_EXPORT_COLUMNS = [
  { label: "Asset", value: (a) => a.name },
  { label: "Domain", value: (a) => a.groupLabel },
  { label: "Type", value: (a) => a.type },
  { label: "Environment", value: (a) => a.environment },
  { label: "Findings", value: (a) => a.finding_count },
  { label: "Critical", value: (a) => a.critical_count },
  { label: "KEV", value: (a) => a.kev_count },
  { label: "Risk Score", value: (a) => a.risk_score },
  { label: "Anomaly Score", value: (a) => a.anomaly_score },
  { label: "Why flagged", value: (a) => (a.reasons || []).join("; ") },
  { label: "Owner", value: (a) => a.owner },
  { label: "Team", value: (a) => a.team },
];

function reasonsHtml(reasons) {
  if (!reasons || !reasons.length) return `<span class="muted">—</span>`;
  return `<ul style="margin:0; padding-left:18px">${reasons.map((r) => `<li style="margin-bottom:2px">${escapeHtml(r)}</li>`).join("")}</ul>`;
}

function anomalyRowHtml(a) {
  return `
    <tr>
      <td data-col="asset">${escapeHtml(a.name)}</td>
      <td data-col="type">${escapeHtml(a.type)}</td>
      <td data-col="environment">${environmentCellHtml(a.environment, escapeHtml)}</td>
      <td data-col="findings">${a.finding_count}</td>
      <td data-col="critical">${a.critical_count}</td>
      <td data-col="kev">${a.kev_count}</td>
      <td data-col="risk">${typeof a.risk_score === "number" ? `<span class="badge badge-${(a.risk_tier || "").toLowerCase()}">${a.risk_score}</span>` : `<span class="muted">—</span>`}</td>
      <td data-col="anomaly_score"><code>${a.anomaly_score}</code></td>
      <td data-col="why_flagged" class="wrap-cell">${reasonsHtml(a.reasons)}</td>
      <td data-col="owner">${escapeHtml(a.owner || "Unowned")}</td>
      <td data-col="team">${escapeHtml(a.team || "—")}</td>
    </tr>`;
}

// Each anomalous asset's domain is derived from its OWN real findings (majority vote,
// the same taxonomy groupLabelFor() already uses for Compensating Controls/Threat
// Intel/Remediation Approvals) rather than a separate asset-type-to-domain table,
// since one asset type (e.g. "unix-server") can host findings from more than one
// domain (e.g. both OS and container-runtime) - ties fall back to the first-encountered
// label. An asset with no findings in the live queue (a rare edge case) honestly falls
// back to "Other" rather than a guessed domain.
function dominantGroupLabel(findings) {
  if (!findings.length) return "Other";
  const counts = new Map();
  for (const f of findings) {
    const label = groupLabelFor(f);
    counts.set(label, (counts.get(label) || 0) + 1);
  }
  let best = null;
  let bestCount = -1;
  for (const [label, count] of counts) {
    if (count > bestCount) { best = label; bestCount = count; }
  }
  return best;
}

// Renders `pagedRows` (each already carrying a `groupLabel`) into a tbody's innerHTML,
// with a divider row before every group change - same pattern remediationApprovals.js/
// compensatingControls.js/threatIntel.js use for their own domain-grouped tables.
// `allFilteredRows` (the full, pre-pagination set) is what each divider's own count is
// computed from, so it stays accurate even when a group spans multiple pages.
function groupedRowsHtml(pagedRows, allFilteredRows, rowHtml, colspan) {
  let lastGroupKey = null;
  const parts = [];
  for (const row of pagedRows) {
    if (row.groupLabel !== lastGroupKey) {
      const groupCount = allFilteredRows.filter((r) => r.groupLabel === row.groupLabel).length;
      parts.push(`<tr class="table-section-row"><td colspan="${colspan}">${escapeHtml(row.groupLabel)} (${groupCount})</td></tr>`);
      lastGroupKey = row.groupLabel;
    }
    parts.push(rowHtml(row));
  }
  return parts.join("");
}

function clusterMembersHtml(members) {
  if (!members.length) return `<tr><td colspan="6" class="empty-state">No members.</td></tr>`;
  return members.map((f) => `
    <tr>
      <td><button type="button" class="link-button cluster-finding-link" data-finding-id="${escapeHtml(f.id)}">${escapeHtml(f.id)}</button></td>
      <td>${escapeHtml(f.asset && f.asset.name)}</td>
      <td>${escapeHtml(f.severity)}</td>
      <td>${f.cvss ?? "—"}</td>
      <td class="wrap-cell">${escapeHtml(f.title)}</td>
      <td>${f.kev && f.kev.listed ? `<span class="badge badge-critical">KEV</span>` : `<span class="muted">—</span>`}</td>
    </tr>`).join("");
}

function clusterRowHtml(summary) {
  return `
    <tr class="cluster-row" data-cluster-id="${summary.cluster_id}">
      <td>#${summary.cluster_id}</td>
      <td>${summary.size}</td>
      <td>${summary.dominant_severity ? `<span class="badge badge-${summary.dominant_severity.toLowerCase()}">${escapeHtml(summary.dominant_severity)}</span>` : "—"}</td>
      <td>${escapeHtml(summary.dominant_asset_type || "—")}</td>
      <td>${summary.avg_cvss ?? "—"}</td>
      <td>${summary.avg_epss !== null && summary.avg_epss !== undefined ? `${(summary.avg_epss * 100).toFixed(1)}%` : "—"}</td>
      <td>${summary.kev_count}</td>
      <td><button type="button" class="link-button cluster-toggle" data-cluster-id="${summary.cluster_id}">View members ▾</button></td>
    </tr>
    <tr class="cluster-members-row" data-cluster-members="${summary.cluster_id}" hidden>
      <td colspan="8">
        <div class="table-scroll">
          <table class="data-table">
            <thead><tr><th>ID</th><th>Asset</th><th>Severity</th><th>CVSS</th><th>Title</th><th>KEV</th></tr></thead>
            <tbody id="cluster-members-${summary.cluster_id}"></tbody>
          </table>
        </div>
        <p class="filter-count" id="cluster-members-note-${summary.cluster_id}"></p>
      </td>
    </tr>`;
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading — fitting real scikit-learn models against the live dataset…</div>`;

  const [anomaliesData, clustersData, queue] = await Promise.all([
    api.mlAssetAnomalies(),
    api.mlFindingClusters(),
    api.queue(),
  ]);

  const findingsByAssetName = new Map();
  for (const f of queue.findings) {
    const name = f.asset && f.asset.name;
    if (!name) continue;
    if (!findingsByAssetName.has(name)) findingsByAssetName.set(name, []);
    findingsByAssetName.get(name).push(f);
  }
  const anomaliesAll = anomaliesData.anomalies.map((a) => ({
    ...a,
    groupLabel: dominantGroupLabel(findingsByAssetName.get(a.name) || []),
  }));
  const groupLabels = [...new Set(anomaliesAll.map((a) => a.groupLabel))].sort();
  const ANOMALY_COLSPAN = ANOMALY_COLUMNS.length;

  const clusters = clustersData.clusters;
  // Cluster members are fetched lazily, one cluster at a time, only when a user
  // actually clicks "View members" - keeps the initial page load to just the anomaly
  // rows + cluster summaries, not all ~9,400 tagged findings up front.
  const loadedMembersByCluster = new Map();

  let page = 1;
  let groupFilter = "all";
  let visibleColumns = loadVisibleColumns("ml-anomalies", ANOMALY_COLUMNS);

  function renderAnomalyRows() {
    const filtered = groupFilter === "all" ? anomaliesAll : anomaliesAll.filter((a) => a.groupLabel === groupFilter);
    const paged = paginate(filtered, page);
    page = paged.page;
    const tbody = container.querySelector("#anomaly-body");
    tbody.innerHTML = paged.rows.length
      ? groupedRowsHtml(paged.rows, filtered, anomalyRowHtml, ANOMALY_COLSPAN)
      : `<tr><td colspan="${ANOMALY_COLSPAN}" class="empty-state">No anomalies flagged${groupFilter === "all" ? "" : " in this domain"}.</td></tr>`;
    applyColumnVisibility(container.querySelector("#anomaly-table"), visibleColumns);
    const paginationEl = container.querySelector("#anomaly-pagination");
    if (paginationEl) paginationEl.innerHTML = paginationHtml(paged.page, paged.totalPages);
    const countEl = container.querySelector("#anomaly-count");
    if (countEl) countEl.textContent = `${filtered.length} of ${anomaliesAll.length} flagged asset(s)`;
  }

  container.innerHTML = `
    <div class="callout">
      <strong>This page is real, live-trained machine learning</strong> - scikit-learn
      models genuinely fit at request time against this app's actual finding/asset data
      (${anomaliesData.total_assets.toLocaleString()} assets, ${clustersData.total_findings.toLocaleString()}
      findings), not a keyword heuristic like the owner suggestions or ATT&amp;CK tags
      elsewhere in this app. It is <strong>unsupervised</strong> learning only (anomaly
      detection, clustering, text similarity) - it needs no labeled examples, which is
      good, because this app's real labeled data (5 asset-ownership entries) is nowhere
      near enough to validate supervised predictions on. It never replaces or feeds into
      the deterministic <a href="/remediation-policy" data-link>Remediation Policy</a> or
      <a href="/priority-rules" data-link>Priority Rules</a> engines - it's an advisory
      insights layer alongside them. See the <a href="/faq" data-link>FAQ</a> for the full
      explanation, including why remediation-outcome prediction isn't (and won't be)
      offered.
    </div>

    <div class="kpi-grid">
      <div class="kpi-card kpi-danger"><div class="kpi-value">${anomaliesAll.length}</div><div class="kpi-label">Anomalous assets flagged</div></div>
      <div class="kpi-card"><div class="kpi-value">${anomaliesData.total_assets.toLocaleString()}</div><div class="kpi-label">Assets analyzed (IsolationForest, per asset type)</div></div>
      <div class="kpi-card"><div class="kpi-value">${clusters.length}</div><div class="kpi-label">Risk-archetype clusters discovered (KMeans)</div></div>
      <div class="kpi-card"><div class="kpi-value">${clustersData.total_findings.toLocaleString()}</div><div class="kpi-label">Findings analyzed</div></div>
    </div>

    <h3>Anomalous Assets</h3>
    <p class="subtitle">
      Each asset's real feature vector (finding count, critical count, KEV count,
      severity mix, max CVSS/EPSS) fit against an <code>IsolationForest</code> trained
      separately per asset type - flags assets whose profile is a genuine statistical
      outlier vs. peers of the <em>same type</em>, with the specific deviating feature(s)
      named (by real z-score) in "Why flagged". Sorted most-anomalous first.
    </p>
    <p class="filter-count" style="margin:-4px 0 8px">
      Grouped by security domain (derived from each asset's own real findings), same
      taxonomy as Compensating Controls/Threat Intel/Remediation Approvals.
    </p>
    <div class="filter-bar">
      <label>Domain
        <select id="anomaly-f-group">
          <option value="all">All (${anomaliesAll.length})</option>
          ${groupLabels.map((label) => `<option value="${escapeHtml(label)}">${escapeHtml(label)}</option>`).join("")}
        </select>
      </label>
      <span class="filter-count" id="anomaly-count"></span>
    </div>
    <div class="table-toolbar">
      ${exportButtonsHtml("ml-anomalies")}
      ${columnPickerHtml("ml-anomalies", ANOMALY_COLUMNS, visibleColumns)}
    </div>
    <div class="table-scroll">
      <table class="data-table" id="anomaly-table">
        <thead>
          <tr>
            <th data-col="asset">Asset</th><th data-col="type">Type</th><th data-col="environment">Environment</th><th data-col="findings">Findings</th><th data-col="critical">Critical</th><th data-col="kev">KEV</th>
            <th data-col="risk">Risk Score</th><th data-col="anomaly_score">Anomaly Score</th><th data-col="why_flagged">Why flagged</th><th data-col="owner">Owner</th><th data-col="team">Team</th>
          </tr>
        </thead>
        <tbody id="anomaly-body"></tbody>
      </table>
    </div>
    <div id="anomaly-pagination"></div>

    <h3 style="margin-top:28px">Finding Risk Clusters</h3>
    <p class="subtitle">
      Findings grouped by <code>KMeans</code> into naturally-occurring risk archetypes
      (by severity, CVSS, EPSS, KEV status, and asset/scan type) - each cluster's profile
      below is computed from its <em>actual</em> members, not a predefined label.
    </p>
    <div class="table-scroll">
      <table class="data-table">
        <thead>
          <tr>
            <th>Cluster</th><th>Size</th><th>Dominant severity</th><th>Dominant asset type</th>
            <th>Avg CVSS</th><th>Avg EPSS</th><th>KEV count</th><th></th>
          </tr>
        </thead>
        <tbody id="cluster-body">${clusters.map((c) => clusterRowHtml(c)).join("")}</tbody>
      </table>
    </div>

    <div class="callout" style="margin-top:16px">
      <strong>Similar findings</strong> (real TF-IDF + cosine-similarity text search) are
      available on any finding's detail view - click a finding ID anywhere in this app,
      then look for the "Similar findings" section.
    </div>`;

  wireExportButtons(container, "ml-anomalies", {
    getRows: () => (groupFilter === "all" ? anomaliesAll : anomaliesAll.filter((a) => a.groupLabel === groupFilter)),
    columns: ANOMALY_EXPORT_COLUMNS,
    filenameBase: "vulnhunter-ml-anomalous-assets",
  });
  wireColumnPicker(container, "ml-anomalies", (visible) => {
    visibleColumns = visible;
    applyColumnVisibility(container.querySelector("#anomaly-table"), visibleColumns);
  });

  renderAnomalyRows();
  wirePagination(container, (p) => { page = p; renderAnomalyRows(); });
  container.querySelector("#anomaly-f-group").addEventListener("change", (e) => {
    groupFilter = e.target.value;
    page = 1;
    renderAnomalyRows();
  });

  container.addEventListener("click", async (e) => {
    const toggleBtn = e.target.closest(".cluster-toggle");
    if (toggleBtn) {
      const clusterId = Number(toggleBtn.dataset.clusterId);
      const membersRow = container.querySelector(`[data-cluster-members="${clusterId}"]`);
      if (membersRow.hidden) {
        if (!loadedMembersByCluster.has(clusterId)) {
          const membersBody = container.querySelector(`#cluster-members-${clusterId}`);
          membersBody.innerHTML = `<tr><td colspan="6" class="empty-state">Loading…</td></tr>`;
          membersRow.hidden = false;
          const res = await api.mlFindingClusterMembers(clusterId);
          loadedMembersByCluster.set(clusterId, res.members);
          membersBody.innerHTML = clusterMembersHtml(res.members);
          const noteEl = container.querySelector(`#cluster-members-note-${clusterId}`);
          if (noteEl && res.total > res.members.length) {
            noteEl.textContent = `Showing ${res.members.length} of ${res.total} finding(s).`;
          }
        }
        membersRow.hidden = false;
        toggleBtn.textContent = "Hide members ▴";
      } else {
        membersRow.hidden = true;
        toggleBtn.textContent = "View members ▾";
      }
      return;
    }

    const findingBtn = e.target.closest(".cluster-finding-link");
    if (findingBtn) {
      const members = [...loadedMembersByCluster.values()].flat();
      const finding = members.find((f) => f.id === findingBtn.dataset.findingId);
      if (finding) openFindingDetail(finding);
    }
  });
}
