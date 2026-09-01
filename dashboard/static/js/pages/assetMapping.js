// Asset -> Vulnerability mapping: which real assets carry the most DISTINCT
// vulnerabilities, ranked, clickable. Same "not a separate data source" rule as
// vulnerabilityMapping.js - built from /api/queue + /api/assets, the same data the
// Remediation Queue and Asset Inventory already show.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { exportButtonsHtml, wireExportButtons } from "../export.js";
import { buildOwnerTeamMaps } from "../assetLookup.js";
import { groupFindingsByAsset, groupAssetsBySubnet } from "../rankings.js";

export const title = "Asset Mapping";

const EOL_BADGE_CLASS = { eol: "badge-critical", "eol-soon": "badge-medium", supported: "badge-auto_approvable" };
const EOL_LABEL = { eol: "EOL", "eol-soon": "EOL soon", supported: "Supported" };

const EXPORT_COLUMNS = [
  { label: "Asset", value: (g) => g.name },
  { label: "Type", value: (g) => g.type },
  { label: "OS", value: (g) => g.os },
  { label: "Distinct Vulnerabilities", value: (g) => g.vulnCount },
  { label: "Critical Findings", value: (g) => g.criticalCount },
  { label: "Risk Score", value: (g) => g.risk_score },
  { label: "Risk Tier", value: (g) => g.risk_tier },
  { label: "Owner", value: (g) => g.owner },
  { label: "Team", value: (g) => g.team },
  { label: "EOL/EOS", value: (g) => g.eolStatus && g.eolStatus.status },
];

// Same badge convention as Asset Inventory's own risk column - see that page's callout
// for the NIST SP 800-30-inspired disclosure this shares.
function riskCellHtml(g) {
  if (typeof g.risk_score !== "number") return `<span class="muted">—</span>`;
  return `<span class="badge badge-${(g.risk_tier || "").toLowerCase()}" data-tooltip="Impact ${g.impact_score} × Likelihood ${g.likelihood_score} (NIST SP 800-30-inspired, not a certified assessment)">${g.risk_score}</span>`;
}

function eolCellHtml(g) {
  const eol = g.eolStatus;
  if (!eol || eol.status === "unknown") return `<span class="muted">Unknown</span>`;
  return `<span class="badge ${EOL_BADGE_CLASS[eol.status]}">${EOL_LABEL[eol.status]}</span>`;
}

function rowHtml(g) {
  return `
    <tr>
      <td><a href="/queue?asset=${encodeURIComponent(g.name)}" data-link>${escapeHtml(g.name)}</a></td>
      <td class="asset-type-cell">${escapeHtml(g.type || "")}</td>
      <td><span class="badge badge-critical">${g.vulnCount}</span></td>
      <td>${g.criticalCount > 0 ? `<span class="badge badge-critical">${g.criticalCount}</span>` : `<span class="muted">0</span>`}</td>
      <td>${riskCellHtml(g)}</td>
      <td>${escapeHtml(g.owner)}</td>
      <td>${escapeHtml(g.team)}</td>
      <td>${eolCellHtml(g)}</td>
    </tr>`;
}

const SUBNET_EXPORT_COLUMNS = [
  { label: "Subnet", value: (g) => g.subnet },
  { label: "IP Version", value: (g) => (g.ipVersion ? `IPv${g.ipVersion}` : "") },
  { label: "Assets", value: (g) => g.assetCount },
  { label: "Distinct Vulnerabilities", value: (g) => g.vulnCount },
  { label: "Critical Findings", value: (g) => g.criticalCount },
  { label: "Asset Names", value: (g) => g.assetNames.join("; ") },
];

function subnetRowHtml(g) {
  const versionBadge = g.ipVersion ? `<span class="badge badge-outline" style="margin-left:6px">IPv${g.ipVersion}</span>` : "";
  const shown = g.assetNames.slice(0, 5);
  const more = g.assetNames.length > shown.length ? ` +${g.assetNames.length - shown.length} more` : "";
  return `
    <tr>
      <td><code>${escapeHtml(g.subnet)}</code>${versionBadge}</td>
      <td>${g.assetCount}</td>
      <td><span class="badge badge-critical">${g.vulnCount}</span></td>
      <td>${g.criticalCount > 0 ? `<span class="badge badge-critical">${g.criticalCount}</span>` : `<span class="muted">0</span>`}</td>
      <td>${shown.map((n) => `<a href="/queue?asset=${encodeURIComponent(n)}" data-link>${escapeHtml(n)}</a>`).join(", ")}${escapeHtml(more)}</td>
    </tr>`;
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [queue, assetsData] = await Promise.all([api.queue(), api.assetsList()]);
  const { ownerByAssetName, teamByAssetName } = buildOwnerTeamMaps(assetsData.assets);
  const riskByAssetName = new Map(assetsData.assets.map((a) => [a.name, a]));
  // Unsliced - subnet aggregation needs every asset with a finding, not just the top
  // 25 shown in the "Individual Assets" table below, or a subnet whose assets are all
  // outside the top 25 would silently under-count.
  const fullGroups = groupFindingsByAsset(queue.findings, ownerByAssetName, teamByAssetName);
  const groups = fullGroups.slice(0, 25).map((g) => {
    const risk = riskByAssetName.get(g.name);
    return risk
      ? { ...g, risk_score: risk.risk_score, impact_score: risk.impact_score, likelihood_score: risk.likelihood_score, risk_tier: risk.risk_tier }
      : g;
  });
  const subnetGroups = groupAssetsBySubnet(fullGroups, assetsData.assets);

  container.innerHTML = `
    <p class="subtitle">
      Real assets ranked by how many DISTINCT vulnerabilities they carry (the same CVE
      seen twice on one asset only counts once). Not a separate data source: built from
      the same <code>/api/queue</code> + <code>/api/assets</code> the Remediation Queue
      and Asset Inventory already show. Click an asset to see every one of its findings
      in the Remediation Queue, pre-filtered - use the queue's own filters there for
      owner/team/device-type (EOL/EOS)/SLA/date.
    </p>

    <label style="display:inline-block;margin-bottom:12px">Group by
      <select id="mapping-view-select">
        <option value="asset">Individual Assets (top 25)</option>
        <option value="subnet">IP Subnet (/24 IPv4, /64 IPv6)</option>
      </select>
    </label>

    <div id="mapping-view-asset">
      ${exportButtonsHtml("asset-mapping")}
      <div class="table-scroll">
        <table class="data-table">
          <thead>
            <tr><th>Asset</th><th>Type</th><th>Distinct Vulnerabilities</th><th>Critical Findings</th><th>Risk Score</th><th>Owner</th><th>Team</th><th>EOL/EOS</th></tr>
          </thead>
          <tbody>${groups.length ? groups.map(rowHtml).join("") : ""}</tbody>
        </table>
      </div>
      ${!groups.length ? `<p class="empty-state">No findings in the live queue.</p>` : ""}
    </div>

    <div id="mapping-view-subnet" hidden>
      <p class="filter-count" style="margin:-4px 0 8px">
        Assets grouped by real IP subnet (<code>remediation/inventory/pattern_recognition.py</code>'s
        <code>ip_subnet()</code>/<code>ipv6_subnet()</code>, computed from each asset's
        real or human-set IP - see Asset Inventory) - which network segment carries the
        most distinct vulnerabilities, not just which single asset does. Assets with no
        recorded IP land in one honest "Unknown" bucket rather than being dropped.
      </p>
      ${exportButtonsHtml("subnet-mapping")}
      <div class="table-scroll">
        <table class="data-table">
          <thead>
            <tr><th>Subnet</th><th>Assets</th><th>Distinct Vulnerabilities</th><th>Critical Findings</th><th>Assets in this subnet</th></tr>
          </thead>
          <tbody>${subnetGroups.length ? subnetGroups.map(subnetRowHtml).join("") : ""}</tbody>
        </table>
      </div>
      ${!subnetGroups.length ? `<p class="empty-state">No findings in the live queue.</p>` : ""}
    </div>`;

  wireExportButtons(container, "asset-mapping", {
    getRows: () => groups,
    columns: EXPORT_COLUMNS,
    filenameBase: "vulnhunter-asset-mapping",
  });
  wireExportButtons(container, "subnet-mapping", {
    getRows: () => subnetGroups,
    columns: SUBNET_EXPORT_COLUMNS,
    filenameBase: "vulnhunter-subnet-mapping",
  });

  container.querySelector("#mapping-view-select").addEventListener("change", (event) => {
    const isSubnet = event.target.value === "subnet";
    container.querySelector("#mapping-view-asset").hidden = isSubnet;
    container.querySelector("#mapping-view-subnet").hidden = !isSubnet;
  });
}
