// Asset -> Vulnerability mapping: which real assets carry the most DISTINCT
// vulnerabilities, ranked, clickable. Same "not a separate data source" rule as
// vulnerabilityMapping.js - built from /api/queue + /api/assets, the same data the
// Remediation Queue and Asset Inventory already show.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { exportButtonsHtml, wireExportButtons } from "../export.js";
import { buildOwnerTeamMaps } from "../assetLookup.js";
import { groupFindingsByAsset } from "../rankings.js";

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

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [queue, assetsData] = await Promise.all([api.queue(), api.assetsList()]);
  const { ownerByAssetName, teamByAssetName } = buildOwnerTeamMaps(assetsData.assets);
  const riskByAssetName = new Map(assetsData.assets.map((a) => [a.name, a]));
  const groups = groupFindingsByAsset(queue.findings, ownerByAssetName, teamByAssetName).slice(0, 25).map((g) => {
    const risk = riskByAssetName.get(g.name);
    return risk
      ? { ...g, risk_score: risk.risk_score, impact_score: risk.impact_score, likelihood_score: risk.likelihood_score, risk_tier: risk.risk_tier }
      : g;
  });

  container.innerHTML = `
    <p class="subtitle">
      Real assets ranked by how many DISTINCT vulnerabilities they carry (the same CVE
      seen twice on one asset only counts once) - top 25. Not a separate data source:
      built from the same <code>/api/queue</code> + <code>/api/assets</code> the
      Remediation Queue and Asset Inventory already show. Click an asset to see every
      one of its findings in the Remediation Queue, pre-filtered - use the queue's own
      filters there for owner/team/device-type (EOL/EOS)/SLA/date.
    </p>
    ${exportButtonsHtml("asset-mapping")}
    <div class="table-scroll">
      <table class="data-table">
        <thead>
          <tr><th>Asset</th><th>Type</th><th>Distinct Vulnerabilities</th><th>Critical Findings</th><th>Risk Score</th><th>Owner</th><th>Team</th><th>EOL/EOS</th></tr>
        </thead>
        <tbody>${groups.length ? groups.map(rowHtml).join("") : ""}</tbody>
      </table>
    </div>
    ${!groups.length ? `<p class="empty-state">No findings in the live queue.</p>` : ""}`;

  wireExportButtons(container, "asset-mapping", {
    getRows: () => groups,
    columns: EXPORT_COLUMNS,
    filenameBase: "vulnhunter-asset-mapping",
  });
}
