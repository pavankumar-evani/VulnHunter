// Risk Management dashboard: a MITRE ATT&CK heat map, top assets by critical-finding
// count, an internal/external-facing breakdown, and a CVSS severity-definitions
// reference. Every number here is computed from the same real /api/queue and
// /api/assets data the Remediation Queue and Asset Inventory pages already show -
// this is a different lens on the same data, not a new data source.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";
import { exportButtonsHtml, wireExportButtons } from "../export.js";

export const title = "Risk Management";

const VULN_EXPORT_COLUMNS = [
  { label: "Vulnerability", value: (g) => g.title },
  { label: "CVE", value: (g) => g.cve },
  { label: "Severity", value: (g) => g.severity },
  { label: "Affected Assets", value: (g) => g.assetCount },
  { label: "Assets", value: (g) => g.assetNames.join("; ") },
  { label: "Owner(s)", value: (g) => g.owners.join("; ") },
];

const ASSET_EXPORT_COLUMNS = [
  { label: "Asset", value: (a) => a.name },
  { label: "Type", value: (a) => a.type },
  { label: "Critical Findings", value: (a) => a.critical_count },
  { label: "KEV", value: (a) => a.kev_count },
  { label: "Facing", value: (a) => a.facing },
  { label: "Owner", value: (a) => a.owner },
];

// Canonical MITRE kill-chain tactic order (attack.mitre.org) - only tactics this
// heuristic actually maps to appear as columns; see attack_mapping.py's module
// docstring for why this is a keyword heuristic, not authoritative attribution.
const TACTIC_ORDER = [
  "Initial Access", "Execution", "Persistence", "Privilege Escalation",
  "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
  "Collection", "Command and Control", "Exfiltration", "Impact",
];

const SEVERITY_DEFINITIONS = [
  { tier: "Critical", range: "9.0 - 10.0", note: "Remote, unauthenticated, high-impact - patch immediately." },
  { tier: "High", range: "7.0 - 8.9", note: "Significant impact or ease of exploitation - prioritize this cycle." },
  { tier: "Medium", range: "4.0 - 6.9", note: "Real but constrained impact/exploitability - schedule normally." },
  { tier: "Low", range: "0.1 - 3.9", note: "Minimal standalone impact - track, don't firefight." },
];

function heatCellClass(count, maxCount) {
  if (count === 0) return "heat-0";
  const ratio = maxCount > 0 ? count / maxCount : 0;
  if (ratio >= 0.75) return "heat-4";
  if (ratio >= 0.5) return "heat-3";
  if (ratio >= 0.25) return "heat-2";
  return "heat-1";
}

function renderHeatmap(heatmap) {
  const maxCount = Math.max(0, ...heatmap.map((r) => r.count));
  const byTactic = new Map();
  for (const row of heatmap) {
    if (!byTactic.has(row.tactic)) byTactic.set(row.tactic, []);
    byTactic.get(row.tactic).push(row);
  }
  const tactics = TACTIC_ORDER.filter((t) => byTactic.has(t));

  return `
    <div class="heatmap-grid">
      ${tactics.map((tactic) => `
        <div class="heatmap-column">
          <div class="heatmap-tactic">${escapeHtml(tactic)}</div>
          ${byTactic.get(tactic).map((row) => `
            <div class="heatmap-cell ${heatCellClass(row.count, maxCount)}"
                 data-tooltip="${escapeHtml(row.technique_name)} (${escapeHtml(row.technique_id)}) - ${row.count} finding(s)">
              <span class="heatmap-technique-id">${escapeHtml(row.technique_id)}</span>
              <span class="heatmap-count">${row.count}</span>
            </div>`).join("")}
        </div>`).join("")}
    </div>`;
}

const FACING_LABELS = { external: "External-facing", internal: "Internal-only", unknown: "Unclassified" };

function facingSelect(asset) {
  return `
    <select class="facing-select" data-asset="${escapeHtml(asset.name)}">
      ${["unknown", "internal", "external"].map((v) =>
        `<option value="${v}" ${v === asset.facing ? "selected" : ""}>${FACING_LABELS[v]}</option>`).join("")}
    </select>`;
}

// Groups live-queue findings into "vulnerability types" - keyed by CVE when the
// finding has one (the real, unambiguous identifier), falling back to its title
// otherwise (e.g. certificate-expiry findings, which have no CVE). Shows how many
// distinct assets each vulnerability type touches and who owns them, so "we have 6
// Critical findings" becomes "which ONE vulnerability is spread across the most
// assets, and whose problem is it to fix."
function groupVulnerabilitiesByType(findings, ownerByAssetName) {
  const rank = { Critical: 3, High: 2, Medium: 1, Low: 0 };
  const groups = new Map();
  for (const f of findings) {
    const key = f.cve || f.title;
    if (!groups.has(key)) {
      groups.set(key, {
        key, title: f.title, cve: f.cve || null, severity: f.severity || f.priority,
        assetNames: new Set(), owners: new Set(),
      });
    }
    const g = groups.get(key);
    if (rank[f.severity] > rank[g.severity]) g.severity = f.severity;
    const assetName = f.asset && f.asset.name;
    if (assetName) {
      g.assetNames.add(assetName);
      const owner = ownerByAssetName.get(assetName);
      g.owners.add(owner || "Unowned");
    }
  }
  return [...groups.values()]
    .map((g) => ({ ...g, assetCount: g.assetNames.size, assetNames: [...g.assetNames], owners: [...g.owners] }))
    .sort((a, b) => b.assetCount - a.assetCount);
}

function topVulnerabilityRows(groups) {
  return groups.map((g) => `
    <tr>
      <td>${escapeHtml(g.title)}</td>
      <td>${g.cve ? `<code>${escapeHtml(g.cve)}</code>` : `<span class="muted">-</span>`}</td>
      <td><span class="badge badge-${(g.severity || "").toLowerCase()}">${escapeHtml(g.severity || "?")}</span></td>
      <td><span class="badge badge-critical">${g.assetCount}</span></td>
      <td title="${g.assetNames.map(escapeHtml).join(', ')}">${escapeHtml(g.assetNames.slice(0, 3).join(", "))}${g.assetNames.length > 3 ? ` +${g.assetNames.length - 3} more` : ""}</td>
      <td>${escapeHtml(g.owners.join(", "))}</td>
    </tr>`).join("");
}

function topAssetsRows(assets) {
  return assets.map((a) => `
    <tr>
      <td>${escapeHtml(a.name)}</td>
      <td>${escapeHtml(a.type)}</td>
      <td><span class="badge badge-critical">${a.critical_count}</span></td>
      <td>${a.kev_count > 0 ? `<span class="badge badge-critical">${a.kev_count} KEV</span>` : `<span class="muted">-</span>`}</td>
      <td>${facingSelect(a)}</td>
      <td>${escapeHtml(a.owner || "Unowned")}</td>
    </tr>`).join("");
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [heatmapData, assetsData, queueData] = await Promise.all([
    api.attackHeatmap(), api.assetsList(), api.queue(),
  ]);
  const assets = assetsData.assets;
  const ownerByAssetName = new Map(assets.map((a) => [a.name, a.owner]));
  const vulnerabilityGroups = groupVulnerabilitiesByType(queueData.findings, ownerByAssetName).slice(0, 10);

  const topCritical = [...assets].filter((a) => a.critical_count > 0)
    .sort((a, b) => b.critical_count - a.critical_count).slice(0, 10);

  const facingCounts = { external: 0, internal: 0, unknown: 0 };
  const facingCriticalCounts = { external: 0, internal: 0, unknown: 0 };
  for (const a of assets) {
    facingCounts[a.facing] = (facingCounts[a.facing] || 0) + 1;
    facingCriticalCounts[a.facing] = (facingCriticalCounts[a.facing] || 0) + a.critical_count;
  }
  const externalCritical = [...assets].filter((a) => a.facing === "external" && a.critical_count > 0)
    .sort((a, b) => b.critical_count - a.critical_count);

  container.innerHTML = `
    <p class="subtitle">A different lens on the same real /api/queue and /api/assets
    data the Remediation Queue and Asset Inventory pages show - not a separate data
    source. Internal/external-facing is a manually-set classification (editable in the
    table below), never auto-detected from a network scan - see the FAQ.</p>

    <div class="kpi-grid">
      <div class="kpi-card kpi-danger"><div class="kpi-value">${facingCriticalCounts.external || 0}</div><div class="kpi-label">Critical findings on external-facing assets</div></div>
      <div class="kpi-card kpi-warn"><div class="kpi-value">${facingCriticalCounts.internal || 0}</div><div class="kpi-label">Critical findings on internal-only assets</div></div>
      <div class="kpi-card"><div class="kpi-value">${facingCounts.unknown || 0}</div><div class="kpi-label">Assets with no facing classification yet</div></div>
    </div>

    <h2>MITRE ATT&amp;CK heat map</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      Counts of live-queue findings per tactic/technique - keyword heuristic, not
      authoritative attribution (<code>remediation/enrichment/attack_mapping.py</code>).
      Zero-count cells are real known techniques this heuristic supports, just absent
      from today's findings.
    </p>
    ${renderHeatmap(heatmapData.heatmap)}

    <h2 style="margin-top:28px">Top assets by critical findings</h2>
    ${exportButtonsHtml("top-assets")}
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Asset</th><th>Type</th><th>Critical</th><th>KEV</th><th>Facing</th><th>Owner</th></tr></thead>
        <tbody id="top-assets-body">${topAssetsRows(topCritical)}</tbody>
      </table>
    </div>
    ${!topCritical.length ? `<p class="empty-state">No asset currently has a Critical-severity finding.</p>` : ""}

    ${externalCritical.length ? `
      <div class="callout callout-warn" style="margin-top:16px">
        <strong>${externalCritical.length}</strong> external-facing asset(s) have at least
        one Critical finding: ${externalCritical.map((a) => `<a href="/queue" data-link><code>${escapeHtml(a.name)}</code></a>`).join(", ")}.
        External exposure + Critical severity is the highest-priority combination on this page.
      </div>` : ""}

    <h2 style="margin-top:28px">Top vulnerabilities by type</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      Grouped by CVE (or title, for findings with no CVE - e.g. certificate expiry) -
      "affected assets" is how many distinct assets carry this exact vulnerability.
    </p>
    ${exportButtonsHtml("top-vulns")}
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Vulnerability</th><th>CVE</th><th>Severity</th><th>Affected Assets</th><th>Assets</th><th>Owner(s)</th></tr></thead>
        <tbody>${topVulnerabilityRows(vulnerabilityGroups)}</tbody>
      </table>
    </div>
    ${!vulnerabilityGroups.length ? `<p class="empty-state">No findings in the live queue.</p>` : ""}

    <h2 style="margin-top:28px">Severity definitions (CVSS v3.1)</h2>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Tier</th><th>CVSS score range</th><th>What it means here</th></tr></thead>
        <tbody>
          ${SEVERITY_DEFINITIONS.map((d) => `
            <tr>
              <td><span class="badge badge-${d.tier.toLowerCase()}">${d.tier}</span></td>
              <td>${d.range}</td>
              <td>${d.note}</td>
            </tr>`).join("")}
        </tbody>
      </table>
    </div>
    <p class="filter-count">Per the
      <a href="https://www.first.org/cvss/v3.1/specification-document" target="_blank" rel="noopener">FIRST.org CVSS v3.1 specification</a> -
      the industry-standard scale, not a VulnHunter-specific invention.</p>`;

  wireExportButtons(container, "top-assets", {
    getRows: () => topCritical,
    columns: ASSET_EXPORT_COLUMNS,
    filenameBase: "vulnhunter-top-assets",
  });
  wireExportButtons(container, "top-vulns", {
    getRows: () => vulnerabilityGroups,
    columns: VULN_EXPORT_COLUMNS,
    filenameBase: "vulnhunter-top-vulnerabilities",
  });

  container.querySelector("#top-assets-body").addEventListener("change", async (e) => {
    const select = e.target.closest(".facing-select");
    if (!select) return;
    try {
      await api.assetSetFacing(select.dataset.asset, select.value);
      flash(`${select.dataset.asset} marked ${FACING_LABELS[select.value].toLowerCase()}.`, "success");
    } catch (err) {
      flash(err.message, "error");
    }
  });
}
