// Risk Management dashboard: a MITRE ATT&CK heat map, top assets by critical-finding
// count, an internal/external-facing breakdown, and a CVSS severity-definitions
// reference. Every number here is computed from the same real /api/queue and
// /api/assets data the Remediation Queue and Asset Inventory pages already show -
// this is a different lens on the same data, not a new data source.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";
import { exportButtonsHtml, wireExportButtons } from "../export.js";
import { buildOwnerTeamMaps } from "../assetLookup.js";
import {
  severityChartBlockHtml, buildTopRankings, topRankingsHtml, wireTopRankings, teamPriorityChartBlockHtml,
  agingChartBlockHtml, agingByPriorityTableHtml, agingDisclaimerHtml,
} from "../domainSummary.js";
import { countBy, wireChartLinks } from "../charts.js";
import { aiTrendAnalysisFabHtml, wireAiTrendAnalysis } from "../aiTrendAnalysis.js";
import { setInsightsContent, insightSectionHtml, insightAlertHtml } from "../insightsPanel.js";

export const title = "Risk Management";

const ASSET_EXPORT_COLUMNS = [
  { label: "Asset", value: (a) => a.name },
  { label: "Type", value: (a) => a.type },
  { label: "Critical Findings", value: (a) => a.critical_count },
  { label: "KEV", value: (a) => a.kev_count },
  { label: "Risk Score", value: (a) => a.risk_score },
  { label: "Risk Tier", value: (a) => a.risk_tier },
  { label: "Facing", value: (a) => a.facing },
  { label: "Owner", value: (a) => a.owner },
];

// Same badge convention as Asset Inventory/Asset Mapping's own risk column - see
// Asset Inventory's callout for the NIST SP 800-30-inspired disclosure this shares.
function riskCellHtml(a) {
  if (typeof a.risk_score !== "number") return `<span class="muted">—</span>`;
  return `<span class="badge badge-${(a.risk_tier || "").toLowerCase()}" data-tooltip="Impact ${a.impact_score} × Likelihood ${a.likelihood_score} (NIST SP 800-30-inspired, not a certified assessment)">${a.risk_score}</span>`;
}

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

function topAssetsRows(assets) {
  return assets.map((a) => `
    <tr>
      <td>${escapeHtml(a.name)}</td>
      <td>${escapeHtml(a.type)}</td>
      <td><span class="badge badge-critical">${a.critical_count}</span></td>
      <td>${a.kev_count > 0 ? `<span class="badge badge-critical">${a.kev_count} KEV</span>` : `<span class="muted">-</span>`}</td>
      <td>${riskCellHtml(a)}</td>
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
  const { ownerByAssetName, teamByAssetName } = buildOwnerTeamMaps(assets);
  const rankings = buildTopRankings(queueData.findings, ownerByAssetName, teamByAssetName);

  // Re-ranked by overall Risk Score (Impact x Likelihood - see risk_scoring.py), not
  // raw critical_count alone: among assets that already have a Critical finding, this
  // surfaces the ones whose real threat-intel signals (KEV/EPSS/EOL/exploit-criteria)
  // make them genuinely the most urgent, not just whichever happens to have the most
  // Critical-tagged rows.
  const topCritical = [...assets].filter((a) => a.critical_count > 0)
    .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0)).slice(0, 5);

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

    <div class="chart-row">
      ${severityChartBlockHtml(queueData.findings)}
    </div>

    <div class="chart-row">
      ${teamPriorityChartBlockHtml(queueData.findings, teamByAssetName)}
    </div>

    <h2 style="margin-top:28px">Open-finding age (30/60/90-day backlog aging)</h2>
    ${agingDisclaimerHtml()}
    <div class="chart-row">
      ${agingChartBlockHtml(queueData.findings)}
    </div>
    <h3 style="margin-top:20px">By priority</h3>
    ${agingByPriorityTableHtml(queueData.findings)}

    <h2>MITRE ATT&amp;CK heat map</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      Counts of live-queue findings per tactic/technique - keyword heuristic, not
      authoritative attribution (<code>remediation/enrichment/attack_mapping.py</code>).
      Zero-count cells are real known techniques this heuristic supports, just absent
      from today's findings.
    </p>
    ${renderHeatmap(heatmapData.heatmap)}

    <h2 style="margin-top:28px">Top assets by critical findings</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      Top 5 shown here, ranked by overall Risk Score (Impact × Likelihood - hover a
      score for its breakdown), not raw Critical-finding count alone. For the full
      ranked list (by distinct vulnerability count, clickable, with
      owner/team/EOL-EOS/SLA/date filters), see
      <a href="/asset-mapping" data-link>the Asset Mapping dashboard →</a>
    </p>
    ${exportButtonsHtml("top-assets")}
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Asset</th><th>Type</th><th>Critical</th><th>KEV</th><th>Risk Score</th><th>Facing</th><th>Owner</th></tr></thead>
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

    ${topRankingsHtml("risk-hub", rankings)}
    <p class="filter-count" style="margin:-10px 0 12px">
      "Top 5 assets by distinct-vulnerability count" above is a different metric than
      "Top assets by critical findings" further up this page - one counts every real,
      distinct vulnerability an asset carries, the other counts only Critical-severity
      findings. Both are genuinely useful, for different questions.
    </p>

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
      the industry-standard scale, not a VulnHunter-specific invention.</p>
    ${aiTrendAnalysisFabHtml("risk-hub")}`;

  wireExportButtons(container, "top-assets", {
    getRows: () => topCritical,
    columns: ASSET_EXPORT_COLUMNS,
    filenameBase: "vulnhunter-top-assets",
  });
  wireTopRankings(container, "risk-hub", rankings);
  wireChartLinks(container);

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

  wireAiTrendAnalysis(container, "risk-hub", "risk management", async () => {
    const priorityData = countBy(queueData.findings, (f) => f.priority);
    const riskTierCounts = countBy(assets, (a) => a.risk_tier || "Unscored");
    return {
      "Total assets": assets.length,
      "Critical findings on external-facing assets": facingCriticalCounts.external || 0,
      "Critical findings on internal-only assets": facingCriticalCounts.internal || 0,
      "Assets with no facing classification": facingCounts.unknown || 0,
      "Assets by risk tier": riskTierCounts.map((d) => `${d.label}=${d.value}`).join(", "),
      "Priority breakdown (live queue)": priorityData.map((d) => `${d.label}=${d.value}`).join(", "),
      "Top 5 assets by risk score": topCritical.map((a) => `${a.name}=${a.risk_score}`).join(", "),
    };
  }, "Risk Management (facing classification, critical findings, Risk Score)");

  const unclassifiedPct = assets.length ? Math.round((facingCounts.unknown / assets.length) * 100) : 0;

  const alerts = [];
  if (externalCritical.length) {
    alerts.push(insightAlertHtml(
      `<strong>${externalCritical.length}</strong> external-facing asset(s) have a Critical finding - the highest-priority combination on this page.`,
      "danger",
    ));
  }
  if (unclassifiedPct > 50) {
    alerts.push(insightAlertHtml(
      `<strong>${unclassifiedPct}%</strong> (${facingCounts.unknown} of ${assets.length}) of assets have no internal/external-facing classification set - edit it directly in the table below.`,
      "warn",
    ));
  }

  // Trimmed to just the one most load-bearing section - see queue.js's own comment on
  // this same change (Part 11: insights panel now starts collapsed by default).
  setInsightsContent(insightSectionHtml("On this page", alerts.join("")));
}
