// Blast Radius: "if this asset is compromised, how far does the damage spread" - a
// sub-page of Risk Management, distinct from /risk's per-FINDING Impact/Likelihood/Risk
// score. Built from a real 4-dimension profiling framework, honestly mapped against
// what this app's real data actually supports - see remediation/enrichment/
// blast_radius.py's module docstring for the full disclosure. This page renders that
// disclosure directly (profilingCoverageHtml below), not as a footnote.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { barChartSvg, wireChartLinks } from "../charts.js";

export const title = "Blast Radius";

const STATUS_LABEL = { available: "Real, measured", partial: "Partially available", not_available: "Not available" };
const STATUS_CLASS = { available: "callout", partial: "callout-warn", not_available: "callout-danger" };

function profilingCoverageHtml(coverage) {
  const cards = coverage.map((d) => `
    <div class="chart-block">
      <h3>${escapeHtml(d.dimension)}</h3>
      <p class="filter-count" style="margin:-4px 0 8px"><em>${escapeHtml(d.question)}</em></p>
      <div class="callout ${STATUS_CLASS[d.status]}" style="margin-bottom:8px">${escapeHtml(STATUS_LABEL[d.status])}</div>
      <p class="filter-count">${escapeHtml(d.detail)}</p>
    </div>`).join("");
  return `<div class="chart-row-grid">${cards}</div>`;
}

function blastRadiusBadge(a) {
  return `<span class="badge badge-${(a.blast_radius_tier || "").toLowerCase()}" data-tooltip="Criticality ${a.blast_radius_factors.criticality_component} × Network reachability proxy ${a.blast_radius_factors.network_reachability_component} - see the profiling coverage panel above for what these do and don't measure">${a.blast_radius_score}</span>`;
}

function immediateRisksHtml(risks) {
  if (!risks.length) {
    return `<div class="callout" style="margin:14px 0">No asset currently combines a high Blast Radius score with real, confirmed exploitability (a KEV-listed finding, or a high likelihood_score). This is the honest current state, not a guarantee nothing is at risk - see the profiling coverage panel above for what isn't measured yet.</div>`;
  }
  const rows = risks.map((a) => `
    <tr>
      <td><a href="/queue?asset=${encodeURIComponent(a.name)}" data-link>${escapeHtml(a.name)}</a></td>
      <td class="asset-type-cell">${escapeHtml(a.type || "")}</td>
      <td>${blastRadiusBadge(a)}</td>
      <td>${a.kev_count > 0 ? `<span class="badge badge-critical">${a.kev_count} KEV-listed</span>` : `<span class="muted">—</span>`}</td>
      <td>${typeof a.likelihood_score === "number" ? a.likelihood_score : "—"}</td>
      <td>${escapeHtml(a.blast_radius_factors.matched_criticality_keyword || "—")}</td>
      <td>${escapeHtml(a.blast_radius_factors.facing)}</td>
    </tr>`).join("");
  return `
    <div class="callout callout-danger" style="margin:14px 0">
      <strong>${risks.length}</strong> asset(s) combine a high Blast Radius score with real, confirmed exploitability -
      the "high blast radius and actively exploitable" pattern worth acting on first.
    </div>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Asset</th><th>Type</th><th>Blast Radius</th><th>KEV</th><th>Likelihood</th><th>Matched keyword</th><th>Facing</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

function topAssetsTableHtml(assets) {
  const rows = assets.slice(0, 25).map((a) => `
    <tr>
      <td><a href="/queue?asset=${encodeURIComponent(a.name)}" data-link>${escapeHtml(a.name)}</a></td>
      <td class="asset-type-cell">${escapeHtml(a.type || "")}</td>
      <td>${blastRadiusBadge(a)}</td>
      <td>${escapeHtml(a.blast_radius_factors.matched_criticality_keyword || "—")}</td>
      <td>${escapeHtml(a.blast_radius_factors.facing)}</td>
      <td>${a.kev_count > 0 ? `<span class="badge badge-critical">${a.kev_count}</span>` : "0"}</td>
      <td>${typeof a.likelihood_score === "number" ? a.likelihood_score : "—"}</td>
    </tr>`).join("");
  return `
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Asset</th><th>Type</th><th>Blast Radius</th><th>Matched keyword</th><th>Facing</th><th>KEV</th><th>Likelihood</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

export async function render(container) {
  container.innerHTML = `<p class="subtitle">Loading…</p>`;
  const data = await api.blastRadius();
  const assets = [...data.assets].sort((a, b) => b.blast_radius_score - a.blast_radius_score);

  const chartData = assets.slice(0, 12).map((a) => ({
    label: a.name, value: a.blast_radius_score,
    detail: `${a.type || "unknown type"} - matched "${a.blast_radius_factors.matched_criticality_keyword || "none"}", ${a.blast_radius_factors.facing}`,
    href: `/queue?asset=${encodeURIComponent(a.name)}`,
  }));

  container.innerHTML = `
    <p class="subtitle">
      If this asset is compromised, how far does the damage spread - not how likely a specific
      finding is to be exploited (see the <a href="/risk" data-link>Risk Dashboard</a> for that).
      Built from a real 4-dimension profiling framework; honestly scoped to what this app's real
      data can actually answer today.
    </p>

    <h2 style="margin-top:8px">What this does and doesn't measure</h2>
    ${profilingCoverageHtml(data.profiling_coverage)}

    <h2 style="margin-top:28px">Immediate risks (Blast Radius × real exploitability)</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      Cross-references Blast Radius against real KEV-listing/likelihood data, not a third
      weighted component - see remediation/config/blast_radius_rules.yaml's
      immediate_risk_* thresholds to retune.
    </p>
    ${immediateRisksHtml(data.immediate_risks)}

    <h2 style="margin-top:28px">Top 12 assets by Blast Radius</h2>
    <div class="chart-row">
      <div class="chart-block">
        ${chartData.length ? barChartSvg(chartData, { width: 760 }) : `<p class="empty-state">No scored assets yet.</p>`}
      </div>
    </div>

    <h2 style="margin-top:28px">All scored assets (top 25)</h2>
    ${topAssetsTableHtml(assets)}`;

  wireChartLinks(container);
}
