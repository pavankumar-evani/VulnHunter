// OT Vulnerabilities hub: brings Operational Technology / IoT device findings
// (infra_category "ot" - the same real tag infra_classification.py already computes
// for asset.type "iot-ot-device", reused here rather than re-derived independently) up
// to the same shape as the Infrastructure/Application/Certificate hubs - a
// total-vulnerabilities KPI, severity/device-type/team/priority/aging charts, top-5
// rankings, an AI trend analysis assistant, and real page-specific insights content.
// Not a separate data source - every count here comes straight from /api/queue. This is
// the ONLY hub-style rollup for OT/IoT findings - Infrastructure Vulnerabilities
// deliberately excludes the "ot" category from its own KPI/cards/charts (see that
// page's module docstring) so OT/ICS data lives in exactly one dedicated place, not
// duplicated across two hubs.
import { api } from "../api.js";
import { pieChartSvg, countBy, wireChartLinks } from "../charts.js";
import { findingsTableHtml, wireFindingsTable } from "../findingsTable.js";
import { buildOwnerTeamMaps } from "../assetLookup.js";
import { dateRangeHtml, wireDateRange, filterByDateRange, computeRange, dateRangeDisclaimerHtml } from "../dateRange.js";
import { filterByTenant, tenantBannerHtml } from "../tenant.js";
import {
  severityChartBlockHtml, buildTopRankings, topRankingsHtml, wireTopRankings,
  totalVulnerabilitiesKpiHtml, teamPriorityChartBlockHtml,
  agingChartBlockHtml, agingByPriorityTableHtml, agingDisclaimerHtml,
} from "../domainSummary.js";
import { aiTrendAnalysisFabHtml, wireAiTrendAnalysis } from "../aiTrendAnalysis.js";
import { makeChartsReorderable } from "../chartLayout.js";
import { setInsightsContent, insightSectionHtml, insightAlertHtml } from "../insightsPanel.js";

export const title = "OT Vulnerabilities";

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [queue, assetsData] = await Promise.all([api.queue(), api.assetsList()]);
  const { ownerByAssetName, teamByAssetName, environmentByAssetName } = buildOwnerTeamMaps(assetsData.assets);

  const otFindings = filterByTenant(queue.findings).filter((f) => f.infra_category === "ot");
  const kevCount = otFindings.filter((f) => f.kev && f.kev.listed).length;
  const breachedCount = otFindings.filter((f) => f.sla && f.sla.breached).length;
  const subgroups = [{ label: "OT / IoT Devices", findings: otFindings }];

  // Real device-type breakdown from each asset's own os field (e.g. "SCADA HMI",
  // "Industrial PLC (Siemens SIMATIC family)", "IP Camera") - not a fabricated
  // taxonomy, and not further bucketed into broader categories (unlike infra's
  // scripted infra_category rollup) since these values are already specific and
  // real; a long tail of single-instance device models is expected and honest, not
  // hidden.
  const deviceTypeData = countBy(otFindings, (f) => (f.asset && f.asset.os) || "Unknown device")
    .map((d) => (d.label === "Unknown device" ? d : { ...d, href: `/queue?assetOs=${encodeURIComponent(d.label)}` }));

  let dateRange = { preset: "", customFrom: "", customTo: "" };
  const rankings = buildTopRankings(otFindings, ownerByAssetName, teamByAssetName);

  container.innerHTML = `
    <p class="subtitle">Operational Technology and IoT device findings - industrial
    control systems (PLCs, SCADA/HMI), building automation, IP cameras, sensor
    gateways, and similar devices. The one dedicated home for this data - Infrastructure
    Vulnerabilities deliberately excludes OT/IoT from its own rollup so it isn't shown
    in two places. Remediation Queue pre-filtered underneath, not a separate data
    source.</p>

    ${tenantBannerHtml()}

    <div class="callout callout-warn">
      ⚠️ No automated fixer exists for OT/IoT devices - unlike windows-server/
      unix-server findings, these can't be patched via Ansible/SCCM. Remediation here
      normally means a vendor firmware update, physical/out-of-band access, or a
      network-level compensating control (segmentation, disabling an exposed
      service) - routed to the owning team rather than auto-generated. See
      <a href="/compensating-controls" data-link>Compensating Controls</a> for the
      keyword-heuristic suggestions available while no OT fixer exists.
    </div>

    <div class="kpi-grid">
      ${totalVulnerabilitiesKpiHtml(subgroups)}
      <div class="kpi-card kpi-danger"><div class="kpi-value">${breachedCount}</div><div class="kpi-label">SLA breached</div></div>
      <div class="kpi-card kpi-danger"><div class="kpi-value">${kevCount}</div><div class="kpi-label">CISA KEV-listed</div></div>
    </div>

    <div class="chart-row">
      ${severityChartBlockHtml(otFindings)}
      <div class="chart-block">
        <h3>By device type</h3>
        ${deviceTypeData.length ? pieChartSvg(deviceTypeData) : `<p class="empty-state">No OT/IoT findings.</p>`}
      </div>
    </div>

    <div class="chart-row">
      ${teamPriorityChartBlockHtml(otFindings, teamByAssetName)}
    </div>
    <p class="filter-count" style="margin:-4px 0 12px">
      Team/priority breakdown - most assets in this demo dataset have no CMDB-imported
      owner/team yet (see <a href="/assets" data-link>Asset Inventory</a>).
    </p>

    <h2 style="margin-top:28px">Open-finding age (30/60/90-day backlog aging)</h2>
    ${agingDisclaimerHtml()}
    <div class="chart-row">
      ${agingChartBlockHtml(otFindings)}
    </div>
    <h3 style="margin-top:20px">By priority</h3>
    ${agingByPriorityTableHtml(otFindings)}

    ${topRankingsHtml("ot-hub", rankings)}

    <h2 style="margin-top:28px">All OT/IoT findings</h2>
    <div class="filter-bar" id="ot-hub-filters">${dateRangeHtml("ot-hub-daterange", dateRange)}</div>
    ${dateRangeDisclaimerHtml()}
    ${findingsTableHtml("ot-hub")}
    ${aiTrendAnalysisFabHtml("ot-hub")}`;

  function rewireTable() {
    const filteredFindings = dateRange.preset
      ? filterByDateRange(otFindings, computeRange(dateRange.preset, dateRange.customFrom, dateRange.customTo), "first_seen")
      : otFindings;
    wireFindingsTable(container, filteredFindings, {
      exportGroupId: "ot-hub",
      filenameBase: "vulnhunter-ot-vulnerabilities",
      ownerByAssetName, teamByAssetName, environmentByAssetName,
    });
  }

  wireDateRange(container, "ot-hub-daterange", (range) => { dateRange = range; rewireTable(); });
  rewireTable();
  wireTopRankings(container, "ot-hub", rankings);
  wireChartLinks(container);
  makeChartsReorderable(container, "ot-vulnerabilities");

  wireAiTrendAnalysis(container, "ot-hub", "OT/IoT", async () => {
    const severityData = countBy(otFindings, (f) => f.severity);
    const priorityData = countBy(otFindings, (f) => f.priority);
    return {
      "Total OT/IoT findings": otFindings.length,
      "SLA breached": breachedCount,
      "CISA KEV-listed": kevCount,
      "By device type (top 5)": deviceTypeData.slice(0, 5).map((d) => `${d.label}=${d.value}`).join(", "),
      "Severity breakdown": severityData.map((d) => `${d.label}=${d.value}`).join(", "),
      "Priority breakdown": priorityData.map((d) => `${d.label}=${d.value}`).join(", "),
    };
  }, "OT / IoT Devices");

  const teamAssignedCount = otFindings.filter((f) => teamByAssetName.get(f.asset && f.asset.name)).length;
  const teamAssignedPct = otFindings.length ? Math.round((teamAssignedCount / otFindings.length) * 100) : 0;

  const alerts = [];
  if (breachedCount > 0) {
    alerts.push(insightAlertHtml(`<strong>${breachedCount}</strong> OT/IoT finding(s) are past their SLA window.`, "danger"));
  }
  if (kevCount > 0) {
    alerts.push(insightAlertHtml(`<strong>${kevCount}</strong> OT/IoT finding(s) are CISA KEV-listed - confirmed actively exploited.`, "warn"));
  }
  if (teamAssignedPct < 50 && otFindings.length) {
    alerts.push(insightAlertHtml(
      `Only <strong>${teamAssignedPct}%</strong> of OT/IoT findings have a team assigned - see <a href="/assets" data-link>Asset Inventory</a> to import ownership.`,
      "warn",
    ));
  }
  if (!otFindings.length) {
    alerts.push(insightAlertHtml("No OT/IoT findings match the current tenant selection.", "info"));
  }
  setInsightsContent(insightSectionHtml("On this page", alerts.join("")));
}
