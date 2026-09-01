// Certificate Vulnerabilities hub: brings Certificate & TLS Lifecycle Management
// findings (scan_type "cert-mgmt") up to the same shape as the Infrastructure/
// Application Vulnerabilities hubs - a total-vulnerabilities KPI, severity/aging
// charts, top-5 rankings, an AI trend analysis panel, and real page-specific insights
// content - instead of a bare filtered Remediation Queue table with none of that. Not
// a separate data source - every count here comes straight from /api/queue, same as
// every other hub page.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { countBy, wireChartLinks } from "../charts.js";
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
import { setInsightsContent, insightSectionHtml, insightAlertHtml } from "../insightsPanel.js";

export const title = "Certificate Vulnerabilities";

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [queue, assetsData] = await Promise.all([api.queue(), api.assetsList()]);
  const { ownerByAssetName, teamByAssetName, environmentByAssetName } = buildOwnerTeamMaps(assetsData.assets);

  const certFindings = filterByTenant(queue.findings).filter((f) => f.scan_type === "cert-mgmt");
  const kevCount = certFindings.filter((f) => f.kev && f.kev.listed).length;
  const breachedCount = certFindings.filter((f) => f.sla && f.sla.breached).length;
  const subgroups = [{ label: "Certificate & TLS Lifecycle Management", findings: certFindings }];

  let dateRange = { preset: "", customFrom: "", customTo: "" };
  const rankings = buildTopRankings(certFindings, ownerByAssetName, teamByAssetName);

  container.innerHTML = `
    <p class="subtitle">Certificate &amp; TLS Lifecycle Management findings - expiring/
    expired certificates, weak protocol versions, and related TLS misconfigurations.
    Remediation Queue pre-filtered underneath, same data as every other hub page.</p>

    ${tenantBannerHtml()}

    <div class="kpi-grid">
      ${totalVulnerabilitiesKpiHtml(subgroups)}
      <div class="kpi-card kpi-danger"><div class="kpi-value">${breachedCount}</div><div class="kpi-label">SLA breached</div></div>
      <div class="kpi-card kpi-danger"><div class="kpi-value">${kevCount}</div><div class="kpi-label">CISA KEV-listed</div></div>
    </div>

    <div class="chart-row">
      ${severityChartBlockHtml(certFindings)}
      ${teamPriorityChartBlockHtml(certFindings, teamByAssetName)}
    </div>
    <p class="filter-count" style="margin:-4px 0 12px">
      Team/priority breakdown - most assets in this demo dataset have no CMDB-imported
      owner/team yet (see <a href="/assets" data-link>Asset Inventory</a>).
    </p>

    <h2 style="margin-top:28px">Open-finding age (30/60/90-day backlog aging)</h2>
    ${agingDisclaimerHtml()}
    <div class="chart-row">
      ${agingChartBlockHtml(certFindings)}
    </div>
    <h3 style="margin-top:20px">By priority</h3>
    ${agingByPriorityTableHtml(certFindings)}

    ${topRankingsHtml("cert-hub", rankings)}

    <h2 style="margin-top:28px">All certificate findings</h2>
    <div class="filter-bar" id="cert-hub-filters">${dateRangeHtml("cert-hub-daterange", dateRange)}</div>
    ${dateRangeDisclaimerHtml()}
    ${findingsTableHtml("cert-hub")}
    ${aiTrendAnalysisFabHtml("cert-hub")}`;

  function rewireTable() {
    const filteredFindings = dateRange.preset
      ? filterByDateRange(certFindings, computeRange(dateRange.preset, dateRange.customFrom, dateRange.customTo), "first_seen")
      : certFindings;
    wireFindingsTable(container, filteredFindings, {
      exportGroupId: "cert-hub",
      filenameBase: "vulnhunter-certificate-vulnerabilities",
      ownerByAssetName, teamByAssetName, environmentByAssetName,
    });
  }

  wireDateRange(container, "cert-hub-daterange", (range) => { dateRange = range; rewireTable(); });
  rewireTable();
  wireTopRankings(container, "cert-hub", rankings);
  wireChartLinks(container);

  wireAiTrendAnalysis(container, "cert-hub", "certificate", async () => {
    const severityData = countBy(certFindings, (f) => f.severity);
    const priorityData = countBy(certFindings, (f) => f.priority);
    return {
      "Total certificate findings": certFindings.length,
      "SLA breached": breachedCount,
      "CISA KEV-listed": kevCount,
      "Severity breakdown": severityData.map((d) => `${d.label}=${d.value}`).join(", "),
      "Priority breakdown": priorityData.map((d) => `${d.label}=${d.value}`).join(", "),
    };
  }, "Certificate & TLS Lifecycle Management");

  const alerts = [];
  if (breachedCount > 0) {
    alerts.push(insightAlertHtml(`<strong>${breachedCount}</strong> certificate finding(s) are past their SLA window.`, "danger"));
  }
  if (kevCount > 0) {
    alerts.push(insightAlertHtml(`<strong>${kevCount}</strong> certificate finding(s) are CISA KEV-listed - confirmed actively exploited.`, "warn"));
  }
  if (!certFindings.length) {
    alerts.push(insightAlertHtml("No certificate findings match the current tenant selection.", "info"));
  }
  setInsightsContent(insightSectionHtml("On this page", alerts.join("")));
}
