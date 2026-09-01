// Application Security hub: a single landing page that rolls up the AppSec-specific
// finding categories (SAST, DAST, SCA, Secrets-in-code, Container, API) into one view
// with a count and a deep link into each's real, pre-filtered page - rather than making
// a user hunt across /vulnhunt and /queue to answer "what does our application security
// posture look like."
// Infrastructure Vulnerability Management and Certificate/TLS findings are deliberately
// NOT rolled up here - those are asset/network-facing categories, not application security
// ones, and each already has its own top-level Security Domains nav entry.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { icon } from "../icons.js";
import { categoryFor } from "./vulnhunt.js";
import {
  findingsTableHtml, wireFindingsTable, findingsFilterBarHtml, applyFindingsFilters, wireFindingsFilterBar,
} from "../findingsTable.js";
import { buildOwnerTeamMaps } from "../assetLookup.js";
import { dateRangeHtml, wireDateRange, filterByDateRange, computeRange, dateRangeDisclaimerHtml } from "../dateRange.js";
import { pieChartSvg, countBy, wireChartLinks } from "../charts.js";
import { filterByTenant, tenantBannerHtml } from "../tenant.js";
import {
  severityChartBlockHtml, buildTopRankings, topRankingsHtml, wireTopRankings,
  totalVulnerabilitiesKpiHtml, severityBreakdownTableHtml, teamPriorityChartBlockHtml,
  agingChartBlockHtml, agingByPriorityTableHtml, agingBreakdownTableHtml, agingDisclaimerHtml,
} from "../domainSummary.js";
import { aiTrendAnalysisFabHtml, wireAiTrendAnalysis } from "../aiTrendAnalysis.js";
import { makeChartsReorderable } from "../chartLayout.js";
import { setInsightsContent, insightSectionHtml, insightAlertHtml } from "../insightsPanel.js";

export const title = "Application Vulnerabilities";

const SCA_DAST_TYPE_OPTIONS = [
  { value: "sca", label: "SCA" },
  { value: "dast", label: "DAST" },
  { value: "secrets", label: "Repository Secret Scanning" },
];

function domainCard({ href, iconName, label, count, note }) {
  return `
    <a class="domain-card" href="${href}" data-link>
      <span class="domain-card-icon">${icon(iconName, 22)}</span>
      <span class="domain-card-count">${count}</span>
      <span class="domain-card-label">${escapeHtml(label)}</span>
      <span class="domain-card-note">${escapeHtml(note)}</span>
    </a>`;
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [vh, queue, assetsData] = await Promise.all([api.vulnhunt(), api.queue(), api.assetsList()]);
  const { ownerByAssetName, teamByAssetName, environmentByAssetName } = buildOwnerTeamMaps(assetsData.assets);

  const sastFindings = vh.available ? vh.findings : [];
  const sastTotal = sastFindings.length;
  const secretsTotal = sastFindings.filter((f) => categoryFor(f.CWE, f.File) === "Secrets").length;
  const containerTotal = sastFindings.filter((f) => categoryFor(f.CWE, f.File) === "Container").length;
  const apiTotal = sastFindings.filter((f) => categoryFor(f.CWE, f.File) === "API").length;
  const scaDastFindings = filterByTenant(queue.findings).filter((f) =>
    f.scan_type === "sca" || f.scan_type === "dast" || f.scan_type === "secrets");
  const scaTotal = scaDastFindings.filter((f) => f.scan_type === "sca").length;
  const dastTotal = scaDastFindings.filter((f) => f.scan_type === "dast").length;
  const repoSecretsTotal = scaDastFindings.filter((f) => f.scan_type === "secrets").length;
  let dateRange = { preset: "", customFrom: "", customTo: "" };
  let colFilters = { priority: "all", assetType: "all", category: "all", owner: "all", team: "all", asset: "", id: "" };
  // SAST findings use capitalized f.Severity (parsed from a markdown table) - a
  // genuinely different key-casing convention than /api/queue's lowercase f.severity -
  // normalized here so the severity chart reflects the whole application-security
  // picture, not just the queue-tracked half.
  const severityFindings = [...scaDastFindings, ...sastFindings.map((f) => ({ severity: f.Severity }))];
  const rankings = buildTopRankings(scaDastFindings, ownerByAssetName, teamByAssetName);

  const dastFindings = scaDastFindings.filter((f) => f.scan_type === "dast");
  const scaFindings = scaDastFindings.filter((f) => f.scan_type === "sca");
  const repoSecretsFindings = scaDastFindings.filter((f) => f.scan_type === "secrets");
  const secretsMgmtFindings = sastFindings.filter((f) => categoryFor(f.CWE, f.File) === "Secrets").map((f) => ({ severity: f.Severity }));
  const containerFindings = sastFindings.filter((f) => categoryFor(f.CWE, f.File) === "Container").map((f) => ({ severity: f.Severity }));
  const apiFindings = sastFindings.filter((f) => categoryFor(f.CWE, f.File) === "API").map((f) => ({ severity: f.Severity }));
  const sastAsSeverity = sastFindings.map((f) => ({ severity: f.Severity }));

  const breakdownSubgroups = [
    { label: "SAST — Code Scan", findings: sastAsSeverity, href: "/vulnhunt" },
    { label: "DAST — Dynamic Testing", findings: dastFindings, href: "/queue?category=dast" },
    { label: "SCA — Software Composition", findings: scaFindings, href: "/queue?category=sca" },
    { label: "Secrets Management", findings: secretsMgmtFindings, href: "/vulnhunt?category=Secrets" },
    { label: "Secret Scanning (Repository)", findings: repoSecretsFindings, href: "/queue?category=secrets" },
    { label: "Container Vulnerabilities", findings: containerFindings, href: "/vulnhunt?category=Container" },
    { label: "API Vulnerabilities", findings: apiFindings, href: "/vulnhunt?category=API" },
  ];
  // Honest total: SAST's own count already includes the Secrets/Container/API
  // subsets above (categoryFor() sub-classifies a SAST finding, it doesn't create a
  // separate one) - summing all 7 cards would double-count those three. The real,
  // non-overlapping distinct pools are SAST + DAST + SCA + Repo Secret Scanning.
  const totalSubgroups = [
    { label: "SAST", findings: sastAsSeverity }, { label: "DAST", findings: dastFindings },
    { label: "SCA", findings: scaFindings }, { label: "Repo Secret Scanning", findings: repoSecretsFindings },
  ];

  container.innerHTML = `
    <p class="subtitle">Application-layer findings only - source code (SAST), bundled/
    third-party libraries (SCA), hardcoded secrets, dynamic/runtime testing (DAST),
    container/base-image issues, and API-security findings.
    Infrastructure and certificate findings live under their own Security Domains entries.</p>

    ${tenantBannerHtml()}

    <div class="kpi-grid">${totalVulnerabilitiesKpiHtml(totalSubgroups)}</div>
    <p class="filter-count" style="margin:-4px 0 12px">
      SAST's own count already includes the Secrets Management/Container/API subsets
      below (they're a sub-classification of the same source-code findings, not a
      separate pool) - this total is SAST + DAST + SCA + Repo Secret Scanning, the
      genuinely non-overlapping categories, not a naive sum of every card below.
    </p>

    <div class="domain-card-grid">
      ${domainCard({
        href: "/vulnhunt", iconName: "scan", label: "SAST — Code Scan", count: sastTotal,
        note: vh.available ? "Source-code findings from the last /vulnhunt run." : "No scan results yet.",
      })}
      ${domainCard({
        href: "/queue?category=dast", iconName: "dast", label: "DAST — Dynamic Testing", count: dastTotal,
        note: dastTotal ? "Findings from a runtime/dynamic scan." : "No sample DAST data yet - see the FAQ.",
      })}
      ${domainCard({
        href: "/queue?category=sca", iconName: "sca", label: "SCA — Software Composition", count: scaTotal,
        note: "Vulnerable third-party / bundled library findings.",
      })}
      ${domainCard({
        href: "/vulnhunt?category=Secrets", iconName: "secrets", label: "Secrets Management", count: secretsTotal,
        note: "Hardcoded credentials/keys found in source (CWE-798).",
      })}
      ${domainCard({
        href: "/queue?category=secrets", iconName: "secrets", label: "Secret Scanning (Repository)", count: repoSecretsTotal,
        note: "GitHub/GitLab secret-scanning alerts on committed repository files - a different data path than Secrets Management above.",
      })}
      ${domainCard({
        href: "/vulnhunt?category=Container", iconName: "container", label: "Container Vulnerabilities (build-time)", count: containerTotal,
        note: "Static Dockerfile/base-image issues from code scanning - root user, baked-in secrets, unpinned tags. Different from Container/Host Runtime Security on the Infrastructure Vulnerabilities hub, which is real-time behavioral detection on a running container/host, not static file analysis.",
      })}
      ${domainCard({
        href: "/vulnhunt?category=API", iconName: "api", label: "API Vulnerabilities", count: apiTotal,
        note: apiTotal ? "Missing auth, permissive CORS, or mass-assignment findings." : "No sample API-security finding yet - see the FAQ.",
      })}
    </div>

    <div class="callout">
      This is a rollup view, not a separate data source - every count above comes straight
      from <code>/api/vulnhunt</code> and <code>/api/queue</code>, the same data the Code
      Scan and Remediation Queue pages already show. Click any card to jump to the
      pre-filtered underlying view.
    </div>

    <div class="chart-row">
      ${severityChartBlockHtml(severityFindings)}
      <div class="chart-block">
        <h3>Findings by category</h3>
        ${pieChartSvg([
          { label: "SAST", value: sastTotal }, { label: "DAST", value: dastTotal },
          { label: "SCA", value: scaTotal }, { label: "Secrets", value: secretsTotal },
          { label: "Container", value: containerTotal }, { label: "API", value: apiTotal },
          { label: "Repo Secret Scanning", value: repoSecretsTotal },
        ].filter((d) => d.value > 0))}
      </div>
    </div>

    <div class="chart-row">
      ${teamPriorityChartBlockHtml(scaDastFindings, teamByAssetName)}
    </div>
    <p class="filter-count" style="margin:-4px 0 12px">
      Team/priority breakdown covers DAST/SCA/Repo Secret Scanning findings only - SAST
      findings have no asset/team association in this data path (see the Code Scan page).
    </p>

    <h2 style="margin-top:28px">Open-finding age (30/60/90-day backlog aging)</h2>
    ${agingDisclaimerHtml()}
    <p class="filter-count" style="margin:-4px 0 8px">
      Covers DAST/SCA/Repo Secret Scanning findings only - SAST/Secrets Management/
      Container/API findings have no first-seen date in this data path (see the Code
      Scan page).
    </p>
    <div class="chart-row">
      ${agingChartBlockHtml(scaDastFindings)}
    </div>
    <h3 style="margin-top:20px">By priority</h3>
    ${agingByPriorityTableHtml(scaDastFindings)}
    ${agingBreakdownTableHtml([
      { label: "DAST", findings: dastFindings, href: "/queue?category=dast" },
      { label: "SCA", findings: scaFindings, href: "/queue?category=sca" },
      { label: "Repo Secret Scanning", findings: repoSecretsFindings, href: "/queue?category=secrets" },
    ])}

    ${severityBreakdownTableHtml(breakdownSubgroups)}
    <p class="filter-count" style="margin:-10px 0 12px">
      This table's own "All sub-categories" row is a plain sum of the 7 rows above (so
      it double-counts Secrets/Container/API within SAST, same as the cards do) - the
      ${totalSubgroups.reduce((sum, s) => sum + s.findings.length, 0)} total-vulnerabilities
      KPI further up this page is the de-duplicated figure.
    </p>

    <p class="filter-count" style="margin:16px 0 -8px">
      Top-5 rankings below are built from SCA/DAST/repository-secret-scanning findings
      only (the SLA-tracked, asset-bearing subset) - SAST/Secrets Management/Container/
      API findings have no asset/CVE shape to rank by (see the Code Scan page).
    </p>
    ${topRankingsHtml("appsec-hub", rankings)}

    <h2 style="margin-top:28px">SCA, DAST, and Repository Secret Scanning findings (SLA-tracked)</h2>
    <p class="subtitle">
      SAST, Secrets Management, Container, and API findings come from source-code
      scanning (<a href="/vulnhunt" data-link>Code Scan Results</a>) and aren't
      SLA-tracked queue items by design - see the callout there. SCA, DAST, and
      repository secret-scanning findings are, so they get the same live findings
      table as the Remediation Queue.
    </p>
    <div class="filter-bar" id="appsec-hub-filters">
      ${findingsFilterBarHtml("appsec-hub", scaDastFindings, {
        ownerByAssetName, teamByAssetName, categoryLabel: "Type", categoryOptions: SCA_DAST_TYPE_OPTIONS,
      })}
      ${dateRangeHtml("appsec-hub-daterange", dateRange)}
    </div>
    ${dateRangeDisclaimerHtml()}
    ${findingsTableHtml("appsec-hub")}
    ${aiTrendAnalysisFabHtml("appsec-hub")}`;

  function rewireTable() {
    let filteredFindings = applyFindingsFilters(scaDastFindings, colFilters, { ownerByAssetName, teamByAssetName });
    filteredFindings = dateRange.preset
      ? filterByDateRange(filteredFindings, computeRange(dateRange.preset, dateRange.customFrom, dateRange.customTo), "first_seen")
      : filteredFindings;
    wireFindingsTable(container, filteredFindings, {
      exportGroupId: "appsec-hub",
      filenameBase: "vulnhunter-appsec-sca-dast",
      ownerByAssetName, teamByAssetName, environmentByAssetName,
    });
  }

  wireFindingsFilterBar(container, "appsec-hub", (filters) => { colFilters = filters; rewireTable(); });
  wireDateRange(container, "appsec-hub-daterange", (range) => { dateRange = range; rewireTable(); });
  rewireTable();
  wireTopRankings(container, "appsec-hub", rankings);
  wireChartLinks(container);
  makeChartsReorderable(container, "appsec");

  wireAiTrendAnalysis(container, "appsec-hub", "application", async () => {
    const teamData = countBy(scaDastFindings, (f) => teamByAssetName.get(f.asset && f.asset.name) || "Unassigned");
    const priorityData = countBy(scaDastFindings, (f) => f.priority);
    return {
      "SAST findings (Code Scan)": sastTotal,
      "DAST findings": dastTotal,
      "SCA findings": scaTotal,
      "Secrets Management findings (source code)": secretsTotal,
      "Repository Secret Scanning findings": repoSecretsTotal,
      "Container Vulnerabilities findings": containerTotal,
      "API Vulnerabilities findings": apiTotal,
      "Priority breakdown (SCA/DAST/Repo Secret Scanning only)": priorityData.map((d) => `${d.label}=${d.value}`).join(", "),
      "Findings by team, top 5 (SCA/DAST/Repo Secret Scanning only)": teamData.slice(0, 5).map((d) => `${d.label}=${d.value}`).join(", "),
    };
  }, "Application Security (SAST/DAST/SCA/Secrets/Container/API)");

  const teamAssignedCount = scaDastFindings.filter((f) => teamByAssetName.get(f.asset && f.asset.name)).length;
  const teamAssignedPct = scaDastFindings.length ? Math.round((teamAssignedCount / scaDastFindings.length) * 100) : 0;
  const criticalCount = severityFindings.filter((f) => f.severity === "Critical").length;

  const alerts = [];
  if (criticalCount > 0) {
    alerts.push(insightAlertHtml(
      `<strong>${criticalCount}</strong> Critical-severity application finding(s) across SAST/DAST/SCA/Secrets/Container/API.`,
      "danger",
    ));
  }
  if (repoSecretsTotal === 0) {
    alerts.push(insightAlertHtml(
      `Repository Secret Scanning shows 0 findings - no sample data for this category yet, not necessarily a clean bill of health. See the FAQ.`,
      "info",
    ));
  }
  if (teamAssignedPct < 50 && scaDastFindings.length) {
    alerts.push(insightAlertHtml(
      `Only <strong>${teamAssignedPct}%</strong> of SCA/DAST/Repo-Secret findings have a team assigned - see <a href="/assets" data-link>Asset Inventory</a> to import ownership.`,
      "warn",
    ));
  }

  // Trimmed to just the one most load-bearing section - see queue.js's own comment on
  // this same change (Part 11: insights panel now starts collapsed by default).
  setInsightsContent(insightSectionHtml("On this page", alerts.join("")));
}
