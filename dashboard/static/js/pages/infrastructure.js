// Infrastructure Vulnerabilities hub: rolls up Infrastructure Vulnerability
// Management findings into the sub-categories a real infra/security team actually
// organizes around - OS-level patching, network hardware, network security
// appliances, OT/IoT devices, and cloud infrastructure - rather than one flat
// "Infrastructure Vulnerabilities" list. Same rollup-view pattern as /appsec: every
// count here comes straight from /api/queue (already tagged with `infra_category` by
// remediation/enrichment/infra_classification.py via dashboard/data.py's
// load_live_queue()), not a separate data source.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { icon } from "../icons.js";
import { INFRA_CATEGORIES, INFRA_CATEGORY_LABELS } from "../infraTypes.js";
import { findingsTableHtml, wireFindingsTable } from "../findingsTable.js";
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
import { setInsightsContent, insightSectionHtml, insightAlertHtml } from "../insightsPanel.js";

export const title = "Infrastructure Vulnerabilities";

const CATEGORY_ICONS = {
  "os": "infra",
  "endpoint": "endpoint",
  "network": "sca",
  "network-security": "certmgmt",
  "ot": "container",
  "virtualization": "virtualization",
  "cloud": "cloud",
  "apps": "assets",
  "printer": "printer",
  "iac": "iac",
  "runtime": "container",
};

const CATEGORY_NOTES = {
  "os": "Windows/Unix server OS-level patching.",
  "endpoint": "Laptops/desktops (patched via SCCM/Microsoft Configuration Manager) and mobile devices (patched via MDM, e.g. Intune) - see a finding's Remediation Mechanism field.",
  "network": "Routers, switches, and other core network hardware.",
  "network-security": "Firewalls, IDS/IPS, and other security appliances.",
  "ot": "Operational technology and IoT devices.",
  "virtualization": "Hypervisor/VM platform CVEs (VMware ESXi/vCenter, Hyper-V, Proxmox, Citrix Hypervisor, KVM).",
  "cloud": "Cloud asset/posture findings (AWS/Azure/GCP/OCI/Alibaba Cloud) - see the by-provider breakdown below.",
  "apps": "Browsers, PDF readers, dev tools, media/utility software, and drivers on end-user workstations.",
  "printer": "Networked printer/MFP firmware (HP, Xerox, Canon, Lexmark, Ricoh, etc.).",
  "iac": "Infrastructure-as-Code misconfigurations (Terraform/CloudFormation-style, Checkov/tfsec detection).",
  "runtime": "Falco-style container/host runtime behavioral detections (a running container/host, not static file analysis). Different from Container Vulnerabilities on the Application Vulnerabilities hub, which is static Dockerfile/base-image scanning from code, not a running-system observation.",
};

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
  const [queue, assetsData] = await Promise.all([api.queue(), api.assetsList()]);
  const { ownerByAssetName, teamByAssetName, environmentByAssetName } = buildOwnerTeamMaps(assetsData.assets);

  const counts = Object.fromEntries(INFRA_CATEGORIES.map((c) => [c, 0]));
  const findingsByCategory = Object.fromEntries(INFRA_CATEGORIES.map((c) => [c, []]));
  const infraFindings = [];
  for (const f of filterByTenant(queue.findings)) {
    if (f.infra_category && f.infra_category in counts) {
      counts[f.infra_category] += 1;
      findingsByCategory[f.infra_category].push(f);
      infraFindings.push(f);
    }
  }

  let dateRange = { preset: "", customFrom: "", customTo: "" };
  const rankings = buildTopRankings(infraFindings, ownerByAssetName, teamByAssetName);
  const subgroups = INFRA_CATEGORIES.map((c) => ({
    label: INFRA_CATEGORY_LABELS[c], findings: findingsByCategory[c],
    href: `/queue?category=infra-vm&infraType=${c}`,
  }));

  container.innerHTML = `
    <p class="subtitle">Infrastructure Vulnerability Management findings, split by the
    asset-type groupings a real infra/security team actually organizes around -
    Tenable/Armis-style asset scanning underneath, not a separate data source.</p>

    ${tenantBannerHtml()}

    <div class="kpi-grid">${totalVulnerabilitiesKpiHtml(subgroups)}</div>

    <div class="domain-card-grid">
      ${INFRA_CATEGORIES.map((c) => domainCard({
        href: `/queue?category=infra-vm&infraType=${c}`,
        iconName: CATEGORY_ICONS[c],
        label: INFRA_CATEGORY_LABELS[c],
        count: counts[c],
        note: counts[c] ? CATEGORY_NOTES[c] : `${CATEGORY_NOTES[c]} No sample finding yet - see the FAQ.`,
      })).join("")}
    </div>

    <div class="callout">
      This is a rollup view, not a separate data source - every count above comes
      straight from <code>/api/queue</code>'s <code>infra_category</code> field
      (<code>remediation/enrichment/infra_classification.py</code>), the same data the
      Remediation Queue page already shows. Click any card to jump to the
      pre-filtered underlying view, or a finding's ID below for its full detail.
    </div>

    <div class="chart-row">
      ${severityChartBlockHtml(infraFindings)}
      <div class="chart-block">
        <h3>By sub-category</h3>
        ${pieChartSvg(INFRA_CATEGORIES.filter((c) => counts[c] > 0).map((c) => ({
          label: INFRA_CATEGORY_LABELS[c], value: counts[c],
          href: `/queue?category=infra-vm&infraType=${encodeURIComponent(c)}`,
        })))}
      </div>
      ${counts.cloud ? `
      <div class="chart-block" style="max-width:380px">
        <h3>Cloud findings by provider</h3>
        <p class="filter-count" style="margin:-4px 0 8px">
          Derived from each cloud asset's own real platform description
          (<code>remediation/enrichment/cloud_provider.py</code>) - not a live
          AWS/Azure/GCP/OCI/Alibaba API integration. A self-managed Kubernetes cluster,
          generic Docker host, or Terraform-provisioned resource honestly has no single
          provider to attribute and is grouped as "Not attributed" rather than guessed.
        </p>
        ${pieChartSvg(countBy(findingsByCategory.cloud, (f) => f.cloud_provider || "Not attributed")
          .map((d) => ({ ...d, href: `/queue?cloudProvider=${encodeURIComponent(d.label)}` })))}
      </div>` : ""}
    </div>

    <div class="chart-row">
      ${teamPriorityChartBlockHtml(infraFindings, teamByAssetName)}
    </div>

    <h2 style="margin-top:28px">Open-finding age (30/60/90-day backlog aging)</h2>
    ${agingDisclaimerHtml()}
    <div class="chart-row">
      ${agingChartBlockHtml(infraFindings)}
    </div>
    <h3 style="margin-top:20px">By priority</h3>
    ${agingByPriorityTableHtml(infraFindings)}
    ${agingBreakdownTableHtml(subgroups)}

    ${severityBreakdownTableHtml(subgroups)}

    ${topRankingsHtml("infra-hub", rankings)}

    <h2 style="margin-top:28px">All infrastructure findings</h2>
    <div class="filter-bar" id="infra-hub-filters">${dateRangeHtml("infra-hub-daterange", dateRange)}</div>
    ${dateRangeDisclaimerHtml()}
    ${findingsTableHtml("infra-hub")}
    ${aiTrendAnalysisFabHtml("infra-hub")}`;

  function rewireTable() {
    const filteredFindings = dateRange.preset
      ? filterByDateRange(infraFindings, computeRange(dateRange.preset, dateRange.customFrom, dateRange.customTo), "first_seen")
      : infraFindings;
    wireFindingsTable(container, filteredFindings, {
      exportGroupId: "infra-hub",
      filenameBase: "vulnhunter-infrastructure-vulnerabilities",
      ownerByAssetName, teamByAssetName, environmentByAssetName,
    });
  }

  wireDateRange(container, "infra-hub-daterange", (range) => { dateRange = range; rewireTable(); });
  rewireTable();
  wireTopRankings(container, "infra-hub", rankings);
  wireChartLinks(container);

  wireAiTrendAnalysis(container, "infra-hub", "infrastructure", async () => {
    const severityData = countBy(infraFindings, (f) => f.severity);
    const priorityData = countBy(infraFindings, (f) => f.priority);
    const teamData = countBy(infraFindings, (f) => teamByAssetName.get(f.asset && f.asset.name) || "Unassigned");
    return {
      "Total infrastructure findings": infraFindings.length,
      "By sub-category": INFRA_CATEGORIES.filter((c) => counts[c] > 0)
        .map((c) => `${INFRA_CATEGORY_LABELS[c]}=${counts[c]}`).join(", "),
      "Severity breakdown": severityData.map((d) => `${d.label}=${d.value}`).join(", "),
      "Priority breakdown": priorityData.map((d) => `${d.label}=${d.value}`).join(", "),
      "Findings by team (top 5)": teamData.slice(0, 5).map((d) => `${d.label}=${d.value}`).join(", "),
    };
  }, "Infrastructure Vulnerability Management");

  const zeroCategories = INFRA_CATEGORIES.filter((c) => counts[c] === 0);
  const teamAssignedCount = infraFindings.filter((f) => teamByAssetName.get(f.asset && f.asset.name)).length;
  const teamAssignedPct = infraFindings.length ? Math.round((teamAssignedCount / infraFindings.length) * 100) : 0;
  const kevCount = infraFindings.filter((f) => f.kev && f.kev.listed).length;

  const alerts = [];
  if (kevCount > 0) {
    alerts.push(insightAlertHtml(
      `<strong>${kevCount}</strong> infrastructure finding(s) are CISA KEV-listed (confirmed actively exploited) - the highest-priority tier regardless of severity.`,
      "danger",
    ));
  }
  if (teamAssignedPct < 50) {
    alerts.push(insightAlertHtml(
      `Only <strong>${teamAssignedPct}%</strong> (${teamAssignedCount} of ${infraFindings.length}) of infrastructure findings have a team assigned - most assets in this demo dataset have no CMDB-imported owner/team yet. Import one on <a href="/assets" data-link>Asset Inventory</a> to populate the "By team" chart above.`,
      "warn",
    ));
  }
  if (zeroCategories.length) {
    alerts.push(insightAlertHtml(
      `${zeroCategories.length} sub-categor${zeroCategories.length === 1 ? "y has" : "ies have"} no sample findings yet (${zeroCategories.map((c) => INFRA_CATEGORY_LABELS[c]).join(", ")}) - see the FAQ.`,
      "info",
    ));
  }

  // Trimmed to just the one most load-bearing section - see queue.js's own comment on
  // this same change (Part 11: insights panel now starts collapsed by default).
  setInsightsContent(insightSectionHtml("On this page", alerts.join("")));
}
