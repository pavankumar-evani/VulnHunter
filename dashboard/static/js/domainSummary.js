// Shared "how are we doing in this domain" building blocks - a severity bar chart
// plus top-5 vulnerabilities-by-affected-asset-count and top-5 assets-by-distinct-
// vulnerability-count mini tables, each linking to its own full ranked dashboard.
// Reused across every per-domain page (Overview, Infrastructure Vulnerabilities,
// Application Vulnerabilities, Risk Dashboard) so this looks and behaves the same
// everywhere instead of several slightly-different one-off implementations. Not a
// separate data source - built entirely from whatever findings subset the calling
// page already fetched from /api/queue.
import { escapeHtml } from "./dom.js";
import { barChartSvg, countBy } from "./charts.js";
import { groupVulnerabilitiesByType, groupFindingsByAsset } from "./rankings.js";
import { exportButtonsHtml, wireExportButtons } from "./export.js";

const VULN_COLUMNS = [
  { label: "Vulnerability", value: (g) => g.title },
  { label: "CVE", value: (g) => g.cve },
  { label: "Severity", value: (g) => g.severity },
  { label: "Affected Assets", value: (g) => g.assetCount },
  { label: "Assets", value: (g) => g.assetNames.join("; ") },
  { label: "Owner(s)", value: (g) => g.owners.join("; ") },
];

const ASSET_COLUMNS = [
  { label: "Asset", value: (a) => a.name },
  { label: "Type", value: (a) => a.type },
  { label: "Distinct Vulnerabilities", value: (a) => a.vulnCount },
  { label: "Critical Findings", value: (a) => a.criticalCount },
  { label: "Owner", value: (a) => a.owner },
];

function vulnRowHtml(g) {
  const href = g.cve ? `/queue?cve=${encodeURIComponent(g.cve)}` : `/queue?title=${encodeURIComponent(g.title)}`;
  return `
    <tr>
      <td class="wrap-cell"><a href="${href}" data-link>${escapeHtml(g.title)}</a></td>
      <td>${g.cve ? `<code>${escapeHtml(g.cve)}</code>` : `<span class="muted">—</span>`}</td>
      <td><span class="badge badge-${(g.severity || "").toLowerCase()}">${escapeHtml(g.severity || "?")}</span></td>
      <td><span class="badge badge-critical">${g.assetCount}</span></td>
      <td>${escapeHtml(g.owners.join(", "))}</td>
    </tr>`;
}

function assetRowHtml(a) {
  return `
    <tr>
      <td><a href="/queue?asset=${encodeURIComponent(a.name)}" data-link>${escapeHtml(a.name)}</a></td>
      <td class="asset-type-cell">${escapeHtml(a.type || "")}</td>
      <td><span class="badge badge-critical">${a.vulnCount}</span></td>
      <td>${a.criticalCount > 0 ? `<span class="badge badge-critical">${a.criticalCount}</span>` : `<span class="muted">0</span>`}</td>
      <td>${escapeHtml(a.owner)}</td>
    </tr>`;
}

// A chart-block fragment - the caller places this inside its own .chart-row
// (alongside a sub-category/methodology pie chart, if it has one).
export function severityChartBlockHtml(findings) {
  const severityData = countBy(findings, (f) => f.severity)
    .map((d) => ({ ...d, href: `/queue?severity=${encodeURIComponent(d.label)}` }));
  // Explicit narrower width - the default 420px (sized for charts with many bars)
  // is needless padding around only 4-5 severity bars, and was wide enough on its
  // own to push a sibling chart-block onto its own row in a .chart-row at anything
  // narrower than a very wide desktop viewport.
  return `
    <div class="chart-block">
      <h3>By severity</h3>
      ${severityData.length ? barChartSvg(severityData, { width: 340 }) : `<p class="empty-state">No findings.</p>`}
    </div>`;
}

// Same "chart-block fragment for the caller's own .chart-row" pattern as
// severityChartBlockHtml above - team ownership (via the same teamByAssetName map every
// consumer of this module already builds via assetLookup.js) and priority (the
// weighted score tier from remediation/config/priority_engine.py, tagged on every real
// /api/queue finding - distinct from raw CVSS severity, which severityChartBlockHtml
// already covers).
export function teamPriorityChartBlockHtml(findings, teamByAssetName) {
  const teams = teamByAssetName || new Map();
  // No href for "Unassigned"/"Unknown" buckets - there's no single real team/priority
  // value that would honestly represent "has none", so leave those bars non-clickable
  // rather than link to a filter that either matches nothing or silently means
  // something different from what was clicked.
  const teamData = countBy(findings, (f) => teams.get(f.asset && f.asset.name) || "Unassigned")
    .map((d) => (d.label === "Unassigned" ? d : { ...d, href: `/queue?team=${encodeURIComponent(d.label)}` }));
  const priorityData = countBy(findings, (f) => f.priority)
    .map((d) => (d.label === "Unknown" ? d : { ...d, href: `/queue?priority=${encodeURIComponent(d.label)}` }));
  return `
    <div class="chart-block">
      <h3>By team</h3>
      ${teamData.length ? barChartSvg(teamData) : `<p class="empty-state">No findings.</p>`}
    </div>
    <div class="chart-block">
      <h3>By priority</h3>
      ${priorityData.length ? barChartSvg(priorityData) : `<p class="empty-state">No findings.</p>`}
    </div>`;
}

export function buildTopRankings(findings, ownerByAssetName, teamByAssetName) {
  return {
    vulnGroups: groupVulnerabilitiesByType(findings, ownerByAssetName, teamByAssetName).slice(0, 5),
    assetGroups: groupFindingsByAsset(findings, ownerByAssetName, teamByAssetName).slice(0, 5),
  };
}

export function topRankingsHtml(idPrefix, { vulnGroups, assetGroups }) {
  return `
    <h3 style="margin-top:20px">Top 5 vulnerabilities by affected-asset count</h3>
    <p class="filter-count" style="margin:-4px 0 8px">
      See <a href="/vulnerability-mapping" data-link>the full Vulnerability Mapping dashboard →</a>
      (top 25, clickable, with owner/team filters).
    </p>
    ${exportButtonsHtml(`${idPrefix}-vulns`)}
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Vulnerability</th><th>CVE</th><th>Severity</th><th>Affected Assets</th><th>Owner(s)</th></tr></thead>
        <tbody>${vulnGroups.map(vulnRowHtml).join("")}</tbody>
      </table>
    </div>
    ${!vulnGroups.length ? `<p class="empty-state">No findings in this view.</p>` : ""}

    <h3 style="margin-top:20px">Top 5 assets by distinct-vulnerability count</h3>
    <p class="filter-count" style="margin:-4px 0 8px">
      See <a href="/asset-mapping" data-link>the full Asset Mapping dashboard →</a>
      (top 25, clickable, EOL/EOS status included).
    </p>
    ${exportButtonsHtml(`${idPrefix}-assets`)}
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Asset</th><th>Type</th><th>Distinct Vulnerabilities</th><th>Critical</th><th>Owner</th></tr></thead>
        <tbody>${assetGroups.map(assetRowHtml).join("")}</tbody>
      </table>
    </div>
    ${!assetGroups.length ? `<p class="empty-state">No findings in this view.</p>` : ""}`;
}

const PRIORITY_TIERS = ["Critical", "High", "Medium", "Low"];

function tierCell(count, tier) {
  if (!count) return `<span class="muted">0</span>`;
  return `<span class="badge badge-${tier.toLowerCase()}">${count}</span>`;
}

// A KPI tile showing the domain-wide total, plus a Critical/High/Medium/Low breakdown
// table per sub-category (each sub-category's own findings array in, its own tally
// out) - "how many, and how bad" at a glance instead of only a flat count per card.
// `subgroups`: [{ label, findings, href? }] - findings must already carry a real
// `severity` field (Critical/High/Medium/Low); callers with a differently-cased
// source (e.g. SAST's capitalized f.Severity) normalize before calling this.
export function totalVulnerabilitiesKpiHtml(subgroups) {
  const total = subgroups.reduce((sum, s) => sum + s.findings.length, 0);
  return `<div class="kpi-card"><div class="kpi-value">${total}</div><div class="kpi-label">Total vulnerabilities</div></div>`;
}

export function severityBreakdownTableHtml(subgroups) {
  const rows = subgroups.map((s) => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    for (const f of s.findings) {
      if (Object.prototype.hasOwnProperty.call(counts, f.severity)) counts[f.severity] += 1;
    }
    return { label: s.label, href: s.href, counts, total: s.findings.length };
  });
  const grandTotal = rows.reduce((sum, r) => sum + r.total, 0);
  const grandTierTotal = (tier) => rows.reduce((sum, r) => sum + r.counts[tier], 0);

  return `
    <h3 style="margin-top:20px">Priority breakdown by sub-category</h3>
    <p class="filter-count" style="margin:-4px 0 8px">
      Critical/High/Medium/Low split for each sub-category shown above.
    </p>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Sub-category</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr></thead>
        <tbody>
          ${rows.map((r) => `
            <tr>
              <td>${r.href ? `<a href="${r.href}" data-link>${escapeHtml(r.label)}</a>` : escapeHtml(r.label)}</td>
              ${PRIORITY_TIERS.map((tier) => `<td>${tierCell(r.counts[tier], tier)}</td>`).join("")}
              <td><strong>${r.total}</strong></td>
            </tr>`).join("")}
        </tbody>
        <tfoot>
          <tr style="font-weight:600">
            <td>All sub-categories</td>
            ${PRIORITY_TIERS.map((tier) => `<td>${tierCell(grandTierTotal(tier), tier)}</td>`).join("")}
            <td>${grandTotal}</td>
          </tr>
        </tfoot>
      </table>
    </div>`;
}

const AGE_BUCKETS = ["0-30", "31-60", "61-90", "90+"];
const AGE_BUCKET_LABELS = { "0-30": "0-30 days", "31-60": "31-60 days", "61-90": "61-90 days", "90+": "90+ days" };
// Reuses the same red-is-worse badge palette as severity/priority (badge-critical etc.)
// - the longer a finding has sat open, the more urgent it reads, same visual language.
const AGE_BUCKET_BADGE_TIER = { "0-30": "low", "31-60": "medium", "61-90": "high", "90+": "critical" };

function ageBucketFor(firstSeen, today) {
  if (!firstSeen) return null;
  const seen = new Date(firstSeen);
  if (Number.isNaN(seen.getTime())) return null;
  const days = Math.floor((today - seen) / 86400000);
  if (days < 0) return null;
  if (days <= 30) return "0-30";
  if (days <= 60) return "31-60";
  if (days <= 90) return "61-90";
  return "90+";
}

// Explains what agingChartBlockHtml/agingByPriorityTableHtml/agingBreakdownTableHtml
// below actually show, since "30/60/90-day remediation analytics" was the literal ask
// but this pipeline has no remediation-completion timestamp (no `remediated_at`/
// `closed_at` field anywhere in the schema) and no historical re-scan-diffing - there is
// no real event to measure "remediated within N days" from. Bucketing currently-open
// findings by how long they've sat open (real `first_seen`) is the honest, adjacent
// substitute: it answers "how stale is today's backlog," not "how fast do we fix
// things" - same zero-fabrication convention as the existing "Findings by month first
// seen" chart and the KEV-by-asset-type chart's own disclaimers.
export function agingDisclaimerHtml() {
  return `
    <div class="callout callout-warn" style="margin:8px 0">
      Not "vulnerabilities remediated within 30/60/90 days" - this pipeline has no
      remediation-completion timestamp and no historical re-scan-diffing, so that metric
      can't be honestly computed from this data (see the FAQ). This instead buckets
      CURRENTLY OPEN findings by how long they've been open (real first-seen date) - a
      genuine backlog-aging signal, not a disguised remediation-speed metric.
    </div>`;
}

// Same zero-fabrication reasoning as agingDisclaimerHtml above, for the OTHER real
// event this pipeline does have a genuine timestamp for: a finding's Remediation
// Approval being marked "remediation_triggered" (see remediation/remediation_approvals/
// store.py's mark_remediation_triggered() - a human clicked Trigger Remediation and
// this app generated the real playbook artifact). That is NOT the same fact as
// "remediated" - this app never executes a playbook against real infrastructure, so
// there is still no real completion/resolved timestamp anywhere. Honestly starts at
// zero on a fresh install and grows only as real Trigger Remediation clicks happen.
export function remediationTriggeredDisclaimerHtml() {
  return `
    <div class="callout callout-warn" style="margin:8px 0">
      Not "vulnerabilities remediated within 30/60/90 days" - "triggered" means a human
      clicked Trigger Remediation and this app generated the real playbook artifact, NOT
      that the fix was actually applied to real infrastructure (this app never executes
      playbooks itself - see the FAQ). This buckets real remediation-trigger events by
      how long ago they happened - a genuine "how much has been handed off, and when"
      signal. Starts empty on a fresh install and grows only as real approvals are
      triggered - never backfilled with fabricated history.
    </div>`;
}

// Chart-block fragment (same .chart-row convention as severityChartBlockHtml). Buckets
// by each item's own `first_seen` date - `heading`/`emptyLabel` let a caller reuse this
// for a differently-dated event too (see remediationTriggeredAgingSectionHtml below),
// as long as it's reshaped into the same {first_seen, priority} pseudo-finding shape.
export function agingChartBlockHtml(findings, heading = "Open-finding age", emptyLabel = "No findings.") {
  const today = new Date();
  const counts = { "0-30": 0, "31-60": 0, "61-90": 0, "90+": 0 };
  for (const f of findings) {
    const bucket = ageBucketFor(f.first_seen, today);
    if (bucket) counts[bucket] += 1;
  }
  const data = AGE_BUCKETS.map((b) => ({ label: AGE_BUCKET_LABELS[b], value: counts[b] }));
  return `
    <div class="chart-block">
      <h3>${escapeHtml(heading)}</h3>
      ${data.some((d) => d.value > 0) ? barChartSvg(data) : `<p class="empty-state">${escapeHtml(emptyLabel)}</p>`}
    </div>`;
}

// Priority x age-bucket cross-tab - the "priority-based" cut of the aging analytics.
export function agingByPriorityTableHtml(findings) {
  const today = new Date();
  const rows = PRIORITY_TIERS.map((tier) => {
    const counts = { "0-30": 0, "31-60": 0, "61-90": 0, "90+": 0 };
    for (const f of findings) {
      if (f.priority !== tier) continue;
      const bucket = ageBucketFor(f.first_seen, today);
      if (bucket) counts[bucket] += 1;
    }
    return { tier, counts, total: AGE_BUCKETS.reduce((sum, b) => sum + counts[b], 0) };
  });
  return `
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Priority</th>${AGE_BUCKETS.map((b) => `<th>${AGE_BUCKET_LABELS[b]}</th>`).join("")}<th>Total</th></tr></thead>
        <tbody>
          ${rows.map((r) => `
            <tr>
              <td><span class="badge badge-${r.tier.toLowerCase()}">${r.tier}</span></td>
              ${AGE_BUCKETS.map((b) => `<td>${r.counts[b] ? `<span class="badge badge-${AGE_BUCKET_BADGE_TIER[b]}">${r.counts[b]}</span>` : `<span class="muted">0</span>`}</td>`).join("")}
              <td><strong>${r.total}</strong></td>
            </tr>`).join("")}
        </tbody>
      </table>
    </div>`;
}

// Sub-domain-wise cut - same {label, findings, href?} subgroups shape as
// severityBreakdownTableHtml, so callers building that table already have what this one
// needs.
export function agingBreakdownTableHtml(subgroups) {
  const today = new Date();
  const rows = subgroups.map((s) => {
    const counts = { "0-30": 0, "31-60": 0, "61-90": 0, "90+": 0 };
    let undated = 0;
    for (const f of s.findings) {
      const bucket = ageBucketFor(f.first_seen, today);
      if (bucket) counts[bucket] += 1; else undated += 1;
    }
    return { label: s.label, href: s.href, counts, total: s.findings.length, undated };
  });
  const grandTotal = rows.reduce((sum, r) => sum + r.total, 0);
  const grandBucketTotal = (b) => rows.reduce((sum, r) => sum + r.counts[b], 0);
  const grandUndated = rows.reduce((sum, r) => sum + r.undated, 0);

  return `
    <h3 style="margin-top:20px">Open-finding age by sub-category</h3>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Sub-category</th>${AGE_BUCKETS.map((b) => `<th>${AGE_BUCKET_LABELS[b]}</th>`).join("")}<th>Total</th></tr></thead>
        <tbody>
          ${rows.map((r) => `
            <tr>
              <td>${r.href ? `<a href="${r.href}" data-link>${escapeHtml(r.label)}</a>` : escapeHtml(r.label)}</td>
              ${AGE_BUCKETS.map((b) => `<td>${r.counts[b] ? `<span class="badge badge-${AGE_BUCKET_BADGE_TIER[b]}">${r.counts[b]}</span>` : `<span class="muted">0</span>`}</td>`).join("")}
              <td><strong>${r.total}</strong></td>
            </tr>`).join("")}
        </tbody>
        <tfoot>
          <tr style="font-weight:600">
            <td>All sub-categories</td>
            ${AGE_BUCKETS.map((b) => `<td>${grandBucketTotal(b) ? `<span class="badge badge-${AGE_BUCKET_BADGE_TIER[b]}">${grandBucketTotal(b)}</span>` : `<span class="muted">0</span>`}</td>`).join("")}
            <td>${grandTotal}</td>
          </tr>
        </tfoot>
      </table>
    </div>
    ${grandUndated ? `<p class="filter-count" style="margin:8px 0 -4px">${grandUndated} finding(s) have no first-seen date recorded and are excluded from the buckets above.</p>` : ""}`;
}

export function wireTopRankings(container, idPrefix, { vulnGroups, assetGroups }) {
  wireExportButtons(container, `${idPrefix}-vulns`, {
    getRows: () => vulnGroups,
    columns: VULN_COLUMNS,
    filenameBase: `vulnhunter-${idPrefix}-top-vulnerabilities`,
  });
  wireExportButtons(container, `${idPrefix}-assets`, {
    getRows: () => assetGroups,
    columns: ASSET_COLUMNS,
    filenameBase: `vulnhunter-${idPrefix}-top-assets`,
  });
}
