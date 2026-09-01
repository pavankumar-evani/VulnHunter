import { api } from "../api.js";
import { escapeHtml, timeAgo, kpiLink } from "../dom.js";
import { barChartSvg, pieChartSvg, countBy, wireChartLinks } from "../charts.js";
import { INFRA_CATEGORIES, INFRA_CATEGORY_LABELS } from "../infraTypes.js";
import { buildOwnerTeamMaps } from "../assetLookup.js";
import {
  buildTopRankings, topRankingsHtml, wireTopRankings, teamPriorityChartBlockHtml,
  agingChartBlockHtml, agingByPriorityTableHtml, agingBreakdownTableHtml, agingDisclaimerHtml,
  remediationTriggeredDisclaimerHtml,
} from "../domainSummary.js";
import { aiTrendAnalysisFabHtml, wireAiTrendAnalysis } from "../aiTrendAnalysis.js";
import { setInsightsContent, insightSectionHtml, insightAlertHtml } from "../insightsPanel.js";

export const title = "Security Posture Overview";

const REFRESH_MS = 20000;

function kpi(value, label, cls = "") {
  return `<div class="kpi-card ${cls}"><div class="kpi-value">${value}</div><div class="kpi-label">${label}</div></div>`;
}

const PRIORITY_ORDER = ["Critical", "High", "Medium", "Low"];

function definitionsPanel(rules) {
  const slaRows = PRIORITY_ORDER.map((tier) => `
    <tr>
      <td><span class="badge badge-${tier.toLowerCase()}">${tier}</span></td>
      <td>${rules.sla_days[tier]} day(s)</td>
      <td>Weighted score ≥ ${rules.priority_thresholds[tier]}</td>
    </tr>`).join("");

  return `
    <details class="faq-item" id="definitions-panel">
      <summary>What do "Priority" and "SLA" mean here? (definitions)</summary>
      <p>Priority is a weighted score (severity + asset criticality + asset type),
      mapped to a tier by the thresholds below - live-configurable on the
      <a href="/priority-rules" data-link>Priority Rules</a> page, not hardcoded.</p>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>Priority tier</th><th>SLA window</th><th>How a finding reaches this tier</th></tr></thead>
          <tbody>${slaRows}</tbody>
        </table>
      </div>
      <p class="filter-count" style="margin-top:10px">
        Two overrides can escalate a finding past its weighted score alone:
        ${rules.kev_override.enabled ? `a <strong>CISA KEV-listed</strong> finding is forced straight to
        <strong>${escapeHtml(rules.kev_override.forces_priority)}</strong>` : "the KEV override is currently disabled"};
        ${rules.epss_escalation.enabled ? `an <strong>EPSS score ≥ ${rules.epss_escalation.threshold}</strong>
        forces at least <strong>${escapeHtml(rules.epss_escalation.forces_priority_at_least)}</strong>` : "the EPSS escalation is currently disabled"}.
      </p>
    </details>`;
}

// Same "live-configured, not hardcoded" pattern as definitionsPanel above, just for the
// two asset-level concepts (facing, criticality) that feed both Priority AND the new
// Risk/Impact scoring, and that the risk-scoring KPIs/charts below now reference.
function assetDefinitionsPanel(rules) {
  const keywordRows = Object.entries(rules.asset_criticality_keywords || {})
    .filter(([keyword]) => keyword !== "default")
    .map(([keyword, points]) => `<tr><td><code>${escapeHtml(keyword)}</code></td><td>+${points}</td></tr>`).join("");
  const typeRows = Object.entries(rules.asset_type_weights || {})
    .map(([assetType, points]) => `<tr><td>${escapeHtml(assetType)}</td><td>+${points}</td></tr>`).join("");

  return `
    <details class="faq-item">
      <summary>What do "Internal/External-facing" and "business-critical" mean here? (definitions)</summary>
      <p>
        <strong>Facing</strong> (Internal-only / External-facing / Unclassified) is a
        manually-set classification per asset, editable on the
        <a href="/risk" data-link>Risk Dashboard</a> - never auto-detected from a network
        scan (this app has no network-topology data to infer it from).
      </p>
      <p>
        <strong>Asset criticality</strong> ("business-critical") comes from two real,
        live-configured signals in <code>remediation/config/priority_rules.yaml</code>
        that feed both a finding's Priority score and its asset's Impact score - an asset
        whose name matches a keyword below, or whose type carries a weight, is treated as
        more critical regardless of severity:
      </p>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>Asset-name keyword</th><th>Points</th></tr></thead>
          <tbody>${keywordRows}</tbody>
        </table>
      </div>
      <div class="table-scroll" style="margin-top:10px">
        <table class="data-table">
          <thead><tr><th>Asset type</th><th>Points</th></tr></thead>
          <tbody>${typeRows}</tbody>
        </table>
      </div>
      <p class="filter-count" style="margin-top:10px">
        Editable on the <a href="/priority-rules" data-link>Priority Rules</a> page - e.g.
        a hostname containing "dc" or "auth" scores as more critical than one with no
        keyword match.
      </p>
    </details>`;
}

// One KPI tile per real Security Domain, all landscape-wide (not per-tenant) - the
// first time these 4 domain totals are shown together in one place, rather than only
// on each domain's own hub page. AppSec's own total is the de-duplicated figure
// (SAST + DAST + SCA + Repo Secret Scanning) appsec.js already computes for its own KPI
// - Secrets Management/Container/API are CWE-based sub-classifications of the same SAST
// findings, not separate ones, so summing all of appsec.js's cards would double-count.
// Each tile is clickable, opening that domain's own dashboard.
// Average whole days between two ISO date fields, across only the records that
// actually have BOTH dates set - never guesses a duration for a record still
// mid-workflow (e.g. approved but not yet triggered has no triggered_at). Returns
// null (never 0, which would misreport "no data" as "instant") when no record has
// both dates.
function daysBetweenAll(records, startField, endField) {
  const durations = records
    .filter((r) => r[startField] && r[endField])
    .map((r) => (new Date(r[endField]) - new Date(r[startField])) / 86400000);
  if (!durations.length) return null;
  return Math.round((durations.reduce((sum, d) => sum + d, 0) / durations.length) * 10) / 10;
}

// Real, dated remediation-lifecycle stages - Detected -> Entered remediation workflow
// -> Approved -> Remediated - each a real query over real data (the live queue and
// remediation/remediation_approvals/store.py's own records), not simulated. There is
// no "closed"/"remediated" concept in this app outside the approval workflow, so a
// finding fixed some other way (e.g. a manual change with no approval request) is
// honestly invisible to this funnel rather than silently guessed at - same
// disclosed-scope honesty as every other stat on this page.
const LIFECYCLE_STAGE_ICONS = ["🔍", "📋", "✅", "🚀"];
const LIFECYCLE_STAGE_COLORS = ["var(--chart-1)", "var(--chart-2)", "var(--chart-3)", "var(--chart-6)"];

function lifecycleStageHtml(stage, index, firstValue) {
  const pct = firstValue > 0 ? Math.round((stage.value / firstValue) * 100) : 0;
  const pctNote = index > 0 ? `<div class="lifecycle-stage-pct">${pct}% of Detected</div>` : `<div class="lifecycle-stage-pct"></div>`;
  const color = LIFECYCLE_STAGE_COLORS[index % LIFECYCLE_STAGE_COLORS.length];
  const barPct = index === 0 ? 100 : pct;
  return `
    <a class="lifecycle-stage" href="${escapeHtml(stage.href)}" data-link data-tooltip="${escapeHtml(stage.detail)}">
      <div class="lifecycle-stage-icon">${LIFECYCLE_STAGE_ICONS[index % LIFECYCLE_STAGE_ICONS.length]}</div>
      <div class="lifecycle-stage-value">${stage.value.toLocaleString()}</div>
      ${pctNote}
      <div class="lifecycle-stage-label">${escapeHtml(stage.label)}</div>
      <div class="lifecycle-stage-bar-track"><div class="lifecycle-stage-bar-fill" style="width:${barPct}%;background:${color}"></div></div>
    </a>`;
}

// Real, dated remediation-lifecycle stages - Detected -> Remediation Initiated ->
// Approved -> Remediation Triggered - each a real query over real data (the live
// queue and remediation/remediation_approvals/store.py's own records), not simulated.
// Stage names/order are informed by NIST CSF's Detect/Respond functions and NIST SP
// 800-40's patch-management lifecycle - not a certified mapping (this app makes no
// compliance claim, same disclosure pattern as Risk Score's "NIST SP 800-30-inspired,
// not a certified assessment"), just the recognizable industry framing instead of an
// app-specific ad-hoc one. "Remediation Triggered" (not "Remediated") is deliberate -
// this app never executes playbooks itself, so a real playbook being generated and
// dispatched is the honest ceiling of what's tracked, not independent confirmation the
// fix was actually applied (see the FAQ). There is no "closed"/"remediated" concept in
// this app outside the approval workflow, so a finding fixed some other way (e.g. a
// manual change with no approval record) is honestly invisible to this pipeline rather
// than silently guessed at - same disclosed-scope honesty as every other stat on this
// page. Rendered as stage cards + arrows rather than a proportional-width funnel: a
// funnel's bars would give a fresh install's real, honest zeros (nothing approved yet)
// a 2px sliver next to invisible - correct, but reads as broken rather than "a real
// pipeline with nothing in it yet" - the number is the primary signal here, the bar
// underneath just a secondary accent.
function lifecycleSection(queue, remediationApprovals) {
  const stages = [
    { label: "Detected", value: queue.findings.length, href: "/queue",
      detail: "Every finding currently in the live remediation queue" },
    { label: "Remediation Initiated", value: remediationApprovals.length, href: "/remediation-approvals",
      detail: "Has a real remediation-approval request (any status)" },
    { label: "Approved", value: remediationApprovals.filter((a) => a.computed_status === "approved" || a.computed_status === "remediation_triggered").length,
      href: "/remediation-approvals", detail: "Approval request approved (or already remediated)" },
    { label: "Remediation Triggered", value: remediationApprovals.filter((a) => a.computed_status === "remediation_triggered").length,
      href: "/remediation-approvals", detail: "Real playbook generated and dispatched - not independent confirmation the fix was applied" },
  ];
  const firstValue = stages[0].value;
  const approvalDays = daysBetweenAll(remediationApprovals, "created_on", "approved_at");
  const remediationDays = daysBetweenAll(remediationApprovals, "approved_at", "triggered_at");

  return `
    <h2>Vulnerability Lifecycle: Detection → Remediation</h2>
    <p class="subtitle">
      Real counts at each real stage of the remediation-approval workflow - stage
      naming informed by NIST CSF's Detect/Respond functions and NIST SP 800-40's
      patch-management lifecycle (not a certified mapping). A finding fixed outside
      this workflow (e.g. a manual change with no approval record on
      <a href="/remediation-approvals" data-link>Remediation Approvals</a>) isn't
      reflected here, same disclosed-scope honesty as everywhere else on this page.
      Click any stage to jump to it.
    </p>
    <div class="lifecycle-pipeline">
      ${stages.map((s, i) => `${i > 0 ? `<div class="lifecycle-arrow">→</div>` : ""}${lifecycleStageHtml(s, i, firstValue)}`).join("")}
    </div>
    <div class="lifecycle-stats">
      <div class="kpi-card">
        <div class="kpi-value">${approvalDays === null ? "—" : `${approvalDays}d`}</div>
        <div class="kpi-label">Avg. time to approve${approvalDays === null ? " (no completed approvals yet)" : ""}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-value">${remediationDays === null ? "—" : `${remediationDays}d`}</div>
        <div class="kpi-label">Avg. time approved → triggered${remediationDays === null ? " (none triggered yet)" : ""}</div>
      </div>
    </div>`;
}

function domainTotalsSection(queue, vh) {
  const infraTotal = queue.findings.filter((f) => f.scan_type === "infra-vm").length;
  const sastTotal = vh.available ? vh.findings.length : 0;
  const dastTotal = queue.findings.filter((f) => f.scan_type === "dast").length;
  const scaTotal = queue.findings.filter((f) => f.scan_type === "sca").length;
  const repoSecretsTotal = queue.findings.filter((f) => f.scan_type === "secrets").length;
  const appsecTotal = sastTotal + dastTotal + scaTotal + repoSecretsTotal;
  const aiMlTotal = queue.findings.filter((f) => f.scan_type === "ai-ml").length;
  const certTotal = queue.findings.filter((f) => f.scan_type === "cert-mgmt").length;

  return `
    <h2 style="margin-top:28px">Security domain totals</h2>
    <p class="filter-count" style="margin:-4px 0 8px">Click a tile to open that domain's own dashboard.</p>
    <div class="kpi-grid">
      ${kpiLink("/infrastructure", infraTotal, "Infrastructure Vulnerabilities")}
      ${kpiLink("/appsec", appsecTotal, "Application Vulnerabilities (SAST+DAST+SCA+Repo Secrets)")}
      ${kpiLink("/ai-vulnerabilities", aiMlTotal, "AI/ML Vulnerabilities")}
      ${kpiLink("/certificate-vulnerabilities", certTotal, "Certificate Vulnerabilities")}
    </div>`;
}

// Real, NIST SP 800-30-inspired per-asset risk scores (remediation/enrichment/
// risk_scoring.py) - see Asset Inventory's own callout for the full honesty caveat.
// Not a separate data source: the same /api/assets response Asset Inventory/Asset
// Mapping/Risk Dashboard already show, just surfaced landscape-wide here too.
// `riskRules` is the live remediation/config/risk_scoring_rules.yaml content (see
// /api/overview's own risk_scoring_rules field) - the methodology panel below quotes
// its actual configured weights, not a hardcoded copy that could drift out of sync.
// Fleet-wide Aggregate Exposure Score - a single, disclosed 0-100 rollup of three real
// signals (average per-asset Risk Score, CISA KEV prevalence, average FIRST.org EPSS)
// computed server-side in remediation/enrichment/exposure_score.py. Deliberately NOT
// claimed as equivalent to Tenable's Cyber Exposure Score (proprietary, unpublished) or
// any other named/certified score - see that module's docstring for the full
// disclosure, repeated in the panel below so it's visible right where the number is.
const EXPOSURE_BAND_CLASS = { Critical: "kpi-danger", High: "kpi-warn", Medium: "kpi-warn", Low: "kpi-good" };

function exposureScoreSectionHtml(exposure, rules) {
  const bandClass = EXPOSURE_BAND_CLASS[exposure.band] || "";
  const weights = (rules && rules.component_weights) || {};
  const pct = (w) => Math.round((w || 0) * 100);
  return `
    <div class="kpi-grid">
      <a class="kpi-card kpi-card-link ${bandClass}" href="/risk" data-link>
        <div class="kpi-value">${exposure.score}</div>
        <div class="kpi-label">Aggregate Exposure Score (${escapeHtml(exposure.band)}) — fleet-wide, 0-100</div>
      </a>
    </div>

    <details class="faq-item">
      <summary>How is the Aggregate Exposure Score calculated? (live criteria, and what it's NOT)</summary>
      <p>An <strong>original, disclosed rollup</strong> of three signals this app already
      computes elsewhere - <strong>not</strong> a reproduction of Tenable's Cyber Exposure
      Score (proprietary, unpublished formula) or any other named/certified scoring product.
      There is no public "industry-standard" aggregate exposure score to reproduce.</p>
      <p>Score = ${pct(weights.avg_risk_score)}% average per-asset Risk Score (see
      Risk Scoring below) + ${pct(weights.kev_prevalence)}% of all findings that are CISA
      KEV-listed + ${pct(weights.avg_epss)}% average FIRST.org EPSS score across findings
      that have one.</p>
      <p>Right now: average Risk Score <strong>${exposure.components.avg_risk_score}</strong>,
      <strong>${exposure.kev_count}</strong> of ${exposure.total_findings} findings KEV-listed
      (${exposure.components.kev_prevalence}%), average EPSS
      <strong>${exposure.components.avg_epss}%</strong>, across ${exposure.total_assets}
      scored assets.</p>
      <p class="filter-count" style="margin-top:8px">
        Live-configured in <code>remediation/config/exposure_score_rules.yaml</code>. See
        <code>remediation/enrichment/exposure_score.py</code>'s module docstring for the
        full disclosure - inspired by OWASP's Risk Rating Methodology's Likelihood ×
        Impact shape and FIRST.org's own EPSS FAQ (which endorses aggregating EPSS scores
        across a portfolio but publishes no single fixed formula for it), not a certified
        or industry-standard score.
      </p>
    </details>`;
}

function riskScoringSection(assets, riskRules) {
  const tierCounts = countBy(assets, (a) => a.risk_tier).filter((d) => d.label);
  const criticalOrHigh = assets.filter((a) => a.risk_tier === "Critical" || a.risk_tier === "High").length;
  const unowned = assets.filter((a) => !a.owner).length;
  const topRisk = [...assets].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0)).slice(0, 5);
  const scoredAssets = assets.filter((a) => typeof a.impact_score === "number");
  const avgImpact = scoredAssets.length
    ? Math.round(scoredAssets.reduce((sum, a) => sum + a.impact_score, 0) / scoredAssets.length)
    : null;

  // Per-tier asset-type breakdown (top 3 types by count) feeds the risk-tier bar
  // chart's hover detail via the shared tooltip.js listener - real composition, not
  // just a bare count - and each bar links to Asset Inventory pre-filtered to that tier.
  const tierChartData = tierCounts.map((d) => {
    const inTier = assets.filter((a) => a.risk_tier === d.label);
    const topTypes = countBy(inTier, (a) => a.type).slice(0, 3).map((t) => `${t.label} (${t.value})`).join(", ");
    return {
      ...d,
      detail: topTypes ? `top asset types: ${topTypes}` : undefined,
      href: `/assets?risk_tier=${encodeURIComponent(d.label)}`,
    };
  });

  const impactWeights = (riskRules && riskRules.impact_weights) || {};
  const likelihoodWeights = (riskRules && riskRules.likelihood_weights) || {};
  const tierThresholds = (riskRules && riskRules.risk_tier_thresholds) || {};
  const pct = (w) => Math.round((w || 0) * 100);

  return `
    <h2 style="margin-top:28px">Risk scoring</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      NIST SP 800-30-inspired Impact × Likelihood risk score per asset - an illustrative,
      disclosed simplification, not a certified RMF/800-30 assessment. See
      <a href="/assets" data-link>Asset Inventory</a> for the full breakdown and
      methodology note.
    </p>

    <details class="faq-item">
      <summary>What is Risk Score actually calculated from? (live criteria)</summary>
      <p><strong>Impact</strong> (0-100) = ${pct(impactWeights.severity)}% worst CVSS/severity
      found on the asset + ${pct(impactWeights.criticality)}% asset criticality (name-keyword
      + asset-type weight - see the facing/criticality definitions below).</p>
      <p><strong>Likelihood</strong> (0-100) = ${pct(likelihoodWeights.kev)}% CISA KEV listing
      + ${pct(likelihoodWeights.epss)}% worst FIRST.org EPSS score among its findings
      + ${pct(likelihoodWeights.exploit_criteria)}% count of exploit-criteria rule matches
      + ${pct(likelihoodWeights.eol)}% EOL/EOS status.</p>
      <p><strong>Risk</strong> = round(Impact × Likelihood / 100), mapped to a tier:
      Critical ≥ ${tierThresholds.Critical ?? "—"}, High ≥ ${tierThresholds.High ?? "—"},
      Medium ≥ ${tierThresholds.Medium ?? "—"}, else Low.</p>
      <p class="filter-count" style="margin-top:8px">
        Live-configured in <code>remediation/config/risk_scoring_rules.yaml</code> - an
        admin who retunes these weights sees this panel, and every Risk Score in this
        app, update immediately. See <code>remediation/enrichment/risk_scoring.py</code>'s
        module docstring for the full honesty caveat on what this is (and isn't).
      </p>
    </details>

    <div class="kpi-grid">
      <a class="kpi-card kpi-card-link ${criticalOrHigh ? "kpi-danger" : "kpi-good"}" href="/assets?risk_tier=Critical,High" data-link>
        <div class="kpi-value">${criticalOrHigh}</div><div class="kpi-label">Assets at Critical/High risk</div>
      </a>
      <a class="kpi-card kpi-card-link ${unowned ? "kpi-warn" : "kpi-good"}" href="/assets?owner=unassigned" data-link>
        <div class="kpi-value">${unowned}</div><div class="kpi-label">Assets with no owner assigned</div>
      </a>
      <div class="kpi-card"><div class="kpi-value">${avgImpact === null ? "—" : avgImpact}</div><div class="kpi-label">Average Impact Score (0-100)</div></div>
    </div>

    <div class="chart-row">
      <div class="chart-block" style="max-width:380px">
        <h3>Assets by risk tier</h3>
        <p class="filter-count" style="margin:-4px 0 8px">Hover a bar for its top asset types; click to see those assets in Asset Inventory.</p>
        ${tierChartData.length ? barChartSvg(tierChartData, { width: 340 }) : `<p class="empty-state">No scored assets yet.</p>`}
      </div>
      <div class="chart-block">
        <h3>Top 5 highest-risk assets</h3>
        <div class="table-scroll">
          <table class="data-table">
            <thead><tr><th>Asset</th><th>Type</th><th>Risk Score</th><th>Tier</th></tr></thead>
            <tbody>
              ${topRisk.map((a) => `
                <tr>
                  <td><a href="/queue?asset=${encodeURIComponent(a.name)}" data-link>${escapeHtml(a.name)}</a></td>
                  <td class="asset-type-cell">${escapeHtml(a.type || "")}</td>
                  <td><span class="badge badge-${(a.risk_tier || "").toLowerCase()}" data-tooltip="Impact ${a.impact_score} × Likelihood ${a.likelihood_score} (NIST SP 800-30-inspired, not a certified assessment)">${a.risk_score}</span></td>
                  <td><span class="badge badge-${(a.risk_tier || "").toLowerCase()}">${escapeHtml(a.risk_tier || "")}</span></td>
                </tr>`).join("")}
            </tbody>
          </table>
        </div>
      </div>
    </div>`;
}

// "Findings by methodology" broken out per real Security Domain (Infrastructure /
// Application / Certificate / AI-ML) instead of one combined pie lumping all 9
// scan_type values together - each domain gets whatever real sub-breakdown actually
// exists for it: Infrastructure has 8 real infra_category sub-methodologies to chart;
// Application has its 4 real methodologies (SAST/DAST/SCA/Repo Secrets, the same
// de-duplicated set domainTotalsSection's own KPI already uses); Certificate and AI/ML
// are each already a SINGLE methodology in this taxonomy - charting a "breakdown" of one
// slice would be decorative, not real, so they get a plain total tile linking to their
// own dashboard (which has its own real breakdown - infra_category-level here reuses
// the same idea, per-severity for AI's ATLAS categories) instead.
function methodologySection(findings, vh) {
  const infraFindings = findings.filter((f) => f.scan_type === "infra-vm");
  const infraCategoryData = INFRA_CATEGORIES.map((cat) => {
    const inCat = infraFindings.filter((f) => f.infra_category === cat);
    if (!inCat.length) return null;
    const topSeverity = countBy(inCat, (f) => f.severity)[0];
    return {
      label: INFRA_CATEGORY_LABELS[cat] || cat,
      value: inCat.length,
      detail: topSeverity ? `most common severity: ${topSeverity.label} (${topSeverity.value})` : undefined,
      href: `/queue?category=infra-vm&infraType=${encodeURIComponent(cat)}`,
    };
  }).filter(Boolean);

  const sastTotal = vh.available ? vh.findings.length : 0;
  const dastTotal = findings.filter((f) => f.scan_type === "dast").length;
  const scaTotal = findings.filter((f) => f.scan_type === "sca").length;
  const secretsTotal = findings.filter((f) => f.scan_type === "secrets").length;
  const appMethodologyData = [
    { label: "SAST (Code Scan)", value: sastTotal, href: "/vulnhunt" },
    { label: "DAST", value: dastTotal, href: "/queue?category=dast" },
    { label: "SCA", value: scaTotal, href: "/queue?category=sca" },
    { label: "Repository Secret Scanning", value: secretsTotal, href: "/queue?category=secrets" },
  ].filter((d) => d.value > 0);

  const certTotal = findings.filter((f) => f.scan_type === "cert-mgmt").length;
  const aiTotal = findings.filter((f) => f.scan_type === "ai-ml").length;

  return `
    <h2 style="margin-top:28px">Findings by methodology</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      Broken out per domain rather than one combined chart - hover a slice for detail,
      click to open that filtered view.
    </p>
    <div class="chart-row">
      <div class="chart-block">
        <h3>Infrastructure, by sub-category</h3>
        ${infraCategoryData.length ? pieChartSvg(infraCategoryData) : `<p class="empty-state">No infrastructure findings.</p>`}
      </div>
      <div class="chart-block">
        <h3>Application, by methodology</h3>
        ${appMethodologyData.length ? pieChartSvg(appMethodologyData) : `<p class="empty-state">No application findings.</p>`}
      </div>
    </div>
    <div class="chart-row-grid">
      <a class="chart-block chart-block-link" href="/certificate-vulnerabilities" data-link>
        <h3>Certificate</h3>
        <div class="kpi-value">${certTotal}</div>
        <p class="filter-count">Single methodology in this taxonomy - no further breakdown to chart honestly. Click to view.</p>
      </a>
      <a class="chart-block chart-block-link" href="/ai-vulnerabilities" data-link>
        <h3>AI/ML</h3>
        <div class="kpi-value">${aiTotal}</div>
        <p class="filter-count">See its own dashboard for the real MITRE ATLAS category breakdown. Click to view.</p>
      </a>
    </div>`;
}

// Aggregated across the WHOLE landscape (Infrastructure + AppSec + SAST/Code Scan) -
// deliberately not per-domain like /infrastructure's or /appsec's own charts (appsec.js's
// own pie explicitly excludes Infra-VM/Cert-Mgmt; this one includes them, plus SAST).
function analyticsSection(data, queue, vh, teamByAssetName, triggeredPseudoFindings, remediationApprovals) {
  const findings = queue.findings;
  const { breached, at_risk, on_track } = data.sla;
  const totalKnown = breached + at_risk + on_track;
  const slaComplianceRate = totalKnown ? Math.round((on_track / totalKnown) * 100) : null;

  // MTTR (Mean Time To Remediate) - the industry-standard vulnerability-management
  // metric: real elapsed time from DETECTION (the finding's own first_seen) to
  // REMEDIATION being triggered, joined via each approval's finding_id back to the
  // actual finding - a genuinely more complete "detection to remediation" figure than
  // this page's own lifecycle-section sub-metrics (which only cover the narrower
  // approved->triggered leg). Scoped, honestly, to findings that completed the
  // remediation-approval workflow - see lifecycleSection's own disclosure for why a
  // fix applied outside that workflow can't be counted. Deliberately no MTTD (Mean
  // Time To Detect) KPI: that metric needs a real vulnerability-introduction or
  // public-disclosure timestamp to compare against detection time, and this app has
  // neither - a real answer here would have to be invented, which this app doesn't do.
  const findingById = new Map(findings.map((f) => [f.id, f]));
  const mttrRecords = remediationApprovals
    .filter((a) => a.triggered_at)
    .map((a) => ({ detected: findingById.get(a.finding_id)?.first_seen, triggered: a.triggered_at }))
    .filter((r) => r.detected);
  const mttrDays = daysBetweenAll(mttrRecords, "detected", "triggered");

  // SAST findings use capitalized f.Severity (parsed from a markdown table, a
  // genuinely different key-casing convention than /api/queue's lowercase f.severity)
  // - normalized here before merging into one combined severity count.
  const sastAsSeverity = vh.available ? vh.findings.map((f) => ({ severity: f.Severity })) : [];
  const severityData = countBy([...findings, ...sastAsSeverity], (f) => f.severity);

  // eol_status is asset-OS-derived, so every finding on a given asset shares the same
  // value - dedupe per distinct asset name rather than double-counting per finding, and
  // don't call /api/assets for this (that response doesn't carry the field).
  const eolByAsset = new Map();
  for (const f of findings) {
    const name = f.asset && f.asset.name;
    if (name && !eolByAsset.has(name) && f.eol_status) eolByAsset.set(name, f.eol_status.status);
  }
  const eolExposedCount = [...eolByAsset.values()].filter((s) => s === "eol" || s === "eol-soon").length;
  const eolData = countBy([...eolByAsset.values()], (s) => s);

  // No historical-snapshot storage exists in this app (only a live snapshot plus each
  // finding's own first_seen/last_seen) - this is the honest substitute for a "KEV
  // trend," not a disguised one.
  const kevData = countBy(findings.filter((f) => f.kev && f.kev.listed), (f) => f.asset && f.asset.type);

  // Same honest-substitute pattern as kevData above: buckets by each finding's own real
  // first_seen month, answering "when did today's findings originate" - NOT "what did
  // total counts look like on a past date" (that still needs snapshot storage this app
  // doesn't have). Split Infrastructure vs Application per the same real definitions
  // domainTotalsSection/methodologySection already use, rather than one combined chart.
  function bucketByMonth(subset) {
    const monthCounts = new Map();
    for (const f of subset) {
      if (!f.first_seen) continue;
      const month = f.first_seen.slice(0, 7);
      monthCounts.set(month, (monthCounts.get(month) || 0) + 1);
    }
    return [...monthCounts.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([label, value]) => ({ label, value }));
  }
  const infraByMonth = bucketByMonth(findings.filter((f) => !!f.infra_category));
  const appsecByMonth = bucketByMonth(findings.filter((f) => ["sca", "dast", "secrets"].includes(f.scan_type)));

  return `
    <h2 style="margin-top:28px">Landscape analytics</h2>
    <p class="subtitle">
      Aggregated across every domain (Infrastructure, AppSec, SAST/Code Scan) - broader
      than any single hub page's own charts.
    </p>

    <div class="kpi-grid">
      ${kpi(slaComplianceRate === null ? "—" : `${slaComplianceRate}%`, "SLA compliance rate",
        slaComplianceRate !== null && slaComplianceRate >= 80 ? "kpi-good" : "kpi-warn")}
      ${kpi(eolExposedCount, "Assets EOL or EOL-soon", eolExposedCount ? "kpi-danger" : "kpi-good")}
      ${kpi(mttrDays === null ? "—" : `${mttrDays}d`, `MTTR (Mean Time to Remediate)${mttrDays === null ? " - none triggered yet" : ""}`)}
    </div>
    <p class="filter-count" style="margin:-8px 0 12px">
      MTTR = detected → remediation triggered, for the ${mttrRecords.length} finding(s)
      that completed the remediation-approval workflow - see the lifecycle pipeline
      below for the approve/trigger breakdown. No MTTD (Mean Time to Detect) KPI is
      shown - that metric needs a real vulnerability-introduction or public-disclosure
      timestamp to compare against detection time, and this app honestly has neither.
    </p>

    <div class="chart-row">
      <div class="chart-block">
        <h3>Severity distribution, entire landscape</h3>
        ${barChartSvg(severityData, { width: 340 })}
      </div>
      <div class="chart-block">
        <h3>EOL/EOS exposure (by distinct asset)</h3>
        ${eolData.length ? barChartSvg(eolData, { width: 340 }) : `<p class="empty-state">No asset OS data to classify.</p>`}
      </div>
    </div>

    <div class="chart-row">
      ${teamPriorityChartBlockHtml(findings, teamByAssetName)}
    </div>
    <p class="filter-count" style="margin:-4px 0 12px">
      Team/priority breakdown covers /api/queue findings only (Infrastructure + AppSec) -
      SAST/Code Scan findings have no team association in this data path.
    </p>

    <h2 style="margin-top:28px">Open-finding age (30/60/90-day backlog aging)</h2>
    ${agingDisclaimerHtml()}
    <p class="filter-count" style="margin:-4px 0 8px">
      Covers /api/queue findings only (Infrastructure + AppSec + AI/ML + Certificate) -
      SAST/Code Scan findings have no first-seen date in this data path.
    </p>
    <div class="chart-row">
      ${agingChartBlockHtml(findings)}
    </div>
    <h3 style="margin-top:20px">By priority</h3>
    ${agingByPriorityTableHtml(findings)}
    ${agingBreakdownTableHtml([
      { label: "Infrastructure Vulnerability Management", findings: findings.filter((f) => f.scan_type === "infra-vm"), href: "/infrastructure" },
      { label: "Infrastructure-as-Code", findings: findings.filter((f) => f.scan_type === "iac"), href: "/queue?category=iac" },
      { label: "Container/Host Runtime Security", findings: findings.filter((f) => f.scan_type === "runtime"), href: "/queue?category=runtime" },
      { label: "DAST", findings: findings.filter((f) => f.scan_type === "dast"), href: "/queue?category=dast" },
      { label: "SCA", findings: findings.filter((f) => f.scan_type === "sca"), href: "/queue?category=sca" },
      { label: "Repo Secret Scanning", findings: findings.filter((f) => f.scan_type === "secrets"), href: "/queue?category=secrets" },
      { label: "AI/ML Vulnerabilities", findings: findings.filter((f) => f.scan_type === "ai-ml"), href: "/ai-vulnerabilities" },
      { label: "Certificate Vulnerabilities", findings: findings.filter((f) => f.scan_type === "cert-mgmt"), href: "/certificate-vulnerabilities" },
    ])}

    <h2 style="margin-top:28px">Remediation-triggered findings (age since trigger)</h2>
    ${remediationTriggeredDisclaimerHtml()}
    <div class="chart-row">
      ${agingChartBlockHtml(triggeredPseudoFindings, "Time since triggered", "No findings have been remediation-triggered yet - see Remediation Approvals.")}
    </div>
    <h3 style="margin-top:20px">By priority</h3>
    ${agingByPriorityTableHtml(triggeredPseudoFindings)}

    ${methodologySection(findings, vh)}

    <div class="chart-row">
      <div class="chart-block">
        <h3>KEV-listed findings by asset type</h3>
        <p class="filter-count" style="margin:-4px 0 8px">
          No historical-snapshot storage exists in this app, so this is a live count, not
          a trend line - a real trend would need new backend work to store daily snapshots.
        </p>
        ${kevData.length ? barChartSvg(kevData) : `<p class="empty-state">No KEV-listed findings currently.</p>`}
      </div>
    </div>

    <div class="chart-row">
      <div class="chart-block" style="max-width:380px">
        <h3>Findings by month first seen (Infrastructure)</h3>
        <p class="filter-count" style="margin:-4px 0 8px">
          No historical-snapshot storage exists in this app, so this shows which of
          today's Infrastructure findings originated in each month - not what total
          counts looked like on a past date.
        </p>
        ${infraByMonth.length ? barChartSvg(infraByMonth, { width: 340 }) : `<p class="empty-state">No dated findings to chart.</p>`}
      </div>
      <div class="chart-block" style="max-width:380px">
        <h3>Findings by month first seen (Application)</h3>
        <p class="filter-count" style="margin:-4px 0 8px">
          Same honest caveat as Infrastructure's chart, left of this one - SAST/Code Scan
          findings aren't included either way (no comparable first-seen date in that data path).
        </p>
        ${appsecByMonth.length ? barChartSvg(appsecByMonth, { width: 340 }) : `<p class="empty-state">No dated findings to chart.</p>`}
      </div>
    </div>`;
}

function renderBody(data, queue, vh, rankings, assets, teamByAssetName, remediationApprovals) {
  // Real remediation-trigger events (see remediation/remediation_approvals/store.py's
  // mark_remediation_triggered()), reshaped into the same {first_seen, priority}
  // pseudo-finding shape agingChartBlockHtml/agingByPriorityTableHtml already expect -
  // `first_seen` here is really `triggered_at`, deliberately NOT the finding's own real
  // first_seen date, since this section is about when the trigger happened.
  const priorityByFindingId = new Map(queue.findings.map((f) => [f.id, f.priority]));
  const triggeredPseudoFindings = remediationApprovals
    .filter((a) => a.computed_status === "remediation_triggered")
    .map((a) => ({ first_seen: a.triggered_at, priority: priorityByFindingId.get(a.finding_id) || "Low" }));
  const riskRows = Object.entries(data.plan.risk_tier_counts || {}).map(([tier, count]) => `
    <tr>
      <td><span class="badge badge-${tier.replaceAll("-", "_")}">${escapeHtml(tier)}</span></td>
      <td>${count}</td>
    </tr>`).join("");

  const assetRows = Object.entries(data.asset_type_breakdown).map(([type, count]) => `
    <tr><td>${escapeHtml(type)}</td><td>${count}</td></tr>`).join("");

  return `
    <p class="subtitle">Real results from the last validated run of both pipelines — not simulated.</p>

    ${exposureScoreSectionHtml(data.exposure_score, data.exposure_score_rules)}

    <div class="kpi-grid">
      ${kpiLink("/queue?slaStatus=breached", data.sla.breached, "SLA breached", "kpi-danger")}
      ${kpiLink("/queue?slaStatus=at_risk", data.sla.at_risk, "SLA at risk (≤3 days)", "kpi-warn")}
      ${kpiLink("/queue?slaStatus=on_track", data.sla.on_track, "SLA on track", "kpi-good")}
      ${kpiLink("/queue?kevOnly=true", data.kev_count, "CISA KEV-listed (actively exploited)", "kpi-danger")}
      ${kpi(data.high_epss_count, "High EPSS (≥50% exploit probability)", "kpi-warn")}
    </div>

    <div class="kpi-grid">
      ${kpiLink("/vulnhunt", data.vulnhunt.total || 0, "Code vulnerabilities found")}
      ${kpiLink("/vulnhunt", data.vulnhunt.auto_fixable || 0, "Auto-fixed on a branch", "kpi-good")}
      ${kpiLink("/queue", data.remediation.total, "Infra findings normalized")}
      ${kpi(data.remediation.eligible, "Auto-remediable today", "kpi-good")}
      ${kpi(data.remediation.manual_only, "Manual-only (no fixer yet)", "kpi-warn")}
      ${kpiLink("/remediate", data.playbook_count, "Playbooks generated")}
    </div>

    ${lifecycleSection(queue, remediationApprovals)}

    ${domainTotalsSection(queue, vh)}

    <div class="callout">
      Priority in the <a href="/queue" data-link>live remediation queue</a> is
      threat-intel-aware, not just severity-based: a finding confirmed in
      <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener">CISA's KEV catalog</a>
      is escalated to top priority regardless of asset type, and EPSS (exploit-probability
      scoring from FIRST.org) catches high-risk CVEs KEV hasn't confirmed yet. SLA windows,
      asset-criticality weights, and these overrides are all editable on the
      <a href="/priority-rules" data-link>Priority Rules</a> page.
    </div>

    ${definitionsPanel(data.priority_rules)}
    ${assetDefinitionsPanel(data.priority_rules)}

    ${analyticsSection(data, queue, vh, teamByAssetName, triggeredPseudoFindings, remediationApprovals)}

    ${riskScoringSection(assets, data.risk_scoring_rules)}

    <p class="filter-count" style="margin:16px 0 -8px">
      Top-5 rankings below are landscape-wide (Infrastructure + AppSec queue findings) -
      SAST/Code Scan findings have no asset/CVE shape to rank by (see the Code Scan page).
    </p>
    ${topRankingsHtml("overview", rankings)}

    ${data.plan.available ? `
      <h2>Risk tier breakdown (remediation queue)</h2>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>Risk Tier</th><th>Count</th></tr></thead>
          <tbody>${riskRows}</tbody>
        </table>
      </div>` : ""}

    <h2>Coverage by asset class</h2>
    <p class="subtitle">Not just code — infra, OS, network, IoT/OT, application, and certificate-level findings.</p>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Asset Type</th><th>Findings</th></tr></thead>
        <tbody>${assetRows}</tbody>
      </table>
    </div>

    <div class="callout">
      Every playbook shown here is a reviewable artifact — nothing in this dashboard executes
      against real infrastructure automatically. See the safety model in
      <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/KNOWLEDGE_TRANSFER.md#43-the-safety-model-the-single-most-important-design-decision" target="_blank" rel="noopener">KNOWLEDGE_TRANSFER.md §4.3</a>.
    </div>`;
}

// Real stats for the AI trend analysis panel, re-fetched fresh at click-time (not
// captured from this page's own auto-refreshing render) - see aiTrendAnalysis.js's own
// comment on why that matters here specifically (this page fully replaces its DOM
// every 20s; a stats snapshot tied to that would go stale mid-click).
async function buildOverviewAiStats() {
  const [data, queue, assetsData] = await Promise.all([api.overview(), api.queue(), api.assetsList()]);
  const { teamByAssetName } = buildOwnerTeamMaps(assetsData.assets);
  const findings = queue.findings;
  const severityData = countBy(findings, (f) => f.severity);
  const priorityData = countBy(findings, (f) => f.priority);
  const teamData = countBy(findings, (f) => teamByAssetName.get(f.asset && f.asset.name) || "Unassigned");
  return {
    "Total findings (Infrastructure + AppSec queue)": findings.length,
    "SLA breached": data.sla.breached,
    "SLA at risk (<=3 days)": data.sla.at_risk,
    "SLA on track": data.sla.on_track,
    "CISA KEV-listed (actively exploited)": data.kev_count,
    "High EPSS (>=50% exploit probability)": data.high_epss_count,
    "Severity breakdown": severityData.map((d) => `${d.label}=${d.value}`).join(", "),
    "Priority breakdown": priorityData.map((d) => `${d.label}=${d.value}`).join(", "),
    "Findings by team (top 5)": teamData.slice(0, 5).map((d) => `${d.label}=${d.value}`).join(", "),
    "Assets at Critical/High risk tier": assetsData.assets.filter((a) => a.risk_tier === "Critical" || a.risk_tier === "High").length,
    "Assets with no owner assigned": assetsData.assets.filter((a) => !a.owner).length,
  };
}

export async function render(container) {
  const topbarExtra = document.getElementById("topbar-extra");
  let lastFetched = null;

  // The AI trend analysis FAB lives OUTSIDE #overview-body on purpose - #overview-body
  // is fully replaced every 20s by the auto-refresh below, which would otherwise wipe an
  // in-progress prompt preview or a just-received (real API cost!) AI response the
  // moment it arrived. Being position:fixed, it doesn't occupy row space either way.
  container.innerHTML = `<div id="overview-body"></div>${aiTrendAnalysisFabHtml("overview")}`;
  const bodyEl = container.querySelector("#overview-body");
  wireAiTrendAnalysis(container, "overview", "landscape-wide", buildOverviewAiStats,
    "the whole landscape (Infrastructure + AppSec + AI/ML + Certificate)");

  function renderLiveBadge() {
    if (!topbarExtra) return;
    topbarExtra.innerHTML = `<span class="live-badge" data-tooltip="Auto-refreshes every ${REFRESH_MS / 1000}s">` +
      `<span class="live-dot"></span> Live · updated ${lastFetched ? timeAgo(lastFetched) : "just now"}</span>`;
  }

  async function load() {
    const [data, queue, vh, assetsData, remediationApprovalsData] = await Promise.all([
      api.overview(), api.queue(), api.vulnhunt(), api.assetsList(), api.remediationApprovalsList(),
    ]);
    lastFetched = new Date();
    const { ownerByAssetName, teamByAssetName } = buildOwnerTeamMaps(assetsData.assets);
    const rankings = buildTopRankings(queue.findings, ownerByAssetName, teamByAssetName);
    bodyEl.innerHTML = renderBody(data, queue, vh, rankings, assetsData.assets, teamByAssetName, remediationApprovalsData.approvals);
    renderLiveBadge();
    wireTopRankings(bodyEl, "overview", rankings);
    wireChartLinks(bodyEl);

    const unownedCount = assetsData.assets.filter((a) => !a.owner).length;
    const unownedPct = assetsData.assets.length ? Math.round((unownedCount / assetsData.assets.length) * 100) : 0;

    const alerts = [];
    if (data.sla.breached > 0) {
      alerts.push(insightAlertHtml(
        `<strong>${data.sla.breached}</strong> finding(s) are past their SLA window - see <a href="/queue" data-link>Remediation Queue</a>.`,
        "danger",
      ));
    }
    if (data.kev_count > 0) {
      alerts.push(insightAlertHtml(
        `<strong>${data.kev_count}</strong> finding(s) are CISA KEV-listed (confirmed actively exploited) across the whole landscape.`,
        "warn",
      ));
    }
    if (unownedPct > 50) {
      alerts.push(insightAlertHtml(
        `<strong>${unownedPct}%</strong> (${unownedCount} of ${assetsData.assets.length}) of assets have no owner assigned - most of this demo dataset has no CMDB-imported ownership yet. See <a href="/assets" data-link>Asset Inventory</a>.`,
        "info",
      ));
    }

    // Trimmed to just the one most load-bearing section - see queue.js's own comment on
    // this same change (Part 11: insights panel now starts collapsed by default).
    setInsightsContent(insightSectionHtml("On this page", alerts.join("")));
  }

  await load();
  const tickTimer = setInterval(renderLiveBadge, 1000);
  const refreshTimer = setInterval(() => { load().catch((err) => console.error(err)); }, REFRESH_MS);

  return () => {
    clearInterval(tickTimer);
    clearInterval(refreshTimer);
  };
}
