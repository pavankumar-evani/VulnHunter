// Threat Intelligence hub: every threat-intel feed this app pulls (or would pull) data
// from, MITRE-documented threat-actor groups relevant to the currently-selected (demo)
// tenant's industry, and zero-days/top vulnerabilities - in that order, feeds first since
// they're the base "where does this all come from" context for everything below. Not a
// separate data source - the "zero-days" section is the same /api/queue data every other
// page shows, filtered through the same filterByTenant() every tenant-aware page already
// uses; the threat-actor-group correlation is a real, verified reference list
// (remediation/enrichment/threat_actor_groups.py) cross-checked against findings'
// already-tagged attack_techniques - not a live feed, and explicitly disclosed as such.
import { api } from "../api.js";
import { escapeHtml, openModal, closeModal, flash } from "../dom.js";
import { icon } from "../icons.js";
import { getTenant, filterByTenant, tenantBannerHtml } from "../tenant.js";
import { correlateFindings, INDUSTRIES } from "../threatActorGroups.js";
import { CONNECTORS } from "../adaptorCatalog.js";
import { THREAT_INTEL_FEEDS } from "../threatIntelFeeds.js";
import { groupLabelFor } from "../domainGrouping.js";
import { groupVulnerabilitiesByType } from "../rankings.js";
import { buildOwnerTeamMaps } from "../assetLookup.js";
import { openGroupDetail } from "../groupDetail.js";
import { sourcesFor, remediationStatusFor, remediationStatusBadgeHtml, REMEDIATION_STATUS_LABELS } from "../threatIntelTagging.js";
import { exportButtonsHtml, wireExportButtons } from "../export.js";
import { paginate, paginationHtml, wirePagination } from "../pagination.js";

export const title = "Threat Intel";

const ZERO_DAY_EXPORT_COLUMNS = [
  { label: "Priority", value: (f) => f.priority },
  { label: "ID", value: (f) => f.id },
  { label: "CVE/Title", value: (f) => f.cve || f.title },
  { label: "Severity", value: (f) => f.severity },
  { label: "Security Domain", value: (f) => f.domainLabel },
  { label: "Source", value: (f) => sourcesFor(f).join(", ") },
  { label: "Remediation Status", value: (f) => REMEDIATION_STATUS_LABELS[f.remediationStatus] || "Unknown (no plan entry)" },
  { label: "Assets Impacted", value: (f) => f.assetsImpacted },
  { label: "Matched exploit criteria", value: (f) => (f.exploit_criteria_matches || []).map((m) => m.label).join("; ") },
  { label: "Asset", value: (f) => f.asset && f.asset.name },
];

function isZeroDay(f) {
  // Same "actively exploited, matches a configured exploit-criteria rule" definition
  // compensatingControls.js's flagsFor() already uses for its own "zero-day" flag.
  return f.kev && f.kev.listed && (f.exploit_criteria_matches || []).length > 0;
}

// Left offsets/widths for the zero-days table's 3 sticky columns (Priority/ID/CVE-Title)
// - fixed pixel widths so `left` can be computed as a plain running sum (no JS layout
// measurement); CVE/Title truncates with an ellipsis at this width (see .sticky-col-truncate
// in style.css) rather than growing, which is the deliberate trade-off of a sticky column
// over variable-width content.
const ZD_STICKY = { priority: { left: 0, width: 100 }, id: { left: 100, width: 90 }, cveTitle: { left: 190, width: 220 } };

function zeroDayRowHtml(f) {
  const statusBadge = remediationStatusBadgeHtml(f.remediationStatus);
  return `
    <tr>
      <td class="sticky-col sticky-col-truncate" style="left:${ZD_STICKY.priority.left}px; width:${ZD_STICKY.priority.width}px"><span class="badge badge-priority-${(f.priority || "").toLowerCase()}">${escapeHtml(f.priority)}</span></td>
      <td class="sticky-col sticky-col-truncate" style="left:${ZD_STICKY.id.left}px; width:${ZD_STICKY.id.width}px"><a href="/queue?highlight=${encodeURIComponent(f.id)}" data-link>${escapeHtml(f.id)}</a></td>
      <td class="sticky-col sticky-col-truncate" style="left:${ZD_STICKY.cveTitle.left}px; width:${ZD_STICKY.cveTitle.width}px" data-tooltip="${escapeHtml(f.cve || f.title)}">${escapeHtml(f.cve || f.title)}</td>
      <td><span class="badge badge-${(f.severity || "").toLowerCase()}">${escapeHtml(f.severity)}</span></td>
      <td>${escapeHtml(f.domainLabel)}</td>
      <td>${escapeHtml(sourcesFor(f).join(", ") || "—")}</td>
      <td>${statusBadge}</td>
      <td>${f.assetsImpacted}</td>
      <td>${escapeHtml((f.exploit_criteria_matches || []).map((m) => m.label).join("; "))}</td>
      <td>${escapeHtml(f.asset && f.asset.name)}</td>
    </tr>`;
}

// Group column width for the threat-actor-groups table's one sticky column.
const GROUP_STICKY_WIDTH = 190;

// Real MITRE-tracked activity status - see threatActorGroups.js's own header comment for
// the 2026-08-05 re-verification note. Not a live intrusion/telemetry signal (this app
// has no live threat-intel feed ingestion - see the Ingestion disclosure below); this is
// MITRE ATT&CK's own current cataloguing status, the honest substitute for "is this group
// still active" that's actually available here. The row itself is clickable (see
// render()'s click-delegation below) - opens a real detail modal (groupDetail.js) with
// this tenant's actual matching assets/findings/remediation-status for this group.
function groupRowHtml(g) {
  return `
    <tr class="group-row-clickable" data-group-name="${escapeHtml(g.name)}" data-tooltip="Click for this group's matching assets, findings, and remediation status">
      <td class="sticky-col" style="left:0; width:${GROUP_STICKY_WIDTH}px"><strong>${escapeHtml(g.name)}</strong><br>
        <span class="muted" style="font-size:0.8rem">${escapeHtml(g.aliases.slice(0, 3).join(", "))}${g.aliases.length > 3 ? ", …" : ""}</span>
      </td>
      <td>${escapeHtml(g.summary)}</td>
      <td>${(g.targetIndustries || []).map((ind) => `<span class="attack-tag">${escapeHtml(ind)}</span>`).join(" ")}</td>
      <td><span class="badge badge-auto_approvable" data-tooltip="Per MITRE ATT&amp;CK's own current catalog - not a live detection signal from your environment.">Active</span></td>
      <td>${escapeHtml(g.mostRecentActivity)}</td>
      <td>${g.matchedTechniqueIds.map((t) => `<span class="attack-tag">${escapeHtml(t)}</span>`).join(" ")}</td>
      <td>${g.findingCount}</td>
      <td><a href="${escapeHtml(g.mitreUrl)}" target="_blank" rel="noopener">MITRE ATT&amp;CK ↗</a></td>
    </tr>`;
}

function feedCardHtml(c) {
  return `
    <a class="domain-card" href="/adaptors?connector=${encodeURIComponent(c.key)}" data-link>
      <span class="domain-card-icon">${icon(c.iconName, 22)}</span>
      <span class="domain-card-label">${escapeHtml(c.label)}</span>
      <span class="domain-card-note">${escapeHtml(c.blurb)}</span>
    </a>`;
}

function feedRowHtml(f) {
  return `
    <tr>
      <td><a href="${escapeHtml(f.url)}" target="_blank" rel="noopener">${escapeHtml(f.name)} ↗</a>
        ${f.note ? `<br><span class="muted" style="font-size:0.8rem">${escapeHtml(f.note)}</span>` : ""}
      </td>
      <td>${escapeHtml(f.category)}</td>
      <td>${f.integrated
        ? `<span class="badge badge-auto_approvable">Live in this app</span>`
        : `<span class="badge badge-manual_only">Reference only</span>`}</td>
      <td>${escapeHtml(f.refreshCadence)}</td>
    </tr>`;
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading…</div>`;
  const [queue, remediatePlan, assetsData, freshness] = await Promise.all([
    api.queue(), api.remediate(), api.assetsList(), api.threatIntelFreshness(),
  ]);
  const { ownerByAssetName, teamByAssetName } = buildOwnerTeamMaps(assetsData.assets);

  const tenant = getTenant();
  const findings = filterByTenant(queue.findings);

  // Assets-impacted (distinct assets carrying the same CVE/vulnerability, keyed the same
  // way vulnerabilityMapping.js already does) and remediation-plan-status lookups, both
  // built once over this tenant's findings and joined onto each zero-day row below.
  const vulnGroups = groupVulnerabilitiesByType(findings);
  const assetCountByVulnKey = new Map(vulnGroups.map((g) => [g.key, g.assetCount]));
  const plan = remediatePlan.plan || {};
  const planByFindingId = new Map((plan.available ? plan.queue : []).map((row) => [row.ID, row]));

  const zeroDays = findings.filter(isZeroDay).map((f) => ({
    ...f,
    domainLabel: groupLabelFor(f),
    assetsImpacted: assetCountByVulnKey.get(f.cve || f.title) || 1,
    remediationStatus: remediationStatusFor(f, planByFindingId),
  }));
  const kevCount = findings.filter((f) => f.kev && f.kev.listed).length;
  const highEpssCount = findings.filter((f) => f.epss && f.epss.score >= 0.5).length;

  const allGroups = correlateFindings(findings);
  const feedConnectors = CONNECTORS.filter((c) => c.category === "Threat Intelligence");

  // The closest REAL signal this pipeline has to "credential/identity exposure" -
  // hardcoded secrets already found in source control (CWE-798). Deliberately NOT
  // labeled "dark web" data - it's a different real exposure category (a leak in YOUR
  // OWN repo, not a hit on a criminal forum) - see the section below for the honest
  // distinction. This app has no live dark-web-monitoring feed at all (see the Dark Web
  // / Identity Exposure category in the feeds table above - none of those are wired up).
  const secretsFindings = findings.filter((f) => f.scan_type === "secrets");
  const secretsAssetCount = new Set(secretsFindings.map((f) => f.asset && f.asset.name).filter(Boolean)).size;

  let zdPage = 1;
  let zdDomainFilter = "all";
  const zdDomainLabels = [...new Set(zeroDays.map((f) => f.domainLabel))].sort();

  function renderZeroDayRows() {
    const filtered = zdDomainFilter === "all" ? zeroDays : zeroDays.filter((f) => f.domainLabel === zdDomainFilter);
    // Sort by domain so every domain's rows stay contiguous across pages, then paginate.
    const sorted = [...filtered].sort((a, b) => a.domainLabel.localeCompare(b.domainLabel));
    const paged = paginate(sorted, zdPage);
    zdPage = paged.page;
    const tbody = container.querySelector("#ti-zerodays-body");
    if (!paged.rows.length) {
      tbody.innerHTML = `<tr><td colspan="10" class="empty-state">No findings currently match a configured exploit-criteria rule.</td></tr>`;
    } else {
      let lastDomain = null;
      const parts = [];
      for (const f of paged.rows) {
        if (f.domainLabel !== lastDomain) {
          const domainCount = filtered.filter((x) => x.domainLabel === f.domainLabel).length;
          parts.push(`<tr class="table-section-row"><td colspan="10">${escapeHtml(f.domainLabel)} (${domainCount})</td></tr>`);
          lastDomain = f.domainLabel;
        }
        parts.push(zeroDayRowHtml(f));
      }
      tbody.innerHTML = parts.join("");
    }
    const paginationEl = container.querySelector("#ti-zerodays-pagination");
    if (paginationEl) paginationEl.innerHTML = paginationHtml(paged.page, paged.totalPages);
    const countEl = container.querySelector("#ti-zerodays-count");
    if (countEl) countEl.textContent = `${filtered.length} of ${zeroDays.length} zero-day(s)`;
  }

  let industryFilter = "all";
  function renderGroupsRows() {
    const filtered = industryFilter === "all"
      ? allGroups
      : allGroups.filter((g) => (g.targetIndustries || []).includes(industryFilter));
    const tbody = container.querySelector("#ti-groups-body");
    tbody.innerHTML = filtered.length
      ? filtered.map(groupRowHtml).join("")
      : `<tr><td colspan="8" class="empty-state">No group in this reference list is documented as targeting the selected industry, or has a matching technique in this tenant's current findings.</td></tr>`;
  }

  container.innerHTML = `
    <p class="subtitle">
      Every threat-intel feed this app pulls (or would pull) vulnerability data from,
      MITRE-documented threat-actor groups, and zero-days - relevant to
      ${tenant.id === "all" ? "the full portfolio" : `<strong>${escapeHtml(tenant.label)}</strong>`}.
      Zero-days and threat-actor correlation are built entirely from data this app
      already computes elsewhere (<code>/api/queue</code>'s KEV/EPSS/exploit-criteria
      tagging and <code>remediation/enrichment/attack_mapping.py</code>'s ATT&amp;CK
      technique tagging).
    </p>

    ${tenantBannerHtml()}

    ${tenant.industry ? `
    <div class="callout">
      Industry context: <strong>${escapeHtml(tenant.industry)}</strong>. Both demo
      tenants happen to be financial-services-flavored, so this 2-tenant demo can't show
      dramatic industry-to-industry contrast today - in a real deployment, a tenant's
      industry would drive which feeds below are actually subscribed to and which
      threat-actor groups get surfaced first. Use the industry filter in "Threat-actor
      groups" below to see any group's real, documented sector targeting regardless of
      the tenant selected.
    </div>` : ""}

    <div class="kpi-grid">
      <div class="kpi-card kpi-danger"><div class="kpi-value">${zeroDays.length}</div><div class="kpi-label">Zero-days (KEV + exploit criteria match)</div></div>
      <div class="kpi-card kpi-danger"><div class="kpi-value">${kevCount}</div><div class="kpi-label">CISA KEV-listed</div></div>
      <div class="kpi-card kpi-warn"><div class="kpi-value">${highEpssCount}</div><div class="kpi-label">EPSS ≥ 50%</div></div>
      <div class="kpi-card"><div class="kpi-value">${allGroups.length}</div><div class="kpi-label">Threat-actor groups with matching techniques</div></div>
    </div>

    <h2>Threat intel feeds</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      Every vendor advisory, government/CERT catalog, vulnerability database, and
      security-news source this app pulls (or would pull) zero-day/vulnerability
      intelligence from. "Live in this app" entries are already real and wired up
      (<code>remediation/enrichment/kev_epss.py</code>, and NVD-sourced CVE data in
      <code>remediation/sample-data/generate_bulk_findings.py</code>) - every other row
      is a real, verified source URL with no working scraper/poller behind it yet, same
      honesty tier as the <a href="/adaptors" data-link>Adaptors catalog</a>. Refresh
      cadence is the configured target, not a claim this demo runs a live scheduled job
      today - see the disclosure below.
    </p>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Feed</th><th>Category</th><th>Status</th><th>Refresh cadence</th></tr></thead>
        <tbody>${THREAT_INTEL_FEEDS.map(feedRowHtml).join("")}</tbody>
      </table>
    </div>

    <div class="callout" style="margin-top:12px">
      ${freshness.available
        ? `<strong>CISA KEV + FIRST.org EPSS last refreshed:</strong> ${escapeHtml(new Date(freshness.last_refreshed).toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZoneName: "short" }))}
           (recommended cadence: ${escapeHtml(freshness.recommended_cadence.cisa_kev || "—")}) - covering
           ${freshness.cve_count.toLocaleString()} CVE(s) across the current findings.`
        : "No normalized findings file yet - nothing to refresh."}
      <button type="button" class="secondary-button" id="ti-refresh-now" style="margin-left:10px">Refresh threat intel now</button>
      <p class="filter-count" style="margin:8px 0 0">
        CVSS itself never changes for an existing CVE, so "staying up to date" concretely
        means re-checking whether a CVE has since been added to CISA's KEV catalog or its
        EPSS score has moved - see <code>remediation/config/threat_intel_refresh_rules.yaml</code>.
        This calls the real, free CISA/FIRST.org APIs (no Claude usage/credits spent) and
        updates the real <code>normalized-findings.json</code> - preview first, it's free.
      </p>
    </div>

    <h2 style="margin-top:28px">Industry intelligence platforms</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      Reference-tier connectors (documented integration shape, no live feed wired up -
      same honesty tier as every other entry in the <a href="/adaptors" data-link>Adaptors
      catalog</a>) illustrating the kind of aggregating intel *platform* a tenant's
      industry would realistically subscribe to, distinct from the direct advisory/news
      sources listed above.
    </p>
    <div class="domain-card-grid">
      ${feedConnectors.map(feedCardHtml).join("")}
    </div>

    <h2 style="margin-top:28px">Threat-actor groups</h2>
    <div class="callout callout-warn">
      ⚠️ Real, MITRE-documented groups (<a href="https://attack.mitre.org/groups/" target="_blank" rel="noopener">attack.mitre.org/groups</a>)
      correlated by matching each group's own known ATT&amp;CK techniques against the
      techniques already tagged on findings above - an illustrative cross-reference, not
      an attribution claim. A shared technique (phishing, PowerShell, valid-account
      abuse) doesn't mean a specific group caused a specific finding; many groups use
      the same common techniques. "Active" reflects MITRE's own current catalog status
      (re-verified 2026-08-05), not a live intrusion-detection signal from your
      environment - this app has no live threat-feed ingestion for that (see Ingestion,
      below). Target industries are sector names explicitly named on that group's own
      MITRE page; a group with no tag for an industry in the filter (e.g. none here is
      documented specifically targeting Capital Markets or Insurance sub-sectors) has no
      such victimology documented today - a real absence, not a placeholder. Verify any
      specific pairing against MITRE before citing it formally - see
      <code>remediation/enrichment/threat_actor_groups.py</code>'s module docstring.
    </div>
    <div class="filter-bar">
      <label>Industry
        <select id="ti-f-industry">
          <option value="all">All industries</option>
          ${INDUSTRIES.map((ind) => `<option value="${escapeHtml(ind)}">${escapeHtml(ind)}</option>`).join("")}
        </select>
      </label>
    </div>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr>
          <th class="sticky-col" style="left:0; width:${GROUP_STICKY_WIDTH}px">Group</th>
          <th>Summary</th><th>Target industries</th><th>Status</th><th>Most recent documented activity</th><th>Matched techniques</th><th>Finding count</th><th></th>
        </tr></thead>
        <tbody id="ti-groups-body"></tbody>
      </table>
    </div>

    <h2 style="margin-top:28px">Zero-days</h2>
    <p class="filter-count" style="margin:-4px 0 8px">
      Actively-exploited (CISA KEV) findings that also match a configured
      <a href="/exploit-criteria" data-link>exploit criteria</a> rule - the same
      definition the <a href="/compensating-controls" data-link>Compensating Controls</a>
      page uses for its own "zero-day" flag, grouped by security domain (same grouping
      Compensating Controls uses) so alerts don't all sit in one flat list. Remediation
      Status reflects <a href="/remediate" data-link>the generated remediation plan's</a>
      own risk-tier classification (an unexecuted plan - see the
      <a href="/faq" data-link>FAQ</a>: this app never marks a finding as actually
      fixed). Assets Impacted counts distinct assets across the live queue carrying this
      same CVE/vulnerability - same grouping
      <a href="/vulnerability-mapping" data-link>Vulnerability Mapping</a> uses. See
      <a href="/vulnerability-mapping" data-link>Vulnerability Mapping</a> and
      <a href="/asset-mapping" data-link>Asset Mapping</a> for the broader top-25
      rankings across every finding, not just zero-days.
    </p>
    <div class="filter-bar">
      <label>Domain
        <select id="ti-f-domain">
          <option value="all">All (${zeroDays.length})</option>
          ${zdDomainLabels.map((label) => `<option value="${escapeHtml(label)}">${escapeHtml(label)}</option>`).join("")}
        </select>
      </label>
      <span class="filter-count" id="ti-zerodays-count"></span>
    </div>
    ${exportButtonsHtml("ti-zerodays")}
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr>
          <th class="sticky-col sticky-col-truncate" style="left:${ZD_STICKY.priority.left}px; width:${ZD_STICKY.priority.width}px">Priority</th>
          <th class="sticky-col sticky-col-truncate" style="left:${ZD_STICKY.id.left}px; width:${ZD_STICKY.id.width}px">ID</th>
          <th class="sticky-col sticky-col-truncate" style="left:${ZD_STICKY.cveTitle.left}px; width:${ZD_STICKY.cveTitle.width}px">CVE/Title</th>
          <th>Severity</th><th>Security Domain</th><th>Source</th><th>Remediation Status</th><th>Assets Impacted</th><th>Matched exploit criteria</th><th>Asset</th>
        </tr></thead>
        <tbody id="ti-zerodays-body"></tbody>
      </table>
    </div>
    <div id="ti-zerodays-pagination"></div>

    <h2 style="margin-top:28px">Dark web &amp; identity exposure monitoring</h2>
    <div class="callout callout-warn">
      This app has <strong>no live dark-web-monitoring integration</strong> today - there
      is no feed here that checks whether an asset, employee identity, or credential
      appears in a breach corpus or a dark-web/criminal-forum listing. The "Dark Web /
      Identity Exposure" category in the Threat intel feeds table above lists 3 real,
      independently-verified reference services a deployment would wire up for that
      (Have I Been Pwned, MISP, SOCRadar Labs) - none are integrated here yet, same
      honesty tier as every other not-yet-wired entry on this page.
    </div>
    <p class="filter-count" style="margin:8px 0">
      The closest REAL signal this pipeline already has is <strong>Repository Secret
      Scanning</strong> - hardcoded credentials, API keys, and connection strings already
      found committed to source control (CWE-798). This is deliberately shown as a
      <em>different</em> real exposure category, not relabeled "dark web": a secret found
      in your own repository is not the same fact as a credential seen for sale on a
      criminal forum, and this app has no source for the latter.
    </p>
    <div class="kpi-grid">
      <div class="kpi-card kpi-danger"><div class="kpi-value">${secretsFindings.length}</div><div class="kpi-label">Hardcoded credential(s) in source control</div></div>
      <div class="kpi-card"><div class="kpi-value">${secretsAssetCount}</div><div class="kpi-label">Distinct repositories affected</div></div>
    </div>
    ${secretsFindings.length ? `
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Priority</th><th>ID</th><th>Title</th><th>Severity</th><th>Repository</th></tr></thead>
        <tbody>${secretsFindings.slice(0, 10).map((f) => `
          <tr>
            <td><span class="badge badge-priority-${(f.priority || "").toLowerCase()}">${escapeHtml(f.priority)}</span></td>
            <td><a href="/queue?highlight=${encodeURIComponent(f.id)}" data-link>${escapeHtml(f.id)}</a></td>
            <td>${escapeHtml(f.title)}</td>
            <td><span class="badge badge-${(f.severity || "").toLowerCase()}">${escapeHtml(f.severity)}</span></td>
            <td>${escapeHtml((f.asset && f.asset.name) || "")}</td>
          </tr>`).join("")}</tbody>
      </table>
    </div>
    <p class="filter-count"><a href="/queue?category=secrets" data-link>See all ${secretsFindings.length} repository secret-scanning finding(s) →</a></p>` :
      `<p class="empty-state">No repository secret-scanning findings currently.</p>`}

    <div class="callout" style="margin-top:20px">
      <strong>Ingestion:</strong> this app's real, working ingestion path for
      externally-sourced findings is <code>remediation/connectors/generic_connector.py</code>
      (see the <a href="/adaptors" data-link>Adaptors</a> catalog) - a webhook adapter
      that accepts finding-shaped JSON (title, severity, asset, optional CVE). It does
      not parse arbitrary raw log lines from multiple source formats; genuine
      multi-source raw-log ingestion is a real capability gap, not something this page
      implies exists.
    </div>`;

  container.querySelector("#ti-refresh-now").addEventListener("click", () => {
    const body = openModal(`
      <h2>Refresh threat intel now</h2>
      <p class="subtitle">
        Re-fetches CISA KEV + FIRST.org EPSS live and updates
        <code>remediation/output/normalized-findings.json</code> in place - the same
        real logic <code>/remediate</code>'s enrichment stage runs. This does NOT call
        the Claude API and spends no usage/credits - preview first (free) to see what
        would happen, or confirm to actually make the two real, free CISA/FIRST.org
        network calls now.
      </p>
      <form class="run-form" id="threat-intel-refresh-form">
        <label class="checkbox-label">
          <input type="checkbox" name="confirm">
          Actually refresh now (leave unchecked for a dry-run preview only)
        </label>
        <button type="submit">Submit</button>
      </form>
      <div id="threat-intel-refresh-result"></div>`);
    body.querySelector("#threat-intel-refresh-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const resultEl = body.querySelector("#threat-intel-refresh-result");
      try {
        const result = await api.threatIntelRefreshNow(event.target.confirm.checked);
        resultEl.innerHTML = `<div class="callout">${escapeHtml(result.message)}</div>`;
        if (!result.dry_run) {
          flash(result.message, "success");
          closeModal();
          render(container);
        }
      } catch (err) {
        resultEl.innerHTML = `<p style="color:var(--danger)">${escapeHtml(err.message)}</p>`;
      }
    });
  });

  renderGroupsRows();
  container.querySelector("#ti-f-industry").addEventListener("change", (e) => {
    industryFilter = e.target.value;
    renderGroupsRows();
  });
  // Event delegation on the stable tbody parent (not individual rows, which
  // renderGroupsRows() rebuilds on every filter change) - clicking a group row opens
  // its real detail modal, unless the click was on the row's own MITRE ATT&CK link
  // (which should keep its normal new-tab behavior).
  container.querySelector("#ti-groups-body").addEventListener("click", (e) => {
    if (e.target.closest("a")) return;
    const row = e.target.closest("tr[data-group-name]");
    if (!row) return;
    const group = allGroups.find((g) => g.name === row.dataset.groupName);
    if (group) openGroupDetail(group, findings, ownerByAssetName, teamByAssetName, planByFindingId);
  });

  renderZeroDayRows();
  container.querySelector("#ti-f-domain").addEventListener("change", (e) => {
    zdDomainFilter = e.target.value;
    zdPage = 1;
    renderZeroDayRows();
  });
  wirePagination(container, (p) => { zdPage = p; renderZeroDayRows(); });
  wireExportButtons(container, "ti-zerodays", {
    getRows: () => zeroDays,
    columns: ZERO_DAY_EXPORT_COLUMNS,
    filenameBase: "vulnhunter-threat-intel-zero-days",
  });
}
