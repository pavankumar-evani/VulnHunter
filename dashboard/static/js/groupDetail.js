// Threat-actor-group detail modal: real assets/owners/teams/findings/remediation-status
// for whichever of this tenant's current findings share a known ATT&CK technique with
// the clicked group - the same illustrative cross-reference the Threat Intel page's own
// table already discloses, just drilled into for one group. Modeled on
// findingDetail.js's openXxxDetail(entity) -> openModal(bodyHtml) pattern - everything
// rendered here comes from data already in memory (no new fetch).
import { escapeHtml, openModal, closeModal } from "./dom.js";
import { findingsForGroup } from "./threatActorGroups.js";
import { remediationStatusFor, remediationStatusBadgeHtml } from "./threatIntelTagging.js";
import { barChartSvg, countBy } from "./charts.js";

function assetRowHtml(a) {
  return `
    <tr>
      <td>${escapeHtml(a.name)}</td>
      <td>${escapeHtml(a.type || "")}</td>
      <td>${escapeHtml(a.owner || "Unowned")}</td>
      <td>${escapeHtml(a.team || "—")}</td>
      <td>${a.findingCount}</td>
    </tr>`;
}

function findingRowHtml(f, planByFindingId) {
  const status = remediationStatusFor(f, planByFindingId);
  return `
    <tr>
      <td><a href="/queue?highlight=${encodeURIComponent(f.id)}" data-link>${escapeHtml(f.id)}</a></td>
      <td>${escapeHtml(f.cve || f.title)}</td>
      <td><span class="badge badge-${(f.severity || "").toLowerCase()}">${escapeHtml(f.severity)}</span></td>
      <td>${escapeHtml((f.asset && f.asset.name) || "")}</td>
      <td>${remediationStatusBadgeHtml(status)}</td>
    </tr>`;
}

export function openGroupDetail(group, findings, ownerByAssetName, teamByAssetName, planByFindingId) {
  const matching = findingsForGroup(group, findings);

  const assetMap = new Map();
  for (const f of matching) {
    const name = f.asset && f.asset.name;
    if (!name) continue;
    if (!assetMap.has(name)) {
      assetMap.set(name, {
        name, type: f.asset.type,
        owner: ownerByAssetName.get(name), team: teamByAssetName.get(name),
        findingCount: 0,
      });
    }
    assetMap.get(name).findingCount += 1;
  }
  const assets = [...assetMap.values()].sort((a, b) => b.findingCount - a.findingCount);
  const severityData = countBy(matching, (f) => f.severity);
  const MAX_ROWS = 50;

  const body = openModal(`
    <h2>${escapeHtml(group.name)}</h2>
    <p class="muted" style="margin-top:-6px">${escapeHtml((group.aliases || []).join(", "))}</p>
    <p>${escapeHtml(group.summary)}</p>
    <div class="callout callout-warn" style="margin:10px 0">
      Illustrative cross-reference: <strong>${matching.length}</strong> of this tenant's
      current findings share at least one of ${escapeHtml(group.name)}'s known ATT&amp;CK
      technique(s) (${escapeHtml((group.matchedTechniqueIds || []).join(", "))}) - not an
      attribution claim (many groups share the same common techniques). See
      <a href="${escapeHtml(group.mitreUrl)}" target="_blank" rel="noopener">MITRE ATT&amp;CK ↗</a>.
    </div>

    <div class="kpi-grid">
      <div class="kpi-card"><div class="kpi-value">${matching.length}</div><div class="kpi-label">Matching findings</div></div>
      <div class="kpi-card"><div class="kpi-value">${assets.length}</div><div class="kpi-label">Distinct assets</div></div>
    </div>

    <h3 style="margin:16px 0 8px">Severity breakdown</h3>
    ${severityData.length ? barChartSvg(severityData, { width: 380, height: 160 }) : `<p class="empty-state">No matching findings.</p>`}

    <h3 style="margin:16px 0 8px">Assets (owner/team)</h3>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>Asset</th><th>Type</th><th>Owner</th><th>Team</th><th>Findings</th></tr></thead>
        <tbody>${assets.length ? assets.map(assetRowHtml).join("") : `<tr><td colspan="5" class="empty-state">No matching assets.</td></tr>`}</tbody>
      </table>
    </div>

    <h3 style="margin:16px 0 8px">Findings (remediation status)</h3>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>ID</th><th>CVE/Title</th><th>Severity</th><th>Asset</th><th>Remediation Status</th></tr></thead>
        <tbody>${matching.length ? matching.slice(0, MAX_ROWS).map((f) => findingRowHtml(f, planByFindingId)).join("") : `<tr><td colspan="5" class="empty-state">No matching findings.</td></tr>`}</tbody>
      </table>
    </div>
    ${matching.length > MAX_ROWS ? `<p class="filter-count">Showing the first ${MAX_ROWS} of ${matching.length} matching findings - use Zero-days/Queue for the full list.</p>` : ""}
  `);

  body.querySelectorAll("[data-link]").forEach((a) => a.addEventListener("click", () => closeModal()));
}
