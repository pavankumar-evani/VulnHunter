// Real threat-intel-derived per-finding facts, shared across every place that shows
// them: the Threat Intel page's own zero-days table, the threat-actor-group detail
// modal (groupDetail.js), and the "Threat Intel" column on every real finding-level
// table in this app (Queue, Infrastructure/AppSec via findingsTable.js, Compensating
// Controls) - "exactly one place defines this," same rule
// remediation/config/priority_engine.py's asset_criticality_score() reuse already
// applies on the Python side.
import { escapeHtml } from "./dom.js";
import { THREAT_ACTOR_GROUPS } from "./threatActorGroups.js";

// Real sources this app's own data already traces back to for a finding - not
// fabricated per-row, just naming which of the already-integrated feeds (see
// threatIntelFeeds.js) actually produced a signal already present on it.
export function sourcesFor(f) {
  const sources = [];
  if (f.kev && f.kev.listed) sources.push("CISA KEV");
  if (f.cve) sources.push("NVD");
  if (f.epss) sources.push("FIRST.org EPSS");
  return sources;
}

// Which of the 6 real, MITRE-documented reference groups (threatActorGroups.js) share
// at least one ATT&CK technique with this SINGLE finding - the same illustrative
// cross-reference the Threat Intel page's own aggregate correlateFindings() already
// does, just scoped to one finding. Same "not an attribution claim" caveat applies.
export function groupsForFinding(f) {
  const techniqueIds = new Set((f.attack_techniques || []).map((t) => t.technique_id).filter(Boolean));
  if (!techniqueIds.size) return [];
  return THREAT_ACTOR_GROUPS.filter((g) => g.associatedTechniqueIds.some((tid) => techniqueIds.has(tid))).map((g) => g.name);
}

// Renders the shared "Threat Intel" column cell - real feed source tag(s) plus any
// matched threat-actor group name(s), or a plain dash when neither applies (the common
// case - most findings match no group, honest, not padded).
export function threatIntelCellHtml(f) {
  const sources = sourcesFor(f);
  const groups = groupsForFinding(f);
  if (!sources.length && !groups.length) return `<span class="muted">—</span>`;
  const parts = [];
  if (sources.length) {
    parts.push(`<span class="badge badge-manual_only" data-tooltip="Real threat-intel feed(s) already tagged on this finding - see the Threat Intel page">${escapeHtml(sources.join(", "))}</span>`);
  }
  for (const name of groups) {
    parts.push(`<a class="badge badge-critical" href="/threat-intel" data-link data-tooltip="Shares a known ATT&amp;CK technique with ${escapeHtml(name)} - illustrative cross-reference, not an attribution claim">${escapeHtml(name)}</a>`);
  }
  return parts.join(" ");
}

export function threatIntelExportValue(f) {
  return [...sourcesFor(f), ...groupsForFinding(f).map((g) => `Group: ${g}`)].join("; ");
}

// REMEDIATION_PLAN.md's own risk-tier classification, joined by finding ID (see
// dashboard/data.py's load_remediation_plan()) - a generated-but-UNEXECUTED plan (see
// the FAQ: this app never marks anything as actually applied/fixed). "auto-approvable"
// means a fixer playbook COULD be generated for this finding today, not that one has
// been run - the same honesty this project already applies everywhere else it surfaces
// this plan.
export const REMEDIATION_STATUS_LABELS = {
  "auto-approvable": "Auto-approvable",
  "needs-change-approval": "Needs change approval",
  "manual-only": "Manual only",
};
const REMEDIATION_STATUS_BADGE = {
  "auto-approvable": "badge-auto_approvable",
  "needs-change-approval": "badge-medium",
  "manual-only": "badge-manual_only",
};

export function remediationStatusFor(f, planByFindingId) {
  const planRow = planByFindingId.get(f.id);
  return planRow ? (planRow["Risk Tier"] || null) : null;
}

export function remediationStatusBadgeHtml(status) {
  if (!status) return `<span class="muted" data-tooltip="No matching row in the generated remediation plan for this finding ID.">Unknown</span>`;
  return `<span class="badge ${REMEDIATION_STATUS_BADGE[status] || ""}">${escapeHtml(REMEDIATION_STATUS_LABELS[status] || status)}</span>`;
}
