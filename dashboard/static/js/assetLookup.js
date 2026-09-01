// Shared owner/team/environment lookup - extracted from risk.js's original one-off
// `ownerByAssetName` map so findingsTable.js, queue.js, and risk.js all build the
// same join from one place instead of several slightly-diverging copies. Backed by
// /api/assets' real owner/team/environment fields (see
// remediation/inventory/asset_inventory.py) - this is a plain name-keyed lookup, not
// a new data source.
export function buildOwnerTeamMaps(assets) {
  return {
    ownerByAssetName: new Map(assets.map((a) => [a.name, a.owner])),
    teamByAssetName: new Map(assets.map((a) => [a.name, a.team])),
    environmentByAssetName: new Map(assets.map((a) => [a.name, a.environment])),
  };
}

// Same manually-set, never-guessed convention as assets.js's own environment select -
// drives the Remediation Policy engine's "dev" domain override (see
// remediation/config/remediation_policy.yaml) for ANY asset type, infra or
// application/code-repository alike, not just servers. Exported here (rather than
// kept private to assets.js) so every findings view that wants to show this tag in
// context - not just the separate Asset Inventory page - renders it identically.
export const ENVIRONMENT_LABELS = { prod: "Production", staging: "Staging", dev: "Dev", unknown: "Unknown" };
const ENVIRONMENT_BADGE_CLASS = { prod: "badge-critical", staging: "badge-medium", dev: "badge-auto_approvable", unknown: "badge-outline" };

export function environmentCellHtml(environment, escapeHtml) {
  const env = environment || "unknown";
  return `<span class="badge ${ENVIRONMENT_BADGE_CLASS[env] || "badge-outline"}">${escapeHtml(ENVIRONMENT_LABELS[env] || env)}</span>`;
}
