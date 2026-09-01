// Cross-cutting "which vulnerability hits the most assets" / "which asset carries the
// most vulnerabilities" groupings - extracted from risk.js (which computed the first
// one inline) so /vulnerability-mapping, /asset-mapping, and risk.js's own condensed
// previews all share one implementation instead of drifting copies.
const SEVERITY_RANK = { Critical: 3, High: 2, Medium: 1, Low: 0 };

// Groups live-queue findings into "vulnerability types" - keyed by CVE when the
// finding has one (the real, unambiguous identifier), falling back to its title
// otherwise (e.g. certificate-expiry findings, which have no CVE). Shows how many
// distinct assets each vulnerability type touches and who owns them, so "we have 6
// Critical findings" becomes "which ONE vulnerability is spread across the most
// assets, and whose problem is it to fix."
export function groupVulnerabilitiesByType(findings, ownerByAssetName, teamByAssetName) {
  const owners = ownerByAssetName || new Map();
  const teams = teamByAssetName || new Map();
  const groups = new Map();
  for (const f of findings) {
    const key = f.cve || f.title;
    if (!groups.has(key)) {
      groups.set(key, {
        key, title: f.title, cve: f.cve || null, severity: f.severity || f.priority,
        assetNames: new Set(), owners: new Set(), teams: new Set(),
      });
    }
    const g = groups.get(key);
    if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[g.severity]) g.severity = f.severity;
    const assetName = f.asset && f.asset.name;
    if (assetName) {
      g.assetNames.add(assetName);
      g.owners.add(owners.get(assetName) || "Unowned");
      g.teams.add(teams.get(assetName) || "—");
    }
  }
  return [...groups.values()]
    .map((g) => ({
      ...g, assetCount: g.assetNames.size,
      assetNames: [...g.assetNames], owners: [...g.owners], teams: [...g.teams],
    }))
    .sort((a, b) => b.assetCount - a.assetCount);
}

// The parallel grouping: which assets carry the most DISTINCT vulnerabilities (again
// keyed by CVE-or-title, so the same CVE seen twice on one asset only counts once).
export function groupFindingsByAsset(findings, ownerByAssetName, teamByAssetName) {
  const owners = ownerByAssetName || new Map();
  const teams = teamByAssetName || new Map();
  const groups = new Map();
  for (const f of findings) {
    const assetName = f.asset && f.asset.name;
    if (!assetName) continue;
    if (!groups.has(assetName)) {
      groups.set(assetName, {
        name: assetName, type: f.asset.type, os: f.asset.os,
        owner: owners.get(assetName) || "Unowned", team: teams.get(assetName) || "—",
        vulnKeys: new Set(), findingIds: [], criticalCount: 0, eolStatus: f.eol_status,
      });
    }
    const g = groups.get(assetName);
    g.vulnKeys.add(f.cve || f.title);
    g.findingIds.push(f.id);
    if (f.severity === "Critical" || f.priority === "Critical") g.criticalCount += 1;
  }
  return [...groups.values()]
    .map((g) => ({ ...g, vulnCount: g.vulnKeys.size }))
    .sort((a, b) => b.vulnCount - a.vulnCount);
}
