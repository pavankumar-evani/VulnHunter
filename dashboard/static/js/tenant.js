// Illustrative MSSP tenant-switcher DEMO. This is a UI-only concept: it partitions the
// same real findings by asset-type category so the app *looks and demos* like a
// multi-tenant MSSP view. It is explicitly NOT real per-tenant authentication or data
// isolation - there is one dataset, one process, no auth layer. See
// KNOWLEDGE_TRANSFER.md §11.1 and dashboard/README.md before mistaking this for a real
// tenancy boundary.
const KEY = "vulnhunter_tenant";

// `initials`/`avatarColor` render a generated placeholder avatar (like GitHub/Slack
// show for an org with no uploaded logo) rather than a fabricated real company logo -
// this demo's "tenants" aren't real companies, so there's no real logo to show.
// `location` is equally illustrative demo metadata, not a real registered address.
export const TENANTS = {
  all: {
    id: "all", label: "All Tenants (MSSP view)", assetTypes: null,
    initials: null, avatarColor: "#4b5563", location: null,
  },
  acme: {
    id: "acme",
    label: "Acme Financial Corp (demo)",
    assetTypes: ["windows-server", "unix-server", "network-routing-switching", "network-security-device"],
    initials: "AF", avatarColor: "#2563eb", location: "New York, USA",
  },
  northwind: {
    id: "northwind",
    label: "Northwind Bank (demo)",
    assetTypes: ["application", "certificate", "iot-ot-device"],
    initials: "NB", avatarColor: "#7c3aed", location: "Toronto, Canada",
  },
};

export function listTenants() {
  return Object.values(TENANTS);
}

export function getTenant() {
  const id = localStorage.getItem(KEY);
  return TENANTS[id] || TENANTS.all;
}

export function setTenant(id) {
  localStorage.setItem(KEY, id in TENANTS ? id : "all");
  window.dispatchEvent(new CustomEvent("tenant-changed", { detail: getTenant() }));
}

// Filters a list of findings (each with an asset.type) down to the selected demo
// tenant's slice. Returns the same array unchanged when "All Tenants" is selected.
export function filterByTenant(findings) {
  const tenant = getTenant();
  if (!tenant.assetTypes) return findings;
  return findings.filter((f) => tenant.assetTypes.includes((f.asset && f.asset.type) || ""));
}
