// Illustrative MSSP tenant-switcher DEMO. This is a UI-only concept: it partitions the
// same real findings by asset-type category so the app *looks and demos* like a
// multi-tenant MSSP view. It is explicitly NOT real per-tenant authentication or data
// isolation - there is one dataset, one process, no auth layer. See
// KNOWLEDGE_TRANSFER.md §11.1 and dashboard/README.md before mistaking this for a real
// tenancy boundary.
import { escapeHtml } from "./dom.js";

const KEY = "vulnhunter_tenant";

// `initials`/`avatarColor` render a generated placeholder avatar (like GitHub/Slack
// show for an org with no uploaded logo) rather than a fabricated real company logo -
// this demo's "tenants" aren't real companies, so there's no real logo to show.
// `location` is equally illustrative demo metadata, not a real registered address.
// `industry` is a real GICS-style sector label used by the Threat Intel page
// (/threat-intel) to frame which zero-days/threat-actor content is "most relevant" to
// the selected tenant - illustrative demo metadata, same honesty tier as
// `location`/`assetTypes`. Both demo tenants happen to be financial-services-flavored
// by name, which the Threat Intel page discloses as a real limitation on how much
// industry-based contrast this 2-tenant demo can actually show.
//
// Both tenants deliberately carry every real infra asset type (see
// remediation/enrichment/infra_classification.py's _ASSET_TYPE_TO_INFRA_CATEGORY) so
// /infrastructure's own 11 sub-category cards show real, non-zero counts under either
// tenant, not empty "0 - no sample finding yet" tiles - a demo with every card reading
// zero looks broken, not illustrative. The remaining differentiation between them is
// AppSec/Certificate scope: only Northwind Bank carries `application`/`certificate`
// asset types, so Acme reads as an infra-only client and Northwind as a full-stack one.
export const TENANTS = {
  all: {
    id: "all", label: "All Tenants (MSSP view)", assetTypes: null, industry: null,
    initials: null, avatarColor: "#4b5563", location: null,
  },
  acme: {
    id: "acme",
    label: "Acme Financial Corp (demo)",
    assetTypes: [
      "windows-server", "unix-server", "network-routing-switching", "network-security-device",
      "cloud-infrastructure", "client-application", "iac-resource", "container-runtime",
      "windows-endpoint", "mobile-device", "printer", "virtualization-host",
    ],
    industry: "Financial Services",
    initials: "AF", avatarColor: "#2563eb", location: "New York, USA",
  },
  northwind: {
    id: "northwind",
    label: "Northwind Bank (demo)",
    assetTypes: [
      "application", "certificate", "iot-ot-device",
      "windows-server", "unix-server", "network-routing-switching", "network-security-device",
      "cloud-infrastructure", "client-application", "iac-resource", "container-runtime",
      "windows-endpoint", "mobile-device", "printer", "virtualization-host",
    ],
    industry: "Financial Services",
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

// Shared "you're not looking at everything" disclosure - every page that applies
// filterByTenant() to what it shows renders this so a card/count here never silently
// disagrees with what the same tenant selection shows on another page (e.g. an
// Infrastructure hub card reading "1096" while a non-matching tenant is selected, only
// to land on 0 results after clicking through to the Queue).
export function tenantBannerHtml() {
  const tenant = getTenant();
  if (tenant.id === "all") return "";
  return `
    <div class="callout callout-warn">
      Viewing as <strong>${escapeHtml(tenant.label)}</strong> - illustrative MSSP demo
      view (partitions the same real findings by asset category). Not real
      per-tenant data isolation - see the <a href="/faq" data-link>FAQ</a>.
    </div>`;
}
