// Renders the sidebar: brand mark, the (demo) tenant switcher, and the nav groups -
// each item gets a real vector icon and a hover tooltip explaining what it does.
import { icon } from "./icons.js";
import { listTenants, getTenant, setTenant } from "./tenant.js";

const NAV = [
  { group: "Overview", items: [
    { path: "/", label: "Dashboard", icon: "dashboard", exact: true,
      tip: "KPIs, SLA status, and coverage across both pipelines at a glance." },
    { path: "/ai-assist", label: "AI Assist", icon: "ai",
      tip: "Ask Claude to explain a finding or draft remediation guidance - preview free, confirm to spend." },
    { path: "/inbox", label: "Inbox", icon: "bell",
      tip: "Real system-generated notifications - SLA breaches, KEV, expiring exceptions - not person-to-person messages." },
  ] },
  { group: "Security Domains", items: [
    { path: "/appsec", label: "Application Vulnerabilities", icon: "appsec",
      tip: "Hub view across SAST, DAST, SCA, and secrets-in-code - counts and links into each." },
    { path: "/queue?category=infra-vm", label: "Infrastructure Vulnerabilities", icon: "infra",
      tip: "Remediation Queue pre-filtered to Infrastructure Vulnerability Management findings (Tenable/Armis-style asset scanning)." },
    { path: "/vulnhunt", label: "SAST (Static Application Security Testing)", icon: "scan",
      tip: "Static Application Security Testing - this is the Code Scan page (source code, no target install)." },
    { path: "/queue?category=dast", label: "DAST (Dynamic Application Security Testing)", icon: "dast",
      tip: "Remediation Queue pre-filtered to Dynamic Application Security Testing findings - no sample data yet, see the FAQ." },
    { path: "/vulnhunt?category=Secrets", label: "Secrets Management", icon: "secrets",
      tip: "Code Scan pre-filtered to hardcoded-secret findings (CWE-798)." },
    { path: "/queue?category=sca", label: "SCA (Software Composition Analysis)", icon: "sca",
      tip: "Remediation Queue pre-filtered to Software Composition Analysis findings (vulnerable third-party/bundled libraries)." },
    { path: "/queue?category=cert-mgmt", label: "Certificate Vulnerabilities", icon: "certmgmt",
      tip: "Remediation Queue pre-filtered to Certificate & TLS Lifecycle Management findings." },
    { path: "/vulnhunt?category=Container", label: "Container Vulnerabilities", icon: "container",
      tip: "Code Scan pre-filtered to base-image/Dockerfile findings (root user, baked-in secrets, unpinned tags)." },
    { path: "/vulnhunt?category=API", label: "API Vulnerabilities", icon: "api",
      tip: "Code Scan pre-filtered to API-security findings (missing auth, permissive CORS, mass assignment) - no sample data yet, see the FAQ." },
  ] },
  { group: "Remediation Engine", items: [
    { path: "/vulnhunt", label: "Code Scan", icon: "scan",
      tip: "Source-code findings from /vulnhunt - agentless static analysis, no target install." },
    { path: "/queue", label: "Remediation Queue", icon: "queue",
      tip: "The live, re-scored queue - priority, SLA, KEV/EPSS, and ATT&CK tags per finding." },
    { path: "/remediate", label: "Remediation Plan", icon: "plan",
      tip: "The static plan snapshot from the last /remediate run, linked to generated playbooks." },
  ] },
  { group: "Risk Management", items: [
    { path: "/risk", label: "Risk Dashboard", icon: "risk",
      tip: "MITRE ATT&CK heat map, top critical assets, and internal/external-facing exposure." },
    { path: "/exceptions", label: "Exceptions", icon: "exception",
      tip: "Request, approve, and track time-boxed risk-acceptance waivers per finding." },
    { path: "/assets", label: "Asset Inventory", icon: "assets",
      tip: "Every asset with findings against it, aggregated, with an editable owner/team." },
  ] },
  { group: "Configuration", items: [
    { path: "/priority-rules", label: "Priority Rules", icon: "rules",
      tip: "Tune severity/asset/KEV/EPSS weights and SLA windows - takes effect immediately." },
  ] },
  { group: "Adaptors — Ticketing / SOAR", items: [
    { path: "/servicenow", label: "ServiceNow", icon: "servicenow",
      tip: "Ticketing - preview or create ServiceNow Incidents per finding via the Table API." },
    { path: "/jira", label: "Jira", icon: "jira",
      tip: "Ticketing - preview or create Jira issues per finding via the REST API v3." },
  ] },
  { group: "Adaptors — SIEM", items: [
    { path: "/splunk", label: "Splunk", icon: "splunk",
      tip: "SIEM - preview or send findings to Splunk as HTTP Event Collector events." },
  ] },
  { group: "Adaptors — XDR / EDR", items: [
    { path: "/xdr", label: "CrowdStrike Falcon", icon: "xdr",
      tip: "Pull alerts from CrowdStrike Falcon and normalize them into findings - reference page, CLI/connector-driven like Tenable/Armis." },
  ] },
  { group: "Adaptors — Asset Discovery / IPAM", items: [
    { path: "/infoblox", label: "Infoblox", icon: "infoblox",
      tip: "Pull DNS host records from Infoblox NIOS (WAPI) and normalize them into asset inventory - reference page, connector-driven." },
    { path: "/axonius", label: "Axonius", icon: "axonius",
      tip: "Pull aggregated device records from Axonius cyber asset management and normalize them into asset inventory - reference page, connector-driven." },
  ] },
  { group: "Operations", items: [
    { path: "/run", label: "Run Pipeline", icon: "run",
      tip: "Trigger /vulnhunt or /remediate - dry-run preview by default." },
    { path: "/reports", label: "Reports", icon: "reports",
      tip: "Generate a shareable KPI/SLA/coverage report snapshot." },
  ] },
  { group: "Help", items: [
    { path: "/support", label: "Support", icon: "support",
      tip: "How to get help, report a bug, and where the deeper docs live." },
    { path: "/faq", label: "FAQ", icon: "faq",
      tip: "Direct answers about what this product does and doesn't do (yet)." },
  ] },
];

// Splits a nav item's path (which may include a deep-link query string, e.g.
// "/queue?category=infra-vm") into its pathname and search parts so active-highlighting
// can require an exact query match - otherwise every "/queue?category=X" item would
// highlight together whenever any of them is active.
function splitItemPath(path) {
  const qIdx = path.indexOf("?");
  return qIdx === -1 ? { pathname: path, search: "" } : { pathname: path.slice(0, qIdx), search: path.slice(qIdx) };
}

export function renderSidebar(currentPath, currentSearch = "") {
  const el = document.getElementById("sidebar");
  const groupsHtml = NAV.map((group) => {
    const itemsHtml = group.items.map((item) => {
      const { pathname, search } = splitItemPath(item.path);
      const active = item.exact
        ? currentPath === pathname
        : currentPath === pathname && currentSearch === search;
      return `<a href="${item.path}" data-link data-tooltip="${item.tip}" class="${active ? "active" : ""}">` +
        `<span class="nav-icon">${icon(item.icon, 17)}</span><span class="nav-label">${item.label}</span></a>`;
    }).join("");
    return `<div class="nav-group"><div class="nav-group-label">${group.group}</div>${itemsHtml}</div>`;
  }).join("");

  const tenant = getTenant();
  const tenantOptions = listTenants().map((t) =>
    `<option value="${t.id}" ${t.id === tenant.id ? "selected" : ""}>${t.label}</option>`).join("");

  // A generated initials avatar (colored circle, like GitHub/Slack show for an org
  // with no uploaded logo) rather than a fabricated real company logo - see
  // tenant.js's comment on why. "All Tenants" has no single logo/location, so it falls
  // back to the generic tenant glyph and hides the location line entirely.
  const avatarHtml = tenant.initials
    ? `<div class="tenant-avatar" style="background:${tenant.avatarColor}">${tenant.initials}</div>`
    : `<div class="tenant-avatar tenant-avatar-generic" style="background:${tenant.avatarColor}">${icon("tenant", 14)}</div>`;
  const locationHtml = tenant.location
    ? `<div class="tenant-location">${icon("pin", 11)} ${tenant.location}</div>` : "";

  el.innerHTML = `
    <a class="brand" href="/" data-link data-tooltip="VulnHunter - AI-driven vulnerability detection &amp; remediation">
      <span class="brand-mark">${LOGO_SVG}</span>
      <span class="brand-text">VulnHunter</span>
    </a>

    <div class="tenant-switcher" data-tooltip="Illustrative MSSP demo (applies to the Remediation Queue) - not real per-tenant data isolation, logo/location are demo placeholders">
      ${avatarHtml}
      <div class="tenant-info">
        <select id="tenant-select" aria-label="Tenant (demo)">${tenantOptions}</select>
        ${locationHtml}
      </div>
    </div>

    <nav class="side-nav">${groupsHtml}</nav>
    <div class="sidebar-footer">
      <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/dashboard/README.md"
         target="_blank" rel="noopener">Scope &amp; limitations ↗</a>
    </div>`;

  document.getElementById("tenant-select").addEventListener("change", (e) => {
    setTenant(e.target.value);
    renderSidebar(window.location.pathname, window.location.search);
  });
}

const LOGO_SVG = `<svg viewBox="0 0 64 64" width="22" height="22" xmlns="http://www.w3.org/2000/svg">
  <path d="M32 3.5 L57 13.5 V31 C57 46.5 46.5 57.5 32 61 C17.5 57.5 7 46.5 7 31 V13.5 Z" fill="#16a34a"/>
  <circle cx="27" cy="27" r="11" fill="none" stroke="#ffffff" stroke-width="3.6"/>
  <line x1="35.2" y1="35.2" x2="45" y2="45" stroke="#ffffff" stroke-width="4" stroke-linecap="round"/>
</svg>`;
