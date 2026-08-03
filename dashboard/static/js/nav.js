// Renders the sidebar: brand mark, the (demo) tenant switcher, and the nav groups -
// each item gets a real vector icon and a hover tooltip explaining what it does.
import { icon } from "./icons.js";
import { listTenants, getTenant, setTenant } from "./tenant.js";

const NAV = [
  { group: "Overview", items: [
    { path: "/", label: "Dashboard", icon: "dashboard", exact: true,
      tip: "KPIs, SLA status, and coverage across both pipelines at a glance." },
  ] },
  { group: "Security", items: [
    { path: "/vulnhunt", label: "Code Scan", icon: "scan",
      tip: "Source-code findings from /vulnhunt - agentless static analysis, no target install." },
    { path: "/queue", label: "Remediation Queue", icon: "queue",
      tip: "The live, re-scored queue - priority, SLA, KEV/EPSS, and ATT&CK tags per finding." },
    { path: "/remediate", label: "Remediation Plan", icon: "plan",
      tip: "The static plan snapshot from the last /remediate run, linked to generated playbooks." },
  ] },
  { group: "Intelligence", items: [
    { path: "/ai-assist", label: "AI Assist", icon: "ai",
      tip: "Ask Claude to explain a finding or draft remediation guidance - preview free, confirm to spend." },
  ] },
  { group: "Configuration", items: [
    { path: "/priority-rules", label: "Priority Rules", icon: "rules",
      tip: "Tune severity/asset/KEV/EPSS weights and SLA windows - takes effect immediately." },
  ] },
  { group: "Integrations", items: [
    { path: "/servicenow", label: "ServiceNow", icon: "servicenow",
      tip: "Preview or create ServiceNow Incidents per finding via the Table API." },
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

export function renderSidebar(currentPath) {
  const el = document.getElementById("sidebar");
  const groupsHtml = NAV.map((group) => {
    const itemsHtml = group.items.map((item) => {
      const active = item.exact ? currentPath === item.path : currentPath.startsWith(item.path);
      return `<a href="${item.path}" data-link data-tooltip="${item.tip}" class="${active ? "active" : ""}">` +
        `<span class="nav-icon">${icon(item.icon, 17)}</span> ${item.label}</a>`;
    }).join("");
    return `<div class="nav-group"><div class="nav-group-label">${group.group}</div>${itemsHtml}</div>`;
  }).join("");

  const tenant = getTenant();
  const tenantOptions = listTenants().map((t) =>
    `<option value="${t.id}" ${t.id === tenant.id ? "selected" : ""}>${t.label}</option>`).join("");

  el.innerHTML = `
    <a class="brand" href="/" data-link data-tooltip="VulnHunter - AI-driven vulnerability detection &amp; remediation">
      <span class="brand-mark">${LOGO_SVG}</span>
      <span class="brand-text">VulnHunter</span>
    </a>

    <div class="tenant-switcher" data-tooltip="Illustrative MSSP demo (applies to the Remediation Queue) - not real per-tenant data isolation">
      <span class="nav-icon">${icon("tenant", 15)}</span>
      <select id="tenant-select" aria-label="Tenant (demo)">${tenantOptions}</select>
    </div>

    <nav class="side-nav">${groupsHtml}</nav>
    <div class="sidebar-footer">
      <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/dashboard/README.md"
         target="_blank" rel="noopener">Scope &amp; limitations ↗</a>
    </div>`;

  document.getElementById("tenant-select").addEventListener("change", (e) => {
    setTenant(e.target.value);
  });
}

const LOGO_SVG = `<svg viewBox="0 0 64 64" width="22" height="22" xmlns="http://www.w3.org/2000/svg">
  <path d="M32 3.5 L57 13.5 V31 C57 46.5 46.5 57.5 32 61 C17.5 57.5 7 46.5 7 31 V13.5 Z" fill="#16a34a"/>
  <circle cx="27" cy="27" r="11" fill="none" stroke="#ffffff" stroke-width="3.6"/>
  <line x1="35.2" y1="35.2" x2="45" y2="45" stroke="#ffffff" stroke-width="4" stroke-linecap="round"/>
</svg>`;
