// Renders the sidebar and highlights whichever section matches the current path.
// A plain data table instead of duplicating this markup in every page's HTML.

const NAV = [
  { group: "Overview", items: [{ path: "/", label: "Dashboard", icon: "◈", exact: true }] },
  { group: "Security", items: [
    { path: "/vulnhunt", label: "Code Scan", icon: "⌥" },
    { path: "/queue", label: "Remediation Queue", icon: "▤" },
    { path: "/remediate", label: "Remediation Plan", icon: "▦" },
  ] },
  { group: "Configuration", items: [{ path: "/priority-rules", label: "Priority Rules", icon: "⚙" }] },
  { group: "Integrations", items: [{ path: "/servicenow", label: "ServiceNow", icon: "⇄" }] },
  { group: "Operations", items: [{ path: "/run", label: "Run Pipeline", icon: "▶" }] },
];

export function renderSidebar(currentPath) {
  const el = document.getElementById("sidebar");
  const groupsHtml = NAV.map((group) => {
    const itemsHtml = group.items.map((item) => {
      const active = item.exact ? currentPath === item.path : currentPath.startsWith(item.path);
      return `<a href="${item.path}" data-link class="${active ? "active" : ""}">` +
        `<span class="nav-icon">${item.icon}</span> ${item.label}</a>`;
    }).join("");
    return `<div class="nav-group"><div class="nav-group-label">${group.group}</div>${itemsHtml}</div>`;
  }).join("");

  el.innerHTML = `
    <a class="brand" href="/" data-link>
      <span class="brand-mark">🔍🛡️</span>
      <span class="brand-text">VulnHunter</span>
    </a>
    <nav class="side-nav">${groupsHtml}</nav>
    <div class="sidebar-footer">
      <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/dashboard/README.md"
         target="_blank" rel="noopener">Scope &amp; limitations ↗</a>
    </div>`;
}
