// Renders the sidebar: brand mark and the nav groups - each item gets a real vector
// icon and a hover tooltip explaining what it does. The (demo) tenant switcher used to
// live here too; it now renders in the topbar's far-right slot (see topbarTenant.js).
import { icon } from "./icons.js";
import { wireSidebarScroll } from "./sidebarScroll.js";

// Exported so commandPalette.js can reuse this exact list (one definition, not a
// second, potentially-drifting copy of every real route) for its own Ctrl/Cmd+K
// instant-navigation search.
export const NAV = [
  { group: "Overview", items: [
    { path: "/", label: "Dashboard", icon: "dashboard", exact: true,
      tip: "KPIs, SLA status, and coverage across both pipelines at a glance." },
    { path: "/ai-assist", label: "AI Assist", icon: "ai",
      tip: "Ask Claude to explain a finding or draft remediation guidance - preview free, confirm to spend." },
    { path: "/ask", label: "Ask Quanta", icon: "search",
      tip: "Free, real search over your live data - findings, CVEs, assets, real counts. No AI call, no cost, never fabricates." },
    { path: "/inbox", label: "Inbox", icon: "bell",
      tip: "Real system-generated notifications - SLA breaches, KEV, expiring exceptions - not person-to-person messages." },
  ] },
  { group: "Threat Intelligence", items: [
    { path: "/threat-intel", label: "Threat Intel", icon: "risk",
      tip: "Zero-days, top vulnerabilities, and MITRE-documented threat-actor groups relevant to the selected tenant's industry - built from data already tagged elsewhere in this app." },
  ] },
  // SAST/DAST/Secrets/SCA/Container/API are deliberately NOT separate top-level
  // entries here anymore - they're sub-listings shown as cards on the Application
  // Vulnerabilities hub page (/appsec) only, so the main menu shows one entry per
  // real domain instead of every sub-category flattened into the sidebar. Same
  // reasoning for Infrastructure Vulnerabilities' OS/Network/Network Security/OT/
  // Cloud split, now a hub page (/infrastructure) instead of a single flat link.
  { group: "Security Domains", items: [
    { path: "/appsec", label: "Application Vulnerabilities", icon: "appsec",
      tip: "Hub view across SAST, DAST, SCA, Secrets, Container, and API sub-categories - counts and links into each." },
    { path: "/infrastructure", label: "Infrastructure Vulnerabilities", icon: "infra",
      tip: "Hub view across OS, Network, Network Security, OT/IoT, and Cloud sub-categories (Tenable/Armis-style asset scanning)." },
    { path: "/ot-vulnerabilities", label: "OT Vulnerabilities", icon: "container",
      tip: "Dedicated hub for Operational Technology/IoT device findings (PLCs, SCADA/HMI, building automation, cameras, sensor gateways) - the same real data as Infrastructure Vulnerabilities' own OT/IoT sub-category, broken out for teams who own OT/ICS specifically." },
    { path: "/ai-vulnerabilities", label: "AI Vulnerabilities", icon: "aiVuln",
      tip: "Prompt injection, model poisoning, and other AI/ML risks - with an illustrative MITRE ATLAS heat map, summaries, and remediation guidance." },
    { path: "/certificate-vulnerabilities", label: "Certificate Vulnerabilities", icon: "certmgmt",
      tip: "Hub view for Certificate & TLS Lifecycle Management findings - KPIs, severity/aging charts, top rankings, and AI trend analysis, same shape as the other Security Domains hubs." },
    { path: "/quantum-readiness", label: "Quantum Readiness", icon: "quantum",
      tip: "Real findings naming classical RSA/ECDSA/Diffie-Hellman crypto or a legacy TLS/cipher weakness - a post-quantum migration inventory against real NIST FIPS 203/204/205 + NIST IR 8547 guidance." },
  ] },
  { group: "Remediation Engine", items: [
    { path: "/quanta-scan", label: "Code Scan", icon: "scan",
      tip: "Source-code findings from /quanta-scan - agentless static analysis, no target install." },
    { path: "/queue", label: "Remediation Queue", icon: "queue",
      tip: "The live, re-scored queue - priority, SLA, KEV/EPSS, and ATT&CK tags per finding." },
    { path: "/remediate", label: "Remediation Plan", icon: "plan",
      tip: "The static plan snapshot from the last /remediate run, linked to generated playbooks." },
    { path: "/remediation-approvals", label: "Remediation Approvals", icon: "exception",
      tip: "Human-in-the-loop approve/reject for normal/emergency-change-type findings - AD-group-validated when Active Directory is configured." },
  ] },
  { group: "Ownership & Assignment", items: [
    { path: "/assignments", label: "Assignments", icon: "ownership",
      tip: "The work queue: findings assigned to you, routed to your team, or still waiting for an owner - assign, track status, and hand off, like an ITSM ticket queue." },
    { path: "/ownership", label: "Ownership Analytics", icon: "reports",
      tip: "Who and which team carries how much of the backlog - open, critical, breaching SLA, unowned - with ageing and workload balance." },
  ] },
  { group: "Risk Management", items: [
    { path: "/ml-insights", label: "ML Insights", icon: "ml",
      tip: "Real, live-trained scikit-learn models (IsolationForest anomaly detection, KMeans risk clustering) - unsupervised, advisory, and never a replacement for the deterministic policy/priority engines." },
    { path: "/risk", label: "Risk Dashboard", icon: "risk",
      tip: "MITRE ATT&CK heat map, top critical assets, and internal/external-facing exposure." },
    { path: "/risk/blast-radius", label: "Blast Radius", icon: "blastRadius",
      tip: "If this asset is compromised, how far does the damage spread - business criticality and reachability, cross-referenced against real exploitability. Honestly scoped: 2 of 4 real profiling dimensions aren't measurable with this app's data yet." },
    { path: "/vulnerability-mapping", label: "Vulnerability Mapping", icon: "risk",
      tip: "Which real vulnerabilities hit the most assets, ranked and clickable." },
    { path: "/asset-mapping", label: "Asset Mapping", icon: "assets",
      tip: "Which real assets carry the most distinct vulnerabilities, ranked and clickable." },
    { path: "/compensating-controls", label: "Compensating Controls", icon: "exception",
      tip: "Findings that can't be remediated right now - Critical EOL/EOS, actively-exploited zero-days with no public POC, or an approved exception - with recommended controls for each." },
    { path: "/attack-paths", label: "Attack Chains", icon: "risk",
      tip: "Findings on the same asset chained by tagged MITRE ATT&CK tactic into entry -> pivot -> impact - fix the pivot to break the whole chain. Heuristic, not runtime-validated." },
    { path: "/dependencies", label: "Dependencies", icon: "assets",
      tip: "SBOM-derived blast radius per vulnerable open-source package - which findings trace to it, its confirmed fixed version, and every other component still exposed until it's upgraded." },
    { path: "/exceptions", label: "Exceptions", icon: "exception",
      tip: "Request, approve, and track time-boxed risk-acceptance waivers per finding." },
    { path: "/assets", label: "Asset Inventory", icon: "assets",
      tip: "Every asset with findings against it, aggregated, with an editable owner/team." },
    { path: "/activity-log", label: "Activity Log", icon: "clock",
      tip: "Real who/what/when audit trail - every asset edit, approval decision, exception revocation, and login attempt in this app." },
  ] },
  { group: "Configuration", items: [
    { path: "/priority-rules", label: "Priority Rules", icon: "rules",
      tip: "Tune severity/asset/KEV/EPSS weights and SLA windows - takes effect immediately." },
    { path: "/exploit-criteria", label: "Exploit Criteria", icon: "aiVuln",
      tip: "Define which real KEV/POC/EPSS signal combinations count as a 'zero-day criteria' match - customizable per client, takes effect immediately." },
    { path: "/notification-settings", label: "Notification Settings", icon: "mail",
      tip: "Schedule sub-domain/team-wise reports (weekly-yearly) and critical/zero-day/threat-intel email alerts - requires real SMTP configuration to actually send." },
    { path: "/remediation-policy", label: "Remediation Policy", icon: "rules",
      tip: "Cadence, ITIL 4 change type, maintenance windows, and PAM backend per remediation domain - the real config driving the Remediation Queue's approval/auto-remediate treatment." },
    { path: "/asset-policy", label: "Asset Policy", icon: "rules",
      tip: "Bulk, rule-based asset owner/team/environment/facing/remediation-schedule editing - match a group of real assets and set fields on all of them in one action." },
    { path: "/admin/people", label: "Users & Teams", icon: "users",
      tip: "Admin-only: user accounts and roles, team records and managers, who is on which team, each person's live workload, and the auto-routing rule." },
    { path: "/admin", label: "Admin Settings", icon: "rules",
      tip: "Admin-only: which real Claude Code model to use, per-user daily token limits (enforced server-side), real usage/cost by user, and read-only system health." },
  ] },
  // A single hub instead of four separate "Adaptors — X" groups (was: Ticketing/SOAR,
  // SIEM, XDR/EDR, Asset Discovery/IPAM as four flat sidebar sections) - /adaptors has
  // a dropdown/filter selecting among all of them (6 with a working preview + a broad
  // researched-but-not-yet-wired-up catalog), consistent settings panel reflecting
  // whichever one is selected. See adaptorCatalog.js.
  { group: "Connectors / Adaptors", items: [
    { path: "/connections", label: "Connections", icon: "adaptor",
      tip: "Admin: store your scanner and asset-source credentials (encrypted) and schedule automatic syncs." },
    { path: "/grc", label: "Risk & Compliance", icon: "rules",
      tip: "Admin: control framework coverage with automated evidence, the risk register, attestations and policies. Evidence and workflow; not a certification." },
    { path: "/cyber-risk", label: "Cyber Risk", icon: "rules",
      tip: "Admin: risk in money. Loss scenarios simulated into an average and a bad-year loss, which treatment is worth its cost, and a cyber health score." },
    { path: "/devsecops", label: "DevSecOps", icon: "rules",
      tip: "The controls a secure delivery pipeline needs, where each repository stands from uploaded scans and pipeline checks, a policy-to-control check, and the code fix queue." },
    { path: "/zero-day-watch", label: "Zero-day Watch", icon: "rules",
      tip: "Newly exploited vulnerabilities (CISA KEV) in products your estate appears to run that no scanner has reported yet. A name match, not a version check." },
    { path: "/firewall", label: "Firewall Rules", icon: "rules",
      tip: "Firewall rules from your exports: broad, unused, shadowed and internet-exposed rules, recertification by owner, and access requests checked against the rules. Quanta never changes a firewall." },
    { path: "/soar", label: "SOAR Playbooks", icon: "rules",
      tip: "Admin: playbooks that investigate, notify and ask your own automation to respond, with a second person approving anything that changes your environment. Dry run first." },
    { path: "/hunting", label: "Hunting & SOC", icon: "rules",
      tip: "Admin: hunts proposed from known-exploited vulnerabilities in your estate, a hunt workspace, and alert triage with vulnerability context and runbooks. Not a SIEM." },
    { path: "/threat-models", label: "Threat Models", icon: "rules",
      tip: "Admin: describe a system, get STRIDE threats raised by explicit rules, each joined to the live findings and security controls on its assets." },
    { path: "/ai-usage", label: "AI Usage", icon: "rules",
      tip: "Admin: AI spend and tokens across the organization by team, application and model, budgets, unusual days, and AI tools nobody reviewed." },
    { path: "/controls", label: "Security Controls", icon: "rules",
      tip: "Which firewalls, EDR, WAF and other controls protect which assets - what makes compensating-control advice specific to you." },
    { path: "/adaptors", label: "Connectors / Adaptors", icon: "adaptor",
      tip: "Every external system Quanta talks to (or has researched), in one place - pick a connector from the dropdown." },
  ] },
  { group: "Operations", items: [
    { path: "/run", label: "Run Pipeline", icon: "run",
      tip: "Trigger /quanta-scan or /remediate - dry-run preview by default." },
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

  el.innerHTML = `
    <a class="brand" href="/" data-link data-tooltip="Quanta - AI-driven vulnerability detection &amp; remediation">
      <span class="brand-mark">${LOGO_SVG}</span>
      <span class="brand-text">Quanta</span>
    </a>

    <button type="button" class="side-nav-scroll side-nav-scroll-up" data-nav-scroll="up" aria-label="Scroll navigation up">
      <span style="display:flex; transform:rotate(180deg)">${icon("chevronDown", 14)}</span>
    </button>
    <nav class="side-nav">${groupsHtml}</nav>
    <button type="button" class="side-nav-scroll side-nav-scroll-down" data-nav-scroll="down" aria-label="Scroll navigation down">
      ${icon("chevronDown", 14)}
    </button>
    <div class="sidebar-footer">
      <a href="/faq" data-link>Scope &amp; limitations</a>
    </div>`;

  wireSidebarScroll();
}

const LOGO_SVG = `<svg viewBox="0 0 64 64" width="22" height="22" xmlns="http://www.w3.org/2000/svg">
  <path d="M32 4 L56.5 18 L56.5 46 L32 60 L7.5 46 L7.5 18 Z" fill="#2f6fed"/>
  <circle cx="32" cy="32" r="11" fill="none" stroke="#ffffff" stroke-width="3.6"/>
  <path d="M32 20V16M32 44V48M20 32H16M44 32H48" fill="none" stroke="#ffffff" stroke-width="4" stroke-linecap="round"/>
</svg>`;
