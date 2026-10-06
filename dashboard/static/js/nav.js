// Renders the sidebar: the brand mark, a small Home block and ONE module at a time. Everything the app does is
// grouped into eight modules. With no module chosen the sidebar is a picker (the modules, one line each). Once a
// module is chosen - by opening it, or by opening any page that belongs to it - the sidebar shows only that
// module: its pages, then the connectors that feed it. The other modules are not listed; "Switch module" opens
// them on request. The choice is remembered. A module the licence does not cover is shown locked in the picker
// and never opens. The same module ids are in remediation/config/capabilities.yaml (the "All modules" page) and
// remediation/config/licensing.yaml (which API prefixes belong to which module); tests keep them in step.
import { icon } from "./icons.js";
import { wireSidebarScroll } from "./sidebarScroll.js";

// Exported so commandPalette.js can reuse this exact list (one definition, not a second, potentially
// drifting copy of every real route) for its own Ctrl/Cmd+K instant-navigation search.
export const NAV = [
  { group: "Home", id: "home", items: [
    { path: "/", label: "Dashboard", icon: "dashboard", exact: true, tip: "KPIs, SLA status, and coverage across both pipelines at a glance." },
    { path: "/capabilities", label: "All modules", icon: "rules", tip: "Pick what you want to do - vulnerability management, cyber risk, detection and hunting, the L1 SOC with SOAR, and more - and open the pages that belong to it." },
    { path: "/ask", label: "Ask Quanta", icon: "search", tip: "Free, real search over your live data - findings, CVEs, assets, real counts. No AI call, no cost, never fabricates." },
    { path: "/ai-assist", label: "AI Assist", icon: "ai", tip: "Ask Claude to explain a finding or draft remediation guidance - preview free, confirm to spend." },
    { path: "/inbox", label: "Inbox", icon: "bell", tip: "Real system-generated notifications - SLA breaches, KEV, expiring exceptions - not person-to-person messages." },
  ] },
  { group: "Threat Detection & Response", id: "soc", number: "1", icon: "signal", summary: "The SOC in one place: triage alerts, hunt, engineer detections, run threat intelligence and respond through playbooks that need a second person for anything that changes your environment.", items: [
    { path: "/capabilities?area=soc", label: "Module overview", icon: "dashboard", tip: "The SOC in one place: triage alerts, hunt, engineer detections, run threat intelligence and respond through playbooks that need a second person for anything that changes your environment." },
    { path: "/graphs?module=soc", label: "Relationship graph", feature: "relationship-graphs", icon: "blastRadius", tip: "How the things in this module are connected, drawn from what Quanta has recorded, with clusters, choke points and single points of failure worked out from the links." },
    { path: "/soc", label: "SOC Operations", icon: "rules", tip: "Admin: cases in L1, L2 and L3 queues with priority, service-level clocks, escalation with hand-off notes, case summaries, log investigation, technique identification and SOC metrics." },
    { path: "/hunting?tab=alerts", label: "Alert Triage", icon: "signal", tip: "Alerts from your SIEM or XDR ranked with vulnerability context, investigated step by step, with a recommended verdict a person validates." },
    { path: "/hunting?tab=suggested", label: "Threat Hunting", icon: "search", tip: "Hypothesis-driven hunt suggestions from your intel, alerts, exposure, identities and detection gaps, each with the reason, queries to run in your own SIEM and verdicts that need an outcome to close." },
    { path: "/hunting?tab=detections", label: "Detection Engineering", icon: "rules", tip: "Per-rule health from analyst outcomes, ATT&CK coverage gaps, and tuning suggestions with before and after." },
    { path: "/threat-intel", label: "Threat Intelligence", icon: "risk", tip: "Zero-days, top vulnerabilities, and MITRE-documented threat-actor groups relevant to the selected tenant's industry - built from data already tagged elsewhere in this app." },
    { path: "/hunting?tab=intel", label: "Intel Intake", icon: "document", tip: "Paste a report or send STIX; Quanta extracts the CVEs, techniques and indicators and scores how much it matters to your estate." },
    { path: "/dark-web-watch", label: "Dark Web Watch", icon: "rules", tip: "Admin: ransomware leak-site feeds and credential-exposure lookups matched against your domains and brands, plus import of crawler and platform output. Hits raise SOC alerts. Quanta never touches Tor." },
    { path: "/soar", label: "SOAR Playbooks", icon: "rules", tip: "Admin: playbooks that investigate, notify and ask your own automation to respond, with a second person approving anything that changes your environment. Dry run first." },
  ], connectors: [
    { path: "/splunk", label: "Splunk", icon: "adaptor", tip: "Send findings to Splunk HEC; search it for hunts and triage" },
    { path: "/cortex-xsiam", label: "Cortex XSIAM", icon: "adaptor", tip: "Pull correlated incidents" },
    { path: "/xdr", label: "CrowdStrike (XDR)", icon: "adaptor", tip: "Reference page for endpoint detections" },
    { path: "/connections", label: "Search, reputation and response endpoints", icon: "adaptor", tip: "Splunk search, VirusTotal, notification and response webhooks" },
  ] },
  { group: "Application Security", id: "appsec", number: "2", icon: "appsec", summary: "Everything found in your own applications: static and dynamic testing, secrets, containers, APIs and the threats to a design, with fixes handed to developers.", items: [
    { path: "/capabilities?area=appsec", label: "Module overview", icon: "dashboard", tip: "Everything found in your own applications: static and dynamic testing, secrets, containers, APIs and the threats to a design, with fixes handed to developers." },
    { path: "/graphs?module=appsec", label: "Relationship graph", feature: "relationship-graphs", icon: "blastRadius", tip: "How the things in this module are connected, drawn from what Quanta has recorded, with clusters, choke points and single points of failure worked out from the links." },
    { path: "/appsec", label: "Application Vulnerabilities", icon: "appsec", tip: "Hub view across SAST, DAST, SCA, Secrets, Container, and API sub-categories - counts and links into each." },
    { path: "/quanta-scan", label: "Code Scan", icon: "scan", tip: "Source-code findings from /quanta-scan - agentless static analysis, no target install." },
    { path: "/api-security", label: "API Security", icon: "rules", tip: "Admin: API inventory from specifications and access logs, OWASP API Top 10 findings with evidence and a request to confirm each, caller activity, your data classes, and protection policies sent as signed requests to an endpoint you own. Quanta changes no firewall." },
    { path: "/threat-models", label: "Threat Models", icon: "rules", tip: "Admin: describe a system, get STRIDE threats raised by explicit rules, each joined to the live findings and security controls on its assets." },
  ], connectors: [
    { path: "/connections", label: "Scanner uploads (SARIF, coverage) and API keys", icon: "adaptor", tip: "Semgrep, CodeQL, ZAP, Trivy and others push results; gateways push API traffic" },
    { path: "/prismacloud", label: "Prisma Cloud", icon: "adaptor", tip: "Code and cloud posture findings" },
  ] },
  { group: "DevSecOps & Supply Chain", id: "devsecops", number: "3", icon: "iac", summary: "The delivery pipeline: the controls it needs, SBOMs and the dependency graph, fix pull requests and the release gate.", items: [
    { path: "/capabilities?area=devsecops", label: "Module overview", icon: "dashboard", tip: "The delivery pipeline: the controls it needs, SBOMs and the dependency graph, fix pull requests and the release gate." },
    { path: "/graphs?module=devsecops", label: "Relationship graph", feature: "relationship-graphs", icon: "blastRadius", tip: "How the things in this module are connected, drawn from what Quanta has recorded, with clusters, choke points and single points of failure worked out from the links." },
    { path: "/devsecops", label: "Control Library", icon: "rules", tip: "The controls a secure delivery pipeline needs, where each repository stands from uploaded scans and pipeline checks, a policy-to-control check, and the code fix queue." },
    { path: "/devsecops?tab=queue", label: "Code Fix Queue", icon: "queue", tip: "Static analysis, dependency, secret and infrastructure-as-code findings tracked with a fix brief until a later scan stops reporting them." },
    { path: "/applications", label: "Applications & SBOM", icon: "assets", tip: "Each application with its SBOM, an interactive dependency and exposure graph, and its findings ranked with the upgrade that closes the most. Generate or upload the SBOM, check it against public advisories, and propose the fix." },
    { path: "/dependencies", label: "Dependencies", icon: "assets", tip: "SBOM-derived blast radius per vulnerable open-source package - which findings trace to it, its confirmed fixed version, and every other component still exposed until it's upgraded." },
    { path: "/fix-prs", label: "Fix Pull Requests", icon: "rules", tip: "Admin: dependency upgrades and code fixes as reviewable pull requests on your Git host, with the evidence in the description. Dry run first; Quanta never merges. Tracks review, merge and verification, and how fast fixes move." },
    { path: "/pipeline-gates", label: "Pipeline Gates", icon: "rules", tip: "The release gate a CI job calls before shipping: pass, warn or fail with reasons, per environment, from findings, scans and the SBOM. Includes the step to paste into GitHub Actions or GitLab CI." },
    { path: "/secure-design", label: "Secure Design", icon: "rules", tip: "Answer a few questions about a system you are about to build and get the security requirements, pipeline controls and threat questions it calls for. A starting point for a design review." },
  ], connectors: [
    { path: "/connections", label: "GitHub, GitLab and OSV", icon: "adaptor", tip: "Open fix pull requests and match SBOM packages to known vulnerabilities" },
  ] },
  { group: "Infrastructure & Exposure", id: "infra", number: "4", icon: "infra", summary: "Hosts, networks, OT, certificates and cryptography: what is vulnerable, what is exposed, what already protects it, and how an attacker could chain it.", items: [
    { path: "/capabilities?area=infra", label: "Module overview", icon: "dashboard", tip: "Hosts, networks, OT, certificates and cryptography: what is vulnerable, what is exposed, what already protects it, and how an attacker could chain it." },
    { path: "/graphs?module=infra", label: "Relationship graph", feature: "relationship-graphs", icon: "blastRadius", tip: "How the things in this module are connected, drawn from what Quanta has recorded, with clusters, choke points and single points of failure worked out from the links." },
    { path: "/infrastructure", label: "Infrastructure Vulnerabilities", icon: "infra", tip: "Hub view across OS, Network, Network Security, OT/IoT, and Cloud sub-categories (Tenable/Armis-style asset scanning)." },
    { path: "/ot-vulnerabilities", label: "OT Vulnerabilities", icon: "container", tip: "Dedicated hub for Operational Technology/IoT device findings (PLCs, SCADA/HMI, building automation, cameras, sensor gateways) - the same real data as Infrastructure Vulnerabilities' own OT/IoT sub-category, broken out for teams who own OT/ICS specifically." },
    { path: "/certificate-vulnerabilities", label: "Certificate Vulnerabilities", icon: "certmgmt", tip: "Hub view for Certificate & TLS Lifecycle Management findings - KPIs, severity/aging charts, top rankings, and AI trend analysis, same shape as the other Security Domains hubs." },
    { path: "/quantum-readiness", label: "Quantum Readiness", icon: "quantum", tip: "Real findings naming classical RSA/ECDSA/Diffie-Hellman crypto or a legacy TLS/cipher weakness - a post-quantum migration inventory against real NIST FIPS 203/204/205 + NIST IR 8547 guidance." },
    { path: "/zero-day-watch", label: "Zero-day Watch", icon: "rules", tip: "Newly exploited vulnerabilities (CISA KEV) in products your estate appears to run that no scanner has reported yet. A name match, not a version check." },
    { path: "/compensating-controls", label: "Compensating Controls", icon: "exception", tip: "Findings that can't be remediated right now - Critical EOL/EOS, actively-exploited zero-days with no public POC, or an approved exception - with recommended controls for each." },
    { path: "/controls", label: "Security Controls", icon: "rules", tip: "Which firewalls, EDR, WAF and other controls protect which assets - what makes compensating-control advice specific to you." },
    { path: "/attack-surface", label: "Attack Surface", icon: "infra", tip: "Admin: domains, addresses, ports, services and technologies imported from the output of subfinder, dnsx, httpx, naabu and nuclei, what changed since the last import, and findings for risky exposure. Quanta never scans; it reads what your own tools wrote." },
    { path: "/firewall", label: "Firewall Rules", icon: "rules", tip: "Firewall rules from your exports: broad, unused, shadowed and internet-exposed rules, recertification by owner, and access requests checked against the rules. Quanta never changes a firewall." },
    { path: "/attack-paths", label: "Attack Chains", icon: "risk", tip: "Findings on the same asset chained by tagged MITRE ATT&CK tactic into entry -> pivot -> impact - fix the pivot to break the whole chain. Heuristic, not runtime-validated." },
    { path: "/risk/blast-radius", label: "Blast Radius", icon: "blastRadius", tip: "If this asset is compromised, how far does the damage spread - business criticality and reachability, cross-referenced against real exploitability. Honestly scoped: 2 of 4 real profiling dimensions aren't measurable with this app's data yet." },
    { path: "/assets", label: "Asset Inventory", icon: "assets", tip: "Every asset with findings against it, aggregated, with an editable owner/team." },
    { path: "/asset-mapping", label: "Asset Mapping", icon: "assets", tip: "Which real assets carry the most distinct vulnerabilities, ranked and clickable." },
    { path: "/vulnerability-mapping", label: "Vulnerability Mapping", icon: "risk", tip: "Which real vulnerabilities hit the most assets, ranked and clickable." },
  ], connectors: [
    { path: "/tenable", label: "Tenable", icon: "adaptor", tip: "Vulnerability scanner" },
    { path: "/qualys", label: "Qualys", icon: "adaptor", tip: "Vulnerability scanner" },
    { path: "/openvas", label: "OpenVAS / GVM", icon: "adaptor", tip: "Open-source scanner" },
    { path: "/prismacloud", label: "Prisma Cloud", icon: "adaptor", tip: "Cloud posture" },
    { path: "/infoblox", label: "Infoblox", icon: "adaptor", tip: "Asset discovery (DNS/DHCP/IPAM)" },
    { path: "/axonius", label: "Axonius", icon: "adaptor", tip: "Asset discovery" },
    { path: "/active-directory", label: "Active Directory", icon: "adaptor", tip: "Asset discovery (computers)" },
  ] },
  { group: "AI Security", id: "ai", number: "5", icon: "aiVuln", summary: "Risks in and around AI: model and prompt vulnerabilities, a register of AI systems checked against the OWASP LLM Top 10, and who is spending what.", items: [
    { path: "/capabilities?area=ai", label: "Module overview", icon: "dashboard", tip: "Risks in and around AI: model and prompt vulnerabilities, a register of AI systems checked against the OWASP LLM Top 10, and who is spending what." },
    { path: "/graphs?module=ai", label: "Relationship graph", feature: "relationship-graphs", icon: "blastRadius", tip: "How the things in this module are connected, drawn from what Quanta has recorded, with clusters, choke points and single points of failure worked out from the links." },
    { path: "/ai-vulnerabilities", label: "AI Vulnerabilities", icon: "aiVuln", tip: "Prompt injection, model poisoning, and other AI/ML risks - with an illustrative MITRE ATLAS heat map, summaries, and remediation guidance." },
    { path: "/ai-security", label: "AI Security", icon: "rules", tip: "Admin: your AI systems, what each can do and how it is defended, checked against the OWASP Top 10 for LLM Applications and MCP hygiene; publish the findings to the queue." },
    { path: "/ai-usage", label: "AI Usage", icon: "rules", tip: "Admin: AI spend and tokens across the organization by team, application and model, budgets, unusual days, and AI tools nobody reviewed." },
  ], connectors: [
    { path: "/connections", label: "AI usage connectors", icon: "adaptor", tip: "Anthropic and OpenAI usage and cost, gateway events and proxy logs" },
  ] },
  { group: "Remediation & Workflow", id: "remediation", number: "6", icon: "plan", summary: "Turn findings into finished work: a prioritised queue, plans and approvals, owners, exceptions and the tickets that carry it.", items: [
    { path: "/capabilities?area=remediation", label: "Module overview", icon: "dashboard", tip: "Turn findings into finished work: a prioritised queue, plans and approvals, owners, exceptions and the tickets that carry it." },
    { path: "/graphs?module=remediation", label: "Relationship graph", feature: "relationship-graphs", icon: "blastRadius", tip: "How the things in this module are connected, drawn from what Quanta has recorded, with clusters, choke points and single points of failure worked out from the links." },
    { path: "/queue", label: "Remediation Queue", icon: "queue", tip: "The live, re-scored queue - priority, SLA, KEV/EPSS, and ATT&CK tags per finding." },
    { path: "/remediate", label: "Remediation Plan", icon: "plan", tip: "The static plan snapshot from the last /remediate run, linked to generated playbooks." },
    { path: "/remediation-approvals", label: "Remediation Approvals", icon: "exception", tip: "Human-in-the-loop approve/reject for normal/emergency-change-type findings - AD-group-validated when Active Directory is configured." },
    { path: "/assignments", label: "Assignments", icon: "ownership", tip: "The work queue: findings assigned to you, routed to your team, or still waiting for an owner - assign, track status, and hand off, like an ITSM ticket queue." },
    { path: "/ownership", label: "Ownership Analytics", icon: "reports", tip: "Who and which team carries how much of the backlog - open, critical, breaching SLA, unowned - with ageing and workload balance." },
    { path: "/exceptions", label: "Exceptions", icon: "exception", tip: "Request, approve, and track time-boxed risk-acceptance waivers per finding." },
    { path: "/run", label: "Run Pipeline", icon: "run", tip: "Trigger /quanta-scan or /remediate - dry-run preview by default." },
  ], connectors: [
    { path: "/servicenow", label: "ServiceNow", icon: "adaptor", tip: "Open and track incidents" },
    { path: "/jira", label: "Jira", icon: "adaptor", tip: "Open and track issues" },
    { path: "/splunk", label: "Splunk", icon: "adaptor", tip: "Append findings to an event stream" },
  ] },
  { group: "Risk, Governance & Compliance", id: "grc", number: "7", icon: "risk", summary: "Put risk in money, show control evidence, govern who has access and keep the audit trail.", items: [
    { path: "/capabilities?area=grc", label: "Module overview", icon: "dashboard", tip: "Put risk in money, show control evidence, govern who has access and keep the audit trail." },
    { path: "/posture", label: "Security Posture Review", icon: "risk", tip: "Admin: the estate and this deployment assessed against zero trust, secure by design, threat modelling, defence in depth, architecture, SDLC, the AI lifecycle, supply chain, AI supply chain and open-source exposure, with the exact setting that closes each gap." },
    { path: "/graphs?module=grc", label: "Relationship graph", feature: "relationship-graphs", icon: "blastRadius", tip: "How the things in this module are connected, drawn from what Quanta has recorded, with clusters, choke points and single points of failure worked out from the links." },
    { path: "/risk", label: "Risk Dashboard", icon: "risk", tip: "MITRE ATT&CK heat map, top critical assets, and internal/external-facing exposure." },
    { path: "/cyber-risk", label: "Cyber Risk", icon: "rules", tip: "Admin: risk in money. Loss scenarios simulated into an average and a bad-year loss, which treatment is worth its cost, and a cyber health score." },
    { path: "/grc", label: "Risk & Compliance", icon: "rules", tip: "Admin: control framework coverage with automated evidence, the risk register, attestations and policies. Evidence and workflow; not a certification." },
    { path: "/ml-insights", label: "ML Insights", icon: "ml", tip: "Real, live-trained scikit-learn models (IsolationForest anomaly detection, KMeans risk clustering) - unsupervised, advisory, and never a replacement for the deterministic policy/priority engines." },
    { path: "/access-governance", label: "Access Governance", icon: "rules", tip: "Leavers with access, dormant and unowned accounts, separation-of-duties conflicts, and manager access reviews. Quanta records decisions; your identity team removes the access." },
    { path: "/reports", label: "Reports", icon: "reports", tip: "Generate a shareable KPI/SLA/coverage report snapshot." },
    { path: "/activity-log", label: "Activity Log", icon: "clock", tip: "Real who/what/when audit trail - every asset edit, approval decision, exception revocation, and login attempt in this app." },
  ], connectors: [
    { path: "/connections", label: "Entitlement and HR roster imports", icon: "adaptor", tip: "Access governance reads exports; evidence comes from the modules above" },
  ] },
  { group: "Administration", id: "admin", number: "8", icon: "users", summary: "Connections and API keys, policies, notifications, users and teams.", items: [
    { path: "/graphs?module=admin", label: "Relationship graph", feature: "relationship-graphs", icon: "blastRadius", tip: "How the things in this module are connected, drawn from what Quanta has recorded, with clusters, choke points and single points of failure worked out from the links." },
    { path: "/connections", label: "Connections", icon: "adaptor", tip: "Admin: store your scanner and asset-source credentials (encrypted) and schedule automatic syncs." },
    { path: "/adaptors", label: "Connectors / Adaptors", icon: "adaptor", tip: "Every external system Quanta talks to (or has researched), in one place - pick a connector from the dropdown." },
    { path: "/priority-rules", label: "Priority Rules", icon: "rules", tip: "Tune severity/asset/KEV/EPSS weights and SLA windows - takes effect immediately." },
    { path: "/exploit-criteria", label: "Exploit Criteria", icon: "aiVuln", tip: "Define which real KEV/POC/EPSS signal combinations count as a 'zero-day criteria' match - customizable per client, takes effect immediately." },
    { path: "/remediation-policy", label: "Remediation Policy", icon: "rules", tip: "Cadence, ITIL 4 change type, maintenance windows, and PAM backend per remediation domain - the real config driving the Remediation Queue's approval/auto-remediate treatment." },
    { path: "/asset-policy", label: "Asset Policy", icon: "rules", tip: "Bulk, rule-based asset owner/team/environment/facing/remediation-schedule editing - match a group of real assets and set fields on all of them in one action." },
    { path: "/notification-settings", label: "Notification Settings", icon: "mail", tip: "Schedule sub-domain/team-wise reports (weekly-yearly) and critical/zero-day/threat-intel email alerts - requires real SMTP configuration to actually send." },
    { path: "/admin/people", label: "Users & Teams", icon: "users", tip: "Admin-only: user accounts and roles, team records and managers, who is on which team, each person's live workload, and the auto-routing rule." },
    { path: "/admin", label: "Admin Settings", icon: "rules", tip: "Admin-only: which real Claude Code model to use, per-user daily token limits (enforced server-side), real usage/cost by user, and read-only system health." },
    { path: "/design-system", label: "Design system", icon: "dashboard", tip: "The living style guide: every component of the interface with a live example, the keyboard shortcuts and how pages are built." },
  ], connectors: [
  ] },
  { group: "Help", id: "help", items: [
    { path: "/support", label: "Support", icon: "support", tip: "How to get help, report a bug, and where the deeper docs live." },
    { path: "/faq", label: "FAQ", icon: "faq", tip: "Direct answers about what this product does and doesn't do (yet)." },
    { path: "/design-system", label: "Design system", icon: "dashboard", tip: "The living style guide: every component of the interface with a live example, the keyboard shortcuts and how pages are built." },
  ] },
];

// Splits a nav item's path (which may include a deep-link query string, e.g. "/hunting?tab=alerts") into its
// pathname and search parts so active-highlighting can require an exact query match - otherwise every item that
// shares a pathname would highlight together whenever any of them is active.
function splitItemPath(path) {
  const qIdx = path.indexOf("?");
  return qIdx === -1 ? { pathname: path, search: "" } : { pathname: path.slice(0, qIdx), search: path.slice(qIdx) };
}

const MODULE_KEY = "quanta.module";
const MODULES = () => NAV.filter((g) => g.id !== "home" && g.id !== "help");

function savedModule() {
  try { return window.localStorage.getItem(MODULE_KEY); } catch { return null; }
}
function saveModule(id) {
  try { if (id) window.localStorage.setItem(MODULE_KEY, id); else window.localStorage.removeItem(MODULE_KEY); } catch { /* private window: the choice is simply not kept */ }
}

// What the licence covers: null means unrestricted (no licence enforcement configured); otherwise a Set of module ids.
// app.js fetches /api/license once and calls setLicense(); until then everything shows as licensed.
let licensed = null;
export function setLicense(info) {
  licensed = info && info.enforced ? new Set(info.modules || []) : null;
}
export function isLicensed(id) {
  return licensed === null || id === "admin" || licensed.has(id);
}

// Feature flags (GET /api/features): an item with a `feature` key is hidden when that flag is off. Until the flags are
// loaded (or if they cannot be) nothing is hidden, so a failed fetch never removes navigation.
let featureFlags = null;
export function setFeatures(snapshot) {
  featureFlags = snapshot && snapshot.features ? snapshot.features : null;
}
export function featureVisible(item) {
  if (!item || !item.feature || featureFlags === null) return true;
  const f = featureFlags[item.feature];
  return !!(f && f.enabled);
}
export function visibleItems(items) {
  return (items || []).filter(featureVisible);
}

function isActive(item, currentPath, currentSearch) {
  const { pathname, search } = splitItemPath(item.path);
  return item.exact ? currentPath === pathname : currentPath === pathname && currentSearch === search;
}

// Which module holds the page being viewed. An exact match (path and query) wins, so /capabilities?area=infra
// opens Infrastructure. Otherwise a page opened without its query string (e.g. /hunting) belongs to the module
// whose tab deep-links it, so fall back to the pathname alone - except the module-overview links, which all
// share /capabilities and would otherwise always select the first module.
export function findModule(currentPath, currentSearch) {
  const all = (g) => [...g.items, ...(g.connectors || [])];
  const mods = MODULES();
  return mods.find((g) => all(g).some((i) => isActive(i, currentPath, currentSearch)))
    || mods.find((g) => all(g).some((i) => !i.path.startsWith("/capabilities") && splitItemPath(i.path).pathname === currentPath));
}

// Modules the sidebar and the command palette may offer (a locked module is listed in the picker but never opened).
export function openableNav() {
  return NAV.filter((g) => g.id === "home" || g.id === "help" || isLicensed(g.id));
}

export function renderSidebar(currentPath, currentSearch = "") {
  const el = document.getElementById("sidebar");

  // Decide which module is in focus: the page being viewed wins; the All modules page without an area clears the
  // choice (that is how you get back to the picker); anything else keeps the remembered module.
  let focus = null;
  const viewed = findModule(currentPath, currentSearch);
  if (currentPath === "/capabilities" && !new URLSearchParams(currentSearch).get("area")) saveModule(null);
  else if (viewed && isLicensed(viewed.id)) { focus = viewed; saveModule(viewed.id); }
  else if (!viewed && savedModule()) focus = MODULES().find((g) => g.id === savedModule() && isLicensed(g.id)) || null;

  const link = (item) => {
    const active = isActive(item, currentPath, currentSearch);
    return `<a href="${item.path}" data-link data-tooltip="${item.tip}" class="${active ? "active" : ""}">` +
      `<span class="nav-icon">${icon(item.icon, 17)}</span><span class="nav-label">${item.label}</span></a>`;
  };
  const moduleLink = (m, cls = "") => {
    const ok = isLicensed(m.id);
    return ok
      ? `<a href="/capabilities?area=${m.id}" data-link data-tooltip="${m.summary}" class="${cls}"><span class="nav-icon">${icon(m.icon, 17)}</span>` +
        `<span class="nav-label"><span class="nav-module-no">${m.number}</span> ${m.group}</span></a>`
      : `<span class="nav-locked" data-tooltip="${m.group} is not part of your licence."><span class="nav-icon">${icon(m.icon, 17)}</span>` +
        `<span class="nav-label"><span class="nav-module-no">${m.number}</span> ${m.group} <em>not licensed</em></span></span>`;
  };

  const home = NAV.find((g) => g.id === "home");
  const homeItems = focus ? home.items.filter((i) => ["/", "/ask", "/inbox"].includes(i.path)) : home.items.filter((i) => i.path !== "/capabilities");
  const homeHtml = `<div class="nav-group"><div class="nav-group-label">Home</div><div class="nav-items">${homeItems.map(link).join("")}</div></div>`;

  let mainHtml;
  if (focus) {
    const others = MODULES().filter((m) => m.id !== focus.id);
    const connectors = (focus.connectors && focus.connectors.length) ? `<div class="nav-sublabel">Connectors</div>${visibleItems(focus.connectors).map(link).join("")}` : "";
    mainHtml = `<div class="nav-group nav-focus" data-nav-group="${focus.id}">
        <a class="nav-back" href="/capabilities" data-link data-tooltip="Back to all modules"><span class="nav-back-arrow">&larr;</span><span class="nav-label">All modules</span></a>
        <div class="nav-focus-title"><span class="nav-icon">${icon(focus.icon, 18)}</span><span class="nav-label"><span class="nav-module-no">${focus.number}</span> ${focus.group}</span></div>
        <div class="nav-items">${visibleItems(focus.items).map(link).join("")}${connectors}</div>
        <details class="nav-switch"><summary data-tooltip="Open another module">Switch module</summary>${others.map((m) => moduleLink(m)).join("")}</details>
      </div>`;
  } else {
    mainHtml = `<div class="nav-group"><div class="nav-group-label">Modules</div><div class="nav-items">${MODULES().map((m) => moduleLink(m)).join("")}</div></div>`;
  }
  const helpHtml = `<div class="nav-group"><div class="nav-group-label">Help</div><div class="nav-items">${visibleItems(NAV.find((g) => g.id === "help").items).map(link).join("")}</div></div>`;

  el.innerHTML = `
    <a class="brand" href="/" data-link data-tooltip="Quanta - AI-driven vulnerability detection &amp; remediation">
      <span class="brand-mark">${LOGO_SVG}</span>
      <span class="brand-text">Quanta</span>
    </a>

    <button type="button" class="side-nav-scroll side-nav-scroll-up" data-nav-scroll="up" aria-label="Scroll navigation up">
      <span style="display:flex; transform:rotate(180deg)">${icon("chevronDown", 14)}</span>
    </button>
    <nav class="side-nav">${homeHtml}${mainHtml}${helpHtml}</nav>
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
