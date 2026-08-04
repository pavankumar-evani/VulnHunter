// Client-side router for the VulnHunter dashboard SPA. Each page module lives in
// ./pages/*.js and exports `render(container, ...params)` plus a `title` (string
// or function taking the matched URL params). No framework, no build step -
// dynamic import() is a native browser feature, not a bundler trick.
import { getCurrentUser, initAccountChip } from "./auth.js";
import { renderSidebar } from "./nav.js";
import { initNotificationBell } from "./notifications.js";
import { initGlobalSearch } from "./search.js";
import { initSidebarToggle } from "./sidebarToggle.js";
import { initTooltips } from "./tooltip.js";

const routes = [
  { pattern: /^\/$/, load: () => import("./pages/overview.js") },
  { pattern: /^\/vulnhunt\/?$/, load: () => import("./pages/vulnhunt.js") },
  { pattern: /^\/remediate\/?$/, load: () => import("./pages/remediate.js") },
  { pattern: /^\/queue\/?$/, load: () => import("./pages/queue.js") },
  { pattern: /^\/priority-rules\/?$/, load: () => import("./pages/priorityRules.js") },
  { pattern: /^\/servicenow\/?$/, load: () => import("./pages/servicenow.js") },
  { pattern: /^\/jira\/?$/, load: () => import("./pages/jira.js") },
  { pattern: /^\/splunk\/?$/, load: () => import("./pages/splunk.js") },
  { pattern: /^\/xdr\/?$/, load: () => import("./pages/xdr.js") },
  { pattern: /^\/infoblox\/?$/, load: () => import("./pages/infoblox.js") },
  { pattern: /^\/axonius\/?$/, load: () => import("./pages/axonius.js") },
  { pattern: /^\/run\/?$/, load: () => import("./pages/run.js") },
  { pattern: /^\/ai-assist\/?$/, load: () => import("./pages/aiAssist.js") },
  { pattern: /^\/reports\/?$/, load: () => import("./pages/reports.js") },
  { pattern: /^\/support\/?$/, load: () => import("./pages/support.js") },
  { pattern: /^\/faq\/?$/, load: () => import("./pages/faq.js") },
  { pattern: /^\/exceptions\/?$/, load: () => import("./pages/exceptions.js") },
  { pattern: /^\/assets\/?$/, load: () => import("./pages/assets.js") },
  { pattern: /^\/appsec\/?$/, load: () => import("./pages/appsec.js") },
  { pattern: /^\/infrastructure\/?$/, load: () => import("./pages/infrastructure.js") },
  { pattern: /^\/inbox\/?$/, load: () => import("./pages/inbox.js") },
  { pattern: /^\/risk\/?$/, load: () => import("./pages/risk.js") },
  { pattern: /^\/ai-vulnerabilities\/?$/, load: () => import("./pages/aiVulnerabilities.js") },
  { pattern: /^\/login\/?$/, load: () => import("./pages/login.js") },
  { pattern: /^\/profile\/?$/, load: () => import("./pages/profile.js") },
  { pattern: /^\/playbooks\/([^/]+)$/, load: () => import("./pages/playbookDetail.js") },
];

const appEl = document.getElementById("app");
const titleEl = document.getElementById("page-title");
const topbarExtraEl = document.getElementById("topbar-extra");

// A page's render() may return a cleanup function (e.g. to clearInterval on an
// auto-refresh poller) - it's called right before navigating to the next page.
let currentCleanup = null;

function matchRoute(pathname) {
  for (const route of routes) {
    const m = pathname.match(route.pattern);
    if (m) return { route, params: m.slice(1) };
  }
  return null;
}

// Client-side login gate: every page except /login redirects to it when nobody is
// logged in. This is a UX gate, not the real security boundary - the real one is
// server-side (app.py's Depends(rbac.require_*) on sensitive mutation routes only).
// Every GET/read route stays reachable directly (e.g. curl /api/queue) regardless of
// this client-side check - see dashboard/README.md's "What this is NOT (yet)" section.
async function renderRoute() {
  if (currentCleanup) {
    currentCleanup();
    currentCleanup = null;
  }
  topbarExtraEl.innerHTML = "";

  let pathname = window.location.pathname;

  if (pathname !== "/login") {
    const user = await getCurrentUser();
    if (!user) {
      const redirect = encodeURIComponent(pathname + window.location.search);
      window.history.replaceState({}, "", `/login?redirect=${redirect}`);
      pathname = "/login";
    }
  }

  document.querySelector(".app-shell").classList.toggle("auth-page", pathname === "/login");
  if (pathname === "/login") {
    document.getElementById("sidebar").innerHTML = "";
  } else {
    renderSidebar(pathname, window.location.search);
  }

  const matched = matchRoute(pathname);
  if (!matched) {
    titleEl.textContent = "Not Found";
    document.title = "Not Found · VulnHunter";
    appEl.innerHTML = `<p class="empty-state">Page not found.</p>`;
    return;
  }

  appEl.innerHTML = `<div class="empty-state">Loading…</div>`;
  try {
    const mod = await matched.route.load();
    const heading = typeof mod.title === "function" ? mod.title(...matched.params) : mod.title;
    titleEl.textContent = heading;
    document.title = `${heading} · VulnHunter`;
    currentCleanup = (await mod.render(appEl, ...matched.params)) || null;
  } catch (err) {
    console.error(err);
    appEl.innerHTML = `<div class="flash flash-error">Failed to load page: ${err.message || err}</div>`;
  }
}

// Intercept clicks on any in-app link (marked with data-link) for real client-side
// navigation - no full page reload, browser back/forward still works via popstate.
document.addEventListener("click", (event) => {
  const link = event.target.closest("[data-link]");
  if (!link) return;
  const url = new URL(link.href, window.location.origin);
  if (url.origin !== window.location.origin) return;
  event.preventDefault();
  if (url.pathname + url.search === window.location.pathname + window.location.search) return;
  window.history.pushState({}, "", url.pathname + url.search);
  renderRoute();
});

window.addEventListener("popstate", renderRoute);

initGlobalSearch();
initNotificationBell();
initAccountChip();
initSidebarToggle();
initTooltips();
renderRoute();
