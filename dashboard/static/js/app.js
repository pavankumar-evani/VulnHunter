// Client-side router for the VulnHunter dashboard SPA. Each page module lives in
// ./pages/*.js and exports `render(container, ...params)` plus a `title` (string
// or function taking the matched URL params). No framework, no build step -
// dynamic import() is a native browser feature, not a bundler trick.
import { renderSidebar } from "./nav.js";

const routes = [
  { pattern: /^\/$/, load: () => import("./pages/overview.js") },
  { pattern: /^\/vulnhunt\/?$/, load: () => import("./pages/vulnhunt.js") },
  { pattern: /^\/remediate\/?$/, load: () => import("./pages/remediate.js") },
  { pattern: /^\/queue\/?$/, load: () => import("./pages/queue.js") },
  { pattern: /^\/priority-rules\/?$/, load: () => import("./pages/priorityRules.js") },
  { pattern: /^\/servicenow\/?$/, load: () => import("./pages/servicenow.js") },
  { pattern: /^\/run\/?$/, load: () => import("./pages/run.js") },
  { pattern: /^\/playbooks\/([^/]+)$/, load: () => import("./pages/playbookDetail.js") },
];

const appEl = document.getElementById("app");
const titleEl = document.getElementById("page-title");

function matchRoute(pathname) {
  for (const route of routes) {
    const m = pathname.match(route.pattern);
    if (m) return { route, params: m.slice(1) };
  }
  return null;
}

async function renderRoute() {
  const pathname = window.location.pathname;
  renderSidebar(pathname);

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
    await mod.render(appEl, ...matched.params);
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
  if (url.pathname === window.location.pathname) return;
  window.history.pushState({}, "", url.pathname);
  renderRoute();
});

window.addEventListener("popstate", renderRoute);

renderRoute();
