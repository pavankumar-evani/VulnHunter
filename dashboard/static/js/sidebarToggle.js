// Lets the left sidebar shrink to a compact, icon-only rail (like a real product's
// own left nav - e.g. Traceable's) - and back to full labels - via a topbar button,
// and minimizes itself automatically once a page is selected. Built entirely on
// standard, universally-supported web platform features (a <button>, a CSS class
// toggle, `localStorage`) rather than anything vendor-specific, so it behaves
// identically in Chrome, Edge, Firefox, Safari, and Opera on both desktop and mobile.
import { icon } from "./icons.js";

const STORAGE_KEY = "vulnhunter-sidebar-collapsed";

function applyState(collapsed) {
  const shell = document.querySelector(".app-shell");
  const button = document.getElementById("sidebar-toggle");
  if (!shell || !button) return;
  shell.classList.toggle("sidebar-collapsed", collapsed);
  button.setAttribute("aria-pressed", String(collapsed));
  button.setAttribute("aria-label", collapsed ? "Expand sidebar" : "Minimize sidebar");
  button.title = collapsed ? "Expand sidebar" : "Minimize sidebar";
  // Icons stay real, visible, focusable links either way (unlike the old fully-
  // hidden behavior this replaced) - nothing to mark inert.
}

export function initSidebarToggle() {
  const button = document.getElementById("sidebar-toggle");
  const sidebar = document.getElementById("sidebar");
  if (!button) return;
  button.innerHTML = icon("sidebarPanel", 18);

  // Defaults to minimized (true) for a new visitor with no saved preference yet -
  // matches the compact-rail-by-default reference this was modeled on, rather than
  // starting fully expanded.
  let collapsed = true;
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved !== null) collapsed = saved === "1";
  } catch {
    // Private-browsing modes in some browsers (notably Safari) can throw on
    // localStorage access - fall back to the default (minimized) state rather than
    // breaking the page.
  }
  applyState(collapsed);

  function setCollapsed(next) {
    collapsed = next;
    applyState(collapsed);
    try {
      localStorage.setItem(STORAGE_KEY, collapsed ? "1" : "0");
    } catch {
      // Same private-browsing fallback as above - the toggle still works for the
      // current page load, it just won't persist across a reload.
    }
  }

  button.addEventListener("click", () => setCollapsed(!collapsed));

  // Once a user has expanded the rail to browse full labels, minimize it again right
  // after they actually pick a page - same "gets out of the way once you've made your
  // selection" behavior as starting minimized, just re-applied on every nav click
  // instead of only on first load. `sidebar` persists across route changes (nav.js
  // only replaces its innerHTML), so one listener attached here covers every future
  // navigation without needing to be re-attached per page.
  sidebar?.addEventListener("click", (e) => {
    if (!collapsed && e.target.closest("[data-link]")) setCollapsed(true);
  });
}
