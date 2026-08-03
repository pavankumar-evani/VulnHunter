// Lets the left sidebar slide fully out of view for a distraction-free, full-width
// content area - and back again - via a topbar button. Built entirely on standard,
// universally-supported web platform features (a <button>, a CSS class toggle,
// `localStorage`) rather than anything vendor-specific, so it behaves identically in
// Chrome, Edge, Firefox, Safari, and Opera on both desktop and mobile.
import { icon } from "./icons.js";

const STORAGE_KEY = "vulnhunter-sidebar-collapsed";

function applyState(collapsed) {
  const shell = document.querySelector(".app-shell");
  const button = document.getElementById("sidebar-toggle");
  const sidebar = document.getElementById("sidebar");
  if (!shell || !button) return;
  shell.classList.toggle("sidebar-collapsed", collapsed);
  button.setAttribute("aria-pressed", String(collapsed));
  button.setAttribute("aria-label", collapsed ? "Expand sidebar" : "Collapse sidebar");
  button.title = collapsed ? "Expand sidebar" : "Collapse sidebar";
  // `inert` (not just visual hiding) keeps keyboard/screen-reader users from tabbing
  // into nav links that are zero-width and invisible while collapsed - widely
  // supported in evergreen Chrome/Edge/Firefox/Safari/Opera. `sidebar` itself
  // persists across route changes (nav.js only replaces its innerHTML), so this
  // survives navigation while collapsed.
  sidebar?.toggleAttribute("inert", collapsed);
}

export function initSidebarToggle() {
  const button = document.getElementById("sidebar-toggle");
  if (!button) return;
  button.innerHTML = icon("sidebarPanel", 18);

  let collapsed = false;
  try {
    collapsed = localStorage.getItem(STORAGE_KEY) === "1";
  } catch {
    // Private-browsing modes in some browsers (notably Safari) can throw on
    // localStorage access - fall back to the default (expanded) state rather than
    // breaking the page.
  }
  applyState(collapsed);

  button.addEventListener("click", () => {
    collapsed = !collapsed;
    applyState(collapsed);
    try {
      localStorage.setItem(STORAGE_KEY, collapsed ? "1" : "0");
    } catch {
      // Same private-browsing fallback as above - the toggle still works for the
      // current page load, it just won't persist across a reload.
    }
  });
}
