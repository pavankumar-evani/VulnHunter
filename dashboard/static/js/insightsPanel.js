// Right-hand "Insights" panel: a persistent sibling of .main-column (lives in
// index.html, not inside the router-controlled #app region) showing page-specific tips,
// term definitions, and highlighted alerts - each page's own render() calls
// setInsightsContent() with whatever's actually relevant to what it just rendered,
// computed from data that page already fetched (same "call a shared helper from within
// your own render()" convention as wireDateRange/wireTopRankings/etc. elsewhere in this
// app). app.js calls resetInsightsContent() before every route change, so a page that
// hasn't been given bespoke content yet still shows a real, useful glossary rather than
// stale content from whatever page was open before, or a blank panel.
//
// Collapse and resize-by-drag both persist via localStorage, mirroring
// sidebarToggle.js's exact pattern (a plain CSS class toggle + try/catch around
// localStorage access, since private-browsing modes can throw on access).
import { icon } from "./icons.js";
import { escapeHtml } from "./dom.js";
import { glossaryHtml } from "./glossary.js";

const WIDTH_KEY = "vulnhunter-insights-width";
const COLLAPSED_KEY = "vulnhunter-insights-collapsed";
const DEFAULT_WIDTH = 300;
const MIN_WIDTH = 220;
const MAX_WIDTH = 480;

function applyCollapsed(collapsed) {
  const shell = document.querySelector(".app-shell");
  const button = document.getElementById("insights-toggle");
  const body = document.getElementById("insights-body");
  if (!shell || !button) return;
  shell.classList.toggle("insights-collapsed", collapsed);
  button.setAttribute("aria-pressed", String(collapsed));
  button.setAttribute("aria-label", collapsed ? "Expand insights panel" : "Collapse insights panel");
  button.title = collapsed ? "Expand insights panel" : "Collapse insights panel";
  // Same `inert`-on-hidden-content safety net as sidebarToggle.js - belt-and-braces
  // with the CSS display:none already applied while collapsed.
  body?.toggleAttribute("inert", collapsed);
}

export function initInsightsPanel() {
  const panel = document.getElementById("insights-panel");
  const button = document.getElementById("insights-toggle");
  const handle = document.getElementById("insights-resize-handle");
  if (!panel || !button || !handle) return;
  button.innerHTML = icon("sidebarPanel", 16);

  let width = DEFAULT_WIDTH;
  // Defaults to collapsed on a first-ever visit (no stored preference yet) - the panel
  // was intrusive-by-default and often needed scrolling, per real user feedback. Once
  // someone explicitly expands or re-collapses it, that choice persists exactly as
  // before - this only changes what a fresh session starts with.
  let collapsed = true;
  try {
    const storedWidth = parseInt(localStorage.getItem(WIDTH_KEY), 10);
    if (!Number.isNaN(storedWidth)) width = Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, storedWidth));
    const storedCollapsed = localStorage.getItem(COLLAPSED_KEY);
    if (storedCollapsed !== null) collapsed = storedCollapsed === "1";
  } catch {
    // Private-browsing modes (notably Safari) can throw on localStorage access - fall
    // back to the defaults rather than breaking the page.
  }
  document.documentElement.style.setProperty("--insights-w", `${width}px`);
  applyCollapsed(collapsed);

  button.addEventListener("click", () => {
    collapsed = !collapsed;
    applyCollapsed(collapsed);
    try {
      localStorage.setItem(COLLAPSED_KEY, collapsed ? "1" : "0");
    } catch {
      // Same fallback as above - toggle still works this page load, just doesn't persist.
    }
  });

  let dragging = false;
  let startX = 0;
  let startWidth = width;
  handle.addEventListener("mousedown", (e) => {
    dragging = true;
    startX = e.clientX;
    startWidth = panel.getBoundingClientRect().width;
    handle.classList.add("dragging");
    document.body.style.userSelect = "none";
    e.preventDefault();
  });
  window.addEventListener("mousemove", (e) => {
    if (!dragging) return;
    // The panel sits on the RIGHT edge, so dragging the handle further LEFT (smaller
    // clientX) should widen it - the delta is inverted relative to a left-edge handle.
    const delta = startX - e.clientX;
    const newWidth = Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, startWidth + delta));
    document.documentElement.style.setProperty("--insights-w", `${newWidth}px`);
  });
  window.addEventListener("mouseup", () => {
    if (!dragging) return;
    dragging = false;
    handle.classList.remove("dragging");
    document.body.style.userSelect = "";
    const finalWidth = panel.getBoundingClientRect().width;
    try {
      localStorage.setItem(WIDTH_KEY, String(Math.round(finalWidth)));
    } catch {
      // Same fallback as above.
    }
  });

  resetInsightsContent();
}

// `level`: "info" (blue, neutral) | "warn" (amber, worth noticing) | "danger" (red,
// needs attention) - same three tiers as this app's existing .callout/.callout-warn/
// .callout-danger classes, just sized for the narrower panel.
export function insightAlertHtml(html, level = "info") {
  return `<div class="insight-alert insight-alert-${level}">${html}</div>`;
}

export function insightSectionHtml(title, bodyHtml) {
  if (!bodyHtml) return "";
  const heading = title ? `<h4>${escapeHtml(title)}</h4>` : "";
  return `<div class="insight-section">${heading}${bodyHtml}</div>`;
}

export function setInsightsContent(html) {
  const body = document.getElementById("insights-body");
  if (body) body.innerHTML = html;
}

// Shown whenever a page hasn't (yet) called setInsightsContent() itself, and reset back
// to this before every route change - see the module doc comment above for why.
const DEFAULT_GLOSSARY_KEYS = ["priority", "severity", "sla", "kev", "epss", "owner"];

export function resetInsightsContent() {
  setInsightsContent(insightSectionHtml("Common terms on this dashboard", glossaryHtml(DEFAULT_GLOSSARY_KEYS)));
}
