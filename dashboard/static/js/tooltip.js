// A single shared tooltip element, appended to <body> and positioned via
// getBoundingClientRect() on hover/focus - replaces a pure-CSS [data-tooltip]::after
// approach that (invisibly, at opacity:0) inflated .side-nav's scrollable width and
// produced a permanent horizontal scrollbar in the sidebar. Living outside any
// scrolling ancestor's box sidesteps that entirely, and as a bonus this also clamps
// to the viewport so a tooltip near a screen edge never renders off-screen.
let tooltipEl = null;
let currentTarget = null;

function ensureTooltipEl() {
  if (!tooltipEl) {
    tooltipEl = document.createElement("div");
    tooltipEl.className = "js-tooltip";
    document.body.appendChild(tooltipEl);
  }
  return tooltipEl;
}

function showTooltip(target) {
  const text = target.getAttribute("data-tooltip");
  if (!text) return;
  currentTarget = target;
  const el = ensureTooltipEl();
  el.textContent = text;
  el.style.display = "block";

  const rect = target.getBoundingClientRect();
  const tipRect = el.getBoundingClientRect();
  const inSidebar = !!target.closest(".side-nav, .tenant-switcher");

  let top, left;
  if (inSidebar) {
    // Beside the item, vertically centered - matches the sidebar's prior "tooltip to
    // the right" placement, just computed in viewport coordinates instead of relying
    // on a CSS ::after anchored inside the scrolling nav list.
    top = rect.top + rect.height / 2 - tipRect.height / 2;
    left = rect.right + 10;
  } else {
    // Everywhere else (KPI cards, topbar, etc.): above and centered, the prior
    // default placement.
    top = rect.top - tipRect.height - 8;
    left = rect.left + rect.width / 2 - tipRect.width / 2;
  }
  const margin = 6;
  top = Math.max(margin, Math.min(top, window.innerHeight - tipRect.height - margin));
  left = Math.max(margin, Math.min(left, window.innerWidth - tipRect.width - margin));
  el.style.top = `${top}px`;
  el.style.left = `${left}px`;
}

function hideTooltip() {
  currentTarget = null;
  if (tooltipEl) tooltipEl.style.display = "none";
}

export function initTooltips() {
  document.addEventListener("mouseover", (e) => {
    const target = e.target.closest("[data-tooltip]");
    if (target && target !== currentTarget) showTooltip(target);
  });
  document.addEventListener("mouseout", (e) => {
    const target = e.target.closest("[data-tooltip]");
    if (target && target === currentTarget) hideTooltip();
  });
  document.addEventListener("focusin", (e) => {
    const target = e.target.closest("[data-tooltip]");
    if (target) showTooltip(target);
  });
  document.addEventListener("focusout", (e) => {
    const target = e.target.closest("[data-tooltip]");
    if (target && target === currentTarget) hideTooltip();
  });
  // A route change (app.js's renderRoute) can remove the currently-tooltipped
  // element from the DOM without ever firing mouseout/focusout on it.
  window.addEventListener("popstate", hideTooltip);
  document.addEventListener("click", (e) => {
    if (e.target.closest("[data-link]")) hideTooltip();
  });
}
