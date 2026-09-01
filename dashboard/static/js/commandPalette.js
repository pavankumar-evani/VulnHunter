// Ctrl/Cmd+K command palette - instant keyboard-driven navigation to any real page in
// the app, from anywhere in the app. Reuses nav.js's own NAV list (one definition of
// "every real page," not a second copy that could drift from the sidebar) - this is a
// different, complementary tool from search.js's global search bar, which searches
// real finding/asset DATA, not pages/commands (the same split real products like
// GitHub draw between a data search box and a Cmd+K command palette).
import { NAV } from "./nav.js";
import { icon } from "./icons.js";

let paletteEl = null;

function flattenNav() {
  const items = [];
  for (const group of NAV) {
    for (const item of group.items) items.push({ ...item, group: group.group });
  }
  return items;
}

function closePalette() {
  if (!paletteEl) return;
  paletteEl.remove();
  paletteEl = null;
  document.removeEventListener("keydown", onPaletteKeydown, true);
}

function itemRowHtml(item, isActive) {
  return `
    <a href="${item.path}" data-link class="command-palette-item ${isActive ? "active" : ""}">
      <span class="command-palette-item-icon">${icon(item.icon, 16)}</span>
      <span class="command-palette-item-label">${item.label}</span>
      <span class="command-palette-item-group">${item.group}</span>
    </a>`;
}

let filtered = [];
let selectedIndex = 0;

function renderResults(resultsEl) {
  resultsEl.innerHTML = filtered.length
    ? filtered.map((item, i) => itemRowHtml(item, i === selectedIndex)).join("")
    : `<div class="empty-state" style="padding:14px">No matching page.</div>`;
  const activeEl = resultsEl.querySelector(".command-palette-item.active");
  if (activeEl) activeEl.scrollIntoView({ block: "nearest" });
}

function navigateTo(path) {
  closePalette();
  window.history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function onPaletteKeydown(e) {
  const resultsEl = paletteEl.querySelector("#command-palette-results");
  if (e.key === "Escape") {
    e.preventDefault();
    closePalette();
  } else if (e.key === "ArrowDown") {
    e.preventDefault();
    selectedIndex = Math.min(selectedIndex + 1, filtered.length - 1);
    renderResults(resultsEl);
  } else if (e.key === "ArrowUp") {
    e.preventDefault();
    selectedIndex = Math.max(selectedIndex - 1, 0);
    renderResults(resultsEl);
  } else if (e.key === "Enter") {
    e.preventDefault();
    const item = filtered[selectedIndex];
    if (item) navigateTo(item.path);
  }
}

function openPalette() {
  if (paletteEl) return;
  const allItems = flattenNav();
  filtered = allItems;
  selectedIndex = 0;

  paletteEl = document.createElement("div");
  paletteEl.className = "command-palette-backdrop";
  paletteEl.innerHTML = `
    <div class="command-palette">
      <input type="text" id="command-palette-input" placeholder="Jump to a page… (Esc to close)" autocomplete="off">
      <div class="command-palette-results" id="command-palette-results"></div>
    </div>`;
  document.body.appendChild(paletteEl);

  const input = paletteEl.querySelector("#command-palette-input");
  const resultsEl = paletteEl.querySelector("#command-palette-results");

  input.addEventListener("input", () => {
    const q = input.value.trim().toLowerCase();
    filtered = q
      ? allItems.filter((item) =>
          item.label.toLowerCase().includes(q) ||
          item.group.toLowerCase().includes(q) ||
          (item.tip || "").toLowerCase().includes(q))
      : allItems;
    selectedIndex = 0;
    renderResults(resultsEl);
  });

  resultsEl.addEventListener("click", (e) => {
    const itemEl = e.target.closest(".command-palette-item");
    if (!itemEl) return;
    e.preventDefault();
    navigateTo(itemEl.getAttribute("href"));
  });

  paletteEl.addEventListener("mousedown", (e) => {
    if (e.target === paletteEl) closePalette();
  });

  // Capture phase so this fires before the palette's own input can swallow it, and so
  // Escape/arrows/Enter work even if focus is somehow elsewhere inside the palette.
  document.addEventListener("keydown", onPaletteKeydown, true);

  renderResults(resultsEl);
  input.focus();
}

export function initCommandPalette() {
  document.addEventListener("keydown", (e) => {
    const isMac = navigator.platform.toUpperCase().includes("MAC");
    const modifierPressed = isMac ? e.metaKey : e.ctrlKey;
    if (!modifierPressed || e.key.toLowerCase() !== "k") return;
    e.preventDefault();
    if (paletteEl) closePalette();
    else openPalette();
  });
}
