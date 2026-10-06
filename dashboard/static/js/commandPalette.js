// Command palette (Ctrl/Cmd+K). One box for: jumping to any page the signed-in user may open (nav.js is the single list of pages,
// so licensing and feature flags are respected), recent pages, actions (switch module, theme, copy link, shortcuts), and
// finding / asset lookup through the same data the top search bar uses. Fuzzy matched and highlighted (fuzzy.js).
// If a natural-language structured-query API (/api/ask/structured) exists it could be added as another group; it does not
// exist in this build, so there is no row for it (nothing is faked).
import { openableNav, visibleItems, NAV, isLicensed } from "./nav.js";
import { getCurrentUser } from "./auth.js";
import { icon } from "./icons.js";
import { escapeHtml } from "./dom.js";
import { rank, highlight } from "./fuzzy.js";
import { lookupData } from "./search.js";
import { toast, showShortcuts, debounce } from "./ui.js";

const RECENT_KEY = "quanta.recent";
const THEME_KEY = "quanta.theme";
let el = null;
let items = [];      // what is shown, in order
let sel = 0;
let user = null;

// ---- recent pages (the router calls recordVisit after each page loads)
function readRecent() { try { return JSON.parse(localStorage.getItem(RECENT_KEY) || "[]"); } catch { return []; } }
export function recordVisit(path, title) {
  if (!path || path === "/login" || path === "/logout") return;
  const list = readRecent().filter((r) => r.path !== path);
  list.unshift({ path, title: title || path });
  try { localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, 6))); } catch { /* private window */ }
}

// ---- theme: "auto" follows the system; "dark"/"light" force it (variables only, see ui.css)
export function currentTheme() { try { return localStorage.getItem(THEME_KEY) || "auto"; } catch { return "auto"; } }
export function applyTheme(mode) {
  const root = document.documentElement;
  if (mode === "dark" || mode === "light") root.setAttribute("data-theme", mode); else root.removeAttribute("data-theme");
  try { if (mode === "auto") localStorage.removeItem(THEME_KEY); else localStorage.setItem(THEME_KEY, mode); } catch { /* ignore */ }
}
export function initTheme() { applyTheme(currentTheme()); }
function cycleTheme() {
  const next = { auto: "dark", dark: "light", light: "auto" }[currentTheme()];
  applyTheme(next);
  toast(`Theme: ${next === "auto" ? "follow system" : next}`, { ms: 2500 });
}

function navigate(path) {
  window.history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

// ---- building the list of things the palette knows about
function pageItems() {
  const isAdmin = user && user.role === "admin";
  const out = [];
  const seen = new Set();
  for (const group of openableNav()) {
    for (const item of [...visibleItems(group.items), ...visibleItems(group.connectors || [])]) {
      if (/^admin\b/i.test(item.tip || "") && !isAdmin) continue; // admin-only pages are not offered to others
      const k = item.path;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push({ kind: "page", label: item.label, sub: group.group, icon: item.icon, path: item.path, extra: item.tip || "" });
    }
  }
  return out;
}

function actionItems() {
  const acts = [];
  NAV.filter((g) => g.id !== "home" && g.id !== "help").forEach((m) => {
    acts.push({ kind: "action", label: `Switch to ${m.group}`, sub: "Module", icon: m.icon, run: () => navigate(`/capabilities?area=${m.id}`), locked: !isLicensed(m.id) });
  });
  acts.push({ kind: "action", label: "Toggle theme (auto / dark / light)", sub: "Action", icon: "dashboard", run: cycleTheme });
  acts.push({ kind: "action", label: "Copy link to this page", sub: "Action", icon: "pin", run: async () => {
    try { await navigator.clipboard.writeText(window.location.href); toast("Link copied", { tone: "good", ms: 2500 }); } catch { toast("Could not copy the link here", { tone: "warn", ms: 3000 }); }
  } });
  acts.push({ kind: "action", label: "Keyboard shortcuts", sub: "Press ?", icon: "faq", run: () => setTimeout(showShortcuts, 0) });
  return acts.filter((a) => !a.locked);
}

function recentItems() {
  return readRecent().filter((r) => r.path !== window.location.pathname + window.location.search).slice(0, 5)
    .map((r) => ({ kind: "recent", label: r.title, sub: "Recent", icon: "clock", path: r.path }));
}

// ---- rendering
const GROUP_TITLES = { recent: "Recent", page: "Pages", action: "Actions", data: "Findings and assets" };
function render() {
  const list = el.querySelector(".pal-list");
  const input = el.querySelector(".pal-input");
  if (!items.length) {
    list.innerHTML = `<div class="pal-empty">No match. Try a page name, a finding ID, a CVE or an asset.</div>`;
    input.removeAttribute("aria-activedescendant");
    return;
  }
  let last = null;
  list.innerHTML = items.map((it, i) => {
    const head = it.kind !== last ? `<div class="pal-group" role="presentation">${GROUP_TITLES[it.kind]}</div>` : "";
    last = it.kind;
    const label = it.hl ? highlight(it.label, it.hl) : escapeHtml(it.label);
    return `${head}<button type="button" class="pal-item" role="option" id="pal-o${i}" data-i="${i}" aria-selected="${i === sel}" tabindex="-1">
      <span class="pal-ico">${icon(it.icon || "search", 16)}</span><span class="pal-label">${label}</span>${it.tag ? `<span class="ui-chip">${escapeHtml(it.tag)}</span>` : ""}<span class="pal-sub">${escapeHtml(it.sub || "")}</span></button>`;
  }).join("");
  input.setAttribute("aria-activedescendant", `pal-o${sel}`);
  const active = list.querySelector('[aria-selected="true"]');
  if (active) active.scrollIntoView({ block: "nearest" });
}

let dataResults = [];
let dataFor = "";
function compute() {
  const q = el.querySelector(".pal-input").value.trim();
  if (!q) {
    items = [...recentItems(), ...pageItems().slice(0, 8), ...actionItems().slice(0, 3)];
  } else {
    const pages = rank(pageItems(), q, (p) => [p.label, p.sub, p.extra], 8).map((r) => ({ ...r.item, hl: r.indices }));
    const acts = rank(actionItems(), q, (a) => [a.label], 4).map((r) => ({ ...r.item, hl: r.indices }));
    items = [...pages, ...acts, ...(dataFor === q ? dataResults : [])];
  }
  sel = Math.min(sel, Math.max(0, items.length - 1));
  render();
}

const fetchData = debounce(async () => {
  if (!el) return;
  const q = el.querySelector(".pal-input").value.trim();
  if (q.length < 2) { dataResults = []; dataFor = ""; return; }
  try {
    const rows = await lookupData(q);
    if (!el || el.querySelector(".pal-input").value.trim() !== q) return; // the box moved on
    dataFor = q;
    dataResults = rows.slice(0, 8).map((r) => ({ kind: "data", label: `${r.id}${r.title && r.title !== r.id ? " · " + r.title : ""}`, sub: r.source, tag: r.tag, icon: r.source === "Assets" ? "assets" : "scan", path: r.href }));
    sel = Math.min(sel, Math.max(0, items.length - 1));
    compute();
  } catch { /* the search sources may be unavailable; pages and actions still work */ }
}, 220);

function run(it) {
  if (!it) return;
  close();
  if (it.run) it.run(); else if (it.path) navigate(it.path);
}

function onKey(e) {
  if (!el) return;
  if (e.key === "Escape") { e.preventDefault(); close(); }
  else if (e.key === "ArrowDown") { e.preventDefault(); sel = (sel + 1) % Math.max(items.length, 1); render(); }
  else if (e.key === "ArrowUp") { e.preventDefault(); sel = (sel - 1 + Math.max(items.length, 1)) % Math.max(items.length, 1); render(); }
  else if (e.key === "Home" && e.target.value === "") { sel = 0; render(); }
  else if (e.key === "Enter") { e.preventDefault(); run(items[sel]); }
  else if (e.key === "Tab") { e.preventDefault(); el.querySelector(".pal-input").focus(); } // keep focus in the box; the list follows with the arrows
}

let opener = null;
function close() {
  if (!el) return;
  document.removeEventListener("keydown", onKey, true);
  el.remove();
  el = null;
  dataResults = [];
  dataFor = "";
  fetchData.cancel();
  if (opener && opener.isConnected) { try { opener.focus(); } catch { /* ignore */ } }
}

async function open() {
  if (el) return;
  opener = document.activeElement;
  try { user = await getCurrentUser(); } catch { user = null; }
  el = document.createElement("div");
  el.className = "pal-backdrop";
  el.innerHTML = `<div class="pal" role="dialog" aria-modal="true" aria-label="Command palette">
    <div class="pal-input-row">${icon("search", 18)}<input class="pal-input" type="text" role="combobox" aria-expanded="true" aria-controls="pal-list" aria-autocomplete="list" autocomplete="off" spellcheck="false" placeholder="Search pages, actions, findings, assets…" aria-label="Search pages, actions, findings and assets"></div>
    <div class="pal-list" id="pal-list" role="listbox" aria-label="Results"></div>
    <div class="pal-foot"><span><kbd>↑</kbd> <kbd>↓</kbd> move</span><span><kbd>Enter</kbd> open</span><span><kbd>Esc</kbd> close</span><span><kbd>?</kbd> shortcuts</span></div></div>`;
  document.body.appendChild(el);
  const input = el.querySelector(".pal-input");
  input.addEventListener("input", () => { sel = 0; compute(); fetchData(); });
  el.addEventListener("mousedown", (e) => { if (e.target === el) close(); });
  el.querySelector(".pal-list").addEventListener("click", (e) => { const b = e.target.closest("[data-i]"); if (b) run(items[Number(b.dataset.i)]); });
  el.querySelector(".pal-list").addEventListener("mousemove", (e) => { const b = e.target.closest("[data-i]"); if (b && Number(b.dataset.i) !== sel) { sel = Number(b.dataset.i); el.querySelectorAll(".pal-item").forEach((n, i) => n.setAttribute("aria-selected", String(i === sel))); input.setAttribute("aria-activedescendant", `pal-o${sel}`); } });
  document.addEventListener("keydown", onKey, true);
  sel = 0;
  compute();
  input.focus();
}

export function openPalette() { return open(); }
export function closePalette() { close(); }

export function initCommandPalette() {
  initTheme();
  document.addEventListener("keydown", (e) => {
    const isMac = /mac/i.test(navigator.platform || "");
    if ((isMac ? e.metaKey : e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); if (el) close(); else open(); }
  });
}
