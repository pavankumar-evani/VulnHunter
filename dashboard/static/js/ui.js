// Quanta UI kit: the small set of building blocks every page should use instead of hand-rolled markup.
// Vanilla JS, no dependency, no build step. Documented with live examples at /design-system and in docs/UI_KIT.md.
//
// Conventions
//   - Functions that return markup return a STRING and escape every value they are given; `html` arguments are trusted markup.
//   - Functions that attach behaviour take an element and return a `destroy()`; the router also runs anything registered with
//     onCleanup() when the page changes, so a page that uses the kit does not leak listeners or timers.
//   - Motion is skipped when the user prefers reduced motion. Nothing here needs a pointer: every control is a real button/link.
import { escapeHtml } from "./dom.js";
import { icon } from "./icons.js";
import { SEVERITY_COLORS } from "./charts.js";
import {
  sortRows, virtualWindow, toCsv, clampWidth, sparkPoints, delta, easeCount, ageLabel, ageState,
} from "./tableMath.js";

const reducedMotion = () => typeof window !== "undefined" && window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const store = {
  get(k) { try { return window.localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { window.localStorage.setItem(k, v); } catch { /* private window: preference just is not kept */ } },
};
let uid = 0;
const nextId = (p) => `${p}-${++uid}`;

// ---------------------------------------------------------------- page lifecycle: cleanup contract and error boundary
// A page's render() may return a cleanup function (existing contract), AND may call onCleanup(fn) any number of times
// (e.g. next to the setInterval or live.subscribe it starts). The router calls runCleanups() before the next page renders.
let cleanups = [];
export function onCleanup(fn) { if (typeof fn === "function") cleanups.push(fn); return fn; }
export function runCleanups() {
  const list = cleanups;
  cleanups = [];
  for (const fn of list.reverse()) { try { fn(); } catch (err) { console.error("page cleanup failed", err); } }
  return list.length;
}
export const pendingCleanups = () => cleanups.length;

// Markup shown when a page fails to load or render, with a retry button (the router wires `data-retry`).
export function errorBoundaryHtml(err, { title = "This page could not be shown" } = {}) {
  const msg = (err && err.message) || String(err || "Unknown error");
  return `<div class="ui-error" role="alert"><div class="ui-error-icon">${icon("risk", 22)}</div>
    <div><h2>${escapeHtml(title)}</h2><p>${escapeHtml(msg)}</p>
    <p class="ui-muted">The rest of the app still works. Nothing was changed.</p>
    <button type="button" class="ui-btn" data-retry>Try again</button> <a class="ui-btn ui-btn-ghost" href="/" data-link>Go to Home</a></div></div>`;
}

export function debounce(fn, ms = 200) {
  let t = null;
  const wrapped = (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
  wrapped.cancel = () => clearTimeout(t);
  return wrapped;
}

// ---------------------------------------------------------------- chips, badges, tooltips
const SEV = ["critical", "high", "medium", "low", "info"];
export function chip(label, { tone = "neutral", title = "" } = {}) {
  return `<span class="ui-chip ui-chip-${escapeHtml(tone)}"${title ? ` data-tooltip="${escapeHtml(title)}"` : ""}>${escapeHtml(label)}</span>`;
}
// Severity chip: the colours come from the shared chart palette, so a chip, a badge and a chart bar always agree.
export function severityChip(severity) {
  const key = String(severity || "").toLowerCase();
  const known = SEV.includes(key);
  const label = known ? key[0].toUpperCase() + key.slice(1) : String(severity || "Unknown");
  const color = SEVERITY_COLORS[label] || "";
  return `<span class="ui-chip ui-chip-sev ui-chip-${known ? key : "neutral"}"${color ? ` style="--chip-c:${color}"` : ""}><span class="ui-chip-dot" aria-hidden="true"></span>${escapeHtml(label)}</span>`;
}
// Attributes that attach the app's shared tooltip (tooltip.js) to any element.
export const tipAttr = (text) => `data-tooltip="${escapeHtml(text)}"`;

// ---------------------------------------------------------------- KPI tile, sparkline, delta chip, counters
export function sparkline(values, { width = 84, height = 28, color = "var(--brand-accent)", label = "Trend" } = {}) {
  const pts = sparkPoints(values, width, height);
  if (!pts.length) return "";
  const line = pts.map((p) => p.join(",")).join(" ");
  const last = pts[pts.length - 1];
  const area = `${pts[0][0]},${height} ${line} ${last[0]},${height}`;
  return `<svg class="ui-spark" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="img" aria-label="${escapeHtml(label)}: ${values.length} points, from ${escapeHtml(values[0])} to ${escapeHtml(values[values.length - 1])}">
    <polygon points="${area}" fill="${color}" opacity=".14"/><polyline points="${line}" fill="none" stroke="${color}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="${last[0]}" cy="${last[1]}" r="2.4" fill="${color}"/></svg>`;
}

// goodWhen: which direction is good news ("down" for vulnerabilities, "up" for coverage). Colour never carries meaning alone: the arrow does too.
export function deltaChip(current, previous, { goodWhen = "down", unit = "%", label = "vs previous" } = {}) {
  const d = delta(current, previous);
  if (!d) return "";
  const arrow = d.dir === "up" ? "▲" : d.dir === "down" ? "▼" : "■";
  const tone = d.dir === "flat" ? "flat" : d.dir === goodWhen ? "good" : "bad";
  const text = d.pct === null ? "new" : `${d.pct > 0 ? "+" : ""}${d.pct}${unit}`;
  return `<span class="ui-delta ui-delta-${tone}" ${tipAttr(`${label}: ${previous} → ${current}`)}><span aria-hidden="true">${arrow}</span> ${escapeHtml(text)}<span class="ui-sr"> ${d.dir === "flat" ? "no change" : d.dir === "up" ? "up" : "down"} ${escapeHtml(label)}</span></span>`;
}

// value: a number animates up to itself (data-count); a string is shown as-is. href makes the whole tile a link.
export function kpiTile({ label, value, previous, spark, href, tone = "", goodWhen = "down", hint = "", decimals = 0, suffix = "" }) {
  const isNum = typeof value === "number" && Number.isFinite(value);
  const val = isNum ? `<span class="ui-kpi-num" data-count="${value}" data-decimals="${decimals}">${value.toLocaleString(undefined, { maximumFractionDigits: decimals, minimumFractionDigits: decimals })}</span>${escapeHtml(suffix)}` : escapeHtml(value ?? "—");
  const body = `<div class="ui-kpi-top"><span class="ui-kpi-label">${escapeHtml(label)}</span>${hint ? `<span class="ui-kpi-hint" ${tipAttr(hint)} tabindex="0" aria-label="${escapeHtml(hint)}">${icon("faq", 13)}</span>` : ""}</div>
    <div class="ui-kpi-value">${val}</div>
    <div class="ui-kpi-foot">${isNum && previous !== undefined ? deltaChip(value, previous, { goodWhen }) : ""}${spark && spark.length > 1 ? sparkline(spark, { label }) : ""}</div>`;
  const cls = `ui-kpi${tone ? ` ui-kpi-${tone}` : ""}${href ? " ui-kpi-link" : ""}`;
  return href ? `<a class="${cls}" href="${escapeHtml(href)}" data-link>${body}</a>` : `<div class="${cls}">${body}</div>`;
}

// Animate every [data-count] under root from 0 (or its last value) to its target. Skipped under reduced motion.
export function animateNumber(el, to, { duration = 700, from = 0, decimals = 0 } = {}) {
  const fmt = (n) => n.toLocaleString(undefined, { maximumFractionDigits: decimals, minimumFractionDigits: decimals });
  if (reducedMotion() || duration <= 0) { el.textContent = fmt(to); return () => {}; }
  let raf = 0;
  const t0 = performance.now();
  const step = (now) => {
    const t = (now - t0) / duration;
    el.textContent = fmt(easeCount(from, to, t, decimals));
    if (t < 1) raf = requestAnimationFrame(step); else el.textContent = fmt(to);
  };
  raf = requestAnimationFrame(step);
  return () => cancelAnimationFrame(raf);
}
export function mountCounters(root) {
  const stops = [...root.querySelectorAll("[data-count]")].map((el) => animateNumber(el, Number(el.dataset.count), { decimals: Number(el.dataset.decimals || 0) }));
  const stop = () => stops.forEach((s) => s());
  onCleanup(stop);
  return stop;
}

// ---------------------------------------------------------------- skeletons and empty states
export function skeleton(kind = "card", n = 1) {
  const one = {
    kpi: `<div class="ui-skel ui-skel-kpi" aria-hidden="true"><i class="ui-skel-line w40"></i><i class="ui-skel-line w60 tall"></i><i class="ui-skel-line w30"></i></div>`,
    card: `<div class="ui-skel ui-skel-card" aria-hidden="true"><i class="ui-skel-line w50 tall"></i><i class="ui-skel-line"></i><i class="ui-skel-line w80"></i><i class="ui-skel-line w60"></i></div>`,
    table: `<div class="ui-skel ui-skel-table" aria-hidden="true">${"<i class=\"ui-skel-line\"></i>".repeat(6)}</div>`,
    text: `<div class="ui-skel" aria-hidden="true"><i class="ui-skel-line"></i><i class="ui-skel-line w80"></i><i class="ui-skel-line w60"></i></div>`,
  }[kind] || "";
  const grid = kind === "kpi" ? "ui-skel-grid" : "";
  return `<div class="${grid}" role="status" aria-live="polite" aria-label="Loading"><span class="ui-sr">Loading…</span>${one.repeat(n)}</div>`;
}
// What a page shows while it loads: no blank flash, no layout shift (same grid as the real content).
export function pageSkeleton() {
  return `<div class="ui-page-skel">${skeleton("kpi", 4)}${skeleton("card", 2)}${skeleton("table")}</div>`;
}

export function emptyState({ title, body = "", actionLabel = "", actionHref = "", iconName = "search" }) {
  return `<div class="ui-empty"><div class="ui-empty-icon" aria-hidden="true">${icon(iconName, 26)}</div><h3>${escapeHtml(title)}</h3>
    ${body ? `<p>${escapeHtml(body)}</p>` : ""}${actionLabel && actionHref ? `<a class="ui-btn" href="${escapeHtml(actionHref)}" data-link>${escapeHtml(actionLabel)}</a>` : ""}</div>`;
}

// ---------------------------------------------------------------- data age badge
// "Updated 12s ago", turning amber then red as it ages. One shared timer updates every badge on the page.
export function dataAgeBadge(ts, { fresh = 60000, stale = 600000, label = "Updated" } = {}) {
  const t = ts instanceof Date ? ts.getTime() : Number(ts) || Date.now();
  return `<span class="ui-age ui-age-fresh" data-age-ts="${t}" data-age-fresh="${fresh}" data-age-stale="${stale}" data-age-label="${escapeHtml(label)}" role="status"><span class="ui-age-dot" aria-hidden="true"></span><span class="ui-age-text">${escapeHtml(label)} just now</span></span>`;
}
let ageTimer = null;
function tickAges() {
  const els = document.querySelectorAll("[data-age-ts]");
  if (!els.length) { clearInterval(ageTimer); ageTimer = null; return; }
  const now = Date.now();
  els.forEach((el) => {
    const ms = now - Number(el.dataset.ageTs);
    el.className = `ui-age ui-age-${ageState(ms, Number(el.dataset.ageFresh), Number(el.dataset.ageStale))}`;
    const text = el.querySelector(".ui-age-text");
    if (text) text.textContent = `${el.dataset.ageLabel} ${ageLabel(ms)}`;
  });
}
export function mountDataAge(root = document) {
  if (root.querySelector && root.querySelector("[data-age-ts]")) tickAges();
  if (!ageTimer) ageTimer = setInterval(tickAges, 5000);
}
export function touchDataAge(el, ts = Date.now()) { if (el) { el.dataset.ageTs = String(ts); tickAges(); } }

// ---------------------------------------------------------------- toasts
let toastHost = null;
export function toast(message, { tone = "info", href = "", ms = 6000, action = "" } = {}) {
  if (!toastHost) {
    toastHost = document.createElement("div");
    toastHost.className = "ui-toasts";
    toastHost.setAttribute("role", "region");
    toastHost.setAttribute("aria-label", "Notifications");
    document.body.appendChild(toastHost);
  }
  while (toastHost.children.length >= 4) toastHost.firstChild.remove();
  const el = document.createElement("div");
  el.className = `ui-toast ui-toast-${tone}`;
  el.setAttribute("role", tone === "bad" || tone === "critical" ? "alert" : "status");
  const link = href ? `<a href="${escapeHtml(href)}" data-link class="ui-toast-link">${escapeHtml(action || "Open")}</a>` : "";
  el.innerHTML = `<span class="ui-toast-msg">${escapeHtml(message)}</span>${link}<button type="button" class="ui-toast-x" aria-label="Dismiss">&times;</button>`;
  const dismiss = () => { el.classList.add("out"); setTimeout(() => el.remove(), reducedMotion() ? 0 : 200); };
  el.querySelector(".ui-toast-x").addEventListener("click", dismiss);
  if (link) el.querySelector("a").addEventListener("click", dismiss);
  toastHost.appendChild(el);
  if (ms > 0) setTimeout(dismiss, ms);
  return dismiss;
}

// ---------------------------------------------------------------- drawer (side panel)
// Detail in context instead of a full navigation. Esc closes, focus is trapped inside and returned on close.
export function openDrawer({ title, html, width = 520, onClose } = {}) {
  const opener = document.activeElement;
  const root = document.createElement("div");
  root.className = "ui-drawer-root";
  const titleId = nextId("drawer-title");
  root.innerHTML = `<div class="ui-drawer-scrim" data-close></div>
    <aside class="ui-drawer" role="dialog" aria-modal="true" aria-labelledby="${titleId}" style="--drawer-w:${Number(width)}px">
      <header><h2 id="${titleId}">${escapeHtml(title)}</h2><button type="button" class="ui-icon-btn" data-close aria-label="Close panel">&times;</button></header>
      <div class="ui-drawer-body">${html || ""}</div></aside>`;
  document.body.appendChild(root);
  const panel = root.querySelector(".ui-drawer");
  const focusables = () => [...panel.querySelectorAll('a[href],button:not([disabled]),input,select,textarea,[tabindex]:not([tabindex="-1"])')];
  setTimeout(() => { root.classList.add("open"); (focusables()[1] || focusables()[0] || panel).focus(); }, 20);
  const close = () => {
    document.removeEventListener("keydown", onKey, true);
    root.classList.remove("open");
    setTimeout(() => root.remove(), reducedMotion() ? 0 : 200);
    if (opener && opener.focus) try { opener.focus(); } catch { /* element gone */ }
    if (onClose) onClose();
  };
  function onKey(e) {
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(); return; }
    if (e.key !== "Tab") return;
    const f = focusables();
    if (!f.length) return;
    const first = f[0]; const last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }
  document.addEventListener("keydown", onKey, true);
  root.addEventListener("click", (e) => { if (e.target.closest("[data-close]")) close(); });
  onCleanup(() => { if (root.isConnected) close(); });
  return { close, body: root.querySelector(".ui-drawer-body"), root };
}

// ---------------------------------------------------------------- keyboard shortcuts and the cheat sheet
const shortcuts = [
  { keys: ["Ctrl/⌘", "K"], text: "Open the command palette" },
  { keys: ["/"], text: "Focus the search box" },
  { keys: ["?"], text: "Show this cheat sheet" },
  { keys: ["g", "h"], text: "Go to Home" },
  { keys: ["g", "m"], text: "Go to all modules" },
  { keys: ["g", "q"], text: "Go to the remediation queue" },
  { keys: ["Esc"], text: "Close a panel, palette or dialog" },
  { keys: ["↑", "↓", "Enter"], text: "Move through and open palette results" },
];
export const registerShortcutHelp = (keys, text) => { shortcuts.push({ keys, text }); };
export function shortcutSheetHtml() {
  return `<table class="ui-keys"><tbody>${shortcuts.map((s) => `<tr><td>${s.keys.map((k) => `<kbd>${escapeHtml(k)}</kbd>`).join(" ")}</td><td>${escapeHtml(s.text)}</td></tr>`).join("")}</tbody></table>`;
}
export function showShortcuts() { return openDrawer({ title: "Keyboard shortcuts", html: shortcutSheetHtml(), width: 420 }); }

const isTyping = (t) => t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
function go(path) { window.history.pushState({}, "", path); window.dispatchEvent(new PopStateEvent("popstate")); }
let shortcutsWired = false;
export function initShortcuts() {
  if (shortcutsWired) return;
  shortcutsWired = true;
  let pendingG = 0;
  document.addEventListener("keydown", (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey || isTyping(e.target)) return;
    if (e.key === "?") { e.preventDefault(); showShortcuts(); return; }
    if (e.key === "/") {
      const box = document.getElementById("global-search-input");
      if (box) { e.preventDefault(); box.focus(); box.select(); }
      return;
    }
    if (e.key === "g") { pendingG = Date.now(); return; }
    if (pendingG && Date.now() - pendingG < 1200) {
      const dest = { h: "/", m: "/capabilities", q: "/queue" }[e.key];
      pendingG = 0;
      if (dest) { e.preventDefault(); go(dest); }
    }
  });
}

// ---------------------------------------------------------------- the shared data table
// columns: [{ key, label, type?: "text"|"number"|"date"|"severity", value?(row), render?(row)->trusted html, align?, width?, hidden?, sortable? }]
// opts: rows, rowKey(row), onRowClick(row), csvName, storageKey (remembers sort/widths/hidden columns), filterable, virtualAt (default 500), rowHeight (default 40),
//       emptyHtml, caption (accessible name), maxHeight.
// Above `virtualAt` rows only the rows in view are in the DOM. Returns { setRows, destroy, getView }.
export function dataTable(host, opts) {
  const o = { virtualAt: 500, rowHeight: 40, filterable: true, maxHeight: 560, ...opts };
  const columns = o.columns.map((c) => ({ type: "text", sortable: true, ...c }));
  const key = o.storageKey ? `quanta.table.${o.storageKey}` : null;
  const saved = (() => { try { return key ? JSON.parse(store.get(key) || "{}") : {}; } catch { return {}; } })();
  const st = {
    rows: o.rows || [],
    sortKey: saved.sortKey || o.sortKey || null,
    sortDir: saved.sortDir || o.sortDir || "asc",
    filter: "",
    hidden: new Set(saved.hidden || columns.filter((c) => c.hidden).map((c) => c.key)),
    widths: saved.widths || {},
    view: [],
  };
  const id = nextId("uit");
  const cellValue = (row, c) => (c.value ? c.value(row) : row[c.key]);
  const persist = () => { if (key) store.set(key, JSON.stringify({ sortKey: st.sortKey, sortDir: st.sortDir, hidden: [...st.hidden], widths: st.widths })); };

  host.innerHTML = `<div class="ui-table" id="${id}">
    <div class="ui-table-bar">
      ${o.filterable ? `<label class="ui-table-filter"><span class="ui-sr">Filter rows</span>${icon("search", 14)}<input type="search" placeholder="Filter…" autocomplete="off"></label>` : ""}
      <span class="ui-table-count" role="status" aria-live="polite"></span>
      <span class="ui-table-tools">
        <span class="ui-menu-wrap"><button type="button" class="ui-btn ui-btn-ghost ui-cols-btn" aria-haspopup="true" aria-expanded="false">Columns</button><div class="ui-menu" hidden role="group" aria-label="Choose columns"></div></span>
        <button type="button" class="ui-btn ui-btn-ghost ui-csv-btn">Export CSV</button>
      </span>
    </div>
    <div class="ui-table-wrap" tabindex="0" role="region" aria-label="${escapeHtml(o.caption || "Table")}" style="max-height:${Number(o.maxHeight)}px">
      <table><caption class="ui-sr">${escapeHtml(o.caption || "Table")}</caption><colgroup></colgroup><thead><tr></tr></thead><tbody></tbody></table>
    </div></div>`;
  const root = host.querySelector(".ui-table");
  const wrap = root.querySelector(".ui-table-wrap");
  const table = root.querySelector("table");
  const colgroup = root.querySelector("colgroup");
  const headRow = root.querySelector("thead tr");
  const tbody = root.querySelector("tbody");
  const countEl = root.querySelector(".ui-table-count");
  const filterInput = root.querySelector(".ui-table-filter input");
  const menu = root.querySelector(".ui-menu");
  const colsBtn = root.querySelector(".ui-cols-btn");
  const csvBtn = root.querySelector(".ui-csv-btn");
  const visibleCols = () => columns.filter((c) => !st.hidden.has(c.key));

  function computeView() {
    let rows = st.rows;
    const q = st.filter.trim().toLowerCase();
    if (q) rows = rows.filter((r) => columns.some((c) => String(cellValue(r, c) ?? "").toLowerCase().includes(q)));
    const col = columns.find((c) => c.key === st.sortKey);
    st.view = col ? sortRows(rows, (r) => cellValue(r, col), col.type, st.sortDir) : rows;
  }

  function drawHead() {
    const cols = visibleCols();
    colgroup.innerHTML = cols.map((c) => `<col data-col="${escapeHtml(c.key)}"${st.widths[c.key] ? ` style="width:${st.widths[c.key]}px"` : (c.width ? ` style="width:${Number(c.width)}px"` : "")}>`).join("");
    headRow.innerHTML = cols.map((c) => {
      const sorted = st.sortKey === c.key;
      const aria = sorted ? (st.sortDir === "asc" ? "ascending" : "descending") : "none";
      return `<th scope="col" data-col="${escapeHtml(c.key)}" aria-sort="${aria}" class="${c.align === "right" ? "num" : ""}">
        ${c.sortable ? `<button type="button" class="ui-th-btn" data-sort="${escapeHtml(c.key)}">${escapeHtml(c.label)}<span class="ui-sort" aria-hidden="true">${sorted ? (st.sortDir === "asc" ? "▲" : "▼") : ""}</span></button>` : escapeHtml(c.label)}
        <span class="ui-th-resize" role="separator" aria-orientation="vertical" aria-label="Resize ${escapeHtml(c.label)} column" tabindex="0" data-resize="${escapeHtml(c.key)}"></span></th>`;
    }).join("");
  }

  function rowHtml(r, i) {
    const cols = visibleCols();
    const k = o.rowKey ? escapeHtml(o.rowKey(r)) : i;
    return `<tr data-i="${i}" data-key="${k}"${o.onRowClick ? ' tabindex="0" class="ui-row-click"' : ""} style="height:${o.rowHeight}px">${cols.map((c) => {
      const raw = cellValue(r, c);
      const content = c.render ? c.render(r) : escapeHtml(raw ?? "");
      return `<td class="${c.align === "right" ? "num" : ""}"${c.render ? "" : ` title="${escapeHtml(raw ?? "")}"`}>${content}</td>`;
    }).join("")}</tr>`;
  }

  function drawBody() {
    const total = st.view.length;
    const cols = visibleCols().length;
    if (!total) {
      tbody.innerHTML = `<tr><td colspan="${cols}" class="ui-table-empty">${o.emptyHtml || emptyState({ title: st.filter ? "No rows match this filter" : "Nothing to show yet", body: st.filter ? "Clear the filter to see every row." : "" })}</td></tr>`;
      return;
    }
    if (total <= o.virtualAt) {
      tbody.innerHTML = st.view.map(rowHtml).join("");
      return;
    }
    const w = virtualWindow({ total, rowHeight: o.rowHeight, viewportHeight: wrap.clientHeight || o.maxHeight, scrollTop: wrap.scrollTop });
    tbody.innerHTML = `${w.padTop ? `<tr class="ui-pad" aria-hidden="true" style="height:${w.padTop}px"><td colspan="${cols}"></td></tr>` : ""}` +
      st.view.slice(w.start, w.end).map((r, j) => rowHtml(r, w.start + j)).join("") +
      `${w.padBottom ? `<tr class="ui-pad" aria-hidden="true" style="height:${w.padBottom}px"><td colspan="${cols}"></td></tr>` : ""}`;
  }

  function drawCount() {
    const total = st.rows.length;
    countEl.textContent = st.view.length === total ? `${total.toLocaleString()} rows${total > o.virtualAt ? " (virtualised)" : ""}` : `${st.view.length.toLocaleString()} of ${total.toLocaleString()} rows`;
    csvBtn.hidden = total < (o.csvMin ?? 1);
  }

  function drawMenu() {
    menu.innerHTML = columns.map((c) => `<label class="ui-menu-item"><input type="checkbox" data-colkey="${escapeHtml(c.key)}" ${st.hidden.has(c.key) ? "" : "checked"}> ${escapeHtml(c.label)}</label>`).join("");
  }

  function redraw({ head = false } = {}) {
    computeView();
    if (head) drawHead();
    drawBody();
    drawCount();
  }

  // events
  const onFilter = debounce(() => { st.filter = filterInput.value; wrap.scrollTop = 0; redraw(); }, 180);
  if (filterInput) filterInput.addEventListener("input", onFilter);
  headRow.addEventListener("click", (e) => {
    const b = e.target.closest("[data-sort]");
    if (!b) return;
    const k = b.dataset.sort;
    st.sortDir = st.sortKey === k && st.sortDir === "asc" ? "desc" : "asc";
    st.sortKey = k;
    persist();
    redraw({ head: true });
  });
  let scrollRaf = 0;
  const onScroll = () => { if (st.view.length > o.virtualAt && !scrollRaf) scrollRaf = requestAnimationFrame(() => { scrollRaf = 0; drawBody(); }); };
  wrap.addEventListener("scroll", onScroll, { passive: true });
  tbody.addEventListener("click", (e) => { const tr = e.target.closest("tr[data-i]"); if (tr && o.onRowClick && !e.target.closest("a,button")) o.onRowClick(st.view[Number(tr.dataset.i)], e); });
  tbody.addEventListener("keydown", (e) => { const tr = e.target.closest("tr[data-i]"); if (tr && o.onRowClick && e.key === "Enter") o.onRowClick(st.view[Number(tr.dataset.i)], e); });

  // resizing: pointer drag and keyboard (arrow keys on the handle)
  const setWidth = (k, px) => { st.widths[k] = clampWidth(px); const c = colgroup.querySelector(`col[data-col="${CSS.escape(k)}"]`); if (c) c.style.width = `${st.widths[k]}px`; };
  headRow.addEventListener("pointerdown", (e) => {
    const h = e.target.closest("[data-resize]");
    if (!h) return;
    e.preventDefault();
    const k = h.dataset.resize;
    const th = h.closest("th");
    const startX = e.clientX;
    const startW = th.getBoundingClientRect().width;
    table.classList.add("ui-resizing");
    const move = (ev) => setWidth(k, startW + ev.clientX - startX);
    const up = () => { document.removeEventListener("pointermove", move); document.removeEventListener("pointerup", up); table.classList.remove("ui-resizing"); persist(); };
    document.addEventListener("pointermove", move);
    document.addEventListener("pointerup", up);
  });
  headRow.addEventListener("keydown", (e) => {
    const h = e.target.closest("[data-resize]");
    if (!h || !/^Arrow(Left|Right)$/.test(e.key)) return;
    e.preventDefault();
    const w = h.closest("th").getBoundingClientRect().width;
    setWidth(h.dataset.resize, w + (e.key === "ArrowRight" ? 16 : -16));
    persist();
  });

  // column chooser
  drawMenu();
  const closeMenu = () => { menu.hidden = true; colsBtn.setAttribute("aria-expanded", "false"); };
  colsBtn.addEventListener("click", (e) => { e.stopPropagation(); menu.hidden = !menu.hidden; colsBtn.setAttribute("aria-expanded", String(!menu.hidden)); });
  menu.addEventListener("change", (e) => {
    const cb = e.target.closest("[data-colkey]");
    if (!cb) return;
    if (cb.checked) st.hidden.delete(cb.dataset.colkey); else if (visibleCols().length > 1) st.hidden.add(cb.dataset.colkey); else cb.checked = true;
    persist();
    redraw({ head: true });
  });
  const onDocClick = (e) => { if (!menu.hidden && !e.target.closest(".ui-menu-wrap")) closeMenu(); };
  const onDocKey = (e) => { if (e.key === "Escape" && !menu.hidden) { closeMenu(); colsBtn.focus(); } };
  document.addEventListener("click", onDocClick);
  document.addEventListener("keydown", onDocKey);

  // CSV of what is shown (the filtered, sorted, visible-column view)
  csvBtn.addEventListener("click", () => {
    const cols = visibleCols();
    const csv = toCsv(cols, st.view, (r, c) => (c.csv ? c.csv(r) : cellValue(r, c)));
    const blob = new Blob([`﻿${csv}`], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${o.csvName || "quanta-table"}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });

  redraw({ head: true });

  const destroy = () => {
    document.removeEventListener("click", onDocClick);
    document.removeEventListener("keydown", onDocKey);
    onFilter.cancel();
    if (scrollRaf) cancelAnimationFrame(scrollRaf);
    host.innerHTML = "";
  };
  onCleanup(destroy);
  return {
    setRows(rows) { st.rows = rows || []; redraw(); },
    destroy,
    getView: () => st.view,
    root,
  };
}

// ---------------------------------------------------------------- a section card
export function card({ title = "", subtitle = "", body = "", actions = "", cls = "" } = {}) {
  return `<section class="ui-card ${escapeHtml(cls)}">${title || actions ? `<header class="ui-card-head"><div><h3>${escapeHtml(title)}</h3>${subtitle ? `<p class="ui-muted">${escapeHtml(subtitle)}</p>` : ""}</div>${actions ? `<div class="ui-card-actions">${actions}</div>` : ""}</header>` : ""}<div class="ui-card-body">${body}</div></section>`;
}
