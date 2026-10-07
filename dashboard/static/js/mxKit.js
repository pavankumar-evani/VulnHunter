// Building blocks shared by the rebuilt module pages (queue, assignments, approvals, exceptions, posture, risk, ...): a selectable, sortable,
// virtualised table whose sort/filter state is owned by the page (so it can live in the URL), a small popover, a KPI strip, a tab bar,
// and a handful of renderers. Sits on top of ui.js / sxKit.js and adds nothing to the global kit. Every value passed in is escaped here.
import { escapeHtml } from "./dom.js";
import { icon } from "./icons.js";
import { kpiTile, onCleanup, mountCounters, tipAttr, emptyState, debounce } from "./ui.js";
import { live } from "./live.js";
import { registerPaletteActions } from "./commandPalette.js";
import { virtualWindow, toCsv, clampWidth } from "./tableMath.js";
import { rangeSelection, toggleSelection, selectionState, moveFocusIndex } from "./queueLogic.js";

const store = {
  get(k) { try { return window.localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { window.localStorage.setItem(k, v); } catch { /* private window */ } },
};
export const readJson = (k, fallback) => { const raw = store.get(k); if (!raw) return fallback; try { return JSON.parse(raw); } catch { return fallback; } };
export const writeJson = (k, v) => store.set(k, JSON.stringify(v));

// Keep the address bar in step with the page state without adding history entries or re-rendering the route.
export function replaceSearch(search) {
  const url = `${window.location.pathname}${search || ""}`;
  if (url !== `${window.location.pathname}${window.location.search}`) window.history.replaceState(window.history.state, "", url);
}

let uid = 0;
// ---------------------------------------------------------------- the table
// columns: [{ key, label, width, align, sortKey, render(row), csv(row), hidden }]; rows are already filtered and sorted by the page.
// opts: rowKey(row), rowHeight, maxHeight, selectable, sort {key,dir}, onSort(sortKey), onOpen(row), onSelection(Set), storageKey, caption, csvName, rowClass(row),
//       emptyHtml, virtualAt (default 150), toolsHtml (extra markup in the bar), selected (Set)
export function selectableTable(host, opts) {
  const o = { rowHeight: 46, maxHeight: 620, virtualAt: 150, selectable: false, sort: { key: "", dir: "desc" }, ...opts };
  const id = `mxt-${++uid}`;
  const columns = o.columns;
  const saved = o.storageKey ? readJson(`quanta.cols.${o.storageKey}`, null) : null;
  const st = {
    rows: o.rows || [], hidden: new Set(saved ? saved.hidden : columns.filter((c) => c.hidden).map((c) => c.key)), widths: (saved && saved.widths) || {},
    selected: o.selected || new Set(), sort: { ...o.sort }, anchor: null, focus: -1,
  };
  const persist = () => { if (o.storageKey) writeJson(`quanta.cols.${o.storageKey}`, { hidden: [...st.hidden], widths: st.widths }); };
  const visible = () => columns.filter((c) => !st.hidden.has(c.key));
  const colspan = () => visible().length + (o.selectable ? 1 : 0);

  host.innerHTML = `<div class="ui-table mx-table" id="${id}">
    <div class="ui-table-bar mx-table-bar"><span class="ui-table-count mx-table-count" role="status" aria-live="polite"></span><span class="ui-table-tools mx-table-tools">${o.toolsHtml || ""}
      <span class="ui-menu-wrap"><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm mx-cols-btn" aria-haspopup="true" aria-expanded="false">Columns</button><div class="ui-menu" hidden role="group" aria-label="Choose columns"></div></span>
      <button type="button" class="ui-btn ui-btn-ghost sx-btn-sm mx-csv-btn">Export CSV</button></span></div>
    <div class="ui-table-wrap mx-wrap" tabindex="0" role="region" aria-label="${escapeHtml(o.caption || "Table")}" style="max-height:${Number(o.maxHeight)}px">
      <table class="mx-grid"><caption class="ui-sr">${escapeHtml(o.caption || "Table")}</caption><colgroup></colgroup><thead><tr></tr></thead><tbody></tbody></table></div></div>`;
  const root = host.querySelector(".ui-table");
  const wrap = root.querySelector(".ui-table-wrap");
  const colgroup = root.querySelector("colgroup");
  const headRow = root.querySelector("thead tr");
  const tbody = root.querySelector("tbody");
  const countEl = root.querySelector(".ui-table-count");
  const menu = root.querySelector(".ui-menu");
  const colsBtn = root.querySelector(".mx-cols-btn");
  const csvBtn = root.querySelector(".mx-csv-btn");
  const keys = () => st.rows.map(o.rowKey);

  function drawHead() {
    const cols = visible();
    const sel = o.selectable ? selectionState(st.selected, keys()) : "none";
    colgroup.innerHTML = (o.selectable ? '<col style="width:38px">' : "") + cols.map((c) => `<col data-col="${escapeHtml(c.key)}"${st.widths[c.key] ? ` style="width:${st.widths[c.key]}px"` : c.width ? ` style="width:${Number(c.width)}px"` : ""}>`).join("");
    headRow.innerHTML = (o.selectable ? `<th class="mx-sel-th"><input type="checkbox" class="mx-sel-all" aria-label="Select all ${st.rows.length} rows in this view" ${sel === "all" ? "checked" : ""}></th>` : "") +
      cols.map((c) => {
        const sk = c.sortKey;
        const sorted = sk && st.sort.key === sk;
        const aria = sorted ? (st.sort.dir === "asc" ? "ascending" : "descending") : "none";
        return `<th scope="col" data-col="${escapeHtml(c.key)}" aria-sort="${aria}" class="${c.align === "right" ? "num" : ""}">${sk ? `<button type="button" class="ui-th-btn" data-sort="${escapeHtml(sk)}">${escapeHtml(c.label)}<span class="ui-sort" aria-hidden="true">${sorted ? (st.sort.dir === "asc" ? "▲" : "▼") : ""}</span></button>` : escapeHtml(c.label)}
          <span class="ui-th-resize" role="separator" aria-orientation="vertical" aria-label="Resize ${escapeHtml(c.label)} column" tabindex="0" data-resize="${escapeHtml(c.key)}"></span></th>`;
      }).join("");
    const all = headRow.querySelector(".mx-sel-all");
    if (all) all.indeterminate = sel === "some";
  }

  function rowHtml(r, i) {
    const k = String(o.rowKey(r));
    const on = st.selected.has(k);
    return `<tr data-i="${i}" data-key="${escapeHtml(k)}" tabindex="${i === st.focus ? 0 : -1}" class="mx-row${on ? " is-selected" : ""}${o.rowClass ? ` ${o.rowClass(r)}` : ""}" aria-selected="${on}" style="height:${o.rowHeight}px">${o.selectable ? `<td class="mx-sel-td"><input type="checkbox" class="mx-sel" data-id="${escapeHtml(k)}" aria-label="Select ${escapeHtml(k)}" ${on ? "checked" : ""}></td>` : ""}${visible().map((c) => `<td class="${c.align === "right" ? "num" : ""}">${c.render(r)}</td>`).join("")}</tr>`;
  }

  function drawBody() {
    const total = st.rows.length;
    if (!total) { tbody.innerHTML = `<tr><td colspan="${colspan()}" class="ui-table-empty">${o.emptyHtml || emptyState({ title: "Nothing to show", body: "" })}</td></tr>`; return; }
    if (total <= o.virtualAt) { tbody.innerHTML = st.rows.map(rowHtml).join(""); return; }
    const w = virtualWindow({ total, rowHeight: o.rowHeight, viewportHeight: wrap.clientHeight || o.maxHeight, scrollTop: wrap.scrollTop, overscan: 10 });
    tbody.innerHTML = `${w.padTop ? `<tr class="ui-pad" aria-hidden="true" style="height:${w.padTop}px"><td colspan="${colspan()}"></td></tr>` : ""}${st.rows.slice(w.start, w.end).map((r, j) => rowHtml(r, w.start + j)).join("")}${w.padBottom ? `<tr class="ui-pad" aria-hidden="true" style="height:${w.padBottom}px"><td colspan="${colspan()}"></td></tr>` : ""}`;
  }
  const drawCount = () => {
    const n = st.rows.length;
    const sel = st.selected.size;
    countEl.textContent = `${n.toLocaleString()} row${n === 1 ? "" : "s"}${n > o.virtualAt ? " (virtualised)" : ""}${sel ? `, ${sel.toLocaleString()} selected` : ""}`;
    csvBtn.hidden = !n;
  };
  const drawMenu = () => { menu.innerHTML = columns.map((c) => `<label class="ui-menu-item"><input type="checkbox" data-colkey="${escapeHtml(c.key)}" ${st.hidden.has(c.key) ? "" : "checked"}> ${escapeHtml(c.label)}</label>`).join(""); };
  const redraw = ({ head = true } = {}) => { if (head) drawHead(); drawBody(); drawCount(); };

  // sorting
  headRow.addEventListener("click", (e) => { const b = e.target.closest("[data-sort]"); if (b && o.onSort) o.onSort(b.dataset.sort); });
  // selection
  const emitSelection = () => { drawCount(); if (o.onSelection) o.onSelection(new Set(st.selected)); };
  headRow.addEventListener("change", (e) => {
    if (!e.target.classList.contains("mx-sel-all")) return;
    st.selected = e.target.checked ? new Set([...st.selected, ...keys()]) : new Set([...st.selected].filter((k) => !keys().includes(k)));
    redraw(); emitSelection();
  });
  tbody.addEventListener("click", (e) => {
    const cb = e.target.closest(".mx-sel");
    const tr = e.target.closest("tr[data-i]");
    if (cb && tr) {
      const k = cb.dataset.id;
      st.selected = e.shiftKey && st.anchor ? rangeSelection(st.selected, keys(), st.anchor, k) : toggleSelection(st.selected, k);
      st.anchor = k;
      redraw(); emitSelection();
      return;
    }
    if (tr && o.onOpen && !e.target.closest("a,button,input,select,label")) { st.focus = Number(tr.dataset.i); o.onOpen(st.rows[st.focus], e); }
  });
  tbody.addEventListener("keydown", (e) => {
    const tr = e.target.closest("tr[data-i]");
    if (!tr || e.target.closest("input,button,a,select")) return;
    const i = Number(tr.dataset.i);
    if (e.key === "Enter" && o.onOpen) { e.preventDefault(); o.onOpen(st.rows[i], e); return; }
    if ((e.key === " " || e.key === "x") && o.selectable) {
      e.preventDefault();
      const k = String(o.rowKey(st.rows[i]));
      st.selected = toggleSelection(st.selected, k); st.anchor = k; st.focus = i; redraw({ head: true }); emitSelection(); focusIndex(i); return;
    }
    if (["ArrowDown", "ArrowUp", "j", "k", "PageDown", "PageUp", "Home", "End"].includes(e.key)) { e.preventDefault(); focusIndex(moveFocusIndex(i, e.key, st.rows.length, 10)); }
  });
  function focusIndex(i) {
    if (i < 0) return;
    st.focus = i;
    const top = i * o.rowHeight;
    if (top < wrap.scrollTop) wrap.scrollTop = top; else if (top + o.rowHeight > wrap.scrollTop + wrap.clientHeight - 40) wrap.scrollTop = top - wrap.clientHeight + o.rowHeight + 48;
    drawBody();
    const tr = tbody.querySelector(`tr[data-i="${i}"]`);
    if (tr) { tr.tabIndex = 0; tr.focus({ preventScroll: true }); }
  }
  let raf = 0;
  const onScroll = () => { if (st.rows.length > o.virtualAt && !raf) raf = requestAnimationFrame(() => { raf = 0; drawBody(); }); };
  wrap.addEventListener("scroll", onScroll, { passive: true });

  // column resizing and chooser
  const setWidth = (k, px) => { st.widths[k] = clampWidth(px); const c = colgroup.querySelector(`col[data-col="${CSS.escape(k)}"]`); if (c) c.style.width = `${st.widths[k]}px`; };
  headRow.addEventListener("pointerdown", (e) => {
    const h = e.target.closest("[data-resize]");
    if (!h) return;
    e.preventDefault();
    const k = h.dataset.resize; const startX = e.clientX; const startW = h.closest("th").getBoundingClientRect().width;
    const move = (ev) => setWidth(k, startW + ev.clientX - startX);
    const up = () => { document.removeEventListener("pointermove", move); document.removeEventListener("pointerup", up); persist(); };
    document.addEventListener("pointermove", move); document.addEventListener("pointerup", up);
  });
  headRow.addEventListener("keydown", (e) => {
    const h = e.target.closest("[data-resize]");
    if (!h || !/^Arrow(Left|Right)$/.test(e.key)) return;
    e.preventDefault(); setWidth(h.dataset.resize, h.closest("th").getBoundingClientRect().width + (e.key === "ArrowRight" ? 16 : -16)); persist();
  });
  drawMenu();
  const closeMenu = () => { menu.hidden = true; colsBtn.setAttribute("aria-expanded", "false"); };
  colsBtn.addEventListener("click", (e) => { e.stopPropagation(); menu.hidden = !menu.hidden; colsBtn.setAttribute("aria-expanded", String(!menu.hidden)); });
  menu.addEventListener("change", (e) => {
    const cb = e.target.closest("[data-colkey]");
    if (!cb) return;
    if (cb.checked) st.hidden.delete(cb.dataset.colkey); else if (visible().length > 1) st.hidden.add(cb.dataset.colkey); else cb.checked = true;
    persist(); redraw();
  });
  const onDocClick = (e) => { if (!menu.hidden && !e.target.closest(".ui-menu-wrap")) closeMenu(); };
  const onDocKey = (e) => { if (e.key === "Escape" && !menu.hidden) { closeMenu(); colsBtn.focus(); } };
  document.addEventListener("click", onDocClick); document.addEventListener("keydown", onDocKey);

  csvBtn.addEventListener("click", () => {
    const cols = visible();
    const csv = toCsv(cols, st.rows, (r, c) => (c.csv ? c.csv(r) : ""));
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([`﻿${csv}`], { type: "text/csv;charset=utf-8" }));
    a.download = `${o.csvName || "quanta-table"}.csv`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });

  redraw();
  const destroy = () => { document.removeEventListener("click", onDocClick); document.removeEventListener("keydown", onDocKey); if (raf) cancelAnimationFrame(raf); host.innerHTML = ""; };
  onCleanup(destroy);
  return {
    setRows(rows) { st.rows = rows || []; redraw(); },
    setSort(sort) { st.sort = { ...sort }; drawHead(); },
    setSelected(set) { st.selected = new Set(set); redraw(); },
    getSelected: () => new Set(st.selected),
    clearSelection() { st.selected = new Set(); redraw(); emitSelection(); },
    scrollToKey(k) { const i = keys().indexOf(k); if (i >= 0) { wrap.scrollTop = Math.max(0, i * o.rowHeight - 80); drawBody(); const tr = tbody.querySelector(`tr[data-i="${i}"]`); if (tr) tr.classList.add("mx-flash"); } return i; },
    visibleColumnLabels: () => visible().map((c) => c.label),
    destroy, root,
  };
}

// ---------------------------------------------------------------- popover anchored to a button (closes on Esc and on outside click)
export function popover(anchor, html, { label = "Details", align = "left", onClose } = {}) {
  document.querySelectorAll(".mx-popover").forEach((n) => n.remove());
  const pop = document.createElement("div");
  pop.className = `mx-popover mx-pop-${align}`;
  pop.setAttribute("role", "dialog");
  pop.setAttribute("aria-label", label);
  pop.innerHTML = html;
  const host = anchor.closest(".sx-pop-host") || anchor.parentElement;
  host.classList.add("sx-pop-host");
  host.appendChild(pop);
  anchor.setAttribute("aria-expanded", "true");
  const close = () => { document.removeEventListener("mousedown", away, true); document.removeEventListener("keydown", key, true); pop.remove(); if (anchor.isConnected) anchor.setAttribute("aria-expanded", "false"); if (onClose) onClose(); };
  const away = (e) => { if (!pop.contains(e.target) && !anchor.contains(e.target)) close(); };
  const key = (e) => { if (e.key === "Escape") { e.stopPropagation(); close(); anchor.focus(); } };
  document.addEventListener("mousedown", away, true);
  document.addEventListener("keydown", key, true);
  onCleanup(close);
  return { close, el: pop };
}

// ---------------------------------------------------------------- KPI strip: each tile is a button that sets a filter (aria-pressed shows when it is on)
// tiles: [{ key, label, value, hint, tone, pressed, spark, previous, goodWhen, filterable, suffix, decimals }]
export function kpiStrip(host, tiles, onPick, leadingHtml = "") {
  host.innerHTML = leadingHtml + tiles.map((t) => {
    const tile = kpiTile({ label: t.label, value: t.value, hint: t.hint, tone: t.tone || "", spark: t.spark, previous: t.previous, goodWhen: t.goodWhen, suffix: t.suffix, decimals: t.decimals });
    return t.filterable === false ? `<div class="sx-kpi-cell">${tile}</div>` : `<div class="sx-kpi-cell" data-kpi="${escapeHtml(t.key)}" role="button" tabindex="0" aria-pressed="${!!t.pressed}" aria-label="${escapeHtml(t.label)}: ${escapeHtml(String(t.value))}. ${t.pressed ? "Filter on. Activate to clear." : "Activate to filter."}">${tile}</div>`;
  }).join("");
  host.hidden = false;
  mountCounters(host);
  const act = (el) => { const c = el.closest("[data-kpi]"); if (c && onPick) onPick(c.dataset.kpi); };
  host.onclick = (e) => act(e.target);
  host.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { const c = e.target.closest("[data-kpi]"); if (c) { e.preventDefault(); act(c); } } };
}

// ---------------------------------------------------------------- small renderers
export function stackedBar(parts, { label = "Breakdown", height = 8 } = {}) {
  const total = parts.reduce((s, p) => s + p.value, 0) || 1;
  return `<div class="mx-stack" role="img" aria-label="${escapeHtml(label)}: ${parts.map((p) => `${p.value} ${p.label}`).join(", ")}" style="height:${height}px">${parts.filter((p) => p.value > 0).map((p) => `<i style="width:${(p.value / total) * 100}%;background:${p.color}" ${tipAttr(`${p.value} ${p.label}`)}></i>`).join("")}</div>`;
}
export function meter(fraction, { tone = "", label = "" } = {}) {
  const pct = Math.round(Math.max(0, Math.min(1, fraction)) * 100);
  return `<span class="mx-meter ${tone}" role="img" aria-label="${escapeHtml(label || `${pct}%`)}"><i style="width:${pct}%"></i></span>`;
}
// Radar chart (SVG): axes = [{label, value 0..1}]. Filled polygon plus rings; every axis value is also written out for screen readers.
export function radarSvg(axes, { size = 240, label = "Scores by area" } = {}) {
  const n = axes.length;
  if (n < 3) return "";
  const W = Math.round(size * 1.7); const H = size; const cx = W / 2; const c = size / 2; const r = size / 2 - 30;
  const pt = (i, f) => { const a = (-Math.PI / 2) + (i * 2 * Math.PI) / n; return [cx + Math.cos(a) * r * f, c + Math.sin(a) * r * f]; };
  const ring = (f) => axes.map((_, i) => pt(i, f).map((v) => v.toFixed(1)).join(",")).join(" ");
  const poly = axes.map((a, i) => pt(i, Math.max(0.02, Math.min(1, a.value))).map((v) => v.toFixed(1)).join(",")).join(" ");
  const labels = axes.map((a, i) => { const [x, y] = pt(i, 1.14); const anchor = x < cx - 8 ? "end" : x > cx + 8 ? "start" : "middle"; const t = a.label.length > 26 ? `${a.label.slice(0, 25)}…` : a.label; return `<text x="${x.toFixed(1)}" y="${y.toFixed(1)}" text-anchor="${anchor}" dominant-baseline="middle" class="mx-radar-t"><title>${escapeHtml(a.label)}: ${Math.round(a.value * 100)}%</title>${escapeHtml(t)}</text>`; }).join("");
  return `<svg class="mx-radar" viewBox="0 0 ${W} ${H}" role="img" aria-label="${escapeHtml(label)}: ${axes.map((a) => `${a.label} ${Math.round(a.value * 100)}%`).join(", ")}">
    ${[0.25, 0.5, 0.75, 1].map((f) => `<polygon points="${ring(f)}" class="mx-radar-ring"/>`).join("")}${axes.map((_, i) => `<line x1="${cx}" y1="${c}" x2="${pt(i, 1)[0].toFixed(1)}" y2="${pt(i, 1)[1].toFixed(1)}" class="mx-radar-ring"/>`).join("")}
    <polygon points="${poly}" class="mx-radar-area"/>${axes.map((a, i) => { const [x, y] = pt(i, Math.max(0.02, Math.min(1, a.value))); return `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3" class="mx-radar-dot"/>`; }).join("")}${labels}</svg>`;
}

// Tab bar with roving tabindex. tabs: [{id,label,count}]; returns markup; wire with wireTabBar(root, cb).
export function tabBar(name, tabs, current) {
  return `<div class="mx-tabs" role="tablist" aria-label="${escapeHtml(name)}">${tabs.map((t) => `<button type="button" role="tab" data-tab="${escapeHtml(t.id)}" aria-selected="${t.id === current}" tabindex="${t.id === current ? 0 : -1}">${escapeHtml(t.label)}${t.count !== undefined ? `<span class="sx-seg-n">${t.count}</span>` : ""}</button>`).join("")}</div>`;
}
export function wireTabBar(root, cb) {
  root.addEventListener("click", (e) => { const b = e.target.closest("[data-tab]"); if (b && root.contains(b)) cb(b.dataset.tab); });
  root.addEventListener("keydown", (e) => {
    const b = e.target.closest("[data-tab]");
    if (!b || !["ArrowRight", "ArrowLeft", "Home", "End"].includes(e.key)) return;
    e.preventDefault();
    const all = [...root.querySelectorAll("[data-tab]")]; const i = all.indexOf(b);
    const next = e.key === "Home" ? 0 : e.key === "End" ? all.length - 1 : (i + (e.key === "ArrowRight" ? 1 : -1) + all.length) % all.length;
    all[next].focus(); cb(all[next].dataset.tab);
  });
}

// A "copy" button for an exact value (a setting, a command, an id). Wire once with wireCopy(root).
export function copyButton(text, label = "Copy") {
  return `<button type="button" class="mx-copy" data-copy="${escapeHtml(text)}" aria-label="${escapeHtml(label)}: ${escapeHtml(String(text).slice(0, 60))}">${icon("document", 13)} ${escapeHtml(label)}</button>`;
}
export function wireCopy(root, copyText) {
  root.addEventListener("click", (e) => { const b = e.target.closest("[data-copy]"); if (b && root.contains(b)) copyText(b.dataset.copy, "Copied"); });
}

export function initialsOf(email) { return String(email || "?").split("@")[0].slice(0, 2).toUpperCase(); }
export function pageHead({ title, sub, rightHtml = "" }) {
  return `<div class="sx-head"><div><h2>${escapeHtml(title)}</h2><p>${escapeHtml(sub)}</p></div><div class="sx-row">${rightHtml}</div></div>`;
}
export function skeletonPage(n = 4) {
  return `<div class="ui-skel-grid" aria-hidden="true">${Array.from({ length: n }, () => '<div class="ui-skel ui-skel-kpi"><span class="ui-skel-line w40"></span><span class="ui-skel-line tall w60"></span></div>').join("")}</div><div class="ui-skel ui-skel-table" aria-hidden="true">${'<i class="ui-skel-line"></i>'.repeat(6)}</div>`;
}

// ---------------------------------------------------------------- refresh: live event when the stream is up, otherwise a timer. Stops on route change.
// fn() reloads and repaints; onMode("live" | "poll") lets the page show the same Live badge the SOC page has.
export function autoRefresh(fn, { every = 20000, onMode } = {}) {
  let lastRun = Date.now();
  const call = () => { lastRun = Date.now(); return fn(); };
  const run = debounce(() => { if (!document.hidden) call(); }, 400);
  const modeOf = () => (live.state.mode === "sse" ? "live" : "poll");
  const offA = live.subscribe("activity", run);
  const offM = live.subscribe("live.mode", () => { if (onMode) onMode(modeOf()); });
  // While the stream is healthy a timer is only a safety net (three times as slow); without it the timer is the refresh.
  const t = setInterval(() => { if (!document.hidden && (live.state.mode !== "sse" || Date.now() - lastRun > every * 3)) call(); }, every);
  if (onMode) onMode(modeOf());
  const stop = () => { clearInterval(t); offA(); offM(); run.cancel(); };
  onCleanup(stop);
  return stop;
}

// Key actions of a page in the command palette while the page is open. [{label, run, icon?, sub?}]
export function pageActions(list) {
  const off = registerPaletteActions(list);
  onCleanup(off);
  return off;
}
