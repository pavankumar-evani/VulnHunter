// Small shared building blocks for the SOC and Threat Hunting pages (modal with a focus trap, pop-up menu, avatar, SLA ring, copy and download helpers).
// They sit on top of ui.js and add nothing to the global kit; every value passed in is escaped here.
import { escapeHtml } from "./dom.js";
import { toast, onCleanup } from "./ui.js";
import { initials, hueOf, ringDash } from "./socLogic.js";

const reduced = () => typeof window !== "undefined" && window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
let uid = 0;

// ---------------------------------------------------------------- modal
// Resolves with `collect(root)` when the person confirms, or null when they cancel. `validate(root)` returns an error string to keep it open.
export function modal({ title, body, confirmLabel = "Confirm", cancelLabel = "Cancel", danger = false, collect = () => true, validate = null, wide = false, hideConfirm = false, description = "" }) {
  return new Promise((resolve) => {
    const opener = document.activeElement;
    const id = `sx-modal-${++uid}`;
    const root = document.createElement("div");
    root.className = "sx-modal-root";
    root.innerHTML = `<div class="sx-modal-scrim" data-cancel></div>
      <div class="sx-modal${wide ? " sx-modal-wide" : ""}" role="dialog" aria-modal="true" aria-labelledby="${id}-t"${description ? ` aria-describedby="${id}-d"` : ""}>
        <header><h2 id="${id}-t">${escapeHtml(title)}</h2><button type="button" class="ui-icon-btn" data-cancel aria-label="Close">&times;</button></header>
        ${description ? `<p class="ui-muted sx-modal-desc" id="${id}-d">${escapeHtml(description)}</p>` : ""}
        <div class="sx-modal-body">${body}</div>
        <p class="sx-modal-error" role="alert" hidden></p>
        <footer><button type="button" class="ui-btn ui-btn-ghost" data-cancel>${escapeHtml(cancelLabel)}</button>${hideConfirm ? "" : `<button type="button" class="ui-btn${danger ? " sx-btn-danger" : ""}" data-ok>${escapeHtml(confirmLabel)}</button>`}</footer>
      </div>`;
    document.body.appendChild(root);
    const dialog = root.querySelector(".sx-modal");
    const focusables = () => [...dialog.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select,textarea,[tabindex]:not([tabindex="-1"])')];
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      document.removeEventListener("keydown", onKey, true);
      root.classList.remove("open");
      setTimeout(() => root.remove(), reduced() ? 0 : 160);
      if (opener && opener.isConnected && opener.focus) try { opener.focus(); } catch { /* gone */ }
      resolve(value);
    };
    function onKey(e) {
      if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); finish(null); return; }
      if (e.key === "Enter" && e.target.tagName !== "TEXTAREA" && e.target.tagName !== "BUTTON" && e.target.tagName !== "A") { e.preventDefault(); ok(); return; }
      if (e.key !== "Tab") return;
      const f = focusables();
      if (!f.length) return;
      if (e.shiftKey && document.activeElement === f[0]) { e.preventDefault(); f[f.length - 1].focus(); }
      else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { e.preventDefault(); f[0].focus(); }
    }
    function ok() {
      const err = validate ? validate(dialog) : "";
      const box = dialog.querySelector(".sx-modal-error");
      if (err) { box.textContent = err; box.hidden = false; return; }
      box.hidden = true;
      finish(collect(dialog));
    }
    root.addEventListener("click", (e) => { if (e.target.closest("[data-cancel]")) finish(null); else if (e.target.closest("[data-ok]")) ok(); });
    document.addEventListener("keydown", onKey, true);
    onCleanup(() => { if (!done) finish(null); });
    requestAnimationFrame(() => { root.classList.add("open"); const f = dialog.querySelector("[autofocus],input,select,textarea") || focusables()[1] || focusables()[0]; if (f) f.focus(); });
  });
}
export const modalOpen = () => !!document.querySelector(".sx-modal-root,.ui-drawer-root,.pal-backdrop");

// ---------------------------------------------------------------- pop-up menu anchored to a button
export function popMenu(anchor, items, { align = "right" } = {}) {
  document.querySelectorAll(".sx-popmenu").forEach((m) => m.remove());
  const menu = document.createElement("div");
  menu.className = `sx-popmenu sx-pop-${align}`;
  menu.setAttribute("role", "menu");
  menu.innerHTML = items.map((it, i) => it.sep ? '<hr>' : `<button type="button" role="menuitem" data-i="${i}"${it.disabled ? " disabled" : ""}>${escapeHtml(it.label)}${it.hint ? `<small>${escapeHtml(it.hint)}</small>` : ""}</button>`).join("");
  const host = anchor.closest(".sx-pop-host") || anchor.parentElement;
  host.classList.add("sx-pop-host");
  host.appendChild(menu);
  const buttons = () => [...menu.querySelectorAll("button:not([disabled])")];
  const close = () => { document.removeEventListener("mousedown", away, true); document.removeEventListener("keydown", key, true); menu.remove(); if (anchor.isConnected) anchor.setAttribute("aria-expanded", "false"); };
  const away = (e) => { if (!menu.contains(e.target) && e.target !== anchor && !anchor.contains(e.target)) close(); };
  const key = (e) => {
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(); anchor.focus(); return; }
    const b = buttons();
    const i = b.indexOf(document.activeElement);
    if (e.key === "ArrowDown") { e.preventDefault(); (b[i + 1] || b[0]).focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); (b[i - 1] || b[b.length - 1]).focus(); }
  };
  menu.addEventListener("click", (e) => { const b = e.target.closest("[data-i]"); if (!b) return; const it = items[Number(b.dataset.i)]; close(); if (it && it.run) it.run(); });
  document.addEventListener("mousedown", away, true);
  document.addEventListener("keydown", key, true);
  anchor.setAttribute("aria-expanded", "true");
  onCleanup(close);
  const first = buttons()[0];
  if (first) first.focus();
  return close;
}

// ---------------------------------------------------------------- small renderers
export function avatar(email, { size = 26 } = {}) {
  if (!email) return `<span class="sx-avatar sx-avatar-none" style="--sz:${size}px" aria-hidden="true">–</span>`;
  return `<span class="sx-avatar" style="--sz:${size}px;--h:${hueOf(email)}" aria-hidden="true">${escapeHtml(initials(email))}</span>`;
}
export function ringSvg(ring, { size = 30, radius = 11 } = {}) {
  const { circumference, offset } = ringDash(ring.fraction, radius);
  const text = ring.state === "breached" ? "!" : ring.state === "done" ? "✓" : "";
  return `<svg class="sx-ring sx-ring-${ring.state}" viewBox="0 0 30 30" width="${size}" height="${size}" role="img" aria-label="${escapeHtml(ring.label)}">
    <circle cx="15" cy="15" r="${radius}" class="sx-ring-bg"/><circle cx="15" cy="15" r="${radius}" class="sx-ring-fg" stroke-dasharray="${circumference}" stroke-dashoffset="${offset}" transform="rotate(-90 15 15)"/>
    ${text ? `<text x="15" y="19" text-anchor="middle" class="sx-ring-t">${text}</text>` : ""}</svg>`;
}
export function liveBadge(mode) {
  const label = mode === "live" ? "Live" : mode === "poll" ? "Refreshing every 20 s" : mode === "reconnecting" ? "Reconnecting" : "Connecting";
  return `<span class="sx-live sx-live-${escapeHtml(mode)}" role="status"><span class="sx-live-dot" aria-hidden="true"></span>${escapeHtml(label)}</span>`;
}
export const fmtWhen = (s) => (s ? String(s).replace("T", " ").replace(/:\d\dZ$/, "Z").replace("Z", " UTC") : "");
export function relTime(s, now = Date.now()) {
  const t = Date.parse(s);
  if (Number.isNaN(t)) return "";
  const m = Math.round((now - t) / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  return h < 48 ? `${h} h ago` : `${Math.round(h / 24)} d ago`;
}

export async function copyText(text, okMessage = "Copied") {
  try { await navigator.clipboard.writeText(text); toast(okMessage, { tone: "good", ms: 2200 }); return true; }
  catch {
    const ta = document.createElement("textarea");
    ta.value = text; ta.setAttribute("readonly", ""); ta.className = "ui-sr"; document.body.appendChild(ta); ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch { ok = false; }
    ta.remove();
    toast(ok ? okMessage : "Could not copy here. Select the text and copy it by hand.", { tone: ok ? "good" : "warn", ms: 3000 });
    return ok;
  }
}
export function downloadText(filename, text, mime = "text/markdown") {
  const url = URL.createObjectURL(new Blob([text], { type: `${mime};charset=utf-8` }));
  const a = document.createElement("a");
  a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

// Segmented control: [{id,label,count}] -> buttons with aria-pressed; wire with onSeg(root, cb).
export function segmented(name, options, current) {
  return `<div class="sx-seg" role="group" aria-label="${escapeHtml(name)}">${options.map((o) => `<button type="button" data-seg="${escapeHtml(o.id)}" aria-pressed="${o.id === current}">${escapeHtml(o.label)}${o.count !== undefined ? `<span class="sx-seg-n">${o.count}</span>` : ""}</button>`).join("")}</div>`;
}
export function onSeg(root, cb) {
  root.addEventListener("click", (e) => { const b = e.target.closest("[data-seg]"); if (b && root.contains(b)) cb(b.dataset.seg, b.closest("[role=group]")); });
}
// Tabs with roving keyboard support. `host` contains .ui-tabs buttons [data-tab] and panels [data-panel].
export function wireTabs(host, onChange) {
  const tabs = () => [...host.querySelectorAll("[data-tab]")];
  const select = (id, focus = false) => {
    tabs().forEach((t) => { const on = t.dataset.tab === id; t.setAttribute("aria-selected", String(on)); t.tabIndex = on ? 0 : -1; if (on && focus) t.focus(); });
    host.querySelectorAll("[data-panel]").forEach((p) => { p.hidden = p.dataset.panel !== id; });
    if (onChange) onChange(id);
  };
  host.addEventListener("click", (e) => { const t = e.target.closest("[data-tab]"); if (t && host.contains(t)) select(t.dataset.tab); });
  host.addEventListener("keydown", (e) => {
    const t = e.target.closest("[data-tab]");
    if (!t || !["ArrowRight", "ArrowLeft", "Home", "End"].includes(e.key)) return;
    e.preventDefault();
    const all = tabs(); const i = all.indexOf(t);
    const next = e.key === "Home" ? 0 : e.key === "End" ? all.length - 1 : (i + (e.key === "ArrowRight" ? 1 : -1) + all.length) % all.length;
    select(all[next].dataset.tab, true);
  });
  return select;
}
