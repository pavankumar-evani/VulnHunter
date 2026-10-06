// The living style guide: every component of the UI kit (ui.js) rendered live, with the call that produces it.
// Anything shown here is the real component, not a picture of it. Reference: docs/UI_KIT.md.
import { escapeHtml } from "../dom.js";
import { live } from "../live.js";
import { currentTheme, applyTheme, openPalette } from "../commandPalette.js";
import {
  card, chip, severityChip, kpiTile, sparkline, deltaChip, skeleton, emptyState, dataAgeBadge, mountDataAge, mountCounters,
  dataTable, openDrawer, toast, showShortcuts, shortcutSheetHtml, onCleanup, errorBoundaryHtml, tipAttr,
} from "../ui.js";

export const title = "Design system";

const code = (s) => `<pre><code>${escapeHtml(s)}</code></pre>`;
const section = (id, name, intro, demo, snippet) => `<section id="${id}" class="ui-card"><div class="ui-card-head"><div><h3>${escapeHtml(name)}</h3><p class="ui-muted">${intro}</p></div></div>${demo}${snippet ? code(snippet) : ""}</section>`;

const TOKENS = [
  ["--bg", "Page background"], ["--surface", "Cards and panels"], ["--border", "Hairlines"], ["--text", "Body text"], ["--text-muted", "Secondary text"],
  ["--brand-accent", "Links, focus, selection"], ["--brand", "Chrome navy"], ["--ui-good", "Good news"], ["--ui-warn", "Caution"], ["--ui-bad", "Bad news"],
];
const CHARTS = Array.from({ length: 8 }, (_, i) => `--chart-${i + 1}`);

function demoRows(n) {
  const sev = ["Critical", "High", "Medium", "Low"];
  return Array.from({ length: n }, (_, i) => ({
    id: `DEMO-${String(i + 1).padStart(4, "0")}`, severity: sev[(i * 7 + (i >> 2)) % 4], asset: `host-${(i * 13) % 97}.example.test`, score: Math.round(((i * 37) % 1000) / 10) / 10,
    seen: new Date(Date.UTC(2026, 0, 1) + ((i * 86400000 * 3) % (86400000 * 280))).toISOString().slice(0, 10),
  }));
}
const COLS = [
  { key: "id", label: "ID", width: 130 },
  { key: "severity", label: "Severity", type: "severity", render: (r) => severityChip(r.severity), width: 120 },
  { key: "asset", label: "Asset" },
  { key: "score", label: "Score", type: "number", align: "right", width: 90 },
  { key: "seen", label: "First seen", type: "date", width: 120 },
];

export async function render(container) {
  const spark = [12, 14, 13, 18, 17, 22, 20, 26, 24, 31];
  const liveMode = () => live.state.mode;
  container.innerHTML = `<p class="subtitle">The building blocks every page uses. Everything here is the real component. Keyboard: <kbd>Ctrl</kbd> <kbd>K</kbd> palette, <kbd>/</kbd> search, <kbd>?</kbd> shortcuts.</p>
  <div class="ui-ds"><nav class="ui-ds-nav" aria-label="On this page">
    ${[["tokens", "Colour"], ["buttons", "Buttons"], ["chips", "Chips"], ["kpi", "KPI tiles"], ["age", "Data age"], ["loading", "Skeletons"], ["empty", "Empty states"], ["table", "Tables"], ["drawer", "Drawer"], ["toast", "Toasts"], ["tips", "Tooltips"], ["keys", "Shortcuts"], ["palette", "Command palette"], ["live", "Live updates"], ["lifecycle", "Page contract"]]
      .map(([id, n]) => `<a href="#${id}">${n}</a>`).join("")}</nav>
  <div>
    ${section("tokens", "Colour", "Theme variables, defined once in style.css and re-used by everything. Charts take their categorical colours from --chart-1..8 and severity from the shared severity palette.",
      `<div class="ui-swatches">${TOKENS.map(([v, n]) => `<div class="ui-swatch"><i style="background:var(${v})"></i><code>${v}</code><br>${n}</div>`).join("")}</div>
       <p class="ui-muted" style="margin:14px 0 6px">Categorical (nominal data, fixed order)</p><div class="ui-swatches">${CHARTS.map((v) => `<div class="ui-swatch"><i style="background:var(${v})"></i><code>${v}</code></div>`).join("")}</div>
       <p style="margin:14px 0 6px"><span class="ui-muted">Theme:</span> <button type="button" class="ui-btn ui-btn-ghost" id="ds-theme">${escapeHtml(currentTheme())}</button> <span class="ui-muted">(auto follows your system; changes colour variables)</span></p>`)}
    ${section("buttons", "Buttons", "One primary action per area; ghost for the rest. Real <button>/<a> elements, visible focus ring.",
      `<p><button class="ui-btn">Primary</button> <button class="ui-btn ui-btn-ghost">Secondary</button> <a class="ui-btn ui-btn-ghost" href="/capabilities" data-link>Link button</a> <button class="ui-icon-btn" aria-label="Close">&times;</button></p>`,
      `<button class="ui-btn">Primary</button>\n<button class="ui-btn ui-btn-ghost">Secondary</button>`)}
    ${section("chips", "Chips and severity", "Severity colours come from the shared chart palette (charts.js SEVERITY_COLORS), so a chip, a badge and a bar for \"Critical\" always match. The label is always text, never colour alone.",
      `<p>${["Critical", "High", "Medium", "Low", "Info"].map(severityChip).join(" ")}</p><p>${chip("in use", { tone: "good" })} ${chip("locked", { tone: "bad" })} ${chip("admin")} ${chip("selected", { tone: "accent" })}</p>`,
      `severityChip("High")\nchip("in use", { tone: "good" })`)}
    ${section("kpi", "KPI tiles", "A number that counts up once, a change chip that says which direction is good, and an optional sparkline. Add href to make the whole tile a link. Never invent a trend: pass previous/spark only when you have them.",
      `<div class="ui-grid">${kpiTile({ label: "Open findings", value: 1284, previous: 1410, spark, hint: "Lower is better" })}${kpiTile({ label: "Coverage", value: 92.4, previous: 88.1, goodWhen: "up", suffix: "%", decimals: 1, tone: "good", spark: [80, 82, 85, 84, 88, 90, 92] })}${kpiTile({ label: "SLA breached", value: 17, previous: 9, tone: "danger", href: "/queue?slaStatus=breached" })}${kpiTile({ label: "No history yet", value: 42 })}</div>
       <p style="margin-top:12px">Standalone: ${deltaChip(120, 100)} ${deltaChip(80, 100)} ${deltaChip(100, 100)} ${sparkline(spark)}</p>`,
      `kpiTile({ label: "Open findings", value: 1284, previous: 1410, spark, goodWhen: "down" })\ndeltaChip(80, 100, { goodWhen: "down" })\nsparkline([1,3,2,5])`)}
    ${section("age", "Data age", "Says how old the numbers are and turns amber, then red, as they age. One shared timer updates every badge.",
      `<p>${dataAgeBadge(Date.now())} ${dataAgeBadge(Date.now() - 3 * 60000, { label: "Synced" })} ${dataAgeBadge(Date.now() - 45 * 60000, { label: "Scanned" })} <button class="ui-btn ui-btn-ghost" id="ds-age">Refresh the first one</button></p>`,
      `dataAgeBadge(fetchedAt, { fresh: 60000, stale: 600000 })\nmountDataAge(container)`)}
    ${section("loading", "Skeletons", "Shown instead of spinners and blank space, in the same shape as the content, so nothing jumps when data arrives. The router uses pageSkeleton() while a page loads.",
      `<div class="ui-grid">${skeleton("kpi", 3)}</div><div style="margin-top:12px">${skeleton("card")}</div>`, `skeleton("kpi", 4)  // kpi | card | table | text`)}
    ${section("empty", "Empty states", "Say what is missing and the next step.", emptyState({ title: "No findings yet", body: "Connect a scanner or import a report to start.", actionLabel: "Open connections", actionHref: "/connections" }),
      `emptyState({ title, body, actionLabel, actionHref })`)}
    ${section("table", "Tables", "Sortable (click a header), resizable (drag the edge or use the arrow keys on it), column chooser, filter, CSV export of exactly what you see. Remembers sort, widths and hidden columns per storageKey. Above 500 rows only the visible rows exist in the page. The second table has 20,000 rows.",
      `<h4>12 rows</h4><div id="ds-table-small"></div><h4 style="margin-top:18px">20,000 rows (virtualised)</h4><div id="ds-table-big"></div>`,
      `dataTable(host, {\n  columns: [{ key: "id", label: "ID" }, { key: "score", label: "Score", type: "number", align: "right" }],\n  rows, rowKey: (r) => r.id, storageKey: "my-page", csvName: "findings",\n  onRowClick: (r) => openDrawer({ title: r.id, html: "..." }),\n})`)}
    ${section("drawer", "Drawer", "Detail beside the list instead of a full navigation. Esc closes, focus is trapped and returned.", `<p><button class="ui-btn ui-btn-ghost" id="ds-drawer">Open a drawer</button></p>`, `openDrawer({ title: "DEMO-0001", html: "<p>…</p>", width: 520 })`)}
    ${section("toast", "Toasts", "Short, polite messages; critical ones use role=alert. At most four at a time.",
      `<p><button class="ui-btn ui-btn-ghost" data-toast="info">Info</button> <button class="ui-btn ui-btn-ghost" data-toast="good">Success</button> <button class="ui-btn ui-btn-ghost" data-toast="warn">Warning</button> <button class="ui-btn ui-btn-ghost" data-toast="bad">Critical with link</button></p>`,
      `toast("Saved", { tone: "good" })\ntoast("SLA breached on 3 findings", { tone: "bad", href: "/queue", action: "Open" })`)}
    ${section("tips", "Tooltips", "Any element with a data-tooltip attribute gets the app's shared tooltip, on hover and on keyboard focus.",
      `<p><span class="ui-chip" tabindex="0" ${tipAttr("This is the shared tooltip")}>Hover or focus me</span></p>`, `<span ${"data-tooltip"}="Text">…</span>  // or tipAttr("Text")`)}
    ${section("keys", "Keyboard shortcuts", "Press ? anywhere (outside a text box) for the cheat sheet. Register a shortcut's help line with registerShortcutHelp(keys, text).", shortcutSheetHtml() + `<p><button class="ui-btn ui-btn-ghost" id="ds-keys">Open the cheat sheet</button></p>`, "")}
    ${section("palette", "Command palette", "Ctrl/Cmd+K. Fuzzy search over every page you may open (licence and admin visibility respected), recent pages, actions (switch module, theme, copy link), and findings and assets from the same data as the search bar.",
      `<p><button class="ui-btn" id="ds-palette">Open the palette</button></p>`, "")}
    ${section("live", "Live updates", "One shared stream. The page asks for a topic; live.js uses Server-Sent Events (GET /api/events) when available and otherwise polls with backoff, paused in a hidden tab.",
      `<p>Transport right now: <strong id="ds-mode">${escapeHtml(liveMode())}</strong> ${chip("topic: activity")}</p><p class="ui-muted" id="ds-live-log">Waiting for an event. Doing something that is audit-logged (for example saving a setting) publishes one.</p>`,
      `const off = live.subscribe("activity", (e) => reload())\nlive.poll("my.topic", fetchSomething, { every: 30000 })  // the fallback source\nonCleanup(off)`)}
    ${section("lifecycle", "Page contract", "What a page module must do so navigation never leaks and one broken page never breaks the app.",
      `<ul><li><code>export const title</code> and <code>export async function render(container, ...params)</code>.</li>
       <li>Anything that outlives the render (timers, <code>live.subscribe</code>, listeners on <code>document</code>) is registered with <code>onCleanup(fn)</code>, or <code>render</code> returns a cleanup function. The router runs both before the next page.</li>
       <li>A thrown error is caught by the router's error boundary, which shows the box below with a retry button.</li></ul>
       <div style="max-width:620px">${errorBoundaryHtml(new Error("Example: the request failed (503)"), { title: "This page failed to load" }).replace("data-retry", "disabled")}</div>`,
      `export async function render(container) {\n  const off = live.subscribe("activity", refresh);\n  onCleanup(off);\n  const t = setInterval(refresh, 20000);\n  return () => clearInterval(t);\n}`)}
  </div></div>`;

  const big = demoRows(20000);
  const rowDrawer = (r) => openDrawer({ title: r.id, html: `<p>${severityChip(r.severity)}</p><dl><dt class="ui-muted">Asset</dt><dd>${escapeHtml(r.asset)}</dd><dt class="ui-muted">Score</dt><dd>${r.score}</dd><dt class="ui-muted">First seen</dt><dd>${r.seen}</dd></dl><p class="ui-muted">Use a drawer for the detail of one row, so the list keeps its place.</p>` });
  dataTable(container.querySelector("#ds-table-small"), { columns: COLS, rows: demoRows(12), rowKey: (r) => r.id, caption: "Example findings", csvName: "design-system-demo", onRowClick: rowDrawer, maxHeight: 420 });
  dataTable(container.querySelector("#ds-table-big"), { columns: COLS, rows: big, rowKey: (r) => r.id, caption: "Twenty thousand example findings", csvName: "design-system-demo-20000", storageKey: "design-system-big", onRowClick: rowDrawer, maxHeight: 420 });

  mountDataAge(container);
  mountCounters(container);
  const q = (s) => container.querySelector(s);
  q("#ds-theme").addEventListener("click", (e) => { const next = { auto: "dark", dark: "light", light: "auto" }[currentTheme()]; applyTheme(next); e.target.textContent = next; });
  q("#ds-age").addEventListener("click", () => { const el = container.querySelector("[data-age-ts]"); el.dataset.ageTs = String(Date.now()); });
  q("#ds-drawer").addEventListener("click", () => openDrawer({ title: "Example drawer", html: "<p>Content goes here. Press Esc to close.</p><button class=\"ui-btn\">A focusable control</button>" }));
  q("#ds-keys").addEventListener("click", () => showShortcuts());
  q("#ds-palette").addEventListener("click", () => openPalette());
  const messages = { info: "Nothing needs your attention.", good: "Saved.", warn: "The last sync was 3 hours ago.", bad: "3 findings breached their SLA." };
  container.querySelectorAll("[data-toast]").forEach((b) => b.addEventListener("click", () => toast(messages[b.dataset.toast], { tone: b.dataset.toast, ...(b.dataset.toast === "bad" ? { href: "/queue?slaStatus=breached", action: "Open queue" } : {}) })));

  const offMode = live.subscribe("live.mode", (e) => { const m = q("#ds-mode"); if (m) m.textContent = e.mode; });
  const offAct = live.subscribe("activity", (e) => { const l = q("#ds-live-log"); if (l) l.textContent = `Received an "activity" event (${e.action || "?"}) at ${new Date().toLocaleTimeString()}.`; });
  onCleanup(offMode);
  onCleanup(offAct);
}
