// Live Remediation Queue: every finding, re-scored on each load, as a fast sortable table with filters kept in the URL, bulk assign and exception
// actions, saved views, and a detail drawer. Pure decisions (filters, sorting, selection, SLA maths) live in queueLogic.js and are tested under
// Node; the table is mxKit.js. API calls are the same ones the page always made.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { icon } from "../icons.js";
import { filterByTenant, tenantBannerHtml } from "../tenant.js";
import { QUEUE_SCAN_TYPES, SCAN_TYPE_LABELS } from "../scanTypes.js";
import { INFRA_CATEGORIES, INFRA_CATEGORY_LABELS } from "../infraTypes.js";
import { buildOwnerTeamMaps, ENVIRONMENT_LABELS } from "../assetLookup.js";
import { dateRangeHtml, wireDateRange, filterByDateRange, computeRange, dateRangeDisclaimerHtml } from "../dateRange.js";
import { threatIntelCellHtml } from "../threatIntelTagging.js";
import { setInsightsContent, insightSectionHtml, insightAlertHtml } from "../insightsPanel.js";
import { getCurrentUser } from "../auth.js";
import { openFindingDrawer } from "../findingDrawer.js";
import { chip, toast, emptyState, onCleanup, registerShortcutHelp, dataAgeBadge, mountDataAge, touchDataAge, debounce, tipAttr } from "../ui.js";
import { modal, popMenu, avatar, ringSvg, liveBadge, copyText, modalOpen } from "../sxKit.js";
import { selectableTable, kpiStrip, popover, stackedBar, replaceSearch, readJson, writeJson, autoRefresh, pageActions, skeletonPage } from "../mxKit.js";
import {
  parseQueueState, queueStateToSearch, applyQueueFilters, sortQueue, queueKpis, activeFilterChips, clearFilter, activeFilterCount, slaRingFor, priorityReasons,
  applyOptimistic, settle, pruneSelection, bulkBatches, MAX_BULK, addView, removeView, sanitizeViews, sameState, PRIORITIES, defaultState,
} from "../queueLogic.js";

export const title = "Live Remediation Queue";

const REFRESH_MS = 20000;
const VIEWS_KEY = "quanta.queue.views";
const PRIORITY_COLOR = { Critical: "var(--sx-crit)", High: "var(--sx-high)", Medium: "var(--sx-med)", Low: "var(--sx-low)" };
const CHANGE_TYPE_CLASS = { emergency: "critical", normal: "warn", standard: "good" };
const SINGLE_ASSET_TYPE_CATEGORIES = new Set(["cert-mgmt", "iac", "runtime", "dast", "secrets", "ai-ml"]);
const BUILT_IN_VIEWS = [
  { name: "SLA breached", search: "?slaStatus=breached" },
  { name: "Actively exploited (KEV)", search: "?kevOnly=true" },
  { name: "Critical and unowned", search: "?priority=Critical&unowned=true" },
  { name: "Likely to be exploited (EPSS 50%+)", search: "?highEpssOnly=true" },
];

const windowText = (w) => (!w || !w.date ? "" : `${w.date} (${w.day_of_week}) ${w.start_time}-${w.end_time} ${w.timezone}`);

export async function render(container) {
  const S = {
    all: [], state: parseQueueState(window.location.search), selected: new Set(), loadedAt: 0, me: null, admin: false, mode: "idle", assignments: new Map(),
    dateRange: { preset: "", customFrom: "", customTo: "" }, views: sanitizeViews(readJson(VIEWS_KEY, [])), view: [], highlightDone: false, table: null,
  };
  let alive = true;
  onCleanup(() => { alive = false; });
  const $ = (sel) => container.querySelector(sel);

  container.innerHTML = `<div class="sx-page mx-page" id="q-root">
    <div class="sx-head"><div><h2>Remediation queue</h2><p>Every finding, re-scored from the current <a href="/priority-rules" data-link>priority rules</a> each time it loads. Filters are kept in the address bar, so a link shares exactly this view.</p></div>
      <div class="sx-row"><span id="q-live"></span><span id="q-age"></span><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="q-refresh">${icon("clock", 14)} Refresh</button>
        <span class="sx-pop-host"><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="q-views" aria-haspopup="menu" aria-expanded="false">Saved views</button></span>
        <button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="q-link">Copy link</button></div></div>
    <div id="q-tenant">${tenantBannerHtml()}</div><div id="q-note"></div>
    <div id="q-skel">${skeletonPage(6)}</div>
    <div id="q-kpis" class="sx-kpis mx-kpis" hidden></div>
    <div id="q-toolbar" hidden></div><div id="q-chips"></div><div id="q-bulk" class="mx-bulk" hidden></div>
    <div id="q-table"></div>
    <details class="sx-panel mx-notes"><summary class="sx-link-btn">How to read this page</summary><div class="mx-notes-body">
      <p>Priority reasoning for each finding is the list behind the little question mark next to its priority. MITRE ATT&amp;CK tags are a keyword heuristic, not authoritative technique attribution (<code>remediation/enrichment/attack_mapping.py</code>). Category is a methodology taxonomy inferred from asset type (<code>scan_type_mapping.py</code>).
      Change type, cadence, maintenance window and auto-remediate come from <a href="/remediation-policy" data-link>Remediation policy</a>; an "override" badge means that asset has its own schedule on <a href="/asset-policy" data-link>Asset policy</a>. Normal and emergency changes wait for a decision on <a href="/remediation-approvals" data-link>Remediation approvals</a>.</p>
      <p>Keys: <kbd>j</kbd>/<kbd>k</kbd> move between rows, <kbd>Enter</kbd> opens the detail, <kbd>x</kbd> or <kbd>Space</kbd> selects, Shift-click selects a range.</p></div></details></div>`;

  const setLive = (m) => { S.mode = m; const el = $("#q-live"); if (el) el.innerHTML = liveBadge(m); };
  setLive("idle");

  // ------------------------------------------------------------------ data
  async function load() {
    const [data, assetsData, me, asg] = await Promise.all([
      api.queue(), api.assetsList(), getCurrentUser().catch(() => null),
      api.assignments({ view: "all", limit: 1000 }).catch(() => null),
    ]);
    if (!alive) return;
    S.me = me; S.admin = !!(me && me.role === "admin");
    const { ownerByAssetName, teamByAssetName, environmentByAssetName } = buildOwnerTeamMaps(assetsData.assets);
    S.assignments = new Map(asg ? asg.rows.filter((r) => r.assignment && r.assignment.assignee_email).map((r) => [r.id, r.assignment]) : []);
    S.all = data.findings.map((f) => {
      const name = f.asset && f.asset.name;
      const a = S.assignments.get(f.id);
      return { ...f, owner: ownerByAssetName.get(name), team: teamByAssetName.get(name), environment: environmentByAssetName.get(name), assignee: a ? a.assignee_email : null };
    });
    S.loadedAt = Date.now();
    S.selected = pruneSelection(S.selected, S.all.map((f) => f.id));
  }

  const scoped = () => filterByTenant(S.all);
  function currentView() {
    let list = applyQueueFilters(scoped(), S.state.filters);
    if (S.dateRange.preset) list = filterByDateRange(list, computeRange(S.dateRange.preset, S.dateRange.customFrom, S.dateRange.customTo), "first_seen");
    return sortQueue(list, S.state.sort.key, S.state.sort.dir);
  }
  const pushUrl = () => replaceSearch(queueStateToSearch(S.state));
  function setFilters(patch, { repaintToolbar = true } = {}) {
    S.state = { ...S.state, filters: { ...S.state.filters, ...patch } };
    pushUrl(); paintKpis(); if (repaintToolbar) paintToolbar(); paintChips(); paintTable();
  }

  // ------------------------------------------------------------------ painting
  function paintKpis() {
    const base = scoped();
    const k = queueKpis(base);
    const f = S.state.filters;
    const slice = S.view.length ? S.view : currentView();
    const mix = queueKpis(slice).byPriority;
    const mixCell = `<div class="sx-kpi-cell mx-mix"><div class="ui-kpi"><div class="ui-kpi-top"><span class="ui-kpi-label">In this view</span></div>
      <div class="ui-kpi-value"><span class="ui-kpi-num">${slice.length.toLocaleString()}</span><span class="mx-of"> of ${base.length.toLocaleString()}</span></div>
      ${stackedBar(PRIORITIES.map((p) => ({ label: p, value: mix[p], color: PRIORITY_COLOR[p] })), { label: "Findings in this view by priority" })}
      <span class="sx-pop-host"><button type="button" class="sx-link-btn" id="q-mix" aria-haspopup="dialog" aria-expanded="false">Priority breakdown</button></span></div></div>`;
    const tiles = [
      { key: "critical", label: "Critical", value: k.byPriority.Critical, tone: k.byPriority.Critical ? "danger" : "good", pressed: f.priority === "Critical", hint: "Findings whose computed priority is Critical." },
      { key: "breached", label: "SLA breached", value: k.breached, tone: k.breached ? "danger" : "good", pressed: f.slaStatus === "breached", hint: "Past the remediation window for their priority." },
      { key: "atRisk", label: "Due in 3 days", value: k.atRisk, tone: k.atRisk ? "warn" : "good", pressed: f.slaStatus === "at_risk", hint: "Not yet breached but due within three days." },
      { key: "kev", label: "KEV listed", value: k.kev, tone: k.kev ? "danger" : "good", pressed: f.kevOnly, hint: "On CISA's Known Exploited Vulnerabilities list: confirmed exploited." },
      { key: "epss", label: "EPSS 50%+", value: k.highEpss, tone: k.highEpss ? "warn" : "", pressed: f.highEpssOnly, hint: "FIRST.org's probability of exploitation in the next 30 days is at least 50%." },
      { key: "unowned", label: "Unowned", value: k.unowned, tone: k.unowned ? "warn" : "good", pressed: f.unownedOnly, hint: "No asset owner, team or assignee. Nobody is accountable yet." },
    ];
    const host = $("#q-kpis");
    $("#q-skel").hidden = true;
    kpiStrip(host, tiles, (key) => {
      if (key === "critical") setFilters({ priority: f.priority === "Critical" ? "all" : "Critical" });
      else if (key === "breached") setFilters({ slaStatus: f.slaStatus === "breached" ? "all" : "breached" });
      else if (key === "atRisk") setFilters({ slaStatus: f.slaStatus === "at_risk" ? "all" : "at_risk" });
      else if (key === "kev") setFilters({ kevOnly: !f.kevOnly });
      else if (key === "epss") setFilters({ highEpssOnly: !f.highEpssOnly });
      else if (key === "unowned") setFilters({ unownedOnly: !f.unownedOnly });
    }, mixCell);
  }

  function paintToolbar() {
    const f = S.state.filters;
    const base = scoped();
    const active = document.activeElement;
    const restore = active && $("#q-toolbar").contains(active) && active.id ? `#${active.id}` : "";
    const caret = active && active.id === "f-q" ? active.selectionStart : null;
    const types = [...new Set(S.all.map((x) => x.asset && x.asset.type).filter(Boolean))].sort();
    const cats = new Map(QUEUE_SCAN_TYPES.map((t) => [t, SCAN_TYPE_LABELS[t]]));
    for (const x of S.all) if (x.scan_type && !cats.has(x.scan_type)) cats.set(x.scan_type, x.scan_type_label || x.scan_type);
    const opt = (v, label, cur) => `<option value="${escapeHtml(v)}" ${v === cur ? "selected" : ""}>${escapeHtml(label)}</option>`;
    const single = SINGLE_ASSET_TYPE_CATEGORIES.has(f.category);
    const el = $("#q-toolbar");
    el.hidden = false;
    el.innerHTML = `<div class="sx-toolbar" role="search" aria-label="Filter findings">
      <input type="search" class="sx-field" id="f-q" placeholder="Search id, title, CVE, asset, owner" value="${escapeHtml(f.q)}" aria-label="Search findings">
      <select class="sx-field" id="f-priority" aria-label="Priority"><option value="all">Any priority</option>${PRIORITIES.map((p) => opt(p, p, f.priority)).join("")}</select>
      <select class="sx-field" id="f-sla" aria-label="Service level"><option value="all">Any SLA state</option>${opt("breached", "Breached", f.slaStatus)}${opt("at_risk", "Due in 3 days", f.slaStatus)}${opt("on_track", "On track", f.slaStatus)}</select>
      <select class="sx-field" id="f-env" aria-label="Environment"><option value="all">Any environment</option>${Object.entries(ENVIRONMENT_LABELS).map(([v, l]) => opt(v, l, f.environment)).join("")}</select>
      ${single ? "" : `<select class="sx-field" id="f-type" aria-label="Asset type"><option value="all">Any asset type</option>${types.map((t) => opt(t, t, f.assetType)).join("")}</select>
      <select class="sx-field" id="f-cat" aria-label="Category"><option value="all">Any category</option>${[...cats.entries()].sort().map(([v, l]) => opt(v, l, f.category)).join("")}</select>
      <select class="sx-field" id="f-infra" aria-label="Infrastructure sub-category"><option value="all">Any infra type</option>${INFRA_CATEGORIES.map((v) => opt(v, INFRA_CATEGORY_LABELS[v], f.infraType)).join("")}</select>`}
      <details class="mx-more"><summary class="ui-btn ui-btn-ghost sx-btn-sm">First seen</summary><div class="mx-more-body">${dateRangeHtml("f-daterange", S.dateRange)}${dateRangeDisclaimerHtml()}</div></details>
      <span class="ui-muted mx-count" id="q-count" role="status" aria-live="polite"></span></div>`;
    wireDateRange(el, "f-daterange", (dr) => { S.dateRange = dr; paintKpis(); paintChips(); paintTable(); });
    if (restore) { const n = el.querySelector(restore); if (n) { n.focus(); if (caret !== null && n.setSelectionRange) n.setSelectionRange(caret, caret); } }
    void base;
  }

  function paintChips() {
    const chips = activeFilterChips(S.state.filters);
    const host = $("#q-chips");
    host.innerHTML = chips.length ? `<div class="mx-chips" role="group" aria-label="Active filters">${chips.map((c) => `<button type="button" class="mx-fchip" data-unfilter="${escapeHtml(c.key)}" aria-label="Remove filter ${escapeHtml(c.label)} ${escapeHtml(c.value)}">${escapeHtml(c.label)}${c.value ? `: <b>${escapeHtml(c.value)}</b>` : ""} <span aria-hidden="true">&times;</span></button>`).join("")}
      <button type="button" class="sx-link-btn" id="q-clear">Clear all</button><button type="button" class="sx-link-btn" id="q-save">Save as a view</button></div>` : "";
  }

  // ------------------------------------------------------------------ the table
  const sevOf = (f) => `<span class="mx-prio mx-prio-${escapeHtml((f.priority || "").toLowerCase())}"><i></i>${escapeHtml(f.priority || "")}</span>`;
  const ownerCell = (f) => {
    const who = f.assignee || f.owner;
    if (who) return `<span class="sx-who">${avatar(who, { size: 22 })}<span class="t" title="${escapeHtml(who)}">${escapeHtml(String(who).split("@")[0])}</span></span>${f.team ? `<div class="mx-sub">${escapeHtml(f.team)}</div>` : ""}`;
    if (f.team) return `<span class="sx-who">${avatar(null, { size: 22 })}<span class="t">${escapeHtml(f.team)}</span></span><div class="mx-sub">team only</div>`;
    return `<span class="mx-unowned">Unowned</span>`;
  };
  const slaCell = (f) => {
    if (!f.sla || !f.sla.due_date) return '<span class="ui-muted">n/a</span>';
    const r = slaRingFor(f);
    return `<span class="mx-slacell"><span ${tipAttr(r.label)}>${ringSvg(r, { size: 26, radius: 11 })}</span><span>${escapeHtml(f.sla.due_date)}<div class="mx-sub">${f.sla.breached ? "breached" : `${f.sla.days_remaining}d left`}</div></span></span>${f.exception ? `<a class="mx-exc" href="/exceptions?highlight=${encodeURIComponent(f.exception.id)}" data-link ${tipAttr(f.exception.reason)}>Risk accepted until ${escapeHtml(f.exception.expires_on)}</a>` : ""}`;
  };
  const columns = [
    { key: "priority", label: "Priority", sortKey: "priority", width: 112, csv: (f) => f.priority, render: (f) => `${sevOf(f)}<button type="button" class="sx-why mx-why" data-why="${escapeHtml(f.id)}" aria-haspopup="dialog" aria-label="Why ${escapeHtml(f.id)} is ${escapeHtml(f.priority)}">${icon("faq", 14)}</button>` },
    { key: "id", label: "ID", sortKey: "id", width: 92, csv: (f) => f.id, render: (f) => `<button type="button" class="sx-link-btn mx-id" data-open="${escapeHtml(f.id)}">${escapeHtml(f.id)}</button>${f.pending ? ' <span class="mx-saving" aria-label="Saving">…</span>' : ""}${f.open_tickets ? ` <a href="/support" data-link class="mx-tix" ${tipAttr(`${f.open_tickets} open support ticket(s)`)}>&#9993; ${f.open_tickets}</a>` : ""}` },
    { key: "asset", label: "Asset", sortKey: "asset", width: 150, csv: (f) => f.asset && f.asset.name, render: (f) => `<span class="mx-clip" title="${escapeHtml(f.asset && f.asset.name)}">${escapeHtml(f.asset && f.asset.name)}</span><div class="mx-sub">${escapeHtml((f.asset && f.asset.type) || "")}</div>` },
    { key: "title", label: "Finding", sortKey: "title", width: 320, csv: (f) => f.title, render: (f) => `<span class="mx-title" title="${escapeHtml(f.title)}">${escapeHtml(f.title)}</span>${f.cve ? `<div class="mx-sub"><code>${escapeHtml(f.cve)}</code></div>` : ""}` },
    { key: "signals", label: "Exploitation", sortKey: "epss", width: 150, csv: (f) => `${f.kev && f.kev.listed ? "KEV " : ""}${f.epss ? `${(f.epss.score * 100).toFixed(1)}%` : ""}`.trim(),
      render: (f) => `${f.kev && f.kev.listed ? `${chip("KEV", { tone: "critical", title: "On CISA's Known Exploited Vulnerabilities list" })} ` : ""}${f.epss ? `<span class="mx-epss" ${tipAttr(`EPSS ${(f.epss.score * 100).toFixed(1)}%, ${(f.epss.percentile * 100).toFixed(0)}th percentile`)}><i style="width:${Math.max(3, Math.round(f.epss.score * 100))}%"></i></span><span class="mx-epss-n">${(f.epss.score * 100).toFixed(0)}%</span>` : '<span class="ui-muted">no EPSS</span>'}` },
    { key: "sla", label: "SLA", sortKey: "sla", width: 160, csv: (f) => (f.sla ? f.sla.due_date : ""), render: slaCell },
    { key: "owner", label: "Owner", width: 150, csv: (f) => f.assignee || f.owner || "", render: ownerCell },
    { key: "category", label: "Category", width: 110, csv: (f) => f.scan_type_label || f.scan_type, render: (f) => (f.scan_type ? `<span class="category-tag" ${tipAttr(f.scan_type_label || "")}>${escapeHtml(f.scan_type)}</span>` : '<span class="ui-muted">-</span>') },
    { key: "change", label: "Change type", width: 110, csv: (f) => (f.remediation_policy || {}).change_type || "", render: (f) => { const p = f.remediation_policy || {}; return p.change_type ? chip(p.change_type, { tone: CHANGE_TYPE_CLASS[p.change_type] || "neutral" }) : '<span class="ui-muted">-</span>'; } },
    { key: "cadence", label: "Cadence", width: 130, csv: (f) => (f.remediation_policy || {}).cadence || "", render: (f) => { const p = f.remediation_policy || {}; return p.cadence ? `${escapeHtml(p.cadence)}${p.schedule_override ? ` ${chip("override", { tone: "warn", title: "Asset-level override, see Asset policy" })}` : ""}` : '<span class="ui-muted">-</span>'; } },
    { key: "env", label: "Environment", hidden: true, width: 110, csv: (f) => ENVIRONMENT_LABELS[f.environment || "unknown"] || f.environment || "", render: (f) => escapeHtml(ENVIRONMENT_LABELS[f.environment || "unknown"] || f.environment || "") },
    { key: "cloud", label: "Cloud", hidden: true, width: 100, csv: (f) => f.cloud_provider || "", render: (f) => escapeHtml(f.cloud_provider || "") },
    { key: "mechanism", label: "Remediation mechanism", hidden: true, width: 170, csv: (f) => f.remediation_mechanism || "", render: (f) => (f.remediation_mechanism ? `<span ${tipAttr("The real-world tool that would normally patch this asset class. Informational, not an integration.")}>${escapeHtml(f.remediation_mechanism)}</span>` : "") },
    { key: "intel", label: "Threat intel", hidden: true, width: 150, csv: (f) => "", render: (f) => threatIntelCellHtml(f) },
    { key: "attack", label: "ATT&CK", hidden: true, width: 130, csv: (f) => (f.attack_techniques || []).map((t) => t.technique_id).join("; "), render: (f) => (f.attack_techniques && f.attack_techniques.length ? f.attack_techniques.slice(0, 3).map((t) => `<span class="attack-tag" ${tipAttr(t.tactic || "")}>${escapeHtml(t.technique_id)}</span>`).join("") : "") },
    { key: "window", label: "Next window", hidden: true, width: 220, csv: (f) => windowText((f.remediation_policy || {}).next_window), render: (f) => escapeHtml(windowText((f.remediation_policy || {}).next_window)) },
    { key: "auto", label: "Auto-remediate", hidden: true, width: 110, csv: (f) => ((f.remediation_policy || {}).auto_remediate ? "Yes" : "No"), render: (f) => ((f.remediation_policy || {}).auto_remediate ? "Yes" : "No") },
    { key: "seen", label: "Last seen", hidden: true, sortKey: "last_seen", width: 110, csv: (f) => f.last_seen || "", render: (f) => escapeHtml(f.last_seen || "") },
    { key: "ai", label: "AI", width: 78, csv: () => "", render: (f) => `<a href="/ai-assist?finding_id=${encodeURIComponent(f.id)}" data-link class="ai-assist-link">${icon("ai", 14)} Ask</a>` },
  ];

  function paintTable() {
    S.view = currentView();
    const count = $("#q-count");
    const base = scoped().length;
    if (count) count.textContent = `${S.view.length.toLocaleString()} of ${base.toLocaleString()} finding${base === 1 ? "" : "s"}${activeFilterCount(S.state.filters) ? " match" : ""}`;
    const mix = $("#q-kpis .mx-mix");
    if (mix) { const p = queueKpis(S.view).byPriority; mix.querySelector(".mx-stack").outerHTML = stackedBar(PRIORITIES.map((x) => ({ label: x, value: p[x], color: PRIORITY_COLOR[x] })), { label: "Findings in this view by priority" }); mix.querySelector(".ui-kpi-num").textContent = S.view.length.toLocaleString(); }
    const empty = !S.all.length
      ? emptyState({ title: "No findings yet", body: "Connect a scanner, run a simulated demonstration load, or ingest a SARIF or CSV export and the queue fills itself. Quanta never invents a finding.", actionLabel: "Connect a source", actionHref: "/connections", iconName: "queue" })
      : emptyState({ title: "No finding matches these filters", body: "Remove a filter chip, or clear them all, to see more.", iconName: "search" });
    if (!S.table) {
      S.table = selectableTable($("#q-table"), {
        columns, rows: S.view, rowKey: (f) => f.id, selectable: true, sort: S.state.sort, storageKey: "queue-v2", caption: "Remediation queue", csvName: "quanta-remediation-queue",
        rowHeight: 56, maxHeight: 640, emptyHtml: empty, selected: S.selected, rowClass: (f) => (f.pending ? "is-pending" : ""),
        onSort: (key) => { const cur = S.state.sort; S.state = { ...S.state, sort: { key, dir: cur.key === key && cur.dir === "desc" ? "asc" : "desc" } }; pushUrl(); S.table.setSort(S.state.sort); paintTable(); },
        onOpen: (f) => openFinding(f), onSelection: (sel) => { S.selected = sel; paintBulk(); },
      });
    } else { S.table.setSort(S.state.sort); S.table.setSelected(S.selected); S.table.setRows(S.view); }
    paintBulk();
    if (S.state.highlight && !S.highlightDone) applyHighlight();
  }

  function applyHighlight() {
    const id = S.state.highlight;
    const note = $("#q-note");
    const idx = S.table ? S.table.scrollToKey(id) : -1;
    if (idx >= 0) { S.highlightDone = true; note.innerHTML = ""; return; }
    if (!S.all.length) return;
    S.highlightDone = true;
    note.innerHTML = S.all.some((f) => f.id === id)
      ? `<div class="mx-callout mx-callout-warn">Finding <code>${escapeHtml(id)}</code> exists but is hidden by the filters or tenant selection. <button type="button" class="sx-link-btn" id="q-clear2">Clear filters</button></div>`
      : `<div class="mx-callout mx-callout-warn">Finding <code>${escapeHtml(id)}</code> was not found.</div>`;
  }

  function openFinding(f) { openFindingDrawer(f, { onChanged: () => { refreshNow(); } }); }

  // ------------------------------------------------------------------ bulk actions (optimistic: the row changes at once, rolls back with a reason on failure)
  function paintBulk() {
    const n = S.selected.size;
    const host = $("#q-bulk");
    if (!n) { host.hidden = true; host.innerHTML = ""; return; }
    host.hidden = false;
    host.innerHTML = `<div class="mx-bulk-in" role="region" aria-label="Actions for selected findings"><strong>${n.toLocaleString()} selected</strong>
      ${S.admin ? `<button type="button" class="ui-btn sx-btn-sm" data-bulk="assign">Assign&hellip;</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-bulk="exception">Request exception&hellip;</button>` : `<span class="ui-muted">Assigning and exceptions need an administrator.</span>`}
      <button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-bulk="copy">Copy IDs</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-bulk="clear">Clear selection</button></div>`;
  }
  function patchLocal(ids, patch) {
    const r = applyOptimistic(S.all, ids, patch);
    S.all = r.next;
    paintKpis(); paintTable();
    return r;
  }
  async function bulkAssign() {
    const ids = [...S.selected];
    if (ids.length > MAX_BULK) { toast(`Select at most ${MAX_BULK} findings at once.`, { tone: "warn" }); return; }
    let people = []; let teams = [];
    try { [{ users: people }, { teams }] = await Promise.all([api.assignableUsers(), api.teams()]); } catch (e) { toast(e.message, { tone: "bad" }); return; }
    const out = await modal({ title: `Assign ${ids.length} finding${ids.length === 1 ? "" : "s"}`, confirmLabel: "Assign", description: "Assigning to a different team moves the findings into that team's view. The change is recorded in each finding's history.",
      body: `<label>Assignee<select id="m-who"><option value="">Nobody yet, route to a team only</option>${people.map((u) => `<option value="${escapeHtml(u.email)}">${escapeHtml(u.name)} (${escapeHtml(u.email)})${u.team ? ` - ${escapeHtml(u.team)}` : ""}</option>`).join("")}</select></label>
        <label>Team<select id="m-team"><option value="">Assignee's own team</option>${teams.map((t) => `<option value="${escapeHtml(t.name)}">${escapeHtml(t.name)}</option>`).join("")}</select></label>
        <label>Note (optional)<textarea id="m-note" maxlength="2000" placeholder="Context, a link, or what to do first"></textarea></label>`,
      validate: (d) => (!d.querySelector("#m-who").value && !d.querySelector("#m-team").value ? "Choose an assignee, a team, or both." : ""),
      collect: (d) => ({ assignee_email: d.querySelector("#m-who").value || null, team: d.querySelector("#m-team").value || null, notes: d.querySelector("#m-note").value.trim() || null }) });
    if (!out) return;
    const opt = patchLocal(ids, { assignee: out.assignee_email, ...(out.team ? { team: out.team } : {}) });
    try {
      let total = 0;
      for (const batch of bulkBatches(ids)) total += (await api.bulkAssign({ finding_ids: batch, ...out })).assigned;
      S.all = settle(S.all, ids);
      toast(`Assigned ${total} finding${total === 1 ? "" : "s"}${out.assignee_email ? ` to ${out.assignee_email}` : ""}${out.team ? ` (${out.team})` : ""}.`, { tone: "good" });
      S.table.clearSelection(); paintKpis(); paintTable();
    } catch (e) {
      S.all = opt.undo(S.all); paintKpis(); paintTable();
      toast(`Not assigned: ${e.message}`, { tone: "bad", ms: 9000 });
    }
  }
  async function bulkException() {
    const ids = [...S.selected];
    if (ids.length > 50) { toast("Request exceptions for at most 50 findings at once. Each one is a separate approval record.", { tone: "warn", ms: 7000 }); return; }
    let admins = [];
    try { admins = ((await api.listUsers()).users || []).filter((u) => u.role === "admin" && u.email.toLowerCase() !== (S.me.email || "").toLowerCase()); } catch (e) { toast(e.message, { tone: "bad" }); return; }
    if (!admins.length) { toast("An exception needs a second administrator to approve it (separation of duties). Create one under People first.", { tone: "warn", ms: 9000 }); return; }
    const soon = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
    const out = await modal({ title: `Request an exception for ${ids.length} finding${ids.length === 1 ? "" : "s"}`, confirmLabel: "Record exception", description: "A risk-acceptance waiver with an expiry. It is recorded against each finding, shows on the queue, and lapses by itself.",
      body: `<label>Reason (required)<textarea id="m-reason" placeholder="Why this risk is accepted, and what limits it"></textarea></label>
        <label>Expires on (at most one year)<input type="text" id="m-exp" value="${soon}" placeholder="YYYY-MM-DD"></label>
        <label>Approved by<select id="m-appr">${admins.map((a) => `<option value="${escapeHtml(a.email)}">${escapeHtml(a.name || a.email)} (${escapeHtml(a.email)})</option>`).join("")}</select></label>`,
      validate: (d) => (d.querySelector("#m-reason").value.trim().length < 10 ? "Write a reason of at least 10 characters." : !/^\d{4}-\d\d-\d\d$/.test(d.querySelector("#m-exp").value.trim()) ? "Use the date format YYYY-MM-DD." : ""),
      collect: (d) => ({ reason: d.querySelector("#m-reason").value.trim(), expires_on: d.querySelector("#m-exp").value.trim(), approved_by: d.querySelector("#m-appr").value }) });
    if (!out) return;
    const opt = patchLocal(ids, { exception: { id: "pending", reason: out.reason, expires_on: out.expires_on } });
    let done = 0; const failed = [];
    for (const id of ids) {
      try { await api.exceptionCreate({ finding_id: id, ...out }); done += 1; } catch (e) { failed.push({ id, message: e.message }); }
    }
    if (failed.length) {
      const failedIds = new Set(failed.map((x) => x.id));
      S.all = S.all.map((f) => (failedIds.has(f.id) ? opt.undo([f])[0] : f));
    }
    S.all = settle(S.all, ids);
    toast(failed.length ? `${done} recorded, ${failed.length} not: ${failed[0].id}: ${failed[0].message}` : `Exception recorded for ${done} finding${done === 1 ? "" : "s"}.`, { tone: failed.length ? "warn" : "good", ms: failed.length ? 10000 : 4000 });
    S.table.clearSelection();
    await refreshNow();
  }

  // ------------------------------------------------------------------ saved views
  function openViews(btn) {
    const here = queueStateToSearch(S.state);
    const items = [
      ...BUILT_IN_VIEWS.map((v) => ({ label: v.name, hint: sameState(v.search, here) ? "current view" : "built in", run: () => applySearch(v.search) })),
      { sep: true },
      ...S.views.map((v) => ({ label: v.name, hint: sameState(v.search, here) ? "current view" : "saved", run: () => applySearch(v.search) })),
      ...(S.views.length ? [{ sep: true }] : []),
      { label: "Save the current view...", run: saveCurrent },
      ...S.views.map((v) => ({ label: `Delete "${v.name}"`, run: () => { S.views = removeView(S.views, v.name); writeJson(VIEWS_KEY, S.views); toast("View deleted.", { tone: "good", ms: 2500 }); } })),
      { sep: true }, { label: "Reset to the default view", run: () => applySearch("") },
    ];
    popMenu(btn, items, { align: "right" });
  }
  function applySearch(search) {
    S.state = parseQueueState(search); S.selected = new Set(); S.dateRange = { preset: "", customFrom: "", customTo: "" };
    if (S.table) S.table.clearSelection();
    pushUrl(); paintKpis(); paintToolbar(); paintChips(); paintTable();
  }
  async function saveCurrent() {
    const out = await modal({ title: "Save this view", confirmLabel: "Save", description: "Saved in this browser only. It stores the filters and sort, not the findings.", body: `<label>Name<input type="text" id="m-name" maxlength="40" placeholder="e.g. Payments, KEV first"></label>`,
      validate: (d) => (d.querySelector("#m-name").value.trim() ? "" : "Give the view a name."), collect: (d) => d.querySelector("#m-name").value });
    if (!out) return;
    const r = addView(S.views, out, queueStateToSearch({ ...S.state, highlight: null }));
    if (r.error) { toast(r.error, { tone: "warn" }); return; }
    S.views = r.views; writeJson(VIEWS_KEY, S.views);
    toast(`Saved view "${out}".`, { tone: "good", ms: 3000 });
  }

  // ------------------------------------------------------------------ why this priority (popover)
  function openWhy(btn, id) {
    const f = S.all.find((x) => x.id === id); if (!f) return;
    const r = priorityReasons(f);
    popover(btn, `<h4>Why ${escapeHtml(f.priority)}</h4>${r.lines.length ? `<ol class="mx-reasons">${r.lines.map((l) => `<li>${escapeHtml(l)}</li>`).join("")}</ol>` : '<p class="ui-muted">No reasons were recorded.</p>'}<p class="ui-muted">Score ${r.score ?? "n/a"}. <a href="/priority-rules" data-link>Edit the weights</a></p>`, { label: `Why ${f.id} has this priority`, align: "left" });
  }
  function openMix(btn) {
    const p = queueKpis(S.view).byPriority; const f = S.state.filters;
    popover(btn, `<h4>Priority breakdown</h4><div class="mx-mixlist">${PRIORITIES.map((x) => `<button type="button" class="mx-mixrow" data-mixfilter="${x}" aria-pressed="${f.priority === x}"><span class="mx-prio mx-prio-${x.toLowerCase()}"><i></i>${x}</span><span class="mx-mixbar"><i style="width:${S.view.length ? (p[x] / S.view.length) * 100 : 0}%;background:${PRIORITY_COLOR[x]}"></i></span><strong>${p[x].toLocaleString()}</strong></button>`).join("")}</div><p class="ui-muted">Counts are for the current view. Choose a row to filter by it.</p>`, { label: "Priority breakdown", align: "left" });
  }

  // ------------------------------------------------------------------ events
  const typeSearch = debounce((v) => setFilters({ q: v }, { repaintToolbar: false }), 220);
  container.addEventListener("input", (e) => { if (e.target.id === "f-q") typeSearch(e.target.value); });
  container.addEventListener("change", (e) => {
    const m = { "f-priority": "priority", "f-sla": "slaStatus", "f-env": "environment", "f-type": "assetType", "f-cat": "category", "f-infra": "infraType" }[e.target.id];
    if (m) setFilters({ [m]: e.target.value });
  });
  container.addEventListener("click", (e) => {
    const t = e.target;
    const un = t.closest("[data-unfilter]"); if (un) { S.state = { ...S.state, filters: clearFilter(S.state.filters, un.dataset.unfilter) }; pushUrl(); paintKpis(); paintToolbar(); paintChips(); paintTable(); return; }
    if (t.closest("#q-clear") || t.closest("#q-clear2")) { S.state = { ...defaultState(), sort: S.state.sort }; pushUrl(); $("#q-note").innerHTML = ""; paintKpis(); paintToolbar(); paintChips(); paintTable(); return; }
    if (t.closest("#q-save")) { saveCurrent(); return; }
    if (t.closest("#q-refresh")) { refreshNow(true); return; }
    if (t.closest("#q-views")) { openViews(t.closest("#q-views")); return; }
    if (t.closest("#q-link")) { copyText(window.location.href, "Link to this view copied"); return; }
    if (t.closest("#q-mix")) { openMix(t.closest("#q-mix")); return; }
    const mf = t.closest("[data-mixfilter]"); if (mf) { const v = mf.dataset.mixfilter; setFilters({ priority: S.state.filters.priority === v ? "all" : v }); document.querySelectorAll(".mx-popover").forEach((n) => n.remove()); return; }
    const why = t.closest("[data-why]"); if (why) { openWhy(why, why.dataset.why); return; }
    const op = t.closest("[data-open]"); if (op) { const f = S.all.find((x) => x.id === op.dataset.open); if (f) openFinding(f); return; }
    const b = t.closest("[data-bulk]");
    if (b) {
      const k = b.dataset.bulk;
      if (k === "assign") bulkAssign(); else if (k === "exception") bulkException(); else if (k === "clear") S.table.clearSelection();
      else if (k === "copy") copyText([...S.selected].join("\n"), `${S.selected.size} ids copied`);
    }
  });
  const onTenant = () => { paintKpis(); paintTable(); };
  window.addEventListener("tenant-changed", onTenant);
  onCleanup(() => window.removeEventListener("tenant-changed", onTenant));

  async function refreshNow(manual = false) {
    try { await load(); paintKpis(); paintToolbar(); paintChips(); paintTable(); const age = $("#q-age .ui-age"); if (age) touchDataAge(age, S.loadedAt); if (manual) toast("Queue refreshed.", { tone: "good", ms: 1800 }); }
    catch (e) { if (manual) toast(`Could not refresh: ${e.message}`, { tone: "bad" }); }
  }

  // ------------------------------------------------------------------ go
  try { await load(); } catch (e) { $("#q-skel").hidden = true; $("#q-table").innerHTML = emptyState({ title: "The queue could not be loaded", body: e.message || "Try again in a moment.", iconName: "risk" }); return; }
  S.view = currentView();
  paintKpis(); paintToolbar(); paintChips(); paintTable();
  $("#q-age").innerHTML = dataAgeBadge(S.loadedAt); mountDataAge($("#q-age"));

  // page-level keys and palette actions
  const onKey = (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey || modalOpen()) return;
    const t = e.target;
    if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
    if ((e.key === "j" || e.key === "k") && !t.closest("tr[data-i]")) { const first = container.querySelector("tr[data-i]"); if (first) { e.preventDefault(); first.tabIndex = 0; first.focus(); } }
  };
  document.addEventListener("keydown", onKey);
  onCleanup(() => document.removeEventListener("keydown", onKey));
  registerShortcutHelp(["j", "k"], "Queue: move between findings");
  registerShortcutHelp(["x", "Space"], "Queue: select the focused finding (Shift-click for a range)");
  pageActions([
    { label: "Queue: show SLA-breached findings", icon: "queue", run: () => applySearch("?slaStatus=breached") },
    { label: "Queue: show actively exploited (KEV) findings", icon: "queue", run: () => applySearch("?kevOnly=true") },
    { label: "Queue: show unowned Critical findings", icon: "queue", run: () => applySearch("?priority=Critical&unowned=true") },
    { label: "Queue: clear all filters", icon: "queue", run: () => applySearch("") },
    { label: "Queue: save the current view", icon: "queue", run: saveCurrent },
    { label: "Queue: focus the search box", icon: "search", run: () => { const i = $("#f-q"); if (i) i.focus(); } },
  ]);
  autoRefresh(() => refreshNow(false), { every: REFRESH_MS, onMode: setLive });

  const kev = scoped().filter((f) => f.kev && f.kev.listed).length;
  const breached = scoped().filter((f) => f.sla && f.sla.breached).length;
  const alerts = [];
  if (breached) alerts.push(insightAlertHtml(`<strong>${breached}</strong> finding(s) are past their SLA window.`, "danger"));
  if (kev) alerts.push(insightAlertHtml(`<strong>${kev}</strong> finding(s) are CISA KEV-listed: confirmed actively exploited.`, "warn"));
  setInsightsContent(insightSectionHtml("On this page", alerts.join("")));
}
