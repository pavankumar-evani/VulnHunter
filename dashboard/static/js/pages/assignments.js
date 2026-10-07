// Assignments: the ITSM-style work queue as a live board (drag a card to change its status) or a table, with counts per view, SLA clocks and bulk assign.
// Where the Remediation queue answers "what is the riskiest thing", this answers "what is mine, what is my team's, what has nobody picked up". The rules for a
// move live in moduleLogic.js (tested under Node); the server stays the authority on who may do what.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { icon } from "../icons.js";
import { getCurrentUser } from "../auth.js";
import { openAssignModal, STATUS_LABELS } from "../assignModal.js";
import { openFindingById } from "../findingLookup.js";
import { kpiTile, severityChip, toast, emptyState, onCleanup, registerShortcutHelp, dataAgeBadge, mountDataAge, touchDataAge, debounce, tipAttr, mountCounters } from "../ui.js";
import { modal, popMenu, avatar, ringSvg, liveBadge, segmented, onSeg, modalOpen } from "../sxKit.js";
import { selectableTable, replaceSearch, autoRefresh, pageActions, skeletonPage, tabBar, wireTabBar } from "../mxKit.js";
import { slaRingFor } from "../queueLogic.js";
import { ASSIGN_STATUSES, ASSIGN_LABELS, ASSIGN_VIEWS, assignStatusOf, groupByStatus, planAssignmentMove, assignmentKpis, assignAgeDays, slaClock, parseAssignState, assignStateToSearch, filterRecords } from "../moduleLogic.js";

export const title = "Assignments";

const VIEWS = [
  { id: "mine", label: "My work", hint: "Findings assigned to you" },
  { id: "team", label: "My team", hint: "Routed to your team, by assignment or by asset ownership" },
  { id: "needs_owner", label: "Needs an owner", hint: "No individual assignee yet: a team may own it, nobody has picked it up" },
  { id: "unowned", label: "Unowned", hint: "No person and no team: nothing routes this anywhere yet" },
  { id: "all", label: "All", hint: "Everything you are allowed to see" },
];
const REFRESH_MS = 20000;

export async function render(container) {
  const me = await getCurrentUser(true);
  if (!me) { window.history.pushState({}, "", "/login?redirect=/assignments"); window.dispatchEvent(new PopStateEvent("popstate")); return; }
  const isAdmin = me.role === "admin";
  const S = { f: parseAssignState(window.location.search), data: null, teams: [], people: [], selected: new Set(), loadedAt: 0, pending: new Set(), flash: new Set(), table: null, drag: null, limit: {} };
  let alive = true;
  onCleanup(() => { alive = false; });
  const $ = (s) => container.querySelector(s);

  container.innerHTML = `<div class="sx-page mx-page" id="a-root">
    <div class="sx-head"><div><h2>Assignments</h2><p>Your work queue. Every finding is assigned to a person, routed to a team, or not owned at all. Take work, hand it off, and move it through Open, In progress, Blocked and Resolved. Every change is recorded in the Activity log.</p></div>
      <div class="sx-row"><span id="a-live"></span><span id="a-age"></span><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="a-refresh">${icon("clock", 14)} Refresh</button>${isAdmin ? `<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="a-route" ${tipAttr("Route every still-unassigned finding to the team that owns its asset. Previews the count first and never overwrites an assignment.")}>Auto-route to asset teams</button>` : ""}</div></div>
    <div id="a-skel">${skeletonPage(5)}</div>
    <div id="a-tabs" hidden></div><div id="a-kpis" class="sx-kpis mx-kpis" hidden></div><div id="a-toolbar" hidden></div><div id="a-bulk" class="mx-bulk" hidden></div><div id="a-main"></div></div>`;
  const setLive = (m) => { const el = $("#a-live"); if (el) el.innerHTML = liveBadge(m); };
  setLive("idle");

  const fetchData = () => api.assignments({ view: S.f.view, team: S.f.team, priority: S.f.priority, status: S.f.status, include_resolved: S.f.includeResolved, limit: 500 });
  async function load() {
    const d = await fetchData();
    if (!alive) return;
    S.data = d; S.loadedAt = Date.now();
    const ids = new Set(d.rows.map((r) => r.id));
    S.selected = new Set([...S.selected].filter((i) => ids.has(i)));
  }
  const rows = () => filterRecords(S.data ? S.data.rows : [], S.f.q, [(r) => r.id, (r) => r.title, (r) => r.asset, (r) => r.cve, (r) => r.team, (r) => r.assignment && r.assignment.assignee_email]);
  const url = () => replaceSearch(assignStateToSearch(S.f));
  const find = (id) => (S.data ? S.data.rows.find((r) => r.id === id) : null);

  // ------------------------------------------------------------------ painting
  function paintTabs() {
    const c = S.data.counts;
    const el = $("#a-tabs"); el.hidden = false;
    el.innerHTML = tabBar("Assignment views", VIEWS.map((v) => ({ id: v.id, label: v.label, count: (c[v.id] ?? 0).toLocaleString() })), S.f.view);
    el.querySelectorAll("[data-tab]").forEach((b) => { const v = VIEWS.find((x) => x.id === b.dataset.tab); if (v) b.setAttribute("data-tooltip", v.hint); });
  }
  function paintKpis() {
    const k = assignmentKpis(S.data.rows);
    const el = $("#a-kpis"); el.hidden = false; $("#a-skel").hidden = true;
    const cell = (key, t, label, pressed) => `<div class="sx-kpi-cell" data-kpi="${key}" role="button" tabindex="0" aria-pressed="${!!pressed}" aria-label="${escapeHtml(label)}">${t}</div>`;
    el.innerHTML = [
      cell("all", kpiTile({ label: "In this view", value: k.total, hint: "Findings in the selected view, before the filters on this page." }), "Show every status", !S.f.status),
      cell("unassigned", kpiTile({ label: "Unassigned", value: k.unassigned, tone: k.unassigned ? "warn" : "good", hint: "Nobody has picked these up." }), "Show only unassigned", S.f.status === "unassigned"),
      cell("in_progress", kpiTile({ label: "In progress", value: k.inProgress, hint: "Someone is working on them." }), "Show only in progress", S.f.status === "in_progress"),
      cell("blocked", kpiTile({ label: "Blocked", value: k.blocked, tone: k.blocked ? "warn" : "good", hint: "Work that cannot move; the note says why." }), "Show only blocked", S.f.status === "blocked"),
      `<div class="sx-kpi-cell">${kpiTile({ label: "SLA breached", value: k.breached, tone: k.breached ? "danger" : "good", hint: "Past the remediation window for their priority (open work only)." })}</div>`,
      `<div class="sx-kpi-cell">${kpiTile({ label: "Due in 3 days", value: k.atRisk, tone: k.atRisk ? "warn" : "good", hint: "Open work due within three days." })}</div>`,
    ].join("");
    mountCounters(el);
  }
  function paintToolbar() {
    const f = S.f;
    const active = document.activeElement; const restore = active && $("#a-toolbar").contains(active) && active.id ? `#${active.id}` : ""; const caret = active && active.id === "a-q" ? active.selectionStart : null;
    const el = $("#a-toolbar"); el.hidden = false;
    const opt = (v, l, cur) => `<option value="${escapeHtml(v)}" ${v === cur ? "selected" : ""}>${escapeHtml(l)}</option>`;
    el.innerHTML = `<div class="sx-toolbar" role="search" aria-label="Filter assignments">
      <input type="search" class="sx-field" id="a-q" placeholder="Search id, title, asset, assignee" value="${escapeHtml(f.q)}" aria-label="Search assignments">
      <select class="sx-field" id="a-priority" aria-label="Priority"><option value="">Any priority</option>${["Critical", "High", "Medium", "Low"].map((p) => opt(p, p, f.priority)).join("")}</select>
      <select class="sx-field" id="a-status" aria-label="Status"><option value="">Any status</option>${ASSIGN_STATUSES.filter((s) => s !== "resolved" || f.includeResolved).map((s) => opt(s, ASSIGN_LABELS[s], f.status)).join("")}</select>
      <select class="sx-field" id="a-team" aria-label="Team"><option value="">Any team</option>${S.teams.map((t) => opt(t.name, t.name, f.team)).join("")}</select>
      <label class="mx-check"><input type="checkbox" id="a-resolved" ${f.includeResolved ? "checked" : ""}> Include resolved</label>
      ${segmented("View as", [{ id: "board", label: "Board" }, { id: "table", label: "Table" }], f.mode)}
      <span class="ui-muted mx-count" role="status" aria-live="polite">${S.data.truncated ? `Showing the top ${S.data.rows.length.toLocaleString()} of ${S.data.total.toLocaleString()}. Narrow the filters to see the rest.` : `${rows().length.toLocaleString()} finding${rows().length === 1 ? "" : "s"}`}</span></div>`;
    if (restore) { const n = el.querySelector(restore); if (n) { n.focus(); if (caret !== null && n.setSelectionRange) n.setSelectionRange(caret, caret); } }
  }

  const ownerLine = (r) => { const a = r.assignment; return a && a.assignee_email ? `<span class="sx-who">${avatar(a.assignee_email, { size: 22 })}<span class="t" title="${escapeHtml(a.assignee_email)}">${escapeHtml(a.assignee_name || a.assignee_email.split("@")[0])}</span></span>` : `<span class="sx-who">${avatar(null, { size: 22 })}<span class="t">${r.team ? `${escapeHtml(r.team)} (team only)` : "Nobody"}</span></span>`; };
  function cardHtml(r) {
    const clock = slaClock(r.sla); const ring = slaRingFor({ ...r, sla: r.sla });
    const age = assignAgeDays(r.first_seen);
    const st = assignStatusOf(r);
    return `<article class="sx-card${S.pending.has(r.id) ? " pending" : ""}" data-card="${escapeHtml(r.id)}" data-sev="${escapeHtml(r.priority)}" draggable="${st === "unassigned" && !me ? "false" : "true"}" tabindex="0" role="listitem" aria-label="${escapeHtml(r.id)}, ${escapeHtml(r.priority)}, ${escapeHtml(r.title)}, ${escapeHtml(ASSIGN_LABELS[st])}">
      <div class="sx-card-top"><span class="sx-row">${severityChip(r.priority)}<span class="sx-card-id">${escapeHtml(r.id)}</span></span>
        <span class="sx-row"><span class="sx-sla" ${tipAttr(clock.text)}>${ringSvg(ring, { size: 26, radius: 11 })}</span><span class="sx-pop-host"><button type="button" class="sx-menu-btn" data-menu="${escapeHtml(r.id)}" aria-haspopup="menu" aria-expanded="false" aria-label="Actions for ${escapeHtml(r.id)}">&#8943;</button></span></span></div>
      <h4 class="sx-card-title"><button type="button" class="sx-link-btn mx-cardlink" data-open="${escapeHtml(r.id)}">${escapeHtml(r.title)}</button></h4>
      <div class="mx-sub">${escapeHtml(r.asset || "")}${r.cve ? ` &middot; ${escapeHtml(r.cve)}` : ""}</div>
      <div class="sx-card-foot">${ownerLine(r)}<span class="ui-muted mx-clock mx-clock-${clock.tone}">${escapeHtml(clock.text)}${age !== null ? ` &middot; ${age}d old` : ""}</span></div>
      ${r.assignment && r.assignment.notes ? `<div class="mx-note" title="${escapeHtml(r.assignment.notes)}">${escapeHtml(r.assignment.notes)}</div>` : ""}</article>`;
  }
  function paintMain() {
    const host = $("#a-main"); const list = rows();
    if (!S.data.rows.length && !S.f.q) { host.innerHTML = `<div class="sx-panel">${emptyState(emptyFor())}</div>`; S.table = null; return; }
    if (S.f.mode === "table") { paintTable(host, list); return; }
    S.table = null;
    const groups = groupByStatus(list);
    const cols = ASSIGN_STATUSES.filter((s) => s !== "resolved" || S.f.includeResolved);
    host.innerHTML = `<div class="sx-board mx-board5" role="list" aria-label="Assignment board. Drag a card to another column, or use the actions menu on a card." style="grid-template-columns:repeat(${cols.length}, minmax(236px, 1fr))">${cols.map((s) => `<section class="sx-col" data-col="${s}" aria-label="${ASSIGN_LABELS[s]}, ${groups[s].length}"><div class="sx-col-head"><h3>${ASSIGN_LABELS[s]}</h3><span class="sx-col-n">${groups[s].length}</span></div>
      <div class="sx-col-body">${groups[s].slice(0, S.limit[s] || 40).map(cardHtml).join("") || `<div class="sx-col-empty">${s === "unassigned" ? "Nothing waiting for an owner" : "Nothing here"}</div>`}${groups[s].length > (S.limit[s] || 40) ? `<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-more="${s}">Show ${Math.min(40, groups[s].length - (S.limit[s] || 40))} more of ${groups[s].length - (S.limit[s] || 40)} left</button>` : ""}</div></section>`).join("")}</div>`;
    S.flash.forEach((id) => { const el = container.querySelector(`[data-card="${CSS.escape(id)}"]`); if (el) el.classList.add("flash"); });
  }
  function emptyFor() {
    if (S.f.view === "mine") return { title: "Nothing is assigned to you", body: "Pick something from Needs an owner, or check My team. Work you take appears here.", actionLabel: "See what needs an owner", actionHref: "/assignments?view=needs_owner", iconName: "ownership" };
    if (S.f.view === "unowned") return { title: "Everything has an owner or a team", body: "Nothing is falling through the cracks in this view.", iconName: "approved" };
    return { title: "No finding matches these filters", body: "Clear a filter to see more.", iconName: "search" };
  }
  function paintTable(host, list) {
    const cols = [
      { key: "priority", label: "Priority", width: 100, csv: (r) => r.priority, render: (r) => severityChip(r.priority) },
      { key: "id", label: "Finding", width: 300, csv: (r) => `${r.id} ${r.title}`, render: (r) => `<button type="button" class="sx-link-btn mx-id" data-open="${escapeHtml(r.id)}">${escapeHtml(r.id)}</button><div class="mx-sub" title="${escapeHtml(r.title)}">${escapeHtml(r.title)}</div>` },
      { key: "asset", label: "Asset", width: 140, csv: (r) => r.asset, render: (r) => `<span class="mx-clip">${escapeHtml(r.asset || "")}</span>` },
      { key: "team", label: "Team", width: 120, csv: (r) => r.team || "", render: (r) => (r.team ? escapeHtml(r.team) : '<span class="ui-muted">-</span>') },
      { key: "who", label: "Assignee", width: 160, csv: (r) => (r.assignment && r.assignment.assignee_email) || "", render: ownerLine },
      { key: "status", label: "Status", width: 150, csv: (r) => assignStatusOf(r), render: (r) => { const a = r.assignment; const can = a && (isAdmin || a.assignee_email === me.email.toLowerCase()); return can ? `<select class="sx-field mx-status-sel" data-status-for="${escapeHtml(r.id)}" aria-label="Status of ${escapeHtml(r.id)}">${Object.entries(STATUS_LABELS).map(([v, l]) => `<option value="${v}" ${v === a.status ? "selected" : ""}>${l}</option>`).join("")}</select>` : `<span class="mx-statuspill mx-st-${assignStatusOf(r)}">${ASSIGN_LABELS[assignStatusOf(r)]}</span>`; } },
      { key: "sla", label: "SLA", width: 150, csv: (r) => slaClock(r.sla).text, render: (r) => { const c = slaClock(r.sla); return `<span class="mx-clock mx-clock-${c.tone}">${escapeHtml(c.text)}</span>`; } },
      { key: "age", label: "Age", width: 70, align: "right", csv: (r) => assignAgeDays(r.first_seen) ?? "", render: (r) => { const a = assignAgeDays(r.first_seen); return a === null ? "-" : `${a}d`; } },
      { key: "act", label: "", width: 100, csv: () => "", render: (r) => `<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-assign="${escapeHtml(r.id)}">${r.assignment ? "Reassign" : "Assign"}</button>` },
    ];
    if (!S.table || !host.querySelector(".mx-table")) {
      host.innerHTML = "";
      S.table = selectableTable(host, { columns: cols, rows: list, rowKey: (r) => r.id, selectable: isAdmin, caption: "Assignments", csvName: "quanta-assignments", storageKey: "assignments-v2", rowHeight: 56, maxHeight: 600, selected: S.selected,
        onSelection: (s) => { S.selected = s; paintBulk(); }, onOpen: (r) => openFindingById(r.id), emptyHtml: emptyState(emptyFor()) });
    } else { S.table.setSelected(S.selected); S.table.setRows(list); }
  }
  function paintBulk() {
    const n = S.selected.size; const host = $("#a-bulk");
    if (!isAdmin || !n || S.f.mode !== "table") { host.hidden = true; host.innerHTML = ""; return; }
    host.hidden = false;
    host.innerHTML = `<div class="mx-bulk-in" role="region" aria-label="Actions for selected findings"><strong>${n} selected</strong><button type="button" class="ui-btn sx-btn-sm" data-bulk="assign">Assign&hellip;</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-bulk="clear">Clear selection</button></div>`;
  }
  function paintAll() {
    if (!alive) return;
    paintTabs(); paintKpis(); paintToolbar(); paintMain(); paintBulk();
    const age = $("#a-age"); if (age) { age.innerHTML = dataAgeBadge(S.loadedAt); mountDataAge(age); }
    setTimeout(() => { S.flash.clear(); container.querySelectorAll(".flash").forEach((n) => n.classList.remove("flash")); }, 2400);
  }

  // ------------------------------------------------------------------ actions (optimistic: the card moves at once; a refusal puts it back and says why)
  async function reload(quiet) { try { await load(); paintAll(); } catch (e) { if (!quiet) toast(`Could not refresh: ${e.message}`, { tone: "bad" }); } }
  async function moveCard(id, toStatus) {
    const r = find(id); if (!r) return;
    const plan = planAssignmentMove(r, toStatus, me);
    if (!plan.ok) { if (!plan.same && plan.reason) toast(plan.reason, { tone: "warn", ms: 6000 }); return; }
    let note = null;
    if (plan.needs === "note") {
      const out = await modal({ title: `Mark ${id} blocked`, confirmLabel: "Mark blocked", description: "Say what it is waiting for. The note stays on the finding for whoever picks it up next.", body: `<label>What is blocking it?<textarea id="m-note" maxlength="2000" placeholder="e.g. waiting for the vendor patch, change window not approved"></textarea></label>`,
        validate: (d) => (d.querySelector("#m-note").value.trim().length < 5 ? "Write what is blocking it (5+ characters)." : ""), collect: (d) => d.querySelector("#m-note").value.trim() });
      if (!out) return; note = out;
    }
    const snap = JSON.parse(JSON.stringify(r));
    const guess = { ...r, assignment: { ...(r.assignment || {}), status: plan.action === "take" ? (plan.then || "open") : plan.status, assignee_email: (r.assignment && r.assignment.assignee_email) || me.email.toLowerCase(), assignee_name: (r.assignment && r.assignment.assignee_name) || me.name, notes: note || (r.assignment && r.assignment.notes) } };
    const i = S.data.rows.findIndex((x) => x.id === id); S.data.rows[i] = guess; S.pending.add(id); paintAll();
    try {
      if (plan.action === "take") { await api.assignFinding(id, { assignee_email: me.email }); if (plan.then) await api.setAssignmentStatus(id, { status: plan.then, notes: note }); }
      else await api.setAssignmentStatus(id, { status: plan.status, notes: note });
      toast(`${id} ${plan.action === "take" ? "assigned to you" : `marked ${ASSIGN_LABELS[plan.status].toLowerCase()}`}.`, { tone: "good", ms: 3000 });
      S.flash.add(id); await load();
    } catch (e) { S.data.rows[i] = snap; toast(`Not done: ${e.message}`, { tone: "bad", ms: 8000 }); }
    finally { S.pending.delete(id); paintAll(); }
  }
  async function take(id) { const r = find(id); if (r) await moveCard(id, "open"); }
  async function assignDialog(id) { const r = find(id); openAssignModal({ findingId: id, title: r && r.title, onSaved: () => { S.flash.add(id); reload(true); } }); }
  async function unassign(id) {
    const ok = await modal({ title: `Remove the assignment on ${id}?`, confirmLabel: "Remove", danger: true, description: "It goes back to its asset owner's team. The change is recorded.", body: "" });
    if (!ok) return;
    try { await api.unassignFinding(id); toast("Assignment removed.", { tone: "good" }); await reload(true); } catch (e) { toast(e.message, { tone: "bad" }); }
  }
  async function bulkAssign() {
    const ids = [...S.selected];
    const out = await modal({ title: `Assign ${ids.length} finding${ids.length === 1 ? "" : "s"}`, confirmLabel: "Assign", description: "Assigning to a different team moves them into that team's view.",
      body: `<label>Assignee<select id="m-who"><option value="">Nobody, route to a team only</option>${S.people.map((u) => `<option value="${escapeHtml(u.email)}">${escapeHtml(u.name)} (${escapeHtml(u.email)})</option>`).join("")}</select></label>
        <label>Team<select id="m-team"><option value="">Assignee's own team</option>${S.teams.map((t) => `<option>${escapeHtml(t.name)}</option>`).join("")}</select></label>`,
      validate: (d) => (!d.querySelector("#m-who").value && !d.querySelector("#m-team").value ? "Choose an assignee, a team, or both." : ""),
      collect: (d) => ({ assignee_email: d.querySelector("#m-who").value || null, team: d.querySelector("#m-team").value || null }) });
    if (!out) return;
    try { const r = await api.bulkAssign({ finding_ids: ids, ...out }); toast(`${r.assigned} finding${r.assigned === 1 ? "" : "s"} assigned.`, { tone: "good" }); S.selected = new Set(); await reload(true); } catch (e) { toast(`Not assigned: ${e.message}`, { tone: "bad", ms: 8000 }); }
  }
  async function autoRoute() {
    try {
      const prev = await api.autoAssign(false);
      if (!prev.would_assign) { toast(`Nothing to route: ${prev.already_assigned} already assigned, ${prev.skipped_no_team} have no asset team.`, { tone: "info", ms: 6000 }); return; }
      const ok = await modal({ title: "Auto-route to asset owners' teams", confirmLabel: `Route ${prev.would_assign.toLocaleString()}`, description: `${prev.would_assign.toLocaleString()} unassigned finding(s) go to the team that owns their asset. ${prev.already_assigned.toLocaleString()} already assigned stay untouched; ${prev.skipped_no_team.toLocaleString()} have no asset team and are skipped.`, body: "" });
      if (!ok) return;
      const done = await api.autoAssign(true); toast(`${done.assigned.toLocaleString()} finding(s) routed to their teams.`, { tone: "good" }); await reload(true);
    } catch (e) { toast(e.message, { tone: "bad" }); }
  }
  function openMenu(btn, id) {
    const r = find(id); if (!r) return;
    const st = assignStatusOf(r); const mine = r.assignment && r.assignment.assignee_email === me.email.toLowerCase();
    const moves = ASSIGN_STATUSES.filter((s) => s !== st && s !== "unassigned" && (s !== "resolved" || true)).map((s) => { const p = planAssignmentMove(r, s, me); return { label: `Move to ${ASSIGN_LABELS[s]}`, hint: p.ok ? p.note : p.reason, disabled: !p.ok, run: () => moveCard(id, s) }; });
    popMenu(btn, [{ label: "Open the finding", run: () => openFindingById(id) }, { label: mine ? "Reassign..." : st === "unassigned" ? "Assign..." : "Reassign...", run: () => assignDialog(id) }, { label: "Take it", hint: "Assign to me", disabled: mine, run: () => take(id) }, { sep: true }, ...moves, ...(isAdmin && st !== "unassigned" ? [{ sep: true }, { label: "Remove assignment...", run: () => unassign(id) }] : [])]);
  }

  // ------------------------------------------------------------------ events
  const setF = async (patch, { reloadData = true } = {}) => { S.f = { ...S.f, ...patch }; url(); if (reloadData) { try { await load(); } catch (e) { toast(e.message, { tone: "bad" }); } } paintAll(); };
  const typeSearch = debounce((v) => { S.f = { ...S.f, q: v }; url(); paintMain(); paintToolbar(); }, 220);
  container.addEventListener("input", (e) => { if (e.target.id === "a-q") typeSearch(e.target.value); });
  container.addEventListener("change", async (e) => {
    const t = e.target;
    if (t.id === "a-priority") setF({ priority: t.value }); else if (t.id === "a-status") setF({ status: t.value }); else if (t.id === "a-team") setF({ team: t.value }); else if (t.id === "a-resolved") setF({ includeResolved: t.checked, status: t.checked ? S.f.status : (S.f.status === "resolved" ? "" : S.f.status) });
    else if (t.dataset && t.dataset.statusFor) moveCard(t.dataset.statusFor, t.value);
  });
  wireTabBar($("#a-tabs"), (id) => { S.selected = new Set(); setF({ view: id }); });
  onSeg($("#a-toolbar"), (id) => { S.table = null; setF({ mode: id }, { reloadData: false }); });
  container.addEventListener("click", (e) => {
    const t = e.target;
    const kpi = t.closest("[data-kpi]"); if (kpi) { const k = kpi.dataset.kpi; setF({ status: k === "all" || S.f.status === k ? "" : k }); return; }
    const op = t.closest("[data-open]"); if (op) { openFindingById(op.dataset.open); return; }
    const mo = t.closest("[data-more]"); if (mo) { S.limit[mo.dataset.more] = (S.limit[mo.dataset.more] || 40) + 40; paintMain(); return; }
    const mn = t.closest("[data-menu]"); if (mn) { e.stopPropagation(); openMenu(mn, mn.dataset.menu); return; }
    const as = t.closest("[data-assign]"); if (as) { assignDialog(as.dataset.assign); return; }
    const b = t.closest("[data-bulk]"); if (b) { if (b.dataset.bulk === "assign") bulkAssign(); else { S.selected = new Set(); if (S.table) S.table.clearSelection(); paintBulk(); } return; }
    if (t.closest("#a-refresh")) { reload(false).then(() => toast("Refreshed.", { tone: "good", ms: 1600 })); return; }
    if (t.closest("#a-route")) { autoRoute(); }
  });
  container.addEventListener("keydown", (e) => { const k = e.target.closest && e.target.closest("[data-kpi]"); if (k && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); k.click(); } });

  // drag and drop: a pointer feature; the card menu is the keyboard route to the same moves
  container.addEventListener("dragstart", (e) => { const c = e.target.closest && e.target.closest("[data-card]"); if (!c) return; S.drag = c.dataset.card; c.classList.add("dragging"); e.dataTransfer.effectAllowed = "move"; try { e.dataTransfer.setData("text/plain", `finding:${S.drag}`); } catch { /* some browsers refuse */ } });
  container.addEventListener("dragend", () => { S.drag = null; container.querySelectorAll(".dragging,.drop-ok,.drop-no").forEach((n) => n.classList.remove("dragging", "drop-ok", "drop-no")); });
  container.addEventListener("dragover", (e) => {
    if (!S.drag) return; const col = e.target.closest("[data-col]");
    container.querySelectorAll(".drop-ok,.drop-no").forEach((n) => n.classList.remove("drop-ok", "drop-no"));
    if (!col) return; const p = planAssignmentMove(find(S.drag) || {}, col.dataset.col, me);
    if (p.ok) { e.preventDefault(); col.classList.add("drop-ok"); } else if (!p.same) col.classList.add("drop-no");
  });
  container.addEventListener("drop", (e) => { if (!S.drag) return; e.preventDefault(); const id = S.drag; S.drag = null; const col = e.target.closest("[data-col]"); container.querySelectorAll(".drop-ok,.drop-no,.dragging").forEach((n) => n.classList.remove("drop-ok", "drop-no", "dragging")); if (col) moveCard(id, col.dataset.col); });

  const onKey = (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey || modalOpen()) return; const t = e.target;
    if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
    const cards = [...container.querySelectorAll("[data-card]")]; const cur = t && t.closest ? t.closest("[data-card]") : null; const idx = cur ? cards.indexOf(cur) : -1;
    if (e.key === "j" || e.key === "k") { if (!cards.length) return; e.preventDefault(); const n = cards[Math.max(0, Math.min(cards.length - 1, idx + (e.key === "j" ? 1 : -1)))]; n.focus(); n.scrollIntoView({ block: "nearest", inline: "nearest" }); return; }
    if (!cur) return; const id = cur.dataset.card;
    if (e.key === "Enter" && !t.closest("button")) { e.preventDefault(); openFindingById(id); } else if (e.key === "t") { e.preventDefault(); take(id); } else if (e.key === "b") { e.preventDefault(); moveCard(id, "blocked"); } else if (e.key === "r") { e.preventDefault(); moveCard(id, "resolved"); }
  };
  document.addEventListener("keydown", onKey); onCleanup(() => document.removeEventListener("keydown", onKey));
  registerShortcutHelp(["j", "k"], "Assignments: move between cards");
  registerShortcutHelp(["t", "b", "r"], "Assignments: take, block or resolve the focused card");

  // ------------------------------------------------------------------ go
  try {
    const [{ teams }, { users }] = await Promise.all([api.teams(), api.assignableUsers()]);
    S.teams = teams; S.people = users;
    await load();
    if (!S.f.explicitView && S.data.total === 0) { const fb = isAdmin ? "needs_owner" : (me.team ? "team" : "needs_owner"); if ((S.data.counts[fb] || 0) > 0) { S.f.view = fb; await load(); } }
  } catch (e) { $("#a-skel").hidden = true; $("#a-main").innerHTML = `<div class="sx-panel">${emptyState({ title: "Assignments could not be loaded", body: e.message || "Try again in a moment.", iconName: "risk" })}</div>`; return; }
  paintAll();
  pageActions([
    { label: "Assignments: show my work", icon: "ownership", run: () => setF({ view: "mine" }) }, { label: "Assignments: show findings that need an owner", icon: "ownership", run: () => setF({ view: "needs_owner" }) },
    { label: "Assignments: show blocked work", icon: "ownership", run: () => setF({ status: "blocked" }) }, { label: "Assignments: switch between board and table", icon: "ownership", run: () => { S.table = null; setF({ mode: S.f.mode === "board" ? "table" : "board" }, { reloadData: false }); } },
    ...(isAdmin ? [{ label: "Assignments: auto-route to asset teams", icon: "ownership", run: autoRoute }] : []),
  ]);
  autoRefresh(() => reload(true), { every: REFRESH_MS, onMode: setLive });
  void ASSIGN_VIEWS;
}
