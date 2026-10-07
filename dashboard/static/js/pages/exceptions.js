// Vulnerability exceptions: time-boxed risk acceptance for findings that cannot be fixed on schedule. A table with expiry countdowns, counts that filter it, a request dialog
// that checks the same rules as the server (a different approver, a future date within a year, a real reason) before it sends anything, and revoke with a confirmation.
import { api } from "../api.js";
import { getCurrentUser } from "../auth.js";
import { escapeHtml } from "../dom.js";
import { icon } from "../icons.js";
import { groupLabelFor } from "../domainGrouping.js";
import { kpiTile, chip, severityChip, toast, emptyState, onCleanup, dataAgeBadge, mountDataAge, debounce, tipAttr, mountCounters } from "../ui.js";
import { modal, liveBadge, avatar } from "../sxKit.js";
import { selectableTable, autoRefresh, pageActions, skeletonPage, replaceSearch } from "../mxKit.js";
import { exceptionState, exceptionKpis, validateException, addDaysIso, daysUntil, filterRecords, MAX_EXCEPTION_DAYS } from "../moduleLogic.js";
import { openFindingById } from "../findingLookup.js";

export const title = "Vulnerability Exceptions";

const REFRESH_MS = 30000;
const FILTERS = ["all", "active", "expiring", "expired", "revoked"];

export async function render(container) {
  const me = await getCurrentUser().catch(() => null);
  const isAdmin = !!me && me.role === "admin";
  const qs = new URLSearchParams(window.location.search);
  const S = { exceptions: [], findings: new Map(), queue: [], approvals: new Map(), filter: FILTERS.includes(qs.get("state")) ? qs.get("state") : "all", q: qs.get("q") || "", domain: qs.get("domain") || "all", highlight: qs.get("highlight"), loadedAt: 0, table: null, done: false };
  let alive = true;
  onCleanup(() => { alive = false; });
  const $ = (s) => container.querySelector(s);

  container.innerHTML = `<div class="sx-page mx-page"><div class="sx-head"><div><h2>Vulnerability exceptions</h2><p>A documented, time-boxed risk acceptance for a finding that cannot be remediated on schedule: a compensating control is in place, no vendor patch exists yet, or the asset is being retired. Every exception has a second person's approval and an expiry.</p></div>
    <div class="sx-row"><span id="x-live"></span><span id="x-age"></span><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="x-refresh">${icon("clock", 14)} Refresh</button>${isAdmin ? '<button type="button" class="ui-btn sx-btn-sm" id="x-new">Request an exception</button>' : ""}</div></div>
    <div class="mx-callout mx-callout-warn">An active exception is shown here and on the queue, but does not pause SLA-breach counting in the priority engine. See <code>remediation/exceptions/store.py</code> for that scope limit.</div>
    <div id="x-skel">${skeletonPage(4)}</div><div id="x-kpis" class="sx-kpis mx-kpis" hidden></div><div id="x-note"></div><div id="x-toolbar" hidden></div><div id="x-main"></div></div>`;
  const setLive = (m) => { const el = $("#x-live"); if (el) el.innerHTML = liveBadge(m); };
  setLive("idle");

  async function load() {
    const [{ exceptions }, queue, { approvals }] = await Promise.all([api.exceptionsList(), api.queue(), api.remediationApprovalsList().catch(() => ({ approvals: [] }))]);
    if (!alive) return;
    S.queue = queue.findings; S.findings = new Map(queue.findings.map((f) => [f.id, f])); S.approvals = new Map(approvals.map((a) => [a.finding_id, a]));
    S.exceptions = exceptions.map((e) => { const f = S.findings.get(e.finding_id); return { ...e, finding: f || null, group: f ? groupLabelFor(f) : "Unknown", st: exceptionState(e) }; });
    S.loadedAt = Date.now();
  }
  const url = () => { const p = new URLSearchParams(); if (S.filter !== "all") p.set("state", S.filter); if (S.q) p.set("q", S.q); if (S.domain !== "all") p.set("domain", S.domain); if (S.highlight) p.set("highlight", S.highlight); replaceSearch(p.toString() ? `?${p}` : ""); };
  const view = () => {
    let l = S.exceptions.filter((e) => (S.filter === "all" ? true : S.filter === "active" ? ["active", "expiring"].includes(e.st.key) : e.st.key === S.filter) && (S.domain === "all" || e.group === S.domain));
    l = filterRecords(l, S.q, [(e) => e.id, (e) => e.finding_id, (e) => e.reason, (e) => e.requested_by, (e) => e.approved_by, (e) => e.finding && e.finding.title]);
    return l.sort((a, b) => (a.st.days ?? 9999) - (b.st.days ?? 9999) || b.id.localeCompare(a.id, undefined, { numeric: true }));
  };

  function paintKpis() {
    const k = exceptionKpis(S.exceptions);
    const cell = (key, t, label) => `<div class="sx-kpi-cell" data-kpi="${key}" role="button" tabindex="0" aria-pressed="${S.filter === key}" aria-label="${escapeHtml(label)}">${t}</div>`;
    const el = $("#x-kpis"); el.hidden = false; $("#x-skel").hidden = true;
    el.innerHTML = [
      cell("all", kpiTile({ label: "All exceptions", value: k.total, hint: "Every exception ever recorded, including expired and revoked." }), "Show all exceptions"),
      cell("active", kpiTile({ label: "Active", value: k.active, tone: "good", hint: "Currently accepted. Each lapses on its own date." }), "Show active exceptions"),
      cell("expiring", kpiTile({ label: "Expiring in 14 days", value: k.expiring, tone: k.expiring ? "warn" : "good", hint: "Review before they lapse: the finding returns to the queue as a normal open item." }), "Show exceptions expiring soon"),
      cell("expired", kpiTile({ label: "Expired", value: k.expired, hint: "Lapsed without renewal." }), "Show expired exceptions"),
      cell("revoked", kpiTile({ label: "Revoked", value: k.revoked, hint: "Withdrawn early by an administrator." }), "Show revoked exceptions"),
    ].join("");
    mountCounters(el);
  }
  function paintToolbar() {
    const el = $("#x-toolbar"); el.hidden = false;
    const active = document.activeElement; const restore = active && el.contains(active) && active.id ? `#${active.id}` : ""; const caret = active && active.id === "x-q" ? active.selectionStart : null;
    const groups = [...new Set(S.exceptions.map((e) => e.group))].sort();
    el.innerHTML = `<div class="sx-toolbar" role="search" aria-label="Filter exceptions"><input type="search" class="sx-field" id="x-q" placeholder="Search id, finding, reason, person" value="${escapeHtml(S.q)}" aria-label="Search exceptions">
      <select class="sx-field" id="x-domain" aria-label="Security domain"><option value="all">All domains</option>${groups.map((g) => `<option value="${escapeHtml(g)}" ${g === S.domain ? "selected" : ""}>${escapeHtml(g)}</option>`).join("")}</select>
      <span class="ui-muted mx-count" role="status" aria-live="polite">${view().length} of ${S.exceptions.length} exception${S.exceptions.length === 1 ? "" : "s"}</span></div>`;
    if (restore) { const n = el.querySelector(restore); if (n) { n.focus(); if (caret !== null && n.setSelectionRange) n.setSelectionRange(caret, caret); } }
  }
  function expiryCell(e) {
    const st = e.st;
    if (st.days === null) return `${escapeHtml(e.expires_on)}<div class="mx-sub">${escapeHtml(st.label)}</div>`;
    const fraction = Math.max(0, Math.min(1, st.days / MAX_EXCEPTION_DAYS));
    return `${escapeHtml(e.expires_on)}<div class="mx-sub mx-clock-${st.tone}">${escapeHtml(st.label)}</div><span class="mx-meter ${st.tone === "warn" ? "warn" : ""}" role="img" aria-label="${st.days} days left"><i style="width:${Math.max(3, Math.round(fraction * 100))}%"></i></span>`;
  }
  const columns = [
    { key: "id", label: "Exception", sortKey: "", width: 100, csv: (e) => e.id, render: (e) => `<strong>${escapeHtml(e.id)}</strong><div class="mx-sub">${escapeHtml(e.created_on || "")}</div>` },
    { key: "finding", label: "Finding", width: 280, csv: (e) => `${e.finding_id} ${e.finding ? e.finding.title : ""}`, render: (e) => `<button type="button" class="sx-link-btn mx-id" data-open="${escapeHtml(e.finding_id)}">${escapeHtml(e.finding_id)}</button>${e.finding ? ` ${severityChip(e.finding.priority)}` : ""}<div class="mx-sub" title="${escapeHtml(e.finding ? e.finding.title : "")}">${escapeHtml(e.finding ? e.finding.title : "No longer in the live queue")}</div>` },
    { key: "reason", label: "Reason", width: 300, csv: (e) => e.reason, render: (e) => `<span class="mx-title" title="${escapeHtml(e.reason)}">${escapeHtml(e.reason)}</span>` },
    { key: "people", label: "Requested / approved", width: 190, csv: (e) => `${e.requested_by} / ${e.approved_by}`, render: (e) => `<span class="sx-who">${avatar(e.requested_by, { size: 18 })}<span class="t">${escapeHtml(String(e.requested_by).split("@")[0])}</span></span><div class="mx-sub">approved by ${escapeHtml(String(e.approved_by).split("@")[0])}</div>` },
    { key: "expiry", label: "Expires", width: 150, csv: (e) => e.expires_on, render: expiryCell },
    { key: "status", label: "Status", width: 120, csv: (e) => e.computed_status, render: (e) => chip(e.st.key === "expiring" ? "Expiring soon" : e.st.label.endsWith("left") ? "Active" : e.st.label, { tone: e.st.key === "active" ? "good" : e.st.key === "expiring" ? "warn" : "neutral" }) },
    { key: "approval", label: "Remediation approval", hidden: false, width: 150, csv: (e) => (S.approvals.get(e.finding_id) || {}).computed_status || "", render: (e) => { const a = S.approvals.get(e.finding_id); return a ? `<a href="/remediation-approvals" data-link ${tipAttr("This finding also has a remediation approval in progress")}>${escapeHtml(a.computed_status)}</a>` : '<span class="ui-muted">none</span>'; } },
    { key: "act", label: "", width: 90, csv: () => "", render: (e) => (isAdmin && ["active", "expiring"].includes(e.st.key) ? `<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-revoke="${escapeHtml(e.id)}">Revoke</button>` : "") },
  ];
  function paintMain() {
    const host = $("#x-main"); const list = view();
    const empty = !S.exceptions.length ? emptyState({ title: "No exceptions recorded", body: "When a finding cannot be fixed on schedule, record why the risk is accepted, who approved it and when it lapses.", actionLabel: isAdmin ? "" : "", iconName: "exception" }) : emptyState({ title: "No exception matches this filter", body: "Clear the search, the domain or the state filter.", iconName: "search" });
    if (!S.table) { S.table = selectableTable(host, { columns, rows: list, rowKey: (e) => e.id, caption: "Exceptions", csvName: "quanta-exceptions", storageKey: "exceptions-v2", rowHeight: 62, maxHeight: 620, emptyHtml: empty, rowClass: (e) => (S.highlight === e.id ? "mx-flash" : ""), onOpen: (e) => openFindingById(e.finding_id) }); }
    else { S.table.setRows(list); }
    if (S.highlight && !S.done) {
      const i = S.table.scrollToKey(S.highlight); S.done = true;
      if (i < 0) $("#x-note").innerHTML = `<div class="mx-callout mx-callout-warn">Exception <code>${escapeHtml(S.highlight)}</code> was not found with these filters. <button type="button" class="sx-link-btn" id="x-clear">Show all</button></div>`;
    }
    if (!isAdmin && !S.exceptions.length) { /* the empty state already explains it */ }
  }
  const paintAll = () => { if (!alive) return; paintKpis(); paintToolbar(); paintMain(); const age = $("#x-age"); if (age) { age.innerHTML = dataAgeBadge(S.loadedAt); mountDataAge(age); } };
  const reload = async (quiet = true) => { try { await load(); paintAll(); } catch (e) { if (!quiet) toast(`Could not refresh: ${e.message}`, { tone: "bad" }); } };

  // ------------------------------------------------------------------ request dialog
  async function requestDialog(prefill = {}) {
    let admins = [];
    try { admins = ((await api.listUsers()).users || []).filter((u) => u.role === "admin" && u.email.toLowerCase() !== me.email.toLowerCase()); } catch (e) { toast(e.message, { tone: "bad" }); return; }
    const opts = admins.map((a) => `<option value="${escapeHtml(a.email)}">${escapeHtml(a.name || a.email)} (${escapeHtml(a.email)})</option>`).join("");
    const p = modal({ title: "Request an exception", confirmLabel: "Record exception", wide: true, description: admins.length ? "Four things: what, why, who approves it, and when it lapses." : "An exception needs a second administrator to approve it (separation of duties). Create one under People first.",
      body: `<fieldset class="mx-fs"><legend>1. What needs an exception</legend><label>Find a finding<input type="text" id="m-fsearch" autocomplete="off" placeholder="Type an id, title, CVE or asset" aria-controls="m-fresults"></label><input type="hidden" id="m-fid" value="${escapeHtml(prefill.finding_id || "")}"><div id="m-fpicked" class="mx-picked"></div><div id="m-fresults" class="mx-results" role="listbox" aria-label="Matching findings"></div><div id="m-conflict"></div></fieldset>
        <fieldset class="mx-fs"><legend>2. Why (reason or compensating control)</legend><div id="m-controls"></div><textarea id="m-reason" maxlength="2000" placeholder="Why this risk is accepted, and what limits it">${escapeHtml(prefill.reason || "")}</textarea></fieldset>
        <fieldset class="mx-fs"><legend>3. Approved by</legend><select id="m-appr">${opts}</select></fieldset>
        <fieldset class="mx-fs"><legend>4. Time-box it (at most ${MAX_EXCEPTION_DAYS} days)</legend><div class="sx-row">${[30, 90, 180].map((d) => `<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-days="${d}">+${d} days</button>`).join("")}<label class="mx-inline">or a date <input type="date" id="m-exp"></label></div><p class="ui-muted" id="m-exp-note"></p></fieldset>`,
      validate: (d) => validateException({ finding_id: d.querySelector("#m-fid").value, reason: d.querySelector("#m-reason").value, requested_by: me.email, approved_by: d.querySelector("#m-appr").value, expires_on: d.querySelector("#m-exp").value }),
      collect: (d) => ({ finding_id: d.querySelector("#m-fid").value, reason: d.querySelector("#m-reason").value.trim(), requested_by: me.email, approved_by: d.querySelector("#m-appr").value, expires_on: d.querySelector("#m-exp").value }) });
    const dlg = [...document.querySelectorAll(".sx-modal")].pop();
    if (dlg) wireDialog(dlg);
    const out = await p;
    if (!out) return;
    try { await api.exceptionCreate(out); toast("Exception recorded.", { tone: "good" }); S.highlight = null; await reload(); } catch (e) { toast(e.message, { tone: "bad", ms: 9000 }); }
  }
  function wireDialog(dlg) {
    const $d = (s) => dlg.querySelector(s);
    const pick = (id) => {
      const f = S.findings.get(id); $d("#m-fid").value = id || "";
      $d("#m-fpicked").innerHTML = f ? `<div class="mx-pickedrow">${severityChip(f.priority)} <strong>${escapeHtml(f.id)}</strong> ${escapeHtml(f.title)} <span class="ui-muted">on ${escapeHtml((f.asset && f.asset.name) || "")}</span></div>` : "";
      const a = S.approvals.get(id);
      $d("#m-conflict").innerHTML = a ? `<div class="mx-callout">This finding already has a remediation approval in progress (${escapeHtml(a.computed_status)}, requested by ${escapeHtml(a.requested_by)}). An exception runs in parallel with it rather than replacing it. Make sure that is what you intend.</div>` : "";
      const ctl = (f && f.compensating_controls) || [];
      $d("#m-controls").innerHTML = ctl.length ? `<div class="mx-callout"><strong>Suggested compensating controls</strong> <span class="ui-muted">(keyword heuristic, not certified)</span><ul class="mx-list">${ctl.map((c) => `<li>${escapeHtml(c)} <button type="button" class="sx-link-btn" data-insert="${escapeHtml(c)}">Insert</button></li>`).join("")}</ul></div>` : "";
    };
    const results = debounce(() => {
      const q = $d("#m-fsearch").value.trim();
      const list = q.length < 2 ? [] : filterRecords(S.queue, q, [(f) => f.id, (f) => f.title, (f) => f.cve, (f) => f.asset && f.asset.name]).slice(0, 8);
      $d("#m-fresults").innerHTML = list.map((f) => `<button type="button" role="option" class="mx-result" data-pick="${escapeHtml(f.id)}">${severityChip(f.priority)} <strong>${escapeHtml(f.id)}</strong> ${escapeHtml(f.title)} <span class="ui-muted">${escapeHtml((f.asset && f.asset.name) || "")}</span></button>`).join("") || (q.length >= 2 ? '<p class="ui-muted">No finding matches.</p>' : "");
    }, 160);
    $d("#m-fsearch").addEventListener("input", results);
    dlg.addEventListener("click", (e) => {
      const pk = e.target.closest("[data-pick]"); if (pk) { pick(pk.dataset.pick); $d("#m-fresults").innerHTML = ""; $d("#m-fsearch").value = ""; return; }
      const ins = e.target.closest("[data-insert]"); if (ins) { const r = $d("#m-reason"); r.value = r.value ? `${r.value}\n${ins.dataset.insert}` : ins.dataset.insert; r.focus(); return; }
      const dd = e.target.closest("[data-days]"); if (dd) { $d("#m-exp").value = addDaysIso(dd.dataset.days); note(); }
    });
    const note = () => { const v = $d("#m-exp").value; const n = v ? daysUntil(v) : null; $d("#m-exp-note").textContent = n === null ? "" : n > 0 ? `Active for ${n} day${n === 1 ? "" : "s"}, until ${v}.` : `${v} is not in the future.`; };
    $d("#m-exp").addEventListener("change", note);
    if ($d("#m-fid").value) pick($d("#m-fid").value);
    if (!$d("#m-fid").value) $d("#m-fsearch").focus();
  }
  async function revoke(id) {
    const e = S.exceptions.find((x) => x.id === id); if (!e) return;
    const ok = await modal({ title: `Revoke ${id}?`, confirmLabel: "Revoke", danger: true, description: `${e.finding_id} returns to the queue as a normal open finding straight away. This is recorded under your name.`, body: "" });
    if (!ok) return;
    const i = S.exceptions.findIndex((x) => x.id === id); const snap = S.exceptions[i];
    S.exceptions[i] = { ...snap, computed_status: "revoked", st: exceptionState({ ...snap, computed_status: "revoked" }) }; paintAll();
    try { await api.exceptionRevoke(id); toast(`${id} revoked.`, { tone: "good" }); await load(); } catch (er) { S.exceptions[i] = snap; toast(`Not revoked: ${er.message}`, { tone: "bad", ms: 8000 }); }
    paintAll();
  }

  // ------------------------------------------------------------------ events
  const typeSearch = debounce((v) => { S.q = v; S.highlight = null; url(); paintMain(); paintToolbar(); }, 220);
  container.addEventListener("input", (e) => { if (e.target.id === "x-q") typeSearch(e.target.value); });
  container.addEventListener("change", (e) => { if (e.target.id === "x-domain") { S.domain = e.target.value; url(); paintMain(); paintToolbar(); } });
  container.addEventListener("click", (e) => {
    const t = e.target;
    const kpi = t.closest("[data-kpi]"); if (kpi) { S.filter = S.filter === kpi.dataset.kpi ? "all" : kpi.dataset.kpi; url(); paintKpis(); paintMain(); paintToolbar(); return; }
    const op = t.closest("[data-open]"); if (op) { openFindingById(op.dataset.open); return; }
    const rv = t.closest("[data-revoke]"); if (rv) { revoke(rv.dataset.revoke); return; }
    if (t.closest("#x-new")) { requestDialog(); return; }
    if (t.closest("#x-refresh")) { reload(false).then(() => toast("Refreshed.", { tone: "good", ms: 1600 })); return; }
    if (t.closest("#x-clear")) { S.filter = "all"; S.q = ""; S.domain = "all"; S.highlight = null; $("#x-note").innerHTML = ""; url(); paintAll(); }
  });
  container.addEventListener("keydown", (e) => { const k = e.target.closest && e.target.closest("[data-kpi]"); if (k && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); k.click(); } });

  try { await load(); } catch (e) { $("#x-skel").hidden = true; $("#x-main").innerHTML = `<div class="sx-panel">${emptyState({ title: "Exceptions could not be loaded", body: e.message || "Try again in a moment.", iconName: "risk" })}</div>`; return; }
  paintAll();
  if (isAdmin && (qs.get("finding_id") || qs.get("reason"))) requestDialog({ finding_id: qs.get("finding_id") || "", reason: qs.get("reason") || "" });
  pageActions([
    ...(isAdmin ? [{ label: "Exceptions: request an exception", icon: "exception", run: () => requestDialog() }] : []),
    { label: "Exceptions: show those expiring in 14 days", icon: "exception", run: () => { S.filter = "expiring"; url(); paintAll(); } }, { label: "Exceptions: show active", icon: "exception", run: () => { S.filter = "active"; url(); paintAll(); } },
  ]);
  autoRefresh(() => reload(true), { every: REFRESH_MS, onMode: setLive });
}
