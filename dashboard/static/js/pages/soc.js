// SOC command center: the work that arrives routed to an analyst, as a live board (or list), with a KPI strip, the auto-closed lane and the roster.
// Pure decisions live in socLogic.js (tested under Node); this file draws and calls the API. Detail for one incident is socIncident.js (/soc?incident=ID).
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { getCurrentUser } from "../auth.js";
import { icon } from "../icons.js";
import { kpiTile, severityChip, chip, toast, emptyState, onCleanup, registerShortcutHelp, mountCounters, dataAgeBadge, mountDataAge, touchDataAge, debounce, tipAttr } from "../ui.js";
import {
  STATUS_LABEL, STATUS_ORDER, SEVERITIES, planMove, nextStatus, parseFilters, filtersToSearch, applyFilters, slaRing, kpis, sparkSeries, killChainDots, sortIncidents, upsertIncident,
  changedIds, newCritical, boardColumns, connectIncidentFeed, verdictText, verdictTone, VERDICTS, fmtMinutes,
} from "../socLogic.js";
import { modal, popMenu, avatar, ringSvg, liveBadge, segmented, onSeg, modalOpen, relTime } from "../sxKit.js";

export const title = "SOC Operations";

const SKILLS = ["endpoint", "network", "identity", "cloud", "email", "ot", "malware", "forensics"];
const SEV_COLOR = { Critical: "var(--sx-crit)", High: "var(--sx-high)", Medium: "var(--sx-med)", Low: "var(--sx-low)", Informational: "var(--sx-info)" };
const REFRESH_MS = 20000;

export async function render(container) {
  const qs = new URLSearchParams(window.location.search);
  const incidentId = Number(qs.get("incident")) || null;
  const me = await getCurrentUser().catch(() => null);
  if (incidentId) {
    const { renderIncident } = await import("../socIncident.js");
    return renderIncident(container, incidentId, { me });
  }
  return renderBoard(container, me, qs);
}

async function renderBoard(container, me, qs) {
  const email = (me && me.email) || "";
  const S = { open: [], resolved: [], auto: [], metrics: null, roster: [], filters: parseFilters(window.location.search), mode: "idle", flash: new Set(), loadedAt: 0, pending: new Set(), focusId: null, drag: null };
  const all = () => sortIncidents([...S.open, ...S.resolved.slice(0, 12)]);
  const shown = () => applyFilters(all(), S.filters, email);
  let alive = true;
  onCleanup(() => { alive = false; });

  container.innerHTML = `<div class="sx-page" id="sx-root" aria-live="off">
    <div class="sx-head"><div><h2>Security operations</h2><p>Alerts are investigated, grouped into incidents and routed to the right analyst or queue as they arrive, with the reason shown. Open one to see the investigation already done.</p></div>
      <div class="sx-row"><span id="sx-live"></span><span id="sx-age"></span><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="sx-refresh">${icon("clock", 14)} Refresh</button></div></div>
    <div class="ui-skel-grid" id="sx-skel"><div class="ui-skel ui-skel-kpi"><span class="ui-skel-line w40"></span><span class="ui-skel-line tall w60"></span></div><div class="ui-skel ui-skel-kpi"><span class="ui-skel-line w40"></span><span class="ui-skel-line tall w60"></span></div><div class="ui-skel ui-skel-kpi"><span class="ui-skel-line w40"></span><span class="ui-skel-line tall w60"></span></div><div class="ui-skel ui-skel-kpi"><span class="ui-skel-line w40"></span><span class="ui-skel-line tall w60"></span></div></div>
    <div id="sx-kpis" class="sx-kpis" hidden></div><div id="sx-toolbar" hidden></div><div id="sx-main"></div><div id="sx-lanes"></div><div id="sx-more"></div></div>`;
  const $ = (sel) => container.querySelector(sel);
  const setLive = (mode) => { S.mode = mode; const el = $("#sx-live"); if (el) el.innerHTML = liveBadge(mode); };
  setLive("idle");

  // ------------------------------------------------------------------ data
  async function load({ quiet = false } = {}) {
    const [open, auto, res, metrics, roster] = await Promise.all([
      api.socIncidents({ open_only: "true" }), api.socIncidents({ status: "auto_closed" }), api.socIncidents({ status: "resolved" }),
      api.socMetrics(14).catch(() => null), api.socAnalysts().catch(() => ({ analysts: [] })),
    ]);
    if (!alive) return;
    const before = all();
    S.open = open.incidents; S.auto = auto.incidents; S.resolved = res.incidents; S.metrics = metrics; S.roster = roster.analysts || [];
    S.loadedAt = Date.now();
    if (quiet) {
      const after = all();
      changedIds(before, after).forEach((id) => S.flash.add(id));
      newCritical(before, after).forEach((i) => toast(`New Critical incident #${i.id}: ${i.title}`, { tone: "critical", href: `/soc?incident=${i.id}`, action: "Open", ms: 12000 }));
    }
  }
  const refresh = debounce(async () => {
    try { await load({ quiet: true }); paintAll(); const age = $("#sx-age .ui-age"); if (age) touchDataAge(age, S.loadedAt); } catch { /* the next tick tries again */ }
  }, 350);

  // ------------------------------------------------------------------ painting
  function paintKpis() {
    const k = kpis([...S.open, ...S.resolved, ...S.auto], email);
    const m = S.metrics;
    const openedSpark = m ? sparkSeries(m.daily, "opened") : null;
    const resolvedSpark = m ? sparkSeries(m.daily, "resolved") : null;
    const pressed = (name) => ({ open: !S.filters.scope || S.filters.scope === "all", mine: S.filters.scope === "mine", unassigned: S.filters.scope === "unassigned", risk: S.filters.sla === "at_risk", breached: S.filters.sla === "breached" }[name]);
    const sevTotal = Math.max(1, k.open);
    const sevBar = `<div class="sx-sevbar" role="img" aria-label="Open incidents by severity: ${SEVERITIES.map((s) => `${k.bySeverity[s]} ${s}`).join(", ")}">${SEVERITIES.map((s) => (k.bySeverity[s] ? `<i style="width:${(k.bySeverity[s] / sevTotal) * 100}%;background:${SEV_COLOR[s]}" ${tipAttr(`${k.bySeverity[s]} ${s}`)}></i>` : "")).join("")}</div>`;
    const cell = (key, tileHtml, label) => `<div class="sx-kpi-cell" data-kpi="${key}" role="button" tabindex="0" aria-pressed="${!!pressed(key)}" aria-label="${escapeHtml(label)}">${tileHtml}</div>`;
    const needHist = (html, missing) => (missing ? html.replace(/<div class="ui-kpi-foot">\s*<\/div>/, '<div class="ui-kpi-foot"><span class="sx-nohist">Not enough history yet</span></div>') : html);
    const tiles = [
      cell("open", kpiTile({ label: "Open incidents", value: k.open, spark: openedSpark, hint: "Incidents in New, Triaging, Investigating or Contained. The bar splits them by severity. The line is incidents opened per day." }), "Show all open incidents"),
      cell("mine", kpiTile({ label: "My queue", value: k.mine, tone: k.mine ? "warn" : "", hint: "Open incidents assigned to you." }), "Show my queue"),
      cell("unassigned", kpiTile({ label: "Unassigned", value: k.unassigned, tone: k.unassigned ? "warn" : "good", hint: "Open incidents in a tier queue with nobody to take them. They are retried on every sweep." }), "Show unassigned incidents"),
      cell("risk", kpiTile({ label: "SLA at risk", value: k.atRisk, tone: k.atRisk ? "warn" : "good", hint: "An open incident whose acknowledge, pick-up or resolve clock is running out." }), "Show incidents at risk of breaching"),
      cell("breached", kpiTile({ label: "SLA breached", value: k.breached, tone: k.breached ? "danger" : "good", hint: "A clock has run out. Breached incidents are escalated automatically on the sweep." }), "Show breached incidents"),
      `<div class="sx-kpi-cell">${kpiTile({ label: "Auto-closed today", value: k.autoClosedToday, hint: "Likely false positives closed by the decision policy. Review them below; undo returns one to the queue." })}</div>`,
      `<div class="sx-kpi-cell">${needHist(kpiTile({ label: "Time to acknowledge", value: m && m.mtta_minutes !== null ? fmtMinutes(m.mtta_minutes) : "n/a", hint: "Mean time from an alert arriving to a person acknowledging it, over the last 14 days. Shown only once cases have been acknowledged." }), !(m && m.mtta_minutes !== null))}</div>`,
      `<div class="sx-kpi-cell">${needHist(kpiTile({ label: "Time to resolve", value: m && m.mttr_minutes !== null ? fmtMinutes(m.mttr_minutes) : "n/a", spark: resolvedSpark, hint: "Mean time from opening to resolving, over the last 14 days. The line is incidents resolved per day." }), !(m && m.mttr_minutes !== null))}</div>`,
    ];
    const el = $("#sx-kpis");
    el.hidden = false; $("#sx-skel").hidden = true;
    el.innerHTML = tiles.join("");
    mountCounters(el);
  }

  function paintToolbar() {
    const f = S.filters;
    const ae = document.activeElement;
    let restore = "";
    if (ae && container.querySelector("#sx-toolbar").contains(ae)) restore = ae.id ? `#${ae.id}` : ae.dataset.seg ? `[aria-label="${ae.closest("[role=group]").getAttribute("aria-label")}"] [data-seg="${ae.dataset.seg}"]` : "";
    const caret = ae && ae.id === "f-q" ? ae.selectionStart : null;
    const counts = { all: all().length, mine: all().filter((i) => String(i.assignee || "").toLowerCase() === email.toLowerCase() && email).length, unassigned: all().filter((i) => !i.assignee).length };
    const opt = (list, cur, label) => `<option value="">${label}</option>${list.map(([v, l]) => `<option value="${v}" ${v === cur ? "selected" : ""}>${l}</option>`).join("")}`;
    const el = $("#sx-toolbar");
    el.hidden = false;
    el.innerHTML = `<div class="sx-toolbar" role="search" aria-label="Filter incidents">
      ${segmented("Queue", [{ id: "all", label: "All", count: counts.all }, { id: "mine", label: "My queue", count: counts.mine }, { id: "team", label: "Team" }, { id: "unassigned", label: "Unassigned", count: counts.unassigned }], f.scope)}
      <select class="sx-field" id="f-tier" aria-label="Tier">${opt([["1", "L1"], ["2", "L2"], ["3", "L3"]], f.tier, "Any tier")}</select>
      <select class="sx-field" id="f-sev" aria-label="Severity">${opt(SEVERITIES.map((s) => [s, s]), f.severity, "Any severity")}</select>
      <select class="sx-field" id="f-status" aria-label="Status">${opt(STATUS_ORDER.map((s) => [s, STATUS_LABEL[s]]), f.status, "Any status")}</select>
      <select class="sx-field" id="f-sla" aria-label="Service level">${opt([["any", "At risk or breached"], ["at_risk", "At risk"], ["breached", "Breached"]], f.sla, "Any service level")}</select>
      <input type="search" class="sx-field" id="f-q" placeholder="Search id, title, host, user, IOC, CVE" value="${escapeHtml(f.q)}" aria-label="Search incidents">
      ${segmented("View", [{ id: "board", label: "Board" }, { id: "list", label: "List" }], f.view)}
      <button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="f-clear" ${filtersToSearch(f) === "" ? "hidden" : ""}>Clear filters</button></div>`;
    if (restore) { const n = el.querySelector(restore); if (n) { n.focus(); if (caret !== null && n.setSelectionRange) n.setSelectionRange(caret, caret); } }
  }

  const entityChips = (i) => {
    const e = i.entities || {};
    const items = [...(e.hosts || []).map((h) => ["host", h]), ...(e.users || []).map((h) => ["user", h]), ...(e.indicators || []).map((h) => ["ioc", h])];
    const show = items.slice(0, 3).map(([k, v]) => `<span class="sx-ent" title="${escapeHtml(k)}: ${escapeHtml(v)}"><b>${escapeHtml(k)}</b> ${escapeHtml(v)}</span>`).join("");
    return show + (items.length > 3 ? `<span class="sx-ent">+${items.length - 3}</span>` : "");
  };
  const verdictLine = (i) => {
    if (i.verdict) return `<div class="sx-verdictline">${chip(verdictText(i.verdict), { tone: verdictTone(i.verdict) })}<span class="ui-muted">analyst verdict</span></div>`;
    if (i.confidence === null || i.confidence === undefined) return `<div class="sx-verdictline">${chip("Not assessed", { tone: "neutral" })}</div>`;
    const c = Number(i.confidence);
    const label = c >= 0.7 ? "Likely real" : c <= 0.3 ? "Likely benign" : "Needs review";
    const tone = c >= 0.7 ? "critical" : c <= 0.3 ? "good" : "warn";
    const col = tone === "critical" ? "var(--sx-bad)" : tone === "good" ? "var(--sx-good)" : "var(--sx-warn)";
    return `<div class="sx-verdictline">${chip(label, { tone })}<span class="sx-conf" ${tipAttr(`${Math.round(c * 100)}% chance this is a real threat (first-look verdict)`)}><i style="width:${Math.round(c * 100)}%;--c:${col}"></i></span><span class="ui-muted">${Math.round(c * 100)}%</span></div>`;
  };
  const whyText = (i) => ((i.routing_reason || []).slice(-2).join(" ") || "Routing reason not recorded.");

  function cardHtml(i) {
    const ring = slaRing(i.sla);
    const kc = killChainDots(i.kill_chain);
    const owner = i.assignee ? `<span class="sx-who">${avatar(i.assignee, { size: 22 })}<span class="t">${escapeHtml(i.assignee.split("@")[0])}</span></span>` : `<span class="sx-who">${avatar(null, { size: 22 })}<span class="t">${escapeHtml(i.queue || "")} queue</span></span>`;
    return `<article class="sx-card${S.pending.has(i.id) ? " pending" : ""}" data-card="${i.id}" data-sev="${escapeHtml(i.severity)}" draggable="${i.status === "merged" ? "false" : "true"}" tabindex="0" role="listitem"
      aria-label="Incident ${i.id}, ${escapeHtml(i.severity)}, ${escapeHtml(i.title)}, ${escapeHtml(STATUS_LABEL[i.status] || i.status)}, ${i.assignee ? "assigned to " + escapeHtml(i.assignee) : "unassigned"}">
      <div class="sx-card-top"><span class="sx-row">${severityChip(i.severity)}<span class="sx-card-id">#${i.id}</span><span class="sx-tier">L${i.tier}</span></span>
        <span class="sx-row"><span class="sx-sla" ${tipAttr(ring.label)}>${ringSvg(ring)}</span><span class="sx-pop-host"><button type="button" class="sx-menu-btn" data-menu="${i.id}" aria-haspopup="menu" aria-expanded="false" aria-label="Actions for incident ${i.id}">&#8943;</button></span></span></div>
      <h4 class="sx-card-title"><a href="/soc?incident=${i.id}" data-open="${i.id}">${escapeHtml(i.title)}</a></h4>
      ${verdictLine(i)}
      <div class="sx-kc"><span class="sx-dots" role="img" aria-label="${kc.count} of 12 kill-chain stages reached${kc.dots.filter((d) => d.reached).length ? ": " + escapeHtml(kc.dots.filter((d) => d.reached).map((d) => d.tactic).join(", ")) : ""}" ${tipAttr(kc.count ? kc.dots.filter((d) => d.reached).map((d) => d.tactic).join(" > ") : "No mapped ATT&CK stage yet")}>${kc.dots.map((d) => `<i class="sx-dot${d.reached ? " on" : ""}"></i>`).join("")}</span>${kc.count ? `${kc.count} stage${kc.count > 1 ? "s" : ""}` : "no stage yet"}</div>
      <div class="sx-chips">${entityChips(i)}</div>
      <div class="sx-card-foot">${owner}<button type="button" class="sx-why" ${tipAttr("Why routed here: " + whyText(i))} aria-label="Why routed here: ${escapeHtml(whyText(i))}">${icon("faq", 14)}</button></div></article>`;
  }

  function paintBoard() {
    const list = shown();
    const host = $("#sx-main");
    if (!all().length && !S.auto.length) { host.innerHTML = `<div class="sx-panel">${emptyState({ title: "Nothing is waiting for you", body: "Incidents appear here on their own. Connect an alert source (your SIEM, XDR or ITSM) and Quanta investigates each alert, groups related ones, and routes the incident to the right analyst with the reason written down. Analysts do not create cases.", actionLabel: "Connect an alert source", actionHref: "/connections", iconName: "signal" })}
      <p class="ui-muted" style="text-align:center;font-size:.84rem">Alerts arrive at <code>POST /api/ingest/alerts</code>, ITSM tickets at <code>POST /api/ingest/itsm-ticket</code>, both with a Quanta API key.</p></div>`; return; }
    if (S.filters.view === "list") { paintList(host, list); return; }
    const cols = boardColumns(list);
    host.innerHTML = `<div class="sx-board" role="list" aria-label="Incident board. Drag a card to another column, or use the actions menu on a card.">${cols.map((c) => `<section class="sx-col" data-col="${c.status}" aria-label="${STATUS_LABEL[c.status]}, ${c.items.length}">
      <div class="sx-col-head"><h3>${STATUS_LABEL[c.status]}</h3><span class="sx-col-n">${c.items.length}</span></div>
      <div class="sx-col-body">${c.items.map(cardHtml).join("") || `<div class="sx-col-empty">${c.status === "new" ? "No new incidents" : "Nothing here"}</div>`}</div></section>`).join("")}</div>`;
  }

  function paintList(host, list) {
    host.innerHTML = `<div class="sx-list-wrap"><table class="sx-list" aria-label="Incidents"><thead><tr><th>Severity</th><th>Incident</th><th>Status</th><th>Assigned to</th><th>Verdict</th><th>Kill chain</th><th>Service level</th><th>Why routed here</th></tr></thead><tbody>
      ${list.map((i) => { const ring = slaRing(i.sla); const kc = killChainDots(i.kill_chain);
        return `<tr class="sx-tr" data-card="${i.id}" tabindex="0" aria-label="Incident ${i.id}, ${escapeHtml(i.title)}"><td>${severityChip(i.severity)}</td><td><a href="/soc?incident=${i.id}" data-open="${i.id}">#${i.id} ${escapeHtml(i.title)}</a><div class="sx-chips">${entityChips(i)}</div></td>
          <td>${escapeHtml(STATUS_LABEL[i.status] || i.status)}</td><td><span class="sx-who">${avatar(i.assignee, { size: 22 })}<span class="t">${escapeHtml(i.assignee ? i.assignee.split("@")[0] : (i.queue || "") + " queue")}</span></span></td>
          <td>${verdictLine(i)}</td><td>${kc.count}/12</td><td><span class="sx-sla">${ringSvg(ring)}${escapeHtml(ring.label)}</span></td><td class="ui-muted">${escapeHtml(whyText(i))}</td></tr>`; }).join("") || '<tr><td colspan="8" class="ui-empty">No incident matches these filters.</td></tr>'}</tbody></table></div>`;
  }

  function paintLanes() {
    const auto = S.auto.slice(0, 12);
    const rosterRows = S.roster.map((a) => {
      const cap = a.capacity || 10; const load = Math.min(1, (a.open_incidents || 0) / cap);
      return `<div class="sx-ros-row" data-ros="${escapeHtml(a.email)}">${avatar(a.email, { size: 30 })}<span class="sx-ros-name" title="${escapeHtml(a.email)}">${escapeHtml(a.email)}</span>
        <label class="sx-switch" ${tipAttr(a.available ? "Available for new work" : "Unavailable: new incidents skip this analyst")}><input type="checkbox" data-avail="${escapeHtml(a.email)}" ${a.available ? "checked" : ""} aria-label="${escapeHtml(a.email)} available"><span></span></label>
        <span class="sx-ros-meta"><span class="sx-tier">L${a.tier}</span>${(a.skills || []).map((s) => chip(s, { tone: "neutral" }).replace("ui-chip ", "ui-chip sx-chip-sm ")).join("")}
          <span class="sx-load${load >= 1 ? " full" : load > 0.6 ? " mid" : ""}" role="img" aria-label="${a.open_incidents || 0} of ${cap} open incidents" ${tipAttr(`${a.open_incidents || 0} open of ${cap} capacity`)}><i style="width:${Math.round(load * 100)}%"></i></span>
          <span class="ui-muted" style="font-size:.74rem">${a.open_incidents || 0}/${cap}${a.on_shift === false ? " · off shift" : ""}${a.on_call ? " · on call" : ""}</span>
          <button type="button" class="sx-link-btn" data-edit-analyst="${escapeHtml(a.email)}">Edit</button></span></div>`;
    }).join("");
    $("#sx-lanes").innerHTML = `<div class="sx-split">
      <section class="sx-panel" aria-labelledby="ac-h"><h3 id="ac-h">${icon("approved", 16)} Auto-closed <span class="ui-chip">${S.auto.length}</span></h3>
        <p class="ui-muted">Closed automatically as likely false positives under the decision policy, never for a Critical alert or a host with a known-exploited vulnerability. Undo returns one to the queue and records that the system was overridden.</p>
        ${auto.map((i) => `<div class="sx-ac-row"><span class="t"><a href="/soc?incident=${i.id}" data-link>#${i.id}</a> ${escapeHtml(i.title)}</span><span class="ui-muted">${escapeHtml(relTime(i.updated_at))}</span><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-undo="${i.id}">Undo</button></div>`).join("") || '<p class="ui-muted">Nothing has been auto-closed. With the shipped decision policy the confidence gate is deliberately strict, so every alert is reviewed by a person until an administrator relaxes it.</p>'}</section>
      <section class="sx-panel" aria-labelledby="ro-h"><h3 id="ro-h">${icon("users", 16)} Analyst roster</h3>
        <p class="ui-muted">Routing uses availability, shift, skills, tier and load. Drop an incident card on a name to reassign it.</p>
        <div class="sx-ros">${rosterRows || '<p class="ui-muted">No analysts yet. Add one under More, or by email through the API.</p>'}</div></section></div>`;
  }

  function paintAll() {
    if (!alive) return;
    const keep = S.focusId;
    paintKpis(); paintToolbar(); paintBoard(); paintLanes();
    S.flash.forEach((id) => { const el = container.querySelector(`[data-card="${id}"]`); if (el) el.classList.add("flash"); });
    setTimeout(() => { S.flash.clear(); container.querySelectorAll(".flash").forEach((n) => n.classList.remove("flash")); }, 2400);
    if (keep) { const el = container.querySelector(`[data-card="${keep}"]`); if (el && container.contains(document.activeElement) === false) el.focus({ preventScroll: true }); }
    const age = $("#sx-age");
    if (age) { age.innerHTML = dataAgeBadge(S.loadedAt); mountDataAge(age); }
  }

  // ------------------------------------------------------------------ acting on incidents
  const find = (id) => [...S.open, ...S.resolved, ...S.auto].find((i) => i.id === id);
  const replaceLocal = (updated) => {
    S.open = S.open.filter((i) => i.id !== updated.id); S.resolved = S.resolved.filter((i) => i.id !== updated.id); S.auto = S.auto.filter((i) => i.id !== updated.id);
    if (["new", "triaging", "investigating", "contained"].includes(updated.status)) S.open = upsertIncident(S.open, updated);
    else if (updated.status === "resolved") S.resolved = upsertIncident(S.resolved, updated);
    else if (updated.status === "auto_closed") S.auto = upsertIncident(S.auto, updated);
  };
  async function ask(kind, inc) {
    if (kind === "verdict") {
      return modal({ title: `Resolve incident #${inc.id}`, confirmLabel: "Resolve", description: "A verdict is required. It judges the first-look recommendation for each alert and feeds calibration.",
        body: `<label>Verdict<select id="m-verdict">${VERDICTS.map((v) => `<option value="${v}">${escapeHtml(verdictText(v))}</option>`).join("")}</select></label>
          <label>Summary (what you found, what you did)<textarea id="m-summary" minlength="20" placeholder="At least 20 characters"></textarea></label>`,
        validate: (d) => (d.querySelector("#m-summary").value.trim().length < 20 ? "Write a summary of at least 20 characters so the next person does not start cold." : ""),
        collect: (d) => ({ verdict: d.querySelector("#m-verdict").value, summary: d.querySelector("#m-summary").value.trim() }) });
    }
    if (kind === "reason") {
      return modal({ title: `Reopen incident #${inc.id}`, confirmLabel: "Reopen", body: `<label>Why reopen?<textarea id="m-reason" placeholder="A reason is required"></textarea></label>`,
        validate: (d) => (d.querySelector("#m-reason").value.trim().length < 5 ? "Say why it is being reopened." : ""), collect: (d) => ({ reason: d.querySelector("#m-reason").value.trim() }) });
    }
    return null;
  }
  async function escalate(inc) {
    const out = await modal({ title: `Escalate incident #${inc.id}`, confirmLabel: "Escalate", description: "It leaves your queue and is routed up. The hand-off summary is the first thing the next analyst reads.",
      body: `<label>Hand-off summary<textarea id="m-summary" placeholder="What you found, what you did, what is left (20+ characters)"></textarea></label>`,
      validate: (d) => (d.querySelector("#m-summary").value.trim().length < 20 ? "A hand-off summary of at least 20 characters is required." : ""), collect: (d) => ({ summary: d.querySelector("#m-summary").value.trim() }) });
    if (out) await runSteps(inc.id, [{ action: "escalate", body: out }], "Escalated.");
  }
  async function reassign(inc) {
    const others = S.roster.filter((a) => a.email !== inc.assignee);
    const out = await modal({ title: `Reassign incident #${inc.id}`, confirmLabel: "Reassign", description: "The person must be an active analyst of a high enough tier. An unavailable analyst is allowed, with a warning on the record.",
      body: `<label>Assign to<select id="m-who">${others.map((a) => `<option value="${escapeHtml(a.email)}">${escapeHtml(a.email)} (L${a.tier}, ${a.open_incidents || 0} open${a.available ? "" : ", unavailable"})</option>`).join("")}</select></label>
        <label>Reason<input type="text" id="m-reason" placeholder="e.g. on leave, has the specialty"></label>`,
      validate: (d) => (d.querySelector("#m-who").value ? "" : "Choose an analyst."), collect: (d) => ({ assignee: d.querySelector("#m-who").value, reason: d.querySelector("#m-reason").value.trim() || null }) });
    if (out) await runSteps(inc.id, [{ action: "reassign", body: out }], `Reassigned to ${out.assignee}.`);
  }

  // Optimistic: show the result at once, call the API, put the card back and say why when it fails.
  async function runSteps(id, steps, okMessage) {
    const inc = find(id);
    const snapshot = inc ? JSON.parse(JSON.stringify(inc)) : null;
    S.pending.add(id);
    if (inc) {
      const target = steps.some((s) => s.action === "resolve") ? "resolved" : steps.some((s) => s.action === "advance") ? steps.find((s) => s.action === "advance").body.status : steps.some((s) => s.action === "accept") ? "triaging" : null;
      const guess = { ...inc, ...(target ? { status: target } : {}), ...(steps.some((s) => s.action === "accept") && !inc.assignee ? { assignee: email } : {}), ...(steps.some((s) => s.action === "reassign") ? { assignee: steps.find((s) => s.action === "reassign").body.assignee } : {}) };
      replaceLocal(guess);
    }
    S.focusId = id; paintAll();
    try {
      for (const s of steps) await api.socIncidentAct(id, s.action, s.body || {});
      const fresh = await api.socIncident(id);
      replaceLocal(fresh);
      toast(okMessage || "Done.", { tone: "good", ms: 3200 });
    } catch (e) {
      if (snapshot) replaceLocal(snapshot);
      toast(`Not done: ${e.message}`, { tone: "bad", ms: 8000 });
    } finally {
      S.pending.delete(id); S.flash.add(id); paintAll();
    }
  }
  async function moveIncident(id, toStatus) {
    const inc = find(id);
    if (!inc) return;
    const plan = planMove(inc, toStatus);
    if (!plan.ok) { if (!plan.same) toast(plan.reason, { tone: "warn", ms: 6000 }); return; }
    const steps = [];
    for (const st of plan.steps) {
      let body = { ...st.body };
      if (st.needs) { const got = await ask(st.needs, inc); if (!got) return; body = { ...body, ...got }; }
      steps.push({ action: st.action, body });
    }
    const verb = steps.some((s) => s.action === "resolve") ? "Resolved." : steps.some((s) => s.action === "undo-auto-close") ? "Returned to the queue." : `Moved to ${STATUS_LABEL[toStatus]}.`;
    await runSteps(id, steps, verb);
  }
  async function accept(id) { const inc = find(id); if (inc && inc.status === "new") await runSteps(id, [{ action: "accept", body: {} }], "Accepted. The acknowledge clock is stopped."); else toast("Only a new incident can be accepted.", { tone: "warn", ms: 3500 }); }
  async function resolveDialog(id) { const inc = find(id); if (inc) await moveIncident(id, "resolved"); }

  function openMenu(btn, id) {
    const inc = find(id); if (!inc) return;
    const move = STATUS_ORDER.filter((s) => s !== inc.status).map((s) => { const p = planMove(inc, s); return { label: `Move to ${STATUS_LABEL[s]}`, hint: p.ok ? (p.note || "") : p.reason, disabled: !p.ok, run: () => moveIncident(id, s) }; });
    popMenu(btn, [{ label: "Open report", run: () => go(`/soc?incident=${id}`) }, { label: "Accept", disabled: inc.status !== "new", run: () => accept(id) }, { sep: true }, ...move, { sep: true },
      { label: "Reassign…", run: () => reassign(inc) }, { label: "Escalate…", disabled: inc.tier >= 3 || !["new", "triaging", "investigating", "contained"].includes(inc.status), run: () => escalate(inc) }]);
  }
  function go(path) { window.history.pushState({}, "", path); window.dispatchEvent(new PopStateEvent("popstate")); }

  // ------------------------------------------------------------------ events
  const setFilters = (patch) => {
    S.filters = { ...S.filters, ...patch };
    window.history.replaceState({}, "", window.location.pathname + filtersToSearch(S.filters));
    paintKpis(); paintToolbar(); paintBoard();
  };
  const typeSearch = debounce((v) => setFilters({ q: v }), 220);

  container.addEventListener("click", (e) => {
    const open = e.target.closest("[data-open]");
    if (open) { e.preventDefault(); go(`/soc?incident=${open.dataset.open}`); return; }
    const menu = e.target.closest("[data-menu]");
    if (menu) { e.preventDefault(); e.stopPropagation(); openMenu(menu, Number(menu.dataset.menu)); return; }
    const undo = e.target.closest("[data-undo]");
    if (undo) { moveIncident(Number(undo.dataset.undo), "triaging"); return; }
    const kpi = e.target.closest("[data-kpi]");
    if (kpi) { kpiClick(kpi.dataset.kpi); return; }
    const edit = e.target.closest("[data-edit-analyst]");
    if (edit) { editAnalyst(edit.dataset.editAnalyst); return; }
    if (e.target.closest("#f-clear")) { setFilters({ scope: "all", tier: "", severity: "", status: "", sla: "", q: "" }); return; }
    if (e.target.closest("#sx-refresh")) { load({ quiet: true }).then(paintAll).catch((er) => toast(er.message, { tone: "bad" })); return; }
    const row = e.target.closest("tr[data-card]");
    if (row && !e.target.closest("a,button,input,select")) go(`/soc?incident=${row.dataset.card}`);
  });
  container.addEventListener("keydown", (e) => {
    const kpi = e.target.closest && e.target.closest("[data-kpi]");
    if (kpi && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); kpiClick(kpi.dataset.kpi); }
  });
  const kpiClick = (key) => {
    const cur = S.filters;
    if (key === "open") setFilters({ scope: "all", sla: "", status: "" });
    else if (key === "mine") setFilters({ scope: cur.scope === "mine" ? "all" : "mine", sla: "" });
    else if (key === "unassigned") setFilters({ scope: cur.scope === "unassigned" ? "all" : "unassigned", sla: "" });
    else if (key === "risk") setFilters({ sla: cur.sla === "at_risk" ? "" : "at_risk" });
    else if (key === "breached") setFilters({ sla: cur.sla === "breached" ? "" : "breached" });
  };
  container.addEventListener("change", async (e) => {
    const t = e.target;
    if (t.id === "f-tier") setFilters({ tier: t.value }); else if (t.id === "f-sev") setFilters({ severity: t.value });
    else if (t.id === "f-status") setFilters({ status: t.value }); else if (t.id === "f-sla") setFilters({ sla: t.value });
    else if (t.dataset && t.dataset.avail) {
      const a = S.roster.find((x) => x.email === t.dataset.avail);
      if (a) a.available = t.checked;
      try { const r = await api.socAnalystUpdate({ email: t.dataset.avail, available: t.checked }); toast(`${t.dataset.avail} is now ${t.checked ? "available" : "unavailable"}.${(r.rerouted_incident_ids || []).length ? ` ${r.rerouted_incident_ids.length} incident(s) re-routed.` : ""}`, { tone: "good", ms: 4000 }); await load({ quiet: true }); paintAll(); }
      catch (er) { t.checked = !t.checked; if (a) a.available = t.checked; toast(er.message, { tone: "bad" }); }
    }
  });
  container.addEventListener("input", (e) => { if (e.target.id === "f-q") typeSearch(e.target.value); });
  const toolbarHost = $("#sx-toolbar");
  onSeg(toolbarHost, (id, group) => {
    const label = group.getAttribute("aria-label");
    if (label === "View") setFilters({ view: id }); else setFilters({ scope: id });
  });

  // drag and drop (a pointer feature; the card menu and the keys are the keyboard route to the same actions)
  container.addEventListener("dragstart", (e) => {
    const card = e.target.closest && e.target.closest("[data-card]");
    if (!card) return;
    S.drag = Number(card.dataset.card);
    card.classList.add("dragging");
    e.dataTransfer.effectAllowed = "move";
    try { e.dataTransfer.setData("text/plain", `incident:${S.drag}`); } catch { /* some browsers refuse */ }
  });
  container.addEventListener("dragend", () => { S.drag = null; container.querySelectorAll(".dragging,.drop-ok,.drop-no").forEach((n) => n.classList.remove("dragging", "drop-ok", "drop-no")); });
  container.addEventListener("dragover", (e) => {
    if (S.drag === null) return;
    const col = e.target.closest("[data-col]"); const ros = e.target.closest("[data-ros]");
    container.querySelectorAll(".drop-ok,.drop-no").forEach((n) => n.classList.remove("drop-ok", "drop-no"));
    if (col) { const p = planMove(find(S.drag) || {}, col.dataset.col); if (p.ok || p.same) { e.preventDefault(); col.classList.add(p.same ? "" : "drop-ok"); } else col.classList.add("drop-no"); }
    else if (ros) { e.preventDefault(); ros.classList.add("drop-ok"); }
  });
  container.addEventListener("drop", (e) => {
    if (S.drag === null) return;
    e.preventDefault();
    const id = S.drag; S.drag = null;
    const col = e.target.closest("[data-col]"); const ros = e.target.closest("[data-ros]");
    container.querySelectorAll(".drop-ok,.drop-no,.dragging").forEach((n) => n.classList.remove("drop-ok", "drop-no", "dragging"));
    if (col) moveIncident(id, col.dataset.col);
    else if (ros) { const inc = find(id); if (inc && inc.assignee !== ros.dataset.ros) runSteps(id, [{ action: "reassign", body: { assignee: ros.dataset.ros, reason: "Dragged onto the analyst in the roster" } }], `Reassigned to ${ros.dataset.ros}.`); }
  });

  async function editAnalyst(addr) {
    const a = S.roster.find((x) => x.email === addr); if (!a) return;
    const out = await modal({ title: `Routing profile: ${a.email}`, confirmLabel: "Save", description: "Used by routing. An incident this change makes unsuitable is re-routed at once.",
      body: `<label>Tier<select id="r-tier">${[1, 2, 3].map((t) => `<option value="${t}" ${t === a.tier ? "selected" : ""}>L${t}</option>`).join("")}</select></label>
        <label>Capacity (open incidents)<input type="number" id="r-cap" min="0" max="100" value="${a.capacity || ""}" placeholder="blank = default"></label>
        <div class="sx-checks" role="group" aria-label="Specialties">${SKILLS.map((s) => `<label><input type="checkbox" value="${s}" ${(a.skills || []).includes(s) ? "checked" : ""}> ${s}</label>`).join("")}</div>
        <label>Shift start (UTC, HH:MM)<input type="text" id="r-ss" value="${escapeHtml(a.shift_start || "")}" placeholder="blank = always"></label>
        <label>Shift end (UTC, HH:MM)<input type="text" id="r-se" value="${escapeHtml(a.shift_end || "")}"></label>
        <label class="sx-row" style="flex-direction:row"><input type="checkbox" id="r-oc" ${a.on_call ? "checked" : ""}> On call for P1 and P2</label>`,
      collect: (d) => ({ email: a.email, tier: Number(d.querySelector("#r-tier").value), capacity: d.querySelector("#r-cap").value === "" ? 0 : Number(d.querySelector("#r-cap").value),
        skills: [...d.querySelectorAll(".sx-checks input:checked")].map((x) => x.value), shift_start: d.querySelector("#r-ss").value.trim() || null, shift_end: d.querySelector("#r-se").value.trim() || null, on_call: d.querySelector("#r-oc").checked }) });
    if (!out) return;
    try { const r = await api.socAnalystUpdate(out); toast(`Saved.${(r.rerouted_incident_ids || []).length ? ` ${r.rerouted_incident_ids.length} incident(s) re-routed.` : ""}`, { tone: "good" }); await load({ quiet: true }); paintAll(); }
    catch (er) { toast(er.message, { tone: "bad" }); }
  }

  // keyboard: j/k move between cards, Enter opens, a accepts, e escalates, r resolves
  const onKey = (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey || modalOpen()) return;
    const t = e.target;
    if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
    const cards = [...container.querySelectorAll("[data-card]")];
    const cur = t && t.closest ? t.closest("[data-card]") : null;
    const idx = cur ? cards.indexOf(cur) : -1;
    if (e.key === "j" || e.key === "k") {
      if (!cards.length) return;
      e.preventDefault();
      const next = cards[Math.max(0, Math.min(cards.length - 1, idx + (e.key === "j" ? 1 : -1)))];
      next.focus(); next.scrollIntoView({ block: "nearest", inline: "nearest" }); S.focusId = Number(next.dataset.card);
      return;
    }
    if (!cur) return;
    const id = Number(cur.dataset.card);
    if (e.key === "Enter" && !e.target.closest("a,button")) { e.preventDefault(); go(`/soc?incident=${id}`); }
    else if (e.key === "a") { e.preventDefault(); accept(id); }
    else if (e.key === "e") { e.preventDefault(); const inc = find(id); if (inc) escalate(inc); }
    else if (e.key === "r") { e.preventDefault(); resolveDialog(id); }
    else if (e.key === "n") { e.preventDefault(); const inc = find(id); const nx = inc && nextStatus(inc.status); if (nx) moveIncident(id, nx); }
  };
  document.addEventListener("keydown", onKey);
  onCleanup(() => document.removeEventListener("keydown", onKey));
  registerShortcutHelp(["j", "k"], "SOC board: move between incident cards");
  registerShortcutHelp(["Enter"], "SOC board: open the focused incident");
  registerShortcutHelp(["a", "e", "r", "n"], "SOC board: accept, escalate, resolve or advance the focused incident");

  // ------------------------------------------------------------------ the older tools, folded under More
  $("#sx-more").innerHTML = `<details class="sx-panel" id="sx-more-d"><summary class="sx-link-btn" style="font-weight:600">More: metrics, log analysis, decisions, add an analyst, create an incident by hand</summary><div id="sx-more-body" style="margin-top:12px"></div></details>`;
  let moreLoaded = false;
  $("#sx-more-d").addEventListener("toggle", async (e) => {
    if (!e.target.open || moreLoaded) return;
    moreLoaded = true;
    const body = $("#sx-more-body");
    body.innerHTML = `<h4>Add or move an analyst</h4><form id="af" class="sx-toolbar"><input class="sx-field" name="email" type="email" required placeholder="analyst email" aria-label="Analyst email"><select class="sx-field" name="tier" aria-label="Tier"><option value="1">L1</option><option value="2">L2</option><option value="3">L3</option></select><button class="ui-btn sx-btn-sm" type="submit">Add or move</button></form>
      <h4>Create an incident by hand (the exception)</h4><p class="ui-muted">Only when no alert exists to start from. A reason is required and recorded; it is routed by the same rules.</p>
      <form id="nc" class="sx-toolbar"><input class="sx-field" name="title" required maxlength="300" placeholder="Title" aria-label="Title"><select class="sx-field" name="severity" aria-label="Severity">${SEVERITIES.map((s) => `<option ${s === "Medium" ? "selected" : ""}>${s}</option>`).join("")}</select><input class="sx-field" name="assets" placeholder="Hosts, comma separated" aria-label="Hosts"><input class="sx-field" name="reason" required minlength="10" placeholder="Reason (10+ characters)" aria-label="Reason"><button class="ui-btn ui-btn-ghost sx-btn-sm" type="submit">Create</button></form>
      <div id="sx-legacy"></div>`;
    body.querySelector("#af").addEventListener("submit", async (ev) => { ev.preventDefault(); const f = ev.target; try { await api.socAnalystAdd({ email: f.email.value, tier: Number(f.tier.value) }); toast("Saved.", { tone: "good" }); f.reset(); await load({ quiet: true }); paintAll(); } catch (er) { toast(er.message, { tone: "bad" }); } });
    body.querySelector("#nc").addEventListener("submit", async (ev) => { ev.preventDefault(); const f = ev.target; try { const i = await api.socIncidentManual({ title: f.title.value, severity: f.severity.value, assets: f.assets.value.split(",").map((x) => x.trim()).filter(Boolean), reason: f.reason.value }); toast("Incident created.", { tone: "good" }); go(`/soc?incident=${i.id}`); } catch (er) { toast(er.message, { tone: "bad" }); } });
    try { const m = await import("./socMore.js"); await m.render(body.querySelector("#sx-legacy"), { tab: "metrics", caseId: qs.get("case") }); } catch (er) { body.querySelector("#sx-legacy").innerHTML = `<p class="ui-muted">${escapeHtml(er.message)}</p>`; }
  });
  if (qs.get("more") || qs.get("case") || qs.get("tab")) { const d = $("#sx-more-d"); d.open = true; d.dispatchEvent(new Event("toggle")); }

  // ------------------------------------------------------------------ go
  try { await load(); } catch (e) { $("#sx-skel").hidden = true; $("#sx-main").innerHTML = `<div class="sx-panel">${emptyState({ title: "The incident queue could not be loaded", body: e.message || "Try again in a moment.", iconName: "risk" })}</div>`; return; }
  paintAll();
  const feed = connectIncidentFeed({ EventSource: typeof window.EventSource === "function" ? window.EventSource : null, setTimeout: window.setTimeout.bind(window), clearTimeout: window.clearTimeout.bind(window) },
    { onEvent: () => refresh(), onMode: setLive, pollFn: () => load({ quiet: true }).then(() => { if (alive) paintAll(); }), pollEvery: REFRESH_MS });
  onCleanup(() => feed.stop());
}
