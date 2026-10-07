// Activity Log: the real who / what / when audit trail (remediation/audit/activity_log.py). Every asset edit, exception change, approval decision, login attempt,
// bulk policy apply and remediation trigger writes here; it is append-only. Rebuilt on the UI kit: a live tail that merges new entries in as they happen (with a pause
// button), filters by action group, actor and text, and an Integrity tab for administrators. Unusual-activity detection is unchanged and still only appears once
// there is enough genuine history to fit on honestly (remediation/enrichment/activity_insights.py).
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { renderIntegrity } from "../integrityPanel.js";
import { kpiTile, chip, toast, emptyState, onCleanup, dataAgeBadge, mountDataAge, touchDataAge, mountCounters, debounce, tipAttr } from "../ui.js";
import { liveBadge, avatar } from "../sxKit.js";
import { selectableTable, autoRefresh, pageActions, skeletonPage, tabBar, wireTabBar, replaceSearch } from "../mxKit.js";
import { mergeTail, activityFilter, activityGroups } from "../moduleLogic.js";
import { relTime } from "../sxKit.js";

export const title = "Activity Log";

const ACTION_LABELS = {
  "asset.set_owner": "Asset owner changed", "asset.set_facing": "Asset facing changed", "asset.set_environment": "Asset environment changed", "asset.set_remediation_schedule": "Asset remediation schedule changed",
  "exception.create": "Exception created", "exception.revoke": "Exception revoked", "approval.request": "Remediation approval requested", "approval.approve": "Remediation approval approved",
  "approval.reject": "Remediation approval rejected", "login.success": "Login succeeded", "login.failure": "Login failed",
};
const actionLabel = (a) => ACTION_LABELS[a] || a;
const detailsText = (d) => (!d || !Object.keys(d).length ? "" : Object.entries(d).map(([k, v]) => `${k}: ${v}`).join(", "));
const TONE = (a) => (/failure|reject|revoke|delete|remove/.test(a) ? "warn" : /success|approve|create|save/.test(a) ? "good" : "neutral");
const MAX_TAIL = 1000;

export async function render(container) {
  let admin = false;
  try { admin = ((await api.authMe()).user || {}).role === "admin"; } catch { admin = false; }
  const tab = new URLSearchParams(window.location.search).get("tab") === "integrity" && admin ? "integrity" : "activity";
  container.innerHTML = `<div class="sx-page mx-page"><div class="sx-head"><div><h2>Activity log</h2><p>The real who, what and when audit trail. Every asset edit, exception change, approval decision, login attempt, bulk policy apply and remediation trigger elsewhere in the app writes here. Append-only: never edited or backdated.</p></div><div class="sx-row"><span id="al-live"></span><span id="al-age"></span></div></div>
    ${admin ? tabBar("Activity log sections", [{ id: "activity", label: "Activity" }, { id: "integrity", label: "Integrity" }], tab) : ""}<div id="al-body">${skeletonPage(4)}</div></div>`;
  const $ = (s) => container.querySelector(s);
  let stopTail = null;
  const setLive = (m) => { const el = $("#al-live"); if (el) el.innerHTML = liveBadge(m); };
  setLive("idle");
  const show = async (t) => {
    if (stopTail) { stopTail(); stopTail = null; }
    const fresh = $("#al-body").cloneNode(false); $("#al-body").replaceWith(fresh); fresh.id = "al-body";
    fresh.innerHTML = skeletonPage(4);
    replaceSearch(t === "integrity" ? "?tab=integrity" : "");
    if (t === "integrity") { const age = $("#al-age"); if (age) age.innerHTML = ""; fresh.innerHTML = ""; return renderIntegrity(fresh); }
    return renderActivity(fresh, { setLive, setStop: (fn) => { stopTail = fn; } });
  };
  if (admin) wireTabBar($("#al-body").previousElementSibling, (id) => { container.querySelectorAll(".mx-tabs [data-tab]").forEach((b) => { b.setAttribute("aria-selected", String(b.dataset.tab === id)); b.tabIndex = b.dataset.tab === id ? 0 : -1; }); show(id); });
  onCleanup(() => { if (stopTail) stopTail(); });
  return show(tab);
}

async function renderActivity(host, { setLive, setStop }) {
  let alive = true;
  onCleanup(() => { alive = false; });
  const root = host.closest(".mx-page") || host;
  const S = { entries: [], fresh: new Set(), q: "", action: "", actor: "", paused: false, loadedAt: 0, table: null, insights: null };
  let logData; let insights;
  try { [logData, insights] = await Promise.all([api.activityLog({ limit: MAX_TAIL }), api.activityLogInsights()]); }
  catch (e) { host.innerHTML = emptyState({ title: "The activity log could not be loaded", body: e.message || "Try again in a moment.", iconName: "risk" }); return; }
  if (!alive) return;
  S.entries = logData.entries.slice(0, MAX_TAIL); S.insights = insights; S.loadedAt = Date.now();
  const age = root.querySelector("#al-age"); if (age) { age.innerHTML = dataAgeBadge(S.loadedAt, { fresh: 60000, stale: 600000 }); mountDataAge(age); }
  const view = () => activityFilter(S.entries, { q: S.q, action: S.action, actor: S.actor });

  function kpis() {
    const s = S.insights.summary; const failed = S.entries.filter((e) => e.action === "login.failure").length;
    const recent = S.entries[0] ? relTime(S.entries[0].timestamp) : "n/a";
    return [kpiTile({ label: "Entries recorded", value: s.total, hint: "Every audit-logged action since the log began." }), kpiTile({ label: "Distinct actors", value: Object.keys(s.by_actor).length }), kpiTile({ label: "Action types", value: Object.keys(s.by_action).length }),
      kpiTile({ label: "Failed logins in view", value: failed, tone: failed ? "warn" : "good", hint: `Among the latest ${S.entries.length} entries.` }), kpiTile({ label: "Most recent", value: recent, hint: s.most_recent_timestamp || "" })].map((t) => `<div class="sx-kpi-cell">${t}</div>`).join("");
  }
  const unusual = () => {
    const un = S.insights.unusual_actors.filter((r) => r.is_anomaly);
    if (!S.insights.unusual_actors.length) return `<div class="mx-callout">Not enough genuine activity history yet to fit anomaly detection honestly (see <code>remediation/enrichment/activity_insights.py</code>). As activity accumulates (asset edits, approvals, logins) this section activates on its own; nothing here is ever backfilled.</div>`;
    return un.length ? `<div class="mx-grid-cards">${un.map((r) => `<article class="mx-card"><div class="mx-card-head"><h4>${escapeHtml(r.actor)}</h4>${chip(`score ${r.anomaly_score}`, { tone: "warn" })}</div><div class="mx-sub">${r.action_count} actions &middot; ${(r.off_hours_fraction * 100).toFixed(0)}% off-hours &middot; ${(r.self_approval_fraction * 100).toFixed(0)}% self-approval</div>${r.reasons.length ? `<ul class="mx-list">${r.reasons.map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ul>` : ""}</article>`).join("")}</div>` : '<p class="ui-muted">Nothing unusual detected.</p>';
  };
  const actors = () => [...new Set(S.entries.map((e) => e.actor))].sort();

  host.innerHTML = `<div id="al-kpis" class="sx-kpis mx-kpis">${kpis()}</div>
    <div class="sx-toolbar" role="search" aria-label="Filter the activity log"><input type="search" class="sx-field" id="al-q" placeholder="Search actor, action, target, details" aria-label="Search the activity log">
      <select class="sx-field" id="al-actor" aria-label="Actor"><option value="">Every actor</option>${actors().map((a) => `<option>${escapeHtml(a)}</option>`).join("")}</select>
      <button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="al-pause" aria-pressed="false">Pause live tail</button><span class="ui-muted mx-count" id="al-count" role="status" aria-live="polite"></span></div>
    <div class="mx-chips" id="al-groups" role="group" aria-label="Filter by kind of action"></div><div id="al-table"></div>
    <h3 class="mx-h3">Unusual activity</h3>${unusual()}`;
  mountCounters(host.querySelector("#al-kpis"));
  const q = (s) => host.querySelector(s);
  function paintGroups() {
    const g = activityGroups(S.entries);
    q("#al-groups").innerHTML = `<button type="button" class="mx-fchip${S.action ? "" : " on"}" data-group="" aria-pressed="${!S.action}">All <b>${S.entries.length}</b></button>${g.map((x) => `<button type="button" class="mx-fchip${S.action === x.group ? " on" : ""}" data-group="${escapeHtml(x.group)}" aria-pressed="${S.action === x.group}">${escapeHtml(x.group)} <b>${x.count}</b></button>`).join("")}`;
  }
  const count = () => { const v = view(); q("#al-count").textContent = `${v.length.toLocaleString()} of ${S.entries.length.toLocaleString()} entr${S.entries.length === 1 ? "y" : "ies"}${S.paused ? " (paused)" : ""}`; return v; };
  S.table = selectableTable(q("#al-table"), { rows: view(), rowKey: (e) => e.id, caption: "Activity log", csvName: "quanta-activity-log", storageKey: "activity-v2", rowHeight: 44, maxHeight: 560, virtualAt: 120, rowClass: (e) => (S.fresh.has(e.id) ? "mx-flash" : ""),
    emptyHtml: emptyState({ title: S.entries.length ? "No entry matches" : "No activity recorded yet", body: S.entries.length ? "Clear the search or the filters." : "Actions appear here as they happen.", iconName: "document" }),
    columns: [
      { key: "t", label: "When", width: 170, csv: (e) => e.timestamp, render: (e) => `<time datetime="${escapeHtml(e.timestamp)}" title="${escapeHtml(e.timestamp)}">${escapeHtml(e.timestamp.replace("T", " ").slice(0, 19))}</time>` },
      { key: "a", label: "Actor", width: 190, csv: (e) => e.actor, render: (e) => `<span class="sx-who">${avatar(e.actor, { size: 20 })}<span class="t">${escapeHtml(e.actor)}</span></span>` },
      { key: "x", label: "Action", width: 250, csv: (e) => actionLabel(e.action), render: (e) => `${chip(actionLabel(e.action), { tone: TONE(e.action) })}` },
      { key: "g", label: "Target", width: 140, csv: (e) => e.target || "", render: (e) => (e.target ? escapeHtml(e.target) : '<span class="ui-muted">-</span>') },
      { key: "d", label: "Details", width: 380, csv: (e) => detailsText(e.details), render: (e) => `<span class="mx-clip" title="${escapeHtml(detailsText(e.details))}">${escapeHtml(detailsText(e.details)) || '<span class="ui-muted">-</span>'}</span>` },
    ] });
  paintGroups(); count();

  const refresh = () => { const v = count(); S.table.setRows(v); paintGroups(); q("#al-kpis").innerHTML = kpis(); };
  const typeSearch = debounce((v) => { S.q = v; refresh(); }, 200);
  host.addEventListener("input", (e) => { if (e.target.id === "al-q") typeSearch(e.target.value); });
  host.addEventListener("change", (e) => { if (e.target.id === "al-actor") { S.actor = e.target.value; refresh(); } });
  host.addEventListener("click", (e) => {
    const g = e.target.closest("[data-group]"); if (g) { S.action = g.dataset.group; refresh(); return; }
    const p = e.target.closest("#al-pause"); if (p) { S.paused = !S.paused; p.setAttribute("aria-pressed", String(S.paused)); p.textContent = S.paused ? "Resume live tail" : "Pause live tail"; count(); if (!S.paused) pull(); }
  });
  // The tail: ask for the newest entries, merge by id, flash what is new. A burst of events costs one request (autoRefresh debounces).
  async function pull() {
    if (S.paused || !alive) return;
    try {
      const d = await api.activityLog({ limit: 60 });
      const m = mergeTail(S.entries, d.entries, MAX_TAIL);
      S.fresh = m.freshIds; S.entries = m.list; S.loadedAt = Date.now();
      if (m.freshIds.size) { refresh(); setTimeout(() => { S.fresh = new Set(); }, 2600); }
      const a = root.querySelector("#al-age .ui-age"); if (a) touchDataAge(a, S.loadedAt);
    } catch { /* the next tick retries */ }
  }
  setStop(autoRefresh(pull, { every: 15000, onMode: setLive }));
  pageActions([{ label: "Activity log: pause or resume the live tail", icon: "document", run: () => q("#al-pause") && q("#al-pause").click() }, { label: "Activity log: show failed logins", icon: "document", run: () => { S.q = "login.failure"; const i = q("#al-q"); if (i) i.value = S.q; refresh(); } }]);
  void toast; void tipAttr;
}
