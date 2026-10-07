// Threat Hunting: a proactive board of suggested hunts, an ATT&CK coverage matrix, active hunts with live trial-hit progress and the hunt report.
// The older tabs (alert triage, intel intake, detection engineering, proposals, hunts, overview) are kept in huntingMore.js and shown under their own tabs.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { icon } from "../icons.js";
import { chip, toast, emptyState, onCleanup, debounce, tipAttr, dataAgeBadge, mountDataAge } from "../ui.js";
import { live } from "../live.js";
import { getCurrentUser } from "../auth.js";
import {
  HUNT_TYPES, TYPE_LABEL, STATE_LABEL, CELL_STATES, parseHuntState, huntStateToSearch, filterSuggestions, facetCounts, scoreBars, scoreTone, readinessText, queryTabs, aggregateMatrix, heatLevel, cellTitle,
  huntProgress, verdictText,
} from "../huntLogic.js";
import { modal } from "../sxKit.js";
import { queryBlock, wireQueryBlocks, renderHuntReport } from "../huntReport.js";

export const title = "Threat Hunting";

const NATIVE = [["suggested", "Suggested hunts"], ["matrix", "ATT&CK coverage"], ["active", "Active hunts"], ["library", "Library & frameworks"]];
const LEGACY = [["alerts", "Alert triage"], ["intel", "Intel intake"], ["detections", "Detection engineering"], ["more", "More"]];
const STATUSES = [["suggested", "Suggested"], ["accepted", "Accepted"], ["running", "Running"], ["evidence-recorded", "Evidence recorded"], ["concluded", "Concluded"], ["dismissed", "Dismissed"]];
const go = (path) => { window.history.pushState({}, "", path); window.dispatchEvent(new PopStateEvent("popstate")); };

export async function render(container) {
  const st = parseHuntState(window.location.search);
  const me = await getCurrentUser().catch(() => null);
  if (st.hunt) return renderHuntReport(container, st.hunt, { back: "/hunting?tab=active" });
  let tab = st.tab || "suggested";
  if (!NATIVE.some(([k]) => k === tab) && !LEGACY.some(([k]) => k === tab) && !["overview", "proposals", "hunts"].includes(tab)) tab = "suggested";
  let alive = true;
  onCleanup(() => { alive = false; });
  const isAdmin = !!(me && me.role === "admin");

  container.innerHTML = `<div class="sx-page"><div class="sx-head"><div><h2>Threat hunting</h2><p>Hunts are hypotheses to test, proposed from what Quanta already holds: intel, exposure, alerts, identities and detection gaps. Quanta is not a SIEM and never runs a search by itself; you confirm each read-only search or run the query in your own tool and record the result.</p></div><span id="hx-age"></span></div>
    <div class="hx-tabs" role="tablist" aria-label="Threat hunting">${[...NATIVE, ...LEGACY].map(([k, l]) => `<button type="button" role="tab" data-t="${k}" aria-selected="${k === tab || (k === "more" && ["overview", "proposals", "hunts"].includes(tab))}">${l}</button>`).join("")}</div>
    <div id="hx-body" role="tabpanel"></div></div>`;
  const body = container.querySelector("#hx-body");
  const setUrl = (patch) => { Object.assign(st, patch); window.history.replaceState({}, "", window.location.pathname + huntStateToSearch(st)); };
  container.querySelector(".hx-tabs").addEventListener("click", (e) => { const b = e.target.closest("[data-t]"); if (b) { go(`/hunting?tab=${b.dataset.t}`); } });
  container.querySelector(".hx-tabs").addEventListener("keydown", (e) => {
    if (!["ArrowRight", "ArrowLeft"].includes(e.key)) return;
    const all = [...container.querySelectorAll(".hx-tabs [data-t]")]; const i = all.indexOf(document.activeElement);
    if (i < 0) return; e.preventDefault(); all[(i + (e.key === "ArrowRight" ? 1 : -1) + all.length) % all.length].focus();
  });
  const stamp = () => { const a = container.querySelector("#hx-age"); if (a) { a.innerHTML = dataAgeBadge(Date.now()); mountDataAge(a); } };

  if (tab === "suggested") await suggested(); else if (tab === "matrix") await matrix(); else if (tab === "active") await active();
  else if (tab === "library") { try { const m = await import("../huntLibrary.js"); await m.render(body, { isAdmin, st, go }); } catch (e) { body.innerHTML = `<div class="sx-callout warn">${escapeHtml(e.message)}</div>`; } }
  else { try { const m = await import("./huntingMore.js"); await m.render(body, { tab: tab === "more" ? "overview" : tab }); } catch (e) { body.innerHTML = `<div class="sx-callout warn">${escapeHtml(e.message)}</div>`; } }

  // ------------------------------------------------------------------ suggested hunts
  async function suggested() {
    body.innerHTML = '<div class="hx-grid"><div class="ui-skel ui-skel-card"></div><div class="ui-skel ui-skel-card"></div><div class="ui-skel ui-skel-card"></div></div>';
    let data; let status = container.dataset.status || "suggested";
    const fetchList = async () => { data = await api.huntingSuggestions(status === "suggested" ? "" : `?status=${status}`); };
    try { await fetchList(); } catch (e) { body.innerHTML = `<div class="sx-callout warn">${escapeHtml(e.message)}</div>`; return; }
    stamp();
    let open = null; // the card whose score popover is open

    const filters = () => ({ type: st.type, tactic: st.tactic, q: st.q, ready: st.ready, technique: st.technique });
    function card(s) {
      const rd = readinessText(s.data_readiness);
      const bars = scoreBars(s.priority);
      const q = (s.queries || [])[0];
      const lifecycle = s.status;
      return `<article class="hx-card" data-s="${escapeHtml(s.id)}">
        <div class="hx-card-top"><span class="sx-row">${chip(TYPE_LABEL[s.hunt_type] || s.hunt_type, { tone: "info" })}${lifecycle !== "suggested" ? chip(lifecycle.replace("-", " "), { tone: "accent" }) : ""}</span>
          <button type="button" class="hx-score t-${scoreTone(s.priority.score)}" data-why="${escapeHtml(s.id)}" aria-expanded="${open === s.id}" aria-label="Priority ${Math.round(s.priority.score)} of 100. Show why this score."><b>${Math.round(s.priority.score)}</b>why this score</button></div>
        ${open === s.id ? `<div class="hx-pop" role="dialog" aria-label="Why this score">${bars.map((b) => `<div class="hx-bar-row"><span>${escapeHtml(b.factor.replace(/_/g, " "))}</span><span class="hx-bar${b.negative ? " neg" : ""}"><i style="width:${b.max ? b.pct : Math.min(100, Math.abs(b.points) * 8)}%"></i></span><span>${b.points > 0 ? "+" : ""}${b.points}${b.max ? "/" + b.max : ""}</span><span class="note">${escapeHtml(b.note)}</span></div>`).join("")}${s.learned && s.learned.note ? `<span class="note">${escapeHtml(s.learned.note)}</span>` : ""}</div>` : ""}
        <h3>${escapeHtml(s.title)}</h3><p class="hx-hyp">${escapeHtml(s.hypothesis)}</p>
        <div><p class="hx-sub">Why now</p><div class="hx-why">${(s.why_now || []).slice(0, 6).map((w) => w.link ? `<a href="${escapeHtml(w.link)}" data-link class="${w.strong ? "strong" : ""}" ${tipAttr(`${w.kind}: ${w.detail || ""}`)}>${escapeHtml(w.label)}</a>` : `<span class="${w.strong ? "strong" : ""}" ${tipAttr(`${w.kind}: ${w.detail || ""}`)}>${escapeHtml(w.label)}</span>`).join("") || '<span class="ui-muted">no triggering record</span>'}${(s.why_now || []).length > 6 ? `<span>+${s.why_now.length - 6}</span>` : ""}</div></div>
        <div class="sx-chips">${(s.techniques || []).slice(0, 5).map((t) => `<button type="button" class="hx-fchip" data-tech="${escapeHtml(t.technique_id)}" ${tipAttr(`${t.technique_name} (${t.tactic || "no tactic"}). Click to filter by this technique.`)}>${escapeHtml(t.technique_id)} ${escapeHtml(t.technique_name)}</button>`).join("")}</div>
        <div class="hx-facts"><span><b>${s.scope.counts.assets}</b> assets</span><span><b>${s.scope.counts.identities}</b> identities</span><span><b>${s.scope.counts.segments}</b> segments</span><span>effort <b>${escapeHtml(s.effort || "?")}</b></span><span>value <b>${escapeHtml(s.expected_value || "?")}</b></span>${chip(rd.label, { tone: rd.tone, title: rd.detail })}</div>
        <div class="hx-two"><div><p class="hx-sub">Expected if malicious</p><ul>${(s.expected_malicious || []).slice(0, 3).map((x) => `<li>${escapeHtml(x)}</li>`).join("") || "<li>-</li>"}</ul></div><div><p class="hx-sub">Likely benign</p><ul>${(s.likely_benign || []).slice(0, 3).map((x) => `<li>${escapeHtml(x)}</li>`).join("") || "<li>-</li>"}</ul></div></div>
        ${queryTabs(q).length ? queryBlock(q, s.id) : '<p class="ui-muted" style="font-size:.8rem;margin:0">No query generated yet; the hunt will ask you to write one for your data model.</p>'}
        ${(s.gaps || []).length ? `<details><summary class="sx-link-btn">What Quanta cannot see (${s.gaps.length})</summary><ul class="sx-gaps">${s.gaps.map((g) => `<li>${escapeHtml(g)}</li>`).join("")}</ul></details>` : ""}
        <div class="hx-actions">${lifecycle === "suggested" ? `<button type="button" class="ui-btn sx-btn-sm" data-do="accept" ${isAdmin ? "" : "disabled"}>Accept as a hunt</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-do="dismiss" ${isAdmin ? "" : "disabled"}>Dismiss…</button>` : ""}
          ${["accepted", "running", "evidence-recorded"].includes(lifecycle) ? `${s.hunt_id ? `<a class="ui-btn sx-btn-sm" href="/hunting?hunt=${s.hunt_id}" data-link>Open hunt report</a>` : ""}<button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" data-do="conclude" ${isAdmin ? "" : "disabled"}>Conclude…</button>` : ""}
          ${lifecycle === "concluded" ? `${s.hunt_id ? `<a class="ui-btn ui-btn-ghost sx-btn-sm" href="/hunting?hunt=${s.hunt_id}" data-link>Report</a>` : ""}<button type="button" class="ui-btn sx-btn-sm" data-do="promote" ${isAdmin && !s.promoted_key ? "" : "disabled"}>${s.promoted_key ? "Promoted to a use case" : "Promote to a detection"}</button>` : ""}
          ${s.next_step ? `<span class="ui-muted" style="font-size:.78rem">Next: ${escapeHtml(s.next_step)}</span>` : ""}</div></article>`;
    }
    function paint() {
      const all = data.suggestions; const list = filterSuggestions(all, filters()); const f = facetCounts(all);
      const tactics = Object.keys(f.tactics).sort();
      body.innerHTML = `<div class="sx-toolbar">${["", ...HUNT_TYPES].map((t) => `<button type="button" class="hx-fchip" data-type="${t}" aria-pressed="${st.type === t}">${t ? TYPE_LABEL[t] : "All types"}${t ? ` <span class="sx-seg-n">${f.types[t] || 0}</span>` : ` <span class="sx-seg-n">${all.length}</span>`}</button>`).join("")}</div>
        <div class="sx-toolbar"><select class="sx-field" id="hx-status" aria-label="Lifecycle">${STATUSES.map(([k, l]) => `<option value="${k}" ${k === status ? "selected" : ""}>${l}</option>`).join("")}</select>
          <select class="sx-field" id="hx-tactic" aria-label="Tactic"><option value="">Any tactic</option>${tactics.map((t) => `<option ${t === st.tactic ? "selected" : ""}>${escapeHtml(t)} (${f.tactics[t]})</option>`).join("")}</select>
          <input type="search" class="sx-field" id="hx-q" placeholder="Search hunts, techniques, assets" value="${escapeHtml(st.q)}" aria-label="Search hunts">
          <button type="button" class="hx-fchip" id="hx-ready" aria-pressed="${st.ready === "connected"}">Data connected only</button>
          ${st.technique ? `<button type="button" class="hx-fchip" data-tech-clear aria-pressed="true">Technique ${escapeHtml(st.technique)} (clear)</button>` : ""}
          <span class="ui-muted" style="font-size:.82rem">${list.length} of ${data.total}${data.capped ? ` (top ${data.cap} shown)` : ""}${data.suppressed_hidden ? ` · ${data.suppressed_hidden} hidden by past outcomes` : ""}</span>
          <button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="hx-refresh" ${isAdmin ? "" : "disabled"}>${icon("clock", 14)} Refresh suggestions</button></div>
        <p class="ui-muted" style="margin:0;font-size:.82rem">${escapeHtml(data.note || "")}${data.last_refresh ? ` Last refreshed ${escapeHtml(data.last_refresh)}.` : ""}</p>
        ${(data.gaps || []).length ? `<details class="sx-panel"><summary class="sx-link-btn">Where Quanta has nothing to suggest from (${data.gaps.length})</summary><ul class="sx-gaps">${data.gaps.map((g) => `<li><b>${escapeHtml(g.generator)}:</b> ${escapeHtml(g.note)}</li>`).join("")}</ul></details>` : ""}
        ${list.length ? `<div class="hx-grid">${list.map(card).join("")}</div>` : `<div class="sx-panel">${emptyState({ title: all.length ? "No suggestion matches these filters" : status === "suggested" ? "No hunts suggested yet" : "Nothing in this state", body: all.length ? "Clear a filter to see the rest." : "Suggestions are generated from imported intel, known-exploited vulnerabilities, alerts, identities and detection gaps. Import a threat report, connect a scanner, or refresh once data is in.", actionLabel: all.length ? "" : "Import threat intel", actionHref: all.length ? "" : "/hunting?tab=intel", iconName: "search" })}</div>`}`;
      wireQueryBlocks(body);
    }
    paint();
    const typeSearch = debounce((v) => { setUrl({ q: v }); paint(); const el = body.querySelector("#hx-q"); if (el) { el.focus(); el.setSelectionRange(v.length, v.length); } }, 220);
    body.addEventListener("input", (e) => { if (e.target.id === "hx-q") typeSearch(e.target.value); });
    body.addEventListener("change", async (e) => {
      if (e.target.id === "hx-tactic") { setUrl({ tactic: e.target.value.replace(/ \(\d+\)$/, "") }); paint(); }
      else if (e.target.id === "hx-status") { status = e.target.value; container.dataset.status = status; await fetchList(); paint(); }
    });
    body.addEventListener("click", async (e) => {
      const t = e.target.closest("[data-type]"); if (t) { setUrl({ type: t.dataset.type }); paint(); return; }
      if (e.target.closest("#hx-ready")) { setUrl({ ready: st.ready === "connected" ? "" : "connected" }); paint(); return; }
      const tech = e.target.closest("[data-tech]"); if (tech) { setUrl({ technique: tech.dataset.tech }); paint(); return; }
      if (e.target.closest("[data-tech-clear]")) { setUrl({ technique: "" }); paint(); return; }
      const why = e.target.closest("[data-why]"); if (why) { open = open === why.dataset.why ? null : why.dataset.why; paint(); return; }
      if (e.target.closest("#hx-refresh")) { try { const r = await api.huntingSuggestionRefresh(); toast(`Refreshed: ${r.new} new, ${r.updated} updated.`, { tone: "good" }); await fetchList(); paint(); } catch (er) { toast(er.message, { tone: "bad" }); } return; }
      const d = e.target.closest("[data-do]"); if (!d) return;
      const id = d.closest("[data-s]").dataset.s;
      try {
        if (d.dataset.do === "accept") { const r = await api.huntingSuggestionAccept(id); toast("Accepted. The hunt is ready with its queries.", { tone: "good", href: `/hunting?hunt=${r.hunt_id}`, action: "Open hunt" }); await fetchList(); paint(); }
        else if (d.dataset.do === "dismiss") {
          const out = await modal({ title: "Dismiss this suggestion", confirmLabel: "Dismiss", description: "It returns only when materially new evidence appears.", body: `<label>Reason<select id="m-r">${[["not-relevant", "Not relevant to us"], ["already-covered", "Already covered"], ["no-data", "No data to test it"], ["accepted-risk", "Accepted risk"], ["other", "Other (say why)"]].map(([v, l]) => `<option value="${v}">${l}</option>`).join("")}</select></label><label>Notes<input type="text" id="m-n"></label>`,
            validate: (m) => (m.querySelector("#m-r").value === "other" && !m.querySelector("#m-n").value.trim() ? "Say why when you choose Other." : ""), collect: (m) => ({ reason: m.querySelector("#m-r").value, notes: m.querySelector("#m-n").value.trim() }) });
          if (out) { await api.huntingSuggestionDismiss(id, out); toast("Dismissed.", { tone: "good" }); await fetchList(); paint(); }
        } else if (d.dataset.do === "conclude") {
          const out = await modal({ title: "Conclude this hunt", confirmLabel: "Conclude", description: "Closes the hunt and teaches the engine which kinds of hunt pay off.", body: `<label>Outcome<select id="m-o"><option value="true-positive">True positive: found something real</option><option value="benign">Benign: explained</option><option value="inconclusive-needs-data">Inconclusive: needs data</option></select></label><label>Notes (required)<textarea id="m-n"></textarea></label>`,
            validate: (m) => (m.querySelector("#m-n").value.trim() ? "" : "Notes are required."), collect: (m) => ({ outcome: m.querySelector("#m-o").value, notes: m.querySelector("#m-n").value.trim() }) });
          if (out) { await api.huntingSuggestionConclude(id, out); toast("Concluded.", { tone: "good" }); await fetchList(); paint(); }
        } else if (d.dataset.do === "promote") {
          const r = await api.huntingSuggestionPromote(id); toast(`Promoted to a proposed detection use case (${r.promoted_key}). It is not counted as coverage until it is deployed.`, { tone: "good", href: "/hunting?tab=detections", action: "Open" }); await fetchList(); paint();
        }
      } catch (er) { toast(er.message, { tone: "bad", ms: 7000 }); }
    });
    const off = live.subscribe("activity", debounce(async () => { if (alive && !modalOpenNow()) { try { await fetchList(); paint(); stamp(); } catch { /* next time */ } } }, 1500));
    onCleanup(off);
  }
  const modalOpenNow = () => !!document.querySelector(".sx-modal-root");

  // ------------------------------------------------------------------ ATT&CK matrix
  async function matrix() {
    body.innerHTML = '<div class="ui-skel ui-skel-table"></div>';
    let M;
    try { M = await api.huntingAttackMatrix(); } catch (e) { body.innerHTML = `<div class="sx-callout warn">${escapeHtml(e.message)}</div>`; return; }
    stamp();
    const f = { state: "", observedOnly: true, q: "" };
    let sel = st.technique || "";
    const draw = () => {
      const agg = aggregateMatrix(M, { state: f.state, observedOnly: f.observedOnly, q: f.q });
      const t = agg.totals;
      body.innerHTML = `<div class="sx-row"><div class="sx-kpis" style="flex:1">
          <div class="ui-kpi"><div class="ui-kpi-top"><span class="ui-kpi-label">Observed techniques</span></div><div class="ui-kpi-value">${t.observed || 0}</div><div class="ui-kpi-foot"><span class="ui-muted" style="font-size:.76rem">in open findings or alerts</span></div></div>
          <div class="ui-kpi ${agg.observedCoveragePct === null ? "" : agg.observedCoveragePct >= 60 ? "ui-kpi-good" : "ui-kpi-warn"}"><div class="ui-kpi-top"><span class="ui-kpi-label">Covered by a rule</span></div><div class="ui-kpi-value">${agg.observedCoveragePct === null ? "n/a" : agg.observedCoveragePct + "%"}</div><div class="ui-kpi-foot"><span class="ui-muted" style="font-size:.76rem">${agg.rulesRecorded ? `${t.observed_covered || 0} of ${t.observed || 0} observed` : "no detection rules recorded: coverage cannot be judged"}</span></div></div>
          <div class="ui-kpi"><div class="ui-kpi-top"><span class="ui-kpi-label">Hunted, no rule</span></div><div class="ui-kpi-value">${t.observed_hunted || 0}</div></div>
          <div class="ui-kpi ${t.observed_gap ? "ui-kpi-danger" : "ui-kpi-good"}"><div class="ui-kpi-top"><span class="ui-kpi-label">Exposed, no rule or hunt</span></div><div class="ui-kpi-value">${t.observed_gap || 0}</div></div></div></div>
        <div class="sx-toolbar"><div class="hx-legend">${CELL_STATES.map((s) => `<button type="button" class="hx-fchip" data-state="${s}" aria-pressed="${f.state === s}"><i style="--cc:var(--${{ covered: "sx-good", hunted: "sx-low", gap: "sx-bad", quiet: "border" }[s]})"></i> ${STATE_LABEL[s]}</button>`).join("")}</div>
          <button type="button" class="hx-fchip" id="mx-obs" aria-pressed="${f.observedOnly}">Observed only</button><input type="search" class="sx-field" id="mx-q" placeholder="Filter by technique" value="${escapeHtml(f.q)}" aria-label="Filter techniques"></div>
        <p class="ui-muted" style="margin:0;font-size:.8rem">Cell shade shows how many open findings and alerts involve the technique. ${escapeHtml(M.note)}</p>
        ${agg.columns.length ? `<div class="hx-matrix-wrap"><div class="hx-matrix">${agg.columns.map((c) => `<div class="hx-mcol"><h4>${escapeHtml(c.tactic)}</h4><span class="tot">${c.observed} observed · ${c.covered} covered</span><div class="hx-cells">${c.cells.map((x) => `<button type="button" class="sx-cell s-${x.state} h${heatLevel(x.exposure, agg.max)}${sel === x.technique_id ? " sel" : ""}" data-cell="${escapeHtml(x.technique_id)}" ${tipAttr(cellTitle(x))} aria-label="${escapeHtml(cellTitle(x))}"><b>${escapeHtml(x.technique_id)}</b><span class="n">${escapeHtml(x.name)}</span></button>`).join("")}</div></div>`).join("")}</div></div>` : `<div class="sx-panel">${emptyState({ title: "Nothing to show", body: "No technique matches these filters, or nothing is tagged yet. Findings and alerts carry ATT&CK techniques when they are ingested.", iconName: "search" })}</div>`}
        <div id="mx-detail">${sel ? detail(sel) : '<p class="ui-muted">Select a technique to see the detections, hunts, findings and suggestions behind it.</p>'}</div>`;
    };
    const detail = (tid) => {
      const c = M.techniques.find((x) => x.technique_id === tid); if (!c) return "";
      return `<div class="hx-detail"><h3 style="margin:0">${escapeHtml(c.technique_id)} ${escapeHtml(c.name)} ${chip(STATE_LABEL[c.state], { tone: c.state === "covered" ? "good" : c.state === "gap" ? "critical" : c.state === "hunted" ? "info" : "neutral" })}</h3>
        <div class="ui-muted">${escapeHtml(c.tactic)}${c.in_library ? " · Quanta has a hunt query for this technique" : ""}</div>
        <div class="hx-facts"><span><b>${c.rules.length}</b> enabled rule(s)${c.rules.length ? ": " + escapeHtml(c.rules.join(", ")) : ""}</span>${c.rules_disabled.length ? `<span><b>${c.rules_disabled.length}</b> disabled</span>` : ""}<span><b>${c.findings}</b> open finding(s)</span><span><b>${c.alerts}</b> alert(s)</span></div>
        <div class="sx-row">${c.hunts.map((h) => `<a class="ui-btn ui-btn-ghost sx-btn-sm" href="/hunting?hunt=${h}" data-link>Hunt #${h}</a>`).join("")}${c.suggestions.length ? `<a class="ui-btn sx-btn-sm" href="/hunting?tab=suggested&technique=${encodeURIComponent(c.technique_id)}" data-link>${c.suggestions.length} suggested hunt(s)</a>` : ""}${c.findings ? `<a class="ui-btn ui-btn-ghost sx-btn-sm" href="/queue?q=${encodeURIComponent(c.technique_id)}" data-link>Findings</a>` : ""}<a class="ui-btn ui-btn-ghost sx-btn-sm" href="/hunting?tab=detections" data-link>Detection engineering</a></div></div>`;
    };
    draw();
    const typeQ = debounce((v) => { f.q = v; draw(); const el = body.querySelector("#mx-q"); if (el) { el.focus(); el.setSelectionRange(v.length, v.length); } }, 200);
    body.addEventListener("input", (e) => { if (e.target.id === "mx-q") typeQ(e.target.value); });
    body.addEventListener("click", (e) => {
      const s = e.target.closest("[data-state]"); if (s) { f.state = f.state === s.dataset.state ? "" : s.dataset.state; draw(); return; }
      if (e.target.closest("#mx-obs")) { f.observedOnly = !f.observedOnly; draw(); return; }
      const c = e.target.closest("[data-cell]"); if (c) { sel = c.dataset.cell; setUrl({ technique: sel }); draw(); const d = body.querySelector("#mx-detail"); if (d) d.scrollIntoView({ block: "nearest" }); }
    });
  }

  // ------------------------------------------------------------------ active hunts
  async function active() {
    body.innerHTML = '<div class="hx-active"><div class="ui-skel ui-skel-card"></div><div class="ui-skel ui-skel-card"></div></div>';
    const draw = async () => {
      let list;
      try { list = (await api.huntingList()).hunts; } catch (e) { body.innerHTML = `<div class="sx-callout warn">${escapeHtml(e.message)}</div>`; return; }
      const live_ = list.filter((h) => h.status !== "closed");
      const reports = await Promise.all(live_.slice(0, 12).map((h) => api.huntReport(h.id).catch(() => null)));
      if (!alive) return;
      stamp();
      body.innerHTML = `${live_.length ? `<div class="hx-active">${live_.slice(0, 12).map((h, i) => { const r = reports[i]; const p = huntProgress(r && r.counts); return `<a class="hx-active-card" href="/hunting?hunt=${h.id}" data-link><div class="sx-row">${chip(h.status, { tone: "info" })}${r ? chip(verdictText(r.verdict.label), { tone: r.verdict.label === "confirmed" ? "critical" : r.verdict.label === "needs-investigation" ? "warn" : r.verdict.label === "no-ioc-match" ? "good" : "neutral" }) : ""}</div>
          <b>${escapeHtml(h.title)}</b><span class="hx-prog" role="progressbar" aria-valuenow="${p.pct}" aria-valuemin="0" aria-valuemax="100" aria-label="Trial hits run"><i style="width:${p.pct}%"></i></span><span class="ui-muted" style="font-size:.8rem">${escapeHtml(p.label)}${r ? ` · ${r.counts.needs_investigation} to investigate · ${r.counts.hits} hit(s)` : ""}</span></a>`; }).join("")}</div>` : `<div class="sx-panel">${emptyState({ title: "No active hunts", body: "Accept a suggested hunt to start one. Each hunt becomes a report with a row per trial hit.", actionLabel: "See suggested hunts", actionHref: "/hunting?tab=suggested", iconName: "search" })}</div>`}
        ${list.some((h) => h.status === "closed") ? `<section class="sx-panel" style="margin-top:12px"><h3>Closed hunts</h3><div class="sx-table-wrap"><table class="sx-table"><tbody>${list.filter((h) => h.status === "closed").slice(0, 15).map((h) => `<tr><td><a href="/hunting?hunt=${h.id}" data-link>#${h.id} ${escapeHtml(h.title)}</a></td><td>${escapeHtml(h.outcome || "")}</td></tr>`).join("")}</tbody></table></div></section>` : ""}`;
    };
    await draw();
    const t = setInterval(() => { if (!document.hidden && alive) draw(); }, 20000);
    onCleanup(() => clearInterval(t));
    onCleanup(live.subscribe("activity", debounce(() => { if (alive) draw(); }, 1500)));
  }
}
