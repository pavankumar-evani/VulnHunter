// Security Posture Review: where the estate and this Quanta deployment stand against ten frameworks, worked out from what Quanta has recorded.
// A score appears only when enough could be observed; what could not be observed is listed, never counted as a pass. Every check opens to the recorded facts,
// what to do and the exact setting to change (with a copy button). It reads and advises: it changes nothing.
// The server keeps no history, so trend deltas and sparklines come from earlier readings taken in this browser (moduleLogic.pushReading).
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";
import { icon } from "../icons.js";
import { kpiTile, chip, toast, emptyState, onCleanup, dataAgeBadge, mountDataAge, touchDataAge, mountCounters, sparkline, deltaChip, tipAttr, debounce } from "../ui.js";
import { copyText, downloadText, segmented, onSeg } from "../sxKit.js";
import { radarSvg, tabBar, wireTabBar, pageActions, replaceSearch, readJson, writeJson, meter, copyButton, wireCopy, skeletonPage, kpiStrip } from "../mxKit.js";
import { settingText, POSTURE_KIND_LABEL, actionsMarkdown, pushReading, readingSeries, scoreTone, postureTotals, filterChecks } from "../moduleLogic.js";

export const title = "Security Posture Review";

const STATUS = { pass: ["Pass", "good"], partial: ["Partial", "warn"], fail: ["Gap", "critical"], unknown: ["Not observable", "neutral"], na: ["Not applicable", "neutral"] };
const HIST_KEY = "quanta.posture.history";
const fmt = (n) => (n === null || n === undefined ? "n/a" : String(Math.round(n)));
const STAGE_TONE = { Traditional: "bad", Initial: "warn", Advanced: "good", Optimal: "good" };

export async function render(container) {
  const $ = (s) => container.querySelector(s);
  let alive = true;
  onCleanup(() => { alive = false; });
  const S = { data: null, active: new URLSearchParams(window.location.search).get("framework") || "overview", filter: "all", q: "", history: [], loadedAt: 0 };

  container.innerHTML = `<div class="sx-page mx-page"><div class="sx-head"><div><h2>Security posture review</h2><p>Where the estate stands against ten frameworks, from what Quanta has recorded. A score appears only when enough could be observed; what could not be observed is listed, never counted as a pass. The numbers are Quanta's own summary (the standards publish none), set in <code>posture_policy.yaml</code>. It advises and changes nothing.</p></div>
    <div class="sx-row"><span id="ps-age"></span><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="ps-refresh">${icon("clock", 14)} Assess again</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="ps-copy">Copy action list</button><button type="button" class="ui-btn ui-btn-ghost sx-btn-sm" id="ps-dl">Download .md</button></div></div>
    <div id="ps-skel">${skeletonPage(4)}<p class="ui-muted" role="status">Assessing ten frameworks from the recorded data. This can take half a minute on a large estate.</p></div>
    <div id="ps-tabs" hidden></div><div id="ps-main"></div></div>`;

  async function load() {
    const data = await api.posture();
    if (!alive) return;
    S.data = data; S.loadedAt = Date.now();
    const reading = { overall: data.overall.score, fw: Object.fromEntries(data.frameworks.map((f) => [f.id, f.score])) };
    S.history = pushReading(readJson(HIST_KEY, []), reading);
    writeJson(HIST_KEY, S.history);
  }
  const fw = () => S.data.frameworks;
  const fwTrend = (id) => readingSeries(S.history, (r) => r.fw && r.fw[id]);
  const url = () => replaceSearch(S.active === "overview" ? "" : `?framework=${encodeURIComponent(S.active)}`);

  function trendBits(series, goodWhen = "up") {
    const spark = series.values.length > 1 ? sparkline(series.values, { width: 70, height: 22, label: "Score over earlier readings in this browser" }) : "";
    let chipHtml = "";
    if (series.previous !== null && series.current !== null) {
      const diff = Math.round((series.current - series.previous) * 10) / 10;
      const dir = diff === 0 ? "flat" : diff > 0 ? "up" : "down";
      const tone = dir === "flat" ? "flat" : dir === goodWhen ? "good" : "bad";
      chipHtml = `<span class="ui-delta ui-delta-${tone}" ${tipAttr(`Previous reading in this browser: ${series.previous}, now ${series.current}`)}><span aria-hidden="true">${dir === "up" ? "▲" : dir === "down" ? "▼" : "■"}</span> ${diff > 0 ? "+" : ""}${diff} pts<span class="ui-sr"> ${dir === "flat" ? "no change" : dir} since the previous reading</span></span>`;
    }
    return `${chipHtml}${spark}`;
  }
  function changeHtml(ch, { compact = false } = {}) {
    if (!ch) return "";
    const text = settingText(ch);
    const link = ch.kind === "page" ? `<a class="ui-btn ui-btn-ghost sx-btn-sm" href="${escapeHtml(ch.where)}" data-link>Open ${escapeHtml(ch.key)}</a>` : "";
    return `<div class="mx-change"><div class="mx-sub"><b>${escapeHtml(POSTURE_KIND_LABEL[ch.kind] || ch.kind)}</b> in <code>${escapeHtml(ch.where || "")}</code>${ch.key && ch.kind !== "env" && ch.kind !== "yaml" ? ` &rsaquo; ${escapeHtml(ch.key)}` : ""}</div>
      ${text ? `<code class="mx-code">${escapeHtml(text)}</code>` : (ch.value !== undefined ? `<div class="mx-sub">${escapeHtml(String(ch.value))}</div>` : "")}
      ${!compact && ch.effect ? `<div class="ui-muted mx-sub">${escapeHtml(ch.effect)}</div>` : ""}<div class="mx-actions">${text ? copyButton(text, "Copy exact setting") : ""}${link}</div></div>`;
  }
  function checkHtml(c) {
    const [label, tone] = STATUS[c.status] || [c.status, "neutral"];
    const ev = (c.evidence || []).map((e) => `<li>${escapeHtml(e)}</li>`).join("");
    const refs = (c.refs || []).map((r) => `<a href="${escapeHtml(r.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(r.label)}</a>`).join(" &middot; ");
    return `<details class="mx-check mx-check-${c.status}"><summary>${chip(label, { tone })}<span class="mx-ct">${escapeHtml(c.title)}</span><span class="ui-muted mx-w" ${tipAttr("How much this check counts in the framework score")}>weight ${c.weight}</span></summary>
      <div class="mx-check-body">${c.detail ? `<p>${escapeHtml(c.detail)}</p>` : ""}${ev ? `<h5 class="mx-h3">What was recorded</h5><ul class="mx-list">${ev}</ul>` : ""}${c.recommendation ? `<h5 class="mx-h3">What to do</h5><p>${escapeHtml(c.recommendation)}</p>` : ""}${changeHtml(c.change)}
        ${c.data_used && c.data_used.length ? `<p class="ui-muted mx-sub">Read: ${c.data_used.map(escapeHtml).join(", ")}</p>` : ""}${refs ? `<p class="ui-muted mx-sub">${refs}</p>` : ""}</div></details>`;
  }

  function overviewHtml() {
    const d = S.data; const o = d.overall;
    const overall = readingSeries(S.history, (r) => r.overall);
    return `<div class="mx-hero"><div class="mx-hero-score mx-tone-${scoreTone(o.score)}"><span class="ui-kpi-label">Overall</span><div class="mx-score">${fmt(o.score)}</div>${chip(o.stage || "not scored", { tone: STAGE_TONE[o.stage] === "bad" ? "critical" : STAGE_TONE[o.stage] || "neutral" })}<div class="mx-trend">${trendBits(overall)}</div>
        <p class="ui-muted mx-sub">${o.scored_frameworks} of ${o.frameworks} frameworks had enough recorded to score.${overall.values.length < 2 ? " Trend appears after a second reading in this browser." : ""}</p></div>
      <div class="mx-hero-radar">${radarSvg(fw().filter((f) => f.score !== null).map((f) => ({ label: f.title.length > 20 ? f.title.slice(0, 19) + "…" : f.title, value: f.score / 100 })), { size: 300, label: "Score by framework" }) || '<p class="ui-muted">The radar needs at least three scored frameworks.</p>'}</div></div>
      <div id="ps-kpis" class="sx-kpis mx-kpis"></div>
      <h3 class="mx-h3">Frameworks</h3>
      <div class="mx-grid-cards">${fw().map((f) => { const tr = fwTrend(f.id); return `<button type="button" class="mx-card mx-fwcard" data-fw="${escapeHtml(f.id)}" aria-label="${escapeHtml(f.title)}, score ${fmt(f.score)}, ${f.counts.fail + f.counts.partial} gaps"><div class="mx-card-head"><h4>${escapeHtml(f.title)}</h4>${chip(f.stage || "not enough recorded", { tone: f.stage ? (STAGE_TONE[f.stage] === "bad" ? "critical" : STAGE_TONE[f.stage]) : "neutral" })}</div>
        <div class="sx-row"><span class="mx-score mx-score-sm mx-tone-${scoreTone(f.score)}">${fmt(f.score)}</span>${meter((f.score || 0) / 100, { tone: scoreTone(f.score) === "bad" ? "bad" : scoreTone(f.score) === "warn" ? "warn" : "", label: `Score ${fmt(f.score)} of 100` })}${trendBits(tr)}</div>
        <div class="mx-sub">${f.counts.pass} pass &middot; ${f.counts.partial} partial &middot; ${f.counts.fail} gaps &middot; ${f.counts.unknown} not observable</div></button>`; }).join("")}</div>
      <h3 class="mx-h3">What to do first</h3>
      ${d.actions.length ? `<ol class="mx-actionlist">${d.actions.map((a) => `<li class="mx-card"><div class="mx-card-head"><span class="sx-row"><button type="button" class="sx-link-btn" data-fw="${escapeHtml(a.framework)}">${escapeHtml(a.framework_title)}</button>${chip(STATUS[a.status][0], { tone: STATUS[a.status][1] })}</span><span class="ui-muted mx-sub" ${tipAttr("Estimated effect on the framework score")}>impact ${a.impact}</span></div>
        <h4>${escapeHtml(a.title)}</h4>${a.evidence.length ? `<div class="ui-muted mx-sub">${escapeHtml(a.evidence[0])}</div>` : ""}<p>${escapeHtml(a.recommendation)}</p>${changeHtml(a.change, { compact: true })}</li>`).join("")}</ol>${d.all_actions > d.actions.length ? `<p class="ui-muted">${d.all_actions - d.actions.length} more are listed under each framework.</p>` : ""}` : emptyState({ title: "No open gaps among what could be observed", body: "Recording more data makes more of the ten frameworks measurable. See the list below.", iconName: "approved" })}
      <details class="sx-panel mx-details"><summary>Not observable (${d.not_observable.length} checks)</summary><p class="ui-muted">Quanta cannot see these from what is recorded, so they are in no score. Recording the data, or connecting the source, makes them measurable.</p>
        <ul class="mx-list">${d.not_observable.map((u) => `<li><b>${escapeHtml(u.title)}</b> <span class="ui-muted">(${escapeHtml(u.framework)})</span>${u.data_used.length ? `<div class="ui-muted mx-sub">Needs: ${u.data_used.map(escapeHtml).join(", ")}</div>` : ""}</li>`).join("")}</ul></details>
      ${Object.keys(d.unavailable_sources).length ? `<p class="ui-muted">Sources that could not be read this time: ${Object.keys(d.unavailable_sources).map(escapeHtml).join(", ")}.</p>` : ""}
      ${Object.keys(d.problems).length ? `<div class="mx-callout mx-callout-warn">Some framework modules did not load: ${Object.entries(d.problems).map(([k, v]) => `${escapeHtml(k)} (${escapeHtml(v)})`).join(", ")}.</div>` : ""}`;
  }
  function frameworkHtml(f) {
    const checks = filterChecks(f.checks, S.filter, S.q);
    const tr = fwTrend(f.id);
    const areas = f.areas.map((a) => `<div class="mx-area"><span>${escapeHtml(a.title)}</span>${meter((a.score || 0) / 100, { tone: a.score !== null && a.score < 40 ? "bad" : a.score !== null && a.score < 70 ? "warn" : "", label: `${a.title}: ${fmt(a.score)}` })}<b>${fmt(a.score)}</b><span class="ui-muted mx-sub">${a.observable}/${a.checks} observable</span></div>`).join("");
    const byArea = f.areas.map((a) => { const mine = checks.filter((c) => c.area === a.id); return mine.length ? `<h4 class="mx-h3">${escapeHtml(a.title)}</h4>${mine.map(checkHtml).join("")}` : ""; }).join("");
    const other = checks.filter((c) => !f.areas.some((a) => a.id === c.area));
    const counts = [["all", "All", f.checks.length], ["gaps", "Gaps and partial", f.counts.fail + f.counts.partial], ["fail", "Gaps", f.counts.fail], ["unknown", "Not observable", f.counts.unknown], ["pass", "Pass", f.counts.pass]];
    return `<section aria-label="${escapeHtml(f.title)}"><div class="mx-fwhead"><div><h3>${escapeHtml(f.title)}</h3><p class="ui-muted">${escapeHtml(f.summary || "")}</p><p>${(f.refs || []).map((r) => `<a href="${escapeHtml(r.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(r.label)}</a>`).join(" &middot; ")}</p></div>
      <div class="mx-hero-score mx-tone-${scoreTone(f.score)}"><div class="mx-score">${fmt(f.score)}</div>${chip(f.stage || "not scored", { tone: f.stage ? (STAGE_TONE[f.stage] === "bad" ? "critical" : STAGE_TONE[f.stage]) : "neutral" })}<div class="mx-trend">${trendBits(tr)}</div></div></div>
      ${f.note ? `<div class="mx-callout">${escapeHtml(f.note)}</div>` : ""}<div class="mx-areas">${areas}</div>
      <p class="ui-muted">${Math.round(f.observable_share * 100)}% of the check weight could be observed.</p>
      <div class="sx-toolbar" role="search">${segmented("Show", counts.map(([id, l, n]) => ({ id, label: l, count: n })), S.filter)}<input type="search" class="sx-field" id="ps-q" placeholder="Search these checks" value="${escapeHtml(S.q)}" aria-label="Search checks"></div>
      ${byArea}${other.length ? `<h4 class="mx-h3">Other</h4>${other.map(checkHtml).join("")}` : ""}${checks.length ? "" : emptyState({ title: "No check matches", body: "Change the filter or the search.", iconName: "search" })}</section>`;
  }

  function paint() {
    if (!alive || !S.data) return;
    $("#ps-skel").hidden = true;
    const tabs = [{ id: "overview", label: "Overview" }, ...fw().map((f) => ({ id: f.id, label: f.title }))];
    const tabsEl = $("#ps-tabs"); tabsEl.hidden = false; tabsEl.innerHTML = tabBar("Frameworks", tabs, S.active);
    const f = fw().find((x) => x.id === S.active);
    $("#ps-main").innerHTML = S.active === "overview" || !f ? overviewHtml() : frameworkHtml(f);
    if (S.active === "overview" || !f) {
      const t = postureTotals(fw());
      kpiStrip($("#ps-kpis"), [
        { key: "gaps", label: "Gaps", value: t.fail, tone: t.fail ? "danger" : "good", filterable: false, hint: "Checks that were observed and not met." },
        { key: "partial", label: "Partial", value: t.partial, tone: t.partial ? "warn" : "good", filterable: false, hint: "Observed and only partly met." },
        { key: "pass", label: "Passing", value: t.pass, tone: "good", filterable: false, hint: "Observed and met." },
        { key: "unknown", label: "Not observable", value: t.unknown, filterable: false, hint: "Quanta cannot see these from what is recorded. They are in no score." },
        { key: "actions", label: "Open actions", value: S.data.all_actions, tone: S.data.all_actions ? "warn" : "good", filterable: false, hint: "Every gap or partial check with something to do, across all frameworks." },
      ], () => {});
    }
    const age = $("#ps-age"); age.innerHTML = dataAgeBadge(S.loadedAt, { fresh: 600000, stale: 3600000 }); mountDataAge(age);
    mountCounters($("#ps-main"));
  }

  wireTabBar($("#ps-tabs"), (id) => { S.active = id; S.filter = "all"; S.q = ""; url(); paint(); });
  wireCopy(container, copyText);
  onSeg($("#ps-main"), (id) => { S.filter = id; paint(); });
  const typeSearch = debounce((v) => { S.q = v; paint(); const i = $("#ps-q"); if (i) { i.focus(); i.setSelectionRange(v.length, v.length); } }, 220);
  container.addEventListener("input", (e) => { if (e.target.id === "ps-q") typeSearch(e.target.value); });
  container.addEventListener("click", (e) => {
    const b = e.target.closest("[data-fw]"); if (b && !e.target.closest(".mx-tabs")) { S.active = b.dataset.fw; S.filter = "all"; S.q = ""; url(); paint(); window.scrollTo({ top: 0 }); return; }
    if (e.target.closest("#ps-refresh")) { refresh(true); return; }
    if (e.target.closest("#ps-copy")) { if (S.data) copyText(actionsMarkdown(S.data.actions, new Date().toISOString().slice(0, 10)), "Action list copied as Markdown"); return; }
    if (e.target.closest("#ps-dl")) { if (S.data) downloadText("security-posture-actions.md", actionsMarkdown(S.data.actions, new Date().toISOString().slice(0, 10))); }
  });
  async function refresh(manual) {
    const btn = $("#ps-refresh"); if (btn) btn.disabled = true;
    try { await load(); paint(); if (manual) toast("Assessed again.", { tone: "good", ms: 2200 }); const age = $("#ps-age .ui-age"); if (age) touchDataAge(age, S.loadedAt); }
    catch (err) { toast(`Could not assess: ${err.message}`, { tone: "bad", ms: 8000 }); }
    finally { if (btn) btn.disabled = false; }
  }

  try { await load(); } catch (err) {
    $("#ps-skel").hidden = true;
    $("#ps-main").innerHTML = emptyState({ title: err.status === 401 || err.status === 403 ? "The posture review is for administrators" : "The review could not be loaded", body: err.message || "Try again in a moment.", actionLabel: err.status === 401 ? "Sign in" : "", actionHref: err.status === 401 ? "/login?redirect=/posture" : "", iconName: "risk" });
    return;
  }
  paint();
  pageActions([
    { label: "Posture: assess again", icon: "risk", run: () => refresh(true) }, { label: "Posture: copy the action list as Markdown", icon: "risk", run: () => S.data && copyText(actionsMarkdown(S.data.actions), "Action list copied") },
    { label: "Posture: show the overview", icon: "risk", run: () => { S.active = "overview"; url(); paint(); } },
  ]);
}
