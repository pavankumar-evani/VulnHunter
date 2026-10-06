// Security Posture Review: one assessment of the recorded estate and of this Quanta deployment against ten frameworks (remediation/posture).
// Every score comes from checks you can open: each shows the recorded facts it looked at, what to do, and the exact setting to change. What Quanta
// cannot observe is listed, never scored. Nothing here changes anything; it reads what Quanta already holds and advises.
import { api } from "../api.js";
import { escapeHtml } from "../dom.js";

export const title = "Security Posture Review";

const STATUS = { pass: ["Pass", "ps-pass"], partial: ["Partial", "ps-partial"], fail: ["Gap", "ps-fail"], unknown: ["Not observable", "ps-unknown"], na: ["Not applicable", "ps-na"] };
const KIND = { env: "Environment variable", yaml: "Config file", helm: "Helm value", page: "Quanta page", process: "Process" };
const stageClass = (s) => ({ Traditional: "ps-trad", Initial: "ps-init", Advanced: "ps-adv", Optimal: "ps-opt" }[s] || "ps-none");
const fmt = (n) => (n === null || n === undefined ? "n/a" : String(Math.round(n)));

function radar(frameworks) {
  const items = frameworks.filter((f) => f.score !== null);
  if (items.length < 3) return `<p class="muted">The radar needs at least three scored frameworks.</p>`;
  const S = 360, c = S / 2, R = 128, n = items.length;
  const pt = (i, v) => { const a = -Math.PI / 2 + (2 * Math.PI * i) / n; return [c + Math.cos(a) * R * (v / 100), c + Math.sin(a) * R * (v / 100)]; };
  const ring = (v) => items.map((_, i) => pt(i, v).map((x) => x.toFixed(1)).join(",")).join(" ");
  const poly = items.map((f, i) => pt(i, f.score).map((x) => x.toFixed(1)).join(",")).join(" ");
  const labels = items.map((f, i) => { const [x, y] = pt(i, 118); const anchor = x < c - 8 ? "end" : x > c + 8 ? "start" : "middle"; return `<text x="${x.toFixed(1)}" y="${y.toFixed(1)}" text-anchor="${anchor}" class="ps-radar-label">${escapeHtml(f.title.length > 22 ? f.title.slice(0, 21) + "…" : f.title)}</text>`; }).join("");
  const dots = items.map((f, i) => { const [x, y] = pt(i, f.score); return `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="4" class="ps-radar-dot"><title>${escapeHtml(f.title)}: ${fmt(f.score)}</title></circle>`; }).join("");
  return `<svg viewBox="0 0 ${S} ${S}" class="ps-radar" role="img" aria-label="Scores by framework">${[25, 50, 75, 100].map((v) => `<polygon points="${ring(v)}" class="ps-radar-ring"/>`).join("")}${items.map((_, i) => { const [x, y] = pt(i, 100); return `<line x1="${c}" y1="${c}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}" class="ps-radar-axis"/>`; }).join("")}<polygon points="${poly}" class="ps-radar-area"/>${dots}${labels}</svg>`;
}

function changeHtml(ch) {
  if (!ch) return "";
  return `<div class="ps-change"><span class="ps-kind">${escapeHtml(KIND[ch.kind] || ch.kind)}</span> <code>${escapeHtml(ch.where || "")}</code>${ch.key ? ` &rsaquo; <code>${escapeHtml(ch.key)}</code>` : ""}${ch.value !== undefined && ch.value !== null && ch.value !== "" ? ` = <code>${escapeHtml(String(ch.value))}</code>` : ""}${ch.effect ? `<div class="muted">${escapeHtml(ch.effect)}</div>` : ""}</div>`;
}

function checkHtml(c) {
  const [label, cls] = STATUS[c.status] || [c.status, ""];
  const ev = (c.evidence || []).map((e) => `<li>${escapeHtml(e)}</li>`).join("");
  const refs = (c.refs || []).map((r) => `<a href="${escapeHtml(r.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(r.label)}</a>`).join(" · ");
  return `<details class="ps-check ${cls}"><summary><span class="ps-chip ${cls}">${escapeHtml(label)}</span><span class="ps-ct">${escapeHtml(c.title)}</span><span class="ps-w" title="How much this counts in the framework score">weight ${c.weight}</span></summary>
    <div class="ps-body">${c.detail ? `<p>${escapeHtml(c.detail)}</p>` : ""}${ev ? `<h5>What was recorded</h5><ul>${ev}</ul>` : ""}${c.recommendation ? `<h5>What to do</h5><p>${escapeHtml(c.recommendation)}</p>` : ""}${changeHtml(c.change)}
    ${c.data_used && c.data_used.length ? `<p class="muted">Read: ${c.data_used.map(escapeHtml).join(", ")}</p>` : ""}${refs ? `<p class="muted">${refs}</p>` : ""}</div></details>`;
}

function frameworkHtml(f, filter) {
  const checks = f.checks.filter((c) => filter === "all" || c.status === filter || (filter === "gaps" && (c.status === "fail" || c.status === "partial")));
  const areas = f.areas.map((a) => `<div class="ps-area"><span>${escapeHtml(a.title)}</span><div class="ps-bar" title="${a.observable} of ${a.checks} checks observable"><i style="width:${a.score === null ? 0 : a.score}%"></i></div><b>${fmt(a.score)}</b></div>`).join("");
  const byArea = f.areas.map((a) => {
    const mine = checks.filter((c) => c.area === a.id);
    return mine.length ? `<h4>${escapeHtml(a.title)}</h4>${mine.map(checkHtml).join("")}` : "";
  }).join("");
  const other = checks.filter((c) => !f.areas.some((a) => a.id === c.area));
  return `<section class="ps-fw"><div class="ps-fw-head"><div><h3>${escapeHtml(f.title)}</h3><p class="muted">${escapeHtml(f.summary || "")}</p>${(f.refs || []).map((r) => `<a href="${escapeHtml(r.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(r.label)}</a>`).join(" · ")}</div>
    <div class="ps-score ${stageClass(f.stage)}"><b>${fmt(f.score)}</b><span>${escapeHtml(f.stage || "not scored")}</span></div></div>
    ${f.note ? `<p class="ps-note">${escapeHtml(f.note)}</p>` : ""}<div class="ps-areas">${areas}</div>
    <p class="muted">${f.counts.pass} pass · ${f.counts.partial} partial · ${f.counts.fail} gaps · ${f.counts.unknown} not observable · ${f.counts.na} not applicable. ${Math.round(f.observable_share * 100)}% of the check weight could be observed.</p>
    ${byArea}${other.length ? `<h4>Other</h4>${other.map(checkHtml).join("")}` : ""}${checks.length ? "" : `<p class="muted">No checks match this filter.</p>`}</section>`;
}

export async function render(container) {
  container.innerHTML = `<p class="subtitle">Where the estate stands against ten frameworks, worked out from what Quanta has recorded. A score appears only when enough could be observed; what could not be observed is listed, never counted as a pass. The numbers are Quanta's own summary (the standards publish none), set in <code>remediation/config/posture_policy.yaml</code>. It advises and changes nothing.</p><div id="ps-root"><p class="muted">Assessing…</p></div>`;
  const root = container.querySelector("#ps-root");
  let data;
  try { data = await api.posture(); } catch (err) { root.innerHTML = `<p class="gv-empty">${escapeHtml(err && err.message ? err.message : "The review could not be loaded.")}</p>`; return; }
  let active = (new URLSearchParams(window.location.search).get("framework")) || "overview", filter = "all";
  const fws = data.frameworks;

  function draw() {
    const tabs = [["overview", "Overview"], ...fws.map((f) => [f.id, f.title])];
    let body;
    if (active === "overview") {
      const o = data.overall;
      body = `<div class="ps-top"><div class="ps-hero ${stageClass(o.stage)}"><span>Overall</span><b>${fmt(o.score)}</b><em>${escapeHtml(o.stage || "not scored")}</em><small>${o.scored_frameworks} of ${o.frameworks} frameworks had enough recorded to score</small></div><div class="ps-radar-wrap">${radar(fws)}</div></div>
        <div class="ps-cards">${fws.map((f) => `<button type="button" class="ps-card ${stageClass(f.stage)}" data-fw="${escapeHtml(f.id)}"><b>${fmt(f.score)}</b><span>${escapeHtml(f.title)}</span><small>${escapeHtml(f.stage || "not enough recorded")} · ${f.counts.fail + f.counts.partial} gaps</small></button>`).join("")}</div>
        <h3>What to do first</h3>${data.actions.length ? `<ol class="ps-actions">${data.actions.map((a) => `<li><div><button type="button" class="link-button" data-fw="${escapeHtml(a.framework)}">${escapeHtml(a.framework_title)}</button> <span class="ps-chip ${STATUS[a.status][1]}">${STATUS[a.status][0]}</span> <b>${escapeHtml(a.title)}</b></div>${a.evidence.length ? `<div class="muted">${escapeHtml(a.evidence[0])}</div>` : ""}<p>${escapeHtml(a.recommendation)}</p>${changeHtml(a.change)}</li>`).join("")}</ol>${data.all_actions > data.actions.length ? `<p class="muted">${data.all_actions - data.actions.length} more are listed under each framework.</p>` : ""}` : `<p class="muted">No open gaps among what could be observed.</p>`}
        <h3>Not observable</h3><p class="muted">Quanta cannot see these from what is recorded, so they are not in any score. Recording the data (or connecting the source) makes them measurable.</p>
        <details class="ps-unobs"><summary>${data.not_observable.length} checks</summary><ul>${data.not_observable.map((u) => `<li><b>${escapeHtml(u.title)}</b> <span class="muted">(${escapeHtml(u.framework)})</span>${u.data_used.length ? `<div class="muted">Needs: ${u.data_used.map(escapeHtml).join(", ")}</div>` : ""}</li>`).join("")}</ul></details>
        ${Object.keys(data.unavailable_sources).length ? `<p class="muted">Sources that could not be read this time: ${Object.keys(data.unavailable_sources).map(escapeHtml).join(", ")}.</p>` : ""}${Object.keys(data.problems).length ? `<p class="ps-note">Some framework modules did not load: ${Object.entries(data.problems).map(([k, v]) => `${escapeHtml(k)} (${escapeHtml(v)})`).join(", ")}.</p>` : ""}`;
    } else {
      const f = fws.find((x) => x.id === active);
      body = `<div class="ps-filter">${[["all", "All"], ["gaps", "Gaps and partial"], ["fail", "Gaps"], ["unknown", "Not observable"], ["pass", "Pass"]].map(([v, l]) => `<button type="button" class="ps-f${filter === v ? " ps-f-on" : ""}" data-filter="${v}">${l}</button>`).join("")}</div>${f ? frameworkHtml(f, filter) : "<p>Unknown framework.</p>"}`;
    }
    root.innerHTML = `<div class="ps-tabs" role="tablist">${tabs.map(([id, name]) => `<button type="button" role="tab" class="ps-tab${id === active ? " ps-tab-on" : ""}" aria-selected="${id === active}" data-fw="${escapeHtml(id)}">${escapeHtml(name)}</button>`).join("")}</div><div class="ps-main">${body}</div>`;
  }
  root.addEventListener("click", (ev) => {
    const fw = ev.target.closest("[data-fw]");
    if (fw) { active = fw.getAttribute("data-fw"); filter = "all"; draw(); window.scrollTo({ top: 0 }); return; }
    const fl = ev.target.closest("[data-filter]");
    if (fl) { filter = fl.getAttribute("data-filter"); draw(); }
  });
  draw();
}
