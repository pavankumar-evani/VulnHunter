// Cyber Risk: risk in money. A scorecard (cyber health with its domains on a radar and, once there are earlier readings in this browser, a trend), loss by scenario,
// the scenario builder and the Monte Carlo analysis with an exceedance curve. The numbers are the user's estimates; Quanta does the arithmetic.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";
import { chip, toast, emptyState, onCleanup, dataAgeBadge, mountDataAge } from "../ui.js";
import { kpiStrip, tabBar, wireTabBar, radarSvg, meter, pageActions, readJson, writeJson, replaceSearch } from "../mxKit.js";
import { pushReading, readingSeries, scoreTone } from "../moduleLogic.js";

export const title = "Cyber Risk";
const HIST_KEY = "quanta.cyberrisk.history";

// Loss against the chance of a year being at least that bad: the curve behind "one year in ten". x = loss, y = probability (log-ish feel is not needed; it is a plain plot).
function exceedanceSvg(points, currency, tolerance) {
  const pts = points.filter((p) => Number.isFinite(p.loss) && Number.isFinite(p.probability));
  if (pts.length < 2) return "";
  const W = 520, H = 190, L = 54, R = 12, T = 12, B = 30;
  const maxLoss = Math.max(...pts.map((p) => p.loss), tolerance || 0) || 1;
  const x = (loss) => L + ((W - L - R) * loss) / maxLoss;
  const y = (prob) => T + (H - T - B) * (1 - prob);
  const line = pts.slice().sort((a, b) => a.loss - b.loss).map((p) => `${x(p.loss).toFixed(1)},${y(p.probability).toFixed(1)}`).join(" ");
  const fmtMoney = (n) => new Intl.NumberFormat(undefined, { style: "currency", currency, notation: "compact", maximumFractionDigits: 1 }).format(n);
  return `<svg class="mx-curve" viewBox="0 0 ${W} ${H}" role="img" aria-label="Chance of a year at least this bad, by loss. ${pts.map((p) => `${Math.round(p.probability * 100)} percent chance of ${fmtMoney(p.loss)} or more`).join("; ")}">
    ${[0, 0.25, 0.5, 0.75, 1].map((f) => `<line x1="${L}" x2="${W - R}" y1="${y(f).toFixed(1)}" y2="${y(f).toFixed(1)}" class="mx-radar-ring"/><text x="${L - 6}" y="${y(f).toFixed(1)}" text-anchor="end" dominant-baseline="middle" class="mx-radar-t">${Math.round(f * 100)}%</text>`).join("")}
    ${[0, 0.5, 1].map((f) => `<text x="${(L + (W - L - R) * f).toFixed(1)}" y="${H - 8}" text-anchor="${f === 0 ? "start" : f === 1 ? "end" : "middle"}" class="mx-radar-t">${fmtMoney(maxLoss * f)}</text>`).join("")}
    ${tolerance ? `<line x1="${x(tolerance).toFixed(1)}" x2="${x(tolerance).toFixed(1)}" y1="${T}" y2="${H - B}" class="mx-curve-tol"/><text x="${(x(tolerance) + 4).toFixed(1)}" y="${T + 10}" class="mx-radar-t">tolerance</text>` : ""}
    <polyline points="${line}" fill="none" class="mx-curve-line"/>${pts.map((p) => `<circle cx="${x(p.loss).toFixed(1)}" cy="${y(p.probability).toFixed(1)}" r="3" class="mx-radar-dot"/>`).join("")}</svg>`;
}

const TABS = [["overview", "Overview"], ["scenarios", "Scenarios"], ["analysis", "Analysis"]];
const NOTE = "Risk in money. Describe a loss scenario with a low, likely and high estimate of how often it happens and what each event costs, and Quanta simulates thousands of years to show the average and the bad-year loss, and which treatment is worth paying for. The numbers are your estimates; Quanta does the arithmetic.";

const money = (n, cur = "USD") => (n === null || n === undefined ? "-" : new Intl.NumberFormat(undefined, { style: "currency", currency: cur, maximumFractionDigits: 0 }).format(n));
const pct = (x) => (x === null || x === undefined ? "-" : Math.round(x * 100) + "%");

export async function render(container) {
  let tab = new URLSearchParams(window.location.search).get("tab") || "overview";
  let draft = null;
  let analysisId = null;
  let alive = true;
  onCleanup(() => { alive = false; });

  const shell = (inner) => {
    if (!alive) return;
    container.innerHTML = `<div class="sx-page mx-page"><div class="sx-head"><div><h2>Cyber risk</h2><p>${NOTE}</p></div><div class="sx-row"><span id="cr-age">${dataAgeBadge(Date.now(), { fresh: 300000, stale: 3600000 })}</span></div></div>
      ${tabBar("Cyber risk sections", TABS.map(([id, label]) => ({ id, label })), tab)}<div id="risk-body">${inner}</div></div>`;
    wireTabBar(container.querySelector(".mx-tabs"), (id) => { tab = id; replaceSearch(id === "overview" ? "" : `?tab=${id}`); show(); });
    mountDataAge(container);
  };
  onCleanup(() => {});
  pageActions([{ label: "Cyber risk: add a scenario", icon: "risk", run: () => { tab = "scenarios"; draft = null; show(); } }, { label: "Cyber risk: show the overview", icon: "risk", run: () => { tab = "overview"; show(); } }, { label: "Cyber risk: show the analysis", icon: "risk", run: () => { tab = "analysis"; show(); } }]);
  const bar = (v, max, color = "var(--brand-accent)") => `<div style="background:rgba(255,255,255,.08);border-radius:3px;height:10px;width:100%"><div style="background:${color};height:10px;border-radius:3px;width:${max ? Math.max(2, Math.round((100 * v) / max)) : 0}%"></div></div>`;

  async function overview() {
    const o = await api.cyberRiskOverview();
    const h = o.health, p = o.portfolio, cur = p.currency;
    const top = p.scenarios[0] ? p.scenarios[0].ale : 0;
    const S_hist = pushReading(readJson(HIST_KEY, []), { health: h.score, ale: p.total_ale }); writeJson(HIST_KEY, S_hist);
    const hs = readingSeries(S_hist, (r) => r.health); const as = readingSeries(S_hist, (r) => r.ale);
    const measured = h.domains.filter((d) => d.score !== null);
    shell(`<div id="cr-kpis" class="sx-kpis mx-kpis"></div>
      ${p.within_appetite === false ? `<div class="mx-callout mx-callout-warn">The expected yearly loss is above your appetite. Open a scenario's Analysis to see which treatment is worth paying for.</div>` : ""}
      <div class="mx-hero"><div class="mx-hero-score mx-tone-${scoreTone(h.score)}"><span class="ui-kpi-label">Cyber health</span><div class="mx-score">${h.score === null ? "n/a" : h.score}</div>${chip(h.score === null ? "not measured" : h.score >= 70 ? "healthy" : h.score >= 40 ? "needs work" : "weak", { tone: h.score === null ? "neutral" : h.score >= 70 ? "good" : h.score >= 40 ? "warn" : "critical" })}
          <p class="ui-muted mx-sub">${measured.length} of ${h.domains.length} domains could be measured.${hs.values.length < 2 ? " A trend appears after a second reading in this browser." : ""}</p></div>
        <div class="mx-hero-radar">${radarSvg(measured.map((d) => ({ label: d.label, value: d.score / 100 })), { size: 300, label: "Cyber health by domain" }) || '<p class="ui-muted">The radar needs at least three measured domains.</p>'}</div></div>
      <h3 class="mx-h3">Cyber health by domain</h3>
      <div class="mx-areas">${h.domains.map((d) => `<div class="mx-area"><span>${escapeHtml(d.label)} <span class="ui-muted mx-sub">weight ${d.weight}</span></span>${d.score === null ? '<span class="ui-muted mx-sub">not measured</span>' : meter(d.score / 100, { tone: d.score >= 80 ? "" : d.score >= 50 ? "warn" : "bad", label: `${d.label}: ${d.score}` })}<b>${d.score === null ? "-" : d.score}</b><span class="ui-muted mx-sub" title="${escapeHtml(d.basis.join("; "))}">${escapeHtml(d.basis.join("; ").slice(0, 80))}</span></div>`).join("")}</div>
      <p class="muted">${escapeHtml(h.how)}${h.not_measured.length ? " Not measured yet: " + h.not_measured.map(escapeHtml).join(", ") + "." : ""} Collect control evidence on Risk &amp; Compliance and record detection snapshots on Hunting &amp; SOC to fill these in.</p>
      <h3>Loss by scenario</h3>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Scenario</th><th>Average year</th><th></th><th>1 year in 10</th><th>Chance of a loss over tolerance</th><th>Exposure now</th></tr></thead><tbody>
      ${p.scenarios.length ? p.scenarios.map((s) => `<tr><td class="wrap-cell"><strong>${escapeHtml(s.name)}</strong><br><span class="muted">${escapeHtml(s.category)}${s.owner ? " &middot; " + escapeHtml(s.owner) : ""}</span></td><td>${money(s.ale, cur)}</td><td style="width:140px">${bar(s.ale, top)}</td>
        <td>${money(s.p90, cur)}</td><td>${pct(s.prob_over_tolerance)}</td><td class="wrap-cell muted">${s.signals ? escapeHtml(s.signals.reading) : "No asset scope set"}</td></tr>`).join("")
        : '<tr><td colspan="6" class="empty-state">No scenarios yet. Add one on the Scenarios tab.</td></tr>'}</tbody></table></div>
      <p class="muted">${escapeHtml(p.note)} ${p.trials.toLocaleString()} simulated years per scenario.</p>`);
    kpiStrip(container.querySelector("#cr-kpis"), [
      { key: "health", label: "Cyber health", value: h.score === null ? "n/a" : h.score, filterable: false, tone: h.score === null ? "" : h.score >= 70 ? "good" : h.score >= 40 ? "warn" : "danger", previous: hs.previous ?? undefined, spark: hs.values.length > 1 ? hs.values : undefined, goodWhen: "up", hint: "Control-test results and detection health, weighted. Domains that are not measured are listed, not counted." },
      { key: "ale", label: "Expected yearly loss", value: Math.round(p.total_ale), suffix: ` ${cur}`, filterable: false, previous: as.previous ?? undefined, spark: as.values.length > 1 ? as.values : undefined, goodWhen: "down", hint: "The average year across all active scenarios, from the simulation." },
      { key: "appetite", label: "Risk appetite", value: Math.round(p.appetite), suffix: ` ${cur}`, filterable: false, tone: p.within_appetite === false ? "danger" : "good", hint: "The yearly loss you said you can live with. Red when the expected loss is above it." },
      { key: "scn", label: "Active scenarios", value: p.scenarios.length, filterable: false },
    ], () => {});
  }

  const blank = (cats) => ({ id: null, name: "", description: "", asset_scope: "", category: cats[0], tef_min: "", tef_likely: "", tef_max: "", loss_min: "", loss_likely: "", loss_max: "", options: [], status: "active", owner: "" });

  async function scenarios() {
    const { scenarios: ss, categories, policy } = await api.cyberRiskScenarios();
    if (draft) return builder(categories);
    shell(`<div class="table-scroll"><table class="data-table"><thead><tr><th>Scenario</th><th>Events a year (low / likely / high)</th><th>Loss per event</th><th>Status</th><th></th></tr></thead><tbody>
      ${ss.length ? ss.map((s) => `<tr><td class="wrap-cell"><strong>${escapeHtml(s.name)}</strong><br><span class="muted">${escapeHtml(s.category)} &middot; ${escapeHtml(s.asset_scope || "no asset scope")}</span></td>
        <td>${s.tef_min} / ${s.tef_likely} / ${s.tef_max}</td><td>${money(s.loss_min, policy.currency)} / ${money(s.loss_likely, policy.currency)} / ${money(s.loss_max, policy.currency)}</td><td>${escapeHtml(s.status)}</td>
        <td><button type="button" class="link-button" data-an="${s.id}">Analyse</button> <button type="button" class="link-button" data-edit="${s.id}">Edit</button> <button type="button" class="link-button danger-link" data-del="${s.id}">Delete</button></td></tr>`).join("")
        : '<tr><td colspan="5" class="empty-state">No scenarios yet.</td></tr>'}</tbody></table></div>
      <p><button type="button" id="new">Add a scenario</button></p>`);
    container.querySelector("#new").addEventListener("click", () => { draft = blank(categories); show(); });
    container.querySelectorAll("[data-an]").forEach((b) => b.addEventListener("click", () => { analysisId = Number(b.dataset.an); tab = "analysis"; show(); }));
    container.querySelectorAll("[data-edit]").forEach((b) => b.addEventListener("click", () => { draft = JSON.parse(JSON.stringify(ss.find((x) => x.id === Number(b.dataset.edit)))); show(); }));
    container.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", async () => { if (window.confirm("Delete this scenario?")) { try { await api.cyberRiskDelete(Number(b.dataset.del)); show(); } catch (e) { flash(e.message, "error"); } } }));
  }

  function builder(categories) {
    const d = draft;
    const num = (name, label, ph) => `<label>${label} <input name="${name}" type="number" step="any" min="0" value="${d[name]}" placeholder="${ph || ""}" required></label>`;
    shell(`<form id="sf" class="run-form"><label>Name <input name="name" value="${escapeHtml(d.name)}" required maxlength="160" placeholder="Ransomware on the file estate"></label>
      <label>Description <input name="description" value="${escapeHtml(d.description || "")}"></label>
      <label>Category <select name="category">${categories.map((c) => `<option${d.category === c ? " selected" : ""}>${c}</option>`).join("")}</select></label>
      <label>Assets in scope (names or patterns, comma separated) <input name="asset_scope" value="${escapeHtml(d.asset_scope || "")}" placeholder="FS-*, NAS-01"></label>
      <label>Owner <input name="owner" value="${escapeHtml(d.owner || "")}"></label>
      <h3>How often (events a year)</h3>
      <p class="muted">For example 0.1 is once in ten years, 2 is twice a year.</p>
      ${num("tef_min", "Low")} ${num("tef_likely", "Most likely")} ${num("tef_max", "High")}
      <h3>What each event costs</h3>
      ${num("loss_min", "Low")} ${num("loss_likely", "Most likely")} ${num("loss_max", "High")}
      <h3>Treatment options</h3>
      <p class="muted">What you could do about it: the yearly cost, and the share it cuts from how often it happens and from what it costs (0.4 is 40%).</p>
      ${d.options.map((o, i) => `<div class="muted">Option ${i + 1}: <input data-o="${i}:name" value="${escapeHtml(o.name)}" placeholder="name" size="20"> cost <input data-o="${i}:annual_cost" type="number" min="0" step="any" value="${o.annual_cost}" size="10">
        less often <input data-o="${i}:frequency_reduction" type="number" min="0" max="1" step="0.05" value="${o.frequency_reduction}" size="5"> cheaper <input data-o="${i}:loss_reduction" type="number" min="0" max="1" step="0.05" value="${o.loss_reduction}" size="5">
        <button type="button" class="link-button danger-link" data-rmo="${i}">Remove</button></div>`).join("")}
      <p><button type="button" class="secondary-button" id="addo">Add an option</button></p>
      <div><button type="submit">Save scenario</button> <button type="button" class="secondary-button" id="cancel">Cancel</button> <button type="button" class="secondary-button" id="whatif">Simulate without saving</button></div>
      <div id="whatif-out"></div></form>`);
    const sync = () => {
      const f = container.querySelector("#sf");
      for (const k of ["name", "description", "category", "asset_scope", "owner", "tef_min", "tef_likely", "tef_max", "loss_min", "loss_likely", "loss_max"]) d[k] = f[k].value;
      container.querySelectorAll("[data-o]").forEach((el) => { const [i, k] = el.dataset.o.split(":"); d.options[Number(i)][k] = k === "name" ? el.value : Number(el.value); });
    };
    const payload = () => ({ ...d, tef_min: Number(d.tef_min), tef_likely: Number(d.tef_likely), tef_max: Number(d.tef_max), loss_min: Number(d.loss_min), loss_likely: Number(d.loss_likely), loss_max: Number(d.loss_max), owner: d.owner || null });
    container.querySelector("#addo").addEventListener("click", () => { sync(); d.options.push({ name: "", annual_cost: 0, frequency_reduction: 0, loss_reduction: 0 }); builder(categories); });
    container.querySelectorAll("[data-rmo]").forEach((b) => b.addEventListener("click", () => { sync(); d.options.splice(Number(b.dataset.rmo), 1); builder(categories); }));
    container.querySelector("#cancel").addEventListener("click", () => { draft = null; show(); });
    container.querySelector("#whatif").addEventListener("click", async () => {
      sync();
      try {
        const r = await api.cyberRiskSimulate(payload());
        container.querySelector("#whatif-out").innerHTML = `<p>Average year <strong>${money(r.baseline.ale)}</strong>, one year in ten <strong>${money(r.baseline.p90)}</strong>, one in twenty ${money(r.baseline.p95)}.</p>`;
      } catch (e) { flash(e.message, "error"); }
    });
    container.querySelector("#sf").addEventListener("submit", async (e) => {
      e.preventDefault(); sync();
      try { const s = d.id ? await api.cyberRiskUpdate(d.id, payload()) : await api.cyberRiskAdd(payload()); draft = null; analysisId = s.id; tab = "analysis"; flash("Saved.", "success"); show(); } catch (err) { flash(err.message, "error"); }
    });
  }

  async function analysis() {
    const { scenarios: ss } = await api.cyberRiskScenarios();
    if (!analysisId || !ss.find((s) => s.id === analysisId)) analysisId = ss[0] && ss[0].id;
    if (!analysisId) return shell('<p class="empty-state">Add a scenario first.</p>');
    const a = await api.cyberRiskAnalysis(analysisId);
    const b = a.baseline, cur = a.currency, max = b.exceedance[b.exceedance.length - 1].loss || 1;
    shell(`<label>Scenario <select id="pick">${ss.map((s) => `<option value="${s.id}"${s.id === analysisId ? " selected" : ""}>${escapeHtml(s.name)}</option>`).join("")}</select></label>
      <div id="cr-kpis" class="sx-kpis mx-kpis"></div>
      ${a.signals ? `<div class="mx-callout">${escapeHtml(a.signals.reading)} (${a.signals.open_findings} open finding(s) on ${a.signals.assets_with_findings} asset(s); ${a.signals.known_exploited} known-exploited, ${a.signals.past_sla} past their deadline.)</div>` : ""}
      <h3 class="mx-h3">How bad can a year get</h3>
      <div class="mx-hero-radar">${exceedanceSvg(b.exceedance, cur, a.tolerance)}</div>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Chance of a year at least this bad</th><th>Loss</th><th></th></tr></thead><tbody>
      ${b.exceedance.map((e) => `<tr><td>${pct(e.probability)}</td><td>${money(e.loss, cur)}</td><td style="width:240px">${bar(e.loss, max, "#f06a6a")}</td></tr>`).join("")}</tbody></table></div>
      <h3>Treatment options</h3>
      ${a.options.length ? `<div class="table-scroll"><table class="data-table"><thead><tr><th>Option</th><th>Yearly cost</th><th>Average year after</th><th>Loss avoided</th><th>Return</th><th></th></tr></thead><tbody>
        ${a.options.map((o) => `<tr><td>${escapeHtml(o.name)}</td><td>${money(o.annual_cost, cur)}</td><td>${money(o.ale_after, cur)}</td><td>${money(o.loss_avoided, cur)}</td><td>${o.return === null ? "-" : o.return + "x"}</td>
          <td><span class="badge ${o.worth_it ? "badge-low" : "badge-high"}">${o.worth_it ? "worth it" : "costs more than it saves"}</span></td></tr>`).join("")}</tbody></table></div>`
        : '<p class="muted">No options on this scenario. Edit it to add what you could do about it.</p>'}
      <p class="muted">${b.trials.toLocaleString()} simulated years. Return is (loss avoided minus cost) divided by cost.</p>`);
    container.querySelector("#pick").addEventListener("change", (e) => { analysisId = Number(e.target.value); show(); });
    const tile = (key, label, value, extra = {}) => ({ key, label, value, filterable: false, ...extra });
    kpiStrip(container.querySelector("#cr-kpis"), [
      tile("ale", "Average year", Math.round(b.ale), { suffix: ` ${cur}`, hint: "The mean loss over the simulated years." }), tile("p90", "One year in ten", Math.round(b.p90), { suffix: ` ${cur}`, hint: "The loss a bad year reaches or passes once in ten." }),
      tile("p95", "One year in twenty", Math.round(b.p95), { suffix: ` ${cur}` }), tile("tol", `Chance a year exceeds ${money(a.tolerance, cur)}`, Math.round((b.prob_over_tolerance || 0) * 100), { suffix: "%", tone: b.prob_over_tolerance > 0.1 ? "danger" : "good", hint: "Share of simulated years whose loss is above your tolerance." }),
    ], () => {});
  }

  async function show() {
    try { await { overview, scenarios, analysis }[tab](); } catch (err) { shell(emptyState({ title: "This could not be loaded", body: err.message || "Try again in a moment.", iconName: "risk" })); }
  }
  await show();
}
