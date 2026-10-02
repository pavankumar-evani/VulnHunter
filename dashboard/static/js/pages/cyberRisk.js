import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Cyber Risk";

const TABS = [["overview", "Overview"], ["scenarios", "Scenarios"], ["analysis", "Analysis"]];
const NOTE = "Risk in money. Describe a loss scenario with a low, likely and high estimate of how often it happens and what each event costs, and Quanta simulates thousands of years to show the average and the bad-year loss, and which treatment is worth paying for. The numbers are your estimates; Quanta does the arithmetic.";

const money = (n, cur = "USD") => (n === null || n === undefined ? "-" : new Intl.NumberFormat(undefined, { style: "currency", currency: cur, maximumFractionDigits: 0 }).format(n));
const pct = (x) => (x === null || x === undefined ? "-" : Math.round(x * 100) + "%");

export async function render(container) {
  let tab = new URLSearchParams(window.location.search).get("tab") || "overview";
  let draft = null;
  let analysisId = null;

  const shell = (inner) => {
    container.innerHTML = `<p class="subtitle">${NOTE}</p>
      <p>${TABS.map(([k, l]) => `<button type="button" class="${k === tab ? "" : "secondary-button"}" data-tab="${k}">${l}</button>`).join(" ")}</p><div id="risk-body">${inner}</div>`;
    container.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; show(); }));
  };
  const bar = (v, max, color = "var(--brand-accent)") => `<div style="background:rgba(255,255,255,.08);border-radius:3px;height:10px;width:100%"><div style="background:${color};height:10px;border-radius:3px;width:${max ? Math.max(2, Math.round((100 * v) / max)) : 0}%"></div></div>`;

  async function overview() {
    const o = await api.cyberRiskOverview();
    const h = o.health, p = o.portfolio, cur = p.currency;
    const top = p.scenarios[0] ? p.scenarios[0].ale : 0;
    shell(`<div class="kpi-grid">
        <div class="kpi-card"><div class="kpi-label">cyber health score</div><div class="kpi-value">${h.score === null ? "-" : h.score}</div></div>
        <div class="kpi-card"><div class="kpi-label">expected yearly loss (all scenarios)</div><div class="kpi-value">${money(p.total_ale, cur)}</div></div>
        <div class="kpi-card ${p.within_appetite === false ? "kpi-danger" : ""}"><div class="kpi-label">risk appetite</div><div class="kpi-value">${money(p.appetite, cur)}</div></div>
        <div class="kpi-card"><div class="kpi-label">active scenarios</div><div class="kpi-value">${p.scenarios.length}</div></div>
      </div>
      ${p.within_appetite === false ? `<p class="callout callout-warn">The expected yearly loss is above your appetite. Open a scenario's Analysis to see which treatment is worth paying for.</p>` : ""}
      <h3>Cyber health</h3>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Domain</th><th>Score</th><th></th><th>Based on</th></tr></thead><tbody>
      ${h.domains.map((d) => `<tr><td>${escapeHtml(d.label)} <span class="muted">(weight ${d.weight})</span></td><td>${d.score === null ? '<span class="muted">not measured</span>' : d.score}</td><td style="width:160px">${d.score === null ? "" : bar(d.score, 100, d.score >= 80 ? "#3fd0b6" : d.score >= 50 ? "#f0b44c" : "#f06a6a")}</td>
        <td class="wrap-cell muted">${d.basis.map(escapeHtml).join("; ")}</td></tr>`).join("")}</tbody></table></div>
      <p class="muted">${escapeHtml(h.how)}${h.not_measured.length ? " Not measured yet: " + h.not_measured.map(escapeHtml).join(", ") + "." : ""} Collect control evidence on Risk &amp; Compliance and record detection snapshots on Hunting &amp; SOC to fill these in.</p>
      <h3>Loss by scenario</h3>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Scenario</th><th>Average year</th><th></th><th>1 year in 10</th><th>Chance of a loss over tolerance</th><th>Exposure now</th></tr></thead><tbody>
      ${p.scenarios.length ? p.scenarios.map((s) => `<tr><td class="wrap-cell"><strong>${escapeHtml(s.name)}</strong><br><span class="muted">${escapeHtml(s.category)}${s.owner ? " &middot; " + escapeHtml(s.owner) : ""}</span></td><td>${money(s.ale, cur)}</td><td style="width:140px">${bar(s.ale, top)}</td>
        <td>${money(s.p90, cur)}</td><td>${pct(s.prob_over_tolerance)}</td><td class="wrap-cell muted">${s.signals ? escapeHtml(s.signals.reading) : "No asset scope set"}</td></tr>`).join("")
        : '<tr><td colspan="6" class="empty-state">No scenarios yet. Add one on the Scenarios tab.</td></tr>'}</tbody></table></div>
      <p class="muted">${escapeHtml(p.note)} ${p.trials.toLocaleString()} simulated years per scenario.</p>`);
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
      <div class="kpi-grid"><div class="kpi-card"><div class="kpi-label">average year</div><div class="kpi-value">${money(b.ale, cur)}</div></div>
        <div class="kpi-card"><div class="kpi-label">one year in ten</div><div class="kpi-value">${money(b.p90, cur)}</div></div>
        <div class="kpi-card"><div class="kpi-label">one year in twenty</div><div class="kpi-value">${money(b.p95, cur)}</div></div>
        <div class="kpi-card ${b.prob_over_tolerance > 0.1 ? "kpi-danger" : ""}"><div class="kpi-label">chance a year exceeds ${money(a.tolerance, cur)}</div><div class="kpi-value">${pct(b.prob_over_tolerance)}</div></div></div>
      ${a.signals ? `<p class="callout">${escapeHtml(a.signals.reading)} (${a.signals.open_findings} open finding(s) on ${a.signals.assets_with_findings} asset(s); ${a.signals.known_exploited} known-exploited, ${a.signals.past_sla} past their deadline.)</p>` : ""}
      <h3>How bad can a year get</h3>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Chance of a year at least this bad</th><th>Loss</th><th></th></tr></thead><tbody>
      ${b.exceedance.map((e) => `<tr><td>${pct(e.probability)}</td><td>${money(e.loss, cur)}</td><td style="width:240px">${bar(e.loss, max, "#f06a6a")}</td></tr>`).join("")}</tbody></table></div>
      <h3>Treatment options</h3>
      ${a.options.length ? `<div class="table-scroll"><table class="data-table"><thead><tr><th>Option</th><th>Yearly cost</th><th>Average year after</th><th>Loss avoided</th><th>Return</th><th></th></tr></thead><tbody>
        ${a.options.map((o) => `<tr><td>${escapeHtml(o.name)}</td><td>${money(o.annual_cost, cur)}</td><td>${money(o.ale_after, cur)}</td><td>${money(o.loss_avoided, cur)}</td><td>${o.return === null ? "-" : o.return + "x"}</td>
          <td><span class="badge ${o.worth_it ? "badge-low" : "badge-high"}">${o.worth_it ? "worth it" : "costs more than it saves"}</span></td></tr>`).join("")}</tbody></table></div>`
        : '<p class="muted">No options on this scenario. Edit it to add what you could do about it.</p>'}
      <p class="muted">${b.trials.toLocaleString()} simulated years. Return is (loss avoided minus cost) divided by cost.</p>`);
    container.querySelector("#pick").addEventListener("change", (e) => { analysisId = Number(e.target.value); show(); });
  }

  async function show() {
    try { await { overview, scenarios, analysis }[tab](); } catch (err) { shell(`<p class="callout callout-warn">${escapeHtml(err.message)}</p>`); }
  }
  await show();
}
