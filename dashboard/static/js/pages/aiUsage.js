import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";
import { barChartSvg } from "../charts.js";

export const title = "AI Usage";

const fmt = (n) => (n === null || n === undefined ? "-" : Number(n).toLocaleString());
const usd = (n) => `$${Number(n || 0).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
const STATE = { ok: "badge-auto_approvable", alert: "badge-high", exceeded: "badge-critical" };

function table(rows, nameLabel) {
  if (!rows.length) return `<p class="muted">Nothing recorded yet.</p>`;
  return `<div class="table-scroll"><table class="data-table"><thead><tr><th>${escapeHtml(nameLabel)}</th><th>Requests</th><th>Tokens</th><th>Cost</th></tr></thead><tbody>
    ${rows.slice(0, 12).map((r) => `<tr><td>${escapeHtml(r.name)}</td><td>${fmt(r.requests)}</td><td>${fmt(r.tokens)}</td>
      <td>${r.cost_known_requests ? usd(r.cost_usd) : "-"}${r.cost_known_requests && !r.cost_complete ? ` <span class="muted" title="Some requests have no known cost">+ unknown</span>` : ""}</td></tr>`).join("")}</tbody></table></div>`;
}

export async function render(container) {
  let days = 30;
  async function load() {
    const [s, apps] = await Promise.all([api.aiUsageSummary(days), api.aiApps()]);
    const t = s.totals;
    let avoided = null;
    try { avoided = (await api.decisionCalibration()).model_calls_avoided; } catch (e) { avoided = null; }
    container.innerHTML = `
      <p class="subtitle">AI usage across the organization: tokens and spend by team, application and model, budgets, unusual days, and AI tools nobody has reviewed.
      Quanta stores counts only, never prompts or responses.</p>
      <div class="callout ${s.coverage.sources_reporting.length > 1 ? "" : "callout-warn"}"><strong>What this covers.</strong> ${escapeHtml(s.coverage.note)}
        Sources reporting: ${s.coverage.sources_reporting.length ? s.coverage.sources_reporting.map(escapeHtml).join(", ") : "none yet"}.
        Add a provider connection on <a href="/connections" data-link>Connections</a>, send OpenTelemetry or gateway events with an API key, or upload a proxy log below.</div>
      <p><label>Period <select id="days">${[7, 30, 90].map((d) => `<option value="${d}"${d === days ? " selected" : ""}>Last ${d} days</option>`).join("")}</select></label></p>
      <div class="kpi-grid">
        <div class="kpi-card"><div class="kpi-label">tokens</div><div class="kpi-value">${fmt(t.tokens)}</div></div>
        <div class="kpi-card"><div class="kpi-label">requests</div><div class="kpi-value">${fmt(t.requests)}</div></div>
        <div class="kpi-card"><div class="kpi-label">known cost${t.requests_with_unknown_cost ? ` (+ ${fmt(t.requests_with_unknown_cost)} requests of unknown cost)` : ""}</div><div class="kpi-value">${usd(t.cost_usd)}</div></div>
        <div class="kpi-card"><div class="kpi-label">input served from cache</div><div class="kpi-value">${t.cache_hit_pct === null ? "-" : `${t.cache_hit_pct}%`}</div></div>
        ${avoided === null ? "" : `<div class="kpi-card" title="Decisions Quanta's rules made without asking a model (an estimate of calls a model-every-time design would have made)"><div class="kpi-label">model calls avoided by the decision gate</div><div class="kpi-value">${fmt(avoided)}</div></div>`}
      </div>
      ${t.requests_with_unknown_cost ? `<p class="muted">Cost is shown only where the source reported it or you entered a price for the model in <code>ai_pricing.yaml</code>. Requests without either are counted separately, never as zero.</p>` : ""}
      <h2>Tokens per day (millions; the label is the day of the month)</h2>
      ${s.daily.length ? barChartSvg(s.daily.map((d) => ({ label: d.date.slice(8), value: Math.round(d.tokens / 1e5) / 10, detail: `${d.date}: ${fmt(d.tokens)} tokens, ${fmt(d.requests)} requests, ${usd(d.cost_usd)}` })), { width: Math.max(600, s.daily.length * 34), height: 220, barColor: "#6d97f7" }) : `<p class="muted">No usage in this period.</p>`}
      ${s.anomalies.length ? `<div class="callout callout-warn"><strong>Worth a look</strong><ul class="guidance-list">${s.anomalies.map((a) => `<li>${escapeHtml(a.date)}: ${escapeHtml(a.detail)}</li>`).join("")}</ul></div>` : ""}
      ${s.outside_allowed_models && s.outside_allowed_models.length ? `<div class="callout callout-warn"><strong>Models outside the approved list</strong><ul class="guidance-list">${s.outside_allowed_models.map((m) => `<li>${escapeHtml(m.model)}: ${fmt(m.tokens)} tokens in ${fmt(m.requests)} requests</li>`).join("")}</ul></div>` : ""}
      <div class="two-col"><div><h2>By team</h2>${table(s.by_team, "Team")}</div><div><h2>By application</h2>${table(s.by_application, "Application")}</div></div>
      <div class="two-col"><div><h2>By model</h2>${table(s.by_model, "Model")}</div><div><h2>By source</h2>${table(s.by_source, "Source")}</div></div>
      <h2>Top users</h2>${table(s.top_users, "User")}

      <h2>Budgets</h2>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Applies to</th><th>Period</th><th>Limit</th><th>Used</th><th>On track for</th><th>State</th><th></th></tr></thead><tbody>
      ${s.budgets.length ? s.budgets.map((b) => `<tr><td>${b.scope === "org" ? "Whole organization" : `${escapeHtml(b.scope)}: ${escapeHtml(b.scope_value)}`}</td><td>${escapeHtml(b.period)} (${escapeHtml(b.period_start)})</td>
        <td>${[b.limit_usd ? usd(b.limit_usd) : null, b.limit_tokens ? `${fmt(b.limit_tokens)} tokens` : null].filter(Boolean).join(" / ")}</td>
        <td>${b.used_pct}%</td><td>${b.projected_pct}%</td><td><span class="badge ${STATE[b.state]}">${escapeHtml(b.state)}</span></td>
        <td><button type="button" class="link-button danger-link" data-del-budget="${b.id}">Delete</button></td></tr>`).join("") : `<tr><td colspan="7" class="empty-state">No budgets set.</td></tr>`}
      </tbody></table></div>
      <form id="budget-form" class="run-form">
        <label>Applies to <select name="scope"><option value="org">Whole organization</option><option value="team">A team</option><option value="application">An application</option></select></label>
        <label>Team or application name <input name="scope_value" placeholder="only for team / application"></label>
        <label>Period <select name="period"><option value="month">Month</option><option value="week">Week</option><option value="day">Day</option></select></label>
        <label>Limit in US dollars <input name="limit_usd" type="number" min="0" step="0.01"></label>
        <label>Limit in tokens <input name="limit_tokens" type="number" min="0" step="1"></label>
        <label>Warn at (%) <input name="alert_pct" type="number" min="1" max="100" value="80"></label>
        <div><button type="submit">Add budget</button></div>
      </form>

      <h2>AI applications found</h2>
      <p class="muted">Recognised from the proxy, DNS or identity logs you give Quanta (${fmt(apps.known_services)} known AI services). New ones start as <em>unreviewed</em>. Quanta records and reports; it does not block.</p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Application</th><th>Domain</th><th>Users seen</th><th>Requests seen</th><th>Seen in</th><th>Status</th></tr></thead><tbody>
      ${apps.apps.length ? apps.apps.map((a) => `<tr><td>${escapeHtml(a.name)}</td><td><code>${escapeHtml(a.domain)}</code></td><td>${fmt(a.users_seen)}</td><td>${fmt(a.requests_seen)}</td><td>${a.signals.map(escapeHtml).join(", ")}</td>
        <td><select data-app="${a.id}">${["unreviewed", "sanctioned", "blocked"].map((st) => `<option value="${st}"${a.status === st ? " selected" : ""}>${st}</option>`).join("")}</select></td></tr>`).join("")
        : `<tr><td colspan="6" class="empty-state">None found yet. Upload a proxy or DNS export below.</td></tr>`}</tbody></table></div>
      <p><label class="inline-file">Upload a proxy / DNS export (CSV with <code>domain</code>, optional <code>user</code>, <code>count</code>; or any text log) <input type="file" id="disc-file"></label></p>`;

    container.querySelector("#days").addEventListener("change", (e) => { days = Number(e.target.value); load(); });
    container.querySelector("#budget-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const f = e.target;
      const num = (v) => (v === "" ? null : Number(v));
      try {
        await api.aiAddBudget({ scope: f.scope.value, scope_value: f.scope_value.value || null, period: f.period.value, limit_usd: num(f.limit_usd.value),
          limit_tokens: num(f.limit_tokens.value), alert_pct: Number(f.alert_pct.value) });
        flash("Budget added.", "success");
        load();
      } catch (err) { flash(err.message, "error"); }
    });
    container.querySelectorAll("[data-del-budget]").forEach((b) => b.addEventListener("click", async () => {
      try { await api.aiDeleteBudget(Number(b.dataset.delBudget)); load(); } catch (err) { flash(err.message, "error"); }
    }));
    container.querySelectorAll("[data-app]").forEach((sel) => sel.addEventListener("change", async () => {
      try { await api.aiSetApp(Number(sel.dataset.app), { status: sel.value }); flash("Saved.", "success"); } catch (err) { flash(err.message, "error"); }
    }));
    container.querySelector("#disc-file").addEventListener("change", async (e) => {
      if (!e.target.files[0]) return;
      try {
        const r = await api.aiDiscovery(e.target.files[0], "proxy-log");
        flash(`${r.services} AI service(s) found, ${r.new} new.`, "success");
        load();
      } catch (err) { flash(err.message, "error"); }
    });
  }
  await load();
}
