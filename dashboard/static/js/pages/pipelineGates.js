// Pipeline gates: the release gate a CI job calls before shipping. The policy (remediation/config/pipeline_gates.yaml), an on-demand evaluation for any
// application, its recorded history, and the step to paste into a pipeline.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Pipeline Gates";

const MODE = { block: "badge-critical", warn: "badge-medium", off: "badge-outline" };
const RULE_STATUS = { pass: ["decision-pass", "pass"], warn: ["decision-warn", "warn"], fail: ["decision-fail", "fail"], skipped: ["muted", "not checked"] };

export async function render(container) {
  let app = new URLSearchParams(window.location.search).get("app") || "";
  let snippet = "github-actions";
  let result = null;

  async function show() {
    const info = await api.gateInfo(app);
    const envs = Object.keys(info.policy.environments);
    const rules = info.policy.rules;
    container.innerHTML = `<p class="subtitle">The release gate. A CI job asks Quanta whether an application may ship, and gets <strong>pass</strong>, <strong>warn</strong> or <strong>fail</strong> with the reasons. The gate judges what Quanta has been told: findings, the scans that were uploaded and the stored SBOM. A scan that never ran is reported, not assumed clean. Policy version <code>${escapeHtml(info.version)}</code>.</p>
      <h3>Try it</h3>
      <form id="gf" class="run-form"><div class="form-grid"><label>Application<input name="app" list="apps" value="${escapeHtml(app)}" required><datalist id="apps">${info.applications.map((a) => `<option value="${escapeHtml(a)}">`).join("")}</datalist></label>
        <label>Environment<select name="env">${envs.map((e) => `<option${e === info.policy.default_environment ? " selected" : ""}>${escapeHtml(e)}</option>`).join("")}</select></label></div>
        <p><button type="submit" class="btn-primary">Evaluate</button> <span class="muted">Each evaluation is recorded below.</span></p></form>
      <div id="out">${result ? resultHtml(result) : ""}</div>
      <h3>Policy</h3>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Rule</th>${envs.map((e) => `<th>${escapeHtml(e)}</th>`).join("")}</tr></thead><tbody>
      ${Object.entries(rules).map(([k, r]) => `<tr><td class="wrap-cell"><strong>${escapeHtml(r.title)}</strong><br><span class="muted">${escapeHtml(describe(k, r))}</span></td>${envs.map((e) => { const m = info.policy.environments[e][k] || "off"; return `<td><span class="badge ${MODE[m]}">${escapeHtml(m)}</span></td>`; }).join("")}</tr>`).join("")}</tbody></table></div>
      <p class="muted"><code>block</code> fails the job, <code>warn</code> lets it pass with a warning, <code>off</code> is not checked. A finding with an approved exception is not counted. Edit <code>remediation/config/pipeline_gates.yaml</code>; it is read on every evaluation.</p>
      <h3>Add it to a pipeline</h3>
      <p class="muted">Create an API key with the <code>read:findings</code> scope (Admin &rarr; API keys), store it as the secret <code>QUANTA_API_KEY</code>, and add the step. The job fails only on <strong>fail</strong>. Pin any third-party action you add to a commit you have reviewed.</p>
      <p class="tab-row">${["github-actions", "gitlab-ci", "shell"].map((k) => `<button type="button" class="secondary-button${k === snippet ? " active" : ""}" data-snip="${k}">${k === "github-actions" ? "GitHub Actions" : k === "gitlab-ci" ? "GitLab CI" : "Shell"}</button>`).join(" ")}</p>
      <pre class="diff-view">${escapeHtml(info.snippets[snippet])}</pre>
      <h3>History${app ? ` for ${escapeHtml(app)}` : ""}</h3>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>When</th><th>Application</th><th>Environment</th><th>Decision</th><th>Called by</th></tr></thead><tbody>
      ${info.history.length ? info.history.map((h) => `<tr><td class="nowrap">${escapeHtml(h.evaluated_at.slice(0, 16).replace("T", " "))}</td><td>${escapeHtml(h.application)}</td><td>${escapeHtml(h.environment)}</td><td><span class="decision-${escapeHtml(h.decision)}">${escapeHtml(h.decision)}</span></td><td>${escapeHtml(h.evaluated_by || "")}</td></tr>`).join("") : '<tr><td colspan="5" class="empty-state">No evaluation has been recorded yet.</td></tr>'}</tbody></table></div>`;
    container.querySelector("#gf").addEventListener("submit", async (e) => {
      e.preventDefault();
      app = e.target.elements.app.value.trim();
      try { result = await api.gateEvaluate({ application: app, environment: e.target.elements.env.value }); await show(); } catch (err) { flash(err.message, "error"); }
    });
    container.querySelectorAll("[data-snip]").forEach((b) => b.addEventListener("click", () => { snippet = b.dataset.snip; show(); }));
  }

  function describe(k, r) {
    if (k === "open_severity") return "Limits: " + Object.entries(r.limits || {}).map(([s, n]) => `${s} ${n}`).join(", ");
    if (k === "fixable_overdue") return `${r.severity_at_least} or above, fix available, open more than ${r.older_than_days} days`;
    if (k === "required_scans") return `${r.scan_types.join(", ")} within ${r.max_age_days} days`;
    if (k === "sbom") return `Stored within ${r.max_age_days} days`;
    return "";
  }
  function resultHtml(r) {
    return `<div class="callout"><strong>${escapeHtml(r.application)}</strong> in ${escapeHtml(r.environment)}${r.requested_environment && r.requested_environment !== r.environment ? ` (asked for ${escapeHtml(r.requested_environment)}, not in the policy)` : ""}: <span class="decision-${escapeHtml(r.decision)}">${escapeHtml(r.decision.toUpperCase())}</span>
      ${r.application_known ? "" : '<br><span class="muted">This application has no record in Quanta, so its environment and SBOM are unknown.</span>'}</div>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>Rule</th><th>Result</th><th>Why</th></tr></thead><tbody>
      ${r.rules.map((x) => `<tr><td>${escapeHtml(x.title)}<br><span class="badge ${MODE[x.mode]}">${escapeHtml(x.mode)}</span></td><td class="${RULE_STATUS[x.status][0]}">${RULE_STATUS[x.status][1]}</td><td class="wrap-cell">${escapeHtml(x.detail)}${x.finding_ids.length ? `<br><span class="muted">${x.finding_ids.slice(0, 8).map(escapeHtml).join(", ")}${x.finding_ids.length > 8 ? ", ..." : ""}</span>` : ""}</td></tr>`).join("")}</tbody></table></div>
      <p class="muted">${escapeHtml(r.note)}</p>`;
  }
  try { await show(); } catch (err) { container.innerHTML = `<p class="callout callout-warn">${escapeHtml(err.message)}</p>`; }
}
