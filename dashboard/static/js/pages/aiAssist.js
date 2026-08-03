import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "AI Assist";

async function loadFindingOptions() {
  const [remediate, vulnhunt] = await Promise.all([api.remediate(), api.vulnhunt()]);
  const remediationOptions = remediate.findings.map((f) => ({ id: f.id, label: `${f.id} - ${f.title}` }));
  const codeOptions = (vulnhunt.available ? vulnhunt.findings : []).map((f) => ({ id: f.ID, label: `${f.ID} - ${f.Title}` }));
  return [...remediationOptions, ...codeOptions];
}

export async function render(container) {
  container.innerHTML = `<div class="empty-state">Loading findings…</div>`;
  const options = await loadFindingOptions();
  const preselect = new URLSearchParams(window.location.search).get("finding_id") || (options[0] && options[0].id) || "";

  container.innerHTML = `
    <p class="subtitle">Ask Claude to explain a finding, draft remediation guidance, or
    write an executive summary - grounded in this finding's real data.</p>
    <div class="callout callout-warn">
      ⚠️ Asking for real (checking confirm) calls the real Claude API and spends real
      usage/credits against your Claude plan. Preview first - it's free and shows the
      exact prompt that would be sent, same pattern as Run Pipeline and ServiceNow.
    </div>

    <form class="run-form" id="ai-form">
      <label>Finding
        <select name="finding_id">
          ${options.map((o) => `<option value="${escapeHtml(o.id)}" ${o.id === preselect ? "selected" : ""}>${escapeHtml(o.label)}</option>`).join("")}
        </select>
      </label>
      <label>What should the AI do?
        <select name="action">
          <option value="explain">Explain this finding in plain English</option>
          <option value="remediate">Draft remediation steps</option>
          <option value="summarize">Write an executive summary</option>
        </select>
      </label>
      <label class="checkbox-label checkbox-danger">
        <input type="checkbox" name="confirm">
        I understand this spends real API usage/credits - actually ask the AI (leave
        unchecked to preview the prompt only, free, no call made)
      </label>
      <button type="submit">Ask</button>
    </form>

    <div id="ai-result"></div>`;

  const form = container.querySelector("#ai-form");
  const resultEl = container.querySelector("#ai-result");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = {
      finding_id: form.finding_id.value,
      action: form.action.value,
      confirm: form.confirm.checked,
    };
    resultEl.innerHTML = `<div class="empty-state">${body.confirm ? "Asking Claude - this calls the real API and can take a little while…" : "Building preview…"}</div>`;
    try {
      const result = await api.aiAssist(body);
      if (result.dry_run) {
        resultEl.innerHTML = `
          <h2>Prompt preview (nothing sent, no cost)</h2>
          <pre class="code-block">${escapeHtml(result.prompt)}</pre>`;
        flash(result.message, "info");
      } else {
        resultEl.innerHTML = `
          <h2>AI response</h2>
          <div class="callout">${escapeHtml(result.response).replaceAll("\n", "<br>")}</div>
          <h2>Prompt sent</h2>
          <pre class="code-block">${escapeHtml(result.prompt)}</pre>`;
        flash("AI response received.", "success");
      }
    } catch (err) {
      resultEl.innerHTML = "";
      flash(err.message, "error");
    }
  });
}
