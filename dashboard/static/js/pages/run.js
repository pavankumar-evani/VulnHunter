import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Run a Pipeline";

export async function render(container) {
  const data = await api.runGet();

  const auditRows = data.audit_log.map((e) => `
    <tr>
      <td>${escapeHtml(e.timestamp)}</td>
      <td>${escapeHtml(e.pipeline)}</td>
      <td>${escapeHtml(e.returncode)}</td>
      <td class="wrap-cell"><code>${escapeHtml(e.command)}</code></td>
    </tr>`).join("");

  container.innerHTML = `
    <div class="callout callout-warn">
      ⚠️ Actually running a pipeline (checking confirm) calls the real Claude API and
      spends real usage/credits against your Claude plan. Preview with dry-run first.
    </div>

    <form class="run-form" id="run-form">
      <label>Pipeline
        <select name="pipeline">
          <option value="scan">/vulnhunt (code scan)</option>
          <option value="remediate">/remediate (infra remediation)</option>
        </select>
      </label>
      <label>Target path (only used for /vulnhunt)
        <input type="text" name="path" value="vulnerable-demo-app"></label>
      <label class="checkbox-label">
        <input type="checkbox" name="fix_or_generate">
        Also apply fixes / generate playbooks (<code>--fix</code> / <code>--generate</code>)
      </label>
      <label>Max spend cap (USD)
        <input type="text" name="max_budget_usd" value="${escapeHtml(data.default_budget)}"></label>
      <label class="checkbox-label checkbox-danger">
        <input type="checkbox" name="confirm">
        I understand this spends real API usage/credits — actually run it (leave unchecked
        for a dry-run preview only)
      </label>
      <button type="submit">Submit</button>
    </form>

    <h2>Recent runs</h2>
    ${data.audit_log.length ? `
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>Timestamp (UTC)</th><th>Pipeline</th><th>Exit Code</th><th>Command</th></tr></thead>
          <tbody>${auditRows}</tbody>
        </table>
      </div>` : `<p class="empty-state">No real runs yet (dry-run previews aren't logged).</p>`}`;

  const form = container.querySelector("#run-form");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = {
      pipeline: form.pipeline.value,
      fix_or_generate: form.fix_or_generate.checked,
      path: form.path.value.trim(),
      max_budget_usd: form.max_budget_usd.value,
      confirm: form.confirm.checked,
    };
    try {
      const result = await api.runPost(body);
      flash(result.message, result.dry_run ? "info" : (result.exit_code === 0 ? "success" : "error"));
    } catch (err) {
      flash(err.message, "error");
    }
  });
}
