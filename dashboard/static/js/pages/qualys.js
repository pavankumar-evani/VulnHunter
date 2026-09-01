// Qualys VMDR - a PULL connector, same shape as tenable.js: Test Connection (a cheap,
// immediate credential check) and Fetch (a live host-detection export write to
// remediation/live-data/), not a payload preview.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Qualys VMDR";

export async function render(container) {
  container.innerHTML = `
    <p class="subtitle">A pull connector for Qualys VMDR's host-detection VM API - the
    other major CVE-scoped host-vulnerability source alongside Tenable. Test your
    credentials, then fetch a live export.</p>

    <div class="callout callout-warn">
      ⚠️ This connector has never been exercised against a real Qualys subscription — no
      credentials were available while building it. It implements the documented VM API
      (XML) host-detection + knowledge-base contract and is unit-tested against mocked
      HTTP responses shaped like that documentation. Verify field names against your
      pod's actual XML response before trusting live output at scale - see
      <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/docs/INTEGRATIONS.md" target="_blank" rel="noopener">docs/INTEGRATIONS.md</a>.
    </div>

    <h2>What it does</h2>
    <ol>
      <li>Fetches host detections (<code>GET .../vm/detection/</code>, XML, paginated via <code>id_min</code>)</li>
      <li>Resolves every QID seen to a CVE/title/severity via the knowledge base (<code>GET .../knowledge_base/vuln/</code>)</li>
      <li>Flattens the result into <strong>Tenable's exact CSV column shape</strong> - both vendors report the same real-world facts, so no second ingestion format is needed</li>
    </ol>

    <div class="callout">
      Like Tenable, Qualys is a CVE-scoped host-vulnerability source that needs
      judgment-based asset-type classification - that's why Fetch below writes a raw
      export file rather than findings this dashboard shows immediately. Bringing it into
      this dashboard's own pages still needs one more, agent-driven step: run
      <code>/remediate remediation/live-data/qualys_export.csv</code> in an interactive
      Claude Code session, then reload. See
      <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/docs/GOING_LIVE.md" target="_blank" rel="noopener">docs/GOING_LIVE.md</a>.
    </div>

    <h2>Connect</h2>
    <form class="run-form" id="qualys-form">
      <label>Platform URL (Qualys assigns one per subscription/region - e.g. https://qualysapi.qualys.com for US Platform 1)
        <input type="text" name="platform_url" placeholder="https://qualysapi.qualys.com"></label>
      <label>Username<input type="text" name="username" autocomplete="off"></label>
      <label>Password<input type="password" name="password" autocomplete="off"></label>
      <button type="button" class="secondary-button" id="test-btn">Test Connection</button>
      <label class="checkbox-label checkbox-danger">
        <input type="checkbox" name="confirm">
        I have real credentials and want to fetch a live Qualys host-detection export now
      </label>
      <button type="submit">Fetch Live Data</button>
    </form>
    <div id="qualys-result"></div>`;

  const form = container.querySelector("#qualys-form");
  const resultEl = container.querySelector("#qualys-result");

  container.querySelector("#test-btn").addEventListener("click", async () => {
    try {
      const result = await api.qualysTestConnection({
        username: form.username.value.trim(),
        password: form.password.value,
        platform_url: form.platform_url.value.trim(),
      });
      flash(result.message, "success");
    } catch (err) {
      flash(err.message, "error");
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = {
      username: form.username.value.trim(),
      password: form.password.value,
      platform_url: form.platform_url.value.trim(),
      confirm: form.confirm.checked,
    };
    try {
      const result = await api.qualysFetch(body);
      flash(result.message, result.preview_only ? "info" : "success");
      resultEl.innerHTML = result.preview_only ? "" : `
        <div class="callout">
          Wrote <strong>${result.count}</strong> row(s) to <code>${escapeHtml(result.written_to)}</code>.
        </div>`;
    } catch (err) {
      flash(err.message, "error");
    }
  });
}
