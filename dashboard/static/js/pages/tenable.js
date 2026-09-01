// Tenable.io - a PULL connector: it fetches vulnerability data FROM Tenable, the
// opposite direction of the ServiceNow/Jira/Splunk integrations. Unlike those push
// connectors, there's nothing to "preview" without first calling a real API - so this
// page offers a real Test Connection (a cheap, immediate credential check) and a real
// Fetch (a live export write to remediation/live-data/), not a payload preview.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Tenable.io";

export async function render(container) {
  container.innerHTML = `
    <p class="subtitle">A pull connector for Tenable.io's Vulnerability Export API - the
    CVE-scoped host-vulnerability source this dashboard's own findings can come from.
    Test your credentials, then fetch a live export.</p>

    <div class="callout callout-warn">
      ⚠️ This connector has never been exercised against a real Tenable.io tenant — no
      credentials were available while building it. It implements the documented
      asynchronous Vulnerability Export API contract and is unit-tested against mocked
      HTTP responses shaped like that documentation. Verify field names against your
      tenant's current API version before trusting live output at scale - see
      <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/docs/INTEGRATIONS.md" target="_blank" rel="noopener">docs/INTEGRATIONS.md</a>.
    </div>

    <h2>What it does</h2>
    <ol>
      <li>Requests an export job (<code>POST /vulns/export</code>) and polls it until it finishes</li>
      <li>Downloads every chunk and flattens each record into the same CSV shape <code>vuln-ingest-normalizer.md</code> already reads</li>
    </ol>

    <div class="callout">
      Tenable's real asset-type classification (windows-server vs. unix-server vs. ...)
      needs judgment against free-text OS fields - that's why Fetch below writes a raw
      export file rather than findings this dashboard shows immediately. Bringing it into
      this dashboard's own pages still needs one more, agent-driven step: run
      <code>/remediate remediation/live-data/tenable_export.csv</code> in an interactive
      Claude Code session, then reload. See
      <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/docs/GOING_LIVE.md" target="_blank" rel="noopener">docs/GOING_LIVE.md</a>
      for exactly why that step is agent-driven, not a plain script.
    </div>

    <h2>Connect</h2>
    <form class="run-form" id="tenable-form">
      <label>Access key (Tenable.io → Settings → My Account → API Keys)
        <input type="text" name="access_key" autocomplete="off"></label>
      <label>Secret key<input type="password" name="secret_key" autocomplete="off"></label>
      <button type="button" class="secondary-button" id="test-btn">Test Connection</button>
      <label class="checkbox-label checkbox-danger">
        <input type="checkbox" name="confirm">
        I have real credentials and want to fetch a live Tenable vulnerability export now
        (a real async export job - can take several minutes for a large tenant)
      </label>
      <button type="submit">Fetch Live Data</button>
    </form>
    <div id="tenable-result"></div>`;

  const form = container.querySelector("#tenable-form");
  const resultEl = container.querySelector("#tenable-result");

  container.querySelector("#test-btn").addEventListener("click", async () => {
    try {
      const result = await api.tenableTestConnection({
        access_key: form.access_key.value.trim(),
        secret_key: form.secret_key.value,
      });
      flash(result.message, "success");
    } catch (err) {
      flash(err.message, "error");
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = {
      access_key: form.access_key.value.trim(),
      secret_key: form.secret_key.value,
      confirm: form.confirm.checked,
    };
    try {
      const result = await api.tenableFetch(body);
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
