// Cortex XSIAM - a PULL connector, same shape as prismacloud.js: Test Connection and
// Fetch, not a payload preview. Like Prisma Cloud (and unlike Tenable/Qualys), XSIAM
// incidents are correlated detections (not CVE-scoped) that the connector normalizes
// directly - so Fetch here writes already-normalized findings, not a raw export.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Palo Alto Cortex XSIAM";

export async function render(container) {
  container.innerHTML = `
    <p class="subtitle">A pull connector for Cortex XSIAM's incidents API - correlated
    detections across hosts, not CVE-scoped vulnerabilities. A genuinely different
    product from the SOAR-orchestration-focused Cortex XSOAR (reference catalog only, no
    working code). Test your credentials, then fetch live incidents.</p>

    <div class="callout callout-warn">
      ⚠️ This connector has never been exercised against a real Cortex XSIAM tenant — no
      credentials were available while building it. It implements the documented
      "Standard" authentication + incident-search API contract and is unit-tested against
      mocked HTTP responses shaped like that documentation - a separate "Advanced" (HMAC
      request-signature) auth mode exists for tenants that require it, not implemented
      here. See <a href="https://github.com/pavankumar-evani/VulnHunter/blob/master/docs/INTEGRATIONS.md" target="_blank" rel="noopener">docs/INTEGRATIONS.md</a>.
    </div>

    <h2>What it does</h2>
    <ol>
      <li>Authenticates via <code>x-xdr-auth-id</code> + <code>Authorization</code> headers (API Key ID + API Key)</li>
      <li>Fetches incidents (<code>POST .../incidents/get_incidents</code>) and normalizes each directly
        into this dashboard's Finding schema - <code>cve</code>/<code>cvss</code>/<code>kev</code>/<code>epss</code>
        stay <code>null</code> (correlated detections, not known-CVE findings), and
        <code>asset.type</code> stays <code>unknown</code> (an incident can span multiple hosts of mixed/unknown platform)</li>
    </ol>

    <div class="callout">
      Like Prisma Cloud, no asset-type-classification judgment is needed, so Fetch below
      writes fully normalized findings straight to
      <code>remediation/live-data/cortex_xsiam_findings.json</code> - but, like the generic
      ingest adapter's own explicit, disclosed choice, this is deliberately <strong>not</strong>
      auto-merged into the live queue. See
      <a href="https://github.com/pavankumar-evani/VulnHunter/blob/master/docs/INTEGRATIONS.md" target="_blank" rel="noopener">docs/INTEGRATIONS.md</a>
      for why.
    </div>

    <h2>Connect</h2>
    <form class="run-form" id="xsiam-form">
      <label>Base URL (tenant- and region-specific - e.g. https://api-yourfqdn.xdr.us.paloaltonetworks.com)
        <input type="text" name="base_url" placeholder="https://api-yourfqdn.xdr.us.paloaltonetworks.com"></label>
      <label>API key ID<input type="text" name="api_key_id" autocomplete="off"></label>
      <label>API key<input type="password" name="api_key" autocomplete="off"></label>
      <button type="button" class="secondary-button" id="test-btn">Test Connection</button>
      <label class="checkbox-label checkbox-danger">
        <input type="checkbox" name="confirm">
        I have real credentials and want to fetch live Cortex XSIAM incidents now
      </label>
      <button type="submit">Fetch Live Data</button>
    </form>
    <div id="xsiam-result"></div>`;

  const form = container.querySelector("#xsiam-form");
  const resultEl = container.querySelector("#xsiam-result");

  container.querySelector("#test-btn").addEventListener("click", async () => {
    try {
      const result = await api.cortexXsiamTestConnection({
        api_key: form.api_key.value,
        api_key_id: form.api_key_id.value.trim(),
        base_url: form.base_url.value.trim(),
      });
      flash(result.message, "success");
    } catch (err) {
      flash(err.message, "error");
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = {
      api_key: form.api_key.value,
      api_key_id: form.api_key_id.value.trim(),
      base_url: form.base_url.value.trim(),
      confirm: form.confirm.checked,
    };
    try {
      const result = await api.cortexXsiamFetch(body);
      flash(result.message, result.preview_only ? "info" : "success");
      resultEl.innerHTML = result.preview_only ? "" : `
        <div class="callout">
          Wrote <strong>${result.count}</strong> normalized finding(s) to <code>${escapeHtml(result.written_to)}</code>.
        </div>`;
    } catch (err) {
      flash(err.message, "error");
    }
  });
}
