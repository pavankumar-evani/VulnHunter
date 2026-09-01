// Prisma Cloud - a PULL connector, same shape as tenable.js/qualys.js: Test Connection
// and Fetch, not a payload preview. Unlike Tenable/Qualys, Prisma Cloud alerts are cloud
// posture/compliance findings (not CVE-scoped) that the connector normalizes directly -
// so Fetch here writes already-normalized findings, not a raw export needing /remediate.
import { api } from "../api.js";
import { escapeHtml, flash } from "../dom.js";

export const title = "Prisma Cloud";

export async function render(container) {
  container.innerHTML = `
    <p class="subtitle">A pull connector for Prisma Cloud's (Palo Alto Networks CNAPP)
    alert-search API - cloud posture/compliance violations, not CVE-scoped
    vulnerabilities. Test your credentials, then fetch live alerts.</p>

    <div class="callout callout-warn">
      ⚠️ This connector has never been exercised against a real Prisma Cloud tenant — no
      credentials were available while building it. It implements the documented login +
      alert-search API contract and is unit-tested against mocked HTTP responses shaped
      like that documentation. Fetches a single page of alerts only (a documented scope
      limit, not silently dropped) - see
      <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/docs/INTEGRATIONS.md" target="_blank" rel="noopener">docs/INTEGRATIONS.md</a>.
    </div>

    <h2>What it does</h2>
    <ol>
      <li>Exchanges the access key ID + secret key for a token (<code>POST /login</code>)</li>
      <li>Fetches open alerts (<code>POST /v2/alert</code>) and normalizes each directly into
        this dashboard's Finding schema - <code>cve</code>/<code>cvss</code>/<code>kev</code>/<code>epss</code>
        stay <code>null</code> (posture/compliance violations, not known-CVE findings)</li>
    </ol>

    <div class="callout">
      Unlike Tenable/Qualys, no asset-type-classification judgment is needed here
      (<code>asset.type</code> is always <code>cloud-infrastructure</code>), so Fetch below
      writes fully normalized findings straight to
      <code>remediation/live-data/prismacloud_findings.json</code> - but, like the generic
      ingest adapter's own explicit, disclosed choice, this is deliberately <strong>not</strong>
      auto-merged into the live queue. See
      <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/docs/INTEGRATIONS.md" target="_blank" rel="noopener">docs/INTEGRATIONS.md</a>
      for why.
    </div>

    <h2>Connect</h2>
    <form class="run-form" id="prismacloud-form">
      <label>Base URL (Prisma Cloud assigns one per region/stack - e.g. https://api.prismacloud.io, https://api2.prismacloud.io, https://api.eu.prismacloud.io)
        <input type="text" name="base_url" placeholder="https://api.prismacloud.io"></label>
      <label>Access key ID<input type="text" name="access_key_id" autocomplete="off"></label>
      <label>Secret key<input type="password" name="secret_key" autocomplete="off"></label>
      <button type="button" class="secondary-button" id="test-btn">Test Connection</button>
      <label class="checkbox-label checkbox-danger">
        <input type="checkbox" name="confirm">
        I have real credentials and want to fetch live Prisma Cloud alerts now
      </label>
      <button type="submit">Fetch Live Data</button>
    </form>
    <div id="prismacloud-result"></div>`;

  const form = container.querySelector("#prismacloud-form");
  const resultEl = container.querySelector("#prismacloud-result");

  container.querySelector("#test-btn").addEventListener("click", async () => {
    try {
      const result = await api.prismacloudTestConnection({
        access_key_id: form.access_key_id.value.trim(),
        secret_key: form.secret_key.value,
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
      access_key_id: form.access_key_id.value.trim(),
      secret_key: form.secret_key.value,
      base_url: form.base_url.value.trim(),
      confirm: form.confirm.checked,
    };
    try {
      const result = await api.prismacloudFetch(body);
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
