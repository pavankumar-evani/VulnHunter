// Like Infoblox, Axonius is a PULL connector: it fetches aggregated device records FROM
// an Axonius instance and normalizes them into asset-inventory records - not
// vulnerability findings, and nothing to preview without real API credentials, so this
// stays a reference page rather than faking a form with a "confirm" checkbox.
export const title = "Adaptors — Axonius";

export async function render(container) {
  container.innerHTML = `
    <p class="subtitle">A pull connector for Axonius's aggregated cyber-asset inventory
    - fetches device records (already merged across whatever adapters/sources Axonius is
    configured with) and normalizes them into asset-inventory entries. Used via the
    connector module directly, not a dashboard form.</p>

    <div class="callout callout-warn">
      ⚠️ This connector has never been exercised against a real Axonius tenant — no
      credentials were available while building it. It implements Axonius's documented
      <code>api-key</code>/<code>api-secret</code> header auth and
      <code>POST /api/devices</code> contract, and is unit-tested against mocked HTTP
      responses shaped like that documentation. The exact response envelope key and
      field-flattening have varied across Axonius versions in public docs - verify
      against your own tenant's current API version before trusting live output.
    </div>

    <h2>What it does</h2>
    <p><code>remediation/connectors/axonius_connector.py</code>'s <code>AxoniusConnector</code>:</p>
    <ol>
      <li>Authenticates via <code>api-key</code>/<code>api-secret</code> request headers</li>
      <li>Fetches a page of device records (<code>POST /api/devices</code> with an
        offset/limit body)</li>
      <li>Normalizes each device into VulnHunter's shared asset shape
        (<code>name, ip, mac, type, source, source_ref, extra</code>)</li>
    </ol>

    <div class="callout">
      Axonius's real query language lets you request specific flattened fields (e.g.
      <code>specific_data.data.hostname</code>) - a raw device record otherwise nests
      almost everything under <code>specific_data.data.*</code>. This connector assumes
      the response has already been shaped with reasonably flattened keys
      (<code>hostname</code>, <code>ip</code>/<code>ips</code>, <code>mac</code>/<code>macs</code>,
      <code>os_type</code>, <code>adapters</code>) rather than replicating that
      flattening/query-building logic in full - an honest MVP scope limit. It also
      fetches a single page only; a real integration needs an offset/limit pagination
      loop the same way <code>ArmisConnector.search_all_pages()</code> does.
    </div>

    <h2>Using it</h2>
    <pre class="code-block">from remediation.connectors.axonius_connector import AxoniusConnector

conn = AxoniusConnector(base_url="https://axonius.example.com", api_key="...", api_secret="...")
assets = conn.fetch_and_normalize_devices()
# assets is a list of {name, ip, mac, type, source, source_ref, extra} dicts - the same
# shape produced by the Infoblox connector, suitable for reconciling into
# remediation/inventory/asset_inventory.py alongside CMDB CSV import.</pre>

    <p class="filter-count">
      See <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/remediation/connectors/README.md" target="_blank" rel="noopener">remediation/connectors/README.md</a>
      for the full verification-status writeup, alongside every other connector in this repo.
    </p>`;
}
