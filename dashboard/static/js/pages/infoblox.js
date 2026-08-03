// Like Tenable/Armis/CrowdStrike, Infoblox is a PULL connector: it fetches DNS host
// records FROM an Infoblox NIOS grid and normalizes them into asset-inventory records -
// not vulnerability findings, and not a form with anything to preview without real
// grid credentials, so this stays a reference page (module, what it does, how to use
// it) rather than faking a "confirm" checkbox that has nothing real behind it yet.
export const title = "Adaptors — Infoblox";

export async function render(container) {
  container.innerHTML = `
    <p class="subtitle">A pull connector for Infoblox NIOS's DNS/IPAM data - fetches
    host records and normalizes them into asset-inventory entries, not vulnerability
    findings. Used via the connector module directly (or wired into an import), not a
    dashboard form.</p>

    <div class="callout callout-warn">
      ⚠️ This connector has never been exercised against a real Infoblox NIOS grid — no
      credentials were available while building it. It implements the WAPI (Web API)
      documented <code>record:host</code> contract and is unit-tested against mocked
      HTTP responses shaped like that documentation. Verify field names against your
      grid's current WAPI version before trusting live output.
    </div>

    <h2>What it does</h2>
    <p><code>remediation/connectors/infoblox_connector.py</code>'s <code>InfobloxConnector</code>:</p>
    <ol>
      <li>Authenticates via HTTP Basic auth against the grid master</li>
      <li>Fetches DNS host records (<code>GET /wapi/&lcub;version&rcub;/record:host</code>, requesting
        <code>name, ipv4addrs, view, extattrs</code>)</li>
      <li>Normalizes each host record into VulnHunter's shared asset shape
        (<code>name, ip, mac, type, source, source_ref, extra</code>)</li>
    </ol>

    <div class="callout">
      A DNS host record doesn't carry MAC address or OS/platform data - Infoblox keeps
      those on separate <code>lease</code>/<code>ipv4address</code> objects this
      connector doesn't fetch. So <code>mac</code> is always <code>null</code> and
      <code>type</code> is always <code>"unknown"</code> on an Infoblox-sourced asset
      record - a deliberate, honest property of this source, not a mapping gap.
      Extensible Attributes (Infoblox admins' own custom metadata, e.g. owner or
      environment tags) are kept in <code>extra</code> rather than the strict schema.
    </div>

    <h2>Using it</h2>
    <pre class="code-block">from remediation.connectors.infoblox_connector import InfobloxConnector

conn = InfobloxConnector(grid_master="grid.example.com", username="...", password="...")
assets = conn.fetch_and_normalize_hosts()
# assets is a list of {name, ip, mac, type, source, source_ref, extra} dicts - the same
# shape produced by the Axonius connector, suitable for reconciling into
# remediation/inventory/asset_inventory.py alongside CMDB CSV import.</pre>

    <p class="filter-count">
      See <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/remediation/connectors/README.md" target="_blank" rel="noopener">remediation/connectors/README.md</a>
      for the full verification-status writeup, alongside every other connector in this repo.
    </p>`;
}
