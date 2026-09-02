// Unlike ServiceNow/Jira/Splunk (VulnHunter pushes findings/events OUT to them, so a
// "preview what would be sent per finding" form makes sense), CrowdStrike Falcon - like
// Tenable and Armis - is a PULL connector: it fetches alerts FROM CrowdStrike and
// normalizes them into findings. There's nothing to "preview" without real credentials
// to actually query, so this stays a reference page (module, what it does, how to use
// it) rather than faking a form with a "confirm" checkbox that has nothing real behind
// it yet - same treatment Tenable/Armis already get (no dedicated dashboard page).
export const title = "XDR / EDR — CrowdStrike Falcon";

export async function render(container) {
  container.innerHTML = `
    <p class="subtitle">A pull connector, not a push one - it fetches alerts FROM
    CrowdStrike, the opposite direction of the ServiceNow/Jira/Splunk integrations. Used
    via the connector module directly (or wired into a pipeline run), not a dashboard form.</p>

    <div class="callout callout-warn">
      ⚠️ This connector has never been exercised against a real CrowdStrike Falcon
      tenant — no credentials were available while building it. It implements Falcon's
      documented OAuth2 client-credentials flow and alert-query/entities API contract,
      and is unit-tested against mocked HTTP responses shaped like that documentation.
      Verify field names against your tenant's current API version before relying on it
      for triage prioritization - see the severity-threshold note below.
    </div>

    <h2>What it does</h2>
    <p><code>remediation/connectors/crowdstrike_connector.py</code>'s <code>CrowdStrikeConnector</code>:</p>
    <ol>
      <li>Authenticates via OAuth2 client-credentials (<code>POST /oauth2/token</code>)</li>
      <li>Queries matching alert IDs (<code>GET /alerts/queries/alerts/v1</code>, optional Falcon Query Language filter)</li>
      <li>Resolves those IDs to full alert objects (<code>POST /alerts/entities/alerts/v2</code>)</li>
      <li>Normalizes each alert into VulnHunter's normalized Finding schema</li>
    </ol>

    <div class="callout">
      Falcon EDR alerts are behavioral detections ("suspicious PowerShell encoded
      command", "process injection"), not CVE-scoped known-vulnerability findings the way
      Tenable/Armis records are - so <code>cve</code>/<code>cvss</code>/<code>kev</code>/
      <code>epss</code> are always <code>null</code> on a CrowdStrike-sourced finding.
      That's a deliberate, expected property of this source, not a mapping gap. Severity
      is derived from Falcon's numeric 1-100 score using a documented-as-arbitrary
      90/70/40 threshold (not sourced from official CrowdStrike docs) - tune it against a
      real tenant before relying on it for triage prioritization.
    </div>

    <h2>Using it</h2>
    <pre class="code-block">from remediation.connectors.crowdstrike_connector import CrowdStrikeConnector

conn = CrowdStrikeConnector(client_id="...", client_secret="...")
findings = conn.fetch_and_normalize_alerts(filter_query="severity:>=70")
# findings is a list of normalized-finding-schema.md dicts, ready for the same
# ingest-normalizer step Tenable/Armis output goes through.</pre>

    <p class="filter-count">
      See <a href="https://github.com/pavankumar-evani/VulnHunter/blob/master/remediation/connectors/README.md" target="_blank" rel="noopener">remediation/connectors/README.md</a>
      and <a href="https://github.com/pavankumar-evani/VulnHunter/blob/master/docs/INTEGRATIONS.md" target="_blank" rel="noopener">docs/INTEGRATIONS.md</a>
      for the full verification-status writeup, alongside Tenable and Armis (the other
      two pull-style connectors, which get the same CLI-driven, no-dashboard-page treatment).
    </p>`;
}
