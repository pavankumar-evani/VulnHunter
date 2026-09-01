// Unlike Infoblox/Axonius (pull connectors fetching FROM a live external system over an
// API), CMDB import is a real, already-working BULK FILE import - a user exports a CSV
// from their own CMDB (ServiceNow CMDB, BMC Remedy, a spreadsheet-based asset register,
// etc.) and uploads it directly on /assets. Marked "live" here because the feature
// genuinely works today (column-guessing, owner/team reconciliation, bulk apply) via a
// real, tested UI form - not because it's a live API pull like its Asset Discovery/IPAM
// category-mates.
export const title = "Adaptors — CMDB Import";

export async function render(container) {
  container.innerHTML = `
    <p class="subtitle">A real, working bulk import - upload a CSV export from your own
    CMDB (ServiceNow CMDB, BMC Remedy, a spreadsheet-based asset register, or any other
    system that can export asset details as CSV) and reconcile it against the real asset
    list this dashboard already builds from findings - not a live API sync.</p>

    <div class="callout">
      This is a file-upload workflow, not an API-pull connector like Infoblox/Axonius
      above - there's no live CMDB system this app polls. See
      <code>remediation/inventory/cmdb_import.py</code>'s own module docstring for the
      same "real, working import - not a live sync" distinction.
    </div>

    <h2>What it does</h2>
    <p><code>remediation/inventory/cmdb_import.py</code>, used by the
    <a href="/assets" data-link>Asset Inventory</a> page's own CSV-upload form:</p>
    <ol>
      <li>Parses the uploaded CSV (stdlib <code>csv.DictReader</code> - no <code>.xlsx</code> support, "Excel" here means CSV, which Excel exports/opens natively)</li>
      <li>Guesses which column holds the asset name/owner/team via a keyword heuristic - a starting point to confirm or correct in the UI, never applied blind</li>
      <li>Reconciles each row against the real, finding-derived asset list: <strong>matched</strong> (already has findings - owner/team applies immediately), <strong>unmatched</strong> (no findings yet, but stored so it applies the moment one appears), or <strong>invalid</strong> (no asset name found)</li>
      <li>On confirm, applies owner/team via the exact same upsert the single-asset "Edit owner" form already uses, just in bulk</li>
    </ol>

    <h2>Using it</h2>
    <p>Go to <a href="/assets" data-link>Asset Inventory</a> and use "Import owner/team
    from a CMDB export (CSV)" - no separate connector page, this feature lives directly
    on the page it updates.</p>`;
}
