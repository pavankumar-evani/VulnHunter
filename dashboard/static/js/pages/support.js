export const title = "Support";

export async function render(container) {
  container.innerHTML = `
    <p class="subtitle">This is a local, single-process MVP - support today is
    repo/community-based, not a hosted helpdesk with SLAs.</p>

    <h2>Get help</h2>
    <ul>
      <li><strong>Bug or unexpected behavior:</strong> open a GitHub issue with the exact
        command you ran (e.g. <code>/vulnhunt vulnerable-demo-app</code> or
        <code>python dashboard/app.py</code>), the full error output, and your OS/Python
        version.</li>
      <li><strong>Security issue in VulnHunter itself:</strong> see
        <code>SECURITY.md</code> for the private disclosure contact - please don't open a
        public issue for a real vulnerability in this tool.</li>
      <li><strong>"Is this safe to point at production?"</strong> read the safety model in
        <a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/KNOWLEDGE_TRANSFER.md#43-the-safety-model-the-single-most-important-design-decision" target="_blank" rel="noopener">KNOWLEDGE_TRANSFER.md §4.3</a>
        first - short answer: nothing here auto-executes against real infrastructure.</li>
    </ul>

    <h2>Check these before filing an issue</h2>
    <ul>
      <li><a href="/faq" data-link>FAQ</a> - direct answers about what this does and doesn't do</li>
      <li><a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/KNOWLEDGE_TRANSFER.md#12-troubleshooting--things-that-tripped-us-up" target="_blank" rel="noopener">KNOWLEDGE_TRANSFER.md §12 Troubleshooting</a> - real issues hit and fixed during development</li>
      <li><a href="https://github.com/Deloitte-US-Consulting/VulnHunter/blob/master/docs/USER_GUIDE.md" target="_blank" rel="noopener">docs/USER_GUIDE.md</a> - the full usage guide</li>
    </ul>

    <h2>Known limitations (read before reporting these as bugs)</h2>
    <ul>
      <li>No authentication - anyone who can reach this port can view findings and
        trigger a real (paid) pipeline run. Don't expose this beyond localhost/a trusted
        network.</li>
      <li>No database - every page re-reads from disk on every request; there's no
        historical trend view.</li>
      <li>The tenant switcher in the sidebar is a UI-only demo, not real per-tenant
        authentication or data isolation.</li>
      <li>The Tenable/Armis/ServiceNow connectors are built against each vendor's public
        API docs and unit-tested against mocked HTTP - never exercised against a real
        vendor tenant.</li>
    </ul>`;
}
