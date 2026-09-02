export const title = "Support";

export async function render(container) {
  container.innerHTML = `
    <p class="subtitle">This is a local, single-process MVP - support today is
    repo/community-based, not a hosted helpdesk with SLAs.</p>

    <div class="callout" style="margin-bottom:18px">
      <strong>Looking for how to do something specific?</strong> Try
      <a href="/ask" data-link>Ask VulnHunter</a> first - type your question in plain
      English (e.g. "how do I approve a remediation" or "change asset owner") and it
      searches this app's own real How-To content live, deterministically, at no cost.
      It's not a chatbot and never guesses - if nothing matches, it says so honestly
      instead of making something up.
    </div>

    <h2>Get help</h2>
    <ul>
      <li><strong>How do I do X?</strong> see the
        <a href="https://github.com/pavankumar-evani/VulnHunter/blob/master/docs/enterprise-suite/user-guide.html" target="_blank" rel="noopener">User &amp; Operations Guide</a>
        - task-oriented answers for login/logout, RBAC, asset edits, exceptions vs.
        approvals, reports, and the AI features - or just ask
        <a href="/ask" data-link>Ask VulnHunter</a> above.</li>
      <li><strong>Bug or unexpected behavior:</strong> open a GitHub issue with the exact
        command you ran (e.g. <code>/vulnhunt vulnerable-demo-app</code> or
        <code>python dashboard/app.py</code>), the full error output, and your OS/Python
        version.</li>
      <li><strong>Feature request:</strong> open a GitHub issue with the Feature
        Request template - it walks through the safety-model checklist before anything
        is scoped.</li>
      <li><strong>Security issue in VulnHunter itself:</strong> see
        <code>SECURITY.md</code> for the private disclosure contact - please don't open a
        public issue for a real vulnerability in this tool.</li>
      <li><strong>"Is this safe to point at production?"</strong> read the safety model in
        <a href="https://github.com/pavankumar-evani/VulnHunter/blob/master/KNOWLEDGE_TRANSFER.md#43-the-safety-model-the-single-most-important-design-decision" target="_blank" rel="noopener">KNOWLEDGE_TRANSFER.md §4.3</a>
        first - short answer: nothing here auto-executes against real infrastructure.</li>
    </ul>

    <h2>Check these before filing an issue</h2>
    <ul>
      <li><a href="/faq" data-link>FAQ</a> - direct answers about what this does and doesn't do</li>
      <li><a href="https://github.com/pavankumar-evani/VulnHunter/blob/master/docs/enterprise-suite/user-guide.html" target="_blank" rel="noopener">User &amp; Operations Guide</a> - how-to answers for every real workflow, with a search box of its own</li>
      <li><a href="https://github.com/pavankumar-evani/VulnHunter/blob/master/KNOWLEDGE_TRANSFER.md#12-troubleshooting--things-that-tripped-us-up" target="_blank" rel="noopener">KNOWLEDGE_TRANSFER.md §12 Troubleshooting</a> - real issues hit and fixed during development</li>
      <li><a href="https://github.com/pavankumar-evani/VulnHunter/blob/master/docs/USER_GUIDE.md" target="_blank" rel="noopener">docs/USER_GUIDE.md</a> - the full usage guide</li>
      <li><a href="https://github.com/pavankumar-evani/VulnHunter/blob/master/docs/enterprise-suite/MANIFEST.md" target="_blank" rel="noopener">Full enterprise documentation suite</a> - architecture, connectors, RBAC, pricing, and more</li>
    </ul>

    <h2>Known limitations (read before reporting these as bugs)</h2>
    <ul>
      <li>Reads stay open by default even though real login/RBAC exists - mutations
        (admin settings, connector actions, approvals) require a real session, but
        anyone who can reach this port can view findings unless
        <code>VULNHUNTER_REQUIRE_LOGIN_FOR_READS=true</code> is set. Don't expose this
        beyond localhost/a trusted network without setting it.</li>
      <li>No database - every page re-reads from disk on every request; there's no
        historical trend view.</li>
      <li>The tenant switcher in the sidebar is a UI-only demo, not real per-tenant
        authentication or data isolation.</li>
      <li>The Tenable/Armis/ServiceNow connectors are built against each vendor's public
        API docs and unit-tested against mocked HTTP - never exercised against a real
        vendor tenant.</li>
    </ul>`;
}
