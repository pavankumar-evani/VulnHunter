export const title = "FAQ";

const FAQS = [
  ["Does this actually scan production infrastructure?",
    "No. Infra findings are ingested from Tenable/Armis exports or their APIs; " +
    "VulnHunter itself never touches a target system. The connectors are built against " +
    "each vendor's public API docs and unit-tested against mocked HTTP - they've never " +
    "been exercised against a real Tenable/Armis tenant (no credentials were available " +
    "while building them)."],
  ["Does anything here ever auto-apply to real systems?",
    "No. Every generated Ansible playbook is a reviewable, unexecuted file. The " +
    "dashboard's Run Pipeline and AI Assist actions default to a dry-run/preview and " +
    "require an explicit confirm checkbox to spend real API usage - see the safety " +
    "model in KNOWLEDGE_TRANSFER.md §4.3."],
  ["What languages can the code scanner find vulnerabilities in?",
    "Python, JavaScript/TypeScript, Java, Go, PHP, and Perl source, per " +
    ".claude/agents/vuln-scanner.md's per-language detection guidance. The scanner " +
    "itself is a Claude Code subagent (model-driven static analysis), not a compiled " +
    "tool - it doesn't need a compiler for whatever language it's scanning."],
  ["Is this agent-based or agentless scanning?",
    "Code scanning (/vulnhunt) is agentless - it reads source code already in a git " +
    "repo, nothing is installed on any target. Infrastructure findings come from " +
    "Tenable/Armis, and whether THEY use an agent or an agentless scan is a " +
    "configuration choice made in those tools, not something VulnHunter re-implements."],
  ["Is this SOC2 / NIST / PCI compliant?",
    "No, and it can't claim to be from a codebase alone - those are audits/" +
    "certifications performed by a licensed third party over operational evidence, not " +
    "a coding deliverable. See docs/COMPLIANCE_MAPPING.md in the repo for an honest, " +
    "explicitly-non-certifying mapping of what exists today to common control " +
    "categories."],
  ["Does it support multiple clients/tenants (MSSP)?",
    "There's a tenant switcher in the sidebar for demo purposes - it partitions the " +
    "same real dataset by asset category to show what an MSSP view could look like. " +
    "It is NOT real per-tenant authentication or data isolation; that needs a " +
    "database + auth architecture decision that hasn't been made yet (see " +
    "KNOWLEDGE_TRANSFER.md §11.1)."],
  ["Can I formally accept risk on a finding instead of remediating it?",
    "Yes - the Exceptions page is a real, documented risk-acceptance workflow: " +
    "request an exception with a reason/compensating control, a requester, and an " +
    "approver, with an expiry date it auto-expires against unless revoked first. One " +
    "honest scope limit: an active exception doesn't yet pause SLA-breach counting in " +
    "the priority engine."],
  ["Does it track who owns each asset?",
    "Yes - the Asset Inventory page aggregates every asset with findings against it " +
    "and lets you attach an owner/team, stored in a real, editable local file - not a " +
    "sync from a real CMDB/asset-management system."],
  ["Where does my data go?",
    "Nowhere - everything is local files in this repo (git history, JSON, YAML). " +
    "There's no cloud service and no telemetry."],
  ["How much does a real scan or AI-assist call cost?",
    "Running /vulnhunt or /remediate for real calls the Claude API and spends usage/" +
    "credits, spend-capped via --max-budget-usd (default shown on the Run Pipeline " +
    "page). AI Assist's real (confirmed) calls do the same, at whatever your Claude " +
    "plan's per-request cost is - always preview first, it's free."],
  ["What if I find a bug or need help?",
    "See the Support page, or docs/SUPPORT.md in the repo."],
];

export async function render(container) {
  container.innerHTML = `
    <p class="subtitle">Direct answers about what this product does and doesn't do
    today - no marketing language.</p>
    <div class="faq-list">
      ${FAQS.map(([q, a]) => `
        <details class="faq-item">
          <summary>${q}</summary>
          <p>${a}</p>
        </details>`).join("")}
    </div>`;
}
