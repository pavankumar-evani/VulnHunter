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
    "sync from a real CMDB/asset-management system. It also has a CMDB CSV import " +
    "panel to bulk-assign owner/team from an uploaded export."],
  ["Are Container and API Vulnerabilities real categories, or placeholders?",
    "Both real, different maturity. Container Vulnerabilities surfaces findings the " +
    "scanner already detected (root user, baked-in secrets, unpinned base image) - they " +
    "were just falling into a generic \"Other\" bucket before a small category-mapping " +
    "fix. API Vulnerabilities is new detection guidance for future scans (missing auth, " +
    "wildcard CORS, mass assignment) - same honest treatment as DAST: wired up and real, " +
    "but shows 0 findings today since the demo app has no planted example."],
  ["Is the AI Vulnerabilities page's MITRE ATLAS mapping authoritative?",
    "No, and it says so on the page itself. The ten AI/ML vulnerability categories " +
    "(prompt injection, model poisoning, supply-chain compromise, etc.) each cross-" +
    "reference a MITRE ATLAS tactic/technique - this module's own reading of published " +
    "ATLAS docs, not a verified mapping, same \"suggestion to verify\" posture as the " +
    "existing ATT&CK heat map. Shows 0 findings against real demo data, same honest " +
    "treatment as DAST and API Vulnerabilities - nothing faked to look populated."],
  ["Is the owner suggestion on Asset Inventory real machine learning?",
    "No. It's three transparent, weighted pattern-matching signals - hostname naming " +
    "convention, IP subnet, and asset type (plus MAC vendor matching for type " +
    "suggestions) - against assets that already have an owner, with the exact reasoning " +
    "shown on hover. Not a trained model: this demo's asset list has about a dozen " +
    "entries, far too few to train or validate real ML on. Never auto-applied - a " +
    "one-click \"Use\" button, same posture as the ATT&CK tags and compensating-control " +
    "suggestions."],
  ["Is there a login now? What are the demo credentials?",
    "Yes - a real local login MVP, not a placeholder. Two demo accounts ship in the " +
    "seed file (intentionally public, since it's a demo seed, not a real secret): " +
    "admin@vulnhunter.local / ChangeMe123! (admin) and analyst@vulnhunter.local / " +
    "ChangeMe123! (user). There's also real OpenID Connect (SSO) client code, but it " +
    "stays inert - the \"Sign in with SSO\" button won't even appear - unless a real " +
    "identity provider is configured. See dashboard/README.md's Authentication section " +
    "for the full design, including exactly which routes require login."],
  ["Does a suggested compensating control mean it's approved or certified?",
    "No. The Exceptions request form suggests candidate compensating controls based " +
    "on keywords in the finding's title/description - same explicitly-non-authoritative " +
    "heuristic as the MITRE ATT&CK tagging. It's a drafting aid, not a determination " +
    "that a control is actually in place, adequate, or certified by anyone."],
  ["Is the Inbox real messaging between users?",
    "No. It's a feed of system-generated notifications only - SLA breaches, KEV-listed " +
    "findings, expiring exceptions, pending generic-ingested findings - never a message " +
    "one person wrote to another. Real person-to-person messaging would need the auth/" +
    "user system this wave added plus a persistence layer to store messages against."],
  ["Is the internal/external-facing tag on the Risk dashboard from a real network scan?",
    "No. It's manually set only, exactly like asset ownership - there's no network " +
    "scan, firewall analysis, or exposure-scanning tool behind it. It defaults to " +
    "\"Unknown\" until someone sets it."],
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
