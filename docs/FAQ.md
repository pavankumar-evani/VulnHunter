# VulnHunter — FAQ

**How to use this doc:** specific yes/no and "does it actually..." questions about this
product, answered plainly. If you want task-oriented how-to instead, see
[USER_GUIDE.md](USER_GUIDE.md). For the full architecture and design rationale, see
[KNOWLEDGE_TRANSFER.md](../KNOWLEDGE_TRANSFER.md) and [README.md](../README.md). Also see
[AI_COMMANDS.md](AI_COMMANDS.md), [INTEGRATIONS.md](INTEGRATIONS.md),
[REMEDIATION_WORKFLOWS.md](REMEDIATION_WORKFLOWS.md),
[COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md), [SUPPORT.md](SUPPORT.md), or the
[docs/README.md](README.md) index.

---

### Does this actually scan production infrastructure?

No. `/remediate` does not connect to, probe, or scan any host, network device, or IoT/OT
device itself. It **ingests** vulnerability/asset-risk data that Tenable and Armis (or an
analyst, for manual threat intel) already produced, via file exports
(`remediation/sample-data/*.csv|*.json` for the bundled demo data) or, if you have
credentials, their live APIs (`remediation/connectors/tenable_connector.py`,
`armis_connector.py`). Those connectors are **built against each vendor's publicly
documented API contract and unit-tested against mocked HTTP — they have never been
exercised against a real Tenable.io or Armis tenant**, because no API credentials were
available while building them (see
[remediation/connectors/README.md](../remediation/connectors/README.md) and
[INTEGRATIONS.md](INTEGRATIONS.md) for exactly what "tested" does and doesn't mean here).
If you point them at a real tenant, verify the output against a manually-checked sample
first — field names and nesting can differ from the public docs by API version and tenant
configuration.

### Does anything ever auto-apply to real systems?

No, by construction, not by policy. Specifics:

- `remediation-fixer-windows` and `remediation-fixer-unix` — the two subagents that
  generate Ansible playbooks — have **only `Read`/`Write` tool access** in their
  `.claude/agents/*.md` frontmatter. No `Bash`, no network tool, no credentials. They
  cannot connect to a host even if a prompt somehow instructed one to "just apply this."
- `vuln-fixer` (the code pipeline's fixer) always works on a new git branch and pushes it
  for review; it never commits to `main`.
- Every generated artifact — a playbook, a pushed branch, `REMEDIATION_PLAN.md` — is
  something a human (or your org's existing approved automation platform, e.g. Ansible
  Tower/AWX) reviews and runs. Nothing in this repo has execution reach to real
  infrastructure at all.
- The headless CLI (`cli/vulnhunter.py`) and the dashboard's `/run` and `/servicenow`
  forms default to dry-run/preview; spending real API usage or sending a real ServiceNow
  ticket requires an explicit flag or confirm checkbox.

Full detail: [KNOWLEDGE_TRANSFER.md §4.3](../KNOWLEDGE_TRANSFER.md#43-the-safety-model-the-single-most-important-design-decision)
and [USER_GUIDE.md §6](USER_GUIDE.md#6-the-safety-model-in-practice).

### What languages can the code scanner find vulnerabilities in?

Per `.claude/agents/vuln-scanner.md`'s documented detection guidance: **Python,
JavaScript/TypeScript, Java, Go, PHP, and Perl**, plus generic checks (hardcoded secrets,
insecure config, dependency risk, unsafe Docker practices) that apply regardless of
language. Each language has its own idiomatic vulnerable-pattern list (e.g. Java XXE via
`DocumentBuilderFactory`, PHP local file inclusion via unsanitized `include`/`require`
paths, Go `text/template` used where `html/template` should be) — see the agent file for
the full per-language breakdown.

**Important distinction:** the scanner's *target* language coverage (what it can find
vulnerabilities in) is unrelated to the scanner's *own* implementation, which is a Claude
Code subagent (Python-adjacent tooling, prompt-driven, running via `Read`/`Grep`/`Glob`/
`Bash`) regardless of what language it's scanning. A real commercial scanner (Semgrep,
Snyk, CodeQL) differentiates on target-language breadth, not implementation language —
that's the same standard applied here. The multi-language fixtures in
`vulnerable-demo-multilang/` and the 31 tests in `tests/test_multilang_scanner_patterns.py`
verify **static text consistency** between the scanner's documented patterns and the
fixture files — not that the scanner was actually run live against Java/Go/PHP/Node code,
since no runtime for those languages was available in the environment this was built in
(see [KNOWLEDGE_TRANSFER.md §11.1](../KNOWLEDGE_TRANSFER.md#111-the-commercial-grade-polyglot-ask--what-actually-happened)).

### Is this SOC2/NIST/PCI compliant?

No. That's an audit/certification question, not a code question. SOC2 requires an audit
by a licensed CPA firm over months of operational evidence; NIST CSF alignment is a
self-attestation or third-party assessment; PCI has its own formal validation process.
No repository, however well-built, can claim any of these on its own — doing so would be
a legal/regulatory risk, not a feature gap (see
[KNOWLEDGE_TRANSFER.md §9, Tier 3](../KNOWLEDGE_TRANSFER.md#9-roadmap--path-to-commercial-grade)).
This repo can build toward the underlying *controls* (audit logging, least-privilege tool
scoping, etc.) that a real compliance program would also need — see
[COMPLIANCE_MAPPING.md](COMPLIANCE_MAPPING.md) for an informational (not certifying) map
of which existing capabilities relate to which control category, and what's still missing.

### Does it support multiple tenants/clients (MSSP)?

There's a tenant switcher in the dashboard sidebar (`dashboard/static/js/tenant.js`) —
"All Tenants (MSSP view)", "Acme Financial Corp (demo)", "Northwind Bank (demo)" — that
partitions the same real findings by asset-type category, so the Remediation Queue page
demos what an MSSP-style per-client view could look like. **This is explicitly a UI-only
illustration, not real per-tenant authentication or data isolation**: there is one
process, one dataset on disk, and no auth layer at all — anyone who can reach the
dashboard's port can switch "tenants" freely and see everything regardless of which one
is selected. A banner on the Queue page repeats this whenever a non-"All" tenant is
active. Building *real* multi-tenant MSSP support needs a database and an auth/RBAC layer
first — a business/architecture decision, not something that can be bolted onto the
current filesystem-reading MVP incrementally without rebuilding it. See
[KNOWLEDGE_TRANSFER.md §11](../KNOWLEDGE_TRANSFER.md#11-the-enterprisemssp-platform-ask--scope-reality-check)
and its subsection
[§11.1](../KNOWLEDGE_TRANSFER.md#111-the-commercial-grade-polyglot-ask--what-actually-happened)
for the full reasoning on what's real here and what isn't.

### Can I formally accept risk on a finding instead of remediating it?

Yes — the `/exceptions` page (backed by `remediation/exceptions/store.py`) is a real,
documented risk-acceptance workflow: request an exception with a reason/compensating
control, a requester, and an approver, with an expiry date it auto-expires against
unless someone explicitly revokes it first. One honest scope limit: an active exception
doesn't yet pause SLA-breach counting in the priority engine, so an accepted-risk finding
can still show as "SLA breached" today - see the module docstring.

### Does it track who owns each asset?

Yes — `/assets` aggregates every asset with findings against it (finding count, highest
severity, KEV exposure) and lets you attach an owner/team, stored in
`remediation/inventory/asset_ownership.json`. That's a real, editable local file, not a
sync from a real CMDB/asset-management system - see the module docstring for what a
production version would need instead.

### Are Container and API Vulnerabilities real categories, or placeholders?

Both are real, but at different maturity. **Container Vulnerabilities** surfaces
findings the scanner has already been detecting since an earlier wave (Dockerfile
issues: running as root, secrets baked into image layers, unpinned base image tags) -
they were just falling into a generic "Other" bucket because "no CWE" (unpinned base
image has none) or an unmapped CWE (CWE-250 for running as root) didn't match the
category lookup in `dashboard/static/js/pages/vulnhunt.js`. That's fixed, so this
category shows real findings today. **API Vulnerabilities** is newly-added detection
guidance in `.claude/agents/vuln-scanner.md` (missing authentication on a route,
wildcard CORS, mass assignment) for scans going forward - the category and its CWE
mappings are real and wired up, but it shows 0 findings today because the demo app has
no planted API-security example, and one wasn't fabricated just to fill the card (DAST,
by contrast, now has real sample data - see the next answer).

### Where did SAST/DAST/Secrets/SCA/Container/API go from the sidebar?

They're still real, working pages - just not separate top-level menu entries
anymore. They're listed as cards on the Application Vulnerabilities hub (`/appsec`)
instead, so the main menu shows one entry per real domain (Application,
Infrastructure, AI, Certificate) rather than every sub-category flattened into the
sidebar. Same idea for Infrastructure Vulnerabilities: `/infrastructure` now splits
it into OS, Network, Network Security, OT/IoT, and Cloud Infrastructure cards
(`remediation/enrichment/infra_classification.py`, a lookup against `asset.type`)
rather than one flat link. Cloud Infrastructure and DAST both used to show 0 findings
honestly (no sample data for either); both now have real sample data (~300 each,
sourced from NVD's public CVE API for Cloud, real CWE/OWASP vulnerability classes for
DAST since dynamic-testing bugs aren't CVE-numbered - see
`remediation/sample-data/generate_bulk_findings.py`). API Vulnerabilities still shows 0
findings, same honest treatment, for the reason in the previous answer.

### Is the AI Vulnerabilities page's MITRE ATLAS mapping authoritative?

No, and it says so directly on the page. `/ai-vulnerabilities`
(`remediation/enrichment/ai_vuln_taxonomy.py`) documents ten real, established AI/ML
security concepts - prompt injection, training-data/model poisoning, supply-chain
compromise, excessive agency, and more - each with a summary and remediation
guidance, plus a cross-reference to a MITRE ATLAS tactic/technique. That
cross-reference is this module's own reading of published ATLAS documentation
(atlas.mitre.org), not a verified/authoritative mapping pulled from a live ATLAS API
- exactly the same "keyword heuristic, suggestion to verify, not a fact to cite"
posture already applied to the Risk Dashboard's MITRE ATT&CK heat map. Verify any
specific tactic/technique ID against atlas.mitre.org before citing it formally. Like
API Vulnerabilities, this shows 0 findings against this repo's real demo data - there's
no AI/ML component in `vulnerable-demo-app/` to actually trigger it, and nothing was
faked to make the category look populated.

### Is the owner suggestion on `/assets` real machine learning?

No, and calling it that would be dishonest. `/assets` can suggest an owner/team for an
unowned asset (`remediation/inventory/pattern_recognition.py`) using three transparent,
explainable pattern-matching signals against assets that already have an owner:
hostname naming-convention prefix (e.g. `WIN-APP07`/`WIN-APP09` sharing `WIN-APP`), IP
`/24` subnet locality, and asset-type match — plus MAC vendor OUI matching for the
separate asset-**type** suggestion (useful for connector-sourced assets like Infoblox's,
which don't carry a type at all). Each is a plain weighted vote with the reasoning
returned alongside the suggestion (hover it to see exactly why), not a trained model —
this demo's asset inventory has roughly a dozen entries, nowhere near enough to
train or validate a real ML model on without overfitting theater. Suggestions are never
auto-applied; a "Use" button lets you accept one with one click, same
suggestion-not-determination posture as the MITRE ATT&CK tagging and compensating-control
suggestions elsewhere in this app.

### Is there a login now? What are the demo credentials?

Yes — a real local login MVP (`dashboard/auth/`), not a placeholder. `/login` checks
email/password against `dashboard/auth/users.json` (PBKDF2-HMAC-SHA256 hashing,
HMAC-signed session cookie), and `/profile` shows the logged-in user's name/email/role
with a change-password form and logout. Two demo accounts ship in the seed file, and
they're intentionally public since it's a demo seed file, not a real secret:
`admin@vulnhunter.local` / `ChangeMe123!` (role: admin) and `analyst@vulnhunter.local` /
`ChangeMe123!` (role: user). Change or remove them before any real deployment. There's
also real, working OpenID Connect (OIDC) Authorization Code + PKCE client code
(`dashboard/auth/oidc.py`) for real single sign-on — but it stays **inert** (the
"Sign in with SSO" button doesn't even appear on `/login`) unless a real identity
provider's `OIDC_ISSUER`/`OIDC_CLIENT_ID`/`OIDC_CLIENT_SECRET`/`OIDC_REDIRECT_URI` are
all configured as real environment variables, same "built vs. verified" honesty as every
connector in this repo — this code has not been exercised against a real identity
provider. See [dashboard/README.md](../dashboard/README.md#authentication) for the full
design, including exactly which routes require login (only sensitive mutations — every
read/GET route stays open server-side, a scope decision stated plainly there).

### Does an exception's suggested compensating control mean it's approved/certified?

No. The `/exceptions` request form suggests candidate compensating controls
(`remediation/enrichment/compensating_controls.py`) based on keywords in the finding's
title/description — the same keyword-heuristic, explicitly-non-authoritative pattern as
the MITRE ATT&CK tagging on `/queue`. It's a drafting aid you can insert into the reason
field with one click, not a determination that a control is actually in place, adequate,
or certified by anyone. Whether a suggested (or any other) compensating control is real,
sufficient, and actually implemented is a judgment call for the requester and approver
to make and document themselves.

### Is the Inbox real messaging between users?

No. `/inbox` (and the bell icon/dropdown on every page) is a feed of **system-generated
notifications only** — SLA breaches, CISA KEV-listed findings not yet SLA-breached,
exceptions expiring within 14 days, and pending generic-ingested findings
(`dashboard_data.build_notifications()`) — never a message written by one person to
another. There's no person-to-person messaging anywhere in this product, which would
need the auth/user system this wave added plus a real persistence layer to store
messages against. Read/dismissed state is tracked client-side (`localStorage`) rather
than server-side, since there's no per-user server-side state to track it against yet.

### Is the internal/external-facing classification on the Risk dashboard from a real network scan?

No. The internal/external-facing tag you can set per asset on `/risk` is **manually
set only**, exactly like asset ownership on `/assets` — there's no network scan,
firewall-rule analysis, or exposure-scanning tool behind it. It's stored in the same
editable local ownership file (`remediation/inventory/asset_inventory.py`'s
`set_facing()`) as the owner/team fields, and defaults to "Unknown" until someone sets
it. Treat it as a place to record what your team already knows, not as a
network-derived exposure assessment.

### What happens to my data / where does it live?

Everything is local files in this repository — git history, JSON, YAML, Markdown. There
is no cloud service and no telemetry:

- Scan findings: `SECURITY_REPORT.md` in the scanned repo, committed to a local branch by
  `vuln-fixer` if you run `--fix`.
- Remediation data: `remediation/output/normalized-findings.json` and generated `.yml`
  playbooks, `REMEDIATION_PLAN.md` at the project root.
- Live connector output (if you use real Tenable/Armis credentials):
  `remediation/live-data/` — gitignored, since it's real vulnerability data about real
  infrastructure and must never be committed.
- CLI audit logs: `.vulnhunter/logs/*.json` — gitignored.
- The only network calls anything in this repo makes on your behalf are: the real Claude
  API (when you actually run a pipeline, not on `--dry-run`), CISA's KEV feed and
  FIRST.org's EPSS API (free, no-auth, during `/remediate`'s enrichment stage), and
  whichever of Tenable/Armis/ServiceNow you explicitly configure credentials for.

### How much does running a real scan cost?

It calls the real Claude API, which costs real money against your Claude usage/plan.
`cli/vulnhunter.py` applies a `--max-budget-usd` spend cap (default `$2.00`) to every real
invocation as a safety net, but that default is not a guarantee it fits your budget or
your plan's actual pricing — you're responsible for understanding what a
`/vulnhunt --fix` or `/remediate --generate` run costs before running it unattended (e.g.
on every CI push). Always run `--dry-run` first to see exactly what would execute without
spending anything. Full detail: [cli/README.md](../cli/README.md)'s "Cost warning"
section.

### What if I find a bug or need help?

See [SUPPORT.md](SUPPORT.md) — the short version: open a GitHub issue on this repo for
bugs/features, use the private contact in [SECURITY.md](../SECURITY.md) for security
issues, and check [KNOWLEDGE_TRANSFER.md §12](../KNOWLEDGE_TRANSFER.md#12-troubleshooting--things-that-tripped-us-up)
first for known environment gotchas (Docker unavailability, GitHub secret-scanning
false-positives on fake demo credentials, etc.) before filing something that's already
documented.
