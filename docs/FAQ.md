# Quanta — FAQ

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
- The headless CLI (`cli/quanta.py`) and the dashboard's `/run` and `/servicenow`
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
illustration, not real per-tenant authentication or data isolation** - it's stored in
the browser's `localStorage` and is completely unconnected to the app's real login
system: any logged-in user (any role) can switch "tenants" freely from the same single
shared dataset, regardless of which one is selected, because there is no server-side
tenant concept anywhere to gate it against - there is one process and one dataset on
disk. A banner on the Queue page repeats this whenever a non-"All" tenant is active.
Audited directly (2026-09-01): no server route accepts or trusts a client-supplied
tenant identifier today, so there's no cross-tenant leakage to have - only a standard to
hold real per-team/per-tenant work to once it's built (NIST SP 800-53 AC-3/AC-4/AC-6,
OWASP API1:2023 Broken Object Level Authorization, and OWASP's own
[Multi-Tenant Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html)).
Building *real* multi-tenant MSSP support needs a real per-tenant data boundary layered
on top of the database and auth/RBAC layer that already exist today — a business/
architecture decision (schema/row-level tenant scoping, enforced server-side on every
query path), not something that can be bolted onto the current shared-dataset model
incrementally. See
[KNOWLEDGE_TRANSFER.md §11](../KNOWLEDGE_TRANSFER.md#11-the-enterprisemssp-platform-ask--scope-reality-check)
(including the 2026-09-01 audit and standards citations) and its subsection
[§11.1](../KNOWLEDGE_TRANSFER.md#111-the-commercial-grade-polyglot-ask--what-actually-happened)
for the full reasoning on what's real here and what isn't.

### Can I formally accept risk on a finding instead of remediating it?

Yes — the `/exceptions` page (backed by `remediation/exceptions/store.py`) is a real,
documented risk-acceptance workflow: request an exception with a reason/compensating
control, a requester, and an approver, with an expiry date it auto-expires against
unless someone explicitly revokes it first. One honest scope limit: an active exception
doesn't yet pause SLA-breach counting in the priority engine, so an accepted-risk finding
can still show as "SLA breached" today - see the module docstring.

### How are findings assigned to people and teams?

Each finding can carry an assignee, a team, a work status (open, in progress, blocked,
resolved) and notes, stored in the local SQLite `finding_assignments` table; teams live in
a first-class `teams` table with a manager. An assignment's team overrides the asset's
team. Auto-route fills gaps from asset ownership (preview by default, one batch audit
entry). `/ownership` shows coverage and workload analytics; `/assignments` is the work
queue; `/admin/people` manages users and teams. "Resolved" is the owner's report, not
proof: the next scan confirms it. Ownership routes require login, and findings outside a
non-admin user's team return 404.

### Does it track who owns each asset?

Yes — `/assets` aggregates every asset with findings against it (finding count, highest
severity, KEV exposure) and lets you attach an owner/team, stored in the local SQLite
`asset_ownership` table (`remediation/inventory/asset_inventory.py`, via
`remediation/utils/db.py` — seeded from the old `asset_ownership.json` file on first
migration). That's real, editable local data, not a sync from a real CMDB/asset-
management system - see the module docstring for what a production version would need
instead.

### Is "Container Vulnerabilities" the same thing as "Container/Host Runtime Security"?

No - genuinely different, both real, same distinction real container-security products
draw between build-time and runtime protection (e.g. image scanning vs. Falco-style
runtime detection). **Container Vulnerabilities** (Application Vulnerabilities hub) is
static Dockerfile/base-image analysis from code scanning - root user, baked-in secrets,
unpinned tags - found before anything runs. **Container/Host Runtime Security**
(Infrastructure Vulnerabilities hub, `scan_type: "runtime"`) is Falco-style behavioral
detection on an already-running container/host - a config mistake in a file vs. an
observed behavior at runtime are different findings from different tools in real
deployments, so they stay as two categories here too, not merged into one.

### Are Container and API Vulnerabilities real categories, or placeholders?

Both are real, but at different maturity. **Container Vulnerabilities** surfaces
findings the scanner has already been detecting since an earlier wave (Dockerfile
issues: running as root, secrets baked into image layers, unpinned base image tags) -
they were just falling into a generic "Other" bucket because "no CWE" (unpinned base
image has none) or an unmapped CWE (CWE-250 for running as root) didn't match the
category lookup in `dashboard/static/js/pages/quanta-scan.js`. That's fixed, so this
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
it into OS, Network, Network Security, and Cloud Infrastructure cards
(`remediation/enrichment/infra_classification.py`, a lookup against `asset.type`)
rather than one flat link - OT/IoT gets its own dedicated hub (`/ot-vulnerabilities`)
instead of a card here, since it's a distinct enough team/domain to warrant its own
page rather than one slice of a broader infra view. Cloud Infrastructure and DAST both used to show 0 findings
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
specific tactic/technique ID against atlas.mitre.org before citing it formally. Unlike
API Vulnerabilities, this one isn't stuck at 0: `vulnerable-demo-app/ai_assistant.py`
plants real AI/ML vulnerabilities (a hardcoded LLM API key, an insecure `pickle.load`
on an uploaded model file, a prompt-injection-shaped string concatenation, an
excessive-agency LLM-to-shell path), a real `vuln-scanner` run found all four
(VULN-10 through VULN-13, see `vulnerable-demo-app/SECURITY_REPORT.md`), and three of
those four tag against this taxonomy for real (Prompt Injection, AI Supply Chain
Compromise, Excessive Agency show genuine non-zero counts on the page). Every other
category on this page is still honestly at 0 - nothing was faked to make them look
populated.

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

### Is there real machine learning anywhere in this app now?

Yes, on `/ml-insights` — and it's worth being precise about which parts of "machine
learning" that does and doesn't cover, because the answer to the question above (owner
suggestions aren't ML) is still true and this doesn't change it. `/ml-insights` adds three
capabilities built with a real library (scikit-learn 1.9), genuinely fit at request time
against this app's own real data (`remediation/enrichment/ml_insights.py`):

- **Anomaly detection** (`IsolationForest`, one model per asset type) — flags assets
  whose real finding-count/critical-count/KEV-count/severity/CVSS/EPSS profile is a
  statistical outlier vs. peers of the *same* asset type, with the specific deviating
  feature(s) named by real z-score.
- **Risk-archetype clustering** (`KMeans`) — groups findings into naturally-occurring
  clusters by real severity/CVSS/EPSS/KEV/asset-type similarity, each with a profile
  computed from its actual members, not a predefined label.
- **Similar-finding search** (`TfidfVectorizer` + cosine similarity) — real text
  similarity over finding titles/descriptions, surfaced as "Similar findings" on any
  finding's detail view.

All three are **unsupervised** — they need no labeled examples, only a large-enough real
feature population to describe a genuine distribution (this app's `normalized-findings.json`
has 9,000+ real findings across 8,000+ distinct assets and 17 asset types — genuinely
enough to fit and validate these on). That's precisely why this is different from the
owner-suggestion heuristic above: owner suggestion would need *labeled* examples (an asset
with a known-correct owner) to learn from, and this demo's real label pool
(`remediation/inventory/asset_ownership.json`) has about half a dozen entries — nowhere
near enough for supervised learning without overfitting theater. Nothing about
`/ml-insights` changes that conclusion; it answers a genuinely different, unsupervised
question with a genuinely larger pool of unlabeled data.

What this deliberately does **not** do:

- **No supervised learning, and no remediation-outcome prediction** ("will this get fixed
  on time"). There is no field anywhere in this app's schema representing a real
  remediation outcome (no `resolved`/`fixed_at`/`time_to_remediate`) to learn from —
  adding one just to make a prediction demo possible would be exactly the kind of
  fabrication this FAQ exists to rule out.
- **It never replaces or feeds into** `remediation_policy_engine.py`'s domain resolution
  or `priority_engine.py`'s scoring. Those stay deterministic and auditable line-by-line;
  `/ml-insights` is an advisory layer that sits alongside them, not inside their decision
  path.

### Is there a login now? What are the demo credentials?

Yes — a real local login MVP (`dashboard/auth/`), not a placeholder. `/login` checks
email/password against `dashboard/auth/users.json` (PBKDF2-HMAC-SHA256 hashing,
HMAC-signed session cookie), and `/profile` shows the logged-in user's name/email/role
with a change-password form and logout. Two demo accounts ship in the seed file, and
they're intentionally public since it's a demo seed file, not a real secret:
`admin@quanta.local` / `ChangeMe123!` (role: admin) and `analyst@quanta.local` /
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

### Does Notification Settings actually send real emails?

Yes, if you configure real SMTP settings — but it's genuinely inert until you do. Set
`SMTP_HOST`, `SMTP_PORT`, and `SMTP_FROM_ADDRESS` (plus optionally `SMTP_USERNAME`/
`SMTP_PASSWORD`/`SMTP_USE_TLS`) as real environment variables and restart the server;
`/notification-settings` shows "SMTP configured"/"not configured" honestly rather than
implying it works either way. Sending uses Python's stdlib `smtplib` — no third-party
email service integration, no new dependency. Like every other connector in this repo,
it was built against the standard protocol and has not been exercised against a real
mail server, since no real SMTP credentials were available while building it — send a
real test email from the page yourself before relying on it.

Scheduled reports (weekly/monthly/quarterly/half-yearly/yearly, scoped to a sub-domain
and/or team) and critical/zero-day/threat-intel team alerts both run on an **in-process
timer inside the dashboard server** — checked hourly by default, only while that server
process stays running. A restart resets the timer (though it never double-sends: a
report's last-sent state and an alert's already-notified findings both persist to disk
separately from the timer itself). For delivery that doesn't depend on this specific
server process staying up, point a real external cron/Task Scheduler at
`POST /api/notification-settings/run-checks-now` instead — it runs the exact same check
on demand.

### Does the AD/PAM integration on Remediation Policy actually connect to a real directory or vault?

AD, yes, if you configure it — but it's **read-only** and inert until you do. Set
`AD_SERVER` and `AD_BASE_DN` (plus optionally `AD_BIND_USER`/`AD_BIND_PASSWORD`) as real
environment variables and restart the server; `/remediation-approvals` shows "Active
Directory is configured"/"NOT configured" honestly. It uses the real `ldap3` library to
check group membership only — it never creates, modifies, or resets anything in your
directory, and, like every other connector in this repo, has not been exercised against a
real Active Directory environment since none was available while building it. When AD
isn't configured, an approval still works, but the group-membership result is reported as
`null` ("not checked"), never faked as `true` or `false`.

PAM is different in kind, not just in configuration state: this application **never**
holds or fetches a live privileged credential, configured or not. When a finding's
resolved Remediation Policy names a `pam_backend` (Vault, CyberArk PAS, or CyberArk
Conjur), the generated Ansible playbook gets a real, standard lookup-plugin snippet in its
`vars:` block (`community.hashi_vault.vault_kv2_get` / `cyberark.pas.cyberark_credential`
/ `cyberark.conjur.conjur_variable`) — the actual secret fetch happens later, when your
organization's own change-management process runs that playbook against your organization's
own real Vault/CyberArk connection. See
[REMEDIATION_WORKFLOWS.md's "Remediation Policy" section](REMEDIATION_WORKFLOWS.md#remediation-policy-applied-alongside-not-a-separate-pipeline-stage)
for the full model and the reasoning behind that line.

### What's the difference between an Exception and a Remediation Approval?

They answer opposite questions. An **Exception** (`/exceptions`) means "accept the risk
instead of fixing this" — a time-boxed waiver on a finding that genuinely isn't getting
remediated right now. A **Remediation Approval** (`/remediation-approvals`) means "yes,
proceed with fixing this" — the human sign-off a `normal`/`emergency`-change-type finding
needs before its generated playbook is considered ready to hand to a human/change-
management process. A finding can only ever need one or the other for a given decision,
never both at once.

### Why don't domains like IaC/SCA/Runtime have a "maintenance window" the way OS/Endpoint do?

Because they're genuinely different remediation mechanisms, not the same mechanism with
different scheduling. `os`/`endpoint`/`network`/etc. really do get fixed by a scheduled
patch pushed to a running system in a specific time window. `iac` and `sca` findings get
fixed by a pull request merging (auto-mergeable on green CI for low-risk patch-level
changes, grounded in the real Renovate/Dependabot convention) — there's no maintenance
window because nothing is being patched live, a template or dependency manifest is being
corrected in source control. `runtime` findings (e.g. a Falco-style behavioral alert) are
investigative SOC triage, not a patchable CVE at all — see "Asset classes with no fixer
yet" in [REMEDIATION_WORKFLOWS.md](REMEDIATION_WORKFLOWS.md). Every domain's `cadence`/
`maintenance_window` fields are still present and editable for consistency, but for these
three, treat them as "how often to check" rather than "when the outage happens."

### What's covered under "cloud vulnerabilities" - just Kubernetes, or real cloud-provider issues too?

Both, and it's all real. The `cloud-infrastructure` category's ~1,400 sample findings are
genuine, NVD-sourced CVEs spanning Kubernetes/Docker/OpenShift/Terraform *and*
provider-specific services - real CVEs affecting Amazon S3, AWS Lambda, AWS IAM, Amazon
RDS, AWS CloudFormation, Azure Active Directory, Azure Storage, Azure DevOps, Google
Cloud Storage, and Google Cloud SDK, among others. They flow through the identical
pipeline as every other category - KEV/EPSS enrichment, priority scoring, and now a
dedicated `cloud` Remediation Policy domain with its own cadence/approval rules and
cloud-native PAM backends (AWS STS AssumeRole, Azure Managed Identity, GCP Workload
Identity Federation - see the AD/PAM question above and
[REMEDIATION_WORKFLOWS.md](REMEDIATION_WORKFLOWS.md)).

### What happens to my data / where does it live?

Everything is local to this machine — git-tracked files (Markdown, YAML, generated
JSON/`.yml`) plus one local database. There is no cloud service and no telemetry:

- Scan findings: `SECURITY_REPORT.md` in the scanned repo, committed to a local branch by
  `vuln-fixer` if you run `--fix`.
- Remediation data: `remediation/output/normalized-findings.json` and generated `.yml`
  playbooks, `REMEDIATION_PLAN.md` at the project root.
- Dashboard record stores (exceptions, remediation approvals, activity/AI-usage logs,
  asset ownership, user accounts, notification-scheduler state, and pending
  generic-ingest/Prisma Cloud/Cortex XSIAM findings): a local SQLite database,
  `remediation/quanta.db` — gitignored, see `remediation/utils/db.py`.
- Live connector output (if you use real Tenable/Qualys/OpenVAS credentials):
  `remediation/live-data/` — gitignored, since it's real vulnerability data about real
  infrastructure and must never be committed.
- CLI audit logs: `.quanta/logs/*.json` — gitignored.
- The only network calls anything in this repo makes on your behalf are: the real Claude
  API (when you actually run a pipeline, not on `--dry-run`), CISA's KEV feed and
  FIRST.org's EPSS API (free, no-auth, during `/remediate`'s enrichment stage), and
  whichever of Tenable/Armis/ServiceNow you explicitly configure credentials for.

### How much does running a real scan cost?

It calls the real Claude API, which costs real money against your Claude usage/plan.
`cli/quanta.py` applies a `--max-budget-usd` spend cap (default `$2.00`) to every real
invocation as a safety net, but that default is not a guarantee it fits your budget or
your plan's actual pricing — you're responsible for understanding what a
`/quanta-scan --fix` or `/remediate --generate` run costs before running it unattended (e.g.
on every CI push). Always run `--dry-run` first to see exactly what would execute without
spending anything. Full detail: [cli/README.md](../cli/README.md)'s "Cost warning"
section.

### Is Quantum Readiness a real "quantum vulnerability scanner"?

No - no such product category exists to honestly claim, since a quantum computer
capable of breaking real-world RSA/ECDSA doesn't exist yet. `/quantum-readiness`
classifies real, already-normalized findings by a disclosed keyword heuristic against
each finding's own real title (same "keyword-matched, not authoritative" honesty tier
as the Risk Dashboard's MITRE ATT&CK heat map - this app's normalized finding schema
carries no separate CWE field to join against) into two categories: **asymmetric
crypto** (RSA/ECDSA/Diffie-Hellman usage - the genuinely quantum-relevant case, since
Shor's algorithm breaks exactly these) and **legacy protocol** (SSLv2/SSLv3, 3DES, RC4,
export-grade ciphers, MD5/SHA-1 signatures - classically broken already, not itself
quantum-relevant, but real evidence worth auditing alongside the same modernization
effort). Every matched finding is real, already-shipped sample data (e.g.
CVE-2011-5095, a real Diffie-Hellman CVE) - nothing fabricated for this feature. The
migration guidance cites real, verifiable standards: NIST FIPS 203/204/205 (finalized
August 2024) and NIST IR 8547 (Initial Public Draft, November 2024 - not yet
finalized), which targets deprecation after 2030 and disallowal after 2035 for the
weaker, 112-bit-strength classical-parameter tier (e.g. RSA-2048) - stronger parameters
skip the earlier milestone. NSA's CNSA 2.0 is a separate, National-Security-Systems-
specific framework with its own different 2025-2033 category schedule, not the same
dates as IR 8547's - not cited here to avoid conflating the two. See
`remediation/enrichment/quantum_readiness.py`'s module docstring for the full
disclosure.

### Is there a single aggregate score on the main dashboard, like Tenable's Cyber Exposure Score?

Yes, on the Overview page - real-time, not a static/fabricated number. It is
**deliberately not claimed as equivalent to Tenable's Cyber Exposure Score (CES)** or
any other named, proprietary scoring product - Tenable doesn't publish CES's formula, so
there's nothing published to actually match, and research confirms no other named,
citable "industry-standard" aggregate exposure score exists either (SSVC, from FIRST/
CISA, is a per-vulnerability decision tree, not a fleet aggregate). What's shipped
instead is an **original, fully disclosed rollup** of three real signals this app
already computes: the average per-asset Risk Score
(`remediation/enrichment/risk_scoring.py`), what fraction of all findings are CISA
KEV-listed, and the average FIRST.org EPSS score. See
`remediation/enrichment/exposure_score.py`'s module docstring and the "How is the
Aggregate Exposure Score calculated?" panel right under the tile for the full math and
the disclosure that inspired it (OWASP's Risk Rating Methodology's Likelihood × Impact
shape, plus FIRST.org's own EPSS FAQ, which endorses portfolio-level EPSS aggregation
without publishing one fixed formula).

### Is "staging validated" on Remediation Approvals a real staging-environment check?

No - it's metadata only, the same honest pattern as `ad_group_validated` on the same
approval record. Clicking "Mark staging validated" records who attests the change was
tested in a staging/test environment and when (ISO/IEC 27002:2022 §8.32's "test changes
before applying" control) - there's no real staging environment behind this app for it
to actually run anything against. It's settable at any point in an approval's lifecycle
(most naturally before Approve, but not enforced), and the Remediation Approvals page
also now surfaces each finding's real generated-playbook rollback procedure (a genuine
`# Rollback: ...` comment the fixer subagent wrote, extracted from the playbook file,
not a fabricated summary) - "Not yet available" honestly means no playbook has been
generated for that finding yet.

### Does this use React, Node.js, or Perl? Is there a real Infrastructure-as-Code layer?

No React, no Node.js/npm - deliberately, not because they were unavailable in principle.
The dashboard frontend is a hand-rolled vanilla-JS SPA on a FastAPI JSON backend; see
[dashboard/README.md](../dashboard/README.md)'s "Why FastAPI + vanilla JS, not Node/React"
section for the full reasoning (this machine had no Node.js/npm installed, so a React
build couldn't be *written and verified running* here - shipping an untested frontend
isn't "modern," it's just unverified). Perl only appears as one of the six languages
`vuln-scanner` can find vulnerabilities *in* ([.claude/agents/vuln-scanner.md](../.claude/agents/vuln-scanner.md))
- Quanta itself has no Perl in it.

Real Infrastructure-as-Code already exists, though: `remediation-fixer-windows`/`-unix`
generate real, reviewable Ansible playbooks (or PowerShell DSC for Windows where more
appropriate) targeting the actual OS/package-manager/service-manager conventions for
each domain - that already *is* the IaC layer this question is usually asking about, not
something still to be built. It's deliberately never auto-applied; see "Does anything
here ever auto-apply to real systems?" above.

If a React (or any other) frontend becomes worth building later, `/api/*`'s JSON contract
is already the exact seam it would build against - `dashboard/data.py`'s parsing logic and
the FastAPI routes underneath don't change either way.

### How do I log out, and why does it show two different messages?

Logging out itself happens from the account menu, `/profile`'s "Log out" button, or
automatically after an idle-timeout — all three call `POST /api/auth/logout` and then
send you to `/logout`, a display-only confirmation screen (it never calls the logout API
itself; by the time it renders, you're already signed out). It shows one of two messages
depending on `?reason=idle` in the URL: "signed out automatically after a period of
inactivity" for the idle-timeout case, or a generic "your session has ended" for a
manual logout — same page, different copy, so you know which one happened.

### How do I change my password?

`/profile` has one field: a new password (minimum 8 characters). There's no
"confirm password" field and no "current password" field required — entering a new
password and submitting changes it immediately (`POST /api/auth/change-password`).

### How do I add a new user, or change someone's role or team?

Admin-only, on `/admin` under "Team Management." Adding a user is a form with email,
name, password (min 8 characters), role (`user` or `admin`), and an optional team —
there are only ever these two roles, no broader permission matrix. For an existing user,
role is a dropdown that saves the moment you change it; team is a free-text field with
its own Save button (blank team means no team-based filtering applies to that user).
This is also where RBAC is actually configured — there's no separate "RBAC settings"
page; role and team here are the whole model.

### How do I request a new feature?

Open a ticket from the **Support** page (`/support`), type *A feature request*. Tickets
live in this deployment's own database (`support_tickets`), are triaged by admins, and are
never sent to a public tracker. See [SUPPORT.md](SUPPORT.md). Any new remediation-fixer
subagent must stay Read/Write-only — that rule is part of how requests are scoped.

### How do I change an asset's owner, team, IP/MAC, or environment?

Click "Edit" on that asset's row in `/assets`. The modal has Owner, Team, IP address,
MAC address, Environment (Production/Staging/Dev/Unknown), and a remediation-schedule
override (Weekly/Monthly/Quarterly/Half-yearly/Yearly/On-demand/none) — each field saves
to its own endpoint on submit. An unowned asset may also show a one-click "Use" button
next to a pattern-matched owner suggestion (see "Is the owner suggestion... real machine
learning?" above) instead of opening the full modal. Bulk changes to owner/team come from
importing a CMDB CSV export via the "Import owner/team from a CMDB export" panel on the
same page.

### Where do I change an asset's internal/external-facing classification?

Not in the Asset Inventory edit modal — that's a separate dropdown, right in the table,
on the **Risk Management page** (`/risk`). It's a manual classification, never inferred
from a real network scan (see "Is the internal/external-facing classification... from a
real network scan?" above).

### Can I change an asset's EOL/EOS status?

No — and this is worth being precise about, since it looks editable from a distance.
EOL/EOS is a **read-only badge**, computed server-side by matching the asset's OS string
against a real vendor-lifecycle table (`remediation/enrichment/eol_lookup.py`). There is
no form field for it anywhere in the app, on purpose: it's a fact derived from the OS
string, not an opinion an owner should be able to override.

### How do I request an exception - and is there a separate approval step?

Request one from `/exceptions`: pick the finding, write a reason (candidate compensating
controls are suggested by keyword and can be inserted with one click - see the FAQ entry
above on what that suggestion does and doesn't mean), and set an expiry (quick +30/+90/
+180-day buttons or a date picker). "Requested by" and "approved by" are both plain text
fields filled in **at request time** - there's no separate in-app "approve" button or
workflow step the way the page's own summary language ("request/approve") might suggest.
The only action available afterward is **Revoke** (admin-only), on an active exception.
Expiry is automatic once `expires_on` passes - nothing to click.

### How do I approve, reject, or trigger a remediation request?

On `/remediation-approvals`: findings whose policy calls for change management appear
under "awaiting a request" with a "Request approval" button. Once requested, a row in
the approvals table gets **Approve** (records who decided; runs a real read-only AD
group-membership check if one is configured, without ever writing to the directory),
**Reject** (records who and why), and **Mark staging validated** (an ISO/IEC 27002:2022
§8.32 attestation field, not a real automated staging check). Once approved, **Trigger
Remediation** is a real, confirm-gated call that spends actual API usage to generate that
finding's playbook — unchecked, it's a free preview of what would run.

### How do I connect a scanner?

On `/connections` (admin only): add a connection, choose the source (Tenable, Qualys, Prisma
Cloud, Cortex XSIAM, Infoblox, Axonius or Active Directory), enter its credentials, use Test
connection, then set a schedule or click Sync now. Credentials are stored encrypted and never
shown again. Each sync is queued as a job a worker runs, merges into the findings queue (a
re-run updates rather than duplicates) and is logged; a second click on Sync now does not queue
a second sync. If your policy keeps scanner credentials out of other systems, have the scanner
push to Quanta with an API key instead. See [INTEGRATION_API.md](INTEGRATION_API.md).

### How do I open ServiceNow or Jira tickets automatically for urgent findings?

Add a ServiceNow, Jira Cloud or Splunk connection on `/connections` (these are "push"
connections) and set its rule: send findings at or above a severity, only those on the CISA KEV
list, a minimum EPSS, and the most tickets per run, so a first sync cannot flood the service
desk. Each run opens a ticket for matching findings not yet sent, most urgent first, and a
re-run never creates a duplicate. Ticket state is read back on each sync.

### How do I create an API key for a scanner, SOAR playbook or CI job?

On `/connections`, in "Send data to Quanta", click Create an API key. Give it a name, tick only
the access it needs (`ingest:write`, `tickets:update`, `read:findings`, `controls:write`,
`ai-usage:write` or `soc:write`) and choose an
expiry (never, 30, 90 or 365 days). The key is shown once, so copy it right away; Quanta keeps
only a hash. Send it as `Authorization: Bearer <key>`. The key table lists your keys and
Revoke stops one working immediately. Endpoints are in [INTEGRATION_API.md](INTEGRATION_API.md).

### How do I import a scanner CSV?

On `/connections`, use "Import a scanner file": choose a CSV in the Tenable column layout, enter
a source name and upload. Tick "this is the complete export" only when the file is everything
that scanner currently reports; it then removes that source's findings missing from the file,
which is how fixed vulnerabilities leave the queue.

### What do the scopes on a Quanta API key allow?

`ingest:write` sends findings, scanner files, SARIF and coverage reports in; `tickets:update`
reports ticket status changes; `read:findings` exports findings; `controls:write` reports
security controls an EDR or firewall observes; `ai-usage:write` reports AI usage (gateway
events or OpenTelemetry JSON); `soc:write` sends SIEM or XDR alerts for triage. Tick only what
a given job needs. Only `/api/ingest/`, `/api/inbound/` and `/api/export/` accept a key in
place of a login. See [INTEGRATION_API.md](INTEGRATION_API.md).

### Does Quanta certify compliance, and what is Risk & Compliance for?

No. Quanta supplies evidence and workflow; it does not certify compliance, and a passing test
shows that Quanta observed something, not that an auditor would agree. The `/grc` page (admin)
maps controls in NIST 800-53 r5, CSF 2.0 and an AI-governance set (built-in subsets, or a full
catalog you import as OSCAL JSON) to automated tests with thresholds in
`remediation/config/grc_tests.yaml`, collected about daily. Too little data gives "na", never
a pass. People add attestations beside the evidence, keep a risk register and versioned
policies with acknowledgements, and can download OSCAL assessment results.

### Is the Hunting & SOC page a SIEM? Does it run hunt queries?

No to both. Quanta knows which assets carry exploitable vulnerabilities, so it proposes one
hunt per open CVE on the CISA KEV list or with EPSS of 0.5 or more, with the hosts, the ATT&CK
techniques it tags and ready-made queries rendered as Splunk SPL by a small translator for
Sigma-style selections. You run them in your own SIEM and record each result and the hunt's
outcome here (closing needs one). Alerts you send with a `soc:write` key are ranked with
vulnerability context and given a runbook; responding stays with your team.

### How do SOC cases, queues and escalation work?

On the SOC Operations page, a case sits in the L1, L2 or L3 queue. Priority is impact times
urgency (P1 to P4), and the acknowledge, pickup and resolve clocks come from the targets in
`remediation/config/soc_ops.yaml`. Escalating, resolving or closing needs a written summary of at
least 20 characters, so the next person never starts cold. A case left in a tier past its resolve
target moves up one tier automatically, with an event saying why. The Metrics tab shows MTTA,
MTTR, service-level compliance, backlog and how often the first-look recommendation matched the
analyst's resolution.

### Which models does the SOC tooling use? Is a language model involved?

Almost none. The alert verdict is a weighted score, reports are assembled from stored data,
technique identification is a Naive Bayes classifier, the playbook recommender is a similarity-
weighted success rate, and detection use cases come from counting patterns. A language model is
used only to draft a playbook and to refine a use case, each asked for explicitly, validated, and
never acted on automatically. The SOC, Hunting and Detection Engineering document gives the method
for each.

### Does Quanta crawl the dark web? How do the dark-web sources get in?

No. Quanta never connects to Tor, crawls onion sites, or logs in to forums. On Dark Web Watch it
reads public ransomware leak-site lists on a schedule and matches them locally against your domains
and brand names, asks IntelligenceX, DeHashed, LeakCheck or Snusbase about your own domains when you
add a key (counts and masked identifiers only; passwords are never kept), and takes in the output of
the crawlers and monitoring platforms your analysts run in an isolated environment, pasted or posted
to `/api/ingest/darkweb`. A hit raises a SOC alert.

### Where do threat-model threats come from? Is an LLM involved?

From explicit rules you can read in `remediation/threatmodel/rules.py`, not an LLM. You
describe a system as components, data flows and trust zones; the rules raise STRIDE threats
and recompute them on every read, so an edited model never leaves stale threats. Each is
scored likelihood x impact, with residual risk reduced by recorded control coverage, and
joined to live findings by ATT&CK technique or CWE overlap. Only people's decisions (accepted,
mitigated, not applicable) are stored. Scores rank and prompt discussion; they are not a
measurement.

### How do I see AI spend, and does Quanta read our prompts?

The `/ai-usage` page (admin) shows tokens and spend by team, application and model, budgets,
unusual days, cache-hit rate and AI tools nobody reviewed. Quanta stores counts, models, times
and attribution only, never prompts or responses. Sources: Anthropic and OpenAI usage
connections (Admin key), gateway events, OpenTelemetry JSON, and Quanta's own calls. Cost is
reported, estimated from `ai_pricing.yaml` (ships empty) or shown as unknown; never zero.
Unreviewed-application discovery comes from an uploaded proxy or DNS export; it records and
reports, and does not block.

### How do I read the guidance on a finding, and does it change by scan type?

Open the finding (click its ID anywhere) and read "How to fix this". Guidance is chosen from
the finding's scan type and its CWE or asset type: code flaws found by static analysis (SAST)
or by testing a running app (DAST), vulnerable libraries (SCA, with the fixed version and
upgrade command when known), committed secrets, infrastructure-as-code, container images,
CI/CD pipeline weaknesses, test-coverage gaps in security-relevant files, and infrastructure
hosts each get steps suited to that kind of problem. It says what it matched on; a finding
with no specific entry gets a general approach, labelled as general. Further down,
"Compensating controls for your environment" lists the MITRE ATT&CK mitigations for the
techniques the flaw enables and whether each is in place on that asset. The guidance changes
nothing by itself.

### How do I bring in SARIF, pipeline or coverage results from my CI?

Create an API key with the `ingest:write` scope (Connections, "Send data to Quanta"), then
post the file from your pipeline: SARIF 2.1.0 from Semgrep, CodeQL, ZAP, Trivy, Checkov,
gitleaks and similar tools to `POST /api/ingest/sarif`; a Cobertura, JaCoCo or lcov report to
`POST /api/ingest/coverage` (only security-relevant files become findings). For GitHub
Actions, GitLab CI and Jenkinsfile weaknesses, an operator runs `quanta-admin scan-pipelines`.
Each finding carries a scan type (the newer ones are container, cicd and coverage); an
explicit scan type sent with the data wins over inference. Examples are in
docs/INTEGRATION_API.md.

### How do I record a security control on an asset?

Admin only. On Security Controls, under "Add a control", enter the asset name or a pattern
such as `WEB-*`, choose the kind of control (for example EDR, network filtering, MFA),
describe it in your own words and click Add control. To load many at once, use "or import a
CSV". A control you or a CSV record is **claimed**; one an EDR or firewall integration reports
through the controls API (an API key with the `controls:write` scope) is **verified**.
Re-sending the same control refreshes its last-seen time instead of duplicating it. The more
complete this list, the more specific the compensating-control advice and threat-model
residual risk become; with nothing recorded for an asset, Quanta says unknown.

### What do verified, claimed, absent and unknown mean in the compensating-control advice?

**In place (verified)**: a connector or script observed the control on that asset. **In place
(recorded, not verified)**: a person recorded it. **Not in place**: controls are recorded for
the asset but this mitigation is not among them. **Not known for this asset**: nothing is
recorded, so Quanta does not guess. The coverage percentage is indicative (verified counts 1,
recorded counts 0.5), and compensating controls reduce risk; they do not close the finding.

### How do I build a threat model and review its threats?

Admin only. Under "New model", name it and start from an editable example, from your assets
(components drafted from the findings), or empty. Open the model, adjust components, data
flows and trust zones in the JSON editor (properties you leave out count as not recorded) and
click Save model. Quanta raises STRIDE threats from explicit rules, not an LLM, and recomputes
them whenever the model changes, so nothing goes stale. Each threat shows likelihood x impact,
the live findings on the affected assets (KEV flagged), the mitigating controls recorded for
them and the residual score. Use the Decision list to mark a threat accepted, mitigated or
not-applicable; only those decisions are stored. Threats marked unconfirmed are questions to
answer, not established weaknesses. The scores rank work for discussion; they are not a
measurement.

### How do I import a framework and collect evidence?

Admin only. On Risk & Compliance, open the Controls tab. The built-in catalogs (NIST 800-53
r5, CSF 2.0 and an AI-governance set) are subsets. To work against every control, use "Import
a full catalog": give it an id and upload the framework's OSCAL JSON (for a licensed standard,
your licensed copy in OSCAL form). Then open the Evidence tab and click Collect evidence now;
it also runs about once a day. Each automated test reports pass, fail, warn or na with what it
measured and the threshold; with too little data it says na, never a pass. Back on the
Controls tab each control shows its status and tests, and you can download the OSCAL
assessment results. Quanta supplies evidence and workflow; it does not certify compliance, and
a passing test shows that Quanta observed something, not that an auditor would agree.

### How do I attest to a control Quanta cannot observe?

On the Controls tab of Risk & Compliance, click Attest beside the control, say whether it is
effective, partially-effective or ineffective, and give the statement it rests on (required).
The attestation sits beside the automated evidence rather than replacing it, and shows as
expired when it is no longer current.

### How do I register a risk?

Admin only. Open the Risk register tab. "Worth registering" lists suggestions drawn from live
findings and threat models: click one to add it. Or fill in "Add a risk": title, owner,
likelihood and impact from 1 to 5, a treatment (mitigate, accept, transfer, avoid) with the
plan or reason, and a review date. The register shows inherent and residual level, owner,
status and whether a review is overdue. Policies are on their own tab; anyone signed in can
read the active ones and click "I have read this" to acknowledge.

### How do I start a hunt from a proposal and close it with an outcome?

Admin only. Quanta is not a SIEM and does not run queries; it proposes where to look and you
run the queries in your own tool. On Proposed hunts, each card is an open CVE that is on the
KEV list or has an EPSS of 0.5 or more, with the hosts, the ATT&CK techniques Quanta tags and
ready-made queries (Splunk SPL, to be adapted to your data model). Click Start this hunt, then
on Hunts open it, run each query in your SIEM, and set each query's result (hits, no-hits,
not-run, error). Add notes and follow-ups, tick "This hunt led to a new detection" if it did,
set the status to closed and choose an outcome (confirmed, not-found or needs-data). Closing
requires an outcome. The Overview tab then shows hunts closed and confirmed and how many of
the techniques in your open findings have been hunted.

### How do I triage a SOC alert?

Alerts reach Quanta from your SIEM or XDR through `POST /api/ingest/alerts` with an API key
that has the `soc:write` scope. On the Alert triage tab they are ranked by a priority that
reflects what Quanta knows about the host: its owner, open findings, and known-exploited ones,
with the reasons listed. Open an alert to see findings that match it and a runbook (chosen by
technique, then title keywords, else a generic one), and set status, disposition
(true-positive, benign, false-positive, needs-data), assignee and notes. Quanta shows the
runbook steps; responding stays with your team or SOAR.

### How do I set an AI budget, and see which AI tools nobody reviewed?

Admin only. AI Usage shows tokens and spend by team, application, model and source. Quanta
stores counts only, never prompts or responses, and the page lists which sources are
reporting; cost is reported or estimated, and requests of unknown cost are counted separately,
never shown as zero. To set a budget, use the "Add budget" form: choose the organization, a
team or an application, a period (month, week, day), a limit in dollars and/or tokens, and a
warning percentage. The table shows used, on-track-for and a state of ok, alert or exceeded.
To find unreviewed tools, upload a proxy or DNS export under "AI applications found" (CSV with
a domain column, optionally user and count); known AI services appear as unreviewed, which you
can change to sanctioned or blocked. That status is a record for reporting; Quanta does not
block anything.

### How do I feed AI usage into Quanta?

Three ways. Add an Anthropic usage or OpenAI usage connection on Connections, using that
provider's Admin key. Or post events from a gateway or script to `POST /api/ingest/ai-usage`,
or send OpenTelemetry JSON to `/api/ingest/otlp/v1/traces`, with an API key that has the
`ai-usage:write` scope. Quanta's own calls are included. See docs/INTEGRATION_API.md. As with
every connector here, these are built against public documentation and tested against mocked
responses, not run against a live provider account.

### How do I register an application?

Admin only. On Applications & SBOM (`/applications`), add an application and fill in what you
know: environment, platform, owner and team, business criticality, whether it is internet-facing,
and (for fix pull requests) its Git provider, repository, default branch and the paths of its
dependency files. The criticality and internet-facing flag feed the ranking, so set them
honestly; they are your statement, not something Quanta discovers.

### How do I upload or generate an SBOM for an application?

Admin only. Open the application's Context & SBOM tab. Upload a CycloneDX or SPDX JSON file (each
application keeps one current SBOM), or generate one from a requirements.txt, package.json,
package-lock.json, pom.xml or go.mod; only a lock file gives transitive dependencies, and Quanta
says so when you generate from a manifest alone. It never runs a package manager. CI can upload
an SBOM with an `ingest:write` API key to `POST /api/ingest/sbom`. Quanta ships no advisory
database: components show as vulnerable only when a scanner finding names the package or when you
run the OSV check (admin-confirmed, package URLs only). Without either, an SBOM shows components,
not a clean bill of health. The OSV connector is unit-tested against fakes and not run live.

### How do I read the dependency and exposure graph and the ranked work?

The graph shows the dependency tree (direct and transitive, with the blast radius of a vulnerable
package) and the lane from the internet through any WAF, load balancer, DMZ and firewall recorded
in `network_topology.yaml`; with nothing recorded the lane is absent, not guessed. The ranked
work lists each finding with its score breakdown: CVSS, EPSS, KEV, application criticality,
package sensitivity, attack surface, attack-chain position and a lower multiplier when the network
path is denied. Dependency findings are grouped into the one upgrade that closes them. The weights
(`appsec_scoring.yaml`) are a disclosed choice, not a standard.

### How do I propose and open a fix pull request?

Admin only for anything that changes state. Store a GitHub or GitLab connection on Connections and
set the repository on the application, then create a proposal (a dependency upgrade or a
first-party code fix) from the ranked work, review the diff and evidence on Fix Pull Requests
(`/fix-prs`) and approve it. Opening is a dry run until you tick confirm; a real open creates a new
branch and a pull request. Quanta never merges, never writes to a default or protected branch and
refuses pipeline files, CODEOWNERS, keys and env files. It does not run a package manager or tests,
so refresh the lock file and run your tests on the branch; with a lock file present the pull
request opens as a draft. Use Sync to read state back and Verify after the next scan. The GitHub
and GitLab connectors are unit-tested against fakes and not run against a live host.

### How do I keep pull request status up to date automatically?

Two ways, and you can use both. An hourly scheduler tick follows every open fix pull request and
re-checks merged ones against the latest scan; it does nothing, and builds no connector, when no
pull request is open. It is on by default; set `QUANTA_GITOPS_SYNC` to `false`, `0` or `no` to
turn it off. Or set up the webhook (next entry) so GitHub or GitLab tells Quanta the moment the
state changes. The Fix Pull Requests page shows whether the hourly check and the webhook are
active. Verification is still evidence from the next scan, not proof.

### How do I set up the GitHub or GitLab webhook?

Set a shared secret in `QUANTA_GIT_WEBHOOK_SECRET` (or `QUANTA_GIT_WEBHOOK_SECRET_FILE` for a
mounted secret), then add a webhook in the repository settings that posts pull request events to
`POST /api/inbound/git-webhook` using the same secret. GitHub signs the body (`X-Hub-Signature-256`,
HMAC-SHA256); GitLab sends the secret as `X-Gitlab-Token`. With no secret set Quanta refuses every
delivery (503), a bad signature gets 401, and a pull request Quanta did not open is ignored. Only
the pull request URL and its open, merged or closed state are used. No login or API key is
involved, because the signature is the check. See docs/INTEGRATION_API.md. The signing is
unit-tested against hand-signed payloads; no delivery has been received from a live host.

### What do I do after a merge to get verification sooner?

On the merged proposal, use "Queue a rescan on the scanner connections" (admin). It queues a sync
on each enabled scanner pull connection (the ones whose output is findings). If none is
configured it tells you to upload the next scan instead. Once that scan lands, Verify reads it and
marks the fix verified, still present or awaiting a rescan.

### Why did my dependency pull request open as a draft?

Because the repository has a lock file. Quanta never runs a package manager, so it cannot
regenerate the lock file for the new version. The proposal page shows a callout saying so: refresh
the lock file on the branch, run your tests, and mark the pull request ready when checks pass.

### How do I load demo data for the application pages?

From the repository, run `python cli/quanta_admin.py seed-appsec-demo` (optionally `--name NAME`).
It registers a demo application from the sample SBOM plus five findings under the source
`appsec-demo`, and prints the `network_topology.yaml` entry to add if you want the exposure lane
to show. `--remove` undoes exactly those and nothing else. It is sample data, not a scan result.

### How do I use the release gate in CI?

Create an API key with the `read:findings` scope. On Pipeline Gates (`/pipeline-gates`), open "Add
it to a pipeline", choose GitHub Actions, GitLab CI or shell, and paste the snippet; it calls
`GET /api/gate/evaluate` and fails the job when the result says block. The Policy section shows
what blocks, warns or is off (`remediation/config/pipeline_gates.yaml`); a finding with an
approved exception is not counted, and every evaluation is recorded in the History.

### How do I use the secure design assistant?

Open Secure Design (`/secure-design`) and answer the questionnaire. You get security requirements
with OWASP ASVS references, the pipeline controls to put in place and questions for the threat
model. They come from explicit rules (`design_rules.yaml`), not a model, so the same answers give
the same result. Treat the output as a starting checklist for a design review.

### How do I add our own DevSecOps control?

Admin only. On DevSecOps (`/devsecops`), open the "Our own controls" tab and add a control that is
specific to your organisation. It uses the same evidence model as the built-in library and can be
edited or deleted later.

### How do I see which ticket belongs to a finding?

Open the finding (click its ID anywhere). The "External tickets" section lists tickets a push
connection opened for it: reference, system, state (Open, In progress, Blocked or Resolved) and
the last error if sending failed. State flows back on each sync and updates the finding's
assignment status. A resolved ticket marks the assignment resolved but does not close the
finding; the next scan decides that.

### How do I get step-by-step instructions to fix a finding?

Open the finding (click its ID anywhere) and read "How to fix this": a summary, why it matters,
ordered steps, how to confirm it is fixed, what to do if you cannot fix it now, effort and
references (OWASP, CIS, NIST, CISA, CWE). It also says what it matched on, and is tailored from
what Quanta knows: the dependency's fixed version and typical upgrade command, a Windows KB
number, CISA KEV listing, high EPSS, a breached SLA, and what the scanner itself recommended.
On the Code Scan page (`/quanta-scan`), use the "How to fix" button in the Guidance column. It
changes nothing itself and states plainly what Quanta can automate for that finding (a playbook,
isolation plan, dependency-upgrade plan, a code fix on a branch, or nothing).

### What does Quanta recommend if I cannot fix a finding right now, and how complete is the guidance?

Each guidance entry lists compensating controls for that class of issue. If you have recorded the
asset's controls on the Security Controls page (`/controls`; or, older, in
`remediation/config/security_controls.yaml`, which ships empty), the guidance shows your actual
coverage; otherwise it says the controls are general and how to add the asset. The knowledge base (`remediation/guidance/knowledge.yaml`) is curated by
hand for 29 common classes, not every CWE; an unmatched finding gets a generic approach,
labelled generic. Compensating controls reduce risk, they do not close the finding.

### How do I set up scheduled reports or team alerts?

Two related pages. `/reports` generates an on-demand snapshot (pick a period, view or
download it) and has its own "Schedule automatic email reports" panel. `/notification-
settings` is the fuller surface: the same report-schedule config, a second config block
for team alert subscriptions (critical findings, zero-days, KEV/EPSS matches), a
Preview/Send-Test flow (build the real email, then confirm-gate an actual send - only
works if `SMTP_HOST`/`SMTP_PORT`/`SMTP_FROM_ADDRESS` are configured), and a "Run checks
now" button that runs the same due-subscription logic the background scheduler runs
hourly, on demand.

### How do I use AI Assist, and how is it different from Ask Quanta?

**AI Assist** (`/ai-assist`) is the one feature that calls the real Claude API: pick a
finding, pick an action (explain it in plain English / draft remediation steps / write an
executive summary), and confirm to spend real API usage - unconfirmed, you get a free
preview of the exact prompt that would be sent. **Ask Quanta** (`/ask`) is a
different, free feature: type a question in plain English and it deterministically
matches it against real query shapes (a finding ID, a CVE, a count, an asset name) or, if
nothing structured matches, against this FAQ file's own entries by keyword overlap - it
is explicitly **not an LLM and not a chatbot** (its own source comment says so), which is
also why it can never hallucinate an answer: no match just means no match. If you're
looking for a persistent, conversational chat interface - there isn't one anywhere in
this app today.

### What is ML Insights, and what does it actually compute?

`/ml-insights` runs two real, unsupervised scikit-learn techniques over the live
findings/asset data on every page load - no login required, no writes: an IsolationForest
flags statistically anomalous assets (with a human-readable "why flagged" reason), and
KMeans clusters findings into groups you can drill into by size/dominant severity/average
CVSS+EPSS. See "Is there real machine learning anywhere in this app now?" above for what
this deliberately does **not** do (no supervised prediction, no "this will get exploited"
forecasting).

### How does this compare to ServiceNow's Vulnerability Response / USEM module?

The short version: Quanta's core bet is that **remediation**, not just detection, is
the differentiator — three separate mechanisms by asset domain (Ansible playbooks for
Windows/Unix, a real git-branch-and-PR flow for application code, and a
compensating-control-only recommendation track for OT/IoT that deliberately never
generates a patch script) under one RBAC/approval model, rather than one generic
"auto-remediate" button. ServiceNow announced its intent to acquire Armis on December 22,
2025, specifically to extend USEM's coverage into OT/IoT/medical devices — which both
validates that gap as real and shows ServiceNow actively closing it, so treat this as a
genuine ongoing competitive space, not a settled advantage. The full breakdown (cost-per-
asset research, feature-by-feature comparison, and where legacy tools still legitimately
win — longer track record, bigger integration ecosystems, formal certifications Quanta
doesn't have yet) is in `docs/enterprise-suite/whitepaper.html` §02 and
`docs/enterprise-suite/pricing.html` §02/§09.

### Has Quanta filed for, or been granted, any patents?

No. A patent-landscape review (not a legal opinion — no attorney has been consulted) found
that the broad concept of "AI analyzes a vulnerability and generates remediation
instructions" is already claimed by multiple existing patents from other companies
(including a Fortinet SOAR-playbook patent and Veracode's April 2025 patent for its
"Veracode Fix" tool), so a patent on that idea alone is unlikely to be novel or grantable.
A couple of narrower angles — the specific three-way domain segregation described above,
and the prompt-injection-resistant "treat external data as data, not instructions" framing
used throughout the ingest/planning subagents — are flagged as candidates worth a real,
licensed patent attorney's independent assessment, not claimed as patentable here. Nothing
in this product should be represented as "patent pending" unless and until a real filing
happens. See `docs/enterprise-suite/whitepaper.html` §04 for the full assessment and
sourcing.

### How are support tickets prioritised, routed and measured?

Priority is impact x urgency (P1 to P4). Rules route a ticket to a team's queue; team
members work that queue, administrators see all of it. Each priority has response and
resolution targets with at-risk and breached states, and the resolution clock pauses while
a ticket waits on the requester. The Analytics tab shows SLA compliance, first-response
time, mean time to resolve, reopen rate, backlog age and workload by team and assignee. A
ticket can link to a finding, and the findings queue badges findings that have open tickets.
Breaches alert the assignee, team manager and admins once per level (email only if SMTP is
configured); requesters can rate a resolved ticket 1 to 5 and the Analytics tab reports
satisfaction. Policy lives in `remediation/config/support_sla.yaml` and
`support_routing.yaml`. See [SUPPORT.md](SUPPORT.md).

### What if I find a bug or need help?

See [SUPPORT.md](SUPPORT.md) — the short version: open a ticket from the in-app Support
page for bugs and features, use the private contact in [SECURITY.md](../SECURITY.md) for
security issues, and check [KNOWLEDGE_TRANSFER.md §12](../KNOWLEDGE_TRANSFER.md#12-troubleshooting--things-that-tripped-us-up)
first for known environment gotchas (Docker unavailability, GitHub secret-scanning
false-positives on fake demo credentials, etc.) before filing something that's already
documented.
