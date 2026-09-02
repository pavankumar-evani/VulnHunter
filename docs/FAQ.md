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
Building *real* multi-tenant MSSP support needs a database and an auth/RBAC layer
first — a business/architecture decision, not something that can be bolted onto the
current filesystem-reading MVP incrementally without rebuilding it. See
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

### Does it track who owns each asset?

Yes — `/assets` aggregates every asset with findings against it (finding count, highest
severity, KEV exposure) and lets you attach an owner/team, stored in
`remediation/inventory/asset_ownership.json`. That's a real, editable local file, not a
sync from a real CMDB/asset-management system - see the module docstring for what a
production version would need instead.

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
- VulnHunter itself has no Perl in it.

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

There's no in-app request form — file a GitHub issue using the **Feature request**
template (`.github/ISSUE_TEMPLATE/feature_request.md`), which walks through the safety-
model checklist (e.g., any new remediation-fixer subagent must stay Read/Write-only)
before the request is scoped. See [SUPPORT.md](SUPPORT.md).

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

### How do I set up scheduled reports or team alerts?

Two related pages. `/reports` generates an on-demand snapshot (pick a period, view or
download it) and has its own "Schedule automatic email reports" panel. `/notification-
settings` is the fuller surface: the same report-schedule config, a second config block
for team alert subscriptions (critical findings, zero-days, KEV/EPSS matches), a
Preview/Send-Test flow (build the real email, then confirm-gate an actual send - only
works if `SMTP_HOST`/`SMTP_PORT`/`SMTP_FROM_ADDRESS` are configured), and a "Run checks
now" button that runs the same due-subscription logic the background scheduler runs
hourly, on demand.

### How do I use AI Assist, and how is it different from Ask VulnHunter?

**AI Assist** (`/ai-assist`) is the one feature that calls the real Claude API: pick a
finding, pick an action (explain it in plain English / draft remediation steps / write an
executive summary), and confirm to spend real API usage - unconfirmed, you get a free
preview of the exact prompt that would be sent. **Ask VulnHunter** (`/ask`) is a
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

### What if I find a bug or need help?

See [SUPPORT.md](SUPPORT.md) — the short version: open a GitHub issue on this repo for
bugs/features, use the private contact in [SECURITY.md](../SECURITY.md) for security
issues, and check [KNOWLEDGE_TRANSFER.md §12](../KNOWLEDGE_TRANSFER.md#12-troubleshooting--things-that-tripped-us-up)
first for known environment gotchas (Docker unavailability, GitHub secret-scanning
false-positives on fake demo credentials, etc.) before filing something that's already
documented.
