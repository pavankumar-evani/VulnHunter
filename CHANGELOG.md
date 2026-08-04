# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project doesn't yet have a formal
release/versioning scheme (tracked in [KNOWLEDGE_TRANSFER.md §9 Roadmap](KNOWLEDGE_TRANSFER.md#9-roadmap)).

## [Unreleased]

### Added
- **A real `network-security-device` finding in the sample data** (`remediation/sample-data/tenable_export.csv`)
  - a Palo Alto Networks PAN-OS GlobalProtect command injection (CVE-2024-3400), a
  real, well-known, actively-exploited 2024 CVE, filling the Infrastructure
  Vulnerabilities hub's previously-empty "Network Security" card. Added by actually
  re-running the real pipeline agents (`vuln-ingest-normalizer` →
  `threat-intel-enricher` → `remediation-planner`), not by hand-editing
  `normalized-findings.json` - the live CISA KEV/EPSS enrichment confirms it's
  genuinely KEV-listed (added 2024-04-12) with an EPSS score of ~99.999%, same as the
  rest of this repo's "real results from the last validated run" claim. Existing
  finding IDs (FIND-1 through FIND-14) were left untouched; the new record was
  appended as FIND-15 per the normalizer's stable-ID rule. Sample data now totals 15
  findings across 7 asset classes (was 14 across 6); 7 KEV-listed, 8 with EPSS ≥ 50%
  (was 6/7). All hardcoded test/doc counts referencing the old totals were updated to
  match.
- **Consistent findings tables (SLA + export) on the Security Domains hub pages**
  (`dashboard/static/js/findingsTable.js`, new shared module) - `/infrastructure` now
  shows a full live findings table (priority, clickable ID, SLA, KEV, EPSS, ATT&CK)
  for every infra sub-category combined, and `/appsec` shows the same table scoped to
  its SLA-tracked SCA/DAST findings (SAST/Secrets/Container/API stay card-links into
  `/vulnhunt`, since raw code-scan findings aren't SLA-tracked queue items by design -
  that distinction is called out on the page rather than faking an SLA for them).
  `/ai-vulnerabilities` gets CSV/JSON/MD export of its taxonomy + heat-map counts
  instead (its findings are honestly all zero today, so a findings table there would
  just be empty). All three now match the Live Remediation Queue's look, per the
  "sub-domain dashboards need to look consistent" ask.
- **Dismissible top threat-intel tip banner and a bottom page footer, shown on every
  route** (`dashboard/static/js/threatTip.js`, `dashboard/static/js/pageFooter.js`,
  new; wired once from `app.js`, living in `index.html`'s shell as siblings of `#app`
  so they persist across client-side navigation, same pattern as
  `flash-container`/`modal-root`). The top banner surfaces a real, live-computed fact
  from the same CISA KEV + FIRST.org EPSS data already on `/queue` (e.g. "N KEV-listed
  findings are past SLA", the single highest-EPSS finding) - never a canned message,
  and only ever says something the data actually supports; a close (×) dismisses it
  for the rest of the browser session (`sessionStorage`). The bottom footer shows
  live finding/playbook counts plus quick links to FAQ/Support/Priority Rules/scope
  docs. Both stay hidden on the login page and reappear immediately after sign-in
  (listening for the existing `vulnhunter-auth-changed` event, no reload needed).
- **Clickable finding ID opens a full detail view** (`dashboard/static/js/findingDetail.js`,
  new) — clicking any finding's ID in the live Remediation Queue opens a modal (reusing
  `dom.js`'s existing `openModal`/`closeModal` pattern) showing everything the normalized
  finding schema carries that the table row doesn't: source/source_ref, description,
  CVSS, full KEV/EPSS detail, asset OS, first-seen date, and the `recommended_fix` text,
  plus quick links to Ask AI and the remediation plan. Wired into `queue.js`; the table
  row's ID cell is now a `<button>` instead of a plain `<td>`.
- **Numbered pagination on the three main finding tables** (`dashboard/static/js/pagination.js`,
  new) — the live Remediation Queue, Code Scan Results, and Remediation Plan tables no
  longer dump every row into one unbounded scroll; they now slice to 15 rows per page with
  a Prev/1 2 3…N/Next bar, matching the "must not require scrolling the whole page" and
  "option to navigate next pages with numbering" ask. A `?highlight=<id>` deep link (from
  global search) now also jumps to whichever page the matching row lands on, not just
  scrolling within the current page. Page resets to 1 whenever a filter, sort, or the
  tenant selection changes.
- **SLA/priority definitions info panel on the Overview page** (`dashboard/static/js/pages/overview.js`,
  `dashboard/data.py`'s new `sla_and_priority_definitions()`) — a collapsible "What do
  Priority and SLA mean here?" block reading the *live* `priority_rules.yaml` values (not
  a hardcoded snapshot), so it can never drift from what `/priority-rules` actually has
  configured.

### Fixed
- **Sidebar/topbar chrome scrolled away with the page instead of staying fixed, and the
  content area could force the whole page to scroll vertically** (`dashboard/static/style.css`)
  — added a fixed-viewport app-shell (`html,body{height:100%}`, `body{overflow:hidden}`,
  `.app-shell{height:100vh}`) with only `.content` scrolling internally
  (`flex:1;min-height:0;overflow-y:auto`), needing `min-height:0` on `.main-column` too
  (the classic flexbox `min-height:auto` gotcha) so it can shrink to make room for its
  scrolling child instead of overflowing the shell.

### Changed
- **Security Domains nav trimmed to one entry per domain, not one per sub-category**
  (`dashboard/static/js/nav.js`) — SAST, DAST, Secrets Management, SCA, Container
  Vulnerabilities, and API Vulnerabilities are no longer separate sidebar items; they
  now appear only as cards on the Application Vulnerabilities hub (`/appsec`), same
  as before this change already did for those categories, just also removed from the
  main menu now. Infrastructure Vulnerabilities gets the same hub-page treatment
  instead of one flat link: a new `/infrastructure` page splits it into OS, Network,
  Network Security, OT/IoT, and Cloud Infrastructure sub-categories
  (`remediation/enrichment/infra_classification.py`, a lookup against `asset.type`,
  same honest "real category, 0 findings" treatment as Cloud Infrastructure - no
  cloud-asset finding in this repo's demo data yet). The Queue page gained a matching
  `infraType` deep-link param and filter dropdown. Certificate Vulnerabilities and AI
  Vulnerabilities stay top-level entries, unchanged - they're their own domains, not
  sub-categories of Application or Infrastructure. 17 new tests.

### Added
- **AI Vulnerabilities** (`/ai-vulnerabilities`, `remediation/enrichment/ai_vuln_taxonomy.py`)
  — a new top-level Security Domains category alongside Application and
  Infrastructure Vulnerabilities: ten real, established AI/ML security concepts
  (prompt injection, training-data/model poisoning, supply-chain compromise,
  improper output handling, excessive agency, unbounded consumption, model theft,
  misinformation, insecure plugin/tool design, sensitive information disclosure),
  each with a summary and concrete remediation guidance, plus an illustrative MITRE
  ATLAS tactic/technique cross-reference and heat map - same "keyword heuristic,
  verify before citing formally" honesty pattern as the existing MITRE ATT&CK heat
  map on the Risk Dashboard. New scanner detection guidance
  (`.claude/agents/vuln-scanner.md`) for AI/ML-specific patterns (prompt injection via
  unsanitized input, insecure model deserialization, excessive agent autonomy) for
  future scans - honestly shows 0 findings today since this repo's demo app has no
  AI/ML component, same treatment as DAST and API Vulnerabilities. 23 new tests.

### Fixed
- **Content area/login page biased toward the left edge on wide screens**
  (`dashboard/static/style.css`) - `.content` had `max-width` but no `margin: 0 auto`,
  so within its column-flex parent it stretched-then-capped flush against the left
  edge instead of centering, most visibly on `/login` (the sign-in card centers
  *within* `.content`'s own box, which itself wasn't centered in the viewport).
  Fixed by centering `.content`'s own box - verified the login card now sits at the
  exact viewport center regardless of window width.
- **Content area capped at 1200px regardless of viewport or sidebar state**
  (`dashboard/static/style.css`) - widened the default cap to 1600px, and removed it
  entirely while the sidebar is collapsed, since a fixed cap defeated the whole point
  of that full-screen view.
- **Permanent, confusing horizontal scrollbar in the sidebar** - not a text-wrapping
  bug (nav labels do wrap correctly), but every nav item's hover-tooltip: a CSS
  `::after` positioned absolute inside `.side-nav` (which has `overflow-y: auto`,
  forcing `overflow-x` to `auto` too per the CSS overflow spec) still counted toward
  `.side-nav`'s scrollable width even at `opacity: 0`/rest, inflating it by the
  tooltip's up-to-220px reach. Replaced the pure-CSS `[data-tooltip]::after` approach
  with a single shared tooltip element (`dashboard/static/js/tooltip.js`) positioned
  via JS on hover/focus and appended to `<body>` - living outside any scrolling
  ancestor's box avoids this class of bug for good, sitewide (KPI cards, tenant
  switcher, not just the sidebar), and clamps to the viewport as a bonus so a tooltip
  near a screen edge never renders off-screen.
- **Timing-based email-enumeration side-channel in local login** (`dashboard/auth/users.py`).
  `verify_login()` used `not user or not verify_password(...)`, whose `or`
  short-circuits and skips the deliberately-slow (600k-iteration PBKDF2)
  `verify_password()` call entirely when the email doesn't exist - an unknown-email
  login returned near-instantly while a known-email wrong-password login took the
  full PBKDF2 cost, a measurable timing difference an attacker could use to enumerate
  valid emails even though both cases returned the same `None`. Fixed by always
  running `verify_password()` against a real-or-precomputed-dummy hash regardless of
  whether the email exists (`_DUMMY_HASH`), so both cases pay the same cost. Two
  regression tests added to `tests/test_auth.py` (spying on `verify_password` to prove
  it's always invoked).
- **CSV/formula-injection (CWE-1236) in dashboard exports** (`dashboard/static/js/export.js`).
  `csvEscape()` handled CSV quoting/escaping correctly but not Excel/Sheets/LibreOffice's
  formula interpretation of a cell starting with `=`, `+`, `-`, or `@` - several
  exported columns are free text a logged-in user (or an uploaded CMDB CSV) controls
  (asset owner/team, exception reason/requester/approver), so a crafted "owner" name
  could execute a formula for whoever next opens the exported file. Fixed with the
  standard OWASP mitigation: prefix a leading `'` when a cell starts with one of those
  characters, forcing every spreadsheet app to read it as literal text.
- **Unescaped account-identity XSS in the topbar account chip** (`dashboard/static/js/auth.js`).
  `initAccountChip()` inserted `user.email`/`user.role` into a `data-tooltip` attribute
  without `escapeHtml()` - the one place these OIDC-sourced identity fields render
  unescaped (contrast `profile.js`, which already escapes the same fields correctly).
  Since `/api/auth/oidc/callback` takes `email`/`name` from the identity provider's
  `userinfo` response with only a non-empty check, a crafted value there could break
  out of the attribute and execute on every page load for that session. Fixed by
  escaping `email`, `role`, and the derived `initials` before insertion.
- **Unescaped asset-type value in the Remediation Queue's filter dropdown**
  (`dashboard/static/js/pages/queue.js`). `assetTypeOptions()` inserted `f.asset.type`
  into an `<option>` element unescaped, the one inconsistent gap in a file that
  escapes the identical field everywhere else it appears. `/queue` is an
  unauthenticated route, so this was reachable by any visitor if a future connector or
  manually-edited fixture ever put unvalidated text in `asset.type` (today's writers
  all constrain it to a fixed enum, so it wasn't yet exploitable through the app's own
  APIs - still fixed rather than left as a latent gap). Both findings came from a
  dedicated security-review pass across this session's work.

### Added
- **Container and API Vulnerabilities as real Security Domains categories**
  (`dashboard/static/js/pages/vulnhunt.js`, `appsec.js`, `.claude/agents/vuln-scanner.md`).
  `/vulnhunt`'s category classifier already had the data - the scanner has detected
  Dockerfile/container issues (root user, baked-in secrets, unpinned base images) since
  an earlier wave, they were just fallen through to the generic "Other" bucket (no
  CWE-250 mapping, and no CWE at all for "unpinned base image"). Added `CWE-250 ->
  Container`, a Dockerfile-path fallback for the no-CWE case, and new API-security CWE
  mappings (CWE-284/863/942/915), plus new scanner detection guidance for API/
  authorization issues (missing auth on a route, wildcard CORS, mass assignment) for
  future scans to actually find. Both get their own Security Domains nav entry and
  `/appsec` hub card. Honest about scope, matching the existing DAST precedent: API
  Vulnerabilities shows 0 findings today since the demo app has no planted example -
  not faked just to fill the category.
- **`.github/dependabot.yml`** — automated version-bump PRs for the real product
  dependencies (`dashboard/`, `remediation/config|connectors|enrichment`) and GitHub
  Actions. Deliberately excludes `vulnerable-demo-app/` and `vulnerable-demo-multilang/`
  - those are intentionally vulnerable scan-target fixtures, so an automated PR bumping
  their pinned-old dependencies would break the demo's purpose, not fix a real issue.
  Note this only controls future version-bump PRs - it doesn't affect Dependabot's
  Security tab alerts, which GitHub generates automatically from the dependency graph
  regardless of this file.
- **Pattern-matched owner/team suggestions for the Asset Inventory**
  (`remediation/inventory/pattern_recognition.py`) — answers the ask for "machine
  learning... to learn from the data and predict patterns for assets, hosts, IPs,
  MAC address, owners, or teams" honestly: this is a transparent, explainable, weighted
  pattern match (hostname naming convention, IP /24 subnet, asset type, MAC vendor OUI)
  against assets that already have an owner - explicitly NOT real ML, since a ~13-asset
  demo dataset is far too small to train or validate anything real on, and calling it
  "ML" would be dishonest in exactly the way this repo's other caveats aren't. Every
  suggestion shows its confidence and the exact reasons (hover tooltip), and a one-click
  "Use" button applies it - never automatic. 28 new tests
  (`tests/test_pattern_recognition.py`), plus `ip`/`mac` fields added to
  `build_asset_inventory()`'s rows so the signals have real data to work with.
- **Tenant logo + location on the (illustrative) tenant switcher** (`dashboard/static/js/tenant.js`,
  `nav.js`) — each demo tenant now shows a generated initials avatar (like GitHub/Slack
  show for an org with no uploaded logo, not a fabricated real company logo - these
  demo "tenants" aren't real companies) and a location line (e.g. "New York, USA").
  "All Tenants" shows a neutral generic icon and no location, since it's the aggregate
  view. Re-renders instantly on tenant change, no page reload.
- **Collapsible sidebar** (`dashboard/static/js/sidebarToggle.js`) — a topbar button
  slides the left nav fully out of view for a full-width, distraction-free content
  area, and back again. Built entirely on standard web-platform features (a `<button>`,
  a CSS class toggle animated via `transition`, `localStorage` for cross-reload
  persistence, and the `inert` attribute so collapsed nav links can't be tabbed into) -
  no vendor-specific code, so it behaves identically across Chrome, Edge, Firefox,
  Safari, and Opera. Fails gracefully to the expanded default if `localStorage` throws
  (e.g. Safari private browsing).
- **"Integrations" nav renamed to "Adaptors"; Infoblox and Axonius asset-discovery
  connectors** (`remediation/connectors/infoblox_connector.py`,
  `remediation/connectors/axonius_connector.py`) — the three "Integrations — X" sidebar
  groups (Ticketing/SOAR, SIEM, XDR/EDR) are now "Adaptors — X", plus a new
  "Adaptors — Asset Discovery / IPAM" group. Infoblox pulls DNS host records from an
  NIOS grid via the documented WAPI `record:host` object (HTTP Basic auth); Axonius
  pulls aggregated device records via its documented `api-key`/`api-secret` header auth
  and `/api/devices` endpoint. Both are **pull** connectors like Tenable/Armis/
  CrowdStrike (reference pages at `/infoblox` and `/axonius`, no send form), but unlike
  every connector before them they normalize into a plain **asset-inventory** record
  (`name`, `ip`, `mac`, `type`, `source`, `source_ref`, `extra`), not a vulnerability
  Finding - since VulnHunter's asset inventory has so far been built entirely from
  findings, not a real CMDB/DNS/IPAM system. Same "built against public docs,
  unit-tested against mocked HTTP, unverified against a live tenant/grid" honesty
  pattern as every other connector in this repo (33 new tests, 489 total).
- **CMDB CSV import for the Asset Inventory** (`/assets`,
  `/api/assets/cmdb-import/*`, `remediation/inventory/cmdb_import.py`) — upload a CSV
  export of asset details; guesses which column is the asset name/owner/team via a
  keyword heuristic (adjustable, same non-authoritative pattern as the ATT&CK/
  compensating-control heuristics), reconciles each row against the real,
  finding-derived asset list (matched / not-yet-seen / invalid), and bulk-applies
  owner/team via the same upsert the single-asset "Edit owner" form already uses.
  CSV, not a fabricated `.xlsx` binary parser - same "no new dependency" reasoning as
  the CSV/JSON/MD export feature.
- **Local auth MVP + OIDC-ready SSO** (`dashboard/auth/`) — PBKDF2-HMAC-SHA256 password
  hashing and a from-scratch HMAC-signed session cookie, both Python stdlib only (no
  `bcrypt`/`passlib`/`itsdangerous` dependency added); `/login`, `/profile`
  (change-password, logout), an account chip in the topbar. A real OpenID Connect
  Authorization Code + PKCE client (`dashboard/auth/oidc.py`) built against the public
  spec using `requests` (no `authlib`/`python-jose` added) - inert (the "Sign in with
  SSO" button stays hidden) unless a real provider's `OIDC_ISSUER`/`OIDC_CLIENT_ID`/
  `OIDC_CLIENT_SECRET`/`OIDC_REDIRECT_URI` are configured, same "built vs. verified"
  honesty as every connector in this repo. RBAC gates only sensitive mutation routes
  (real connector sends, real pipeline runs, real AI-assist calls, priority-rule edits,
  exception create/revoke, asset owner/facing edits) - every read route stays open, a
  scope decision stated plainly in `dashboard/README.md`. Opt-in local HTTPS via
  `SSL_KEYFILE`/`SSL_CERTFILE` env vars; a real deployment should terminate TLS at a
  reverse proxy instead.
- **Jira, Splunk, and CrowdStrike Falcon connectors** (`remediation/connectors/
  jira_connector.py`, `splunk_connector.py`, `crowdstrike_connector.py`) — same
  "built against public docs, unit-tested against mocked HTTP, unverified against a
  live tenant" pattern as the existing ServiceNow/Tenable/Armis connectors. Jira and
  Splunk are push connectors with dashboard preview/send pages (`/jira`, `/splunk`);
  CrowdStrike is a pull connector (OAuth2 client-credentials + query/fetch-entities),
  documented on a reference page (`/xdr`) rather than a send form, matching how
  Tenable/Armis are also CLI/connector-driven with no dashboard send UI.
- **Interactive global search** (`dashboard/static/js/search.js`) — a topbar search box
  across Code Scan and Remediation Queue findings by ID/title/CVE/asset name; results
  deep-link to the matching page with `?highlight=<id>`, which scrolls to and
  highlights the row (or explains why it's filtered out / not found).
- **System-notification feed** (`/inbox`, `/api/notifications`,
  `dashboard_data.build_notifications()`) — real, system-generated events (SLA
  breaches, CISA KEV-listed findings not yet SLA-breached, exceptions expiring within
  14 days, pending generic-ingested findings) - explicitly not person-to-person
  messaging, which would need the auth/user system this wave also added. A bell icon +
  dropdown on every page; read/dismissed state is tracked client-side (localStorage),
  since there's no per-user server-side state to track it against yet.
- **Risk Management dashboard** (`/risk`, `/api/risk/attack-heatmap`) — a MITRE ATT&CK
  heat map (tactic × technique, covering every technique the keyword heuristic
  supports, including zero-count ones, not just what appears in today's findings), top
  vulnerabilities by type (grouped by CVE, showing affected-asset count and owner/
  team), top assets by critical-finding count, an editable internal/external-facing
  classification per asset (manually set, never auto-detected from a network scan -
  `remediation/inventory/asset_inventory.py`'s `set_facing`), and a CVSS v3.1
  severity-definitions reference.
- **Compensating-control suggestions** (`remediation/enrichment/
  compensating_controls.py`) — a keyword heuristic (same honesty pattern as
  `attack_mapping.py`) suggesting candidate compensating controls for a finding,
  surfaced on the `/exceptions` request form with one-click insert into the reason
  field.
- **Configurable prioritization model presets** (`/priority-rules`) — one-click
  toggles between a pure-CVSS/severity model (KEV/EPSS overrides disabled) and the
  shipped VPR-style, threat-intel-aware model (both overrides enabled) - both are the
  same underlying weighted-score engine (`priority_engine.py`), already fully custom
  via the YAML file; the presets just document and toggle the two most common starting
  points.
- **Client-side export** (`dashboard/static/js/export.js`) — CSV/JSON/Markdown-table
  download (of whatever's currently filtered/sorted on screen, not always the full
  dataset) wired into Code Scan, Remediation Queue, Remediation Plan, Exceptions,
  Asset Inventory, and both Risk-dashboard tables. "Excel" is offered as CSV (which
  Excel opens natively) rather than a fabricated `.xlsx` binary, since generating a
  real one would need a new dependency this project doesn't otherwise use.
- **Nav restructure**: a "Security Domains" group (Infrastructure Vulnerabilities,
  Application Vulnerabilities hub, SAST, DAST, Secrets Management, SCA, Certificate
  Vulnerabilities - each deep-linking into a pre-filtered Queue/Code Scan view) now
  precedes the renamed "Remediation Engine" group (Code Scan, Remediation Queue,
  Remediation Plan); Integrations split into Ticketing/SOAR, SIEM, and XDR/EDR
  sub-groups instead of one flat list; AI Assist moved to the Overview group, directly
  under Dashboard.
- **Vulnerability exception/waiver management** (`/exceptions`, `/api/exceptions*`,
  `remediation/exceptions/store.py`) — a documented, time-boxed risk-acceptance
  workflow: request an exception with a reason/compensating control, requester, and
  approver, with an expiry date after which it auto-expires (computed on read, never
  silently left "active" forever) unless explicitly revoked first. Surfaced on the
  Remediation Queue as a "Risk-accepted until <date>" tag. Honest scope limit: an
  active exception does not yet pause SLA-breach counting in the priority engine - see
  the module docstring.
- **Asset inventory + ownership** (`/assets`, `/api/assets*`,
  `remediation/inventory/asset_inventory.py`) — aggregates the asset data already
  scattered across individual findings into one row per asset (finding count, highest
  severity, KEV exposure), with an editable owner/team field persisted locally (same
  real-editable-config pattern as `priority_rules.yaml`, not a CMDB sync).
- **Finding-category taxonomy** (`remediation/enrichment/scan_type_mapping.py`) —
  classifies each remediation finding as Infrastructure Vulnerability Management,
  Software Composition Analysis (SCA), or Certificate/TLS Lifecycle Management, based
  on asset type; surfaced as a "Category" column + filter on the Remediation Queue.
  Dynamic Application Security Testing (DAST) is a documented category with no sample
  finding yet, rather than a fabricated one - see the module docstring. Static
  Application Security Testing (SAST) is `/vulnhunt`'s own findings by definition,
  handled separately.
- **Generic XDR/EDR/SIEM ingestion adapter** (`/api/ingest/generic`,
  `remediation/connectors/generic_connector.py`) — a vendor-agnostic "bring your own
  tool" webhook receiver: validates and normalizes an inbound JSON payload from any
  tool that can send a custom outbound webhook (most modern SIEM/XDR/EDR/SOAR products
  support this) into VulnHunter's normalized Finding schema, instead of building
  bespoke per-vendor connectors for products with no real API access to verify
  against. IDs continue the real pipeline's FIND-N sequence (never collide with a
  real finding's ID); writes to `remediation/live-data/` (gitignored), not
  auto-merged into the live queue - consistent with how live Tenable/Armis connector
  output is also not auto-merged.
- 69 new tests (`test_exceptions_store.py`, `test_asset_inventory.py`,
  `test_generic_connector.py`, `test_scan_type_mapping.py`, plus new
  `ApiExceptions`/`ApiAssets`/`ApiIngestGeneric` classes in `test_dashboard.py`) —
  full suite now 288/288 across 15 files.

### Fixed
- A real bug in `remediation/exceptions/store.py` and
  `remediation/inventory/asset_inventory.py`: their functions used bound default
  parameters (e.g. `def load_exceptions(path=DEFAULT_STORE_PATH):`), so
  `unittest.mock.patch.object(module, "DEFAULT_STORE_PATH", tmp_path)` in tests
  silently failed to redirect I/O to a temp file — Python binds a default parameter
  value once at function-definition time, so patching the module attribute afterward
  doesn't affect it (the same class of bug as `priority_engine.load_rules`'s
  documented gotcha). Tests were actually reading/writing the real shipped
  `exceptions.json`/`asset_ownership.json` files until this was caught (by the real
  seed files unexpectedly changing) and fixed by resolving the default path inside
  the function body instead.

- **AI Assist** (`/ai-assist`, `/api/ai-assist`, `dashboard/ai_assist.py`) — ask Claude to
  explain a finding, draft remediation steps, or write an executive summary, grounded in
  that finding's real data. Same dry-run-preview-by-default / explicit-confirm-to-spend
  pattern as `/run` and `/servicenow`: preview the exact prompt for free, confirm to
  actually call the real Claude API and spend usage/credits. A per-row "Ask AI" link on
  the Remediation Queue deep-links here with the finding preselected.
- **Reports** (`/reports`, `/api/reports/generate[.html]`, `dashboard/reports.py`) — a
  real, on-demand report generator (daily/weekly/monthly/quarterly/half-yearly/yearly
  framing) summarizing SLA, KEV/EPSS, risk-tier, and asset-coverage KPIs from the actual
  artifacts, downloadable as a standalone HTML snapshot. Honest caveat built into the
  report itself: without a persistence layer, every period currently renders the same
  real, current-moment snapshot rather than aggregating historical data.
- **Illustrative MSSP tenant-switcher demo** (`dashboard/static/js/tenant.js`) — a sidebar
  selector ("All Tenants" / "Acme Financial Corp (demo)" / "Northwind Bank (demo)") that
  partitions the same real findings by asset category on the Remediation Queue page, with
  a persistent on-page banner and FAQ entry making clear this is a UI-only illustration,
  not real per-tenant authentication or data isolation.
- **Categorization/filtering** on Code Scan (severity, CWE-derived category), Remediation
  Queue (priority, asset type, KEV-only), and Remediation Plan (risk tier, automation
  target) — all client-side over already-fetched data, with a live match count.
- **Live-refresh indicators** on Overview and the Remediation Queue — poll the same real
  API every 20s with a "Live · updated Xs ago" badge, so the dashboard reflects changes
  (e.g. a priority-rules edit) without a manual reload.
- **Visual/brand redesign** — a real SVG logo mark + favicon, a hand-drawn stroke-icon set
  replacing the earlier unicode-glyph nav icons, hover tooltips on every nav item and the
  tenant switcher explaining what each does, dark-mode-aware form inputs.
- **Support and FAQ pages** (`/support`, `/faq`) plus a full `docs/` folder (`USER_GUIDE.md`,
  `FAQ.md`, `AI_COMMANDS.md`, `INTEGRATIONS.md`, `REMEDIATION_WORKFLOWS.md`,
  `COMPLIANCE_MAPPING.md`, `SUPPORT.md`) covering usage, every AI-facing entry point,
  integrations, the remediation lifecycle, and an explicitly non-certifying
  control-mapping reference (NIST CSF / SOC2 categories - not a compliance claim).
- 37 new tests (`test_ai_assist.py`, `test_reports.py`, plus new `dashboard` API test
  classes) — full suite now 219/219 across 11 files.

### Changed
- **Dashboard: Flask + Jinja2 → FastAPI + a hand-rolled vanilla-JS single-page app.**
  Reframed from a hackathon entry toward a commercial-grade product, the ask included
  "modern JS interface" and using whichever of Java/JavaScript/Go/Python/Perl/PHP fit
  best. This machine has Python and Perl available but no Node/npm, Java, Go, or PHP
  runtime, and Docker's daemon was unreachable - so anything written in those other
  languages couldn't be compiled, run, or verified here. Rather than ship unverified
  code, the platform itself stayed on what's genuinely buildable-and-testable
  (`dashboard/app.py` is now FastAPI serving a JSON API at `/api/*`; the frontend is a
  real SPA - client-side routing, `fetch()`-based rendering, dynamic `import()` per
  page, live client-side table sorting - with zero build step). Every page was verified
  live in a browser during development, not just unit-tested. Full reasoning in
  [KNOWLEDGE_TRANSFER.md §11.1](KNOWLEDGE_TRANSFER.md#111-the-commercial-grade-polyglot-ask--what-actually-happened).
  `tests/test_dashboard.py` now uses `fastapi.testclient.TestClient` against the JSON
  API (31 tests, up from 25) rather than grepping rendered HTML, since there's no
  server-side HTML left to grep.

### Added
- **Multi-language code-scanning coverage.** `.claude/agents/vuln-scanner.md`'s
  detection guidance now explicitly covers JavaScript/TypeScript, Java, Go, PHP, and
  Perl (previously Python-only patterns plus generic/Docker/dependency checks) - real
  commercial scanners (Semgrep, Snyk, CodeQL) differentiate on breadth of *target*
  languages, not implementation language. New `vulnerable-demo-multilang/` fixtures (one
  small, realistic, intentionally-vulnerable file per language) and 31 new tests in
  `tests/test_multilang_scanner_patterns.py` verify the fixtures and the scanner's
  documented patterns stay consistent with each other via static text inspection - no
  Java/Go/PHP/Node runtime was available to actually execute the fixtures or run a live
  scan against them, so that's exactly what these tests do and don't claim.
- **Dashboard: SLA/priority engine, MITRE ATT&CK tagging, ServiceNow adapter, modern
  sidebar nav.** In response to a broader ask for a more "industry tool"-grade
  experience — built the realistic subset, deferred the rest with reasons (see
  [KNOWLEDGE_TRANSFER.md §11](KNOWLEDGE_TRANSFER.md#11-the-enterprisemssp-platform-ask--scope-reality-check)):
  - `remediation/config/priority_engine.py` + `priority_rules.yaml` — a configurable,
    form-editable (`/priority-rules`) scoring engine computing priority + SLA due
    dates/breach status per finding, independent of `remediation-planner`'s own static
    snapshot. Edits take effect immediately on `/queue` and the Overview KPIs.
  - `remediation/enrichment/attack_mapping.py` — MITRE ATT&CK technique tagging via
    keyword heuristic (explicitly documented as non-authoritative), surfaced on `/queue`.
  - `remediation/connectors/servicenow_connector.py` — creates ServiceNow Incidents per
    finding via the Table API, idempotent, with a no-credentials-needed preview mode at
    `/servicenow`. Same "built against docs, unverified against a live instance" caveat
    as the Tenable/Armis connectors.
  - New `/queue` (live, re-scored) page, distinct from `/remediate`'s static snapshot;
    sidebar navigation replacing the top bar.
  - 49 new tests at the time (`test_priority_engine.py`, `test_attack_mapping.py`,
    `test_servicenow_connector.py`, plus dashboard route tests) — full suite was
    145/145 across 8 files before the dashboard/scanner-coverage work above landed on
    top of it (now 182/182 across 9 files - see the entries above).
- **Live CISA KEV + EPSS threat-intel enrichment** (`remediation/enrichment/`,
  `threat-intel-enricher` subagent) — real, free, public, no-auth APIs, verified against
  the live endpoints during development (unlike the Tenable/Armis connectors). Moves
  `/remediate`'s prioritization beyond raw CVSS: `remediation-planner` now escalates a
  finding's priority when it's confirmed KEV-listed (actively exploited) or has EPSS ≥
  50% (high near-term exploitation probability) — never overriding `risk_tier`, which
  still gates what's safe to auto-apply. 13 new tests, including one deliberate live
  smoke test against the real APIs.
- **`application` and `certificate` asset classes** — `/remediate` now explicitly covers
  more than OS/infra findings: a Log4Shell (CVE-2021-44228) sample finding demonstrates
  application-layer library CVEs, and two new certificate/TLS sample findings (SSL
  expiry, deprecated TLSv1.0/1.1) demonstrate findings with no CVE at all. Both route to
  `manual-only` today, same honest-gap treatment as network/IoT.
- Dashboard now shows KEV-listed / high-EPSS KPI counts and an asset-class coverage
  table on the Overview page, and KEV/EPSS columns on the remediation queue.
- Sample data grew to 14 findings (was 11); full test suite now 96/96 across 5 files.

### Fixed
- A hand-counting error in `REMEDIATION_PLAN.md`'s summary (claimed 7 KEV-listed
  findings; the real, live-verified count is 6) — caught by cross-checking against the
  dashboard's programmatically-computed KPI rather than trusting the hand count.

## Tier 2 (headless CLI, dashboard, connectors)

### Added
- `cli/vulnhunter.py` — headless CLI wrapping `claude -p` so either pipeline runs from a
  script/CI/cron without an interactive session. Spend-capped, dry-run by default in
  spirit, with a JSON audit log per real invocation. 13 tests, no real API calls made in
  any test.
- `dashboard/` — MVP Flask web UI: overview KPIs, code scan findings, remediation queue
  linked to generated playbooks, playbook detail view, and a run-trigger page wrapping
  the CLI (dry-run by default). 14 tests via Flask's test client, no real server or API
  calls in any test.
- `remediation/connectors/` — live Tenable.io and Armis API clients implementing each
  vendor's publicly documented contract, writing output in the same file shapes as the
  sample data so the normalizer needs no changes. 18 tests against mocked HTTP
  responses. **Not yet verified against a real Tenable/Armis tenant** — no credentials
  were available while building this; see `remediation/connectors/README.md`.
- Full test suite now 78/78 passing across 4 files (pipeline artifacts, CLI, dashboard,
  connectors).

### Fixed
- A real UTF-8 mojibake bug: `subprocess.run(text=True)` without an explicit
  `encoding="utf-8"` decoded git's UTF-8 output with the platform default codec (cp1252
  on Windows), corrupting em-dashes and other non-ASCII characters. Fixed across every
  affected `subprocess.run` call; caught by manually verifying the dashboard's rendered
  pages, not by a pre-written test.
- An actual infinite loop in `TenableConnector.poll_export_status`'s timeout logic
  (an elapsed-time accumulator that a zero step size could never advance past). Fixed by
  switching to a wall-clock deadline. Caught by the test suite itself hanging.

## Tier 1 repo hygiene

### Added
- `LICENSE` (proprietary/all-rights-reserved), `SECURITY.md`, GitHub Actions CI running
  the test suite on every push/PR, `CODEOWNERS`, issue/PR templates, this changelog.

## 2026-08-03

### Added
- `TEST_CASES.md` — formal test case log (33 cases, TC-ID per test method, steps,
  expected vs. actual results, plus a "notable findings" section).
- `KNOWLEDGE_TRANSFER.md` — full KT doc: executive summary, problem statement, design
  rationale, product details, step-by-step operating instructions, repo map, test
  evidence, roadmap, and a troubleshooting log.
- `deliverables/` — Deloitte-branded hackathon pitch deck (`.pptx`) and full project/test
  report (`.docx`).
- `tests/test_pipeline_artifacts.py` — 33 automated tests (stdlib-only `unittest`)
  validating both pipelines' real output artifacts via git history and generated files.
- **Remediation engine (`/remediate`)**: ingests Tenable CSV, Armis JSON, and manual
  threat-intel JSON; normalizes into one Finding schema; plans remediation with risk
  tiers (`auto-approvable` / `needs-change-approval` / `manual-only`); generates
  reviewable Ansible playbooks for `windows-server` and `unix-server` findings via
  `remediation-fixer-windows`/`remediation-fixer-unix`. Network/firewall/IoT-OT asset
  classes are ingested and planned but not yet auto-remediated (documented gap, not a
  silent one).
- Validated `/remediate` end-to-end against realistic mock data: 11 findings normalized,
  7 Ansible playbooks generated, `REMEDIATION_PLAN.md` produced.

### Changed
- Corrected README's stated `/vulnhunt` demo numbers (9 findings / 6 auto-fixed) to match
  the actual validated scan, after the original estimate (~6 findings / 3-4 auto-fixed)
  was found not to match reality.
- `vuln-fixer` reworked to stop at `git push` instead of calling `gh pr create` — no
  `gh` CLI dependency; the PR-creation URL GitHub prints on push is the actual mechanism
  to open the PR.
- Safety story reworked from "run the scan in a Docker sandbox" to tool-scoping (no
  Edit/Write access for scanners, no Bash/network access for infra fixers) after Docker
  proved unreliable in the target environment — arguably a stronger safety model anyway.

### Fixed
- Reformatted a fake demo Stripe API key that was realistic enough to trip GitHub's
  secret-scanning push protection; rewrote the (not-yet-pushed) local git history to
  remove the flagged string from every commit.
- Two test assertions that produced false positives by matching comment prose instead of
  actual code (Dockerfile `USER` directive check, secret-removal check).

## 2026-08-03 (initial)

### Added
- Initial `/vulnhunt` pipeline scaffold: `vuln-scanner`, `vuln-triage-reporter`,
  `vuln-fixer` subagents, the `/vulnhunt` slash command, and the intentionally
  vulnerable `vulnerable-demo-app/` Flask app (6 planted vulnerabilities plus 3
  Dockerfile-level issues).
- Validated `/vulnhunt` end-to-end: 9 findings detected, 6 auto-fixed and pushed to
  `vulnhunter/auto-fixes-20260803`, `SECURITY_REPORT.md` generated.
