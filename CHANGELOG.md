# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project doesn't yet have a formal
release/versioning scheme (tracked in [KNOWLEDGE_TRANSFER.md §9 Roadmap](KNOWLEDGE_TRANSFER.md#9-roadmap)).

## [Unreleased]

### Fixed
- **Flaky CI test on `tests/test_file_lock.py`**: `test_without_the_lock_concurrent_increments_are_unsafe`
  relied on a `time.sleep()`-widened race actually manifesting within 50 iterations
  across 4 threads - a probabilistic assertion that could pass on Windows (where it was
  developed) while flaking on the Linux `ubuntu-latest` GitHub Actions runner, the
  likely cause of a real, recurring CI failure. Replaced with
  `test_without_the_lock_two_threads_reading_the_same_value_lose_an_update`, which uses
  a `threading.Barrier` to force two threads to both finish reading before either
  writes - a deterministic proof of the same lost-update race instead of hoping one
  shows up. Full suite re-verified 1161/1161 locally.
- **Broken Overview dashboard**: `overview.js` referenced `aiTrendAnalysisTileHtml()`
  without importing it (only the old `aiTrendAnalysisSectionHtml` was imported) - a
  `ReferenceError` that threw on every page load, confirmed live in-browser (showed the
  "Failed to load page" error banner instead of the dashboard). Found via a smoke-test
  sweep, not a targeted report.
- **Charts silently stacking instead of sitting side by side** (reported on
  Infrastructure Vulnerabilities, same root cause anywhere else two charts share a
  `.chart-row`): `pieChartSvg()`'s legend had no width limit, so one long category label
  could stretch the whole chart-block wide enough to push a sibling chart onto its own
  row at any viewport narrower than a wide desktop. Reproduced with real data at 1180px
  width (453.6px + 533.9px did not fit an 828.8px row) and fixed by capping
  `.chart-legend` to 150px with wrapping text, plus narrowing
  `severityChartBlockHtml`'s bar chart from its 420px default to 340px.

### Added
- **Dashboard Test Connection + Fetch forms for 7 connectors, plus 4 brand-new
  connectors** (Qualys VMDR, Prisma Cloud, Cortex XSIAM, Active Directory
  asset-inventory) - closes the gap between "a real connector class exists" and "a real
  person can actually try connecting it from the dashboard," for Tenable, Qualys, Prisma
  Cloud, Cortex XSIAM, Infoblox, Axonius, and Active Directory. Every form takes
  credentials fresh on every request (never stored server-side), offers a real,
  immediate **Test Connection** action (the smallest real authenticated call each
  vendor's API has), and a confirm-gated **Fetch Live Data** action:
  - Tenable/Qualys (CVE-scoped host-vulnerability sources) write a raw export file to
    `remediation/live-data/` - Qualys deliberately reuses Tenable's exact CSV column
    shape rather than teaching the ingest normalizer a second format. Bringing either
    into this dashboard's own pages still needs the existing, agent-driven
    `/remediate <file>` step (asset-type classification needs judgment, not a
    deterministic script).
  - Prisma Cloud/Cortex XSIAM (posture/correlated-detection sources, not CVE-scoped)
    normalize directly into the Finding schema and write straight to
    `remediation/live-data/*_findings.json`, ID-sequenced like the generic ingest
    adapter - deliberately not auto-merged into the live queue, same disclosed choice
    that adapter already makes for its own output.
  - Infoblox/Axonius/Active Directory (asset-inventory sources) reconcile real ip/mac
    ground truth directly into `asset_ownership.json` via a new
    `asset_inventory.reconcile_pulled_assets()` helper - the same real, bounded action
    CMDB CSV import already performs, now driven by a live API/LDAP pull instead of an
    uploaded file.
  - The Active Directory connector (`remediation/connectors/active_directory_connector.py`)
    is a new, separate concern from the pre-existing AD group-membership check
    (`dashboard/auth/ad_directory.py`) that gates Remediation Approvals - this one pulls
    the domain's computer inventory via LDAP instead, reusing the same `ldap3` dependency
    and mirroring `tests/test_ad_directory.py`'s fake-connection test-double convention.
  - All 4 new connectors follow the existing "real implementation of the vendor's
    documented API contract, unit-tested against mocked HTTP (or a fake LDAP connection
    for AD), never exercised against a live account" honesty convention - 91 new tests
    across 4 connector test files plus `asset_inventory`'s reconcile tests, and 35 new
    dashboard-route safety-boundary tests (rbac gating, field validation, the
    without-confirm dry-run guarantee) in `tests/test_dashboard.py`. Live-verified in a
    real browser against real external endpoints: a fake Tenable credential produced a
    genuine `401` from `cloud.tenable.com`, a fake Infoblox grid master produced a
    genuine DNS resolution failure, and a fake AD server produced a genuine `ldap3`
    connection error - proof the full credential → connector → real network path works
    end to end, not just that the code compiles.
  - `docs/INTEGRATIONS.md`, `docs/GOING_LIVE.md`, `docs/README.md`,
    `KNOWLEDGE_TRANSFER.md`, and `docs/VR_PLATFORM_COMPARISON.md` updated accordingly -
    Qualys/Prisma Cloud/Cortex XSIAM moved out of the "reference catalog, not yet built"
    tables into full connector sections; the cross-scanner dedup engine and Prisma
    Cloud/XSIAM roadmap items marked done where they'd been tracked as open.
- **A real open-source scan engine, not just another pull connector**:
  `remediation/connectors/openvas_connector.py` drives OpenVAS/Greenbone Community
  Edition (GVM) directly via GMP (Greenbone's protocol, over `python-gvm`) - create a
  target, create + start a scan task, poll it, pull real results - the first connector
  in this project that launches a scan itself rather than reading one out of a scanner
  someone already owns. Results flatten into Tenable's exact CSV shape (zero normalizer
  changes). New dashboard flow at `/openvas` (Connect → Start Scan → Check Status →
  Import Results - four steps, not one Fetch button, since a real scan can run for
  hours and a request shouldn't block on it). 21 new connector tests
  (`tests/test_openvas_connector.py`) plus 9 new dashboard-route safety-boundary tests,
  against a hand-rolled fake GMP client - **never exercised against a real GVM server**,
  same disclosed limitation as this project's other connectors. Full design, engine
  comparison (vs. Nessus/Nuclei/ZAP/Trivy), schema, and the "zero-security-headcount
  company's first scan" walkthrough in the new
  [`docs/VULNERABILITY_ENGINE_ARCHITECTURE.md`](docs/VULNERABILITY_ENGINE_ARCHITECTURE.md).
- **OWASP secure response headers**: every dashboard response now carries
  `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy`
  unconditionally (zero-risk - this SPA never used the capabilities they remove), plus an
  opt-in `Content-Security-Policy` (`VULNHUNTER_ENABLE_CSP=true`, off by default because
  this codebase's existing inline `style="..."` attributes need `style-src
  'unsafe-inline'` - shipping it on by default risked breaking the UI it's meant to
  protect). Same "opt-in, off by default" convention as `VULNHUNTER_REQUIRE_LOGIN_FOR_READS`.
- **[docs/GOING_LIVE.md](docs/GOING_LIVE.md)**: the operational checklist for actually
  connecting a real account - exact credentials needed per connector, exact commands/
  steps, and an honest split between what's ready today with zero code changes
  (ServiceNow/Jira/Splunk - real credentials typed into that connector's own page,
  never stored) versus what needs a script or Python session run outside the dashboard
  (Tenable/Armis via the existing `fetch_live_data.py`; CrowdStrike/Infoblox/Axonius,
  which have no such script yet - noted as a real, bounded next step once real
  credentials for any of them exist). States plainly, up front, that no connector in
  this repo has ever been exercised against a real account, and that going live
  requires real credentials this project has never had - not something further code
  changes alone can substitute for.
- **Word-wrap sweep** across ~35 table columns app-wide (Threat Intel Feed/Zero-Days/
  Matched Exploit Criteria, Certificate Vulnerabilities Title, Remediation Queue/Plan,
  and others) via a new opt-in `.wrap-cell` class - the shared `.data-table` `nowrap`
  default stays correct for short data cells, prose-like columns now wrap instead of
  overflowing.
- **Compact AI trend analysis tile** (`aiTrendAnalysisTileHtml()`) rolled out to all 5
  pages that have the feature (Overview, AppSec, Certificate Vulnerabilities,
  Infrastructure, Risk Management) - sits as a chart-block next to each page's
  team/priority (or aging) chart instead of pushing the page down as a full-width
  section at the bottom. `aiTrendAnalysisSectionHtml()` removed once confirmed unused
  anywhere.
- **Interactive Reports page**: every KPI (SLA breached/at-risk/on-track, CISA
  KEV-listed, High EPSS, Infra findings, Code vulnerabilities, Playbooks generated) is
  now a real deep link into a pre-filtered Queue/Code Scan/Remediation Plan view, and
  Top Priority Findings rows link to `/queue?highlight=<id>`. Added a matching
  `highEpssOnly` deep-link filter (mirrors the existing `kevOnly` one) since no
  equivalent existed for that KPI. Added a "Schedule automatic email reports" section
  directly on the Reports page (reuses the existing `/api/report-schedule` endpoint
  Notification Settings already exposed) so scheduling doesn't require leaving the page.
- **Clickable severity/team/priority chart bars** on AppSec, Certificate
  Vulnerabilities, Infrastructure, and Risk Management, via two new `queue.js` deep-link
  filters (`severity`, `team` - silent, exact-match, same pattern as the existing
  `cve`/`title`/`assetName`) plus deep-link support for the `priority` filter's existing
  dropdown. "Unassigned"/"Unknown" buckets are deliberately left non-clickable rather
  than link to a filter value that would misrepresent what was clicked.
- **[docs/VR_PLATFORM_COMPARISON.md](docs/VR_PLATFORM_COMPARISON.md)**: independently-
  verified research (not the AI-drafted source deck's uncited numbers) comparing
  VulnHunter and ServiceNow VR against Nucleus Security, DefectDojo, Brinqa, and
  ArmorCode - real sourced pricing/connector-count facts, VulnHunter's actual current
  gaps (no cross-scanner deduplication; only 8 connectors, 8 of 10 total integrations
  never exercised against a live account), and a phased roadmap recommendation.
- **Production-readiness pass**, closing/mitigating four of the real blockers named
  in a production-readiness assessment:
  - **Closing the anonymous-read gap (opt-in)**: `VULNHUNTER_REQUIRE_LOGIN_FOR_READS=true`
    is a new environment flag enabling `dashboard/app.py`'s `_require_login_for_api_reads`
    middleware - every `/api/*` route then requires a real session except the login
    flow itself. One middleware, not ~100 individual route changes, so the large
    existing test suite (which exercises the still-default OFF state) is completely
    unaffected. Also closes per-team RBAC's own documented anonymous-bypass caveat.
    Requires a real `VULNHUNTER_SESSION_SECRET` too - `rbac.validate_production_requirements()`
    (called at startup) refuses to start otherwise, since gating every read while
    sessions reset on every restart would lock everyone out.
  - **Real concurrent-write safety** for the highest-risk JSON stores: new
    `remediation/utils/file_lock.py` (a dependency-free, cross-platform advisory
    file lock - real threads/real filesystem tested, not just unit-tested in
    isolation) now guards the read-modify-write cycle in `activity_log.py`,
    `ai_usage_log.py`, `exceptions/store.py`, and `remediation_approvals/store.py`.
    Found and fixed two real bugs while building this: a clock-domain mismatch
    (comparing a monotonic-clock deadline against a wall-clock file mtime, which
    made stale-lock detection silently never trigger) and a missed `PermissionError`
    on Windows (a `CreateFile` racing another thread's concurrent unlink of the same
    lock file can raise `PermissionError` instead of `FileExistsError` - especially
    visible inside a OneDrive-synced directory - which was aborting the whole
    acquire loop instead of retrying). `asset_inventory.py` and `auth/users.py` are
    NOT locked yet - same real race, lower-frequency/admin-gated edits, disclosed as
    real follow-up in `dashboard/README.md` rather than done in this pass.
  - **Real deployment guidance**: new `.env.example` (every real environment
    variable this app actually reads, audited file:line, nothing invented) and a
    concrete nginx reverse-proxy + multi-worker `uvicorn` config in
    `dashboard/README.md`, replacing a one-line "use a reverse proxy" mention.
  - Corrected a stale claim in `dashboard/README.md`: Node.js/
    npm ARE installed in this environment (checked directly) - the "no Node.js" reasoning
    for staying on vanilla JS was accurate when originally written, on a different
    machine, but the actual reason to keep the current architecture is cost/risk of
    rewriting 30+ already-verified page modules, not a hard technical blocker.
  - 20 new tests (`test_file_lock.py`'s real-thread concurrency proofs, plus one
    concurrency test added to each of `test_activity_log.py` [new file],
    `test_ai_usage_log.py`, `test_exceptions_store.py`, `test_remediation_approvals.py`,
    plus the middleware/startup-check tests in `test_auth.py`/`test_dashboard.py`).
  - **Fixed a real UI bug** (reported live): the Threat Intel page's feed
    name+description table cells inherited the app-wide `.data-table` "no wrap"
    rule (correct for short data cells like IDs/dates/badges, wrong for a real
    descriptive sentence) and overflowed instead of wrapping - scoped fix via a new
    `.feed-name-cell` class, not a change to the shared rule every other table relies on.
- **Per-team RBAC on finding/asset views**: `dashboard/auth/users.py` gained a real
  `team` field (`create_user`, new `set_team()`/`set_role()`/`list_users()`), carried
  through the session cookie (`sessions.py`/`rbac.get_current_user()`) alongside
  `role`. New `dashboard/app.py` `_scope_to_team()` filters Queue, Asset Inventory,
  Exceptions, and Remediation Approvals to a logged-in non-admin's own team - a real
  server-side check (NIST AC-3/AC-4/AC-6, OWASP API1:2023 BOLA), not a client-side
  UI restriction. Findings don't carry their own team (only their asset does), so
  `_team_by_asset_name()`/`_annotate_finding_teams()` do the same asset→team join
  server-side that `assetLookup.js`'s `buildOwnerTeamMaps()` already does
  client-side. Overview/Dashboard, ML Insights, and Compliance stay org-wide by
  design (per the confirmed scope). Team-scoping is opt-in narrowing, not
  deny-by-default: no session, an admin, or an account with no team assigned all see
  everything unfiltered - see `_scope_to_team()`'s own docstring and
  `dashboard/README.md`'s new "What this is NOT (yet)" bullet for the full,
  disclosed limitation (it inherits this app's existing "reads are public" MVP
  posture; an anonymous request bypasses team-scoping the same way it bypasses
  every other read-route restriction today).
  - New Admin Settings "Team Management" section (list/create users, edit
    role/team inline) and a real `POST /api/admin/users`, `/team`, `/role` route
    family - there was previously no way to onboard a user or change a role at all
    through the running app, only by hand-editing `users.json`.
  - Profile page now shows the logged-in user's own team and an honest explanation
    of what it does/doesn't restrict.
  - Caught a real bug while testing this live: the first draft's queue/exceptions/
    approvals filtering read a `team` field that doesn't exist on a raw finding
    (only `assetLookup.js`'s client-side join adds it) - would have silently
    returned zero results for every team-scoped user regardless of team. Fixed by
    doing the same asset→team join server-side before filtering.
  - 42 new tests (`test_auth.py`, `test_dashboard.py`); full suite green
    (1132 tests).
- **Round 17 (in progress)**: production-readiness pass driven by a request for a
  searchable finding picker, real admin observability/billing, MAC/IPv4/IPv6 asset
  identification, and richer lifecycle visualizations.
  - **Searchable finding picker** (`searchableSelect.js`, new): replaces the native
    `<select>` on AI Assist and Exceptions (both dump 9,000+ findings into one
    unstyleable, overflowing OS popup) with a type-to-filter combobox - same
    interaction model as the Ctrl/Cmd+K command palette. The underlying `<select>`
    stays in the DOM so every existing `form.finding_id.value`/`change`-listener call
    site works unchanged.
  - **Admin Settings gained three real sections**, all sourced from data this app
    already collects (no new fabricated numbers):
    - **AI Spend vs. Budget**: real cumulative Claude API spend (today/7d/30d/all-time,
      `/api/admin/ai-usage`'s new `budget` field) against the real per-call spend cap
      (`cli.DEFAULT_MAX_BUDGET_USD`) - the only honest "billing" figure in an app with
      no subscription/invoice system.
    - **System Health**: `/api/status` now also reports real process uptime, whether
      the in-process notification scheduler is actually still running, and freshness/
      size of every gitignored runtime data store (exceptions, remediation approvals,
      activity log, AI usage log).
    - **Connector/Adaptor Health**: reuses `adaptorCatalog.js`'s own live/reference
      distinction (one source of truth, not a second copy) to report which connectors
      have a real wired preview/send form vs. are catalogued but not yet wired -
      honestly framed as "no stored credentials to health-ping," not a fake green
      check.
  - **Real MAC/IPv4/IPv6 asset support**: `asset_inventory.py`'s `ip`/`mac` fields
    existed but `mac` was always unpopulated and `ip` assumed IPv4-only.
    `pattern_recognition.py` gained `ip_version()`/`ipv6_subnet()`/`is_valid_mac()`
    (stdlib `ipaddress`, not hand-rolled parsing) and now votes on IPv6 subnet
    matches too, not just IPv4. New `set_network_info()` lets a human set/correct an
    asset's IP/MAC (validated, takes precedence over whatever a scan finding
    reported) via a new `POST /api/assets/{name}/network-info` route and Asset
    Inventory's existing edit modal. `/api/assets` rows now carry `ip_version` and a
    real `/24`-or-`/64` `subnet` grouping key.
  - **Subnet-based asset grouping**: Asset Mapping gained a "Group by: IP Subnet"
    view (`rankings.js`'s new `groupAssetsBySubnet()`) - which network segment
    carries the most distinct vulnerabilities, unioned correctly (not summed) across
    every asset in that subnet.
  - **Vulnerability Lifecycle funnel on Overview**: new `funnelChartSvg()` in
    `charts.js` (same hand-rolled-SVG, no-library convention as the existing bar/pie
    charts) renders Detected → Entered remediation workflow → Approved → Remediated,
    with real average time-in-stage, computed entirely from
    `remediation_approvals`' own real dated fields (`created_on`/`approved_at`/
    `triggered_at`) - reports an honest "—" (never a fabricated `0d`) when no record
    has completed that stage yet.
  - 22 new tests (`test_pattern_recognition.py`, `test_asset_inventory.py`) for the
    new IP/MAC validation and asset-inventory merge behavior; full suite green
    (1066 tests).
  - **"Ask VulnHunter"** (new `/ask` page, `remediation/search/query_engine.py`): a
    real, deterministic "ask your data" search - the free/open alternative to an
    LLM-based assistant the original request asked for. No external API call, no
    signup, no cost, no data leaves the machine; it is pattern/keyword matching over
    a fixed, disclosed set of real query shapes (finding ID, CVE, severity/KEV/SLA/
    team/owner/asset filters combined into a real count or list, else a real
    keyword-overlap match against `docs/FAQ.md`) - never an LLM, so it can never
    hallucinate: a query with no confident match says so honestly instead of
    guessing. New `POST /api/search/ask` route (no login required, same convention
    as `/api/queue`/`/api/assets`). Designed so a real hosted or local open model
    (e.g. Qwen3 via Ollama) could be layered on top later as an optional upgrade for
    more flexible phrasing, without changing this module. 26 new tests
    (`test_query_engine.py`) plus 4 new `/api/search/ask` integration tests; caught
    and fixed one real bug along the way (a bold-text FAQ excerpt that line-wraps in
    the markdown source wasn't being cleaned of `**`/`` ` `` markers, since `.` in a
    non-DOTALL regex doesn't match the newline mid-span).
- **Round 16 UX/scale pass (in progress)**: a large follow-on request driven by
  screenshots of the Asset Inventory, Exceptions, ML Insights, and Remediation
  Approvals pages at real data scale (thousands of rows) plus a request for session
  security and login/logout polish.
  - **Pagination everywhere large tables had none**: Asset Inventory (`assets.js`,
    20/page) and both Remediation Approvals tables (`remediationApprovals.js`) - the
    latter also gained domain-based grouping (divider rows, same taxonomy as
    Compensating Controls/Threat Intel) and a domain filter dropdown on both its
    "Findings awaiting approval" and "Approval requests" tables.
  - **ML Insights' Anomalous Assets table** (`mlInsights.js`) is now grouped by
    security domain too - each anomalous asset's domain is derived from its own real
    findings (majority vote via the existing `groupLabelFor()`, not a new fabricated
    asset-type-to-domain table), with the same filter-dropdown + paginated-grouped-rows
    pattern, plus a new "Domain" export column.
  - **Fixed a real, previously-shipped bug**: `overview.js`'s "Remediation-triggered
    findings" section referenced `triggeredPseudoFindings` inside `analyticsSection()`,
    a sibling function that was never passed it - a `ReferenceError` that broke the
    entire Dashboard/Overview page (the app's home page) on every load. Fixed by
    threading the value through as a parameter; caught via live-browser verification,
    not a linter.
  - **Fixed a real listener-stacking bug** in `assets.js` and `remediationApprovals.js`:
    both delegate a single click listener on the outer page container, but several
    actions call `render(container)` again on success (a full re-fetch+re-render) -
    without a guard, each such reload stacked another copy of the same listener on the
    persistent `#app` node. Both now stash the handler on the container and remove any
    previous copy before re-adding.
  - **Session inactivity timeout**: new `idleTimeout.js` - 15 real minutes of no mouse/
    keyboard/scroll/touch activity anywhere in the app (NIST SP 800-53 AC-11 / PCI-DSS
    8.2.8) calls the real logout endpoint, with a 60-second warm warning + live
    countdown first. Fixed default, not yet admin-configurable.
  - **Dedicated logout screen**: new `/logout` route (`pages/logout.js`) replaces the
    old behavior of dropping straight back onto the bare login form - a real
    confirmation screen with a distinct message for a manual logout vs. an idle-timeout
    one. Both logout call sites (`profile.js`, the topbar account menu in `auth.js`)
    now land here.
  - **Split-screen login/logout redesign**: new shared `authHero.js` - an original
    branded illustration (this app's own shield mark, radar-ring + network-node motif,
    brand-blue palette) in the general spirit of enterprise security products'
    split-screen sign-in pages, not a copy of any one product's proprietary design.
    Collapses to a plain centered card below 860px viewport width.
  - **Exceptions page modernized + really integrated with Remediation Approvals**
    (`exceptions.js`): domain-grouped pagination (same taxonomy as elsewhere) on the
    exceptions table; an expiring-soon badge (≤14 days) on each active exception's real
    `expires_on`; the request form reorganized into 4 labeled sections with quick-pick
    expiry buttons (+30/+90/+180 days) and a live "active for N days" preview. The real
    integration: selecting a finding that already has a remediation-approval record in
    progress shows its live status right on the form (the two workflows stay
    deliberately separate concepts - accept the risk vs. schedule the fix - this just
    makes an overlap between them visible instead of invisible), and the exceptions
    table shows each row's approval status too, both via the existing
    `remediation-approvals`/`queue` APIs, no new backend fields.
  - **Cross-tenant isolation audit**: confirmed via direct code audit (not assumed) that
    no server route trusts a client-supplied tenant identifier today - the "(demo)
    tenant switcher" (`tenant.js`) is 100% client-side/`localStorage`, unconnected to
    the real login system. Documented the real standards (NIST SP 800-53 AC-3/AC-4/AC-6,
    OWASP API1:2023 Broken Object Level Authorization, OWASP's Multi-Tenant Security
    Cheat Sheet) that any future per-team/tenant scoping (see the RBAC roadmap item)
    must be built against from its first commit - `KNOWLEDGE_TRANSFER.md` §11,
    `docs/FAQ.md`. Also fixed a stale FAQ claim ("no auth layer at all") that predated
    the real login system built earlier in this same round.
  - **Self-healing**: new `remediation/utils/retry.py` - a small retry-with-backoff
    helper (5 tests), wired into the two real network calls that can transiently fail
    (`kev_epss.py`'s CISA KEV/FIRST.org EPSS fetches, `email_sender.py`'s SMTP send),
    deliberately scoped to retry only genuinely transient exceptions (dropped
    connections, timeouts) - never authentication/permanent failures, which retrying
    can't fix. `/api/status` is now a real health check instead of a hardcoded
    `"status": "ok"` - reports actual checked facts (is the findings file readable, is
    SMTP configured, is a real session secret set, real threat-intel freshness), each
    check independently guarded so one broken check can't crash the others or the whole
    endpoint. Caught a real bug while testing this: the threat-intel-freshness check
    internally re-reads the findings file through an unguarded second call - fixed by
    giving each independent check its own try/except rather than one shared one.
  - **AI model/token governance + Admin Settings page**: new `/admin` page (admin-only,
    both server- and client-gated) covering everything asked for - which real model
    (`sonnet`/`opus`/`fable`, verified real aliases via `claude --help`'s own
    `--model` flag) every AI Assist/AI Trend Analysis/`/vulnhunt`/`/remediate` call
    should use, a real per-user daily token cap actually enforced server-side before a
    call is made (never trusted from the client), real per-user usage/cost (not
    estimated), and read-only system health (SMTP/session-secret/threat-intel status,
    reusing `/api/status`). New `remediation/config/ai_governance.py` (5 tests) and
    `remediation/audit/ai_usage_log.py` (12 tests) - usage/cost extraction from Claude
    Code's `--output-format json` response is deliberately defensive (tries multiple
    real key spellings, never guesses a number that wasn't actually present) since
    there's no officially published schema for that response envelope. `/api/ai-assist`
    and `/api/ai-trend-analysis` switched from `--output-format text` to `json`
    specifically so usage could be read at all. Caught and fixed a real bug while
    testing this: saving the model policy got silently reverted to null by a
    subsequent token-limit or override save, because only the limit form synced its
    own field back into the shared client-side state after saving - the model form
    didn't.
  - **Competitor-UX proposals**: clickable KPI tiles (Overview's SLA/KEV/code-scan/
    playbook tiles now use the existing `kpiLink()` pattern instead of the dead
    `kpi()` one, each landing on a REAL matching filtered view - added a new
    `slaStatus` deep-link filter to `queue.js` mirroring `dashboard_data.sla_summary()`'s
    exact breached/at_risk/on_track definition so the count on the tile always matches
    the count on the page it links to, and made `?kevOnly=true` deep-linkable +
    fixed the KEV-only checkbox to actually reflect that state visually, which it
    never did before); a new Ctrl/Cmd+K command palette (`commandPalette.js`, reuses
    `nav.js`'s own route list rather than a second copy) for instant keyboard-driven
    navigation to any page, from anywhere. Deferred saved-views, bulk actions on
    findings, and a first-visit tour as lower-value for this round.
  - **Real page-load performance fix** (found live-testing the above, not simulated):
    `dashboard_data.load_live_queue()` - the function behind `/api/queue` and
    `/api/overview` - was recomputing real priority scoring, exceptions, and
    remediation-policy resolution over all ~9,400 findings on *every single call*, by
    original design ("recomputed every call since those can change between
    requests"). That tradeoff stopped being free as the real sample dataset grew:
    profiled at **4.4 real seconds per call**. Fixed the same way `_load_scored_assets()`
    already was earlier this round - a cache keyed on the real mtime of every file
    that can actually change the output (findings, ownership, priority/risk/
    exploit-criteria/remediation-policy rules, exceptions, approvals), so a real edit
    to any of them is reflected on the very next call regardless of cache state, but
    an unchanged state now costs **~0.25s instead of 4.4s (~18x)**. Also bumped that
    cache's and `_load_scored_assets()`'s TTL from 5s to 30s (both are pure mtime-keyed
    backstops, so this costs zero real freshness) - measured live: Overview went from
    ~1.1-4.4s to ~0.3-0.5s per load. Shallow-copies every row before returning from
    cache, same in-place-mutation guard `_load_scored_assets()`'s cache already needed.
  - **Cloud provider (AWS/Azure/GCP/OCI/Alibaba Cloud) attribution + showcase data**:
    asked "I am not seeing the cloud vulnerabilities" - the real gap was
    discoverability, not data (1,388 real `cloud-infrastructure` findings already
    existed, ~428 already organically named AWS/Azure/GCP in their asset `os` string,
    e.g. "Amazon EKS worker node"). New `remediation/enrichment/cloud_provider.py`
    (13 tests) derives a `cloud_provider` field via real-content keyword matching -
    honestly `None` (not guessed) for a self-managed/multi-cloud asset like
    "Terraform-provisioned cloud resource". OCI and Alibaba Cloud had zero real sample
    findings, so added 10 new ones from 5 real, well-documented Kubernetes/container
    CVEs (CVE-2018-1002105, CVE-2019-11253, CVE-2024-21626, CVE-2022-0185,
    CVE-2024-3177 - independently confirmed relevant to Alibaba's ACK by Alibaba's own
    security bulletins, and equally applicable to Oracle's OKE), with real EPSS scores
    fetched live from FIRST.org and KEV status checked live against the actual CISA KEV
    catalog (neither fabricated). `REMEDIATION_PLAN.md` regenerated via the existing
    `bulk_plan.py` script to stay in sync. New "Cloud findings by provider" pie chart on
    the Infrastructure Vulnerabilities hub, and a Cloud Provider column (off by default)
    on the shared findings table and the Remediation Queue.
- **Cross-cutting platform hardening (12-part request, delivered as 13 parts)**: a single
  large ask spanning audit trail/ML coverage, search predictions, bulk asset policy,
  click-to-remediate, a tech-stack question, compact table columns, patch-management
  standards, an aggregate exposure score, sidebar/insights UX, threat-intel freshness,
  and quantum readiness. Researched first (3 parallel agents: patch-management
  standards + exposure scoring, quantum readiness, existing audit-trail gaps), then used
  3 scope-clarifying questions before planning (all "recommended" options chosen:
  click-to-remediate never executes against real infrastructure; asset `type` stays
  derived-only, never bulk-overridable; user-activity ML covers real recorded admin
  actions, not clickstream telemetry).
  - **Real, unified activity audit trail**: new `remediation/audit/activity_log.py`
    (`record_activity`/`list_activity`, gitignored JSON log) - every asset edit,
    exception revocation, approval decision, and login attempt now records who/what/
    when. New `/activity-log` page with a real `IsolationForest` "unusual activity"
    section (honest "not enough data yet" floor below `_MIN_ACTIONS_FOR_ANOMALY_DETECTION`).
  - **Search predictions**: `search.js`'s existing live-as-you-type dropdown gained
    keyboard nav (arrows/Enter) and a third "Assets" result group; `findingsTable.js`'s
    Asset/ID filters gained native `<datalist>` autocomplete from real distinct values.
  - **Bulk asset-editing policy**: new `remediation/inventory/asset_policy.py` +
    `asset_policy_rules.yaml` - match-and-set rules (name/type/environment/facing) for
    owner/team/environment/facing/remediation-schedule in bulk, real preview-then-apply,
    new `/asset-policy` page. New per-asset `remediation_schedule` override
    (`asset_inventory.set_remediation_schedule()`) takes precedence over a domain's
    default cadence in `remediation_policy_engine.py`, shown with an "override" badge.
  - **Click-to-remediate**: `cli/vulnhunter.py`'s `remediate_prompt()` and `/api/run`
    gained an optional `finding_id` to scope a run to one already-approved finding -
    reuses the exact existing dry-run-preview-then-confirm mechanism, never executes
    against real infrastructure. New `remediation_triggered` approval status
    (`mark_remediation_triggered()`) and a "Trigger Remediation" button on Remediation
    Approvals.
  - **Compact, per-user table columns**: new shared `columnPicker.js` (a native
    `<details>` disclosure, localStorage-persisted per table) wired into Queue (22
    columns), the shared findings table (Infra/AppSec hubs), Asset Inventory,
    Compensating Controls, and ML Insights' anomaly table - addresses a screenshot
    showing far more columns visible than useful at once.
  - **3 real NIST/CIS/ISO patch-management gaps closed**: a real staging-validation
    attestation (`mark_staging_validated()`, ISO 27002 §8.32) alongside the existing
    approval workflow; each finding's real generated-playbook `# Rollback: ...` comment
    now surfaced directly on Remediation Approvals instead of only inside the playbook
    file; asset-criticality-tiered SLA (CIS Controls v8 §7.2) - a real, disclosed asset
    `risk_tier` now multiplies the base SLA window (`sla_risk_tier_multiplier` in
    `priority_rules.yaml`), tightening it for Critical-risk assets and loosening it for
    Low-risk ones. New "Patch Management Standards" section in `docs/COMPLIANCE_MAPPING.md`
    naming what's covered vs. what needs real infrastructure this demo doesn't have.
  - **Aggregate Exposure Score**: new `remediation/enrichment/exposure_score.py` - an
    originally-authored, fully disclosed 0-100 rollup of average per-asset Risk Score,
    CISA KEV prevalence, and average FIRST.org EPSS - explicitly NOT claimed as
    equivalent to Tenable's Cyber Exposure Score (proprietary, unpublished formula) or
    any other named/certified score. New KPI tile at the top of Overview plus a "How is
    this calculated?" disclosure panel with live-interpolated weights.
  - **Sidebar scroll UX**: new `sidebarScroll.js` - up/down chevrons above/below
    `.side-nav`, shown only while it genuinely overflows and only for the direction
    with room left to scroll.
  - **Insights panel default-collapsed**: `insightsPanel.js` now defaults to collapsed
    on a first-ever visit (previously expanded) - still fully togglable and persists
    whichever state a user picks. Every page's `setInsightsContent()` call trimmed from
    stacked alerts+tips+glossary down to just the one real, page-specific alerts
    section.
  - **Threat-intel freshness workflow**: new `remediation/config/threat_intel_refresh_rules.yaml`
    (documents the real recommended CISA KEV/FIRST.org EPSS re-check cadence - CVSS
    itself never changes for an existing CVE, so there's nothing to refresh there) + a
    real "last refreshed" fact (from `normalized-findings.json`'s own real mtime) added
    to the existing global threat-intel banner, plus a `POST /api/threat-intel/refresh-now`
    (preview-then-confirm, admin-gated, reuses `kev_epss.py`'s real fetch logic) on the
    Threat Intel page - spends no Claude API usage, just two real free public REST calls.
  - **Quantum readiness**: new `remediation/enrichment/quantum_readiness.py` - a
    disclosed keyword classification (this app's schema carries no CWE field to join
    against) of already-real findings into "asymmetric crypto" (RSA/ECDSA/Diffie-Hellman
    - genuinely quantum-relevant, Shor's algorithm breaks exactly these) and "legacy
    protocol" (SSLv2/SSLv3/3DES/RC4/MD5-sig - classically broken already, not itself
    quantum-relevant). Found 30 real, already-organically-present matches in the
    existing sample data (e.g. `CVE-2011-5095` Diffie-Hellman, `CVE-2018-0735` ECDSA) -
    nothing fabricated. New `quantum-crypto` remediation-policy domain (cuts across
    normal asset classification the same way the "dev" environment override does) and
    new `/quantum-readiness` page citing real, verified NIST FIPS 203/204/205 (finalized
    August 2024) and NIST IR 8547 (draft, Nov 2024) migration deadlines - deliberately
    NOT attributed to NSA's CNSA 2.0, a separate framework with its own different
    2025-2033 schedule that a research pass caught this module almost conflating.
  - Docs: new FAQ.md/faq.js Q&As for the tech-stack question (no React/Node/Perl by
    design, real Ansible IaC already exists in the remediation-fixer subagents), the
    exposure score, staging validation/rollback surfacing, and quantum readiness.
  - New/updated tests throughout (`test_activity_insights.py`, `test_asset_policy.py`,
    `test_exposure_score.py`, `test_quantum_readiness.py`, plus extensions to
    `test_priority_engine.py`, `test_remediation_policy_engine.py`,
    `test_remediation_approvals.py`, `test_dashboard.py`, and others) - full suite at
    993 tests; live-verified in-browser across all 13 parts.
- **Real, unsupervised machine learning (`/ml-insights`)**: asked to make the app
  "ML-enabled" so it "can learn the behavior and patterns of the assets, vulnerabilities,
  remediation engine." Researched what's honestly trainable first (3 parallel Explore
  agents): this app's only real labeled data (`asset_ownership.json`) has ~5 entries -
  nowhere near enough for supervised learning without overfitting theater, so that
  conclusion (and the existing owner-suggestion heuristic) is unchanged. But
  `normalized-findings.json` has 9,000+ real findings across 8,000+ assets and 17 asset
  types - genuinely enough for real **unsupervised** learning, which needs no labels.
  - New `remediation/enrichment/ml_insights.py` (new dependency: `scikit-learn>=1.9`,
    verified via WebSearch as current-stable and Python-3.11-3.14 compatible): real
    `IsolationForest` asset anomaly detection (fit separately per asset type, so a
    certificate asset is judged against certificate peers, not the whole fleet),
    real `KMeans` finding risk-archetype clustering, and real `TfidfVectorizer` +
    cosine-similarity "similar finding" search - all genuinely fit at request time
    against live data, not canned output. Enforced floors
    (`_MIN_ASSETS_FOR_ANOMALY_DETECTION`, `_MIN_FINDINGS_FOR_CLUSTERING`) refuse to fit
    on too little data, same rule `pattern_recognition.py`'s docstring already states in
    prose, now enforced in code.
  - New `/ml-insights` dashboard page: an Anomalous Assets table (each row's "why
    flagged" names the real deviating feature(s) by z-score), a Finding Risk Clusters
    table with an expandable per-cluster member list, and a "Similar findings" section
    added to the existing finding-detail modal.
  - New routes: `GET /api/ml-insights/anomalies`, `/clusters`,
    `/clusters/{id}/members`, `/similar/{finding_id}` - wired via new
    `load_asset_anomalies()`/`load_finding_clusters()`/`find_similar_findings()` in
    `dashboard/data.py`, cached in-process the same mtime-keyed way
    `_load_content_enriched_findings()` already is.
  - **Never replaces or feeds into** the deterministic `remediation_policy_engine.py` or
    `priority_engine.py` - this is strictly an advisory insights layer alongside them.
    Still explicitly does NOT do supervised learning or remediation-outcome prediction
    (no real resolved/fixed_at field exists anywhere to learn that from).
  - **Real bug found and fixed during test-writing**: `detect_asset_anomalies()`'s
    "why flagged" explanation required each of its top-2 candidate features to deviate
    by at least 1.0 std dev - against the live dataset, 2 of 427 real flagged anomalies
    had their single strongest deviation land just under that cutoff (e.g. `CLOUD-0026`
    at exactly +0.996 std dev), producing a genuinely flagged anomaly with an empty
    explanation. Fixed so the single most-deviating feature is always reported
    regardless of magnitude; the second slot stays threshold-gated. Added a regression
    test reproducing the exact scenario.
  - Docs: new FAQ.md/faq.js Q&A, a cross-referencing docstring addition to
    `pattern_recognition.py`, and `KNOWLEDGE_TRANSFER.md`'s "AI-based anomaly/behavioral
    detection" deferred item marked built with its unsupervised-only scope stated.
  - New `tests/test_ml_insights.py` (synthetic, deterministic fixtures - a planted
    outlier/near-duplicate is expected to be found every run) plus new
    `ApiMlInsights` route tests in `tests/test_dashboard.py`; live-verified in-browser
    against the real dataset (real `LNX-AUTH01`/`LNX-DB03` KEV+EPSS outliers, 8
    differentiated real clusters, and the real Log4Shell finding family - `FIND-12` -
    correctly surfacing `FIND-619`/`FIND-622`/`FIND-623` as its most similar findings).
- **Environment (dev/prod) tag surfaced on Server and Application Vulnerabilities views**:
  asked for Server Vulnerabilities (Windows/Linux/Unix) to carry a dev/prod tag, then to
  research and add the same for Application Vulnerabilities so dev-tagged assets can be
  scheduled through the Remediation Policy engine. Investigation found the `environment`
  tag (Round 12) already worked correctly end-to-end for **every** asset type - fully
  editable on `/assets` for application/code-repository assets exactly like servers, and
  `_domain_for_finding()` already checks `environment == "dev"` before either
  `infra_category` or `scan_type`, so a dev-tagged application asset already routed to
  the `dev` policy domain the same way a dev-tagged server does. The real gap was
  **visibility**: the tag was invisible everywhere except the separate Asset Inventory
  page - nowhere on `/queue`, `/infrastructure`, or `/appsec` themselves.
  - **New Environment column** on `/queue` (`dashboard/static/js/pages/queue.js`) and on
    the shared findings table used by both `/infrastructure` and `/appsec`
    (`dashboard/static/js/findingsTable.js`) - same badge styling as the `/assets` page's
    own Environment select, now exported from `dashboard/static/js/assetLookup.js`
    (`environmentCellHtml`/`ENVIRONMENT_LABELS`) instead of staying private to
    `assets.js`, alongside a new `environmentByAssetName` map (mirrors the existing
    owner/team map pattern) so this needed no new backend/API work - the client-side
    join that already powers Owner/Team columns just gained a third field.
  - **New Environment filter** on `/queue` so admins can isolate dev-tagged findings
    directly for scheduling, without cross-referencing Asset Inventory separately.
  - **Closed a real, previously-unverified test gap**: the dev-environment override was
    only ever tested against an `infra_category`-based domain (`os`) - added
    `test_dev_environment_tag_wins_over_scan_type_too` to `test_remediation_policy_engine.py`
    confirming it works identically for a `scan_type`-based domain (`sca`), the exact
    path an application/code-repository finding takes.
  - **Tagged a real application asset** (`APP-ORDERS01`) as `environment: dev` in the
    seed data so the feature is visibly demonstrated for an application-type asset in
    the running app, not just `WIN-DC01` (already `prod` from Round 12).
  - **Incidental fix found during live verification**: the KEV emergency override in
    `remediation_policy_engine.py` was setting `change_type: "emergency"` without also
    clearing `auto_remediate`, so a KEV-listed finding in an `auto_remediate: true`
    domain (e.g. `dev`, `endpoint`) could show "emergency" and "Auto-Remediate: Yes" on
    the same Queue row - contradicting the documented ITIL 4 rule that emergency changes
    are "still approved, never skipped." Fixed so the override clears `auto_remediate`
    too, with a new regression test.
- **Full-taxonomy Remediation Policy + live communication templates + cloud vulnerability
  expansion (Round 13)**: after confirming Round 12's policy engine mechanism was sound,
  asked for its `communication_template` field (real, editable, but never rendered/sent
  anywhere) to be made actually usable, and for the engine itself to be expanded into
  "the most possible available, user-friendly, convenient, industry-standard patch
  management engine" with segregated policy workflows per major vulnerability category
  (infra/application/certs/AI/cloud/etc.), plus a specific check that cloud
  vulnerabilities have real, broad data flowing end-to-end.
  - **14 new policy domains** (`remediation/config/remediation_policy.yaml`), one per
    real category this app already tracks - `network`, `network-security`, `ot`,
    `virtualization`, `cloud`, `apps`, `printer`, `iac`, `runtime`, `sca`, `dast`,
    `cert-mgmt`, `secrets`, `ai-ml` - on top of Round 12's `endpoint`/`os`/`dev`/`default`,
    for 18 domains total. Since `_domain_for_finding()`'s resolver was already a pure
    dict lookup (no code change needed), this is purely config, each grounded in a real,
    citable convention: [NIST SP 800-82 Rev.3](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
    for `ot` (risk-based cadence, real maintenance windows "months apart," not a 30-day IT
    SLA); the real, current [Renovate/Dependabot patch-level auto-merge convention](https://www.systemshardening.com/articles/cicd/renovate-dependabot-security/)
    for `sca`; the real, current [ACME/Let's Encrypt 90-day auto-renewal standard](https://letsecure.me/acme-automation-ssl-renewal-best-practices-2026/)
    for `cert-mgmt`; `secrets` defaults to `change_type: emergency` on its own (a leaked
    credential is an assumed compromise); `iac`/`runtime` are explicitly documented as
    PR-merge/investigative-triage mechanisms, not maintenance-window patch cycles.
    Verified live against the real ~9,400-finding dataset: **0 findings now fall through
    to the generic `default` domain** (down from 100% of non-endpoint/os/dev findings
    before this round).
  - **3 new cloud-native PAM backends** (`aws-sts-assume-role`, `azure-managed-identity`,
    `gcp-workload-identity`) in `pam_vars_snippet()` - the same real, keyless,
    short-lived-credential posture as Round 12's Vault/CyberArk snippets, now grounded in
    real [`amazon.aws.sts_assume_role`](https://docs.ansible.com/projects/ansible/latest/collections/amazon/aws/sts_assume_role_module.html),
    [Azure managed identity](https://learn.microsoft.com/en-us/azure/azure-arc/servers/onboard-ansible-playbooks)
    (production-recommended, no stored secret), and
    [GCP Workload Identity Federation](https://docs.cloud.google.com/iam/docs/workload-identity-federation)
    (keyless token exchange) - independently verified, not recalled from memory.
  - **Communication templates - drafted, rendered, and actually sendable**: every
    finding's resolved policy now carries a live `rendered_communication` string
    (`dashboard/data.py`, using the real approver name once an approval exists). New
    `POST /api/remediation-approvals/{id}/send-communication` - the same
    dry-run-preview-then-confirm shape as every other real-send action in this app,
    reusing Round 11's real SMTP sender with zero new email code; honestly 503s if SMTP
    isn't configured rather than fabricating a "sent" response. `/remediation-approvals`
    gained a "Communication" action per request showing the exact rendered text with a
    real Send button.
  - **Cloud vulnerability data broadened beyond Kubernetes-only**: the `cloud`
    category's real, NVD-sourced sample data was Kubernetes/Docker-only in practice
    (1,097/1,097 rows) despite its query list nominally including "Amazon Web Services"/
    "Microsoft Azure"/"Google Cloud Platform" - those broad umbrella terms return far
    fewer real NVD keyword-search hits than "Kubernetes" does, so the two-pass fill
    always backfilled from the container queries. Added 15 new, specific real queries
    (Amazon S3, AWS Lambda, AWS IAM, Amazon RDS, AWS CloudFormation, AWS CLI, Amazon ECR,
    AWS Systems Manager, Azure Active Directory, Azure Storage, Azure DevOps, Azure CLI,
    Google Cloud Storage, Google Cloud SDK, gcloud) and raised the category target from
    1,100 to 1,400 - the regenerated file now genuinely spans Kubernetes/Docker/Terraform
    *and* real AWS/Azure/GCP provider-specific CVEs (~1,388 real findings after
    re-normalization/re-enrichment/re-planning at the new ~9,415-finding scale, still 100%
    real KEV/EPSS-enriched). Fixed a stale `infra_classification.py` docstring claiming
    cloud "has no sample finding yet."
  - **Real bug found and fixed along the way**: `dashboard/data.py`'s
    `parse_markdown_table()` split every table row on a bare `line.split("|")`, but
    `bulk_plan.py`'s writer correctly escapes a literal `|` inside a title as `\|` (valid
    Markdown) - one of the new real AWS CVE descriptions (a WordPress "... | LOGIN"
    plugin) was the first title in this app's history to actually contain a pipe
    character, silently dropping that one row (`len(cells)` never matched the header
    again) and surfacing as a real 9,414-vs-9,415 finding-count mismatch. Fixed with a
    new `_split_markdown_table_row()` that splits on unescaped `|` only and unescapes
    `\|` back to a literal `|` per cell - covered by new regression tests.
  - **Tests + docs**: extended `test_remediation_policy_engine.py` (all 18 domains
    resolve correctly against the real shipped file, the 3 new PAM backends, the
    `secrets` domain's own-emergency-not-via-KEV-override behavior) and
    `test_dashboard.py` (the new send-communication route's preview/confirm/SMTP-
    not-configured/login-gating branches, plus a new `ParseMarkdownTable` regression
    class for the escaped-pipe fix); bumped `test_ai_vuln_taxonomy.py`'s incidental-match
    ceiling (5→10) after confirming the new real matches - a real CVE in Amazon Braket
    (AWS's ML/quantum SDK) about unsafe deserialization among them - are genuinely
    on-topic, not false positives. `docs/REMEDIATION_WORKFLOWS.md`'s "Remediation
    Policy" section rewritten with the full 18-domain table and every new citation;
    `docs/FAQ.md`/`faq.js` gained two new Q&As (why some domains have no maintenance
    window; cloud vulnerability data's real provider-specific coverage).
- **Remediation Policy engine + AD/PAM-aware Remediation Approvals**: asked for a "real
  policy configuration workflow" governing how the remediation engine actually behaves -
  per-domain cadence/change-type/maintenance-window/auto-remediate rules (the literal
  EUC/server/dev examples given), plus AD/identity/PAM integration so approvals can be
  authorized "on behalf of humans" while humans stay in the loop on policy and decisions.
  Grounded in NIST SP 800-40r4 (patch management strategy), CIS Controls v8 Control 7
  ("automate OS and app patch management"), ITIL 4 Change Enablement's
  standard/normal/emergency vocabulary, real SCCM Automatic Deployment
  Rules/Maintenance Windows mechanics, and real PAM credential-broker patterns
  (CyberArk CCP, HashiCorp Vault dynamic secrets - both just-in-time, never cached).
  - **Policy config + engine**: new `remediation/config/remediation_policy.yaml`
    (admin-editable, same heavily-commented pattern as `priority_rules.yaml`) with
    `endpoint`/`os`/`dev`/`default` domains, each setting `change_type` (ITIL 4
    standard/normal/emergency), `cadence`, `maintenance_window`, `auto_remediate`,
    `requires_approval_group`, `downtime_expected`, a `$placeholder`-templated
    `communication_template`, and `pam_backend`/`pam_credential_path` - populated with
    the exact three examples given (weekly auto-patch-and-restart EUC via SCCM;
    monthly approval-gated server maintenance with downtime communication and a named
    AD approval group; nightly no-approval dev-environment auto-updates). New
    `remediation/config/remediation_policy_engine.py`: `policy_for_finding()` resolves
    a domain (asset `environment` tag → `infra_category` → `scan_type` → `default`)
    and applies a `kev_emergency_override` (KEV-listed always escalates to
    `emergency`, same override convention as `priority_rules.yaml`'s `kev_override`);
    `next_maintenance_window()` (pure date math); `render_communication()` (safe
    `string.Template.safe_substitute()` - an unknown placeholder is left as literal
    text, never crashes the page); `pam_vars_snippet()` (real Ansible lookup-plugin
    snippets for Vault/CyberArk PAS/CyberArk Conjur). Every finding on `/api/queue`
    gains a live-computed `remediation_policy` field (same "recomputed live, not
    baked in" convention as priority/SLA).
  - **The one judgment call, made explicit upfront and confirmed before building**:
    this repo's foundational safety line - `remediation-fixer-windows`/`-unix` never
    execute anything against real infrastructure, Read/Write tools only - stays
    unchanged. "AD/PAM integration... on behalf of humans" is built as (a) AD: a real,
    **read-only** LDAP group-membership check validating who's allowed to click
    Approve, never a write/reset/create; (b) PAM: never a Python-side credential
    fetch inside this app - a real Ansible lookup-plugin snippet embedded in a
    generated playbook's `vars:` block, with the actual credential-broker call
    happening later, at playbook-run-time, on whatever machine an organization's own
    change-management process uses to run it.
  - **Real, read-only AD/LDAP connector**: new `dashboard/auth/ad_directory.py`
    (mirrors `oidc.py`'s "dormant until configured, honest about never being
    exercised against a real environment" pattern exactly) using the new `ldap3`
    dependency (a genuinely new one, flagged plainly - no honest stdlib way to speak
    LDAP). `is_configured()` gates on `AD_SERVER`/`AD_BASE_DN`; `is_member_of_group()`
    does a real bind + search using AD's actual `LDAP_MATCHING_RULE_IN_CHAIN` OID for
    nested group membership, with an injectable connection so tests never open a real
    socket. New `GET /api/directory/status` route.
  - **Remediation Approvals workflow (the missing human-in-the-loop piece)**: today,
    `normal`/`emergency`-change-type findings had no actual approve/reject action -
    only the Exceptions/waiver store, which means something different (accept risk
    vs. proceed with the fix). New `remediation/remediation_approvals/store.py`
    (mirrors `exceptions/store.py`'s JSON-file + derive-status-on-read pattern
    exactly; `pending`/`approved`/`rejected`/`expired`, the last computed not stored).
    New routes: `GET/POST /api/remediation-approvals`,
    `POST /api/remediation-approvals/{id}/approve` (admin-gated; if AD is configured
    and the finding's policy names a `requires_approval_group`, runs the real LDAP
    check and reports the honest result - `ad_group_validated` is `null`, never a
    fabricated `false`, when AD isn't configured), `POST .../reject`.
  - **New `environment` asset tag** (`prod`/`staging`/`dev`/`unknown`, mirrors the
    existing `facing` field's manually-set/defaults-to-unknown convention exactly) -
    an asset tagged `dev` routes its findings to the `dev` policy domain regardless of
    its underlying infra classification. New `POST /api/assets/{name}/environment`.
  - **Dashboard UI**: new `/remediation-policy` page (YAML editor + a parsed
    human-readable summary table, same pattern as Priority Rules/Exploit Criteria);
    new `/remediation-approvals` page (a "needs approval request" list sorted by
    priority + an approval-requests table with Approve/Reject actions, an honest
    AD-configured/not-configured callout); three new Remediation Queue columns
    (Change Type badge, Next Maintenance Window, Auto-Remediate) sourced from each
    finding's already-resolved `remediation_policy`. New nav entries under
    Configuration and Remediation Engine respectively.
  - **Tests**: three new test files (`test_remediation_policy_engine.py` - domain
    resolution/fallback chain/KEV override/date math/PAM snippets, 22 tests;
    `test_ad_directory.py` - configured-gating + a fake `ldap3.Connection` double, 10
    tests; `test_remediation_approvals.py` - full store lifecycle, 18 tests) plus
    three new `test_dashboard.py` classes covering the policy/approvals/directory-
    status routes and the asset environment endpoint end-to-end, including the
    "AD not configured, honestly reported" branch. 830 tests passing overall.
  - **Verified live**: `/remediation-policy` renders the real YAML with a matching
    summary table; `/remediation-approvals` correctly shows KEV-listed findings
    (PrintNightmare, EternalBlue, Log4Shell, ...) as `change_type: emergency`
    regardless of domain default, and honestly reports "AD not configured" on
    approve since no real `AD_SERVER`/`AD_BASE_DN` exist in this environment; the new
    Queue columns render real per-finding policy data; a full approval
    request/approve/reject round-trip was exercised directly against the running
    server, then the test artifact was reset so no fabricated approval history ships
    in the demo seed.
- **Scheduled reports + team email alerts (real SMTP, dry-run-first)**: asked for
  configurable weekly/monthly/quarterly/half-yearly/yearly reports "sub-domain team
  wise" and email alerts for critical/zero-day/threat-intel findings to specific teams.
  - **Real SMTP delivery**: new `remediation/notifications/email_sender.py` sends real
    email via Python's stdlib `smtplib` - zero new dependency. Deliberately inert
    (`is_configured()` false, every send raises `EmailNotConfiguredError`) unless
    `SMTP_HOST`/`SMTP_PORT`/`SMTP_FROM_ADDRESS` (+ optional `SMTP_USERNAME`/
    `SMTP_PASSWORD`/`SMTP_USE_TLS`) are set as real environment variables - same
    "built against the standard protocol, not exercised against a real server" honesty
    as every other connector in this repo (ServiceNow/Jira/Splunk/OIDC).
  - **Sub-domain + team scoped reports**: `dashboard/reports.py`'s
    `generate_report_data()` gained `scope` (this app's existing scan_type taxonomy,
    or "all") and `team` (from `remediation/inventory/asset_ownership.json`) params -
    landscape-wide (scope="all", team=None) behavior is unchanged byte-for-byte from
    before. A scoped report explicitly discloses what it can't include (SAST/Code Scan
    findings have no team/sub-domain association; the static REMEDIATION_PLAN.md
    risk-tier snapshot/playbook count are whole-pipeline artifacts) via a new
    `scope_note` rather than silently zeroing them. New `render_report_text()` for the
    email plaintext body alongside the existing `render_report_html()`.
  - **Cadence scheduling**: new `remediation/config/report_schedule_rules.yaml`
    (admin-editable, same live-YAML-editor pattern as `priority_rules.yaml`) lists
    subscriptions (`scope`/`team`/`cadence`/`recipients`/`enabled`); new
    `remediation/notifications/report_scheduler.py` computes which are due (real
    rolling-window day-math per cadence, not a calendar-aware scheduler) and orchestrates
    building + sending each one. Last-sent tracking lives in a separate
    `schedule_state.json`, deliberately NOT inside the human-edited YAML, so an admin's
    own comments/formatting are never silently stripped by an automated write.
  - **Critical/zero-day/threat-intel team alerts**: new
    `remediation/config/alert_rules.yaml` + `remediation/notifications/alert_checker.py`
    - "zero-day" reuses the exact same KEV-listed-AND-Exploit-Criteria-match definition
    already shown on `/threat-intel` (not a new one invented here); "threat_intel" reuses
    the existing MITRE ATT&CK threat-actor-group correlation
    (`threat_actor_groups.py`), checked per finding instead of per group. An alert fires
    once per finding per subscription (`alert_state.json` dedup), not on every check.
  - **In-process scheduler + real cron-callable alternative**: `dashboard/app.py` starts
    a background timer (hourly by default, `NOTIFICATION_CHECK_INTERVAL_SECONDS` to
    change it) checking both due reports and new alert matches - honestly documented as
    only running while this server process stays alive (a restart resets the timer,
    though state-file dedup means it never double-sends). New
    `POST /api/notification-settings/run-checks-now` runs the identical check on demand -
    the real, uptime-independent alternative for a genuine external cron/Task Scheduler
    to call instead.
  - **New `/notification-settings` page**: SMTP configured/not-configured status: YAML
    editors for both config files; a preview/send-test panel (same dry-run-preview-by-
    default, explicit-confirm-to-spend pattern as AI Assist/ServiceNow/Jira) showing the
    exact subject/body an email would contain before ever sending one; a "Run checks
    now" button. Verified live: real team names populate the team dropdown from
    `/api/assets`; a report preview and a zero-day alert preview (106 real matches)
    both rendered correctly; the dry-run send-test path correctly returned
    "preview only" with no email sent; a real (confirm=true) send correctly 503s with
    SMTP unconfigured (tested via the automated suite, not triggered live).
- **Footer copyright**: `VulnHunter v1.0.0 · © 2026 Deloitte Development LLC.` corrected
  to `© 2026 VulnHunter LLC.` (`pageFooter.js`) - the LICENSE file's own copyright holder
  was left untouched (a separate, more significant legal decision than a footer string,
  out of scope here).
- **Right-hand "Insights" panel + CVD-validated chart colors**: reviewing a live
  screenshot of `/infrastructure`, the user pointed out the large empty space to the
  right of the content column and asked for it to carry page-specific guidance/
  definitions/highlighted alerts, be collapsible and drag-resizable, and separately
  asked why every bar chart rendered in one flat color regardless of category.
  - **Chart colors**: `charts.js`'s `barChartSvg`/`pieChartSvg` previously defaulted
    every bar/slice to the same `var(--brand-accent)` blue unless a caller passed a
    per-item color (none did). Replaced with two real color jobs, per the dataviz
    skill's color-formula method: Severity/Priority (Critical/High/Medium/Low) are
    ordinal/status data, so they now reuse this app's own `.badge-critical/high/medium/
    low` hex values - a chart's Critical bar matches every Critical badge on the same
    page. Everything else (team names, asset types, months, sub-categories - genuinely
    nominal data) draws from a new 8-hue, fixed-order categorical palette
    (`--chart-1`..`--chart-8` in `style.css`, light and dark steps), independently
    CVD-validated (protanopia/deuteranopia simulated, OKLab ΔE) against this app's own
    chart-card surfaces via the dataviz skill's `validate_palette.js` - both modes clear
    every hard gate (worst adjacent ΔE 9.1 light / 8.4 dark against an ≥8 target; worst
    normal-vision floor 19.6 light / 19.3 dark against a ≥15 floor); the light mode's
    3-slot contrast WARN is already mitigated by this app's existing visible bar-value/
    label text, not a new addition. Never reorder the 8 slots - the order is the
    CVD-safety mechanism.
  - **Insights panel**: new persistent `<aside id="insights-panel">` (index.html, sibling
    of `.main-column`, not inside the router-controlled `#app` region) showing tips,
    term definitions, and data-driven highlighted alerts. Collapsible (icon toggle,
    mirrors `sidebarToggle.js`'s exact collapse pattern) and drag-resizable (220-480px,
    handle on the panel's left edge) - both persisted via `localStorage`, both
    independently live-verified (collapse/expand toggles `.app-shell.insights-collapsed`
    and the correct width; a simulated drag correctly widened the panel and persisted
    the new width). New `insightsPanel.js` (`initInsightsPanel`/`setInsightsContent`/
    `resetInsightsContent`/`insightAlertHtml`/`insightTipsHtml`/`insightSectionHtml`) and
    `glossary.js` (a ~19-term dictionary of what Priority/Risk Score/Remediation
    Mechanism/Facing/etc. specifically mean IN THIS APP, since several mean something
    narrower here than the term suggests generically). `app.js` resets the panel to a
    generic glossary default before every route change, so a page that hasn't been given
    bespoke content still shows something real and useful rather than stale content from
    the previous page or a blank panel. Overview, Infrastructure, Application
    Vulnerabilities, Risk Management, and the Remediation Queue each call
    `setInsightsContent()` from within their own `render()`/auto-refresh `load()` with
    real, already-computed alerts (e.g. Infrastructure's panel live-verified showing
    "Only 0% (3 of 7888) of infrastructure findings have a team assigned... Import one on
    Asset Inventory" - a real, computed stat, not a canned message) - every other page
    falls back to the generic glossary. Hidden below 900px viewport width and on the
    login page (`.auth-page`).
- **Banking-blue rebrand**: replaced every green brand/status color across the app -
  `:root` CSS variables (`--brand`/`--brand-dark`/`--brand-accent`), the logo mark
  (`nav.js`/`login.js` inline SVG + `brand/logo-mark.svg`/`brand/favicon.svg`), the
  categorical chart palette (`charts.js`), and hardcoded literals in status badges/hover
  states/the live-pulse animation - with a new navy/cobalt palette. Introduced a
  dedicated `--success`/`--success-bg` teal pairing for "approved/live" status badges,
  kept deliberately distinct from both the new blue brand-accent and the pre-existing
  blue `--info-*` callout color, so those three meanings stay visually distinguishable
  instead of collapsing into one blue once green was no longer available to tell them
  apart.
- **Dashboard layout/centering fix**: `.content`'s width now resolves via
  `width: min(100%, 1600px)` instead of `max-width: 1600px` + `width: auto` - the old
  combination had a genuine flexbox bug (confirmed live) where content overflowed past
  the true viewport edge on wide screens once the 1600px cap started binding, because an
  auto-width flex item's cross-size doesn't reliably resolve against
  `min(max-width, available-space)` under a single non-auto margin. `margin-left` is now
  `max(0px, calc(50vw - 800px - var(--sidebar-w)))` (true-viewport-relative centering,
  not just centering within the space left after the sidebar), verified correct both
  edge-to-edge below the cap and exactly centered above it.
- **Team-wise / priority-wise breakdown charts, all 4 analytics dashboards**: a new
  shared `teamPriorityChartBlockHtml()` (`domainSummary.js`) renders "By team"/"By
  priority" bar charts from whatever findings subset the caller already has - wired into
  Overview, Infrastructure, Application Vulnerabilities, and Risk Management, each with
  its own honest scope disclosure where the underlying data doesn't cover every finding
  type on that page (e.g. AppSec's covers DAST/SCA/Repo Secret Scanning only - SAST has
  no team association in this data path).
- **AI-based trend analysis panel, real Claude integration, all 4 analytics
  dashboards**: reuses the exact same dry-run-preview-by-default / explicit-confirm-to-
  spend / admin-gated pattern the existing single-finding "AI Assist" feature already
  established (`dashboard/ai_assist.py` + `/api/ai-assist`, calling the real `claude` CLI
  binary), generalized to a page-level stats snapshot instead of one finding. New
  `build_trend_analysis_prompt(scope, stats)` (`ai_assist.py`) formats a flat dict of
  already-computed real numbers (severity/priority/team breakdowns, SLA/KEV/EPSS totals,
  etc.) into a prompt that explicitly instructs the model not to invent any number beyond
  what's given; new `POST /api/ai-trend-analysis` route mirrors `/api/ai-assist`'s own
  `AiAssistBody` shape (`confirm: bool = False` gates the real spend, same as the
  existing route - not a fabricated "AI insight" and never auto-run on page load). New
  shared frontend module `aiTrendAnalysis.js` (`aiTrendAnalysisSectionHtml`/
  `wireAiTrendAnalysis`) wired into Overview, Infrastructure, Application Vulnerabilities,
  and Risk Management, each with its own `build*AiStats()` scoped to that page's real
  data. On Overview specifically (which auto-refreshes every 20s), the AI panel's markup
  now lives outside the auto-refreshed `#overview-body` region so an in-progress or
  just-received (real API cost) response survives the next refresh tick instead of being
  wiped mid-read; its stats function is async and re-fetches fresh data at click-time
  rather than closing over a stale render-time snapshot. Verified live: the free
  dry-run/preview path returns the real prompt with genuine live stats embedded on all 4
  pages; the real (`confirm=true`) API-spend path was deliberately never triggered during
  this session's own verification, to avoid spending the user's real API usage/credits.
- **Open-finding age analytics (honest substitute for "remediated within 30/60/90
  days")**: the literal ask - remediation-completion analytics bucketed at 30/60/90 days,
  priority-based, sub-domain-wise - can't be honestly built from this pipeline's real
  data: there is no `remediated_at`/`closed_at` field anywhere in the schema and no
  historical re-scan-diffing, so "remediated within N days" isn't a computable metric
  here (confirmed by explicit repo-wide check before designing the substitute). Built
  the honest, adjacent alternative instead: new shared `agingChartBlockHtml`/
  `agingByPriorityTableHtml`/`agingBreakdownTableHtml`/`agingDisclaimerHtml`
  (`domainSummary.js`) bucket CURRENTLY OPEN findings by real first-seen age (0-30/
  31-60/61-90/90+ days) - a genuine backlog-staleness signal, explicitly and repeatedly
  disclosed in-UI as not a remediation-speed metric. Wired into Overview (landscape-wide,
  broken out by all 8 real scan-type sub-domains), Infrastructure (all 11 infra
  sub-categories), Application Vulnerabilities (DAST/SCA/Repo Secret Scanning - SAST
  excluded, no first-seen date in that data path), and Risk Management (live-queue-wide).
  Every "All sub-categories" grand total was verified live to tie out exactly against
  that page's own total finding count.
- **CMDB connector visibility**: research confirmed a real, working CMDB bulk-import
  feature already existed (`remediation/inventory/cmdb_import.py` + `/assets` UI) but was
  never listed in the Adaptors catalog, so it was undiscoverable from the connector hub.
  Added a new `cmdb-import` Adaptors catalog entry (`cmdbConnector.js`) documenting it
  honestly as a CSV bulk-import reconciled against the real asset list - explicitly not a
  live API sync, distinct from Infoblox/Axonius's actual live-pull connectors.
- **4 new Infrastructure Vulnerability sub-categories, real NVD-CVE-sourced**: **End-User
  Devices** (`windows-endpoint` - laptops/desktops; `mobile-device` - phones/tablets, both
  rolling into a new "endpoint" infra category, distinct from server OS patching),
  **Printers** (`printer` - HP/Xerox/Canon/Lexmark/Ricoh/Brother firmware CVEs), and
  **Virtualization** (`virtualization-host` - VMware ESXi/vCenter, Microsoft Hyper-V,
  Proxmox VE, Citrix Hypervisor, KVM/QEMU, Nutanix AHV). "OS Vulnerabilities" is renamed
  "Server Vulnerabilities (Windows, Linux/Unix)" now that `windows-endpoint` has moved out
  of it into the new endpoint category (a `windows-endpoint` asset type existed in the
  schema before this round but was never actually populated - it's now real, sourced
  sample data). All 4 new categories are sourced from real NVD keyword queries via the
  same `collect_real_cves()` infrastructure the 5 original infra sub-categories and
  DAST/SCA already use - not hand-authored. A new, purely informational
  `remediation_mechanism` field (SCCM/Microsoft Configuration Manager, MDM e.g. Intune,
  vendor firmware update, vendor hypervisor patch tooling) is now surfaced as a column on
  every real finding table (Queue, Infrastructure/AppSec) - explicitly disclosed as naming
  the real-world tool that would handle that asset class, not a working integration
  (`remediation_domain`, which does imply real Ansible-fixer automation, stays `null` for
  all 4 new types, same as every other non-windows-server/unix-server asset type).
  `remediation/config/priority_rules.yaml` gained real asset-type criticality weights for
  the new types (virtualization-host weighted higher than every existing type, reflecting
  a hypervisor's real blast-radius). `docs/REMEDIATION_WORKFLOWS.md`'s "no fixer yet"
  table, previously stale (missing 4 asset types from earlier rounds), is now complete for
  every manual-only asset type in the taxonomy. Both illustrative demo tenants
  (`tenant.js`) carry the 4 new asset types too, so no Infrastructure sub-category
  regresses to a "0 - no sample finding yet" tile under either tenant.

### Fixed
- **Demo tenants no longer show empty Infrastructure sub-categories**: both illustrative
  MSSP demo tenants (`dashboard/static/js/tenant.js`) now carry every real infra asset
  type, so all 8 of `/infrastructure`'s sub-category cards (OS Vulnerabilities, Network,
  Network Security, OT/IoT, Cloud Infrastructure, OS Applications, Infrastructure-as-Code,
  Container/Host Runtime Security) show real, non-zero counts under either tenant instead
  of reading "0 - no sample finding yet" for everything except whichever single asset
  type that tenant happened to carry before (e.g. Northwind Bank previously showed real
  data only for OT/IoT). The remaining tenant differentiation is AppSec/Certificate
  scope - only Northwind Bank carries `application`/`certificate` asset types.

### Added
- **Threat Intel drill-down: sticky columns, group-detail modal, dark web monitoring
  section, and threat-intel tagging everywhere**: the Threat-actor groups table's Group
  column and the Zero-days table's Priority/ID/CVE-Title columns now stay pinned to the
  left edge while the rest of the wide table scrolls horizontally (new `.sticky-col`/
  `.sticky-col-truncate` CSS - a first for this codebase's tables). Clicking a
  threat-actor-group row now opens a real detail modal (new `groupDetail.js`, modeled on
  `findingDetail.js`'s `openModal` pattern) showing that group's actual matching
  findings, distinct assets with owner/team, a severity breakdown chart, and each
  finding's remediation status - all derived from this tenant's real data via a new
  `findingsForGroup()` export on `threatActorGroups.js`, not fabricated. A new "Dark web
  & identity exposure monitoring" section honestly discloses this app has **no live
  dark-web-monitoring integration** (no fabricated "compromised identity" list), lists 3
  independently-verified real reference services under a new "Dark Web / Identity
  Exposure" feed category (Have I Been Pwned - noting its Pwned Passwords API is
  genuinely free/keyless while email/domain breach search now requires a paid
  subscription key; MISP, free/open-source/self-hosted; SOCRadar Labs' free tier), and
  surfaces the closest REAL adjacent signal this pipeline already has - Repository
  Secret Scanning findings (hardcoded credentials in source control) - explicitly
  distinguished as a *different* real exposure category, not relabeled "dark web." A new
  shared `threatIntelTagging.js` module (`sourcesFor`/`groupsForFinding`/
  `threatIntelCellHtml`/remediation-status helpers, consolidated out of `threatIntel.js`
  so every consumer shares one definition) adds a "Threat Intel" column - real feed
  tags (CISA KEV/NVD/FIRST.org EPSS) and/or matched threat-actor-group badge(s) - to
  every real finding-level table in the app: the Remediation Queue, Infrastructure/
  AppSec (via the already-shared `findingsTable.js`), and Compensating Controls.
- **Overview (`/`) drill-down interactivity + methodology transparency**: `charts.js`'s
  `barChartSvg`/`pieChartSvg` gained optional per-item `detail` (richer hover text via
  the app's existing shared `tooltip.js` listener, which - unlike a CSS `::after` - works
  on SVG shapes too) and `href` (click-to-navigate, wired by a new `wireChartLinks()`
  helper using `pushState` + a synthetic `popstate` rather than an SVG `<a>`, since
  `SVGAElement.href` returns an `SVGAnimatedString` that would silently break app.js's
  own `[data-link]` click delegation). On Overview: the 4 "Security domain totals" tiles
  and both new "Assets at Critical/High risk"/"Assets with no owner assigned" KPI tiles
  are now clickable, opening `/infrastructure`, `/appsec`, `/ai-vulnerabilities`,
  `/queue?category=cert-mgmt`, or a newly-real `/assets?risk_tier=…`/`?owner=unassigned`
  pre-filter (`assets.js` now reads these from the URL - a real, if minimal, filter, not
  a fake link); the "Assets by risk tier" bar chart shows each tier's top asset types on
  hover and links to that filtered view; "Top 5 highest-risk assets" gained a Type column
  and the same Impact×Likelihood tooltip badge Asset Inventory already uses. A new live
  "What is Risk Score actually calculated from?" panel quotes the actual configured
  weights from `remediation/config/risk_scoring_rules.yaml` (via a new
  `risk_scoring_rules` field on `/api/overview`) - not a hardcoded copy, so retuning the
  YAML updates this panel immediately, same as the existing Priority/SLA panel. A
  companion "What do Internal/External-facing and business-critical mean here?" panel
  quotes the real `asset_criticality_keywords`/`asset_type_weights` from
  `priority_rules.yaml` (now also exposed via `/api/overview`) and explains `facing` as a
  manually-set, never-auto-detected classification. "Findings by methodology, entire
  landscape" (one combined pie) is now 4 domain-specific interactive blocks: Infrastructure
  broken down by its 8 real `infra_category` sub-methodologies, Application by its 4 real
  methodologies (SAST/DAST/SCA/Repo Secrets), and Certificate/AI-ML as plain total tiles
  linking to their own dashboards (each is already a single methodology in this taxonomy -
  charting a "breakdown" of one slice would be decorative, not real, so this is an honest
  absence, not a filled-in placeholder). "Findings by month first seen" is now two
  separate charts (Infrastructure via `infra_category` truthy, Application via
  `scan_type` in sca/dast/secrets) instead of one combined chart.
- **Threat Intel (`/threat-intel`) reorder + industry/domain drill-down**: sections now
  render Threat intel feeds → Industry intelligence platforms → Threat-actor groups →
  Zero-days (previously zero-days first). Threat-actor groups gained a real
  `target_industries` tag per group (drawn from sector names explicitly named on that
  group's own live MITRE ATT&CK page, independently re-verified 2026-08-05 - a group with
  no tag for an industry, e.g. no group here documents Capital Markets/Insurance
  victimology, is a real absence, not an oversight) plus an industry filter dropdown
  (Financial Services & Banking, Capital Markets, Insurance, Healthcare, Retail &
  Consumer, Government & Defense, Energy & Utilities, Technology & Telecom, Education,
  Media & Entertainment, Transportation & Logistics, Hospitality), and a "Status: Active"
  badge - MITRE's own current catalog status as of the same re-verification pass, honestly
  disclosed as not a live intrusion-detection signal (this app has no live threat-feed
  ingestion). Zero-days gained 3 new columns - Security Domain (reusing
  `compensatingControls.js`'s own infra/scan-type grouping, now extracted into a shared
  `dashboard/static/js/domainGrouping.js` so both pages stay in sync), Remediation Status
  (joined from `REMEDIATION_PLAN.md`'s own risk-tier classification - an unexecuted plan,
  not a live fix-completion status), and Assets Impacted (reusing
  `rankings.js`'s existing `groupVulnerabilitiesByType()`) - and the list is now grouped
  into per-domain sections with a domain filter, instead of one flat table.
- **Per-asset risk scoring (NIST SP 800-30 Rev. 1-inspired)**: new
  `remediation/enrichment/risk_scoring.py` computes an **Impact score**, **Likelihood
  score**, and overall **Risk score** (0-100 each) plus a Critical/High/Medium/Low
  **risk tier** for every asset, built entirely from data this pipeline already computes
  - no new external source, no fabricated sub-metric. Impact weighs worst-CVSS-on-asset
    (falling back to `highest_severity` when no CVSS is present) and asset criticality
    (asset-name-keyword + asset-type weights, extracted out of
    `remediation/config/priority_engine.py`'s `compute_priority()` into a new standalone
    `asset_criticality_score()` so this is reused, not duplicated, from the one place that
    already defines "how critical is this asset"). Likelihood weighs CISA KEV listing,
    max FIRST.org EPSS score, `/exploit-criteria` rule matches, and EOL/EOS status. Risk =
    Impact x Likelihood / 100, an honest, disclosed simplification of SP 800-30's real
    Likelihood x Impact model (mapped there via lookup tables, not a literal continuous
    product) - explicitly documented as "NIST SP 800-30-inspired," not a certified
    RMF/800-30 output, since SP 800-37 ("RMF" proper) is a 7-step process with no scoring
    formula of its own to borrow. Weights and risk-tier thresholds live in a new,
    admin-editable `remediation/config/risk_scoring_rules.yaml` (deliberately does not
    redeclare criticality/severity weights already in `priority_rules.yaml`). Covered by
    11 new tests (`tests/test_risk_scoring.py`).
- **Risk/impact scores surfaced across every asset-focused dashboard**: Asset Inventory
  (`/assets`), Asset Mapping (`/asset-mapping`), and the Risk Dashboard (`/risk`) all gained
  a Risk Score column (badge-styled, hover for the Impact x Likelihood breakdown, same
  honesty caveat as above), sourced from the same `/api/assets` response each page already
  fetches - no new endpoint. The Risk Dashboard's "Top assets by critical findings" table
  is now ranked by overall Risk Score rather than raw Critical-finding count alone, so it
  surfaces assets whose real threat-intel signals (KEV/EPSS/EOL/exploit-criteria matches)
  make them genuinely most urgent, not just whichever has the most Critical-tagged rows.
- **Overview (`/`) analytics enrichment**: a new "Security domain totals" KPI row
  (Infrastructure/Application-de-duplicated/AI-ML/Certificate); a new "Risk scoring"
  section with Critical/High-risk and unowned-asset KPIs, an assets-by-risk-tier bar
  chart, and a "Top 5 highest-risk assets" table (all from the new risk-scoring engine
  above); and a new "Findings by month first seen" chart in Landscape Analytics, honestly
  captioned as showing when today's findings originated, not historical point-in-time
  totals (this app has no snapshot storage), and scoped to `/api/queue` findings only
  (SAST/Code Scan lacks a comparable first-seen field).
- **Threat Intel (`/threat-intel`) quick fixes**: removed the redundant "Top 5
  vulnerabilities"/"Top 5 assets" rankings (Vulnerability Mapping and Asset Mapping already
  cover this, linked instead); added a real "Source" column to the zero-days table
  (`CISA KEV`/`NVD`/`FIRST.org EPSS`, filtered to whichever are actually present on that
  finding); added a new 14-entry "Threat intel feeds" table
  (`dashboard/static/js/threatIntelFeeds.js`) listing real vendor/government/news advisory
  sources with a genuinely-disclosed live-vs-reference-tier split (only CISA KEV, NVD, and
  FIRST.org EPSS are marked "Live in this app," matching what `kev_epss.py` actually
  ingests today; the rest are real URLs with no working scraper) and an illustrative
  "every 12 hours" target refresh cadence (not a claim this demo runs a live scheduler -
  it doesn't).
- **AI/ML vulnerability TTP visibility + 100 new pipeline findings**: the AI Vulnerabilities
  category list (`/ai-vulnerabilities`) now shows each category's MITRE ATLAS technique ID
  as an inline badge next to its name, not just inside the collapsed detail accordion
  (`dashboard/static/js/pages/aiVulnerabilities.js`). Added `AI_ML_CLASSES`
  (`remediation/sample-data/generate_bulk_findings.py`) - 100 hand-authored findings (10
  per one of the 10 real, already-cited ATLAS categories in
  `remediation/enrichment/ai_vuln_taxonomy.py`), each phrased to naturally tag correctly
  against that module's existing keyword heuristic - verified 100/100 tag with zero
  untagged stragglers and exactly 10 per category. New `ai-ml-system` asset type and
  `ai-ml` scan type (`scan_type_mapping.py`/`scanTypes.js`), wired through
  `bulk_normalize.py`/`bulk_plan.py`/the schema doc. Along the way, fixed two real bugs
  the new content's correctly-spelled English surfaced: a pre-existing typo in
  `ai_vuln_taxonomy.py`'s misinformation regex (`overeliance` → `overreliance`), and 3 of
  the new findings' own descriptions that accidentally used the phrase "prompt injection"
  as narrative flavor, causing them to be captured by that earlier-ordered pattern instead
  of their intended category.
- **New "Threat Intelligence" nav section** (`/threat-intel`, positioned above Security
  Domains): zero-days (KEV-listed findings also matching a configured exploit-criteria
  rule - the same definition Compensating Controls uses) and top-5 vulnerability/asset
  rankings, both filtered per the selected (demo) tenant via the existing
  `filterByTenant()`; a **threat-actor-group correlation** table
  (`remediation/enrichment/threat_actor_groups.py` + JS mirror
  `dashboard/static/js/threatActorGroups.js`) - 6 real, MITRE-documented groups (APT28,
  APT29, Lazarus Group, FIN7, Sandworm Team, APT41; ids/aliases/technique associations
  independently verified live against attack.mitre.org/groups/ during implementation, not
  guessed from memory) correlated against whichever ATT&CK techniques are already tagged
  on a tenant's findings, with the same "illustrative cross-reference, not an attribution
  claim" disclosure this project applies to every other keyword-heuristic taxonomy; 3 new
  reference-tier Adaptors catalog entries (Recorded Future, Mandiant Advantage, FS-ISAC)
  under a new "Threat Intelligence" category; and an honest disclosure that this app's
  real ingestion path (`remediation/connectors/generic_connector.py`) accepts
  finding-shaped JSON, not raw multi-source log parsing. Added a per-tenant `industry`
  field to `tenant.js` (both demo tenants are financial-services-flavored, which the page
  discloses as a real limit on how much industry contrast this 2-tenant demo can show).
- **Compensating Controls: infra/domain grouping for team-ownership visibility**
  (`dashboard/static/js/pages/compensatingControls.js`) - every flagged finding is now
  grouped into a labeled section (its `infra_category` when present, else its
  `scan_type_label`) with a section-header row and running count, sorted so each group's
  rows stay contiguous across pages, plus a "Group" filter dropdown. Also fixed a
  pre-existing off-by-one (`colspan="8"` on a 9-column table's empty-state row).
- **Exceptions ↔ Compensating Controls: closed the loop.** An "Exception approved" chip
  (on both Compensating Controls and the Remediation Queue) now links straight to the
  specific exception record via a new `/exceptions?highlight=<id>` deep-link, mirroring
  the Queue's own existing `?highlight=<finding-id>` scroll-and-mark pattern (now ported
  to `exceptions.js`, which had no equivalent before). No backend change was needed - the
  full exception record (id, reason, expiry, requester/approver) already reached the
  browser via `/api/queue`'s existing per-finding merge; only the frontend was missing the
  link.
- **Filter-bar cleanup on 5 single-fixed-asset-type Queue views**
  (`dashboard/static/js/pages/queue.js`): Certificate Vulnerabilities, Infrastructure-as-
  Code, Container/Host Runtime Security, DAST, and Repository Secret Scanning deep-links
  no longer show the Asset Type/Category/Infra-sub-category filters - each view is
  already fixed to one asset type and one category the moment its URL selects it, so
  those controls were pure redundancy. Priority, CISA KEV-listed, and Date range stay
  (still meaningful everywhere).
- **Cross-dashboard severity chart + top-5 rankings, an honest total-vulnerabilities KPI,
  and a per-sub-category severity breakdown table** (`dashboard/static/js/domainSummary.js`,
  new shared module) — added to `/infrastructure`, `/appsec`, `/risk`, and `/` Overview: a
  "By severity" bar chart (also fixing Infrastructure's pre-existing bug where it charted
  `priority`, the weighted score tier, under a "By severity" heading), "Top 5 assets by
  vulnerability count" and "Top 5 vulnerabilities by affected-asset count" tables (reusing
  `rankings.js`'s existing grouping logic), and a Critical/High/Medium/Low × sub-category
  breakdown table. AppSec's KPI deliberately sums only the 4 non-overlapping finding pools
  (SAST+DAST+SCA+Repo Secret Scanning), not a naive sum of all 7 domain cards, since
  Secrets Management/Container/API are CWE-based sub-classifications of the same SAST
  findings, not separate ones — an on-page disclaimer explains why this honestly differs
  from the breakdown table's own (intentionally non-deduplicated) footer sum. Not added to
  `/ai-vulnerabilities`, which only exposes taxonomy/aggregate counts, not individual
  findings to rank.
- **Redesigned (demo) tenant switcher**: replaced the native `<select>` (unstylable beyond
  browser chrome) with a button + popover (`topbarTenant.js`, matching the existing
  account-menu popover pattern) — a rounded pill button and a dropdown with rounded,
  highlighted rows. Each tenant shows a generated colored-initials avatar (`tenant.js`'s
  existing `initials`/`avatarColor`) as its "logo," consistent with this being an
  illustrative, not a real, MSSP demo.

### Fixed
- **`barChartSvg()`'s `<svg>` was missing `width`/`height` attributes** (only `viewBox`),
  unlike `pieChartSvg()` — with nothing else constraining it in a flex `.chart-row`, the
  browser collapsed it to ~75×35px. This was the cause of the "By severity" chart
  appearing broken/tiny on Infrastructure.
- **Dashboard felt slow to load, and the tenant dropdown didn't always close after a
  selection** — both traced to the same root cause: `StaticFiles` was serving `/static/*`
  with no `Cache-Control` header at all, letting the browser skip revalidation for an
  extended, heuristic-decided period and keep serving stale JS. Added a middleware
  forcing `Cache-Control: no-cache` (still allows a cheap 304 on an unchanged file, just
  never skips the check) on every `/static/*` response.
- **`/api/queue` (and `/api/remediate`, `/api/assets`) were slow to serve** even after the
  cache-control fix above — two real, separately-profiled costs on top of it: (1) the
  MITRE ATT&CK and compensating-controls regex-tagging passes were being recomputed from
  scratch on every single request (~1.8s combined for ~8,000 findings), now cached
  in-process (`dashboard/data.py`'s `_load_content_enriched_findings()`), keyed on the
  source file's mtime plus today's date so a pipeline re-run or day rollover invalidates
  it automatically — exploit-criteria matching, exceptions, and priority scoring stay
  uncached since they must reflect an admin's edits immediately, but together they only
  cost ~0.1s; (2) FastAPI's automatic `jsonable_encoder()` pass, invoked whenever a route
  returns a plain dict, was recursively type-checking the entire ~14MB `/api/queue`
  payload even though it's already 100% JSON-safe data straight from `json.loads()` plus
  arithmetic — profiled at over 1s of pure overhead, avoided by serializing these three
  endpoints' payloads directly with `json.dumps()` (`dashboard/app.py`'s `_fast_json()`)
  instead of returning a plain dict for FastAPI to re-encode. `load_vulnhunt_data()` (two
  `git` subprocess spawns per call, now invoked by more pages than before) also gained a
  10-second in-process TTL cache. Combined, warm-cache requests to `/api/queue` dropped
  from ~1.8-3s+ to ~0.15-0.4s in live testing; the very first request after a server
  restart or data regeneration still pays the one-time cache-building cost (~5-6s at the
  current ~8,000-finding scale). New tests: `ContentEnrichedFindingsCache`/
  `VulnhuntDataCache` in `tests/test_dashboard.py`.

### Added
- **Dashboard UX overhaul: navigation/search, real trend filtering, hand-rolled charts,
  two new cross-cutting ranking dashboards, and honest EOL/EOS tracking.**
  - **Nav/topbar**: the topbar is now a continuous brand-green bar (search widened to
    640px with match-highlighting and per-source grouping in the results dropdown);
    the account avatar opens a popover (name/email/role/profile-link/logout) instead
    of navigating away; the (demo) tenant switcher moved from the sidebar into a
    compact pill at the topbar's far right (`topbarTenant.js`); export buttons are
    right-aligned everywhere via one shared CSS rule.
  - **Date-range filtering** (`dashboard/static/js/dateRange.js`): rolling-window
    presets (last 7/30/60/90 days) plus completed-calendar-period presets (last
    week/last 2 weeks/last month - a genuine distinction from the rolling windows,
    matching how a real SIEM time picker separates them) and a custom range, wired
    into `/queue`, `/infrastructure`, and `/appsec`. Filters on each finding's real
    `first_seen` date - honestly disclosed as unable to reconstruct past total counts,
    since this dashboard has no historical snapshot storage.
  - **Hand-rolled charts** (`dashboard/static/js/charts.js`): zero-dependency SVG
    bar/pie charts (matching the existing hand-rolled MITRE heat-map precedent, not a
    new library), added to `/infrastructure` (severity bar, sub-category pie) and
    `/appsec` (category pie).
  - **Two new ranking dashboards** (`dashboard/static/js/rankings.js`, extracted from
    `risk.js`'s existing vulnerability-grouping logic): `/vulnerability-mapping` (top
    25 real vulnerabilities ranked by distinct assets affected) and `/asset-mapping`
    (top 25 real assets ranked by distinct vulnerabilities carried, including EOL/EOS
    status) - both clickable, deep-linking into a pre-filtered `/queue` (`?cve=`/
    `?title=`/`?asset=`) that inherits every other filter (owner/team/EOL-EOS/SLA/date)
    for free. `risk.js` keeps a condensed top-5 preview of each with a link to the
    full dashboard.
  - **Owner/Team columns** (`dashboard/static/js/assetLookup.js`, extracted from
    `risk.js`'s original one-off join): added to the shared findings table
    (`findingsTable.js`, used by `/infrastructure`/`/appsec`) and `/queue`.
  - **End-of-Life/End-of-Support tracking** (`remediation/enrichment/eol_lookup.py`,
    new): a small, real table of publicly-documented vendor lifecycle dates (Microsoft
    Windows Server 2012R2/2016/2019/2022 and Windows 10, Ubuntu 22.04/20.04 LTS, CentOS
    7), matched against each finding/asset's real OS string - "unknown" when nothing
    matches, never a guessed date, same honesty pattern as `pattern_recognition.py`'s
    owner-suggestion heuristic. Wired into `/api/queue` and `/api/assets`
    (`asset_inventory.py` now backfills `os` the same way it already does `ip`/`mac`),
    shown as a badge on `/assets` and in the finding-detail modal (with a callout +
    one-click "Request an exception" deep-link into `/exceptions`, pre-filling the
    reason - `exceptions.js` now accepts `?finding_id=`/`?reason=` query params for
    this).
  - **Footer**: now shows the real app version (`/api/status`'s `app_version`,
    surfacing FastAPI's own `app.version`) and a copyright line, plus compliance/
    data-source references (NIST CSF, SOC 2, NVD - only the frameworks this repo's own
    `docs/COMPLIANCE_MAPPING.md` actually has a conceptual mapping for, not the full
    list a customer might ask about) framed as informational-only, reusing that doc's
    own disclaimer language rather than inventing new compliance copy.
  - **Real bug found and fixed while building this**: `generate_bulk_findings.py`'s
    `collect_real_cves()` pulled from each NVD query in strict order until its
    category's target was reached *at all* - since "Google Chrome" alone has far more
    real CVEs than the whole "OS Applications" category's ~1,100-finding target, every
    one of those findings ended up sourced from that one query (and thus labeled
    "Google Chrome"), even though the category's other 25 product queries (Firefox,
    Adobe Reader, VS Code, etc.) were never touched. Fixed with a two-pass quota
    allocation (`ceil(target / len(queries))` per query, then an uncapped fill pass
    for any shortfall) so every query actually contributes - `tenable_bulk_os_apps.csv`
    now has 23 distinct real products instead of 1. Regenerated and re-merged
    (2,415 → 7,487 → 7,440 after the corrected os_apps data changed which CVEs
    matched what was already in the dataset).

- **Zero-day/exploit-criteria intelligence, a Compensating Controls watchlist dashboard,
  landscape-wide analytics, a ~15-entry Adaptors expansion, and three new finding
  categories (IaC, GitHub/GitLab repository, runtime/container security).**
  - **Zero-day/exploit-criteria intelligence**: two new real, never-fabricated signals
    extracted from NVD's own cached CVE data (`remediation/enrichment/poc_enrichment.py`) -
    `poc_available` (NVD's own `references[].tags` containing `"Exploit"`) and
    `user_interaction_required` (NVD's own CVSS v3.x `userInteraction` metric; `null`,
    not guessed, when only CVSS v2 exists). A new configurable rule engine
    (`remediation/enrichment/exploit_criteria.py` + `remediation/config/
    exploit_criteria_rules.yaml`, same admin-editable-YAML pattern as
    `priority_rules.yaml`) combines these with `kev`/`epss` into named
    `exploit_criteria_matches` per finding - seeded with the client's own two example
    criteria ("actively exploited + no user interaction + POC available" / "...+ no
    POC known"). New `/exploit-criteria` admin page with a live match-count preview
    (`GET`/`POST /api/exploit-criteria`, `POST /api/exploit-criteria/preview`).
  - **Compensating Controls watchlist** (`/compensating-controls`, new, under Risk
    Management): lists every finding that can't be remediated right now - Critical +
    EOL/EOS, actively-exploited (KEV) findings matching a configured exploit-criteria
    rule, or ones already covered by an approved exception - with each one's
    already-computed `compensating_controls` shown inline (not click-to-reveal, unlike
    `/exceptions`'s existing per-finding treatment), KPI counts per reason, and
    drill-down/exception-request actions. Zero new backend endpoints - same
    client-side-aggregation precedent as `/vulnerability-mapping`/`/asset-mapping`.
  - **Landscape analytics** (`/` Overview, extended): a whole-landscape severity bar
    chart and methodology pie chart (Infra+AppSec+SAST combined, deliberately broader
    than any single hub page's own charts), an SLA-compliance-rate tile, an EOL/EOS
    exposure tile+chart (deduped per distinct asset), and a KEV-by-asset-type chart
    (explicitly captioned as the honest substitute for a "KEV trend," since this app
    has no historical-snapshot storage).
  - **Adaptors catalog expansion** (`dashboard/static/js/adaptorCatalog.js`): ~15 new
    reference-tier entries (Microsoft Entra ID, AWS IAM Access Analyzer, GCP Security
    Command Center, Cortex XSIAM, Elastic/ELK SIEM, Black Duck, Polaris, SonarQube,
    Snyk, BishopFox, BitSight, Palo Alto Panorama, Cisco FMC, Fortinet FortiManager, F5
    BIG-IP) across 4 new categories (Identity/IAM, Application Security Testing,
    External Risk/ASM, Network Security Management - the last being this catalog's
    first *remediation-actuation*, push-a-config-change archetype). Same honesty tier
    as the existing 14 reference entries - documented integration shape, no working
    code. 4 requested vendors (Qualys, QRadar, Prisma Cloud, Defender for Cloud) were
    already present and skipped as duplicates.
  - **Three new finding categories** (`generate_bulk_findings.py`): **IaC
    misconfigurations** (new `iac-resource` asset type, 219 findings - 8
    independently-verified real Checkov rule IDs against fictional Terraform/
    CloudFormation resources, no CVE, same hand-authored-class pattern as DAST);
    **GitHub/GitLab repository vulnerabilities** (new `code-repository` asset type,
    219 findings - a real-CVE Dependabot-style half reusing `collect_real_cves()`
    against queries deliberately non-overlapping with the `sca` category's own, plus a
    CWE-798 secret-scanning half whose descriptions are deliberately generic and never
    embed a secret-shaped literal, given `NoRealSecretsLeakedAnywhere`'s unconditional
    repo-wide check); **runtime/container security** (new `container-runtime` asset
    type, 218 findings - 14 independently-verified real Falco default rule names,
    directly satisfying the pending "Container/host vulnerability taxonomy expansion"
    backlog item). A couple of plausible-sounding rule IDs/names surfaced in research
    (`CKV_AWS_53`/`57`, "Launch Privileged Container", "Write below etc") could not be
    independently confirmed against current official sources and were deliberately
    excluded. New `iac`/`secrets`/`runtime` scan-type and `iac`/`runtime` infra-category
    taxonomy entries (`scan_type_mapping.py`, `infra_classification.py`, and their JS
    mirrors) - all three appear automatically on `/infrastructure`/`/appsec`/`/queue`'s
    filter dropdowns with no further JS changes, per those pages' existing
    taxonomy-driven rendering. Re-ran the full normalize → KEV/EPSS-enrich →
    POC-enrich → plan pipeline at the new 8,096-finding scale (112 KEV-listed, 253 with
    EPSS ≥ 50%).

- **Infrastructure findings scaled from 2,415 → 7,487, plus a new "OS Applications"
  sub-category.** Each of the 5 existing infra sub-categories grew from ~300 to ~1,100
  real, distinct CVEs sourced from NVD (`remediation/sample-data/generate_bulk_findings.py`
  category targets bumped, with expanded NVD queries per category so the larger targets
  are still reachable). A brand-new sixth sub-category, "OS Applications"
  (`client-application` asset type), adds ~1,100 more real CVEs against realistic
  end-user desktop/laptop software - browsers, PDF readers, dev tools (VS Code, Git,
  Docker Desktop), media/utility apps (VLC, 7-Zip, Notepad++, OBS), and more - wired
  through `infra_classification.py`/`infraTypes.js` (`apps` category),
  `dashboard/static/js/pages/infrastructure.js` (6th card), `bulk_normalize.py`
  (`tenable_bulk_os_apps` → `client-application`), `bulk_plan.py` (patch/manual-review
  action-type rule, new remediation note), and `priority_rules.yaml`
  (`client-application` asset-type weight). Re-ran the full
  normalize → KEV/EPSS-enrich → plan pipeline at the new ~7,487-finding scale (104
  KEV-listed, 226 with EPSS ≥ 50%, 1,099 eligible for automated Windows/Unix fixes).
- **Fixed the bulk-generator's ID scheme**: replaced a per-process incrementing counter
  (which silently produced duplicate/colliding IDs across separate script invocations,
  causing real findings to be dropped as false "already exists" matches) with
  `_stable_id()` - a CVE-hash-derived ID stable across any number of re-runs. Added
  `bulk_normalize.py --reset-asset-types`/`drop_bulk_findings_of_type()`/
  `compact_bulk_ids()` to safely re-merge a subset of categories under the new ID scheme
  without duplicating already-merged entries, and to keep the live finding-ID range
  contiguous (`FIND-1`..`FIND-N`) after the reset.
- **Real, planted AI/ML and secrets/API-authorization vulnerabilities, genuinely
  scanned** - two new fixture files in `vulnerable-demo-app/`: `ai_assistant.py` (VULN-10
  hardcoded LLM API key, VULN-11 insecure `pickle.load` model deserialization, VULN-12
  prompt injection, VULN-13 excessive agency) and `admin_api.py` (VULN-14 hardcoded AWS
  keys, VULN-15 hardcoded JWT secret, VULN-16 unauthenticated admin route, VULN-17
  wildcard CORS, VULN-18 mass assignment). A real `vuln-scanner` run found all 9;
  `SECURITY_REPORT.md` now documents 18 findings total, and the 5 newly auto-fixable
  ones (VULN-10, 14, 15, 17, 18) were actually mechanically fixed (secrets moved to
  environment variables, CORS scoped to a named origin, mass assignment closed with a
  field allow-list) on the `vulnhunter/auto-fixes-*` branch, matching the same
  behavior-preserving pattern as the original 6. Broadened one `ai_vuln_taxonomy.py`
  regex (`\b(unsafe|insecure) (pickle|deserializ)`, previously `unsafe` only) so
  VULN-11's "insecure deserialization" wording - standard OWASP terminology - correctly
  tags as AI Supply Chain Compromise. `/api/ai-vulnerabilities` now combines both the
  remediation-pipeline findings and `/vulnhunt`'s own SAST findings, so the AI
  Vulnerabilities heat map shows genuine non-zero counts for Prompt Injection, AI Supply
  Chain Compromise, and Excessive Agency - previously honestly zero, now honestly
  non-zero, with every other category still honestly at zero.
- **Massive real-data expansion: 15 → 2,415 findings**, sourced from NVD's public CVE
  API, not fabricated (`remediation/sample-data/generate_bulk_findings.py`, new). Added
  ~300 real, distinct CVEs to each of: OS (180 Windows + 120 Linux), Network
  (Cisco/Juniper/Arista), Network Security (Fortinet/Palo Alto/Check Point/F5/SonicWall/
  Citrix), Cloud Infrastructure (Kubernetes/Docker/AWS/Azure/GCP - a brand-new,
  previously-empty category), Certificate/TLS (OpenSSL/GnuTLS/X.509), SCA (Log4j/Struts/
  Spring/jQuery/etc.), and OT/IoT (SCADA/cameras/PLCs/building automation, via Armis-shaped
  data). DAST (300 findings) is the one deliberate exception: real dynamic-testing bugs
  aren't CVE-numbered, so these carry real, well-established CWE/OWASP vulnerability
  classes (reflected/stored XSS, SQLi, SSRF, XXE, IDOR, etc.) instead - required teaching
  `remediation/enrichment/scan_type_mapping.py` a new real distinguishing signal
  (`application` + has a CVE → SCA, `application` + no CVE → DAST) since DAST had no path
  to real data before. All 2,400 new findings went through the same real pipeline
  (`remediation/sample-data/bulk_normalize.py` implementing vuln-ingest-normalizer.md's
  documented classification rules as a script - an LLM-subagent pass isn't tractable at
  this volume - then the real, live `remediation/enrichment/kev_epss.py` against CISA
  KEV + FIRST.org EPSS: 41 genuinely KEV-listed, 152 with EPSS ≥ 50%). REMEDIATION_PLAN.md
  was regenerated the same way (`remediation/sample-data/bulk_plan.py`), with a disclosed,
  uniform action_type/risk_tier heuristic for the bulk majority (vs. individual per-CVE
  research for the original 15) and its per-finding prose section capped to the top 60
  by priority for readability - the compact queue table (all `dashboard/data.py` actually
  parses) still covers every finding. AI Vulnerabilities and SAST-side code-scan
  categories (Secrets/Container/API) were deliberately left out of this wave - see the
  session notes on why (git-branch dependency for `/vulnhunt`'s data source).
- **Consolidated Adaptors hub** (`/adaptors`, `dashboard/static/js/pages/adaptors.js`,
  `dashboard/static/js/adaptorCatalog.js`) - replaces four separate "Adaptors — X"
  sidebar groups (Ticketing/SOAR, SIEM, XDR/EDR, Asset Discovery/IPAM, six items total)
  with one nav entry and a single dropdown/filter selector; picking a connector
  dynamically renders its settings/preview panel below, reusing the existing
  ServiceNow/Jira/Splunk/CrowdStrike/Infoblox/Axonius page modules unchanged. Also adds
  14 new "reference catalog" connector entries - real, researched facts (auth model,
  actual API/data shape) for Qualys, Rapid7 InsightVM, Wiz, Prisma Cloud, AWS Security
  Hub, Microsoft Defender for Cloud, IBM QRadar, Microsoft Sentinel, Cortex XSOAR,
  SentinelOne, Microsoft Defender for Endpoint, Slack, Microsoft Teams, and PagerDuty -
  each honestly labeled "Reference" (no working preview/send code yet) versus the six
  "Preview available" live connectors, one clear step short of the existing
  built-against-docs-but-unverified honesty tier. `docs/INTEGRATIONS.md`'s former "Not
  yet built" list is now this same researched catalog in doc form.
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
