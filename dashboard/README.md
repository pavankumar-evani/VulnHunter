# VulnHunter Dashboard (MVP)

A read-only-by-default web UI over both pipelines' real generated artifacts, plus a form
to trigger a run via the [headless CLI](../cli/README.md). A FastAPI JSON API
(`dashboard/app.py`) behind a hand-rolled vanilla-JS single-page frontend
(`dashboard/static/`) — no Node/npm/build step. See "Why FastAPI + vanilla JS" below for
the reasoning.

## Running it

```bash
pip install -r dashboard/requirements.txt
python scripts/migrate_json_to_db.py  # one-time: seeds the SQLite DB from the committed example data
python dashboard/app.py
# open http://127.0.0.1:5050
```

The migration step carries the one seeded example in `remediation/exceptions/exceptions.json`
into `remediation/vulnhunter.db` (gitignored, created on first run either way) - see "What
this is NOT (yet)" below for which stores this covers. Safe to skip on a repeat run; the
script no-ops if there's nothing left to migrate.

It reads directly from the repo it's run in: git history (for `/vulnhunt`'s
`SECURITY_REPORT.md`, via the `vulnhunter/auto-fixes-*` branch) and files under
`remediation/` (for `/remediate`'s `normalized-findings.json`, `REMEDIATION_PLAN.md`, and
generated playbooks). If those artifacts don't exist yet, the relevant pages show an
empty state with instructions instead of erroring.

## Architecture

- **`dashboard/app.py`** — a FastAPI app with two kinds of routes:
  - `/api/*` — the JSON API. This is the only thing the frontend talks to, and the only
    thing worth testing from Python (see Testing below).
  - Everything else (`/`, `/vulnhunt`, `/remediate`, `/queue`, `/priority-rules`,
    `/servicenow`, `/run`, `/playbooks/{filename}`, and any unrecognized path) serves the
    exact same file: `dashboard/static/index.html`. This is what makes it a single-page
    app — there's no server-side templating left at all.
- **`dashboard/static/js/app.js`** — the client-side router. It reads
  `window.location.pathname`, dynamically `import()`s the matching page module from
  `static/js/pages/`, and re-renders `#app` in place (no full page reload). Clicking any
  in-app link uses `history.pushState` instead of a real navigation; the browser's
  back/forward buttons still work via `popstate`.
- **`dashboard/static/js/pages/*.js`** — one module per page. Each calls the JSON API
  (via `static/js/api.js`), builds HTML from the response, and wires up any forms
  (priority-rules editor, ServiceNow send, run-pipeline trigger). All dynamic text goes
  through `escapeHtml()` in `static/js/dom.js` before hitting `innerHTML`.
- **`dashboard/data.py`** — unchanged by the rewrite. It has no Flask/FastAPI-specific
  code at all; it just parses real artifacts into plain dicts, and both the old Flask
  routes and the new FastAPI routes called it the same way.
- **`dashboard/ai_assist.py`** — pure prompt-construction for the AI-assist feature
  (`build_ai_assist_prompt(finding, action)`); no subprocess/network code of its own.
- **`dashboard/reports.py`** — real, live-computed report generation
  (`generate_report_data`, `render_report_html`) for the Reports page and
  `/api/reports/*`; no fabricated numbers, and honest about what "period" does and
  doesn't mean without a persistence layer (see its module docstring).
- **`dashboard/static/js/tenant.js`** — the illustrative MSSP tenant-switcher demo
  (client-side only, partitions findings by asset category - not real per-tenant
  auth/data isolation, see the FAQ page). Each demo tenant also shows a generated
  initials avatar (not a real company logo - there's no real logo to show) and a
  location line in the sidebar.
- **`remediation/exceptions/store.py`** and **`remediation/inventory/asset_inventory.py`**
  — the exception/waiver workflow and asset ownership/facing-classification storage the
  `/exceptions` and `/assets` routes wrap. Both live under `remediation/` (not
  `dashboard/`) since they're domain logic, same reasoning as `priority_engine.py`.
- **`remediation/inventory/pattern_recognition.py`** — pattern-matched (hostname
  naming convention, IP subnet, asset type, MAC vendor OUI) owner/team suggestions for
  unowned assets on `/assets`. Explicitly NOT machine learning - see its module
  docstring for why claiming ML on this dataset size would be dishonest. Every
  suggestion carries its reasoning and a confidence score; nothing is auto-applied.
- **`remediation/enrichment/compensating_controls.py`** — keyword-heuristic
  compensating-control suggestions (same honesty pattern as `attack_mapping.py`) shown on
  the `/exceptions` request form.
- **`remediation/enrichment/blast_radius.py`** — per-asset "if compromised, how far does
  the damage spread" scoring, shown on `/risk/blast-radius`. Explicitly maps a real
  4-dimension profiling framework against what this app's data can actually answer:
  Business Criticality and a coarse Network-reachability proxy are real and scored;
  Identity & Privilege isn't measurable at all with this app's data and is disclosed as
  such, not approximated. Cross-referenced against `risk_scoring.py`'s already-real
  `kev_count`/`likelihood_score`, never re-derived.
- **`remediation/enrichment/ai_vuln_taxonomy.py`** — twelve real AI/ML vulnerability
  categories (prompt injection, model poisoning, MCP tool poisoning, shadow AI agents,
  etc.) with summary/remediation
  guidance and an illustrative MITRE ATLAS cross-reference, shown on
  `/ai-vulnerabilities`. Same "keyword heuristic, verify before citing formally"
  honesty pattern as `attack_mapping.py`'s ATT&CK tagging.
- **`remediation/enrichment/infra_classification.py`** — splits Infrastructure
  Vulnerability Management findings into OS/Network/Network Security/OT-IoT/Cloud/...
  sub-categories by `asset.type`, tagged onto every live queue finding in
  `load_live_queue()` alongside `scan_type`/`attack_techniques`. OT-IoT is rolled up on
  its own dedicated `/ot-vulnerabilities` hub, not `/infrastructure` - see below.
- **`remediation/connectors/jira_connector.py`**, **`splunk_connector.py`**,
  **`crowdstrike_connector.py`** — same "built against public docs, unverified against a
  live tenant" pattern as the ServiceNow/Tenable/Armis connectors. Jira and Splunk are
  push connectors with dashboard preview/send pages (`/jira`, `/splunk`); CrowdStrike is a
  pull connector with no dashboard form yet, only a reference page (`/xdr`).
- **`remediation/connectors/qualys_connector.py`**, **`prismacloud_connector.py`**,
  **`cortex_xsiam_connector.py`** — three more pull connectors, each with a real
  dashboard **Test Connection + Fetch** page (`/qualys`, `/prismacloud`,
  `/cortex-xsiam`). Qualys is CVE-scoped like Tenable (reuses its exact CSV shape);
  Prisma Cloud/Cortex XSIAM are posture/correlated-detection sources like CrowdStrike
  (normalize directly into the Finding schema, `cve`/`cvss`/`kev`/`epss` stay `null`).
- **`remediation/connectors/infoblox_connector.py`**, **`axonius_connector.py`**,
  **`active_directory_connector.py`** — the sidebar's "Integrations" groups are now
  "Adaptors"; these three are pull connectors for DNS/IPAM, cyber-asset-management, and
  on-prem AD data (WAPI `record:host`, the `/api/devices` API, and LDAP computer-object
  search, respectively), each with a real dashboard **Test Connection + Fetch** page
  (`/infoblox`, `/axonius`, `/active-directory`). Unlike every connector above, they
  normalize into a plain asset-inventory record, not a vulnerability Finding — Fetch
  reconciles real ip/mac into `asset_ownership.json` instead of writing an export file
  or normalized findings - see "Adaptors — Asset Discovery / IPAM" below. The Active
  Directory connector here is a distinct concern from `dashboard/auth/ad_directory.py`'s
  read-only AD group-membership check (gates Remediation Approvals) - see that module's
  own docstring.
- **`dashboard/auth/`** — local login MVP + OIDC-ready SSO client. See "Authentication"
  below.
- **`dashboard/static/js/sidebarToggle.js`** — the topbar's sidebar-collapse toggle. A
  `<button>` + CSS class + `localStorage`, no framework; state persists across reloads
  and the collapsed sidebar is marked `inert` so it can't be tabbed into while hidden.
- **`dashboard/static/js/export.js`** — client-side CSV/JSON/Markdown-table export,
  wired into every major table page (Code Scan, Queue, Remediation Plan, Exceptions,
  Asset Inventory, Risk dashboard).

## Pages

| Route | Shows |
|---|---|
| `/` | KPI overview across both pipelines, SLA/KEV/EPSS summary, risk-tier + asset-class breakdown, live-refreshed every 20s |
| `/ai-assist` | Ask Claude to explain/remediate/summarize a finding - dry-run preview by default, explicit confirm to spend real API usage |
| `/inbox` | Real system-generated notifications (SLA breaches, KEV, expiring exceptions, pending generic-ingested findings) - not person-to-person messaging; also a bell icon + dropdown in the topbar on every page |
| `/appsec` | Application Vulnerabilities hub - rolls up SAST/DAST/SCA/Secrets/Container/API/Repository-Secret-Scanning counts with links into each pre-filtered view (plus a by-category pie chart) and a date-range filter (real first-seen date) on the SCA/DAST/Secrets findings table. These are sidebar-menu-only reachable through this hub, not separate top-level nav entries |
| `/infrastructure` | Infrastructure Vulnerabilities hub - rolls up OS/Network/Network Security/Cloud/OS Applications/Infrastructure-as-Code/Runtime counts (`remediation/enrichment/infra_classification.py`) with links into each pre-filtered `/queue` view; a severity bar chart and sub-category pie chart (`charts.js`, hand-rolled SVG, no dependency), plus a date-range filter (by real first-seen date, honestly caveated - see the FAQ) on the findings table below. OT-IoT is deliberately excluded here - see `/ot-vulnerabilities` |
| `/ot-vulnerabilities` | OT Vulnerabilities hub - the one dedicated home for `infra_category="ot"` findings (Operational Technology/IoT devices), same shape as the other Security Domains hubs: total-vulnerabilities KPI, severity/device-type/team/priority/aging charts, top-5 rankings, AI trend analysis, and the full findings table |
| `/queue?category=infra-vm` / `?category=dast` / `?category=sca` / `?category=cert-mgmt` | The Security Domains menu's deep links into `/queue`, pre-filtered by category |
| `/vulnhunt` / `/vulnhunt?category=Secrets` | Code scan findings table (from `SECURITY_REPORT.md`), filterable by severity and CWE-derived category; also serves as the SAST and Secrets Management nav entries |
| `/queue` | The *live*, re-scored remediation queue (priority/SLA/KEV/EPSS/ATT&CK/Owner/Team), sortable and filterable client-side (priority, asset type, category, infra sub-category, KEV-only, date range by real first-seen date), the (demo) tenant switcher applies here, live-refreshed every 20s, per-row "Ask AI" link, CSV/JSON/MD export. Also accepts `?cve=`/`?title=`/`?asset=` deep-links from the Vulnerability/Asset Mapping dashboards for pre-filtered drill-down |
| `/remediate` | The *static* remediation plan snapshot (from `REMEDIATION_PLAN.md`), linked to generated playbooks, filterable by risk tier and automation target, CSV/JSON/MD export |
| `/playbooks/<filename>` | Full content of one generated Ansible playbook |
| `/risk` | Risk Management dashboard - MITRE ATT&CK heat map, a condensed top-5 preview of vulnerabilities-by-affected-asset-count and assets-by-critical-findings (each linking to its full dashboard below), an editable internal/external-facing classification per asset, and a CVSS v4.0 severity-definitions reference |
| `/risk/blast-radius` | Blast Radius - per-asset "if compromised, how far does the damage spread" scoring (`remediation/enrichment/blast_radius.py`), cross-referenced against real KEV/likelihood exploitability. Honestly scoped: renders a real disclosure of which of the 4 source profiling dimensions (Identity & Privilege, Network Topology, Business Criticality, Attack Surface) this app's real data can and can't measure today, rather than fabricating the two it can't |
| `/vulnerability-mapping` | Full ranked dashboard (top 25) of real vulnerabilities by how many distinct assets they affect - click one to jump to a pre-filtered `/queue` view of every affected finding (`rankings.js`) |
| `/asset-mapping` | Full ranked dashboard (top 25) of real assets by how many distinct vulnerabilities they carry, including each asset's EOL/EOS status - click one to jump to a pre-filtered `/queue` view of every one of its findings (`rankings.js`) |
| `/compensating-controls` | Findings that can't be remediated right now - Critical + EOL/EOS, actively-exploited (CISA KEV) findings matching a configured exploit-criteria rule, or ones already covered by an approved exception - with each one's compensating controls listed inline (not click-to-reveal), owner/team, and drill-down/exception-request actions |
| `/ai-vulnerabilities` | AI Vulnerabilities - twelve real AI/ML security categories (prompt injection, model poisoning, MCP tool poisoning, shadow AI agents, supply-chain compromise, etc.) with summary/remediation guidance and an illustrative MITRE ATLAS heat map; `vulnerable-demo-app/ai_assistant.py` plants 4 real AI/ML findings and 3 tag against this taxonomy for genuine non-zero counts (Prompt Injection, AI Supply Chain Compromise, Excessive Agency) - the bulk sample dataset additionally seeds 10 hand-authored findings per category (120 total) so every category, including the two newest, has a genuine non-zero count |
| `/exceptions` | Request/approve/revoke time-boxed risk-acceptance waivers per finding, with keyword-suggested compensating controls on the request form, CSV/JSON/MD export |
| `/assets` | Every asset with findings against it, aggregated, with an editable owner/team, a real, dated End-of-Life/End-of-Support status (`remediation/enrichment/eol_lookup.py` - a small table of real public vendor lifecycle dates, "Unknown" when nothing matches rather than a guess), CSV/JSON/MD export, and a "CMDB import" panel to bulk-assign owner/team from an uploaded CSV export (see below) |
| `/priority-rules` | Live YAML editor for `remediation/config/priority_rules.yaml`, with one-click presets for a pure-CVSS/severity model vs. the shipped VPR-style (threat-intel-aware) model - both are the same underlying weighted-score engine, just with the KEV/EPSS overrides toggled |
| `/exploit-criteria` | Live YAML editor for `remediation/config/exploit_criteria_rules.yaml` - defines which combinations of real signals (CISA KEV, NVD-derived `poc_available`/`user_interaction_required`, FIRST.org EPSS) count as a customizable "exploit criteria" match; shows a live match-count preview per rule before saving |
| `/servicenow`, `/jira`, `/splunk` | Ticketing/SIEM Incident/Issue/Event preview (no credentials needed) and send form, one page per connector |
| `/xdr` | CrowdStrike Falcon reference page - a pull connector with no dashboard form yet; shows what the connector does and how to use it from Python |
| `/tenable`, `/qualys` | Tenable.io and Qualys VMDR Test Connection + Fetch pages - CVE-scoped host-vulnerability pull connectors; Fetch writes a raw export file, still needing `/remediate <file>` to reach this dashboard's own pages (asset-type classification needs judgment - see `docs/GOING_LIVE.md`) |
| `/prismacloud`, `/cortex-xsiam` | Prisma Cloud and Cortex XSIAM Test Connection + Fetch pages - posture/correlated-detection pull connectors (not CVE-scoped); Fetch writes already-normalized findings straight to `remediation/live-data/`, deliberately not auto-merged into the live queue |
| `/infoblox`, `/axonius`, `/active-directory` | Infoblox NIOS, Axonius, and Active Directory (LDAP) Test Connection + Fetch pages - asset-discovery pull connectors; Fetch reconciles real ip/mac into the asset inventory (`asset_inventory.reconcile_pulled_assets()`), not vulnerability findings |
| `/run` | Form to trigger a pipeline run (dry-run by default), plus recent-run audit log |
| `/reports` | Generate a real, downloadable KPI/SLA/coverage snapshot report (daily through yearly framing) |
| `/support` | How to get help, known limitations, before-you-file-a-bug checklist |
| `/faq` | Direct answers about what this product does and doesn't do |
| `/login` | Local email/password sign-in; shows a "Sign in with SSO" button only when real OIDC provider env vars are configured |
| `/profile` | Current user's name/email/role, change-password form, log out |
| `/api/status` | JSON health/status endpoint (also surfaces `app_version`, shown in the page footer alongside a copyright line and informational-only compliance-framework references linking to `docs/COMPLIANCE_MAPPING.md`'s own disclaimer) |

## The `/run`, `/servicenow`, `/jira`, and `/splunk` safety design

All four forms **default to a dry-run/preview** — `/run` shows the exact command that
would execute and spends nothing; the connector send forms show exactly what payload
would be posted (a ServiceNow Incident, a Jira Issue, a Splunk HEC event), with zero
network calls. Actually executing any of them requires explicitly checking a confirm
box - and, since the auth system was added, being logged in as an **admin** (see
"Authentication" below; the preview itself never requires login). This mirrors the
CLI's own default posture (see [cli/README.md](../cli/README.md)) rather than adding a
different, looser rule just because there's now a button instead of a terminal command.

## Authentication

A real local login MVP, plus genuine OpenID Connect (OIDC) client code that stays
inert until a real identity provider is configured - see `dashboard/auth/`'s module
docstrings for the full design. Summary:

- **Password hashing**: PBKDF2-HMAC-SHA256 (`dashboard/auth/passwords.py`), Python
  stdlib only (`hashlib.pbkdf2_hmac`) - no `bcrypt`/`passlib` dependency added.
- **Sessions**: a from-scratch HMAC-signed cookie (`dashboard/auth/sessions.py`), stdlib
  only - a lighter alternative to Starlette's `SessionMiddleware`, which depends on the
  third-party `itsdangerous` package. Set `VULNHUNTER_SESSION_SECRET` to a real, stable
  value before any real deployment; without it, a random per-process secret is used and
  every session is invalidated on restart (a startup warning says so).
- **Users**: one row per account in the shared SQLite database (see
  `remediation/utils/db.py`) - previously a flat JSON file, seeded from the same two
  demo accounts (one admin, one regular user) via `scripts/migrate_json_to_db.py` - see
  the demo credentials below. Not a real user-management system; a production
  deployment should use real SSO instead (see OIDC below).
- **OIDC (SSO)**: `dashboard/auth/oidc.py` implements a real Authorization Code + PKCE
  flow against OIDC discovery/token/userinfo endpoints, using `requests` (already a
  dependency via the ServiceNow/Jira/Splunk/CrowdStrike connectors) - no `authlib`/
  `python-jose` dependency added. Like every connector in this repo, it's built against
  the public spec and has **not been exercised against a real identity provider** - the
  login page hides the "Sign in with SSO" button entirely unless `OIDC_ISSUER`,
  `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, and `OIDC_REDIRECT_URI` are all set as real
  environment variables, since this code can't register a real OAuth application on
  anyone's behalf.
- **Email notifications** (`remediation/notifications/email_sender.py`): real SMTP
  sending via Python's stdlib `smtplib` - no new dependency. Set `SMTP_HOST`,
  `SMTP_PORT`, and `SMTP_FROM_ADDRESS` (optionally `SMTP_USERNAME`/`SMTP_PASSWORD`/
  `SMTP_USE_TLS`) as real environment variables to enable it; `/notification-settings`
  shows configured/not-configured honestly. Same "built against the standard protocol,
  not exercised against a real server" caveat as every other connector here - send a
  real test email yourself before relying on it. Scheduled reports and team alerts both
  run on an in-process timer (hourly by default, `NOTIFICATION_CHECK_INTERVAL_SECONDS`
  to change it) that only ticks while this server process stays running - for delivery
  independent of server uptime, point a real external cron at
  `POST /api/notification-settings/run-checks-now` instead.
- **Active Directory group validation** (`dashboard/auth/ad_directory.py`): real,
  **read-only** LDAP group-membership lookups via `ldap3` (a genuinely new dependency -
  no honest stdlib way to speak LDAP) - used only to validate a Remediation Approval's
  approver against the policy's configured `requires_approval_group`; never creates,
  modifies, or resets an AD object. Set `AD_SERVER` and `AD_BASE_DN` (optionally
  `AD_BIND_USER`/`AD_BIND_PASSWORD`) as real environment variables to enable it;
  `/remediation-approvals` shows configured/not-configured honestly (`GET
  /api/directory/status`), and an approval proceeds either way - `ad_group_validated`
  is `null` ("not checked") when AD isn't configured, never fabricated as pass/fail.
  Same "built against the standard protocol, not exercised against a real directory"
  caveat as every other connector here - point it at a real test AD environment and
  verify a real lookup manually before relying on it. See
  `remediation/config/remediation_policy_engine.py` and
  [docs/REMEDIATION_WORKFLOWS.md](../docs/REMEDIATION_WORKFLOWS.md) for how this fits
  into the Remediation Policy/Approvals workflow, including the PAM (Vault/CyberArk)
  side, which never involves this application holding a live credential at all.
- **RBAC scope decision (stated plainly)**: sensitive *mutation* routes are gated -
  real ServiceNow/Jira/Splunk sends, a real (paid) pipeline run, a real (paid) AI-assist
  call, priority-rule edits (admin), exception create (any logged-in user) and revoke
  (admin), asset owner/facing edits (any logged-in user). Every GET/read route stays
  open **by default** - see "Closing the anonymous-read gap" just below for the real,
  opt-in way to close that for a production deployment. Finding/asset-level views
  (Queue, Asset Inventory, Exceptions, Remediation Approvals) additionally get real
  server-side **per-team filtering** for any logged-in non-admin with a team assigned
  (Admin Settings' "Team Management") - `dashboard/app.py`'s `_scope_to_team()`;
  Overview, ML Insights, and Compliance stay org-wide by design. The client-side router
  also redirects an unauthenticated browser to `/login` for every page (not just gated
  ones) for a coherent UX - but that's a UX gate, not the real security boundary on its
  own; see below for what actually closes it.
- **Closing the anonymous-read gap**: set `VULNHUNTER_REQUIRE_LOGIN_FOR_READS=true` to
  require a valid session on every `/api/*` route (the login flow itself stays
  reachable) - one middleware (`dashboard/app.py`'s `_require_login_for_api_reads`),
  not a change to any individual route, so it doesn't touch the large existing test
  suite that exercises the (still-default) open-reads behavior. This also closes the
  one real caveat on per-team filtering: without it, an anonymous request bypasses
  `_scope_to_team()` the same way it bypasses everything else. Requires a real
  `VULNHUNTER_SESSION_SECRET` too (below) - the app refuses to start otherwise, since
  gating every read while sessions reset on every restart would lock everyone out.
- **`VULNHUNTER_SESSION_SECRET`**: set this to a real, random, stable value before any
  real deployment (`python -c "import secrets; print(secrets.token_hex(32))"` generates
  one) - without it, a random secret is generated fresh per process, so every session is
  invalidated on restart and multiple worker processes mint incompatible cookies.
- **HTTPS**: opt-in for local dev via `SSL_KEYFILE`/`SSL_CERTFILE` environment variables
  (uvicorn's native TLS support - see `dashboard/app.py`'s `__main__` block). Generate a
  self-signed cert for local testing:
  ```bash
  openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost"
  ```
  A real deployment should terminate TLS at a reverse proxy instead of uvicorn's own TLS
  directly - a self-signed cert is for local dev only, never production. A minimal, real
  nginx config doing that (real TLS + WebSocket-safe headers + no path rewriting, since
  this app's own router expects the full path):
  ```nginx
  server {
      listen 443 ssl;
      server_name your-real-hostname;
      ssl_certificate     /etc/letsencrypt/live/your-real-hostname/fullchain.pem;
      ssl_certificate_key /etc/letsencrypt/live/your-real-hostname/privkey.pem;

      location / {
          proxy_pass http://127.0.0.1:5050;
          proxy_set_header Host $host;
          proxy_set_header X-Real-IP $remote_addr;
          proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
          proxy_set_header X-Forwarded-Proto $scheme;
      }
  }
  server {
      listen 80;
      server_name your-real-hostname;
      return 301 https://$host$request_uri;   # never serve real data over plain HTTP
  }
  ```
  Run the app itself with a real process manager, not `python dashboard/app.py`'s bare
  `uvicorn.run()` (that binds `127.0.0.1` only, by design, precisely so it's never
  accidentally internet-reachable without the reverse proxy in front of it):
  ```bash
  uvicorn app:app --host 127.0.0.1 --port 5050 --workers 4
  ```
  Multiple `--workers` is safe for this app's own session mechanism as long as
  `VULNHUNTER_SESSION_SECRET` is a real, shared, stable value (see above) - the signed-
  cookie design has no server-side session state to fall out of sync between workers.

**Demo credentials** (intentionally public - this is a demo seed file, not a real
secret; change or remove before any real deployment):
- `admin@vulnhunter.local` / `ChangeMe123!` (role: admin)
- `analyst@vulnhunter.local` / `ChangeMe123!` (role: user)

## CMDB import (Asset Inventory)

`/assets` has a "Import owner/team from a CMDB export" panel
(`remediation/inventory/cmdb_import.py`): upload a CSV export of your asset details,
and it will:

1. Guess which column is the asset name/owner/team via a keyword heuristic (same
   non-authoritative-suggestion pattern as `attack_mapping.py`'s ATT&CK tagging and
   `compensating_controls.py`'s control suggestions) - adjustable in the UI before
   applying, never applied blind.
2. Reconcile every row against the real, finding-derived asset list: **matched**
   (already has findings - owner/team applies immediately), **not yet seen** (no
   findings yet - owner/team is stored and applies the moment one appears), or
   **invalid** (no asset name found in the mapped column).
3. Let you review/edit each row's owner/team inline, then bulk-apply - writing to
   `remediation/inventory/asset_ownership.json` via the exact same upsert the
   single-asset "Edit owner" form already uses, just applied to many assets at once.

**CSV, not `.xlsx`**: this accepts CSV, not a fabricated Excel-binary parser - the same
reasoning as the export feature's download side (see "What this is NOT (yet)" below).
Every spreadsheet tool (Excel included) exports/opens CSV natively, so "export your
CMDB sheet to CSV first" is a one-click step, not a real limitation. Real `.xlsx`
upload would need a new dependency (`openpyxl`) this project doesn't otherwise use -
a reasonable one to add if genuinely needed, just not added speculatively here.

This is a real, working bulk-import - not a live CMDB sync/connector. There's no
scheduled or automatic re-sync; re-upload the same export whenever your CMDB data
changes.

## Why FastAPI + vanilla JS, not Node/React (or staying on Flask/Jinja2)

The ask behind this rewrite was a genuinely modern, commercial-grade interface. A
from-scratch React/TypeScript build was the obvious first thought — but at the time this
choice was made, the machine running this had no Node.js/npm installed, so a React build
couldn't be *written and verified running* there; shipping an untested frontend isn't
"modern," it's just unverified. Two real options remained:

1. **Stay on Flask + server-rendered Jinja2** (the original MVP's choice) — safe, but not
   what "modern JS interface" actually means, and doesn't showcase real client-side
   interactivity (sorting, live re-render, no full-page reloads).
2. **FastAPI (JSON API) + a hand-rolled vanilla-JS SPA** — real client-side routing,
   `fetch()`-based data loading, dynamic `import()` per page, live in-browser table
   sorting - everything a React app would give you for this scope, using only what
   ships in every modern browser. No bundler, no `node_modules`, no build step to get
   wrong. Every page was clicked through and verified live in a browser during
   development (not just unit-tested) - see KNOWLEDGE_TRANSFER.md §11.1.

That's what this dashboard now is. Node.js/npm are available in later environments this
has run in, but that alone isn't a reason to migrate now: this SPA has grown to 30+ page
modules, each already clicked through and verified live in a browser, and a from-scratch
React rewrite would mean re-verifying all of it for a visual upgrade well-built hand-
rolled SVG (`dashboard/static/js/charts.js`) already delivers - real risk for marginal
gain, not free just because the runtime constraint that originally ruled it out is gone.
If a React (or any other) frontend is ever built here, `/api/*`'s JSON contract is the
exact seam it would build against - `dashboard/data.py`'s parsing logic underneath
doesn't change either way, and neither would the FastAPI routes, which are already
framework-appropriate JSON endpoints rather than Flask's `render_template` calls.

## What this is NOT (yet)

This is a single-process MVP with a real but partial auth model and no persistence
layer:

- **Reads are still ungated server-side** — login is required by the client-side router
  for a coherent UX, and real mutations (sends, real pipeline runs, priority-rule edits,
  exception revoke) require a real server-side session, but every GET/read API route
  still returns real data with no login at all if called directly (`curl`, etc). Do not
  expose this beyond localhost/a trusted network as-is - see "Authentication" above for
  the full scope decision.
- **Per-team RBAC follows the same "reads are public" limitation above** — Queue, Asset
  Inventory, Exceptions, and Remediation Approvals are real, server-side filtered to a
  logged-in non-admin's own team (`dashboard/app.py`'s `_scope_to_team()`, set via Admin
  Settings' "Team Management"; see `dashboard/auth/users.py`). An admin, or any account
  with no team assigned, sees everything unfiltered - by design, this is opt-in
  *narrowing*, not deny-by-default, so it never makes a logged-in-but-unassigned account
  more restricted than an anonymous `curl`. That also means it's bypassable the same way
  every other read is: an anonymous request (no session cookie) always sees everything,
  team-scoping included. Closing that gap means making these four routes login-required
  outright - a separate, larger change from team-scoping itself (see the bullet above).
  Overview/Dashboard, ML Insights, and Compliance badges are deliberately never
  team-filtered - they're cross-cutting, org-wide views by design.
- **Local users only by default** — the shipped `users.json` has two demo accounts; OIDC
  (SSO) is real, working client code but stays disabled until a real identity provider's
  credentials are configured (see "Authentication" above).
- **Findings/plans still aren't in a database** — they're re-read from disk on every
  request; there's no historical trend view across multiple pipeline runs. Six of the
  smaller, actively-written record stores (`alert_state`/`schedule_state` in
  `remediation/notifications/`, plus `exceptions`, `remediation_approvals`,
  `activity_log`, and `ai_usage_log`) **have** moved off flat JSON files onto a real,
  local SQLite database (`remediation/vulnhunter.db`, gitignored - see
  `remediation/utils/db.py`), accessed through SQLAlchemy Core so a future move to
  Postgres for real multi-tenancy is a connection-string change, not a rewrite. A
  first-time run against a checkout that still has the old JSON seed files
  (`remediation/exceptions/exceptions.json`, `remediation/remediation_approvals/
  remediation_approvals.json`) should run `python scripts/migrate_json_to_db.py` once
  to carry that content into the new DB - safe to re-run, and a no-op if there's
  nothing left to migrate. `asset_inventory.py` (owner/team/facing/environment/
  network-info), `auth/users.py`, and the three inline JSON buffers `dashboard/app.py`
  writes directly (`generic-ingested.json`, `prismacloud_findings.json`,
  `cortex_xsiam_findings.json`) are still flat JSON, still only protected by
  `remediation/utils/file_lock.py`'s advisory lock (a dependency-free, cross-platform
  primitive; see its own module docstring) - real, but weaker than a DB transaction,
  and closing that gap is scoped follow-up work, not done in this pass. Even for the
  six migrated stores, SQLite is a genuine mitigation for a single-machine deployment,
  not a distributed-lock or multi-machine story - real ACID transactions on one file,
  not a client-server database.
- **Synchronous pipeline execution** — a real (non-dry-run) `/api/run` submission blocks
  the request until the pipeline finishes, which can be slow. A production version needs
  a job queue.
- **Single-tenant** — one repo's worth of findings, not a multi-customer SaaS view. The
  sidebar's tenant switcher is a UI-only demo (partitions the same dataset by asset
  category) - not real per-tenant auth or data isolation.
- **No report history** — `/reports`' period selector (daily/weekly/monthly/...) labels
  the report's intended cadence, but every period currently renders the same real,
  current-moment snapshot; there's no historical data to aggregate yet.

These are exactly the gaps [KNOWLEDGE_TRANSFER.md](../KNOWLEDGE_TRANSFER.md)'s
commercialization roadmap (Tier 2b/3) already names — this MVP is meant to prove the
data layer and interaction model, not to be deployed as-is.

## Testing

`tests/test_dashboard.py` uses `fastapi.testclient.TestClient` (in-process ASGI calls, no
real HTTP server or network) to verify the JSON API's contract precisely and that every
route serves the SPA shell correctly. Because the frontend renders client-side, these
tests validate JSON payloads rather than rendered HTML - the actual DOM rendering was
verified live in a browser during development (see KNOWLEDGE_TRANSFER.md). Every route
that can trigger a real, paid action (`/api/run`, `/api/servicenow/send`,
`/api/jira/send`, `/api/splunk/send`, `/api/ai-assist`) is tested only with `confirm`
omitted or, for the confirm=True path, with login omitted (asserting a 401 before the
real call would even happen) or with the real subprocess/HTTP call mocked out - never a
real spend in the test suite. A module-scoped temporary user store
(`tests/test_dashboard.py`'s `setUpModule`) logs a known admin/user in and out around
gated-route tests, so the suite never depends on (or mutates) the real shipped
`dashboard/auth/users.json`.

```bash
python -m unittest tests.test_dashboard -v      # dashboard API + auth-gating tests
python -m unittest tests.test_auth -v            # passwords/sessions/users/OIDC unit tests
python -m unittest discover -s tests -p "test_*.py"   # everything, repo-wide
```
