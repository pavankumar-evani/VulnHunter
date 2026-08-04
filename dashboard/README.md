# VulnHunter Dashboard (MVP)

A read-only-by-default web UI over both pipelines' real generated artifacts, plus a form
to trigger a run via the [headless CLI](../cli/README.md). A FastAPI JSON API
(`dashboard/app.py`) behind a hand-rolled vanilla-JS single-page frontend
(`dashboard/static/`) — no Node/npm/build step. See "Why FastAPI + vanilla JS" below for
the reasoning.

## Running it

```bash
pip install -r dashboard/requirements.txt
python dashboard/app.py
# open http://127.0.0.1:5050
```

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
- **`remediation/enrichment/ai_vuln_taxonomy.py`** — ten real AI/ML vulnerability
  categories (prompt injection, model poisoning, etc.) with summary/remediation
  guidance and an illustrative MITRE ATLAS cross-reference, shown on
  `/ai-vulnerabilities`. Same "keyword heuristic, verify before citing formally"
  honesty pattern as `attack_mapping.py`'s ATT&CK tagging.
- **`remediation/enrichment/infra_classification.py`** — splits Infrastructure
  Vulnerability Management findings into OS/Network/Network Security/OT-IoT/Cloud
  sub-categories by `asset.type`, shown on `/infrastructure`. Tagged onto every live
  queue finding in `load_live_queue()`, alongside `scan_type`/`attack_techniques`.
- **`remediation/connectors/jira_connector.py`**, **`splunk_connector.py`**,
  **`crowdstrike_connector.py`** — same "built against public docs, unverified against a
  live tenant" pattern as the ServiceNow/Tenable/Armis connectors. Jira and Splunk are
  push connectors with dashboard preview/send pages (`/jira`, `/splunk`); CrowdStrike is a
  pull connector like Tenable/Armis, with a reference page (`/xdr`) instead of a send form.
- **`remediation/connectors/infoblox_connector.py`**, **`axonius_connector.py`** — the
  sidebar's "Integrations" groups are now "Adaptors"; these two are pull connectors for
  DNS/IPAM and cyber-asset-management data (WAPI `record:host` and the `/api/devices`
  API, respectively), each with a reference page (`/infoblox`, `/axonius`). Unlike every
  connector above, they normalize into a plain asset-inventory record, not a
  vulnerability Finding — see "Adaptors — Asset Discovery / IPAM" below.
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
| `/appsec` | Application Vulnerabilities hub - rolls up SAST/DAST/SCA/Secrets/Container/API counts with links into each pre-filtered view. These six are sidebar-menu-only reachable through this hub, not separate top-level nav entries |
| `/infrastructure` | Infrastructure Vulnerabilities hub - rolls up OS/Network/Network Security/OT-IoT/Cloud counts (`remediation/enrichment/infra_classification.py`) with links into each pre-filtered `/queue` view |
| `/queue?category=infra-vm` / `?category=dast` / `?category=sca` / `?category=cert-mgmt` | The Security Domains menu's deep links into `/queue`, pre-filtered by category |
| `/vulnhunt` / `/vulnhunt?category=Secrets` | Code scan findings table (from `SECURITY_REPORT.md`), filterable by severity and CWE-derived category; also serves as the SAST and Secrets Management nav entries |
| `/queue` | The *live*, re-scored remediation queue (priority/SLA/KEV/EPSS/ATT&CK), sortable and filterable client-side (priority, asset type, category, infra sub-category, KEV-only), the (demo) tenant switcher applies here, live-refreshed every 20s, per-row "Ask AI" link, CSV/JSON/MD export |
| `/remediate` | The *static* remediation plan snapshot (from `REMEDIATION_PLAN.md`), linked to generated playbooks, filterable by risk tier and automation target, CSV/JSON/MD export |
| `/playbooks/<filename>` | Full content of one generated Ansible playbook |
| `/risk` | Risk Management dashboard - MITRE ATT&CK heat map, top vulnerabilities by type (with affected-asset count and owner), top assets by critical findings, an editable internal/external-facing classification per asset, and a CVSS v3.1 severity-definitions reference |
| `/ai-vulnerabilities` | AI Vulnerabilities - ten real AI/ML security categories (prompt injection, model poisoning, supply-chain compromise, etc.) with summary/remediation guidance and an illustrative MITRE ATLAS heat map; 0 findings against this repo's demo data (no AI/ML component), same honest treatment as DAST |
| `/exceptions` | Request/approve/revoke time-boxed risk-acceptance waivers per finding, with keyword-suggested compensating controls on the request form, CSV/JSON/MD export |
| `/assets` | Every asset with findings against it, aggregated, with an editable owner/team, CSV/JSON/MD export, and a "CMDB import" panel to bulk-assign owner/team from an uploaded CSV export (see below) |
| `/priority-rules` | Live YAML editor for `remediation/config/priority_rules.yaml`, with one-click presets for a pure-CVSS/severity model vs. the shipped VPR-style (threat-intel-aware) model - both are the same underlying weighted-score engine, just with the KEV/EPSS overrides toggled |
| `/servicenow`, `/jira`, `/splunk` | Ticketing/SIEM Incident/Issue/Event preview (no credentials needed) and send form, one page per connector |
| `/xdr` | CrowdStrike Falcon reference page - a pull connector like Tenable/Armis, so no send form; shows what the connector does and how to use it from Python |
| `/infoblox`, `/axonius` | Infoblox NIOS and Axonius asset-discovery/IPAM reference pages - pull connectors like Tenable/Armis/CrowdStrike, so no send form; normalize into asset-inventory records, not vulnerability findings |
| `/run` | Form to trigger a pipeline run (dry-run by default), plus recent-run audit log |
| `/reports` | Generate a real, downloadable KPI/SLA/coverage snapshot report (daily through yearly framing) |
| `/support` | How to get help, known limitations, before-you-file-a-bug checklist |
| `/faq` | Direct answers about what this product does and doesn't do |
| `/login` | Local email/password sign-in; shows a "Sign in with SSO" button only when real OIDC provider env vars are configured |
| `/profile` | Current user's name/email/role, change-password form, log out |
| `/api/status` | JSON health/status endpoint |

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
- **Users**: `dashboard/auth/users.json`, a real, editable, committed seed file (same
  pattern as `priority_rules.yaml`/`exceptions.json`) with two demo accounts (one admin,
  one regular user) - see the demo credentials below. Not a real user-management system;
  a production deployment should use real SSO instead (see OIDC below).
- **OIDC (SSO)**: `dashboard/auth/oidc.py` implements a real Authorization Code + PKCE
  flow against OIDC discovery/token/userinfo endpoints, using `requests` (already a
  dependency via the ServiceNow/Jira/Splunk/CrowdStrike connectors) - no `authlib`/
  `python-jose` dependency added. Like every connector in this repo, it's built against
  the public spec and has **not been exercised against a real identity provider** - the
  login page hides the "Sign in with SSO" button entirely unless `OIDC_ISSUER`,
  `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, and `OIDC_REDIRECT_URI` are all set as real
  environment variables, since this code can't register a real OAuth application on
  anyone's behalf.
- **RBAC scope decision (stated plainly)**: only sensitive *mutation* routes are
  gated - real ServiceNow/Jira/Splunk sends, a real (paid) pipeline run, a real (paid)
  AI-assist call, priority-rule edits (admin), exception create (any logged-in user) and
  revoke (admin), asset owner/facing edits (any logged-in user). Every GET/read route
  stays open, exactly as before this feature existed - gating every read route too would
  mean retrofitting auth into the entire existing test suite in one pass; this scopes the
  security-sensitive *actions* first, mirroring the project's existing dry-run-by-default
  safety model. The client-side router also redirects an unauthenticated browser to
  `/login` for every page (not just gated ones) for a coherent UX - but that's a UX gate,
  not the real security boundary: `curl http://host/api/queue` still returns real data
  with no cookie at all, by design in this pass.
- **HTTPS**: opt-in for local dev via `SSL_KEYFILE`/`SSL_CERTFILE` environment variables
  (uvicorn's native TLS support - see `dashboard/app.py`'s `__main__` block). Generate a
  self-signed cert for local testing:
  ```bash
  openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost"
  ```
  A real deployment should terminate TLS at a reverse proxy (nginx/Caddy) instead of
  uvicorn's own TLS directly - a self-signed cert is for local dev only, never production.

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
from-scratch React/TypeScript build was the obvious first thought — but this machine has
no Node.js/npm installed, so a React build couldn't be *written and verified running*
here; shipping an untested frontend isn't "modern," it's just unverified. Two real
options remained:

1. **Stay on Flask + server-rendered Jinja2** (the original MVP's choice) — safe, but not
   what "modern JS interface" actually means, and doesn't showcase real client-side
   interactivity (sorting, live re-render, no full-page reloads).
2. **FastAPI (JSON API) + a hand-rolled vanilla-JS SPA** — real client-side routing,
   `fetch()`-based data loading, dynamic `import()` per page, live in-browser table
   sorting - everything a React app would give you for this scope, using only what
   ships in every modern browser. No bundler, no `node_modules`, no build step to get
   wrong. Every page was clicked through and verified live in a browser during
   development (not just unit-tested) - see KNOWLEDGE_TRANSFER.md §11.1.

That's what this dashboard now is. If Node.js becomes available in the target
environment, `/api/*`'s JSON contract is the exact seam a React (or any other) frontend
would build against - `dashboard/data.py`'s parsing logic underneath doesn't change
either way, and neither would the FastAPI routes, which are already framework-appropriate
JSON endpoints rather than Flask's `render_template` calls.

## What this is NOT (yet)

This is a single-process MVP with a real but partial auth model and no persistence
layer:

- **Reads are still ungated server-side** — login is required by the client-side router
  for a coherent UX, and real mutations (sends, real pipeline runs, priority-rule edits,
  exception revoke) require a real server-side session, but every GET/read API route
  still returns real data with no login at all if called directly (`curl`, etc). Do not
  expose this beyond localhost/a trusted network as-is - see "Authentication" above for
  the full scope decision.
- **Local users only by default** — the shipped `users.json` has two demo accounts; OIDC
  (SSO) is real, working client code but stays disabled until a real identity provider's
  credentials are configured (see "Authentication" above).
- **No database** — findings/plans are re-read from disk on every request; there's no
  historical trend view across multiple runs.
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
