# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

VulnHunter started as a Claude Code **extension** — two slash commands plus seven scoped
subagents, no runnable application. It has since grown a second, much larger half on top:
a real, deployable web application. Both halves are real and current today:

- **The pipelines** — `/vulnhunt` and `/remediate`, orchestrating 8 subagents total (3 + 5)
  via markdown prompt/config files under `.claude/`. No build system or package manifest
  of their own. See "Architecture: the 3-stage subagent pipeline" and "Architecture: the
  remediation engine" below.
- **The dashboard** (`dashboard/app.py`) — a FastAPI backend plus a hand-rolled vanilla-JS
  single-page frontend (~50 routes), a real auth/RBAC/session model, 8 live pull
  connectors and 3 push connectors, a headless CLI (`cli/vulnhunter.py`) that drives either
  pipeline non-interactively, and a Python `unittest` suite of 1,343 tests — all passing as
  of 2026-09-02 (`python -m unittest discover -s tests -p "test_*.py"`). See "Architecture:
  the dashboard" below.

The dashboard reads the pipelines' own output artifacts (`SECURITY_REPORT.md`,
`remediation/output/normalized-findings.json`, `REMEDIATION_PLAN.md`) directly off disk,
and can also trigger either pipeline as a subprocess — this is one system, not two
unrelated projects sharing a repo.

For depth beyond this file: [dashboard/README.md](dashboard/README.md) and
[cli/README.md](cli/README.md) are the primary sources this file draws from and defers to.
`docs/enterprise-suite/` holds seven longer technical references (`architecture.html`,
`vuln-engine.html`, `remediation-engine.html`, `connectors.html`, `rbac-governance.html`,
`pages.html`, `developer-guide.html`) plus a task-oriented `user-guide.html` for
end-users ("how do I...?" — kept in sync with `docs/FAQ.md` and
`dashboard/static/js/pages/faq.js`'s own hardcoded FAQ array, per
`docs/enterprise-suite/MANIFEST.md`'s sync table) — indexed in
[docs/enterprise-suite/MANIFEST.md](docs/enterprise-suite/MANIFEST.md)), each covering one
subsystem in more depth than fits here and meant to be kept in sync with the app (see
"Enterprise documentation suite" at the end of this file).

## Running things

```bash
# The dashboard (see dashboard/README.md for TLS/env-var options before any real deployment)
pip install -r dashboard/requirements.txt
python dashboard/app.py                      # http://127.0.0.1:5050
# (.claude/launch.json config name: "vulnhunter-dashboard")

# The two pipelines, interactively inside Claude Code
claude
/vulnhunt <path-to-target-repo> [--fix]
/vulnhunt vulnerable-demo-app         # scan+report only
/vulnhunt vulnerable-demo-app --fix   # scan+report, then auto-fix and push a branch
/remediate                            # ingests remediation/sample-data/* by default
/remediate --generate                 # also generates Ansible playbooks for auto-remediable findings

# The same two pipelines, headless (CI/cron/the dashboard's own /run page) - see cli/README.md
python cli/vulnhunter.py --dry-run scan vulnerable-demo-app --fix   # preview only, no spend
python cli/vulnhunter.py scan vulnerable-demo-app --fix             # real run, spends API usage
python cli/vulnhunter.py --dry-run remediate --generate
python cli/vulnhunter.py remediate --generate

# The demo app standalone (for manual verification - never deploy this anywhere reachable)
cd vulnerable-demo-app
pip install -r requirements.txt
python init_db.py    # creates vulnshop.db with seed users
python app.py         # listens on 0.0.0.0:5000, debug=True
```

Full test suite (see "Testing" below for exactly what CI installs first):

```bash
python -m unittest discover -s tests -p "test_*.py"
```

Modifying the pipelines themselves means editing `.claude/agents/*.md` or
`.claude/commands/*.md` directly and re-running the relevant command against
`vulnerable-demo-app/` (for `/vulnhunt`) or `remediation/sample-data/` (for `/remediate`)
to see the effect — there's no separate build or lint step for that half of the repo. The
dashboard and `remediation/` Python modules are ordinary Python: edit, then re-run
`python dashboard/app.py` or the relevant `tests/test_*.py` file to see the effect.

## Architecture: the dashboard

One FastAPI process (`dashboard/app.py`, ~2,450 lines) serves the JSON API, the SPA shell,
and every static asset — no message queue, cache layer, or microservice boundary to
operate. Admin-editable policy still lives in YAML files under `remediation/config/`, read
fresh on every request; the record stores that see real read-modify-write traffic
(exceptions, approvals, activity/AI-usage logs, asset ownership, users, notification
scheduler state, and pending live-data adapter output) now live in a real local SQLite
database instead — see "Data & storage" below. Judgment-heavy work (classification,
playbook drafting) is delegated to the
same Claude Code subagents the pipelines use, invoked as a subprocess exactly the way
`cli/vulnhunter.py` does it — the dashboard's `/run` page is a thin UI over that same CLI
entry point (same dry-run default, same confirm gate, same budget cap), not a separate
implementation.

### Request path and middleware

Every request passes through three middlewares, in order: (1) a static no-cache rule, so
an edited JS/CSS file is never served stale; (2) secure response headers
(`X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`,
`Permissions-Policy` always on; a full `Content-Security-Policy` is opt-in via
`VULNHUNTER_ENABLE_CSP=true`); (3) an opt-in require-login-for-reads gate, off by default
(see "Authentication & RBAC" below). Routes are two kinds: `/api/*` (the JSON API — the
only thing the frontend calls, and the only thing worth testing from Python) and
everything else, which all serve the same `dashboard/static/index.html` shell.

`dashboard/static/js/app.js` is the client-side router: it maps
`window.location.pathname` to a page module under `static/js/pages/*.js` (each exports
`title` and an async `render(container)`, and owns its own markup, API calls, and event
wiring) and re-renders `#app` in place via `history.pushState` — no full-page reloads, no
bundler, no `node_modules`. Shared libraries: `api.js` (every backend call in one place),
`dom.js` (HTML-escaping, flash messages, KPI-card helpers), `charts.js` (hand-rolled SVG
bar/pie charts, shared severity palette).

For the full route table (every one of the ~50 pages and what it shows), see the "Pages"
section of [dashboard/README.md](dashboard/README.md) or `docs/enterprise-suite/pages.html`
— it's long enough that reproducing it here would just be a second copy to keep in sync.
The shape worth knowing without opening either: a "Security Domains" layer of hub pages
(`/appsec`, `/infrastructure`, `/ot-vulnerabilities`, `/ai-vulnerabilities`) that roll up
counts and link into pre-filtered `/queue` views; a live, re-scored `/queue` versus a
static `/remediate` plan snapshot; one Test Connection + Fetch page per pull connector (see
"The connector pattern" below); governance pages (`/exceptions`, `/remediation-approvals`,
`/priority-rules`, `/exploit-criteria`); and account/ops pages (`/login`, `/profile`,
`/run`, `/reports`, `/support`, `/faq`).

### Data & storage

The files most worth knowing:

| Path | What it is |
|---|---|
| `remediation/output/normalized-findings.json` | Every finding, in the schema below — the system of record |
| `REMEDIATION_PLAN.md` | Point-in-time snapshot written by `remediation-planner` — risk tier, action type, rollback plan per finding |
| `remediation/output/*.yml` | Generated Ansible playbooks, one per remediable finding |
| `remediation/config/*.yaml` | Every admin-editable policy — priority weights, SLA windows, remediation policy, risk/exposure scoring, exploit-criteria rules, alerting, report schedules, AI governance |
| `remediation/vulnhunter.db` | Shared local SQLite database (gitignored) — see below |
| `remediation/live-data/*` | Raw CSV/XML exports written by a CVE-scoped connector's Fetch action (Tenable/Qualys/OpenVAS), before ingestion via `/remediate` |

**`remediation/utils/db.py`** — a real local SQLite database (accessed through
SQLAlchemy Core, not raw `sqlite3`, so a future move to Postgres for real multi-tenancy
is a connection-string change, not a rewrite) backs every record store that sees real
read-modify-write traffic: `alert_state`/`schedule_state` (notification scheduler dedup
state), `exceptions`, `remediation_approvals`, `activity_log`, `ai_usage_log`,
`asset_ownership`, `users` (the local login store), and `live_data_findings` (pending,
not-yet-merged output from the generic ingest webhook and the PrismaCloud/Cortex XSIAM
connectors' fetch routes — see `remediation/connectors/live_data_store.py`). Several of
these were previously flat JSON files with real, committed seed/example data
(`exceptions.json`'s one waiver example, `asset_ownership.json`'s five, `users.json`'s
two demo accounts) — `scripts/migrate_json_to_db.py` is the one-time, idempotent
migration that carries that seed content into the DB; run it once on a fresh checkout
(see "Running things" above). `remediation/utils/file_lock.py` — a real, dependency-free,
cross-platform advisory file lock, not a placeholder — still guards every one of these
stores' own read-modify-write cycle (e.g. compute-next-id-then-insert) even though the
storage backend is now a real database: SQLite's own locking gives atomicity for a
single statement, but a caller whose critical section spans more than one statement (or
slow I/O) still needs its own explicit mutual exclusion. `activity_log`/`ai_usage_log`
are the one exception — a plain autoincrement `INSERT` has no read-modify-write gap left
to protect, so those two dropped the lock entirely once migrated. None of this
substitutes for a real multi-machine database story; it's a genuine mitigation for a
single-machine deployment, not a distributed-lock story.

### The Finding schema

Every source that ingests vulnerability data — Tenable, Qualys, OpenVAS/GVM, Prisma Cloud,
Cortex XSIAM, Armis, a generic webhook, or manually-curated threat intel — maps its own
export format into one common shape, documented field-by-field in
[remediation/schema/normalized-finding-schema.md](remediation/schema/normalized-finding-schema.md)
(the source of truth for field names — nothing downstream needs to know a source-specific
field again). `asset.type` is the routing key: **17 types today** (windows/unix server and
endpoint OS, network routing/switching, network security devices, IoT/OT, virtualization
hosts, cloud infrastructure, applications, certificates, client applications, mobile
devices, printers, IaC resources, code repositories, container runtimes, and AI/ML
systems), but only `windows-server` and `unix-server` route to a working
`remediation-fixer-*` subagent today — every other type is still normalized, enriched,
scored, and planned, just routed to "no automated fixer yet, here's who should own it"
instead of a generated artifact. `kev`/`epss` (CISA KEV + FIRST.org EPSS) and
`poc_available`/`user_interaction_required` are added by later enrichment stages, not at
ingestion, and stay `null` whenever `cve` is null — these are inherently CVE-scoped
signals, so a policy finding with no CVE honestly carries none rather than a guessed one.

## Authentication & RBAC

A real local login MVP plus genuine OIDC client code that stays inert until a real
provider is configured. Full detail (every env var, every edge case) is in
`dashboard/README.md`'s "Authentication" section and
`docs/enterprise-suite/rbac-governance.html`; the load-bearing facts:

- **Passwords**: PBKDF2-HMAC-SHA256, stdlib only (`dashboard/auth/passwords.py`).
- **Sessions**: an HMAC-signed cookie (`dashboard/auth/sessions.py`), stdlib only. Set
  `VULNHUNTER_SESSION_SECRET` to a real, stable value before any real deployment — without
  it, a random per-process secret means every session is invalidated on restart.
- **Users**: `dashboard/auth/users.json`, a real, editable, committed seed file with two
  demo accounts (`admin@vulnhunter.local`, role admin; `analyst@vulnhunter.local`, role
  user; both `ChangeMe123!`) — not a real user-management system; use OIDC/SSO for a real
  deployment instead.
- **OIDC (SSO)**: `dashboard/auth/oidc.py`, a real Authorization Code + PKCE flow. The
  login page hides the "Sign in with SSO" button entirely unless `OIDC_ISSUER`,
  `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, and `OIDC_REDIRECT_URI` are all set — never
  exercised against a real identity provider.
- **RBAC model — deliberately simple** (`dashboard/auth/rbac.py`): one boolean,
  `require_admin` vs. plain `require_login`. A second, independent axis — **team** —
  narrows which findings/approvals a non-admin's queries return (`dashboard/app.py`'s
  `_scope_to_team()`); admins and accounts with no team assigned see everything
  unfiltered. There's no granular permission matrix (no separate analyst/approver/
  read-only roles).
- **Reads are public by default.** Every state-changing route is gated per-route with an
  explicit RBAC dependency, but every `GET`/`/api/*` read route returns real data with no
  login at all (`curl`, etc.) unless `VULNHUNTER_REQUIRE_LOGIN_FOR_READS=true` is set —
  which itself requires a real, stable `VULNHUNTER_SESSION_SECRET` or the app refuses to
  start. This was a deliberate choice, made explicitly, to narrow the gap in an opt-in way
  rather than close it by default and break the ~50 existing test call sites/assumptions
  built on today's open-reads behavior — closing it fully is a real, one-line change for
  any deployment that needs it, just not the shipped default. Per-team scoping is
  bypassable the same way until that flag is set: an anonymous request always sees
  everything, team-scoping included.
- **Active Directory group validation** (`dashboard/auth/ad_directory.py`): real,
  **read-only** LDAP lookups (`ldap3`) used only to validate a Remediation Approval's
  approver against policy — never creates, modifies, or resets an AD object. A distinct
  concern from the `active_directory_connector.py` pull connector below.

## The connector pattern

Every pull connector — 8 today (Tenable, Qualys, OpenVAS/GVM, Prisma Cloud, Cortex XSIAM,
Infoblox, Axonius, Active Directory) — implements the same small contract (full checklist
in `docs/enterprise-suite/developer-guide.html` §2-3):

```python
class SomeConnector:
    def __init__(self, ...credentials..., session=None):
        self.session = session or requests.Session()   # DI seam for tests

    def test_connection(self):
        """Cheapest real authenticated call - no confirm gate needed."""

    def fetch_and_write_csv(self, output_path):
        """Real fetch, confirm-gated at the route level, never here."""
```

Credentials are always a constructor argument, never a stored setting. A stateful
protocol (LDAP, GMP) takes an injectable connection/client object instead of a
`requests.Session` — same seam, different transport. Each pull connector has a real
dashboard **Test Connection + Fetch** page (`/tenable`, `/qualys`, `/openvas`,
`/prismacloud`, `/cortex-xsiam`, `/infoblox`, `/axonius`, `/active-directory`).
CVE-scoped host sources (Tenable, Qualys) flatten into `tenable_connector.CSV_FIELDNAMES`
and still need `/remediate <file>` to reach the dashboard's own pages; posture/
correlated-detection sources (Prisma Cloud, Cortex XSIAM) normalize straight into the
Finding schema; the asset-discovery sources (Infoblox, Axonius, Active Directory)
normalize into the asset inventory instead of findings. Three push connectors —
ServiceNow, Jira, Splunk (`/servicenow`, `/jira`, `/splunk`) — send *to* an external
system, behind the same dry-run-by-default + explicit confirm + admin-login pattern as a
real pipeline run. `armis_connector.py` and `crowdstrike_connector.py` are real but
Python-only so far — CrowdStrike has a reference page (`/xdr`), Armis has neither a
dashboard page nor form yet. **Every connector in this repo is built against the vendor's
real, public API and unit-tested against a hand-rolled fake, but none has been exercised
against a real, live vendor account** — each says so plainly in its own module docstring
and dashboard page. That's the expected, disclosed state for a new connector, not a gap to
hide.

**Adding a new connector**: write `remediation/connectors/<name>_connector.py`
(`test_connection()` + a fetch method); decide the output shape (flatten into the Tenable
CSV shape, normalize directly to the Finding schema, or the asset-inventory shape);
unit-test against a hand-rolled fake (not the vendor SDK's own mock utilities); add
`POST /api/<name>/test-connection` (admin-gated, no confirm) and `POST /api/<name>/fetch`
(confirm-gated, returns `preview_only` when unconfirmed); wire `api.js` + a page module
under `pages/` + an `app.js` router entry; disclose the verification status honestly in
both the module docstring and the dashboard page — "built against public docs, unit-tested
against mocked responses, never exercised against a real account" is the default and
expected state for a new connector, not something to gloss over.

## Testing

```bash
python -m unittest discover -s tests -p "test_*.py"   # everything, repo-wide - 1,343 tests today, all passing
python -m unittest tests.test_dashboard -v              # dashboard API + auth-gating tests
python -m unittest tests.test_auth -v                    # passwords/sessions/users/OIDC unit tests
```

One `unittest` file per module/route group, hand-rolled fakes over vendor mock libraries.
Every route that can trigger a real, paid action (`/api/run`, `/api/servicenow/send`,
`/api/jira/send`, `/api/splunk/send`, `/api/ai-assist`) is tested only with `confirm`
omitted, or with login omitted (asserting a 401 before the real call would happen), or
with the real subprocess/HTTP call mocked out — never a real spend in the test suite. A
module-scoped temporary user store in `tests/test_dashboard.py` logs a known admin/user in
and out around gated-route tests, so the suite never depends on or mutates the real
shipped `dashboard/auth/users.json`. `.github/workflows/ci.yml` installs
`dashboard/requirements.txt`, `remediation/connectors/requirements.txt`,
`remediation/enrichment/requirements.txt`, and `remediation/config/requirements.txt` (in
that order) and runs the full suite on every push and PR.

For JS: `node --check <file>` catches syntax errors only — necessary, never sufficient. It
will not catch a missing or mismatched import, which only surfaces as a runtime
`ReferenceError` when the function is actually invoked in a browser. Verify any JS/frontend
change live — reload the page, check the console for errors, click through the actual
feature — before calling it done. This SPA has 30+ page modules; each was clicked through
and verified live in a browser during development, not just unit-tested, and a
shared-function edit can silently break a sibling page that wasn't the focus of the change.

## Architecture: the 3-stage subagent pipeline

`/vulnhunt` (`.claude/commands/vulnhunt.md`) is the orchestrator. It parses `$ARGUMENTS`
for a target path (default: cwd) and an optional `--fix` flag, then sequences three
subagents strictly in order, each with **deliberately scoped tool access** — this scoping
is the core design idea of the project, not an incidental detail:

1. **`vuln-scanner`** (tools: `Read, Grep, Glob, Bash` — no write access, by design) scans
   the target for injection flaws, hardcoded secrets, auth/crypto weaknesses, insecure
   config, risky pinned dependencies, and Docker issues. It returns *only* a raw JSON
   array of findings (id, file, line, title, cwe, severity, description, evidence,
   `auto_fixable`, `fix_hint`) — no prose, no markdown fences. The orchestrator must not
   proceed until this JSON is valid.
2. **`vuln-triage-reporter`** (tools: `Write` only — cannot read source, only receives
   findings JSON in its prompt) turns that JSON into `SECURITY_REPORT.md` written to the
   *target* repo's root: summary table, findings ranked Critical→Low with plain-English
   impact, and a remediation plan splitting auto-fixable vs. needs-human-review.
3. **`vuln-fixer`** (tools: `Read, Edit, Write, Bash`) runs only if `--fix` was passed (or
   the user confirms after seeing the report). It acts *only* on findings marked
   `auto_fixable: true`, re-reads each file immediately before editing (line numbers from
   the scan may be stale), and follows a fixed git workflow: new branch
   `vulnhunter/auto-fixes-<timestamp>` → commit referencing finding IDs → `git push`,
   surfacing the PR-creation URL GitHub prints in the push output. No `gh` CLI dependency
   — opening the actual PR is a manual click in the browser or VS Code afterward. If push
   fails, it must stop and tell the user the manual step rather than failing silently.

The chat output from `/vulnhunt` stays a short summary (counts by severity, auto-fixable
count); full detail always lives in `SECURITY_REPORT.md`, never dumped into the
conversation.

### Why the tool scoping matters

Each agent's `tools:` list in its frontmatter is a hard security boundary, not a
suggestion: the scanner is read-only so the component that *finds* vulnerabilities cannot
introduce new ones; the reporter can only `Write`, so it cannot scan or fix; the fixer is
the only agent allowed to touch git/`gh`. When editing any of the three agent files
(`.claude/agents/*.md`), preserve this separation — don't widen an agent's tool access to
"make it easier," since the narrow scope is the point.

### Fix conventions the fixer follows (`vuln-fixer.md`)

- SQL injection → parameterized queries (`?` for sqlite3, `%s` for psycopg2/MySQLdb).
- Hardcoded secrets → `os.environ[...]`, added to `.env.example` as a placeholder (never
  the real value), with `.env` added to `.gitignore`.
- `eval()`/`exec()` → only fixed if a safe mechanical replacement exists (e.g.
  `ast.literal_eval`); genuine dynamic-eval requirements are left for manual review rather
  than fixed and potentially broken.
- Docker running as root → add a non-root `USER` instruction after deps are installed.
- Debug mode in a prod entrypoint → gate behind an env var defaulting to `False`.

## Architecture: the remediation engine (`/remediate`)

`/remediate` (`.claude/commands/remediate.md`) orchestrates **six** subagents, same
scoped-tool-access philosophy as `/vulnhunt`:

1. **`vuln-ingest-normalizer`** (tools: `Read, Glob, Write`) parses Tenable CSV, Armis
   JSON, and threat-intel JSON exports into one common schema — see
   `remediation/schema/normalized-finding-schema.md`. Writes
   `remediation/output/normalized-findings.json`. Assigns `asset.type` (the routing key
   for everything downstream — 17 types today) and `remediation_domain` (non-null only
   for `windows-server`/`unix-server`/`iot-ot-device`, the three domains with a working
   fixer — see item 4 below for why the OT one is a different shape).
2. **`threat-intel-enricher`** (tools: `Read, Write, Bash`) runs next, before planning: it
   shells out to `remediation/enrichment/kev_epss.py` to attach real CISA KEV and
   FIRST.org EPSS data to every finding that already has a CVE, overwriting
   `normalized-findings.json` in place. If the enrichment script fails (e.g. no network
   access in this environment), the orchestrator proceeds to planning anyway and notes in
   the chat summary that KEV/EPSS data is unavailable for this run — a fabricated
   "this CVE is KEV-listed" claim would be a serious credibility problem for a security
   tool, worse than honestly reporting the enrichment step didn't run.
3. **`remediation-planner`** (tools: `Read, Write`) assigns each finding an `action_type`,
   `automation_target`, `risk_tier` (`auto-approvable` / `needs-change-approval` /
   `manual-only`), `rollback_plan`, and `priority`. Writes `REMEDIATION_PLAN.md` to the
   project root. Defaults to the more conservative risk tier when uncertain — this is a
   deliberate design choice, not caution to relax later.
4. **`remediation-fixer-windows`** / **`remediation-fixer-unix`** (tools: `Read, Write`
   only — no `Bash`, deliberately) generate Ansible playbooks per finding into
   `remediation/output/<finding-id>-<slug>.yml`, only for findings already routed to their
   domain by the planner. They never execute anything — that's the whole safety model of
   this pipeline (see README's "Remediation Engine" section for the full rationale).
   **`remediation-fixer-ot`** (same `Read, Write`-only tool scope) handles
   `iot-ot-device` findings, but generates a different kind of artifact entirely: a
   compensating-control/isolation recommendation plus a vendor-coordination checklist
   (`remediation/output/<finding-id>-ot-recommendation.md`), never a direct patch or
   config script — OT/ICS devices are frequently unsafe to patch or reboot live, so
   "generate the fix" for this domain means "generate the human-actionable risk-reduction
   plan," not automation. See that subagent's own file for the full rationale (grounded
   in NIST SP 800-82's OT security guidance).

A `--finding-id FIND-N` argument (what the dashboard's "Trigger Remediation" button on an
already-approved finding uses, via `/api/run`) skips steps 1-3 entirely and delegates
straight to whichever fixer matches that one finding's `remediation_domain`, rather than
re-running ingest/enrich/plan for the whole batch to reach one already-known finding.

### Why network/firewall/IoT findings stay manual-only

`vuln-ingest-normalizer`, `threat-intel-enricher`, and `remediation-planner` handle every
asset type — ingestion, enrichment, and planning are asset-agnostic by design. Only
fix-generation is incomplete: there's no `remediation-fixer-network` or
`remediation-fixer-iot` yet, out of the 17 types the schema recognizes today (network
routing/switching, network security devices, IoT/OT, cloud infrastructure, certificates,
AI/ML findings, code repositories, and more — see
`remediation/schema/normalized-finding-schema.md` for the full list and why each was
added). Adding one means adding a new subagent with `tools: Read, Write` (same restricted
pattern) that generates vendor-appropriate config (e.g. Ansible's
`cisco.ios`/`junipernetworks.junos` collections for network gear), plus updating
`remediation-planner`'s `automation_target` assignment to route to it. Don't add real
execution capability (`Bash`, SSH, API calls) to any fixer subagent — every fixer in this
project stays artifact-generation-only.

## The demo app (`vulnerable-demo-app/`)

Six labeled, intentional vulnerabilities used as the `/vulnhunt` scoring/demo baseline — if
you modify this app, keep the vuln count and CWE labels in its docstring/comments
accurate, since the README's "expected result" (9 findings, 6 auto-fixed) depends on them:

1. Hardcoded Stripe key (`app.py`, `Dockerfile` `ENV`) — CWE-798
2. SQL injection via string concatenation in `/user` — CWE-89
3. `eval()` on user input in `/calc` — CWE-95
4. Command injection (`shell=True`) in `/ping` — CWE-78
5. `debug=True` in `app.run()` — CWE-489
6. Plaintext password storage in `/register` — CWE-256

Plus Dockerfile-level issues: no `USER` directive (runs as root, CWE-250), unpinned base
image tag, secret baked into an image layer via `ENV`.

**Never deploy this app anywhere reachable** — it exists solely as a scan target.

## Enterprise documentation suite — keep it in sync with the application

`docs/enterprise-suite/` holds 11 HTML documents (an executive brief, 7 technical
references, a POC methodology, and a commercial pricing/SLA page — indexed in
`docs/enterprise-suite/MANIFEST.md`, each also published as a live, shareable Artifact
page at the URL listed there) plus `docs/PRICING.md`, the plain-markdown source of truth
for pricing/SLA terms.

**Whenever a change to the application would make a claim in one of these documents — or
in this file — wrong, stale, or incomplete, update the affected document(s) in the same
change.** `docs/enterprise-suite/MANIFEST.md` has the exact "if you change X, update Y"
table (it now includes this file as a target for several rows: connector changes, RBAC/
auth changes, repo-structure/subagent-convention changes, and any change to a pipeline's
subagent sequence) and the republish instructions (edit the local `.html` file, then use
the Artifact tool's `publish` action with that file and the document's existing URL, so it
updates in place rather than creating a duplicate).

This cuts both ways: if `docs/PRICING.md` or the commercial model changes, sweep
`docs/enterprise-suite/pricing.html`, `executive-brief.html`, and
`docs/VR_PLATFORM_COMPARISON.md` for now-stale cost claims (e.g. an old "$0 / free"
framing) before considering the change done.
