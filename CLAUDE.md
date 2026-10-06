# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**New session, especially in a fresh account with no memory of prior work on this
repo**: read [SESSION_SNAPSHOT.md](SESSION_SNAPSHOT.md) at the repo root right after
this file. This file describes what the repo *is*, timelessly; that one describes what's
*already been decided* (the dark-navy theme, Chakra Petch everywhere, no Deloitte
branding, and a handful of other standing preferences a from-scratch read of the code
won't surface) and what was in progress as of the date at its top.

**If you're joining as one of several parallel sessions working this repo at once**:
also read [BRANCHES.md](BRANCHES.md) — it says which branch owns which folder, so you
can stay in your lane without needing to check out or read anyone else's branch.

## What this repository is

Quanta started as a Claude Code **extension** — two slash commands plus seven scoped
subagents, no runnable application. It has since grown a second, much larger half on top:
a real, deployable web application. Both halves are real and current today:

- **The pipelines** — `/quanta-scan` and `/remediate`, orchestrating 12 subagents total
  (4 + 8) via markdown prompt/config files under `.claude/`. No build system or package
  manifest of their own. See "Architecture: the 3-stage subagent pipeline" and
  "Architecture: the remediation engine" below.
- **The dashboard** (`dashboard/app.py`) — a FastAPI backend plus a hand-rolled vanilla-JS
  single-page frontend (~50 routes), a real auth/RBAC/session model, 8 live pull
  connectors and 3 push connectors, a headless CLI (`cli/quanta.py`) that drives either
  pipeline non-interactively, and a Python `unittest` suite of 2,302 tests — all passing as
  of 2026-09-03 (`python -m unittest discover -s tests -p "test_*.py"`). See "Architecture:
  the dashboard" below.

The dashboard reads the pipelines' own output artifacts (`SECURITY_REPORT.md`,
`remediation/output/normalized-findings.json`, `REMEDIATION_PLAN.md`) directly off disk,
and can also trigger either pipeline as a subprocess — this is one system, not two
unrelated projects sharing a repo.

For depth beyond this file: [dashboard/README.md](dashboard/README.md) and
[cli/README.md](cli/README.md) are the primary sources this file draws from and defers to.
`docs/enterprise-suite/` holds nine longer technical references (`architecture.html`,
`vuln-engine.html`, `remediation-engine.html`, `connectors.html`, `rbac-governance.html`,
`ai-capabilities.html`, `reporting.html`, `pages.html`, `developer-guide.html`) plus a
task-oriented `user-guide.html` for
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
python dashboard/app.py                      # https://127.0.0.1:5050 (auto-generates a
                                              # local HTTPS cert on first run - see
                                              # dashboard/README.md's "HTTPS" section)
# (.claude/launch.json config name: "quanta-dashboard")

# The two pipelines, interactively inside Claude Code
claude
/quanta-scan <path-to-target-repo> [--fix]
/quanta-scan vulnerable-demo-app         # scan+report only
/quanta-scan vulnerable-demo-app --fix   # scan+report, then auto-fix and push a branch
/quanta-scan vulnerable-demo-app --verify VULN-2 quanta/auto-fixes-<branch>  # re-check one fix
/remediate                            # ingests remediation/sample-data/* by default
/remediate --generate                 # also generates Ansible playbooks for auto-remediable findings

# The same two pipelines, headless (CI/cron/the dashboard's own /run page) - see cli/README.md
python cli/quanta.py --dry-run scan vulnerable-demo-app --fix   # preview only, no spend
python cli/quanta.py scan vulnerable-demo-app --fix             # real run, spends API usage
python cli/quanta.py --dry-run remediate --generate
python cli/quanta.py remediate --generate

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
`vulnerable-demo-app/` (for `/quanta-scan`) or `remediation/sample-data/` (for `/remediate`)
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
`cli/quanta.py` does it — the dashboard's `/run` page is a thin UI over that same CLI
entry point (same dry-run default, same confirm gate, same budget cap), not a separate
implementation.

### Request path and middleware

Every request passes through three middlewares, in order: (1) a static no-cache rule, so
an edited JS/CSS file is never served stale; (2) secure response headers
(`X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`,
`Permissions-Policy`, `Strict-Transport-Security`, `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy` always on; a same-origin-only
`Content-Security-Policy` is on by default when `QUANTA_PRODUCTION` is set and otherwise opt-in via `QUANTA_ENABLE_CSP=true`; the font is self-hosted so no outside host is
named; failed sign-ins are throttled per account and per address, and the session cookie is `Secure` over HTTPS); (3) an opt-in require-login-for-reads gate, off by default
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
`/priority-rules`, `/exploit-criteria`); risk-correlation pages (`/attack-paths` — entry/
pivot/impact chains built on each finding's tagged MITRE ATT&CK tactic;
`/dependencies` — SBOM-derived blast radius per vulnerable package; both real, both
honestly empty until the underlying data — a shared asset/tactic, or a matched SBOM
component — actually exists); and account/ops pages (`/login`, `/profile`, `/run`,
`/reports`, `/support`, `/faq`). The finding-detail modal (opened from any finding-ID
link, `dashboard/static/js/findingDetail.js`) additionally shows real compensating-control
coverage and network-reachability data, lazily fetched per finding — see
`remediation/enrichment/control_coverage.py` and `network_reachability.py`.

### Data & storage

The files most worth knowing:

| Path | What it is |
|---|---|
| `remediation/output/normalized-findings.json` | Every finding, in the schema below — the system of record |
| `REMEDIATION_PLAN.md` | Point-in-time snapshot written by `remediation-planner` — risk tier, action type, rollback plan per finding |
| `remediation/output/*.yml` | Generated Ansible playbooks, one per remediable finding |
| `remediation/config/*.yaml` | Every admin-editable policy — priority weights, SLA windows, remediation policy, risk/exposure scoring, exploit-criteria rules, alerting, report schedules, AI governance, plus two hand-maintained datasets: `security_controls.yaml` (per-asset firewall rules + EDR policy state) and `network_topology.yaml` (per-asset hop path to the internet) — both ship empty, feeding `remediation/enrichment/control_coverage.py` and `network_reachability.py` respectively |
| `remediation/quanta.db` | Shared local SQLite database (gitignored) — see below |
| `remediation/live-data/*` | Raw CSV/XML exports written by a CVE-scoped connector's Fetch action (Tenable/Qualys/OpenVAS), before ingestion via `/remediate` |
| `remediation/sample-data/sbom.json` | A hand-authored CycloneDX SBOM — the input `remediation/enrichment/sbom.py` computes dependency blast radius from, and `vuln-ingest-normalizer` cross-references to populate a finding's `dependency` field |

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
cross-platform advisory file lock, not a placeholder (a lock records its owner's process id and host and is taken over only when that process is gone, never merely because the holder is slow) — still guards every one of these
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
systems), but only `windows-server`, `unix-server`, `iot-ot-device`, and (for SCA findings
with a CVE) `application` route to a working `remediation-fixer-*` subagent today — every
other type is still normalized, enriched, scored, and planned, just routed to "no
automated fixer yet, here's who should own it" instead of a generated artifact.
`kev`/`epss` (CISA KEV + FIRST.org EPSS) and `poc_available`/`user_interaction_required`
are added by later enrichment stages, not at ingestion, and stay `null` whenever `cve` is
null — these are inherently CVE-scoped signals, so a policy finding with no CVE honestly
carries none rather than a guessed one. `dependency` (package/ecosystem/version/
fixed_version/direct) is nullable too, populated only for `application`/SCA findings when
a CycloneDX SBOM was supplied alongside the scanner exports and the normalizer's own LLM
judgment matched a component to the finding — see that field's own note in the schema doc
for why there's no mechanical CVE-to-package lookup table for this.

## Authentication & RBAC

A real local login MVP plus genuine OIDC client code that stays inert until a real
provider is configured. Full detail (every env var, every edge case) is in
`dashboard/README.md`'s "Authentication" section and
`docs/enterprise-suite/rbac-governance.html`; the load-bearing facts:

- **Passwords**: PBKDF2-HMAC-SHA256, stdlib only (`dashboard/auth/passwords.py`).
- **Sessions**: an HMAC-signed cookie (`dashboard/auth/sessions.py`), stdlib only. Set
  `QUANTA_SESSION_SECRET` to a real, stable value before any real deployment — without
  it, a random per-process secret means every session is invalidated on restart.
- **Users**: `dashboard/auth/users.json`, a real, editable, committed seed file with two
  demo accounts (`admin@quanta.local`, role admin; `analyst@quanta.local`, role
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
- **Identities come from the session, never the request body.** Exception and approval routes take the requester, approver and validator from `user["email"]`; creating an exception is administrator-only with a different administrator as approver. A new state-changing route must do the same and must not trust a name the caller sends.
- **Reads are public by default.** Every state-changing route is gated per-route with an
  explicit RBAC dependency, but every `GET`/`/api/*` read route returns real data with no
  login at all (`curl`, etc.) unless `QUANTA_REQUIRE_LOGIN_FOR_READS=true` is set —
  which itself requires a real, stable `QUANTA_SESSION_SECRET` or the app refuses to
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
python -m unittest discover -s tests -p "test_*.py"   # everything, repo-wide - 2,302 tests today, all passing
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

## Architecture: the 3-stage subagent pipeline (+ optional verification)

`/quanta-scan` (`.claude/commands/quanta-scan.md`) is the orchestrator. It parses `$ARGUMENTS`
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
   `quanta/auto-fixes-<timestamp>` → commit referencing finding IDs → `git push`,
   surfacing the PR-creation URL GitHub prints in the push output. No `gh` CLI dependency
   — opening the actual PR is a manual click in the browser or VS Code afterward. If push
   fails, it must stop and tell the user the manual step rather than failing silently.

A fourth subagent, **`vuln-verifier`** (tools: `Read, Grep, Glob, Bash` — same read-only
scope as `vuln-scanner`, no Edit/Write), runs only when `--verify FINDING-ID BRANCH` is
passed instead of `--fix`: it re-reads `SECURITY_REPORT.md` to reconstruct one finding,
re-checks it against the named branch/commit with `git show`/`git grep` (never checking
that branch out into the working tree), and returns a `resolved`/`still-present`/
`inconclusive` verdict — closing the loop `vuln-fixer` otherwise leaves open (it pushes a
branch and stops; nothing before this re-confirmed the fix actually worked). The
orchestrator logs the verdict via `remediation/audit/record_verification.py` to the real
activity log, and the dashboard's `/quanta-scan` page shows it as a "Verified" column,
defaulting to "Not yet verified" — never implied as verified just because a fix branch
exists.

The chat output from `/quanta-scan` stays a short summary (counts by severity, auto-fixable
count); full detail always lives in `SECURITY_REPORT.md`, never dumped into the
conversation.

### Why the tool scoping matters

Each agent's `tools:` list in its frontmatter is a hard security boundary, not a
suggestion: the scanner is read-only so the component that *finds* vulnerabilities cannot
introduce new ones; the reporter can only `Write`, so it cannot scan or fix; the fixer is
the only agent allowed to touch git/`gh`; the verifier can run `git show`/`git grep` via
Bash but has no Edit/Write, so it can inspect a fix but never apply or alter one. When
editing any of these agent files (`.claude/agents/*.md`), preserve this separation — don't
widen an agent's tool access to "make it easier," since the narrow scope is the point.

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

`/remediate` (`.claude/commands/remediate.md`) orchestrates **eight** subagents, same
scoped-tool-access philosophy as `/quanta-scan`:

1. **`vuln-ingest-normalizer`** (tools: `Read, Glob, Write`) parses Tenable CSV, Armis
   JSON, and threat-intel JSON exports into one common schema — see
   `remediation/schema/normalized-finding-schema.md`. Writes
   `remediation/output/normalized-findings.json`. Assigns `asset.type` (the routing key
   for everything downstream — 17 types today) and `remediation_domain` (non-null only
   for `windows-server`/`unix-server`/`iot-ot-device`/`application`, the four domains
   with a working fixer — see items 4-5 below for why the OT and application ones are
   each a different shape).
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
5. **`remediation-fixer-application`** (same `Read, Write`-only scope) handles
   `application`-type findings with a real CVE (the SCA case) that the planner routed to
   `automation_target: "dependency-upgrade"`. Generates a dependency-upgrade *plan*, not
   a manifest edit or a PR — it has no Bash/git access, so a real version bump, test run,
   and PR are left to a developer's own workflow. Uses the finding's `dependency` field
   (populated by `vuln-ingest-normalizer` from a CycloneDX SBOM — see
   `remediation/enrichment/sbom.py`) when available; when it isn't, generates a plan that
   says so and asks for one, rather than guessing a package or fixed version.

A `--finding-id FIND-N` argument (what the dashboard's "Trigger Remediation" button on an
already-approved finding uses, via `/api/run`) skips steps 1-3 entirely and delegates
straight to whichever fixer matches that one finding's `remediation_domain`, rather than
re-running ingest/enrich/plan for the whole batch to reach one already-known finding.

6. **`remediation-fixer-code`** (same `Read, Write`-only scope) handles first-party code findings: it confirms the flaw, records what behaviour must be preserved and writes
   a proposed unified diff to `remediation/output/code-fixes/<id>.json`. It edits nothing; Quanta's gitops layer validates and applies the diff and an administrator
   decides whether to open a pull request (see "Application security" above).

### Why network/firewall findings stay manual-only

`vuln-ingest-normalizer`, `threat-intel-enricher`, and `remediation-planner` handle every
asset type — ingestion, enrichment, and planning are asset-agnostic by design. Only
fix-generation is incomplete: there's no `remediation-fixer-network` yet, out of the 17
types the schema recognizes today (network routing/switching, network security devices,
cloud infrastructure, certificates, AI/ML findings, code repositories, and more — see
`remediation/schema/normalized-finding-schema.md` for the full list and why each was
added; `iot-ot-device` and `application` both have working fixers today —
`remediation-fixer-ot` and `remediation-fixer-application` respectively, see above).
Adding a network fixer means adding a new subagent with `tools: Read, Write` (same
restricted pattern) that generates vendor-appropriate config (e.g. Ansible's
`cisco.ios`/`junipernetworks.junos` collections for network gear), plus updating
`remediation-planner`'s `automation_target` assignment to route to it. Don't add real
execution capability (`Bash`, SSH, API calls) to any fixer subagent — every fixer in this
project stays artifact-generation-only.

## The demo app (`vulnerable-demo-app/`)

Six labeled, intentional vulnerabilities used as the `/quanta-scan` scoring/demo baseline — if
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

`docs/enterprise-suite/` holds 14 HTML documents (an executive brief, a companion
whitepaper, 9 technical references, a POC methodology, a commercial pricing/SLA page,
and a task-oriented user guide — indexed in `docs/enterprise-suite/MANIFEST.md`, each
also published as a live, shareable Artifact page at the URL listed there) plus
`docs/PRICING.md`, the plain-markdown source of truth for pricing/SLA terms.

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

### Generating PDFs and an offline copy from the suite

`scripts/doc-pdf-pipeline/` regenerates, from the real `docs/enterprise-suite/*.html`
files, every dark-navy PDF the suite ships as (15 individual chapter PDFs, one combined
PDF with a bookmark outline) plus a single self-contained offline HTML file with a
sidebar that switches between all 15 — all without touching the source `.html` files
themselves, which stay light-themed and print-CSS-free (the dark/print treatment is
applied on the fly to copies). It also regenerates the 3 standalone documents (Developer
& Contributor Guide, Commercial Brochure, Cloud Hosting & Commercial Launch Guide) from
their own already-dark-themed sources. See `scripts/doc-pdf-pipeline/README.md` for exact
commands and two real, hard-won gotchas: Puppeteer/Playwright cannot drive Chrome on a
machine where an enterprise policy disallows the DevTools remote-debugging protocol (this
one's machine included) — use plain `--headless --print-to-pdf` instead — and
`@page { margin: 0; }` is required for a full-bleed dark background in the PDF output,
not optional polish (Chrome's print margin gutter doesn't get painted by any element's
own `background`, regardless of what `body` says).

## Ownership & assignment (ITSM-style)

Findings can be assigned to a person and/or a team. Tables `teams` and `finding_assignments`
(`remediation/utils/db.py`); logic in `remediation/assignments/store.py` (assign, bulk
assign up to 2,000, status, auto-route from asset ownership, history) and `analytics.py`
(coverage, ageing, by-team, by-person, unowned-urgent). Routes: `/api/teams`,
`/api/assignable-users`, `/api/assignments*`, `/api/findings/{id}/assign|assignment`,
`/api/admin/teams*`. Pages: `/assignments`, `/ownership`, `/admin/people`. States:
assigned / team_only / unowned; work status open / in_progress / blocked / resolved.
An assignment's team overrides the asset's team. Ownership routes require login.

## Remediation safety, verification and rollout

Three deterministic layers wrap the LLM fixers. `remediation/validation/playbook_lint.py`
lints every generated playbook (header, real rollback, approval gate, YAML shape, no literal
credentials, no `hosts: all`; warnings for missing pre/post checks and raw shell) and
`/api/remediation-approvals/{id}/approve` refuses a playbook that fails. `remediation/
verification/closed_loop.py` reads the next scan to mark triggered remediations verified /
still-present / awaiting-rescan (evidence, not proof; surfaced on the Approvals page and at
`/api/remediation-verification`), and builds the per-remediation evidence pack. Rollout rings
(`rollout_profiles` in `remediation_policy.yaml`, resolved into each policy as
`rollout_rings`) stage a fix canary, pilot, broad. See `docs/AGENTIC_REMEDIATION_ROADMAP.md`
and `docs/DEPLOYMENT_ARCHITECTURE.md` (Dockerfile, compose, `QUANTA_DATABASE_URL`).

## Production data path, connections and operations

Real data no longer needs an interactive agent session. `remediation/ingest/` converts the
scanner CSV into Findings with explicit rules (`classify.py`, `scanner_csv.py`) and merges them
into `normalized-findings.json` atomically (`merge.py`: stable ids, last-seen refresh, optional
reconcile for complete exports, `.bak` copy). `remediation/connections/` stores connector
credentials encrypted (`crypto.py`, Fernet, key in `QUANTA_ENCRYPTION_KEY`, rotation supported),
lists the 7 syncable pull connectors and 3 push connectors (ServiceNow, Jira, Splunk) in
`registry.py`, and runs/schedules syncs (`sync.py`, `store.py`; table `connections`). Push
connections carry a rule (`min_severity`, `kev_only`, `min_epss`, `max_per_run`) in `push.py`,
keep finding-to-ticket links and map external ticket state back onto assignments in `links.py`
(table `ticket_links`). Admin routes
`/api/connections*` and the Connections page. Schema changes to existing tables use recorded
migrations (`remediation/utils/migrations.py`). `cli/quanta_admin.py` is the operator tool
(gen-key, init, bootstrap, create-admin, check, backup, restore, rotate-keys, migrate).
`QUANTA_PRODUCTION=true` requires a session secret, refuses published demo passwords, and closes
anonymous reads by default. `/healthz`, `/readyz`, `/metrics` (token), JSON logs and request ids
are in `dashboard/observability.py`. Deployment: `Dockerfile`, `docker-compose.yml` (app,
PostgreSQL, Caddy TLS), `.env.production.example`, `deploy/`. See `docs/PRODUCTION_GUIDE.md` and
`docs/CONNECTOR_ONBOARDING.md`. Still true: AI fixers need the Claude Code CLI, and no connector
has been run against a live vendor tenant.

**Scanner ingest**: `remediation/ingest/sarif.py` reads SARIF 2.1.0 (Semgrep, CodeQL, ZAP, Trivy, Checkov, gitleaks, ...) into findings
with `scan_type`, `location`, `cwe`, `rule_id` and `tool` fields (`POST /api/ingest/sarif`); `remediation/scanners/cicd.py` checks
GitHub Actions / GitLab CI / Jenkinsfiles against OWASP CI/CD risks (`quanta-admin scan-pipelines`); `remediation/ingest/coverage.py`
turns Cobertura/JaCoCo/lcov reports into findings for security-relevant files only (`POST /api/ingest/coverage`). The new scan
types are `container`, `cicd` and `coverage`; an explicit `scan_type` on a finding wins over inference.

**Client-specific compensating controls**: `remediation/enrichment/attack_mitigations.yaml` holds the MITRE ATT&CK mitigations for every
technique Quanta tags (read from attack.mitre.org; T1600 has none and the result says so) plus CWE-to-technique and indicative NIST
800-53 mappings; `remediation/controls/store.py` is the controls inventory (table `asset_controls`, verified vs claimed, glob asset
patterns, CSV import, `POST /api/ingest/controls` with a `controls:write` key, the Controls page); `client_controls.assess()` checks a
finding's applicable mitigations against the asset's recorded controls (verified / claimed / absent / unknown) and is shown in the
guidance (`/api/findings/{id}/compensating-controls`). With nothing recorded for an asset it says unknown rather than guessing.

**AI usage analytics** (`remediation/aiusage/`, page `/ai-usage`, admin only): table `ai_usage_events` (counts only, never prompt text; unique per
source + event_key) fed by provider usage connectors (`remediation/connectors/ai_usage_connector.py`: Anthropic Usage & Cost Admin API and
OpenAI organization usage, stored connections of kind pull/output `ai-usage`), `POST /api/ingest/ai-usage` and OTLP JSON
`/api/ingest/otlp/v1/traces` (key scope `ai-usage:write`), plus Quanta's own calls from `ai_usage_log`. Cost is reported, estimated from
`ai_pricing.yaml` (ships empty) or unknown, never zero. `analytics.py` gives totals, breakdowns, cache-hit rate, unusual days, budgets
(table `ai_budgets`) and models outside `ai_usage_policy.yaml`'s approved list; `discovery.py` + `ai_domains.yaml` find unreviewed AI
applications from proxy/DNS exports (table `ai_apps`; record and report only).

**Threat models** (`remediation/threatmodel/`, page `/threat-models`, admin only): a system described as components, data flows and trust zones
(tables `threat_models`, `threat_reviews`); `rules.py` raises STRIDE threats from explicit rules, computed on read so an edited model never leaves
stale threats; `engine.py` scores them (likelihood x impact; residual = inherent x (1 - 0.7 x control coverage)) and joins each to live findings
(ATT&CK technique or CWE overlap) and recorded controls; only people's decisions (accepted, mitigated, not applicable) are stored. `seed.py` builds a
starting model from the asset inventory.

**Governance, risk and compliance** (`remediation/grc/`, page `/grc`, admin only; policies list and acknowledgement need login only): framework
catalogs (`catalog.py`: built-in subset catalogs in `builtin.yaml` for NIST 800-53 r5, CSF 2.0 and an AI-governance set, or a full catalog imported as
OSCAL JSON), a risk register with likelihood x impact grids and suggestions drawn from live findings and threat models (`risks.py`), automated
control tests (`evidence.py`, thresholds and test-to-control mappings in `remediation/config/grc_tests.yaml`, collected hourly by the leader's
scheduler tick; too little data gives `na`, never a pass), attestations that sit beside the evidence, and versioned policies with acknowledgements.
`report.py` gives per-control status and an OSCAL assessment-results export. Quanta supplies evidence and workflow; it does not certify compliance.

**Threat hunting and SOC triage** (`remediation/hunting/`, page `/hunting`, admin only; tables `hunts`, `soc_alerts`): `generate.py` proposes one
hunt per open CVE that is on the KEV list or has EPSS >= 0.5, with the affected hosts, the ATT&CK techniques Quanta tags and queries from
`library.yaml` rendered as Splunk SPL by `translate.py` (a small translator for Sigma-style selections, not pySigma). Quanta does not run queries and is
not a SIEM: the analyst runs them in their own tool and records each result and the hunt's outcome (closing needs one). Alerts arrive at
`POST /api/ingest/alerts` (key scope `soc:write`); `triage.py` ranks them with vulnerability context and attaches a runbook from `runbooks.yaml`
(technique, then title keywords, else a generic one). Hunt metrics include ATT&CK coverage of the techniques in the estate's open findings.

**API security** (`remediation/apisec/`, page `/api-security`, admin only; full reference `docs/API_SECURITY.md`): an API inventory built from OpenAPI uploads or URL fetches
(`openapi.py`, `store.import_spec`) and imported gateway/WAF/access logs (`logs.py`; JSON lines, array, common/combined log, CSV; `POST /api/ingest/api-traffic`, key scope `api:write`).
Quanta cannot sniff traffic and never changes a WAF. Endpoints are keyed (service, method, path key); shadow/zombie/drift come from spec vs traffic; daily metrics, per-caller rows and
service dependencies are aggregated in memory per upload (tables `api_specs`, `api_endpoints`, `api_metrics`, `api_actor_hits`, `api_dependencies`). `classify.py` detects kinds of data and maps
them ONLY to the customer's imported framework (`api_data_classes`); unmapped data is "unclassified", never assumed sensitive. `rules.py` applies the OWASP API Top 10 (2023) with an evidence
chain and a placeholder-only cURL, thresholds in `remediation/config/api_security.yaml`; findings publish to the queue (source `api-security`, scan type dast) with curated guidance matched by
`rule_id` (`match.rule_ids` in `knowledge.yaml`). `identity.py` joins callers to endpoints and data classes; `metrics.py` derives error rate (errors/calls) and trend; `cicd.py` takes CI results
(`/api/ingest/api-test-results`, gate, DevSecOps control `api-security-testing`, scan type `api-test`); `policies.py` holds protection policies (monitor default, block needs a second
approver, versioned, audited; tables `api_policies`, `api_policy_events`, `api_policy_pushes`), sent via `PolicyWebhook` (signed like the SOAR response webhook; connection type
`api-policy-endpoint`; edge result reported back at `/api/inbound/api-policy-status`) with alerts on the notification webhook/email (`QUANTA_ALERT_EMAIL`); `waf.py` renders AWS WAF and Cloud Armor
review artifacts (data-loss limits and Cloud Armor body matches are honestly "not expressible"); `rollout.py` is the onboarding checklist. Built against public docs, never run against a live source.

**SOC agents** (`remediation/hunting/`, extends the hunting page): `siem_search_connector.py` runs a read-only Splunk search (only `search ...`,
write/delete/script commands refused, rows capped, slow searches cancelled) for a hunt lead or an alert investigation, only after a person confirms;
`reputation_connector.py` looks up public indicators (VirusTotal API v3; private addresses never sent). Both are connection types of kind `tool`
(`splunk-search`, `reputation`; `sync.run` does nothing for a tool). `ocsf.py` maps OCSF Detection Findings (`POST /api/ingest/alerts/ocsf`, key scope
`soc:write`); `intel.py` extracts CVEs/ATT&CK ids/indicators/actors from text or STIX and scores relevance to the estate (`POST /api/ingest/threat-intel`);
`verdict.py` gives each hunt lead and the whole hunt a verdict from the result and the analyst's assessment (an unassessed hit is never benign) and
renders the report; `soc.py` is the L1 investigation (classify, history, indicators, optional SIEM evidence, host context, a weighted-signal verdict of
likely-true-positive / likely-false-positive / escalate-l2, never a false positive for a Critical alert; thresholds in `config/soc_triage.yaml`);
`detection.py` is detection engineering (per-rule TP/noise rates over closed alerts, six health tiers, Maintain/Tune/Disable, Sigma before/after
tuning, ATT&CK coverage, weekly snapshots; thresholds in `config/detection_policy.yaml`). Alerts now carry `rule_name` and `entities`.

**SOAR** (`remediation/soar/`, page `/soar`, admin only; tables `soar_playbooks`, `soar_runs`; policy `config/soar_policy.yaml`): playbooks are validated
step lists (investigate, enrich-indicators, add-note, update-alert, notify, request-approval, response-action). A response action that changes the
environment needs an approval step before it (checked on save and again at run time), a different person must approve, dry runs contact nothing, a
playbook can set an alert investigating but never close it, and on-alert playbooks may only do local or non-destructive things. Response actions are
signed webhooks (`webhook_connector.py`, HMAC-SHA256 over timestamp.body) to endpoints the customer owns (`response-webhook`, `notify-webhook` tool
connections); Quanta never acts on a system itself.

**Cyber risk** (`remediation/risk/`, page `/cyber-risk`, admin only; table `risk_scenarios`; `config/risk_policy.yaml`): FAIR-style Monte Carlo (PERT
frequency and loss, Poisson events, seeded so results repeat) giving ALE, P90/P95, chance over tolerance and appetite, treatment ROI, plus the cyber
health score (control-test results and detection health, weighted; unmeasured domains are listed, not counted). The inputs are the user's estimates.

**DevSecOps** (`remediation/devsecops/`, page `/devsecops`; tables `scan_runs`, `devsecops_status`, `remediation_factory`): a 27-control library
(`library.yaml`, mapped to OWASP CI/CD and NIST SSDF, with CI snippets) with per-repository status from scan runs (a clean SARIF scan is recorded and
counts), pipeline-check findings (failing) and recorded states (never override observation); keyword policy mapping; a code-finding fix queue with a fix
brief per finding (resolved only by a later scan). `enrichment/zero_day_watch.py` (page `/zero-day-watch`) matches recent CISA KEV additions to the
vendor/product vocabulary of the estate (name match, not a version check).

**Firewall rules** (`remediation/firewall/`, page `/firewall`; tables `fw_rules`, `fw_requests`; `config/firewall_policy.yaml`): rules from CSV, JSON,
PAN-OS XML or FortiGate policy text; findings FW001-FW013 (any-any, internet-exposed risky ports, broad service/destination, clear text, no logging,
unused, stale, shadowed, redundant, no owner, expired); internet exposure; owner recertification (survives re-import while a rule's match is unchanged);
access requests checked against the rules (already allowed, blocked, needs a rule, risk, auto-approvable) with cycle-time metrics. Zone-specific rules
decide a request only when it names the zones. Quanta never changes a firewall.

**AI security** (`remediation/aisec/`, page `/ai-security`, admin only; table `ai_assets`): a register of AI systems checked against the OWASP LLM Top 10
(2025), MCP exposure and governance with explicit rules; an unanswered question is a gap, not a pass; findings can be published to the queue as
source `ai-security` (asset type `ai-ml-system`, a complete set each time).

**Access governance** (`remediation/iam/`, page `/access-governance`; tables `iam_entitlements`, `iam_roster`, `iam_campaigns`, `iam_review_items`;
`config/iam_policy.yaml`): entitlement and HR-roster intake; findings IAM001-IAM007 (leavers with access, dormant, unowned, too many privileged systems,
separation of duties, shared accounts, never used); manager access reviews (a revoke is a recorded decision, the identity team acts); SoD pre-check.

**Module layout** (sidebar `dashboard/static/js/nav.js`, catalog `remediation/config/capabilities.yaml`): the app is organised into eight modules - 1 Threat Detection & Response (SOC, hunting, detection
engineering, threat intel, SOAR), 2 Application Security, 3 DevSecOps & Supply Chain, 4 Infrastructure & Exposure, 5 AI Security, 6 Remediation & Workflow, 7 Risk, Governance & Compliance, 8 Administration -
plus Home and Help. `nav.js` shows ONE module at a time: a picker when none is chosen, otherwise only the chosen module (its pages, then its `connectors`), with the others behind "Switch module". The module of the
current route wins and is remembered in `localStorage` key `quanta.module`; /capabilities with no `area` clears it. `setLicense()`/`isLicensed()` lock modules the licence does not cover (picker shows
them locked; `app.js` refuses their pages). `capabilities.yaml` uses the same module ids and also lists `connectors`; the "All modules" page
(`/capabilities?area=<id>`) renders them. When you add a page, add it to the right module in BOTH files - `tests/test_capabilities.py` (`SidebarModuleTests`) fails if the module ids, a catalog page
or a connector page are missing from the sidebar, or a sidebar path has no route.

**Module licensing** (`remediation/licensing/license.py`, `config/licensing.yaml`, `cli/quanta_license.py`, `GET /api/license`; reference `docs/LICENSING.md`): the licence unit is the module. A licence is an
Ed25519-signed claim set (customer, edition label, modules, issued, expires, optional grace_days) verified offline against the vendor public key (`QUANTA_LICENSE` / `QUANTA_LICENSE_FILE`,
`QUANTA_LICENSE_PUBLIC_KEY_FILE`); nothing is sent anywhere. `QUANTA_LICENSE_MODE` is `off` (default: nothing checked), `warn` (reported, never blocks) or `enforce` (a middleware answers 403 for a route of an
unlicensed module). `licensing.yaml` maps every API route prefix to `core` or a module (longest prefix; `shared` prefixes need any one of several modules) and a test fails if an API route has no entry,
so add new route prefixes there when you add a feature. Core (sign-in, findings store, support, connections, administration) is never blocked. An expired licence keeps working for a grace period, then only core
remains. A technical guardrail and a clear contract, not copy protection; never used with a real issued licence.

**Capabilities page / All modules** (`remediation/capabilities.py`, `config/capabilities.yaml`, page `/capabilities`): the eight modules above, each listing its capabilities with a live count,
what to connect when it is empty, and its connectors. Add a capability to the YAML and it appears.

**Inbound API** (`docs/INTEGRATION_API.md`): `remediation/apikeys/store.py` issues Quanta API keys
(`qk_<prefix>_<secret>`, SHA-256 hash only, scopes `ingest:write` / `tickets:update` /
`read:findings` / `controls:write` / `ai-usage:write` / `soc:write` / `api:write`, expiry, revoke; table `api_keys`). `require_api_key(scope)` in `dashboard/app.py`
guards `POST /api/ingest/findings`, `/api/ingest/scanner-csv`, `/api/inbound/ticket-status`,
`GET /api/export/findings`; only `/api/ingest/`, `/api/inbound/`, `/api/export/` are exempt from the
login gate, and only because each route checks a key itself. `/api/ingest/generic` needs a key when
`QUANTA_PRODUCTION` is on. `GET /api/connections/schema` describes every connection type as JSON
Schema. Validation of pushed findings is `remediation/ingest/api_findings.py`.

**Running several replicas** (`docs/KUBERNETES.md`, Helm chart `deploy/helm/quanta`):
`remediation/coordination/` has database leases (`leases.py`; `QUANTA_LOCK_BACKEND=db` makes
`FileLock` use them), scheduler leader election (`leader.py`), a durable job queue with
`SKIP LOCKED` claims, heartbeats and retries (`jobs.py`, tables `leases` and `jobs`), and the worker
(`worker.py`, `quanta-admin worker`; the web process runs one embedded unless
`QUANTA_EMBEDDED_WORKER=false`). Scheduled and manual syncs are queued, not run in a thread.
`quanta-admin prepare` does first-run setup once per release under a lease; PostgreSQL schema
creation takes an advisory lock. Secrets can come from files (`remediation/utils/secret_files.py`:
`QUANTA_SESSION_SECRET_FILE` etc.) so a key vault mounted by External Secrets or the Secrets Store
CSI driver never appears as an environment variable. `QUANTA_FILES_BACKEND=db` (the chart default) makes the database the source of truth for the findings
file, playbooks, plan and policy YAML: `remediation/utils/file_sync.py` reconciles each replica's local
copy with table `file_snapshots` (versioned, tombstones, database wins on conflict; middleware in
`dashboard/app.py` syncs around requests, `merge.py` syncs under its lease), so no shared volume is
needed. `secret_files.reload_changed()` re-reads rotated secret files live (all but the session secret
and database URL). Still true: the findings are one whole stored file (tens of thousands of findings,
not millions), and the chart is checked by `helm lint`/`template`, `scripts/e2e_replicas.py` (real processes), a kind install job (`.github/workflows/helm-kind.yml`, not yet run), static tests (`tests/test_helm_chart.py`), CI
(`helm lint`/`template`/kubeconform) and unit tests but not yet installed on a live cluster.

## Application security: SBOMs, the dependency graph, fix pull requests, the release gate

`remediation/appsec/` holds the application model. `store.py` keeps applications (table `applications`: environment, platform, owner, team, business criticality,
internet-facing flag, Git provider/repository/default branch/dependency-file paths, connection id) and one parsed SBOM each (`app_sboms`). `sbom_parse.py` reads
CycloneDX and SPDX JSON into one shape; `manifest_gen.py` builds a CycloneDX SBOM from requirements.txt, package.json, package-lock.json, pom.xml or go.mod
(only a lock file gives transitive dependencies; it says so, and never runs a package manager). `graph.py` computes depth, direct vs transitive, paths and blast
radius and matches findings (by `dependency.package`) to components; `criticality.py` + `config/appsec_criticality.yaml` rate package sensitivity;
`scoring.py` + `config/appsec_scoring.yaml` rank every finding with a visible breakdown (CVSS, EPSS, KEV, application criticality, package sensitivity, attack
surface, attack-chain position, a lower multiplier for a denied network path); `analysis.py` joins it all, groups dependency findings into the one upgrade that
closes them, and adds the internet-to-application lane from `network_topology.yaml`. `connectors/osv_connector.py` turns an SBOM into findings via the public OSV
API (admin-confirmed, package URLs only, built against public docs and never run live). The graph UI is `static/js/depGraph.js` (plain SVG).

`remediation/gitops/` is the pull-request workflow. `upgrade.py` makes the manifest edit deterministically (no model); `diffing.py` applies a code-fix patch strictly;
`policy.py` + `config/gitops_policy.yaml` hold branch naming, protected branches, denied paths (pipeline files, CODEOWNERS, keys), approval rules and the process
steps; `prbody.py` writes the evidence-carrying description; `proposals.py` is the lifecycle (draft, approved, pr-opened, in-review, merged/closed, failed, discarded;
table `fix_proposals`) with `open_pr` as the **only** place Quanta writes to a repository: dry run unless `confirm`, a new branch, never the default or a protected
branch, never merged. `connectors/git_host_connector.py` (GitHub and GitLab; stored as `tool` connections `github` / `gitlab`) is the only code that talks to the host;
writes are not retried. State comes back by `POST /api/gitops/sync` or `POST /api/inbound/pr-status` (key scope `tickets:update`); verification reuses the closed-loop
rule (gone from the latest scan = resolved); `velocity.py` reports stage times. The subagents stay Read/Write only: `remediation-fixer-application` also writes
`remediation/output/upgrade-plans/<id>.json`, and `remediation-fixer-code` (new) writes `remediation/output/code-fixes/<id>.json` (a unified diff plus an honest
validation record); Python checks and applies them.

Keeping pull requests current is automatic where it can be: an hourly scheduler tick (`_run_gitops_sync_if_due`, off with `QUANTA_GITOPS_SYNC=false`) follows open pull
requests and re-checks merged ones against the latest scan; `POST /api/inbound/git-webhook` accepts signed GitHub / GitLab webhooks (`gitops/webhooks.py`, secret
`QUANTA_GIT_WEBHOOK_SECRET`, refuses everything when unset); `POST /api/gitops/proposals/{id}/rescan` queues a sync on each enabled scanner connection after a merge.
`python cli/quanta_admin.py seed-appsec-demo` (`remediation/appsec/demo.py`) registers a demo application, its SBOM and a few findings under source `appsec-demo`
(`--remove` undoes exactly that) and prints the topology entry that makes the graph's exposure lane show a path.

`remediation/devsecops/` additionally has `gates.py` + `config/pipeline_gates.yaml` (the CI release gate: `GET /api/gate/evaluate`, key scope `read:findings`, every
evaluation recorded in `gate_runs` and used as evidence for the `vulnerability-gate` control; the `sbom` control is evidenced by a stored SBOM), `design.py` +
`design_rules.yaml` (the secure design assistant: questionnaire to requirements, ASVS references, library controls, STRIDE prompts), and organisation-specific controls
(`devsecops_custom_controls`, `full_library()`) that use the same evidence model as the built-in library. Routes live in `dashboard/appsec_api.py` (an APIRouter built
by `build_router()` with dependencies injected); `POST /api/ingest/sbom` lets CI upload an SBOM. Pages: `/applications`, `/fix-prs`, `/pipeline-gates`,
`/secure-design`, and an "Our own controls" tab on `/devsecops`. Honest limits: the Git host connectors and OSV are unit-tested against fakes and not run live; Quanta
cannot regenerate lock files, run tests or know a customer's business logic (the PR says so and opens as a draft when a lock file exists); vulnerabilities in an SBOM
come from scanner findings or the OSV check, since Quanta ships no advisory database.

## SOC operations, models and use cases

`remediation/soc/` holds the case side of the SOC: `cases.py` (ITIL cases in L1/L2/L3 queues, priority = impact x urgency, service-level clocks derived on read,
escalation that needs a written hand-off summary, an hourly-style `sweep()` that auto-escalates a case once per tier past its resolve target, `auto_case()` from an
investigation, a deterministic `summarise()`), `metrics.py` (MTTA/MTTR, SLA compliance, backlog, escalation/reopen/false-positive rates, recommendation accuracy, workload,
daily series; None rather than zero when there is no data) and `loganalysis.py` (z-score bursts, interval-CV beaconing, fail-then-success, indicators; classical statistics only).
Policy: `remediation/config/soc_ops.yaml`. Tables `soc_cases`, `soc_case_events`, `soc_case_alerts`, `soc_analysts`, `detection_usecases`. `remediation/hunting/ttp.py` is a
multinomial Naive Bayes technique classifier (phrase list `ttp_lexicon.yaml` + hunt library + analyst-confirmed alerts); `usecases.py` + `usecase_store.py` generate and track
detection use cases (coverage gap, hunt promotion, tactic-pair sequence mining, indicator watchlist) as Sigma drafts that are never counted as coverage; `remediation/soar/recommend.py`
ranks playbooks by similarity-weighted past success; `remediation/soar/ai_draft.py` is the only language-model path (playbook drafts validated by `playbooks.validate`, use-case
refinement), confirm-gated through `_enforce_ai_usage_limit`/`_run_ai_call_and_record_usage`, never auto-saved. Page `/soc`; routes under `/api/soc/*`, `/api/detections/usecases*`,
`/api/soar/draft-playbook`. Method and models: `docs/enterprise-suite/soc-operations.html`. None of this is deep learning, and none has run against a live SIEM.

**SOC workflow** (`dashboard/app.py`): `_AutoInvestigator` investigates each new alert on both ingest routes, locally (no reputation or SIEM), loading context once per request and capped
by `auto_investigate.max_per_request`, then `soc_cases.auto_case`; `POST /api/soc/alerts/{id}/follow-up` merges a question into the stored investigation (optional confirmed SIEM
search); `_lookback_cfg` enforces the look-back ceiling (`max_lookback_days`, past it a written justification, hard stop at `extended_lookback_days`) for investigations, single
lead runs and `POST /api/hunting/hunts/{id}/run-all` (capped by `hunting.max_trial_hits_per_run`); a high-relevance report pushed to `/api/ingest/threat-intel` creates its hunt
(`hunting.auto_create_hunt_at_or_above`); `_identity_map()` feeds privileged-access detail from the Access Governance entitlements into the report; metrics include alert-to-action timing.

**Dark Web Watch** (`remediation/darkweb/`, `remediation/connectors/darkweb_connector.py`, page `/dark-web-watch`, admin only; tables `darkweb_hits`, `darkweb_sources`;
`config/darkweb_watch.yaml`, ships empty): `catalog.yaml` lists every source and how it is used (feed, lookup, import, guide). Active: Ransomwatch and ransomware.live
feeds (public, matched locally against the watch terms, polled by the leader tick) and credential-exposure lookups for the org's own domains (IntelligenceX, DeHashed,
LeakCheck, Snusbase: tool connections, confirm-gated, daily once enabled; counts, breach names and masked identifiers only, passwords dropped in the connector). Everything
else is import via the page or `POST /api/ingest/darkweb` (key scope `darkweb:write`). Quanta never connects to Tor or crawls. A hit raises a SOC alert from source
`darkweb`. Built against public docs and fakes; never run with a live account.

## Support tickets (ITSM service desk)

The Support page is a real helpdesk, not a link to an external tracker. Tables
`support_tickets` / `support_ticket_comments` (`remediation/utils/db.py`; older tables gain
new columns via `_add_missing_columns`), logic in `remediation/support/`: `store.py`
(create/comment/triage, pause, reopen), `sla.py` (priority = impact x urgency, response and
resolution clocks derived on read), `routing.py` (rules in `remediation/config/
support_routing.yaml`, only to teams that exist), `analytics.py` (SLA compliance, first
response, MTTR, reopen rate, ageing, by team/assignee, trend). `escalation.py` (one alert per ticket per level, via the activity log; hourly scheduler tick
and `POST /api/support/escalations/run`), CSAT (`rate_ticket`, `POST .../csat`). Policy:
`remediation/config/support_sla.yaml`. Routes `/api/support/tickets*`, `/api/support/analytics`,
`/api/support/policy`, `/api/findings/{id}/tickets`. Three roles per ticket: requester (own
ticket, public replies), agent (a member of the routed team: works the queue, no priority/team
change, no vendor escalation), admin (everything). Other users get 404. Optional vendor
escalation is an admin-confirmed email (`QUANTA_SUPPORT_EMAIL` + SMTP), public content only.
Tickets deliberately never go to a public issue tracker: they can describe the customer's
environment.

## Naming

The product name is **Quanta** everywhere: UI, documents, env vars (`QUANTA_*`),
`cli/quanta.py`, `remediation/quanta.db`, the `quanta_session` cookie, the
`*@quanta.local` demo accounts, and the code-scan slash command `/quanta-scan`
(`/remediate` is unchanged). It was renamed from an earlier working name; do not
reintroduce that name. Only the repository folder and GitHub repository name still carry
it, because they live outside the code.
